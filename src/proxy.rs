//! A Postgres-compatible front door. Agents connect with psql or any driver,
//! using their agent name as the user and their token as the password.
//!
//! Supports the simple query protocol. Drivers that need the extended
//! protocol (prepared statements with parameters) are not supported yet.

use crate::audit::AuditLog;
use crate::config::Config;
use crate::exec::{Outcome, Session};
use async_trait::async_trait;
use futures::{StreamExt, stream};
use pgwire::api::auth::cleartext::CleartextPasswordAuthStartupHandler;
use pgwire::api::auth::{AuthSource, DefaultServerParameterProvider, LoginInfo, Password};
use pgwire::api::query::SimpleQueryHandler;
use pgwire::api::results::{DataRowEncoder, FieldFormat, FieldInfo, QueryResponse, Response, Tag};
use pgwire::api::store::PortalStore;
use pgwire::api::{ClientInfo, ClientPortalStore, PgWireServerHandlers, Type};
use pgwire::error::{ErrorInfo, PgWireError, PgWireResult};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

pub async fn serve(config: Arc<Config>, audit: Arc<AuditLog>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&config.proxy.listen).await?;
    println!(
        "ariodb: agents can connect to postgres://<agent>@{}",
        config.proxy.listen
    );
    loop {
        let (socket, _addr) = listener.accept().await?;
        // One set of handlers per connection, so each connection has its own session.
        let handlers = Arc::new(Handlers::new(config.clone(), audit.clone()));
        tokio::spawn(async move {
            if let Err(e) = pgwire::tokio::process_socket(socket, None, handlers).await {
                eprintln!("ariodb: connection error: {e}");
            }
        });
    }
}

struct Handlers {
    startup: Arc<CleartextPasswordAuthStartupHandler<AgentAuth, DefaultServerParameterProvider>>,
    query: Arc<QueryHandler>,
}

impl Handlers {
    fn new(config: Arc<Config>, audit: Arc<AuditLog>) -> Handlers {
        let auth = AgentAuth {
            config: config.clone(),
        };
        Handlers {
            startup: Arc::new(CleartextPasswordAuthStartupHandler::new(
                auth,
                DefaultServerParameterProvider::default(),
            )),
            query: Arc::new(QueryHandler {
                config,
                audit,
                session: Mutex::new(None),
            }),
        }
    }
}

impl PgWireServerHandlers for Handlers {
    fn simple_query_handler(&self) -> Arc<impl SimpleQueryHandler> {
        self.query.clone()
    }

    fn startup_handler(&self) -> Arc<impl pgwire::api::auth::StartupHandler> {
        self.startup.clone()
    }
}

/// Agents log in with their name and token. Unknown agents cannot log in.
#[derive(Debug)]
struct AgentAuth {
    config: Arc<Config>,
}

#[async_trait]
impl AuthSource for AgentAuth {
    async fn get_password(&self, login: &LoginInfo) -> PgWireResult<Password> {
        let user = login.user().unwrap_or_default();
        match self.config.agent(user).and_then(|a| a.token()) {
            Some(token) => Ok(Password::new(None, token.into_bytes())),
            None => Err(PgWireError::InvalidPassword(user.to_string())),
        }
    }
}

struct QueryHandler {
    config: Arc<Config>,
    audit: Arc<AuditLog>,
    session: Mutex<Option<Session>>,
}

#[async_trait]
impl SimpleQueryHandler for QueryHandler {
    async fn do_query<C>(&self, client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
    where
        C: ClientInfo + ClientPortalStore + Unpin + Send + Sync,
        C::PortalStore: PortalStore,
    {
        if query.trim().is_empty() {
            return Ok(vec![Response::EmptyQuery]);
        }
        let mut guard = self.session.lock().await;
        if guard.is_none() {
            let user = client.metadata().get("user").cloned().unwrap_or_default();
            let Some(agent) = self.config.agent(&user).cloned() else {
                return Ok(vec![error("28000", format!("unknown agent '{user}'"))]);
            };
            match Session::connect(&self.config, agent, self.audit.clone()).await {
                Ok(session) => *guard = Some(session),
                Err(message) => return Ok(vec![error("08006", message)]),
            }
        }
        let session = guard.as_mut().expect("session was just created");
        let outcomes = session.run(query).await;
        Ok(outcomes.into_iter().map(to_response).collect())
    }
}

fn to_response(outcome: Outcome) -> Response {
    match outcome {
        Outcome::Rows { columns, rows } => {
            let fields: Vec<FieldInfo> = columns
                .into_iter()
                .map(|name| FieldInfo::new(name, None, None, Type::TEXT, FieldFormat::Text))
                .collect();
            let schema = Arc::new(fields);
            let mut encoder = DataRowEncoder::new(schema.clone());
            let data = stream::iter(rows).map(move |row| {
                for value in &row {
                    encoder.encode_field(value)?;
                }
                Ok(encoder.take_row())
            });
            Response::Query(QueryResponse::new(schema, data))
        }
        Outcome::Done { command, rows } => {
            let tag = Tag::new(&command).with_rows(rows as usize);
            Response::Execution(if command == "INSERT" {
                tag.with_oid(0)
            } else {
                tag
            })
        }
        Outcome::Refused { message } => error("42501", format!("ariodb: {message}")),
        Outcome::Failed { code, message } => error(&code, message),
    }
}

fn error(code: &str, message: String) -> Response {
    Response::Error(Box::new(ErrorInfo::new(
        "ERROR".to_string(),
        code.to_string(),
        message,
    )))
}
