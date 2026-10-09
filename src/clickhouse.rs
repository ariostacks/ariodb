//! ClickHouse over HTTP. Agents send ClickHouse HTTP requests to ariodb with
//! their agent name and token; ariodb checks the SQL, then forwards it with
//! its own ClickHouse login.
//!
//! Reads run with `readonly = 2`, so ClickHouse itself refuses any hidden
//! write. Client-supplied settings are dropped except formatting and query
//! parameters, so an agent cannot switch read-only mode off. ClickHouse has
//! no transactions, so writes (INSERT only) cannot be rolled back or undone;
//! rules and approvals are the control.

use crate::chsql;
use crate::classify::Kind;
use crate::config::{Agent, Config};
use crate::gate::{self, Ctx, State};
use axum::Router;
use axum::body::Body;
use axum::extract::{RawQuery, State as AxState};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use base64::Engine;
use std::sync::Arc;
use std::time::Instant;

pub async fn serve_http(state: Arc<State>) -> Result<(), String> {
    let config = state.config();
    if config.clickhouse.http_listen.is_empty() {
        return Ok(());
    }
    let app = Router::new()
        .route("/ping", get(|| async { "Ok.\n" }))
        .route("/", any(query))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(&config.clickhouse.http_listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", config.clickhouse.http_listen))?;
    println!(
        "ariodb: ClickHouse HTTP clients can connect to http://{}",
        config.clickhouse.http_listen
    );
    axum::serve(listener, app).await.map_err(|e| e.to_string())
}

/// The agent as ClickHouse sees it: its ClickHouse access and tables.
pub fn clickhouse_agent(config: &Config, name: &str, token: &str) -> Result<Agent, &'static str> {
    let agent = config.agent(name).ok_or("unknown agent")?;
    let expected = config.agent_token(agent).ok_or("unknown agent")?;
    let ok = expected.len() == token.len()
        && expected
            .bytes()
            .zip(token.bytes())
            .fold(0, |a, (x, y)| a | (x ^ y))
            == 0;
    if !ok {
        return Err("wrong token");
    }
    let ch = agent
        .clickhouse
        .as_ref()
        .ok_or("this agent has no ClickHouse access")?;
    let mut view = agent.clone();
    view.access = ch.access;
    view.tables = ch.tables.clone();
    Ok(view)
}

/// ClickHouse-style error text, which clients show as-is.
fn ch_error(status: StatusCode, code: u32, message: &str) -> Response {
    let mut r = (
        status,
        format!("Code: {code}. DB::Exception: ariodb: {message}. (ARIODB)\n"),
    )
        .into_response();
    r.headers_mut()
        .insert("x-clickhouse-exception-code", HeaderValue::from(code));
    r
}

fn param_allowed(name: &str) -> bool {
    matches!(
        name,
        "database"
            | "default_format"
            | "query_id"
            | "wait_end_of_query"
            | "compress"
            | "decompress"
    ) || name.starts_with("param_")
        || name.starts_with("output_format_")
        || name.starts_with("input_format_")
        || name.starts_with("format_")
        || name == "date_time_output_format"
}

async fn query(
    AxState(state): AxState<Arc<State>>,
    method: Method,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let started = Instant::now();
    let config = state.config();
    let params: Vec<(String, String)> = form_urlencoded::parse(raw.unwrap_or_default().as_bytes())
        .into_owned()
        .collect();
    let param = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let header = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };

    // Who is asking: basic auth, X-ClickHouse-User/Key, or user/password parameters.
    let (user, token) = if let Some(auth) =
        header("authorization").and_then(|a| a.strip_prefix("Basic ").map(str::to_string))
    {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(auth)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default();
        let (u, p) = decoded.split_once(':').unwrap_or((&decoded, ""));
        (u.to_string(), p.to_string())
    } else if let Some(u) = header("x-clickhouse-user") {
        (u, header("x-clickhouse-key").unwrap_or_default())
    } else {
        (
            param("user").unwrap_or_default(),
            param("password").unwrap_or_default(),
        )
    };
    let agent = match clickhouse_agent(&config, &user, &token) {
        Ok(a) => a,
        Err(why) => return ch_error(StatusCode::UNAUTHORIZED, 516, &format!("{user}: {why}")),
    };

    // The statement: the `query` parameter, or else the whole body.
    let (sql, data) = match param("query") {
        Some(q) => (q, body),
        None if method == Method::POST => (
            String::from_utf8_lossy(&body).to_string(),
            axum::body::Bytes::new(),
        ),
        None => return ch_error(StatusCode::BAD_REQUEST, 62, "no query"),
    };
    let database = param("database")
        .or_else(|| header("x-clickhouse-database"))
        .unwrap_or_else(|| "default".into());
    let session = format!("ch-{}", agent.name);
    let ctx = Ctx {
        agent: &agent,
        session: &session,
        database: &database,
    };
    let audit = |outcome: &str,
                 rows: Option<u64>,
                 reason: Option<&str>,
                 rule: Option<&str>,
                 stmt: Option<&crate::classify::Statement>| {
        let tables = stmt.map(|s| s.tables.clone()).unwrap_or_default();
        state.audit.record(&crate::audit::Entry {
            session: &session,
            agent: &agent.name,
            sql: &sql,
            kind: stmt
                .map(|s| s.kind.to_string())
                .unwrap_or_else(|| "unknown".into()),
            tables: &tables,
            outcome,
            rows,
            reason,
            rule,
            latency_ms: Some(started.elapsed().as_millis() as u64),
            engine: "clickhouse",
            database: &database,
        });
    };

    let stmt = match chsql::classify(&sql) {
        Ok(mut s) => {
            chsql::scope_to_database(&mut s, &database);
            s
        }
        Err(e) => {
            audit("refused", None, Some(&e), None, None);
            return ch_error(StatusCode::FORBIDDEN, 497, &e);
        }
    };
    let (plan, approved) =
        match gate::check_detailed(&state, &ctx, std::slice::from_ref(&stmt)).await {
            Ok(p) => p,
            Err(r) => {
                audit(
                    "refused",
                    None,
                    Some(&r.message),
                    r.rule.as_deref(),
                    Some(&stmt),
                );
                return ch_error(StatusCode::FORBIDDEN, 497, &r.message);
            }
        };

    // Build the upstream request.
    let (mut url, resolve) = match config.clickhouse_http_url() {
        Ok(u) => u,
        Err(e) => return ch_error(StatusCode::INTERNAL_SERVER_ERROR, 1000, &e),
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in params
            .iter()
            .filter(|(k, _)| param_allowed(k) && k != "database")
        {
            q.append_pair(k, v);
        }
        // Always name the database, so ClickHouse resolves table names in
        // the same database ariodb judged them in.
        q.append_pair("database", &database);
        if stmt.kind == Kind::Read || plan == gate::Plan::Read {
            q.append_pair("readonly", "2");
        }
        let seconds = config.limits.statement_timeout_ms.div_ceil(1000).max(1);
        q.append_pair("max_execution_time", &seconds.to_string());
        if param("query").is_some() {
            q.append_pair("query", &sql);
        }
    }
    let upstream_body = if param("query").is_some() {
        data
    } else {
        axum::body::Bytes::from(sql.clone())
    };
    let password = match config.clickhouse_password() {
        Ok(p) => p,
        Err(e) => return ch_error(StatusCode::INTERNAL_SERVER_ERROR, 1000, &e),
    };
    crate::tls::init();
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.clickhouse.accept_invalid_certificate);
    if let Some((domain, addr)) = &resolve {
        builder = builder.resolve(domain, *addr);
    }
    let client = builder.build().expect("HTTP client");
    let mut req = client
        .post(url)
        .header("x-clickhouse-user", &config.clickhouse.user)
        .header("x-clickhouse-key", password)
        .body(upstream_body);
    for h in ["content-type", "content-encoding", "accept-encoding"] {
        if let Some(v) = headers.get(h) {
            req = req.header(h, v);
        }
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            audit("failed", None, Some(&e.to_string()), None, Some(&stmt));
            return ch_error(
                StatusCode::BAD_GATEWAY,
                210,
                &format!("cannot reach ClickHouse: {e}"),
            );
        }
    };

    let status = resp.status();
    let summary = resp
        .headers()
        .get("x-clickhouse-summary")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let rows = summary
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .map(|v| {
            let n = |k: &str| {
                v[k].as_str()
                    .and_then(|x| x.parse::<u64>().ok())
                    .unwrap_or(0)
            };
            if stmt.kind == Kind::Write {
                n("written_rows")
            } else {
                n("read_rows")
            }
        });
    let outcome = if status.is_success() {
        "allowed"
    } else {
        "failed"
    };
    let reason = (!status.is_success()).then(|| format!("ClickHouse answered {status}"));
    audit(
        outcome,
        rows,
        reason.as_deref(),
        approved.as_deref(),
        Some(&stmt),
    );

    let mut out = Response::builder().status(status.as_u16());
    for (k, v) in resp.headers() {
        let name = k.as_str();
        if name.starts_with("x-clickhouse-") || matches!(name, "content-type" | "content-encoding")
        {
            out = out.header(k, v);
        }
    }
    out.body(Body::from_stream(resp.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
