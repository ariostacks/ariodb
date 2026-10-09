//! The dashboard: a web app and JSON API for people, plus the callback
//! endpoints approvers use (signed approval links, Slack buttons).
//!
//! Security: every management endpoint needs a signed-in session with a
//! role that allows it (viewer, approver, admin), checked here on the
//! server, not only in the app. Sessions are random tokens in an HttpOnly,
//! SameSite=Strict cookie, stored only as SHA-256 hashes. Every
//! state-changing request must also carry the session's CSRF token in
//! `x-ariodb-csrf` and, when the browser sends one, an Origin that matches
//! the dashboard. People sign in with a local password or, when
//! `[dashboard.oidc]` is set, with single sign-on (see oidc.rs). The first
//! password can be set from this machine only (or with
//! `ariodb dashboard-password`).

use crate::config::Config;
use crate::gate::State;
use crate::store::{self, Role};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use axum::extract::{ConnectInfo, Path, Query, State as AxState};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;

const SESSION_HOURS: i64 = 12;
const COOKIE: &str = "ariodb_session";

/// The app's own pages (see dashboard/src/lib/router.ts).
pub const PAGES: &[&str] = &[
    "/approvals",
    "/decisions",
    "/sessions",
    "/rules",
    "/config",
    "/settings",
];

pub async fn serve(state: Arc<State>) -> Result<(), String> {
    let config = state.config();
    if config.dashboard.listen.is_empty() {
        return Ok(());
    }
    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind(&config.dashboard.listen)
        .await
        .map_err(|e| {
            format!(
                "dashboard cannot listen on {}: {e}",
                config.dashboard.listen
            )
        })?;
    println!("ariodb: dashboard at {}", config.dashboard.public_url);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| e.to_string())
}

pub fn router(state: Arc<State>) -> Router {
    let api = crate::dashboard_api::routes();
    Router::new()
        .route("/", get(crate::dashboard_files::serve))
        .route("/api/setup", post(setup))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/approvals", get(list_approvals))
        .route("/api/approvals/{id}", post(decide_approval))
        .route("/auth/login", get(crate::oidc::login))
        .route("/hooks/approvals/{id}", get(hook_confirm).post(hook_decide))
        .route("/slack/actions", post(slack_actions))
        .merge(api)
        // The single sign-on callback (its path is configurable, so it is
        // matched here), then the app's own pages and files.
        .fallback(fallback)
        .with_state(state)
}

async fn fallback(
    AxState(state): AxState<Arc<State>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let config = state.config();
    if method == Method::GET
        && let Some(o) = &config.dashboard.oidc
        && uri.path() == o.redirect_path
    {
        return crate::oidc::callback(&state, &headers, uri.query().unwrap_or("")).await;
    }
    crate::dashboard_files::serve(method, uri).await
}

// ---------------------------------------------------------------------------
// Errors and auth

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<String> for ApiError {
    fn from(e: String) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e)
    }
}

/// A signed-in person and what they may do.
pub struct User {
    pub name: String,
    pub role: Role,
    pub email: Option<String>,
    /// Single sign-on groups; none for local users.
    pub groups: Vec<String>,
    /// Signed in with single sign-on rather than a local password.
    pub sso: bool,
}

impl User {
    /// How this person is recorded when they decide an approval.
    pub fn decider(&self) -> String {
        if self.sso {
            format!("sso:{}", self.name)
        } else {
            format!("dashboard:{}", self.name)
        }
    }
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|c| c.split(';'))
        .map(str::trim)
        .find_map(|c| c.strip_prefix(&prefix).map(str::to_string))
}

/// `; Secure` when the dashboard is served over https.
pub(crate) fn secure_flag(config: &Config) -> &'static str {
    if config.dashboard.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    }
}

/// Who is signed in, if anyone, and the session's CSRF token. The role is
/// worked out on every request: a local user's from the users table, a
/// single sign-on user's from their groups and the current config. So a
/// changed role, a changed group mapping or email domain list, or
/// switched-off password logins apply at once, not at the next sign-in.
fn session(state: &State, headers: &HeaderMap) -> Option<(User, String)> {
    let token = cookie_value(headers, COOKIE)?;
    let s = state.db.session(&hash_token(&token)).ok()??;
    let config = state.config();
    let sso = s.method == "sso";
    let role = if sso {
        let o = config.dashboard.oidc.as_ref()?;
        if !crate::oidc::email_allowed(o, s.email.as_deref()) {
            return None;
        }
        o.role_for(&s.groups)?
    } else if !crate::oidc::password_login_allowed(&config) {
        return None;
    } else if s.user == "root" {
        Role::Admin
    } else {
        s.local_role?
    };
    Some((
        User {
            name: s.user,
            role,
            email: s.email,
            groups: s.groups,
            sso,
        },
        s.csrf,
    ))
}

fn signed_in(state: &State, headers: &HeaderMap) -> Result<(User, String), ApiError> {
    session(state, headers).ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "log in first".into()))
}

fn needs(user: &User, role: Role) -> Result<(), ApiError> {
    if user.role >= role {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::FORBIDDEN,
            format!(
                "this needs the {} role; {} has the {} role",
                role.as_str(),
                user.name,
                user.role.as_str()
            ),
        ))
    }
}

/// For reads: a signed-in user with at least this role.
pub fn require_role(state: &State, headers: &HeaderMap, role: Role) -> Result<User, ApiError> {
    let (user, _) = signed_in(state, headers)?;
    needs(&user, role)?;
    Ok(user)
}

/// For changes: a signed-in user with at least this role, the right CSRF
/// token, and a same-origin request.
pub fn require_change(state: &State, headers: &HeaderMap, role: Role) -> Result<User, ApiError> {
    let (user, csrf) = signed_in(state, headers)?;
    let given = headers
        .get("x-ariodb-csrf")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if given.is_empty() || !constant_eq(given, &csrf) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "missing or wrong CSRF token".into(),
        ));
    }
    same_origin(headers)?;
    needs(&user, role)?;
    Ok(user)
}

/// For reads any signed-in user may make.
pub fn require_user(state: &State, headers: &HeaderMap) -> Result<User, ApiError> {
    require_role(state, headers, Role::Viewer)
}

/// For changes to ariodb itself (config, users, secrets, undo): admins only.
pub fn require_writer(state: &State, headers: &HeaderMap) -> Result<User, ApiError> {
    require_change(state, headers, Role::Admin)
}

fn same_origin(headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return Ok(()); // non-browser clients send no Origin
    };
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let origin_host = origin.split("://").nth(1).unwrap_or("");
    if origin_host != host {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "cross-site request refused".into(),
        ));
    }
    Ok(())
}

pub(crate) fn constant_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0, |acc, (x, y)| acc | (x ^ y))
            == 0
}

pub fn hash_password(password: &str) -> Result<String, String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Set a local user's password, adding the user (as an admin, unless
/// `role` says otherwise) if they are new. An existing user keeps their
/// role unless `role` is given; root is always an admin.
pub fn set_password(
    state_db: &store::Db,
    user: &str,
    password: &str,
    role: Option<Role>,
) -> Result<(), String> {
    if password.len() < 12 {
        return Err("use a password of at least 12 characters".to_string());
    }
    if user == "root" && role.is_some_and(|r| r != Role::Admin) {
        return Err("root is always an admin".to_string());
    }
    let hash = hash_password(password)?;
    state_db.with(|c| {
        c.execute(
            "INSERT INTO dashboard_users (name, password_hash, created_ms, role) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET password_hash = excluded.password_hash",
            params![user, hash, store::now_ms(), role.unwrap_or(Role::Admin).as_str()],
        )?;
        if let Some(role) = role {
            c.execute(
                "UPDATE dashboard_users SET role = ?2 WHERE name = ?1",
                params![user, role.as_str()],
            )?;
        }
        // A new password ends every existing session for that user.
        c.execute(
            "DELETE FROM dashboard_sessions WHERE user = ?1 AND method = 'password'",
            [user],
        )?;
        Ok(())
    })
}

fn user_count(state: &State) -> i64 {
    state
        .db
        .with(|c| c.query_row("SELECT count(*) FROM dashboard_users", [], |r| r.get(0)))
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct Credentials {
    #[serde(default = "root")]
    user: String,
    password: String,
}

fn root() -> String {
    "root".to_string()
}

async fn setup(
    AxState(state): AxState<Arc<State>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Credentials>,
) -> Result<Response, ApiError> {
    same_origin(&headers)?;
    if state.config().dashboard.oidc.is_some() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "single sign-on is configured; set a break-glass password with ariodb dashboard-password"
                .into(),
        ));
    }
    if user_count(&state) > 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "a password is already set".into(),
        ));
    }
    if !addr.ip().is_loopback() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "set the first password from the server itself, or run ariodb dashboard-password"
                .into(),
        ));
    }
    set_password(&state.db, "root", &body.password, Some(Role::Admin))
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    start_session(&state, "root")
}

async fn login(
    AxState(state): AxState<Arc<State>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Credentials>,
) -> Result<Response, ApiError> {
    same_origin(&headers)?;
    let config = state.config();
    if !crate::oidc::password_login_allowed(&config) {
        let provider = config
            .dashboard
            .oidc
            .as_ref()
            .map(|o| o.provider_name.clone())
            .unwrap_or_default();
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            format!("local passwords are switched off; sign in with {provider}"),
        ));
    }
    let now = store::now_ms();
    let address = format!("address:{}", addr.ip());
    let user_key = format!("user:{}", body.user);
    if LOGINS
        .lock()
        .expect("login limiter")
        .blocked(&address, &user_key, now)
    {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed logins; wait 15 minutes and try again".into(),
        ));
    }
    let stored: Option<String> = state.db.with(|c| {
        c.query_row(
            "SELECT password_hash FROM dashboard_users WHERE name = ?1",
            [&body.user],
            |r| r.get(0),
        )
        .optional()
    })?;
    // Unknown users are checked against a dummy hash, so the time a wrong
    // answer takes does not say whether the user exists.
    let known = stored.is_some();
    let hash = stored.unwrap_or_else(|| DUMMY_HASH.clone());
    let verified = PasswordHash::new(&hash).is_ok_and(|h| {
        Argon2::default()
            .verify_password(body.password.as_bytes(), &h)
            .is_ok()
    });
    let ok = known && verified;
    if !ok {
        LOGINS.lock().expect("login limiter").failed(
            &address,
            known.then_some(user_key.as_str()),
            now,
        );
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "wrong user name or password".into(),
        ));
    }
    LOGINS
        .lock()
        .expect("login limiter")
        .succeeded(&address, &user_key);
    if config.dashboard.oidc.is_some() {
        println!(
            "ariodb: {} signed in to the dashboard with a local password (break glass)",
            body.user
        );
    }
    start_session(&state, &body.user)
}

/// A hash of a password nobody uses, to verify unknown users against.
static DUMMY_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    hash_password(&hex::encode(rand::random::<[u8; 16]>())).unwrap_or_default()
});

static LOGINS: std::sync::LazyLock<std::sync::Mutex<LoginLimiter>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(LoginLimiter::default()));

const LOGIN_WINDOW_MS: i64 = 15 * 60 * 1000;
/// Failed logins one client address may make in the window.
const MAX_FAILURES_PER_ADDRESS: u32 = 5;
/// Failed logins against one user in the window, from anywhere. Higher than
/// the per-address cap, so one noisy address cannot lock a person out, but
/// it still bounds guessing spread over many addresses.
const MAX_FAILURES_PER_USER: u32 = 20;
/// Past this many tracked keys, expired ones are swept out.
const MAX_TRACKED: usize = 10_000;

/// Counts failed dashboard logins per client address and per user name.
/// Argon2 makes each guess slow; this caps how many guesses anyone gets.
/// Counts live in memory, so a restart clears them.
#[derive(Default)]
pub struct LoginLimiter {
    /// Key to (failures, start of the window in ms).
    failures: std::collections::HashMap<String, (u32, i64)>,
}

impl LoginLimiter {
    fn count(&self, key: &str, now: i64) -> u32 {
        match self.failures.get(key) {
            Some((n, start)) if now - start < LOGIN_WINDOW_MS => *n,
            _ => 0,
        }
    }

    /// Should this attempt be refused without checking the password?
    pub fn blocked(&self, address: &str, user: &str, now: i64) -> bool {
        self.count(address, now) >= MAX_FAILURES_PER_ADDRESS
            || self.count(user, now) >= MAX_FAILURES_PER_USER
    }

    /// Record a failure. `user` is only counted for users that exist, so
    /// made-up names cannot fill the table.
    pub fn failed(&mut self, address: &str, user: Option<&str>, now: i64) {
        if self.failures.len() > MAX_TRACKED {
            self.failures
                .retain(|_, (_, start)| now - *start < LOGIN_WINDOW_MS);
        }
        for key in std::iter::once(address).chain(user) {
            let entry = self.failures.entry(key.to_string()).or_insert((0, now));
            if now - entry.1 >= LOGIN_WINDOW_MS {
                *entry = (0, now);
            }
            entry.0 += 1;
        }
    }

    pub fn succeeded(&mut self, address: &str, user: &str) {
        self.failures.remove(address);
        self.failures.remove(user);
    }
}


/// Start a session; returns its cookie and CSRF token. `sso` carries what
/// the identity provider said, for single sign-on sessions.
pub(crate) fn new_session(
    state: &State,
    user: &str,
    sso: Option<&crate::oidc::Identity>,
) -> Result<(String, String), String> {
    let token = hex::encode(rand::random::<[u8; 32]>());
    let csrf = hex::encode(rand::random::<[u8; 16]>());
    let no_groups = Vec::new();
    state.db.insert_session(&store::NewSession {
        token_hash: &hash_token(&token),
        user,
        csrf: &csrf,
        expires_ms: store::now_ms() + SESSION_HOURS * 3_600_000,
        method: if sso.is_some() { "sso" } else { "password" },
        subject: sso.map(|s| s.subject.as_str()),
        email: sso.and_then(|s| s.email.as_deref()),
        groups: sso.map_or(&no_groups, |s| &s.groups),
    })?;
    let cookie = format!(
        "{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{}",
        SESSION_HOURS * 3600,
        secure_flag(&state.config())
    );
    Ok((cookie, csrf))
}

fn start_session(state: &State, user: &str) -> Result<Response, ApiError> {
    let (cookie, csrf) = new_session(state, user, None)?;
    let role = state
        .db
        .users()?
        .into_iter()
        .find(|(name, _)| name == user)
        .map(|(_, role)| if user == "root" { Role::Admin } else { role })
        .unwrap_or(Role::Viewer);
    let me = User {
        name: user.to_string(),
        role,
        email: None,
        groups: Vec::new(),
        sso: false,
    };
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(me_json(&state.config(), &me, &csrf)),
    )
        .into_response())
}

/// What the app is told about the signed-in user.
fn me_json(config: &Config, user: &User, csrf: &str) -> Value {
    json!({
        "user": user.name,
        "csrf": csrf,
        "role": user.role,
        "email": user.email,
        "groups": user.groups,
        "method": if user.sso { "sso" } else { "password" },
        "provider": config.dashboard.oidc.as_ref().map(|o| o.provider_name.clone()),
        "config_writes": config.dashboard.config_writes,
    })
}

async fn logout(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let user = require_change(&state, &headers, Role::Viewer)?;
    if let Some(token) = cookie_value(&headers, COOKIE) {
        state.db.end_session(&hash_token(&token))?;
    }
    let config = state.config();
    let logout_url = if user.sso {
        crate::oidc::logout_url(&config).await
    } else {
        None
    };
    let cookie = format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "ok": true, "logout_url": logout_url })),
    )
        .into_response())
}

async fn me(AxState(state): AxState<Arc<State>>, headers: HeaderMap) -> Json<Value> {
    let config = state.config();
    match session(&state, &headers) {
        Some((user, csrf)) => Json(me_json(&config, &user, &csrf)),
        None => {
            let oidc = config.dashboard.oidc.as_ref();
            let password_login = match oidc {
                None => "primary",
                Some(o) if o.password_login == crate::oidc::PasswordLogin::Off => "off",
                Some(_) => "break_glass",
            };
            Json(json!({
                "user": null,
                "needs_setup": oidc.is_none() && user_count(&state) == 0,
                "sso": oidc.map(|o| json!({ "provider": o.provider_name, "login_url": "/auth/login" })),
                "password_login": password_login,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// Approvals

/// The single sign-on groups that may decide an approver's requests; empty
/// when anyone with the approver role may.
fn decider_groups<'a>(config: &'a Config, approver: &str) -> &'a [String] {
    config
        .approvers
        .iter()
        .find(|a| a.name == approver)
        .map_or(&[], |a| a.groups.as_slice())
}

/// May this person decide a request waiting on this approver?
pub fn may_decide(config: &Config, user: &User, approver: &str) -> Result<(), String> {
    if user.role < Role::Approver {
        return Err(format!(
            "{} has the {} role; deciding needs the approver role",
            user.name,
            user.role.as_str()
        ));
    }
    let groups = decider_groups(config, approver);
    if !groups.is_empty() && !user.groups.iter().any(|g| groups.contains(g)) {
        return Err(format!(
            "only members of {} may decide requests for approver '{approver}'",
            groups.join(", ")
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    all: bool,
}

async fn list_approvals(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let user = require_user(&state, &headers)?;
    let config = state.config();
    let items: Vec<Value> = state
        .db
        .approvals(!q.all, 200)?
        .into_iter()
        .map(|a| {
            let mut v = json!(a);
            v["decider_groups"] = json!(decider_groups(&config, &a.approver));
            v["you_may_decide"] = json!(may_decide(&config, &user, &a.approver).is_ok());
            v
        })
        .collect();
    Ok(Json(json!({ "approvals": items })))
}

#[derive(Deserialize)]
struct DecideBody {
    verdict: String,
    note: Option<String>,
}

async fn decide_approval(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DecideBody>,
) -> Result<Json<Value>, ApiError> {
    let user = require_change(&state, &headers, Role::Approver)?;
    let allow = match body.verdict.as_str() {
        "allow" => true,
        "deny" => false,
        _ => {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "verdict must be allow or deny".into(),
            ));
        }
    };
    let approval = state
        .db
        .approval(&id)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such approval request".into()))?;
    may_decide(&state.config(), &user, &approval.approver)
        .map_err(|e| ApiError(StatusCode::FORBIDDEN, e))?;
    let decided = state
        .db
        .decide(&id, allow, &user.decider(), body.note.as_deref())?;
    if !decided {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "already decided or expired".into(),
        ));
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct HookQuery {
    verdict: String,
    token: String,
    /// Set on the page's own reload (see `hook_confirm`).
    #[serde(default)]
    again: Option<String>,
}

impl HookQuery {
    /// The link itself, as a path on this dashboard.
    fn path(&self, id: &str) -> String {
        format!(
            "/hooks/approvals/{}?{}",
            form_urlencoded::byte_serialize(id.as_bytes()).collect::<String>(),
            form_urlencoded::Serializer::new(String::new())
                .append_pair("verdict", &self.verdict)
                .append_pair("token", &self.token)
                .finish()
        )
    }
}

/// Who may follow an approval link, when links need a signed-in approver.
enum LinkUser {
    Allowed(User, String),
    /// Signed in, but may not decide this request.
    Refused(String),
    /// Nobody is signed in (as far as this request shows).
    Nobody,
}

fn link_user(state: &State, headers: &HeaderMap, approver: &str) -> LinkUser {
    match session(state, headers) {
        None => LinkUser::Nobody,
        Some((user, csrf)) => match may_decide(&state.config(), &user, approver) {
            Ok(()) => LinkUser::Allowed(user, csrf),
            Err(e) => LinkUser::Refused(e),
        },
    }
}

/// An approval link, opened in a browser. Chat apps and mail scanners
/// fetch links to preview them, so a GET only shows what would be decided;
/// the decision itself needs the POST this page's button sends.
///
/// With `approval_links = "sign_in"` (the default under single sign-on),
/// the page also needs a signed-in approver. A link clicked in a chat app
/// or email is a cross-site navigation, so the browser leaves out the
/// SameSite=Strict session cookie; the page then reloads itself once, as
/// a same-site navigation that carries the cookie, before asking anyone to
/// sign in.
async fn hook_confirm(
    AxState(state): AxState<Arc<State>>,
    Path(id): Path<String>,
    Query(q): Query<HookQuery>,
    headers: HeaderMap,
) -> Response {
    let config = state.config();
    if !matches!(q.verdict.as_str(), "allow" | "deny")
        || !crate::approvals::verify_link(&config, &id, &q.verdict, &q.token)
    {
        return hook_page(
            StatusCode::FORBIDDEN,
            "<p>This approval link is not valid.</p>".into(),
        );
    }
    let Ok(Some(a)) = state.db.approval(&id) else {
        return hook_page(
            StatusCode::NOT_FOUND,
            "<p>No such approval request.</p>".into(),
        );
    };
    let action = if q.verdict == "allow" {
        "Approve"
    } else {
        "Deny"
    };
    let link = q.path(&id);
    let (signed_in_as, csrf_field) = if config.dashboard.links_need_sign_in() {
        match link_user(&state, &headers, &a.approver) {
            LinkUser::Allowed(user, csrf) => (
                format!(
                    "<p>Signed in as <b>{}</b>; you will be recorded as the decider.</p>",
                    html_escape(&user.name)
                ),
                format!(
                    "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
                    html_escape(&csrf)
                ),
            ),
            LinkUser::Refused(why) => {
                return hook_page(
                    StatusCode::FORBIDDEN,
                    format!("<p>You may not decide this request: {}.</p>", html_escape(&why)),
                );
            }
            LinkUser::Nobody => {
                let cross_site = headers
                    .get("sec-fetch-site")
                    .and_then(|v| v.to_str().ok())
                    == Some("cross-site");
                if cross_site && q.again.is_none() {
                    let again = format!("{link}&again=1");
                    return hook_page(
                        StatusCode::OK,
                        format!(
                            "<meta http-equiv=\"refresh\" content=\"0;url={0}\"><p><a href=\"{0}\">Continue</a></p>",
                            html_escape(&again)
                        ),
                    );
                }
                return sign_in_page(&config, &link);
            }
        }
    } else {
        (String::new(), String::new())
    };
    hook_page(
        StatusCode::OK,
        format!(
            "<p>Agent <b>{}</b> wants to run:</p><pre>{}</pre><p>Rule: {} ({}). Status: {}.</p>{signed_in_as}\
             <form method=\"post\" action=\"{}\">{csrf_field}<button type=\"submit\">{action} this request</button></form>",
            html_escape(&a.agent),
            html_escape(&a.sql),
            html_escape(&a.rule),
            html_escape(&a.reason),
            html_escape(&a.status),
            html_escape(&link),
        ),
    )
}

/// Asks the person to sign in, then come back to the link.
fn sign_in_page(config: &Config, link: &str) -> Response {
    let mut body = "<p>Sign in to decide this request.</p>".to_string();
    if let Some(o) = &config.dashboard.oidc {
        let next = form_urlencoded::byte_serialize(link.as_bytes()).collect::<String>();
        body.push_str(&format!(
            "<p><a href=\"/auth/login?next={}\">Sign in with {}</a></p>",
            html_escape(&next),
            html_escape(&o.provider_name)
        ));
    }
    if crate::oidc::password_login_allowed(config) {
        body.push_str(
            "<p>Or <a href=\"/\">sign in to the dashboard</a> with a password, then open this link again.</p>",
        );
    }
    hook_page(StatusCode::UNAUTHORIZED, body)
}

async fn hook_decide(
    AxState(state): AxState<Arc<State>>,
    Path(id): Path<String>,
    Query(q): Query<HookQuery>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let config = state.config();
    if !matches!(q.verdict.as_str(), "allow" | "deny")
        || !crate::approvals::verify_link(&config, &id, &q.verdict, &q.token)
    {
        return hook_page(
            StatusCode::FORBIDDEN,
            "<p>This approval link is not valid.</p>".into(),
        );
    }
    let mut decider = "webhook".to_string();
    if config.dashboard.links_need_sign_in() {
        let approver = state
            .db
            .approval(&id)
            .ok()
            .flatten()
            .map(|a| a.approver)
            .unwrap_or_default();
        match link_user(&state, &headers, &approver) {
            LinkUser::Allowed(user, csrf) => {
                let given = form_urlencoded::parse(body.as_bytes())
                    .find(|(k, _)| k == "csrf")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                if !constant_eq(&given, &csrf) || same_origin(&headers).is_err() {
                    return hook_page(
                        StatusCode::FORBIDDEN,
                        "<p>This form is out of date. Open the link again.</p>".into(),
                    );
                }
                decider = user.decider();
            }
            LinkUser::Refused(why) => {
                return hook_page(
                    StatusCode::FORBIDDEN,
                    format!("<p>You may not decide this request: {}.</p>", html_escape(&why)),
                );
            }
            LinkUser::Nobody => return sign_in_page(&config, &q.path(&id)),
        }
    }
    match state.db.decide(&id, q.verdict == "allow", &decider, None) {
        Ok(true) => hook_page(
            StatusCode::OK,
            format!(
                "<p>Recorded: {}.</p>",
                if q.verdict == "allow" {
                    "approved"
                } else {
                    "denied"
                }
            ),
        ),
        Ok(false) => hook_page(
            StatusCode::OK,
            "<p>This request was already decided or has expired.</p>".into(),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// The small pages behind approval links and sign-in errors: no scripts,
/// never framed (so the button cannot be clickjacked), and the token in
/// the URL is not passed on.
pub(crate) fn hook_page(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
            ),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>ariodb approval</title>{body}"
        )),
    )
        .into_response()
}

pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn slack_actions(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let config = state.config();
    let h = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let signed_by = crate::approvals::verify_slack(
        &config,
        &h("x-slack-request-timestamp"),
        &body,
        &h("x-slack-signature"),
    );
    if signed_by.is_empty() {
        return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
    }
    let payload = form_urlencoded::parse(body.as_bytes())
        .find(|(k, _)| k == "payload")
        .map(|(_, v)| v.into_owned());
    let Some(payload) = payload.and_then(|p| serde_json::from_str::<Value>(&p).ok()) else {
        return (StatusCode::BAD_REQUEST, "no payload").into_response();
    };
    let action = &payload["actions"][0];
    let (Some(kind), Some(id)) = (action["action_id"].as_str(), action["value"].as_str()) else {
        return (StatusCode::BAD_REQUEST, "no action").into_response();
    };
    // A Slack signature only speaks for requests waiting on that Slack
    // approver, not for ones meant for the dashboard or another approver.
    let waiting_on = state.db.approval(id).ok().flatten().map(|a| a.approver);
    if !waiting_on.is_some_and(|name| signed_by.contains(&name)) {
        return (
            StatusCode::FORBIDDEN,
            "this request is not waiting on a Slack approver",
        )
            .into_response();
    }
    let who = payload["user"]["username"]
        .as_str()
        .or(payload["user"]["id"].as_str())
        .unwrap_or("someone");
    let decided = state
        .db
        .decide(id, kind == "approve", &format!("slack:{who}"), None)
        .unwrap_or(false);
    let text = match (decided, kind) {
        (true, "approve") => format!("Approved by {who}."),
        (true, _) => format!("Denied by {who}."),
        (false, _) => "This request was already decided or has expired.".to_string(),
    };
    Json(json!({ "response_type": "in_channel", "replace_original": false, "text": text }))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_limiter_caps_guesses() {
        let mut l = LoginLimiter::default();
        let (addr, user) = ("address:192.0.2.7", "user:root");
        for _ in 0..MAX_FAILURES_PER_ADDRESS {
            assert!(!l.blocked(addr, user, 1_000));
            l.failed(addr, Some(user), 1_000);
        }
        // That address is now refused, even with the right password.
        assert!(l.blocked(addr, user, 2_000));
        // Another address may still try the same user...
        assert!(!l.blocked("address:198.51.100.1", user, 2_000));
        // ...until guesses at that user from anywhere reach their own cap.
        for i in 0..MAX_FAILURES_PER_USER {
            l.failed(&format!("address:203.0.113.{i}"), Some(user), 3_000);
        }
        assert!(l.blocked("address:198.51.100.1", user, 3_000));
        // The window passes.
        assert!(!l.blocked(addr, user, 3_000 + LOGIN_WINDOW_MS));
        // A success clears the counts for that address and user.
        l.failed(addr, Some(user), 5_000);
        l.succeeded(addr, user);
        assert_eq!(l.count(addr, 5_000) + l.count(user, 5_000), 0);
    }

    #[test]
    fn made_up_user_names_are_not_tracked() {
        let mut l = LoginLimiter::default();
        l.failed("address:192.0.2.7", None, 1_000);
        assert_eq!(l.failures.len(), 1);
    }

    #[test]
    fn deciding_needs_the_role_and_the_approvers_groups() {
        let config = Config::from_toml(
            r#"
[database]
url = "postgres://localhost:5432/app"

[[approvers]]
name = "ops"
type = "dashboard"

[[approvers]]
name = "dba-ops"
type = "dashboard"
groups = ["dba"]

[dashboard.oidc]
issuer = "https://login.example.test"
client_id = "ariodb"
admin_groups = ["admins"]
"#,
        )
        .unwrap();
        let user = |role, groups: &[&str]| User {
            name: "pat@example.test".into(),
            role,
            email: None,
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sso: true,
        };
        assert!(may_decide(&config, &user(Role::Viewer, &["dba"]), "ops").is_err());
        assert!(may_decide(&config, &user(Role::Approver, &[]), "ops").is_ok());
        assert!(may_decide(&config, &user(Role::Approver, &[]), "dba-ops").is_err());
        assert!(may_decide(&config, &user(Role::Admin, &["admins"]), "dba-ops").is_err());
        assert!(may_decide(&config, &user(Role::Approver, &["dba"]), "dba-ops").is_ok());
        assert_eq!(user(Role::Admin, &[]).decider(), "sso:pat@example.test");
        assert!(needs(&user(Role::Approver, &[]), Role::Admin).is_err());
        assert!(needs(&user(Role::Admin, &[]), Role::Approver).is_ok());
    }

    #[test]
    fn hook_pages_escape_what_they_show() {
        assert_eq!(
            html_escape(r#"<script>"x" & 'y'</script>"#),
            "&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/script&gt;"
        );
    }
}
