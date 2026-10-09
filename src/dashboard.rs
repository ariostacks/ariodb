//! The dashboard: a web page and JSON API for people, plus the callback
//! endpoints approvers use (signed webhook links, Slack buttons).
//!
//! Security: every management endpoint needs a logged-in session. Sessions
//! are random tokens in an HttpOnly, SameSite=Strict cookie, stored only as
//! SHA-256 hashes. Every state-changing request must also carry the
//! session's CSRF token in `x-ariodb-csrf` and, when the browser sends one,
//! an Origin that matches the dashboard. The first password can be set from
//! this machine only (or with `ariodb dashboard-password`).

use crate::gate::State;
use crate::store;
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use axum::extract::{ConnectInfo, Path, Query, State as AxState};
use axum::http::{HeaderMap, StatusCode, header};
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
        .route("/", get(index))
        .route("/api/setup", post(setup))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/approvals", get(list_approvals))
        .route("/api/approvals/{id}", post(decide_approval))
        .route("/hooks/approvals/{id}", get(hook_confirm).post(hook_decide))
        .route("/slack/actions", post(slack_actions))
        .merge(api)
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
            ),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html(crate::dashboard_ui::PAGE),
    )
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

pub struct User {
    pub name: String,
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies
        .split(';')
        .map(str::trim)
        .find_map(|c| c.strip_prefix(&format!("{COOKIE}=")).map(str::to_string))
}

/// Who is logged in, if anyone. Returns the user and the session's CSRF token.
fn session(state: &State, headers: &HeaderMap) -> Option<(String, String)> {
    let token = cookie_token(headers)?;
    let hash = hash_token(&token);
    state
        .db
        .with(|c| {
            c.query_row(
                "SELECT user, csrf FROM dashboard_sessions WHERE token_hash = ?1 AND expires_ms > ?2",
                params![hash, store::now_ms()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
        })
        .ok()
        .flatten()
}

/// For reads: a logged-in user.
pub fn require_user(state: &State, headers: &HeaderMap) -> Result<User, ApiError> {
    session(state, headers)
        .map(|(name, _)| User { name })
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "log in first".into()))
}

/// For changes: a logged-in user, the right CSRF token, and a same-origin request.
pub fn require_writer(state: &State, headers: &HeaderMap) -> Result<User, ApiError> {
    let (name, csrf) = session(state, headers)
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "log in first".into()))?;
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
    Ok(User { name })
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

fn constant_eq(a: &str, b: &str) -> bool {
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

pub fn set_password(state_db: &store::Db, user: &str, password: &str) -> Result<(), String> {
    if password.len() < 12 {
        return Err("use a password of at least 12 characters".to_string());
    }
    let hash = hash_password(password)?;
    state_db.with(|c| {
        c.execute(
            "INSERT INTO dashboard_users (name, password_hash, created_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET password_hash = excluded.password_hash",
            params![user, hash, store::now_ms()],
        )?;
        // A new password ends every existing session for that user.
        c.execute("DELETE FROM dashboard_sessions WHERE user = ?1", [user])?;
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
    set_password(&state.db, "root", &body.password)
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

fn start_session(state: &State, user: &str) -> Result<Response, ApiError> {
    let token = hex::encode(rand::random::<[u8; 32]>());
    let csrf = hex::encode(rand::random::<[u8; 16]>());
    let expires = store::now_ms() + SESSION_HOURS * 3_600_000;
    state.db.with(|c| {
        c.execute("DELETE FROM dashboard_sessions WHERE expires_ms < ?1", [store::now_ms()])?;
        c.execute(
            "INSERT INTO dashboard_sessions (token_hash, user, csrf, expires_ms) VALUES (?1, ?2, ?3, ?4)",
            params![hash_token(&token), user, csrf, expires],
        )
    })?;
    let secure = if state.config().dashboard.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{secure}",
        SESSION_HOURS * 3600
    );
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "user": user, "csrf": csrf })),
    )
        .into_response())
}

async fn logout(
    AxState(state): AxState<Arc<State>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_writer(&state, &headers)?;
    if let Some(token) = cookie_token(&headers) {
        state.db.with(|c| {
            c.execute(
                "DELETE FROM dashboard_sessions WHERE token_hash = ?1",
                [hash_token(&token)],
            )
        })?;
    }
    let cookie = format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

async fn me(AxState(state): AxState<Arc<State>>, headers: HeaderMap) -> Json<Value> {
    match session(&state, &headers) {
        Some((user, csrf)) => Json(json!({ "user": user, "csrf": csrf })),
        None => Json(json!({ "user": null, "needs_setup": user_count(&state) == 0 })),
    }
}

// ---------------------------------------------------------------------------
// Approvals

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
    require_user(&state, &headers)?;
    let items = state.db.approvals(!q.all, 200)?;
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
    let user = require_writer(&state, &headers)?;
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
    let decided = state.db.decide(
        &id,
        allow,
        &format!("dashboard:{}", user.name),
        body.note.as_deref(),
    )?;
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
}

/// A webhook decision link, opened in a browser. Chat apps and mail
/// scanners fetch links to preview them, so a GET only shows what would be
/// decided; the decision itself needs the POST this page's button sends.
async fn hook_confirm(
    AxState(state): AxState<Arc<State>>,
    Path(id): Path<String>,
    Query(q): Query<HookQuery>,
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
    let target = format!(
        "/hooks/approvals/{}?verdict={}&token={}",
        html_escape(&id),
        html_escape(&q.verdict),
        html_escape(&q.token)
    );
    hook_page(
        StatusCode::OK,
        format!(
            "<p>Agent <b>{}</b> wants to run:</p><pre>{}</pre><p>Rule: {} ({}). Status: {}.</p>\
             <form method=\"post\" action=\"{target}\"><button type=\"submit\">{action} this request</button></form>",
            html_escape(&a.agent),
            html_escape(&a.sql),
            html_escape(&a.rule),
            html_escape(&a.reason),
            html_escape(&a.status),
        ),
    )
}

async fn hook_decide(
    AxState(state): AxState<Arc<State>>,
    Path(id): Path<String>,
    Query(q): Query<HookQuery>,
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
    match state.db.decide(&id, q.verdict == "allow", "webhook", None) {
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

/// The small pages behind webhook links: no scripts, never framed (so the
/// button cannot be clickjacked), and the token in the URL is not passed on.
fn hook_page(status: StatusCode, body: String) -> Response {
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

fn html_escape(s: &str) -> String {
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
    fn hook_pages_escape_what_they_show() {
        assert_eq!(
            html_escape(r#"<script>"x" & 'y'</script>"#),
            "&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/script&gt;"
        );
    }
}
