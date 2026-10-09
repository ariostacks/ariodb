//! Single sign-on for the dashboard with OpenID Connect.
//!
//! The authorisation code flow with PKCE, state and nonce. The provider's
//! discovery document and signing keys are fetched and cached; an unknown
//! key id fetches the keys again, so the provider can rotate them. An ID
//! token is let in only with a good signature from an allowed algorithm,
//! the right issuer and audience, an expiry in the future (a minute's
//! leeway) and the nonce this browser was given. Roles come from the
//! groups the token names; no matching group means no access.

use crate::config::Config;
use crate::dashboard::{html_escape, hook_page};
use crate::gate::State;
use crate::store::Role;
use axum::extract::{Query, State as AxState};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `[dashboard.oidc]`. Unknown keys are refused, so a misspelt
/// `password_login` cannot leave passwords on unnoticed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The provider's issuer URL; `/.well-known/openid-configuration` is
    /// read from under it.
    pub issuer: String,
    /// Shown on the sign-in button: "Sign in with <provider_name>".
    #[serde(default = "default_provider_name")]
    pub provider_name: String,
    pub client_id: String,
    /// The client secret, for confidential clients. Public clients rely on
    /// PKCE alone and set neither.
    pub client_secret_env: Option<String>,
    pub client_secret_secret: Option<String>,
    /// Where the provider sends people back, under `dashboard.public_url`.
    #[serde(default = "default_redirect_path")]
    pub redirect_path: String,
    /// Default: openid, profile and email, plus groups when any role
    /// groups are configured.
    pub scopes: Option<Vec<String>>,
    /// The ID token claim that lists a person's groups. A dotted name
    /// reaches into objects (`realm_access.roles`).
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default)]
    pub admin_groups: Vec<String>,
    #[serde(default)]
    pub approver_groups: Vec<String>,
    #[serde(default)]
    pub viewer_groups: Vec<String>,
    /// Only people whose verified email is in one of these domains.
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    /// Local passwords: `break_glass` (still accepted, offered below the
    /// sign-in button) or `off`.
    #[serde(default)]
    pub password_login: PasswordLogin,
    /// Also end the session at the provider when signing out, if it
    /// supports RP-initiated logout.
    #[serde(default)]
    pub logout_at_provider: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordLogin {
    #[default]
    BreakGlass,
    Off,
}

fn default_provider_name() -> String {
    "single sign-on".to_string()
}

fn default_redirect_path() -> String {
    "/auth/callback".to_string()
}

fn default_groups_claim() -> String {
    "groups".to_string()
}

impl OidcConfig {
    pub fn scopes(&self) -> Vec<String> {
        if let Some(s) = &self.scopes {
            return s.clone();
        }
        let mut s: Vec<String> = ["openid", "profile", "email"].map(String::from).to_vec();
        if !(self.admin_groups.is_empty()
            && self.approver_groups.is_empty()
            && self.viewer_groups.is_empty())
        {
            s.push("groups".to_string());
        }
        s
    }

    /// The highest role any of these groups maps to.
    pub fn role_for(&self, groups: &[String]) -> Option<Role> {
        let any = |list: &[String]| groups.iter().any(|g| list.contains(g));
        if any(&self.admin_groups) {
            Some(Role::Admin)
        } else if any(&self.approver_groups) {
            Some(Role::Approver)
        } else if any(&self.viewer_groups) {
            Some(Role::Viewer)
        } else {
            None
        }
    }
}

/// Whether local passwords may be used to sign in.
pub fn password_login_allowed(config: &Config) -> bool {
    config
        .dashboard
        .oidc
        .as_ref()
        .is_none_or(|o| o.password_login != PasswordLogin::Off)
}

fn is_loopback_url(url: &str) -> bool {
    let rest = url.strip_prefix("http://").unwrap_or("");
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    };
    host == "localhost"
        || host == "[::1]"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Checks on `[dashboard.oidc]` and approver groups when the config loads.
pub fn validate(config: &Config) -> Result<(), String> {
    let grouped = config.approvers.iter().find(|a| !a.groups.is_empty());
    let Some(o) = &config.dashboard.oidc else {
        if let Some(a) = grouped {
            return Err(format!(
                "approver '{}' sets groups, which need [dashboard.oidc]",
                a.name
            ));
        }
        return Ok(());
    };
    if !o.issuer.starts_with("https://") && !is_loopback_url(&o.issuer) {
        return Err(
            "dashboard.oidc.issuer must be an https:// URL (http:// only for localhost)".into(),
        );
    }
    if o.client_id.is_empty() {
        return Err("dashboard.oidc.client_id is empty".into());
    }
    if o.client_secret_env.is_some() && o.client_secret_secret.is_some() {
        return Err(
            "dashboard.oidc: set client_secret_env or client_secret_secret, not both".into(),
        );
    }
    let p = &o.redirect_path;
    if !p.starts_with('/')
        || p == "/"
        || p.contains(['?', '#'])
        || ["/api/", "/hooks/", "/slack/", "/assets/"]
            .iter()
            .any(|prefix| p.starts_with(prefix))
        || p == "/auth/login"
        || crate::dashboard::PAGES.contains(&p.as_str())
    {
        return Err(format!(
            "dashboard.oidc.redirect_path '{p}' must be a path of its own, such as /auth/callback"
        ));
    }
    if o.admin_groups.is_empty() && o.approver_groups.is_empty() && o.viewer_groups.is_empty() {
        return Err(
            "dashboard.oidc maps no groups to a role, so nobody could sign in: set admin_groups, approver_groups or viewer_groups".into(),
        );
    }
    if o.groups_claim.is_empty() {
        return Err("dashboard.oidc.groups_claim is empty".into());
    }
    if !o.scopes().iter().any(|s| s == "openid") {
        return Err("dashboard.oidc.scopes must include openid".into());
    }
    if !config.dashboard.public_url.starts_with("https://")
        && !is_loopback_url(&config.dashboard.public_url)
    {
        eprintln!(
            "ariodb: warning: single sign-on with dashboard.public_url {} sends session cookies without Secure; use https",
            config.dashboard.public_url
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ID tokens

/// Signature algorithms accepted on ID tokens: public-key ones only, so
/// never `none` and never an HMAC keyed with a public key.
const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Clock difference tolerated on `exp`, `nbf` and `iat`, in seconds.
const LEEWAY: u64 = 60;

/// What an ID token must say to be accepted.
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
}

#[derive(Debug, PartialEq)]
pub enum TokenError {
    /// No key in the set has the token's key id: fetch the keys again.
    UnknownKey(String),
    Invalid(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TokenError::UnknownKey(kid) => write!(f, "no signing key with id '{kid}'"),
            TokenError::Invalid(why) => write!(f, "{why}"),
        }
    }
}

fn invalid(why: impl Into<String>) -> TokenError {
    TokenError::Invalid(why.into())
}

/// Check an ID token against the provider's keys and return its claims.
pub fn validate_id_token(
    token: &str,
    keys: &JwkSet,
    expected: &Expected,
) -> Result<serde_json::Map<String, Value>, TokenError> {
    // The header is read by hand first, so `none` and HMAC get a clear
    // answer rather than a parse error.
    let header_part = token.split('.').next().unwrap_or("");
    let header: Value = B64URL
        .decode(header_part)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| invalid("the ID token is not a JWT"))?;
    let alg_name = header["alg"].as_str().unwrap_or("");
    let alg = alg_name
        .parse::<Algorithm>()
        .ok()
        .filter(|a| ALLOWED_ALGS.contains(a))
        .ok_or_else(|| invalid(format!("ID token algorithm '{alg_name}' is not allowed")))?;
    let kid = header["kid"].as_str();
    let family_matches = |p: &AlgorithmParameters| {
        matches!(
            (p, alg.family()),
            (
                AlgorithmParameters::RSA(_),
                jsonwebtoken::AlgorithmFamily::Rsa
            ) | (
                AlgorithmParameters::EllipticCurve(_),
                jsonwebtoken::AlgorithmFamily::Ec
            ) | (
                AlgorithmParameters::OctetKeyPair(_),
                jsonwebtoken::AlgorithmFamily::Ed
            )
        )
    };
    let usable = |k: &&jsonwebtoken::jwk::Jwk| {
        family_matches(&k.algorithm)
            && !matches!(&k.common.public_key_use, Some(u) if *u != PublicKeyUse::Signature)
            && k.common
                .key_algorithm
                .is_none_or(|ka| key_algorithm_is(ka, alg))
    };
    let jwk = match kid {
        Some(kid) => {
            let found = keys
                .keys
                .iter()
                .find(|k| k.common.key_id.as_deref() == Some(kid))
                .ok_or_else(|| TokenError::UnknownKey(kid.to_string()))?;
            if !usable(&found) {
                return Err(invalid(format!(
                    "signing key '{kid}' does not fit algorithm {alg_name}"
                )));
            }
            found
        }
        None => {
            let mut candidates = keys.keys.iter().filter(usable);
            match (candidates.next(), candidates.next()) {
                (Some(k), None) => k,
                (None, _) => return Err(TokenError::UnknownKey(String::new())),
                _ => {
                    return Err(invalid(
                        "the ID token names no key id and the provider has several keys",
                    ));
                }
            }
        }
    };
    let key = DecodingKey::from_jwk(jwk).map_err(|e| invalid(format!("signing key: {e}")))?;
    let mut validation = Validation::new(alg);
    validation.leeway = LEEWAY;
    validation.validate_nbf = true;
    validation.set_issuer(&[expected.issuer]);
    validation.set_audience(&[expected.client_id]);
    validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
    let data = jsonwebtoken::decode::<serde_json::Map<String, Value>>(token, &key, &validation)
        .map_err(|e| {
            use jsonwebtoken::errors::ErrorKind::*;
            invalid(match e.kind() {
                ExpiredSignature => "the ID token has expired".to_string(),
                ImmatureSignature => "the ID token is not valid yet".to_string(),
                InvalidIssuer => "the ID token is from another issuer".to_string(),
                InvalidAudience => "the ID token is for another client".to_string(),
                InvalidSignature => "the ID token's signature is wrong".to_string(),
                MissingRequiredClaim(c) => format!("the ID token has no '{c}' claim"),
                _ => format!("the ID token is not valid: {e}"),
            })
        })?;
    let claims = data.claims;
    let now = jsonwebtoken::get_current_timestamp();
    if claims
        .get("iat")
        .and_then(Value::as_u64)
        .is_some_and(|iat| iat > now + LEEWAY)
    {
        return Err(invalid("the ID token was issued in the future"));
    }
    let nonce = claims.get("nonce").and_then(Value::as_str).unwrap_or("");
    if nonce.is_empty() || !crate::dashboard::constant_eq(nonce, expected.nonce) {
        return Err(invalid("the ID token's nonce does not match this sign-in"));
    }
    // With several audiences, the token must say it was issued to us.
    let several = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|a| a.len() > 1);
    match claims.get("azp").and_then(Value::as_str) {
        Some(azp) if azp != expected.client_id => {
            return Err(invalid("the ID token was issued to another client"));
        }
        None if several => {
            return Err(invalid(
                "the ID token has several audiences and no authorised party",
            ));
        }
        _ => {}
    }
    Ok(claims)
}

fn key_algorithm_is(ka: KeyAlgorithm, alg: Algorithm) -> bool {
    ka == KeyAlgorithm::from(alg)
}

/// Who an ID token says someone is.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub subject: String,
    /// The name shown and recorded as the decider: a verified email, the
    /// preferred user name, or the subject.
    pub name: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub groups: Vec<String>,
    /// Whether the token had the groups claim at all. Some providers leave
    /// it out for someone in no group; others when no mapper adds it.
    pub groups_claimed: bool,
}

pub fn identity(
    o: &OidcConfig,
    claims: &serde_json::Map<String, Value>,
) -> Result<Identity, String> {
    let text = |k: &str| {
        claims
            .get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(clean)
    };
    let subject = text("sub").ok_or("the ID token has no subject")?;
    let email = text("email");
    let email_verified = claims.get("email_verified").and_then(Value::as_bool);
    let mut groups_value = claims.get(o.groups_claim.split('.').next().unwrap_or(""));
    for part in o.groups_claim.split('.').skip(1) {
        groups_value = groups_value.and_then(|v| v.get(part));
    }
    let groups: Vec<String> = match groups_value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(clean)
            .collect(),
        Some(Value::String(one)) => vec![clean(one)],
        _ => Vec::new(),
    };
    let trusted_email = email.clone().filter(|_| email_verified != Some(false));
    let name = trusted_email
        .or_else(|| text("preferred_username"))
        .unwrap_or_else(|| subject.clone());
    Ok(Identity {
        subject,
        name,
        email,
        email_verified,
        groups_claimed: groups_value.is_some(),
        groups,
    })
}

/// Text from the provider, without control characters, kept short.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(256).collect()
}

/// Is this email in one of the allowed domains (when any are set)?
pub fn email_allowed(o: &OidcConfig, email: Option<&str>) -> bool {
    if o.allowed_email_domains.is_empty() {
        return true;
    }
    let domain = email.and_then(|e| e.rsplit_once('@')).map(|(_, d)| d);
    domain.is_some_and(|d| {
        o.allowed_email_domains
            .iter()
            .any(|a| a.eq_ignore_ascii_case(d))
    })
}

/// May this person use the dashboard, and as what?
pub fn admit(o: &OidcConfig, who: &Identity) -> Result<Role, String> {
    if !o.allowed_email_domains.is_empty() {
        let email = who
            .email
            .as_deref()
            .filter(|_| who.email_verified != Some(false))
            .ok_or("this dashboard needs a verified email address, and the provider sent none")?;
        if !email_allowed(o, Some(email)) {
            return Err(format!(
                "{email} is not in a domain allowed to use this dashboard"
            ));
        }
    }
    o.role_for(&who.groups).ok_or_else(|| {
        let hint = if who.groups_claimed {
            String::new()
        } else {
            format!(
                " (the ID token has no '{}' claim: the provider must put groups in it)",
                o.groups_claim
            )
        };
        format!(
            "{} is not in any group that may use this dashboard{hint}",
            who.name
        )
    })
}

// ---------------------------------------------------------------------------
// The provider: discovery document and keys, cached

#[derive(Debug, Clone, Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

struct Provider {
    /// The configured issuer this was fetched for.
    configured: String,
    fetched: Instant,
    meta: Metadata,
    keys: JwkSet,
    keys_fetched: Instant,
}

/// How long a discovery document and key set are used before fetching
/// them again.
const REFRESH: Duration = Duration::from_secs(3600);
/// An unknown key id fetches the keys again, but not more often than this.
const KEY_REFETCH_GAP: Duration = Duration::from_secs(10);

static PROVIDER: tokio::sync::Mutex<Option<Provider>> = tokio::sync::Mutex::const_new(None);

fn http() -> reqwest::Client {
    crate::tls::init();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client")
}

async fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    let resp = http()
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("{url} answered {}", resp.status()));
    }
    resp.json().await.map_err(|e| format!("{url}: {e}"))
}

async fn fetch(o: &OidcConfig) -> Result<Provider, String> {
    let issuer = o.issuer.trim_end_matches('/');
    let meta: Metadata = get_json(&format!("{issuer}/.well-known/openid-configuration")).await?;
    if meta.issuer.trim_end_matches('/') != issuer {
        return Err(format!(
            "the provider calls itself {}, not {issuer}",
            meta.issuer
        ));
    }
    let keys = get_json(&meta.jwks_uri).await?;
    Ok(Provider {
        configured: o.issuer.clone(),
        fetched: Instant::now(),
        meta,
        keys,
        keys_fetched: Instant::now(),
    })
}

/// The provider's metadata, from the cache when fresh.
async fn metadata(o: &OidcConfig) -> Result<Metadata, String> {
    let mut cache = PROVIDER.lock().await;
    if let Some(p) = cache.as_ref()
        && p.configured == o.issuer
        && p.fetched.elapsed() < REFRESH
    {
        return Ok(p.meta.clone());
    }
    let p = fetch(o).await?;
    let meta = p.meta.clone();
    *cache = Some(p);
    Ok(meta)
}

/// Validate an ID token with the cached keys, fetching them again once if
/// the token names a key the cache does not have (the provider rotated).
async fn check_token(
    o: &OidcConfig,
    token: &str,
    nonce: &str,
) -> Result<serde_json::Map<String, Value>, String> {
    let mut cache = PROVIDER.lock().await;
    if cache
        .as_ref()
        .is_none_or(|p| p.configured != o.issuer || p.fetched.elapsed() >= REFRESH)
    {
        *cache = Some(fetch(o).await?);
    }
    let p = cache.as_mut().expect("provider fetched");
    let expected = Expected {
        issuer: &p.meta.issuer,
        client_id: &o.client_id,
        nonce,
    };
    match validate_id_token(token, &p.keys, &expected) {
        Err(TokenError::UnknownKey(_)) if p.keys_fetched.elapsed() >= KEY_REFETCH_GAP => {
            p.keys = get_json(&p.meta.jwks_uri).await?;
            p.keys_fetched = Instant::now();
            validate_id_token(token, &p.keys, &expected).map_err(|e| e.to_string())
        }
        other => other.map_err(|e| e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// The browser flow

/// A sign-in that has gone to the provider and not come back yet.
struct Pending {
    created: Instant,
    /// SHA-256 of the value in this browser's sign-in cookie, so a
    /// callback only completes in the browser that started it.
    binding: String,
    nonce: String,
    verifier: String,
    next: String,
}

const PENDING_FOR: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 10_000;
const LOGIN_COOKIE: &str = "ariodb_sso";

static PENDING: Mutex<Option<HashMap<String, Pending>>> = Mutex::new(None);

fn random_token() -> String {
    B64URL.encode(rand::random::<[u8; 32]>())
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// Where to go after signing in: a path on this dashboard, never another site.
pub fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n)
            if n.starts_with('/')
                && !n.starts_with("//")
                && !n.contains('\\')
                && !n.chars().any(char::is_control) =>
        {
            n.to_string()
        }
        _ => "/".to_string(),
    }
}

/// `/auth/login?next=...`: send the browser to the provider.
pub async fn login(
    AxState(state): AxState<std::sync::Arc<State>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let config = state.config();
    let Some(o) = config.dashboard.oidc.clone() else {
        return error_page(StatusCode::NOT_FOUND, "Single sign-on is not configured.");
    };
    let meta = match metadata(&o).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ariodb: single sign-on: {e}");
            return error_page(
                StatusCode::BAD_GATEWAY,
                &format!("ariodb cannot reach {} at the moment.", o.provider_name),
            );
        }
    };
    let state_param = random_token();
    let binding = random_token();
    let nonce = random_token();
    let verifier = random_token();
    let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
    {
        let mut pending = PENDING.lock().expect("pending sign-ins");
        let map = pending.get_or_insert_with(HashMap::new);
        map.retain(|_, p| p.created.elapsed() < PENDING_FOR);
        // Past the cap the oldest sign-in is dropped, so a flood of
        // unfinished sign-ins slows people down rather than locking them out.
        if map.len() >= MAX_PENDING
            && let Some(oldest) = map
                .iter()
                .min_by_key(|(_, p)| p.created)
                .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
        map.insert(
            state_param.clone(),
            Pending {
                created: Instant::now(),
                binding: sha256_hex(&binding),
                nonce: nonce.clone(),
                verifier,
                next: safe_next(q.get("next").map(String::as_str)),
            },
        );
    }
    let mut url = meta.authorization_endpoint.clone();
    url.push(if url.contains('?') { '&' } else { '?' });
    url.push_str(
        &form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", &o.client_id)
            .append_pair("redirect_uri", &redirect_uri(&config, &o))
            .append_pair("scope", &o.scopes().join(" "))
            .append_pair("state", &state_param)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .finish(),
    );
    // Lax, not Strict: the provider's redirect back is a cross-site
    // navigation, and this cookie must come with it.
    let cookie = format!(
        "{LOGIN_COOKIE}={binding}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}{}",
        PENDING_FOR.as_secs(),
        crate::dashboard::secure_flag(&config)
    );
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, url),
            (header::SET_COOKIE, cookie),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response()
}

fn redirect_uri(config: &Config, o: &OidcConfig) -> String {
    format!(
        "{}{}",
        config.dashboard.public_url.trim_end_matches('/'),
        o.redirect_path
    )
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

/// The provider's redirect back, at `redirect_path`.
pub async fn callback(state: &State, headers: &HeaderMap, query: &str) -> Response {
    let config = state.config();
    let Some(o) = config.dashboard.oidc.clone() else {
        return error_page(StatusCode::NOT_FOUND, "Single sign-on is not configured.");
    };
    let q: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let clear = format!("{LOGIN_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    let refuse = |status: StatusCode, msg: &str| {
        let mut r = error_page(status, msg);
        if let Ok(v) = clear.parse() {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
        r
    };
    let pending = q.get("state").and_then(|s| {
        PENDING
            .lock()
            .expect("pending sign-ins")
            .as_mut()
            .and_then(|m| m.remove(s))
    });
    let Some(pending) = pending.filter(|p| p.created.elapsed() < PENDING_FOR) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "This sign-in has expired or was already used. Start again.",
        );
    };
    let binding = crate::dashboard::cookie_value(headers, LOGIN_COOKIE).unwrap_or_default();
    if !crate::dashboard::constant_eq(&sha256_hex(&binding), &pending.binding) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "This sign-in was started in another browser. Start again here.",
        );
    }
    if let Some(err) = q.get("error") {
        let detail = q.get("error_description").unwrap_or(err);
        return refuse(
            StatusCode::FORBIDDEN,
            &format!("{} refused the sign-in: {}", o.provider_name, clean(detail)),
        );
    }
    let Some(code) = q.get("code") else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "The provider sent no authorisation code.",
        );
    };
    let claims = match exchange(&config, &o, code, &pending).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ariodb: single sign-on refused: {e}");
            return refuse(
                StatusCode::FORBIDDEN,
                &format!("Sign-in with {} failed: {e}", o.provider_name),
            );
        }
    };
    let who = match identity(&o, &claims) {
        Ok(w) => w,
        Err(e) => return refuse(StatusCode::FORBIDDEN, &e),
    };
    let role = match admit(&o, &who) {
        Ok(r) => r,
        Err(e) => {
            println!("ariodb: single sign-on refused {}: {e}", who.name);
            return refuse(StatusCode::FORBIDDEN, &e);
        }
    };
    let cookie = match crate::dashboard::new_session(state, &who.name, Some(&who)) {
        Ok((cookie, _)) => cookie,
        Err(e) => return refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    println!(
        "ariodb: {} signed in to the dashboard with {} as {}",
        who.name,
        o.provider_name,
        role.as_str()
    );
    let mut r = (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, pending.next),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response();
    for c in [cookie, clear] {
        if let Ok(v) = c.parse() {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

/// Trade the code for tokens and check the ID token.
async fn exchange(
    config: &Config,
    o: &OidcConfig,
    code: &str,
    pending: &Pending,
) -> Result<serde_json::Map<String, Value>, String> {
    let meta = metadata(o).await?;
    let secret = if o.client_secret_env.is_some() || o.client_secret_secret.is_some() {
        Some(crate::approvals::secret_value(
            config,
            &o.client_secret_secret,
            &o.client_secret_env,
        )?)
    } else {
        None
    };
    let redirect = redirect_uri(config, o);
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect.as_str()),
        ("code_verifier", pending.verifier.as_str()),
        ("client_id", o.client_id.as_str()),
    ];
    let mut req = http().post(&meta.token_endpoint);
    if let Some(secret) = &secret {
        let methods = &meta.token_endpoint_auth_methods_supported;
        if methods.is_empty() || methods.iter().any(|m| m == "client_secret_basic") {
            // RFC 6749 says the id and secret are form-encoded before Basic.
            let enc = |s: &str| form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            req = req.basic_auth(enc(&o.client_id), Some(enc(secret)));
        } else {
            form.push(("client_secret", secret.as_str()));
        }
    }
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let resp = req
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("token endpoint: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let why = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v["error"].as_str().map(clean))
            .unwrap_or_default();
        return Err(format!("the token endpoint answered {status} {why}"));
    }
    let tokens: TokenResponse =
        serde_json::from_str(&text).map_err(|e| format!("token endpoint: {e}"))?;
    let id_token = tokens.id_token.ok_or("the provider sent no ID token")?;
    check_token(o, &id_token, &pending.nonce).await
}

/// Where to send the browser to end the provider's session too, if asked.
pub async fn logout_url(config: &Config) -> Option<String> {
    let o = config.dashboard.oidc.as_ref()?;
    if !o.logout_at_provider {
        return None;
    }
    let end = metadata(o).await.ok()?.end_session_endpoint?;
    let mut url = end;
    url.push(if url.contains('?') { '&' } else { '?' });
    url.push_str(
        &form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &o.client_id)
            .append_pair(
                "post_logout_redirect_uri",
                &format!("{}/", config.dashboard.public_url.trim_end_matches('/')),
            )
            .finish(),
    );
    Some(url)
}

fn error_page(status: StatusCode, message: &str) -> Response {
    hook_page(
        status,
        format!(
            "<h1>Sign-in</h1><p>{}</p><p><a href=\"/\">Back to the dashboard</a></p>",
            html_escape(message)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair};
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    const ISSUER: &str = "https://login.example.test/realms/ops";
    const CLIENT: &str = "ariodb";
    const NONCE: &str = "nonce-local-test-only";

    struct Key {
        enc: EncodingKey,
        jwk: Jwk,
        alg: Algorithm,
    }

    fn ec_key(kid: &str) -> Key {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let enc = EncodingKey::from_ec_der(pair.to_pkcs8v1().unwrap().as_ref());
        let mut jwk = Jwk::from_encoding_key(&enc, Algorithm::ES256).unwrap();
        jwk.common.key_id = Some(kid.into());
        Key {
            enc,
            jwk,
            alg: Algorithm::ES256,
        }
    }

    fn ed_key(kid: &str) -> Key {
        let pair = Ed25519KeyPair::generate().unwrap();
        let enc = EncodingKey::from_ed_der(pair.to_pkcs8v1().unwrap().as_ref());
        let mut jwk = Jwk::from_encoding_key(&enc, Algorithm::EdDSA).unwrap();
        jwk.common.key_id = Some(kid.into());
        Key {
            enc,
            jwk,
            alg: Algorithm::EdDSA,
        }
    }

    fn now() -> u64 {
        jsonwebtoken::get_current_timestamp()
    }

    fn claims() -> Value {
        json!({
            "iss": ISSUER,
            "aud": CLIENT,
            "sub": "user-1",
            "iat": now(),
            "exp": now() + 300,
            "nonce": NONCE,
            "email": "pat@example.test",
            "email_verified": true,
            "groups": ["ariodb-approvers"],
        })
    }

    fn sign(key: &Key, kid: Option<&str>, claims: &Value) -> String {
        let mut h = Header::new(key.alg);
        h.kid = kid.map(str::to_string);
        encode(&h, claims, &key.enc).unwrap()
    }

    fn set(keys: &[&Key]) -> JwkSet {
        JwkSet {
            keys: keys.iter().map(|k| k.jwk.clone()).collect(),
        }
    }

    fn check(token: &str, keys: &JwkSet) -> Result<serde_json::Map<String, Value>, TokenError> {
        validate_id_token(
            token,
            keys,
            &Expected {
                issuer: ISSUER,
                client_id: CLIENT,
                nonce: NONCE,
            },
        )
    }

    fn refused(token: &str, keys: &JwkSet, why: &str) {
        match check(token, keys) {
            Err(TokenError::Invalid(e)) => assert!(e.contains(why), "{e} does not say {why}"),
            other => panic!("expected a refusal saying {why}, got {other:?}"),
        }
    }

    fn with(change: impl FnOnce(&mut Value)) -> Value {
        let mut c = claims();
        change(&mut c);
        c
    }

    #[test]
    fn a_good_token_is_accepted() {
        let k = ec_key("k1");
        let e = ed_key("k2");
        let keys = set(&[&k, &e]);
        let c = check(&sign(&k, Some("k1"), &claims()), &keys).unwrap();
        assert_eq!(c["sub"], "user-1");
        assert!(check(&sign(&e, Some("k2"), &claims()), &keys).is_ok());
        // With one key, a token may leave out the key id.
        assert!(check(&sign(&k, None, &claims()), &set(&[&k])).is_ok());
    }

    #[test]
    fn wrong_issuer_audience_or_nonce_is_refused() {
        let k = ec_key("k1");
        let keys = set(&[&k]);
        let t = |c: Value| sign(&k, Some("k1"), &c);
        refused(
            &t(with(|c| c["iss"] = json!("https://evil.example.test"))),
            &keys,
            "another issuer",
        );
        refused(
            &t(with(|c| c["aud"] = json!("someone-else"))),
            &keys,
            "another client",
        );
        refused(
            &t(with(|c| c["nonce"] = json!("replayed"))),
            &keys,
            "nonce",
        );
        refused(
            &t(with(|c| {
                c.as_object_mut().unwrap().remove("nonce");
            })),
            &keys,
            "nonce",
        );
        refused(
            &t(with(|c| c["aud"] = json!([CLIENT, "other"]))),
            &keys,
            "authorised party",
        );
        refused(
            &t(with(|c| {
                c["aud"] = json!([CLIENT, "other"]);
                c["azp"] = json!("other");
            })),
            &keys,
            "another client",
        );
        assert!(
            check(
                &t(with(|c| {
                    c["aud"] = json!([CLIENT, "other"]);
                    c["azp"] = json!(CLIENT);
                })),
                &keys
            )
            .is_ok()
        );
    }

    #[test]
    fn expiry_has_a_small_leeway() {
        let k = ec_key("k1");
        let keys = set(&[&k]);
        let t = |c: Value| sign(&k, Some("k1"), &c);
        refused(
            &t(with(|c| c["exp"] = json!(now() - 3600))),
            &keys,
            "expired",
        );
        assert!(check(&t(with(|c| c["exp"] = json!(now() - 10))), &keys).is_ok());
        refused(
            &t(with(|c| c["iat"] = json!(now() + 3600))),
            &keys,
            "future",
        );
        refused(
            &t(with(|c| {
                c.as_object_mut().unwrap().remove("exp");
            })),
            &keys,
            "'exp'",
        );
    }

    #[test]
    fn a_bad_signature_is_refused() {
        let k = ec_key("k1");
        let impostor = ec_key("k1");
        refused(
            &sign(&impostor, Some("k1"), &claims()),
            &set(&[&k]),
            "signature",
        );
        // A token edited after signing.
        let token = sign(&k, Some("k1"), &claims());
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let mut body: Value = serde_json::from_slice(&B64URL.decode(&parts[1]).unwrap()).unwrap();
        body["groups"] = json!(["ariodb-admins"]);
        parts[1] = B64URL.encode(body.to_string());
        refused(&parts.join("."), &set(&[&k]), "signature");
    }

    #[test]
    fn alg_none_and_hmac_are_refused() {
        let k = ec_key("k1");
        let keys = set(&[&k]);
        let b64 = |v: Value| B64URL.encode(v.to_string());
        let none = format!(
            "{}.{}.",
            b64(json!({"alg": "none", "kid": "k1"})),
            b64(claims())
        );
        refused(&none, &keys, "'none' is not allowed");
        // HS256 keyed with the provider's public key, which anyone can read.
        let AlgorithmParameters::EllipticCurve(ec) = &k.jwk.algorithm else {
            panic!("an EC key");
        };
        let mut h = Header::new(Algorithm::HS256);
        h.kid = Some("k1".into());
        let hs = encode(&h, &claims(), &EncodingKey::from_secret(ec.x.as_bytes())).unwrap();
        refused(&hs, &keys, "'HS256' is not allowed");
        // An algorithm that does not fit the key.
        let e = ed_key("k1");
        refused(&sign(&e, Some("k1"), &claims()), &keys, "does not fit");
    }

    #[test]
    fn an_unknown_key_asks_for_the_keys_again() {
        let k = ec_key("k1");
        let rotated = ec_key("k2");
        assert_eq!(
            check(&sign(&rotated, Some("k2"), &claims()), &set(&[&k])),
            Err(TokenError::UnknownKey("k2".into()))
        );
        assert!(check(&sign(&rotated, Some("k2"), &claims()), &set(&[&k, &rotated])).is_ok());
        refused(
            &sign(&k, None, &claims()),
            &set(&[&k, &rotated]),
            "several keys",
        );
    }

    fn config() -> OidcConfig {
        toml::from_str(
            r#"
issuer = "https://login.example.test/realms/ops"
client_id = "ariodb"
admin_groups = ["ariodb-admins"]
approver_groups = ["ariodb-approvers", "dba"]
viewer_groups = ["ariodb-viewers"]
"#,
        )
        .unwrap()
    }

    fn map(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn groups_map_to_the_highest_role() {
        let o = config();
        let groups = |g: &[&str]| g.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(o.role_for(&groups(&["ariodb-viewers"])), Some(Role::Viewer));
        assert_eq!(
            o.role_for(&groups(&["ariodb-viewers", "dba"])),
            Some(Role::Approver)
        );
        assert_eq!(
            o.role_for(&groups(&["dba", "ariodb-admins"])),
            Some(Role::Admin)
        );
        assert_eq!(o.role_for(&groups(&["everyone"])), None);
        assert_eq!(o.role_for(&[]), None);
        assert!(o.scopes().contains(&"groups".to_string()));
    }

    #[test]
    fn missing_groups_mean_no_access() {
        let o = config();
        let mut c = claims();
        c.as_object_mut().unwrap().remove("groups");
        let who = identity(&o, &map(c)).unwrap();
        assert!(who.groups.is_empty());
        let refused = admit(&o, &who).unwrap_err();
        assert!(refused.contains("not in any group"), "{refused}");
        assert!(refused.contains("no 'groups' claim"), "{refused}");
        let who = identity(&o, &map(with(|c| c["groups"] = json!(["everyone"])))).unwrap();
        assert!(admit(&o, &who).unwrap_err().contains("not in any group"));
        let who = identity(&o, &map(claims())).unwrap();
        assert_eq!(admit(&o, &who), Ok(Role::Approver));
        assert_eq!(who.name, "pat@example.test");
    }

    #[test]
    fn nested_group_claims_and_unverified_emails() {
        let mut o = config();
        o.groups_claim = "realm_access.roles".into();
        let who = identity(
            &o,
            &map(with(|c| {
                c["realm_access"] = json!({ "roles": ["ariodb-admins"] });
                c["email_verified"] = json!(false);
                c["preferred_username"] = json!("pat");
            })),
        )
        .unwrap();
        assert_eq!(who.groups, vec!["ariodb-admins"]);
        // An unverified email is not used as the name people see.
        assert_eq!(who.name, "pat");
        o.allowed_email_domains = vec!["example.test".into()];
        assert!(admit(&o, &who).unwrap_err().contains("verified email"));
    }

    #[test]
    fn email_domains_limit_who_gets_in() {
        let mut o = config();
        o.allowed_email_domains = vec!["Example.test".into()];
        let ok = identity(&o, &map(claims())).unwrap();
        assert_eq!(admit(&o, &ok), Ok(Role::Approver));
        let other = identity(
            &o,
            &map(with(|c| c["email"] = json!("pat@elsewhere.test"))),
        )
        .unwrap();
        assert!(admit(&o, &other).unwrap_err().contains("not in a domain"));
    }

    #[test]
    fn next_stays_on_this_site() {
        assert_eq!(safe_next(Some("/approvals")), "/approvals");
        assert_eq!(
            safe_next(Some("/hooks/approvals/a-1?verdict=allow&token=x")),
            "/hooks/approvals/a-1?verdict=allow&token=x"
        );
        for bad in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "/a\nb",
            "",
        ] {
            assert_eq!(safe_next(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn config_checks() {
        let base = r#"
[database]
url = "postgres://localhost:5432/app"

[dashboard.oidc]
issuer = "ISSUER"
client_id = "ariodb"
redirect_path = "PATH"
admin_groups = ["ariodb-admins"]
"#;
        let load = |issuer: &str, path: &str| {
            Config::from_toml(&base.replace("ISSUER", issuer).replace("PATH", path))
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        assert!(load("https://login.example.test", "/auth/callback").is_ok());
        assert!(load("http://127.0.0.1:8180/realms/x", "/auth/callback").is_ok());
        assert!(load("http://login.example.test", "/auth/callback").is_err());
        assert!(load("http://localhost.evil.example", "/auth/callback").is_err());
        assert!(load("http://127.evil.example", "/auth/callback").is_err());
        assert!(load("http://127.0.0.1@evil.example", "/auth/callback").is_err());
        let typo = base
            .replace("ISSUER", "https://login.example.test")
            .replace("PATH", "/cb")
            + "pasword_login = \"off\"\n";
        assert!(Config::from_toml(&typo).is_err());
        for path in ["/api/callback", "/", "auth", "/approvals", "/auth/login"] {
            assert!(load("https://login.example.test", path).is_err(), "{path}");
        }
        let no_groups = base
            .replace("ISSUER", "https://login.example.test")
            .replace("PATH", "/cb")
            .replace("admin_groups = [\"ariodb-admins\"]", "");
        assert!(
            Config::from_toml(&no_groups)
                .unwrap_err()
                .to_string()
                .contains("nobody could sign in")
        );
        let grouped = "[database]\nurl = \"postgres://localhost:5432/app\"\n\n[[approvers]]\nname = \"ops\"\ntype = \"dashboard\"\ngroups = [\"dba\"]\n";
        assert!(
            Config::from_toml(grouped)
                .unwrap_err()
                .to_string()
                .contains("need [dashboard.oidc]")
        );
    }
}
