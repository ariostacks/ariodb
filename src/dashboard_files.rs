//! The dashboard's web page: the React app under `dashboard/`, built to
//! `dashboard/dist` and embedded in the binary so ariodb still ships as one
//! file. `cargo build` needs no Node; `scripts/build-dashboard.sh` rebuilds
//! the files after a front-end change.
//!
//! Every path that is not an API, a hook or a file is a page of the app, so
//! it gets index.html and the app's router takes over.

use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;
use serde_json::json;

#[derive(RustEmbed)]
#[folder = "dashboard/dist/"]
struct Files;

/// No inline script anywhere, so scripts come only from this origin.
/// Styles still allow 'unsafe-inline': Radix dialogs and the toast library
/// add small `<style>` elements at run time. Nothing is loaded from
/// elsewhere, and the page may not be framed.
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; \
form-action 'self'; frame-ancestors 'none'";

/// Built file names under assets/ carry a content hash, so they never change
/// and browsers may keep them for good.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

pub async fn serve(method: Method, uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || path.starts_with("/hooks/") || path.starts_with("/slack/") {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(json!({ "error": "not found" })),
        )
            .into_response();
    }
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let name = path.trim_start_matches('/');
    if !name.is_empty()
        && name != "index.html"
        && let Some(file) = Files::get(name)
    {
        let cache = if name.starts_with("assets/") {
            IMMUTABLE
        } else {
            "public, max-age=3600"
        };
        return file_response(name, file.data.into_owned(), cache);
    }
    // A missing file (it has an extension) is a 404, not the app.
    let last = name.rsplit('/').next().unwrap_or("");
    if last.contains('.') && name != "index.html" {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    index()
}

fn index() -> Response {
    let Some(file) = Files::get("index.html") else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "the dashboard was built without its page; run scripts/build-dashboard.sh",
        )
            .into_response();
    };
    let mut res = file_response("index.html", file.data.into_owned(), "no-store");
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    res
}

fn file_response(name: &str, body: Vec<u8>, cache: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type(name)),
            (header::CACHE_CONTROL, cache),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_page_is_embedded_and_has_no_inline_script() {
        let page = Files::get("index.html").expect("dashboard/dist/index.html is embedded");
        let text = String::from_utf8_lossy(&page.data);
        assert!(text.contains("<div id=\"root\">"));
        // Every <script> must load a file: the CSP forbids inline ones.
        for part in text.split("<script").skip(1) {
            let tag = &part[..part.find('>').unwrap()];
            assert!(
                tag.contains("src=\"/assets/"),
                "inline script in index.html"
            );
        }
    }

    #[test]
    fn every_asset_the_page_names_is_embedded() {
        let page = Files::get("index.html").unwrap();
        let text = String::from_utf8_lossy(&page.data);
        for part in text.split("\"/assets/").skip(1) {
            let name = &part[..part.find('"').unwrap()];
            assert!(
                Files::get(&format!("assets/{name}")).is_some(),
                "assets/{name} is missing"
            );
        }
    }

    #[test]
    fn content_types() {
        assert_eq!(
            content_type("assets/index-abc.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type("assets/index-abc.css"),
            "text/css; charset=utf-8"
        );
        assert_eq!(content_type("assets/font.woff2"), "font/woff2");
        assert_eq!(content_type("favicon.svg"), "image/svg+xml");
    }
}
