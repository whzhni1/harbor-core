use axum::body::Body;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/assets_gen.rs"));

fn find(path: &str) -> Option<(&'static [u8], &'static str)> {
    let key = path.trim_start_matches('/');
    let key = key.strip_prefix("assets/").unwrap_or(key);
    ASSETS
        .iter()
        .find(|(name, _, _)| *name == key)
        .map(|(_, bytes, mime)| (*bytes, *mime))
}

fn mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=UTF-8",
        "js" => "application/javascript; charset=UTF-8",
        "css" => "text/css; charset=UTF-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=UTF-8",
        "map" => "application/json",
        _ => "application/octet-stream",
    }
}

static DEV_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_dev_mode(enabled: bool) {
    DEV_MODE.store(enabled, Ordering::Relaxed);
}

pub fn dev_mode() -> bool {
    DEV_MODE.load(Ordering::Relaxed)
}

const DEV_BADGE: &str = r#"<div style="position:fixed;bottom:12px;right:12px;z-index:2147483647;background:#e60012;color:#ffffff;font:700 14px/1.2 system-ui,sans-serif;letter-spacing:.1em;padding:9px 16px;border-radius:6px;box-shadow:0 2px 12px rgba(0,0,0,.5);pointer-events:none">DEV MODE</div>"#;

fn inject_dev_badge(bytes: Vec<u8>) -> Vec<u8> {
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let marked = match text.find("<body") {
        Some(index) => match text[index..].find('>') {
            Some(end) => {
                let pos = index + end + 1;
                format!("{}{}{}", &text[..pos], DEV_BADGE, &text[pos..])
            }
            None => format!("{DEV_BADGE}{text}"),
        },
        None => format!("{DEV_BADGE}{text}"),
    };
    marked.into_bytes()
}

fn maybe_inject_badge(bytes: Vec<u8>, path: &str) -> Vec<u8> {
    if dev_mode() && (path.ends_with("index.html") || path.ends_with("login.html")) {
        inject_dev_badge(bytes)
    } else {
        bytes
    }
}

async fn external_asset(path: &str) -> Option<(Vec<u8>, &'static str)> {
    if !dev_mode() {
        return None;
    }
    let key = path.trim_start_matches('/');
    let key = key.strip_prefix("assets/").unwrap_or(key);

    for candidate in ["./www/harbor-core/assets", "./assets"] {
        let Ok(base) = tokio::fs::canonicalize(candidate).await else {
            continue;
        };
        let Ok(target) = tokio::fs::canonicalize(base.join(key)).await else {
            continue;
        };
        if !target.starts_with(&base) {
            continue;
        }
        let Ok(bytes) = tokio::fs::read(&target).await else {
            continue;
        };
        return Some((substitute_asset_version(bytes, key), mime_for(key)));
    }
    None
}

fn substitute_asset_version(bytes: Vec<u8>, key: &str) -> Vec<u8> {
    if !(key.ends_with(".html") || key == "app-config.js") {
        return bytes;
    }
    static TAG: OnceLock<String> = OnceLock::new();
    let tag = TAG.get_or_init(|| UI_REV.to_string());
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let text = text
        .replace("__HARBOR_ASSET_VERSION__", tag)
        .replace("__HARBOR_PKG_VERSION__", env!("CARGO_PKG_VERSION"));
    if key == "index.html" && text.contains("__HARBOR_ICON_") {
        // Development mode serves templates from disk; icon data still comes
        // from the same driver embedded at build time.
        return crate::icons::render_template(&text)
            .unwrap_or(text)
            .into_bytes();
    }
    text.into_bytes()
}

static VERSION_TAG: OnceLock<String> = OnceLock::new();

fn version_tag() -> &'static str {
    VERSION_TAG.get_or_init(|| env!("CARGO_PKG_VERSION").to_string())
}

pub fn serve_bytes(
    headers: &HeaderMap,
    method: &Method,
    bytes: &[u8],
    mime: &'static str,
    cache: &str,
) -> Response {
    let bytes_len = bytes.len();
    let etag = format!("\"{}-{}\"", version_tag(), bytes_len);
    if let Some(inm) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if inm.split(',').any(|t| t.trim() == etag) {
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, etag)
                .header("X-Asset-Source", "embedded")
                .body(Body::empty())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    }
    if method == Method::HEAD {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, bytes.len().to_string())
            .header(header::ETAG, etag)
            .header(header::CACHE_CONTROL, cache)
            .header("X-Asset-Source", "embedded")
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, bytes_len.to_string())
        .header(header::ETAG, etag)
        .header(header::CACHE_CONTROL, cache)
        .header("X-Asset-Source", "embedded")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(bytes.to_vec()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub const IMMUTABLE: &str = "public, max-age=31536000, immutable, stale-while-revalidate=86400";

pub async fn serve_asset(headers: &HeaderMap, method: &Method, path: &str) -> Response {
    if let Some((bytes, mime)) = external_asset(path).await {
        let bytes = maybe_inject_badge(bytes, path);
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, bytes.len().to_string())
            .header(header::CACHE_CONTROL, "no-store")
            .header("X-Asset-Source", "external")
            .header("X-Content-Type-Options", "nosniff")
            .body(Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let (bytes, mime) = match find(path) {
        Some((bytes, mime)) => (bytes.to_vec(), mime),
        None => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let bytes = maybe_inject_badge(bytes, path);
    let cache = if path.ends_with("index.html") || path.ends_with("login.html") {
        "no-cache"
    } else {
        IMMUTABLE
    };
    serve_bytes(headers, method, &bytes, mime, cache)
}
