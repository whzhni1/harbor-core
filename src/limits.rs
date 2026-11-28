use crate::reply::fail_code;
use crate::state::AppState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyReadError {
    TooLarge,
    Invalid,
    TimedOut,
}

/// Read a request body with a strict streaming limit; callers choose their
/// own response wording while sharing the same size and error handling.
pub(crate) async fn read_body_limited(req: Request, limit: u64) -> Result<Vec<u8>, BodyReadError> {
    read_body_limited_with_idle(req, limit, None).await
}

pub(crate) async fn read_body_limited_with_idle(
    req: Request,
    limit: u64,
    idle: Option<std::time::Duration>,
) -> Result<Vec<u8>, BodyReadError> {
    use futures_util::StreamExt;
    let mut stream = req.into_body().into_data_stream();
    let mut out = Vec::new();
    loop {
        let next = match idle {
            Some(timeout) => tokio::time::timeout(timeout, stream.next())
                .await
                .map_err(|_| BodyReadError::TimedOut)?,
            None => stream.next().await,
        };
        let Some(chunk) = next else {
            break;
        };
        let bytes = chunk.map_err(|_| BodyReadError::Invalid)?;
        if (out.len() as u64).saturating_add(bytes.len() as u64) > limit {
            return Err(BodyReadError::TooLarge);
        }
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

pub struct Limits {
    pub connections: Arc<Semaphore>,
    pub transfers: Arc<Semaphore>,
}

impl Limits {
    pub fn new(max_connections: usize, max_transfers: usize) -> Limits {
        Limits {
            connections: Arc::new(Semaphore::new(max_connections.clamp(1, 512))),
            transfers: Arc::new(Semaphore::new(max_transfers.clamp(1, 64))),
        }
    }

    pub fn begin_transfer(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.transfers.clone().try_acquire_owned().ok()
    }
}

pub async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let permit = match state.limits.connections.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return fail_code(
                StatusCode::SERVICE_UNAVAILABLE,
                1,
                "queue_full",
                "Too many concurrent requests",
                serde_json::Value::Null,
            )
        }
    };
    let is_long_operation = request
        .uri()
        .query()
        .map(|query| {
            query
                .split('&')
                .any(|part| part == "mode=sha256" || part == "mode=search")
        })
        .unwrap_or(false);
    let timeout_seconds = if is_long_operation {
        state.settings.request_timeout.max(3600)
    } else {
        state.settings.request_timeout
    };
    let timeout = std::time::Duration::from_secs(timeout_seconds);
    let response = match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => fail_code(
            StatusCode::REQUEST_TIMEOUT,
            1,
            "request_timeout",
            "The request took too long",
            serde_json::Value::Null,
        ),
    };
    drop(permit);
    response
}

pub async fn session_refresh(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let renewal = if matches!(request.uri().path(), "/login" | "/logout") {
        None
    } else {
        renewal_cookie(&state, request.headers())
    };
    let mut response = next.run(request).await;
    if let Some((cookie, key)) = renewal {
        if response.status().is_success() && state.auth_key().as_deref() == Some(key.as_slice()) {
            if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
                response.headers_mut().append("set-cookie", value);
            }
        }
    }
    response
}

fn renewal_cookie(state: &AppState, headers: &axum::http::HeaderMap) -> Option<(String, Vec<u8>)> {
    if !state.settings.session_sliding || state.settings.session_idle <= 0 {
        return None;
    }
    let raw = headers.get("cookie").and_then(|v| v.to_str().ok());
    let token = crate::auth::cookie_value(raw, crate::auth::COOKIE_NAME)?;
    let key = state.auth_key()?;
    let now = crate::meta::now_secs();
    let payload = crate::auth::verify_token(&key, &token, now)?;
    let expiry = payload.get("exp").and_then(|v| v.as_i64())?;
    let sid = payload.get("sid").and_then(|v| v.as_str())?;
    let username = payload.get("username").and_then(|v| v.as_str())?;
    let perm = payload.get("perm").and_then(|v| v.as_str())?;
    if sid.is_empty() || username.is_empty() || perm != "session" || !state.sessions.touch(sid, now)
    {
        return None;
    }
    let remaining = expiry.saturating_sub(now);
    if remaining <= 0 {
        return None;
    }
    let max_age = remaining.min(state.settings.session_idle).max(1);
    Some((
        crate::auth::session_cookie(&token, max_age, state.settings.secure_cookie),
        key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn request_body_idle_timeout_and_byte_limit() {
        use axum::body::Body;
        let request = |body| Request::builder().body(body).unwrap();
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        let result = read_body_limited_with_idle(
            request(Body::from_stream(pending)),
            32,
            Some(std::time::Duration::from_millis(20)),
        )
        .await;
        assert_eq!(result, Err(BodyReadError::TimedOut));
        assert_eq!(
            read_body_limited(request(Body::from("abcd")), 3).await,
            Err(BodyReadError::TooLarge)
        );
    }

    #[test]
    fn clamps_connection_limits() {
        let limits = Limits::new(0, 0);
        assert_eq!(limits.connections.available_permits(), 1);
        assert_eq!(limits.transfers.available_permits(), 1);
        let wide = Limits::new(10_000, 10_000);
        assert_eq!(wide.connections.available_permits(), 512);
        assert_eq!(wide.transfers.available_permits(), 64);
    }
}
