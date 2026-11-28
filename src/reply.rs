//! JSON envelope used by the frontend: `{ code, message, data }`.

use crate::i18n;
use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

pub fn json_response(status: StatusCode, body: Value) -> Response {
    let text = serde_json::to_string(&body).unwrap_or_else(|_| "{\"code\":1}".to_string());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(text))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub fn ok(data: Value) -> Response {
    json_response(
        StatusCode::OK,
        json!({ "code": 0, "message": "success", "data": data }),
    )
}

pub fn fail(code: i64, message: &str, data: Value) -> Response {
    json_response(
        StatusCode::OK,
        json!({ "code": code, "message": i18n::translate(message), "data": data }),
    )
}

pub fn fail_status(status: StatusCode, code: i64, message: &str, data: Value) -> Response {
    let mut body = json!({ "code": code, "message": i18n::translate(message) });
    if !data.is_null() {
        body["data"] = data;
    }
    json_response(status, body)
}

pub fn fail_code(
    status: StatusCode,
    code: i64,
    slug: &str,
    message: &str,
    data: Value,
) -> Response {
    let localized = i18n::translate(message);
    let mut body = json!({
        "code": code,
        "message": localized,
        "error": { "code": slug, "message": localized }
    });
    if !data.is_null() {
        body["error"]["detail"] = data.clone();
        body["data"] = data;
    }
    json_response(status, body)
}

pub type ApiResult<T = Response> = Result<T, ApiError>;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: i64,
    pub message: String,
    pub data: Value,
}

impl ApiError {
    pub fn new(status: StatusCode, code: i64, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
            data: Value::Null,
        }
    }

    pub fn invalid_path() -> Self {
        ApiError::new(StatusCode::OK, 1, "Invalid path")
    }

    pub fn system_blocked_at(path: &str) -> Self {
        let mut data = serde_json::json!({ "system_access_required": true });
        if !path.is_empty() {
            data["path"] = serde_json::json!(path);
        }
        ApiError {
            status: StatusCode::FORBIDDEN,
            code: 1,
            message: "System folder operations are disabled".to_string(),
            data,
        }
    }

    pub fn is_system_access_required(&self) -> bool {
        self.data
            .get("system_access_required")
            .and_then(|value| value.as_bool())
            == Some(true)
    }

    pub fn into_response(self) -> Response {
        if self.status == StatusCode::OK {
            fail(self.code, &self.message, self.data)
        } else {
            fail_status(self.status, self.code, &self.message, self.data)
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        ApiError::into_response(self)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(value: std::io::Error) -> Self {
        ApiError::new(StatusCode::OK, 5, value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::ApiError;

    #[test]
    fn system_blocked_at_includes_path() {
        let error = ApiError::system_blocked_at("/etc");
        assert_eq!(error.data["system_access_required"], true);
        assert_eq!(error.data["path"], "/etc");
        let blank = ApiError::system_blocked_at("");
        assert_eq!(blank.data["system_access_required"], true);
        assert!(blank.data.get("path").is_none());
    }
}
