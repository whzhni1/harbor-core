//! HTTP surface: the `/api/v1/<name>` dispatcher that mirrors the LuCI endpoint names.

pub mod archops;
pub mod fsops;
pub mod pathops;
pub mod prefops;
pub mod secops;
pub mod textops;
pub mod transferops;
pub mod updateops;

use crate::params::{parse_form, Params};
use crate::reply::{fail, fail_status, json_response, ok};
use crate::state::{AppState, Ctx};
use axum::body::Body;
use axum::extract::State;
use axum::extract::{Path, Request};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;

const FORM_LIMIT: usize = 64 * 1024 * 1024;
const TEXT_SAVE_LIMIT: usize = 4 * 1024 * 1024;

fn public_router_response(name: &str, st: &AppState, headers: &HeaderMap) -> Option<Response> {
    if name == "auth_status" {
        let prefs = st.prefs();
        let login_wallpaper = if prefs.wallpaper_enabled != 0 && prefs.wallpaper_login_enabled != 0
        {
            crate::wallpapers::current(st, &prefs)
        } else {
            json!({ "enabled": false })
        };
        return Some(ok(json!({
            "mode": "password",
            "authenticated": crate::ioops::authorized(st, headers, &Params::default()),
            "needs_setup": st.password_hash().is_none(),
            "totp_enabled": crate::security::is_enabled(st),
            "login_wallpaper": login_wallpaper,
            "version": st.settings.version,
            "started": st.started
        })));
    }
    if name == "icons" {
        return Some(ok(crate::icons::manifest()));
    }
    if name == "i18n" {
        let lang = crate::i18n::current();
        let languages: Vec<serde_json::Value> = crate::i18n::available()
            .map(|(code, label)| json!({ "code": code, "label": label }))
            .collect();
        return Some(ok(json!({
            "lang": lang.code(),
            "configured": crate::config::configured_language(&st.settings.config_path),
            "languages": languages,
            "messages": crate::i18n::catalog_json(lang)
        })));
    }
    if name == "version" {
        return Some(ok(json!({
            "version": st.settings.version,
            "architecture": std::env::consts::ARCH,
            "build_target": env!("HARBOR_BUILD_TARGET"),
            "ui_rev": crate::web::UI_REV,
            "dev_mode": crate::web::dev_mode()
        })));
    }
    None
}

fn wants_html(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false)
}

fn unauthorized(headers: &axum::http::HeaderMap) -> Response {
    if wants_html(headers) {
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/login")
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    fail_status(
        StatusCode::UNAUTHORIZED,
        1,
        "Authentication required",
        serde_json::Value::Null,
    )
}

pub fn check_auth(st: &AppState, headers: &axum::http::HeaderMap, params: &Params) -> bool {
    crate::ioops::authorized(st, headers, params)
}

#[allow(clippy::result_large_err)]
fn require_query_auth(
    st: &AppState,
    headers: &axum::http::HeaderMap,
    query: &str,
) -> Result<Params, Response> {
    let params = Params::parse(query);
    if check_auth(st, headers, &params) {
        Ok(params)
    } else {
        Err(unauthorized(headers))
    }
}

#[allow(clippy::result_large_err)]
async fn acquire_editor_permit(
    st: &AppState,
) -> Result<tokio::sync::SemaphorePermit<'_>, Response> {
    st.editor_io.acquire().await.map_err(|_| {
        fail_status(
            StatusCode::SERVICE_UNAVAILABLE,
            1,
            "Text editor is busy",
            serde_json::Value::Null,
        )
    })
}

#[allow(clippy::result_large_err)]
async fn collect_body(req: Request, limit: usize) -> std::result::Result<Vec<u8>, Response> {
    crate::limits::read_body_limited(req, limit as u64)
        .await
        .map_err(|error| match error {
            crate::limits::BodyReadError::TooLarge => fail_status(
                StatusCode::PAYLOAD_TOO_LARGE,
                1,
                "Request body too large",
                serde_json::Value::Null,
            ),
            crate::limits::BodyReadError::Invalid => fail_status(
                StatusCode::BAD_REQUEST,
                1,
                "Invalid request body",
                serde_json::Value::Null,
            ),
            crate::limits::BodyReadError::TimedOut => fail_status(
                StatusCode::REQUEST_TIMEOUT,
                1,
                "Request body timed out",
                serde_json::Value::Null,
            ),
        })
}

fn query_of(uri: &Uri) -> String {
    uri.query().unwrap_or("").to_string()
}

pub async fn dispatch(
    State(st): State<Arc<AppState>>,
    Path(name): Path<String>,
    req: Request,
) -> Response {
    let lang = crate::i18n::lang_for(req.headers(), &Params::parse(&query_of(req.uri())));
    crate::i18n::scope(lang, dispatch_request(st, name, req)).await
}

async fn dispatch_request(st: Arc<AppState>, name: String, req: Request) -> Response {
    let uri = req.uri().clone();
    let method = req.method().clone();
    let headers = req.headers().clone();
    let query = query_of(&uri);

    if name == "service_info" {
        let policy = st.root_policy_config();
        return ok(json!({
            "version": st.settings.version,
            "root_policy": policy.policy.as_str(),
            "root_policy_cli_override": st.settings.root_policy_cli_override
        }));
    }

    if name == "language" {
        let params = Params::parse(&query);
        if method == Method::POST {
            if headers
                .get("x-harbor-language")
                .and_then(|v| v.to_str().ok())
                != Some("1")
            {
                return fail_status(
                    axum::http::StatusCode::BAD_REQUEST,
                    1,
                    "Missing language header",
                    serde_json::Value::Null,
                );
            }
            let raw = match params.first_of(&["lang", "locale"]) {
                Some(raw) => raw,
                None => {
                    return fail_status(
                        axum::http::StatusCode::BAD_REQUEST,
                        1,
                        "Language required",
                        serde_json::Value::Null,
                    )
                }
            };
            if raw.trim().eq_ignore_ascii_case("auto") {
                if let Err(error) =
                    crate::config::remove_option(&st.settings.config_path, "language")
                {
                    return fail_status(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        1,
                        &error,
                        serde_json::Value::Null,
                    );
                }
                return ok(
                    json!({ "lang": crate::config::configured_language(&st.settings.config_path) }),
                );
            }
            let lang = match crate::i18n::Lang::supported(&raw) {
                Some(lang) => lang,
                None => {
                    return fail_status(
                        axum::http::StatusCode::BAD_REQUEST,
                        1,
                        "Unsupported language",
                        serde_json::Value::Null,
                    )
                }
            };
            if let Err(error) =
                crate::config::save_option(&st.settings.config_path, "language", lang.code())
            {
                return fail_status(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    1,
                    &error,
                    serde_json::Value::Null,
                );
            }
            return ok(json!({ "lang": lang.code() }));
        }
        return ok(json!({ "lang": crate::config::configured_language(&st.settings.config_path) }));
    }

    if let Some(response) = public_router_response(&name, &st, &headers) {
        return response;
    }

    if name == "upload_chunk" || name == "wallpaper_upload" {
        if let Err(response) = require_query_auth(&st, &headers, &query) {
            return response;
        }
        return if name == "upload_chunk" {
            transferops::api_upload_chunk_stream(st, req).await
        } else {
            secops::api_wallpaper_upload(st, req).await
        };
    }
    if (name == "save_text" && is_multipart(&headers))
        || name == "upload"
        || name == "save_editor_upload"
    {
        let params = match require_query_auth(&st, &headers, &query) {
            Ok(params) => params,
            Err(response) => return response,
        };
        if name != "upload" {
            let _editor_permit = match acquire_editor_permit(&st).await {
                Ok(permit) => permit,
                Err(response) => return response,
            };
            return textops::api_save_editor_upload(st.clone(), params, headers, req).await;
        }
        if params.get("directory").as_deref() == Some("1") || !is_multipart(&headers) {
            return textops::handle_upload_directory(st.clone(), &params, &headers);
        }
        return textops::api_upload_multipart(st, params, req).await;
    }

    let _editor_permit = if name == "save_text" {
        match acquire_editor_permit(&st).await {
            Ok(permit) => Some(permit),
            Err(response) => return response,
        }
    } else {
        None
    };
    let body_limit = if name == "save_text" {
        TEXT_SAVE_LIMIT
    } else {
        FORM_LIMIT
    };
    let body = match collect_body(req, body_limit).await {
        Ok(b) => b,
        Err(response) => return response,
    };
    let mut params = Params::parse(&query);
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if method == Method::POST && content_type.contains("application/x-www-form-urlencoded") {
        match parse_form(&body, body_limit) {
            Some(form) => params.merge(form),
            None => {
                return fail_status(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    1,
                    "Request body too large",
                    serde_json::Value::Null,
                )
            }
        }
    }

    if !check_auth(&st, &headers, &params) {
        return unauthorized(&headers);
    }

    let ctx = Ctx {
        st: st.clone(),
        params: params.clone(),
        method: method.clone(),
        headers: headers.clone(),
    };

    if params.get("remote_action").is_some() || params.get("rpc_action").is_some() {
        let mut remote_params = params.clone();
        if let Some(session_id) = st.session_id(&headers) {
            remote_params.set("__system_session_id", &session_id);
        }
        if remote_params.get("remote_action").is_none() {
            remote_params.set("remote_action", "rpc");
        }
        return crate::remote::dispatch(&st, &remote_params, ctx.is_post()).await;
    }
    if params.get("_hf_device").is_some() {
        return fail(
            1,
            "Remote requests must use remote_action",
            serde_json::Value::Null,
        );
    }

    dispatch_endpoint(&name, &ctx).await
}

fn api_ssh_journal() -> Response {
    ok(serde_json::json!({
        "pool": crate::ssh::pool_snapshot(),
    }))
}

fn system_access_scope(ctx: &Ctx) -> Option<(String, String, String)> {
    let path = ctx.params.get("path").unwrap_or_default();
    let device_id = ctx.params.get("device_id").unwrap_or_default();
    if device_id.len() > 256 || device_id.chars().any(char::is_control) {
        return None;
    }
    let scope = if device_id.is_empty() {
        crate::paths::system_path_scope(&path).or_else(|| {
            crate::paths::canonical(&path)
                .and_then(|actual| crate::paths::system_path_scope(&actual))
        })
    } else if let Some(scope) = crate::paths::system_path_scope(&path) {
        Some(scope)
    } else {
        let device = crate::remote::checked_device(&ctx.st, &device_id, None).ok()?;
        crate::remote::ensure_trusted_pub(&ctx.st, &device).ok()?;
        let target = crate::remote::authenticated_target(&ctx.st, &device);
        let actual = crate::remote::run(
            &target,
            &format!(
                "readlink -f -- {} 2>/dev/null",
                crate::remote::shell_quote(&path)
            ),
            Some(10),
        )
        .ok()?;
        crate::paths::system_path_scope(String::from_utf8_lossy(&actual).trim())
    }?;
    if !device_id.is_empty() && crate::remote::checked_device(&ctx.st, &device_id, None).is_err() {
        return None;
    }
    Some((device_id, path, scope))
}

fn api_system_access_status(ctx: &Ctx) -> Response {
    let (device_id, _, scope) = match system_access_scope(ctx) {
        Some(scope) => scope,
        None => return fail(1, "System folder required", serde_json::Value::Null),
    };
    let session_id = match ctx.st.session_id(&ctx.headers) {
        Some(id) => id,
        None => return unauthorized(&ctx.headers),
    };
    let prefs = ctx.prefs();
    let all_allowed = ctx.st.system_access.allowed(&session_id, &device_id, "*");
    let scope_allowed = ctx
        .st
        .system_access
        .allowed(&session_id, &device_id, &scope);
    ok(json!({
        "allowed": all_allowed || scope_allowed,
        "scope": if all_allowed { "*" } else { scope.as_str() },
        "timeout_enabled": prefs.system_access_timeout_enabled != 0,
        "timeout_minutes": prefs.system_access_timeout_minutes,
    }))
}

async fn api_system_access_unlock(ctx: &Ctx) -> Response {
    if !ctx.is_post() {
        return fail_status(
            StatusCode::METHOD_NOT_ALLOWED,
            1,
            "POST required",
            serde_json::Value::Null,
        );
    }
    let (device_id, _, _scope) = match system_access_scope(ctx) {
        Some(scope) => scope,
        None => return fail(1, "System folder required", serde_json::Value::Null),
    };
    let session_id = match ctx.st.session_id(&ctx.headers) {
        Some(id) => id,
        None => return unauthorized(&ctx.headers),
    };
    let password = ctx.params.get("password").unwrap_or_default().to_string();
    let verify_st = ctx.st.clone();
    let password_ok =
        tokio::task::spawn_blocking(move || crate::security::check_password(&verify_st, &password))
            .await
            .unwrap_or(false);
    if !password_ok {
        return fail_status(
            StatusCode::UNAUTHORIZED,
            1,
            "Password verification failed",
            serde_json::Value::Null,
        );
    }
    if crate::security::is_enabled(&ctx.st)
        && !crate::security::verify_active_code(
            &ctx.st,
            &ctx.params.get("totp_code").unwrap_or_default(),
        )
    {
        return fail_status(
            StatusCode::UNAUTHORIZED,
            1,
            "Two-factor verification failed",
            serde_json::Value::Null,
        );
    }
    let timeout_enabled = ctx.params.get("timeout_enabled").as_deref() != Some("0");
    let current_prefs = ctx.prefs();
    let timeout_minutes = match ctx.params.int("timeout_minutes") {
        Some(value) if (1..=10080).contains(&value) => value,
        None => current_prefs.system_access_timeout_minutes,
        _ => {
            return fail(
                1,
                "Timeout must be between 1 and 10080 minutes",
                serde_json::Value::Null,
            );
        }
    };
    let timeout_secs = if timeout_enabled {
        timeout_minutes.saturating_mul(60)
    } else {
        0
    };
    let settings = vec![
        (
            "system_access_timeout_enabled".to_string(),
            (if timeout_enabled { "1" } else { "0" }).to_string(),
        ),
        (
            "system_access_timeout_minutes".to_string(),
            timeout_minutes.to_string(),
        ),
    ];
    if let Err(message) = crate::config::save_values(&ctx.st.settings.config_path, &settings) {
        return fail_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            &message,
            serde_json::Value::Null,
        );
    }
    ctx.st
        .system_access
        .grant(&session_id, &device_id, "*", timeout_secs);
    ok(json!({
        "allowed": true,
        "scope": "*",
        "timeout_enabled": timeout_enabled,
        "timeout_minutes": timeout_minutes
    }))
}

fn api_system_access_lock(ctx: &Ctx) -> Response {
    if !ctx.is_post() {
        return fail_status(
            StatusCode::METHOD_NOT_ALLOWED,
            1,
            "POST required",
            serde_json::Value::Null,
        );
    }
    let device_id = ctx.params.get("device_id").unwrap_or_default();
    if device_id.len() > 256 || device_id.chars().any(char::is_control) {
        return fail(1, "Invalid device", serde_json::Value::Null);
    }
    let session_id = match ctx.st.session_id(&ctx.headers) {
        Some(id) => id,
        None => return unauthorized(&ctx.headers),
    };
    if device_id == "*" {
        ctx.st.system_access.revoke_session(&session_id);
        return ok(json!({ "locked": true }));
    }
    if ctx.params.get("path").is_some() {
        let (scope_device, _, scope) = match system_access_scope(ctx) {
            Some(scope) => scope,
            None => return fail(1, "System folder required", serde_json::Value::Null),
        };
        if scope_device != device_id {
            return fail(1, "Invalid device", serde_json::Value::Null);
        }
        if ctx.params.get("revoke_scope").as_deref() == Some("1") {
            ctx.st
                .system_access
                .revoke_scope(&session_id, &device_id, &scope);
        } else {
            ctx.st
                .system_access
                .retain_scope(&session_id, &device_id, &scope);
        }
    } else {
        ctx.st.system_access.revoke(&session_id, &device_id);
    }
    ok(json!({ "locked": true }))
}

async fn dispatch_endpoint(name: &str, ctx: &Ctx) -> Response {
    match name {
        "navigation" => fsops::api_navigation(ctx).await,
        "list" => fsops::api_list(ctx).await,
        "create_directory" => fsops::api_create_directory(ctx).await,
        "create_file" => fsops::api_create_file(ctx).await,
        "rename" => fsops::api_rename(ctx).await,
        "delete" => fsops::api_delete(ctx).await,
        "copy" => fsops::api_copy(ctx).await,
        "move" => fsops::api_move(ctx).await,
        "batch_copy" => fsops::api_batch_copy(ctx).await,
        "batch_move" => fsops::api_batch_move(ctx).await,
        "batch_delete" => fsops::api_batch_delete(ctx).await,
        "batch_check" => fsops::api_batch_check(ctx).await,
        "chmod" => fsops::api_chmod(ctx).await,
        "detect_type" => fsops::api_detect_type(ctx).await,
        "read_text" => textops::api_read_text(ctx).await,
        "save_text" => textops::api_save_text(ctx).await,
        "upload_check" => textops::api_upload_check(ctx).await,
        "preferences" => prefops::api_preferences(ctx).await,
        "save_preferences" => prefops::api_save_preferences(ctx).await,
        "root_policy" => pathops::api_root_policy(ctx),
        "save_root_policy" => pathops::api_save_root_policy(ctx).await,
        "update_check" => updateops::api_check(ctx).await,
        "update_start" => updateops::api_start(ctx).await,
        "update_status" => updateops::api_status(ctx).await,
        "save_last_directory" => prefops::api_save_last_directory(ctx).await,
        "save_show_line_numbers" => prefops::api_save_show_line_numbers(ctx).await,
        "bookmark_save" => prefops::api_bookmark_save(ctx).await,
        "bookmark_delete" => prefops::api_bookmark_delete(ctx).await,
        "bookmark_move" => prefops::api_bookmark_move(ctx).await,
        "bookmark_folder_add" => prefops::api_bookmark_folder_add(ctx).await,
        "bookmark_folder_rename" => prefops::api_bookmark_folder_rename(ctx).await,
        "bookmark_folder_delete" => prefops::api_bookmark_folder_delete(ctx).await,
        "bookmark_folder_state" => prefops::api_bookmark_folder_state(ctx).await,
        "bookmark_folder_move" => prefops::api_bookmark_folder_move(ctx).await,
        "quick_item_save" => prefops::api_quick_item_save(ctx).await,
        "quick_item_delete" => prefops::api_quick_item_delete(ctx).await,
        "quick_item_move" => prefops::api_quick_item_move(ctx).await,
        "archive_list" => archops::api_archive_list(ctx).await,
        "archive_create_start" => archops::api_archive_create_start(ctx).await,
        "archive_extract_start" => archops::api_archive_extract_start(ctx).await,
        "archive_status" => archops::api_archive_status(ctx).await,
        "tool_install_start" => archops::api_tool_install_start(ctx).await,
        "package_install_start" => archops::api_package_install_start(ctx).await,
        "package_install_status" => archops::api_package_install_status(ctx).await,
        "thumbnail_generate_start" => archops::api_thumbnail_generate_start(ctx).await,
        "thumbnail_generate_status" => archops::api_thumbnail_generate_status(ctx).await,
        "system_access_status" => api_system_access_status(ctx),
        "system_access_unlock" => api_system_access_unlock(ctx).await,
        "system_access_lock" => api_system_access_lock(ctx),
        "security_state" => secops::api_security_state(ctx).await,
        "security_account" => secops::api_security_account(ctx).await,
        "security_password" => secops::api_security_password(ctx).await,
        "security_username" => secops::api_security_username(ctx).await,
        "security_totp_setup" => secops::api_security_totp_setup(ctx).await,
        "security_totp_cancel" => secops::api_security_totp_cancel(ctx).await,
        "security_totp_enable" => secops::api_security_totp_enable(ctx).await,
        "security_totp_disable" => secops::api_security_totp_disable(ctx).await,
        "wallpaper_catalog" => secops::api_wallpaper_catalog(ctx).await,
        "wallpaper_current" => secops::api_wallpaper_current(ctx).await,
        "wallpaper_apply" => secops::api_wallpaper_apply(ctx).await,
        "wallpaper_remove" => secops::api_wallpaper_remove(ctx).await,
        "wallpaper_delete" => secops::api_wallpaper_delete(ctx).await,
        "stat" => transferops::api_stat(ctx).await,
        "storage" => transferops::api_storage_api(ctx).await,
        "upload_init" => transferops::api_upload_init(ctx).await,
        "upload_status" => transferops::api_upload_status(ctx).await,
        "upload_complete" => transferops::api_upload_complete(ctx).await,
        "tasks" => transferops::api_tasks(ctx).await,
        "task_cancel" => transferops::api_task_cancel(ctx).await,
        "ssh_journal" => api_ssh_journal(),
        other => fail(
            404,
            &format!("Unknown endpoint: {other}"),
            serde_json::Value::Null,
        ),
    }
}

fn is_multipart(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("multipart/form-data"))
        .unwrap_or(false)
}

pub async fn health(st: Arc<AppState>) -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "code": 0,
            "data": {
                "version": st.settings.version,
                "uptime": crate::meta::now_secs() - st.started,
                "assets": crate::web::ASSET_COUNT,
                "pid": std::process::id(),
                "connections_available": st.limits.connections.available_permits(),
                "transfers_available": st.limits.transfers.available_permits(),
                "max_connections": st.settings.max_connections,
                "max_transfers": st.settings.max_transfers,
                "session_ttl": st.settings.session_ttl,
                "session_idle": st.settings.session_idle,
                "session_sliding": st.settings.session_sliding,
                "sessions_active": st.sessions.len()
            }
        }),
    )
}
