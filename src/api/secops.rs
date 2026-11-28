use crate::config;
use crate::reply::{fail_status, ok};
use crate::security;
use crate::state::{AppState, Ctx};
use crate::wallpapers;
use axum::extract::{FromRequest, Multipart, Request};
use axum::http::{Method, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::sync::Arc;

fn post_only(ctx: &Ctx) -> Option<Response> {
    match ctx.require_post() {
        Ok(()) => None,
        Err(e) => Some(crate::reply::ApiError::into_response(e)),
    }
}

pub async fn api_security_state(ctx: &Ctx) -> Response {
    security::api_state(&ctx.st).await
}

pub async fn api_security_password(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    let current = ctx.params.str_or("current_password", "");
    let new_password = ctx
        .params
        .get("new_password")
        .or_else(|| ctx.params.get("password"))
        .unwrap_or_default();
    let confirm = ctx.params.get("confirm_password");
    ctx.st.system_access.clear();
    security::api_change_password(&ctx.st, &current, &new_password, confirm.as_deref()).await
}

pub async fn api_security_account(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    let current = ctx.params.str_or("current_password", "");
    let username = ctx.params.get("username");
    let new_password = ctx.params.get("new_password");
    let confirm = ctx.params.get("confirm_password");
    let response = security::api_change_account(
        &ctx.st,
        &current,
        username.as_deref(),
        new_password.as_deref(),
        confirm.as_deref(),
    )
    .await;
    if response.status().is_success() {
        ctx.st.system_access.clear();
    }
    response
}

pub async fn api_security_username(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    let current = ctx.params.str_or("current_password", "");
    let name = ctx.params.str_or("username", "");
    ctx.st.system_access.clear();
    security::api_change_username(&ctx.st, &current, &name).await
}

pub async fn api_security_totp_setup(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    let current = ctx.params.str_or("current_password", "");
    ctx.st.system_access.clear();
    security::api_totp_setup(&ctx.st, &current).await
}

pub async fn api_security_totp_cancel(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    ctx.st.system_access.clear();
    security::api_totp_cancel(&ctx.st).await
}

pub async fn api_security_totp_enable(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    let code = ctx.params.str_or("code", "");
    ctx.st.system_access.clear();
    security::api_totp_enable(&ctx.st, &code).await
}

pub async fn api_security_totp_disable(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    let password = ctx.params.str_or("password", "");
    let code = ctx.params.str_or("code", "");
    ctx.st.system_access.clear();
    security::api_totp_disable(&ctx.st, &password, &code).await
}

fn count_param(ctx: &Ctx) -> usize {
    ctx.params
        .get("count")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 24)
}

fn page_param(ctx: &Ctx) -> usize {
    ctx.params
        .get("page")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(1)
        .max(1)
}

async fn fetch_provider_json(url: &str) -> Result<Value, String> {
    fetch_provider(url).await
}

async fn fetch_provider(url: &str) -> Result<Value, String> {
    let max_bytes = 1024 * 1024;
    let curl_args: Vec<String> = vec![
        "-fsSL".into(),
        "--max-time".into(),
        "15".into(),
        "--max-filesize".into(),
        max_bytes.to_string(),
        "--proto".into(),
        "=https".into(),
        "--proto-redir".into(),
        "=https".into(),
        url.into(),
    ];
    let wget_args: Vec<String> = vec![
        "-q".into(),
        "-T".into(),
        "15".into(),
        "-O".into(),
        "-".into(),
        url.into(),
    ];
    let commands: [(&str, Vec<String>); 3] = [
        ("curl", curl_args),
        ("wget", wget_args.clone()),
        ("uclient-fetch", wget_args),
    ];
    let mut last = "No HTTP client is installed".to_string();
    for (program, args) in commands {
        let output = match tokio::process::Command::new(program)
            .args(&args)
            .output()
            .await
        {
            Ok(output) => output,
            Err(_) => continue,
        };
        if !output.status.success() {
            last = String::from_utf8_lossy(&output.stderr)
                .trim()
                .chars()
                .take(200)
                .collect();
            continue;
        }
        if output.stdout.len() > max_bytes {
            return Err("Wallpaper provider response is too large".into());
        }
        return serde_json::from_slice(&output.stdout)
            .map_err(|_| "Wallpaper provider returned invalid JSON".into());
    }
    Err(if last.is_empty() {
        "Cannot reach wallpaper provider".into()
    } else {
        last
    })
}

async fn fetch_redirect_url(url: &str) -> Result<String, String> {
    let output = tokio::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "15",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "-o",
            "/dev/null",
            "-w",
            "%{url_effective}",
            url,
        ])
        .output()
        .await
        .map_err(|_| "No HTTP client is installed".to_string())?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr)
            .trim()
            .chars()
            .take(200)
            .collect::<String>();
        return Err(if message.is_empty() {
            "Cannot reach wallpaper provider".into()
        } else {
            message
        });
    }
    let target = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if target.is_empty() {
        return Err("Cannot reach wallpaper provider".into());
    }
    Ok(target)
}

fn absolute_bing_url(raw: &str) -> Option<String> {
    let url = if raw.starts_with('/') {
        format!("https://www.bing.com{raw}")
    } else {
        raw.to_string()
    };
    crate::wallpapers::is_provider_url(&url).then_some(url)
}

async fn wallpaper_provider_items(
    st: &AppState,
    source: &str,
    image_type: &str,
    page: usize,
    count: usize,
) -> Result<(Vec<Value>, bool), String> {
    let page = page.clamp(1, 10_000);
    let count = count.clamp(1, 8);
    match source {
        "builtin" => Ok((wallpapers::builtin_items(), false)),
        "custom" => Ok((wallpapers::custom_items(st), false)),
        "uapipro" => {
            const CATEGORIES: &[&str] = &[
                "acg",
                "landscape",
                "anime",
                "pc_wallpaper",
                "general_anime",
                "bq",
                "furry",
            ];
            let category = if image_type == "all" || !CATEGORIES.contains(&image_type) {
                ""
            } else {
                image_type
            };
            let endpoint = if category.is_empty() {
                "https://uapis.cn/api/v1/random/image".to_string()
            } else {
                format!("https://uapis.cn/api/v1/random/image?category={category}")
            };
            let pending = (0..count).map(|_| {
                let endpoint = endpoint.clone();
                async move { fetch_redirect_url(&endpoint).await }
            });
            let results = futures_util::future::join_all(pending).await;
            let mut items = Vec::new();
            let mut last = String::new();
            for result in results {
                match result {
                    Ok(full) => {
                        if !crate::wallpapers::is_provider_url(&full) {
                            continue;
                        }
                        items.push(json!({
                            "id": full,
                            "url": full,
                            "full": full,
                            "thumb": full,
                            "title": "UApiPro",
                            "source": "uapipro",
                            "type": image_type
                        }));
                    }
                    Err(error) => last = error,
                }
            }
            if items.is_empty() {
                return Err(if last.is_empty() {
                    "Cannot reach wallpaper provider".to_string()
                } else {
                    last
                });
            }
            Ok((items, true))
        }
        "bing" => {
            let idx = (page - 1) * count;
            let url = format!(
                "https://www.bing.com/HPImageArchive.aspx?format=js&idx={idx}&n={count}&mkt=zh-CN"
            );
            let data = fetch_provider_json(&url).await?;
            let images = data
                .get("images")
                .and_then(Value::as_array)
                .ok_or("Bing returned an invalid catalog")?;
            let mut items = Vec::new();
            for image in images {
                let full = image
                    .get("url")
                    .and_then(Value::as_str)
                    .and_then(absolute_bing_url)
                    .or_else(|| {
                        image
                            .get("urlbase")
                            .and_then(Value::as_str)
                            .and_then(|base| absolute_bing_url(&format!("{base}_1920x1080.jpg")))
                    });
                let Some(full) = full else { continue };

                let thumb = full.clone();
                let title = image
                    .get("copyright")
                    .and_then(Value::as_str)
                    .or_else(|| image.get("title").and_then(Value::as_str))
                    .unwrap_or("Bing Daily");
                items.push(json!({
                    "id": full,
                    "url": full,
                    "full": full,
                    "thumb": thumb,
                    "title": title,
                    "source": "bing",
                    "type": "all"
                }));
            }
            let has_more = items.len() == count;
            Ok((items, has_more))
        }
        "openverse" => {
            let query = crate::wallpapers::type_query(image_type);
            let url = format!(
                "https://api.openverse.org/v1/images/?q={query}&page={page}&page_size={count}&license=cc0,pdm,by,by-sa,by-nd&mature=false"
            );
            let data = fetch_provider_json(&url).await?;
            let results = data
                .get("results")
                .and_then(Value::as_array)
                .ok_or("Openverse returned an invalid catalog")?;
            let mut items = Vec::new();
            for image in results {
                let full = image.get("url").and_then(Value::as_str).unwrap_or("");
                let thumb = image.get("thumbnail").and_then(Value::as_str).unwrap_or("");
                if !crate::wallpapers::is_provider_url(full)
                    || !crate::wallpapers::is_provider_url(thumb)
                {
                    continue;
                }
                let title = image
                    .get("title")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("Openly licensed photo");
                let creator = image
                    .get("creator")
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown creator");
                let creator_url = image
                    .get("creator_url")
                    .and_then(Value::as_str)
                    .filter(|url| crate::wallpapers::is_provider_url(url))
                    .unwrap_or("");
                let license = image
                    .get("license")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let license_version = image
                    .get("license_version")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let license_url = image
                    .get("license_url")
                    .and_then(Value::as_str)
                    .filter(|url| crate::wallpapers::is_provider_url(url))
                    .unwrap_or("");
                let attribution = image
                    .get("attribution")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let source_url = image
                    .get("foreign_landing_url")
                    .and_then(Value::as_str)
                    .filter(|url| crate::wallpapers::is_provider_url(url))
                    .unwrap_or("");
                items.push(json!({
                    "id": full,
                    "url": full,
                    "full": full,
                    "thumb": thumb,
                    "title": title,
                    "creator": creator,
                    "creator_url": creator_url,
                    "license": license,
                    "license_version": license_version,
                    "license_url": license_url,
                    "attribution": attribution,
                    "source_url": source_url,
                    "source": "openverse",
                    "type": image_type
                }));
            }
            let page_count = data
                .get("page_count")
                .and_then(Value::as_u64)
                .unwrap_or(page as u64);
            Ok((items, (page as u64) < page_count))
        }
        _ => Err("Unknown wallpaper source".into()),
    }
}

fn random_index(length: usize) -> usize {
    if length <= 1 {
        return 0;
    }
    let bytes = crate::auth::random_bytes(8);
    let value = bytes
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    (value % length as u64) as usize
}

fn complete_wallpaper(mut item: Value, mode: &str, source: &str, image_type: &str) -> Value {
    if let Value::Object(map) = &mut item {
        map.insert("enabled".into(), json!(true));
        map.insert("mode".into(), json!(mode));
        map.insert("source".into(), json!(source));
        map.insert("type".into(), json!(image_type));
    }
    item
}

async fn automatic_wallpaper(
    st: &AppState,
    source: &str,
    image_type: &str,
) -> Result<Value, String> {
    if source == "builtin" {
        return Ok(complete_wallpaper(
            wallpapers::builtin_item(),
            "auto",
            source,
            image_type,
        ));
    }
    let (items, _) = wallpaper_provider_items(st, source, image_type, 1, 8).await?;
    if items.is_empty() {
        return Err("No wallpaper is currently available from this source".into());
    }
    Ok(complete_wallpaper(
        items[random_index(items.len())].clone(),
        "auto",
        source,
        image_type,
    ))
}

pub async fn api_wallpaper_catalog(ctx: &Ctx) -> Response {
    let source = ctx.params.str_or("source", "builtin");
    let image_type = ctx.params.str_or("type", "all");
    if !wallpapers::valid_source(&source)
        || !wallpapers::valid_type(&image_type)
        || (source != "openverse" && source != "uapipro" && image_type != "all")
    {
        return fail_status(
            StatusCode::BAD_REQUEST,
            1,
            "Unknown wallpaper source or type",
            Value::Null,
        );
    }
    let page = page_param(ctx);
    let count = count_param(ctx).min(8);
    let (items, has_more) =
        match wallpaper_provider_items(&ctx.st, &source, &image_type, page, count).await {
            Ok(result) => result,
            Err(message) => {
                return fail_status(StatusCode::BAD_GATEWAY, 1, &message, Value::Null);
            }
        };
    let mut body = wallpapers::page_shell(&source, &image_type, page, count, items, has_more);
    if let Value::Object(map) = &mut body {
        map.insert("current".into(), wallpapers::current(&ctx.st, &ctx.prefs()));
        if source == "custom" {
            map.insert("custom_limit".into(), json!(wallpapers::CUSTOM_LIMIT));
            map.insert(
                "custom_max_bytes".into(),
                json!(wallpapers::CUSTOM_MAX_BYTES),
            );
        }
    }
    ok(body)
}

pub async fn api_wallpaper_current(ctx: &Ctx) -> Response {
    let prefs = ctx.prefs();
    if prefs.wallpaper_enabled != 0 && prefs.wallpaper_mode == "auto" {
        return match automatic_wallpaper(&ctx.st, &prefs.wallpaper_source, &prefs.wallpaper_type)
            .await
        {
            Ok(current) => {
                let id = current
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if let Err(message) = config::save_values(
                    &ctx.st.settings.config_path,
                    &[("wallpaper_id".to_string(), id)],
                ) {
                    return fail_status(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        1,
                        &message,
                        Value::Null,
                    );
                }
                ok(current)
            }
            Err(message) => fail_status(StatusCode::BAD_GATEWAY, 1, &message, Value::Null),
        };
    }
    ok(wallpapers::current(&ctx.st, &prefs))
}

pub async fn api_wallpaper_apply(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    if ctx.params.get("url").is_some() {
        return fail_status(
            StatusCode::GONE,
            1,
            "Wallpaper images are loaded directly from their provider and are not stored on this device",
            Value::Null,
        );
    }
    let id = ctx.params.str_or("id", "");
    let id = match config::sanitize_wallpaper_id(&id) {
        Some(id) if !id.is_empty() => id,
        _ => {
            return fail_status(StatusCode::BAD_REQUEST, 1, "Unknown wallpaper", Value::Null);
        }
    };
    let source = ctx.params.str_or("source", "builtin");
    let image_type = ctx.params.str_or("type", "all");
    if !wallpapers::valid_source(&source)
        || !wallpapers::valid_type(&image_type)
        || (source != "openverse" && source != "uapipro" && image_type != "all")
    {
        return fail_status(
            StatusCode::BAD_REQUEST,
            1,
            "Unknown wallpaper source or type",
            Value::Null,
        );
    }
    if (source == "custom") != wallpapers::parse_custom_id(&id).is_some()
        || (source == "custom" && wallpapers::custom_item_for_id(&ctx.st, &id).is_none())
    {
        return fail_status(StatusCode::BAD_REQUEST, 1, "Unknown wallpaper", Value::Null);
    }
    let mode = ctx.params.str_or("mode", "fixed");
    if !["fixed", "auto"].contains(&mode.as_str()) {
        return fail_status(
            StatusCode::BAD_REQUEST,
            1,
            "Unknown wallpaper mode",
            Value::Null,
        );
    }
    let values = vec![
        ("wallpaper_id".into(), id),
        ("wallpaper_enabled".into(), "1".into()),
        ("wallpaper_mode".into(), mode),
        ("wallpaper_source".into(), source),
        ("wallpaper_type".into(), image_type),
    ];
    if let Err(message) = config::save_values(&ctx.st.settings.config_path, &values) {
        return fail_status(StatusCode::INTERNAL_SERVER_ERROR, 1, &message, Value::Null);
    }
    let prefs = ctx.prefs();
    if prefs.wallpaper_mode == "auto" {
        return match automatic_wallpaper(&ctx.st, &prefs.wallpaper_source, &prefs.wallpaper_type)
            .await
        {
            Ok(current) => ok(current),
            Err(message) => fail_status(StatusCode::BAD_GATEWAY, 1, &message, Value::Null),
        };
    }
    ok(wallpapers::current(&ctx.st, &prefs))
}

pub async fn api_wallpaper_save(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    let mut values: Vec<(String, String)> = Vec::new();
    if let Some(raw) = ctx.params.get("enabled") {
        match raw.as_str() {
            "0" | "1" => values.push(("wallpaper_enabled".into(), raw)),
            _ => {
                return fail_status(
                    StatusCode::BAD_REQUEST,
                    1,
                    "Invalid wallpaper value",
                    Value::Null,
                );
            }
        }
    }
    if let Some(raw) = ctx.params.get("login_enabled") {
        match raw.as_str() {
            "0" | "1" => values.push(("wallpaper_login_enabled".into(), raw)),
            _ => {
                return fail_status(
                    StatusCode::BAD_REQUEST,
                    1,
                    "Invalid wallpaper value",
                    Value::Null,
                );
            }
        }
    }
    if let Some(mode) = ctx.params.get("mode") {
        if !["fixed", "auto"].contains(&mode.as_str()) {
            return fail_status(
                StatusCode::BAD_REQUEST,
                1,
                "Unknown wallpaper mode",
                Value::Null,
            );
        }
        values.push(("wallpaper_mode".into(), mode));
    }
    if let Some(source) = ctx.params.get("source") {
        if !wallpapers::valid_source(&source) {
            return fail_status(
                StatusCode::BAD_REQUEST,
                1,
                "Unknown wallpaper source",
                Value::Null,
            );
        }
        values.push(("wallpaper_source".into(), source));
    }
    if let Some(image_type) = ctx.params.get("type") {
        let saved_source = ctx.prefs().wallpaper_source;
        let source = ctx.params.str_or("source", &saved_source);
        if !wallpapers::valid_type(&image_type)
            || (source != "openverse" && source != "uapipro" && image_type != "all")
        {
            return fail_status(
                StatusCode::BAD_REQUEST,
                1,
                "Unknown wallpaper type",
                Value::Null,
            );
        }
        values.push(("wallpaper_type".into(), image_type));
    }
    if let Some(id) = ctx.params.get("id") {
        match config::sanitize_wallpaper_id(&id) {
            Some(id) => values.push(("wallpaper_id".into(), id)),
            None => {
                return fail_status(StatusCode::BAD_REQUEST, 1, "Unknown wallpaper", Value::Null);
            }
        }
    }
    if !values.is_empty() {
        if let Err(message) = config::save_values(&ctx.st.settings.config_path, &values) {
            return fail_status(StatusCode::INTERNAL_SERVER_ERROR, 1, &message, Value::Null);
        }
    }
    let prefs = ctx.prefs();
    if prefs.wallpaper_enabled != 0 && prefs.wallpaper_mode == "auto" {
        return match automatic_wallpaper(&ctx.st, &prefs.wallpaper_source, &prefs.wallpaper_type)
            .await
        {
            Ok(current) => {
                let id = current
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if let Err(message) = config::save_values(
                    &ctx.st.settings.config_path,
                    &[("wallpaper_id".to_string(), id)],
                ) {
                    return fail_status(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        1,
                        &message,
                        Value::Null,
                    );
                }
                ok(current)
            }
            Err(message) => fail_status(StatusCode::BAD_GATEWAY, 1, &message, Value::Null),
        };
    }
    ok(wallpapers::current(&ctx.st, &prefs))
}

pub async fn api_wallpaper_remove(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    let values = vec![("wallpaper_enabled".to_string(), "0".to_string())];
    if let Err(message) = config::save_values(&ctx.st.settings.config_path, &values) {
        return fail_status(StatusCode::INTERNAL_SERVER_ERROR, 1, &message, Value::Null);
    }
    ok(wallpapers::current(&ctx.st, &ctx.prefs()))
}

pub async fn api_wallpaper_delete(ctx: &Ctx) -> Response {
    if let Some(response) = post_only(ctx) {
        return response;
    }
    let name = ctx.params.str_or("name", "");
    if !wallpapers::valid_custom_name(&name) {
        return fail_status(StatusCode::BAD_REQUEST, 1, "Unknown wallpaper", Value::Null);
    }
    let path = wallpapers::custom_dir(&ctx.st).join(&name);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return fail_status(StatusCode::BAD_REQUEST, 1, "Unknown wallpaper", Value::Null);
        }
        Err(_) => {
            return fail_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
                "Delete failed",
                Value::Null,
            );
        }
    }
    let prefs = ctx.prefs();
    if prefs.wallpaper_source == "custom" && prefs.wallpaper_id == wallpapers::custom_id(&name) {
        if let Err(message) = config::save_values(
            &ctx.st.settings.config_path,
            &[("wallpaper_enabled".to_string(), "0".to_string())],
        ) {
            return fail_status(StatusCode::INTERNAL_SERVER_ERROR, 1, &message, Value::Null);
        }
    }
    ok(json!({ "deleted": name }))
}

pub async fn api_wallpaper_upload(st: Arc<AppState>, req: Request) -> Response {
    if req.method() != Method::POST {
        return fail_status(
            StatusCode::METHOD_NOT_ALLOWED,
            1,
            "POST required",
            Value::Null,
        );
    }
    let dir = match wallpapers::ensure_custom_dir(&st) {
        Some(dir) => dir,
        None => {
            return fail_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
                "Save failed: cannot store wallpaper",
                Value::Null,
            )
        }
    };
    let existing = wallpapers::custom_items(&st).len();
    let mut multipart = match Multipart::from_request(req, &()).await {
        Ok(multipart) => multipart,
        Err(_) => {
            return fail_status(
                StatusCode::BAD_REQUEST,
                1,
                "Invalid or interrupted upload request",
                Value::Null,
            )
        }
    };
    let mut saved: Vec<String> = Vec::new();
    let mut failure: Option<(String, StatusCode)> = None;
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => {
                failure = Some((
                    "Invalid or interrupted upload request".to_string(),
                    StatusCode::BAD_REQUEST,
                ));
                break;
            }
        };
        let raw_name = match field.file_name().map(str::to_string) {
            Some(name) => name,
            None => continue,
        };
        if existing + saved.len() >= wallpapers::CUSTOM_LIMIT {
            failure = Some(("Too many wallpapers".to_string(), StatusCode::BAD_REQUEST));
            break;
        }
        let name = match wallpaper_upload_name(&raw_name) {
            Some(name) => name,
            None => {
                failure = Some((
                    "Unsupported image format".to_string(),
                    StatusCode::BAD_REQUEST,
                ));
                break;
            }
        };
        let name = match unique_wallpaper_name(&dir, &name) {
            Some(name) => name,
            None => {
                failure = Some(("Too many wallpapers".to_string(), StatusCode::BAD_REQUEST));
                break;
            }
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let tmp = dir.join(format!(".harbor-wallpaper-{stamp}.tmp"));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(file) => file,
            Err(error) => {
                failure = Some((
                    format!("Save failed: {error}"),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
                break;
            }
        };
        let mut written: u64 = 0;
        let mut aborted: Option<String> = None;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    written += chunk.len() as u64;
                    if written > wallpapers::CUSTOM_MAX_BYTES {
                        aborted = Some("Wallpaper file is too large".to_string());
                        break;
                    }
                    if let Err(error) = file.write_all(&chunk) {
                        aborted = Some(format!("Save failed: {error}"));
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    aborted = Some("Invalid or interrupted upload request".to_string());
                    break;
                }
            }
        }
        drop(file);
        if let Some(message) = aborted {
            let _ = fs::remove_file(&tmp);
            let status = if message.starts_with("Wallpaper file is too large") {
                StatusCode::PAYLOAD_TOO_LARGE
            } else if message.starts_with("Save failed") {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            };
            failure = Some((message, status));
            break;
        }
        if let Err(error) = fs::rename(&tmp, dir.join(&name)) {
            let _ = fs::remove_file(&tmp);
            failure = Some((
                format!("Save failed: {error}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
            break;
        }
        saved.push(name);
    }
    if let Some((message, status)) = failure {
        for name in &saved {
            let _ = fs::remove_file(dir.join(name));
        }
        return fail_status(status, 1, &message, Value::Null);
    }
    if saved.is_empty() {
        return fail_status(
            StatusCode::BAD_REQUEST,
            1,
            "Invalid or interrupted upload request",
            Value::Null,
        );
    }
    let items: Vec<Value> = saved
        .iter()
        .map(|name| wallpapers::custom_item(name))
        .collect();
    ok(json!({ "saved": items, "count": existing + saved.len() }))
}

fn wallpaper_upload_name(raw: &str) -> Option<String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("").trim();
    if base.is_empty() || base.len() > 128 {
        return None;
    }
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let (stem, ext) = cleaned.rsplit_once('.')?;
    let stem = stem.trim_matches(|c| c == '.' || c == ' ');
    let ext = ext.to_ascii_lowercase();
    if stem.is_empty() || stem.len() > 64 || !wallpapers::CUSTOM_EXTS.contains(&ext.as_str()) {
        return None;
    }
    Some(format!("{stem}.{ext}"))
}

fn unique_wallpaper_name(dir: &std::path::Path, name: &str) -> Option<String> {
    if !dir.join(name).exists() {
        return Some(name.to_string());
    }
    let (stem, ext) = name.rsplit_once('.')?;
    for index in 1..1000 {
        let candidate = format!("{stem} ({index}).{ext}");
        if !dir.join(&candidate).exists() {
            return Some(candidate);
        }
    }
    None
}
