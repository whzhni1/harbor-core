//! Core-owned path policy settings and re-authenticated policy updates.
use crate::paths::normalize_path;
use crate::reply::{fail, fail_status, ok};
use crate::state::{Ctx, RootPolicy, RootPolicyConfig};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{json, Value};

fn policy_json(ctx: &Ctx) -> Value {
    let config = ctx.st.root_policy_config();
    json!({
        "policy": config.policy.as_str(),
        "roots": config.roots,
        "excluded_roots": config.excluded_roots,
        "managed_by_cli": ctx.st.settings.root_policy_cli_override,
        "totp_required": crate::security::is_enabled(&ctx.st)
    })
}

pub fn api_root_policy(ctx: &Ctx) -> Response {
    ok(policy_json(ctx))
}

fn parse_roots(params: &crate::params::Params, key: &str) -> Result<Vec<String>, &'static str> {
    let Some(raw) = params.get(key) else {
        return Ok(Vec::new());
    };
    let items: Vec<String> = if let Ok(value) = serde_json::from_str::<Value>(&raw) {
        let Some(array) = value.as_array() else {
            return Err("Invalid path list");
        };
        let mut out = Vec::with_capacity(array.len());
        for item in array {
            let Some(path) = item.as_str() else {
                return Err("Invalid path list");
            };
            out.push(path.to_string());
        }
        out
    } else {
        raw.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect()
    };
    let mut roots = Vec::new();
    for item in items {
        if item.chars().any(char::is_control) {
            return Err("Invalid path list");
        }
        let Some(path) = normalize_path(item.trim()) else {
            return Err("Paths must be absolute");
        };
        if !roots.contains(&path) {
            roots.push(path);
        }
    }
    Ok(roots)
}

pub async fn api_save_root_policy(ctx: &Ctx) -> Response {
    if let Err(error) = ctx.require_post() {
        return error.into_response();
    }
    if ctx.st.settings.root_policy_cli_override {
        return fail_status(
            StatusCode::CONFLICT,
            1,
            "Path policy is controlled by command-line options",
            Value::Null,
        );
    }
    let mode = ctx.params.str_or("policy", "");
    let current = ctx.st.root_policy_config();
    let roots = if ctx.params.get("roots").is_some() {
        match parse_roots(&ctx.params, "roots") {
            Ok(values) => values,
            Err(message) => return fail(1, message, Value::Null),
        }
    } else {
        current.roots
    };
    let excluded_roots = if ctx.params.get("excluded_roots").is_some() {
        match parse_roots(&ctx.params, "excluded_roots") {
            Ok(values) => values,
            Err(message) => return fail(1, message, Value::Null),
        }
    } else {
        current.excluded_roots
    };
    let policy = match mode.as_str() {
        "unrestricted" => RootPolicy::Unrestricted,
        "allowlist" if !roots.is_empty() => RootPolicy::Allowlist,
        "allowlist" => {
            return fail(
                1,
                "Allowlist requires at least one root directory",
                Value::Null,
            );
        }
        "denylist" if !excluded_roots.is_empty() => RootPolicy::Denylist,
        "denylist" => {
            return fail(
                1,
                "Blacklist requires at least one root directory",
                Value::Null,
            );
        }
        _ => return fail(1, "Invalid path policy", Value::Null),
    };
    let (policy, roots, excluded_roots) = (policy, roots, excluded_roots);

    let current_password = ctx.params.str_or("current_password", "");
    if !crate::security::check_password(&ctx.st, &current_password) {
        return fail_status(
            StatusCode::UNAUTHORIZED,
            1,
            "Password verification failed",
            Value::Null,
        );
    }
    if crate::security::is_enabled(&ctx.st) {
        let code = ctx.params.str_or("totp_code", "");
        if !crate::security::verify_active_code(&ctx.st, &code) {
            return fail_status(
                StatusCode::UNAUTHORIZED,
                1,
                "Two-factor verification failed",
                Value::Null,
            );
        }
    }

    if let Err(error) = crate::config::save_root_policy(
        &ctx.st.settings.config_path,
        policy,
        &roots,
        &excluded_roots,
    ) {
        return fail_status(StatusCode::INTERNAL_SERVER_ERROR, 1, &error, Value::Null);
    }
    let config = RootPolicyConfig {
        policy,
        roots,
        excluded_roots,
    };
    if ctx.st.set_root_policy_config(config).is_err() {
        return fail_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "Cannot update active path policy",
            Value::Null,
        );
    }
    ok(policy_json(ctx))
}
