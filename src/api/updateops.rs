//! Adapter for the fixed external Harbor Core updater script.
//!
//! The kernel never discovers releases, selects assets, downloads packages, or
//! installs binaries. Those operations belong exclusively to
//! `/usr/libexec/harbor/harbor-update.sh`.
use crate::reply::{fail, fail_status, ok};
use crate::state::Ctx;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{timeout_at, Duration, Instant};

const SCRIPT_PATH: &str = "/usr/libexec/harbor/harbor-update.sh";
const SCRIPT_STDOUT_LIMIT: usize = 16 * 1024;
const BUILD_TARGET: &str = env!("HARBOR_BUILD_TARGET");
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const CHECK_TIMEOUT: Duration = Duration::from_secs(18);
const STATUS_TIMEOUT: Duration = Duration::from_secs(6);
const START_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
struct ScriptOutput {
    code: Option<i32>,
    json: Value,
}

fn valid_mirror(raw: &str) -> Option<&'static str> {
    match raw {
        "auto" => Some("auto"),
        "github" => Some("github"),
        "gitlab" => Some("gitlab"),
        "gitee" => Some("gitee"),
        "cloudflare" => Some("cloudflare"),
        _ => None,
    }
}

fn task_id_valid(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn script_is_executable() -> bool {
    let path = Path::new(SCRIPT_PATH);
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

/// Run the fixed script with a fixed argv vector, no shell, bounded stdout,
/// discarded stderr, a timeout, and kill-on-drop. Caller-supplied values are
/// passed as individual argv entries only after enum/identifier validation.
fn kill_child_group(child: &tokio::process::Child) {
    if let Some(pid) = child.id() {
        // SAFETY: pid is the direct child PID; it was placed in its own process
        // group so a negative pid targets only this updater invocation tree.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

async fn run_script(args: &[String], limit: Duration) -> Result<ScriptOutput, String> {
    if !script_is_executable() {
        return Err(format!(
            "Updater script is missing or not executable: {SCRIPT_PATH}"
        ));
    }
    let mut child = Command::new(SCRIPT_PATH)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("Cannot execute updater script: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Cannot capture updater script output".to_string())?;
    let deadline = Instant::now() + limit;
    let mut output = Vec::new();
    let mut reader = stdout.take((SCRIPT_STDOUT_LIMIT + 1) as u64);
    match timeout_at(deadline, reader.read_to_end(&mut output)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            kill_child_group(&child);
            return Err(format!("Cannot read updater script output: {error}"));
        }
        Err(_) => {
            kill_child_group(&child);
            return Err("Updater script timed out".into());
        }
    }
    if output.len() > SCRIPT_STDOUT_LIMIT {
        kill_child_group(&child);
        let _ = child.kill().await;
        return Err("Updater script output exceeded 16 KiB".into());
    }
    let status = match timeout_at(deadline, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            kill_child_group(&child);
            return Err(format!("Cannot wait for updater script: {error}"));
        }
        Err(_) => {
            kill_child_group(&child);
            return Err("Updater script timed out".into());
        }
    };
    let text = String::from_utf8(output)
        .map_err(|_| "Updater script output is not valid UTF-8".to_string())?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|_| "Updater script did not return a valid JSON object".to_string())?;
    if !value.is_object() {
        return Err("Updater script JSON response must be an object".into());
    }
    Ok(ScriptOutput {
        code: status.code(),
        json: value,
    })
}

fn script_message(value: &Value, fallback: &str) -> String {
    value
        .get("error")
        .or_else(|| value.get("message"))
        .and_then(Value::as_str)
        .filter(|message| !message.trim().is_empty())
        .unwrap_or(fallback)
        .chars()
        .take(2048)
        .collect()
}

fn script_failure(output: ScriptOutput, fallback: &str) -> String {
    script_message(&output.json, fallback)
}

fn base_args(command: &str) -> Vec<String> {
    vec![command.into()]
}

fn version_target_args(command: &str, mirror: &str) -> Vec<String> {
    let mut args = base_args(command);
    args.extend([
        "--current-version".into(),
        CURRENT_VERSION.into(),
        "--target".into(),
        BUILD_TARGET.into(),
        "--mirror".into(),
        mirror.into(),
    ]);
    args
}

async fn call_check(mirror: &str) -> Result<ScriptOutput, String> {
    let output = run_script(&version_target_args("check", mirror), CHECK_TIMEOUT).await?;
    if output.code != Some(0) {
        return Err(script_failure(output, "Updater check command failed"));
    }
    if output.json.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(script_message(
            &output.json,
            "Updater could not check for updates",
        ));
    }
    if output.json.get("current_version").and_then(Value::as_str) != Some(CURRENT_VERSION)
        || output.json.get("target").and_then(Value::as_str) != Some(BUILD_TARGET)
    {
        return Err(
            "Updater check response version or target did not match the running Core".into(),
        );
    }
    if output
        .json
        .get("update_available")
        .and_then(Value::as_bool)
        .is_none()
        || output
            .json
            .get("installable")
            .and_then(Value::as_bool)
            .is_none()
    {
        return Err("Updater check response is missing update availability fields".into());
    }
    Ok(output)
}

pub async fn api_check(ctx: &Ctx) -> Response {
    let mirror = match valid_mirror(&ctx.prefs().update_mirror) {
        Some(mirror) => mirror,
        None => return fail(1, "Invalid update source", Value::Null),
    };
    let current = ctx.st.settings.version.clone();
    if !script_is_executable() {
        return ok(json!({
            "supported": false,
            "current_version": current,
            "latest": null,
            "has_update": false,
            "mirror": mirror,
            "target": BUILD_TARGET
        }));
    }
    match call_check(mirror).await {
        Ok(output) => {
            let value = output.json;
            let latest = value.get("latest_version").cloned().unwrap_or(Value::Null);
            let has_update = value
                .get("update_available")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let installable = value
                .get("installable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            ok(json!({
                "supported": true,
                "current_version": current,
                "latest": latest,
                "has_update": has_update,
                "installable": installable,
                "asset_version": value.get("asset_version").cloned().unwrap_or(Value::Null),
                "message": value.get("message").cloned().unwrap_or(Value::Null),
                "mirror": mirror,
                "target": BUILD_TARGET
            }))
        }
        Err(error) => fail(
            1,
            &error,
            json!({
                "supported": true,
                "current_version": current,
                "mirror": mirror,
                "target": BUILD_TARGET
            }),
        ),
    }
}

fn launch_args(task_id: &str, mirror: &str) -> Vec<String> {
    let mut args = base_args("start");
    args.extend([
        "--task-id".into(),
        task_id.into(),
        "--current-version".into(),
        CURRENT_VERSION.into(),
        "--target".into(),
        BUILD_TARGET.into(),
        "--mirror".into(),
        mirror.into(),
    ]);
    args
}

pub async fn api_start(ctx: &Ctx) -> Response {
    if let Err(error) = ctx.require_post() {
        return error.into_response();
    }
    let mirror = match valid_mirror(&ctx.prefs().update_mirror) {
        Some(mirror) => mirror,
        None => return fail(1, "Invalid update source", Value::Null),
    };
    if !script_is_executable() {
        return fail_status(
            StatusCode::NOT_IMPLEMENTED,
            1,
            "Updater script is missing or not executable",
            json!({ "supported": false }),
        );
    }

    // Only acknowledge the generated ID after the script confirms persistence.
    // The script owns the authoritative check and worker lifecycle.
    let id = format!("hc-{}", crate::uci::random_hex(12));
    let result = run_script(&launch_args(&id, mirror), START_TIMEOUT).await;
    if let Ok(output) = &result {
        if output.code == Some(0)
            && output.json.get("task_id").and_then(Value::as_str) == Some(id.as_str())
        {
            if let Some(state) = output.json.get("state").and_then(Value::as_str) {
                if ["queued", "running", "succeeded", "failed"].contains(&state) {
                    return ok(json!({
                        "task_id": id,
                        "supported": true,
                        "state": state,
                        "message": output.json.get("message").cloned().unwrap_or(Value::Null)
                    }));
                }
            }
        }
    }

    // A command timeout or malformed acknowledgement can happen after the
    // script has persisted its record. Return the ID only if status confirms it.
    if let Some(response) = confirmed_start_response(&id).await {
        return response;
    }
    let message = match &result {
        Ok(output) if output.code != Some(0) => {
            script_message(&output.json, "Updater could not start the update task")
        }
        Ok(_) => "Updater start response was invalid".to_string(),
        Err(error) => error.clone(),
    };
    fail_status(
        StatusCode::BAD_GATEWAY,
        1,
        &message,
        json!({ "supported": true }),
    )
}

fn api_task(
    task_id: &str,
    state: &str,
    phase: &str,
    progress: u64,
    downloaded: u64,
    total: u64,
    message: &str,
) -> Value {
    let done = matches!(state, "succeeded" | "failed");
    let success = state == "succeeded";
    json!({
        "supported": true,
        "task_id": task_id,
        "state": state,
        "done": done,
        "success": success,
        "phase": phase,
        "progress": progress,
        "downloaded": downloaded,
        "total": total,
        "message": message,
        "log": message
    })
}

fn validated_status(value: &Value, task_id: &str) -> Result<Value, String> {
    if value.get("task_id").and_then(Value::as_str) != Some(task_id) {
        return Err("Updater status response did not match the requested task".into());
    }
    let state = value.get("state").and_then(Value::as_str).unwrap_or("");
    if !["queued", "running", "succeeded", "failed"].contains(&state) {
        return Err("Updater status response has an invalid state".into());
    }
    let phase = match value.get("phase") {
        None | Some(Value::Null) => state,
        Some(raw) => raw
            .as_str()
            .filter(|phase| phase.len() <= 128)
            .ok_or_else(|| "Updater status phase is invalid".to_string())?,
    };
    let progress = match value.get("progress") {
        None | Some(Value::Null) => 0,
        Some(raw) => raw
            .as_u64()
            .filter(|progress| *progress <= 100)
            .ok_or_else(|| "Updater status progress is invalid".to_string())?,
    };
    let downloaded = match value.get("downloaded") {
        None | Some(Value::Null) => 0,
        Some(raw) => raw
            .as_u64()
            .ok_or_else(|| "Updater downloaded byte count is invalid".to_string())?,
    };
    let total = match value.get("total") {
        None | Some(Value::Null) => 0,
        Some(raw) => raw
            .as_u64()
            .ok_or_else(|| "Updater total byte count is invalid".to_string())?,
    };
    let message_value = if state == "failed" {
        value.get("error").or_else(|| value.get("message"))
    } else {
        value.get("message")
    };
    let message = match message_value {
        None | Some(Value::Null) => "",
        Some(raw) => raw
            .as_str()
            .ok_or_else(|| "Updater status message is invalid".to_string())?,
    };
    if state == "failed" && message.trim().is_empty() {
        return Err("Updater failure status is missing an error message".into());
    }
    Ok(api_task(
        task_id,
        state,
        phase,
        progress,
        downloaded,
        total,
        &message.chars().take(2048).collect::<String>(),
    ))
}

async fn confirmed_start_response(task_id: &str) -> Option<Response> {
    let mut args = base_args("status");
    args.extend(["--task-id".into(), task_id.into()]);
    let output = run_script(&args, STATUS_TIMEOUT).await.ok()?;
    if output.code != Some(0) {
        return None;
    }
    let data = validated_status(&output.json, task_id).ok()?;
    Some(ok(json!({
        "task_id": task_id,
        "supported": true,
        "state": data.get("state").cloned().unwrap_or(Value::Null),
        "message": data.get("message").cloned().unwrap_or(Value::Null)
    })))
}

pub async fn api_status(ctx: &Ctx) -> Response {
    let task_id = ctx.params.get("task_id").unwrap_or_default();
    if !task_id_valid(&task_id) {
        return fail_status(
            StatusCode::BAD_REQUEST,
            1,
            "Invalid update task ID",
            Value::Null,
        );
    }
    let mut args = base_args("status");
    args.extend(["--task-id".into(), task_id.clone()]);
    match run_script(&args, STATUS_TIMEOUT).await {
        Ok(output) if output.code == Some(0) => match validated_status(&output.json, &task_id) {
            Ok(data) => ok(data),
            Err(error) => fail(1, &error, json!({ "supported": true, "task_id": task_id })),
        },
        Ok(output) => {
            let message = script_failure(output, "Updater status command failed");
            fail_status(
                StatusCode::BAD_GATEWAY,
                1,
                &message,
                json!({ "supported": true, "task_id": task_id }),
            )
        }
        Err(error) => fail_status(
            StatusCode::BAD_GATEWAY,
            1,
            &error,
            json!({ "supported": true, "task_id": task_id }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_ids_are_safe_single_argv_values() {
        assert!(task_id_valid("hc-a1b2c3"));
        assert!(!task_id_valid(""));
        assert!(!task_id_valid("../bad"));
        assert!(!task_id_valid("id;reboot"));
        assert!(!task_id_valid(&"a".repeat(65)));
    }

    #[test]
    fn status_validation_requires_task_identity_and_terminal_state_semantics() {
        let active = json!({
            "task_id":"hc-1", "state":"running",
            "phase":"install", "progress":45, "downloaded":10, "total":20, "message":"Installing"
        });
        let api = validated_status(&active, "hc-1").unwrap();
        assert_eq!(api["done"], false);
        assert_eq!(api["success"], false);
        assert_eq!(api["progress"], 45);
        assert!(validated_status(&active, "hc-other").is_err());
        let complete = json!({"task_id":"hc-1","state":"succeeded"});
        assert_eq!(
            validated_status(&complete, "hc-1").unwrap()["success"],
            true
        );
    }

    #[test]
    fn start_arguments_are_fixed_and_include_task_version_target_mirror() {
        let args = launch_args("hc-id", "gitee");
        assert_eq!(args[0], "start");
        assert_eq!(args[1], "--task-id");
        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "--target" && pair[1] == BUILD_TARGET));
        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "--mirror" && pair[1] == "gitee"));
        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "--task-id" && pair[1] == "hc-id"));
    }
}
