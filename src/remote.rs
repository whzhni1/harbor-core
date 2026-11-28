use crate::meta;
use crate::params::Params;
use crate::paths::{join_path, normalize_path, parent_path, path_name, valid_component};
use crate::reply::{fail, ok};
use crate::security::secret_store;
use crate::ssh::{self, Target, Workspace};
use crate::state::AppState;
use crate::uci::Uci;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const RUNTIME_DIR: &str = "/tmp/harbor_file_pro";
pub const REMOTE_ROOT: &str = "/tmp/harbor_file_pro/remote";
const SPACE_MARGIN: i64 = 16 * 1024 * 1024;
const MAX_PATHS: usize = 4096;
const COMMAND_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct RemoteError {
    pub code: i64,
    pub message: String,
    pub data: Value,
}

impl RemoteError {
    pub fn new(message: impl Into<String>) -> Self {
        RemoteError {
            code: 1,
            message: message.into(),
            data: Value::Null,
        }
    }

    pub fn system_access_required() -> Self {
        RemoteError::with_data(
            "System folder access requires verification",
            json!({ "system_access_required": true }),
        )
    }

    pub fn system_access_required_at(path: &str, device_id: &str) -> Self {
        RemoteError::with_data(
            "System folder access requires verification",
            json!({"system_access_required": true, "path": path, "device_id": device_id}),
        )
    }

    pub fn with_data(message: impl Into<String>, data: Value) -> Self {
        Self::with_code_data(1, message, data)
    }

    pub fn with_code_data(code: i64, message: impl Into<String>, data: Value) -> Self {
        RemoteError {
            code,
            message: message.into(),
            data,
        }
    }

    pub fn missing_tool(tool: &str, package: &str, message: impl Into<String>) -> Self {
        RemoteError::with_data(
            message,
            json!({
                "missing_tool": tool,
                "package_name": package,
                "dependency_preflight": true,
                "stat_missing": tool == "stat",
            }),
        )
    }

    pub fn response(self) -> axum::response::Response {
        fail(self.code, &self.message, self.data)
    }
}

impl From<String> for RemoteError {
    fn from(message: String) -> Self {
        RemoteError::new(message)
    }
}

impl From<&str> for RemoteError {
    fn from(message: &str) -> Self {
        RemoteError::new(message)
    }
}

type RResult<T> = Result<T, RemoteError>;

pub(crate) fn safe_preflight(mut error: RemoteError) -> RemoteError {
    if error.data["outcome_unknown"] == json!(true) || error.data["partial"] == json!(true) {
        return error;
    }
    if !error.data.is_object() {
        error.data = json!({});
    }
    error.data["preflight_safe"] = json!(true);
    error
}

#[derive(Clone, Debug)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub revision: String,
    pub host_key: String,
    pub has_password: bool,
}

impl Device {
    pub fn public_json(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "revision": self.revision,
            "trusted": !self.host_key.is_empty(),

            "has_password": self.has_password,
        })
    }
}

fn load_uci(st: &AppState) -> Uci {
    Uci::load(&st.settings.config_path).unwrap_or_default()
}

pub fn devices(st: &AppState) -> Vec<Device> {
    let uci = load_uci(st);
    let store = secret_store(st);
    let mut result = Vec::new();
    let legacy_passwords_present = uci.of_kind("remote_device").iter().any(|section| {
        section
            .get("password")
            .map(|value| !value.is_empty())
            .unwrap_or(false)
    });
    for section in uci.of_kind("remote_device") {
        let id = section.name.clone();
        result.push(Device {
            name: section.get("name").unwrap_or("").to_string(),
            host: section.get("host").unwrap_or("").to_string(),
            port: section
                .get("port")
                .and_then(|p| p.trim().parse::<u16>().ok())
                .filter(|p| *p > 0)
                .unwrap_or(22),
            username: section.get("username").unwrap_or("").to_string(),
            revision: section.get("revision").unwrap_or("").to_string(),
            host_key: section.get("host_key").unwrap_or("").to_string(),
            has_password: store.has(&id),
            id,
        });
    }
    if legacy_passwords_present && scrub_plaintext_passwords(st).is_err() {
        eprintln!("harbor-core: cannot scrub obsolete plaintext passwords from UCI");
    }
    result
}

fn scrub_plaintext_passwords(st: &AppState) -> Result<(), String> {
    let mut uci = load_uci(st);
    let ids: Vec<String> = uci
        .of_kind("remote_device")
        .iter()
        .filter(|s| s.get("password").map(|p| !p.is_empty()).unwrap_or(false))
        .map(|s| s.name.clone())
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    for id in ids {
        if let Some(section) = uci.section_mut(&id) {
            section.remove("password");
        }
    }
    uci.save(&st.settings.config_path)
        .map_err(|e| e.to_string())?;
    restrict_config_permissions(&st.settings.config_path);
    Ok(())
}

fn restrict_config_permissions(path: &str) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

pub fn find_device(st: &AppState, id: &str) -> Option<Device> {
    devices(st).into_iter().find(|d| d.id == id)
}

pub fn checked_device(st: &AppState, id: &str, revision: Option<&str>) -> RResult<Device> {
    if id.is_empty() {
        return Err(RemoteError::new("Device not found"));
    }
    let device = find_device(st, id).ok_or_else(|| RemoteError::new("Device not found"))?;
    if let Some(revision) = revision {
        if !revision.is_empty() && revision != device.revision {
            return Err(RemoteError::new(
                "Device settings changed; reopen the device",
            ));
        }
    }
    Ok(device)
}

pub fn ensure_trusted_pub(st: &AppState, device: &Device) -> RResult<()> {
    ensure_trusted(st, device)
}

fn connection_settings(st: &AppState) -> (u64, usize) {
    let uci = load_uci(st);
    let section = uci.section(crate::config::CONFIG_SECTION);
    let idle = section
        .and_then(|s| s.get("remote_ssh_idle_timeout"))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(300)
        .clamp(30, 3600);
    let max = section
        .and_then(|s| s.get("remote_ssh_max_sessions"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(1, 16);
    (idle, max)
}

fn connection_settings_json(st: &AppState) -> Value {
    let (idle, max) = connection_settings(st);
    json!({
        "idle_timeout": idle,
        "max_sessions": max,
    })
}

fn save_connection_settings(st: &AppState, params: &Params) -> RResult<Value> {
    let idle = params
        .get("idle_timeout")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| (30..=3600).contains(v))
        .ok_or_else(|| RemoteError::new("SSH idle timeout must be 30–3600 seconds"))?;
    let max = params
        .get("max_sessions")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| (1..=16).contains(v))
        .ok_or_else(|| RemoteError::new("Maximum SSH sessions must be 1–16"))?;
    crate::config::save_values(
        &st.settings.config_path,
        &[
            ("remote_ssh_idle_timeout".into(), idle.to_string()),
            ("remote_ssh_max_sessions".into(), max.to_string()),
        ],
    )
    .map_err(RemoteError::new)?;
    ssh::close_all_sessions();
    Ok(connection_settings_json(st))
}

fn target_for(st: &AppState, device: &Device, password: Option<String>) -> Target {
    let (idle_timeout_secs, max_sessions) = connection_settings(st);
    Target {
        id: device.id.clone(),
        host: device.host.clone(),
        port: device.port,
        username: device.username.clone(),
        password,
        host_key: device.host_key.clone(),
        idle_timeout_secs,
        max_sessions,
    }
}

pub fn authenticated_target(st: &AppState, device: &Device) -> Target {
    let password = secret_store(st).get(&device.id).map(|p| p.to_string());
    target_for(st, device, password)
}

fn local_tool(name: &str) -> bool {
    meta::have_tool(name)
}

pub fn local_tool_available(name: &str) -> bool {
    match name {
        "stat" => tool_info(None).map(|info| info.stat).unwrap_or(false),
        _ => local_tool(name),
    }
}

pub fn device_tool_available(target: &Target, name: &str) -> RResult<bool> {
    if !crate::tools::valid_name(name) {
        return Err(RemoteError::new("Invalid tool name"));
    }
    if name == "stat" {
        return Ok(tool_info(Some(target))?.stat);
    }
    if name == "sftp" {
        return Ok(matches!(
            ssh::sftp::ensure_sftp(target).map_err(RemoteError::new)?,
            ssh::sftp::SftpStatus::Ready
        ));
    }
    let script = format!(
        "if command -v {} >/dev/null 2>&1; then printf yes; else printf no; fi",
        shell_quote(name)
    );
    let raw = run(target, &script, Some(30))?;
    Ok(String::from_utf8_lossy(&raw).trim() == "yes")
}

fn require_tool(name: &str, package: &str) -> RResult<()> {
    if local_tool_available(name) {
        return Ok(());
    }
    Err(RemoteError::missing_tool(
        name,
        package,
        format!("{name} is not installed"),
    ))
}

pub fn workspace_pub(target: &Target) -> RResult<Workspace> {
    workspace(target)
}

fn workspace(target: &Target) -> RResult<Workspace> {
    crate::tasks::ensure_remote_dir().map_err(|_| RemoteError::new("Unsafe runtime directory"))?;
    let identity = format!(
        "{}\0{}\0{}\0{}\0{}",
        target.id, target.host, target.port, target.username, target.host_key
    );
    let key = format!(
        "ws-{}",
        hex::encode(crate::auth::sha256_bytes(identity.as_bytes()))
    );
    Workspace::shared(REMOTE_ROOT, &key).map_err(RemoteError::new)
}

pub fn run(target: &Target, script: &str, timeout: Option<u64>) -> RResult<Vec<u8>> {
    run_args(target, script, &[], timeout)
}

pub fn enforce_configured_root(
    st: &AppState,
    target: Option<&Target>,
    path: &str,
) -> Result<(), RemoteError> {
    enforce_configured_roots(st, target, &[path.to_string()])
}

pub(crate) fn parse_policy_frames(bytes: &[u8]) -> RResult<Vec<String>> {
    if bytes.is_empty() || bytes.len() >= 16 * 1024 * 1024 || bytes.last() != Some(&0) {
        return Err(RemoteError::new("Cannot resolve path for policy"));
    }
    bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .map(|value| {
            std::str::from_utf8(value)
                .ok()
                .and_then(normalize_path)
                .ok_or_else(|| RemoteError::new("Cannot resolve path for policy"))
        })
        .collect()
}

pub(crate) fn resolve_policy_paths(
    target: Option<&Target>,
    paths: &[String],
) -> RResult<Vec<String>> {
    let normalized: Vec<String> = paths
        .iter()
        .map(|path| normalize_path(path).ok_or_else(|| RemoteError::new("Invalid path")))
        .collect::<Result<_, _>>()?;
    let resolved: Vec<String> = if let Some(target) = target {
        let make = |batch: &[String]| {
            let words = batch
                .iter()
                .map(|path| ssh::shell_quote(path))
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                r#"set -e
for p in {words}; do
    suffix=''
    while [ ! -e "$p" ] && [ ! -L "$p" ]; do
        [ "$p" != / ] || exit 44
        name="${{p##*/}}"
        suffix="/$name$suffix"
        parent="${{p%/*}}"
        [ -n "$parent" ] || parent=/
        p="$parent"
    done
    # The sentinel preserves newlines in resolved paths through command substitution.
    base=$(readlink -fn "$p" && printf '.') || exit 44
    base=${{base%.}}
    if [ "$base" = / ]; then printf '%s%s\0' "$base" "${{suffix#/}}"; else printf '%s%s\0' "$base" "$suffix"; fi
done
"#
            )
        };
        let mut batches: Vec<Vec<String>> = Vec::new();
        let mut batch = Vec::new();
        for path in &normalized {
            batch.push(path.clone());
            if batch.len() > 1 && ssh::script_exec_len(&make(&batch)) > ssh::SCRIPT_EXEC_LIMIT {
                let last = batch.pop().unwrap();
                batches.push(std::mem::take(&mut batch));
                batch.push(last);
            }
            if ssh::script_exec_len(&make(&batch)) > ssh::SCRIPT_EXEC_LIMIT {
                return Err(RemoteError::new("Path is too long to resolve safely"));
            }
        }
        if !batch.is_empty() {
            batches.push(batch);
        }
        let mut resolved = Vec::new();
        let mut total = 0usize;
        for batch in batches {
            let bytes = run(target, &make(&batch), Some(30))?;
            total = total.saturating_add(bytes.len());
            if total >= COMMAND_OUTPUT_LIMIT {
                return Err(RemoteError::new("Resolved paths exceed the safety limit"));
            }
            let values = parse_policy_frames(&bytes)?;
            if values.len() != batch.len() {
                return Err(RemoteError::new("Cannot resolve path for policy"));
            }
            resolved.extend(values);
        }
        resolved
    } else {
        normalized
            .iter()
            .map(|path| {
                crate::paths::canonical_for_policy(path)
                    .ok_or_else(|| RemoteError::new("Invalid path"))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    if resolved.len() != normalized.len() {
        return Err(RemoteError::new("Cannot resolve path for policy"));
    }
    Ok(resolved)
}

pub fn enforce_configured_roots(
    st: &AppState,
    target: Option<&Target>,
    paths: &[String],
) -> Result<(), RemoteError> {
    let policy = st.root_policy_config();
    if policy.policy == crate::state::RootPolicy::Unrestricted {
        return Ok(());
    }
    let resolved = resolve_policy_paths(target, paths)?;
    if resolved.iter().all(|path| {
        crate::paths::path_allowed_by_policy(
            policy.policy,
            &policy.roots,
            &policy.excluded_roots,
            path,
        )
    }) {
        Ok(())
    } else {
        Err(RemoteError::new(crate::paths::root_policy_error(
            policy.policy,
        )))
    }
}

pub fn run_args(
    target: &Target,
    script: &str,
    args: &[String],
    timeout: Option<u64>,
) -> RResult<Vec<u8>> {
    let space = workspace(target)?;
    let output = ssh::run_args(target, &space, script, args, timeout, COMMAND_OUTPUT_LIMIT)?;
    if output.timed_out {
        return Err(RemoteError::with_data(
            "SSH command timed out",
            json!({"timed_out": true}),
        ));
    }
    if !output.ok() {
        return Err(RemoteError::with_data(
            command_failure(&output),
            json!({"exit_code": output.status}),
        ));
    }
    if output.stdout_truncated || output.stdout_read_failed {
        return Err(RemoteError::new(
            "SSH command output was incomplete or exceeded the limit",
        ));
    }
    Ok(output.stdout)
}

pub fn run_mutating_once(target: &Target, script: &str, timeout: Option<u64>) -> RResult<Vec<u8>> {
    let space = workspace(target)?;
    let output = ssh::run_args_once(target, &space, script, &[], timeout, COMMAND_OUTPUT_LIMIT)
        .map_err(RemoteError::new)?;
    mutating_output(output)
}

pub fn run_mutating_once_logged(
    target: &Target,
    script: &str,
    timeout: Option<u64>,
    log: &Path,
) -> RResult<Vec<u8>> {
    let space = workspace(target)?;
    let output = ssh::run_args_once(target, &space, script, &[], timeout, COMMAND_OUTPUT_LIMIT)
        .map_err(RemoteError::new)?;
    let mut body = String::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for chunk in [stdout.as_ref(), stderr.as_ref()] {
        let chunk = chunk.trim_end();
        if chunk.is_empty() {
            continue;
        }
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(chunk);
    }
    if body.is_empty() {
        body = if output.ok() {
            "Installation finished".into()
        } else {
            format!("Command failed (exit {})", output.status.unwrap_or(-1))
        };
    }
    body.push('\n');
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
    {
        let _ = file.write_all(body.as_bytes());
    }
    mutating_output(output)
}

fn mutating_output(output: crate::ssh::Output) -> RResult<Vec<u8>> {
    if output.timed_out || output.status.is_none() || output.status == Some(255) {
        return Err(RemoteError::with_data(
            "Remote operation outcome is unknown; check the destination before retrying",
            json!({"outcome_unknown": true}),
        ));
    }
    if !output.ok() {
        return Err(RemoteError::with_data(
            command_failure(&output),
            json!({"exit_code": output.status}),
        ));
    }
    if output.stdout_truncated || output.stdout_read_failed {
        return Err(RemoteError::with_data(
            "Remote operation result is incomplete; check the destination before retrying",
            json!({"outcome_unknown": true}),
        ));
    }
    Ok(output.stdout)
}

fn command_failure(output: &crate::ssh::Output) -> String {
    let detail = output.stderr_tail(4096);
    if !detail.is_empty() {
        return detail;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_tail = stdout.trim();
    if !stdout_tail.is_empty() {
        let chars: Vec<char> = stdout_tail.chars().collect();
        let start = chars.len().saturating_sub(1024);
        return chars[start..].iter().collect();
    }
    match output.status {
        Some(code) => format!("SSH command failed (exit {code})"),
        None => "SSH command failed".to_string(),
    }
}

pub fn run_cancelled(
    target: &Target,
    script: &str,
    timeout: Option<u64>,
    cancelled: Arc<AtomicBool>,
) -> RResult<Vec<u8>> {
    let space = workspace(target)?;
    let output = ssh::run_args_cancelled(
        target,
        &space,
        script,
        &[],
        timeout,
        COMMAND_OUTPUT_LIMIT,
        cancelled,
    )
    .map_err(RemoteError::new)?;
    if output.timed_out {
        return Err(RemoteError::new("SSH command timed out"));
    }
    if !output.ok() {
        return Err(RemoteError::new(command_failure(&output)));
    }
    if output.stdout_truncated || output.stdout_read_failed {
        return Err(RemoteError::new(
            "SSH command output was incomplete or exceeded the limit",
        ));
    }
    Ok(output.stdout)
}

fn trusted_host_key(key: &str) -> bool {
    let key = key.trim();
    key.starts_with("SHA256:")
        && key.len() > "SHA256:".len()
        && !key.as_bytes().iter().any(u8::is_ascii_whitespace)
}

pub fn ensure_trusted(st: &AppState, device: &Device) -> RResult<()> {
    if trusted_host_key(&device.host_key) {
        return Ok(());
    }
    let probe = target_for(st, device, None);
    let space = workspace(&probe)?;
    let (host_key, fingerprint) = ssh::probe_host_key(&probe, &space).map_err(RemoteError::new)?;
    let challenge = crate::uci::random_hex(16);
    let payload = json!({
        "id": device.id,
        "host": device.host,
        "port": device.port,
        "key": host_key,
        "expires": meta::now_secs() + 300,
    });
    let path = format!("{REMOTE_ROOT}/trust-{challenge}");
    std::fs::write(&path, payload.to_string())
        .map_err(|_| RemoteError::new("Cannot save host key"))?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Err(RemoteError::with_code_data(
        11,
        "Confirm SSH host key fingerprint",
        json!({
            "challenge": challenge,
            "device_id": device.id,
            "name": device.name,
            "host": device.host,
            "port": device.port,
            "fingerprint": fingerprint,
        }),
    ))
}

fn confirm_trust(st: &AppState, challenge: &str, device_id: &str) -> RResult<()> {
    if challenge.len() != 32 || !challenge.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RemoteError::new("Invalid host key confirmation"));
    }
    let path = format!("{REMOTE_ROOT}/trust-{challenge}");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    let payload: Value = serde_json::from_str(&text)
        .map_err(|_| RemoteError::new("Host key confirmation expired"))?;
    let device = find_device(st, device_id).ok_or_else(|| RemoteError::new("Device not found"))?;
    let expires = payload["expires"].as_i64().unwrap_or(0);
    if payload["id"].as_str() != Some(device.id.as_str())
        || payload["host"].as_str() != Some(device.host.as_str())
        || payload["port"].as_i64() != Some(device.port as i64)
        || expires < meta::now_secs()
    {
        return Err(RemoteError::new("Host key confirmation expired"));
    }
    let key = payload["key"].as_str().unwrap_or("").to_string();
    if trusted_host_key(&device.host_key) && device.host_key != key {
        return Err(RemoteError::new(
            "Host key was already confirmed; reconnect",
        ));
    }
    let mut uci = load_uci(st);
    {
        let section = uci
            .section_mut(&device.id)
            .ok_or_else(|| RemoteError::new("Device not found"))?;
        section.set("host_key", &key);
    }
    uci.save(&st.settings.config_path)
        .map_err(|_| RemoteError::new("Cannot save host key"))?;
    restrict_config_permissions(&st.settings.config_path);
    Ok(())
}

const TOOL_INFO_SCRIPT: &str = "stat_kind=missing\nif command -v stat >/dev/null 2>&1 && stat -c '%s %Y %a' / >/dev/null 2>&1; then\n stat_kind=command\nelif command -v gnu-stat >/dev/null 2>&1 && gnu-stat -c '%s %Y %a' / >/dev/null 2>&1; then\n stat_kind=command\nelif /usr/libexec/stat-coreutils -c '%s %Y %a' / >/dev/null 2>&1; then\n stat_kind=command\nelif busybox stat -c '%s %Y %a' / >/dev/null 2>&1; then\n stat_kind=busybox\nfi\nprintf \"%s\\n\" \"$stat_kind\"\nif command -v apk >/dev/null 2>&1; then echo apk; elif command -v opkg >/dev/null 2>&1; then echo opkg; elif command -v apt-get >/dev/null 2>&1; then echo apt; elif command -v dnf >/dev/null 2>&1; then echo dnf; elif command -v yum >/dev/null 2>&1; then echo yum; elif command -v pacman >/dev/null 2>&1; then echo pacman; else echo none; fi\nif [ \"$(id -u)\" = 0 ]; then echo 0; elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then echo 0; else echo 1; fi\n";

#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub stat: bool,
    pub stat_provider: String,
    pub installer: String,
    pub can_install: bool,
    pub root: bool,
}

fn tool_info_cache() -> &'static Mutex<HashMap<String, (ToolInfo, Instant)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (ToolInfo, Instant)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn tool_info_cache_key(target: &Target) -> String {
    format!("{}:{}:{}", target.id, target.host, target.port)
}

pub(crate) fn invalidate_tool_info(target: &Target) {
    if let Ok(mut guard) = tool_info_cache().lock() {
        guard.remove(&tool_info_cache_key(target));
    }
}

fn tool_info(target: Option<&Target>) -> RResult<ToolInfo> {
    tool_info_cached(target, false)
}

fn tool_info_cached(target: Option<&Target>, fresh: bool) -> RResult<ToolInfo> {
    if let Some(target) = target {
        let cache = tool_info_cache();
        let key = tool_info_cache_key(target);
        if !fresh {
            if let Ok(guard) = cache.lock() {
                if let Some((info, at)) = guard.get(&key) {
                    if at.elapsed() < Duration::from_secs(120) {
                        return Ok(info.clone());
                    }
                }
            }
        }
        let info = tool_info_uncached(Some(target))?;
        if let Ok(mut guard) = cache.lock() {
            guard.insert(key, (info.clone(), Instant::now()));
        }
        return Ok(info);
    }
    tool_info_uncached(None)
}

fn tool_info_uncached(target: Option<&Target>) -> RResult<ToolInfo> {
    let raw = match target {
        Some(target) => run(target, TOOL_INFO_SCRIPT, Some(30))?,
        None => {
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(TOOL_INFO_SCRIPT)
                .output()
                .map_err(|_| RemoteError::new("Cannot inspect local tools"))?;
            output.stdout
        }
    };
    let text = String::from_utf8_lossy(&raw);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() < 3 {
        return Err(RemoteError::new("Invalid remote tool response"));
    }
    let provider = lines[0].to_string();
    if !["command", "busybox", "missing"].contains(&provider.as_str()) {
        return Err(RemoteError::new("Invalid remote tool response"));
    }
    let installer = lines[1].to_string();
    if !["apk", "opkg", "apt", "dnf", "yum", "pacman", "none"].contains(&installer.as_str()) {
        return Err(RemoteError::new("Invalid remote tool response"));
    }
    let uid: u32 = lines[2].parse().unwrap_or(1);
    let (installer, root) = if target.is_none() {
        (
            crate::api::archops::detect_package_manager()
                .unwrap_or("none")
                .to_string(),
            unsafe { libc::geteuid() } == 0,
        )
    } else {
        (installer, uid == 0)
    };
    Ok(ToolInfo {
        stat: provider != "missing",
        stat_provider: provider,
        can_install: installer != "none" && root,
        root,
        installer,
    })
}

#[derive(Debug, Clone)]
pub struct RemoteItem {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: i64,
    pub mtime: i64,
    pub mode: String,
    pub is_symlink: bool,
    pub link_target: String,
}

impl RemoteItem {
    pub fn json(&self) -> Value {
        meta::item_json(meta::ItemView {
            name: &self.name,
            path: &self.path,
            is_directory: matches!(self.kind.as_str(), "directory" | "directory_link"),
            is_symlink: self.is_symlink,
            size: self.size,
            mtime: self.mtime,
            mode: &self.mode,
            link_target: (!self.link_target.is_empty()).then_some(self.link_target.as_str()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Listing {
    pub path: String,
    pub physical: String,
    pub parent: String,
    pub items: Vec<RemoteItem>,
    pub available_bytes: i64,
    pub total_bytes: i64,
    pub used_bytes: i64,
    pub drives: Vec<Value>,
}

impl Listing {
    pub fn json(&self, capacity: bool) -> Value {
        let mut value = json!({
            "path": self.path,
            "physical": self.physical,
            "parent": self.parent,
            "available_bytes": self.available_bytes,
            "total_bytes": self.total_bytes,
            "used_bytes": self.used_bytes,
            "operation_space_margin": SPACE_MARGIN,
            "has_operation_space": self.available_bytes >= SPACE_MARGIN,
            "drives": Value::Array(self.drives.clone()),
        });
        if !capacity {
            value["items"] = Value::Array(
                self.items
                    .iter()
                    .map(|item| item.json())
                    .collect::<Vec<_>>(),
            );
        }
        value
    }
}

pub(crate) fn map_sftp(error: ssh::sftp::SftpError) -> RemoteError {
    match error {
        ssh::sftp::SftpError::Missing | ssh::sftp::SftpError::Disabled => {
            RemoteError::missing_tool(
                "sftp",
                "openssh-sftp-server",
                "openssh-sftp-server is required to open this device",
            )
        }
        ssh::sftp::SftpError::Unknown(text) => {
            RemoteError::with_data(text, json!({ "outcome_unknown": true }))
        }
        other => RemoteError::new(other.message()),
    }
}

fn remote_path(value: &str) -> RResult<String> {
    if value.contains('\0') {
        return Err(RemoteError::new("Invalid path"));
    }
    let path = normalize_path(value).ok_or_else(|| RemoteError::new("Invalid path"))?;
    if path.len() > 4096 {
        return Err(RemoteError::new("Invalid path"));
    }
    Ok(path)
}

pub fn listing(target: &Target, path: &str, capacity: bool) -> RResult<Listing> {
    let path = remote_path(path)?;
    let listed = match ssh::sftp::list_dir(target, &path, capacity) {
        Ok(listed) => listed,
        Err(error) => return Err(map_sftp(error)),
    };
    let mut items = Vec::new();
    for item in listed.items {
        items.push(RemoteItem {
            path: join_path(&path, &item.name),
            name: item.name,
            kind: item.kind.as_str().to_string(),
            size: item.size,
            mtime: item.mtime,
            mode: item.mode,
            is_symlink: item.is_symlink,
            link_target: item.link_target,
        });
    }
    Ok(Listing {
        path: path.clone(),
        parent: parent_path(&path).unwrap_or_else(|| "/".to_string()),
        physical: listed.physical,
        available_bytes: listed.available_bytes,
        total_bytes: listed.total_bytes,
        used_bytes: listed.used_bytes,
        items,
        drives: parse_drives(&listed.drives_raw),
    })
}

fn parse_drives(raw: &str) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut seen_mount: Vec<String> = Vec::new();
    let mut seen_name: Vec<String> = Vec::new();
    for line in raw.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let device = fields[0];
        let mount = fields[5..].join(" ");
        if !(mount == "/" || mount == "/tmp" || device.starts_with("/dev/")) {
            continue;
        }
        if crate::meta::HIDDEN_MOUNTS.contains(&mount.as_str()) || seen_mount.contains(&mount) {
            continue;
        }
        seen_mount.push(mount.clone());
        let name = crate::meta::drive_name(device, &mount);
        let key = name.to_lowercase();
        if seen_name.contains(&key) {
            continue;
        }
        seen_name.push(key);
        let kib =
            |index: usize| -> i64 { fields.get(index).and_then(|v| v.parse().ok()).unwrap_or(0) };
        out.push(crate::meta::drive_entry(
            device,
            &mount,
            kib(1),
            kib(2),
            kib(3),
        ));
    }
    if !seen_mount.iter().any(|m| m == "/") {
        out.insert(0, crate::meta::drive_entry("rootfs", "/", 0, 0, 0));
    }
    out
}

pub fn local_listing(path: &str) -> Result<Listing, String> {
    let real = crate::paths::canonical(path).ok_or_else(|| "Invalid path".to_string())?;
    let meta = crate::meta::stat(&real).ok_or_else(|| "Invalid path".to_string())?;
    if meta.kind != crate::meta::Kind::Directory {
        return Err("Not a directory".to_string());
    }
    let entries = std::fs::read_dir(&real).map_err(|_| "Cannot read directory".to_string())?;
    let mut items = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." || !valid_component(&name) {
            continue;
        }
        let child = join_path(&real, &name);
        let lst = match crate::meta::lstat(&child) {
            Some(info) => info,
            None => continue,
        };
        let info = crate::meta::stat(&child).unwrap_or(lst);
        let (kind, link_target) = match lst.kind {
            crate::meta::Kind::Directory => ("directory", String::new()),
            crate::meta::Kind::File => ("file", String::new()),
            crate::meta::Kind::Symlink => {
                let target = crate::meta::readlink(&child).unwrap_or_default();
                if crate::meta::stat(&child).map(|m| m.kind) == Some(crate::meta::Kind::Directory) {
                    ("directory_link", target)
                } else {
                    ("symlink", target)
                }
            }
            crate::meta::Kind::Other => ("special", String::new()),
        };
        items.push(RemoteItem {
            path: child.clone(),
            name,
            kind: kind.to_string(),
            size: info.size,
            mtime: info.mtime,
            mode: meta::mode_string(info.mode),
            is_symlink: lst.kind == crate::meta::Kind::Symlink,
            link_target,
        });
    }
    items.sort_by(|a, b| {
        let a_dir = a.kind == "directory" || a.kind == "directory_link";
        let b_dir = b.kind == "directory" || b.kind == "directory_link";
        b_dir
            .cmp(&a_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    let space = crate::meta::space_info(&real);
    Ok(Listing {
        parent: parent_path(&real).unwrap_or_else(|| "/".to_string()),
        path: path.to_string(),
        physical: real,
        items,
        available_bytes: space.available.unwrap_or(0) as i64,
        total_bytes: space.total.unwrap_or(0) as i64,
        used_bytes: space.used.unwrap_or(0) as i64,
        drives: crate::meta::list_drives(),
    })
}

pub use crate::ssh::shell_quote;

#[derive(Debug, Clone)]
pub struct TransferItem {
    pub source: RemoteItem,
    pub target_name: String,
}

#[derive(Debug)]
pub struct Plan {
    pub source: Option<Device>,
    pub target: Option<Device>,
    pub parent: String,
    pub dest: String,
    pub same_directory: bool,
    pub items: Vec<TransferItem>,
    pub conflicts: Vec<Value>,
    pub rename_names: serde_json::Map<String, Value>,
}

fn path_list(params: &Params, key: &str) -> RResult<Vec<String>> {
    let raw = params.get(key).unwrap_or_default();
    let parsed: Value =
        serde_json::from_str(&raw).map_err(|_| RemoteError::new("Invalid selection"))?;
    let array = parsed
        .as_array()
        .ok_or_else(|| RemoteError::new("Invalid selection"))?;
    if array.is_empty() || array.len() > MAX_PATHS {
        return Err(RemoteError::new("Invalid selection"));
    }
    array
        .iter()
        .map(|value| remote_path(value.as_str().unwrap_or("")))
        .collect()
}

fn resolved_system_scope(target: Option<&Target>, path: &str) -> Option<String> {
    if let Some(scope) = crate::paths::system_path_scope(path) {
        return Some(scope);
    }
    match target {
        Some(target) => crate::remote::run(
            target,
            &format!(
                "readlink -f -- {} 2>/dev/null",
                crate::remote::shell_quote(path)
            ),
            Some(10),
        )
        .ok()
        .and_then(|bytes| crate::paths::system_path_scope(String::from_utf8_lossy(&bytes).trim())),
        None => crate::paths::canonical(path)
            .and_then(|actual| crate::paths::system_path_scope(&actual)),
    }
}

fn require_system_scope(
    st: &AppState,
    session_id: &str,
    device_id: &str,
    scope: Option<String>,
) -> RResult<()> {
    if let Some(scope) = scope {
        if session_id.is_empty() || !st.system_access.allowed(session_id, device_id, &scope) {
            return Err(RemoteError::system_access_required());
        }
    }
    Ok(())
}

fn require_system_scope_at(
    st: &AppState,
    session_id: &str,
    device_id: &str,
    path: &str,
    scope: Option<String>,
) -> RResult<()> {
    if let Some(scope) = scope {
        if session_id.is_empty() || !st.system_access.allowed(session_id, device_id, &scope) {
            return Err(RemoteError::with_data(
                "System folder access requires verification",
                json!({ "system_access_required": true, "path": path, "device_id": device_id }),
            ));
        }
    }
    Ok(())
}

fn build_plan(st: &AppState, params: &Params) -> RResult<Plan> {
    let operation = params
        .get("operation")
        .unwrap_or_else(|| "copy".to_string());
    if operation != "copy" && operation != "move" {
        return Err(RemoteError::new("Invalid transfer operation"));
    }
    let source = {
        let id = params.get("source_device").unwrap_or_default();
        if id.is_empty() {
            None
        } else {
            Some(checked_device(
                st,
                &id,
                params.get("source_revision").as_deref(),
            )?)
        }
    };
    let target = {
        let id = params.get("target_device").unwrap_or_default();
        if id.is_empty() {
            None
        } else {
            Some(checked_device(
                st,
                &id,
                params.get("target_revision").as_deref(),
            )?)
        }
    };
    if source.is_none() && target.is_none() {
        return Err(RemoteError::new("A remote device is required"));
    }
    if let Some(device) = &source {
        ensure_trusted(st, device)?;
    }
    if let Some(device) = &target {
        ensure_trusted(st, device)?;
    }

    let dest = remote_path(&params.get("target_dir").unwrap_or_default())?;
    let paths = path_list(params, "sources")?;
    let parent = parent_path(&paths[0]).unwrap_or_else(|| "/".to_string());
    let session_id = params.get("__system_session_id").unwrap_or_default();
    let target_id = target
        .as_ref()
        .map(|device| device.id.as_str())
        .unwrap_or("");
    let source_id = source
        .as_ref()
        .map(|device| device.id.as_str())
        .unwrap_or("");
    require_system_scope_at(
        st,
        &session_id,
        target_id,
        &dest,
        crate::paths::system_path_scope(&dest),
    )?;
    for path in &paths {
        require_system_scope_at(
            st,
            &session_id,
            source_id,
            path,
            crate::paths::system_path_scope(path),
        )?;
    }
    let mut seen = std::collections::BTreeSet::new();
    for path in &paths {
        if path == "/"
            || parent_path(path).unwrap_or_default() != parent
            || !seen.insert(path.clone())
        {
            return Err(RemoteError::new("Select files from one directory"));
        }
    }

    let source_target = source.as_ref().map(|d| authenticated_target(st, d));
    let target_target = target.as_ref().map(|d| authenticated_target(st, d));
    enforce_configured_root(st, source_target.as_ref(), &parent)?;
    enforce_configured_root(st, target_target.as_ref(), &dest)?;
    for path in &paths {
        require_system_scope_at(
            st,
            &session_id,
            source_id,
            path,
            resolved_system_scope(source_target.as_ref(), path),
        )?;
    }
    require_system_scope_at(
        st,
        &session_id,
        target_id,
        &dest,
        resolved_system_scope(target_target.as_ref(), &dest),
    )?;
    let same = match (&source, &target) {
        (Some(a), Some(b)) => {
            a.host.eq_ignore_ascii_case(&b.host) && a.port == b.port && a.username == b.username
        }
        _ => false,
    };
    let source_listing = match &source_target {
        Some(t) => listing(t, &parent, false)?,
        None => local_listing(&parent).map_err(RemoteError::new)?,
    };
    let target_listing = match (&target_target, same && parent == dest) {
        (Some(_), true) => source_listing.clone(),
        (Some(t), false) => listing(t, &dest, false)?,
        (None, _) => local_listing(&dest).map_err(RemoteError::new)?,
    };
    enforce_configured_root(st, source_target.as_ref(), &source_listing.physical)?;
    enforce_configured_root(st, target_target.as_ref(), &target_listing.physical)?;
    for path in &paths {
        if let Some(item) = source_listing.items.iter().find(|item| &item.path == path) {
            if item.is_symlink {
                enforce_configured_root(st, source_target.as_ref(), &item.path)?;
            }
        }
    }
    if target_listing.available_bytes < SPACE_MARGIN {
        return Err(RemoteError::new("Not enough free space"));
    }
    if crate::paths::system_path_scope(&dest).is_none() {
        require_system_scope_at(
            st,
            &session_id,
            target_id,
            &target_listing.physical,
            crate::paths::system_path_scope(&target_listing.physical),
        )?;
    }

    let mut renames: serde_json::Map<String, Value> = serde_json::Map::new();
    if let Some(raw) = params.get("rename_map") {
        match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Object(map)) => renames = map,
            _ => return Err(RemoteError::new("Invalid name")),
        }
    }

    let mut used: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut reserved: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for item in &target_listing.items {
        used.insert(item.name.clone());
        reserved.insert(item.name.clone());
    }
    for path in &paths {
        reserved.insert(
            renames
                .get(path)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| path_name(path)),
        );
    }

    let mut items = Vec::new();
    let mut conflicts = Vec::new();
    let mut rename_names = serde_json::Map::new();
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for path in &paths {
        let item = source_listing
            .items
            .iter()
            .find(|item| &item.path == path)
            .ok_or_else(|| RemoteError::new("Source not found or unsupported file type"))?;
        if item.kind == "special" {
            return Err(RemoteError::new(
                "Source not found or unsupported file type",
            ));
        }
        let mut name = renames
            .get(path)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| item.name.clone());
        if !valid_component(&name) || name.len() > 255 || !names.insert(name.clone()) {
            return Err(RemoteError::new("Invalid or duplicate target name"));
        }
        let physical_source = join_path(&source_listing.physical, &item.name);
        require_system_scope(
            st,
            &session_id,
            source_id,
            crate::paths::system_path_scope(&item.path)
                .or_else(|| crate::paths::system_path_scope(&physical_source)),
        )?;
        if operation == "move" && crate::paths::is_descendant(&physical_source, RUNTIME_DIR) {
            return Err(RemoteError::new("Source directory cannot be moved"));
        }
        let mut conflicted = false;
        if used.contains(&name) {
            conflicted = true;
            if !renames.is_empty() {
                return Err(RemoteError::new("Target already exists"));
            }
            conflicts.push(json!({
                "path": item.path,
                "name": item.name,
                "type": if item.is_symlink { "symlink" } else { item.kind.as_str() },
            }));
            let (base, suffix) = if item.kind == "directory" && !item.is_symlink {
                (item.name.clone(), String::new())
            } else {
                match item.name.rfind('.') {
                    Some(index) if index > 0 => (
                        item.name[..index].to_string(),
                        item.name[index..].to_string(),
                    ),
                    _ => (item.name.clone(), String::new()),
                }
            };
            let mut counter = 1;
            let mut candidate = format!("{base} ({counter}){suffix}");
            while reserved.contains(&candidate) || names.contains(&candidate) {
                counter += 1;
                candidate = format!("{base} ({counter}){suffix}");
            }
            reserved.insert(candidate.clone());
            rename_names.insert(item.path.clone(), Value::String(candidate.clone()));
            if params.get("conflict_action").as_deref() == Some("rename") && renames.is_empty() {
                names.insert(candidate.clone());
                name = candidate;
            }
        }
        let final_target = join_path(&target_listing.physical, &name);
        require_system_scope_at(
            st,
            &session_id,
            target_id,
            &final_target,
            resolved_system_scope(target_target.as_ref(), &final_target),
        )?;
        let conflict_action = params.get("conflict_action").unwrap_or_default();
        if into_itself_rejected(
            &item.kind,
            item.is_symlink,
            same,
            &final_target,
            &physical_source,
            conflicted,
            &conflict_action,
        ) {
            return Err(RemoteError::new("Cannot transfer a directory into itself"));
        }
        items.push(TransferItem {
            source: item.clone(),
            target_name: name,
        });
    }

    let same_directory = same && source_listing.physical == target_listing.physical;
    Ok(Plan {
        source,
        target,
        parent,
        dest,
        same_directory,
        items,
        conflicts,
        rename_names,
    })
}

fn into_itself_rejected(
    kind: &str,
    is_symlink: bool,
    same_device: bool,
    final_target: &str,
    physical_source: &str,
    conflicted: bool,
    conflict_action: &str,
) -> bool {
    kind == "directory"
        && !is_symlink
        && same_device
        && (final_target == physical_source
            || crate::paths::is_descendant(physical_source, final_target))
        && !(conflicted && (conflict_action == "skip" || conflict_action == "error"))
}

use crate::task_registry::{write_progress, write_progress_file};

fn find_escape_pattern(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '*' | '?' | '[' | ']') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn excluded_patterns(dir: &str, names: &[String], excluded: &[String]) -> Vec<String> {
    let mut patterns = std::collections::BTreeSet::new();
    for name in names {
        let root = join_path(dir, name);
        for path in excluded {
            if let Some(suffix) = path.strip_prefix(&root) {
                if suffix.starts_with('/') && suffix.len() > 1 {
                    patterns.insert(format!("./{}{}", name, suffix));
                }
            }
        }
    }
    patterns.into_iter().collect()
}

fn find_exclusion_args(patterns: &[String]) -> String {
    patterns
        .iter()
        .flat_map(|pattern| {
            let escaped = find_escape_pattern(pattern);
            [escaped.clone(), format!("{escaped}/*")]
        })
        .map(|pattern| format!("! -path {}", shell_quote(&pattern)))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
fn remap_excluded_paths(items: &[TransferItem], dest: &str, excluded: &[String]) -> Vec<String> {
    let mut mapped = std::collections::BTreeSet::new();
    for item in items {
        let source_root = item.source.path.trim_end_matches('/');
        for path in excluded {
            if let Some(suffix) = path.strip_prefix(source_root) {
                if suffix.starts_with('/') && suffix.len() > 1 {
                    mapped.insert(join_path(dest, &format!("{}{}", item.target_name, suffix)));
                }
            }
        }
    }
    mapped.into_iter().collect()
}

pub enum Side<'a> {
    Local { dir: &'a str },
    Remote { target: &'a Target, dir: &'a str },
}

#[derive(Clone, Copy)]
enum TransferDirection {
    Read,
    Write,
}

impl Side<'_> {
    fn dir(&self) -> &str {
        match self {
            Side::Local { dir } => dir,
            Side::Remote { dir, .. } => dir,
        }
    }

    fn spawn_read(&self, names: &[String], excluded: &[String]) -> RResult<ssh::ByteStream> {
        let excludes = excluded_patterns(self.dir(), names, excluded);
        let exclude_args = excludes
            .iter()
            .map(|pattern| shell_quote(&format!("--exclude={}", find_escape_pattern(pattern))))
            .collect::<Vec<_>>()
            .join(" ");
        let args = names
            .iter()
            .map(|name| shell_quote(&format!("./{name}")))
            .collect::<Vec<_>>()
            .join(" ");
        let script = format!(
            "set -e\ncd {}\ntar -cpf - {} {}",
            shell_quote(self.dir()),
            exclude_args,
            args
        );
        self.spawn(&script, TransferDirection::Read)
    }

    fn spawn_write(&self, names: &[String], excluded: &[String]) -> RResult<ssh::ByteStream> {
        let excludes = excluded_patterns(self.dir(), names, excluded);
        let exclude_args = excludes
            .iter()
            .map(|pattern| shell_quote(&format!("--exclude={}", find_escape_pattern(pattern))))
            .collect::<Vec<_>>()
            .join(" ");
        let script = format!(
            "set -e\numask 077\ncd {}\ntar -xpf - {}\ncat >/dev/null",
            shell_quote(self.dir()),
            exclude_args
        );
        self.spawn(&script, TransferDirection::Write)
    }

    fn spawn(&self, script: &str, direction: TransferDirection) -> RResult<ssh::ByteStream> {
        match self {
            Side::Remote { target, .. } => {
                let space = workspace(target)?;
                match direction {
                    TransferDirection::Read => ssh::spawn_download(target, &space, script),
                    TransferDirection::Write => ssh::spawn_upload(target, &space, script),
                }
                .map_err(RemoteError::new)
            }
            Side::Local { .. } => {
                let mut cmd = std::process::Command::new("sh");
                cmd.arg("-c").arg(script);
                cmd.env("LC_ALL", "C");
                cmd.stdin(match direction {
                    TransferDirection::Read => std::process::Stdio::null(),
                    TransferDirection::Write => std::process::Stdio::piped(),
                });
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());
                use std::os::unix::process::CommandExt;
                unsafe {
                    cmd.pre_exec(|| {
                        if libc::setsid() < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(())
                        }
                    });
                }
                let child = cmd
                    .spawn()
                    .map_err(|_| RemoteError::new("Cannot start a local transfer"))?;
                ssh::ByteStream::from_child(child, true).map_err(RemoteError::new)
            }
        }
    }

    fn run(&self, script: &str, timeout: Option<u64>) -> RResult<Vec<u8>> {
        match self {
            Side::Remote { target, .. } => run(target, script, timeout),
            Side::Local { .. } => {
                let mut child = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(script)
                    .env("LC_ALL", "C")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|_| RemoteError::new("Cannot run a local command"))?;
                let stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| RemoteError::new("Cannot read local command output"))?;
                let stderr = child
                    .stderr
                    .take()
                    .ok_or_else(|| RemoteError::new("Cannot read local command errors"))?;
                let out =
                    std::thread::spawn(move || ssh::capture_bounded(stdout, COMMAND_OUTPUT_LIMIT));
                let err = std::thread::spawn(move || ssh::capture_bounded(stderr, 64 * 1024));
                let started = Instant::now();
                let status = loop {
                    if timeout
                        .is_some_and(|seconds| started.elapsed() >= Duration::from_secs(seconds))
                    {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(RemoteError::new("Local command timed out"));
                    }
                    match child.try_wait() {
                        Ok(Some(status)) => break status,
                        Ok(None) => std::thread::sleep(Duration::from_millis(40)),
                        Err(_) => return Err(RemoteError::new("Cannot wait for local command")),
                    }
                };
                let (stdout, truncated, read_failed) =
                    out.join().unwrap_or_else(|_| (Vec::new(), false, true));
                let (stderr, _, _) = err.join().unwrap_or_else(|_| (Vec::new(), false, true));
                if !status.success() {
                    let detail = String::from_utf8_lossy(&stderr).trim().to_string();
                    return Err(RemoteError::new(if detail.is_empty() {
                        "Local command failed".to_string()
                    } else {
                        detail
                    }));
                }
                if truncated || read_failed {
                    return Err(RemoteError::new(
                        "Local command output was incomplete or exceeded the limit",
                    ));
                }
                Ok(stdout)
            }
        }
    }

    fn run_mutating_once(&self, script: &str, timeout: Option<u64>) -> RResult<Vec<u8>> {
        match self {
            Side::Remote { target, .. } => run_mutating_once(target, script, timeout),
            Side::Local { .. } => self.run(script, timeout),
        }
    }

    fn run_reported(
        &self,
        script: &str,
        timeout: Option<u64>,
        mut on_chunk: impl FnMut(&[u8]),
    ) -> RResult<Vec<u8>> {
        use std::os::unix::io::AsRawFd;
        let mut child = TransferChild(self.spawn(script, TransferDirection::Read)?);
        let mut stdout = child
            .0
            .stdout
            .take()
            .ok_or_else(|| RemoteError::new("Cannot read command output"))?;
        let mut stderr = child.0.stderr.take();
        nonblocking(&stdout).map_err(|_| RemoteError::new("Cannot configure command pipe"))?;
        if let Some(pipe) = &stderr {
            nonblocking(pipe).map_err(|_| RemoteError::new("Cannot configure command pipe"))?;
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut buf = [0u8; 8192];
        let started = Instant::now();
        let limit = timeout.map(Duration::from_secs);
        let mut status = None;
        let mut eof = false;
        loop {
            if limit.is_some_and(|bound| started.elapsed() >= bound) {
                child.terminate_group();
                return Err(RemoteError::new(match self {
                    Side::Remote { .. } => "SSH command timed out",
                    Side::Local { .. } => "Local command timed out",
                }));
            }
            if !eof {
                match stdout.read(&mut buf) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        if out.len().saturating_add(n) > COMMAND_OUTPUT_LIMIT {
                            child.terminate_group();
                            return Err(RemoteError::new("Transfer tree exceeds the safety limit"));
                        }
                        on_chunk(&buf[..n]);
                        out.extend_from_slice(&buf[..n]);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => {
                        child.terminate_group();
                        return Err(RemoteError::new("Cannot read command output"));
                    }
                }
            }
            if drain_nonblocking(&mut stderr, &mut err, 64 * 1024).is_err() {
                child.terminate_group();
                return Err(RemoteError::new("Cannot read command errors"));
            }
            if status.is_none() {
                match child.0.try_wait() {
                    Ok(value) => status = value,
                    Err(_) => {
                        child.terminate_group();
                        return Err(RemoteError::new("Cannot wait for command"));
                    }
                }
            }
            if eof && status.is_some() {
                break;
            }
            let mut fds = Vec::<libc::pollfd>::new();
            let mut watch = |fd, events| {
                fds.push(libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                });
            };
            if !eof {
                watch(stdout.as_raw_fd(), libc::POLLIN);
            }
            if let Some(pipe) = &stderr {
                watch(pipe.as_raw_fd(), libc::POLLIN);
            }
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            if rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                child.terminate_group();
                return Err(RemoteError::new("Cannot poll command pipes"));
            }
        }
        if status != Some(0) {
            let detail = String::from_utf8_lossy(&err).trim().to_string();
            return Err(RemoteError::new(if detail.is_empty() {
                match self {
                    Side::Remote { .. } => "SSH command failed".to_string(),
                    Side::Local { .. } => "Local command failed".to_string(),
                }
            } else {
                detail
            }));
        }
        Ok(out)
    }
}

fn parse_mountpoints(raw: &[u8]) -> RResult<Vec<Vec<u8>>> {
    let invalid = || RemoteError::new("Cannot safely inspect the filesystem mount layout");
    if raw.is_empty() || !raw.ends_with(b"\n") {
        return Err(invalid());
    }
    let mut mounts = Vec::new();
    for line in raw
        .split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<&[u8]> = line
            .split(|&byte| byte == b' ')
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() < 10 || !fields.iter().any(|field| *field == b"-") {
            return Err(invalid());
        }
        let path = fields[4];
        let mut decoded = Vec::with_capacity(path.len());
        let mut i = 0;
        while i < path.len() {
            if path[i] == b'\\' {
                if i + 3 >= path.len()
                    || !path[i + 1..=i + 3]
                        .iter()
                        .all(|byte| (b'0'..=b'7').contains(byte))
                {
                    return Err(invalid());
                }
                let value = (path[i + 1] - b'0') as u16 * 64
                    + (path[i + 2] - b'0') as u16 * 8
                    + (path[i + 3] - b'0') as u16;
                if value == 0 || value > 255 {
                    return Err(invalid());
                }
                decoded.push(value as u8);
                i += 4;
            } else {
                decoded.push(path[i]);
                i += 1;
            }
        }
        if !decoded.starts_with(b"/") {
            return Err(invalid());
        }
        mounts.push(decoded);
    }
    if mounts.is_empty() {
        return Err(invalid());
    }
    Ok(mounts)
}

fn byte_path_contains(root: &[u8], path: &[u8]) -> bool {
    if root == b"/" {
        return path.starts_with(b"/");
    }
    path == root || (path.len() > root.len() && path.starts_with(root) && path[root.len()] == b'/')
}

fn ensure_no_nested_mounts(side: &Side<'_>, names: &[String]) -> RResult<()> {
    let target = match side {
        Side::Remote { target, .. } => Some(*target),
        Side::Local { .. } => None,
    };
    let physical = resolve_policy_paths(target, &[side.dir().to_string()])?
        .into_iter()
        .next()
        .ok_or_else(|| RemoteError::new("Cannot resolve transfer directory"))?;
    let raw = side
        .run("cat /proc/self/mountinfo", Some(30))
        .map_err(|_| RemoteError::new("Cannot safely inspect the filesystem mount layout"))?;
    let mounts = parse_mountpoints(&raw)?;
    for name in names {
        let root = join_path(&physical, name);
        if mounts
            .iter()
            .any(|mount| byte_path_contains(root.as_bytes(), mount))
        {
            return Err(RemoteError::new("Transfer would move or replace a filesystem mount; source and destination were retained"));
        }
    }
    Ok(())
}

pub(crate) fn ensure_remote_no_nested_mounts(target: &Target, roots: &[String]) -> RResult<()> {
    let parents = roots
        .iter()
        .map(|path| parent_path(path).ok_or_else(|| RemoteError::new("Invalid mutation path")))
        .collect::<RResult<Vec<_>>>()?;
    let resolved = resolve_policy_paths(Some(target), &parents)?;
    let raw = run(target, "cat /proc/self/mountinfo", Some(30))
        .map_err(|_| RemoteError::new("Cannot safely inspect the filesystem mount layout"))?;
    let mounts = parse_mountpoints(&raw)?;
    for (root, parent) in roots.iter().zip(&resolved) {
        let physical = join_path(parent, &path_name(root));
        if mounts
            .iter()
            .any(|mount| byte_path_contains(physical.as_bytes(), mount))
        {
            return Err(RemoteError::new(
                "Operation would cross a filesystem mount; no changes were made",
            ));
        }
    }
    Ok(())
}

fn parse_transfer_paths(
    raw: &[u8],
    roots: &[String],
    require_roots: bool,
) -> RResult<std::collections::BTreeSet<String>> {
    let invalid = || RemoteError::new("Cannot inspect the complete transfer tree safely");
    let mut result = std::collections::BTreeSet::new();
    let mut fields = raw.split(|&byte| byte == 0);
    loop {
        let value = fields.next().ok_or_else(invalid)?;
        if value == b"E" {
            if fields.next() != Some(&b""[..]) || fields.next().is_some() {
                return Err(invalid());
            }
            break;
        }
        let path = std::str::from_utf8(value)
            .map_err(|_| invalid())?
            .strip_prefix("./")
            .ok_or_else(invalid)?;
        if path.is_empty()
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !roots.iter().any(|root| {
                path == root
                    || path
                        .strip_prefix(root)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
            || !result.insert(path.to_string())
        {
            return Err(invalid());
        }
    }
    if require_roots && roots.iter().any(|root| !result.contains(root)) {
        return Err(invalid());
    }
    Ok(result)
}

#[derive(Default)]
struct TransferListing {
    relative: std::collections::BTreeSet<String>,
    resolved: std::collections::BTreeMap<String, String>,
}

struct PathReporter<'a> {
    task_dir: Option<&'a Path>,
    bytes: u64,
    total: u64,
    phase: &'static str,
    last: Instant,
}

impl PathReporter<'_> {
    fn scanning(task_dir: Option<&Path>, total: u64) -> PathReporter<'_> {
        PathReporter {
            task_dir,
            bytes: 0,
            total,
            phase: "scanning",
            last: Instant::now() - Duration::from_secs(1),
        }
    }

    fn emit(&mut self, path: &str) {
        let Some(dir) = self.task_dir else {
            return;
        };
        if path.is_empty() || self.last.elapsed() < Duration::from_millis(150) {
            return;
        }
        self.last = Instant::now();
        write_progress_file(dir, self.bytes, self.total, self.phase, Some(path));
    }
}

struct NulSniffer {
    pending: Vec<u8>,
    fields: usize,
    paired: bool,
}

impl NulSniffer {
    fn new(paired: bool) -> Self {
        Self {
            pending: Vec::new(),
            fields: 0,
            paired,
        }
    }

    fn push(&mut self, chunk: &[u8], report: &mut PathReporter<'_>) {
        self.pending.extend_from_slice(chunk);
        while let Some(index) = self.pending.iter().position(|&byte| byte == 0) {
            let field = self.pending.drain(..=index).collect::<Vec<_>>();
            let value = &field[..field.len().saturating_sub(1)];
            if value == b"E" {
                self.fields = 0;
                continue;
            }
            let even = self.fields % 2 == 0;
            self.fields = self.fields.saturating_add(1);
            if self.paired && !even {
                continue;
            }
            if let Ok(path) = std::str::from_utf8(value) {
                let path = path.strip_prefix("./").unwrap_or(path);
                if !path.is_empty() {
                    report.emit(path);
                }
            }
        }
    }
}

fn parse_transfer_entries(
    raw: &[u8],
    roots: &[String],
    require_roots: bool,
) -> RResult<TransferListing> {
    let invalid = || RemoteError::new("Cannot inspect the complete transfer tree safely");
    let mut listing = TransferListing::default();
    let mut fields = raw.split(|&byte| byte == 0);
    loop {
        let value = fields.next().ok_or_else(invalid)?;
        if value == b"E" {
            if fields.next() != Some(&b""[..]) || fields.next().is_some() {
                return Err(invalid());
            }
            break;
        }
        let path = std::str::from_utf8(value)
            .map_err(|_| invalid())?
            .strip_prefix("./")
            .ok_or_else(invalid)?;
        if path.is_empty()
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !roots.iter().any(|root| {
                path == root
                    || path
                        .strip_prefix(root)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        {
            return Err(invalid());
        }
        let resolved =
            std::str::from_utf8(fields.next().ok_or_else(invalid)?).map_err(|_| invalid())?;
        if resolved.is_empty()
            || !resolved.starts_with('/')
            || resolved
                .split('/')
                .skip(1)
                .any(|part| part == "." || part == "..")
            || !listing.relative.insert(path.to_string())
            || listing
                .resolved
                .insert(path.to_string(), resolved.to_string())
                .is_some()
        {
            return Err(invalid());
        }
    }
    if require_roots && roots.iter().any(|root| !listing.relative.contains(root)) {
        return Err(invalid());
    }
    Ok(listing)
}

fn local_resolved(dir: &str, dir_actual: &str, relative: &str) -> RResult<String> {
    let original = join_path(dir, relative);
    match std::fs::symlink_metadata(&original) {
        Ok(meta) if meta.file_type().is_symlink() => crate::paths::canonical_for_policy(&original)
            .ok_or_else(|| RemoteError::new("Cannot inspect the complete transfer tree safely")),
        Ok(_) => Ok(join_path(dir_actual, relative)),
        Err(_) => crate::paths::canonical_for_policy(&original)
            .ok_or_else(|| RemoteError::new("Cannot inspect the complete transfer tree safely")),
    }
}

fn projected_actual(
    relative: &str,
    existing: &std::collections::BTreeMap<String, String>,
    dir_actual: &str,
) -> String {
    let mut cursor = relative;
    loop {
        if let Some(actual) = existing.get(cursor) {
            let suffix = &relative[cursor.len()..];
            if suffix.is_empty() {
                return actual.clone();
            }
            if actual == "/" {
                return suffix.to_string();
            }
            return format!("{actual}{suffix}");
        }
        match cursor.rsplit_once('/') {
            Some((parent, _)) => cursor = parent,
            None => return join_path(dir_actual, relative),
        }
    }
}

fn transfer_listing(
    side: &Side<'_>,
    names: &[String],
    excluded: &[String],
    require_roots: bool,
    mut reporter: Option<&mut PathReporter<'_>>,
) -> RResult<TransferListing> {
    if names.is_empty() {
        return Ok(TransferListing::default());
    }
    let remote = matches!(side, Side::Remote { .. });
    let resolve_each = r#"for p do
        printf '%s\000' "$p" || exit 1
        suffix=''
        q="$p"
        while [ ! -e "$q" ] && [ ! -L "$q" ]; do
            [ "$q" != / ] || exit 1
            name="${q##*/}"
            suffix="/$name$suffix"
            parent="${q%/*}"
            [ -n "$parent" ] || parent=/
            q="$parent"
        done
        base=$(readlink -fn "$q" && printf '.') || exit 1
        base=${base%.}
        if [ "$base" = / ]; then printf '%s%s\000' "$base" "${suffix#/}"; else printf '%s%s\000' "$base" "$suffix"; fi
    done"#;
    let make = |batch: &[String]| {
        let listing = batch
            .iter()
            .map(|name| shell_quote(&format!("./{name}")))
            .collect::<Vec<_>>()
            .join(" ");
        let exclusions = find_exclusion_args(&excluded_patterns(side.dir(), batch, excluded));
        let missing = if require_roots { "exit 1" } else { ":" };
        if remote {
            format!(
                "set -e\ncd {}\nfor f in {listing}; do\n if [ -e \"$f\" ] || [ -L \"$f\" ]; then find \"$f\" {exclusions} -exec sh -c {} sh '{{}}' + || exit 1; else {missing}; fi\ndone\nprintf 'E\\000'\n",
                shell_quote(side.dir()),
                shell_quote(resolve_each)
            )
        } else {
            format!("set -e\ncd {}\nfor f in {listing}; do\n if [ -e \"$f\" ] || [ -L \"$f\" ]; then find \"$f\" {exclusions} -print0 || exit 1; else {missing}; fi\ndone\nprintf 'E\\000'\n", shell_quote(side.dir()))
        }
    };
    let mut batches: Vec<Vec<String>> = Vec::new();
    let mut batch: Vec<String> = Vec::new();
    for name in names {
        batch.push(name.clone());
        if batch.len() > 1 && ssh::script_exec_len(&make(&batch)) > ssh::SCRIPT_EXEC_LIMIT {
            let last = batch.pop().unwrap();
            batches.push(std::mem::take(&mut batch));
            batch.push(last);
        }
        if ssh::script_exec_len(&make(&batch)) > ssh::SCRIPT_EXEC_LIMIT {
            return Err(RemoteError::new(
                "Transfer selection is too long to inspect safely",
            ));
        }
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    let mut result = TransferListing::default();
    let mut total = 0usize;
    let dir_actual = if remote {
        None
    } else {
        Some(
            crate::paths::canonical_for_policy(side.dir()).ok_or_else(|| {
                RemoteError::new("Cannot inspect the complete transfer tree safely")
            })?,
        )
    };
    for batch in batches {
        let mut sniffer = NulSniffer::new(remote);
        let bytes = if let Some(reporter) = reporter.as_deref_mut() {
            side.run_reported(&make(&batch), Some(900), |chunk| {
                sniffer.push(chunk, reporter)
            })?
        } else {
            side.run(&make(&batch), Some(900))?
        };
        total = total.saturating_add(bytes.len());
        if total > COMMAND_OUTPUT_LIMIT {
            return Err(RemoteError::new("Transfer tree exceeds the safety limit"));
        }
        let listing = if remote {
            parse_transfer_entries(&bytes, &batch, require_roots)?
        } else {
            let relative = parse_transfer_paths(&bytes, &batch, require_roots)?;
            let dir_actual = dir_actual.as_deref().unwrap_or(side.dir());
            let mut resolved = std::collections::BTreeMap::new();
            for path in &relative {
                resolved.insert(path.clone(), local_resolved(side.dir(), dir_actual, path)?);
            }
            TransferListing { relative, resolved }
        };
        for relative in listing.relative {
            if !result.relative.insert(relative.clone()) {
                return Err(RemoteError::new("Duplicate transfer tree entry"));
            }
            if let Some(resolved) = listing.resolved.get(&relative) {
                result.resolved.insert(relative, resolved.clone());
            }
        }
    }
    Ok(result)
}

struct TransferSecurity<'a> {
    state: &'a AppState,
    session: &'a str,
    source_device: &'a str,
    target_device: &'a str,
}

fn authorize_resolved_paths(
    security: &TransferSecurity<'_>,
    device: &str,
    pairs: &[(String, String)],
) -> RResult<()> {
    let policy = security.state.root_policy_config();
    for (path, actual) in pairs {
        if !crate::paths::path_allowed_by_policy(
            policy.policy,
            &policy.roots,
            &policy.excluded_roots,
            actual,
        ) {
            return Err(RemoteError::new(crate::paths::root_policy_error(
                policy.policy,
            )));
        }
        if let Some(missing) = security.state.system_access.missing_path(
            (!security.session.is_empty()).then_some(security.session),
            device,
            path,
            actual,
        ) {
            return Err(RemoteError::system_access_required_at(missing, device));
        }
    }
    Ok(())
}

fn side_target<'a>(side: &'a Side<'_>) -> Option<&'a Target> {
    match side {
        Side::Remote { target, .. } => Some(*target),
        Side::Local { .. } => None,
    }
}

fn authorize_transfer_tree(
    security: &TransferSecurity<'_>,
    source: &Side<'_>,
    target: &Side<'_>,
    items: &[TransferItem],
    excluded: &[String],
    overwrite: bool,
) -> RResult<std::collections::BTreeSet<String>> {
    authorize_transfer_tree_reported(security, source, target, items, excluded, overwrite, None)
}

fn authorize_transfer_tree_reported(
    security: &TransferSecurity<'_>,
    source: &Side<'_>,
    target: &Side<'_>,
    items: &[TransferItem],
    excluded: &[String],
    overwrite: bool,
    mut reporter: Option<&mut PathReporter<'_>>,
) -> RResult<std::collections::BTreeSet<String>> {
    let names: Vec<String> = items.iter().map(|item| item.source.name.clone()).collect();
    let target_names: Vec<String> = items.iter().map(|item| item.target_name.clone()).collect();
    let roots: std::collections::BTreeMap<&str, &str> = items
        .iter()
        .map(|item| (item.source.name.as_str(), item.target_name.as_str()))
        .collect();
    let listed = transfer_listing(source, &names, excluded, true, reporter.as_deref_mut())?;
    let dest_dir_actual = resolve_policy_paths(side_target(target), &[target.dir().to_string()])?
        .into_iter()
        .next()
        .ok_or_else(|| RemoteError::new("Cannot resolve path for policy"))?;
    let existing = if overwrite {
        transfer_listing(target, &target_names, &[], false, reporter.as_deref_mut())?
    } else {
        TransferListing::default()
    };
    let mut source_pairs = Vec::with_capacity(listed.relative.len());
    let mut destination_pairs = Vec::with_capacity(listed.relative.len() + existing.relative.len());
    for relative in &listed.relative {
        let source_name = relative.split('/').next().unwrap_or("");
        let target_name = roots
            .get(source_name)
            .ok_or_else(|| RemoteError::new("Invalid transfer tree"))?;
        let suffix = &relative[source_name.len()..];
        let dest_relative = format!("{target_name}{suffix}");
        let actual =
            listed.resolved.get(relative).cloned().ok_or_else(|| {
                RemoteError::new("Cannot inspect the complete transfer tree safely")
            })?;
        source_pairs.push((join_path(source.dir(), relative), actual));
        destination_pairs.push((
            join_path(target.dir(), &dest_relative),
            projected_actual(&dest_relative, &existing.resolved, &dest_dir_actual),
        ));
        if let Some(reporter) = reporter.as_deref_mut() {
            reporter.emit(relative);
        }
    }
    authorize_resolved_paths(security, security.source_device, &source_pairs)?;
    authorize_resolved_paths(security, security.target_device, &destination_pairs)?;
    if overwrite {
        let paths: Vec<(String, String)> = existing
            .relative
            .iter()
            .map(|path| {
                let actual = existing
                    .resolved
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| join_path(&dest_dir_actual, path));
                (join_path(target.dir(), path), actual)
            })
            .collect();
        authorize_resolved_paths(security, security.target_device, &paths)?;
    }
    Ok(listed.relative)
}

fn require_transfer_side_tools(
    side: &Side<'_>,
    names: &[&str],
    device: &str,
    revision: &str,
) -> RResult<()> {
    if names.is_empty() || names.iter().any(|name| !crate::tools::valid_name(name)) {
        return Err(RemoteError::new("Invalid transfer tool list"));
    }
    let words = names
        .iter()
        .map(|name| shell_quote(name))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        r#"for t in {words}; do
 if command -v "$t" >/dev/null 2>&1; then continue; fi
 if [ "$t" = stat ] && {{ gnu-stat -c %d / >/dev/null 2>&1 || /usr/libexec/stat-coreutils -c %d / >/dev/null 2>&1 || busybox stat -c %d / >/dev/null 2>&1; }}; then continue; fi
 printf '%s\000' "$t" || exit 1
done
printf 'E\000'"#
    );
    let raw = side.run(&script, Some(30))?;
    let mut fields = raw.split(|&byte| byte == 0);
    let mut missing = Vec::new();
    loop {
        let field = fields
            .next()
            .ok_or_else(|| RemoteError::new("Invalid transfer tool response"))?;
        if field == b"E" {
            if fields.next() != Some(&b""[..]) || fields.next().is_some() {
                return Err(RemoteError::new("Invalid transfer tool response"));
            }
            break;
        }
        let name = std::str::from_utf8(field)
            .map_err(|_| RemoteError::new("Invalid transfer tool response"))?;
        if !names.contains(&name) || missing.contains(&name) {
            return Err(RemoteError::new("Invalid transfer tool response"));
        }
        missing.push(name);
    }
    if let Some(tool) = missing.first() {
        let mut data = crate::tools::missing_tool_data(tool);
        data["dependency_preflight"] = json!(true);
        data["device_id"] = json!(device);
        data["device_revision"] = json!(revision);
        return Err(RemoteError::with_data(
            format!("{tool} is not installed"),
            data,
        ));
    }
    Ok(())
}

struct TreeSelection<'a> {
    source_names: &'a [String],
    source_excluded: &'a [String],
}

struct TransferChild(ssh::ByteStream);
impl TransferChild {
    fn terminate_group(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
    fn terminate(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            self.terminate_group();
        }
    }
}
impl Drop for TransferChild {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn nonblocking(pipe: &impl std::os::unix::io::AsRawFd) -> std::io::Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn drain_nonblocking<R: Read>(
    pipe: &mut Option<R>,
    capture: &mut Vec<u8>,
    limit: usize,
) -> std::io::Result<()> {
    let mut closed = false;
    if let Some(pipe) = pipe.as_mut() {
        let mut buffer = [0u8; 8192];
        for _ in 0..16 {
            match pipe.read(&mut buffer) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => {
                    let keep = n.min(limit.saturating_sub(capture.len()));
                    capture.extend_from_slice(&buffer[..keep]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
    }
    if closed {
        *pipe = None;
    }
    Ok(())
}

#[cfg(test)]
fn pump_transfer(
    reader: ssh::ByteStream,
    writer: ssh::ByteStream,
    task_dir: &Path,
    total: u64,
    idle_limit: Duration,
) -> RResult<u64> {
    pump_transfer_controlled(reader, writer, task_dir, total, idle_limit, None, false)
}

fn tar_cstr(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn tar_octal(bytes: &[u8]) -> u64 {
    u64::from_str_radix(tar_cstr(bytes).trim(), 8).unwrap_or(0)
}

fn tar_header_name(header: &[u8]) -> Option<(String, u64)> {
    if header.len() < 512 || header.iter().take(512).all(|&byte| byte == 0) {
        return None;
    }
    let size = tar_octal(&header[124..136]);
    let name = tar_cstr(&header[0..100]);
    let prefix = if header.get(257..262) == Some(&b"ustar"[..]) {
        tar_cstr(&header[345..500])
    } else {
        String::new()
    };
    let path = if prefix.is_empty() {
        name
    } else if name.is_empty() {
        prefix
    } else {
        format!("{prefix}/{name}")
    };
    let path = path.trim_start_matches("./").to_string();
    if path.is_empty()
        || path.starts_with("PaxHeader/")
        || path.starts_with("./PaxHeader")
        || path.contains("@LongLink")
    {
        return Some((String::new(), size));
    }
    Some((path, size))
}

struct TarScan {
    header: Vec<u8>,
    remaining: u64,
    current: String,
}

impl TarScan {
    fn new() -> Self {
        Self {
            header: Vec::with_capacity(512),
            remaining: 0,
            current: String::new(),
        }
    }

    fn ingest(&mut self, data: &[u8]) -> Option<&str> {
        let mut offset = 0;
        let mut updated = false;
        while offset < data.len() {
            if self.remaining > 0 {
                let take = (data.len() - offset).min(self.remaining as usize);
                offset += take;
                self.remaining -= take as u64;
                continue;
            }
            let need = 512 - self.header.len();
            let take = (data.len() - offset).min(need);
            self.header.extend_from_slice(&data[offset..offset + take]);
            offset += take;
            if self.header.len() < 512 {
                break;
            }
            match tar_header_name(&self.header) {
                Some((name, size)) => {
                    self.remaining = size.saturating_add(511) & !511;
                    self.header.clear();
                    if !name.is_empty() {
                        self.current = name;
                        updated = true;
                    }
                }
                None => {
                    self.header.clear();
                    break;
                }
            }
        }
        updated.then_some(self.current.as_str())
    }
}

fn pump_transfer_controlled(
    reader: ssh::ByteStream,
    writer: ssh::ByteStream,
    task_dir: &Path,
    total: u64,
    idle_limit: Duration,
    control: Option<&crate::task_registry::JobControl>,
    remote_writer: bool,
) -> RResult<u64> {
    use std::os::unix::io::AsRawFd;
    let mut reader = TransferChild(reader);
    let mut writer = TransferChild(writer);
    let mut source = reader
        .0
        .stdout
        .take()
        .ok_or_else(|| RemoteError::new("Cannot read transfer source"))?;
    let mut destination = Some(
        writer
            .0
            .stdin
            .take()
            .ok_or_else(|| RemoteError::new("Cannot write transfer target"))?,
    );
    let mut source_err = reader.0.stderr.take();
    let mut target_err = writer.0.stderr.take();
    let mut target_out = writer.0.stdout.take();
    nonblocking(&source).map_err(|_| RemoteError::new("Cannot configure transfer pipe"))?;
    nonblocking(destination.as_ref().unwrap())
        .map_err(|_| RemoteError::new("Cannot configure transfer pipe"))?;
    if let Some(p) = &source_err {
        nonblocking(p).map_err(|_| RemoteError::new("Cannot configure transfer pipe"))?;
    }
    if let Some(p) = &target_err {
        nonblocking(p).map_err(|_| RemoteError::new("Cannot configure transfer pipe"))?;
    }
    if let Some(p) = &target_out {
        nonblocking(p).map_err(|_| RemoteError::new("Cannot configure transfer pipe"))?;
    }
    let mut source_log = Vec::new();
    let mut target_log = Vec::new();
    let mut ignored = Vec::new();
    let mut buffer = vec![0u8; 256 * 1024];
    let (mut position, mut length) = (0usize, 0usize);
    let mut eof = false;
    let mut copied = 0u64;
    let mut read = 0u64;
    let mut progress = Instant::now();
    let mut report = progress;
    let mut tar_scan = TarScan::new();
    let mut current_file = String::new();
    let (mut reader_status, mut writer_status) = (None, None);
    let mut failure: Option<&str> = None;
    let mut cancel_requested = false;
    loop {
        if control.is_some_and(|control| control.requested()) {
            cancel_requested = true;
            break;
        }
        if drain_nonblocking(&mut source_err, &mut source_log, 64 * 1024).is_err()
            || drain_nonblocking(&mut target_err, &mut target_log, 64 * 1024).is_err()
            || drain_nonblocking(&mut target_out, &mut ignored, 0).is_err()
        {
            failure = Some("Cannot read transfer diagnostics");
            break;
        }
        if position == length && !eof {
            match source.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(n) => {
                    position = 0;
                    length = n;
                    read = read.saturating_add(n as u64);
                    progress = Instant::now();
                    if let Some(name) = tar_scan.ingest(&buffer[..n]) {
                        current_file = name.to_string();
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => {
                    failure = Some("Cannot read the transfer source");
                    break;
                }
            }
        }
        if position < length {
            let Some(pipe) = destination.as_mut() else {
                failure = Some("Target closed the transfer stream");
                break;
            };
            match pipe.write(&buffer[position..length]) {
                Ok(0) => {
                    failure = Some("Target closed the transfer stream");
                    break;
                }
                Ok(n) => {
                    position += n;
                    copied = copied.saturating_add(n as u64);
                    progress = Instant::now();
                    if report.elapsed() >= Duration::from_millis(200) {
                        write_progress_file(
                            task_dir,
                            copied,
                            total,
                            "copying",
                            (!current_file.is_empty()).then_some(current_file.as_str()),
                        );
                        report = Instant::now();
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => {
                    failure = Some("Cannot write to the transfer target");
                    break;
                }
            }
        }
        if eof && position == length {
            destination.take();
        }
        if reader_status.is_none() {
            match reader.0.try_wait() {
                Ok(status) => reader_status = status,
                Err(_) => {
                    failure = Some("Cannot wait for transfer source");
                    break;
                }
            }
        }
        if writer_status.is_none() {
            match writer.0.try_wait() {
                Ok(status) => writer_status = status,
                Err(_) => {
                    failure = Some("Cannot wait for transfer target");
                    break;
                }
            }
        }
        if reader_status.is_some_and(|status| status != 0) {
            failure = Some("Source read failed");
            break;
        }
        if writer_status.is_some_and(|status| status != 0) {
            failure = Some("Target write failed");
            break;
        }
        if eof && position == length && reader_status.is_some() && writer_status.is_some() {
            break;
        }
        if progress.elapsed() >= idle_limit {
            failure = Some("Transfer stalled and timed out");
            break;
        }
        let mut fds = Vec::<libc::pollfd>::new();
        let mut watch = |fd, events| {
            fds.push(libc::pollfd {
                fd,
                events,
                revents: 0,
            })
        };
        if !eof && position == length {
            watch(source.as_raw_fd(), libc::POLLIN);
        }
        if position < length {
            if let Some(pipe) = &destination {
                watch(pipe.as_raw_fd(), libc::POLLOUT);
            }
        }
        if let Some(pipe) = &source_err {
            watch(pipe.as_raw_fd(), libc::POLLIN);
        }
        if let Some(pipe) = &target_err {
            watch(pipe.as_raw_fd(), libc::POLLIN);
        }
        if let Some(pipe) = &target_out {
            watch(pipe.as_raw_fd(), libc::POLLIN);
        }
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
        if rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            failure = Some("Cannot poll transfer pipes");
            break;
        }
    }
    if cancel_requested {
        destination.take();
        reader.terminate_group();
        writer.terminate_group();
        return Err(cancelled_transfer(None, remote_writer));
    }
    if let Some(message) = failure {
        destination.take();
        reader.terminate_group();
        writer.terminate_group();
        let _ = drain_nonblocking(&mut source_err, &mut source_log, 64 * 1024);
        let _ = drain_nonblocking(&mut target_err, &mut target_log, 64 * 1024);
        let detail = if !target_log.is_empty() {
            &target_log
        } else {
            &source_log
        };
        let detail = String::from_utf8_lossy(detail).trim().to_string();
        return Err(RemoteError::new(if detail.is_empty() {
            message.to_string()
        } else {
            format!("{message}: {detail}")
        }));
    }
    if read != copied {
        return Err(RemoteError::new("Transfer byte count mismatch"));
    }
    write_progress(task_dir, copied, total, "copying");
    Ok(copied)
}

#[cfg(test)]
fn stream_tree(
    source: &Side<'_>,
    target: &Side<'_>,
    selection: &TreeSelection<'_>,
    task_dir: &Path,
    total: u64,
) -> RResult<u64> {
    stream_tree_controlled(source, target, selection, task_dir, total, None)
}

fn same_remote_endpoint(source: &Side<'_>, target: &Side<'_>) -> bool {
    match (source, target) {
        (Side::Remote { target: a, .. }, Side::Remote { target: b, .. }) => {
            !a.host.is_empty() && a.host == b.host && a.port == b.port && a.username == b.username
        }
        _ => false,
    }
}

fn crosses_devices(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EXDEV) || error.kind() == std::io::ErrorKind::CrossesDevices
}

fn dest_blocks_rename(source: &Path, dest: &Path) -> bool {
    let dest_meta = match std::fs::symlink_metadata(dest) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    let source_meta = match std::fs::symlink_metadata(source) {
        Ok(meta) => meta,
        Err(_) => return true,
    };
    dest_meta.is_dir() || source_meta.is_dir()
}

fn try_rename_move(
    source: &Side<'_>,
    target: &Side<'_>,
    items: &[TransferItem],
    overwrite: bool,
    control: Option<&crate::task_registry::JobControl>,
) -> RResult<bool> {
    if items.is_empty() {
        return Ok(true);
    }
    match (source, target) {
        (Side::Local { dir: src }, Side::Local { dir: dst }) => {
            try_rename_local(src, dst, items, overwrite, control)
        }
        (Side::Remote { .. }, Side::Remote { .. }) if same_remote_endpoint(source, target) => {
            try_rename_remote(source, target, items, overwrite, control)
        }
        _ => Ok(false),
    }
}

fn try_rename_local(
    src_dir: &str,
    dst_dir: &str,
    items: &[TransferItem],
    overwrite: bool,
    control: Option<&crate::task_registry::JobControl>,
) -> RResult<bool> {
    for item in items {
        let src = join_path(src_dir, &item.source.name);
        let dst = join_path(dst_dir, &item.target_name);
        if dest_blocks_rename(Path::new(&src), Path::new(&dst)) {
            return Ok(false);
        }
        if !overwrite && std::fs::symlink_metadata(&dst).is_ok() {
            return Err(RemoteError::new(
                "Target already exists or publication failed",
            ));
        }
    }
    let mut started = false;
    for item in items {
        if !started && control.is_some_and(|control| control.requested()) {
            return Err(cancelled_transfer(None, false));
        }
        let src = join_path(src_dir, &item.source.name);
        let dst = join_path(dst_dir, &item.target_name);
        match std::fs::rename(&src, &dst) {
            Ok(()) => {
                if !started {
                    let _ = control.map(|control| control.seal());
                    started = true;
                }
            }
            Err(error) if !started && crosses_devices(&error) => return Ok(false),
            Err(_) => {
                return Err(RemoteError::new(
                    "Target already exists or publication failed",
                ));
            }
        }
    }
    Ok(true)
}

fn try_rename_remote(
    source: &Side<'_>,
    target: &Side<'_>,
    items: &[TransferItem],
    overwrite: bool,
    control: Option<&crate::task_registry::JobControl>,
) -> RResult<bool> {
    let token = crate::uci::random_hex(8);
    let probe_src = join_path(source.dir(), &format!(".harbor-rename-{token}"));
    let probe_dst = join_path(target.dir(), &format!(".harbor-rename-{token}"));
    let mut script = format!(
        "set -e\nps={}\npd={}\nprintf p > \"$ps\" || exit 1\nif ! ln \"$ps\" \"$pd\" 2>/dev/null; then\n rm -f \"$ps\"\n echo HARBOR_NEED_COPY >&2\n exit 1\nfi\nrm -f \"$ps\" \"$pd\"\n",
        shell_quote(&probe_src),
        shell_quote(&probe_dst)
    );
    for item in items {
        let src = shell_quote(&join_path(source.dir(), &item.source.name));
        let dst = shell_quote(&join_path(target.dir(), &item.target_name));
        script.push_str(&format!(
            "if [ -e {dst} ] || [ -L {dst} ]; then\n if [ -d {dst} ] && [ ! -L {dst} ]; then echo HARBOR_NEED_COPY >&2; exit 1; fi\n if [ -d {src} ] && [ ! -L {src} ]; then echo HARBOR_NEED_COPY >&2; exit 1; fi\nfi\n"
        ));
    }
    if ssh::script_exec_len(&script) > ssh::SCRIPT_EXEC_LIMIT {
        return Ok(false);
    }
    if let Err(error) = source.run_mutating_once(&script, Some(60)) {
        if error.message.contains("HARBOR_NEED_COPY") {
            return Ok(false);
        }
        return Err(error);
    }
    if control.is_some_and(|control| !control.seal()) {
        return Err(cancelled_transfer(None, false));
    }
    for item in items {
        let src = shell_quote(&join_path(source.dir(), &item.source.name));
        let dst = shell_quote(&join_path(target.dir(), &item.target_name));
        let line = if overwrite {
            format!("set -e\nmv -fT {src} {dst}\n[ ! -e {src} ] && [ ! -L {src} ] || exit 1\n")
        } else {
            format!("set -e\nmv -nT {src} {dst} && [ ! -e {src} ] && [ ! -L {src} ] || {{ echo 'Target already exists or publication failed' >&2; exit 1; }}\n")
        };
        if ssh::script_exec_len(&line) > ssh::SCRIPT_EXEC_LIMIT {
            return Err(RemoteError::new("Transfer publication path is too long"));
        }
        source.run_mutating_once(&line, Some(60))?;
    }
    Ok(true)
}

fn tree_walk_script(
    dir: &str,
    names: &[String],
    excluded: &[String],
    inspect: &str,
    trailer: &str,
) -> String {
    let listing = names
        .iter()
        .map(|name| shell_quote(&format!("./{name}")))
        .collect::<Vec<_>>()
        .join(" ");
    let exclusions = find_exclusion_args(&excluded_patterns(dir, names, excluded));
    format!(
        "set -e\ncd {}\nfor f in {listing}; do\n [ -e \"$f\" ] || [ -L \"$f\" ] || exit 1\n find \"$f\" {exclusions} -exec sh -c {} sh '{{}}' + || exit 1\ndone\n{trailer}",
        shell_quote(dir),
        shell_quote(inspect)
    )
}

fn tree_name_batches(
    dir: &str,
    names: &[String],
    excluded: &[String],
    inspect: &str,
    trailer: &str,
) -> RResult<Vec<Vec<String>>> {
    if names.is_empty() {
        return Err(RemoteError::new("No transfer entries to verify"));
    }
    let make = |batch: &[String]| tree_walk_script(dir, batch, excluded, inspect, trailer);
    let mut batches = Vec::new();
    let mut current = Vec::new();
    for name in names {
        current.push(name.clone());
        if current.len() > 1 && ssh::script_exec_len(&make(&current)) > ssh::SCRIPT_EXEC_LIMIT {
            let last = current.pop().unwrap();
            batches.push(std::mem::take(&mut current));
            current.push(last);
        }
        if ssh::script_exec_len(&make(&current)) > ssh::SCRIPT_EXEC_LIMIT {
            return Err(RemoteError::new(
                "Transfer verification path is too long; source was retained",
            ));
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    Ok(batches)
}

fn stream_tree_controlled(
    source: &Side<'_>,
    target: &Side<'_>,
    selection: &TreeSelection<'_>,
    task_dir: &Path,
    total: u64,
    control: Option<&crate::task_registry::JobControl>,
) -> RResult<u64> {
    if same_remote_endpoint(source, target) {
        return stream_tree_on_same_host(source, target, selection, task_dir, total, control);
    }
    let reader = source.spawn_read(selection.source_names, selection.source_excluded)?;
    match target.spawn_write(selection.source_names, &[]) {
        Ok(writer) => pump_transfer_controlled(
            reader,
            writer,
            task_dir,
            total,
            Duration::from_secs(300),
            control,
            matches!(target, Side::Remote { .. }),
        ),
        Err(error) => {
            drop(TransferChild(reader));
            Err(error)
        }
    }
}

fn take_progress_lines(buf: &mut Vec<u8>) -> Option<u64> {
    let mut latest = None;
    let mut kept = Vec::new();
    let mut start = 0usize;
    for index in 0..buf.len() {
        if buf[index] != b'\n' {
            continue;
        }
        let line = &buf[start..=index];
        let text = String::from_utf8_lossy(line);
        if let Some(rest) = text.trim().strip_prefix("P ") {
            if let Ok(value) = rest.parse::<u64>() {
                latest = Some(value);
            }
        } else {
            kept.extend_from_slice(line);
        }
        start = index + 1;
    }
    kept.extend_from_slice(&buf[start..]);
    *buf = kept;
    latest
}

fn stream_tree_on_same_host(
    source: &Side<'_>,
    target: &Side<'_>,
    selection: &TreeSelection<'_>,
    task_dir: &Path,
    total: u64,
    control: Option<&crate::task_registry::JobControl>,
) -> RResult<u64> {
    let excludes = excluded_patterns(
        source.dir(),
        selection.source_names,
        selection.source_excluded,
    );
    let exclude_args = excludes
        .iter()
        .map(|pattern| shell_quote(&format!("--exclude={}", find_escape_pattern(pattern))))
        .collect::<Vec<_>>()
        .join(" ");
    let args = selection
        .source_names
        .iter()
        .map(|name| shell_quote(&format!("./{name}")))
        .collect::<Vec<_>>()
        .join(" ");
    let mut script = format!(
        "set -e\numask 077\nsrc={}\ndst={}\ncd \"$src\"\ntar -cpf - {exclude_args} {args} | tar -xpf - -C \"$dst\" &\npid=$!\n",
        shell_quote(source.dir()),
        shell_quote(target.dir()),
    );
    script.push_str(
        r#"trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null; exit 1' INT TERM HUP
while kill -0 "$pid" 2>/dev/null; do
  if out=$(du -sb "$dst" 2>/dev/null); then
    bytes=${out%%[!0-9]*}
  else
    out=$(du -sk "$dst" 2>/dev/null || echo 0)
    kb=${out%%[!0-9]*}
    bytes=$((kb * 1024))
  fi
  printf 'P %s\n' "$bytes" >&2
  sleep 1
done
wait "$pid"
"#,
    );
    let mut child = TransferChild(source.spawn(&script, TransferDirection::Read)?);
    let mut stdout = child.0.stdout.take();
    let mut stderr = child.0.stderr.take();
    if let Some(pipe) = &stdout {
        nonblocking(pipe).map_err(|_| RemoteError::new("Cannot configure transfer pipe"))?;
    }
    if let Some(pipe) = &stderr {
        nonblocking(pipe).map_err(|_| RemoteError::new("Cannot configure transfer pipe"))?;
    }
    let mut discarded = Vec::new();
    let mut err_buf = Vec::new();
    let mut copied = 0u64;
    let mut idle = Instant::now();
    let idle_limit = Duration::from_secs(300);
    loop {
        if control.is_some_and(|control| control.requested()) {
            child.terminate();
            return Err(cancelled_transfer(None, false));
        }
        discarded.clear();
        drain_nonblocking(&mut stdout, &mut discarded, 0)
            .map_err(|_| RemoteError::new("Cannot read transfer diagnostics"))?;
        drain_nonblocking(&mut stderr, &mut err_buf, 64 * 1024)
            .map_err(|_| RemoteError::new("Cannot read transfer diagnostics"))?;
        if let Some(value) = take_progress_lines(&mut err_buf) {
            copied = value;
            write_progress(task_dir, copied.min(total), total, "copying");
            idle = Instant::now();
        }
        match child.0.try_wait() {
            Ok(Some(0)) => {
                let _ = drain_nonblocking(&mut stderr, &mut err_buf, 64 * 1024);
                if let Some(value) = take_progress_lines(&mut err_buf) {
                    copied = value;
                }
                write_progress(task_dir, total, total, "copying");
                return Ok(copied.max(total));
            }
            Ok(Some(_)) => {
                let _ = drain_nonblocking(&mut stderr, &mut err_buf, 64 * 1024);
                let _ = take_progress_lines(&mut err_buf);
                let detail = String::from_utf8_lossy(&err_buf);
                let detail = detail.trim();
                return Err(RemoteError::new(if detail.is_empty() {
                    "On-device copy failed".to_string()
                } else {
                    format!("On-device copy failed: {detail}")
                }));
            }
            Ok(None) => {
                if idle.elapsed() > idle_limit {
                    child.terminate();
                    return Err(RemoteError::new("On-device copy stalled"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                child.terminate();
                return Err(RemoteError::new("Cannot wait for on-device copy"));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManifestEntry {
    Directory,
    File { size: u64, mtime: i64 },
    Symlink(Vec<u8>),
}
type TreeManifest = std::collections::BTreeMap<String, ManifestEntry>;

fn parse_tree_manifest(raw: &[u8], roots: &[String]) -> RResult<TreeManifest> {
    let invalid = || {
        RemoteError::new("Incomplete or invalid transfer verification listing; source was retained")
    };
    if roots.is_empty() {
        return Err(invalid());
    }
    let mut fields = raw.split(|&byte| byte == 0);
    let mut result = TreeManifest::new();
    loop {
        let tag = fields.next().ok_or_else(invalid)?;
        if tag == b"E" {
            if fields.next() != Some(&b""[..]) || fields.next().is_some() {
                return Err(invalid());
            }
            break;
        }
        let path = std::str::from_utf8(fields.next().ok_or_else(invalid)?)
            .map_err(|_| invalid())?
            .strip_prefix("./")
            .ok_or_else(invalid)?;
        if path.is_empty()
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !roots.iter().any(|root| {
                path == root
                    || path
                        .strip_prefix(root)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        {
            return Err(invalid());
        }
        let value = fields.next().ok_or_else(invalid)?;
        let entry = match tag {
            b"D" if value.is_empty() => ManifestEntry::Directory,
            b"F" => {
                let text = std::str::from_utf8(value).map_err(|_| invalid())?;
                let mut parts = text.split(' ');
                let size = parts
                    .next()
                    .and_then(|part| part.parse().ok())
                    .ok_or_else(invalid)?;
                let mtime = parts
                    .next()
                    .and_then(|part| part.parse().ok())
                    .ok_or_else(invalid)?;
                if parts.next().is_some() {
                    return Err(invalid());
                }
                ManifestEntry::File { size, mtime }
            }
            b"L" if !value.is_empty() => ManifestEntry::Symlink(value.to_vec()),
            _ => return Err(invalid()),
        };
        if result.insert(path.to_string(), entry).is_some() {
            return Err(invalid());
        }
    }
    if roots.iter().any(|root| !result.contains_key(root)) {
        return Err(invalid());
    }
    Ok(result)
}

#[cfg(test)]
fn transfer_manifests_match(
    source: &TreeManifest,
    target: &TreeManifest,
    items: &[TransferItem],
) -> bool {
    if source.is_empty()
        || items
            .iter()
            .any(|item| !source.contains_key(&item.source.name))
    {
        return false;
    }
    let roots: std::collections::BTreeMap<&str, &str> = items
        .iter()
        .map(|item| (item.source.name.as_str(), item.target_name.as_str()))
        .collect();
    if roots.len() != items.len() {
        return false;
    }
    source.iter().all(|(path, entry)| {
        let name = path.split('/').next().unwrap_or("");
        roots.get(name).is_some_and(|target_name| {
            let mapped = format!("{}{}", target_name, &path[name.len()..]);
            target.get(&mapped) == Some(entry)
        })
    })
}

#[cfg(test)]
fn tree_manifest(side: &Side<'_>, names: &[String], excluded: &[String]) -> RResult<TreeManifest> {
    tree_manifest_reported(side, names, excluded, None)
}

fn tree_manifest_reported(
    side: &Side<'_>,
    names: &[String],
    excluded: &[String],
    mut reporter: Option<&mut PathReporter<'_>>,
) -> RResult<TreeManifest> {
    let inspect = r#"for p do
        if [ -L "$p" ]; then
            printf 'L\000%s\000' "$p" || exit 1
            readlink -n "$p" || exit 1
            printf '\000' || exit 1
        elif [ -d "$p" ]; then
            printf 'D\000%s\000\000' "$p" || exit 1
        elif [ -f "$p" ]; then
            s=$(stat -c '%s %Y' "$p" 2>/dev/null || gnu-stat -c '%s %Y' "$p" 2>/dev/null || /usr/libexec/stat-coreutils -c '%s %Y' "$p" 2>/dev/null || busybox stat -c '%s %Y' "$p") || exit 1
            printf 'F\000%s\000%s\000' "$p" "$s" || exit 1
        else
            echo 'Unsupported file type in transfer' >&2; exit 1
        fi
    done"#;
    let trailer = "printf 'E\\000'\n";
    let make = |batch: &[String]| tree_walk_script(side.dir(), batch, excluded, inspect, trailer);
    let batches = tree_name_batches(side.dir(), names, excluded, inspect, trailer)?;
    let mut result = TreeManifest::new();
    let mut total_bytes = 0usize;
    for batch in batches {
        let mut pending = Vec::new();
        let mut fields: Vec<Vec<u8>> = Vec::new();
        let raw = if reporter.is_some() {
            side.run_reported(&make(&batch), Some(900), |chunk| {
                pending.extend_from_slice(chunk);
                while let Some(index) = pending.iter().position(|&byte| byte == 0) {
                    let field = pending.drain(..=index).collect::<Vec<_>>();
                    let value = field[..field.len().saturating_sub(1)].to_vec();
                    if fields.is_empty() && value == b"E" {
                        fields.clear();
                        continue;
                    }
                    fields.push(value);
                    if fields.len() == 3 {
                        if let Ok(path) = std::str::from_utf8(&fields[1]) {
                            if let Some(relative) = path.strip_prefix("./") {
                                if let Some(reporter) = reporter.as_deref_mut() {
                                    reporter.emit(relative);
                                }
                            }
                        }
                        fields.clear();
                    }
                }
            })?
        } else {
            side.run(&make(&batch), Some(900))?
        };
        total_bytes = total_bytes.saturating_add(raw.len());
        if total_bytes > COMMAND_OUTPUT_LIMIT {
            return Err(RemoteError::new(
                "Transfer verification listing exceeded the limit; source was retained",
            ));
        }
        for (path, entry) in parse_tree_manifest(&raw, &batch)? {
            if result.insert(path, entry).is_some() {
                return Err(RemoteError::new(
                    "Duplicate transfer verification entry; source was retained",
                ));
            }
        }
    }
    Ok(result)
}

fn remove_transferred_sources(
    side: &Side<'_>,
    manifest: &TreeManifest,
    excluded: &[String],
) -> RResult<()> {
    if manifest.is_empty() {
        return Err(RemoteError::new(
            "Empty verification listing; source was retained",
        ));
    }
    let mut entries: Vec<_> = manifest.iter().collect();
    entries.sort_by(|(a, _), (b, _)| {
        b.matches('/')
            .count()
            .cmp(&a.matches('/').count())
            .then_with(|| a.cmp(b))
    });
    let header = format!("set -e\ncd {}\n", shell_quote(side.dir()));
    let mut lines = Vec::new();
    for (path, entry) in entries {
        let p = shell_quote(&format!("./{path}"));
        let line = match entry {
            ManifestEntry::File { size, mtime } => format!(
                "[ -f {p} ] && [ ! -L {p} ] || exit 1; s=$(stat -c '%s %Y' {p} 2>/dev/null || gnu-stat -c '%s %Y' {p} 2>/dev/null || /usr/libexec/stat-coreutils -c '%s %Y' {p} 2>/dev/null || busybox stat -c '%s %Y' {p}) || exit 1; [ \"$s\" = {} ] || exit 1; rm -f {p}",
                shell_quote(&format!("{size} {mtime}"))
            ),
            ManifestEntry::Symlink(value) => match std::str::from_utf8(value) {
                Ok(target) => {
                    let mut expected = target.to_string();
                    expected.push('.');
                    format!(
                        "[ -L {p} ] || exit 1; g=$(readlink -n {p}; printf .) || exit 1; [ \"$g\" = {} ] || exit 1; rm -f {p}",
                        shell_quote(&expected)
                    )
                }
                Err(_) => format!(
                    "[ -L {p} ] || exit 1; c=$(readlink -n {p} | wc -c) || exit 1; [ \"$c\" -eq {} ] || exit 1; rm -f {p}",
                    value.len()
                ),
            },
            ManifestEntry::Directory => {
                let full = join_path(side.dir(), path);
                let retains_exclusions = excluded.iter().any(|skip| skip != &full && crate::paths::is_descendant(&full, skip));
                if retains_exclusions {
                    format!("[ -d {p} ] && [ ! -L {p} ] || exit 1; rmdir {p} 2>/dev/null || true")
                } else {
                    format!("[ -d {p} ] && [ ! -L {p} ] || exit 1; rmdir {p}")
                }
            }
        };
        if ssh::script_exec_len(&format!("{header}{line}")) > ssh::SCRIPT_EXEC_LIMIT {
            return Err(RemoteError::new(
                "Transfer deletion path is too long; source was retained",
            ));
        }
        lines.push(line);
    }
    let mut batches = Vec::new();
    let mut batch = header.clone();
    for line in lines {
        let candidate = format!("{batch}{line}\n");
        if ssh::script_exec_len(&candidate) > ssh::SCRIPT_EXEC_LIMIT && batch != header {
            batches.push(std::mem::replace(&mut batch, header.clone()));
        }
        batch.push_str(&line);
        batch.push('\n');
    }
    if batch != header {
        batches.push(batch);
    }
    for script in batches {
        if let Err(mut error) = side.run_mutating_once(&script, Some(900)) {
            error.message = format!(
                "Source removal may be partial; inspect source and destination: {}",
                error.message
            );
            if !error.data.is_object() {
                error.data = json!({});
            }
            error.data["partial"] = json!(true);
            return Err(error);
        }
    }
    Ok(())
}

pub fn spawn_task(
    st: &AppState,
    state: Value,
    worker: impl FnOnce(PathBuf) -> RResult<()> + Send + 'static,
) -> RResult<String> {
    st.tasks
        .spawn_job(state, move |dir| worker(dir).map_err(Into::into))
        .map_err(RemoteError::new)
}

pub(crate) fn update_task_fields(task_dir: &Path, fields: &Value) -> RResult<()> {
    crate::task_registry::update_job_fields(task_dir, fields).map_err(RemoteError::new)
}

pub fn task_status(st: &AppState, task_id: &str) -> RResult<Value> {
    st.tasks.job_status(task_id).map_err(RemoteError::new)
}

fn status(st: &AppState, task_id: &str) -> RResult<Value> {
    task_status(st, task_id)
}

fn spawn_cancellable_task(
    st: &AppState,
    state: Value,
    worker: impl FnOnce(PathBuf, Arc<crate::task_registry::JobControl>) -> RResult<()> + Send + 'static,
) -> RResult<String> {
    st.tasks
        .spawn_cancellable_job(state, move |dir, control| {
            worker(dir, control).map_err(Into::into)
        })
        .map_err(RemoteError::new)
}

pub async fn dispatch(
    st: &Arc<AppState>,
    params: &Params,
    is_post: bool,
) -> axum::response::Response {
    let action = params.get("remote_action").unwrap_or_default();
    let write = matches!(
        action.as_str(),
        "get"
            | "save"
            | "delete"
            | "trust"
            | "start"
            | "install_stat"
            | "rpc"
            | "connection_settings_save"
    );
    if write && !is_post {
        return fail(1, "POST required", Value::Null);
    }
    let st = Arc::clone(st);
    let params = params.clone();
    match tokio::task::spawn_blocking(move || handle(&st, &action, &params)).await {
        Ok(Ok(value)) => ok(value),
        Ok(Err(error)) => error.response(),
        Err(_) => fail(1, "Remote operation failed", Value::Null),
    }
}

fn handle(st: &Arc<AppState>, action: &str, params: &Params) -> RResult<Value> {
    match action {
        "devices" => {
            let list: Vec<Value> = devices(st).iter().map(|d| d.public_json()).collect();
            Ok(json!({
                "devices": list,
                "connection": connection_settings_json(st),
            }))
        }
        "dependency" | "tool_check" => dependency(st, params),
        "connection_settings_save" => save_connection_settings(st, params),
        "tools" => {
            let device = checked_device(st, &params.get("device_id").unwrap_or_default(), None)?;
            let target = authenticated_target(st, &device);
            let info = tool_info(Some(&target))?;
            Ok(json!({
                "stat": info.stat,
                "stat_provider": info.stat_provider,
                "installer": info.installer,
                "can_install": info.can_install,
                "root": info.root,
                "device_revision": device.revision,
            }))
        }
        "get" => {
            let device = find_device(st, &params.get("id").unwrap_or_default())
                .ok_or_else(|| RemoteError::new("Device not found"))?;
            Ok(json!({
                "id": device.id,
                "name": device.name,
                "has_password": device.has_password,
            }))
        }
        "save" => save_device(st, params),
        "delete" => delete_device(st, params),
        "trust" => {
            confirm_trust(
                st,
                &params.get("challenge").unwrap_or_default(),
                &params.get("device_id").unwrap_or_default(),
            )?;
            Ok(json!({}))
        }
        "list" | "capacity" => {
            let device = checked_device(
                st,
                &params.get("device_id").unwrap_or_default(),
                params.get("device_revision").as_deref(),
            )?;
            ensure_trusted(st, &device)?;
            let target = authenticated_target(st, &device);
            let path = params.get("path").unwrap_or_else(|| "/".into());
            enforce_configured_root(st, Some(&target), &path)?;
            let session_id = params.get("__system_session_id").unwrap_or_default();
            require_system_scope(
                st,
                &session_id,
                &device.id,
                resolved_system_scope(Some(&target), &path),
            )?;
            let listing = listing(&target, &path, action == "capacity")?;
            enforce_configured_root(st, Some(&target), &listing.physical)?;
            if crate::paths::system_path_scope(&path).is_none() {
                require_system_scope(
                    st,
                    &session_id,
                    &device.id,
                    crate::paths::system_path_scope(&listing.physical),
                )?;
            }
            let mut value =
                crate::remoteops::listing_json(st, &target, &listing, action == "capacity");
            value["device_revision"] = Value::String(device.revision.clone());
            value["device_name"] = Value::String(device.name.clone());
            Ok(value)
        }
        "check" => {
            if let Some(tree_path) = params.get("tree_path") {
                let device = checked_device(
                    st,
                    &params.get("source_device").unwrap_or_default(),
                    params.get("source_revision").as_deref(),
                )?;
                ensure_trusted(st, &device)?;
                let target = authenticated_target(st, &device);
                enforce_configured_root(st, Some(&target), &tree_path)?;
                let session_id = params.get("__system_session_id").unwrap_or_default();
                require_system_scope(
                    st,
                    &session_id,
                    &device.id,
                    resolved_system_scope(Some(&target), &tree_path),
                )?;
                let listing = listing(&target, &tree_path, false)?;
                enforce_configured_root(st, Some(&target), &listing.physical)?;
                if crate::paths::system_path_scope(&tree_path).is_none() {
                    require_system_scope(
                        st,
                        &session_id,
                        &device.id,
                        crate::paths::system_path_scope(&listing.physical),
                    )?;
                }
                let children: Vec<Value> = listing
                    .items
                    .iter()
                    .map(|item| {
                        json!({
                            "path": item.path,
                            "name": item.name,
                            "type": if item.kind == "directory_link" { "directory" } else { item.kind.as_str() },
                        })
                    })
                    .collect();
                return Ok(json!({ "children": children, "path": listing.path }));
            }
            let plan = build_plan(st, params)?;
            Ok(json!({
                "conflicts": plan.conflicts,
                "rename_names": plan.rename_names,
                "count": plan.items.len(),
            }))
        }
        "start" => start_transfer(st, params),
        "status" => status(st, &params.get("task_id").unwrap_or_default()),
        "agent_prepare" | "agent_info" => {
            let device = checked_device(
                st,
                &params.get("device_id").unwrap_or_default(),
                params.get("device_revision").as_deref(),
            )?;
            Ok(crate::remoteops::agent_ready(&device))
        }
        "agent_install" => {
            let device = checked_device(st, &params.get("device_id").unwrap_or_default(), None)?;
            let task_id = spawn_task(
                st,
                json!({ "operation": "agent_install", "device": device.id }),
                |dir| {
                    write_progress(&dir, 1, 1, "complete");
                    Ok(())
                },
            )?;
            Ok(json!({ "task_id": task_id, "done": true, "success": true, "ready": true }))
        }
        "install_stat" => {
            let device = checked_device(st, &params.get("device_id").unwrap_or_default(), None)?;
            ensure_trusted(st, &device)?;
            crate::remoteops::install_packages(st, &device, &["coreutils-stat".to_string()])
        }
        "plan" => {
            let plan = build_plan(st, params)?;
            Ok(json!({
                "conflicts": plan.conflicts,
                "rename_names": plan.rename_names,
                "count": plan.items.len(),
                "items": plan.items.iter().map(|item| json!({
                    "from": item.source.path,
                    "name": item.target_name,
                })).collect::<Vec<_>>(),
            }))
        }
        "rpc" => crate::remoteops::rpc(st, params),
        other => Err(RemoteError::new(format!(
            "Unknown remote operation: {other}"
        ))),
    }
}

fn sftp_dependency_json(target: &Target, info: &ToolInfo) -> RResult<Value> {
    let status = ssh::sftp::ensure_sftp(target).map_err(RemoteError::new)?;
    let (installed, can_install, sftp) = match status {
        ssh::sftp::SftpStatus::Ready => (true, info.can_install, Value::Null),
        ssh::sftp::SftpStatus::Missing => (false, info.can_install, Value::Null),
        ssh::sftp::SftpStatus::Disabled => (false, info.can_install, json!("disabled")),
    };
    Ok(json!({
        "tool": "sftp",
        "installed": installed,
        "available": installed,
        "running": false,
        "package_name": crate::tools::package_name_for("sftp"),
        "installer": info.installer,
        "can_install": can_install,
        "root": info.root,
        "sftp": sftp,
    }))
}

fn dependency(st: &Arc<AppState>, params: &Params) -> RResult<Value> {
    let tool = params.get("tool").unwrap_or_default();
    if !crate::tools::valid_name(&tool) {
        return Err(RemoteError::new("Invalid tool name"));
    }
    let device_id = params.get("device_id").unwrap_or_default();
    if !device_id.is_empty() && tool == "ucode" {
        return Ok(json!({
            "tool": tool,
            "installed": true,
            "available": true,
            "running": false,
            "package_name": "in-process",
            "can_install": false,
            "installer": "in-process",
        }));
    }
    if tool == "sftp" {
        if device_id.is_empty() {
            return Err(RemoteError::new("sftp is provided by the remote device"));
        }
        let device = checked_device(st, &device_id, params.get("device_revision").as_deref())?;
        ensure_trusted(st, &device)?;
        let target = authenticated_target(st, &device);
        let info = tool_info(Some(&target))?;
        return sftp_dependency_json(&target, &info);
    }
    let (installed, info) = if device_id.is_empty() {
        let info = tool_info(None)?;
        let installed = match tool.as_str() {
            "stat" => info.stat,
            _ => meta::have_tool(&tool),
        };
        (installed, info)
    } else {
        let device = checked_device(st, &device_id, params.get("device_revision").as_deref())?;
        ensure_trusted(st, &device)?;
        let target = authenticated_target(st, &device);
        let info = tool_info_cached(Some(&target), true)?;
        let installed = if tool == "stat" {
            info.stat
        } else {
            device_tool_available(&target, &tool)?
        };
        (installed, info)
    };
    let mapped = crate::tools::package_for(&tool);
    Ok(json!({
        "tool": tool.clone(),
        "installed": installed,
        "available": installed,
        "running": false,
        "stat_provider": if tool == "stat" { info.stat_provider.clone() } else { String::new() },
        "package_name": if mapped.is_empty() { tool.clone() } else { mapped.to_string() },
        "installer": info.installer,
        "can_install": info.can_install,
        "root": info.root,
    }))
}

fn save_device(st: &Arc<AppState>, params: &Params) -> RResult<Value> {
    let name = params.get("name").unwrap_or_default().trim().to_string();
    if name.is_empty() || name.chars().count() > 128 {
        return Err(RemoteError::new("Invalid device name"));
    }
    let existing = {
        let id = params.get("id").unwrap_or_default();
        if id.is_empty() {
            None
        } else {
            Some(find_device(st, &id).ok_or_else(|| RemoteError::new("Device not found"))?)
        }
    };
    let mut host = params.get("host").unwrap_or_default().trim().to_string();
    if host.starts_with('[') && host.ends_with(']') && host.len() > 2 {
        host = host[1..host.len() - 1].to_string();
    }
    let host_provided = !host.is_empty();
    if !host_provided {
        host = existing
            .as_ref()
            .map(|device| device.host.clone())
            .unwrap_or_default();
    }
    if host_provided {
        if host.len() > 253
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".:%_-".contains(c))
        {
            return Err(RemoteError::new("Invalid IP address or domain name"));
        }
    } else if host.is_empty() {
        return Err(RemoteError::new("Invalid IP address or domain name"));
    }
    let raw_username = params.get("username").unwrap_or_default();
    let username = if raw_username.is_empty() {
        existing
            .as_ref()
            .map(|device| device.username.clone())
            .unwrap_or_default()
    } else {
        raw_username.clone()
    };
    if !raw_username.is_empty() {
        if username.len() > 64
            || !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
            || username.starts_with('-')
        {
            return Err(RemoteError::new("Invalid username"));
        }
    } else if username.is_empty() && existing.is_none() {
        return Err(RemoteError::new("Invalid username"));
    }
    let raw_port = params.get("port").map(|value| value.trim().to_string());
    let port: u16 = match raw_port.as_deref() {
        Some("") | None if existing.is_some() => {
            existing.as_ref().map(|device| device.port).unwrap_or(22)
        }
        Some("") => return Err(RemoteError::new("Invalid port")),
        None => 22,
        Some(value) => {
            let port: u16 = value
                .parse()
                .map_err(|_| RemoteError::new("Invalid port"))?;
            if port == 0 {
                return Err(RemoteError::new("Invalid port"));
            }
            port
        }
    };
    let password = params.get("password").unwrap_or_default();
    if password.is_empty() {
        if !existing.as_ref().is_some_and(|device| device.has_password) {
            return Err(RemoteError::new(
                "A password is required for a new device or a device without a saved password",
            ));
        }
    } else if password.trim().is_empty()
        || password.len() > 1024
        || password.contains('\0')
        || password.contains('\n')
        || password.contains('\r')
    {
        return Err(RemoteError::new(
            "Invalid password: use 1–1024 bytes, not only whitespace, with no line breaks or NUL characters",
        ));
    }

    let mut uci = load_uci(st);
    let id = match &existing {
        Some(device) => device.id.clone(),
        None => uci.add_section("remote_device").name.clone(),
    };
    let host_changed = existing
        .as_ref()
        .map(|device| {
            !device.host.eq_ignore_ascii_case(&host)
                || device.port != port
                || device.username != username
        })
        .unwrap_or(true);
    let revision = if host_changed
        || existing
            .as_ref()
            .map(|d| d.revision.is_empty())
            .unwrap_or(true)
    {
        crate::uci::random_hex(16)
    } else {
        existing
            .as_ref()
            .map(|d| d.revision.clone())
            .unwrap_or_default()
    };
    {
        let section = uci
            .section_mut(&id)
            .ok_or_else(|| RemoteError::new("Cannot save device"))?;
        section.set("name", &name);
        section.set("host", &host);
        section.set("port", &port.to_string());
        section.set("username", &username);
        section.set("revision", &revision);

        section.remove("password");
        if host_changed {
            section.remove("host_key");
        }
    }
    uci.save(&st.settings.config_path)
        .map_err(|_| RemoteError::new("Cannot save device"))?;
    restrict_config_permissions(&st.settings.config_path);

    let mut store = secret_store(st);
    if !password.is_empty() {
        store.set(&id, &password);
    }
    store.save().map_err(RemoteError::new)?;
    ssh::close_device_sessions(&id);
    if host_changed {
        st.system_access.revoke_device(&id);
    }
    Ok(json!({ "id": id, "revision": revision }))
}

fn delete_device(st: &Arc<AppState>, params: &Params) -> RResult<Value> {
    let id = params.get("id").unwrap_or_default();
    let device = find_device(st, &id).ok_or_else(|| RemoteError::new("Device not found"))?;
    let mut uci = load_uci(st);
    uci.sections.retain(|section| section.name != device.id);
    uci.save(&st.settings.config_path)
        .map_err(|_| RemoteError::new("Cannot delete device"))?;
    let mut store = secret_store(st);
    store.remove(&device.id);
    let _ = store.save();
    ssh::close_device_sessions(&device.id);
    st.system_access.revoke_device(&device.id);
    Ok(json!({}))
}

fn start_transfer(st: &Arc<AppState>, params: &Params) -> RResult<Value> {
    let plan = build_plan(st, params)?;
    let action = params
        .get("conflict_action")
        .unwrap_or_else(|| "error".to_string());
    if !["overwrite", "error", "rename", "skip"].contains(&action.as_str()) {
        return Err(RemoteError::new("Invalid conflict action"));
    }
    if !plan.conflicts.is_empty() && action == "error" {
        return Err(RemoteError::new("Target already exists"));
    }
    let operation = params
        .get("operation")
        .unwrap_or_else(|| "copy".to_string());

    let excluded: Vec<String> = match params.get("exclude_paths") {
        Some(raw) => {
            let parsed: Value =
                serde_json::from_str(&raw).map_err(|_| RemoteError::new("Invalid selection"))?;
            parsed
                .as_array()
                .ok_or_else(|| RemoteError::new("Invalid selection"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .and_then(normalize_path)
                        .ok_or_else(|| RemoteError::new("Invalid selection"))
                })
                .collect::<RResult<Vec<_>>>()?
        }
        None => Vec::new(),
    };
    let mut items: Vec<TransferItem> = plan
        .items
        .into_iter()
        .filter(|item| {
            !excluded
                .iter()
                .any(|path| crate::paths::is_descendant(path, &item.source.path))
        })
        .collect();
    if action == "skip" {
        let conflicted: std::collections::BTreeSet<String> = plan
            .conflicts
            .iter()
            .filter_map(|c| c["path"].as_str().map(str::to_string))
            .collect();
        items.retain(|item| !conflicted.contains(&item.source.path));
    }
    if plan.same_directory {
        items.retain(|item| item.target_name != item.source.name);
    }
    if items.is_empty() {
        return Ok(json!({
            "operation": operation,
            "source_results": [],
            "done": true,
            "success": true,
            "bytes": 0,
            "elapsed": 0,
        }));
    }

    if plan.source.is_none() || plan.target.is_none() {
        require_tool("tar", "tar")?;
    }
    let total: u64 = items
        .iter()
        .map(|item| item.source.size.max(0) as u64)
        .sum();

    if plan.source.is_none() && plan.target.is_none() {
        return Err(RemoteError::new("A remote device is required"));
    }
    let source_target = plan
        .source
        .as_ref()
        .map(|device| authenticated_target(st, device));
    let target_target = plan
        .target
        .as_ref()
        .map(|device| authenticated_target(st, device));

    let parent = plan.parent.clone();
    let dest = plan.dest.clone();
    let state = json!({
        "operation": operation,
        "started": meta::now_secs(),
        "done": false,
        "success": false,
        "total": total,
        "source_device": plan.source.as_ref().map(|d| d.id.clone()).unwrap_or_default(),
        "target_device": plan.target.as_ref().map(|d| d.id.clone()).unwrap_or_default(),
        "target_dir": dest,
        "items": items.iter().map(|i| json!({ "from": i.source.path, "name": i.target_name })).collect::<Vec<_>>(),
    });
    let remove_source = operation == "move";
    let overwrite = action == "overwrite";
    let state_for_policy = Arc::clone(st);
    let session = params.get("__system_session_id").unwrap_or_default();
    let source_id = plan
        .source
        .as_ref()
        .map(|device| device.id.clone())
        .unwrap_or_default();
    let target_id = plan
        .target
        .as_ref()
        .map(|device| device.id.clone())
        .unwrap_or_default();
    let source_revision = plan
        .source
        .as_ref()
        .map(|device| device.revision.clone())
        .unwrap_or_default();
    let target_revision = plan
        .target
        .as_ref()
        .map(|device| device.revision.clone())
        .unwrap_or_default();
    let permit = st.limits.begin_transfer().ok_or_else(|| {
        RemoteError::with_data(
            "Too many active transfers",
            json!({"error_code": "queue_full"}),
        )
    })?;
    let task_id = spawn_cancellable_task(st, state, move |dir, control| {
        let _permit = permit;
        transfer_cancel_checkpoint(Some(&control), None)?;
        write_progress(&dir, 0, total, "scanning");
        let source_side = match &source_target {
            Some(target) => Side::Remote {
                target,
                dir: &parent,
            },
            None => Side::Local { dir: &parent },
        };
        let target_side = match &target_target {
            Some(target) => Side::Remote { target, dir: &dest },
            None => Side::Local { dir: &dest },
        };
        let mut source_tools = vec!["tar", "find", "readlink"];
        if remove_source {
            source_tools.extend(["rm", "rmdir", "stat"]);
        }
        let mut target_tools = vec!["tar", "find", "readlink", "mv", "mkdir", "rm", "cat"];
        if overwrite {
            target_tools.extend(["cp", "stat"]);
        }
        std::thread::scope(|scope| {
            let source_check = scope.spawn(|| {
                require_transfer_side_tools(
                    &source_side,
                    &source_tools,
                    &source_id,
                    &source_revision,
                )
            });
            let target_check = scope.spawn(|| {
                require_transfer_side_tools(
                    &target_side,
                    &target_tools,
                    &target_id,
                    &target_revision,
                )
            });
            source_check
                .join()
                .unwrap_or_else(|_| Err(RemoteError::new("Transfer tool check failed")))
                .and(
                    target_check
                        .join()
                        .unwrap_or_else(|_| Err(RemoteError::new("Transfer tool check failed"))),
                )
        })
        .map_err(safe_preflight)?;
        transfer_cancel_checkpoint(Some(&control), None)?;
        let security = TransferSecurity {
            state: &state_for_policy,
            session: &session,
            source_device: &source_id,
            target_device: &target_id,
        };
        let mut scan = PathReporter::scanning(Some(&dir), total);
        let checked = authorize_transfer_tree_reported(
            &security,
            &source_side,
            &target_side,
            &items,
            &excluded,
            overwrite,
            Some(&mut scan),
        )
        .map_err(safe_preflight)?;
        transfer_cancel_checkpoint(Some(&control), None)?;
        staged_transfer_controlled(
            &source_side,
            &target_side,
            &items,
            StagedTransferOptions {
                excluded: &excluded,
                remove_source,
                overwrite,
                task_dir: &dir,
                total,
                authorization: Some((&security, &checked)),
                control: Some(&control),
            },
        )
    })?;

    Ok(json!({
        "task_id": task_id,
        "operation": operation,
        "started": meta::now_secs(),
        "done": false,
        "cancelable": true,
        "cancel_requested": false,
        "total": total,
        "target_dir": plan.dest,
    }))
}

fn cancelled_transfer(stage: Option<&str>, remote_writer_may_continue: bool) -> RemoteError {
    let mut data = json!({"cancel_requested": true});
    if remote_writer_may_continue {
        data["outcome_unknown"] = json!(true);
    } else {
        data["cancelled"] = json!(true);
    }
    if let Some(stage) = stage {
        data["staging_path"] = json!(stage);
        data["partial"] = json!(true);
    }
    RemoteError::with_data(
        if remote_writer_may_continue {
            "Cancellation was requested, but the remote writer may still be running; inspect the staging directory before retrying"
        } else if stage.is_some() {
            "Transfer cancelled before publication; source and destination were retained, but staging files remain"
        } else {
            "Transfer cancelled before publication; source and destination were retained"
        },
        data,
    )
}

fn transfer_cancel_checkpoint(
    control: Option<&crate::task_registry::JobControl>,
    stage: Option<&str>,
) -> RResult<()> {
    if control.is_some_and(|control| control.requested()) {
        Err(cancelled_transfer(stage, false))
    } else {
        Ok(())
    }
}

fn transfer_error(mut error: RemoteError, stage: Option<&str>) -> RemoteError {
    error.message = format!(
        "Transfer may be partial; inspect source and destination before retrying: {}",
        error.message
    );
    if !error.data.is_object() {
        error.data = json!({});
    }
    error.data["partial"] = json!(true);
    error.data["preflight_safe"] = json!(false);
    if let Some(stage) = stage {
        error.data["staging_path"] = json!(stage);
    }
    error
}

fn staged_publish_line(
    stage: &str,
    dest: &str,
    item: &TransferItem,
    overwrite: bool,
    index: usize,
) -> String {
    let source_path = join_path(&join_path(stage, "incoming"), &item.source.name);
    let target_path = join_path(dest, &item.target_name);
    let previous_path = join_path(&join_path(stage, "previous"), &index.to_string());
    let merged_path = join_path(&join_path(stage, "merged"), &index.to_string());
    let assigns = format!(
        "s={}\nt={}\np={}\nm={}\ng={}\n",
        shell_quote(&source_path),
        shell_quote(&target_path),
        shell_quote(&previous_path),
        shell_quote(&merged_path),
        shell_quote(stage)
    );
    let no_clobber = "mv -nT \"$s\" \"$t\" && { [ ! -e \"$s\" ] && [ ! -L \"$s\" ]; } || { echo 'Target already exists or publication failed' >&2; exit 1; }";
    if !overwrite {
        return format!("{assigns}[ -e \"$s\" ] || [ -L \"$s\" ] || exit 1\n{no_clobber}");
    }
    format!(
        r#"{assigns}[ -e "$s" ] || [ -L "$s" ] || exit 1
if [ ! -e "$t" ] && [ ! -L "$t" ]; then
    {no_clobber}
else
    statdev() {{ stat -c %d -- "$1" 2>/dev/null || gnu-stat -c %d -- "$1" 2>/dev/null || /usr/libexec/stat-coreutils -c %d -- "$1" 2>/dev/null || busybox stat -c %d -- "$1" 2>/dev/null; }}
    target_dev=$(statdev "$t") || exit 1
    stage_dev=$(statdev "$g") || exit 1
    [ "$target_dev" = "$stage_dev" ] || {{ echo 'Cannot overwrite a mount point on another filesystem' >&2; exit 1; }}
    if {{ [ ! -d "$t" ] || [ -L "$t" ]; }} && {{ [ ! -d "$s" ] || [ -L "$s" ]; }}; then
        mv -nT "$t" "$p" || exit 1
        [ ! -e "$t" ] && [ ! -L "$t" ] || {{ echo 'Target changed during publication' >&2; exit 1; }}
        if mv -nT "$s" "$t" && [ ! -e "$s" ] && [ ! -L "$s" ]; then
            rm -rf -- "$p"
        else
            if [ ! -e "$t" ] && [ ! -L "$t" ]; then mv -nT "$p" "$t" || :; fi
            echo 'Publication failed; inspect the staging directory for the previous target' >&2
            exit 1
        fi
    else
        if [ -d "$t" ] && [ ! -L "$t" ] && [ -d "$s" ] && [ ! -L "$s" ]; then
            if ! cp -alT "$t" "$m" 2>/dev/null; then
                rm -rf -- "$m"
                cp -aT "$t" "$m" || exit 1
            fi
            cp -a "$s/." "$m/" || exit 1
            publish=$m
        else
            publish=$s
        fi
        mv -nT "$t" "$p" || exit 1
        [ ! -e "$t" ] && [ ! -L "$t" ] || {{ echo 'Target changed during publication' >&2; exit 1; }}
        if mv -nT "$publish" "$t" && [ ! -e "$publish" ] && [ ! -L "$publish" ]; then
            rm -rf -- "$p"
        else
            if [ ! -e "$t" ] && [ ! -L "$t" ]; then mv -nT "$p" "$t" || :; fi
            echo 'Publication failed; inspect the staging directory for the previous target' >&2
            exit 1
        fi
    fi
fi"#
    )
}

struct StagedTransferOptions<'a, 'security> {
    excluded: &'a [String],
    remove_source: bool,
    overwrite: bool,
    task_dir: &'a Path,
    total: u64,
    authorization: Option<(
        &'a TransferSecurity<'security>,
        &'a std::collections::BTreeSet<String>,
    )>,
    control: Option<&'a crate::task_registry::JobControl>,
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn staged_transfer(
    source: &Side<'_>,
    target: &Side<'_>,
    items: &[TransferItem],
    excluded: &[String],
    remove_source: bool,
    overwrite: bool,
    task_dir: &Path,
    total: u64,
    authorization: Option<(&TransferSecurity<'_>, &std::collections::BTreeSet<String>)>,
) -> RResult<()> {
    staged_transfer_controlled(
        source,
        target,
        items,
        StagedTransferOptions {
            excluded,
            remove_source,
            overwrite,
            task_dir,
            total,
            authorization,
            control: None,
        },
    )
}

fn staged_transfer_controlled(
    source: &Side<'_>,
    target: &Side<'_>,
    items: &[TransferItem],
    options: StagedTransferOptions<'_, '_>,
) -> RResult<()> {
    let StagedTransferOptions {
        excluded,
        remove_source,
        overwrite,
        task_dir,
        total,
        authorization,
        control,
    } = options;
    transfer_cancel_checkpoint(control, None)?;
    let names: Vec<String> = items.iter().map(|item| item.source.name.clone()).collect();
    let target_names: Vec<String> = items.iter().map(|item| item.target_name.clone()).collect();
    if remove_source {
        ensure_no_nested_mounts(source, &names)?;
    }
    if overwrite {
        ensure_no_nested_mounts(target, &target_names)?;
    }
    transfer_cancel_checkpoint(control, None)?;
    if remove_source && try_rename_move(source, target, items, overwrite, control)? {
        write_progress(task_dir, total, total, "complete");
        return Ok(());
    }
    let original = if remove_source {
        Some(tree_manifest_reported(source, &names, excluded, None)?)
    } else {
        None
    };
    let stage = join_path(
        target.dir(),
        &format!(".harbor-transfer-{}", crate::uci::random_hex(16)),
    );
    let incoming = join_path(&stage, "incoming");
    let previous = join_path(&stage, "previous");
    let merged = join_path(&stage, "merged");
    update_task_fields(task_dir, &json!({"staging_path": stage}))?;
    let create = format!(
        "umask 077; mkdir -m 700 {} && mkdir -m 700 {} {} {}",
        shell_quote(&stage),
        shell_quote(&incoming),
        shell_quote(&previous),
        shell_quote(&merged)
    );
    target
        .run_mutating_once(&create, Some(60))
        .map_err(|error| transfer_error(error, Some(&stage)))?;
    transfer_cancel_checkpoint(control, Some(&stage))?;
    let staged_side = match target {
        Side::Local { .. } => Side::Local { dir: &incoming },
        Side::Remote { target, .. } => Side::Remote {
            target,
            dir: &incoming,
        },
    };
    let copied = stream_tree_controlled(
        source,
        &staged_side,
        &TreeSelection {
            source_names: &names,
            source_excluded: excluded,
        },
        task_dir,
        total,
        control,
    )
    .map_err(|error| transfer_error(error, Some(&stage)))?;
    transfer_cancel_checkpoint(control, Some(&stage))?;
    if let Some((security, checked)) = authorization {
        if &authorize_transfer_tree(security, source, target, items, excluded, overwrite)
            .map_err(|error| transfer_error(error, Some(&stage)))?
            != checked
        {
            return Err(transfer_error(RemoteError::new("Transfer tree changed during authorization; source and destination were retained"), Some(&stage)));
        }
    }
    if overwrite {
        ensure_no_nested_mounts(target, &target_names)
            .map_err(|error| transfer_error(error, Some(&stage)))?;
    }
    if let Some(original) = original.as_ref() {
        let current = tree_manifest_reported(source, &names, excluded, None)
            .map_err(|error| transfer_error(error, Some(&stage)))?;
        if &current != original {
            return Err(transfer_error(
                RemoteError::new("Source changed during transfer; source was retained"),
                Some(&stage),
            ));
        }
    }
    write_progress(task_dir, copied, total, "publishing");
    let lines: Vec<String> = items
        .iter()
        .enumerate()
        .map(|(index, item)| staged_publish_line(&stage, target.dir(), item, overwrite, index))
        .collect();
    if lines
        .iter()
        .any(|line| ssh::script_exec_len(&format!("set -e\n{line}")) > ssh::SCRIPT_EXEC_LIMIT)
    {
        return Err(transfer_error(
            RemoteError::new("Transfer publication path is too long"),
            Some(&stage),
        ));
    }
    if control.is_some_and(|control| !control.seal()) {
        return Err(cancelled_transfer(Some(&stage), false));
    }
    for line in lines {
        target
            .run_mutating_once(&format!("set -e\n{line}"), Some(900))
            .map_err(|error| transfer_error(error, Some(&stage)))?;
    }
    if remove_source {
        if let Some((security, checked)) = authorization {
            if &authorize_transfer_tree(security, source, target, items, excluded, overwrite)
                .map_err(|error| transfer_error(error, Some(&stage)))?
                != checked
            {
                return Err(transfer_error(
                    RemoteError::new(
                        "Transfer tree changed during authorization; source was retained",
                    ),
                    Some(&stage),
                ));
            }
        }
        let original = original.ok_or_else(|| {
            transfer_error(
                RemoteError::new("Empty verification listing; source was retained"),
                Some(&stage),
            )
        })?;
        let current = tree_manifest_reported(source, &names, excluded, None)
            .map_err(|error| transfer_error(error, Some(&stage)))?;
        if current != original {
            return Err(transfer_error(
                RemoteError::new("Source changed during transfer; source was retained"),
                Some(&stage),
            ));
        }
        ensure_no_nested_mounts(source, &names)
            .map_err(|error| transfer_error(error, Some(&stage)))?;
        write_progress(task_dir, copied, total, "deleting");
        remove_transferred_sources(source, &original, excluded)
            .map_err(|error| transfer_error(error, Some(&stage)))?;
    }
    ensure_no_nested_mounts(target, &[crate::paths::path_name(&stage)])
        .map_err(|error| transfer_error(error, Some(&stage)))?;
    target
        .run_mutating_once(&format!("rm -rf -- {}", shell_quote(&stage)), Some(900))
        .map_err(|error| transfer_error(error, Some(&stage)))?;
    write_progress(task_dir, copied, total, "complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ssh_workspaces_are_partitioned_by_target_and_host_key() {
        let id = format!("workspace-test-{}", crate::uci::random_hex(8));
        let base = crate::ssh::Target {
            id,
            host: "host.invalid".into(),
            port: 22,
            username: "alice".into(),
            host_key: "SHA256:workspace-fixture".into(),
            ..Default::default()
        };
        let first = super::workspace(&base).unwrap();
        let same = super::workspace(&base).unwrap();
        let mut changed = base.clone();
        changed.host_key.push('x');
        let second = super::workspace(&changed).unwrap();
        assert_eq!(first.path(), same.path());
        assert_ne!(first.path(), second.path());
        assert!(crate::tasks::check_private_dir(first.path()).is_ok());
        assert!(crate::tasks::check_private_dir(second.path()).is_ok());
        std::fs::remove_dir_all(first.path()).unwrap();
        std::fs::remove_dir_all(second.path()).unwrap();
    }
    use super::*;

    #[test]
    fn same_remote_endpoint_matches_host_port_user() {
        let a = crate::ssh::Target {
            host: "10.0.0.8".into(),
            port: 22,
            username: "root".into(),
            ..Default::default()
        };
        let mut b = a.clone();
        b.id = "other".into();
        assert!(same_remote_endpoint(
            &Side::Remote {
                target: &a,
                dir: "/tmp",
            },
            &Side::Remote {
                target: &b,
                dir: "/abc",
            }
        ));
        b.port = 2222;
        assert!(!same_remote_endpoint(
            &Side::Remote {
                target: &a,
                dir: "/tmp",
            },
            &Side::Remote {
                target: &b,
                dir: "/abc",
            }
        ));
        let empty = crate::ssh::Target {
            host: String::new(),
            port: 22,
            username: "root".into(),
            ..Default::default()
        };
        assert!(!same_remote_endpoint(
            &Side::Remote {
                target: &empty,
                dir: "/tmp",
            },
            &Side::Remote {
                target: &empty,
                dir: "/abc",
            }
        ));
    }

    #[test]
    fn take_progress_lines_keeps_errors() {
        let mut buf = b"P 12\nboom\nP 40\npartial".to_vec();
        assert_eq!(take_progress_lines(&mut buf), Some(40));
        assert_eq!(buf, b"boom\npartial");
    }

    #[test]
    fn policy_frames_fail_closed_on_truncation_or_invalid_data() {
        assert_eq!(
            parse_policy_frames(b"/alpha\0/beta\nend\0").unwrap(),
            vec!["/alpha", "/beta\nend"]
        );
        assert!(parse_policy_frames(b"").is_err());
        assert!(parse_policy_frames(b"/valid\0/partial").is_err());
        assert!(parse_policy_frames(b"/valid\0\0").is_err());
        assert!(parse_policy_frames(b"relative\0").is_err());
        assert!(parse_policy_frames(&[b'/', 0xff, 0]).is_err());
        let mut max = vec![b'x'; 16 * 1024 * 1024];
        max[0] = b'/';
        *max.last_mut().unwrap() = 0;
        assert!(parse_policy_frames(&max).is_err());
    }

    #[test]
    fn task_worker_reports_success_failures_and_panics() {
        let root =
            std::env::temp_dir().join(format!("harbor-task-test-{}", crate::uci::random_hex(8)));
        let st = AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            ..Default::default()
        });
        fn await_done(st: &AppState, id: &str) -> Value {
            for _ in 0..100 {
                let status = task_status(st, id).unwrap();
                if status["done"] == json!(true) {
                    return status;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("task did not finish");
        }
        let success = spawn_task(&st, json!({"operation": "test"}), |dir| {
            write_progress(&dir, 7, 10, "copying");
            Ok(())
        })
        .unwrap();
        let status = await_done(&st, &success);
        assert_eq!(status["success"], json!(true));
        assert_eq!(status["bytes"], json!(7));
        let failure = spawn_task(&st, json!({"operation": "test"}), |_| {
            Err(RemoteError::with_code_data(
                3,
                "clash",
                json!({"conflicts": ["x"]}),
            ))
        })
        .unwrap();
        let status = await_done(&st, &failure);
        assert_eq!(status["state"], json!("failed"));
        assert_eq!(status["failure_code"], json!(3));
        assert_eq!(status["failure_data"]["conflicts"], json!(["x"]));
        let panicking =
            spawn_task(&st, json!({"operation": "test"}), |_| panic!("test panic")).unwrap();
        let status = await_done(&st, &panicking);
        assert_eq!(status["done"], json!(true));
        assert_eq!(status["success"], json!(false));
        for id in [success, failure, panicking] {
            let _ = std::fs::remove_dir_all(Path::new(REMOTE_ROOT).join(id));
        }
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    fn transfer_item(name: &str, target_name: &str) -> TransferItem {
        TransferItem {
            source: RemoteItem {
                name: name.to_string(),
                path: format!("/src/{name}"),
                kind: "file".to_string(),
                size: 7,
                mtime: 0,
                mode: "0644".to_string(),
                is_symlink: false,
                link_target: String::new(),
            },
            target_name: target_name.to_string(),
        }
    }

    #[test]
    fn into_itself_error_waits_for_conflict_rename() {
        let source = "/mnt/a/folder";
        assert!(into_itself_rejected(
            "directory",
            false,
            true,
            source,
            source,
            false,
            ""
        ));
        assert!(into_itself_rejected(
            "directory",
            false,
            true,
            "/mnt/a/folder/inner",
            source,
            false,
            ""
        ));
        assert!(into_itself_rejected(
            "directory",
            false,
            true,
            source,
            source,
            true,
            "overwrite"
        ));
        assert!(!into_itself_rejected(
            "directory",
            false,
            true,
            "/mnt/a/folder (2)",
            source,
            true,
            "rename"
        ));
        assert!(!into_itself_rejected(
            "directory",
            false,
            true,
            source,
            source,
            true,
            "skip"
        ));
        assert!(!into_itself_rejected(
            "file", false, true, source, source, false, ""
        ));
        assert!(!into_itself_rejected(
            "directory",
            true,
            true,
            source,
            source,
            false,
            ""
        ));
        assert!(!into_itself_rejected(
            "directory",
            false,
            false,
            source,
            source,
            false,
            ""
        ));
    }

    #[test]
    fn parse_drives_filters_and_names_mounts_like_local() {
        let raw = "tmpfs 244864 27700 217164 12% /tmp\n\
                   overlay 5145088 267900 4615788 6% /\n\
                   /dev/mmcblk0p6 53786164 35240628 15825676 69% /mnt/data\n\
                   proc 0 0 0 0% /proc\n\
                   /dev/sda1 1000 500 500 50% /mnt/usb\n\
                   /dev/sda1 1000 500 500 50% /mnt/usb2\n";
        let drives = parse_drives(raw);
        assert_eq!(drives.len(), 4);
        assert_eq!(drives[0]["name"], "Temporary Space");
        assert_eq!(drives[1]["name"], "System Disk");
        assert_eq!(drives[1]["is_system"], true);
        assert_eq!(drives[2]["name"], "mmcblk0p6");
        assert_eq!(drives[2]["path"], "/mnt/data");
        assert_eq!(drives[2]["total_kb"], 53786164);
        assert_eq!(drives[2]["usage_percent"], 65);
        assert_eq!(drives[3]["name"], "sda1");
    }

    #[test]
    fn parse_drives_keeps_root_and_tmp() {
        let raw = "overlay 5145088 267900 4615788 6% /\ntmpfs 244864 27700 217164 12% /tmp\n";
        let drives = parse_drives(raw);
        assert_eq!(drives.len(), 2);
        assert_eq!(drives[0]["path"], "/");
        assert_eq!(drives[1]["path"], "/tmp");
    }

    #[test]
    fn staged_publication_scripts_are_individually_bounded() {
        for i in 0..600 {
            let item = transfer_item(&format!("file-{i}.txt"), &format!("file-{i}.txt"));
            let script = staged_publish_line(
                "/target dir/.harbor-transfer-test",
                "/target dir",
                &item,
                true,
                i,
            );
            assert!(ssh::script_exec_len(&format!("set -e\n{script}")) <= ssh::SCRIPT_EXEC_LIMIT);
        }
    }

    #[test]
    fn local_stream_direction_has_explicit_stdin_semantics() {
        let side = Side::Local { dir: "/tmp" };
        let read = side
            .spawn("cat; printf eof", TransferDirection::Read)
            .unwrap();
        assert!(
            read.stdin.is_none(),
            "read side must receive EOF, not an open pipe"
        );
        let output = read.wait_with_output().unwrap();
        assert!(output.success());
        assert_eq!(output.stdout, b"eof");
        let mut write = side.spawn("cat", TransferDirection::Write).unwrap();
        assert!(write.stdin.is_some(), "write side must expose a pipe");
        write
            .stdin
            .take()
            .unwrap()
            .write_all(b"sent to stdin")
            .unwrap();
        let output = write.wait_with_output().unwrap();
        assert!(output.success());
        assert_eq!(output.stdout, b"sent to stdin");
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_tar_streams_in_both_directions_with_explicit_stdin() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-tree", 60).expect("HARBOR_E2E_SSH_PORT");
        let id = crate::uci::random_hex(8);
        let local = std::env::temp_dir().join(format!("harbor-stream-local-{id}"));
        let remote_root = format!("/tmp/harbor-stream-remote-{id}");
        let src = local.join("src");
        let dst = local.join("dst");
        let task = local.join("task");
        std::fs::create_dir_all(src.join("folder/sub")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::create_dir_all(&task).unwrap();
        let bytes: Vec<u8> = (0..300_000).map(|n| (n % 251) as u8).collect();
        std::fs::write(src.join("folder/sub/a quote' 数据.bin"), &bytes).unwrap();
        std::fs::write(src.join("folder/empty"), b"").unwrap();
        run(
            &target,
            &format!("mkdir -p -- {}", shell_quote(&remote_root)),
            Some(30),
        )
        .unwrap();
        let remote = Side::Remote {
            target: &target,
            dir: &remote_root,
        };
        let read = remote
            .spawn("cat; printf eof", TransferDirection::Read)
            .unwrap();
        assert!(read.stdin.is_none(), "remote read must receive EOF");
        let output = read.wait_with_output().unwrap();
        assert!(
            output.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"eof");
        let mut write = remote.spawn("cat", TransferDirection::Write).unwrap();
        assert!(write.stdin.is_some(), "remote write must expose stdin");
        write
            .stdin
            .take()
            .unwrap()
            .write_all(b"ssh stream")
            .unwrap();
        let output = write.wait_with_output().unwrap();
        assert!(output.success());
        assert_eq!(output.stdout, b"ssh stream");
        let names = vec!["folder".to_string()];
        let selection = TreeSelection {
            source_names: &names,
            source_excluded: &[],
        };
        let local_source = Side::Local {
            dir: src.to_str().unwrap(),
        };
        let local_target = Side::Local {
            dir: dst.to_str().unwrap(),
        };
        assert!(
            stream_tree(
                &local_source,
                &remote,
                &selection,
                &task,
                bytes.len() as u64
            )
            .unwrap()
                >= bytes.len() as u64
        );
        assert!(
            stream_tree(
                &remote,
                &local_target,
                &selection,
                &task,
                bytes.len() as u64
            )
            .unwrap()
                >= bytes.len() as u64
        );
        assert_eq!(
            std::fs::read(dst.join("folder/sub/a quote' 数据.bin")).unwrap(),
            bytes
        );
        assert_eq!(std::fs::read(dst.join("folder/empty")).unwrap(), b"");
        run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&remote_root)),
            Some(30),
        )
        .unwrap();
        std::fs::remove_dir_all(local).unwrap();
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_cross_filesystem_copy_and_verified_move() {
        use std::os::unix::fs::MetadataExt;
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-cross-filesystem", 60).expect("HARBOR_E2E_SSH_PORT");
        let Ok(cross_base) = std::env::var("HARBOR_E2E_CROSS_FS") else {
            eprintln!("cross-filesystem E2E not configured (HARBOR_E2E_CROSS_FS), skipped");
            return;
        };
        let id = crate::uci::random_hex(8);
        let local = std::path::Path::new(&cross_base).join(format!("harbor-cross-{id}"));
        let remote_root = format!("/tmp/harbor-cross-{id}");
        assert_ne!(
            std::fs::metadata(&cross_base).unwrap().dev(),
            std::fs::metadata("/tmp").unwrap().dev(),
            "test requires distinct local mounts"
        );
        std::fs::create_dir_all(local.join("src/folder/sub")).unwrap();
        std::fs::create_dir_all(local.join("out")).unwrap();
        let bytes: Vec<u8> = (0..200_000).map(|n| (n % 251) as u8).collect();
        std::fs::write(local.join("src/folder/sub/data.bin"), &bytes).unwrap();
        std::fs::write(local.join("src/folder/skip.txt"), b"excluded").unwrap();
        std::fs::write(local.join("src/move.bin"), b"verified move").unwrap();
        run(
            &target,
            &format!("mkdir -p -- {}/dest", shell_quote(&remote_root)),
            Some(30),
        )
        .unwrap();
        let (seed, state_dir) = crate::ssh::e2e_state(&target, "/");
        let mut settings = seed.settings.clone();
        settings.root_policy = crate::state::RootPolicy::Unrestricted;
        settings.roots.clear();
        let st = AppState::new(settings);
        let session = "cross-filesystem-test";
        st.system_access.grant(session, "", "*", 600);
        st.system_access.grant(session, &target.id, "*", 600);
        let wait = |id: &str| {
            for _ in 0..300 {
                let value = task_status(&st, id).unwrap();
                if value["done"] == json!(true) {
                    assert_eq!(value["success"], true, "{value}");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            panic!("transfer {id} did not complete");
        };
        let mut p = Params::default();
        p.set("target_device", &target.id);
        p.set("target_revision", "e2e");
        p.set("target_dir", &format!("{remote_root}/dest"));
        p.set("operation", "copy");
        p.set("conflict_action", "error");
        p.set("__system_session_id", session);
        p.set(
            "sources",
            &json!([
                local.join("src/folder").to_str().unwrap(),
                local.join("src/move.bin").to_str().unwrap()
            ])
            .to_string(),
        );
        p.set(
            "exclude_paths",
            &json!([local.join("src/folder/skip.txt").to_str().unwrap()]).to_string(),
        );
        let started = start_transfer(&st, &p).unwrap();
        let copy_id = started["task_id"].as_str().unwrap().to_string();
        wait(&copy_id);
        assert_eq!(
            run(
                &target,
                &format!("cat {}/dest/folder/sub/data.bin", shell_quote(&remote_root)),
                Some(30)
            )
            .unwrap(),
            bytes
        );
        assert!(run(
            &target,
            &format!(
                "test ! -e {}/dest/folder/skip.txt",
                shell_quote(&remote_root)
            ),
            Some(30)
        )
        .is_ok());
        assert!(local.join("src/move.bin").exists());
        let mut p = Params::default();
        p.set("source_device", &target.id);
        p.set("source_revision", "e2e");
        p.set("target_dir", local.join("out").to_str().unwrap());
        p.set("operation", "move");
        p.set("conflict_action", "error");
        p.set("__system_session_id", session);
        p.set(
            "sources",
            &json!([format!("{remote_root}/dest/move.bin")]).to_string(),
        );
        let started = start_transfer(&st, &p).unwrap();
        let move_id = started["task_id"].as_str().unwrap().to_string();
        wait(&move_id);
        assert_eq!(
            std::fs::read(local.join("out/move.bin")).unwrap(),
            b"verified move"
        );
        assert!(run(
            &target,
            &format!("test ! -e {}/dest/move.bin", shell_quote(&remote_root)),
            Some(30)
        )
        .is_ok());
        for id in [&copy_id, &move_id] {
            let _ = std::fs::remove_dir_all(std::path::Path::new(REMOTE_ROOT).join(id));
        }
        let _ = run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&remote_root)),
            Some(30),
        );
        drop(st);
        drop(seed);
        let _ = std::fs::remove_dir_all(state_dir);
        let _ = std::fs::remove_dir_all(local);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_staged_internal_transfer() {
        let _e2e_guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-shot", 60).expect("HARBOR_E2E_SSH_PORT");
        run(&target, "echo probe", Some(20)).expect("configured SSH E2E credentials must work");
        let base = format!("/tmp/harbor-shot-{}", crate::uci::random_hex(8));
        let setup = format!(
            "set -e\nmkdir -p {base}/src {base}/dst/md {base}/src/md\nprintf one > {base}/src/plain.txt\nprintf new > {base}/src/conf.txt\nprintf old > {base}/dst/conf.txt\nprintf keep > {base}/dst/md/keep.txt\nprintf inner > {base}/src/md/inner.txt\nprintf rename > {base}/src/ren.txt",
        );
        run(&target, &setup, Some(30)).unwrap();
        let item = |name: &str, target: &str| transfer_item(name, target);
        let copy_items = vec![
            item("plain.txt", "plain.txt"),
            item("conf.txt", "conf.txt"),
            item("md", "md"),
            item("ren.txt", "ren (2).txt"),
        ];
        let task_dir =
            std::env::temp_dir().join(format!("harbor-shot-task-{}", crate::uci::random_hex(4)));
        std::fs::create_dir_all(&task_dir).unwrap();
        let total = copy_items.iter().map(|i| i.source.size as u64).sum::<u64>();
        std::fs::write(task_dir.join("state"), b"{}").unwrap();
        let source_dir = format!("{base}/src");
        let dest_dir = format!("{base}/dst");
        let source = Side::Remote {
            target: &target,
            dir: &source_dir,
        };
        let destination = Side::Remote {
            target: &target,
            dir: &dest_dir,
        };
        staged_transfer(
            &source,
            &destination,
            &copy_items,
            &[],
            false,
            true,
            &task_dir,
            total,
            None,
        )
        .unwrap();
        let output = |script: String| {
            String::from_utf8_lossy(&run(&target, &script, Some(20)).unwrap())
                .trim()
                .to_string()
        };
        assert_eq!(output(format!("cat {base}/dst/plain.txt")), "one");
        assert_eq!(output(format!("cat {base}/dst/conf.txt")), "new");
        assert_eq!(output(format!("cat {base}/dst/md/keep.txt")), "keep");
        assert_eq!(output(format!("cat {base}/dst/md/inner.txt")), "inner");
        assert_eq!(
            output(format!(
                "cat {}",
                shell_quote(&format!("{base}/dst/ren (2).txt"))
            )),
            "rename"
        );
        assert_eq!(output(format!("cat {base}/src/plain.txt")), "one");
        assert_eq!(output(format!("cat {base}/src/conf.txt")), "new");
        let move_items = vec![item("plain.txt", "plain.txt")];
        let total = move_items.iter().map(|i| i.source.size as u64).sum::<u64>();
        staged_transfer(
            &source,
            &destination,
            &move_items,
            &[],
            true,
            true,
            &task_dir,
            total,
            None,
        )
        .unwrap();
        assert!(run(&target, &format!("test -e {base}/src/plain.txt"), Some(20)).is_err());
        assert!(run(&target, &format!("test -d {base}/src/md"), Some(20)).is_ok());
        assert_eq!(output(format!("cat {base}/dst/md/inner.txt")), "inner");
        assert_eq!(output(format!("cat {base}/dst/md/keep.txt")), "keep");
        assert_eq!(output(format!("cat {base}/src/conf.txt")), "new");
        let progress = std::fs::read_to_string(task_dir.join("progress")).unwrap_or_default();
        assert!(progress.ends_with(" complete"), "progress: {progress}");
        let _ = run(&target, &format!("rm -rf {base}"), Some(30));
        let _ = std::fs::remove_dir_all(&task_dir);
    }
}

#[cfg(test)]
mod listing_schema_parity_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn real_local_and_ssh_listings_share_fields_modes_and_links() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-schema", 60).expect("HARBOR_E2E_SSH_PORT");
        let dir = std::env::temp_dir().join(format!(
            "harbor-real-item-schema-{}",
            crate::uci::random_hex(8)
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir(dir.join("folder")).unwrap();
        std::fs::write(dir.join("odd name\nimage.jpg"), b"image").unwrap();
        std::fs::set_permissions(
            dir.join("odd name\nimage.jpg"),
            std::fs::Permissions::from_mode(0o2750),
        )
        .unwrap();
        symlink("odd name\nimage.jpg", dir.join("link.jpg")).unwrap();
        symlink("folder", dir.join("directory-link")).unwrap();
        symlink("missing-target", dir.join("dangling")).unwrap();
        let root = dir.to_str().unwrap();
        let local = local_listing(root).unwrap();
        let remote = listing(&target, root, false).unwrap();
        assert_eq!(local.items.len(), remote.items.len());
        for item in &remote.items {
            let local_item = local
                .items
                .iter()
                .find(|other| other.name == item.name)
                .unwrap();
            let path = dir.join(&item.name).to_string_lossy().into_owned();
            let lst = meta::lstat(&path).unwrap();
            let stat = meta::stat(&path).unwrap_or(lst);
            let expected = crate::api::fsops::stat_to_item(&item.name, &path, stat, Some(lst));
            assert_eq!(
                local_item.json(),
                expected,
                "local listing item {}",
                item.name
            );
            assert_eq!(item.json(), expected, "SSH listing item {}", item.name);
        }
        assert_eq!(
            remote
                .items
                .iter()
                .find(|item| item.name == "odd name\nimage.jpg")
                .unwrap()
                .json()["mode"],
            "2750"
        );
        assert_eq!(
            remote
                .items
                .iter()
                .find(|item| item.name == "directory-link")
                .unwrap()
                .json()["type"],
            "directory"
        );
        assert_eq!(
            remote
                .items
                .iter()
                .find(|item| item.name == "dangling")
                .unwrap()
                .json()["link_target"]["path"],
            dir.join("missing-target").to_str().unwrap()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn local_and_remote_items_use_exactly_one_schema() {
        let dir =
            std::env::temp_dir().join(format!("harbor-item-schema-{}", crate::uci::random_hex(8)));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("target.jpg"), b"image").unwrap();
        symlink("target.jpg", dir.join("link.jpg")).unwrap();
        for name in ["target.jpg", "link.jpg"] {
            let path = dir.join(name).to_string_lossy().into_owned();
            let stat = meta::stat(&path).unwrap();
            let lst = meta::lstat(&path).unwrap();
            let local = crate::api::fsops::stat_to_item(name, &path, stat, Some(lst));
            let remote = RemoteItem {
                name: name.into(),
                path: path.clone(),
                kind: if lst.kind == meta::Kind::Symlink {
                    "symlink"
                } else {
                    "file"
                }
                .into(),
                size: stat.size,
                mtime: stat.mtime,
                mode: meta::mode_string(stat.mode),
                is_symlink: lst.kind == meta::Kind::Symlink,
                link_target: meta::readlink(&path).unwrap_or_default(),
            }
            .json();
            assert_eq!(local, remote);
            assert_eq!(local["thumbnail_available"], false);
            if name == "link.jpg" {
                assert_eq!(
                    local["link_target"]["path"],
                    dir.join("target.jpg").to_str().unwrap()
                );
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod transfer_safety_tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;

    fn assert_local_child_reaped(pid: u32) {
        if pid <= 1 {
            return;
        }
        assert_eq!(
            unsafe { libc::kill(pid as i32, 0) },
            -1,
            "child {pid} was not reaped"
        );
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "harbor-transfer-safety-{}",
                crate::uci::random_hex(8)
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn dir(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::create_dir_all(&path).unwrap();
            path
        }
        fn task(&self) -> PathBuf {
            let task = self.dir("task");
            std::fs::write(task.join("state"), b"{}").unwrap();
            task
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn item(source: &Path, target: &str, kind: &str) -> TransferItem {
        TransferItem {
            source: RemoteItem {
                name: source.file_name().unwrap().to_str().unwrap().into(),
                path: source.to_str().unwrap().into(),
                kind: kind.into(),
                size: 0,
                mtime: 0,
                mode: "0644".into(),
                is_symlink: false,
                link_target: String::new(),
            },
            target_name: target.into(),
        }
    }

    #[test]
    fn same_volume_move_renames_without_staging() {
        let f = Fixture::new();
        let src = f.dir("src");
        let dst = f.dir("dst");
        let task = f.task();
        std::fs::write(src.join("file"), b"data").unwrap();
        let source = Side::Local {
            dir: src.to_str().unwrap(),
        };
        let target = Side::Local {
            dir: dst.to_str().unwrap(),
        };
        let entries = vec![item(&src.join("file"), "file", "file")];
        staged_transfer(&source, &target, &entries, &[], true, false, &task, 4, None).unwrap();
        assert!(!src.join("file").exists());
        assert_eq!(std::fs::read(dst.join("file")).unwrap(), b"data");
        assert!(!std::fs::read_dir(&dst).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".harbor-transfer-")));
    }

    #[test]
    fn manifest_is_complete_nul_framed_and_compares_files_links_and_empty_dirs() {
        let f = Fixture::new();
        let src = f.dir("src/dir/sub");
        let dst = f.dir("dst/renamed/sub");
        std::fs::create_dir(src.join("empty")).unwrap();
        std::fs::create_dir(dst.join("empty")).unwrap();
        std::fs::write(src.join("a\\b\nline"), b"content").unwrap();
        std::fs::write(dst.join("a\\b\nline"), b"content").unwrap();
        symlink("../dangling\n\n", src.join("link")).unwrap();
        symlink("../dangling\n\n", dst.join("link")).unwrap();
        std::fs::write(src.join("skip*[x]"), b"secret").unwrap();
        std::fs::write(dst.join("skip*[x]"), b"existing destination").unwrap();
        std::fs::write(dst.join("extra"), b"merge allowed").unwrap();
        let source_dir = f.0.join("src");
        let source = Side::Local {
            dir: source_dir.to_str().unwrap(),
        };
        let target_dir = f.0.join("dst");
        let target = Side::Local {
            dir: target_dir.to_str().unwrap(),
        };
        let source_root = f.0.join("src/dir");
        let source_names = vec!["dir".to_string()];
        let target_names = vec!["renamed".to_string()];
        let excluded = vec![src.join("skip*[x]").to_str().unwrap().to_string()];
        let entries = vec![item(&source_root, "renamed", "directory")];
        let target_excluded = remap_excluded_paths(&entries, target.dir(), &excluded);
        let sm = tree_manifest(&source, &source_names, &excluded).unwrap();
        let tm = tree_manifest(&target, &target_names, &target_excluded).unwrap();
        assert!(sm.contains_key("dir/sub/empty"));
        assert!(sm.contains_key("dir/sub/a\\b\nline"));
        assert_eq!(
            sm["dir/sub/link"],
            ManifestEntry::Symlink(b"../dangling\n\n".to_vec())
        );
        assert!(!sm.contains_key("dir/sub/skip*[x]"));
        assert_eq!(sm.get("dir/sub/link"), tm.get("renamed/sub/link"));
        std::fs::remove_file(dst.join("link")).unwrap();
        symlink("../changed", dst.join("link")).unwrap();
        let tm2 = tree_manifest(&target, &target_names, &target_excluded).unwrap();
        assert_ne!(sm.get("dir/sub/link"), tm2.get("renamed/sub/link"));
        assert!(!transfer_manifests_match(&sm, &tm2, &entries));
        assert!(!transfer_manifests_match(
            &TreeManifest::new(),
            &tm2,
            &entries
        ));
        assert!(tree_manifest(&source, &["missing".into()], &[]).is_err());
        for raw in [
            b"D\0./dir\0\0".as_slice(),
            b"D\0./dir\0\0E".as_slice(),
            b"D\0./dir\0\0D\0./dir\0\0E\0".as_slice(),
            b"D\0./other\0\0E\0".as_slice(),
            b"F\0./dir\0short\0E\0".as_slice(),
            b"D\0./dir/../escape\0\0E\0".as_slice(),
            b"D\0./dir\0\0E\0garbage".as_slice(),
        ] {
            assert!(
                parse_tree_manifest(raw, &source_names).is_err(),
                "accepted {raw:?}"
            );
        }
        std::fs::write(src.join(std::ffi::OsString::from_vec(vec![0xff])), b"bytes").unwrap();
        assert!(
            tree_manifest(&source, &source_names, &excluded).is_err(),
            "non-UTF8 names must not be silently omitted"
        );
    }

    #[test]
    fn manifest_matching_scales_to_many_distinct_roots() {
        let mut source = TreeManifest::new();
        let mut target = TreeManifest::new();
        let mut items = Vec::new();
        for index in 0..4096 {
            let name = format!("source-{index}");
            let dest = format!("target-{index}");
            source.insert(name.clone(), ManifestEntry::File { size: 1, mtime: 1 });
            target.insert(dest.clone(), ManifestEntry::File { size: 1, mtime: 1 });
            items.push(item(Path::new(&name), &dest, "file"));
        }
        assert!(transfer_manifests_match(&source, &target, &items));
        target.remove("target-4000");
        assert!(!transfer_manifests_match(&source, &target, &items));
    }

    #[test]
    fn verification_rejects_special_entries_and_does_not_remove_any_source() {
        let f = Fixture::new();
        let dir = f.dir("src/dir");
        std::fs::write(dir.join("regular"), b"safe").unwrap();
        let fifo = dir.join("pipe");
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let source_dir = f.0.join("src");
        let source = Side::Local {
            dir: source_dir.to_str().unwrap(),
        };
        assert!(tree_manifest(&source, &["dir".into()], &[]).is_err());
        assert_eq!(std::fs::read(dir.join("regular")).unwrap(), b"safe");
        assert!(fifo.exists());
    }

    #[test]
    fn verified_delete_rechecks_content_and_never_recursively_deletes_new_files() {
        let f = Fixture::new();
        let dir = f.dir("src/dir");
        std::fs::write(dir.join("changed"), b"old").unwrap();
        let source_dir = f.0.join("src");
        let source = Side::Local {
            dir: source_dir.to_str().unwrap(),
        };
        let manifest = tree_manifest(&source, &["dir".into()], &[]).unwrap();
        std::fs::write(dir.join("changed"), b"newer external edit").unwrap();
        assert!(remove_transferred_sources(&source, &manifest, &[]).is_err());
        assert_eq!(
            std::fs::read(dir.join("changed")).unwrap(),
            b"newer external edit"
        );
        std::fs::remove_file(dir.join("changed")).unwrap();
        symlink("../before\n\n", dir.join("link")).unwrap();
        let manifest = tree_manifest(&source, &["dir".into()], &[]).unwrap();
        std::fs::remove_file(dir.join("link")).unwrap();
        symlink("../after", dir.join("link")).unwrap();
        assert!(remove_transferred_sources(&source, &manifest, &[]).is_err());
        assert_eq!(
            std::fs::read_link(dir.join("link")).unwrap(),
            Path::new("../after")
        );
        std::fs::remove_file(dir.join("link")).unwrap();
        std::fs::write(dir.join("transferred"), b"old").unwrap();
        let manifest = tree_manifest(&source, &["dir".into()], &[]).unwrap();
        std::fs::write(dir.join("newly-added"), b"do not delete").unwrap();
        assert!(remove_transferred_sources(&source, &manifest, &[]).is_err());
        assert!(!dir.join("transferred").exists());
        assert_eq!(
            std::fs::read(dir.join("newly-added")).unwrap(),
            b"do not delete"
        );
    }

    #[test]
    fn verified_delete_batches_always_use_correct_directory_and_preserve_exclusions() {
        let f = Fixture::new();
        let dir = f.dir("src/dir/sub");
        for i in 0..160 {
            std::fs::write(dir.join(format!("file-{i:04}")), b"transferred").unwrap();
        }
        std::fs::write(dir.join("skip*[x]"), b"retained").unwrap();
        let excluded = vec![dir.join("skip*[x]").to_str().unwrap().to_string()];
        let source_dir = f.0.join("src");
        let source = Side::Local {
            dir: source_dir.to_str().unwrap(),
        };
        let manifest = tree_manifest(&source, &["dir".into()], &excluded).unwrap();
        assert_eq!(manifest.len(), 162);
        remove_transferred_sources(&source, &manifest, &excluded).unwrap();
        assert_eq!(std::fs::read(dir.join("skip*[x]")).unwrap(), b"retained");
        for i in 0..160 {
            assert!(!dir.join(format!("file-{i:04}")).exists());
        }
    }

    #[test]
    fn staged_move_merges_and_renames_without_touching_exclusions_or_existing_names() {
        let f = Fixture::new();
        let src = f.dir("src/dir/sub");
        let dst = f.dir("dst/renamed/sub");
        let task = f.task();
        std::fs::write(src.join("a"), b"new").unwrap();
        std::fs::write(src.join("skip*[x]"), b"source kept").unwrap();
        std::fs::write(dst.join("skip*[x]"), b"destination kept").unwrap();
        std::fs::write(dst.join("old"), b"merge kept").unwrap();
        symlink("../missing\n", src.join("link")).unwrap();
        let original = f.0.join("dst/dir");
        std::fs::write(&original, b"same-name destination kept").unwrap();
        let source_dir = f.0.join("src");
        let source = Side::Local {
            dir: source_dir.to_str().unwrap(),
        };
        let target_dir = f.0.join("dst");
        let target = Side::Local {
            dir: target_dir.to_str().unwrap(),
        };
        let entries = vec![item(&f.0.join("src/dir"), "renamed", "directory")];
        let excluded = vec![src.join("skip*[x]").to_str().unwrap().to_string()];
        staged_transfer(
            &source, &target, &entries, &excluded, true, true, &task, 3, None,
        )
        .unwrap();
        assert_eq!(std::fs::read(dst.join("a")).unwrap(), b"new");
        assert_eq!(
            std::fs::read(dst.join("skip*[x]")).unwrap(),
            b"destination kept"
        );
        assert_eq!(std::fs::read(dst.join("old")).unwrap(), b"merge kept");
        assert_eq!(
            std::fs::read(&original).unwrap(),
            b"same-name destination kept"
        );
        assert_eq!(
            std::fs::read_link(dst.join("link")).unwrap(),
            Path::new("../missing\n")
        );
        assert_eq!(std::fs::read(src.join("skip*[x]")).unwrap(), b"source kept");
        assert!(!src.join("a").exists());
        assert!(!src.join("link").is_symlink());
        assert!(!std::fs::read_dir(f.0.join("dst")).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".harbor-transfer-")));
    }

    #[test]
    fn no_clobber_publication_detects_a_target_created_after_check() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let stage = f.dir("stage");
        let incoming = f.dir("stage/incoming");
        f.dir("stage/previous");
        f.dir("stage/merged");
        let dst = f.dir("dest");
        let bin = f.dir("bin");
        std::fs::write(incoming.join("file"), b"staged").unwrap();
        let fake = bin.join("mv");
        std::fs::write(
            &fake,
            b"#!/bin/sh\nif [ \"$1\" = -nT ]; then printf race > \"$3\"; fi\nexec /bin/mv \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let entries = item(&incoming.join("file"), "file", "file");
        let command = format!(
            "PATH={}:$PATH; export PATH; set -e\n{}",
            shell_quote(bin.to_str().unwrap()),
            staged_publish_line(
                stage.to_str().unwrap(),
                dst.to_str().unwrap(),
                &entries,
                false,
                0
            )
        );
        let side = Side::Local {
            dir: dst.to_str().unwrap(),
        };
        assert!(side.run_mutating_once(&command, Some(5)).is_err());
        assert_eq!(std::fs::read(dst.join("file")).unwrap(), b"race");
        assert_eq!(std::fs::read(incoming.join("file")).unwrap(), b"staged");
    }

    #[test]
    fn transfer_tool_preflight_reports_missing_tool_and_owner() {
        let f = Fixture::new();
        let side = Side::Local {
            dir: f.0.to_str().unwrap(),
        };
        assert!(require_transfer_side_tools(&side, &["sh", "cat"], "dev", "revision").is_ok());
        let error = require_transfer_side_tools(
            &side,
            &["sh", "harbor_missing_fixture_tool"],
            "dev",
            "revision",
        )
        .unwrap_err();
        assert_eq!(error.data["missing_tool"], "harbor_missing_fixture_tool");
        assert_eq!(error.data["dependency_preflight"], true);
        assert_eq!(error.data["device_id"], "dev");
        assert_eq!(error.data["device_revision"], "revision");
    }

    #[test]
    fn map_sftp_distinguishes_missing_and_disabled() {
        let missing = map_sftp(ssh::sftp::SftpError::Missing);
        assert_eq!(missing.data["missing_tool"], json!("sftp"));
        assert_eq!(missing.data["package_name"], json!("openssh-sftp-server"));
        assert_eq!(missing.data["dependency_preflight"], json!(true));
        let disabled = map_sftp(ssh::sftp::SftpError::Disabled);
        assert_eq!(disabled.data["missing_tool"], json!("sftp"));
        assert_eq!(disabled.data["package_name"], json!("openssh-sftp-server"));
        assert_eq!(disabled.data["dependency_preflight"], json!(true));
        let unknown = map_sftp(ssh::sftp::SftpError::Unknown("rename raced".into()));
        assert_eq!(unknown.data["outcome_unknown"], json!(true));
    }

    #[test]
    fn only_sha256_host_keys_count_as_trusted() {
        assert!(trusted_host_key("SHA256:abcdef"));
        assert!(!trusted_host_key(""));
        assert!(!trusted_host_key("host.invalid ssh-ed25519 AAAA"));
        assert!(!trusted_host_key("SHA256: abc"));
    }

    #[test]
    fn transfer_path_framing_rejects_truncation_duplicates_and_escape() {
        let roots = vec!["tree".to_string()];
        let paths = parse_transfer_paths(b"./tree\0./tree/odd\nname\0E\0", &roots, true).unwrap();
        assert!(paths.contains("tree/odd\nname"));
        for raw in [
            b"./tree\0".as_slice(),
            b"./tree\0E".as_slice(),
            b"./tree\0./tree\0E\0".as_slice(),
            b"./tree/../escape\0E\0".as_slice(),
            b"./other\0E\0".as_slice(),
            b"./tree\0E\0garbage".as_slice(),
        ] {
            assert!(
                parse_transfer_paths(raw, &roots, true).is_err(),
                "accepted {raw:?}"
            );
        }
        assert!(parse_transfer_paths(b"E\0", &roots, true).is_err());
        assert!(parse_transfer_paths(b"E\0", &roots, false)
            .unwrap()
            .is_empty());
        let entries = parse_transfer_entries(
            b"./tree\0/src/tree\0./tree/file\0/src/tree/file\0E\0",
            &roots,
            true,
        )
        .unwrap();
        assert_eq!(
            entries.resolved.get("tree/file").map(String::as_str),
            Some("/src/tree/file")
        );
        assert!(parse_transfer_entries(b"./tree\0E\0", &roots, true).is_err());
        assert_eq!(
            projected_actual("tree/new", &entries.resolved, "/dst"),
            "/src/tree/new"
        );
        assert_eq!(
            projected_actual("other", &entries.resolved, "/dst"),
            "/dst/other"
        );
    }

    #[test]
    fn tar_headers_expose_ustar_names_for_progress() {
        let mut header = vec![0u8; 512];
        header[..9].copy_from_slice(b"dir/a.txt");
        header[124..135].copy_from_slice(b"00000000013");
        header[257..262].copy_from_slice(b"ustar");
        let (name, size) = tar_header_name(&header).unwrap();
        assert_eq!(name, "dir/a.txt");
        assert_eq!(size, 11);
        header[345..351].copy_from_slice(b"prefix");
        let (name, _) = tar_header_name(&header).unwrap();
        assert_eq!(name, "prefix/dir/a.txt");
    }

    #[test]
    fn transfer_authorization_checks_source_target_and_existing_merge_descendants() {
        let f = Fixture::new();
        let src = f.dir("src/tree/blocked");
        let dest_tree = f.dir("dst/tree");
        std::fs::write(src.join("secret"), b"private").unwrap();
        std::fs::write(f.0.join("src/tree/public"), b"public").unwrap();
        std::fs::write(dest_tree.join("keep"), b"keep").unwrap();
        let st = AppState::new(crate::state::Settings {
            state_dir: f.0.join("state").to_string_lossy().into_owned(),
            config_path: f.0.join("config").to_string_lossy().into_owned(),
            root_policy: crate::state::RootPolicy::Denylist,
            excluded_roots: vec![src.to_string_lossy().into_owned()],
            ..Default::default()
        });
        let source_dir = f.0.join("src");
        let target_dir = f.0.join("dst");
        let source = Side::Local {
            dir: source_dir.to_str().unwrap(),
        };
        let target = Side::Local {
            dir: target_dir.to_str().unwrap(),
        };
        let security = TransferSecurity {
            state: &st,
            session: "",
            source_device: "",
            target_device: "",
        };
        let entries = vec![item(&f.0.join("src/tree"), "tree", "directory")];
        assert!(
            authorize_transfer_tree(&security, &source, &target, &entries, &[], true)
                .unwrap_err()
                .message
                .contains("blocked")
        );
        let excluded = vec![src.to_string_lossy().into_owned()];
        let allowed =
            authorize_transfer_tree(&security, &source, &target, &entries, &excluded, true)
                .unwrap();
        assert!(allowed.contains("tree/public"));
        assert!(!allowed.contains("tree/blocked"));
        let mut config = st.root_policy_config();
        config.excluded_roots = vec![dest_tree.join("public").to_string_lossy().into_owned()];
        st.set_root_policy_config(config).unwrap();
        assert!(
            authorize_transfer_tree(&security, &source, &target, &entries, &excluded, true)
                .is_err(),
            "prospective target must be authorized"
        );
        let mut config = st.root_policy_config();
        config.excluded_roots = vec![dest_tree.join("keep").to_string_lossy().into_owned()];
        st.set_root_policy_config(config).unwrap();
        assert!(
            authorize_transfer_tree(&security, &source, &target, &entries, &excluded, true)
                .is_err(),
            "existing merge subtree must be authorized"
        );
        let mut config = st.root_policy_config();
        config.policy = crate::state::RootPolicy::Unrestricted;
        st.set_root_policy_config(config).unwrap();
        symlink("/etc/passwd", f.0.join("src/tree/system-link")).unwrap();
        let error = authorize_transfer_tree(&security, &source, &target, &entries, &excluded, true)
            .unwrap_err();
        assert_eq!(error.data["system_access_required"], true);
        st.system_access.grant("policy-test", "", "/etc", 60);
        let granted = TransferSecurity {
            session: "policy-test",
            ..security
        };
        assert!(
            authorize_transfer_tree(&granted, &source, &target, &entries, &excluded, true).is_ok()
        );
        drop(st);
    }

    #[test]
    fn mountinfo_parsing_checks_nested_and_same_device_bind_mounts() {
        let raw = b"1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:1 / /tmp/has\\040space rw - ext4 /dev/x rw\n3 1 0:1 / /tmp/bind\\134name rw - ext4 /dev/x rw\n";
        let mounts = parse_mountpoints(raw).unwrap();
        assert_eq!(mounts[1], b"/tmp/has space");
        assert_eq!(mounts[2], b"/tmp/bind\\name");
        assert!(byte_path_contains(b"/tmp", &mounts[1]));
        assert!(!byte_path_contains(b"/tm", &mounts[1]));
        assert!(byte_path_contains(b"/tmp/has space", &mounts[1]));
        assert!(parse_mountpoints(b"1 0 0:1 / /tmp/bad\\999 rw - fs source rw\n").is_err());
        assert!(parse_mountpoints(b"1 0 0:1 / / rw - fs source rw").is_err());
        let root = Side::Local { dir: "/" };
        assert!(ensure_no_nested_mounts(&root, &["dev".into()]).is_err());
    }

    #[test]
    fn failed_file_overwrite_preserves_existing_and_staged_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let stage = f.dir("stage");
        let incoming = f.dir("stage/incoming");
        let previous = f.dir("stage/previous");
        f.dir("stage/merged");
        let dst = f.dir("dest");
        let bin = f.dir("bin");
        std::fs::write(incoming.join("file"), b"new").unwrap();
        std::fs::write(dst.join("file"), b"old").unwrap();
        let fake = bin.join("mv");
        std::fs::write(
            &fake,
            b"#!/bin/sh\ncase \"$2\" in */incoming/file) exit 73;; esac\nexec /bin/mv \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let entry = item(&incoming.join("file"), "file", "file");
        let command = format!(
            "PATH={}:$PATH; export PATH; set -e\n{}",
            shell_quote(bin.to_str().unwrap()),
            staged_publish_line(
                stage.to_str().unwrap(),
                dst.to_str().unwrap(),
                &entry,
                true,
                0
            )
        );
        let side = Side::Local {
            dir: dst.to_str().unwrap(),
        };
        assert!(side.run_mutating_once(&command, Some(5)).is_err());
        assert_eq!(std::fs::read(dst.join("file")).unwrap(), b"old");
        assert!(!previous.join("0").exists());
        assert_eq!(std::fs::read(incoming.join("file")).unwrap(), b"new");
    }

    #[test]
    fn file_overwrite_drops_previous_after_successful_rename() {
        let f = Fixture::new();
        let stage = f.dir("stage");
        let incoming = f.dir("stage/incoming");
        let previous = f.dir("stage/previous");
        f.dir("stage/merged");
        let dst = f.dir("dest");
        std::fs::write(incoming.join("file"), b"new").unwrap();
        std::fs::write(dst.join("file"), b"old").unwrap();
        let entry = item(&incoming.join("file"), "file", "file");
        let command = format!(
            "set -e\n{}",
            staged_publish_line(
                stage.to_str().unwrap(),
                dst.to_str().unwrap(),
                &entry,
                true,
                0
            )
        );
        let side = Side::Local {
            dir: dst.to_str().unwrap(),
        };
        side.run_mutating_once(&command, Some(5)).unwrap();
        assert_eq!(std::fs::read(dst.join("file")).unwrap(), b"new");
        assert!(!incoming.join("file").exists());
        assert!(!previous.join("0").exists());
    }

    #[test]
    fn merge_does_not_follow_an_existing_directory_symlink() {
        let f = Fixture::new();
        let src = f.dir("src/tree/link");
        let dst = f.dir("dst/tree");
        let outside = f.dir("outside");
        let task = f.task();
        std::fs::write(src.join("in"), b"new").unwrap();
        std::fs::write(outside.join("sentinel"), b"old").unwrap();
        symlink(&outside, dst.join("link")).unwrap();
        let source_dir = f.0.join("src");
        let target_dir = f.0.join("dst");
        let source = Side::Local {
            dir: source_dir.to_str().unwrap(),
        };
        let target = Side::Local {
            dir: target_dir.to_str().unwrap(),
        };
        let entry = item(&f.0.join("src/tree"), "tree", "directory");
        assert!(
            staged_transfer(&source, &target, &[entry], &[], true, true, &task, 0, None).is_err()
        );
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"old");
        assert!(!outside.join("in").exists());
        assert!(dst.join("link").is_symlink());
        assert_eq!(std::fs::read(src.join("in")).unwrap(), b"new");
    }

    #[test]
    fn failed_directory_merge_preparation_leaves_target_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let stage = f.dir("stage");
        let incoming = f.dir("stage/incoming/tree");
        let previous = f.dir("stage/previous");
        f.dir("stage/merged");
        let dst = f.dir("dest/tree");
        let bin = f.dir("bin");
        std::fs::write(incoming.join("a"), b"new").unwrap();
        std::fs::write(dst.join("a"), b"old").unwrap();
        let fake = bin.join("cp");
        std::fs::write(&fake, b"#!/bin/sh\n/bin/cp \"$@\" || exit $?\ncase \"$2\" in */incoming/tree/.) exit 73;; esac\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let entry = item(&incoming, "tree", "directory");
        let dest_dir = f.0.join("dest");
        let command = format!(
            "PATH={}:$PATH; export PATH; set -e\n{}",
            shell_quote(bin.to_str().unwrap()),
            staged_publish_line(
                stage.to_str().unwrap(),
                dest_dir.to_str().unwrap(),
                &entry,
                true,
                0
            )
        );
        let side = Side::Local {
            dir: dest_dir.to_str().unwrap(),
        };
        assert!(side.run_mutating_once(&command, Some(5)).is_err());
        assert_eq!(std::fs::read(dst.join("a")).unwrap(), b"old");
        assert_eq!(std::fs::read(incoming.join("a")).unwrap(), b"new");
        assert!(!previous.join("0").exists());
    }

    #[test]
    fn failed_type_change_rolls_back_or_retains_the_previous_target() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let stage = f.dir("stage");
        let incoming = f.dir("stage/incoming/tree");
        f.dir("stage/previous");
        f.dir("stage/merged");
        let dest = f.dir("dest");
        let bin = f.dir("bin");
        std::fs::write(incoming.join("child"), b"new").unwrap();
        std::fs::write(dest.join("tree"), b"old").unwrap();
        let fake = bin.join("mv");
        std::fs::write(
            &fake,
            b"#!/bin/sh\ncase \"$2\" in */incoming/tree) exit 73;; esac\nexec /bin/mv \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let entry = item(&incoming, "tree", "directory");
        let command = format!(
            "PATH={}:$PATH; export PATH; set -e\n{}",
            shell_quote(bin.to_str().unwrap()),
            staged_publish_line(
                stage.to_str().unwrap(),
                dest.to_str().unwrap(),
                &entry,
                true,
                0
            )
        );
        let side = Side::Local {
            dir: dest.to_str().unwrap(),
        };
        assert!(side.run_mutating_once(&command, Some(5)).is_err());
        assert_eq!(std::fs::read(dest.join("tree")).unwrap(), b"old");
        assert_eq!(std::fs::read(incoming.join("child")).unwrap(), b"new");
    }

    #[test]
    fn raced_directory_publication_keeps_both_racer_and_previous_tree() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let stage = f.dir("stage");
        let incoming = f.dir("stage/incoming/tree");
        let previous = f.dir("stage/previous");
        f.dir("stage/merged");
        let dst = f.dir("dest/tree");
        let bin = f.dir("bin");
        std::fs::write(incoming.join("new"), b"new").unwrap();
        std::fs::write(dst.join("old"), b"old").unwrap();
        let fake = bin.join("mv");
        std::fs::write(&fake, b"#!/bin/sh\ncase \"$2\" in */merged/0) printf racer > \"$3\";; esac\nexec /bin/mv \"$@\"\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let entry = item(&incoming, "tree", "directory");
        let dest_dir = f.0.join("dest");
        let command = format!(
            "PATH={}:$PATH; export PATH; set -e\n{}",
            shell_quote(bin.to_str().unwrap()),
            staged_publish_line(
                stage.to_str().unwrap(),
                dest_dir.to_str().unwrap(),
                &entry,
                true,
                0
            )
        );
        let side = Side::Local {
            dir: dest_dir.to_str().unwrap(),
        };
        assert!(side.run_mutating_once(&command, Some(5)).is_err());
        assert_eq!(std::fs::read(dest_dir.join("tree")).unwrap(), b"racer");
        assert_eq!(std::fs::read(previous.join("0/old")).unwrap(), b"old");
        assert_eq!(std::fs::read(incoming.join("new")).unwrap(), b"new");
    }

    #[test]
    fn unsupported_source_fails_before_overwrite_publication() {
        let f = Fixture::new();
        let src = f.dir("src/tree");
        let dst = f.dir("dst/tree");
        let task = f.task();
        std::fs::write(src.join("new"), b"new").unwrap();
        std::fs::write(dst.join("old"), b"old").unwrap();
        let fifo = std::ffi::CString::new(src.join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let source_dir = f.0.join("src");
        let target_dir = f.0.join("dst");
        let source = Side::Local {
            dir: source_dir.to_str().unwrap(),
        };
        let target = Side::Local {
            dir: target_dir.to_str().unwrap(),
        };
        let entry = item(&src, "tree", "directory");
        let failure = staged_transfer(&source, &target, &[entry], &[], true, true, &task, 0, None)
            .unwrap_err();
        assert!(
            failure.data.get("staging_path").is_none() || failure.data["staging_path"].is_null(),
            "{failure:?}"
        );
        assert_eq!(std::fs::read(src.join("new")).unwrap(), b"new");
        assert_eq!(std::fs::read(dst.join("old")).unwrap(), b"old");
        assert!(!dst.join("new").exists());
    }

    #[test]
    fn cancellation_before_publication_retains_sources_and_existing_targets() {
        let f = Fixture::new();
        let src = f.dir("src");
        let dst = f.dir("dst");
        let task = f.task();
        std::fs::write(src.join("file"), b"new").unwrap();
        std::fs::write(dst.join("file"), b"old").unwrap();
        let source = Side::Local {
            dir: src.to_str().unwrap(),
        };
        let target = Side::Local {
            dir: dst.to_str().unwrap(),
        };
        let control = crate::task_registry::JobControl::default();
        assert!(control.request());
        let error = staged_transfer_controlled(
            &source,
            &target,
            &[item(&src.join("file"), "file", "file")],
            StagedTransferOptions {
                excluded: &[],
                remove_source: true,
                overwrite: true,
                task_dir: &task,
                total: 3,
                authorization: None,
                control: Some(&control),
            },
        )
        .unwrap_err();
        assert_eq!(error.data["cancelled"], true);
        assert!(error.data["staging_path"].is_null());
        assert_eq!(std::fs::read(src.join("file")).unwrap(), b"new");
        assert_eq!(std::fs::read(dst.join("file")).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(&dst).unwrap().count(), 1);
    }

    #[test]
    fn cancelling_active_pump_reaps_local_children_and_remote_writer_is_unknown() {
        for remote_writer in [false, true] {
            let f = Fixture::new();
            let task = f.task();
            let side = Side::Local {
                dir: f.0.to_str().unwrap(),
            };
            let read = side.spawn("sleep 30", TransferDirection::Read).unwrap();
            let write = side.spawn("sleep 30", TransferDirection::Write).unwrap();
            let pids = [read.id(), write.id()];
            let control = Arc::new(crate::task_registry::JobControl::default());
            let worker_control = control.clone();
            let worker = std::thread::spawn(move || {
                pump_transfer_controlled(
                    read,
                    write,
                    &task,
                    1,
                    Duration::from_secs(5),
                    Some(&worker_control),
                    remote_writer,
                )
            });
            std::thread::sleep(Duration::from_millis(100));
            assert!(control.request());
            let failure = worker.join().unwrap().unwrap_err();
            assert_eq!(failure.data["cancel_requested"], true);
            if remote_writer {
                assert_eq!(failure.data["outcome_unknown"], true);
                assert!(failure.data["cancelled"].is_null());
            } else {
                assert_eq!(failure.data["cancelled"], true);
                assert!(failure.data["outcome_unknown"].is_null());
            }
            for pid in pids {
                assert_local_child_reaped(pid);
            }
        }
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_ssh_staged_copy_cancellation_keeps_source_and_existing_destination() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-cancel-stage", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-cancel-stage-{}", crate::uci::random_hex(8));
        run(&target, &format!("mkdir -p {root}/src {root}/dst; dd if=/dev/zero of={root}/src/file bs=1048576 count=16 2>/dev/null; printf existing > {root}/dst/file"), Some(30)).unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let mut params = Params::default();
        params.set("source_device", &target.id);
        params.set("target_device", &target.id);
        params.set("source_revision", "e2e");
        params.set("target_revision", "e2e");
        params.set("target_dir", &format!("{root}/dst"));
        params.set("operation", "copy");
        params.set("conflict_action", "overwrite");
        params.set("sources", &json!([format!("{root}/src/file")]).to_string());
        let started = start_transfer(&st, &params).unwrap();
        assert_eq!(started["cancelable"], true);
        let id = started["task_id"].as_str().unwrap();
        let mut stage = None;
        for _ in 0..3000 {
            let status = task_status(&st, id).unwrap();
            if let Some(path) = status["staging_path"].as_str() {
                stage = Some(path.to_string());
                break;
            }
            assert_ne!(
                status["done"], true,
                "worker completed before it published a stage: {status}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let stage = stage.expect("staging phase did not start");
        assert!(
            st.tasks.request_job_cancel(id),
            "cancellation must win before publication"
        );
        let mut result = None;
        for _ in 0..1200 {
            let status = task_status(&st, id).unwrap();
            if status["done"] == json!(true) {
                result = Some(status);
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let result = result.expect("cancelled worker did not terminate");
        assert!(
            result["state"] == json!("cancelled") || result["state"] == json!("unknown"),
            "{result}"
        );
        assert_eq!(result["success"], false);
        assert_eq!(result["cancel_requested"], true);
        assert_eq!(result["failure_data"]["staging_path"], stage);
        run(&target, &format!("test -f {root}/src/file && test \"$(wc -c < {root}/src/file)\" -eq 16777216 && test \"$(cat {root}/dst/file)\" = existing && test -d {}", shell_quote(&stage)), Some(30)).unwrap();
        std::thread::sleep(Duration::from_secs(1));
        let _ = run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
        let _ = std::fs::remove_dir_all(Path::new(REMOTE_ROOT).join(id));
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_cancelling_a_stalled_real_ssh_writer_reports_unknown() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-cancel-pump", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-cancel-pump-{}", crate::uci::random_hex(8));
        run(
            &target,
            &format!("mkdir -p {}", shell_quote(&root)),
            Some(30),
        )
        .unwrap();
        let f = Fixture::new();
        let task = f.task();
        let local = Side::Local {
            dir: f.0.to_str().unwrap(),
        };
        let remote = Side::Remote {
            target: &target,
            dir: &root,
        };
        let reader = local
            .spawn("head -c 33554432 /dev/zero", TransferDirection::Read)
            .unwrap();
        let writer = remote
            .spawn(
                &format!("trap '' HUP; printf ready > {root}/ready; sleep 2; cat >/dev/null"),
                TransferDirection::Write,
            )
            .unwrap();
        let pids = [reader.id(), writer.id()];
        let control = Arc::new(crate::task_registry::JobControl::default());
        let worker_control = control.clone();
        let pump = std::thread::spawn(move || {
            pump_transfer_controlled(
                reader,
                writer,
                &task,
                33554432,
                Duration::from_secs(10),
                Some(&worker_control),
                true,
            )
        });
        for _ in 0..1000 {
            if Path::new(&format!("{root}/ready")).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            Path::new(&format!("{root}/ready")).exists(),
            "remote writer never started"
        );
        assert!(control.request());
        let error = pump.join().unwrap().unwrap_err();
        assert_eq!(error.data["outcome_unknown"], true);
        assert_eq!(error.data["cancel_requested"], true);
        for pid in pids {
            assert_local_child_reaped(pid);
        }
        std::thread::sleep(Duration::from_secs(3));
        let _ = run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
    }

    #[test]
    fn pipe_pump_drains_noisy_children_and_kills_stalled_process_groups() {
        let f = Fixture::new();
        let task = f.task();
        let side = Side::Local {
            dir: f.0.to_str().unwrap(),
        };
        let read = side
            .spawn(
                "head -c 2097152 /dev/zero >&2; head -c 1048576 /dev/zero",
                TransferDirection::Read,
            )
            .unwrap();
        let write = side
            .spawn(
                "head -c 2097152 /dev/zero >&2; cat >/dev/null; head -c 2097152 /dev/zero",
                TransferDirection::Write,
            )
            .unwrap();
        assert_eq!(
            pump_transfer(read, write, &task, 1048576, Duration::from_secs(5)).unwrap(),
            1048576
        );
        let read = side
            .spawn("head -c 33554432 /dev/zero", TransferDirection::Read)
            .unwrap();
        let write = side.spawn("sleep 30", TransferDirection::Write).unwrap();
        let pids = [read.id(), write.id()];
        let started = Instant::now();
        let error =
            pump_transfer(read, write, &task, 33554432, Duration::from_millis(300)).unwrap_err();
        assert!(error.message.contains("timed out"), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        for pid in pids {
            assert_local_child_reaped(pid);
        }
    }

    #[test]
    fn bounded_command_output_and_mutation_uncertainty_are_explicit() {
        assert_eq!(
            ssh::capture_bounded(std::io::Cursor::new(b"abc"), 3),
            (b"abc".to_vec(), false, false)
        );
        assert_eq!(
            ssh::capture_bounded(std::io::Cursor::new(b"abcd"), 3),
            (b"abc".to_vec(), true, false)
        );
        let out = ssh::Output {
            stdout: b"prefix".to_vec(),
            stdout_truncated: true,
            stdout_read_failed: false,
            stderr: Vec::new(),
            status: Some(0),
            timed_out: false,
        };
        assert_eq!(
            mutating_output(out).unwrap_err().data["outcome_unknown"],
            true
        );
        let out = ssh::Output {
            stdout: Vec::new(),
            stdout_truncated: false,
            stdout_read_failed: false,
            stderr: Vec::new(),
            status: Some(255),
            timed_out: false,
        };
        assert_eq!(
            mutating_output(out).unwrap_err().data["outcome_unknown"],
            true
        );
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_ssh_move_merge_exclusions_and_single_attempt_uncertainty() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-safe-move", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-safe-move-{}", crate::uci::random_hex(8));
        let setup = format!("mkdir -p {root}/src/dir/sub {root}/dst/dir/sub; printf new > {root}/src/dir/sub/a; printf protected > {root}/src/dir/sub/skip; printf old > {root}/dst/dir/sub/old; ln -s '../missing' {root}/src/dir/sub/link");
        run(&target, &setup, Some(30)).unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let mut params = Params::default();
        params.set("source_device", &target.id);
        params.set("target_device", &target.id);
        params.set("source_revision", "e2e");
        params.set("target_revision", "e2e");
        params.set("target_dir", &format!("{root}/dst"));
        params.set("operation", "move");
        params.set("conflict_action", "overwrite");
        params.set("sources", &json!([format!("{root}/src/dir")]).to_string());
        params.set(
            "exclude_paths",
            &json!([format!("{root}/src/dir/sub/skip")]).to_string(),
        );
        let started = start_transfer(&st, &params).unwrap();
        let id = started["task_id"].as_str().unwrap();
        let mut result = None;
        for _ in 0..400 {
            let status = task_status(&st, id).unwrap();
            if status["done"] == json!(true) {
                result = Some(status);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let result = result.expect("move did not finish");
        assert_eq!(result["success"], true, "{result}");
        let checks = format!("test \"$(cat {root}/dst/dir/sub/a)\" = new && test \"$(cat {root}/dst/dir/sub/old)\" = old && test \"$(cat {root}/src/dir/sub/skip)\" = protected && test ! -e {root}/src/dir/sub/a && test -L {root}/dst/dir/sub/link && test ! -L {root}/src/dir/sub/link");
        run(&target, &checks, Some(30)).unwrap();
        let marker = format!("{root}/once");
        let failure = run_mutating_once(
            &target,
            &format!("printf x >> {}; exit 255", shell_quote(&marker)),
            Some(30),
        )
        .unwrap_err();
        assert_eq!(failure.data["outcome_unknown"], true);
        assert_eq!(
            run(&target, &format!("cat {}", shell_quote(&marker)), Some(30)).unwrap(),
            b"x"
        );
        let out = ssh::run_args(
            &target,
            &workspace(&target).unwrap(),
            "head -c 8192 /dev/zero",
            &[],
            Some(30),
            1024,
        )
        .unwrap();
        assert_eq!(out.stdout.len(), 1024);
        assert!(out.stdout_truncated);
        assert!(!out.stdout_read_failed);
        assert!(run(&target, "head -c 16777217 /dev/zero", Some(30))
            .unwrap_err()
            .message
            .contains("exceeded"));
        let _ = run(&target, &format!("rm -rf {}", shell_quote(&root)), Some(30));
        let _ = std::fs::remove_dir_all(Path::new(REMOTE_ROOT).join(id));
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
        ssh::close_device_sessions(&target.id);
    }

    #[test]
    fn stalled_pipe_kills_descendants_even_if_shell_leader_has_exited() {
        let f = Fixture::new();
        let task = f.task();
        let pidfile = f.0.join("background.pid");
        let side = Side::Local {
            dir: f.0.to_str().unwrap(),
        };
        let command = format!(
            "sleep 30 & echo $! > {}; printf x",
            shell_quote(pidfile.to_str().unwrap())
        );
        let read = side.spawn(&command, TransferDirection::Read).unwrap();
        let write = side
            .spawn("cat >/dev/null", TransferDirection::Write)
            .unwrap();
        assert!(pump_transfer(read, write, &task, 1, Duration::from_millis(300)).is_err());
        let pid: i32 = std::fs::read_to_string(pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let status = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let state = status
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().next());
            if status.is_empty() || matches!(state, Some("Z" | "X")) {
                break;
            }
            if Instant::now() >= deadline {
                panic!("descendant still running: {status}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_same_device_merge_rename_and_physical_alias_are_safe() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-same-safe", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-same-safe-{}", crate::uci::random_hex(8));
        let setup = format!("mkdir -p {root}/src/dir {root}/dst/dir; printf new > {root}/src/dir/new; printf old > {root}/dst/dir/old; printf source-copy > {root}/src/copy.txt; printf target-copy > {root}/dst/copy.txt; printf source-move > {root}/src/move.txt; printf target-move > {root}/dst/move.txt; printf same > {root}/src/same.txt; ln -s {root}/src {root}/alias");
        run(&target, &setup, Some(30)).unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let mut admission = Params::default();
        admission.set("source_device", &target.id);
        admission.set("target_device", &target.id);
        admission.set("source_revision", "e2e");
        admission.set("target_revision", "e2e");
        admission.set("target_dir", &format!("{root}/dst"));
        admission.set("operation", "move");
        admission.set("conflict_action", "error");
        admission.set(
            "sources",
            &json!([format!("{root}/src/same.txt")]).to_string(),
        );
        admission.set("exclude_paths", "{not-an-array}");
        assert!(start_transfer(&st, &admission)
            .unwrap_err()
            .message
            .contains("Invalid selection"));
        admission.set("exclude_paths", &json!([format!("{root}/src")]).to_string());
        assert_eq!(
            start_transfer(&st, &admission).unwrap()["done"],
            true,
            "ancestor exclusion must skip the source"
        );
        admission.set("exclude_paths", "[]");
        let permits: Vec<_> = (0..st.settings.max_transfers)
            .map(|_| st.limits.begin_transfer().unwrap())
            .collect();
        let error = start_transfer(&st, &admission).unwrap_err();
        assert_eq!(error.data["error_code"], "queue_full");
        drop(permits);
        let run_job = |file: &str, dest: &str, operation: &str, action: &str| -> Value {
            let mut params = Params::default();
            params.set("source_device", &target.id);
            params.set("target_device", &target.id);
            params.set("source_revision", "e2e");
            params.set("target_revision", "e2e");
            params.set("target_dir", dest);
            params.set("operation", operation);
            params.set("conflict_action", action);
            params.set(
                "sources",
                &json!([format!("{root}/src/{file}")]).to_string(),
            );
            let started = start_transfer(&st, &params).unwrap();
            if started["done"] == json!(true) {
                return started;
            }
            let id = started["task_id"].as_str().unwrap();
            for _ in 0..400 {
                let status = task_status(&st, id).unwrap();
                if status["done"] == json!(true) {
                    let _ = std::fs::remove_dir_all(Path::new(REMOTE_ROOT).join(id));
                    assert_eq!(status["success"], true, "{status}");
                    return status;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!("transfer did not finish");
        };
        run_job("dir", &format!("{root}/dst"), "move", "overwrite");
        run_job("copy.txt", &format!("{root}/dst"), "copy", "rename");
        run_job("move.txt", &format!("{root}/dst"), "move", "rename");
        let no_op = run_job("same.txt", &format!("{root}/alias"), "move", "overwrite");
        assert_eq!(no_op["done"], true);
        assert_eq!(no_op["success"], true);
        let checks = format!("test \"$(cat {root}/dst/dir/new)\" = new && test \"$(cat {root}/dst/dir/old)\" = old && test ! -e {root}/src/dir && test \"$(cat {root}/dst/copy.txt)\" = target-copy && test \"$(cat {})\" = source-copy && test \"$(cat {root}/dst/move.txt)\" = target-move && test \"$(cat {})\" = source-move && test ! -e {root}/src/move.txt && test \"$(cat {root}/src/same.txt)\" = same",
            shell_quote(&format!("{root}/dst/copy (1).txt")), shell_quote(&format!("{root}/dst/move (1).txt")));
        run(&target, &checks, Some(30)).unwrap();
        let _ = run(&target, &format!("rm -rf {}", shell_quote(&root)), Some(30));
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_policy_resolution_batches_quotes_and_newlines_without_truncation() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-policy-batch", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-policy-batch-{}", crate::uci::random_hex(8));
        run(
            &target,
            &format!("mkdir -p -- {}", shell_quote(&root)),
            Some(30),
        )
        .unwrap();
        let paths: Vec<String> = (0..320)
            .map(|i| format!("{root}/quote'{i}\nline/missing"))
            .collect();
        let result = resolve_policy_paths(Some(&target), &paths).unwrap();
        assert_eq!(result, paths);
        let _ = run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_remote_transfer_rejects_blocked_descendants_before_copying() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-transfer-policy", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-policy-transfer-{}", crate::uci::random_hex(8));
        run(&target, &format!("mkdir -p {root}/src/tree/blocked {root}/dst/tree; \
            printf secret > {root}/src/tree/blocked/secret; printf public > {root}/src/tree/public; printf old > {root}/dst/tree/old"), Some(30)).unwrap();
        let (seed, state_dir) = crate::ssh::e2e_state(&target, "/");
        let mut settings = seed.settings.clone();
        settings.root_policy = crate::state::RootPolicy::Denylist;
        settings.roots.clear();
        settings.excluded_roots = vec![format!("{root}/src/tree/blocked")];
        let st = AppState::new(settings);
        let run_job = |exclusions: &[String]| -> Value {
            let mut p = Params::default();
            p.set("source_device", &target.id);
            p.set("source_revision", "e2e");
            p.set("target_device", &target.id);
            p.set("target_revision", "e2e");
            p.set("target_dir", &format!("{root}/dst"));
            p.set("operation", "copy");
            p.set("conflict_action", "overwrite");
            p.set("sources", &json!([format!("{root}/src/tree")]).to_string());
            p.set("exclude_paths", &json!(exclusions).to_string());
            let started = start_transfer(&st, &p).unwrap();
            let id = started["task_id"].as_str().unwrap();
            let mut result = None;
            for _ in 0..600 {
                let status = task_status(&st, id).unwrap();
                if status["done"] == json!(true) {
                    result = Some(status);
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let status = result.expect("policy transfer did not finish");
            let _ = std::fs::remove_dir_all(Path::new(REMOTE_ROOT).join(id));
            status
        };
        let denied = run_job(&[]);
        assert_eq!(denied["success"], false, "{denied}");
        assert_eq!(denied["failure_data"]["preflight_safe"], true, "{denied}");
        assert!(
            denied["staging_path"].is_null(),
            "denied content must not be staged: {denied}"
        );
        run(&target, &format!("test \"$(cat {root}/dst/tree/old)\" = old && test ! -e {root}/dst/tree/public && test -e {root}/src/tree/blocked/secret"), Some(30)).unwrap();
        let allowed = run_job(&[format!("{root}/src/tree/blocked")]);
        assert_eq!(allowed["success"], true, "{allowed}");
        run(&target, &format!("test \"$(cat {root}/dst/tree/old)\" = old && test \"$(cat {root}/dst/tree/public)\" = public && test ! -e {root}/dst/tree/blocked"), Some(30)).unwrap();
        st.set_root_policy_config(crate::state::RootPolicyConfig {
            policy: crate::state::RootPolicy::Unrestricted,
            roots: vec![],
            excluded_roots: vec![],
        })
        .unwrap();
        run_mutating_once(
            &target,
            &format!("ln -s /etc {root}/src/tree/system"),
            Some(30),
        )
        .unwrap();
        let denied = run_job(&[]);
        assert_eq!(denied["failure_data"]["preflight_safe"], true, "{denied}");
        assert_eq!(
            denied["failure_data"]["system_access_required"], true,
            "{denied}"
        );
        assert_eq!(denied["failure_data"]["device_id"], target.id);
        assert_eq!(denied["failure_data"]["path"], "/etc");
        assert!(denied["staging_path"].is_null(), "{denied}");
        let _ = run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
        drop(st);
        drop(seed);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_same_ssh_device_cross_filesystem_moves_are_staged_and_verified() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-same-cross-fs", 60).expect("HARBOR_E2E_SSH_PORT");
        let Ok(cross_base) = std::env::var("HARBOR_E2E_CROSS_FS") else {
            eprintln!("cross-filesystem E2E not configured (HARBOR_E2E_CROSS_FS), skipped");
            return;
        };
        let root = format!("/tmp/harbor-same-cross-{}", crate::uci::random_hex(8));
        let cross = join_path(
            &cross_base,
            &format!("harbor-same-cross-{}", crate::uci::random_hex(8)),
        );
        let setup = format!("set -e; mkdir -p {root}/src/tree {root}/out {cross}/dst/tree; \
            test \"$(stat -c %d {root})\" != \"$(stat -c %d {cross})\"; \
            printf new > {root}/src/file; printf old > {cross}/dst/file; \
            printf keep-source > {root}/src/tree/new; mkfifo {root}/src/tree/pipe; printf keep-target > {cross}/dst/tree/old");
        run(&target, &setup, Some(30)).unwrap();
        let (seed, state_dir) = crate::ssh::e2e_state(&target, "/");
        let mut settings = seed.settings.clone();
        settings.root_policy = crate::state::RootPolicy::Unrestricted;
        settings.roots.clear();
        let st = AppState::new(settings);
        let session = "same-cross-filesystem";
        st.system_access.grant(session, &target.id, "*", 600);
        let transfer = |src: String, dst: String, expect_success: bool| -> Value {
            let mut p = Params::default();
            p.set("source_device", &target.id);
            p.set("source_revision", "e2e");
            p.set("target_device", &target.id);
            p.set("target_revision", "e2e");
            p.set("target_dir", &dst);
            p.set("operation", "move");
            p.set("conflict_action", "overwrite");
            p.set("__system_session_id", session);
            p.set("sources", &json!([src]).to_string());
            let started = start_transfer(&st, &p).unwrap();
            let id = started["task_id"].as_str().unwrap();
            let mut result = None;
            for _ in 0..600 {
                let status = task_status(&st, id).unwrap();
                if status["done"] == json!(true) {
                    result = Some(status);
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let status = result.expect("same-host cross-filesystem move did not finish");
            assert_eq!(status["success"], expect_success, "{status}");
            assert!(
                status["staging_path"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{dst}/.harbor-transfer-")),
                "{status}"
            );
            let _ = std::fs::remove_dir_all(Path::new(REMOTE_ROOT).join(id));
            status
        };
        transfer(format!("{root}/src/file"), format!("{cross}/dst"), true);
        assert_eq!(
            run(
                &target,
                &format!("cat {cross}/dst/file; test ! -e {root}/src/file"),
                Some(30)
            )
            .unwrap(),
            b"new"
        );
        transfer(format!("{cross}/dst/file"), format!("{root}/out"), true);
        assert_eq!(
            run(
                &target,
                &format!("cat {root}/out/file; test ! -e {cross}/dst/file"),
                Some(30)
            )
            .unwrap(),
            b"new"
        );
        let failure = transfer(format!("{root}/src/tree"), format!("{cross}/dst"), false);
        assert!(failure["failure_data"]["partial"] == json!(true));
        run(&target, &format!("test \"$(cat {root}/src/tree/new)\" = keep-source && test -p {root}/src/tree/pipe && \
            test \"$(cat {cross}/dst/tree/old)\" = keep-target && test ! -e {cross}/dst/tree/new"), Some(30)).unwrap();
        let _ = run(
            &target,
            &format!("rm -rf -- {} {}", shell_quote(&root), shell_quote(&cross)),
            Some(30),
        );
        drop(st);
        drop(seed);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_cross_device_rename_never_displaces_predictable_user_files() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-rename-safe", 60).expect("HARBOR_E2E_SSH_PORT");
        let Ok(cross_base) = std::env::var("HARBOR_E2E_CROSS_FS") else {
            return;
        };
        let local =
            Path::new(&cross_base).join(format!("harbor-rename-{}", crate::uci::random_hex(8)));
        let root = format!("/tmp/harbor-rename-{}", crate::uci::random_hex(8));
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("data.txt"), b"incoming").unwrap();
        run(&target, &format!("mkdir -p {root}; printf original > {root}/data.txt; printf sentinel > {root}/.harbor-cftmp-0"), Some(30)).unwrap();
        let (seed, state_dir) = crate::ssh::e2e_state(&target, "/");
        let mut settings = seed.settings.clone();
        settings.root_policy = crate::state::RootPolicy::Unrestricted;
        settings.roots.clear();
        let st = AppState::new(settings);
        let session = "rename-check";
        st.system_access.grant(session, "", "*", 600);
        st.system_access.grant(session, &target.id, "*", 600);
        let mut params = Params::default();
        params.set("target_device", &target.id);
        params.set("target_revision", "e2e");
        params.set("target_dir", &root);
        params.set("operation", "copy");
        params.set("conflict_action", "rename");
        params.set("__system_session_id", session);
        params.set(
            "sources",
            &json!([local.join("data.txt").to_str().unwrap()]).to_string(),
        );
        let started = start_transfer(&st, &params).unwrap();
        let id = started["task_id"].as_str().unwrap();
        let mut result = None;
        for _ in 0..400 {
            let status = task_status(&st, id).unwrap();
            if status["done"] == json!(true) {
                result = Some(status);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let result = result.expect("copy did not finish");
        assert_eq!(result["success"], true, "{result}");
        assert_eq!(
            run(&target, &format!("cat {root}/data.txt"), Some(30)).unwrap(),
            b"original"
        );
        assert_eq!(
            run(
                &target,
                &format!("cat {}", shell_quote(&format!("{root}/data (1).txt"))),
                Some(30)
            )
            .unwrap(),
            b"incoming"
        );
        assert_eq!(
            run(&target, &format!("cat {root}/.harbor-cftmp-0"), Some(30)).unwrap(),
            b"sentinel"
        );
        let _ = run(&target, &format!("rm -rf {}", shell_quote(&root)), Some(30));
        let _ = std::fs::remove_dir_all(Path::new(REMOTE_ROOT).join(id));
        drop(st);
        drop(seed);
        let _ = std::fs::remove_dir_all(state_dir);
        let _ = std::fs::remove_dir_all(local);
    }
}
