use crate::atomic_u64::AtomicU64;
use crate::params::Params;
use crate::paths;
use crate::remote::{authenticated_target, checked_device, shell_quote, RemoteError};
use crate::ssh;
use crate::state::AppState;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use tokio_util::io::ReaderStream;

const CHUNK: usize = 256 * 1024;

#[derive(Clone)]
pub struct RemoteStat {
    pub kind: String,
    pub is_symlink: bool,
    pub size: u64,
    pub mtime: i64,
    pub mode: String,
    pub(crate) revision: Option<String>,
}

fn stat_script(path: &str) -> String {
    format!(
        r#"p={p}
if [ ! -e "$p" ] && [ ! -L "$p" ]; then
 ancestor=$p
 while [ ! -e "$ancestor" ] && [ ! -L "$ancestor" ]; do
  [ "$ancestor" != / ] || break
  ancestor=${{ancestor%/*}}; [ -n "$ancestor" ] || ancestor=/
 done
 if [ -d "$ancestor" ] && [ ! -x "$ancestor" ]; then
  echo 'Cannot access parent directory' >&2; exit 46
 fi
 exit 44
fi
link=0; [ ! -L "$p" ] || link=1
if [ -d "$p" ]; then k=directory
elif [ -f "$p" ]; then k=file
elif [ "$link" = 1 ]; then k=symlink
else k=special; fi
# Follow a live link like local metadata(); retain lstat for dangling links.
follow=-L; if [ "$link" = 1 ] && [ ! -e "$p" ]; then follow=; fi
fmt='%s %Y %a %d %i %Z %y %z'
if command -v stat >/dev/null 2>&1 && stat -L -c '%s %Y %a' / >/dev/null 2>&1; then
 value=$(stat $follow -c "$fmt" "$p") || exit 46
elif command -v gnu-stat >/dev/null 2>&1 && gnu-stat -L -c '%s %Y %a' / >/dev/null 2>&1; then
 value=$(gnu-stat $follow -c "$fmt" "$p") || exit 46
elif /usr/libexec/stat-coreutils -L -c '%s %Y %a' / >/dev/null 2>&1; then
 value=$(/usr/libexec/stat-coreutils $follow -c "$fmt" "$p") || exit 46
elif busybox stat -L -c '%s %Y %a' / >/dev/null 2>&1; then
 value=$(busybox stat $follow -c "$fmt" "$p") || exit 46
else
 echo 'stat is required on this device' >&2; exit 127
fi
printf '%s %s %s\n' "$k" "$link" "$value""#,
        p = shell_quote(path)
    )
}

pub fn remote_stat(target: &ssh::Target, path: &str) -> Result<RemoteStat, RemoteError> {
    let raw = crate::remote::run(target, &stat_script(path), Some(30)).map_err(|error| {
        if error.data["exit_code"] == json!(127) && error.message.contains("stat is required") {
            let mut missing = RemoteError::missing_tool(
                "stat",
                crate::tools::package_name_for("stat"),
                error.message,
            );
            missing.data["device_id"] = json!(target.id);
            missing
        } else {
            error
        }
    })?;
    let text =
        std::str::from_utf8(&raw).map_err(|_| RemoteError::new("Cannot stat the remote file"))?;
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 5 || !matches!(parts[1], "0" | "1") {
        return Err(RemoteError::new("Cannot stat the remote file"));
    }
    Ok(RemoteStat {
        kind: parts[0].to_string(),
        is_symlink: parts[1] == "1",
        size: parts[2]
            .parse()
            .map_err(|_| RemoteError::new("Cannot stat the remote file"))?,
        mtime: parts[3]
            .parse()
            .map_err(|_| RemoteError::new("Cannot stat the remote file"))?,
        mode: parts[4].to_string(),
        revision: (parts.len() >= 8).then(|| parts[2..].join(" ")),
    })
}

fn fail(status: StatusCode, message: &str) -> Response {
    let body = json!({
        "code": 1,
        "message": crate::i18n::translate(message),
        "data": Value::Null,
    });
    (status, axum::Json(body)).into_response()
}

fn fail_remote(status: StatusCode, error: RemoteError) -> Response {
    (
        status,
        axum::Json(json!({
            "code": error.code,
            "message": crate::i18n::translate(&error.message),
            "data": error.data,
        })),
    )
        .into_response()
}

fn fail_sftp(error: ssh::sftp::SftpError) -> Response {
    let remote = crate::remote::map_sftp(error);
    let status = if remote.data["missing_tool"].is_string() {
        StatusCode::FAILED_DEPENDENCY
    } else {
        StatusCode::BAD_GATEWAY
    };
    fail_remote(status, remote)
}

fn fail_unknown_commit(error: ssh::sftp::SftpError, staging_path: &str) -> Response {
    let mut remote = crate::remote::map_sftp(error);
    remote.data["staging_path"] = json!(staging_path);
    fail_remote(StatusCode::BAD_GATEWAY, remote)
}

fn fail_system_access() -> Response {
    let body = json!({
        "code": 1,
        "message": crate::i18n::translate("System folder access requires verification"),
        "data": { "system_access_required": true },
    });
    (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
}

#[allow(clippy::result_large_err)]
pub(crate) fn checked_io_paths(
    st: &AppState,
    target: Option<&ssh::Target>,
    headers: &axum::http::HeaderMap,
    device_id: &str,
    paths_to_check: &[String],
) -> Result<Vec<String>, Response> {
    if paths_to_check.is_empty() {
        return Ok(Vec::new());
    }
    let actual = crate::remote::resolve_policy_paths(target, paths_to_check).map_err(|error| {
        let status = if error.data["missing_tool"].is_string() {
            StatusCode::FAILED_DEPENDENCY
        } else if error.data["timed_out"] == json!(true) {
            StatusCode::GATEWAY_TIMEOUT
        } else if target.is_some() && error.data["exit_code"] != json!(44) {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::FORBIDDEN
        };
        fail_remote(status, error)
    })?;
    if actual.len() != paths_to_check.len() {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "Cannot resolve path for policy",
        ));
    }
    let policy = st.root_policy_config();
    let session = st.session_id(headers);
    for (path, resolved) in paths_to_check.iter().zip(&actual) {
        if !paths::path_allowed_by_policy(
            policy.policy,
            &policy.roots,
            &policy.excluded_roots,
            resolved,
        ) {
            return Err(fail(
                StatusCode::FORBIDDEN,
                paths::root_policy_error(policy.policy),
            ));
        }
        if !st
            .system_access
            .paths_allowed(session.as_deref(), device_id, path, resolved)
        {
            return Err(fail_system_access());
        }
    }
    Ok(actual)
}

#[allow(clippy::result_large_err)]
pub(crate) fn checked_io_path(
    st: &AppState,
    target: Option<&ssh::Target>,
    headers: &axum::http::HeaderMap,
    device_id: &str,
    path: &str,
) -> Result<String, Response> {
    checked_io_paths(st, target, headers, device_id, &[path.to_string()])?
        .into_iter()
        .next()
        .ok_or_else(|| fail(StatusCode::FORBIDDEN, "Cannot resolve path for policy"))
}

/// A locally owned SSH child. Dropping the handle asks its reaper to kill the
/// client; it does not assert that every remote descendant has stopped.
pub(crate) struct RemoteDownload {
    stop: Arc<AtomicBool>,
    result: Option<tokio::sync::oneshot::Receiver<Result<i32, String>>>,
}
impl RemoteDownload {
    pub(crate) fn stop_handle(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }
    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn test_reaper() -> (Self, tokio::sync::oneshot::Sender<Result<i32, String>>) {
        let (sender, result) = tokio::sync::oneshot::channel();
        (
            Self {
                stop: Arc::new(AtomicBool::new(false)),
                result: Some(result),
            },
            sender,
        )
    }

    /// Wait for the local child to be reaped, without blocking the executor.
    /// After EOF a lingering client is terminated; cancellation interrupts
    /// this wait immediately. An uninterruptible kernel wait is not called a
    /// confirmed cancellation and continues holding the transfer permit.
    pub(crate) async fn finish(
        mut self,
        task: &crate::transfers::Transfer,
        force: bool,
    ) -> Result<(i32, bool), String> {
        let mut result = self.result.take().ok_or("Missing SSH download reaper")?;
        if force {
            self.stop();
        }
        let mut timed_out = false;
        let value = if force {
            result.await
        } else {
            tokio::select! {
                value = &mut result => value,
                _ = task.wait_cancelled() => { self.stop(); result.await }
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                    timed_out = true; self.stop(); result.await
                }
            }
        };
        let status =
            value.map_err(|_| "SSH download reaper stopped unexpectedly".to_string())??;
        Ok((status, timed_out))
    }
}
impl Drop for RemoteDownload {
    fn drop(&mut self) {
        self.stop();
    }
}

// If setup fails, a request is dropped, or the reaper unwinds, do not orphan
// the process. The owner is used only on a blocking thread.
#[cfg(test)]
struct DownloadChildOwner(Option<crate::ssh::ByteStream>);
#[cfg(test)]
impl Drop for DownloadChildOwner {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            kill_upload_child(&mut child);
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
fn wait_download_child(
    child: &mut crate::ssh::ByteStream,
    stop: &AtomicBool,
) -> Result<i32, String> {
    use std::io::Read;
    use std::os::unix::io::AsRawFd;
    let mut stderr = child.stderr.take();
    if let Some(pipe) = stderr.as_ref() {
        let fd = pipe.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err("Cannot monitor SSH download stderr".into());
        }
    }
    loop {
        if let Some(pipe) = stderr.as_mut() {
            let mut buf = [0u8; 8192];
            // Never block on stderr or accumulate unbounded diagnostics.
            for _ in 0..16 {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
        if stop.load(Ordering::Acquire) {
            kill_upload_child(child);
            return child
                .wait()
                .map_err(|error| format!("Cannot reap SSH download: {error}"));
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(error) => return Err(format!("Cannot wait for SSH download: {error}")),
        }
    }
}

pub(crate) fn stream_range(
    target: &ssh::Target,
    path: &str,
    offset: u64,
    len: u64,
) -> Result<(Body, RemoteDownload), RemoteError> {
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, result) = tokio::sync::oneshot::channel();
    if len == 0 {
        let _ = sender.send(Ok(0));
        return Ok((
            Body::empty(),
            RemoteDownload {
                stop,
                result: Some(result),
            },
        ));
    }
    let body = ssh::sftp::open_range(target, path, offset, len).map_err(crate::remote::map_sftp)?;
    let _ = sender.send(Ok(0));
    Ok((
        Body::from_stream(ReaderStream::with_capacity(body, CHUNK)),
        RemoteDownload {
            stop,
            result: Some(result),
        },
    ))
}

pub(crate) fn managed_device(
    st: &Arc<AppState>,
    params: &Params,
) -> Result<ssh::Target, RemoteError> {
    let device = checked_device(
        st,
        &params.get("device_id").unwrap_or_default(),
        params.get("device_revision").as_deref(),
    )?;
    crate::remote::ensure_trusted(st, &device)?;
    Ok(authenticated_target(st, &device))
}

pub(crate) fn push_body(
    target: &ssh::Target,
    script: &str,
    body: &[u8],
) -> Result<Vec<u8>, RemoteError> {
    let space = crate::remote::workspace_pub(target)?;
    let mut child = ssh::spawn_upload(target, &space, script)?;
    let (result, wrote) = std::thread::scope(|scope| {
        let writer = child.stdin.take().map(|mut stdin| {
            scope.spawn(move || stdin.write_all(body).and_then(|_| stdin.flush()))
        });
        let result = child.wait_with_output();
        let wrote = writer
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err(std::io::Error::other("writer panicked")))
            })
            .unwrap_or_else(|| Err(std::io::Error::other("missing writer")));
        (result, wrote)
    });
    // A failed streaming patch can have written a prefix before an SSH
    // disconnect or dd failure. Never report it as safely retryable.
    match result {
        Ok(output) if output.success() && wrote.is_ok() => Ok(output.stdout),
        output => {
            let detail = match output {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    if stderr.is_empty() {
                        format!("Remote command failed (exit {})", output.status)
                    } else {
                        stderr
                    }
                }
                Err(_) => "Cannot write to the device".to_string(),
            };
            Err(RemoteError::with_data(
                format!("{detail}. Remote write may be partial; check the file before retrying"),
                json!({"outcome_unknown": true}),
            ))
        }
    }
}

fn target_identity(target: &ssh::Target) -> String {
    format!(
        "{}\0{}\0{}\0{}\0{}",
        target.id, target.host, target.port, target.username, target.host_key
    )
}

const ARCHIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(120);

static ARCHIVE_STAGED_BYTES: AtomicU64 = AtomicU64::new(0);
static ARCHIVE_ACTIVE: AtomicUsize = AtomicUsize::new(0);

struct ArchiveSlot;
impl ArchiveSlot {
    fn acquire() -> Option<Self> {
        let mut active = ARCHIVE_ACTIVE.load(Ordering::Acquire);
        loop {
            if active >= 64 {
                return None;
            }
            match ARCHIVE_ACTIVE.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self),
                Err(current) => active = current,
            }
        }
    }
}
impl Drop for ArchiveSlot {
    fn drop(&mut self) {
        ARCHIVE_ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reserve_archive_bytes(counter: &AtomicU64, amount: u64, max: u64) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(amount).filter(|total| *total <= max) else {
            return false;
        };
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

// Archive uploads are staged as compressed bytes before extraction. This
// makes it possible to validate *every* member and its destination rather
// than trusting a client-generated archive or a textual tar listing.
struct ArchiveSession {
    device_id: String,
    owner: Option<String>,
    target_identity: Option<String>,
    path: String,
    spool_path: std::path::PathBuf,
    spool: Option<std::fs::File>,
    overwrite: bool,
    preserve: bool,
    preserve_paths: Vec<String>,
    received: u64,
    _slot: ArchiveSlot,
    _transfer: tokio::sync::OwnedSemaphorePermit,
    activity: crate::task_registry::SessionActivity,
}

impl crate::task_registry::SessionResource for ArchiveSession {
    fn activity(&self) -> &crate::task_registry::SessionActivity {
        &self.activity
    }
    fn activity_mut(&mut self) -> &mut crate::task_registry::SessionActivity {
        &mut self.activity
    }
    fn progress(&self) -> u64 {
        self.received
    }
}

impl Drop for ArchiveSession {
    fn drop(&mut self) {
        self.spool.take();
        let _ = std::fs::remove_file(&self.spool_path);
        ARCHIVE_STAGED_BYTES.fetch_sub(self.received, Ordering::AcqRel);
    }
}

const ARCHIVE_UPLOAD_MAX_DEFAULT: u64 = 2 * 1024 * 1024 * 1024;
fn archive_upload_max() -> u64 {
    std::env::var("HARBOR_ARCHIVE_UPLOAD_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|value: &u64| *value > 0)
        .unwrap_or(ARCHIVE_UPLOAD_MAX_DEFAULT)
}

fn archive_total_max() -> u64 {
    std::env::var("HARBOR_ARCHIVE_UPLOAD_TOTAL_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|value: &u64| *value > 0)
        .unwrap_or(4 * 1024 * 1024 * 1024)
}

fn archive_uncompressed_max() -> u64 {
    std::env::var("HARBOR_ARCHIVE_UPLOAD_UNCOMPRESSED_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|value: &u64| *value > 0)
        .unwrap_or(8 * 1024 * 1024 * 1024)
}

fn create_archive_spool(st: &AppState) -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = std::path::Path::new(&st.settings.state_dir).join("archive-uploads");
    crate::tasks::ensure_private_dir(&dir)?;
    for _ in 0..16 {
        let path = dir.join(format!(
            ".harbor-upload-{}.tar.gz",
            crate::uci::random_hex(16)
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                crate::paths::journal_tmp(&path.to_string_lossy());
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "cannot create archive staging file",
    ))
}

fn archive_script(dir: &str, overwrite: bool, preserve: bool, preserve_paths: &[String]) -> String {
    let mut script = String::from("set -e\numask 022\n");
    script.push_str(&format!("cd {} || exit 44\n", shell_quote(dir)));
    if overwrite && preserve {
        for (index, path) in preserve_paths.iter().enumerate() {
            let mode = format!("harbor_mode_{index}");
            let quoted = shell_quote(path);
            script.push_str(&format!(
                "{mode}=; if [ -e {path} ] && [ ! -L {path} ]; then {mode}=$(stat -c '%a' {path} 2>/dev/null || busybox stat -c '%a' {path} 2>/dev/null || true); fi\n",
                mode = mode,
                path = quoted
            ));
        }
        script.push_str("tar -xzof -\n");
        for (index, path) in preserve_paths.iter().enumerate() {
            let mode = format!("harbor_mode_{index}");
            let quoted = shell_quote(path);
            script.push_str(&format!(
                "if [ -n \"${mode}\" ]; then chmod \"${mode}\" {path}; fi\n",
                mode = mode,
                path = quoted
            ));
        }
    } else if overwrite {
        script.push_str("tar -xzof -\n");
    } else {
        let nonce = crate::uci::random_hex(12);
        script.push_str(&format!(
            "staging=.harbor-incoming-{nonce}\nconflicts=.harbor-conflicts-{nonce}\n"
        ));
        script.push_str("trap 'rm -rf -- \"$staging\"; rm -f -- \"$conflicts\"' EXIT\n");
        script.push_str("mkdir -- \"$staging\"\n");
        script.push_str("tar -xzof - -C \"$staging\"\n");
        script.push_str("find \"$staging\" -mindepth 1 | while IFS= read -r entry; do\n");
        script.push_str(" rel=${entry#\"$staging\"/}\n");
        script
            .push_str(" if [ -e \"$rel\" ] || [ -L \"$rel\" ]; then printf '%s\\n' \"$rel\"; fi\n");
        script.push_str("done | head -n 512 > \"$conflicts\"\n");
        script.push_str("if [ -s \"$conflicts\" ]; then printf 'CONFLICT\\n' >&2; exit 45; fi\n");
        script.push_str("rm -f -- \"$conflicts\"\n");
        script.push_str("cd \"$staging\"\n");
        script.push_str("find . -mindepth 1 -maxdepth 1 -exec mv -f {} .. \\;\n");
        script.push_str("cd ..\nrmdir \"$staging\"\n");
    }
    script.push_str("printf 'OK\\n'");
    script
}

fn remote_script_fits(script: &str) -> bool {
    crate::ssh::script_exec_len(script) <= crate::ssh::SCRIPT_EXEC_LIMIT
}

#[allow(clippy::result_large_err)]
fn capture_remote_modes(
    target: &ssh::Target,
    dir: &str,
    paths: &[String],
) -> Result<Vec<(String, String)>, Response> {
    let mut modes = Vec::new();
    let mut index = 0;
    while index < paths.len() {
        let mut script = format!("set -e\ncd {} || exit 44\n", shell_quote(dir));
        let mut count = 0;
        while index + count < paths.len() {
            let quoted = shell_quote(&paths[index + count]);
            let line = format!(
                "if [ -e {path} ] && [ ! -L {path} ]; then m=$(stat -c '%a' {path} 2>/dev/null || busybox stat -c '%a' {path} 2>/dev/null || true); if [ -n \"$m\" ]; then printf '%s\\t%s\\n' {path} \"$m\"; fi; fi\n",
                path = quoted
            );
            let candidate = format!("{script}{line}");
            if count > 0 && !remote_script_fits(&candidate) {
                break;
            }
            if count == 0 && !remote_script_fits(&candidate) {
                index += 1;
                count = 0;
                script = format!("set -e\ncd {} || exit 44\n", shell_quote(dir));
                continue;
            }
            script = candidate;
            count += 1;
        }
        if count == 0 {
            break;
        }
        let output = crate::remote::run(target, &script, Some(120))
            .map_err(|error| fail(StatusCode::BAD_GATEWAY, &error.message))?;
        for line in String::from_utf8_lossy(&output).lines() {
            let Some((path, mode)) = line.split_once('\t') else {
                continue;
            };
            if path.is_empty()
                || !mode.chars().all(|ch| matches!(ch, '0'..='7'))
                || !(3..=4).contains(&mode.len())
            {
                continue;
            }
            modes.push((path.to_string(), mode.to_string()));
        }
        index += count;
    }
    Ok(modes)
}

#[allow(clippy::result_large_err)]
fn restore_remote_modes(
    target: &ssh::Target,
    dir: &str,
    modes: &[(String, String)],
) -> Result<(), Response> {
    let mut index = 0;
    while index < modes.len() {
        let mut script = format!("set -e\ncd {} || exit 44\n", shell_quote(dir));
        let mut count = 0;
        while index + count < modes.len() {
            let (path, mode) = &modes[index + count];
            if !mode.chars().all(|ch| matches!(ch, '0'..='7')) || !(3..=4).contains(&mode.len()) {
                count += 1;
                continue;
            }
            let quoted = shell_quote(path);
            let line = format!(
                "if [ -e {path} ] && [ ! -L {path} ]; then chmod {mode} {path}; fi\n",
                path = quoted,
                mode = mode
            );
            let candidate = format!("{script}{line}");
            if count > 0 && !remote_script_fits(&candidate) {
                break;
            }
            if count == 0 && !remote_script_fits(&candidate) {
                index += 1;
                count = 0;
                script = format!("set -e\ncd {} || exit 44\n", shell_quote(dir));
                continue;
            }
            script = candidate;
            count += 1;
        }
        if count == 0 {
            break;
        }
        crate::remote::run(target, &script, Some(120))
            .map_err(|error| fail(StatusCode::BAD_GATEWAY, &error.message))?;
        index += count;
    }
    Ok(())
}

fn spawn_archive_writer(
    target: Option<&ssh::Target>,
    script: &str,
) -> Result<crate::ssh::ByteStream, String> {
    match target {
        Some(target) => {
            let space = crate::remote::workspace_pub(target).map_err(|error| error.message)?;
            ssh::spawn_upload(target, &space, script)
        }
        None => {
            let mut cmd = std::process::Command::new("sh");
            cmd.arg("-c")
                .arg(script)
                .env("LC_ALL", "C")
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            cmd.spawn()
                .map_err(|_| "Cannot start the upload".to_string())
                .and_then(|child| ssh::ByteStream::from_child(child, true))
        }
    }
}

fn archive_append(
    registry: &crate::task_registry::TaskRegistry,
    session_id: &str,
    data: &[u8],
) -> Result<(), (StatusCode, String)> {
    registry
        .with_session::<ArchiveSession, _>(session_id, |session| {
            let total = session.received.checked_add(data.len() as u64).ok_or((
                StatusCode::PAYLOAD_TOO_LARGE,
                "Archive upload is too large".to_string(),
            ))?;
            if total > archive_upload_max() {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Archive upload is too large".to_string(),
                ));
            }
            let spool = session.spool.as_mut().ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Upload is already closed".to_string(),
            ))?;
            let amount = data.len() as u64;
            if !reserve_archive_bytes(&ARCHIVE_STAGED_BYTES, amount, archive_total_max()) {
                return Err((
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Archive upload staging capacity exceeded".to_string(),
                ));
            }
            if spool.write_all(data).is_err() {
                ARCHIVE_STAGED_BYTES.fetch_sub(amount, Ordering::AcqRel);
                return Err((
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Cannot stage the archive upload".to_string(),
                ));
            }
            session.received = total;
            session.activity.touched = std::time::Instant::now();
            Ok(())
        })
        .unwrap_or_else(|| {
            Err((
                StatusCode::NOT_FOUND,
                "Upload session not found".to_string(),
            ))
        })
}

fn archive_abort(registry: &crate::task_registry::TaskRegistry, session_id: &str) {
    registry.discard_session::<ArchiveSession>(
        session_id,
        crate::task_registry::SessionCleanup::Aborted,
    );
}

#[allow(clippy::result_large_err)]
fn archive_finish(
    st: &AppState,
    target: Option<&ssh::Target>,
    headers: &axum::http::HeaderMap,
    mut session: ArchiveSession,
) -> Result<u64, Response> {
    let mut spool = session.spool.take().ok_or_else(|| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Upload is already closed",
        )
    })?;
    spool.flush().map_err(|_| {
        fail(
            StatusCode::INSUFFICIENT_STORAGE,
            "Cannot stage the archive upload",
        )
    })?;
    drop(spool);
    let spool_path = session.spool_path.to_str().ok_or_else(|| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid archive staging path",
        )
    })?;
    let members = crate::archive_inspect::inspect_local_tar_with_limit(
        spool_path,
        "targz",
        crate::api::archops::ARCHIVE_LIST_LIMIT,
        Some(archive_uncompressed_max()),
    )
    .map_err(|message| fail(StatusCode::BAD_REQUEST, &message))?;
    if members.iter().any(|member| member.mode & 0o7000 != 0) {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "Archive upload contains privileged permissions",
        ));
    }
    let names = crate::api::archops::archive_selection_paths(&members, None)
        .map_err(|message| fail(StatusCode::BAD_REQUEST, &message))?;
    let candidates = crate::api::archops::archive_destination_paths(&session.path, &names)
        .map_err(|message| fail(StatusCode::BAD_REQUEST, &message))?;
    let actual = checked_io_paths(st, target, headers, &session.device_id, &candidates)?;
    let resolved_dir = actual
        .first()
        .ok_or_else(|| fail(StatusCode::FORBIDDEN, "Cannot resolve upload directory"))?;
    match target {
        Some(target) => crate::remoteops::reject_archive_symlinks(target, &session.path, &names)
            .map_err(|error| fail(StatusCode::FORBIDDEN, &error.message))?,
        None => crate::api::archops::check_local_archive_destinations(&session.path, &names)
            .map_err(|message| fail(StatusCode::FORBIDDEN, &message))?,
    }
    if !session.overwrite {
        let mut top_levels = std::collections::HashSet::new();
        for name in &names {
            if let Some(top) = name.split('/').next() {
                top_levels.insert(top.to_string());
            }
        }
        let conflicts = match target {
            Some(target) => crate::remoteops::archive_conflicts(target, &session.path, &names)
                .map_err(|error| fail(StatusCode::BAD_GATEWAY, &error.message))?,
            None => top_levels
                .into_iter()
                .filter(|top| {
                    std::fs::symlink_metadata(paths::join_path(&session.path, top)).is_ok()
                })
                .collect(),
        };
        if !conflicts.is_empty() {
            return Err(fail(StatusCode::CONFLICT, "upload target already exists"));
        }
    }
    let member_names: std::collections::HashSet<&str> = names.iter().map(String::as_str).collect();
    // Stay relative: archive_script already cds into the destination, and full
    // paths blow past SCRIPT_EXEC_LIMIT on ordinary overwrite batches.
    let preserve: Vec<String> = session
        .preserve_paths
        .iter()
        .filter(|name| member_names.contains(name.as_str()))
        .cloned()
        .collect();
    let inline = session.preserve && !preserve.is_empty();
    let combined = archive_script(resolved_dir, session.overwrite, inline, &preserve);
    let remote_overflow = target.is_some()
        && inline
        && crate::ssh::script_exec_len(&combined) > crate::ssh::SCRIPT_EXEC_LIMIT;
    let saved_modes = if remote_overflow {
        let Some(remote) = target else {
            return Err(fail(
                StatusCode::BAD_GATEWAY,
                "Cannot preserve permissions for this upload",
            ));
        };
        capture_remote_modes(remote, resolved_dir, &preserve)?
    } else {
        Vec::new()
    };
    let script = if remote_overflow {
        archive_script(resolved_dir, session.overwrite, false, &[])
    } else {
        combined
    };
    let mut input = std::fs::File::open(&session.spool_path).map_err(|_| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Cannot read staged archive",
        )
    })?;
    let mut child = spawn_archive_writer(target, &script)
        .map_err(|message| fail(StatusCode::BAD_GATEWAY, &message))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| fail(StatusCode::BAD_GATEWAY, "Cannot write to the device"))?;
    let (output, wrote) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || std::io::copy(&mut input, &mut stdin));
        let output = child.wait_with_output();
        (output, writer.join().ok())
    });
    let output = output.map_err(|_| {
        fail(
            StatusCode::BAD_GATEWAY,
            "Upload outcome is unknown; check the destination before retrying",
        )
    })?;
    if !output.success() || !matches!(wrote, Some(Ok(count)) if count == session.received) {
        let detail = String::from_utf8_lossy(&output.stderr);
        if Some(output.status) == Some(45) || detail.contains("CONFLICT") {
            return Err(fail(StatusCode::CONFLICT, "upload target already exists"));
        }
        if Some(output.status).is_none() || Some(output.status) == Some(255) || wrote.is_none() {
            return Err(fail(
                StatusCode::BAD_GATEWAY,
                "Upload outcome is unknown; check the destination before retrying",
            ));
        }
        return Err(fail(
            StatusCode::BAD_GATEWAY,
            if detail.trim().is_empty() {
                "Archive upload failed"
            } else {
                detail.trim()
            },
        ));
    }
    if !saved_modes.is_empty() {
        let Some(remote) = target else {
            return Err(fail(
                StatusCode::BAD_GATEWAY,
                "Cannot preserve permissions for this upload",
            ));
        };
        restore_remote_modes(remote, resolved_dir, &saved_modes)?;
    }
    Ok(session.received)
}

fn sftp_remote_target(path: &str) -> Option<(String, String)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return None;
    }
    let (dir, name) = match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(idx) => (&trimmed[..idx], &trimmed[idx + 1..]),
        None => (".", trimmed),
    };
    if name.is_empty() {
        return None;
    }
    Some((dir.to_string(), name.to_string()))
}

struct UploadReservation {
    key: String,
}

fn upload_reservations() -> &'static Mutex<std::collections::HashSet<String>> {
    static ACTIVE: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

impl UploadReservation {
    fn acquire(key: String) -> Option<Self> {
        let mut active = upload_reservations().lock().ok()?;
        if active.len() >= 64 || !active.insert(key.clone()) {
            return None;
        }
        Some(Self { key })
    }
}

impl Drop for UploadReservation {
    fn drop(&mut self) {
        if let Ok(mut active) = upload_reservations().lock() {
            active.remove(&self.key);
        }
    }
}

struct UploadSession {
    device_id: String,
    owner: Option<String>,
    target_identity: String,
    path: String,
    dir: String,
    name: String,
    temp_dir: String,
    expected: Option<u64>,
    overwrite: bool,
    preserve: bool,
    resumable: bool,
    _reservation: UploadReservation,
    _transfer: tokio::sync::OwnedSemaphorePermit,
    child: crate::ssh::ByteStream,
    staged: u64,
    activity: crate::task_registry::SessionActivity,
    target: ssh::Target,
}

const UPLOAD_IDLE: std::time::Duration = std::time::Duration::from_secs(120);

#[derive(Clone, Copy)]
enum SftpFinishOutcome {
    Running,
    Completed,
    Failed(StatusCode),
    Unknown,
}

struct SftpFinishReceipt {
    device_id: String,
    owner: Option<String>,
    target_identity: String,
    path: String,
    staging_path: String,
    staged: u64,
    outcome: SftpFinishOutcome,
    activity: crate::task_registry::SessionActivity,
}
impl crate::task_registry::SessionResource for SftpFinishReceipt {
    fn activity(&self) -> &crate::task_registry::SessionActivity {
        &self.activity
    }
    fn activity_mut(&mut self) -> &mut crate::task_registry::SessionActivity {
        &mut self.activity
    }
    fn progress(&self) -> u64 {
        self.staged
    }
}
impl SftpFinishReceipt {
    fn from_upload(session: &UploadSession) -> Self {
        let mut activity = crate::task_registry::SessionActivity::new(UPLOAD_IDLE);
        activity.busy = true;
        Self {
            device_id: session.device_id.clone(),
            owner: session.owner.clone(),
            target_identity: session.target_identity.clone(),
            path: session.path.clone(),
            staging_path: session.temp_dir.clone(),
            staged: session.staged,
            outcome: SftpFinishOutcome::Running,
            activity,
        }
    }
    fn response(&self, finish: bool) -> Response {
        match self.outcome {
            SftpFinishOutcome::Running => fail(StatusCode::CONFLICT, "Upload session is busy"),
            SftpFinishOutcome::Completed if finish => {
                axum::Json(json!({"code": 0, "message": "success",
                "data": {"path": self.path, "uploaded_bytes": self.staged, "done": true}}))
                .into_response()
            }
            SftpFinishOutcome::Completed => {
                fail(StatusCode::CONFLICT, "Upload has already completed")
            }
            SftpFinishOutcome::Failed(status) => fail(status, "Upload could not be completed"),
            SftpFinishOutcome::Unknown => fail_remote(
                StatusCode::BAD_GATEWAY,
                RemoteError::with_data(
                    "Upload outcome is unknown; check the destination before retrying",
                    json!({"outcome_unknown": true, "staging_path": self.staging_path}),
                ),
            ),
        }
    }
}

fn sftp_receipt_or_missing(
    st: &AppState,
    id: &str,
    target: &ssh::Target,
    path: &str,
    owner: &Option<String>,
    identity: &str,
    finish: bool,
) -> Response {
    match st
        .tasks
        .try_with_session::<SftpFinishReceipt, _>(id, |receipt| {
            (receipt.device_id == target.id
                && receipt.path == path
                && &receipt.owner == owner
                && receipt.target_identity == identity)
                .then(|| receipt.response(finish))
        }) {
        Ok(Some(response)) => response,
        Err(crate::task_registry::SessionError::Busy) => {
            fail(StatusCode::CONFLICT, "Upload session is busy")
        }
        _ => fail(StatusCode::NOT_FOUND, "Upload session not found"),
    }
}

struct SftpFinishGuard {
    registry: Arc<crate::task_registry::TaskRegistry>,
    id: String,
    recorded: bool,
}
impl SftpFinishGuard {
    fn record(&mut self, outcome: SftpFinishOutcome) {
        self.registry
            .with_session::<SftpFinishReceipt, _>(&self.id, |receipt| {
                receipt.outcome = outcome;
                receipt.activity.busy = false;
                receipt.activity.touched = std::time::Instant::now();
            });
        self.recorded = true;
    }
}
impl Drop for SftpFinishGuard {
    fn drop(&mut self) {
        if !self.recorded {
            self.record(SftpFinishOutcome::Unknown);
        }
    }
}

fn upload_kill(session: &mut UploadSession) {
    session.child.stdin.take();
    kill_upload_child(&mut session.child);
    let _ = session.child.wait();
}

impl Drop for UploadSession {
    fn drop(&mut self) {
        upload_kill(self);
    }
}

impl crate::task_registry::SessionResource for UploadSession {
    const ASYNC_CLEANUP: bool = true;
    fn activity(&self) -> &crate::task_registry::SessionActivity {
        &self.activity
    }
    fn activity_mut(&mut self) -> &mut crate::task_registry::SessionActivity {
        &mut self.activity
    }
    fn progress(&self) -> u64 {
        self.staged
    }
    fn cleanup(&mut self, reason: crate::task_registry::SessionCleanup) {
        upload_kill(self);
        if matches!(
            reason,
            crate::task_registry::SessionCleanup::Interrupted
                | crate::task_registry::SessionCleanup::Aborted
        ) || (reason == crate::task_registry::SessionCleanup::Expired && !self.resumable)
        {
            let _ = crate::remote::run(
                &self.target,
                &format!("rm -rf -- {}", shell_quote(&self.temp_dir)),
                Some(30),
            );
        }
    }
}

fn upload_abort(registry: &crate::task_registry::TaskRegistry, session_id: &str) {
    registry.discard_session::<UploadSession>(
        session_id,
        crate::task_registry::SessionCleanup::Aborted,
    );
}

fn parse_sftp_ready(prefix: &[u8], expected: Option<u64>) -> Option<u64> {
    let digits = prefix.strip_prefix(b"READY ")?.strip_suffix(b"\n")?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let size = std::str::from_utf8(digits).ok()?.parse::<u64>().ok()?;
    if expected.is_some_and(|limit| size > limit) {
        return None;
    }
    Some(size)
}

#[cfg(test)]
type SftpAuthRaceHook = (
    String,
    std::sync::mpsc::Sender<()>,
    std::sync::mpsc::Receiver<()>,
);
#[cfg(test)]
static SFTP_AUTH_RACE_HOOK: std::sync::Mutex<Option<SftpAuthRaceHook>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
fn test_pause_after_sftp_authorization(id: &str) {
    let hook = {
        let mut slot = SFTP_AUTH_RACE_HOOK.lock().unwrap();
        if slot.as_ref().is_some_and(|(expected, _, _)| expected == id) {
            slot.take()
        } else {
            None
        }
    };
    if let Some((_, entered, release)) = hook {
        let _ = entered.send(());
        release
            .recv_timeout(std::time::Duration::from_secs(15))
            .expect("SFTP race test was not released");
    }
}

pub(crate) async fn upload_sftp(
    st: &Arc<AppState>,
    target: Option<&ssh::Target>,
    path: &str,
    params: &Params,
    headers: &axum::http::HeaderMap,
    req: axum::extract::Request,
) -> Response {
    let Some(target) = target else {
        return fail(StatusCode::BAD_REQUEST, "Upload requires a remote device");
    };
    let existing = params.get("upload_session").unwrap_or_default();
    let finish = params.get("finish").as_deref() == Some("1");
    let abort = params.get("abort").as_deref() == Some("1");
    let pause = params.get("pause").as_deref() == Some("1");
    let owner = st.session_id(headers);
    let identity = target_identity(target);

    if !existing.is_empty() {
        match st
            .tasks
            .try_with_session::<UploadSession, _>(&existing, |session| {
                session.device_id == target.id
                    && session.path == path
                    && session.owner == owner
                    && session.target_identity == identity
            }) {
            Ok(true) => (),
            Err(crate::task_registry::SessionError::Busy) => {
                return fail(StatusCode::CONFLICT, "Upload session is busy")
            }
            Err(crate::task_registry::SessionError::Missing) => {
                return sftp_receipt_or_missing(
                    st, &existing, target, path, &owner, &identity, finish,
                );
            }
            Ok(false) => return fail(StatusCode::NOT_FOUND, "Upload session not found"),
        }
    }

    #[cfg(test)]
    test_pause_after_sftp_authorization(&existing);

    if pause {
        if !existing.is_empty() {
            let session = match st.tasks.take_session::<UploadSession>(&existing, true) {
                Ok(session) => session,
                Err(crate::task_registry::SessionError::Busy) => {
                    return fail(StatusCode::CONFLICT, "Upload session is busy")
                }
                Err(crate::task_registry::SessionError::Missing) => {
                    return sftp_receipt_or_missing(
                        st, &existing, target, path, &owner, &identity, finish,
                    )
                }
            };
            if tokio::task::spawn_blocking(move || {
                let mut session = session;
                upload_kill(&mut session);
            })
            .await
            .is_err()
            {
                return fail(StatusCode::BAD_GATEWAY, "Cannot pause the upload");
            }
        }
        return axum::Json(json!({ "code": 0, "message": "success", "data": { "paused": true } }))
            .into_response();
    }

    if abort {
        if !existing.is_empty() {
            let session = match st.tasks.take_session::<UploadSession>(&existing, true) {
                Ok(session) => session,
                Err(crate::task_registry::SessionError::Busy) => {
                    return fail(StatusCode::CONFLICT, "Upload session is busy")
                }
                Err(crate::task_registry::SessionError::Missing) => {
                    return sftp_receipt_or_missing(
                        st, &existing, target, path, &owner, &identity, finish,
                    )
                }
            };
            if tokio::task::spawn_blocking(move || {
                use crate::task_registry::SessionResource;
                let mut session = session;
                session.cleanup(crate::task_registry::SessionCleanup::Aborted);
            })
            .await
            .is_err()
            {
                return fail(StatusCode::BAD_GATEWAY, "Cannot abort the upload");
            }
        }
        return axum::Json(json!({ "code": 0, "message": "success", "data": { "aborted": true } }))
            .into_response();
    }

    if existing.is_empty() {
        let st = st.clone();
        let target = target.clone();
        let path = path.to_string();
        let params = params.clone();
        let headers = headers.clone();
        return match tokio::task::spawn_blocking(move || {
            start_sftp(&st, &target, &path, &params, &headers, owner, identity)
        })
        .await
        {
            Ok(response) => response,
            Err(_) => fail(StatusCode::BAD_GATEWAY, "Cannot start the upload"),
        };
    }

    if !finish {
        let mut request_guard = match st.tasks.acquire_session::<UploadSession>(&existing) {
            Ok(guard) => guard,
            Err(crate::task_registry::SessionError::Busy) => {
                return fail(StatusCode::CONFLICT, "Upload session is busy")
            }
            Err(crate::task_registry::SessionError::Missing) => {
                return sftp_receipt_or_missing(
                    st, &existing, target, path, &owner, &identity, finish,
                )
            }
        };
        let idle = std::time::Duration::from_secs(st.settings.body_idle_timeout.max(1));
        let body =
            match crate::limits::read_body_limited_with_idle(req, 16 * 1024 * 1024, Some(idle))
                .await
            {
                Ok(body) => body,
                Err(crate::limits::BodyReadError::TooLarge) => {
                    return fail(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
                }
                Err(crate::limits::BodyReadError::Invalid) => {
                    return fail(StatusCode::BAD_REQUEST, "invalid request body")
                }
                Err(crate::limits::BodyReadError::TimedOut) => {
                    return fail(StatusCode::REQUEST_TIMEOUT, "Upload request timed out")
                }
            };
        if body.is_empty() {
            let staged = st
                .tasks
                .with_session::<UploadSession, _>(&existing, |s| s.staged)
                .unwrap_or(0);
            request_guard.finish();
            return axum::Json(json!({
                "code": 0,
                "message": "success",
                "data": { "upload_session": existing, "received": staged, "path": path },
            }))
            .into_response();
        }
        // Move stdin out while the blocking writer runs. The session mutex
        // must remain free so an interrupted request can kill the child and
        // release a writer blocked on SSH backpressure.
        let prepared = st
            .tasks
            .with_session::<UploadSession, _>(&existing, |session| {
                session.activity.touched = std::time::Instant::now();
                let next = session
                    .staged
                    .checked_add(body.len() as u64)
                    .ok_or_else(|| "upload size does not match".to_string())?;
                if session.expected.is_some_and(|expected| next > expected) {
                    return Err("upload size does not match".to_string());
                }
                let stdin = session
                    .child
                    .stdin
                    .take()
                    .ok_or_else(|| "Upload is already closed".to_string())?;
                Ok((stdin, next))
            })
            .unwrap_or_else(|| Err("upload session not found".to_string()));
        let (mut stdin, next) = match prepared {
            Ok(prepared) => prepared,
            Err(message) => {
                let registry = st.tasks.clone();
                let id = existing.clone();
                let _ = tokio::task::spawn_blocking(move || upload_abort(&registry, &id)).await;
                request_guard.finish();
                return if message.contains("size") {
                    fail(StatusCode::BAD_REQUEST, &message)
                } else if message.contains("session") {
                    fail(StatusCode::NOT_FOUND, &message)
                } else {
                    fail(StatusCode::BAD_GATEWAY, &message)
                };
            }
        };
        let write = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            tokio::task::spawn_blocking(move || {
                let result = stdin.write_all(&body);
                (stdin, result)
            }),
        )
        .await;
        let (stdin, result) = match write {
            Ok(Ok(result)) => result,
            _ => return fail(StatusCode::GATEWAY_TIMEOUT, "Cannot write to the device"),
        };
        if result.is_err() {
            drop(stdin);
            let registry = st.tasks.clone();
            let id = existing.clone();
            let _ = tokio::task::spawn_blocking(move || upload_abort(&registry, &id)).await;
            request_guard.finish();
            return fail(StatusCode::BAD_GATEWAY, "Cannot write to the device");
        }
        let restored = st
            .tasks
            .with_session::<UploadSession, _>(&existing, |session| {
                session.child.stdin = Some(stdin);
                session.staged = next;
            })
            .is_some();
        if !restored {
            return fail(StatusCode::NOT_FOUND, "upload session not found");
        }
        request_guard.finish();
        return axum::Json(json!({
            "code": 0, "message": "success",
            "data": { "upload_session": existing, "received": next, "path": path },
        }))
        .into_response();
    }

    let session = match st
        .tasks
        .replace_session::<UploadSession, SftpFinishReceipt>(
            &existing,
            SftpFinishReceipt::from_upload,
        ) {
        Ok(session) => session,
        Err(crate::task_registry::SessionError::Busy) => {
            return fail(StatusCode::CONFLICT, "Upload session is busy")
        }
        Err(crate::task_registry::SessionError::Missing) => {
            return sftp_receipt_or_missing(st, &existing, target, path, &owner, &identity, finish)
        }
    };
    let target = target.clone();
    let registry = st.tasks.clone();
    let id = existing.clone();
    match tokio::task::spawn_blocking(move || {
        let mut guard = SftpFinishGuard {
            registry,
            id,
            recorded: false,
        };
        let response = finish_sftp(&target, session);
        let status = response.status();
        let outcome = if status.is_success() {
            SftpFinishOutcome::Completed
        } else if status.is_client_error() {
            SftpFinishOutcome::Failed(status)
        } else {
            SftpFinishOutcome::Unknown
        };
        guard.record(outcome);
        response
    })
    .await
    {
        Ok(response) => response,
        Err(_) => fail_remote(
            StatusCode::BAD_GATEWAY,
            RemoteError::with_data(
                "Upload outcome is unknown; check the destination before retrying",
                json!({"outcome_unknown": true}),
            ),
        ),
    }
}

// The startup protocol uses blocking child-process and SSH operations; it is
// always called from Tokio's blocking pool.
fn start_sftp(
    st: &Arc<AppState>,
    target: &ssh::Target,
    path: &str,
    params: &Params,
    headers: &axum::http::HeaderMap,
    owner: Option<String>,
    identity: String,
) -> Response {
    let overwrite = params.get("overwrite").as_deref() == Some("1");
    let preserve = params.get("preserve_permissions").as_deref() != Some("0");
    let Some((dir, name)) = sftp_remote_target(path) else {
        return fail(StatusCode::BAD_REQUEST, "invalid upload path");
    };
    let dest = format!("{}/{}", dir.trim_end_matches('/'), name);
    let token = crate::uci::random_hex(16);
    let resume_size = match params.get("upload_size") {
        Some(value) => match value.parse::<u64>() {
            Ok(value) => Some(value),
            Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid upload size"),
        },
        None => None,
    };
    let resume_mtime = params
        .get("upload_mtime")
        .and_then(|value| value.parse::<i64>().ok());
    let resumable = resume_size.is_some() && resume_mtime.is_some();
    let temp_dir = if resumable {
        let digest = crate::auth::sha256_bytes(
            format!(
                "{}\0{}\0{dir}\0{name}\0{}\0{}",
                identity,
                owner.as_deref().unwrap_or(""),
                resume_size.unwrap_or(0),
                resume_mtime.unwrap_or(0)
            )
            .as_bytes(),
        );
        paths::join_path(
            &dir,
            &format!(".harbor-upload-{}", hex::encode(&digest[..16])),
        )
    } else {
        paths::join_path(&dir, &format!(".harbor-upload-{token}"))
    };
    if let Err(response) = checked_io_path(st, Some(target), headers, &target.id, &temp_dir) {
        return response;
    }
    let Some(reservation) = UploadReservation::acquire(format!("{identity}\0{temp_dir}")) else {
        return fail(
            StatusCode::CONFLICT,
            "An upload for this file is already active",
        );
    };
    let Some(transfer) = st.limits.begin_transfer() else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many transfers in flight",
        );
    };
    let mut attempt = 0;
    let (child, staged) = loop {
        attempt += 1;
        if attempt > 1 {
            ssh::reset_control(target);
        }
        let spawned = ssh::sftp::spawn_upload_stream(
            target,
            &dir,
            &name,
            &temp_dir,
            overwrite,
            if resumable { resume_size } else { None },
        );
        let mut child = match spawned {
            Ok((child, _)) => child,
            Err(ssh::sftp::SftpError::Message(message)) if message.contains("already exists") => {
                return fail(StatusCode::CONFLICT, "upload target already exists");
            }
            Err(error) => return fail_sftp(error),
        };
        let mut stdout = child.stdout.take();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        if let Some(mut out) = stdout.take() {
            std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = Vec::with_capacity(8);
                let mut byte = [0u8; 1];
                loop {
                    match out.read(&mut byte) {
                        Ok(0) => break,
                        Ok(_) => {
                            buf.push(byte[0]);
                            if byte[0] == b'\n' || buf.len() >= 48 {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = ready_tx.send(buf);
            });
        } else {
            let _ = ready_tx.send(Vec::new());
        }
        match ready_rx.recv_timeout(std::time::Duration::from_secs(15)) {
            Ok(prefix) if prefix.starts_with(b"READY ") && prefix.ends_with(b"\n") => {
                let staged = parse_sftp_ready(&prefix, resume_size);
                if staged.is_none() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return fail(StatusCode::BAD_GATEWAY, "Invalid upload resume response");
                }
                break (child, staged.unwrap());
            }
            Ok(_) => {
                let mut exited = None;
                for _ in 0..50 {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            exited = Some(status);
                            break;
                        }
                        Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
                        Err(_) => break,
                    }
                }
                if exited.is_none() {
                    let _ = child.kill();
                }
                let status = match child.wait() {
                    Ok(code) => Some(code),
                    Err(_) => exited,
                };
                let mut detail = String::new();
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let _ = err.read_to_string(&mut detail);
                }
                let detail = detail.trim().to_string();
                if status == Some(45) || detail.contains("upload target already exists") {
                    return fail(StatusCode::CONFLICT, "upload target already exists");
                }
                if attempt == 1 {
                    continue;
                }
                let message = if detail.is_empty() {
                    format!(
                        "Remote command failed (exit {})",
                        status
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "?".to_string())
                    )
                } else {
                    detail
                };
                return fail(StatusCode::BAD_GATEWAY, &message);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if attempt == 1 {
                    if let Ok(Some(_)) = child.try_wait() {
                        let _ = child.wait();
                        continue;
                    }
                }
                let _ = child.kill();
                let _ = child.wait();
                return fail(StatusCode::GATEWAY_TIMEOUT, "Cannot start the upload");
            }
        }
    };
    st.tasks.start_reaper();
    let session = UploadSession {
        device_id: target.id.clone(),
        owner,
        target_identity: identity,
        path: dest.clone(),
        dir,
        name,
        temp_dir,
        expected: resume_size,
        overwrite,
        preserve,
        resumable,
        _reservation: reservation,
        _transfer: transfer,
        child,
        staged,
        activity: crate::task_registry::SessionActivity::new(UPLOAD_IDLE),
        target: target.clone(),
    };
    if let Err(mut session) = st.tasks.insert_session(
        token.clone(),
        "sftp_upload",
        &dest,
        resume_size.unwrap_or(0),
        session,
    ) {
        use crate::task_registry::SessionResource;
        session.cleanup(crate::task_registry::SessionCleanup::Aborted);
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Upload session is unavailable",
        );
    }
    axum::Json(json!({
        "code": 0,
        "message": "success",
        "data": { "upload_session": token, "path": dest, "received": staged },
    }))
    .into_response()
}

fn finish_sftp(target: &ssh::Target, mut session: UploadSession) -> Response {
    let staged = session.staged;
    let temp_dir = session.temp_dir.clone();
    let dest = paths::join_path(&session.dir, &session.name);
    if session.expected.is_some_and(|expected| expected != staged) {
        upload_kill(&mut session);
        let _ = crate::remote::run(
            target,
            &format!("rm -rf -- {}", shell_quote(&temp_dir)),
            Some(30),
        );
        return fail(StatusCode::BAD_REQUEST, "upload size does not match");
    }
    let overwrite = session.overwrite;
    let preserve = session.preserve;
    session.child.stdin.take();
    let (status, stderr) =
        wait_upload_child(&mut session.child, std::time::Duration::from_secs(120));
    if status.is_none_or(|status| status != 0) {
        let _ = crate::remote::run(
            target,
            &format!("rm -rf -- {}", shell_quote(&temp_dir)),
            Some(30),
        );
        let detail = String::from_utf8_lossy(&stderr).trim().to_string();
        return fail(
            StatusCode::BAD_GATEWAY,
            if detail.is_empty() {
                "Cannot finish the upload"
            } else {
                &detail
            },
        );
    }
    let temp_file = format!("{}/body", temp_dir.trim_end_matches('/'));
    if let Err(error) =
        ssh::sftp::commit_upload(target, &temp_file, &dest, staged, overwrite, preserve)
    {
        let message = error.message();
        if message.contains("size") {
            return fail(StatusCode::BAD_REQUEST, "upload size does not match");
        }
        if message.contains("already exists") {
            return fail(StatusCode::CONFLICT, "upload target already exists");
        }
        if matches!(error, ssh::sftp::SftpError::Unknown(_)) {
            return fail_unknown_commit(error, &temp_dir);
        }
        let _ = crate::remote::run(
            target,
            &format!("rm -rf -- {}", shell_quote(&temp_dir)),
            Some(30),
        );
        return fail_sftp(error);
    }
    let _ = crate::remote::run(
        target,
        &format!("rm -rf -- {}", shell_quote(&temp_dir)),
        Some(30),
    );
    axum::Json(json!({
        "code": 0,
        "message": "success",
        "data": { "path": dest, "uploaded_bytes": staged },
    }))
    .into_response()
}

#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
pub(crate) async fn upload_archive(
    st: &Arc<AppState>,
    target: Option<&ssh::Target>,
    params: &Params,
    headers: &axum::http::HeaderMap,
    req: axum::extract::Request,
    dir: &str,
) -> Response {
    use futures_util::StreamExt;
    let device_id = params.get("device_id").unwrap_or_default();
    let overwrite = params.get("overwrite").as_deref() == Some("1");
    let session_id = params.get("upload_session").unwrap_or_default();
    let finishing = params.get("finish").as_deref() == Some("1");
    let owner = st.session_id(headers);
    let identity = target.map(target_identity);

    if !session_id.is_empty() {
        match st
            .tasks
            .try_with_session::<ArchiveSession, _>(&session_id, |session| {
                session.device_id == device_id
                    && session.path == dir
                    && session.owner == owner
                    && session.target_identity == identity
            }) {
            Ok(true) => (),
            Err(crate::task_registry::SessionError::Busy) => {
                return fail(StatusCode::CONFLICT, "Upload session is busy")
            }
            _ => return fail(StatusCode::NOT_FOUND, "Upload session not found"),
        }
    }
    if !session_id.is_empty() && params.get("abort").as_deref() == Some("1") {
        let session = match st.tasks.take_session::<ArchiveSession>(&session_id, true) {
            Ok(session) => session,
            Err(crate::task_registry::SessionError::Busy) => {
                return fail(StatusCode::CONFLICT, "Upload session is busy")
            }
            Err(crate::task_registry::SessionError::Missing) => {
                return fail(StatusCode::NOT_FOUND, "Upload session not found")
            }
        };
        drop(session); // releases the spool, quota and slot
        return axum::Json(json!({ "code": 0, "message": "success", "data": {} })).into_response();
    }

    let check_st = st.clone();
    let check_target = target.cloned();
    let check_headers = headers.clone();
    let check_device = device_id.clone();
    let check_dir = dir.to_string();
    let resolved = match tokio::task::spawn_blocking(move || {
        checked_io_path(
            &check_st,
            check_target.as_ref(),
            &check_headers,
            &check_device,
            &check_dir,
        )
    })
    .await
    {
        Ok(Ok(path)) => path,
        Ok(Err(response)) => return response,
        Err(_) => return fail(StatusCode::BAD_GATEWAY, "Cannot validate upload path"),
    };
    if !session_id.is_empty() && finishing {
        let session = match st.tasks.take_session::<ArchiveSession>(&session_id, true) {
            Ok(session) => session,
            Err(crate::task_registry::SessionError::Busy) => {
                return fail(StatusCode::CONFLICT, "Upload session is busy")
            }
            Err(crate::task_registry::SessionError::Missing) => {
                return fail(StatusCode::NOT_FOUND, "Upload session not found")
            }
        };
        let st = Arc::clone(st);
        let target = target.cloned();
        let headers = headers.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            archive_finish(&st, target.as_ref(), &headers, session)
        })
        .await;
        return match outcome {
            Ok(Ok(received)) => axum::Json(json!({"code": 0, "message": "success", "data": {"path": dir, "uploaded_bytes": received}})).into_response(),
            Ok(Err(response)) => response,
            Err(_) => fail(StatusCode::INTERNAL_SERVER_ERROR, "Upload outcome is unknown; check the destination before retrying"),
        };
    }

    if !session_id.is_empty() {
        let mut request_guard = match st.tasks.acquire_session::<ArchiveSession>(&session_id) {
            Ok(guard) => guard,
            Err(crate::task_registry::SessionError::Busy) => {
                return fail(StatusCode::CONFLICT, "Upload session is busy")
            }
            Err(crate::task_registry::SessionError::Missing) => {
                return fail(StatusCode::NOT_FOUND, "Upload session not found")
            }
        };
        let mut stream = req.into_body().into_data_stream();
        let mut buffer: Vec<u8> = Vec::with_capacity(512 * 1024);
        let mut received_total: u64 = 0;
        loop {
            let next = match tokio::time::timeout(
                std::time::Duration::from_secs(st.settings.body_idle_timeout.max(1)),
                stream.next(),
            )
            .await
            {
                Ok(next) => next,
                Err(_) => return fail(StatusCode::REQUEST_TIMEOUT, "Upload request timed out"),
            };
            let chunk = match next {
                Some(Ok(chunk)) => chunk,
                Some(Err(_)) => {
                    archive_abort(&st.tasks, &session_id);
                    return fail(StatusCode::BAD_REQUEST, "invalid request body");
                }
                None => break,
            };
            received_total = received_total.saturating_add(chunk.len() as u64);
            if received_total > 16 * 1024 * 1024 {
                archive_abort(&st.tasks, &session_id);
                return fail(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
            }
            buffer.extend_from_slice(&chunk);
            if buffer.len() >= 256 * 1024 {
                if let Err((status, message)) = archive_append(&st.tasks, &session_id, &buffer) {
                    archive_abort(&st.tasks, &session_id);
                    return fail(status, &message);
                }
                buffer.clear();
            }
        }
        if !buffer.is_empty() {
            if let Err((status, message)) = archive_append(&st.tasks, &session_id, &buffer) {
                archive_abort(&st.tasks, &session_id);
                return fail(status, &message);
            }
        }
        if received_total == 0 {
            return fail(StatusCode::BAD_REQUEST, "empty upload chunk");
        }
        request_guard.finish();
        return axum::Json(json!({
            "code": 0,
            "message": "success",
            "data": { "received": received_total }
        }))
        .into_response();
    }

    let preserve = params.get("preserve_permissions").as_deref() != Some("0");
    let manifest = match axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await {
        Ok(bytes) if bytes.is_empty() => Value::Null,
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) if value.is_object() => value,
            _ => return fail(StatusCode::BAD_REQUEST, "Invalid upload manifest"),
        },
        Err(_) => return fail(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    let mut preserve_paths = Vec::new();
    if overwrite && preserve {
        if let Some(entries) = manifest.get("preserve_paths").and_then(Value::as_array) {
            if entries.len() > crate::api::archops::ARCHIVE_LIST_LIMIT {
                return fail(StatusCode::BAD_REQUEST, "Too many permissions to preserve");
            }
            for entry in entries {
                let Some(relative) = entry.as_str() else {
                    return fail(StatusCode::BAD_REQUEST, "invalid upload path");
                };
                if relative.starts_with('/')
                    || relative
                        .split('/')
                        .any(|part| !paths::valid_rename_name(part))
                {
                    return fail(StatusCode::BAD_REQUEST, "invalid upload path");
                }
                preserve_paths.push(relative.to_string());
            }
        }
    }
    let Some(slot) = ArchiveSlot::acquire() else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many active archive uploads",
        );
    };
    let Some(transfer) = st.limits.begin_transfer() else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many transfers in flight",
        );
    };
    let (spool_path, spool) = match create_archive_spool(st) {
        Ok(result) => result,
        Err(_) => {
            return fail(
                StatusCode::INSUFFICIENT_STORAGE,
                "Cannot stage the archive upload",
            )
        }
    };
    st.tasks.start_reaper();
    let new_id = crate::uci::random_hex(16);
    let session = ArchiveSession {
        device_id: device_id.clone(),
        owner,
        target_identity: identity,
        path: dir.to_string(),
        spool_path,
        spool: Some(spool),
        overwrite,
        preserve,
        preserve_paths,
        received: 0,
        _slot: slot,
        _transfer: transfer,
        activity: crate::task_registry::SessionActivity::new(ARCHIVE_IDLE),
    };
    if st
        .tasks
        .insert_session(new_id.clone(), "archive_upload", dir, 0, session)
        .is_err()
    {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Upload session is unavailable",
        );
    }
    axum::Json(json!({
        "code": 0,
        "message": "success",
        "data": { "upload_session": new_id, "path": resolved }
    }))
    .into_response()
}

// Publish only after the input stream and both SSH processes have succeeded.
// The temporary file lives in an exclusively-created private directory so it
// is never reopened through a predictable or shared pathname.
pub(crate) fn stream_remote_rewrite(
    target: &ssh::Target,
    src_path: String,
    output_path: String,
    stat: RemoteStat,
    plan: crate::ioops::ReplacePlan,
    progress: Option<crate::ioops::ReplaceProgress>,
    cancelled: Arc<AtomicBool>,
) -> Result<(u64, u64), RemoteError> {
    let parent = paths::parent_path(&output_path).unwrap_or_else(|| "/".to_string());
    let temp_dir_name = format!(".harbor-rewrite.{}", crate::uci::random_hex(16));
    let temp_dir = paths::join_path(&parent, &temp_dir_name);
    let temp_path = paths::join_path(&temp_dir, "body");
    if stat.mode.is_empty()
        || stat.mode.len() > 4
        || !stat.mode.bytes().all(|b| (b'0'..=b'7').contains(&b))
    {
        return Err("Cannot determine remote file permissions".into());
    }
    let read_script = format!("exec cat {}", shell_quote(&src_path));
    let source_check = src_path.clone();
    // Phase one only writes a uniquely created temporary file. It must NOT
    // publish until the input stream and both SSH commands have succeeded.
    let write_script = format!(
        r#"set -e
umask 077
cd {parent}
tempdir={tempdir}
mkdir -- "$tempdir" || exit 45
ready=0
trap '[ "$ready" = 1 ] || rm -rf -- "$tempdir"' EXIT
cat > "$tempdir/body"
chmod 0{mode} "$tempdir/body"
ready=1"#,
        parent = shell_quote(&parent),
        tempdir = shell_quote(&temp_dir_name),
        mode = stat.mode,
    );
    let commit_script = format!(
        "set -e\n[ -d {dir} ] && [ ! -L {dir} ] && [ -f {tmp} ] && [ ! -L {tmp} ] || exit 44\nmv -fT -- {tmp} {out}\nrmdir -- {dir} || :",
        dir = shell_quote(&temp_dir), tmp = shell_quote(&temp_path), out = shell_quote(&output_path),
    );
    let cleanup_script = format!("rm -rf -- {}", shell_quote(&temp_dir));
    let target = target.clone();
    {
        let result = (|| -> Result<(u64, u64), RemoteError> {
            if cancelled.load(Ordering::Relaxed) {
                return Err("rewrite cancelled".into());
            }
            let space = crate::remote::workspace_pub(&target)?;
            let mut reader = ssh::spawn_download(&target, &space, &read_script)?;
            let mut writer = match ssh::spawn_upload(&target, &space, &write_script) {
                Ok(writer) => writer,
                Err(error) => {
                    kill_upload_child(&mut reader);
                    let _ = reader.wait();
                    return Err(error.into());
                }
            };
            let pipes = (|| -> Result<_, String> {
                let stdout = reader
                    .stdout
                    .take()
                    .ok_or_else(|| "Cannot stream from the device".to_string())?;
                let stdin = writer
                    .stdin
                    .take()
                    .ok_or_else(|| "Cannot write to the device".to_string())?;
                Ok((
                    CancellablePipe::new(stdout, cancelled.clone()).map_err(|e| e.to_string())?,
                    CancellablePipe::new(stdin, cancelled.clone()).map_err(|e| e.to_string())?,
                ))
            })();
            let (mut stdout, mut stdin) = match pipes {
                Ok(pipes) => pipes,
                Err(error) => {
                    kill_upload_child(&mut reader);
                    kill_upload_child(&mut writer);
                    let _ = reader.wait();
                    let _ = writer.wait();
                    return Err(error.into());
                }
            };
            // Drain both children's diagnostics while streaming. The waiters
            // terminate them if the request is cancelled or the deadline hits.
            let read_flag = cancelled.clone();
            let write_flag = cancelled.clone();
            let read_wait = std::thread::spawn(move || {
                wait_upload_child_controlled(
                    &mut reader,
                    std::time::Duration::from_secs(3600),
                    Some(read_flag),
                )
            });
            let write_wait = std::thread::spawn(move || {
                wait_upload_child_controlled(
                    &mut writer,
                    std::time::Duration::from_secs(3600),
                    Some(write_flag),
                )
            });
            let total = stat.size;
            let report = |done: u64| {
                if let Some(progress) = &progress {
                    progress.update(done, total);
                }
            };
            let outcome =
                crate::ioops::replace_stream(&mut stdout, &mut stdin, &plan, total, &report);
            if outcome.is_err() {
                cancelled.store(true, Ordering::Relaxed);
            }
            drop(stdin);
            drop(stdout);
            let (read_status, read_detail) = read_wait.join().unwrap_or((None, Vec::new()));
            let (write_status, write_detail) = write_wait.join().unwrap_or((None, Vec::new()));
            let (replaced, written) = outcome?;
            if cancelled.load(Ordering::Relaxed) {
                return Err("rewrite cancelled".into());
            }
            if read_status.is_none_or(|status| status != 0) {
                let detail = String::from_utf8_lossy(&read_detail).trim().to_string();
                return Err(RemoteError::new(if detail.is_empty() {
                    "Cannot read the source".into()
                } else {
                    detail
                }));
            }
            if write_status.is_none_or(|status| status != 0) {
                let detail = String::from_utf8_lossy(&write_detail).trim().to_string();
                return Err(RemoteError::new(if detail.is_empty() {
                    "Cannot write to the target".into()
                } else {
                    detail
                }));
            }
            // Best-effort optimistic concurrency check; the final check and
            // remote rename cannot be made atomic over the shell protocol.
            if let Some(expected) = &stat.revision {
                let current = remote_stat(&target, &source_check)
                    .map_err(|_| "file changed during rewrite".to_string())?;
                if current.revision.as_ref() != Some(expected) {
                    return Err("file changed during rewrite".into());
                }
            }
            if cancelled.load(Ordering::Relaxed) {
                return Err("rewrite cancelled".into());
            }
            crate::remote::run_mutating_once(&target, &commit_script, Some(600)).map_err(
                |mut error| {
                    error.message = format!("Commit failed: {}", error.message);
                    error
                },
            )?;
            Ok((replaced, written))
        })();
        if result
            .as_ref()
            .err()
            .is_some_and(|error| error.data["outcome_unknown"] != json!(true))
        {
            let _ = crate::remote::run(&target, &cleanup_script, Some(30));
        }
        result
    }
}

// Cancel a child in its own SSH process group where possible. The getpgid
// check avoids signaling our server's process group for injected/test children.
fn kill_upload_child(child: &mut crate::ssh::ByteStream) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let _ = child.kill();
}

// A pipe read/write may block indefinitely when the SSH peer stops consuming.
// Nonblocking I/O plus a short poll allows the request cancellation to break
// that wait without relying on an external process killer.
struct CancellablePipe<T> {
    inner: T,
    cancelled: Arc<AtomicBool>,
}
impl<T: std::os::unix::io::AsRawFd> CancellablePipe<T> {
    fn new(inner: T, cancelled: Arc<AtomicBool>) -> std::io::Result<Self> {
        let fd = inner.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { inner, cancelled })
    }
    fn wait(&self, events: libc::c_short) -> std::io::Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("rewrite cancelled"));
        }
        let mut pfd = libc::pollfd {
            fd: self.inner.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pfd, 1, 100) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    }
}
impl<T: std::io::Read + std::os::unix::io::AsRawFd> std::io::Read for CancellablePipe<T> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(std::io::Error::other("rewrite cancelled"));
            }
            match self.inner.read(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLIN)?
                }
                result => return result,
            }
        }
    }
}
impl<T: std::io::Write + std::os::unix::io::AsRawFd> std::io::Write for CancellablePipe<T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        loop {
            if self.cancelled.load(Ordering::Relaxed) {
                return Err(std::io::Error::other("rewrite cancelled"));
            }
            match self.inner.write(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLOUT)?
                }
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn wait_upload_child(
    child: &mut crate::ssh::ByteStream,
    timeout: std::time::Duration,
) -> (Option<i32>, Vec<u8>) {
    wait_upload_child_controlled(child, timeout, None)
}

fn wait_upload_child_controlled(
    child: &mut crate::ssh::ByteStream,
    timeout: std::time::Duration,
    cancelled: Option<Arc<AtomicBool>>,
) -> (Option<i32>, Vec<u8>) {
    use std::io::Read;
    use std::os::unix::io::AsRawFd;
    fn make_nonblocking(pipe: &impl AsRawFd) -> bool {
        let fd = pipe.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0
    }
    fn drain(pipe: &mut impl Read, capture: &mut Vec<u8>, limit: usize) {
        let mut buf = [0u8; 8192];
        // Bound work per iteration, even if a child produces infinite output.
        for _ in 0..16 {
            match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let keep = n.min(limit.saturating_sub(capture.len()));
                    capture.extend_from_slice(&buf[..keep]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    }
    let mut stdout = child.stdout.take().filter(make_nonblocking);
    let mut stderr = child.stderr.take().filter(make_nonblocking);
    let mut captured = Vec::new();
    let started = std::time::Instant::now();
    loop {
        if let Some(pipe) = stdout.as_mut() {
            drain(pipe, &mut Vec::new(), 0);
        }
        if let Some(pipe) = stderr.as_mut() {
            drain(pipe, &mut captured, 64 * 1024);
        }
        if cancelled
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            kill_upload_child(child);
            let _ = child.wait();
            return (None, captured);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // Drain what is already available but never wait for EOF: a
                // descendant may retain the descriptor after the child exits.
                if let Some(pipe) = stderr.as_mut() {
                    drain(pipe, &mut captured, 64 * 1024);
                }
                return (Some(status), captured);
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            _ => {
                if let Some(flag) = cancelled.as_ref() {
                    flag.store(true, Ordering::Relaxed);
                }
                kill_upload_child(child);
                let _ = child.wait();
                return (None, captured);
            }
        }
    }
}

struct DirectUploadGuard {
    child: Option<crate::ssh::ByteStream>,
    target: ssh::Target,
    temp_dir: String,
    cleanup: bool,
    preserve: bool,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Drop for DirectUploadGuard {
    fn drop(&mut self) {
        let mut child = self.child.take();
        if let Some(child) = child.as_mut() {
            kill_upload_child(child);
        }
        if child.is_none() && !self.cleanup {
            return;
        }
        let target = self.target.clone();
        let temp_dir = self.temp_dir.clone();
        let cleanup = self.cleanup;
        let permit = self.permit.take();
        let _ = std::thread::Builder::new()
            .name("harbor-upload-cleanup".into())
            .spawn(move || {
                let _permit = permit;
                if let Some(mut child) = child {
                    let _ = child.wait();
                }
                if cleanup {
                    let _ = crate::remote::run(
                        &target,
                        &format!("rm -rf -- {}", shell_quote(&temp_dir)),
                        Some(30),
                    );
                }
            });
    }
}

fn finish_direct_upload(
    mut guard: DirectUploadGuard,
    destination: String,
    overwrite: bool,
    written: u64,
) -> Response {
    let Some(child) = guard.child.as_mut() else {
        return fail(StatusCode::BAD_GATEWAY, "Cannot finish the upload");
    };
    let (status, stderr) = wait_upload_child(child, std::time::Duration::from_secs(120));
    guard.child.take(); // already reaped
    if status.is_none_or(|status| status != 0) {
        let detail = String::from_utf8_lossy(&stderr).trim().to_string();
        if status == Some(45) || detail.contains("upload target already exists") {
            return fail(StatusCode::CONFLICT, "upload target already exists");
        }
        return fail(
            StatusCode::BAD_GATEWAY,
            if detail.is_empty() {
                "Remote command failed"
            } else {
                &detail
            },
        );
    }
    let temp_file = format!("{}/body", guard.temp_dir.trim_end_matches('/'));
    let preserve = guard.preserve;
    if let Err(error) = ssh::sftp::commit_upload(
        &guard.target,
        &temp_file,
        &destination,
        written,
        overwrite,
        preserve,
    ) {
        let message = error.message();
        if message.contains("size") {
            return fail(StatusCode::BAD_REQUEST, "upload size does not match");
        }
        if message.contains("already exists") {
            return fail(StatusCode::CONFLICT, "upload target already exists");
        }
        if matches!(error, ssh::sftp::SftpError::Unknown(_)) {
            guard.cleanup = false;
            return fail_unknown_commit(error, &guard.temp_dir);
        }
        return fail_sftp(error);
    }
    let _ = crate::remote::run(
        &guard.target,
        &format!("rm -rf -- {}", shell_quote(&guard.temp_dir)),
        Some(30),
    );
    guard.cleanup = false;
    axum::Json(
        json!({"code": 0, "message": "success", "data": {"path": destination, "size": written}}),
    )
    .into_response()
}

#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
pub(crate) async fn upload(
    st: &Arc<AppState>,
    target: &ssh::Target,
    params: &Params,
    headers: &axum::http::HeaderMap,
    req: axum::extract::Request,
    dir: &str,
) -> Response {
    use futures_util::StreamExt;
    let relative = params.get("relative_path").unwrap_or_default();
    let Some(destination) = paths::safe_join_relative(dir, &relative) else {
        return fail(StatusCode::BAD_REQUEST, "invalid upload path");
    };
    let device_id = params.get("device_id").unwrap_or_default();
    let directory = params.get("directory").as_deref() == Some("1");
    let check_st = st.clone();
    let check_target = target.clone();
    let check_headers = headers.clone();
    let check_device = device_id.clone();
    let check_paths = vec![dir.to_string(), destination.clone()];
    match tokio::task::spawn_blocking(move || {
        checked_io_paths(
            &check_st,
            Some(&check_target),
            &check_headers,
            &check_device,
            &check_paths,
        )
    })
    .await
    {
        Ok(Ok(_)) => (),
        Ok(Err(response)) => return response,
        Err(_) => return fail(StatusCode::BAD_GATEWAY, "Cannot validate upload path"),
    }
    if directory {
        let script = format!(
            "umask 022\nmkdir -p -m 755 -- {}",
            shell_quote(&destination)
        );
        let target = target.clone();
        let output = destination.clone();
        return match tokio::task::spawn_blocking(move || {
            crate::remote::run_mutating_once(&target, &script, Some(120))
        })
        .await
        {
            Ok(Ok(_)) => {
                axum::Json(json!({"code": 0, "message": "success", "data": {"path": output}}))
                    .into_response()
            }
            Ok(Err(error)) => fail_remote(StatusCode::BAD_GATEWAY, error),
            Err(_) => fail_remote(
                StatusCode::BAD_GATEWAY,
                RemoteError::with_data(
                    "Upload outcome is unknown; check the destination before retrying",
                    json!({"outcome_unknown":true}),
                ),
            ),
        };
    }
    let expected = match params.get("expected_size") {
        Some(value) => match value.parse::<u64>() {
            Ok(value) => Some(value),
            Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid upload size"),
        },
        None => None,
    };
    let overwrite = params.get("overwrite").as_deref() == Some("1");
    let preserve = params.get("preserve_permissions").as_deref() != Some("0");
    let parent = paths::parent_path(&destination).unwrap_or_else(|| "/".to_string());
    let temp_dir = paths::join_path(
        &parent,
        &format!(".harbor-upload-{}", crate::uci::random_hex(16)),
    );
    let slot = match st.limits.begin_transfer() {
        Some(slot) => slot,
        None => {
            return fail(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many transfers in flight",
            )
        }
    };
    let start_st = st.clone();
    let start_target = target.clone();
    let start_headers = headers.clone();
    let start_device = device_id;
    let start_temp = temp_dir.clone();
    let start_dest = destination.clone();
    let start = tokio::task::spawn_blocking(move || -> Result<DirectUploadGuard, Response> {
        // The blocking startup/cleanup worker owns the permit even if the
        // HTTP request is cancelled before this closure returns.
        let permit = slot;
        checked_io_path(
            &start_st,
            Some(&start_target),
            &start_headers,
            &start_device,
            &start_temp,
        )?;
        let name = crate::paths::path_name(&start_dest);
        if name.is_empty() || name == "/" {
            return Err(fail(StatusCode::BAD_REQUEST, "invalid upload path"));
        }
        let child = match ssh::sftp::spawn_upload_stream(
            &start_target,
            &parent,
            &name,
            &start_temp,
            overwrite,
            None,
        ) {
            Ok((child, _)) => child,
            Err(ssh::sftp::SftpError::Message(message)) if message.contains("already exists") => {
                return Err(fail(StatusCode::CONFLICT, "upload target already exists"));
            }
            Err(error) => return Err(fail_sftp(error)),
        };
        Ok(DirectUploadGuard {
            child: Some(child),
            target: start_target,
            temp_dir: start_temp,
            cleanup: true,
            preserve,
            permit: Some(permit),
        })
    })
    .await;
    let mut guard = match start {
        Ok(Ok(guard)) => guard,
        Ok(Err(response)) => return response,
        Err(_) => return fail(StatusCode::BAD_GATEWAY, "Cannot start the upload"),
    };
    let Some(mut stdin) = guard.child.as_mut().and_then(|child| child.stdin.take()) else {
        return fail(StatusCode::BAD_GATEWAY, "Cannot write to the device");
    };
    let mut stream = req.into_body().into_data_stream();
    let mut written = 0u64;
    let idle = std::time::Duration::from_secs(st.settings.body_idle_timeout.max(1));
    loop {
        let frame = match tokio::time::timeout(idle, stream.next()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(_))) => return fail(StatusCode::BAD_GATEWAY, "Cannot write to the device"),
            Ok(None) => break,
            Err(_) => return fail(StatusCode::REQUEST_TIMEOUT, "Upload request timed out"),
        };
        let Some(next) = written.checked_add(frame.len() as u64) else {
            return fail(StatusCode::BAD_REQUEST, "upload size does not match");
        };
        if expected.is_some_and(|expected| next > expected) {
            return fail(StatusCode::BAD_REQUEST, "upload size does not match");
        }
        let write = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            tokio::task::spawn_blocking(move || {
                let result = stdin.write_all(&frame);
                (stdin, result)
            }),
        )
        .await;
        match write {
            Ok(Ok((pipe, Ok(())))) => {
                stdin = pipe;
                written = next;
            }
            Ok(Ok((_, Err(_)))) => {
                return fail(StatusCode::BAD_GATEWAY, "Cannot write to the device")
            }
            _ => return fail(StatusCode::GATEWAY_TIMEOUT, "Cannot write to the device"),
        }
    }
    drop(stdin);
    if expected.is_some_and(|expected| expected != written) {
        return fail(StatusCode::BAD_REQUEST, "upload size does not match");
    }
    // Once all bytes are accepted, the blocking worker owns the guarded child
    // and publication. Dropping the HTTP future cannot replay or abandon it.
    match tokio::task::spawn_blocking(move || {
        finish_direct_upload(guard, destination, overwrite, written)
    })
    .await
    {
        Ok(response) => response,
        Err(_) => fail_remote(
            StatusCode::BAD_GATEWAY,
            RemoteError::with_data(
                "Upload outcome is unknown; check the destination before retrying",
                json!({"outcome_unknown":true}),
            ),
        ),
    }
}

// A bounded reader for the shared streaming search implementation. Fetching
// larger chunks amortizes SSH setup while avoiding whole-file buffering.
struct RemoteSearchReader {
    target: ssh::Target,
    path: String,
    offset: u64,
    end: u64,
    buffer: std::io::Cursor<Vec<u8>>,
    cancelled: Arc<AtomicBool>,
}

impl std::io::Read for RemoteSearchReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.buffer.position() >= self.buffer.get_ref().len() as u64 {
            if self.offset >= self.end {
                return Ok(0);
            }
            let amount = (self.end - self.offset).min(4 * 1024 * 1024);
            let start = self
                .offset
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("invalid offset"))?;
            let script = format!(
                "tail -c +{} {} | head -c {}",
                start,
                shell_quote(&self.path),
                amount
            );
            let raw = crate::remote::run_cancelled(
                &self.target,
                &script,
                Some(300),
                self.cancelled.clone(),
            )
            .map_err(|e| std::io::Error::other(e.message))?;
            if raw.len() as u64 != amount {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "remote file changed during search",
                ));
            }
            self.offset += amount;
            self.buffer = std::io::Cursor::new(raw);
        }
        std::io::Read::read(&mut self.buffer, output)
    }
}

pub(crate) fn search_reader(
    target: &ssh::Target,
    path: &str,
    start: u64,
    end: u64,
    cancelled: Arc<AtomicBool>,
) -> Box<dyn std::io::Read + Send> {
    Box::new(RemoteSearchReader {
        target: target.clone(),
        path: path.to_string(),
        offset: start,
        end,
        buffer: std::io::Cursor::new(Vec::new()),
        cancelled,
    })
}

#[cfg(test)]
// Fixture tests intentionally serialize shared environment/process state across awaits.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;

    fn into_stream(child: std::process::Child) -> ssh::ByteStream {
        ssh::ByteStream::from_child(child, true).unwrap()
    }

    async fn handle(
        st: &Arc<AppState>,
        mode: &str,
        path: &str,
        params: &Params,
        req: axum::extract::Request,
    ) -> Response {
        let mut params = params.clone();
        params.set("mode", mode);
        params.set("path", path);
        crate::ioops::handle(st.clone(), params, req).await
    }

    #[test]
    fn download_reaper_drains_noisy_stderr_without_blocking_stdout() {
        use std::io::Read;
        use std::process::{Command, Stdio};
        let mut child = Command::new("sh")
            .args(["-c", "head -c 1048576 /dev/zero >&2; printf ok"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let pid = child.id();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut owner = DownloadChildOwner(Some(into_stream(child)));
            let result = wait_download_child(owner.0.as_mut().unwrap(), &worker_stop);
            drop(owner);
            let _ = tx.send(result);
        });
        let result = rx.recv_timeout(std::time::Duration::from_secs(5));
        if result.is_err() {
            stop.store(true, Ordering::Release);
        }
        worker.join().unwrap();
        assert_eq!(result.expect("stderr drain stalled").unwrap(), 0);
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"ok");
        assert_eq!(
            unsafe { libc::kill(pid as i32, 0) },
            -1,
            "child was not reaped"
        );
    }

    fn test_tar(name: &str, entry_type: tar::EntryType, mode: u32, content: &[u8]) -> Vec<u8> {
        let mut header = tar::Header::new_ustar();
        header.set_size(content.len() as u64);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(entry_type);
        if entry_type == tar::EntryType::Symlink {
            header.set_link_name("../outside").unwrap();
        }
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        let mut tar = tar::Builder::new(Vec::new());
        tar.append(&header, content).unwrap();
        tar.into_inner().unwrap()
    }

    fn gzip_parts(raw: &[u8]) -> Vec<u8> {
        use std::process::{Command, Stdio};
        let mut result = Vec::new();
        // Browser archive uploads concatenate independently-compressed parts.
        for part in raw.chunks(1024) {
            let mut child = Command::new("gzip")
                .arg("-c")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(part).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            result.extend_from_slice(&output.stdout);
        }
        result
    }

    async fn response_json(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn archive_upload_stages_validates_authorizes_and_cleans_up() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root =
            std::env::temp_dir().join(format!("harbor-upload-check-{}", crate::uci::random_hex(8)));
        let dest = root.join("dest");
        let outside = root.join("outside");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let st = AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            root_policy: crate::state::RootPolicy::Allowlist,
            roots: vec![dest.to_string_lossy().into_owned()],
            ..Default::default()
        });
        async fn send(
            st: &Arc<AppState>,
            dir: &str,
            params: &Params,
            bytes: &[u8],
        ) -> (StatusCode, Value) {
            let request = axum::http::Request::builder()
                .method("POST")
                .body(Body::from(bytes.to_vec()))
                .unwrap();
            response_json(
                upload_archive(
                    st,
                    None,
                    params,
                    &axum::http::HeaderMap::new(),
                    request,
                    dir,
                )
                .await,
            )
            .await
        }
        async fn upload(
            st: &Arc<AppState>,
            dir: &str,
            tar: &[u8],
            overwrite: bool,
            preserve: &[&str],
        ) -> (StatusCode, Value) {
            let mut p = Params::default();
            if overwrite {
                p.set("overwrite", "1");
            }
            let manifest = json!({"preserve_paths": preserve}).to_string();
            let (status, init) = send(st, dir, &p, manifest.as_bytes()).await;
            assert_eq!(status, StatusCode::OK, "{init}");
            let id = init["data"]["upload_session"].as_str().unwrap();
            p.set("upload_session", id);
            let bytes = gzip_parts(tar);
            for chunk in bytes.chunks(200) {
                let (status, value) = send(st, dir, &p, chunk).await;
                assert_eq!(status, StatusCode::OK, "{value}");
            }
            p.set("finish", "1");
            send(st, dir, &p, b"").await
        }
        let dest_str = dest.to_str().unwrap();
        let (status, result) = upload(
            &st,
            dest_str,
            &test_tar("good.txt", tar::EntryType::Regular, 0o644, b"hello"),
            false,
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(std::fs::read(dest.join("good.txt")).unwrap(), b"hello");
        let (status, _) = upload(
            &st,
            dest_str,
            &test_tar("good.txt", tar::EntryType::Regular, 0o644, b"no"),
            false,
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(std::fs::read(dest.join("good.txt")).unwrap(), b"hello");
        std::fs::set_permissions(
            dest.join("good.txt"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let (status, value) = upload(
            &st,
            dest_str,
            &test_tar("good.txt", tar::EntryType::Regular, 0o644, b"new"),
            true,
            &["good.txt"],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(std::fs::read(dest.join("good.txt")).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(dest.join("good.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        for (name, kind, mode) in [
            ("../outside/pwn", tar::EntryType::Regular, 0o644),
            ("malicious", tar::EntryType::Symlink, 0o644),
            ("privileged", tar::EntryType::Regular, 0o4755),
        ] {
            let (status, _) =
                upload(&st, dest_str, &test_tar(name, kind, mode, b""), true, &[]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
        }
        symlink(&outside, dest.join("link")).unwrap();
        let (status, _) = upload(
            &st,
            dest_str,
            &test_tar("link/pwn", tar::EntryType::Regular, 0o644, b"bad"),
            true,
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!outside.join("pwn").exists());
        assert_eq!(
            std::fs::read_dir(root.join("state/archive-uploads"))
                .unwrap()
                .count(),
            0,
            "spool leaked"
        );
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    fn test_headers(st: &AppState, user: &str) -> axum::http::HeaderMap {
        let key = st.auth_key().unwrap();
        let (token, sid, expires) = crate::auth::make_session(&key, user, 600, "session");
        assert!(st.sessions.register(&sid, crate::meta::now_secs(), expires));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("{}={token}", crate::auth::COOKIE_NAME)
                .parse()
                .unwrap(),
        );
        headers
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn archive_upload_session_is_bound_to_auth_identity_and_target() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("harbor-owner-{}", crate::uci::random_hex(8)));
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let st = AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            ..Default::default()
        });
        let a = test_headers(&st, "alice");
        let b = test_headers(&st, "bob");
        let request = |bytes: Vec<u8>| {
            axum::http::Request::builder()
                .method("POST")
                .body(Body::from(bytes))
                .unwrap()
        };
        let mut params = Params::default();
        let (_, init) = response_json(
            upload_archive(
                &st,
                None,
                &params,
                &a,
                request(b"{}".to_vec()),
                dest.to_str().unwrap(),
            )
            .await,
        )
        .await;
        params.set(
            "upload_session",
            init["data"]["upload_session"].as_str().unwrap(),
        );
        let packed = gzip_parts(&test_tar(
            "owned.txt",
            tar::EntryType::Regular,
            0o644,
            b"owned",
        ));
        let response = upload_archive(
            &st,
            None,
            &params,
            &b,
            request(packed.clone()),
            dest.to_str().unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let mut other_dir = root.join("another").to_string_lossy().to_string();
        if other_dir == dest.to_string_lossy() {
            other_dir.push('x');
        }
        assert_eq!(
            upload_archive(&st, None, &params, &a, request(packed.clone()), &other_dir)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            upload_archive(
                &st,
                None,
                &params,
                &a,
                request(packed),
                dest.to_str().unwrap()
            )
            .await
            .status(),
            StatusCode::OK
        );
        params.set("finish", "1");
        let (status, body) = response_json(
            upload_archive(
                &st,
                None,
                &params,
                &a,
                request(vec![]),
                dest.to_str().unwrap(),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(std::fs::read(dest.join("owned.txt")).unwrap(), b"owned");
        assert_eq!(
            std::fs::read_dir(root.join("state/archive-uploads"))
                .unwrap()
                .count(),
            0
        );
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn archive_abort_reap_and_oversized_chunk_release_quota_and_slots() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("harbor-quota-{}", crate::uci::random_hex(8)));
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let st = AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            ..Default::default()
        });
        let headers = test_headers(&st, "alice");
        let base_bytes = ARCHIVE_STAGED_BYTES.load(Ordering::Acquire);
        let base_slots = ARCHIVE_ACTIVE.load(Ordering::Acquire);
        let request = |body| {
            axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap()
        };
        for cleanup in ["abort", "reap", "too-large"] {
            let (_, init) = response_json(
                upload_archive(
                    &st,
                    None,
                    &Params::default(),
                    &headers,
                    request(Body::from("{}")),
                    dest.to_str().unwrap(),
                )
                .await,
            )
            .await;
            let id = init["data"]["upload_session"].as_str().unwrap().to_string();
            let mut p = Params::default();
            p.set("upload_session", &id);
            assert_eq!(
                upload_archive(
                    &st,
                    None,
                    &p,
                    &headers,
                    request(Body::from("abc")),
                    dest.to_str().unwrap()
                )
                .await
                .status(),
                StatusCode::OK
            );
            assert_eq!(ARCHIVE_STAGED_BYTES.load(Ordering::Acquire), base_bytes + 3);
            match cleanup {
                "abort" => {
                    p.set("abort", "1");
                    assert_eq!(
                        upload_archive(
                            &st,
                            None,
                            &p,
                            &headers,
                            request(Body::empty()),
                            dest.to_str().unwrap()
                        )
                        .await
                        .status(),
                        StatusCode::OK
                    );
                }
                "reap" => {
                    st.tasks.with_session::<ArchiveSession, _>(&id, |session| {
                        session.activity.touched = std::time::Instant::now()
                            - ARCHIVE_IDLE
                            - std::time::Duration::from_secs(1)
                    });
                    st.tasks.reap_idle_sessions();
                }
                _ => {
                    assert_eq!(
                        upload_archive(
                            &st,
                            None,
                            &p,
                            &headers,
                            request(Body::from(vec![1u8; 16 * 1024 * 1024 + 1])),
                            dest.to_str().unwrap()
                        )
                        .await
                        .status(),
                        StatusCode::PAYLOAD_TOO_LARGE
                    );
                }
            }
            assert!(st.tasks.get(&id).is_none());
            assert_eq!(ARCHIVE_STAGED_BYTES.load(Ordering::Acquire), base_bytes);
            assert_eq!(ARCHIVE_ACTIVE.load(Ordering::Acquire), base_slots);
            assert_eq!(
                std::fs::read_dir(root.join("state/archive-uploads"))
                    .unwrap()
                    .count(),
                0
            );
        }
        // The cap includes finish operations still holding their slot.
        let slots: Vec<_> = (base_slots..64)
            .map(|_| ArchiveSlot::acquire().unwrap())
            .collect();
        assert!(ArchiveSlot::acquire().is_none());
        drop(slots);
        assert_eq!(ARCHIVE_ACTIVE.load(Ordering::Acquire), base_slots);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cancelled_rewrite_unblocks_stalled_os_pipes_and_reaps_children() {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        for writer in [false, true] {
            let flag = Arc::new(AtomicBool::new(false));
            let mut child = Command::new("sh")
                .arg("-c")
                .arg("exec sleep 15")
                .stdin(if writer {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let started = std::time::Instant::now();
            let cancel_flag = flag.clone();
            let cancel = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                cancel_flag.store(true, Ordering::Relaxed);
            });
            let result = if writer {
                let mut pipe =
                    CancellablePipe::new(child.stdin.take().unwrap(), flag.clone()).unwrap();
                pipe.write_all(&vec![0u8; 1024 * 1024])
            } else {
                let mut pipe =
                    CancellablePipe::new(child.stdout.take().unwrap(), flag.clone()).unwrap();
                pipe.read(&mut [0u8; 16]).map(|_| ())
            };
            assert!(result.is_err());
            let mut child = into_stream(child);
            let (status, _) = wait_upload_child_controlled(
                &mut child,
                std::time::Duration::from_secs(2),
                Some(flag),
            );
            assert!(status.is_none());
            cancel.join().unwrap();
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "stalled pipe was not cancelled promptly"
            );
        }
    }

    #[test]
    fn sftp_ready_frame_is_strict_and_bounded() {
        assert_eq!(parse_sftp_ready(b"READY 10\n", Some(10)), Some(10));
        assert_eq!(parse_sftp_ready(b"READY 0\n", None), Some(0));
        for frame in [
            &b"READY +1\n"[..],
            &b"READY -1\n"[..],
            &b"READY 1 \n"[..],
            &b"READY 1"[..],
            &b"noise READY 1\n"[..],
            &b"READY 18446744073709551616\n"[..],
            &b"READY \n"[..],
        ] {
            assert_eq!(parse_sftp_ready(frame, None), None, "{frame:?}");
        }
        assert_eq!(parse_sftp_ready(b"READY 11\n", Some(10)), None);
    }

    #[test]
    fn archive_byte_budget_is_overflow_safe() {
        let counter = AtomicU64::new(4);
        assert!(reserve_archive_bytes(&counter, 6, 10));
        assert!(!reserve_archive_bytes(&counter, 1, 10));
        assert_eq!(counter.load(Ordering::Acquire), 10);
        counter.store(u64::MAX, Ordering::Release);
        assert!(!reserve_archive_bytes(&counter, 1, u64::MAX));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn archive_upload_concurrency_and_idle_cleanup() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("harbor-busy-{}", crate::uci::random_hex(8)));
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let st = AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            body_idle_timeout: 1,
            ..Default::default()
        });
        let headers = test_headers(&st, "alice");
        let request = |body| {
            axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap()
        };
        let mut params = Params::default();
        let (_, init) = response_json(
            upload_archive(
                &st,
                None,
                &params,
                &headers,
                request(Body::from("{}")),
                dest.to_str().unwrap(),
            )
            .await,
        )
        .await;
        let id = init["data"]["upload_session"].as_str().unwrap().to_string();
        params.set("upload_session", &id);
        let guard = st.tasks.acquire_session::<ArchiveSession>(&id).unwrap();
        assert!(st.tasks.acquire_session::<ArchiveSession>(&id).is_err());
        let mut finish = params.clone();
        finish.set("finish", "1");
        assert_eq!(
            upload_archive(
                &st,
                None,
                &finish,
                &headers,
                request(Body::empty()),
                dest.to_str().unwrap()
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        drop(guard); // interrupted chunk invalidates the whole session
        assert!(st.tasks.get(&id).is_none());
        assert_eq!(
            std::fs::read_dir(root.join("state/archive-uploads"))
                .unwrap()
                .count(),
            0
        );
        let (_, init) = response_json(
            upload_archive(
                &st,
                None,
                &Params::default(),
                &headers,
                request(Body::from("{}")),
                dest.to_str().unwrap(),
            )
            .await,
        )
        .await;
        params.set(
            "upload_session",
            init["data"]["upload_session"].as_str().unwrap(),
        );
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        let response = upload_archive(
            &st,
            None,
            &params,
            &headers,
            request(Body::from_stream(pending)),
            dest.to_str().unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            std::fs::read_dir(root.join("state/archive-uploads"))
                .unwrap()
                .count(),
            0
        );
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn archive_upload_checks_every_member_before_writing() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root =
            std::env::temp_dir().join(format!("harbor-members-{}", crate::uci::random_hex(8)));
        let dest = root.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let st = AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            root_policy: crate::state::RootPolicy::Denylist,
            excluded_roots: vec![dest.join("blocked").to_string_lossy().into_owned()],
            ..Default::default()
        });
        let headers = test_headers(&st, "alice");
        let request = |body| {
            axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap()
        };
        let mut params = Params::default();
        params.set("overwrite", "1");
        let (_, init) = response_json(
            upload_archive(
                &st,
                None,
                &params,
                &headers,
                request(Body::from("{}")),
                dest.to_str().unwrap(),
            )
            .await,
        )
        .await;
        params.set(
            "upload_session",
            init["data"]["upload_session"].as_str().unwrap(),
        );
        let mut tar = tar::Builder::new(Vec::new());
        for name in ["safe", "blocked/secret"] {
            let mut header = tar::Header::new_ustar();
            header.set_path(name).unwrap();
            header.set_size(4);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, &b"test"[..]).unwrap();
        }
        let packed = gzip_parts(&tar.into_inner().unwrap());
        assert_eq!(
            upload_archive(
                &st,
                None,
                &params,
                &headers,
                request(Body::from(packed)),
                dest.to_str().unwrap()
            )
            .await
            .status(),
            StatusCode::OK
        );
        params.set("finish", "1");
        assert_eq!(
            upload_archive(
                &st,
                None,
                &params,
                &headers,
                request(Body::empty()),
                dest.to_str().unwrap()
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert!(!dest.join("safe").exists());
        assert!(!dest.join("blocked").exists());
        assert_eq!(
            std::fs::read_dir(root.join("state/archive-uploads"))
                .unwrap()
                .count(),
            0
        );
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn busybox_extracts_the_concatenated_gzip_upload_format() {
        use std::os::unix::fs::symlink;
        if std::process::Command::new("busybox")
            .arg("true")
            .status()
            .is_err()
        {
            return;
        }
        let root = upload_script_dir("busybox");
        let dest = root.join("dest");
        let bin = root.join("bin");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        symlink("/usr/bin/busybox", bin.join("tar")).unwrap();
        let packed = gzip_parts(&test_tar(
            "nested/你好.txt",
            tar::EntryType::Regular,
            0o644,
            b"browser-like",
        ));
        let script = format!(
            "PATH={}:$PATH; export PATH\n{}",
            shell_quote(bin.to_str().unwrap()),
            archive_script(dest.to_str().unwrap(), false, false, &[])
        );
        let (code, _, stderr) = run_upload_script(&script, &packed);
        assert_eq!(code, Some(0), "{}", String::from_utf8_lossy(&stderr));
        assert_eq!(
            std::fs::read(dest.join("nested/你好.txt")).unwrap(),
            b"browser-like"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_stage_operations_check_companion_path() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("harbor-stage-{}", crate::uci::random_hex(8)));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("file");
        let stage = root.join("file.harbor-stage");
        std::fs::write(&path, b"old").unwrap();
        std::fs::write(&stage, b"new").unwrap();
        let st = AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            root_policy: crate::state::RootPolicy::Denylist,
            excluded_roots: vec![stage.to_string_lossy().into_owned()],
            ..Default::default()
        });
        let call = |mode: &str, stage_flag: bool| {
            let mut params = Params::default();
            params.set("mode", mode);
            params.set("path", path.to_str().unwrap());
            if stage_flag {
                params.set("stage", "1");
                params.set("q", "old");
                params.set("r", "new");
            }
            let req = axum::http::Request::builder()
                .method("POST")
                .body(Body::empty())
                .unwrap();
            crate::ioops::handle(st.clone(), params, req)
        };
        for (mode, flag) in [
            ("stage_commit", false),
            ("stage_discard", false),
            ("replace_all", true),
        ] {
            assert_eq!(
                call(mode, flag).await.status(),
                StatusCode::FORBIDDEN,
                "{mode}"
            );
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        assert_eq!(std::fs::read(&stage).unwrap(), b"new");
        st.set_root_policy_config(crate::state::RootPolicyConfig {
            policy: crate::state::RootPolicy::Unrestricted,
            roots: vec![],
            excluded_roots: vec![],
        })
        .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(call("stage_commit", false).await.status(), StatusCode::OK);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        symlink(&path, &stage).unwrap();
        assert_eq!(
            call("stage_commit", false).await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(call("stage_discard", false).await.status(), StatusCode::OK);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn upload_child_wait_is_bounded_and_does_not_wait_for_inherited_pipes() {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("sleep 30 & printf 'diagnostic\\n' >&2; exit 3")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let spawned = command.spawn().unwrap();
        let group = spawned.id() as i32;
        let mut child = into_stream(spawned);
        let start = std::time::Instant::now();
        let (status, stderr) = wait_upload_child(&mut child, std::time::Duration::from_secs(2));
        // Test-only cleanup for the intentionally orphaned process group.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
        assert_eq!(status, Some(3));
        assert!(String::from_utf8_lossy(&stderr).contains("diagnostic"));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "inherited pipe must not keep a reader thread waiting"
        );

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exec sleep 30")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut child = into_stream(command.spawn().unwrap());
        let start = std::time::Instant::now();
        assert!(
            wait_upload_child(&mut child, std::time::Duration::from_millis(150))
                .0
                .is_none()
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn remote_stat_script_reports_missing_tool_explicitly() {
        let root =
            std::env::temp_dir().join(format!("harbor-empty-path-{}", crate::uci::random_hex(8)));
        std::fs::create_dir(&root).unwrap();
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(stat_script("/"))
            .env("PATH", &root)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(127));
        assert!(String::from_utf8_lossy(&output.stderr).contains("stat is required"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remote_stat_script_accepts_openwrt_gnu_stat() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("harbor-gnu-stat-{}", crate::uci::random_hex(8)));
        std::fs::create_dir(&root).unwrap();
        let gnu = root.join("gnu-stat");
        std::fs::write(&gnu, "#!/bin/sh\necho '4096 1 755 1 1 UTC 1 +0000'\n").unwrap();
        std::fs::set_permissions(&gnu, std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(stat_script("/"))
            .env("PATH", &root)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn e2e_remote_upload_commit_and_resume_are_safe() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-upload", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-upload-e2e-{}", crate::uci::random_hex(8));
        let file = format!("{root}/file.txt");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -p {root}; printf original > {file}; chmod 600 {file}",
                root = shell_quote(&root),
                file = shell_quote(&file)
            ),
            Some(30),
        )
        .unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let a = test_headers(&st, "alice");
        let b = test_headers(&st, "bob");
        let request = |headers: &axum::http::HeaderMap, body: Body| {
            let mut req = axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap();
            *req.headers_mut() = headers.clone();
            req
        };
        let read = || {
            crate::remote::run(&target, &format!("cat {}", shell_quote(&file)), Some(30)).unwrap()
        };
        let mut p = Params::default();
        p.set("device_id", &target.id);
        p.set("relative_path", "file.txt");
        p.set("overwrite", "1");
        p.set("expected_size", "9");
        let response = handle(
            &st,
            "api_upload",
            &root,
            &p,
            request(&a, Body::from("short")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(read(), b"original");
        p.set("expected_size", "3");
        let broken = futures_util::stream::iter(vec![
            Ok::<axum::body::Bytes, std::io::Error>(axum::body::Bytes::from_static(b"a")),
            Err(std::io::Error::other("connection lost")),
        ]);
        let response = handle(
            &st,
            "api_upload",
            &root,
            &p,
            request(&a, Body::from_stream(broken)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(read(), b"original");
        let response = handle(&st, "api_upload", &root, &p, request(&a, Body::from("new"))).await;
        let (status, value) = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(read(), b"new");
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("stat -c %a {}", shell_quote(&file)),
                Some(30)
            )
            .unwrap(),
            b"600\n"
        );
        p.set("overwrite", "0");
        assert_eq!(
            handle(&st, "api_upload", &root, &p, request(&a, Body::from("bad")))
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(read(), b"new");
        p.set("relative_path", "created");
        assert_eq!(
            handle(&st, "api_upload", &root, &p, request(&a, Body::from("yes")))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("cat {}/created", shell_quote(&root)),
                Some(30)
            )
            .unwrap(),
            b"yes"
        );

        let mut sftp = Params::default();
        sftp.set("device_id", &target.id);
        sftp.set("upload_size", "6");
        sftp.set("upload_mtime", "1234");
        sftp.set("overwrite", "1");
        let (status, initial) = response_json(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &sftp,
                request(&a, Body::empty()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{initial}");
        let id = initial["data"]["upload_session"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &sftp,
                request(&a, Body::empty())
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        sftp.set("upload_session", &id);
        assert_eq!(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &sftp,
                request(&b, Body::from("abc"))
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &sftp,
                request(&a, Body::from("abc"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        sftp.set("pause", "1");
        assert_eq!(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &sftp,
                request(&a, Body::empty())
            )
            .await
            .status(),
            StatusCode::OK
        );
        let mut resume = Params::default();
        resume.set("device_id", &target.id);
        resume.set("upload_size", "6");
        resume.set("upload_mtime", "1234");
        resume.set("overwrite", "1");
        let (status, resumed) = response_json(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &resume,
                request(&a, Body::empty()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resumed}");
        assert_eq!(resumed["data"]["received"], json!(3));
        resume.set(
            "upload_session",
            resumed["data"]["upload_session"].as_str().unwrap(),
        );
        assert_eq!(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &resume,
                request(&a, Body::from("def"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        resume.set("finish", "1");
        resume.set("overwrite", "0"); // original flags remain bound to session
        let (status, result) = response_json(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &resume,
                request(&a, Body::empty()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(read(), b"abcdef");
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("stat -c %a {}", shell_quote(&file)),
                Some(30)
            )
            .unwrap(),
            b"600\n"
        );
        let mut incomplete = Params::default();
        incomplete.set("device_id", &target.id);
        incomplete.set("upload_size", "4");
        incomplete.set("upload_mtime", "5678");
        incomplete.set("overwrite", "1");
        let (_, started) = response_json(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &incomplete,
                request(&a, Body::empty()),
            )
            .await,
        )
        .await;
        incomplete.set(
            "upload_session",
            started["data"]["upload_session"].as_str().unwrap(),
        );
        assert_eq!(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &incomplete,
                request(&a, Body::from("x"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        incomplete.set("finish", "1");
        assert_eq!(
            handle(
                &st,
                "api_upload_sftp",
                &file,
                &incomplete,
                request(&a, Body::empty())
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(read(), b"abcdef");
        let leftovers = crate::remote::run(
            &target,
            &format!(
                "find {} -name '.harbor-upload-*' -print",
                shell_quote(&root)
            ),
            Some(30),
        )
        .unwrap();
        assert!(leftovers.is_empty(), "upload temp leaked: {leftovers:?}");
        let _ = crate::remote::run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn e2e_sftp_abort_cancel_oversize_and_target_change() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-upload-errors", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-upload-failure-{}", crate::uci::random_hex(8));
        let path = format!("{root}/file.txt");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -p {}; printf original > {}",
                shell_quote(&root),
                shell_quote(&path)
            ),
            Some(30),
        )
        .unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let headers = test_headers(&st, "alice");
        let request = |body| {
            axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap()
        };
        let start = |mtime: &str| {
            let mut p = Params::default();
            p.set("upload_size", "2");
            p.set("upload_mtime", mtime);
            p.set("overwrite", "1");
            p
        };
        // Unchanged identity is required even if the device id is the same.
        let mut p = start("1");
        let (_, init) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &p,
                &headers,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        let id = init["data"]["upload_session"].as_str().unwrap().to_string();
        p.set("upload_session", &id);
        let mut changed = target.clone();
        changed.host_key.push_str(" changed");
        assert_eq!(
            upload_sftp(
                &st,
                Some(&changed),
                &path,
                &p,
                &headers,
                request(Body::from("a"))
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &p,
                &headers,
                request(Body::from("abc"))
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(st.tasks.get(&id).is_none());
        // Explicit abort deletes the private staging area, leaving the original.
        let mut p = start("2");
        let (_, init) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &p,
                &headers,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        let id = init["data"]["upload_session"].as_str().unwrap().to_string();
        p.set("upload_session", &id);
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &p,
                &headers,
                request(Body::from("a"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        p.set("abort", "1");
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &p,
                &headers,
                request(Body::empty())
            )
            .await
            .status(),
            StatusCode::OK
        );
        // A lost SSH child during staging must fail, remove the session, and
        // leave the destination unchanged rather than replaying a write.
        let mut disconnected = start("disconnect");
        let (_, init) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &disconnected,
                &headers,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        let lost_id = init["data"]["upload_session"].as_str().unwrap().to_string();
        disconnected.set("upload_session", &lost_id);
        {
            st.tasks
                .with_session::<UploadSession, _>(&lost_id, |session| {
                    session.child.kill().unwrap();
                    session.child.wait().unwrap();
                })
                .unwrap();
        }
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &disconnected,
                &headers,
                request(Body::from("a"))
            )
            .await
            .status(),
            StatusCode::BAD_GATEWAY
        );
        assert!(st.tasks.get(&lost_id).is_none());
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30)).unwrap(),
            b"original"
        );
        // A cancelled in-flight body must not be finished concurrently or reused.
        let mut p = start("3");
        let (_, init) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &p,
                &headers,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        let id = init["data"]["upload_session"].as_str().unwrap().to_string();
        p.set("upload_session", &id);
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        let st2 = st.clone();
        let target2 = target.clone();
        let path2 = path.clone();
        let p2 = p.clone();
        let headers2 = headers.clone();
        let task = tokio::spawn(async move {
            upload_sftp(
                &st2,
                Some(&target2),
                &path2,
                &p2,
                &headers2,
                request(Body::from_stream(pending)),
            )
            .await
        });
        for _ in 0..100 {
            if st
                .tasks
                .with_session::<UploadSession, _>(&id, |s| s.activity.busy)
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(st
            .tasks
            .with_session::<UploadSession, _>(&id, |s| s.activity.busy)
            .unwrap());
        let mut finish = p.clone();
        finish.set("finish", "1");
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &finish,
                &headers,
                request(Body::empty())
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        task.abort();
        let _ = task.await;
        for _ in 0..100 {
            if st.tasks.get(&id).is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(st.tasks.get(&id).is_none());
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30)).unwrap(),
            b"original"
        );
        // Wait for asynchronous abort cleanup to release its path reservation.
        for _ in 0..100 {
            if upload_reservations().lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
        assert!(upload_reservations().lock().unwrap().is_empty());
        let leftovers = crate::remote::run(
            &target,
            &format!(
                "find {} -name '.harbor-upload-*' -print",
                shell_quote(&root)
            ),
            Some(30),
        )
        .unwrap();
        assert!(leftovers.is_empty(), "upload temp leaked: {leftovers:?}");
        let _ = crate::remote::run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn e2e_sftp_unknown_commit_preserves_staging_and_never_replays() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-unknown", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-upload-unknown-{}", crate::uci::random_hex(8));
        let path = format!("{root}/file");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -p {}; printf original > {}",
                shell_quote(&root),
                shell_quote(&path)
            ),
            Some(30),
        )
        .unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let alice = test_headers(&st, "alice");
        let request = |body| {
            axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap()
        };
        let mut p = Params::default();
        p.set("upload_size", "3");
        p.set("upload_mtime", "44");
        p.set("overwrite", "1");
        let (_, started) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &p,
                &alice,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        let id = started["data"]["upload_session"]
            .as_str()
            .unwrap()
            .to_string();
        p.set("upload_session", &id);
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &p,
                &alice,
                request(Body::from("new"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        let session = st
            .tasks
            .replace_session::<UploadSession, SftpFinishReceipt>(
                &id,
                SftpFinishReceipt::from_upload,
            )
            .unwrap();
        let temp = session.temp_dir.clone();
        // Keep the real staging SSH connection but make the one-shot commit
        // connection fail, modeling an unknown transport result.
        let mut offline = target.clone();
        offline.port = 1;
        let registry = st.tasks.clone();
        let id2 = id.clone();
        let response = tokio::task::spawn_blocking(move || {
            let mut guard = SftpFinishGuard {
                registry,
                id: id2,
                recorded: false,
            };
            let result = finish_sftp(&offline, session);
            guard.record(SftpFinishOutcome::Unknown);
            result
        })
        .await
        .unwrap();
        let (status, value) = response_json(response).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(value["data"]["outcome_unknown"], true);
        assert_eq!(value["data"]["staging_path"], temp);
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30)).unwrap(),
            b"original"
        );
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("cat {}/body", shell_quote(&temp)),
                Some(30)
            )
            .unwrap(),
            b"new"
        );
        p.set("finish", "1");
        let (_, retry) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &p,
                &alice,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        assert_eq!(retry["data"]["outcome_unknown"], true);
        assert_eq!(retry["data"]["staging_path"], temp);
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30)).unwrap(),
            b"original"
        );
        let _ = crate::remote::run(&target, &format!("rm -rf {}", shell_quote(&root)), Some(30));
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn transfer_limit_is_shared_by_downloads_and_upload_sessions() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-quota", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-upload-slot-{}", crate::uci::random_hex(8));
        let path = format!("{root}/file");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -p {}; printf a > {}",
                shell_quote(&root),
                shell_quote(&path)
            ),
            Some(30),
        )
        .unwrap();
        let (seed, state_dir) = crate::ssh::e2e_state(&target, &root);
        let mut settings = seed.settings.clone();
        settings.max_transfers = 1;
        let st = AppState::new(settings);
        let alice = test_headers(&st, "alice");
        let request = |body| {
            axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap()
        };
        let slot = st.limits.begin_transfer().unwrap();
        let mut sftp = Params::default();
        sftp.set("upload_size", "1");
        sftp.set("upload_mtime", "1");
        sftp.set("overwrite", "1");
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &sftp,
                &alice,
                request(Body::empty())
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            upload_archive(
                &st,
                None,
                &Params::default(),
                &alice,
                request(Body::from("{}")),
                &root
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let mut params = Params::default();
        params.set("device_id", &target.id);
        params.set("relative_path", "file");
        params.set("overwrite", "1");
        let mut direct = request(Body::from("a"));
        *direct.headers_mut() = alice.clone();
        assert_eq!(
            handle(&st, "api_upload", &root, &params, direct)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let mut read = request(Body::empty());
        *read.headers_mut() = alice.clone();
        assert_eq!(
            handle(&st, "download", &path, &params, read).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(slot);
        let (_, started) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &sftp,
                &alice,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        let id = started["data"]["upload_session"].as_str().unwrap();
        sftp.set("upload_session", id);
        sftp.set("abort", "1");
        assert_eq!(st.limits.transfers.available_permits(), 0);
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &sftp,
                &alice,
                request(Body::empty())
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(st.limits.transfers.available_permits(), 1);
        let _ = crate::remote::run(&target, &format!("rm -rf {}", shell_quote(&root)), Some(30));
        drop(st);
        drop(seed);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_cancel_unblocks_real_ssh_backpressure() {
        use std::io::{Read, Write};
        let _serial = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-pipe-backpressure", 60).expect("HARBOR_E2E_SSH_PORT");
        let workspace = crate::remote::workspace_pub(&target).unwrap();
        let pidfile = format!("/tmp/harbor-backpressure-{}.pid", crate::uci::random_hex(8));
        let script = format!(
            "echo $$ > {}; printf READY; exec sleep 30",
            shell_quote(&pidfile)
        );
        let mut child = crate::ssh::spawn_upload(&target, &workspace, &script).unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut ready = [0u8; 5];
        stdout.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"READY");
        drop(stdout);
        let flag = Arc::new(AtomicBool::new(false));
        let cancel = flag.clone();
        let stdin = child.stdin.take().unwrap();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let mut pipe = CancellablePipe::new(stdin, cancel).unwrap();
            let result = pipe.write_all(&vec![b'x'; 32 * 1024 * 1024]);
            let _ = finished_tx.send(result.is_err());
        });
        let wait_flag = flag.clone();
        let waiter = std::thread::spawn(move || {
            wait_upload_child_controlled(
                &mut child,
                std::time::Duration::from_secs(30),
                Some(wait_flag),
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(
            finished_rx.try_recv().is_err(),
            "SSH writer never reached genuine backpressure"
        );
        let started = std::time::Instant::now();
        flag.store(true, Ordering::Release);
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            "stalled SSH write must fail on cancel"
        );
        writer.join().unwrap();
        let _ = waiter.join().unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        let _ = crate::remote::run(
            &target,
            &format!(
                "if [ -f {p} ]; then kill \"$(cat {p})\" 2>/dev/null || :; rm -f -- {p}; fi",
                p = shell_quote(&pidfile)
            ),
            Some(30),
        );
        let _ = std::fs::remove_dir_all(workspace.path());
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn e2e_sftp_receipt_replaces_session_during_authorized_requests() {
        let _serial = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-receipt-race", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-receipt-race-{}", crate::uci::random_hex(8));
        crate::remote::run(
            &target,
            &format!("mkdir -p -- {}", shell_quote(&root)),
            Some(30),
        )
        .unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let headers = test_headers(&st, "alice");
        let request = |body| {
            axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap()
        };
        for action in ["abort", "pause", "chunk", "finish"] {
            let path = format!("{root}/{action}");
            let mut params = Params::default();
            params.set("upload_size", "3");
            params.set("upload_mtime", "100");
            params.set("overwrite", "1");
            let (status, started) = response_json(
                upload_sftp(
                    &st,
                    Some(&target),
                    &path,
                    &params,
                    &headers,
                    request(Body::empty()),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{started}");
            let id = started["data"]["upload_session"]
                .as_str()
                .unwrap()
                .to_string();
            params.set("upload_session", &id);
            assert_eq!(
                upload_sftp(
                    &st,
                    Some(&target),
                    &path,
                    &params,
                    &headers,
                    request(Body::from("new"))
                )
                .await
                .status(),
                StatusCode::OK
            );
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            *SFTP_AUTH_RACE_HOOK.lock().unwrap() = Some((id.clone(), entered_tx, release_rx));
            let st2 = st.clone();
            let target2 = target.clone();
            let path2 = path.clone();
            let headers2 = headers.clone();
            let mut racing = params.clone();
            if action != "chunk" {
                racing.set(action, "1");
            }
            let pending = tokio::spawn(async move {
                upload_sftp(
                    &st2,
                    Some(&target2),
                    &path2,
                    &racing,
                    &headers2,
                    request(Body::empty()),
                )
                .await
            });
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            let mut finish = params.clone();
            finish.set("finish", "1");
            let (status, completed) = response_json(
                upload_sftp(
                    &st,
                    Some(&target),
                    &path,
                    &finish,
                    &headers,
                    request(Body::empty()),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{completed}");
            crate::remote::run(
                &target,
                &format!("printf external > {}", shell_quote(&path)),
                Some(30),
            )
            .unwrap();
            release_tx.send(()).unwrap();
            let response = tokio::time::timeout(std::time::Duration::from_secs(5), pending)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                response.status(),
                if action == "finish" {
                    StatusCode::OK
                } else {
                    StatusCode::CONFLICT
                },
                "{action} must see the receipt, not a missing session"
            );
            assert_eq!(
                crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30))
                    .unwrap(),
                b"external"
            );
        }
        let _ = crate::remote::run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn e2e_sftp_finish_survives_disconnected_http_and_reports_busy_and_receipt() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-finish", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-upload-finish-{}", crate::uci::random_hex(8));
        let path = format!("{root}/file.bin");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -p -- {}; printf old > {}",
                shell_quote(&root),
                shell_quote(&path)
            ),
            Some(30),
        )
        .unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let alice = test_headers(&st, "alice");
        let bob = test_headers(&st, "bob");
        let request = |body| {
            axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap()
        };
        let mut params = Params::default();
        params.set("upload_size", "3");
        params.set("upload_mtime", "12345");
        params.set("overwrite", "1");
        let (_, started) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &params,
                &alice,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        let id = started["data"]["upload_session"]
            .as_str()
            .unwrap()
            .to_string();
        params.set("upload_session", &id);
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &params,
                &alice,
                request(Body::from("new"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        let temp = st
            .tasks
            .with_session::<UploadSession, _>(&id, |s| s.temp_dir.clone())
            .unwrap();
        // Ensure the real SSH writer has staged the data before replacing it
        // by a slow child. The eventual publication itself is real SSH.
        for _ in 0..100 {
            let data = crate::remote::run(
                &target,
                &format!("cat {}/body", shell_quote(&temp)),
                Some(30),
            )
            .unwrap();
            if data == b"new" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("cat {}/body", shell_quote(&temp)),
                Some(30)
            )
            .unwrap(),
            b"new"
        );
        st.tasks
            .with_session::<UploadSession, _>(&id, |session| {
                upload_kill(session);
                session.child = into_stream(
                    std::process::Command::new("/bin/sh")
                        .arg("-c")
                        .arg("sleep 2; exit 0")
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .unwrap(),
                );
            })
            .unwrap();
        let st2 = st.clone();
        let target2 = target.clone();
        let path2 = path.clone();
        let alice2 = alice.clone();
        let mut finish = params.clone();
        finish.set("finish", "1");
        let finish2 = finish.clone();
        let worker = tokio::spawn(async move {
            upload_sftp(
                &st2,
                Some(&target2),
                &path2,
                &finish2,
                &alice2,
                request(Body::empty()),
            )
            .await
        });
        for _ in 0..200 {
            if matches!(
                st.tasks
                    .try_with_session::<SftpFinishReceipt, _>(&id, |r| r.outcome),
                Ok(SftpFinishOutcome::Running)
            ) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(matches!(
            st.tasks
                .try_with_session::<SftpFinishReceipt, _>(&id, |r| r.outcome),
            Ok(SftpFinishOutcome::Running)
        ));
        let mut abort = params.clone();
        abort.set("abort", "1");
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &abort,
                &alice,
                request(Body::empty())
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &finish,
                &alice,
                request(Body::empty())
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &finish,
                &bob,
                request(Body::empty())
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        worker.abort();
        let _ = worker.await;
        for _ in 0..400 {
            if matches!(
                st.tasks
                    .try_with_session::<SftpFinishReceipt, _>(&id, |r| r.outcome),
                Ok(SftpFinishOutcome::Completed)
            ) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let (status, receipt) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &finish,
                &alice,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(receipt["data"]["done"], true);
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30)).unwrap(),
            b"new"
        );
        crate::remote::run(
            &target,
            &format!("printf external > {}", shell_quote(&path)),
            Some(30),
        )
        .unwrap();
        assert_eq!(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &finish,
                &alice,
                request(Body::empty())
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30)).unwrap(),
            b"external"
        );
        assert!(upload_reservations().lock().unwrap().is_empty());
        st.tasks.with_session::<SftpFinishReceipt, _>(&id, |r| {
            r.activity.touched =
                std::time::Instant::now() - UPLOAD_IDLE - std::time::Duration::from_secs(1)
        });
        st.tasks.reap_idle_sessions();
        assert!(st.tasks.get(&id).is_none());
        let _ = crate::remote::run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn e2e_direct_upload_idle_cancel_and_disconnected_finish_hold_transfer_slot() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-direct-idle", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-direct-idle-{}", crate::uci::random_hex(8));
        let path = format!("{root}/file");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -p -- {}; printf original > {}",
                shell_quote(&root),
                shell_quote(&path)
            ),
            Some(30),
        )
        .unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let alice = test_headers(&st, "alice");
        let mut params = Params::default();
        params.set("device_id", &target.id);
        params.set("relative_path", "file");
        params.set("expected_size", "3");
        params.set("overwrite", "1");
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        // The fixture default is 30s; create a second state with the same
        // config and auth data but a one-second body idle timeout.
        let mut settings = st.settings.clone();
        settings.body_idle_timeout = 1;
        let idle_st = AppState::new(settings);
        let idle_headers = test_headers(&idle_st, "alice");
        let make = |headers: &axum::http::HeaderMap, body| {
            let mut r = axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap();
            *r.headers_mut() = headers.clone();
            r
        };
        let response = handle(
            &idle_st,
            "api_upload",
            &root,
            &params,
            make(&idle_headers, Body::from_stream(pending)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30)).unwrap(),
            b"original"
        );
        // A client disconnect during streaming must terminate the child and
        // eventually release its permit and private temporary directory.
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        let st2 = idle_st.clone();
        let params2 = params.clone();
        let root2 = root.clone();
        let headers2 = idle_headers.clone();
        let task = tokio::spawn(async move {
            handle(
                &st2,
                "api_upload",
                &root2,
                &params2,
                make(&headers2, Body::from_stream(pending)),
            )
            .await
        });
        for _ in 0..200 {
            if idle_st.limits.transfers.available_permits() < idle_st.settings.max_transfers {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        task.abort();
        let _ = task.await;
        for _ in 0..400 {
            if idle_st.limits.transfers.available_permits() == idle_st.settings.max_transfers {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            idle_st.limits.transfers.available_permits(),
            idle_st.settings.max_transfers
        );
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30)).unwrap(),
            b"original"
        );
        // Simulate an HTTP future disappearing after all bytes were staged. The
        // real remote commit continues, and its permit stays with the worker.
        let temp = format!("{root}/.harbor-upload-finish-test");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -m700 {}; printf new > {}/body",
                shell_quote(&temp),
                shell_quote(&temp)
            ),
            Some(30),
        )
        .unwrap();
        let child = into_stream(
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg("sleep 2; exit 0")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let permit = idle_st.limits.begin_transfer().unwrap();
        let guard = DirectUploadGuard {
            child: Some(child),
            target: target.clone(),
            temp_dir: temp,
            cleanup: true,
            preserve: true,
            permit: Some(permit),
        };
        let path2 = path.clone();
        let finish = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || finish_direct_upload(guard, path2, true, 3)).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        finish.abort();
        let _ = finish.await;
        assert_eq!(
            idle_st.limits.transfers.available_permits(),
            idle_st.settings.max_transfers - 1
        );
        for _ in 0..400 {
            if idle_st.limits.transfers.available_permits() == idle_st.settings.max_transfers {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            idle_st.limits.transfers.available_permits(),
            idle_st.settings.max_transfers
        );
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&path)), Some(30)).unwrap(),
            b"new"
        );
        let leftovers = crate::remote::run(
            &target,
            &format!(
                "find {} -name '.harbor-upload-*' -print",
                shell_quote(&root)
            ),
            Some(30),
        )
        .unwrap();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = crate::remote::run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
        drop(idle_st);
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
        let _ = alice;
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn e2e_sftp_slow_writer_keeps_other_requests_responsive_and_abort_honest() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-slow-upload", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-upload-slow-{}", crate::uci::random_hex(8));
        let path = format!("{root}/file.bin");
        crate::remote::run(
            &target,
            &format!("mkdir -p -- {}", shell_quote(&root)),
            Some(30),
        )
        .unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let headers = test_headers(&st, "alice");
        let request = |body| {
            axum::http::Request::builder()
                .method("POST")
                .body(body)
                .unwrap()
        };
        let mut params = Params::default();
        params.set("upload_size", "4194304");
        params.set("upload_mtime", "97531");
        params.set("overwrite", "1");
        let (status, init) = response_json(
            upload_sftp(
                &st,
                Some(&target),
                &path,
                &params,
                &headers,
                request(Body::empty()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{init}");
        let id = init["data"]["upload_session"].as_str().unwrap().to_string();
        params.set("upload_session", &id);
        // Replace SSH stdin with an intentionally undrained pipe. Cleanup
        // must still acquire the session and kill this child when interrupted.
        st.tasks
            .with_session::<UploadSession, _>(&id, |session| {
                upload_kill(session);
                let child = into_stream(
                    std::process::Command::new("/bin/sh")
                        .arg("-c")
                        .arg("exec sleep 20")
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .unwrap(),
                );
                session.child = child;
            })
            .unwrap();
        let st2 = st.clone();
        let target2 = target.clone();
        let path2 = path.clone();
        let params2 = params.clone();
        let headers2 = headers.clone();
        let writer = tokio::spawn(async move {
            upload_sftp(
                &st2,
                Some(&target2),
                &path2,
                &params2,
                &headers2,
                request(Body::from(vec![b'x'; 4 * 1024 * 1024])),
            )
            .await
        });
        let mut locked = false;
        for _ in 0..200 {
            if st
                .tasks
                .try_with_session::<UploadSession, _>(&id, |s| {
                    s.activity.busy && s.child.stdin.is_none()
                })
                .unwrap_or(false)
            {
                locked = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(locked, "writer must reach the blocked SSH stdin");
        let started = std::time::Instant::now();
        for action in ["abort", "pause", "finish"] {
            let mut concurrent = params.clone();
            concurrent.set(action, "1");
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                upload_sftp(
                    &st,
                    Some(&target),
                    &path,
                    &concurrent,
                    &headers,
                    request(Body::empty()),
                ),
            )
            .await
            .expect("busy request blocked Tokio");
            assert_eq!(
                result.status(),
                StatusCode::CONFLICT,
                "{action} must not claim to stop an active write"
            );
        }
        let unrelated = st.tasks.create("download", "/unrelated", 1);
        assert!(st.tasks.active() >= 1);
        unrelated.set_status(crate::task_registry::Status::Completed);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        writer.abort();
        let _ = writer.await;
        for _ in 0..200 {
            if st.tasks.get(&id).is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(st.tasks.get(&id).is_none(), "abandoned write must clean up");
        for _ in 0..200 {
            if upload_reservations().lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            upload_reservations().lock().unwrap().is_empty(),
            "cleanup must terminate the blocked child without external help"
        );
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("test ! -e {}", shell_quote(&path)),
                Some(30)
            )
            .unwrap(),
            b""
        );
        let _ = crate::remote::run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    fn run_upload_script(script: &str, stdin: &[u8]) -> (Option<i32>, String, Vec<u8>) {
        use std::io::Write;
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            output.stderr,
        )
    }

    fn upload_script_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "harbor-script-{}-{}",
            tag,
            crate::uci::random_hex(6)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn e2e_remote_io_contract_policy_and_safe_rewrite() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-io", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-io-e2e-{}", crate::uci::random_hex(8));
        let file = format!("{root}/a';touch INJECTED;#");
        let stage = format!("{file}.harbor-stage");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -p {root}; printf abcdefabc > {file}; chmod 600 {file}",
                root = shell_quote(&root),
                file = shell_quote(&file)
            ),
            Some(30),
        )
        .unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let common = || {
            let mut p = Params::default();
            p.set("device_id", &target.id);
            p
        };
        async fn call(
            st: &Arc<AppState>,
            mode: &str,
            path: &str,
            p: &Params,
            body: &[u8],
        ) -> Response {
            let req = axum::http::Request::builder()
                .method("POST")
                .body(Body::from(body.to_vec()))
                .unwrap();
            handle(st, mode, path, p, req).await
        }
        async fn data(response: Response) -> Value {
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 32 * 1024 * 1024)
                .await
                .unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert!(
                status.is_success() && value["code"] == 0,
                "{status}: {value}"
            );
            value["data"].clone()
        }
        let mut p = common();
        p.set("q", "abc");
        let result = data(call(&st, "search", &file, &p, b"").await).await;
        assert_eq!(result["matches"], json!([0, 6]));
        p = common();
        p.set("offset", "2");
        p.set("length", "4");
        let slice = call(&st, "slice", &file, &p, b"").await;
        assert_eq!(slice.status(), StatusCode::OK);
        assert_eq!(
            &axum::body::to_bytes(slice.into_body(), 100).await.unwrap()[..],
            b"cdef"
        );
        p = common();
        p.set("offset", "2");
        p.set("expected_size", "99");
        assert_eq!(
            call(&st, "patch", &file, &p, b"X").await.status(),
            StatusCode::CONFLICT
        );
        p.set("expected_size", "9");
        assert_eq!(
            data(call(&st, "patch", &file, &p, b"X").await).await["written"],
            json!(1)
        );
        p.set("offset", &u64::MAX.to_string());
        assert_eq!(
            call(&st, "patch", &file, &p, b"X").await.status(),
            StatusCode::BAD_REQUEST
        );
        p = common();
        p.set("start", "2");
        p.set("end", "5");
        p.set("expected_size", "9");
        let result = data(call(&st, "splice", &file, &p, b"XYZ").await).await;
        assert_eq!(result["removed"], json!(3));
        assert_eq!(result["inserted"], json!(3));
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&file)), Some(30)).unwrap(),
            b"abXYZfabc"
        );
        assert!(crate::remote::run(
            &target,
            &format!("test ! -e {}/INJECTED", shell_quote(&root)),
            Some(30)
        )
        .is_ok());
        p = common();
        p.set("q", "abc");
        p.set("r", "J");
        p.set("stage", "1");
        let result = data(call(&st, "replace_all", &file, &p, b"").await).await;
        assert_eq!(result["replaced"], json!(1));
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("stat -c %a {}", shell_quote(&stage)),
                Some(30)
            )
            .unwrap(),
            b"600\n"
        );
        data(call(&st, "stage_commit", &file, &common(), b"").await).await;
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&file)), Some(30)).unwrap(),
            b"abXYZfJ"
        );
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("stat -c %a {}", shell_quote(&file)),
                Some(30)
            )
            .unwrap(),
            b"600\n"
        );
        crate::remote::run(
            &target,
            &format!(
                "ln -s {file} {stage}",
                file = shell_quote(&file),
                stage = shell_quote(&stage)
            ),
            Some(30),
        )
        .unwrap();
        assert_eq!(
            call(&st, "stage_commit", &file, &common(), b"")
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        data(call(&st, "stage_discard", &file, &common(), b"").await).await;
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&file)), Some(30)).unwrap(),
            b"abXYZfJ"
        );
        let mut short_stat = remote_stat(&target, &file).unwrap();
        short_stat.size += 3;
        let plan = crate::ioops::ReplacePlan {
            needle: Vec::new(),
            repl: b"z".to_vec(),
            icase: false,
            regex: None,
            range: Some((1, 1)),
        };
        assert!(stream_remote_rewrite(
            &target,
            file.clone(),
            file.clone(),
            short_stat,
            plan,
            None,
            Arc::new(AtomicBool::new(false))
        )
        .is_err());
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&file)), Some(30)).unwrap(),
            b"abXYZfJ"
        );
        let leftovers = crate::remote::run(
            &target,
            &format!(
                "find {} -name '.harbor-rewrite.*' -print",
                shell_quote(&root)
            ),
            Some(30),
        )
        .unwrap();
        assert!(
            leftovers.is_empty(),
            "temporary rewrite leaked: {leftovers:?}"
        );
        // Exercise the archive-upload protocol through the real SSH executor.
        let mut upload_params = common();
        let (_, init) =
            response_json(call(&st, "api_upload_archive", &root, &upload_params, br#"{}"#).await)
                .await;
        let upload_id = init["data"]["upload_session"].as_str().unwrap();
        upload_params.set("upload_session", upload_id);
        // Changing any SSH target identity cannot attach to an existing session.
        for changed in [
            {
                let mut t = target.clone();
                t.id.push('x');
                t
            },
            {
                let mut t = target.clone();
                t.host.push('x');
                t
            },
            {
                let mut t = target.clone();
                t.port = t.port.wrapping_add(1);
                t
            },
            {
                let mut t = target.clone();
                t.username.push('x');
                t
            },
            {
                let mut t = target.clone();
                t.host_key.push('x');
                t
            },
        ] {
            let request = axum::http::Request::builder()
                .method("POST")
                .body(Body::from("bad"))
                .unwrap();
            assert_eq!(
                upload_archive(
                    &st,
                    Some(&changed),
                    &upload_params,
                    &axum::http::HeaderMap::new(),
                    request,
                    &root
                )
                .await
                .status(),
                StatusCode::NOT_FOUND
            );
        }
        let packed = gzip_parts(&test_tar(
            "uploaded/safe.txt",
            tar::EntryType::Regular,
            0o644,
            b"safe over ssh",
        ));
        data(call(&st, "api_upload_archive", &root, &upload_params, &packed).await).await;
        upload_params.set("finish", "1");
        data(call(&st, "api_upload_archive", &root, &upload_params, b"").await).await;
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("cat {}", shell_quote(&format!("{root}/uploaded/safe.txt"))),
                Some(30)
            )
            .unwrap(),
            b"safe over ssh"
        );
        assert_eq!(
            std::fs::read_dir(state_dir.join("state/archive-uploads"))
                .unwrap()
                .count(),
            0
        );
        crate::remote::run(
            &target,
            &format!("ln -s /etc {}/escape", shell_quote(&root)),
            Some(30),
        )
        .unwrap();
        let mut upload_params = common();
        upload_params.set("overwrite", "1");
        let (_, init) =
            response_json(call(&st, "api_upload_archive", &root, &upload_params, br#"{}"#).await)
                .await;
        upload_params.set(
            "upload_session",
            init["data"]["upload_session"].as_str().unwrap(),
        );
        let packed = gzip_parts(&test_tar(
            "escape/harbor-test",
            tar::EntryType::Regular,
            0o644,
            b"blocked",
        ));
        data(call(&st, "api_upload_archive", &root, &upload_params, &packed).await).await;
        upload_params.set("finish", "1");
        assert_eq!(
            call(&st, "api_upload_archive", &root, &upload_params, b"")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            std::fs::read_dir(state_dir.join("state/archive-uploads"))
                .unwrap()
                .count(),
            0
        );
        p = common();
        assert_eq!(
            call(&st, "slice", &format!("{root}/escape/passwd"), &p, b"")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&st, "api_upload_sftp", "/etc/harbor-test", &p, b"")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        // A stale same-size source is rejected before publication.
        let stale = remote_stat(&target, &file).unwrap();
        crate::remote::run(
            &target,
            &format!("printf 1234567 > {}", shell_quote(&file)),
            Some(30),
        )
        .unwrap();
        let plan = crate::ioops::ReplacePlan {
            needle: Vec::new(),
            repl: b"Z".to_vec(),
            icase: false,
            regex: None,
            range: Some((1, 1)),
        };
        let error = stream_remote_rewrite(
            &target,
            file.clone(),
            file.clone(),
            stale,
            plan,
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap_err();
        assert!(error.message.contains("changed"), "{error:?}");
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&file)), Some(30)).unwrap(),
            b"1234567"
        );
        // Both the logical file and its companion must satisfy root policy.
        crate::remote::run(
            &target,
            &format!("printf staged > {}", shell_quote(&stage)),
            Some(30),
        )
        .unwrap();
        st.set_root_policy_config(crate::state::RootPolicyConfig {
            policy: crate::state::RootPolicy::Denylist,
            roots: vec![],
            excluded_roots: vec![stage.clone()],
        })
        .unwrap();
        for mode in ["stage_commit", "stage_discard"] {
            assert_eq!(
                call(&st, mode, &file, &common(), b"").await.status(),
                StatusCode::FORBIDDEN,
                "{mode}"
            );
        }
        let mut denied = common();
        denied.set("stage", "1");
        denied.set("q", "1");
        denied.set("r", "2");
        assert_eq!(
            call(&st, "replace_all", &file, &denied, b"").await.status(),
            StatusCode::FORBIDDEN
        );
        st.set_root_policy_config(crate::state::RootPolicyConfig {
            policy: crate::state::RootPolicy::Allowlist,
            roots: vec![root.clone()],
            excluded_roots: vec![],
        })
        .unwrap();
        crate::remote::run(&target, &format!("rm -- {}", shell_quote(&file)), Some(30)).unwrap();
        data(call(&st, "stage_commit", &file, &common(), b"").await).await;
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&file)), Some(30)).unwrap(),
            b"staged"
        );
        let newline_path = format!("{root}/trailing\n");
        crate::remote::run(
            &target,
            &format!("mkdir -- {}", shell_quote(&newline_path)),
            Some(30),
        )
        .unwrap();
        let resolved = crate::remote::resolve_policy_paths(
            Some(&target),
            &[format!("{newline_path}/missing")],
        )
        .unwrap();
        assert_eq!(resolved[0], format!("{newline_path}/missing"));
        let _ = crate::remote::run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        );
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[test]
    fn remote_upload_target_keeps_paths_beneath_the_selected_directory() {
        assert_eq!(
            paths::safe_join_relative("/mnt/data", "folder/file.txt"),
            Some("/mnt/data/folder/file.txt".to_string())
        );
        assert_eq!(paths::safe_join_relative("/mnt/data", "../escape"), None);
        assert_eq!(
            paths::safe_join_relative("/mnt/data", "folder/../escape"),
            Some("/mnt/data/escape".to_string())
        );
    }

    #[test]
    fn stat_script_quotes_the_path() {
        let script = stat_script("/etc/it's here");
        assert!(script.contains("'/etc/it'\\''s here'"));
    }
}
