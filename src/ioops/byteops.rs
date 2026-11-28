//! A single /io protocol dispatcher with local and SSH byte executors.
//!
//! Parsing, validation, response shapes and search/rewrite plans live here;
//! executors only perform the filesystem operations that differ. SSH writes
//! are deliberately not retried after a side effect may have occurred.

use super::*;
use crate::remote::{shell_quote, RemoteError};
use crate::ssh::Target;

#[derive(Clone)]
enum Snapshot {
    Local(meta::Meta),
    Remote(crate::remoteio::RemoteStat),
}

#[derive(Clone)]
struct FileInfo {
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    is_file: bool,
    is_symlink: bool,
    snapshot: Snapshot,
}

struct OperationError {
    status: StatusCode,
    code: i64,
    message: String,
    data: Value,
}

impl OperationError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code: 1,
            message: message.into(),
            data: Value::Null,
        }
    }
    fn remote(status: StatusCode, error: RemoteError) -> Self {
        Self {
            status,
            code: error.code,
            message: error.message,
            data: error.data,
        }
    }
    fn response(self) -> Response {
        reply_status(
            self.status,
            json!({"code": self.code, "message": self.message, "data": self.data}),
        )
    }
}

type OpResult<T> = Result<T, OperationError>;

// All methods below are blocking; the dispatcher runs them in the Tokio
// blocking pool. This avoids blocking an async worker on a slow SSH device.
trait ByteOps: Clone + Send + Sync + 'static {
    fn device_id(&self) -> &str;
    fn target(&self) -> Option<&Target>;
    fn stat(&self, path: &str) -> OpResult<FileInfo>;
    fn read_at(&self, path: &str, offset: u64, length: u64) -> OpResult<Vec<u8>>;
    fn write_at(&self, path: &str, offset: u64, data: &[u8], before: &FileInfo) -> OpResult<u64>;
    fn span_read(
        &self,
        path: &str,
        plan: &SearchPlan,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Box<dyn Read + Send>, String>;
    fn splice_rewrite(
        &self,
        source: String,
        destination: String,
        before: FileInfo,
        plan: ReplacePlan,
        progress: Option<ReplaceProgress>,
        cancelled: Arc<AtomicBool>,
    ) -> OpResult<(u64, u64)>;
    fn sha256(&self, path: &str, before: &FileInfo) -> OpResult<(String, FileInfo)>;
    fn thumbnail(
        &self,
        st: &AppState,
        path: &str,
        before: &FileInfo,
    ) -> Option<(String, u64, i64, i64)>;
    fn stage(&self, path: &str, commit: bool) -> OpResult<()>;
    fn source<'a>(&'a self, path: &'a str) -> Source<'a>;
    fn rewrite_limit(&self) -> Option<u64> {
        None
    }
}

#[derive(Clone)]
struct LocalByteOps;

#[derive(Clone)]
struct RemoteByteOps {
    target: Target,
}

fn local_info(path: &str) -> Option<FileInfo> {
    let stat = meta::stat(path)?;
    Some(FileInfo {
        size: stat.size.max(0) as u64,
        mtime: stat.mtime,
        mtime_ns: stat.mtime_ns,
        is_file: stat.kind == Kind::File,
        is_symlink: meta::lstat(path).is_some_and(|s| s.kind == Kind::Symlink),
        snapshot: Snapshot::Local(stat),
    })
}

fn remote_stat_error(error: RemoteError) -> OperationError {
    if error.data["exit_code"] == json!(44) {
        return OperationError::new(StatusCode::NOT_FOUND, "file not found");
    }
    if error.data["exit_code"] == json!(46) {
        return OperationError::remote(StatusCode::FORBIDDEN, error);
    }
    let status = if error.data["missing_tool"].is_string() {
        StatusCode::FAILED_DEPENDENCY
    } else if error.data["timed_out"] == json!(true) {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::BAD_GATEWAY
    };
    OperationError::remote(status, error)
}

fn remote_info(target: &Target, path: &str) -> OpResult<FileInfo> {
    let stat = crate::remoteio::remote_stat(target, path).map_err(remote_stat_error)?;
    Ok(FileInfo {
        size: stat.size,
        mtime: stat.mtime,
        mtime_ns: 0,
        is_file: stat.kind == "file",
        is_symlink: stat.is_symlink,
        snapshot: Snapshot::Remote(stat),
    })
}

fn changed() -> OperationError {
    OperationError::new(
        StatusCode::CONFLICT,
        "the file changed on disk since it was opened",
    )
}

impl ByteOps for LocalByteOps {
    fn device_id(&self) -> &str {
        ""
    }
    fn target(&self) -> Option<&Target> {
        None
    }
    fn stat(&self, path: &str) -> OpResult<FileInfo> {
        local_info(path).ok_or_else(|| OperationError::new(StatusCode::NOT_FOUND, "file not found"))
    }
    fn read_at(&self, path: &str, offset: u64, length: u64) -> OpResult<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let file = fs::File::open(path)
            .map_err(|_| OperationError::new(StatusCode::FORBIDDEN, "cannot open file"))?;
        let mut data = vec![0; length as usize];
        let mut done = 0;
        while done < data.len() {
            let n = file
                .read_at(&mut data[done..], offset + done as u64)
                .map_err(|_| {
                    OperationError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "cannot seek to requested offset",
                    )
                })?;
            if n == 0 {
                break;
            }
            done += n;
        }
        data.truncate(done);
        Ok(data)
    }
    fn write_at(&self, path: &str, offset: u64, data: &[u8], before: &FileInfo) -> OpResult<u64> {
        use std::os::unix::fs::FileExt;
        let file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| OperationError::new(StatusCode::INTERNAL_SERVER_ERROR, "short write"))?;
        if let Snapshot::Local(snapshot) = before.snapshot {
            if !file
                .metadata()
                .ok()
                .is_some_and(|m| metadata_matches_snapshot(&m, snapshot))
            {
                return Err(changed());
            }
        } else {
            return Err(changed());
        }
        let mut done = 0usize;
        while done < data.len() {
            let n =
                match file.write_at(&data[done..], offset + done as u64) {
                    Ok(n) if n > 0 => n,
                    _ if done > 0 => return Err(OperationError {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        code: 1,
                        message:
                            "The write was only partially applied; check the file before retrying"
                                .into(),
                        data: json!({"outcome_unknown":true, "written":done}),
                    }),
                    _ => {
                        return Err(OperationError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "short write",
                        ))
                    }
                };
            done += n;
        }
        Ok(done as u64)
    }
    fn span_read(
        &self,
        path: &str,
        plan: &SearchPlan,
        _cancelled: Arc<AtomicBool>,
    ) -> Result<Box<dyn Read + Send>, String> {
        let mut file = fs::File::open(path).map_err(|_| "cannot open file".to_string())?;
        file.seek(SeekFrom::Start(plan.read_start()))
            .map_err(|_| "cannot seek in file".to_string())?;
        Ok(Box::new(std::io::BufReader::with_capacity(CHUNK, file)))
    }
    fn splice_rewrite(
        &self,
        source: String,
        destination: String,
        before: FileInfo,
        plan: ReplacePlan,
        progress: Option<ReplaceProgress>,
        cancelled: Arc<AtomicBool>,
    ) -> OpResult<(u64, u64)> {
        use std::os::unix::fs::OpenOptionsExt;
        let snapshot = match before.snapshot {
            Snapshot::Local(value) => value,
            _ => return Err(changed()),
        };
        let parent = paths::parent_path(&destination).unwrap_or_else(|| "/".to_string());
        let tmp = format!("{parent}/.harbor-rewrite.{}", crate::uci::random_hex(16));
        let mut input = fs::File::open(&source).map_err(|_| {
            OperationError::new(StatusCode::INTERNAL_SERVER_ERROR, "cannot open file")
        })?;
        let original = input.metadata().map_err(|_| {
            OperationError::new(StatusCode::INTERNAL_SERVER_ERROR, "cannot open file")
        })?;
        if !metadata_matches_snapshot(&original, snapshot) {
            return Err(changed());
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| {
                OperationError::new(StatusCode::INTERNAL_SERVER_ERROR, "rewrite failed")
            })?;
        let _cleanup = RemoveRewriteTemp(tmp.clone());
        crate::paths::journal_tmp(&tmp);
        let report = |done: u64| {
            if let Some(progress) = &progress {
                progress.update(done, before.size);
            }
        };
        let (count, written) = replace_stream(
            &mut CancelRead {
                inner: &mut input,
                cancelled: cancelled.clone(),
            },
            &mut CancelWrite {
                inner: &mut output,
                cancelled: cancelled.clone(),
            },
            &plan,
            before.size,
            &report,
        )
        .map_err(|error| OperationError::new(StatusCode::INTERNAL_SERVER_ERROR, error))?;
        output.flush().map_err(|_| {
            OperationError::new(StatusCode::INTERNAL_SERVER_ERROR, "rewrite failed")
        })?;
        drop(output);
        fs::set_permissions(
            &tmp,
            std::os::unix::fs::PermissionsExt::from_mode(snapshot.mode & 0o7777),
        )
        .map_err(|_| {
            OperationError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cannot preserve file permissions",
            )
        })?;
        verify_file_revision(&input, &source, &original).map_err(|_| changed())?;
        // Cancellation before publication is safe to abandon. The check and
        // rename are not atomic; a lost response must still be treated as an
        // unknown result and the destination inspected before retrying.
        if cancelled.load(Ordering::Relaxed) {
            return Err(OperationError::new(
                StatusCode::CONFLICT,
                "rewrite cancelled",
            ));
        }
        fs::rename(&tmp, &destination)
            .map_err(|_| OperationError::new(StatusCode::INTERNAL_SERVER_ERROR, "rename failed"))?;
        Ok((count, written))
    }
    fn sha256(&self, path: &str, before: &FileInfo) -> OpResult<(String, FileInfo)> {
        let mut file = fs::File::open(path).map_err(|_| {
            OperationError::new(
                StatusCode::FORBIDDEN,
                "cannot read file for SHA256 calculation",
            )
        })?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; CHUNK];
        loop {
            let n = file.read(&mut buffer).map_err(|_| {
                OperationError::new(
                    StatusCode::FORBIDDEN,
                    "cannot read file for SHA256 calculation",
                )
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let after = local_info(path).ok_or_else(|| {
            OperationError::new(
                StatusCode::CONFLICT,
                "file changed during SHA256 calculation",
            )
        })?;
        match (&before.snapshot, &after.snapshot) {
            (Snapshot::Local(a), Snapshot::Local(b))
                if a.dev == b.dev
                    && a.ino == b.ino
                    && a.size == b.size
                    && a.mtime == b.mtime
                    && a.mtime_ns == b.mtime_ns
                    && a.ctime == b.ctime => {}
            _ => {
                return Err(OperationError::new(
                    StatusCode::CONFLICT,
                    "file changed during SHA256 calculation",
                ))
            }
        }
        Ok((hex::encode(hasher.finalize()), after))
    }
    fn thumbnail(
        &self,
        st: &AppState,
        path: &str,
        before: &FileInfo,
    ) -> Option<(String, u64, i64, i64)> {
        let Snapshot::Local(snapshot) = before.snapshot else {
            return None;
        };
        let cache = crate::api::fsops::thumbnail_cache_path(path, &snapshot, &st.prefs())?;
        let info = meta::stat(&cache)?;
        Some((cache, info.size.max(0) as u64, info.mtime, info.mtime_ns))
    }
    fn stage(&self, path: &str, commit: bool) -> OpResult<()> {
        let stage = format!("{path}.harbor-stage");
        if commit {
            if !meta::lstat(&stage).is_some_and(|s| s.kind == Kind::File) {
                return Err(OperationError::new(
                    StatusCode::NOT_FOUND,
                    "no staged changes",
                ));
            }
            fs::rename(&stage, path).map_err(|_| {
                OperationError::new(StatusCode::INTERNAL_SERVER_ERROR, "commit failed")
            })?;
        } else {
            let _ = fs::remove_file(&stage);
        }
        Ok(())
    }
    fn source<'a>(&'a self, _path: &'a str) -> Source<'a> {
        Source::Local
    }
}

impl ByteOps for RemoteByteOps {
    fn device_id(&self) -> &str {
        &self.target.id
    }
    fn target(&self) -> Option<&Target> {
        Some(&self.target)
    }
    fn stat(&self, path: &str) -> OpResult<FileInfo> {
        remote_info(&self.target, path)
    }
    fn read_at(&self, path: &str, offset: u64, length: u64) -> OpResult<Vec<u8>> {
        let start = offset
            .checked_add(1)
            .ok_or_else(|| OperationError::new(StatusCode::BAD_REQUEST, "offset out of range"))?;
        let quoted = shell_quote(path);
        let script = format!("[ -r {quoted} ] || {{ echo 'cannot open file' >&2; exit 46; }}\ntail -c +{start} {quoted} | head -c {length}");
        let bytes = crate::remote::run(&self.target, &script, Some(120)).map_err(|e| {
            if e.data["exit_code"] == json!(46) {
                OperationError::new(StatusCode::FORBIDDEN, "cannot open file")
            } else {
                remote_stat_error(e)
            }
        })?;
        if bytes.len() as u64 != length {
            return Err(changed());
        }
        Ok(bytes)
    }
    fn write_at(&self, path: &str, offset: u64, data: &[u8], before: &FileInfo) -> OpResult<u64> {
        let previous = match &before.snapshot {
            Snapshot::Remote(s) => s,
            _ => return Err(changed()),
        };
        let current = crate::remoteio::remote_stat(&self.target, path).map_err(|error| {
            if error.data["exit_code"] == json!(44) {
                changed()
            } else {
                remote_stat_error(error)
            }
        })?;
        if previous.revision.is_some() && previous.revision != current.revision {
            return Err(changed());
        }
        let script = format!(
            "dd of={} bs=1 seek={} conv=notrunc 2>/dev/null",
            shell_quote(path),
            offset
        );
        crate::remoteio::push_body(&self.target, &script, data)
            .map_err(|e| OperationError::remote(StatusCode::BAD_GATEWAY, e))?;
        Ok(data.len() as u64)
    }
    fn span_read(
        &self,
        path: &str,
        plan: &SearchPlan,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Box<dyn Read + Send>, String> {
        Ok(crate::remoteio::search_reader(
            &self.target,
            path,
            plan.read_start(),
            plan.read_end(),
            cancelled,
        ))
    }
    fn splice_rewrite(
        &self,
        source: String,
        destination: String,
        before: FileInfo,
        plan: ReplacePlan,
        progress: Option<ReplaceProgress>,
        cancelled: Arc<AtomicBool>,
    ) -> OpResult<(u64, u64)> {
        let snapshot = match before.snapshot {
            Snapshot::Remote(s) => s,
            _ => return Err(changed()),
        };
        crate::remoteio::stream_remote_rewrite(
            &self.target,
            source,
            destination,
            snapshot,
            plan,
            progress,
            cancelled,
        )
        .map_err(|e| OperationError::remote(StatusCode::INTERNAL_SERVER_ERROR, e))
    }
    fn sha256(&self, path: &str, before: &FileInfo) -> OpResult<(String, FileInfo)> {
        // Redirect input rather than pass a filename: sha256sum otherwise
        // prefixes an escape character for paths containing newlines.
        let script = format!("sha256sum < {}", shell_quote(path));
        let raw = crate::remote::run(&self.target, &script, Some(3600))
            .map_err(|e| OperationError::remote(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let text = std::str::from_utf8(&raw).unwrap_or("");
        let hash = text.split_whitespace().next().unwrap_or("");
        if hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(OperationError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cannot read file for SHA256 calculation",
            ));
        }
        let after = remote_info(&self.target, path).map_err(|error| {
            if error.status == StatusCode::NOT_FOUND {
                OperationError::new(
                    StatusCode::CONFLICT,
                    "file changed during SHA256 calculation",
                )
            } else {
                error
            }
        })?;
        match (&before.snapshot, &after.snapshot) {
            (Snapshot::Remote(a), Snapshot::Remote(b))
                if a.size == b.size
                    && a.mtime == b.mtime
                    && (a.revision.is_none() || a.revision == b.revision) => {}
            _ => {
                return Err(OperationError::new(
                    StatusCode::CONFLICT,
                    "file changed during SHA256 calculation",
                ))
            }
        }
        Ok((hash.to_ascii_lowercase(), after))
    }
    fn thumbnail(
        &self,
        _st: &AppState,
        path: &str,
        _before: &FileInfo,
    ) -> Option<(String, u64, i64, i64)> {
        crate::remoteops::thumbnail_file(&self.target, path)
            .map(|(p, s, t)| (p, s.max(0) as u64, t, 0))
    }
    fn stage(&self, path: &str, commit: bool) -> OpResult<()> {
        let staged = shell_quote(&format!("{path}.harbor-stage"));
        let script = if commit {
            format!(
                "set -e\n[ -f {staged} ] && [ ! -L {staged} ] || exit 44\nmv -fT -- {staged} {}",
                shell_quote(path)
            )
        } else {
            format!("rm -f {staged}")
        };
        crate::remote::run_mutating_once(&self.target, &script, Some(600))
            .map(|_| ())
            .map_err(|e| {
                if commit && e.data["exit_code"] == json!(44) {
                    OperationError::new(StatusCode::NOT_FOUND, "no staged changes")
                } else {
                    OperationError::remote(StatusCode::BAD_GATEWAY, e)
                }
            })
    }
    fn source<'a>(&'a self, path: &'a str) -> Source<'a> {
        Source::Remote {
            target: &self.target,
            path,
        }
    }
    fn rewrite_limit(&self) -> Option<u64> {
        Some(remote_replace_limit())
    }
}

#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
async fn perform<T: Send + 'static>(
    f: impl FnOnce() -> OpResult<T> + Send + 'static,
) -> Result<T, Response> {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.response()),
        Err(_) => Err(io_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "operation failed",
        )),
    }
}

#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
async fn perform_rewrite<T: Send + 'static>(
    f: impl FnOnce(Arc<AtomicBool>) -> OpResult<T> + Send + 'static,
) -> Result<T, Response> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut guard = RequestCancelGuard::new(cancelled.clone());
    let result = perform(move || f(cancelled)).await;
    guard.finish();
    result
}

#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
async fn check_paths(
    st: &Arc<AppState>,
    target: Option<&Target>,
    headers: &HeaderMap,
    device_id: &str,
    paths: Vec<String>,
) -> Result<(), Response> {
    let st = st.clone();
    let target = target.cloned();
    let headers = headers.clone();
    let device_id = device_id.to_string();
    match tokio::task::spawn_blocking(move || {
        crate::remoteio::checked_io_paths(&st, target.as_ref(), &headers, &device_id, &paths)
    })
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(response)) => Err(response),
        Err(_) => Err(io_error(StatusCode::BAD_GATEWAY, "Cannot validate path")),
    }
}

#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
async fn get_stat<B: ByteOps>(ops: &B, path: &str) -> Result<FileInfo, Response> {
    let ops = ops.clone();
    let path = path.to_string();
    perform(move || ops.stat(&path)).await
}

fn expected_size(params: &Params, size: u64) -> Option<Response> {
    if byte_int(params, "expected_size").is_some_and(|value| value != size) {
        Some(reply_status(
            StatusCode::CONFLICT,
            json!({ "code": 2,
            "message": "the file changed on disk since it was opened", "size": size }),
        ))
    } else {
        None
    }
}

fn rewrite_too_large<B: ByteOps>(ops: &B, size: u64) -> Option<Response> {
    if ops.rewrite_limit().is_some_and(|limit| size > limit) {
        Some(io_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the file is too large to rewrite over SSH",
        ))
    } else {
        None
    }
}

pub(super) async fn handle(st: Arc<AppState>, params: Params, req: Request) -> Response {
    let mode = params.str_or("mode", "download");
    let device = params.get("device_id");
    let is_special_upload = matches!(mode.as_str(), "api_upload_archive" | "api_upload_sftp");
    let raw_path = if device.is_some() || is_special_upload {
        params.get("path").unwrap_or_else(|| "/".to_string())
    } else {
        params.get("path").unwrap_or_default()
    };
    let path = match paths::normalize_path(&raw_path) {
        Some(path) => path,
        None => return io_error(StatusCode::BAD_REQUEST, "invalid path"),
    };
    let headers = req.headers().clone();
    let target = if mode == "api_upload_archive" && device.as_deref().unwrap_or("").is_empty() {
        None
    } else if device.is_some() || mode == "api_upload_sftp" {
        match crate::remoteio::managed_device(&st, &params) {
            Ok(target) => Some(target),
            Err(error) => return remote_stat_error(error).response(),
        }
    } else {
        None
    };
    if is_special_upload || (mode == "api_upload" && target.is_some()) {
        if req.method() != Method::POST {
            return io_error(StatusCode::METHOD_NOT_ALLOWED, "POST required");
        }
        return match mode.as_str() {
            "api_upload_archive" => {
                crate::remoteio::upload_archive(&st, target.as_ref(), &params, &headers, req, &path)
                    .await
            }
            "api_upload_sftp" => {
                let target = target.as_ref().expect("SFTP requires a managed target");
                if let Err(response) =
                    check_paths(&st, Some(target), &headers, &target.id, vec![path.clone()]).await
                {
                    return response;
                }
                crate::remoteio::upload_sftp(&st, Some(target), &path, &params, &headers, req).await
            }
            _ => {
                crate::remoteio::upload(
                    &st,
                    target.as_ref().expect("remote upload target"),
                    &params,
                    &headers,
                    req,
                    &path,
                )
                .await
            }
        };
    }
    if let Some(target) = target {
        dispatch(st, params, req, path, mode, RemoteByteOps { target }).await
    } else {
        dispatch(st, params, req, path, mode, LocalByteOps).await
    }
}

async fn dispatch<B: ByteOps>(
    st: Arc<AppState>,
    params: Params,
    req: Request,
    path: String,
    mode: String,
    ops: B,
) -> Response {
    let headers = req.headers().clone();
    let method = req.method().clone();
    let staged = format!("{path}.harbor-stage");
    let mut checked = vec![path.clone()];
    if matches!(mode.as_str(), "stage_commit" | "stage_discard")
        || (mode == "replace_all" && params.get("stage").as_deref() == Some("1"))
    {
        checked.push(staged.clone());
    }
    if let Err(response) = check_paths(&st, ops.target(), &headers, ops.device_id(), checked).await
    {
        return response;
    }
    if mode == "replace_progress" {
        return replace_progress(ops.device_id(), &path, &params);
    }
    if matches!(mode.as_str(), "stage_commit" | "stage_discard") {
        let commit = mode == "stage_commit";
        let copy_ops = ops.clone();
        let copy_path = path.clone();
        return match perform(move || copy_ops.stage(&copy_path, commit)).await {
            Ok(()) => reply(json!({"code":0,"message":"success","data":{"path":path}})),
            Err(response) => response,
        };
    }
    let staging = mode == "replace_all" && params.get("stage").as_deref() == Some("1");
    let source_path = if staging {
        match params.get("src") {
            Some(src) => match paths::normalize_path(&src) {
                Some(src) if src == path || src == staged => src,
                _ => return io_error(StatusCode::BAD_REQUEST, "invalid source"),
            },
            None => path.clone(),
        }
    } else {
        path.clone()
    };
    let info = match get_stat(&ops, &source_path).await {
        Ok(info) => info,
        Err(response)
            if staging && source_path == staged && response.status() == StatusCode::NOT_FOUND =>
        {
            return io_error(StatusCode::NOT_FOUND, "staged source missing")
        }
        Err(response) => return response,
    };
    if staging && source_path == staged && info.is_symlink {
        return io_error(StatusCode::NOT_FOUND, "staged source missing");
    }
    if mode != "thumbnail" && !info.is_file {
        return io_error(StatusCode::BAD_REQUEST, "not a regular file");
    }

    match mode.as_str() {
        "thumbnail" => {
            let copy_ops = ops.clone();
            let copy_path = path.clone();
            let copy_st = st.clone();
            let copy_info = info.clone();
            let cache =
                perform(move || Ok(copy_ops.thumbnail(&copy_st, &copy_path, &copy_info))).await;
            let (cache, size, mtime, mtime_ns) = match cache {
                Ok(Some(cache)) => cache,
                Ok(None) => return io_error(StatusCode::NOT_FOUND, "thumbnail not generated"),
                Err(response) => return response,
            };
            serve_file(
                &st,
                &headers,
                &method,
                FileHeaders {
                    path: &cache,
                    name: paths::path_name(&path).replace('.', "_") + ".jpg",
                    mime: "image/jpeg".to_string(),
                    size,
                    mtime,
                    mtime_ns,
                    inline: true,
                },
                ops.source(&cache),
            )
            .await
        }
        "slice" => {
            let offset = byte_int(&params, "offset").unwrap_or(0).min(info.size);
            let length = byte_int(&params, "length")
                .unwrap_or(4096)
                .min(SLICE_MAX)
                .min(info.size.saturating_sub(offset));
            let copy_ops = ops.clone();
            let copy_path = path.clone();
            let data = match perform(move || copy_ops.read_at(&copy_path, offset, length)).await {
                Ok(data) => data,
                Err(response) => return response,
            };
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, data.len().to_string())
                .header("X-Harbor-Offset", offset.to_string())
                .header("X-Harbor-Total", info.size.to_string())
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::from(data))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        "patch" => {
            let offset = match byte_int(&params, "offset") {
                Some(offset) => offset,
                None => return io_error(StatusCode::BAD_REQUEST, "offset out of range"),
            };
            let data = match read_body(req, 64 * 1024 * 1024).await {
                Ok(data) => data,
                Err(response) => return response,
            };
            if offset
                .checked_add(data.len() as u64)
                .is_none_or(|end| end > info.size)
            {
                return io_error(
                    StatusCode::BAD_REQUEST,
                    "patch would extend the file, use mode=splice",
                );
            }
            if let Some(response) = expected_size(&params, info.size) {
                return response;
            }
            let copy_ops = ops.clone();
            let copy_path = path.clone();
            let copy_info = info.clone();
            match perform(move || copy_ops.write_at(&copy_path, offset, &data, &copy_info)).await {
                Ok(written) => reply(
                    json!({"code":0,"message":"success","data":{"path":path,"offset":offset,"written":written,"size":info.size}}),
                ),
                Err(response) => response,
            }
        }
        "splice" => {
            let (start, end) = match (byte_int(&params, "start"), byte_int(&params, "end")) {
                (Some(start), Some(end)) if start <= end && end <= info.size => (start, end),
                _ => return io_error(StatusCode::BAD_REQUEST, "range out of bounds"),
            };
            if let Some(response) = expected_size(&params, info.size) {
                return response;
            }
            if let Some(response) = rewrite_too_large(&ops, info.size) {
                return response;
            }
            let data = match read_body(req, 64 * 1024 * 1024).await {
                Ok(data) => data,
                Err(response) => return response,
            };
            let inserted = data.len();
            let plan = ReplacePlan {
                needle: Vec::new(),
                repl: data,
                icase: false,
                regex: None,
                range: Some((start, end - start)),
            };
            let copy_ops = ops.clone();
            let copy_path = path.clone();
            match perform_rewrite(move |cancelled| {
                copy_ops.splice_rewrite(copy_path.clone(), copy_path, info, plan, None, cancelled)
            })
            .await
            {
                Ok((_, size)) => reply(
                    json!({"code":0,"message":"success","data":{"path":path,"start":start,"end":end,"removed":end-start,"inserted":inserted,"size":size}}),
                ),
                Err(response) => response,
            }
        }
        "search" => {
            let plan = match prepare_search(&params, info.size) {
                Ok(plan) => plan,
                Err(message) => return io_error(StatusCode::BAD_REQUEST, &message),
            };
            let cancelled = Arc::new(AtomicBool::new(false));
            let mut guard = RequestCancelGuard::new(cancelled.clone());
            let copy_ops = ops.clone();
            let copy_path = path.clone();
            let result = perform(move || {
                let mut reader = copy_ops
                    .span_read(&copy_path, &plan, cancelled.clone())
                    .map_err(|e| OperationError::new(StatusCode::BAD_REQUEST, e))?;
                scan_search(&mut reader, &copy_path, &plan, &cancelled)
                    .map_err(|e| OperationError::new(StatusCode::BAD_REQUEST, e))
            })
            .await;
            guard.finish();
            match result {
                Ok(data) => reply(json!({"code":0,"message":"success","data":data})),
                Err(response) => response,
            }
        }
        "sha256" => {
            let copy_ops = ops.clone();
            let copy_path = path.clone();
            match perform(move || copy_ops.sha256(&copy_path, &info)).await {
                Ok((sha256, after)) => reply(
                    json!({"code":0,"message":"success","data":{"path":path,"sha256":sha256,"size":after.size,"mtime":after.mtime}}),
                ),
                Err(response) => response,
            }
        }
        "replace_all" => {
            let plan = match parse_replace(&params) {
                Ok(plan) => plan,
                Err((status, message)) => return io_error(status, &message),
            };
            if plan
                .range
                .is_some_and(|(at, len)| at.checked_add(len).is_none_or(|end| end > info.size))
            {
                return io_error(StatusCode::BAD_REQUEST, "invalid range");
            }
            if let Some(response) = rewrite_too_large(&ops, info.size) {
                return response;
            }
            let dest = if staging {
                staged.clone()
            } else {
                path.clone()
            };
            let progress = ReplaceProgress::start(ops.device_id(), &path, &params);
            let copy_ops = ops.clone();
            match perform_rewrite(move |cancelled| {
                copy_ops.splice_rewrite(source_path, dest, info, plan, Some(progress), cancelled)
            })
            .await
            {
                Ok((replaced, size)) => reply(
                    json!({"code":0,"message":"success","data":{"path":path,"replaced":replaced,"size":size,"staged":if staging {Some(staged)} else {None}}}),
                ),
                Err(response) => response,
            }
        }
        _ => {
            let inline = mode == "inline";
            let name = params
                .get("filename")
                .map(|f| paths::path_name(&format!("/{f}")))
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| paths::path_name(&path));
            let mime = params.get("mimetype").unwrap_or_else(|| {
                if inline {
                    meta::mime_for(&path).to_string()
                } else {
                    "application/octet-stream".to_string()
                }
            });
            serve_file(
                &st,
                &headers,
                &method,
                FileHeaders {
                    path: &path,
                    name,
                    mime,
                    size: info.size,
                    mtime: info.mtime,
                    mtime_ns: info.mtime_ns,
                    inline,
                },
                ops.source(&path),
            )
            .await
        }
    }
}

#[cfg(test)]
// Fixture tests intentionally serialize shared environment/process state across awaits.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    async fn invoke(
        st: &Arc<AppState>,
        device: Option<&str>,
        path: &str,
        mode: &str,
        fields: &[(&str, &str)],
        body: &[u8],
        range: Option<&str>,
    ) -> Response {
        let mut params = Params::default();
        params.set("path", path);
        params.set("mode", mode);
        if let Some(id) = device {
            params.set("device_id", id);
        }
        for (key, value) in fields {
            params.set(key, value);
        }
        let mut request = Request::builder().method("POST");
        if let Some(range) = range {
            request = request.header(header::RANGE, range);
        }
        super::handle(
            st.clone(),
            params,
            request.body(Body::from(body.to_vec())).unwrap(),
        )
        .await
    }
    async fn json_body(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_rewrite_future_signals_worker_and_cancelled_local_rewrite_never_publishes() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (cancelled_tx, cancelled_rx) = std::sync::mpsc::channel();
        let future = tokio::spawn(perform_rewrite(move |flag| -> OpResult<()> {
            started_tx.send(()).unwrap();
            for _ in 0..200 {
                if flag.load(Ordering::Relaxed) {
                    cancelled_tx.send(()).unwrap();
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(OperationError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "cancel was not delivered",
            ))
        }));
        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        future.abort();
        let _ = future.await;
        cancelled_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();

        let root = std::env::temp_dir().join(format!(
            "harbor-rewrite-cancel-{}",
            crate::uci::random_hex(8)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("file").to_string_lossy().into_owned();
        fs::write(&path, b"original").unwrap();
        let ops = LocalByteOps;
        let info = match ops.stat(&path) {
            Ok(info) => info,
            Err(_) => panic!("stat failed"),
        };
        let plan = ReplacePlan {
            needle: Vec::new(),
            repl: b"NEW".to_vec(),
            icase: false,
            regex: None,
            range: Some((0, 3)),
        };
        let cancelled = Arc::new(AtomicBool::new(true));
        assert!(ops
            .splice_rewrite(path.clone(), path.clone(), info, plan, None, cancelled)
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            1,
            "rewrite temporary file must be removed"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn remote_stat_distinguishes_missing_permissions_and_offline_device() {
        let _lock = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target =
            crate::ssh::e2e_target("byteops-stat-errors", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-byteops-stat-{}", crate::uci::random_hex(8));
        let hidden = format!("{root}/private");
        let file = format!("{hidden}/file");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -p {hidden}; printf secret > {file}; chmod 000 {hidden}",
                hidden = shell_quote(&hidden),
                file = shell_quote(&file)
            ),
            Some(30),
        )
        .unwrap();
        let ops = RemoteByteOps {
            target: target.clone(),
        };
        let absent = ops.stat(&format!("{root}/absent")).err().unwrap();
        assert_eq!(absent.status, StatusCode::NOT_FOUND);
        let denied = ops.stat(&file).err().unwrap();
        assert_eq!(
            denied.status,
            StatusCode::FORBIDDEN,
            "{} {:?}",
            denied.message,
            denied.data
        );
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let response = invoke(&st, Some(&target.id), &file, "slice", &[], b"", None).await;
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "permission errors are not missing files"
        );
        let mut offline = target.clone();
        offline.port = 1;
        let offline_ops = RemoteByteOps { target: offline };
        let unavailable = offline_ops.stat(&file).err().unwrap();
        assert_eq!(unavailable.status, StatusCode::BAD_GATEWAY);
        let error = remote_stat_error(RemoteError::missing_tool(
            "stat",
            "coreutils-stat",
            "stat is required",
        ));
        assert_eq!(error.status, StatusCode::FAILED_DEPENDENCY);
        assert_eq!(error.data["missing_tool"], "stat");
        assert_eq!(error.data["dependency_preflight"], true);
        let error = remote_stat_error(RemoteError::with_data("timeout", json!({"timed_out":true})));
        assert_eq!(error.status, StatusCode::GATEWAY_TIMEOUT);
        let _ = crate::remote::run(
            &target,
            &format!(
                "chmod 700 {hidden}; rm -rf {root}",
                hidden = shell_quote(&hidden),
                root = shell_quote(&root)
            ),
            Some(30),
        );
        drop(st);
        let _ = fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn real_ssh_and_local_use_the_same_byte_contract() {
        let _lock = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("byteops-parity", 60).expect("HARBOR_E2E_SSH_PORT");
        let suffix = crate::uci::random_hex(8);
        let remote_root = format!("/tmp/harbor-byteops-remote-{suffix}");
        let remote_path = format!("{remote_root}/newline\nfile");
        crate::remote::run(
            &target,
            &format!(
                "mkdir -p -- {}; printf abcdefabc > {}; chmod 600 -- {}",
                shell_quote(&remote_root),
                shell_quote(&remote_path),
                shell_quote(&remote_path)
            ),
            Some(30),
        )
        .unwrap();
        let (remote_st, remote_state_dir) = crate::ssh::e2e_state(&target, &remote_root);
        let local_root = std::env::temp_dir().join(format!("harbor-byteops-local-{suffix}"));
        fs::create_dir_all(&local_root).unwrap();
        let local_path = local_root
            .join("newline\nfile")
            .to_string_lossy()
            .into_owned();
        fs::write(&local_path, b"abcdefabc").unwrap();
        fs::set_permissions(&local_path, fs::Permissions::from_mode(0o600)).unwrap();
        let local_st = AppState::new(crate::state::Settings {
            state_dir: local_root.join("state").to_string_lossy().into_owned(),
            config_path: local_root.join("config").to_string_lossy().into_owned(),
            root_policy: crate::state::RootPolicy::Allowlist,
            roots: vec![local_root.to_string_lossy().into_owned()],
            ..Default::default()
        });
        let call = |remote: bool,
                    mode: &'static str,
                    fields: Vec<(&'static str, &'static str)>,
                    body: &'static [u8],
                    range: Option<&'static str>| {
            let st = if remote {
                remote_st.clone()
            } else {
                local_st.clone()
            };
            let id = remote.then(|| target.id.clone());
            let path = if remote {
                remote_path.clone()
            } else {
                local_path.clone()
            };
            async move { invoke(&st, id.as_deref(), &path, mode, &fields, body, range).await }
        };
        for remote in [false, true] {
            let response = call(
                remote,
                "slice",
                vec![("offset", "2"), ("length", "900")],
                b"",
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["x-harbor-offset"], "2");
            assert_eq!(response.headers()["x-harbor-total"], "9");
            assert_eq!(
                &axum::body::to_bytes(response.into_body(), 100)
                    .await
                    .unwrap()[..],
                b"cdefabc"
            );
            let response = call(remote, "download", vec![], b"", Some("bytes=2-4")).await;
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-4/9");
            assert_eq!(
                &axum::body::to_bytes(response.into_body(), 100)
                    .await
                    .unwrap()[..],
                b"cde"
            );
            let (status, conflict) = json_body(
                call(
                    remote,
                    "patch",
                    vec![("offset", "2"), ("expected_size", "10")],
                    b"X",
                    None,
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(conflict["code"], 2);
            assert_eq!(conflict["size"], 9);
            let (status, error) =
                json_body(call(remote, "patch", vec![("offset", "9")], b"X", None).await).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(error["code"], 1);
            assert_eq!(
                json_body(
                    call(
                        remote,
                        "patch",
                        vec![("offset", "2"), ("expected_size", "9")],
                        b"X",
                        None
                    )
                    .await
                )
                .await
                .1["data"]["written"],
                1
            );
            assert_eq!(
                json_body(
                    call(
                        remote,
                        "splice",
                        vec![("start", "2"), ("end", "5"), ("expected_size", "9")],
                        b"XYZ",
                        None
                    )
                    .await
                )
                .await
                .1["data"]["size"],
                9
            );
            let search = json_body(
                call(
                    remote,
                    "search",
                    vec![("q", "abc"), ("limit", "10")],
                    b"",
                    None,
                )
                .await,
            )
            .await;
            assert_eq!(search.0, StatusCode::OK);
            assert_eq!(search.1["data"]["matches"], json!([6]));
            let digest = json_body(call(remote, "sha256", vec![], b"", None).await).await;
            assert_eq!(digest.0, StatusCode::OK);
            assert_eq!(
                digest.1["data"]["sha256"],
                hex::encode(Sha256::digest(b"abXYZfabc"))
            );
            let replaced = json_body(
                call(
                    remote,
                    "replace_all",
                    vec![("q", "abc"), ("r", "J"), ("stage", "1")],
                    b"",
                    None,
                )
                .await,
            )
            .await;
            assert_eq!(replaced.0, StatusCode::OK);
            assert_eq!(replaced.1["data"]["replaced"], 1);
            assert_eq!(
                json_body(call(remote, "stage_commit", vec![], b"", None).await)
                    .await
                    .0,
                StatusCode::OK
            );
            let slice = call(remote, "slice", vec![], b"", None).await;
            assert_eq!(
                &axum::body::to_bytes(slice.into_body(), 100).await.unwrap()[..],
                b"abXYZfJ"
            );
            let (status, _) =
                json_body(call(remote, "stage_commit", vec![], b"", None).await).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        assert_eq!(
            fs::metadata(&local_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("stat -c %a {}", shell_quote(&remote_path)),
                Some(30)
            )
            .unwrap(),
            b"600\n"
        );
        let partial = format!("{remote_root}/partial");
        let error = crate::remoteio::push_body(
            &target,
            &format!(
                "dd of={} bs=1 count=1 2>/dev/null; exit 1",
                shell_quote(&partial)
            ),
            b"patch",
        )
        .unwrap_err();
        assert_eq!(error.data["outcome_unknown"], true);
        assert_eq!(
            crate::remote::run(&target, &format!("cat {}", shell_quote(&partial)), Some(30))
                .unwrap(),
            b"p"
        );
        let _ = crate::remote::run(
            &target,
            &format!("rm -rf -- {}", shell_quote(&remote_root)),
            Some(30),
        );
        drop(remote_st);
        drop(local_st);
        let _ = fs::remove_dir_all(remote_state_dir);
        let _ = fs::remove_dir_all(local_root);
    }
}
