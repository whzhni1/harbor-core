use crate::meta;
use crate::params::Params;
use crate::paths;
use crate::reply::{fail, fail_code, ok, ApiResult};
use crate::state::{AppState, Ctx};
use crate::transfers::{self, Status, Transfer};
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UploadPhase {
    #[default]
    Receiving,
    Publishing,
    Published,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionMeta {
    session_id: String,
    dir: String,
    filename: String,
    total_size: u64,
    chunk_size: u64,
    total_chunks: u64,
    created_at: i64,
    #[serde(default)]
    staging_dir: String,
    #[serde(default = "default_preserve_permissions")]
    preserve_permissions: bool,
    // Old sessions did not persist overwrite/owner; their original overwrite
    // behavior is retained when resuming after an upgrade.
    #[serde(default = "legacy_overwrite")]
    overwrite: bool,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    state_binding: Option<String>,
    #[serde(default)]
    cancelled: bool,
    #[serde(default)]
    phase: UploadPhase,
    uploaded: Vec<u64>,
    task_id: Option<String>,
}

fn default_preserve_permissions() -> bool {
    true
}
fn legacy_overwrite() -> bool {
    true
}

struct LocalUploadSession {
    activity: crate::task_registry::SessionActivity,
    received: u64,
    id: String,
    task_id: Option<String>,
    registry: std::sync::Weak<crate::task_registry::TaskRegistry>,
}
impl crate::task_registry::SessionResource for LocalUploadSession {
    fn activity(&self) -> &crate::task_registry::SessionActivity {
        &self.activity
    }
    fn activity_mut(&mut self) -> &mut crate::task_registry::SessionActivity {
        &mut self.activity
    }
    fn progress(&self) -> u64 {
        self.received
    }
    fn cleanup(&mut self, reason: crate::task_registry::SessionCleanup) {
        // Cancellation and shutdown preserve resumable on-disk chunks. Only
        // expiry (or an explicit abort handled by the API) removes them.
        if reason != crate::task_registry::SessionCleanup::Expired {
            return;
        }
        if let Some(task) = self
            .registry
            .upgrade()
            .and_then(|r| self.task_id.as_ref().and_then(|id| r.get(id)))
        {
            if !task.status().terminal() {
                task.fail("Upload session expired");
            }
        }
        let _ = transfers::destroy_upload_session(&self.id);
        transfers::remove_empty_staging_roots();
    }
}

fn session_key(id: &str) -> String {
    format!("local-upload:{id}")
}

fn state_binding(st: &AppState) -> String {
    let mut material = st.secret.clone();
    material.extend_from_slice(b"\0harbor-local-upload-v1");
    hex::encode(crate::auth::sha256_bytes(&material))
}

fn session_owned_by(st: &AppState, headers: &axum::http::HeaderMap, session: &SessionMeta) -> bool {
    // Legacy metadata without a trustworthy owner/state binding cannot be
    // safely claimed by the first authenticated user who knows its id.
    session.state_binding.as_deref() == Some(state_binding(st).as_str())
        && session
            .owner
            .as_ref()
            .is_some_and(|owner| st.session_username(headers).as_ref() == Some(owner))
        && !session_stale(st, &session.session_id)
}

fn session_stale(st: &AppState, id: &str) -> bool {
    let Some(dir) = session_metadata_dir(id) else {
        return true;
    };
    let age = std::fs::metadata(dir.join("meta.json"))
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok());
    age.is_some_and(|age| {
        age > std::time::Duration::from_secs(
            st.settings.upload_session_hours.max(1).saturating_mul(3600),
        )
    })
}

fn uploaded_bytes(session: &SessionMeta) -> u64 {
    let mut indices = session.uploaded.clone();
    indices.sort_unstable();
    indices.dedup();
    indices
        .into_iter()
        .filter_map(|i| {
            expected_chunk_size(
                session.total_size,
                session.chunk_size,
                session.total_chunks,
                i,
            )
        })
        .fold(0u64, u64::saturating_add)
        .min(session.total_size)
}

fn ensure_local_gate(st: &AppState, session: &SessionMeta) -> bool {
    let key = session_key(&session.session_id);
    if st.tasks.get(&key).is_none() {
        let idle = std::time::Duration::from_secs(
            st.settings.upload_session_hours.max(1).saturating_mul(3600),
        );
        let resource = LocalUploadSession {
            activity: crate::task_registry::SessionActivity::new(idle),
            received: uploaded_bytes(session),
            id: session.session_id.clone(),
            task_id: session.task_id.clone(),
            registry: Arc::downgrade(&st.tasks),
        };
        let target = paths::join_path(&session.dir, &session.filename);
        let _ = st.tasks.insert_session(
            key.clone(),
            "chunk_upload_session",
            &target,
            session.total_size,
            resource,
        );
    }
    st.tasks.start_reaper();
    st.tasks
        .try_with_session::<LocalUploadSession, _>(&key, |_| ())
        .is_ok()
}

fn register_local_session(st: &AppState, session: &SessionMeta) -> bool {
    if session.cancelled
        || session.phase != UploadPhase::Receiving
        || !ensure_local_gate(st, session)
    {
        return false;
    }
    // A request can read a manifest immediately before the reaper deletes it.
    // Revalidate under the gate's resource lock before restoring any task;
    // tombstones prevent registration until an older cleanup has finished.
    let key = session_key(&session.session_id);
    let valid = st
        .tasks
        .try_with_session::<LocalUploadSession, _>(&key, |_| {
            let Some(current) = read_meta(&session.session_id) else {
                return false;
            };
            if current.cancelled
                || current.phase != UploadPhase::Receiving
                || current.owner != session.owner
                || current.state_binding != session.state_binding
                || current.created_at != session.created_at
                || session_stale(st, &current.session_id)
            {
                return false;
            }
            let target = paths::join_path(&current.dir, &current.filename);
            if let Some(task_id) = &current.task_id {
                let Some(task) = st.tasks.restore_upload(
                    task_id,
                    &target,
                    current.total_size,
                    uploaded_bytes(&current),
                    current.created_at,
                    &current.session_id,
                ) else {
                    return false;
                };
                if task.cancelled() || task.status().terminal() {
                    return false;
                }
                task.bind_upload_session(&current.session_id);
            }
            true
        });
    match valid {
        Ok(true) => true,
        Ok(false) => {
            st.tasks.discard_idle_session::<LocalUploadSession>(
                &key,
                crate::task_registry::SessionCleanup::Interrupted,
            );
            false
        }
        Err(_) => false,
    }
}

/// Remove only this state's expired durable sessions, while holding the same
/// per-session lease used by chunks and commits. Busy publications are never
/// reaped. Legacy unbound metadata is deliberately not claimed by a new state.
pub(crate) fn reap_persistent_uploads(st: &Arc<AppState>) {
    if !transfers::upload_dir_is_private() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(transfers::upload_dir()) else {
        return;
    };
    let binding = state_binding(st);
    for entry in entries.flatten() {
        let Some(id) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Some(meta) = read_meta(&id) else {
            continue;
        };
        if meta.state_binding.as_deref() != Some(binding.as_str()) || !session_stale(st, &id) {
            continue;
        }
        if !ensure_local_gate(st, &meta) {
            continue;
        }
        let Ok(mut lease) = st
            .tasks
            .acquire_session::<LocalUploadSession>(&session_key(&id))
        else {
            continue;
        };
        if read_meta(&id)
            .is_some_and(|current| current.state_binding.as_deref() == Some(binding.as_str()))
            && session_stale(st, &id)
        {
            lease.discard(crate::task_registry::SessionCleanup::Expired);
        } else {
            lease.finish();
        }
    }
}

pub(crate) fn start_upload_maintenance(st: &Arc<AppState>) {
    let weak = Arc::downgrade(st);
    let _ = std::thread::Builder::new()
        .name("harbor-upload-maintenance".into())
        .spawn(move || loop {
            let Some(st) = weak.upgrade() else {
                break;
            };
            reap_persistent_uploads(&st);
            transfers::clean_orphan_staging(st.settings.upload_session_hours);
            drop(st);
            std::thread::sleep(std::time::Duration::from_secs(300));
        });
}

/// A durable publication marker is set immediately before the final
/// rename/link. If the process dies in that window, never replay a possibly
/// successful commit. The caller must inspect the destination instead.
fn upload_phase_response(
    st: &AppState,
    meta: &SessionMeta,
    allow_completed: bool,
) -> Option<Response> {
    if meta.phase == UploadPhase::Receiving {
        return None;
    }
    let target = paths::join_path(&meta.dir, &meta.filename);
    if meta.phase == UploadPhase::Publishing {
        let busy = match st
            .tasks
            .try_with_session::<LocalUploadSession, _>(&session_key(&meta.session_id), |s| {
                s.activity.busy
            }) {
            Ok(value) => value,
            Err(crate::task_registry::SessionError::Busy) => true,
            Err(crate::task_registry::SessionError::Missing) => false,
        };
        if busy {
            return Some(session_busy());
        }
    }
    if let Some(task) = meta.task_id.as_ref().and_then(|id| {
        st.tasks.restore_upload(
            id,
            &target,
            meta.total_size,
            uploaded_bytes(meta),
            meta.created_at,
            &meta.session_id,
        )
    }) {
        if meta.phase == UploadPhase::Published {
            task.resolve_status(Status::Completed);
        } else {
            task.set_status(Status::Unknown);
        }
    }
    if meta.phase == UploadPhase::Published && allow_completed {
        Some(ok(
            json!({"session_id": meta.session_id, "path": target, "size": meta.total_size,
            "task_id": meta.task_id, "complete": true, "done": true, "success": true}),
        ))
    } else if meta.phase == UploadPhase::Published {
        Some(fail_code(
            StatusCode::CONFLICT,
            1,
            "session_completed",
            "The upload has already completed",
            json!({"path": target, "task_id": meta.task_id}),
        ))
    } else {
        Some(fail_code(
            StatusCode::CONFLICT,
            1,
            "outcome_unknown",
            "Upload outcome is unknown; check the destination before retrying",
            json!({"outcome_unknown": true, "path": target, "task_id": meta.task_id}),
        ))
    }
}

fn session_unavailable() -> Response {
    fail_code(
        StatusCode::NOT_FOUND,
        2,
        "session_not_found",
        "Unknown upload session",
        Value::Null,
    )
}

fn session_busy() -> Response {
    fail_code(
        StatusCode::CONFLICT,
        1,
        "session_busy",
        "Upload session is busy",
        Value::Null,
    )
}

fn registration_failure(
    st: &AppState,
    headers: &axum::http::HeaderMap,
    id: &str,
    allow_completed: bool,
) -> Response {
    if let Some(current) =
        read_meta(id).filter(|current| !current.cancelled && session_owned_by(st, headers, current))
    {
        if let Some(response) = upload_phase_response(st, &current, allow_completed) {
            return response;
        }
        match st
            .tasks
            .try_with_session::<LocalUploadSession, _>(&session_key(id), |session| {
                session.activity.busy
            }) {
            Ok(true) | Err(crate::task_registry::SessionError::Busy) => return session_busy(),
            _ => (),
        }
    }
    session_unavailable()
}

#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
fn acquire_local_session(
    st: &AppState,
    id: &str,
) -> Result<crate::task_registry::SessionLease<LocalUploadSession>, Response> {
    match st
        .tasks
        .acquire_session::<LocalUploadSession>(&session_key(id))
    {
        Ok(lease) => Ok(lease),
        Err(crate::task_registry::SessionError::Busy) => Err(session_busy()),
        Err(crate::task_registry::SessionError::Missing) => Err(session_unavailable()),
    }
}

// The initial metadata read is only a lookup hint. Once the lease is held,
// verify the current persisted state again before any mutation or abort.
#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
fn receiving_under_lease(
    st: &AppState,
    headers: &axum::http::HeaderMap,
    id: &str,
    lease: &mut crate::task_registry::SessionLease<LocalUploadSession>,
    allow_completed: bool,
) -> Result<SessionMeta, Response> {
    let current = match read_meta(id) {
        Some(current) if !current.cancelled && session_owned_by(st, headers, &current) => current,
        _ => {
            lease.finish();
            return Err(session_unavailable());
        }
    };
    if current.phase != UploadPhase::Receiving {
        lease.finish();
        return Err(upload_phase_response(st, &current, allow_completed)
            .unwrap_or_else(session_unavailable));
    }
    Ok(current)
}

#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
fn cancel_local_session(st: &AppState, mut meta_value: SessionMeta) -> Result<bool, Response> {
    // Persist cancellation before deleting staging; if deletion fails or the
    // service crashes, a later restart must not revive this upload.
    meta_value.cancelled = true;
    if !write_meta(&meta_value)
        && !read_meta(&meta_value.session_id).is_some_and(|meta| meta.cancelled)
    {
        return Err(fail(5, "Cannot cancel the upload session", Value::Null));
    }
    if let Some(task) = &meta_value.task_id {
        st.tasks.cancel(task);
    }
    let removed = transfers::destroy_upload_session(&meta_value.session_id);
    transfers::remove_empty_staging_roots();
    Ok(removed)
}

#[allow(clippy::result_large_err)] // HTTP error response is returned directly to Axum.
fn abort_under_lease(
    st: &AppState,
    meta: SessionMeta,
    lease: &mut crate::task_registry::SessionLease<LocalUploadSession>,
) -> Result<bool, Response> {
    match cancel_local_session(st, meta) {
        Ok(removed) => {
            lease.discard(crate::task_registry::SessionCleanup::Aborted);
            Ok(removed)
        }
        Err(error) => {
            lease.finish();
            Err(error)
        }
    }
}

fn restore_upload_tasks(st: &AppState, headers: &axum::http::HeaderMap) {
    if !transfers::upload_dir_is_private() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(transfers::upload_dir()) else {
        return;
    };
    for entry in entries.flatten().take(4096) {
        let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(meta_value) = read_meta(&id) {
            if !meta_value.cancelled
                && session_owned_by(st, headers, &meta_value)
                && upload_phase_response(st, &meta_value, true).is_none()
            {
                let _ = register_local_session(st, &meta_value);
            }
        }
    }
}

fn session_metadata_dir(id: &str) -> Option<PathBuf> {
    if !valid_session_id(id) {
        return None;
    }
    if !transfers::upload_dir_is_private() {
        return None;
    }
    let dir = PathBuf::from(transfers::upload_dir()).join(id);
    crate::tasks::check_private_dir(&dir).ok()?;
    Some(dir)
}

fn session_dir(id: &str) -> Option<PathBuf> {
    let metadata_dir = session_metadata_dir(id)?;
    let meta_path = metadata_dir.join("meta.json");
    let meta_value: SessionMeta = serde_json::from_slice(&std::fs::read(meta_path).ok()?).ok()?;
    if meta_value.staging_dir.is_empty() {
        Some(metadata_dir)
    } else {
        let dir = PathBuf::from(meta_value.staging_dir);
        transfers::staging_session_is_private(&dir, std::ffi::OsStr::new(id)).then_some(dir)
    }
}

fn expected_chunk_size(
    total_size: u64,
    chunk_size: u64,
    total_chunks: u64,
    index: u64,
) -> Option<u64> {
    if index >= total_chunks || chunk_size == 0 {
        return None;
    }
    let offset = index.checked_mul(chunk_size)?;
    let size = total_size.saturating_sub(offset).min(chunk_size);
    (size > 0).then_some(size)
}

fn valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn read_meta(id: &str) -> Option<SessionMeta> {
    let path = session_metadata_dir(id)?.join("meta.json");
    let text = std::fs::read_to_string(path).ok()?;
    let value: SessionMeta = serde_json::from_str(&text).ok()?;
    if value.session_id != id
        || !paths::valid_rename_name(&value.filename)
        || paths::normalize_path(&value.dir).as_deref() != Some(value.dir.as_str())
        || value.chunk_size == 0
        || value.total_chunks != value.total_size.div_ceil(value.chunk_size)
        || value
            .uploaded
            .iter()
            .any(|index| *index >= value.total_chunks)
    {
        return None;
    }
    Some(value)
}

fn write_meta(meta_value: &SessionMeta) -> bool {
    let dir = match session_metadata_dir(&meta_value.session_id) {
        Some(dir) => dir,
        None => return false,
    };
    let text = match serde_json::to_string(meta_value) {
        Ok(text) => text,
        Err(_) => return false,
    };
    crate::private_file::atomic_replace(&dir, "meta.json", text.as_bytes()).is_ok()
}

fn session_param(params: &Params) -> Option<String> {
    params
        .first_of(&["session", "session_id"])
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn target_of(ctx: &Ctx, meta_value: &SessionMeta) -> ApiResult<String> {
    let dir = ctx.write_path(&meta_value.dir)?;
    ctx.create_path(&paths::join_path(&dir, &meta_value.filename))
}

fn space_of(dir: &str) -> Option<u64> {
    meta::space_info(dir).available
}

pub async fn api_storage_api(ctx: &Ctx) -> Response {
    let path = match ctx.params.first_of(&["path"]) {
        Some(value) => match ctx.read_path(&value) {
            Ok(path) => path,
            Err(error) => return error.into_response(),
        },
        None => "/".to_string(),
    };
    let space = meta::space_info(&path);
    let available = space.available.unwrap_or(0);
    ok(json!({
        "path": path,
        "available_bytes": available,
        "total_bytes": space.total.unwrap_or(0),
        "used_bytes": space.used.unwrap_or(0),
        "operation_space_margin": meta::OPERATION_SPACE_MARGIN,
        "has_operation_space": available >= meta::OPERATION_SPACE_MARGIN,
    }))
}

pub async fn api_stat(ctx: &Ctx) -> Response {
    let raw = match ctx.params.first_of(&["path"]) {
        Some(value) => value,
        None => return fail(1, "Invalid path", Value::Null),
    };
    let path = match ctx.read_path(&raw) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    let info = match meta::lstat_or_stat(&path) {
        Some(info) => info,
        None => {
            return fail_code(
                StatusCode::NOT_FOUND,
                2,
                "not_found",
                "No such file or directory",
                json!({ "path": path }),
            )
        }
    };
    let kind = if info.kind == meta::Kind::Directory {
        "dir"
    } else if info.kind == meta::Kind::File {
        "file"
    } else {
        "other"
    };
    ok(json!({
        "path": path,
        "name": paths::path_name(&path),
        "size": info.size.max(0),
        "mtime": info.mtime,
        "mode": meta::mode_string(info.mode),
        "type": kind,
        "mime": meta::mime_for(&path),
        "is_system_path": paths::is_system_path(&path),
    }))
}

fn param_u64(params: &Params, keys: &[&str]) -> Option<u64> {
    let raw = params.first_of(keys)?;
    raw.trim().parse::<u64>().ok()
}

pub async fn api_upload_init(ctx: &Ctx) -> Response {
    if let Err(error) = ctx.require_post() {
        return error.into_response();
    }
    let directory = match ctx
        .params
        .first_of(&["directory", "dir", "target_dir", "path"])
    {
        Some(value) => value,
        None => return fail(1, "Invalid upload directory", Value::Null),
    };
    let directory = match ctx.write_path(&directory) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    let prefs = ctx.prefs();
    if !ctx.upload_base(&directory, &prefs) {
        return fail(1, "Invalid upload directory", Value::Null);
    }
    let filename = match ctx.params.first_of(&["filename", "name"]) {
        Some(value) if paths::valid_rename_name(&value) => value,
        _ => return fail(1, "Invalid file name", Value::Null),
    };
    let owner = match ctx.st.session_username(&ctx.headers) {
        Some(owner) => owner,
        None => {
            return fail_code(
                StatusCode::UNAUTHORIZED,
                1,
                "authentication_required",
                "Authentication required",
                Value::Null,
            )
        }
    };
    let total_size = param_u64(&ctx.params, &["total_size", "size"]).unwrap_or(0);
    let chunk_size = param_u64(&ctx.params, &["chunk_size"])
        .unwrap_or(ctx.st.settings.chunk_size)
        .clamp(64 * 1024, ctx.st.settings.chunk_limit);
    if param_u64(&ctx.params, &["total_size", "size"]).is_none() {
        return fail(1, "Missing total_size", Value::Null);
    }
    let overwrite = ctx.params.get("overwrite").as_deref() == Some("1");
    let preserve_permissions = ctx.params.get("preserve_permissions").as_deref() != Some("0");
    let target = paths::join_path(&directory, &filename);
    if !overwrite && meta::lstat(&target).is_some() {
        return fail_code(
            StatusCode::CONFLICT,
            2,
            "file_exists",
            "The target file already exists",
            json!({ "path": target }),
        );
    }
    if let Some(available) = space_of(&directory) {
        let needed = total_size.saturating_add(meta::OPERATION_SPACE_MARGIN);
        if available < needed {
            return fail_code(
                StatusCode::INSUFFICIENT_STORAGE,
                3,
                "insufficient_storage",
                "Not enough free space in the destination for this upload",
                json!({ "needed": needed, "available": available, "path": directory }),
            );
        }
    }
    let runtime = match transfers::ensure_upload_dir() {
        Some(dir) => dir,
        None => {
            return fail(
                5,
                "Cannot create the upload session metadata directory",
                Value::Null,
            )
        }
    };
    let staging_root =
        match transfers::select_upload_staging_root(total_size, chunk_size, &directory) {
            Some(dir) => dir,
            None => {
                return fail_code(
                    StatusCode::INSUFFICIENT_STORAGE,
                    3,
                    "insufficient_staging_storage",
                    "No writable storage has enough free space to stage this upload",
                    json!({
                        "needed": total_size.saturating_add(meta::OPERATION_SPACE_MARGIN),
                        "destination": directory
                    }),
                )
            }
        };
    let total_chunks = if total_size == 0 {
        0
    } else {
        total_size.div_ceil(chunk_size)
    };
    let session_id = format!("{}-{}", meta::now_secs(), crate::uci::random_hex(6));
    let meta_value = SessionMeta {
        session_id: session_id.clone(),
        dir: directory.clone(),
        filename: filename.clone(),
        total_size,
        chunk_size,
        total_chunks,
        created_at: meta::now_secs(),
        staging_dir: PathBuf::from(&staging_root)
            .join(&session_id)
            .to_string_lossy()
            .into_owned(),
        preserve_permissions,
        overwrite,
        owner: Some(owner),
        state_binding: Some(state_binding(&ctx.st)),
        cancelled: false,
        phase: UploadPhase::Receiving,
        uploaded: Vec::new(),
        task_id: None,
    };
    let metadata_folder = PathBuf::from(&runtime).join(&session_id);
    let data_folder = PathBuf::from(&meta_value.staging_dir);
    if crate::tasks::create_private_dir(&metadata_folder).is_err() {
        return fail(5, "Cannot create the upload session metadata", Value::Null);
    }
    if crate::tasks::create_private_dir(&data_folder).is_err() {
        let _ = std::fs::remove_dir_all(&metadata_folder);
        return fail(
            5,
            "Cannot create the upload session staging area",
            Value::Null,
        );
    }
    if !write_meta(&meta_value)
        || std::fs::File::open(&runtime)
            .and_then(|dir| dir.sync_all())
            .is_err()
        || std::fs::File::open(&staging_root)
            .and_then(|dir| dir.sync_all())
            .is_err()
    {
        let _ = std::fs::remove_dir_all(&metadata_folder);
        let _ = std::fs::remove_dir_all(&data_folder);
        return fail(5, "Cannot create the upload session metadata", Value::Null);
    }
    let transfer = match ctx.st.tasks.try_create_upload(&target, total_size) {
        Some(transfer) => transfer,
        None => {
            let _ = transfers::destroy_upload_session(&session_id);
            return fail_code(
                StatusCode::SERVICE_UNAVAILABLE,
                1,
                "queue_full",
                "Too many active upload sessions",
                Value::Null,
            );
        }
    };
    transfer.bind_upload_session(&session_id);
    let mut meta_value = meta_value;
    meta_value.task_id = Some(transfer.id.clone());
    if !write_meta(&meta_value) || !register_local_session(&ctx.st, &meta_value) {
        transfer.fail("Cannot create the upload session metadata");
        let _ = transfers::destroy_upload_session(&session_id);
        return fail(5, "Cannot create the upload session metadata", Value::Null);
    }
    ok(json!({
        "session_id": session_id,
        "task_id": transfer.id,
        "chunk_size": meta_value.chunk_size,
        "total_chunks": meta_value.total_chunks,
        "total_size": meta_value.total_size,
        "uploaded": [],
        "path": target,
    }))
}

pub async fn api_upload_status(ctx: &Ctx) -> Response {
    let id = match session_param(&ctx.params) {
        Some(id) => id,
        None => return fail(1, "Missing session", Value::Null),
    };
    let meta_value = match read_meta(&id) {
        Some(meta_value) => meta_value,
        None => {
            return fail_code(
                StatusCode::NOT_FOUND,
                2,
                "session_not_found",
                "Unknown upload session",
                json!({ "session_id": id }),
            )
        }
    };
    if !session_owned_by(&ctx.st, &ctx.headers, &meta_value) || meta_value.cancelled {
        return session_unavailable();
    }
    if let Some(response) = upload_phase_response(&ctx.st, &meta_value, true) {
        return response;
    }
    if !register_local_session(&ctx.st, &meta_value) {
        return registration_failure(&ctx.st, &ctx.headers, &id, true);
    }
    let missing: Vec<u64> = (0..meta_value.total_chunks)
        .filter(|index| !meta_value.uploaded.contains(index))
        .collect();
    ok(json!({
        "session_id": meta_value.session_id,
        "dir": meta_value.dir,
        "filename": meta_value.filename,
        "total_size": meta_value.total_size,
        "chunk_size": meta_value.chunk_size,
        "total_chunks": meta_value.total_chunks,
        "uploaded": meta_value.uploaded,
        "missing": missing,
        "complete": meta_value.uploaded.len() as u64 == meta_value.total_chunks,
        "task_id": meta_value.task_id,
    }))
}

struct ChunkWrite {
    session: String,
    index: u64,
    written: u64,
}

// Unlink a unique, private partial even when the request future is dropped.
// The guard is constructed in the blocking open operation itself so that a
// cancelled open cannot create an untracked file after its caller has gone.
struct ChunkTemp(std::path::PathBuf);
impl Drop for ChunkTemp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[allow(clippy::result_large_err)]
async fn write_chunk(
    st: &AppState,
    request: axum::extract::Request,
) -> std::result::Result<ChunkWrite, Response> {
    let uri = request.uri().clone();
    let params = Params::parse(uri.query().unwrap_or(""));
    let id = match session_param(&params) {
        Some(id) => id,
        None => return Err(fail(1, "Missing session", Value::Null)),
    };
    let index = match params
        .first_of(&["index", "chunk"])
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(index) => index,
        None => return Err(fail(1, "Missing chunk index", Value::Null)),
    };
    let meta_value = match read_meta(&id) {
        Some(meta_value) => meta_value,
        None => return Err(fail(2, "Unknown upload session", Value::Null)),
    };
    let expected_chunk = match expected_chunk_size(
        meta_value.total_size,
        meta_value.chunk_size,
        meta_value.total_chunks,
        index,
    ) {
        Some(size) => size,
        None => return Err(fail(1, "Chunk index out of range", Value::Null)),
    };
    let folder = match session_dir(&id) {
        Some(folder) => folder,
        None => return Err(fail(1, "Invalid session", Value::Null)),
    };
    let expected = params
        .first_of(&["sha256", "checksum"])
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty());
    let limit = st.settings.chunk_limit;
    let idle = std::time::Duration::from_secs(st.settings.body_idle_timeout);
    let temp = folder.join(format!("chunk_{index}.part-{}", crate::uci::random_hex(8)));
    let final_path = folder.join(format!("chunk_{index}"));
    let slot = match st.limits.begin_transfer() {
        Some(slot) => slot,
        None => {
            return Err(fail_code(
                StatusCode::SERVICE_UNAVAILABLE,
                1,
                "queue_full",
                "Too many transfers in flight",
                Value::Null,
            ))
        }
    };
    let temp_for_open = temp.clone();
    let (file, _partial) = match tokio::task::spawn_blocking(move || {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_for_open)?;
        Ok::<_, std::io::Error>((file, ChunkTemp(temp_for_open)))
    })
    .await
    {
        Ok(Ok(pair)) => pair,
        _ => return Err(fail(5, "Cannot write the chunk", Value::Null)),
    };
    let mut file = tokio::fs::File::from_std(file);
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    let mut stream = request.into_body().into_data_stream();
    use futures_util::StreamExt;
    let mut written = 0u64;
    loop {
        let next = tokio::time::timeout(idle, stream.next()).await;
        let frame = match next {
            Ok(Some(Ok(bytes))) => bytes,
            Ok(Some(Err(_))) => {
                let _ = tokio::fs::remove_file(&temp).await;
                return Err(fail(1, "Invalid request body", Value::Null));
            }
            Ok(None) => break,
            Err(_) => {
                let _ = tokio::fs::remove_file(&temp).await;
                return Err(fail_code(
                    StatusCode::REQUEST_TIMEOUT,
                    1,
                    "chunk_timeout",
                    "The chunk upload stalled",
                    Value::Null,
                ));
            }
        };
        written += frame.len() as u64;
        if written > limit {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(fail_code(
                StatusCode::PAYLOAD_TOO_LARGE,
                1,
                "payload_too_large",
                "Chunk is larger than the configured limit",
                json!({ "limit": limit }),
            ));
        }
        hasher.update(&frame);
        if file.write_all(&frame).await.is_err() {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(fail(5, "Cannot write the chunk", Value::Null));
        }
    }
    if written != expected_chunk {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(fail_code(
            StatusCode::BAD_REQUEST,
            1,
            "chunk_size_mismatch",
            "Chunk size does not match the declared upload size",
            json!({ "expected": expected_chunk, "actual": written }),
        ));
    }
    if let Some(expected) = expected {
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(fail_code(
                StatusCode::BAD_REQUEST,
                1,
                "checksum_mismatch",
                "Chunk checksum does not match",
                json!({ "expected": expected, "actual": actual }),
            ));
        }
    }
    if file.flush().await.is_err() || file.sync_all().await.is_err() {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(fail(5, "Cannot persist the chunk", Value::Null));
    }
    drop(file);
    if tokio::fs::rename(&temp, &final_path).await.is_err() {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(fail(5, "Cannot store the chunk", Value::Null));
    }
    // Do not advertise a chunk as durable until its renamed directory entry
    // has also been synced. An error leaves the chunk retryable.
    let sync_folder = folder.clone();
    if !matches!(
        tokio::task::spawn_blocking(
            move || std::fs::File::open(sync_folder).and_then(|dir| dir.sync_all())
        )
        .await,
        Ok(Ok(()))
    ) {
        return Err(fail(5, "Cannot persist the chunk", Value::Null));
    }
    drop(slot);
    Ok(ChunkWrite {
        session: id,
        index,
        written,
    })
}

pub async fn api_upload_chunk_stream(
    st: Arc<AppState>,
    request: axum::extract::Request,
) -> Response {
    let query = request.uri().query().unwrap_or("").to_string();
    let params = Params::parse(&query);
    let Some(id) = session_param(&params) else {
        return fail(1, "Missing session", Value::Null);
    };
    let meta_value = match read_meta(&id) {
        Some(meta_value)
            if !meta_value.cancelled && session_owned_by(&st, request.headers(), &meta_value) =>
        {
            meta_value
        }
        _ => return session_unavailable(),
    };
    if let Some(response) = upload_phase_response(&st, &meta_value, false) {
        return response;
    }
    if !register_local_session(&st, &meta_value) {
        return registration_failure(&st, request.headers(), &id, false);
    }
    let mut lease = match acquire_local_session(&st, &id) {
        Ok(lease) => lease,
        Err(response) => return response,
    };
    let meta_value = match receiving_under_lease(&st, request.headers(), &id, &mut lease, false) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if params.get("abort").as_deref() == Some("1") {
        return match abort_under_lease(&st, meta_value, &mut lease) {
            Ok(aborted) => ok(json!({ "aborted": aborted, "session_id": id })),
            Err(response) => response,
        };
    }
    let chunk = match write_chunk(&st, request).await {
        Ok(chunk) => chunk,
        Err(response) => {
            lease.finish();
            return response;
        }
    };
    let mut meta_value = match read_meta(&chunk.session) {
        Some(meta_value) if !meta_value.cancelled => meta_value,
        _ => {
            lease.finish();
            return session_unavailable();
        }
    };
    let new_chunk = !meta_value.uploaded.contains(&chunk.index);
    if new_chunk {
        meta_value.uploaded.push(chunk.index);
        meta_value.uploaded.sort_unstable();
    }
    if !write_meta(&meta_value) {
        lease.finish();
        return fail(5, "Cannot persist the upload session", Value::Null);
    }
    if new_chunk {
        if let Some(task_id) = &meta_value.task_id {
            if let Some(task) = st.tasks.get(task_id) {
                task.set_status(Status::Running);
                task.add(chunk.written);
            }
        }
    }
    let progress = uploaded_bytes(&meta_value);
    st.tasks
        .with_session::<LocalUploadSession, _>(&session_key(&id), |s| s.received = progress);
    lease.finish();
    ok(json!({
        "session_id": meta_value.session_id, "index": chunk.index, "received": chunk.written,
        "uploaded_chunks": meta_value.uploaded.len(), "total_chunks": meta_value.total_chunks,
        "task_id": meta_value.task_id,
    }))
}

#[cfg(test)]
fn upload_crash_hook(point: &str) {
    if std::env::var("HARBOR_UPLOAD_TEST_CRASH").as_deref() == Ok(point) {
        // Exit without unwinding, like an abrupt daemon death. This hook is
        // compiled only into the test harness, never the shipped binary.
        unsafe {
            libc::_exit(73);
        }
    }
}

struct UploadAssembly<'a> {
    folder: &'a Path,
    target: &'a str,
    temp_target: &'a str,
    total_size: u64,
    chunk_size: u64,
    total_chunks: u64,
    preserve_permissions: bool,
    overwrite: bool,
}

fn merge_chunks(
    assembly: UploadAssembly<'_>,
    published: &mut bool,
    before_publish: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<u64> {
    let UploadAssembly {
        folder,
        target,
        temp_target,
        total_size,
        chunk_size,
        total_chunks,
        preserve_permissions,
        overwrite,
    } = assembly;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let temp_path = Path::new(temp_target);
    let mut output = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(temp_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(temp_path)?
        }
        Err(error) => return Err(error),
    };
    let metadata = output.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe upload staging file",
        ));
    }
    let existing_size = metadata.len();
    if existing_size > total_size {
        drop(output);
        let _ = std::fs::remove_file(temp_path);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "assembled upload exceeds declared size",
        ));
    }
    let mut merged_chunks = 0u64;
    let mut merged_size = 0u64;
    while merged_chunks < total_chunks {
        let size = expected_chunk_size(total_size, chunk_size, total_chunks, merged_chunks)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk"))?;
        if merged_size.saturating_add(size) > existing_size {
            break;
        }
        merged_size += size;
        merged_chunks += 1;
    }
    if merged_size != existing_size {
        output.set_len(merged_size)?;
    }
    output.seek(SeekFrom::Start(merged_size))?;
    output.sync_all()?;

    for index in 0..total_chunks {
        let chunk_path = folder.join(format!("chunk_{index}"));
        match std::fs::metadata(&chunk_path) {
            Ok(metadata) => {
                let expected = expected_chunk_size(total_size, chunk_size, total_chunks, index)
                    .ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk")
                    })?;
                if metadata.len() != expected {
                    drop(output);
                    let _ = std::fs::remove_file(temp_path);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "chunk size does not match declared upload size",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && index < merged_chunks => {
            }
            Err(error) => return Err(error),
        }
    }

    for index in 0..merged_chunks {
        let chunk_path = folder.join(format!("chunk_{index}"));
        match std::fs::remove_file(chunk_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    for index in merged_chunks..total_chunks {
        let chunk_path = folder.join(format!("chunk_{index}"));
        let expected = expected_chunk_size(total_size, chunk_size, total_chunks, index)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk"))?;
        let mut input = std::fs::File::open(&chunk_path)?;
        let copied = std::io::copy(&mut input, &mut output)?;
        if copied != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk size does not match declared upload size",
            ));
        }
        output.flush()?;
        output.sync_all()?;
        merged_size = merged_size.saturating_add(copied);
        if output.metadata()?.len() != merged_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "assembled upload size does not match declared size",
            ));
        }
        std::fs::remove_file(chunk_path)?;
    }

    let written = output.metadata()?.len();
    if written != total_size || merged_size != total_size {
        drop(output);
        let _ = std::fs::remove_file(temp_path);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "assembled upload size does not match declared size",
        ));
    }
    output.flush()?;
    output.sync_all()?;
    if overwrite && preserve_permissions {
        if let Some(info) = meta::lstat(target) {
            if info.kind == meta::Kind::File {
                use std::os::unix::fs::PermissionsExt;
                // Apply to the opened file, never through a swapped symlink.
                output.set_permissions(std::fs::Permissions::from_mode(info.mode & 0o7777))?;
                output.sync_all()?;
            }
        }
    }
    // Refuse a staging name that was replaced while we assembled it. This
    // narrows, but does not eliminate, the final path race in writable dirs.
    let fd = output.metadata()?;
    let named = std::fs::symlink_metadata(temp_path)?;
    if !named.is_file() || fd.dev() != named.dev() || fd.ino() != named.ino() || named.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "upload staging file changed",
        ));
    }
    before_publish()?;
    if overwrite {
        std::fs::rename(temp_path, target)?;
        *published = true;
    } else {
        // Atomic create-if-absent; never replace a target created after init.
        std::fs::hard_link(temp_path, target)?;
        *published = true;
        // The target is committed once the link succeeds; cleanup failure
        // must not be reported as if publication had not occurred.
        let _ = std::fs::remove_file(temp_path);
    }
    #[cfg(test)]
    {
        upload_crash_hook("after_publish");
        if std::env::var_os("HARBOR_UPLOAD_TEST_FAIL_AFTER_PUBLISH").is_some() {
            return Err(std::io::Error::other("injected directory sync failure"));
        }
    }
    // A successful file sync alone does not make the rename/link durable.
    let parent = Path::new(target).parent().unwrap_or_else(|| Path::new("/"));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(written)
}

pub async fn api_upload_complete(ctx: &Ctx) -> Response {
    if let Err(error) = ctx.require_post() {
        return error.into_response();
    }
    let id = match session_param(&ctx.params) {
        Some(id) => id,
        None => return fail(1, "Missing session", Value::Null),
    };
    let meta_value = match read_meta(&id) {
        Some(meta_value) => meta_value,
        None => {
            return fail_code(
                StatusCode::NOT_FOUND,
                2,
                "session_not_found",
                "Unknown upload session",
                json!({ "session_id": id }),
            )
        }
    };
    if !session_owned_by(&ctx.st, &ctx.headers, &meta_value) || meta_value.cancelled {
        return session_unavailable();
    }
    if let Some(response) = upload_phase_response(&ctx.st, &meta_value, true) {
        return response;
    }
    if !register_local_session(&ctx.st, &meta_value) {
        return registration_failure(&ctx.st, &ctx.headers, &id, true);
    }
    let mut lease = match acquire_local_session(&ctx.st, &id) {
        Ok(lease) => lease,
        Err(response) => return response,
    };
    let meta_value = match receiving_under_lease(&ctx.st, &ctx.headers, &id, &mut lease, true) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let missing: Vec<u64> = (0..meta_value.total_chunks)
        .filter(|index| !meta_value.uploaded.contains(index))
        .collect();
    if !missing.is_empty() {
        lease.finish();
        return fail_code(
            StatusCode::BAD_REQUEST,
            1,
            "missing_chunks",
            "Some chunks have not been uploaded yet",
            json!({ "missing": missing }),
        );
    }
    let directory = match ctx.write_path(&meta_value.dir) {
        Ok(path) => path,
        Err(error) => {
            lease.finish();
            return error.into_response();
        }
    };
    if !ctx.upload_base(&directory, &ctx.prefs()) {
        lease.finish();
        return fail(1, "Invalid upload directory", Value::Null);
    }
    let target = match target_of(ctx, &meta_value) {
        Ok(path) => path,
        Err(error) => {
            lease.finish();
            return error.into_response();
        }
    };
    let folder = match session_dir(&id) {
        Some(folder) => folder,
        None => {
            lease.finish();
            return fail(1, "Invalid session", Value::Null);
        }
    };
    let merge_temp = Path::new(&target)
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join(format!(".harbor-upload-{id}.part"))
        .to_string_lossy()
        .into_owned();
    if let Err(error) = ctx.create_path(&merge_temp) {
        lease.finish();
        return error.into_response();
    }
    let merge_target = target.clone();
    let temp_for_merge = merge_temp.clone();
    let folder_for_merge = folder.clone();
    let total_size = meta_value.total_size;
    let chunk_size = meta_value.chunk_size;
    let total_chunks = meta_value.total_chunks;
    let preserve_permissions = meta_value.preserve_permissions;
    let overwrite = meta_value.overwrite;
    let registry = ctx.st.tasks.clone();
    let worker_id = id.clone();
    let task_id = meta_value.task_id.clone();
    let mut persisted = meta_value.clone();
    enum MergeFailure {
        Retryable(std::io::Error),
        Unknown,
    }
    let merged = tokio::task::spawn_blocking(move || {
        let mut published = false;
        let assembly = UploadAssembly {
            folder: &folder_for_merge,
            target: &merge_target,
            temp_target: &temp_for_merge,
            total_size,
            chunk_size,
            total_chunks,
            preserve_permissions,
            overwrite,
        };
        let result = merge_chunks(assembly, &mut published, || {
            persisted.phase = UploadPhase::Publishing;
            if write_meta(&persisted) {
                #[cfg(test)]
                upload_crash_hook("before_publish");
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "cannot persist upload publication marker",
                ))
            }
        });
        match result {
            Ok(written) => {
                persisted.phase = UploadPhase::Published;
                if !write_meta(&persisted) {
                    if let Some(task) = task_id.as_ref().and_then(|id| registry.get(id)) {
                        task.set_status(Status::Unknown);
                    }
                    lease.finish();
                    return Err(MergeFailure::Unknown);
                }
                #[cfg(test)]
                upload_crash_hook("after_receipt");
                if let Some(task) = task_id.as_ref().and_then(|id| registry.get(id)) {
                    task.set_total(written);
                    task.set_status(Status::Completed);
                }
                // Keep the small durable Published receipt for the configured
                // retention window: a lost HTTP response can be reconciled
                // after a daemon restart. Bulk chunks can be released now.
                if session_metadata_dir(&worker_id).as_ref() != Some(&folder_for_merge) {
                    let _ = std::fs::remove_dir_all(&folder_for_merge);
                }
                transfers::remove_empty_staging_roots();
                lease.finish();
                Ok(written)
            }
            Err(_error) if published => {
                if let Some(task) = task_id.as_ref().and_then(|id| registry.get(id)) {
                    task.set_status(Status::Unknown);
                }
                lease.finish();
                Err(MergeFailure::Unknown)
            }
            Err(error) => {
                if persisted.phase == UploadPhase::Publishing {
                    persisted.phase = UploadPhase::Receiving;
                    if !write_meta(&persisted) {
                        if let Some(task) = task_id.as_ref().and_then(|id| registry.get(id)) {
                            task.set_status(Status::Unknown);
                        }
                        lease.finish();
                        return Err(MergeFailure::Unknown);
                    }
                }
                lease.finish();
                Err(MergeFailure::Retryable(error))
            }
        }
    })
    .await;
    let written = match merged {
        Ok(Ok(written)) => written,
        Ok(Err(MergeFailure::Retryable(error)))
            if error.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            return fail_code(
                StatusCode::CONFLICT,
                2,
                "file_exists",
                "The target file already exists",
                json!({"path": target}),
            );
        }
        Ok(Err(MergeFailure::Retryable(error)))
            if error.kind() == std::io::ErrorKind::InvalidData =>
        {
            return fail_code(
                StatusCode::BAD_REQUEST,
                1,
                "upload_size_mismatch",
                "The assembled upload size does not match the declared size",
                json!({ "expected": meta_value.total_size }),
            );
        }
        Ok(Err(MergeFailure::Retryable(error))) => {
            return fail(
                5,
                &format!("Cannot assemble the upload: {error}"),
                Value::Null,
            )
        }
        Ok(Err(MergeFailure::Unknown)) | Err(_) => {
            if let Some(mut persisted) = read_meta(&id) {
                if persisted.phase != UploadPhase::Published {
                    persisted.phase = UploadPhase::Publishing;
                    let _ = write_meta(&persisted);
                }
            }
            if let Some(task) = meta_value
                .task_id
                .as_ref()
                .and_then(|id| ctx.st.tasks.get(id))
            {
                task.set_status(Status::Unknown);
            }
            return fail_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                5,
                "outcome_unknown",
                "Upload outcome is unknown; check the destination before retrying",
                json!({"outcome_unknown": true, "path": target}),
            );
        }
    };
    ok(json!({
        "session_id": meta_value.session_id,
        "path": target,
        "size": written,
        "task_id": meta_value.task_id,
    }))
}

pub async fn api_tasks(ctx: &Ctx) -> Response {
    restore_upload_tasks(&ctx.st, &ctx.headers);
    let active = ctx.st.tasks.active();
    ok(
        json!({ "tasks": ctx.st.tasks.list(), "active": active, "upload_dir": transfers::upload_dir() }),
    )
}

pub async fn api_task_cancel(ctx: &Ctx) -> Response {
    if let Err(error) = ctx.require_post() {
        return error.into_response();
    }
    let id = match ctx.params.first_of(&["id", "task_id"]) {
        Some(id) => id,
        None => return fail(1, "Missing task id", Value::Null),
    };
    if ctx.st.tasks.get(&id).is_none() {
        restore_upload_tasks(&ctx.st, &ctx.headers);
    }
    let Some(task) = ctx.st.tasks.get(&id) else {
        return fail_code(
            StatusCode::NOT_FOUND,
            2,
            "task_not_found",
            "Unknown task",
            json!({ "id": id }),
        );
    };
    if task.is_job() {
        if ctx.st.tasks.request_job_cancel(&id) {
            // This acknowledges a request, not a completed cancellation.
            // Keep the task addressable and let clients poll its final result.
            return ok(
                json!({"id": id, "cancel_requested": true, "cancelled": false, "purged": false}),
            );
        }
        return fail_code(
            StatusCode::CONFLICT,
            1,
            "task_not_cancelable",
            "This task cannot be cancelled",
            json!({"id": id}),
        );
    }
    if !task.is_transfer() || task.status().terminal() {
        return fail_code(
            StatusCode::CONFLICT,
            1,
            "task_not_cancelable",
            "This task cannot be cancelled",
            json!({"id": id}),
        );
    }
    if let Some(session_id) = task.upload_session() {
        let meta_value = match read_meta(&session_id) {
            Some(meta_value)
                if !meta_value.cancelled
                    && session_owned_by(&ctx.st, &ctx.headers, &meta_value) =>
            {
                meta_value
            }
            _ => return session_unavailable(),
        };
        if let Some(response) = upload_phase_response(&ctx.st, &meta_value, false) {
            return response;
        }
        if !register_local_session(&ctx.st, &meta_value) {
            return registration_failure(&ctx.st, &ctx.headers, &session_id, false);
        }
        let mut lease = match acquire_local_session(&ctx.st, &session_id) {
            Ok(lease) => lease,
            Err(response) => return response,
        };
        let current =
            match receiving_under_lease(&ctx.st, &ctx.headers, &session_id, &mut lease, false) {
                Ok(value) => value,
                Err(response) => return response,
            };
        if let Err(response) = abort_under_lease(&ctx.st, current, &mut lease) {
            return response;
        }
    } else {
        if !ctx.st.tasks.cancel(&id) {
            return fail_code(
                StatusCode::CONFLICT,
                1,
                "task_not_cancelable",
                "This task cannot be cancelled",
                json!({"id": id}),
            );
        }
        if task.kind == "download" {
            // An accepted signal is not a stopped stream. The producer must
            // release its source/permit and reap its local SSH child first.
            return ok(
                json!({"id": id, "cancel_requested": true, "cancelled": false, "purged": false}),
            );
        }
    }
    let purged = if ctx.params.get("purge").as_deref() == Some("1") {
        ctx.st.tasks.remove(&id)
    } else {
        false
    };
    ok(json!({ "cancelled": true, "id": id, "purged": purged }))
}

pub fn track_download(
    st: &AppState,
    path: &str,
    size: u64,
    body: Body,
    child: Option<crate::remoteio::RemoteDownload>,
    slot: tokio::sync::OwnedSemaphorePermit,
) -> (String, Body) {
    let transfer = st.tasks.create("download", path, size);
    transfer.set_status(Status::Running);
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let (delivered, delivery) = tokio::sync::oneshot::channel();
    let tracked = TrackedBody {
        receiver,
        transfer: transfer.clone(),
        delivered: Some(delivered),
        stop_child: child.as_ref().map(|child| child.stop_handle()),
        ended: false,
    };
    let guard = DownloadGuard {
        transfer: transfer.clone(),
        slot: Some(slot),
        finished: false,
    };
    // The producer owns the source and permit independently of HTTP body
    // polling. Cancellation therefore interrupts a pending source or a full
    // output channel even when the client is backpressured or stops reading.
    tokio::spawn(pump_download(body, child, sender, delivery, guard, size));
    (transfer.id.clone(), Body::from_stream(tracked))
}

struct DownloadGuard {
    transfer: Arc<Transfer>,
    slot: Option<tokio::sync::OwnedSemaphorePermit>,
    finished: bool,
}
impl DownloadGuard {
    fn finish(mut self, status: Status, message: Option<String>) {
        drop(self.slot.take());
        self.transfer.finish_download(status, message);
        self.finished = true;
    }
}
impl Drop for DownloadGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        drop(self.slot.take());
        self.transfer.finish_download(
            Status::Unknown,
            Some("Download worker ended unexpectedly; cleanup could not be confirmed".into()),
        );
    }
}

#[derive(Debug)]
enum DownloadRead {
    Complete,
    Cancelled,
    Interrupted,
    Failed(String),
}

async fn pump_download(
    body: Body,
    child: Option<crate::remoteio::RemoteDownload>,
    sender: tokio::sync::mpsc::Sender<axum::body::Bytes>,
    delivery: tokio::sync::oneshot::Receiver<bool>,
    guard: DownloadGuard,
    total: u64,
) {
    use futures_util::StreamExt;
    let transfer = guard.transfer.clone();
    let mut stream = body.into_data_stream();
    let mut read = 0u64;
    let outcome = loop {
        if read >= total {
            break DownloadRead::Complete;
        }
        let next = tokio::select! {
            biased;
            _ = transfer.wait_cancelled() => break DownloadRead::Cancelled,
            _ = sender.closed() => break DownloadRead::Interrupted,
            next = stream.next() => next,
        };
        let bytes = match next {
            Some(Ok(bytes)) => bytes,
            Some(Err(error)) => break DownloadRead::Failed(error.to_string()),
            None => break DownloadRead::Failed("download interrupted".into()),
        };
        if bytes.is_empty() {
            continue;
        }
        let count = (bytes.len() as u64).min(total - read) as usize;
        let bytes = bytes.slice(..count);
        let sent = tokio::select! {
            biased;
            _ = transfer.wait_cancelled() => break DownloadRead::Cancelled,
            result = sender.send(bytes) => result,
        };
        if sent.is_err() {
            break DownloadRead::Interrupted;
        }
        read += count as u64;
    };
    drop(stream);
    drop(sender); // wake the body even if the source failed or was cancelled

    let force = !matches!(outcome, DownloadRead::Complete) || transfer.cancelled();
    let child_result = match child {
        Some(child) => Some(child.finish(&transfer, force).await),
        None => None,
    };
    if let Some(Err(error)) = child_result.as_ref() {
        return guard.finish(Status::Unknown, Some(error.clone()));
    }
    if transfer.cancelled() {
        return guard.finish(Status::Cancelled, None);
    }
    match outcome {
        DownloadRead::Cancelled => guard.finish(Status::Cancelled, None),
        DownloadRead::Interrupted => {
            guard.finish(Status::Failed, Some("download interrupted".into()))
        }
        DownloadRead::Failed(error) => guard.finish(Status::Failed, Some(error)),
        DownloadRead::Complete => {
            if let Some(Ok((status, timed_out))) = child_result {
                if timed_out {
                    return guard.finish(
                        Status::Failed,
                        Some("SSH download did not exit after streaming".into()),
                    );
                }
                if status != 0 {
                    return guard.finish(
                        Status::Failed,
                        Some("SSH download exited unsuccessfully".into()),
                    );
                }
            }
            let delivered = tokio::select! {
                biased;
                _ = transfer.wait_cancelled() => false,
                result = delivery => result.unwrap_or(false),
            };
            if delivered {
                guard.finish(Status::Completed, None);
            } else if transfer.cancelled() {
                guard.finish(Status::Cancelled, None);
            } else {
                guard.finish(Status::Failed, Some("download interrupted".into()));
            }
        }
    }
}

struct TrackedBody {
    receiver: tokio::sync::mpsc::Receiver<axum::body::Bytes>,
    transfer: Arc<Transfer>,
    delivered: Option<tokio::sync::oneshot::Sender<bool>>,
    stop_child: Option<Arc<std::sync::atomic::AtomicBool>>,
    ended: bool,
}
impl TrackedBody {
    fn complete(&mut self, delivered: bool) {
        if self.ended {
            return;
        }
        self.ended = true;
        if !delivered {
            if let Some(stop) = &self.stop_child {
                stop.store(true, Ordering::Release);
            }
        }
        self.receiver.close();
        if let Some(sender) = self.delivered.take() {
            let _ = sender.send(delivered);
        }
    }
    fn all_delivered(&self) -> bool {
        self.transfer.done.load(Ordering::Relaxed) >= self.transfer.total.load(Ordering::Relaxed)
    }
}
impl futures_util::Stream for TrackedBody {
    type Item = Result<axum::body::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        if self.ended {
            return Poll::Ready(None);
        }
        if self.transfer.cancelled() {
            self.complete(false);
            return Poll::Ready(Some(Err(std::io::Error::other("download cancelled"))));
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                self.transfer.add(bytes.len() as u64);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(None) => {
                let delivered = self.all_delivered();
                self.complete(delivered);
                if delivered {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Err(std::io::Error::other("download interrupted"))))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Drop for TrackedBody {
    fn drop(&mut self) {
        let delivered = !self.transfer.cancelled() && self.all_delivered();
        self.complete(delivered);
    }
}

#[cfg(test)]
// Fixture tests intentionally serialize shared environment/process state across awaits.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, Method, Request};
    use std::os::unix::fs::symlink;

    fn headers(st: &AppState, username: &str) -> HeaderMap {
        let (token, sid, expires) =
            crate::auth::make_session(&st.auth_key().unwrap(), username, 600, "session");
        assert!(st.sessions.register(&sid, crate::meta::now_secs(), expires));
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("{}={token}", crate::auth::COOKIE_NAME)
                .parse()
                .unwrap(),
        );
        headers
    }
    fn state(root: &Path) -> Arc<AppState> {
        AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            root_policy: crate::state::RootPolicy::Allowlist,
            roots: vec![root.join("dest").to_string_lossy().into_owned()],
            body_idle_timeout: 2,
            ..Default::default()
        })
    }
    fn ctx(st: &Arc<AppState>, headers: &HeaderMap, pairs: &[(&str, &str)]) -> Ctx {
        let mut params = Params::default();
        for (key, value) in pairs {
            params.set(key, value);
        }
        Ctx {
            st: st.clone(),
            params,
            method: Method::POST,
            headers: headers.clone(),
        }
    }
    async fn body(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn init(
        st: &Arc<AppState>,
        headers: &HeaderMap,
        dir: &str,
        name: &str,
        size: &str,
    ) -> Value {
        let response = api_upload_init(&ctx(
            st,
            headers,
            &[
                ("dir", dir),
                ("filename", name),
                ("total_size", size),
                ("chunk_size", "65536"),
                ("overwrite", "0"),
            ],
        ))
        .await;
        let (status, value) = body(response).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value["data"].clone()
    }
    fn chunk_request(headers: &HeaderMap, id: &str, index: usize, payload: Body) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/upload_chunk?session={id}&index={index}"))
            .body(payload)
            .unwrap();
        *request.headers_mut() = headers.clone();
        request
    }
    fn root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "harbor-local-upload-test-{}",
            crate::uci::random_hex(8)
        ));
        std::fs::create_dir_all(root.join("dest")).unwrap();
        root
    }

    struct ObservedPending {
        polled: Arc<std::sync::atomic::AtomicBool>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }
    impl futures_util::Stream for ObservedPending {
        type Item = Result<axum::body::Bytes, std::io::Error>;
        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.polled.store(true, Ordering::Release);
            std::task::Poll::Pending
        }
    }
    impl Drop for ObservedPending {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }
    async fn wait_for_status(task: &Transfer, expected: Status) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while task.status() != expected {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected {expected:?}, got {:?}", task.status()));
    }
    async fn wait_for_flag(flag: &std::sync::atomic::AtomicBool) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !flag.load(Ordering::Acquire) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("flag was not set");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_cancellation_wakes_pending_source_even_if_client_never_polls() {
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let permits = st.limits.transfers.available_permits();
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let source = Body::from_stream(ObservedPending {
            polled: polled.clone(),
            dropped: dropped.clone(),
        });
        let (id, response_body) = track_download(
            &st,
            "/pending",
            10,
            source,
            None,
            st.limits.begin_transfer().unwrap(),
        );
        let task = st.tasks.get(&id).unwrap();
        wait_for_flag(&polled).await;
        let (status, response) =
            body(api_task_cancel(&ctx(&st, &alice, &[("task_id", &id), ("purge", "1")])).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["data"]["cancel_requested"], true);
        assert_eq!(response["data"]["cancelled"], false);
        assert_eq!(response["data"]["purged"], false);
        wait_for_status(&task, Status::Cancelled).await;
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(st.limits.transfers.available_permits(), permits);
        assert!(st.tasks.get(&id).is_some());
        assert!(
            axum::body::to_bytes(response_body, 1024).await.is_err(),
            "a cancelled body must not look complete"
        );
        assert_eq!(
            api_task_cancel(&ctx(&st, &alice, &[("task_id", &id)]))
                .await
                .status(),
            StatusCode::CONFLICT
        );
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_cancellation_interrupts_a_full_output_queue() {
        struct FastSource {
            polls: Arc<std::sync::atomic::AtomicUsize>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }
        impl futures_util::Stream for FastSource {
            type Item = Result<axum::body::Bytes, std::io::Error>;
            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                self.polls.fetch_add(1, Ordering::Release);
                std::task::Poll::Ready(Some(Ok(axum::body::Bytes::from(vec![3; 256 * 1024]))))
            }
        }
        impl Drop for FastSource {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }
        let root = root();
        let st = state(&root);
        let permits = st.limits.transfers.available_permits();
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let source = Body::from_stream(FastSource {
            polls: polls.clone(),
            dropped: dropped.clone(),
        });
        let (id, response_body) = track_download(
            &st,
            "/backpressure",
            10 * 1024 * 1024,
            source,
            None,
            st.limits.begin_transfer().unwrap(),
        );
        let task = st.tasks.get(&id).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while polls.load(Ordering::Acquire) < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(st.tasks.cancel(&id));
        wait_for_status(&task, Status::Cancelled).await;
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(st.limits.transfers.available_permits(), permits);
        assert!(
            axum::body::to_bytes(response_body, 1024 * 1024)
                .await
                .is_err(),
            "buffered frames are not delivered after cancellation"
        );
        assert_eq!(task.done.load(Ordering::Relaxed), 0);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_cancellation_waits_for_local_reaper_and_keeps_slot_until_confirmed() {
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let permits = st.limits.transfers.available_permits();
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let source = Body::from_stream(ObservedPending {
            polled: polled.clone(),
            dropped: dropped.clone(),
        });
        let (child, finish_child) = crate::remoteio::RemoteDownload::test_reaper();
        let stop = child.stop_handle();
        let (id, response_body) = track_download(
            &st,
            "/pending-ssh",
            10,
            source,
            Some(child),
            st.limits.begin_transfer().unwrap(),
        );
        let task = st.tasks.get(&id).unwrap();
        wait_for_flag(&polled).await;
        let (status, ack) =
            body(api_task_cancel(&ctx(&st, &alice, &[("task_id", &id), ("purge", "1")])).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ack["data"]["cancelled"], false);
        wait_for_flag(&stop).await;
        wait_for_flag(&dropped).await;
        assert_eq!(
            task.status(),
            Status::Running,
            "request is not proof that the SSH client stopped"
        );
        assert_eq!(task.json()["cancel_requested"], true);
        assert_eq!(task.json()["cancelable"], false);
        assert_eq!(st.limits.transfers.available_permits(), permits - 1);
        finish_child.send(Ok(9)).unwrap();
        wait_for_status(&task, Status::Cancelled).await;
        assert_eq!(st.limits.transfers.available_permits(), permits);
        assert!(axum::body::to_bytes(response_body, 1024).await.is_err());
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_unconfirmed_reaper_is_unknown_and_cannot_be_reported_cancelled() {
        let root = root();
        let st = state(&root);
        let (child, finish_child) = crate::remoteio::RemoteDownload::test_reaper();
        let stop = child.stop_handle();
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        let (id, response_body) = track_download(
            &st,
            "/unknown-ssh",
            1,
            Body::from_stream(pending),
            Some(child),
            st.limits.begin_transfer().unwrap(),
        );
        let task = st.tasks.get(&id).unwrap();
        assert!(st.tasks.cancel(&id));
        wait_for_flag(&stop).await;
        finish_child.send(Err("reaper failure".into())).unwrap();
        wait_for_status(&task, Status::Unknown).await;
        assert!(task.cancelled());
        assert_eq!(task.json()["message"], "reaper failure");
        assert!(axum::body::to_bytes(response_body, 1024).await.is_err());
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_completion_disconnect_and_short_body_release_their_slots() {
        let root = root();
        let st = state(&root);
        let permits = st.limits.transfers.available_permits();
        let (id, response_body) = track_download(
            &st,
            "/complete",
            3,
            Body::from("abc"),
            None,
            st.limits.begin_transfer().unwrap(),
        );
        assert_eq!(
            axum::body::to_bytes(response_body, 100)
                .await
                .unwrap()
                .as_ref(),
            b"abc"
        );
        wait_for_status(&st.tasks.get(&id).unwrap(), Status::Completed).await;
        let (id, response_body) = track_download(
            &st,
            "/short",
            4,
            Body::from("abc"),
            None,
            st.limits.begin_transfer().unwrap(),
        );
        assert!(axum::body::to_bytes(response_body, 100).await.is_err());
        wait_for_status(&st.tasks.get(&id).unwrap(), Status::Failed).await;
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let source = Body::from_stream(ObservedPending {
            polled: polled.clone(),
            dropped: dropped.clone(),
        });
        let (id, response_body) = track_download(
            &st,
            "/disconnect",
            9,
            source,
            None,
            st.limits.begin_transfer().unwrap(),
        );
        let task = st.tasks.get(&id).unwrap();
        wait_for_flag(&polled).await;
        drop(response_body);
        wait_for_status(&task, Status::Failed).await;
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(st.limits.transfers.available_permits(), permits);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[tokio::test(flavor = "multi_thread")]
    async fn e2e_download_ssh_range_empty_and_backpressured_cancellation_reap_client() {
        let _serial = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let target =
            crate::ssh::e2e_target("cfg-e2e-download-cancel", 60).expect("HARBOR_E2E_SSH_PORT");
        let name = format!("/tmp/harbor-download-{}", crate::uci::random_hex(8));
        let small = format!("{name}-small");
        let large = format!("{name}-large");
        crate::remote::run(
            &target,
            &format!(
                "printf abcdef > {}; dd if=/dev/zero of={} bs=1048576 count=32 2>/dev/null",
                crate::ssh::shell_quote(&small),
                crate::ssh::shell_quote(&large)
            ),
            Some(30),
        )
        .unwrap();
        let root = root();
        let st = state(&root);
        let permits = st.limits.transfers.available_permits();
        for (offset, len, expected) in [(2, 3, b"cde".as_slice()), (0, 0, b"".as_slice())] {
            let target = target.clone();
            let path = small.clone();
            let (source, child) = tokio::task::spawn_blocking(move || {
                crate::remoteio::stream_range(&target, &path, offset, len)
            })
            .await
            .unwrap()
            .unwrap();
            let (id, response) = track_download(
                &st,
                &small,
                len,
                source,
                Some(child),
                st.limits.begin_transfer().unwrap(),
            );
            assert_eq!(
                axum::body::to_bytes(response, 100).await.unwrap().as_ref(),
                expected
            );
            wait_for_status(&st.tasks.get(&id).unwrap(), Status::Completed).await;
        }
        let target2 = target.clone();
        let path = large.clone();
        let (source, child) = tokio::task::spawn_blocking(move || {
            crate::remoteio::stream_range(&target2, &path, 0, 32 * 1024 * 1024)
        })
        .await
        .unwrap()
        .unwrap();
        let (id, response) = track_download(
            &st,
            &large,
            32 * 1024 * 1024,
            source,
            Some(child),
            st.limits.begin_transfer().unwrap(),
        );
        let task = st.tasks.get(&id).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            task.status(),
            Status::Running,
            "fixture must actually be backpressured"
        );
        assert!(st.tasks.cancel(&id));
        wait_for_status(&task, Status::Cancelled).await;
        assert_eq!(st.limits.transfers.available_permits(), permits);
        assert!(axum::body::to_bytes(response, 1024 * 1024).await.is_err());
        crate::remote::run(
            &target,
            &format!(
                "rm -f -- {} {}",
                crate::ssh::shell_quote(&small),
                crate::ssh::shell_quote(&large)
            ),
            Some(30),
        )
        .unwrap();
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn download_cancel_and_completion_race_has_one_terminal_winner() {
        for _ in 0..200 {
            let registry = Arc::new(crate::task_registry::TaskRegistry::new(8));
            let task = registry.create("download", "/race", 1);
            task.set_status(Status::Running);
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let cancel_task = task.clone();
            let cancel_barrier = barrier.clone();
            let cancel = std::thread::spawn(move || {
                cancel_barrier.wait();
                cancel_task.cancel()
            });
            let finish_task = task.clone();
            let finish_barrier = barrier.clone();
            let finish = std::thread::spawn(move || {
                finish_barrier.wait();
                finish_task.finish_download(Status::Completed, None);
            });
            barrier.wait();
            let accepted = cancel.join().unwrap();
            finish.join().unwrap();
            assert_eq!(
                task.status(),
                if accepted {
                    Status::Cancelled
                } else {
                    Status::Completed
                }
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn job_cancel_endpoint_acknowledges_request_without_claiming_completion_or_purging() {
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let id = st
            .tasks
            .spawn_cancellable_job(json!({"operation":"copy"}), move |_, control| {
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                assert!(control.requested());
                Err(crate::task_registry::JobFailure {
                    code: 1,
                    message: "cancelled".into(),
                    data: json!({"cancelled":true}),
                })
            })
            .unwrap();
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        let (status, response) =
            body(api_task_cancel(&ctx(&st, &alice, &[("task_id", &id), ("purge", "1")])).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["data"]["cancel_requested"], true);
        assert_eq!(response["data"]["cancelled"], false);
        assert_eq!(response["data"]["purged"], false);
        assert!(st.tasks.get(&id).is_some());
        assert_eq!(st.tasks.job_status(&id).unwrap()["done"], false);
        release_tx.send(()).unwrap();
        for _ in 0..200 {
            if st.tasks.job_status(&id).unwrap()["done"] == json!(true) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(st.tasks.job_status(&id).unwrap()["state"], "cancelled");
        assert_eq!(
            api_task_cancel(&ctx(&st, &alice, &[("task_id", &id)]))
                .await
                .status(),
            StatusCode::CONFLICT
        );
        let _ = std::fs::remove_dir_all(std::path::Path::new(crate::remote::REMOTE_ROOT).join(id));
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validation_and_failed_abort_keep_the_same_usable_gate() {
        let _serial = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let dir = root.join("dest").to_string_lossy().into_owned();
        let started = init(&st, &alice, &dir, "recover.bin", "3").await;
        let id = started["session_id"].as_str().unwrap();
        let key = session_key(id);
        let gate = st.tasks.get(&key).unwrap();
        let (status, missing) =
            body(api_upload_complete(&ctx(&st, &alice, &[("session", id)])).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{missing}");
        assert!(
            Arc::ptr_eq(&gate, &st.tasks.get(&key).unwrap()),
            "normal validation errors must not discard the session"
        );
        let mut lease = acquire_local_session(&st, id).unwrap();
        let current = read_meta(id).unwrap();
        // Replace the manifest with a directory so atomic rename must fail,
        // even under root. Keep the old bytes for recovery.
        let meta = session_metadata_dir(id).unwrap().join("meta.json");
        let backup = meta.with_extension("backup");
        std::fs::rename(&meta, &backup).unwrap();
        std::fs::create_dir(&meta).unwrap();
        assert!(abort_under_lease(&st, current, &mut lease).is_err());
        assert!(
            Arc::ptr_eq(&gate, &st.tasks.get(&key).unwrap()),
            "failed durable cancellation must not discard the gate"
        );
        std::fs::remove_dir(&meta).unwrap();
        std::fs::rename(&backup, &meta).unwrap();
        assert_eq!(
            api_upload_chunk_stream(st.clone(), chunk_request(&alice, id, 0, Body::from("new")))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            api_upload_complete(&ctx(&st, &alice, &[("session", id)]))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            std::fs::read(root.join("dest/recover.bin")).unwrap(),
            b"new"
        );
        let _ = transfers::destroy_upload_session(id);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stale_metadata_cannot_resurrect_a_reaped_gate_or_overwrite_a_receipt() {
        let _serial = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let dir = root.join("dest").to_string_lossy().into_owned();
        let started = init(&st, &alice, &dir, "expired.bin", "3").await;
        let id = started["session_id"].as_str().unwrap();
        let task = started["task_id"].as_str().unwrap();
        let stale = read_meta(id).unwrap();
        let mut lease = acquire_local_session(&st, id).unwrap();
        lease.discard(crate::task_registry::SessionCleanup::Expired);
        assert!(read_meta(id).is_none());
        assert!(st.tasks.remove(task));
        assert!(!register_local_session(&st, &stale));
        assert!(
            st.tasks.get(task).is_none(),
            "must not restore the stale task"
        );
        assert!(
            st.tasks.get(&session_key(id)).is_none(),
            "must not leave a phantom session gate"
        );
        let started = init(&st, &alice, &dir, "receipt.bin", "3").await;
        let id2 = started["session_id"].as_str().unwrap();
        let old = read_meta(id2).unwrap();
        let mut lease = acquire_local_session(&st, id2).unwrap();
        let mut published = old.clone();
        published.phase = UploadPhase::Published;
        assert!(write_meta(&published));
        lease.finish();
        assert!(!register_local_session(&st, &old));
        let (status, receipt) = body(registration_failure(&st, &alice, id2, true)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(receipt["data"]["done"], true);
        assert_eq!(read_meta(id2).unwrap().phase, UploadPhase::Published);
        let _ = transfers::destroy_upload_session(id2);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn chunk_sessions_recover_after_restart_and_preserve_identity_and_progress() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let dir = root.join("dest").to_string_lossy().into_owned();
        let started = init(&st, &alice, &dir, "resume.bin", "70000").await;
        let id = started["session_id"].as_str().unwrap();
        let task_id = started["task_id"].as_str().unwrap();
        let bytes = vec![7u8; 65536];
        for _ in 0..2 {
            let (status, value) = body(
                api_upload_chunk_stream(
                    st.clone(),
                    chunk_request(&alice, id, 0, Body::from(bytes.clone())),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{value}");
        }
        assert_eq!(
            st.tasks.get(task_id).unwrap().done.load(Ordering::Relaxed),
            65536,
            "duplicate retry must not double count"
        );
        // A new app state has an empty in-memory registry but the same stable
        // secret. A new login by the same user can resume the durable session.
        let restarted = state(&root);
        let new_alice = headers(&restarted, "alice");
        let bob = headers(&restarted, "bob");
        let denied = api_upload_status(&ctx(&restarted, &bob, &[("session", id)])).await;
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        let (status, recovered) =
            body(api_upload_status(&ctx(&restarted, &new_alice, &[("session", id)])).await).await;
        assert_eq!(status, StatusCode::OK, "{recovered}");
        assert_eq!(recovered["data"]["uploaded"], json!([0]));
        assert_eq!(
            restarted
                .tasks
                .get(task_id)
                .unwrap()
                .done
                .load(Ordering::Relaxed),
            65536
        );
        let second = vec![9u8; 4464];
        assert_eq!(
            api_upload_chunk_stream(
                restarted.clone(),
                chunk_request(&new_alice, id, 1, Body::from(second.clone()))
            )
            .await
            .status(),
            StatusCode::OK
        );
        let (status, completed) =
            body(api_upload_complete(&ctx(&restarted, &new_alice, &[("session", id)])).await).await;
        assert_eq!(status, StatusCode::OK, "{completed}");
        let mut expected = bytes;
        expected.extend(second);
        assert_eq!(
            std::fs::read(root.join("dest/resume.bin")).unwrap(),
            expected
        );
        assert_eq!(
            restarted.tasks.get(task_id).unwrap().status(),
            Status::Completed
        );
        assert_eq!(read_meta(id).unwrap().phase, UploadPhase::Published);
        assert!(!std::path::Path::new(&read_meta(id).unwrap().staging_dir).exists());
        // A later daemon and the same user can recover an acknowledged
        // publication; a different user/state cannot inspect the receipt.
        let after_restart = state(&root);
        let alice3 = headers(&after_restart, "alice");
        let bob3 = headers(&after_restart, "bob");
        let (_, receipt) =
            body(api_upload_status(&ctx(&after_restart, &alice3, &[("session", id)])).await).await;
        assert_eq!(receipt["data"]["done"], true);
        assert_eq!(receipt["data"]["success"], true);
        assert_eq!(
            api_upload_status(&ctx(&after_restart, &bob3, &[("session", id)]))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        std::fs::write(root.join("dest/resume.bin"), b"changed later").unwrap();
        let (_, repeat) =
            body(api_upload_complete(&ctx(&after_restart, &alice3, &[("session", id)])).await)
                .await;
        assert_eq!(repeat["data"]["done"], true);
        assert_eq!(
            std::fs::read(root.join("dest/resume.bin")).unwrap(),
            b"changed later"
        );
        let foreign_root = root.join("different-state");
        let foreign = state(&foreign_root);
        let foreign_alice = headers(&foreign, "alice");
        assert_eq!(
            api_upload_status(&ctx(&foreign, &foreign_alice, &[("session", id)]))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let _ = transfers::destroy_upload_session(id);
        drop(foreign);
        drop(after_restart);
        drop(restarted);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn chunk_commit_never_clobbers_late_conflicts_or_follows_staging_symlink() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let dir = root.join("dest").to_string_lossy().into_owned();
        let started = init(&st, &alice, &dir, "conflict.bin", "3").await;
        let id = started["session_id"].as_str().unwrap();
        assert_eq!(
            api_upload_chunk_stream(st.clone(), chunk_request(&alice, id, 0, Body::from("new")))
                .await
                .status(),
            StatusCode::OK
        );
        std::fs::write(root.join("dest/conflict.bin"), b"old").unwrap();
        assert_eq!(
            api_upload_complete(&ctx(&st, &alice, &[("session", id)]))
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            std::fs::read(root.join("dest/conflict.bin")).unwrap(),
            b"old"
        );
        std::fs::remove_file(root.join("dest/conflict.bin")).unwrap();
        let (status, result) =
            body(api_upload_complete(&ctx(&st, &alice, &[("session", id)])).await).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(
            std::fs::read(root.join("dest/conflict.bin")).unwrap(),
            b"new"
        );
        let _ = transfers::destroy_upload_session(id);
        let started = init(&st, &alice, &dir, "unsafe.bin", "3").await;
        let id = started["session_id"].as_str().unwrap();
        assert_eq!(
            api_upload_chunk_stream(st.clone(), chunk_request(&alice, id, 0, Body::from("bad")))
                .await
                .status(),
            StatusCode::OK
        );
        let protected = root.join("dest/protected");
        std::fs::write(&protected, b"safe").unwrap();
        let link = root.join("dest").join(format!(".harbor-upload-{id}.part"));
        symlink(&protected, &link).unwrap();
        let (_, rejected) =
            body(api_upload_complete(&ctx(&st, &alice, &[("session", id)])).await).await;
        assert_ne!(rejected["code"], json!(0), "{rejected}");
        assert_eq!(std::fs::read(&protected).unwrap(), b"safe");
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/upload_chunk?session={id}&abort=1"))
            .header(
                axum::http::header::COOKIE,
                alice[axum::http::header::COOKIE].clone(),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            api_upload_chunk_stream(st.clone(), req).await.status(),
            StatusCode::OK
        );
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn durable_commit_markers_do_not_replay_unknown_outcomes() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let dir = root.join("dest").to_string_lossy().into_owned();
        let started = init(&st, &alice, &dir, "phase.bin", "3").await;
        let id = started["session_id"].as_str().unwrap();
        let task_id = started["task_id"].as_str().unwrap();
        assert_eq!(
            api_upload_chunk_stream(st.clone(), chunk_request(&alice, id, 0, Body::from("new")))
                .await
                .status(),
            StatusCode::OK
        );
        let mut lease = st
            .tasks
            .acquire_session::<LocalUploadSession>(&session_key(id))
            .unwrap();
        let mut meta = read_meta(id).unwrap();
        meta.phase = UploadPhase::Publishing;
        assert!(write_meta(&meta));
        let (_, busy) = body(api_upload_status(&ctx(&st, &alice, &[("session", id)])).await).await;
        assert_eq!(busy["error"]["code"], json!("session_busy"), "{busy}");
        lease.discard(crate::task_registry::SessionCleanup::Interrupted);
        // Simulate a new daemon with no live lease and a crash at the commit boundary.
        let restarted = state(&root);
        let alice2 = headers(&restarted, "alice");
        let (status, unknown) =
            body(api_upload_complete(&ctx(&restarted, &alice2, &[("session", id)])).await).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(unknown["data"]["outcome_unknown"], true);
        assert_eq!(
            restarted.tasks.get(task_id).unwrap().status(),
            Status::Unknown
        );
        assert!(
            !root.join("dest/phase.bin").exists(),
            "uncertain publication must never be replayed"
        );
        // A durable published marker is conclusive evidence and resolves the
        // earlier unknown state, without ever writing the target again.
        std::fs::write(root.join("dest/phase.bin"), b"externally changed").unwrap();
        meta.phase = UploadPhase::Published;
        assert!(write_meta(&meta));
        let (status, done) =
            body(api_upload_complete(&ctx(&restarted, &alice2, &[("session", id)])).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(done["data"]["done"], true);
        assert_eq!(
            restarted.tasks.get(task_id).unwrap().status(),
            Status::Completed
        );
        assert_eq!(
            std::fs::read(root.join("dest/phase.bin")).unwrap(),
            b"externally changed"
        );
        assert_eq!(
            api_upload_chunk_stream(
                restarted.clone(),
                chunk_request(&alice2, id, 0, Body::from("new"))
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let _ = transfers::destroy_upload_session(id);
        drop(restarted);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    fn age_metadata(id: &str) {
        use std::os::unix::ffi::OsStrExt;
        let path = session_metadata_dir(id).unwrap().join("meta.json");
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let old = crate::meta::now_secs() - 26 * 3600;
        let times = [libc::timespec {
            tv_sec: old as libc::time_t,
            tv_nsec: 0,
        }; 2];
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) },
            0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stale_sessions_and_receipts_are_reaped_without_touching_busy_or_foreign_sessions() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let dir = root.join("dest").to_string_lossy().into_owned();
        let stale = init(&st, &alice, &dir, "stale", "3").await;
        let busy = init(&st, &alice, &dir, "busy", "3").await;
        let legacy = init(&st, &alice, &dir, "legacy", "3").await;
        let stale_id = stale["session_id"].as_str().unwrap();
        let busy_id = busy["session_id"].as_str().unwrap();
        let legacy_id = legacy["session_id"].as_str().unwrap();
        let mut old = read_meta(legacy_id).unwrap();
        old.owner = None;
        old.state_binding = None;
        assert!(write_meta(&old));
        assert_eq!(
            api_upload_status(&ctx(&st, &alice, &[("session", legacy_id)]))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let mut lease = st
            .tasks
            .acquire_session::<LocalUploadSession>(&session_key(busy_id))
            .unwrap();
        age_metadata(stale_id);
        age_metadata(busy_id);
        age_metadata(legacy_id);
        reap_persistent_uploads(&st);
        assert!(read_meta(stale_id).is_none());
        assert_eq!(
            st.tasks
                .get(stale["task_id"].as_str().unwrap())
                .unwrap()
                .status(),
            Status::Failed
        );
        assert!(
            read_meta(busy_id).is_some(),
            "busy transfer must not be reaped"
        );
        assert!(
            read_meta(legacy_id).is_some(),
            "unbound old metadata must not be claimed or purged automatically"
        );
        lease.finish();
        reap_persistent_uploads(&st);
        assert!(read_meta(busy_id).is_none());
        let _ = transfers::destroy_upload_session(legacy_id);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn idle_registry_reaper_deletes_persistent_chunks() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let dir = root.join("dest").to_string_lossy().into_owned();
        let started = init(&st, &alice, &dir, "idle", "3").await;
        let id = started["session_id"].as_str().unwrap();
        let stage = read_meta(id).unwrap().staging_dir;
        st.tasks
            .with_session::<LocalUploadSession, _>(&session_key(id), |s| {
                s.activity.touched =
                    std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600);
            })
            .unwrap();
        st.tasks.reap_idle_sessions();
        assert!(read_meta(id).is_none());
        assert!(!std::path::Path::new(&stage).exists());
        assert_eq!(
            st.tasks
                .get(started["task_id"].as_str().unwrap())
                .unwrap()
                .status(),
            Status::Failed
        );
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    // Invoked by the parent test in a fresh process so crash and I/O-failure
    // injection cannot affect any concurrently running test.
    #[tokio::test(flavor = "multi_thread")]
    async fn child_upload_crash_point() {
        let Ok(root) = std::env::var("HARBOR_UPLOAD_TEST_ROOT") else {
            return;
        };
        let id = std::env::var("HARBOR_UPLOAD_TEST_SESSION").unwrap();
        let st = state(std::path::Path::new(&root));
        let alice = headers(&st, "alice");
        let (status, value) =
            body(api_upload_complete(&ctx(&st, &alice, &[("session", &id)])).await).await;
        if std::env::var_os("HARBOR_UPLOAD_TEST_FAIL_AFTER_PUBLISH").is_some() {
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{value}");
            assert_eq!(value["data"]["outcome_unknown"], true);
        } else {
            panic!("crash hook did not trigger: {status}: {value}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn process_crashes_at_publication_boundaries_never_replay_a_commit() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for point in [
            "before_publish",
            "after_publish",
            "after_receipt",
            "sync_failure",
        ] {
            let root = root();
            let st = state(&root);
            let alice = headers(&st, "alice");
            let dir = root.join("dest").to_string_lossy().into_owned();
            let started = init(&st, &alice, &dir, "crash.bin", "3").await;
            let id = started["session_id"].as_str().unwrap().to_string();
            assert_eq!(
                api_upload_chunk_stream(
                    st.clone(),
                    chunk_request(&alice, &id, 0, Body::from("new"))
                )
                .await
                .status(),
                StatusCode::OK
            );
            drop(st);
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("api::transferops::tests::child_upload_crash_point")
                .arg("--nocapture")
                .env("HARBOR_UPLOAD_TEST_ROOT", &root)
                .env("HARBOR_UPLOAD_TEST_SESSION", &id);
            if point == "sync_failure" {
                command.env("HARBOR_UPLOAD_TEST_FAIL_AFTER_PUBLISH", "1");
            } else {
                command.env("HARBOR_UPLOAD_TEST_CRASH", point);
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(if point == "sync_failure" { 0 } else { 73 }),
                "{point}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let restarted = state(&root);
            let alice = headers(&restarted, "alice");
            let (status, response) =
                body(api_upload_complete(&ctx(&restarted, &alice, &[("session", &id)])).await)
                    .await;
            if point == "after_receipt" {
                assert_eq!(status, StatusCode::OK, "{point}: {response}");
                assert_eq!(response["data"]["done"], true);
            } else {
                assert_eq!(status, StatusCode::CONFLICT, "{point}: {response}");
                assert_eq!(response["data"]["outcome_unknown"], true);
            }
            let destination = root.join("dest/crash.bin");
            if point == "before_publish" {
                assert!(!destination.exists());
            } else {
                assert_eq!(std::fs::read(&destination).unwrap(), b"new");
            }
            // A reconciliation request must never publish/rewrite an unknown
            // outcome, even if an external actor changes the destination.
            std::fs::write(&destination, b"external").unwrap();
            let _ = api_upload_complete(&ctx(&restarted, &alice, &[("session", &id)])).await;
            assert_eq!(std::fs::read(&destination).unwrap(), b"external");
            let _ = transfers::destroy_upload_session(&id);
            drop(restarted);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_or_cancelled_chunk_does_not_leak_partial_files() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let dir = root.join("dest").to_string_lossy().into_owned();
        let started = init(&st, &alice, &dir, "partial.bin", "3").await;
        let id = started["session_id"].as_str().unwrap().to_string();
        let folder = session_dir(&id).unwrap();
        let permits: Vec<_> = (0..st.settings.max_transfers)
            .map(|_| st.limits.begin_transfer().unwrap())
            .collect();
        let denied =
            api_upload_chunk_stream(st.clone(), chunk_request(&alice, &id, 0, Body::from("new")))
                .await;
        assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            std::fs::read_dir(&folder).unwrap().count(),
            0,
            "no temporary file before permit"
        );
        drop(permits);
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        let request = chunk_request(&alice, &id, 0, Body::from_stream(pending));
        let st2 = st.clone();
        let worker = tokio::spawn(async move { api_upload_chunk_stream(st2, request).await });
        for _ in 0..100 {
            if std::fs::read_dir(&folder).unwrap().count() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(std::fs::read_dir(&folder).unwrap().count(), 1);
        worker.abort();
        let _ = worker.await;
        assert_eq!(
            std::fs::read_dir(&folder).unwrap().count(),
            0,
            "cancelled partial must be unlinked"
        );
        assert_eq!(
            api_upload_chunk_stream(st.clone(), chunk_request(&alice, &id, 0, Body::from("new")))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            api_upload_complete(&ctx(&st, &alice, &[("session", &id)]))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            std::fs::read(root.join("dest/partial.bin")).unwrap(),
            b"new"
        );
        let _ = transfers::destroy_upload_session(&id);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_is_serialized_against_an_inflight_chunk_and_survives_restart() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = root();
        let st = state(&root);
        let alice = headers(&st, "alice");
        let dir = root.join("dest").to_string_lossy().into_owned();
        let started = init(&st, &alice, &dir, "cancel.bin", "3").await;
        let id = started["session_id"].as_str().unwrap().to_string();
        let task_id = started["task_id"].as_str().unwrap().to_string();
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        let request = chunk_request(&alice, &id, 0, Body::from_stream(pending));
        let st2 = st.clone();
        let worker = tokio::spawn(async move { api_upload_chunk_stream(st2, request).await });
        for _ in 0..100 {
            if st
                .tasks
                .with_session::<LocalUploadSession, _>(&session_key(&id), |s| s.activity.busy)
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(st
            .tasks
            .with_session::<LocalUploadSession, _>(&session_key(&id), |s| s.activity.busy)
            .unwrap());
        assert_eq!(
            api_task_cancel(&ctx(&st, &alice, &[("task_id", &task_id)]))
                .await
                .status(),
            StatusCode::CONFLICT
        );
        worker.abort();
        let _ = worker.await;
        let (status, cancelled) =
            body(api_task_cancel(&ctx(&st, &alice, &[("task_id", &task_id)])).await).await;
        assert_eq!(status, StatusCode::OK, "{cancelled}");
        assert_eq!(cancelled["data"]["cancelled"], json!(true));
        let restarted = state(&root);
        let new_alice = headers(&restarted, "alice");
        assert_eq!(
            api_upload_status(&ctx(&restarted, &new_alice, &[("session", &id)]))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert!(!root.join("dest/cancel.bin").exists());
        drop(restarted);
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }
}
