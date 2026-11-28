use crate::meta::{self, Kind};
use crate::params::Params;
use crate::paths::{self, join_path, normalize_path, parent_path, path_name};
use crate::reply::{fail, fail_code, ok};
use crate::state::{AppState, Ctx};
use axum::extract::{FromRequest, Multipart, Request};
use axum::http::{Method, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::Arc;

pub const TEXT_READ_LIMIT: u64 = 4 * 1024 * 1024;

pub async fn api_read_text(ctx: &Ctx) -> Response {
    let _editor_permit = match ctx.st.editor_io.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            return fail_code(
                StatusCode::SERVICE_UNAVAILABLE,
                1,
                "queue_full",
                "Text editor is busy",
                Value::Null,
            )
        }
    };
    let path = match ctx.read_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let st = match meta::stat(&path) {
        Some(m) if m.kind == Kind::File => m,
        _ => return fail(2, "Not a regular file", Value::Null),
    };
    if st.size as u64 > TEXT_READ_LIMIT {
        return fail(
            4,
            &format!(
                "The file is larger than {} MB, open it with the hex editor",
                TEXT_READ_LIMIT / (1024 * 1024)
            ),
            json!({ "path": path, "size": st.size, "too_large": true }),
        );
    }
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(_) => return fail(3, "Open failed", Value::Null),
    };
    let is_text = meta::looks_like_text(&bytes);
    let content = String::from_utf8_lossy(&bytes).into_owned();
    ok(json!({
        "path": path,
        "content": content,
        "size": st.size,
        "mtime": st.mtime,
        "is_text": is_text,
        "numeric_permissions": meta::numeric_permissions(st.mode)
    }))
}

pub async fn api_save_text(ctx: &Ctx) -> Response {
    let path = match ctx.write_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let content = ctx
        .params
        .get("content")
        .unwrap_or_default()
        .replace('\u{200b}', "");
    if let Some(st) = meta::lstat(&path) {
        if st.kind == Kind::Directory {
            return fail(2, "Target is a directory", Value::Null);
        }
    }
    let mode = meta::lstat(&path).map(|m| m.mode & 0o7777).unwrap_or(0o644);
    let parent = parent_path(&path).unwrap_or_else(|| "/".to_string());
    let staging = match crate::api::fsops::create_staging_directory(&parent, ".harbor-editor.") {
        Some(s) => s,
        None => return fail(3, "Cannot create temporary file", Value::Null),
    };
    let tmp = format!("{staging}/data");
    let written = write_new_file(&tmp, content.as_bytes(), mode);
    if !written || fs::rename(&tmp, &path).is_err() {
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_dir(&staging);
        return fail(4, "Write failed", Value::Null);
    }
    let _ = fs::remove_dir(&staging);
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(mode));
    let nst = meta::stat(&path);
    ok(json!({
        "path": path,
        "size": nst.map(|m| m.size).unwrap_or(0),
        "mtime": nst.map(|m| m.mtime).unwrap_or(0)
    }))
}

fn write_new_file(path: &str, data: &[u8], mode: u32) -> bool {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
    {
        Ok(mut f) => f.write_all(data).is_ok() && f.flush().is_ok(),
        Err(_) => false,
    }
}

pub fn upload_target(
    ctx: &Ctx,
    dir: &str,
    relative: &str,
    directory: bool,
    create_missing: bool,
) -> Option<String> {
    let cleaned = relative.replace('\\', "/");
    let rel = normalize_path(&format!("/{cleaned}"))?;
    if rel == "/" {
        return None;
    }
    let mut cur = ctx.write_path(dir).ok()?;
    let parts: Vec<&str> = rel.trim_start_matches('/').split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if !paths::valid_component(part) {
            return None;
        }
        let last = i == parts.len() - 1;
        let candidate = join_path(&cur, part);
        match meta::lstat(&candidate) {
            Some(m) => {
                if m.kind == Kind::Directory {
                    let actual = paths::canonical(&candidate).unwrap_or_else(|| candidate.clone());
                    ctx.write_path(&actual).ok()?;
                    cur = actual;
                    continue;
                }
                if m.kind == Kind::Symlink {
                    let resolved = paths::canonical(&candidate)?;
                    if meta::stat(&resolved)
                        .map(|s| s.kind == Kind::Directory)
                        .unwrap_or(false)
                    {
                        ctx.write_path(&resolved).ok()?;
                        cur = resolved;
                        continue;
                    }
                }
                if last && !directory {
                    ctx.write_path(&candidate).ok()?;
                    return Some(candidate);
                }
                return None;
            }
            None => {
                let candidate = ctx.create_path(&candidate).ok()?;
                if last && !directory {
                    return Some(candidate);
                }
                if !create_missing {
                    cur = candidate;
                    continue;
                }
                meta::mkdir_p(&candidate);
                let actual = paths::canonical(&candidate).unwrap_or_else(|| candidate.clone());
                if meta::stat(&actual)
                    .map(|m| m.kind == Kind::Directory)
                    .unwrap_or(false)
                {
                    ctx.write_path(&actual).ok()?;
                    cur = actual;
                } else {
                    return None;
                }
            }
        }
    }
    if directory {
        Some(cur)
    } else {
        None
    }
}

pub async fn api_upload_check(ctx: &Ctx) -> Response {
    let dir = match ctx.params.first_of(&["target_dir", "path"]) {
        Some(raw) => match ctx.write_path(&raw) {
            Ok(path) => path,
            Err(error) => return error.into_response(),
        },
        None => return fail(1, "Invalid upload directory", Value::Null),
    };
    let prefs = ctx.prefs();
    if !ctx.upload_base(&dir, &prefs) {
        return fail(1, "Invalid upload directory", Value::Null);
    }
    let names = ctx.params.path_array("names").unwrap_or_default();
    let directories = ctx.params.path_array("directories").unwrap_or_default();
    let mut total_size = ctx.params.int("total_size").unwrap_or(0);
    if total_size < 0 {
        total_size = 0;
    }
    let mut conflicts = Vec::new();
    let mut directory_conflicts = Vec::new();
    let mut blocked = Vec::new();
    for name in &names {
        match upload_target(ctx, &dir, name, false, false) {
            None => blocked.push(name.clone()),
            Some(target) => {
                if meta::lstat(&target).is_some() {
                    conflicts.push(name.clone());
                }
            }
        }
    }
    for name in &directories {
        match upload_target(ctx, &dir, name, true, false) {
            None => blocked.push(name.clone()),
            Some(target) => {
                if meta::lstat(&target).is_some() {
                    directory_conflicts.push(name.clone());
                }
            }
        }
    }
    let space = meta::space_info(&dir);
    let available = space.available.unwrap_or(0);
    let enough = space.available.is_none() || available >= total_size as u64;
    ok(json!({
        "path": dir,
        "target_dir": dir,
        "conflicts": conflicts,
        "directory_conflicts": directory_conflicts,
        "blocked_conflicts": blocked,
        "enough_space": enough,
        "space_message": if enough { "" } else { "Not enough free space for this upload" },
        "total_size": total_size,
        "available_bytes": available,
        "operation_space_margin": meta::OPERATION_SPACE_MARGIN
    }))
}

pub fn handle_upload_directory(
    st: Arc<AppState>,
    params: &Params,
    headers: &axum::http::HeaderMap,
) -> Response {
    let ctx = Ctx {
        st,
        params: params.clone(),
        method: Method::GET,
        headers: headers.clone(),
    };
    let dir = match ctx.params.first_of(&["target_dir", "path"]) {
        Some(raw) => match ctx.write_path(&raw) {
            Ok(path) => path,
            Err(error) => return error.into_response(),
        },
        None => return fail(1, "Invalid upload directory", Value::Null),
    };
    let prefs = ctx.prefs();
    if !ctx.upload_base(&dir, &prefs) {
        return fail(1, "Invalid upload directory", Value::Null);
    }
    let relative = ctx.params.get("relative_path").unwrap_or_default();
    match upload_target(&ctx, &dir, &relative, true, true) {
        Some(path) => ok(json!({ "path": path, "directory": true })),
        None => fail(1, "Invalid directory path", Value::Null),
    }
}

struct UploadSink {
    staging: Option<String>,
    tmp: String,
    fd: Option<fs::File>,
    written: u64,
    mode: u32,
}

struct StagingGuard(Option<String>);

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

pub async fn api_upload_multipart(st: Arc<AppState>, params: Params, req: Request) -> Response {
    let ctx = Ctx {
        st: st.clone(),
        params: params.clone(),
        method: req.method().clone(),
        headers: req.headers().clone(),
    };
    let dir = match ctx.params.first_of(&["target_dir", "path"]) {
        Some(raw) => match ctx.write_path(&raw) {
            Ok(path) => path,
            Err(error) => return error.into_response(),
        },
        None => return fail(1, "Invalid upload directory", Value::Null),
    };
    if !ctx.upload_base(&dir, &ctx.prefs()) {
        return fail(1, "Invalid upload directory", Value::Null);
    }
    let overwrite = params.get("overwrite").as_deref() == Some("1");
    let preserve = params.get("preserve_permissions").as_deref() != Some("0");
    let expected: i64 = params.int("expected_size").unwrap_or(-1);
    let relative_param = params.get("relative_path");
    if expected >= 0 {
        if let Some(available) = meta::space_info(&dir).available {
            let needed = expected as u64;
            if available < needed {
                return fail_code(
                    StatusCode::INSUFFICIENT_STORAGE,
                    3,
                    "insufficient_storage",
                    "Not enough free space for this upload",
                    json!({ "needed": needed, "available": available, "path": dir }),
                );
            }
        }
    }

    let mut multipart = match Multipart::from_request(req, &()).await {
        Ok(m) => m,
        Err(_) => return fail(1, "Invalid or interrupted upload request", Value::Null),
    };

    let mut sink: Option<UploadSink> = None;
    let mut target_path: Option<String> = None;
    let mut files_seen = 0;
    let mut error: Option<String> = None;
    let mut staging_guard = StagingGuard(None);

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => {
                error = Some("invalid or interrupted upload request".to_string());
                break;
            }
        };
        let file_name = field.file_name().map(|s| s.to_string());
        let is_file = file_name.is_some() || sink.is_some();
        if !is_file {
            continue;
        }
        files_seen += 1;
        if files_seen > 1 {
            error = Some("multiple files in one upload are not supported".to_string());
            break;
        }
        let relative = relative_param
            .clone()
            .or_else(|| file_name.clone())
            .unwrap_or_else(|| "upload.bin".to_string());
        let mut target = match upload_target(&ctx, &dir, &relative, false, true) {
            Some(t) => t,
            None => {
                error = Some("invalid upload path or conflicting type".to_string());
                break;
            }
        };
        if meta::lstat(&target).is_some() && !overwrite {
            let parent = parent_path(&target).unwrap_or_else(|| "/".to_string());
            target = match meta::unique_target(&parent, &path_name(&target), &[], false)
                .and_then(|path| ctx.create_path(&path).ok())
            {
                Some(path) => path,
                None => {
                    error = Some("cannot allocate a unique name".to_string());
                    break;
                }
            };
        }
        let mode = if preserve {
            meta::lstat(&target)
                .filter(|m| m.kind == Kind::File)
                .map(|m| m.mode & 0o7777)
                .unwrap_or(0o644)
        } else {
            0o644
        };
        let parent = parent_path(&target).unwrap_or_else(|| "/".to_string());
        let staging = match crate::api::fsops::create_staging_directory(&parent, ".harbor-upload.")
        {
            Some(s) => s,
            None => {
                error = Some("cannot create target file".to_string());
                break;
            }
        };
        staging_guard.0 = Some(staging.clone());
        let tmp = format!("{staging}/data");
        let fd = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
        {
            Ok(f) => f,
            Err(_) => {
                let _ = fs::remove_dir(&staging);
                error = Some("cannot create target file".to_string());
                break;
            }
        };
        target_path = Some(target);
        sink = Some(UploadSink {
            staging: Some(staging),
            tmp,
            fd: Some(fd),
            written: 0,
            mode,
        });

        let mut field = field;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    if let Some(s) = sink.as_mut() {
                        if let Some(f) = s.fd.as_mut() {
                            if f.write_all(&chunk).is_err() {
                                error = Some("write failed (disk full?)".to_string());
                                break;
                            }
                            s.written += chunk.len() as u64;
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    error = Some("invalid or interrupted upload request".to_string());
                    break;
                }
            }
        }
        if error.is_some() {
            break;
        }
    }

    let sink = match sink {
        Some(s) => s,
        None => {
            return match error {
                Some(e) => fail(1, &e, Value::Null),
                None => fail(1, "No file received", Value::Null),
            }
        }
    };
    let written = sink.written;
    let staging = sink.staging.clone().unwrap_or_default();
    let tmp = sink.tmp.clone();
    drop(sink.fd);
    if error.is_none() && expected >= 0 && written as i64 != expected {
        error = Some("uploaded size mismatch".to_string());
    }
    if error.is_none() {
        let target = target_path.clone().unwrap_or_default();
        if fs::set_permissions(&tmp, fs::Permissions::from_mode(sink.mode)).is_err()
            && meta::lstat(&target).is_some()
        {
            error = Some("cannot preserve existing file permissions".to_string());
        }
        if error.is_none() && fs::rename(&tmp, &target).is_err() {
            error = Some("finalize failed".to_string());
        }
    }
    if error.is_some() {
        let _ = fs::remove_file(&tmp);
    }
    if !staging.is_empty() {
        let _ = fs::remove_dir(&staging);
    }
    match error {
        Some(e) => fail(1, &e, Value::Null),
        None => match target_path {
            Some(path) => ok(json!({ "path": path, "size": written })),
            None => fail(1, "No file received", Value::Null),
        },
    }
}

pub async fn api_save_editor_upload(
    st: Arc<AppState>,
    params: Params,
    headers: axum::http::HeaderMap,
    req: Request,
) -> Response {
    let ctx = Ctx {
        st,
        params,
        method: Method::POST,
        headers,
    };
    let ctx = &ctx;
    let target = match ctx.write_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if let Some(st) = meta::lstat(&target) {
        if st.kind == Kind::Directory {
            return fail(2, "Target is a directory", Value::Null);
        }
    }
    let mode = meta::lstat(&target)
        .map(|m| m.mode & 0o7777)
        .unwrap_or(0o644);
    let parent = parent_path(&target).unwrap_or_else(|| "/".to_string());
    let staging = match crate::api::fsops::create_staging_directory(&parent, ".harbor-editor.") {
        Some(s) => s,
        None => return fail(3, "Cannot create temporary file", Value::Null),
    };
    let _staging_guard = StagingGuard(Some(staging.clone()));
    let tmp = format!("{staging}/data");
    let mut out = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(_) => {
            let _ = fs::remove_dir(&staging);
            return fail(3, "Cannot create temporary file", Value::Null);
        }
    };

    let content_type = ctx.header("content-type").unwrap_or_default();
    let mut written: u64 = 0;
    let mut failure: Option<String> = None;

    if content_type.starts_with("multipart/form-data") {
        let mut multipart = match Multipart::from_request(req, &()).await {
            Ok(m) => m,
            Err(_) => {
                let _ = fs::remove_file(&tmp);
                let _ = fs::remove_dir(&staging);
                return fail(1, "invalid or interrupted upload request", Value::Null);
            }
        };
        'outer: loop {
            match multipart.next_field().await {
                Ok(Some(mut field)) => loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            if out.write_all(&chunk).is_err() {
                                failure = Some("write failed".to_string());
                                break 'outer;
                            }
                            written += chunk.len() as u64;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            failure = Some("invalid or interrupted upload request".to_string());
                            break 'outer;
                        }
                    }
                },
                Ok(None) => break,
                Err(_) => {
                    failure = Some("invalid or interrupted upload request".to_string());
                    break;
                }
            }
        }
    } else {
        use futures_util::StreamExt;
        let mut stream = req.into_body().into_data_stream();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    if out.write_all(&bytes).is_err() {
                        failure = Some("write failed".to_string());
                        break;
                    }
                    written += bytes.len() as u64;
                }
                Err(_) => {
                    failure = Some("invalid or interrupted upload request".to_string());
                    break;
                }
            }
        }
    }
    if out.flush().is_err() && failure.is_none() {
        failure = Some("write failed".to_string());
    }
    drop(out);

    if failure.is_none() && fs::rename(&tmp, &target).is_err() {
        failure = Some("finalize failed".to_string());
    }
    if failure.is_some() {
        let _ = fs::remove_file(&tmp);
    }
    let _ = fs::remove_dir(&staging);
    match failure {
        Some(e) => fail(1, &e, Value::Null),
        None => {
            let st = meta::stat(&target);
            ok(json!({
                "path": target,
                "size": st.map(|m| m.size).unwrap_or(written as i64),
                "mtime": st.map(|m| m.mtime).unwrap_or(0)
            }))
        }
    }
}
