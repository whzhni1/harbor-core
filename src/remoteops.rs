use crate::params::Params;
use crate::paths::{join_path, normalize_path, parent_path, path_name, valid_component};
use crate::remote::{authenticated_target, checked_device, shell_quote, Device, RemoteError};
use crate::state::AppState;
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

pub const MAX_TEXT_BYTES: usize = 8 * 1024 * 1024;

type RResult<T> = Result<T, RemoteError>;

fn data_of(params: &Params) -> RResult<Value> {
    match params.get("rpc_data") {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(&raw).map_err(|_| RemoteError::new("Invalid operation payload"))
        }
        _ => Ok(json!({})),
    }
}

fn collect_paths(value: &Value, key: &str, result: &mut Vec<String>) {
    match value {
        Value::String(raw)
            if matches!(key, "paths" | "sources") && raw.trim_start().starts_with('[') =>
        {
            if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
                collect_paths(&parsed, key, result);
            }
        }
        Value::String(path)
            if matches!(
                key,
                "path"
                    | "directory"
                    | "target_dir"
                    | "source"
                    | "destination"
                    | "from"
                    | "to"
                    | "paths"
                    | "sources"
            ) && path.starts_with('/') =>
        {
            result.push(path.clone())
        }
        Value::Array(items) => {
            for item in items {
                collect_paths(item, key, result);
            }
        }
        Value::Object(map) => {
            for (name, item) in map {
                collect_paths(item, name, result);
            }
        }
        _ => {}
    }
}

fn ensure_system_access(
    st: &Arc<AppState>,
    params: &Params,
    device: &Device,
    target: &crate::ssh::Target,
    data: &Value,
) -> RResult<()> {
    let mut candidates = Vec::new();
    collect_paths(data, "", &mut candidates);
    if candidates.len() > 8192 {
        return Err(RemoteError::new("Too many paths to validate safely"));
    }
    let paths = candidates
        .iter()
        .map(|candidate| check_path(candidate))
        .collect::<RResult<Vec<_>>>()?;
    if paths.is_empty() {
        return Ok(());
    }
    let resolved = crate::remote::resolve_policy_paths(Some(target), &paths)?;
    let session_id = params.get("__system_session_id").unwrap_or_default();
    for (path, actual) in paths.iter().zip(resolved.iter()) {
        if let Some(missing) = st.system_access.missing_path(
            (!session_id.is_empty()).then_some(session_id.as_str()),
            &device.id,
            path,
            actual,
        ) {
            return Err(RemoteError::system_access_required_at(missing, &device.id));
        }
    }
    Ok(())
}

fn text_field(data: &Value, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn operation_path(data: &Value) -> RResult<String> {
    let path = text_field(data, "path");
    if !path.is_empty() {
        return Ok(path);
    }
    let directory = text_field(data, "target_dir");
    let name = check_name(&text_field(data, "name"))?;
    if directory.is_empty() {
        return Ok(path);
    }
    Ok(join_path(&directory, &name))
}

fn valid_mode(mode: &str) -> bool {
    mode.len() == 3 && mode.chars().all(|c| ('0'..='7').contains(&c))
}

fn check_path(path: &str) -> RResult<String> {
    normalize_path(path).ok_or_else(|| RemoteError::new("Invalid path"))
}

fn configured_root_paths(action: &str, data: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    let push = |paths: &mut Vec<String>, value: Option<&str>| {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            paths.push(value.to_string());
        }
    };
    match action {
        "list"
        | "detect_type"
        | "read_text"
        | "save_text"
        | "save_editor_upload"
        | "chmod"
        | "sha256"
        | "search"
        | "thumbnail_generate_start"
        | "archive_list" => {
            push(&mut paths, data.get("path").and_then(Value::as_str));
        }
        "create_directory" | "create_file" => {
            push(
                &mut paths,
                data.get("path")
                    .or_else(|| data.get("target_dir"))
                    .and_then(Value::as_str),
            );
        }
        "rename" => {
            if let Some(path) = data.get("path").and_then(Value::as_str) {
                push(&mut paths, Some(path));
                if let (Some(parent), Some(name)) = (
                    parent_path(path),
                    data.get("new_name")
                        .or_else(|| data.get("name"))
                        .and_then(Value::as_str),
                ) {
                    push(&mut paths, Some(&join_path(&parent, name)));
                }
            }
        }
        "delete" | "batch_delete" => {
            push(&mut paths, data.get("path").and_then(Value::as_str));
            paths.extend(string_list_param(data, "paths"));
        }
        "upload_check" => push(
            &mut paths,
            data.get("target_dir")
                .or_else(|| data.get("path"))
                .and_then(Value::as_str),
        ),
        "archive_create_start" => {
            push(&mut paths, data.get("target_dir").and_then(Value::as_str));
            paths.extend(string_list_param(data, "sources"));
        }
        "archive_extract_start" => {
            push(&mut paths, data.get("path").and_then(Value::as_str));
            push(
                &mut paths,
                data.get("target_dir")
                    .or_else(|| data.get("directory"))
                    .and_then(Value::as_str),
            );
        }
        _ => {}
    }
    paths
}

fn safe_name(name: &str) -> String {
    if name.starts_with('-') {
        format!("./{name}")
    } else {
        name.to_string()
    }
}

fn check_name(name: &str) -> RResult<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 255 || !valid_component(name) {
        return Err(RemoteError::new("Invalid name"));
    }
    Ok(name.to_string())
}

fn detect(target: &crate::ssh::Target, path: &str) -> RResult<Value> {
    let path = check_path(path)?;
    let stat = crate::remoteio::remote_stat(target, &path)?;
    if stat.kind == "directory" {
        return Ok(
            json!({"path": path, "type": "directory", "kind": "directory",
            "preview": "none", "mime": Value::Null, "size": -1, "mtime": stat.mtime}),
        );
    }
    if stat.kind != "file" {
        return Err(RemoteError::new("Path is not a regular file"));
    }
    let (kind, mime) = match crate::meta::known_content_type(&path) {
        Some(known) => known,
        None => {
            let script = format!("head -c 4096 -- {}", shell_quote(&path));
            let sample = crate::remote::run(target, &script, Some(20))?;
            crate::meta::sampled_content_type(&sample)
        }
    };
    let mode = u32::from_str_radix(&stat.mode, 8)
        .map_err(|_| RemoteError::new("Cannot stat the remote file"))?;
    Ok(
        json!({"path": path, "type": kind, "kind": kind, "mime": mime,
        "size": stat.size, "mtime": stat.mtime,
        "numeric_permissions": crate::meta::numeric_permissions(mode), "editable": true}),
    )
}

fn checked_rpc_task_status(
    st: &AppState,
    task_id: &str,
    operation: &str,
    device_id: &str,
) -> RResult<Value> {
    let mut status = crate::remote::task_status(st, task_id)?;
    if status["state"] == json!("gone") {
        status["state"] = json!("unknown");
        status["success"] = json!(false);
        status["message"] = json!("Task status is unknown");
    } else if status["operation"] != json!(operation)
        || status.get("device_id").or_else(|| status.get("device")) != Some(&json!(device_id))
    {
        return Err(RemoteError::new("Invalid task for this device"));
    }
    Ok(status)
}

pub fn rpc(st: &Arc<AppState>, params: &Params) -> RResult<Value> {
    let action = params.get("rpc_action").unwrap_or_default();
    let device = checked_device(
        st,
        &params.get("device_id").unwrap_or_default(),
        params.get("device_revision").as_deref(),
    )?;
    crate::remote::ensure_trusted_pub(st, &device)?;
    let target = authenticated_target(st, &device);
    let data = data_of(params)?;
    ensure_system_access(st, params, &device, &target, &data)?;
    let root_paths = configured_root_paths(&action, &data);
    crate::remote::enforce_configured_roots(st, Some(&target), &root_paths)?;
    let value = match action.as_str() {
        "list" => list(st, &target, &data)?,
        "detect_type" => detect(&target, &text_field(&data, "path"))?,
        "read_text" => read_text(&target, &data)?,
        "save_text" | "save_editor_upload" => save_text(&target, &data)?,
        "create_directory" => json!({ "path": directories(&target, &data)? }),
        "create_file" => json!({ "path": create_file(&target, &data)? }),
        "rename" => json!({ "path": rename(st, &target, params, &data)? }),
        "delete" | "batch_delete" => delete(st, &target, params, &data)?,
        "chmod" => chmod(st, &target, params, &data)?,
        "upload_check" => upload_check(&target, &data)?,
        "sha256" => sha256(&target, &data)?,
        "search" => search(&target, &data)?,
        "archive_status" | "thumbnail_generate_status" | "package_install_status" => {
            let operation = match action.as_str() {
                "archive_status" => "archive",
                "thumbnail_generate_status" => "thumbnail",
                _ => "package_install",
            };
            match data.get("task_id").and_then(Value::as_str) {
                Some(task_id) => checked_rpc_task_status(st, task_id, operation, &device.id)?,
                None => json!({ "state": "idle", "done": true, "success": false }),
            }
        }
        "thumbnail_generate_start" => thumbnail_start(st, &target, params, &data)?,
        "package_install_start" => install_packages(st, &device, &packages_of(&data)?)?,
        "tool_install_start" => match data.get("tool").and_then(Value::as_str) {
            Some(tool) => install_tool(st, &device, tool)?,
            None => install_packages(st, &device, &packages_of(&data)?)?,
        },
        "archive_list" => archive_list(&target, &data)?,
        "archive_create_start" | "archive_extract_start" => {
            archive_start(st, &target, params, &action, &data)?
        }
        other => {
            return Err(RemoteError::with_data(
                format!("This operation is not available on remote devices: {other}"),
                json!({ "unsupported": other, "remote_unsupported": true }),
            ))
        }
    };
    let mut value = value;
    if let Value::Object(map) = &mut value {
        map.insert("device_id".into(), Value::String(device.id.clone()));
        map.insert(
            "device_revision".into(),
            Value::String(device.revision.clone()),
        );
    }
    Ok(value)
}

pub fn agent_ready(device: &crate::remote::Device) -> Value {
    json!({
        "ready": true,
        "agent": "native-ssh",
        "install_needed": false,
        "missing": [],
        "device_revision": device.revision,
        "packages": [],
    })
}

fn is_directory_size(data: &Value) -> bool {
    match data.get("directory_size") {
        Some(value) => value.as_str() == Some("1") || value.as_i64() == Some(1),
        None => false,
    }
}

fn append_task_log(dir: &Path, line: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("log"))
    {
        let _ = writeln!(file, "{line}");
    }
}

fn directory_size_remote(target: &crate::ssh::Target, path: &str) -> RResult<Value> {
    require_device_tools(target, &["stat"])?;
    let script = format!(
        "d={}\nif [ ! -d \"$d\" ]; then exit 43; fi\nidentity=$(stat -c \'%d:%i\' \"$d\" 2>/dev/null || gnu-stat -c \'%d:%i\' \"$d\" 2>/dev/null || /usr/libexec/stat-coreutils -c \'%d:%i\' \"$d\" 2>/dev/null || busybox stat -c \'%d:%i\' \"$d\" 2>/dev/null || echo \'-\')\nout=$(find \"$d\" -type f -exec stat -c \'%s\' {{}} + 2>/dev/null | awk \'{{s+=$1; n+=1}} END{{printf \"%d %d\", s+0, n+0}}\')\nsize=${{out%% *}}\nfiles=${{out##* }}\ntotal=$(find \"$d\" -type f 2>/dev/null | wc -l)\nfolders=$(find \"$d\" -mindepth 1 -type d 2>/dev/null | wc -l)\nprintf \'RESULT %s %s %s %s %s\\n\' \"$identity\" \"${{size:-0}}\" \"${{files:-0}}\" \"${{total:-0}}\" \"${{folders:-0}}\"\n",
        shell_quote(path)
    );
    let raw = crate::remote::run(target, &script, Some(120))?;
    let text = String::from_utf8_lossy(&raw);
    let line = text
        .lines()
        .find(|line| line.starts_with("RESULT "))
        .ok_or_else(|| RemoteError::new("Invalid remote directory response"))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return Err(RemoteError::new("Invalid remote directory response"));
    }
    let identity = fields[1].to_string();
    let size = fields[2].parse::<i64>().unwrap_or(0);
    let files = fields[3].parse::<i64>().unwrap_or(0);
    let total = fields[4].parse::<i64>().unwrap_or(files);
    let folders = fields[5].parse::<i64>().unwrap_or(0);
    let skipped = total.saturating_sub(files);
    Ok(json!({
        "path": path,
        "size": size,
        "files": files,
        "directories": [],
        "skipped": skipped,
        "links": 0,
        "identity": identity,
        "folders": folders,
    }))
}

fn list(st: &AppState, target: &crate::ssh::Target, data: &Value) -> RResult<Value> {
    let path = check_path(&text_field(data, "path"))?;
    if is_directory_size(data) {
        return directory_size_remote(target, &path);
    }
    let mut listing = crate::remote::listing(target, &path, false)?;
    if st.root_policy_config().policy != crate::state::RootPolicy::Unrestricted {
        listing.items.retain(|item| {
            !item.is_symlink
                || crate::remote::enforce_configured_root(st, Some(target), &item.path).is_ok()
        });
    }
    Ok(listing_json(st, target, &listing, false))
}

pub(crate) fn listing_json(
    st: &AppState,
    target: &crate::ssh::Target,
    listing: &crate::remote::Listing,
    capacity: bool,
) -> Value {
    let mut value = listing.json(capacity);
    if capacity || st.prefs().enable_thumbnails != 1 {
        return value;
    }
    let blocks: Vec<String> = listing
        .items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            if !matches!(item.kind.as_str(), "file" | "symlink")
                || crate::meta::classify_preview(&item.path, &item.name) != "image"
            {
                return None;
            }
            let cache = shell_quote(&thumbnail_cache_path(
                target, &item.path, item.size, item.mtime,
            ));
            Some(format!(
                "if [ -f {cache} ] && [ ! -L {cache} ]; then printf '%s\\n' {index}; fi"
            ))
        })
        .collect();
    for script in crate::ssh::chunk_script(&blocks) {
        // Thumbnail availability is optional; a failed cache probe must not
        // make the directory itself unreadable.
        let script = format!("{}\n{}", thumbnail_cache_read_guard(target), script);
        if let Ok(raw) = crate::remote::run(target, &script, Some(20)) {
            for index in String::from_utf8_lossy(&raw)
                .lines()
                .filter_map(|line| line.parse::<usize>().ok())
            {
                if let Some(item) = value["items"]
                    .as_array_mut()
                    .and_then(|items| items.get_mut(index))
                {
                    item["thumbnail_available"] = json!(true);
                }
            }
        }
    }
    value
}

fn read_text(target: &crate::ssh::Target, data: &Value) -> RResult<Value> {
    let path = check_path(&text_field(data, "path"))?;
    let info = detect(target, &path)?;
    if info["kind"] == json!("directory") {
        return Err(RemoteError::new("Cannot read a directory"));
    }
    let size = info["size"].as_i64().unwrap_or(0);
    if size > MAX_TEXT_BYTES as i64 {
        return Err(RemoteError::new("File is too large to open in the editor"));
    }
    let raw = crate::remote::run(target, &format!("cat {}", shell_quote(&path)), Some(60))?;
    let content = String::from_utf8_lossy(&raw).to_string();
    let truncated = raw.len() > MAX_TEXT_BYTES;
    Ok(json!({
        "path": path,
        "content": content,
        "size": size,
        "truncated": truncated,
        "eol": if content.contains('\r') { "crlf" } else { "lf" },
    }))
}

/// Build a one-shot upload whose temporary name is independent of the user
/// filename. The complete byte count is checked before atomic publication.
fn text_write_script(path: &str, size: usize, mode: Option<&str>, nonce: &str) -> RResult<String> {
    let parent = parent_path(path).ok_or_else(|| RemoteError::new("Invalid path"))?;
    let stage = join_path(&parent, &format!(".harbor-editor-{nonce}"));
    let requested = mode.filter(|value| valid_mode(value)).unwrap_or("");
    Ok(format!(
        r#"set -e
umask 077
dest={dest}; stage={stage}; mode={mode}
mkdir -- "$stage"
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
[ ! -d "$dest" ] || [ -L "$dest" ] || exit 45
if [ -z "$mode" ]; then
 mode=644
 if [ -f "$dest" ] && [ ! -L "$dest" ]; then
  mode=$(stat -c '%a' -- "$dest" 2>/dev/null || gnu-stat -c '%a' -- "$dest" 2>/dev/null || /usr/libexec/stat-coreutils -c '%a' -- "$dest" 2>/dev/null || busybox stat -c '%a' -- "$dest" 2>/dev/null) || exit 46
 fi
fi
case "$mode" in ''|*[!0-7]*) exit 46;; esac
cat > "$stage/data"
sz=$(wc -c < "$stage/data") || exit 47
[ "$sz" -eq {size} ] || exit 47
chmod "$mode" "$stage/data"
mv -fT -- "$stage/data" "$dest"
"#,
        dest = shell_quote(path),
        stage = shell_quote(&stage),
        mode = shell_quote(requested)
    ))
}

/// Drain diagnostics while writing, enforce a bounded deadline and never
/// replay a mutation whose SSH result was lost. `expected` is also enforced
/// by the remote script, so an interrupted upload cannot publish a prefix.
fn drive_text_writer(
    mut child: crate::ssh::ByteStream,
    bytes: Vec<u8>,
    timeout: std::time::Duration,
) -> RResult<()> {
    use std::io::Write;
    use std::time::Instant;
    let input = child.stdin.take();
    let output = child.stdout.take();
    let errors = child.stderr.take();
    let kill = |child: &mut crate::ssh::ByteStream| {
        let _ = child.kill();
        let _ = child.wait();
    };
    let (Some(mut input), Some(output), Some(errors)) = (input, output, errors) else {
        kill(&mut child);
        return Err(RemoteError::with_data(
            "Remote write outcome is unknown; inspect the destination before retrying",
            json!({"outcome_unknown": true}),
        ));
    };
    let writer = std::thread::spawn(move || input.write_all(&bytes));
    let stdout = std::thread::spawn(move || crate::ssh::capture_bounded(output, 4096));
    let stderr = std::thread::spawn(move || crate::ssh::capture_bounded(errors, 64 * 1024));
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(code)) => break (Some(code), false),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(std::time::Duration::from_millis(25))
            }
            _ => {
                kill(&mut child);
                break (None, true);
            }
        }
    };
    let sent = writer.join().ok().is_some_and(|result| result.is_ok());
    let _ = stdout.join();
    let detail = stderr
        .join()
        .map(|(data, _, _)| String::from_utf8_lossy(&data).trim().to_string())
        .unwrap_or_default();
    let code = status;
    if timed_out || !sent || code.is_none() || code == Some(255) {
        return Err(RemoteError::with_data(
            "Remote write outcome is unknown; inspect the destination before retrying",
            json!({"outcome_unknown": true}),
        ));
    }
    if code != Some(0) {
        return Err(RemoteError::with_data(
            if detail.is_empty() {
                "Cannot write to the target".into()
            } else {
                detail
            },
            json!({"exit_code": code}),
        ));
    }
    Ok(())
}

fn write_bytes(
    target: &crate::ssh::Target,
    path: &str,
    bytes: &[u8],
    mode: Option<&str>,
) -> RResult<()> {
    let script = text_write_script(path, bytes.len(), mode, &crate::uci::random_hex(16))?;
    if crate::ssh::script_exec_len(&script) > crate::ssh::SCRIPT_EXEC_LIMIT {
        return Err(RemoteError::new("Path is too long to write safely"));
    }
    let space = crate::remote::workspace_pub(target)?;
    let child = crate::ssh::spawn_upload(target, &space, &script).map_err(RemoteError::new)?;
    drive_text_writer(child, bytes.to_vec(), std::time::Duration::from_secs(120))
}

fn save_text(target: &crate::ssh::Target, data: &Value) -> RResult<Value> {
    let path = check_path(&text_field(data, "path"))?;
    if path == "/" {
        return Err(RemoteError::new("Invalid path"));
    }
    let content = text_field(data, "content");
    if content.len() > MAX_TEXT_BYTES {
        return Err(RemoteError::new("Content is too large"));
    }
    write_bytes(target, &path, content.as_bytes(), None)?;
    Ok(json!({ "path": path, "size": content.len() }))
}

fn directories(target: &crate::ssh::Target, data: &Value) -> RResult<String> {
    let path = check_path(&operation_path(data)?)?;
    let _parent = parent_path(&path).ok_or_else(|| RemoteError::new("Invalid path"))?;
    let _name = check_name(&path_name(&path))?;
    crate::ssh::sftp::mkdir(target, &path, 0o755).map_err(crate::remote::map_sftp)?;
    Ok(path)
}

fn create_file(target: &crate::ssh::Target, data: &Value) -> RResult<String> {
    let path = check_path(&operation_path(data)?)?;
    let parent = parent_path(&path).ok_or_else(|| RemoteError::new("Invalid path"))?;
    let name = check_name(&path_name(&path))?;
    // `set -C` prevents clobbering a file or symlink created after the check.
    // Do not proceed in a different cwd if `cd` fails.
    let script = format!(
        "set -e\ncd {}\n[ ! -e {name} ] && [ ! -L {name} ] || exit 45\nset -C\n: > {name}",
        shell_quote(&parent),
        name = shell_quote(&safe_name(&name))
    );
    crate::remote::run_mutating_once(target, &script, Some(30))?;
    Ok(path)
}

fn mark_partial(mut error: RemoteError) -> RemoteError {
    if !error.data.is_object() {
        error.data = json!({});
    }
    error.data["partial"] = json!(true);
    error.message = format!(
        "Operation may be partial; inspect the affected paths before retrying: {}",
        error.message
    );
    error
}

fn rename(
    st: &AppState,
    target: &crate::ssh::Target,
    params: &Params,
    data: &Value,
) -> RResult<String> {
    let path = check_path(&text_field(data, "path"))?;
    if path == "/" {
        return Err(RemoteError::new("Cannot rename root"));
    }
    let name = data
        .get("new_name")
        .or_else(|| data.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let name = check_name(name)?;
    let parent = parent_path(&path).ok_or_else(|| RemoteError::new("Invalid path"))?;
    let destination = join_path(&parent, &name);
    if destination == path {
        return Ok(path);
    }
    let roots = vec![path.clone()];
    let tree = remote_tree_paths(target, &roots)?;
    authorize_remote_paths(st, target, params, &tree)?;
    let destinations: Vec<_> = tree
        .iter()
        .map(|entry| format!("{}{}", destination, &entry[path.len()..]))
        .collect();
    authorize_remote_paths(st, target, params, &destinations)?;
    crate::remote::ensure_remote_no_nested_mounts(target, &roots)?;
    crate::ssh::sftp::rename_exclusive(target, &path, &destination)
        .map_err(crate::remote::map_sftp)?;
    Ok(destination)
}

fn delete(
    st: &AppState,
    target: &crate::ssh::Target,
    params: &Params,
    data: &Value,
) -> RResult<Value> {
    let paths: Vec<String> = if data.get("paths").is_some() {
        string_list_param(data, "paths")
            .iter()
            .map(|value| check_path(value))
            .collect::<RResult<_>>()?
    } else {
        vec![check_path(&text_field(data, "path"))?]
    };
    if paths.is_empty() || paths.len() > 4096 || paths.iter().any(|path| path == "/") {
        return Err(RemoteError::new("Invalid selection"));
    }
    let tree = remote_tree_paths(target, &paths)?;
    authorize_remote_paths(st, target, params, &tree)?;
    crate::remote::ensure_remote_no_nested_mounts(target, &paths)?;
    if paths.len() == 1 {
        if let Ok(meta) = crate::ssh::sftp::stat(target, &paths[0]) {
            if meta.kind != "directory" {
                crate::ssh::sftp::remove_file(target, &paths[0])
                    .map_err(crate::remote::map_sftp)?;
                return Ok(json!({ "deleted": paths.len(), "paths": paths }));
            }
        }
    }
    let lines: Vec<String> = paths
        .iter()
        .map(|path| format!("rm -rf -- {}", shell_quote(path)))
        .collect();
    for script in crate::ssh::chunk_script(&lines) {
        crate::remote::run_mutating_once(target, &format!("set -e\n{script}"), Some(3600))
            .map_err(mark_partial)?;
    }
    Ok(json!({ "deleted": paths.len(), "paths": paths }))
}

fn chmod(
    st: &AppState,
    target: &crate::ssh::Target,
    params: &Params,
    data: &Value,
) -> RResult<Value> {
    let path = check_path(&text_field(data, "path"))?;
    let mode = text_field(data, "mode");
    if !valid_mode(&mode) {
        return Err(RemoteError::new("Invalid permission"));
    }
    if data.get("recursive").and_then(Value::as_str) != Some("1") {
        let bits =
            u32::from_str_radix(&mode, 8).map_err(|_| RemoteError::new("Invalid permission"))?;
        crate::ssh::sftp::chmod(target, &path, bits).map_err(crate::remote::map_sftp)?;
        return Ok(json!({ "path": path, "mode": mode }));
    }
    let directories = data
        .get("recursive_directories")
        .and_then(Value::as_str)
        .unwrap_or("1");
    if !matches!(directories, "0" | "1") {
        return Err(RemoteError::new("Invalid value"));
    }
    let directory_check = format!(
        "[ ! -L {path} ] && [ -d {path} ]",
        path = shell_quote(&path)
    );
    crate::remote::run(target, &directory_check, Some(20))
        .map_err(|_| RemoteError::new("Not a directory"))?;
    let roots = vec![path.clone()];
    let tree = remote_tree_paths(target, &roots)?;
    authorize_remote_paths(st, target, params, &tree)?;
    crate::remote::ensure_remote_no_nested_mounts(target, &roots)?;
    let file_expression = if directories == "1" {
        "! -type d ! -type l"
    } else {
        "-type f"
    };
    let mut script = format!(
        "set -e\nfind {path} {file_expression} -exec chmod 0{mode} {{}} \\;",
        path = shell_quote(&path)
    );
    if directories == "1" {
        script.push_str(&format!(
            "\nfind {path} -depth -type d -exec chmod 0{mode} {{}} \\;",
            path = shell_quote(&path)
        ));
    }
    crate::remote::run_mutating_once(target, &script, Some(300)).map_err(mark_partial)?;
    Ok(
        json!({"path": path, "mode": mode, "recursive": true, "recursive_directories": directories == "1"}),
    )
}

fn string_list_param(data: &Value, key: &str) -> Vec<String> {
    match data.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(|value| value.to_string())
            .collect(),
        Some(Value::String(raw)) => serde_json::from_str(raw).unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn upload_check(target: &crate::ssh::Target, data: &Value) -> RResult<Value> {
    let dir = check_path(&text_field(data, "target_dir"))
        .or_else(|_| check_path(&text_field(data, "path")))?;
    let names = string_list_param(data, "names");
    let directories = string_list_param(data, "directories");
    let mut blocked = Vec::new();
    let mut checks: Vec<(String, String, bool)> = Vec::new();
    let mut check_lines: Vec<String> = Vec::new();
    for (kind, items, is_file) in [
        ("F", names.as_slice(), true),
        ("D", directories.as_slice(), false),
    ] {
        for item in items {
            match crate::paths::safe_join_relative(&dir, item) {
                Some(path) => {
                    let index = checks.len();
                    check_lines.push(format!(
                        "\nif [ -e {path} ] || [ -L {path} ]; then printf '{kind}{index}\\n'; fi",
                        path = shell_quote(&path),
                    ));
                    checks.push((kind.to_string(), item.clone(), is_file));
                }
                None => blocked.push(item.clone()),
            }
        }
    }
    let header = format!("cd {} || exit 44\ndf -Pk . | tail -n 1", shell_quote(&dir));
    let mut lines = vec![header];
    lines.extend(check_lines);
    let chunks = crate::ssh::chunk_script(&lines);
    let mut available: u64 = 0;
    let mut conflicts = Vec::new();
    let mut directory_conflicts = Vec::new();
    for (position, script) in chunks.iter().enumerate() {
        let raw = crate::remote::run(target, script, Some(30))?;
        let output = String::from_utf8_lossy(&raw);
        let mut lines = output.lines();
        if position == 0 {
            let df = lines.next().unwrap_or_default();
            let fields: Vec<&str> = df.split_whitespace().collect();
            available = fields
                .get(3)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_mul(1024);
        }
        for line in lines {
            if line.len() < 2 {
                continue;
            }
            let kind = &line[..1];
            let index = match line[1..].parse::<usize>() {
                Ok(index) => index,
                Err(_) => continue,
            };
            let Some((expected_kind, name, is_file)) = checks.get(index) else {
                continue;
            };
            if expected_kind.as_str() == kind {
                if *is_file {
                    conflicts.push(name.clone());
                } else {
                    directory_conflicts.push(name.clone());
                }
            }
        }
    }
    let total_size = data
        .get("total_size")
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
        .unwrap_or(0);
    let enough = available >= total_size;
    Ok(json!({
        "path": dir,
        "target_dir": dir,
        "conflicts": conflicts,
        "directory_conflicts": directory_conflicts,
        "blocked_conflicts": blocked,
        "enough_space": enough,
        "space_message": if enough {
            ""
        } else {
            "Not enough free space for this upload"
        },
        "total_size": total_size,
        "available_bytes": available,
        "operation_space_margin": 0,
    }))
}

fn sha256(target: &crate::ssh::Target, data: &Value) -> RResult<Value> {
    let path = check_path(&text_field(data, "path"))?;
    let raw = crate::remote::run(
        target,
        &format!("sha256sum {}", shell_quote(&path)),
        Some(900),
    )?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let hash = text.split_whitespace().next().unwrap_or("").to_string();
    if hash.len() != 64 {
        return Err(RemoteError::new("Cannot hash the file"));
    }
    Ok(json!({ "path": path, "sha256": hash }))
}

fn search(target: &crate::ssh::Target, data: &Value) -> RResult<Value> {
    let path = check_path(&text_field(data, "path"))?;
    let pattern = text_field(data, "query");
    if pattern.is_empty() || pattern.len() > 1024 {
        return Err(RemoteError::new("Invalid search pattern"));
    }
    let limit = data
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(2000)
        .clamp(1, 10000);
    let script = format!(
        "grep -aobF -e {} -- {} | head -n {}",
        shell_quote(&pattern),
        shell_quote(&path),
        limit
    );
    let raw = crate::remote::run(target, &script, Some(120))?;
    let mut matches = Vec::new();
    for line in String::from_utf8_lossy(&raw).lines() {
        let (offset, _) = match line.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        if let Ok(offset) = offset.parse::<u64>() {
            matches.push(json!({ "offset": offset }));
        }
    }
    Ok(json!({
        "path": path,
        "matches": matches,
        "truncated": matches.len() as u64 >= limit,
    }))
}

fn require_device_tools(target: &crate::ssh::Target, tools: &[&str]) -> RResult<()> {
    for tool in tools {
        if crate::remote::device_tool_available(target, tool)? {
            continue;
        }
        let mut data = crate::tools::missing_tool_data(tool);
        data["dependency_preflight"] = json!(true);
        return Err(RemoteError::with_code_data(
            2,
            format!("{tool} is not installed"),
            data,
        ));
    }
    Ok(())
}

fn archive_shell_command(program: &str, args: &[String]) -> String {
    std::iter::once(shell_quote(program))
        .chain(args.iter().map(|arg| shell_quote(arg)))
        .collect::<Vec<String>>()
        .join(" ")
}

fn archive_list(target: &crate::ssh::Target, data: &Value) -> RResult<Value> {
    let path = check_path(&text_field(data, "path"))?;
    let plan = crate::api::archops::archive_listing_plan(&path)
        .map_err(|error| RemoteError::new(error.message))?;
    let command = match plan {
        crate::api::archops::ArchiveListingPlan::SingleFile(name) => {
            return Ok(json!({
                "archive": path,
                "entries": [{ "name": name, "dir": false, "size": Value::Null }],
                "truncated": false
            }));
        }
        crate::api::archops::ArchiveListingPlan::Command(command) => command,
    };
    let required = crate::api::archops::archive_required_tools(command.kind, command.program);
    require_device_tools(target, &required)?;
    let script = archive_shell_command(command.program, &command.args);
    let raw = crate::remote::run(target, &script, Some(120))?;
    let lines: Vec<String> = String::from_utf8_lossy(&raw)
        .lines()
        .map(|line| line.to_string())
        .collect();
    let (entries, truncated) = crate::api::archops::parse_archive_entries(
        &lines,
        command.with_sizes,
        crate::api::archops::ARCHIVE_LIST_LIMIT,
    );
    Ok(json!({ "archive": path, "entries": entries, "truncated": truncated }))
}

#[derive(Clone)]
enum ArchiveJob {
    Create {
        target_dir: String,
        target_path: String,
        source_dir: String,
        sources: Vec<String>,
        format: String,
        plan: crate::api::archops::ArchiveCommand,
        overwrite: bool,
    },
    Extract {
        path: String,
        target_dir: String,
        kind: &'static str,
        members: Option<Vec<String>>,
        selection_dir: String,
        plan: crate::api::archops::ArchiveCommand,
        overwrite: bool,
    },
}

fn plan_archive_job(action: &str, data: &Value) -> RResult<ArchiveJob> {
    let overwrite = data.get("overwrite").and_then(Value::as_str) == Some("1");
    if action == "archive_create_start" {
        let target_dir = check_path(&text_field(data, "target_dir"))?;
        let raw_name = data
            .get("output_name")
            .or_else(|| data.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if !valid_component(raw_name) {
            return Err(RemoteError::new("Invalid archive name"));
        }
        let format = data
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("tar.gz")
            .to_string();
        let name = crate::api::archops::archive_named(raw_name, &format);
        let sources = string_list_param(data, "sources");
        if sources.is_empty() || sources.len() > 4096 {
            return Err(RemoteError::new("No source given"));
        }
        let sources = sources
            .iter()
            .map(|source| check_path(source))
            .collect::<RResult<Vec<_>>>()?;
        if sources.iter().any(|source| source == "/") {
            return Err(RemoteError::new("Invalid archive source path"));
        }
        let source_dir = parent_path(&sources[0]).unwrap_or_else(|| "/".to_string());
        if sources
            .iter()
            .any(|source| parent_path(source).as_deref() != Some(source_dir.as_str()))
        {
            return Err(RemoteError::new("Archive sources must share a directory"));
        }
        let target_path = join_path(&target_dir, &name);
        if sources.iter().any(|source| {
            source == &target_path || crate::paths::is_descendant(source, &target_path)
        }) {
            return Err(RemoteError::new(
                "The archive cannot be written inside its own source",
            ));
        }
        let relatives: Vec<String> = sources.iter().map(|source| path_name(source)).collect();
        let plan = crate::api::archops::archive_create_plan(&format, &target_path, &relatives)
            .ok_or_else(|| RemoteError::new("Unsupported archive format"))?;
        Ok(ArchiveJob::Create {
            target_dir,
            target_path,
            source_dir,
            sources,
            format,
            plan,
            overwrite,
        })
    } else {
        let path = check_path(&text_field(data, "path"))?;
        let target_dir = check_path(
            data.get("target_dir")
                .or_else(|| data.get("directory"))
                .and_then(Value::as_str)
                .unwrap_or(""),
        )?;
        let members_raw = data
            .get("members")
            .and_then(Value::as_str)
            .map(str::to_string);
        let members =
            crate::api::archops::parse_archive_members(members_raw).map_err(RemoteError::new)?;
        let kind = crate::api::archops::archive_kind_for_path(&path)
            .ok_or_else(|| RemoteError::new("Unsupported archive format"))?;
        // A private, unguessable directory avoids a shared selection-file race.
        let selection_dir = format!("/tmp/harbor-archive-{}", crate::uci::random_hex(16));
        let selection_file = format!("{selection_dir}/members");
        let plan = crate::api::archops::archive_extract_plan(
            &path,
            kind,
            members.as_deref(),
            &selection_file,
        )
        .map_err(|error| RemoteError::new(error.message))?;
        Ok(ArchiveJob::Extract {
            path,
            target_dir,
            kind,
            members,
            selection_dir,
            plan,
            overwrite,
        })
    }
}

fn archive_start(
    st: &Arc<AppState>,
    target: &crate::ssh::Target,
    params: &Params,
    action: &str,
    data: &Value,
) -> RResult<Value> {
    let job = plan_archive_job(action, data)?;
    let plan = match &job {
        ArchiveJob::Create { plan, .. } | ArchiveJob::Extract { plan, .. } => plan,
    };
    let required = crate::api::archops::archive_required_tools(plan.kind, plan.program);
    require_device_tools(target, &required)?;
    let command = archive_shell_command(plan.program, &plan.args);
    let mut state = match &job {
        ArchiveJob::Create {
            target_path,
            target_dir,
            format,
            ..
        } => json!({
            "mode": "create", "path": target_path, "output_path": target_path,
            "target_dir": target_dir, "format": format
        }),
        ArchiveJob::Extract {
            path,
            target_dir,
            kind,
            ..
        } => json!({
            "mode": "extract", "path": path, "destination_path": target_dir,
            "target_dir": target_dir, "format": kind
        }),
    };
    state["operation"] = json!("archive");
    state["device_id"] = json!(target.id);
    state["state"] = json!("running");
    state["done"] = json!(false);
    state["success"] = json!(false);
    state["command"] = json!(command.chars().take(4096).collect::<String>());
    let worker_st = Arc::clone(st);
    let target = target.clone();
    let params = params.clone();
    let task_id = crate::remote::spawn_task(st, state.clone(), move |dir| {
        execute_archive_job(&worker_st, &target, &params, job, &dir)
    })?;
    state["task_id"] = json!(task_id);
    Ok(state)
}

fn remote_archive_members(
    target: &crate::ssh::Target,
    path: &str,
    kind: &str,
) -> RResult<Vec<crate::archive_inspect::Member>> {
    use crate::api::archops;
    if let Some((program, args)) = crate::archive_inspect::tar_stream_command(path, kind) {
        let script = format!("exec {}", archive_shell_command(program, &args));
        let workspace = crate::remote::workspace_pub(target)?;
        let child =
            crate::ssh::spawn_download(target, &workspace, &script).map_err(RemoteError::new)?;
        return crate::archive_inspect::inspect_child(child, archops::ARCHIVE_LIST_LIMIT)
            .map_err(RemoteError::new);
    }
    if matches!(
        archops::archive_listing_plan(path),
        Ok(archops::ArchiveListingPlan::SingleFile(_))
    ) {
        return archops::archive_single_member(path, kind)
            .map_err(|error| RemoteError::new(error.message));
    }
    let list = |flag: &str| -> RResult<Vec<String>> {
        let args = vec![flag.to_string(), path.to_string()];
        let script = format!(
            "LC_ALL=C.UTF-8; export LC_ALL; {}",
            archive_shell_command("bsdtar", &args)
        );
        let bytes = crate::remote::run(target, &script, Some(3600))?;
        archops::strict_listing_lines(bytes).map_err(|error| RemoteError::new(error.message))
    };
    archops::parse_safe_bsdtar_listing(&list("-tf")?, &list("-tvf")?, archops::ARCHIVE_LIST_LIMIT)
        .map_err(|error| RemoteError::new(error.message))
}

pub(crate) fn reject_archive_symlinks(
    target: &crate::ssh::Target,
    base: &str,
    names: &[String],
) -> RResult<()> {
    let candidates =
        crate::api::archops::archive_destination_paths(base, names).map_err(RemoteError::new)?;
    let blocks: Vec<String> = candidates
        .iter()
        .map(|path| format!("[ ! -L {} ] || exit 45", shell_quote(path)))
        .collect();
    for script in crate::ssh::chunk_script(&blocks) {
        crate::remote::run(target, &script, Some(30)).map_err(|_| {
            RemoteError::new("Archive destination contains a symbolic link or cannot be inspected")
        })?;
    }
    Ok(())
}

fn authorize_remote_paths(
    st: &AppState,
    target: &crate::ssh::Target,
    params: &Params,
    paths: &[String],
) -> RResult<Vec<String>> {
    let resolved = crate::remote::resolve_policy_paths(Some(target), paths)?;
    let policy = st.root_policy_config();
    let session = params.get("__system_session_id").unwrap_or_default();
    for (original, actual) in paths.iter().zip(resolved.iter()) {
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
        if let Some(missing) = st.system_access.missing_path(
            (!session.is_empty()).then_some(session.as_str()),
            &target.id,
            original,
            actual,
        ) {
            return Err(RemoteError::system_access_required_at(missing, &target.id));
        }
    }
    Ok(resolved)
}

// Enumerate the complete tree before any recursive mutation or archive read.
// `find` does not follow directory symlinks. Reject incomplete, non-UTF8,
// oversized or unrelated results rather than silently skipping descendants.
fn remote_tree_paths(target: &crate::ssh::Target, sources: &[String]) -> RResult<Vec<String>> {
    if sources.is_empty() || sources.len() > 4096 {
        return Err(RemoteError::new("Invalid selection"));
    }
    let roots = sources
        .iter()
        .map(|source| check_path(source))
        .collect::<RResult<Vec<_>>>()?;
    let blocks: Vec<String> = roots
        .iter()
        .map(|path| format!("find {} -print0", shell_quote(path)))
        .collect();
    if blocks.iter().any(|line| {
        crate::ssh::script_exec_len(&format!("set -e\n{line}")) > crate::ssh::SCRIPT_EXEC_LIMIT
    }) {
        return Err(RemoteError::new("Path is too long to inspect safely"));
    }
    let mut paths = std::collections::BTreeSet::new();
    let mut size = 0usize;
    for script in crate::ssh::chunk_script(&blocks) {
        let bytes = crate::remote::run(target, &format!("set -e\n{script}"), Some(3600))?;
        size = size.saturating_add(bytes.len());
        if size >= 16 * 1024 * 1024 {
            return Err(RemoteError::new(
                "Directory is too large to validate safely",
            ));
        }
        for path in crate::remote::parse_policy_frames(&bytes)? {
            if !roots
                .iter()
                .any(|root| crate::paths::is_descendant(root, &path))
            {
                return Err(RemoteError::new("Cannot inspect directory safely"));
            }
            paths.insert(path);
            if paths.len() > 16_384 {
                return Err(RemoteError::new(
                    "Directory is too large to validate safely",
                ));
            }
        }
    }
    if roots.iter().any(|root| !paths.contains(root)) {
        return Err(RemoteError::new("Cannot inspect directory safely"));
    }
    Ok(paths.into_iter().collect())
}

pub(crate) fn archive_conflicts(
    target: &crate::ssh::Target,
    target_dir: &str,
    names: &[String],
) -> RResult<Vec<String>> {
    let mut tops = Vec::new();
    for name in names {
        let top = name.split('/').next().unwrap_or("");
        if !top.is_empty() && !tops.iter().any(|old| old == top) {
            tops.push(top.to_string());
        }
    }
    let blocks: Vec<String> = tops
        .iter()
        .enumerate()
        .map(|(index, top)| {
            let candidate = shell_quote(&join_path(target_dir, top));
            format!("if [ -e {candidate} ] || [ -L {candidate} ]; then printf '%s\\n' {index}; fi")
        })
        .collect();
    let mut conflicts = Vec::new();
    for script in crate::ssh::chunk_script(&blocks) {
        let raw = crate::remote::run(target, &script, Some(30))?;
        for line in String::from_utf8_lossy(&raw).lines() {
            let index: usize = line
                .parse()
                .map_err(|_| RemoteError::new("Cannot inspect archive conflicts"))?;
            let top = tops
                .get(index)
                .ok_or_else(|| RemoteError::new("Cannot inspect archive conflicts"))?;
            conflicts.push(top.clone());
        }
    }
    Ok(conflicts)
}

fn archive_extract_script(
    target_dir: &str,
    selection_dir: &str,
    plan: &crate::api::archops::ArchiveCommand,
    members: Option<&[String]>,
) -> (String, Option<String>) {
    let mut script = format!("set -e\ncd {} || exit 44\n", shell_quote(target_dir));
    let selection = if let Some(members) = members {
        let quoted_dir = shell_quote(selection_dir);
        script.push_str(&format!(
            "umask 077\nselection={quoted_dir}\nmkdir -- \"$selection\"\ntrap 'rm -rf -- \"$selection\"' EXIT\ncat > \"$selection/members\"\n"
        ));
        Some(members.join("\n") + "\n")
    } else {
        None
    };
    let command = archive_shell_command(plan.program, &plan.args);
    if let Some(output) = &plan.redirect {
        script.push_str(&format!(
            "{} > {}\n",
            command,
            shell_quote(&join_path(target_dir, output))
        ));
    } else {
        script.push_str(&command);
        script.push('\n');
    }
    (script, selection)
}

fn execute_archive_job(
    st: &AppState,
    target: &crate::ssh::Target,
    params: &Params,
    job: ArchiveJob,
    dir: &std::path::Path,
) -> RResult<()> {
    match job {
        ArchiveJob::Create {
            target_dir,
            target_path,
            source_dir,
            sources,
            plan,
            overwrite,
            ..
        } => {
            let existing = (|| -> RResult<String> {
                let mut paths = sources.clone();
                paths.push(target_path.clone());
                let resolved = authorize_remote_paths(st, target, params, &paths)?;
                let resolved_target = resolved.last().ok_or_else(|| RemoteError::new("Invalid path"))?;
                if resolved[..sources.len()].iter().any(|source| crate::paths::is_descendant(source, resolved_target)) {
                    return Err(RemoteError::new("The archive cannot be written inside its own source"));
                }
                let source_tree = remote_tree_paths(target, &sources)?;
                authorize_remote_paths(st, target, params, &source_tree)?;
                let existence = crate::remote::run(target, &format!(
                    r#"for p in {sources}; do [ -e "$p" ] || [ -L "$p" ] || exit 44; done; if [ -d {out} ] && [ ! -L {out} ]; then echo dir; elif [ -e {out} ] || [ -L {out} ]; then echo file; else echo none; fi"#,
                    sources = sources.iter().map(|source| shell_quote(source)).collect::<Vec<_>>().join(" "), out = shell_quote(&target_path),
                ), Some(30))?;
                let existing = String::from_utf8_lossy(&existence).trim().to_string();
                if existing == "dir" { return Err(RemoteError::new("Cannot replace a directory with an archive")); }
                if existing == "file" && !overwrite {
                    return Err(RemoteError::with_code_data(3, "archive already exists", json!({ "output_path": target_path, "target_is_directory": false })));
                }
                if existing != "file" && existing != "none" { return Err(RemoteError::new("Cannot inspect archive target")); }
                Ok(existing)
            })().map_err(crate::remote::safe_preflight)?;
            // Past this boundary even a known nonzero exit may have changed
            // the filesystem; report partial/unknown and never auto-replay.
            crate::remote::run_mutating_once(
                target,
                &format!("mkdir -p -- {}", shell_quote(&target_dir)),
                Some(60),
            )
            .map_err(mark_partial)?;
            if existing == "file" && overwrite {
                crate::remote::run_mutating_once(
                    target,
                    &format!("rm -f -- {}", shell_quote(&target_path)),
                    Some(30),
                )
                .map_err(mark_partial)?;
            }
            let script = format!(
                "set -e\ncd {} || exit 44\n{}",
                shell_quote(&source_dir),
                archive_shell_command(plan.program, &plan.args)
            );
            run_archive_logged(target, &script, None, dir).map_err(mark_partial)
        }
        ArchiveJob::Extract {
            path,
            target_dir,
            kind,
            members,
            selection_dir,
            plan,
            overwrite,
        } => {
            let execution_members = (|| -> RResult<Option<Vec<String>>> {
                let archive_members = remote_archive_members(target, &path, kind)?;
                let selected = crate::api::archops::archive_selection_paths(&archive_members, members.as_deref()).map_err(RemoteError::new)?;
                let execution_members = crate::api::archops::archive_selection_arguments(&archive_members, members.as_deref()).map_err(RemoteError::new)?;
                // Authorize every effective and legacy name, even for selections:
                // remote tar variants disagree on extension semantics.
                let all_paths = crate::api::archops::archive_selection_paths(&archive_members, None).map_err(RemoteError::new)?;
                let mut destinations: Vec<String> = all_paths.iter().map(|name| join_path(&target_dir, name)).collect();
                destinations.push(target_dir.clone());
                authorize_remote_paths(st, target, params, &destinations)?;
                reject_archive_symlinks(target, &target_dir, &all_paths)?;
                let qdir = shell_quote(&target_dir);
                let dir_kind = crate::remote::run(target, &format!(
                    "if [ -L {qdir} ] || [ -f {qdir} ]; then echo file; elif [ -d {qdir} ]; then echo dir; else echo none; fi"), Some(20))?;
                if String::from_utf8_lossy(&dir_kind).trim() == "file" {
                    return Err(RemoteError::with_code_data(3, "Target path is a file, not a directory", json!({ "target_is_directory": false, "target_path": target_dir, "path": path })));
                }
                if !overwrite {
                    let conflicts = archive_conflicts(target, &target_dir, &selected)?;
                    if !conflicts.is_empty() {
                        return Err(RemoteError::with_code_data(3, "the destination already contains these entries", json!({ "conflicts": conflicts, "destination_path": target_dir, "path": path })));
                    }
                }
                Ok(execution_members)
            })().map_err(crate::remote::safe_preflight)?;
            crate::remote::run_mutating_once(
                target,
                &format!("mkdir -p -- {}", shell_quote(&target_dir)),
                Some(60),
            )
            .map_err(mark_partial)?;
            let (script, selection) = archive_extract_script(
                &target_dir,
                &selection_dir,
                &plan,
                execution_members.as_deref(),
            );
            run_archive_logged(target, &script, selection, dir).map_err(mark_partial)
        }
    }
}

fn run_archive_logged(
    target: &crate::ssh::Target,
    script: &str,
    input: Option<String>,
    dir: &std::path::Path,
) -> RResult<()> {
    // The argv builder sends scripts as a single SSH command, not a shell pipe.
    if crate::ssh::script_exec_len(script) > crate::ssh::SCRIPT_EXEC_LIMIT {
        return Err(RemoteError::new("Archive command is too large"));
    }
    let workspace = crate::remote::workspace_pub(target)?;
    let child = crate::ssh::spawn_upload(target, &workspace, script).map_err(RemoteError::new)?;
    drive_archive_child(child, input, dir)
}

fn drive_archive_child(
    mut child: crate::ssh::ByteStream,
    input: Option<String>,
    dir: &std::path::Path,
) -> RResult<()> {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let log_path = dir.join("log");
    fn drain<R: Read + Send + 'static>(
        mut reader: R,
        path: std::path::PathBuf,
    ) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok();
            let mut buffer = [0u8; 8192];
            let mut written = 0usize;
            let mut tail = Vec::new();
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if written < 1024 * 1024 {
                    let count = n.min(1024 * 1024 - written);
                    if let Some(log) = log.as_mut() {
                        let _ = log.write_all(&buffer[..count]);
                    }
                    written += count;
                }
                tail.extend_from_slice(&buffer[..n]);
                if tail.len() > 4096 {
                    tail.drain(..tail.len() - 4096);
                }
            }
            String::from_utf8_lossy(&tail).trim().to_string()
        })
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| RemoteError::new("Cannot read archive output"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| RemoteError::new("Cannot read archive errors"))?;
    let out_reader = drain(stdout, log_path.clone());
    let err_reader = drain(stderr, log_path);
    let writer = child.stdin.take().map(|mut stdin| {
        std::thread::spawn(move || {
            if let Some(input) = input {
                stdin.write_all(input.as_bytes())
            } else {
                Ok(())
            }
        })
    });
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(code)) => break (Some(code), false),
            Ok(None) if started.elapsed() < Duration::from_secs(3600) => {
                std::thread::sleep(Duration::from_millis(100))
            }
            _ => {
                let _ = child.kill();
                let status = child.wait().ok();
                break (status, true);
            }
        }
    };
    let write_ok = writer
        .map(|w| w.join().ok().is_some_and(|r| r.is_ok()))
        .unwrap_or(false);
    let stdout_tail = out_reader.join().unwrap_or_default();
    let stderr_tail = err_reader.join().unwrap_or_default();
    if timed_out {
        return Err(RemoteError::with_data(
            "Archive status is unknown after SSH timeout",
            json!({ "outcome_unknown": true }),
        ));
    }
    let exit_code = status;
    if exit_code.is_none() || exit_code == Some(255) {
        return Err(RemoteError::with_data(
            "Archive status is unknown after SSH connection loss",
            json!({ "outcome_unknown": true }),
        ));
    }
    if !write_ok || exit_code != Some(0) {
        let detail = if stderr_tail.is_empty() {
            stdout_tail
        } else {
            stderr_tail
        };
        return Err(RemoteError::with_data(
            if detail.is_empty() {
                "Archive command failed".to_string()
            } else {
                detail
            },
            json!({ "exit_code": exit_code.unwrap_or(1) }),
        ));
    }
    Ok(())
}

fn packages_of(data: &Value) -> RResult<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    if let Some(array) = data.get("packages").and_then(|v| v.as_array()) {
        names.extend(
            array
                .iter()
                .filter_map(|v| v.as_str())
                .map(|value| value.to_string()),
        );
    }
    for key in ["package", "name", "tool"] {
        if let Some(value) = data.get(key).and_then(|v| v.as_str()) {
            names.extend(value.split_whitespace().map(|value| value.to_string()));
        }
    }
    names.retain(|name| !name.is_empty());
    if names.is_empty() || names.len() > 64 {
        return Err(RemoteError::new("Invalid package name"));
    }
    if names.iter().any(|name| !crate::tools::valid_package(name)) {
        return Err(RemoteError::new("Invalid package name"));
    }
    names.dedup();
    Ok(names)
}

fn install_tool(st: &Arc<AppState>, device: &Device, tool: &str) -> RResult<Value> {
    if !crate::tools::valid_name(tool) {
        return Err(RemoteError::new("Invalid tool name"));
    }
    let target = authenticated_target(st, device);
    if tool == "sftp" {
        match crate::ssh::sftp::ensure_sftp(&target).map_err(RemoteError::new)? {
            crate::ssh::sftp::SftpStatus::Ready => {
                return Ok(crate::tools::installed_tool(tool));
            }
            crate::ssh::sftp::SftpStatus::Disabled | crate::ssh::sftp::SftpStatus::Missing => {}
        }
        let packages = crate::tools::packages_for_tool(tool);
        return install_packages(st, device, &packages);
    }
    if crate::remote::device_tool_available(&target, tool)? {
        return Ok(crate::tools::installed_tool(tool));
    }
    let packages = crate::tools::packages_for_tool(tool);
    install_packages(st, device, &packages)
}

fn remote_install_script(packages: &[String]) -> RResult<String> {
    if packages.is_empty()
        || packages.len() > 64
        || packages
            .iter()
            .any(|name| !crate::tools::valid_package(name))
    {
        return Err(RemoteError::new("Invalid package name"));
    }
    let list = packages
        .iter()
        .map(|package| shell_quote(package))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!(
        r#"set -e
S='sudo -n'
if [ "$(id -u)" = 0 ]; then S=; elif ! command -v sudo >/dev/null 2>&1 || ! sudo -n true >/dev/null 2>&1; then S=missing; fi
if command -v apk >/dev/null 2>&1; then
 if [ "$S" = missing ]; then printf '%s\n' 'root access is required' >&2; exit 127; fi
 $S apk add --no-cache {list}
elif command -v opkg >/dev/null 2>&1; then
 if [ "$S" = missing ]; then printf '%s\n' 'root access is required' >&2; exit 127; fi
 $S opkg update || true
 $S opkg install {list}
elif command -v apt-get >/dev/null 2>&1; then
 if [ "$S" = missing ]; then printf '%s\n' 'root access is required' >&2; exit 127; fi
 $S apt-get update -qq >/dev/null 2>&1 || true
 DEBIAN_FRONTEND=noninteractive $S apt-get install -y -qq {list}
elif command -v dnf >/dev/null 2>&1; then
 if [ "$S" = missing ]; then printf '%s\n' 'root access is required' >&2; exit 127; fi
 $S dnf install -y {list}
elif command -v yum >/dev/null 2>&1; then
 if [ "$S" = missing ]; then printf '%s\n' 'root access is required' >&2; exit 127; fi
 $S yum install -y {list}
elif command -v pacman >/dev/null 2>&1; then
 if [ "$S" = missing ]; then printf '%s\n' 'root access is required' >&2; exit 127; fi
 $S pacman -Sy --noconfirm {list}
else
 printf '%s\n' 'no package manager on this device' >&2
 exit 127
fi"#
    ))
}

pub fn install_packages(
    st: &Arc<AppState>,
    device: &Device,
    packages: &[String],
) -> RResult<Value> {
    crate::remote::ensure_trusted(st, device)?;
    let target = authenticated_target(st, device);
    let script = remote_install_script(packages)?;
    let label = packages.join(" ");
    let log_label = label.clone();
    let task_id = crate::remote::spawn_task(
        st,
        json!({
            "operation": "package_install",
            "device": device.id,
            "device_id": device.id,
            "packages": packages,
            "package_name": label.clone(),
            "package_type": "repository",
            "path": label.clone(),
        }),
        move |dir| {
            // A disconnect can occur after the package manager has changed
            // the system. Report unknown instead of replaying the mutation.
            let header = format!("Installing {log_label}...\n");
            let _ = std::fs::write(dir.join("log"), &header);
            let result = crate::remote::run_mutating_once_logged(
                &target,
                &script,
                Some(1800),
                &dir.join("log"),
            );
            crate::remote::invalidate_tool_info(&target);
            result?;
            let _ = std::fs::write(dir.join("progress"), "1 1 complete");
            Ok(())
        },
    )?;
    Ok(json!({
        "task_id": task_id,
        "done": false,
        "packages": packages,
        "package_name": label,
        "package_type": "repository",
        "path": label,
    }))
}

fn thumbnail_cache_dir(target: &crate::ssh::Target) -> String {
    // A private per-remote-user cache avoids cross-account collisions in /tmp.
    let owner = hex::encode(crate::auth::sha256_bytes(target.username.as_bytes()));
    format!("/tmp/harbor-thumbs-{}", &owner[..16])
}

fn thumbnail_cache_read_guard(target: &crate::ssh::Target) -> String {
    format!(
        r#"cache_dir={dir}
[ -d "$cache_dir" ] && [ ! -L "$cache_dir" ] || exit 45
owner=$(stat -c '%u:%a' "$cache_dir" 2>/dev/null || gnu-stat -c '%u:%a' "$cache_dir" 2>/dev/null || /usr/libexec/stat-coreutils -c '%u:%a' "$cache_dir" 2>/dev/null || busybox stat -c '%u:%a' "$cache_dir" 2>/dev/null) || exit 45
[ "$owner" = "$(id -u):700" ] || exit 45"#,
        dir = shell_quote(&thumbnail_cache_dir(target))
    )
}

fn thumbnail_cache_path(target: &crate::ssh::Target, path: &str, size: i64, mtime: i64) -> String {
    let key = crate::api::fsops::thumbnail_key_parts(path, size, mtime);
    format!("{}/{key}.jpg", thumbnail_cache_dir(target))
}

fn thumbnail_script(target: &crate::ssh::Target, path: &str, cache: &str) -> String {
    let dir = thumbnail_cache_dir(target);
    let work = format!("{}/.work-{}", dir, crate::uci::random_hex(12));
    format!(
        r#"set -e
umask 077
cache_dir={dir}; work={work}; src={src}; out={out}
[ ! -L "$cache_dir" ] || exit 45
[ -d "$cache_dir" ] || mkdir -m 700 -- "$cache_dir"
owner=$(stat -c '%u:%a' "$cache_dir" 2>/dev/null || gnu-stat -c '%u:%a' "$cache_dir" 2>/dev/null || /usr/libexec/stat-coreutils -c '%u:%a' "$cache_dir" 2>/dev/null || busybox stat -c '%u:%a' "$cache_dir" 2>/dev/null) || exit 45
[ "$owner" = "$(id -u):700" ] || exit 45
mkdir -m 700 -- "$work"
trap 'rm -rf -- "$work"' EXIT
if command -v gm >/dev/null 2>&1; then
 gm convert -thumbnail 256x256 -quality 82 "$src[0]" "$work/out.jpg"
elif command -v ffmpeg >/dev/null 2>&1; then
 ffmpeg -y -loglevel error -i "$src" -vf scale=256:-2 -frames:v 1 "$work/out.jpg"
else
 echo 'thumbnail tool is not installed on this device' >&2; exit 127
fi
[ -f "$work/out.jpg" ] && [ ! -L "$work/out.jpg" ] || exit 46
mv -fT -- "$work/out.jpg" "$out""#,
        dir = shell_quote(&dir),
        work = shell_quote(&work),
        src = shell_quote(path),
        out = shell_quote(cache)
    )
}

fn thumbnail_start(
    st: &AppState,
    target: &crate::ssh::Target,
    params: &Params,
    data: &Value,
) -> RResult<Value> {
    let path = check_path(&text_field(data, "path"))?;
    let listing = crate::remote::listing(target, &path, false)?;
    let prefs = st.prefs();
    let mut candidates: Vec<_> = listing
        .items
        .into_iter()
        .filter(|item| {
            matches!(item.kind.as_str(), "file" | "symlink")
                && (prefs.show_hidden_files == 1 || !item.name.starts_with('.'))
                && crate::meta::classify_preview(&item.path, &item.name) == "image"
        })
        .collect();
    if candidates.len() > 4096 {
        return Err(RemoteError::new(
            "Directory is too large to generate thumbnails safely",
        ));
    }
    let names: Vec<String> = candidates.iter().map(|item| item.path.clone()).collect();
    let actual = crate::remote::resolve_policy_paths(Some(target), &names)?;
    let policy = st.root_policy_config();
    let session = params.get("__system_session_id").unwrap_or_default();
    let mut allowed = std::collections::HashSet::new();
    for (index, (item, resolved)) in candidates.iter().zip(&actual).enumerate() {
        let permitted = crate::paths::path_allowed_by_policy(
            policy.policy,
            &policy.roots,
            &policy.excluded_roots,
            resolved,
        ) && st.system_access.paths_allowed(
            (!session.is_empty()).then_some(session.as_str()),
            &target.id,
            &item.path,
            resolved,
        );
        if permitted {
            allowed.insert(index);
        }
    }
    candidates = candidates
        .into_iter()
        .enumerate()
        .filter_map(|(index, item)| allowed.contains(&index).then_some(item))
        .collect();
    let probes: Vec<String> = candidates
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let cache = shell_quote(&thumbnail_cache_path(
                target, &item.path, item.size, item.mtime,
            ));
            format!("if [ -f {cache} ] && [ ! -L {cache} ]; then printf '%s\\n' {index}; fi")
        })
        .collect();
    let mut cached = std::collections::HashSet::new();
    for script in crate::ssh::chunk_script(&probes) {
        let script = format!("{}\n{}", thumbnail_cache_read_guard(target), script);
        if let Ok(raw) = crate::remote::run(target, &script, Some(30)) {
            for index in String::from_utf8_lossy(&raw)
                .lines()
                .filter_map(|line| line.parse::<usize>().ok())
            {
                cached.insert(index);
            }
        }
    }
    let cached_count = cached.len();
    let jobs: Vec<_> = candidates
        .into_iter()
        .enumerate()
        .filter_map(|(index, item)| {
            (!cached.contains(&index)).then(|| {
                let cache = thumbnail_cache_path(target, &item.path, item.size, item.mtime);
                (item.path, cache)
            })
        })
        .collect();
    if cached_count + jobs.len() > 0
        && !crate::remote::device_tool_available(target, "gm")?
        && !crate::remote::device_tool_available(target, "ffmpeg")?
    {
        return Err(RemoteError::missing_tool(
            "gm",
            crate::tools::package_for("gm"),
            "GraphicsMagick is not installed",
        ));
    }
    let total = jobs.len();
    let state = json!({"operation": "thumbnail", "device_id": target.id, "path": path,
        "directory": path, "total": total, "processed": 0, "success_count": 0,
        "failed_count": 0, "cached_count": cached_count, "current_file": ""});
    let target = target.clone();
    let task_id = crate::remote::spawn_task(st, state, move |task_dir| {
        let mut success = 0usize;
        let mut failures = 0usize;
        if jobs.is_empty() {
            append_task_log(
                &task_dir,
                &format!("{cached_count} thumbnails already cached"),
            );
            return Ok(());
        }
        for (source, cache) in jobs {
            crate::remote::update_task_fields(&task_dir, &json!({"current_file": source}))?;
            append_task_log(&task_dir, &format!("BEGIN {source}"));
            let script = thumbnail_script(&target, &source, &cache);
            match crate::remote::run_mutating_once(&target, &script, Some(600)) {
                Ok(_) => {
                    success += 1;
                    append_task_log(&task_dir, &format!("OK {source}"));
                }
                Err(error) if error.data["outcome_unknown"] == json!(true) => return Err(error),
                Err(error) => {
                    failures += 1;
                    append_task_log(&task_dir, &format!("FAIL {source}"));
                    append_task_log(&task_dir, &format!("  {}", error.message));
                }
            }
            crate::remote::update_task_fields(
                &task_dir,
                &json!({"processed": success + failures,
                "success_count": success, "failed_count": failures, "current_file": ""}),
            )?;
        }
        if failures > 0 {
            Err(RemoteError::new("Thumbnail generation failed"))
        } else {
            Ok(())
        }
    })?;
    Ok(
        json!({"task_id": task_id, "path": path, "directory": path, "done": false, "state": "running",
        "total": total, "processed": 0, "success_count": 0, "failed_count": 0,
        "cached_count": cached_count, "current_file": ""}),
    )
}

pub fn thumbnail_file(target: &crate::ssh::Target, path: &str) -> Option<(String, i64, i64)> {
    let source = crate::remoteio::remote_stat(target, path).ok()?;
    if source.kind != "file" {
        return None;
    }
    let cache = thumbnail_cache_path(target, path, source.size as i64, source.mtime);
    let guard = format!(
        "{}\n[ -f {} ] && [ ! -L {} ]",
        thumbnail_cache_read_guard(target),
        shell_quote(&cache),
        shell_quote(&cache)
    );
    crate::remote::run(target, &guard, Some(30)).ok()?;
    let result = crate::remoteio::remote_stat(target, &cache).ok()?;
    if result.kind != "file" || result.is_symlink {
        return None;
    }
    Some((cache, result.size as i64, result.mtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_writer_quotes_names_checks_complete_input_and_reports_uncertainty() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let root =
            std::env::temp_dir().join(format!("harbor-text-safe-{}", crate::uci::random_hex(8)));
        std::fs::create_dir(&root).unwrap();
        let target = root.join("file $(touch injected) ' quote.txt");
        std::fs::write(&target, b"original").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let script = text_write_script(target.to_str().unwrap(), 5, None, "short").unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"bad").unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(47));
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
        assert!(!root.join(".harbor-editor-short").exists());
        let script = text_write_script(target.to_str().unwrap(), 3, None, "complete").unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", &script])
            .stdin(Stdio::piped())
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
        drive_text_writer(
            crate::ssh::ByteStream::from_child(command.spawn().unwrap(), true).unwrap(),
            b"new".to_vec(),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!root.join("injected").exists());
        let mut lost = Command::new("/bin/sh");
        lost.args(["-c", "cat >/dev/null; exit 255"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            lost.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let error = drive_text_writer(
            crate::ssh::ByteStream::from_child(lost.spawn().unwrap(), true).unwrap(),
            b"data".to_vec(),
            std::time::Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(error.data["outcome_unknown"], true);
        let _ = std::fs::remove_dir_all(root);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_remote_text_save_preserves_mode_and_metacharacters() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-text-save", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-text-e2e-{}", crate::uci::random_hex(8));
        let path = format!("{root}/file $(touch injected) ' quote.txt");
        crate::remote::run_mutating_once(
            &target,
            &format!(
                "mkdir -p {root}; printf old > {path}; chmod 600 {path}",
                root = shell_quote(&root),
                path = shell_quote(&path)
            ),
            Some(30),
        )
        .unwrap();
        save_text(&target, &json!({"path":path, "content":"after"})).unwrap();
        assert_eq!(
            crate::remote::run(
                &target,
                &format!(
                    "cat {}; stat -c %a {}",
                    shell_quote(&path),
                    shell_quote(&path)
                ),
                Some(30)
            )
            .unwrap(),
            b"after600\n"
        );
        assert!(crate::remote::run(
            &target,
            &format!("test ! -e {}/injected", shell_quote(&root)),
            Some(30)
        )
        .is_ok());
        assert!(crate::remote::run(
            &target,
            &format!(
                "test -z \"$(find {} -name '.harbor-editor-*' -print)\"",
                shell_quote(&root)
            ),
            Some(30)
        )
        .is_ok());
        crate::remote::run_mutating_once(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        )
        .unwrap();
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_recursive_mutations_enforce_descendant_policy_and_rename_contract() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-recursive", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-recursive-e2e-{}", crate::uci::random_hex(8));
        let script = format!("mkdir -p {r}/blocked {r}/good {r}/linktree; printf secret > {r}/blocked/secret; printf nested > {r}/good/hidden; printf original > {r}/simple; ln -s /etc {r}/linktree/system; ln -s missing {r}/dangling", r=shell_quote(&root));
        crate::remote::run_mutating_once(&target, &script, Some(30)).unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let params = Params::default();
        st.set_root_policy_config(crate::state::RootPolicyConfig {
            policy: crate::state::RootPolicy::Denylist,
            roots: vec![],
            excluded_roots: vec![
                format!("{root}/blocked/secret"),
                format!("{root}/renamed/hidden"),
            ],
        })
        .unwrap();
        let blocked = format!("{root}/blocked");
        assert!(delete(&st, &target, &params, &json!({"path":blocked})).is_err());
        assert!(chmod(
            &st,
            &target,
            &params,
            &json!({"path":blocked, "mode":"600", "recursive":"1"})
        )
        .is_err());
        assert!(rename(
            &st,
            &target,
            &params,
            &json!({"path":blocked, "new_name":"elsewhere"})
        )
        .is_err());
        let good = format!("{root}/good");
        assert!(
            rename(
                &st,
                &target,
                &params,
                &json!({"path":good, "new_name":"renamed"})
            )
            .is_err(),
            "destination descendant policy must be checked"
        );
        assert_eq!(
            crate::remote::run(
                &target,
                &format!(
                    "cat {r}/blocked/secret {r}/good/hidden",
                    r = shell_quote(&root)
                ),
                Some(30)
            )
            .unwrap(),
            b"secretnested"
        );
        st.set_root_policy_config(crate::state::RootPolicyConfig {
            policy: crate::state::RootPolicy::Unrestricted,
            roots: vec![],
            excluded_roots: vec![],
        })
        .unwrap();
        let denied = delete(
            &st,
            &target,
            &params,
            &json!({"path":format!("{root}/linktree")}),
        )
        .unwrap_err();
        assert_eq!(denied.data["system_access_required"], true);
        assert_eq!(denied.data["device_id"], target.id);
        assert_eq!(
            denied.data["path"], "/etc",
            "report the resolved protected scope"
        );
        assert!(crate::remote::ensure_remote_no_nested_mounts(&target, &["/dev".into()]).is_err());
        let mut granted = Params::default();
        granted.set("__system_session_id", "fixture");
        st.system_access.grant("fixture", &target.id, "/etc", 60);
        delete(
            &st,
            &target,
            &granted,
            &json!({"path":format!("{root}/linktree")}),
        )
        .unwrap();
        assert_eq!(
            crate::remote::run(&target, "test -d /etc && printf safe", Some(20)).unwrap(),
            b"safe"
        );
        let source = format!("{root}/simple");
        assert!(
            rename(
                &st,
                &target,
                &params,
                &json!({"path":source, "new_name":"dangling"})
            )
            .is_err(),
            "do not replace a dangling symlink"
        );
        let destination = rename(
            &st,
            &target,
            &params,
            &json!({"path":source, "new_name":"new name"}),
        )
        .unwrap();
        assert_eq!(destination, format!("{root}/new name"));
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("cat {}", shell_quote(&destination)),
                Some(30)
            )
            .unwrap(),
            b"original"
        );
        chmod(
            &st,
            &target,
            &params,
            &json!({"path":good, "mode":"700", "recursive":"1"}),
        )
        .unwrap();
        delete(&st, &target, &params, &json!({"path":good})).unwrap();
        crate::remote::run_mutating_once(
            &target,
            &format!("rm -rf -- {}", shell_quote(&root)),
            Some(30),
        )
        .unwrap();
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_remote_archive_tasks_create_extract_and_reject_unsafe_members() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-archive", 60).expect("HARBOR_E2E_SSH_PORT");
        let root = format!("/tmp/harbor-archive-e2e-{}", crate::uci::random_hex(8));
        let prepare = format!("mkdir -p {r}/input/sub {r}/archives {r}/output {r}/conflict {r}/bad {r}/policy; printf alpha > {r}/input/a.txt; printf beta > {r}/input/sub/b.txt; printf existing > {r}/conflict/a.txt; ln -s /etc {r}/input/escape; tar -czf {r}/archives/unsafe.tar.gz -C {r}/input escape; mkdir -p {r}/input/blocked; printf secret > {r}/input/blocked/secret; tar -czf {r}/archives/policy.tar.gz -C {r}/input a.txt blocked",
            r=shell_quote(&root));
        crate::remote::run(&target, &prepare, Some(60)).unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let params = Params::default();
        let mut ids = Vec::new();
        let wait = |started: Value| -> Value {
            assert_eq!(started["done"], json!(false), "{started}");
            let id = started["task_id"].as_str().unwrap();
            (0..600)
                .find_map(|_| {
                    let status = checked_rpc_task_status(&st, id, "archive", &target.id).unwrap();
                    if status["done"] == json!(true) {
                        Some(status)
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        None
                    }
                })
                .expect("archive task timed out")
        };
        let start = archive_start(
            &st,
            &target,
            &params,
            "archive_create_start",
            &json!({
                "target_dir":format!("{root}/archives"), "output_name":"result", "format":"tar.gz",
                "sources":[format!("{root}/input/a.txt"),format!("{root}/input/sub")]
            }),
        )
        .unwrap();
        ids.push(start["task_id"].as_str().unwrap().to_string());
        let status = wait(start);
        assert_eq!(status["success"], json!(true), "{status}");
        let archive = format!("{root}/archives/result.tar.gz");
        let start = archive_start(
            &st,
            &target,
            &params,
            "archive_extract_start",
            &json!({
                "path":archive, "target_dir":format!("{root}/output")
            }),
        )
        .unwrap();
        ids.push(start["task_id"].as_str().unwrap().to_string());
        let status = wait(start);
        assert_eq!(status["success"], json!(true), "{status}");
        assert_eq!(
            crate::remote::run(
                &target,
                &format!(
                    "cat {r}/output/a.txt {r}/output/sub/b.txt",
                    r = shell_quote(&root)
                ),
                Some(30)
            )
            .unwrap(),
            b"alphabeta"
        );
        let start = archive_start(
            &st,
            &target,
            &params,
            "archive_extract_start",
            &json!({
                "path":archive, "target_dir":format!("{root}/conflict")
            }),
        )
        .unwrap();
        ids.push(start["task_id"].as_str().unwrap().to_string());
        let status = wait(start);
        assert_eq!(status["success"], json!(false), "{status}");
        assert_eq!(status["failure_code"], json!(3));
        assert_eq!(status["failure_data"]["preflight_safe"], json!(true));
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("cat {}/conflict/a.txt", shell_quote(&root)),
                Some(30)
            )
            .unwrap(),
            b"existing"
        );
        let start = archive_start(
            &st,
            &target,
            &params,
            "archive_extract_start",
            &json!({
                "path":format!("{root}/archives/unsafe.tar.gz"), "target_dir":format!("{root}/bad")
            }),
        )
        .unwrap();
        ids.push(start["task_id"].as_str().unwrap().to_string());
        let status = wait(start);
        assert_eq!(status["success"], json!(false), "{status}");
        assert!(
            status["message"].as_str().unwrap_or("").contains("links"),
            "{status}"
        );
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("find {}/bad -mindepth 1 -print", shell_quote(&root)),
                Some(30)
            )
            .unwrap(),
            b""
        );
        st.set_root_policy_config(crate::state::RootPolicyConfig {
            policy: crate::state::RootPolicy::Denylist,
            roots: vec![],
            excluded_roots: vec![format!("{root}/policy/blocked")],
        })
        .unwrap();
        let start = archive_start(&st, &target, &params, "archive_extract_start", &json!({
            "path":format!("{root}/archives/policy.tar.gz"), "target_dir":format!("{root}/policy"), "overwrite":"1"
        })).unwrap();
        ids.push(start["task_id"].as_str().unwrap().to_string());
        let status = wait(start);
        assert_eq!(status["success"], json!(false), "{status}");
        assert_eq!(
            crate::remote::run(
                &target,
                &format!("find {}/policy -mindepth 1 -print", shell_quote(&root)),
                Some(30)
            )
            .unwrap(),
            b""
        );
        st.set_root_policy_config(crate::state::RootPolicyConfig {
            policy: crate::state::RootPolicy::Unrestricted,
            roots: vec![],
            excluded_roots: vec![],
        })
        .unwrap();
        crate::remote::run_mutating_once(
            &target,
            &format!(
                "mkdir -p {r}/system-dest; ln -s /etc {r}/system-dest/blocked",
                r = shell_quote(&root)
            ),
            Some(30),
        )
        .unwrap();
        let start = archive_start(&st, &target, &params, "archive_extract_start", &json!({
            "path":format!("{root}/archives/policy.tar.gz"), "target_dir":format!("{root}/system-dest"), "overwrite":"1"
        })).unwrap();
        ids.push(start["task_id"].as_str().unwrap().to_string());
        let status = wait(start);
        assert_eq!(status["success"], false, "{status}");
        assert_eq!(status["failure_data"]["preflight_safe"], true, "{status}");
        assert_eq!(
            status["failure_data"]["system_access_required"], true,
            "{status}"
        );
        assert_eq!(status["failure_data"]["device_id"], target.id);
        assert!(status["failure_data"]["path"]
            .as_str()
            .unwrap()
            .starts_with("/etc"));
        assert_eq!(
            crate::remote::run(
                &target,
                &format!(
                    "find {}/system-dest -mindepth 1 -maxdepth 1 | wc -l",
                    shell_quote(&root)
                ),
                Some(30)
            )
            .unwrap(),
            b"1\n"
        );
        for id in ids {
            let _ =
                std::fs::remove_dir_all(std::path::Path::new(crate::remote::REMOTE_ROOT).join(id));
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
    #[test]
    fn e2e_remote_thumbnail_batch_cache_and_listing_schema() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-thumbs", 60).expect("HARBOR_E2E_SSH_PORT");
        if !crate::remote::device_tool_available(&target, "gm").unwrap_or(false) {
            eprintln!("SSH thumbnail E2E skipped: gm unavailable");
            return;
        }
        let root = format!("/tmp/harbor-thumbnail-e2e-{}", crate::uci::random_hex(8));
        let image = format!("{root}/photo.png");
        let alias = format!("{root}/alias.png");
        let outside = format!("{root}-outside");
        let create = format!("mkdir -p {root} {outside}; gm convert -size 4x4 xc:red {image}; cp {image} {outside}/secret.png; cp {image} {root}/.hidden.png; ln -s {outside}/secret.png {root}/blocked.png; ln -s photo.png {alias}; mkdir {root}/folder; ln -s folder {root}/folder-link; printf hi > {root}/note.txt",
            root=shell_quote(&root), outside=shell_quote(&outside), image=shell_quote(&image), alias=shell_quote(&alias));
        crate::remote::run(&target, &create, Some(30)).unwrap();
        let (st, state_dir) = crate::ssh::e2e_state(&target, &root);
        let listing = crate::remote::listing(&target, &root, false).unwrap();
        let image_item = listing
            .items
            .iter()
            .find(|item| item.path == image)
            .unwrap();
        let alias_item = listing
            .items
            .iter()
            .find(|item| item.path == alias)
            .unwrap();
        let image_cache = thumbnail_cache_path(&target, &image, image_item.size, image_item.mtime);
        let alias_cache = thumbnail_cache_path(&target, &alias, alias_item.size, alias_item.mtime);
        assert_eq!(image_item.size, alias_item.size);
        let link = alias_item.json();
        assert_eq!(link["type"], json!("symlink"));
        assert_eq!(link["link_target"]["path"], json!(image));
        assert_eq!(link["permissions"], image_item.json()["permissions"]);
        let dirlink = listing
            .items
            .iter()
            .find(|item| item.name == "folder-link")
            .unwrap()
            .json();
        assert_eq!(dirlink["type"], json!("directory"));
        assert_eq!(dirlink["size"], json!(-1));
        assert_eq!(
            detect(&target, &format!("{root}/folder-link")).unwrap()["type"],
            json!("directory")
        );
        assert_eq!(
            detect(&target, &format!("{root}/note.txt")).unwrap()["type"],
            json!("text")
        );
        let weird = format!("{root}/binary.txt");
        crate::remote::run(
            &target,
            &format!("printf '\\000abc' > {}", shell_quote(&weird)),
            Some(30),
        )
        .unwrap();
        for path in [&image, &format!("{root}/note.txt"), &weird] {
            let local = crate::meta::detect_content_type(path);
            let remote = detect(&target, path).unwrap();
            assert_eq!(remote["type"], json!(local.0));
            assert_eq!(remote["mime"], json!(local.1));
            assert!(remote["numeric_permissions"].is_string());
            assert_eq!(remote["editable"], json!(true));
        }
        let started =
            thumbnail_start(&st, &target, &Params::default(), &json!({"path": root})).unwrap();
        assert_eq!(started["total"], json!(2));
        let id = started["task_id"].as_str().unwrap();
        let status = (0..300)
            .find_map(|_| {
                let status = crate::remote::task_status(&st, id).unwrap();
                if status["done"] == json!(true) {
                    Some(status)
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    None
                }
            })
            .expect("thumbnail task timed out");
        assert_eq!(status["success"], json!(true), "{status}");
        assert_eq!(status["processed"], json!(2));
        assert_eq!(status["success_count"], json!(2));
        let listing = crate::remote::listing(&target, &root, false).unwrap();
        let rendered = listing_json(&st, &target, &listing, false);
        for name in ["photo.png", "alias.png"] {
            let item = rendered["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["name"] == json!(name))
                .unwrap();
            assert_eq!(item["thumbnail_available"], json!(true), "{item}");
        }
        assert_eq!(thumbnail_file(&target, &image).unwrap().0, image_cache);
        assert_eq!(thumbnail_file(&target, &alias).unwrap().0, alias_cache);
        assert!(
            thumbnail_file(&target, &format!("{root}/.hidden.png")).is_none(),
            "hidden image must not be generated"
        );
        assert!(
            thumbnail_file(&target, &format!("{root}/blocked.png")).is_none(),
            "outside-root symlink must not be generated"
        );
        let cached =
            thumbnail_start(&st, &target, &Params::default(), &json!({"path": root})).unwrap();
        assert_eq!(cached["total"], json!(0));
        assert_eq!(cached["cached_count"], json!(2));
        crate::remote::run(
            &target,
            &format!("touch -t 200001010000 {}", shell_quote(&image)),
            Some(30),
        )
        .unwrap();
        assert!(
            thumbnail_file(&target, &image).is_none(),
            "changed mtime must invalidate the cache"
        );
        let _ = crate::remote::run(
            &target,
            &format!(
                "rm -rf -- {} {}; rm -f -- {} {}",
                shell_quote(&root),
                shell_quote(&outside),
                shell_quote(&image_cache),
                shell_quote(&alias_cache)
            ),
            Some(30),
        );
        for task_id in [id, cached["task_id"].as_str().unwrap()] {
            let _ = std::fs::remove_dir_all(
                std::path::Path::new(crate::remote::REMOTE_ROOT).join(task_id),
            );
        }
        drop(st);
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[test]
    fn installer_apk_and_opkg_root_and_sudo_paths_are_noninteractive() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("harbor-install-mock-{}", crate::uci::random_hex(8)));
        std::fs::create_dir(&dir).unwrap();
        let log = dir.join("log");
        let write = |name: &str, text: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{text}\n")).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        write("id", "echo \"$MOCK_UID\"");
        write("sudo", "echo \"sudo $*\" >> \"$LOG\"; [ \"$1\" = -n ] || exit 2; shift; [ \"$1\" = true ] && exit 0; \"$@\"");
        write("apk", "echo \"apk $*\" >> \"$LOG\"");
        let script = remote_install_script(&["alpha".into(), "beta-tool".into()]).unwrap();
        let run = |uid: &str| {
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .env_clear()
                .env("PATH", &dir)
                .env("MOCK_UID", uid)
                .env("LOG", &log)
                .output()
                .unwrap()
        };
        assert!(run("0").status.success());
        let lines = std::fs::read_to_string(&log).unwrap();
        assert!(lines.contains("apk add --no-cache alpha beta-tool"));
        assert!(!lines.contains("sudo"));
        std::fs::remove_file(&log).unwrap();
        assert!(run("1000").status.success());
        let lines = std::fs::read_to_string(&log).unwrap();
        assert!(lines.contains("sudo -n true"));
        assert!(lines.contains("sudo -n apk add --no-cache alpha beta-tool"));
        std::fs::remove_file(&log).unwrap();
        std::fs::remove_file(dir.join("apk")).unwrap();
        write("opkg", "echo \"opkg $*\" >> \"$LOG\"");
        assert!(run("1000").status.success());
        let lines = std::fs::read_to_string(&log).unwrap();
        assert!(lines.contains("sudo -n opkg update"));
        assert!(lines.contains("sudo -n opkg install alpha beta-tool"));
        std::fs::remove_file(&log).unwrap();
        std::fs::remove_file(dir.join("sudo")).unwrap();
        let denied = run("1000");
        assert_eq!(denied.status.code(), Some(127));
        assert!(String::from_utf8_lossy(&denied.stderr).contains("root access is required"));
        assert!(
            !log.exists(),
            "package manager was called without elevation"
        );
        assert!(remote_install_script(&["bad;command".into()]).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn thumbnail_cache_refuses_symlink_and_nonprivate_parent() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let target = crate::ssh::Target {
            username: format!("test-{}", crate::uci::random_hex(8)),
            ..Default::default()
        };
        let dir = std::path::PathBuf::from(thumbnail_cache_dir(&target));
        let outside = std::env::temp_dir().join(format!(
            "harbor-thumb-outside-{}",
            crate::uci::random_hex(8)
        ));
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, &dir).unwrap();
        let run = |script: &str| {
            std::process::Command::new("sh")
                .arg("-c")
                .arg(script)
                .status()
                .unwrap()
                .code()
        };
        assert_eq!(run(&thumbnail_cache_read_guard(&target)), Some(45));
        let src = outside.join("source.png");
        let dst = dir.join("cache.jpg");
        std::fs::write(&src, b"not an image").unwrap();
        assert_eq!(
            run(&thumbnail_script(
                &target,
                src.to_str().unwrap(),
                dst.to_str().unwrap()
            )),
            Some(45)
        );
        assert!(!outside.join("cache.jpg").exists());
        std::fs::remove_file(&dir).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(run(&thumbnail_cache_read_guard(&target)), Some(45));
        assert_eq!(
            run(&thumbnail_script(
                &target,
                src.to_str().unwrap(),
                dst.to_str().unwrap()
            )),
            Some(45)
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(run(&thumbnail_cache_read_guard(&target)), Some(0));
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[test]
    fn rpc_task_status_is_scoped_to_operation_and_device() {
        let root =
            std::env::temp_dir().join(format!("harbor-rpc-job-{}", crate::uci::random_hex(8)));
        let st = AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            ..Default::default()
        });
        let id = crate::remote::spawn_task(
            &st,
            json!({"operation": "thumbnail", "device_id": "device-a"}),
            |_| Ok(()),
        )
        .unwrap();
        assert!(checked_rpc_task_status(&st, &id, "thumbnail", "device-a").is_ok());
        assert!(checked_rpc_task_status(&st, &id, "archive", "device-a").is_err());
        assert!(checked_rpc_task_status(&st, &id, "thumbnail", "device-b").is_err());
        let missing =
            checked_rpc_task_status(&st, &"f".repeat(32), "thumbnail", "device-a").unwrap();
        assert_eq!(missing["state"], json!("unknown"));
        assert_eq!(missing["success"], json!(false));
        // Task workers may still be writing briefly; let them finish before cleanup.
        for _ in 0..100 {
            if crate::remote::task_status(&st, &id).unwrap()["done"] == json!(true) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_dir_all(std::path::Path::new(crate::remote::REMOTE_ROOT).join(id));
        drop(st);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn json_string_path_arrays_are_authorized_and_not_silently_truncated() {
        let data = json!({ "sources": "[\"/ok\",\"/etc/secret\"]", "target_dir": "/dest" });
        let mut collected = Vec::new();
        collect_paths(&data, "", &mut collected);
        assert!(collected.contains(&"/etc/secret".to_string()));
        assert_eq!(
            configured_root_paths("archive_create_start", &data).len(),
            3
        );
        let deleting = json!({ "paths": "[\"/safe\",\"/blocked\"]" });
        assert_eq!(
            configured_root_paths("batch_delete", &deleting),
            vec!["/safe", "/blocked"]
        );
        let huge = json!({ "paths": vec!["/tmp/file"; 8193] });
        let mut paths = Vec::new();
        collect_paths(&huge, "", &mut paths);
        assert_eq!(paths.len(), 8193);
    }

    #[test]
    fn archive_child_reports_unknown_on_ssh_disconnect_and_captures_errors() {
        use std::process::{Command, Stdio};
        let dir =
            std::env::temp_dir().join(format!("harbor-child-test-{}", crate::uci::random_hex(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let spawn = |script: &str| {
            crate::ssh::ByteStream::from_child(
                Command::new("sh")
                    .args(["-c", script])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
                true,
            )
            .unwrap()
        };
        assert!(drive_archive_child(
            spawn("cat >/dev/null; echo ok"),
            Some("members".into()),
            &dir
        )
        .is_ok());
        let error = drive_archive_child(spawn("echo connection-lost >&2; exit 255"), None, &dir)
            .unwrap_err();
        assert_eq!(error.data["outcome_unknown"], json!(true));
        let error = drive_archive_child(spawn("echo broken >&2; exit 2"), None, &dir).unwrap_err();
        assert_eq!(error.data["exit_code"], json!(2));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_invalid_names_and_modes() {
        assert!(check_name("ok.txt").is_ok());
        assert!(check_name("..").is_err());
        assert!(check_name("a/b").is_err());
        assert!(check_name("").is_err());
        assert!(valid_mode("644"));
        assert!(!valid_mode("999"));
        assert!(!valid_mode("64"));
    }

    #[test]
    fn agent_is_always_ready() {
        let device = crate::remote::Device {
            id: "d1".into(),
            name: "router".into(),
            host: "10.0.0.1".into(),
            port: 22,
            username: "root".into(),
            revision: "abc".into(),
            host_key: String::new(),
            has_password: true,
        };
        assert_eq!(agent_ready(&device)["ready"], json!(true));
    }
}
