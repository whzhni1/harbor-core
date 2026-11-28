//! Archive creation/extraction, package installation and thumbnail generation.

use crate::meta::{self, Kind};
use crate::paths::{self, basename_checked, join_path, parent_path, path_name};
use crate::reply::{fail, fail_status, ok};
use crate::state::Ctx;
use crate::tasks;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{json, Value};
use std::fs;
use std::sync::Mutex;

static ARCHIVE_START_LOCK: Mutex<()> = Mutex::new(());
static PACKAGE_START_LOCK: Mutex<()> = Mutex::new(());
static THUMBNAIL_START_LOCK: Mutex<()> = Mutex::new(());

// Archive preflight may walk directories or inspect a compressed file. Run
// it off the async executor, and let concurrent starts fail busy immediately.
struct StartRequestGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Drop for StartRequestGuard {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}
async fn run_blocking(
    ctx: &Ctx,
    work: fn(&Ctx, &std::sync::Arc<std::sync::atomic::AtomicBool>) -> Response,
) -> Response {
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let guard = StartRequestGuard(cancelled.clone());
    let ctx = ctx.clone();
    let result = tokio::task::spawn_blocking(move || work(&ctx, &cancelled)).await;
    drop(guard);
    match result {
        Ok(response) => response,
        Err(_) => fail_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "Cannot start the operation",
            Value::Null,
        ),
    }
}
fn start_cancelled(cancelled: &std::sync::atomic::AtomicBool) -> Option<Response> {
    cancelled
        .load(std::sync::atomic::Ordering::Acquire)
        .then(|| {
            fail_status(
                StatusCode::REQUEST_TIMEOUT,
                1,
                "Request was cancelled",
                Value::Null,
            )
        })
}
#[allow(clippy::result_large_err)]
fn try_start_lock(
    lock: &'static Mutex<()>,
    message: &str,
) -> Result<std::sync::MutexGuard<'static, ()>, Response> {
    match lock.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => {
            Err(fail_status(StatusCode::CONFLICT, 1, message, Value::Null))
        }
    }
}

pub const ARCHIVE_STATE_FILE: &str = "/tmp/harbor_file_pro/harbor_file_pro_archive_state.json";
pub const ARCHIVE_LOG: &str = "/tmp/harbor_file_pro/harbor_file_pro_archive.log";
pub const ARCHIVE_RC: &str = "/tmp/harbor_file_pro/harbor_file_pro_archive.rc";
pub const ARCHIVE_SEL_FILE: &str = "/tmp/harbor_file_pro/harbor_file_pro_archive_sel.txt";
pub const PACKAGE_STATE_FILE: &str =
    "/tmp/harbor_file_pro/harbor_file_pro_package_install_state.json";
pub const PACKAGE_LOG: &str = "/tmp/harbor_file_pro/harbor_file_pro_package_install.log";
pub const PACKAGE_RC: &str = "/tmp/harbor_file_pro/harbor_file_pro_package_install.rc";
pub const THUMBNAIL_STATE_FILE: &str = "/tmp/harbor_file_pro/harbor_file_pro_thumbnail_state.json";
pub const THUMBNAIL_LOG: &str = "/tmp/harbor_file_pro/harbor_file_pro_thumbnail.log";
pub const THUMBNAIL_RC: &str = "/tmp/harbor_file_pro/harbor_file_pro_thumbnail.rc";
pub const ARCHIVE_LIST_LIMIT: usize = 4000;

fn single_file_kind(kind: &str) -> bool {
    matches!(
        kind,
        "bz2" | "xz" | "lzma" | "zst" | "zstd" | "lz4" | "lzo" | "z" | "lz" | "lrz"
    )
}

pub fn archive_kind(src: &str, ext: &str) -> Option<&'static str> {
    let lower = src.to_lowercase();
    let endswith = |suffix: &str| lower.ends_with(suffix);
    if ext == "zip" {
        return Some("zip");
    }
    if endswith(".tar.gz") || ext == "tgz" {
        return Some("targz");
    }
    if endswith(".tar.bz2") || ext == "tbz" || ext == "tbz2" {
        return Some("tarbz2");
    }
    if endswith(".tar.xz") || ext == "txz" {
        return Some("tarxz");
    }
    if ext == "tar" {
        return Some("tar");
    }
    if endswith(".cpio.gz") {
        return Some("cpio");
    }
    if ext == "gz" {
        return Some("gz");
    }
    if ext == "7z" {
        return Some("7z");
    }
    if ext == "rar" {
        return Some("rar");
    }
    if ext == "iso" {
        return Some("iso");
    }
    if endswith(".tar.zst") || endswith(".tar.zstd") || ext == "tzst" {
        return Some("tarzst");
    }
    if endswith(".tar.lzma") || ext == "tlz" {
        return Some("tarlzma");
    }
    if endswith(".tar.lz4") {
        return Some("tarlz4");
    }
    if endswith(".tar.lzo") {
        return Some("tarlzo");
    }
    if endswith(".tar.z") {
        return Some("tarz");
    }
    if endswith(".tar.lrz") {
        return Some("tarlrz");
    }
    if endswith(".tar.bz") {
        return Some("tarbz");
    }
    if matches!(
        ext,
        "cab" | "lha" | "lzh" | "xar" | "warc" | "cpio" | "deb" | "rpm" | "zipx"
    ) {
        return Some(match ext {
            "cab" => "cab",
            "lha" => "lha",
            "lzh" => "lzh",
            "xar" => "xar",
            "warc" => "warc",
            "cpio" => "cpio",
            "deb" => "deb",
            "rpm" => "rpm",
            _ => "zipx",
        });
    }
    if ext == "ipk" {
        return Some("targz");
    }
    if ext == "apk" {
        return Some("zip");
    }
    if single_file_kind(ext) {
        return Some(match ext {
            "bz2" => "bz2",
            "xz" => "xz",
            "lzma" => "lzma",
            "zst" => "zst",
            "zstd" => "zstd",
            "lz4" => "lz4",
            "lzo" => "lzo",
            "z" => "z",
            "lz" => "lz",
            _ => "lrz",
        });
    }
    None
}

fn tar_flag(kind: &str) -> Option<&'static str> {
    match kind {
        "targz" => Some("z"),
        "tarbz2" => Some("j"),
        "tarxz" => Some("J"),
        "tar" => Some(""),
        _ => None,
    }
}

fn is_bsdtar_kind(kind: &str) -> bool {
    tar_flag(kind).is_none() && kind != "gz" && !single_file_kind(kind)
}

fn one_file_name(src: &str, kind: &str) -> String {
    let base = basename_checked(src);
    if kind == "gz" {
        return base.strip_suffix(".gz").unwrap_or(&base).to_string();
    }
    match base.rfind('.') {
        Some(idx) if idx > 0 => base[..idx].to_string(),
        _ => base,
    }
}

#[derive(Clone, Debug)]
pub struct ArchiveCommand {
    pub kind: &'static str,
    pub program: &'static str,
    pub args: Vec<String>,
    pub redirect: Option<String>,
    pub with_sizes: bool,
}

pub enum ArchiveListingPlan {
    SingleFile(String),
    Command(ArchiveCommand),
}

pub fn archive_kind_for_path(path: &str) -> Option<&'static str> {
    archive_kind(path, &paths::file_extension(path))
}

pub fn archive_required_tools(kind: &str, program: &str) -> Vec<&'static str> {
    let mut tools = vec![match program {
        "bsdtar" => "bsdtar",
        "gunzip" => "gzip",
        _ => "tar",
    }];
    if let Some(compressor) = archive_compressor(kind) {
        if !tools.contains(&compressor) {
            tools.push(compressor);
        }
    }
    tools
}

pub fn archive_listing_plan(src: &str) -> Result<ArchiveListingPlan, ArchiveError> {
    let kind = archive_kind_for_path(src).ok_or_else(|| err("Unsupported archive format"))?;
    if kind == "gz" || single_file_kind(kind) {
        return Ok(ArchiveListingPlan::SingleFile(one_file_name(src, kind)));
    }
    let (program, args) = if let Some(flag) = tar_flag(kind) {
        ("tar", vec![format!("-t{flag}f"), src.to_string()])
    } else if is_bsdtar_kind(kind) {
        ("bsdtar", vec!["-tvf".to_string(), src.to_string()])
    } else {
        return Err(err("Unsupported archive format"));
    };
    Ok(ArchiveListingPlan::Command(ArchiveCommand {
        kind,
        program,
        args,
        redirect: None,
        with_sizes: is_bsdtar_kind(kind),
    }))
}

pub fn archive_create_plan(
    format: &str,
    target: &str,
    sources: &[String],
) -> Option<ArchiveCommand> {
    let (kind, program, flag) = match format {
        "tar" => ("tar", "tar", "-cvf"),
        "tar.gz" => ("targz", "tar", "-czvf"),
        "zip" => ("zip", "bsdtar", "-a"),
        _ => return None,
    };
    let mut args = if format == "zip" {
        vec![flag.to_string(), "-cf".to_string(), target.to_string()]
    } else {
        vec![flag.to_string(), target.to_string()]
    };
    args.extend(sources.iter().map(|source| {
        if source.starts_with('-') {
            format!("./{source}")
        } else {
            source.clone()
        }
    }));
    Some(ArchiveCommand {
        kind,
        program,
        args,
        redirect: None,
        with_sizes: false,
    })
}

pub fn archive_extract_plan(
    src: &str,
    kind: &'static str,
    members: Option<&[String]>,
    selection_file: &str,
) -> Result<ArchiveCommand, ArchiveError> {
    let mut args = Vec::new();
    let (program, redirect) = if is_bsdtar_kind(kind) {
        if members.is_some() {
            args.extend(
                ["-x", "-v", "-T", selection_file, "-f", src].map(|value| value.to_string()),
            );
        } else {
            args.extend(["-xvf", src].map(|value| value.to_string()));
        }
        ("bsdtar", None)
    } else if let Some(flag) = tar_flag(kind) {
        if members.is_some() {
            args.push(format!("-x{flag}"));
            args.extend(["-v", "-T", selection_file, "-f", src].map(|value| value.to_string()));
        } else {
            args.push(format!("-x{flag}vf"));
            args.push(src.to_string());
        }
        ("tar", None)
    } else if kind == "gz" {
        if members.is_some() {
            return Err(err("This archive format only supports one regular file"));
        }
        args.extend(["-c", src].map(|value| value.to_string()));
        ("gunzip", Some(one_file_name(src, kind)))
    } else if single_file_kind(kind) {
        if members.is_some() {
            return Err(err("This archive format only supports one regular file"));
        }
        args.extend(["-xOf", src].map(|value| value.to_string()));
        ("bsdtar", Some(one_file_name(src, kind)))
    } else {
        return Err(err("Unsupported archive format"));
    };
    Ok(ArchiveCommand {
        kind,
        program,
        args,
        redirect,
        with_sizes: false,
    })
}

#[derive(Debug)]
pub struct ArchiveError {
    pub message: String,
    pub detail: String,
    pub missing_tool: Option<&'static str>,
    pub package_name: Option<String>,
}

fn err(message: &str) -> ArchiveError {
    ArchiveError {
        message: message.to_string(),
        detail: String::new(),
        missing_tool: None,
        package_name: None,
    }
}

fn require_archive_tool(name: &'static str) -> Result<(), ArchiveError> {
    if meta::have_tool(name) {
        return Ok(());
    }
    Err(ArchiveError {
        message: format!("{name} is not installed"),
        detail: String::new(),
        missing_tool: Some(name),
        package_name: Some(crate::tools::package_for(name).to_string()),
    })
}

fn archive_compressor(kind: &str) -> Option<&'static str> {
    match kind {
        "targz" => Some("gzip"),
        "tarbz2" => Some("bzip2"),
        "tarxz" => Some("xz"),
        _ => None,
    }
}

fn missing_archive_tool(error: ArchiveError) -> Response {
    let mut data = error
        .missing_tool
        .map(crate::tools::missing_tool_data)
        .unwrap_or_else(|| json!({}));
    if error.missing_tool.is_some() {
        data["dependency_preflight"] = json!(true);
    }
    data["detail"] = json!(error.detail);
    if let Some(package) = error.package_name {
        data["package_name"] = json!(package);
    }
    fail(2, &error.message, data)
}

// Bounded, cancellable subprocess capture for archive listings. In
// particular, never allocate all of a hostile archive's listing or leave a
// decompressor running after the HTTP future disappears.
fn bounded_listing(
    program: &str,
    args: &[String],
    cancelled: &std::sync::atomic::AtomicBool,
    cap: usize,
) -> Result<(Vec<u8>, Vec<u8>, i32, bool), String> {
    use std::io::Read;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    fn nonblocking(fd: i32) -> std::io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    fn drain(reader: &mut impl Read, into: &mut Vec<u8>, cap: usize) -> (bool, bool) {
        let mut buf = [0u8; 8192];
        let mut overflow = false;
        let mut eof = false;
        for _ in 0..16 {
            match reader.read(&mut buf) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => {
                    let keep = n.min(cap.saturating_sub(into.len()));
                    into.extend_from_slice(&buf[..keep]);
                    overflow |= keep < n;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    eof = true;
                    break;
                }
            }
        }
        (overflow, eof)
    }
    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .env("LC_ALL", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = cmd.spawn().map_err(|error| error.to_string())?;
    let pid = child.id() as i32;
    let mut stdout = child.stdout.take().ok_or("Cannot read archive listing")?;
    let mut stderr = child.stderr.take().ok_or("Cannot read archive listing")?;
    if nonblocking(stdout.as_raw_fd()).is_err() || nonblocking(stderr.as_raw_fd()).is_err() {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = child.wait();
        return Err("Cannot read archive listing".into());
    }
    let start = std::time::Instant::now();
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let mut overflow = false;
    loop {
        let (too_much, _) = drain(&mut stdout, &mut output, cap);
        overflow |= too_much;
        let _ = drain(&mut stderr, &mut errors, 64 * 1024);
        if cancelled.load(std::sync::atomic::Ordering::Acquire)
            || start.elapsed() > std::time::Duration::from_secs(3600)
        {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = child.wait();
            return Err(if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                "Archive listing cancelled"
            } else {
                "Archive listing timed out"
            }
            .into());
        }
        if overflow {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = child.wait();
            if let Some(last) = output.iter().rposition(|byte| *byte == b'\n') {
                output.truncate(last + 1);
            } else {
                output.clear();
            }
            return Ok((output, errors, -1, true));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // Drain data already in the pipe but never wait for an inherited
                // descriptor to reach EOF after the direct child has exited.
                loop {
                    let before = output.len();
                    let (too_much, _) = drain(&mut stdout, &mut output, cap);
                    overflow |= too_much;
                    if overflow || output.len() == before {
                        break;
                    }
                }
                let _ = drain(&mut stderr, &mut errors, 64 * 1024);
                if overflow {
                    if let Some(last) = output.iter().rposition(|byte| *byte == b'\n') {
                        output.truncate(last + 1);
                    } else {
                        output.clear();
                    }
                }
                return Ok((output, errors, status.code().unwrap_or(-1), overflow));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(error) => {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
    }
}

pub fn parse_archive_entries(
    lines: &[String],
    with_sizes: bool,
    limit: usize,
) -> (Vec<Value>, bool) {
    let mut entries: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut truncated = false;
    for raw in lines {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > 4096 {
            truncated = true;
            continue;
        }
        let mut name = line.to_string();
        let mut size: Option<i64> = None;
        let mut is_dir = false;
        if with_sizes {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 9 {
                continue;
            }
            size = fields[4].parse::<i64>().ok();
            is_dir = fields[0].starts_with('d');
            let idx = line.find(fields[8]).unwrap_or(0);
            name = line[idx..].to_string();
            if let Some(arrow) = name.find(" -> ") {
                name.truncate(arrow);
            }
        }
        if name.starts_with("./") {
            name = name[2..].to_string();
        }
        if name.ends_with('/') {
            is_dir = true;
            name.pop();
        }
        if name.is_empty() || name == "." || name == ".." || seen.contains(&name) {
            continue;
        }
        if entries.len() >= limit {
            truncated = true;
            break;
        }
        seen.insert(name.clone());
        entries.push(json!({ "name": name, "dir": is_dir, "size": if with_sizes { json!(size) } else { Value::Null } }));
    }
    // Include inferred parent directories, but never exceed the same limit or
    // permit one deeply nested name to cause quadratic allocation.
    for entry in entries.clone() {
        let name = entry["name"].as_str().unwrap_or("");
        let parts: Vec<&str> = name.split('/').collect();
        if parts.len() < 2 {
            continue;
        }
        let mut acc = String::new();
        for part in &parts[..parts.len() - 1] {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            if seen.contains(&acc) {
                continue;
            }
            if entries.len() >= limit {
                truncated = true;
                break;
            }
            seen.insert(acc.clone());
            entries.push(json!({ "name": acc, "dir": true, "size": Value::Null }));
        }
        if truncated && entries.len() >= limit {
            break;
        }
    }
    (entries, truncated)
}

// BSD tar escapes control characters in listings. A strict pair of plain and
// verbose listings is used only for non-tar formats; ordinary tar streams are
// inspected by their binary headers (BusyBox listing is not trustworthy).
pub(crate) fn parse_safe_bsdtar_listing(
    names: &[String],
    verbose: &[String],
    limit: usize,
) -> Result<Vec<crate::archive_inspect::Member>, ArchiveError> {
    if names.len() != verbose.len() {
        return Err(err("Cannot safely inspect archive members"));
    }
    let mut members = Vec::new();
    for (index, (name, mode)) in names.iter().zip(verbose).enumerate() {
        if index >= limit {
            return Err(err("Archive is too large to validate safely"));
        }
        let bytes = mode.as_bytes();
        if bytes.len() < 10 || !bytes[1..10].iter().all(|c| b"rwxstST-".contains(c)) {
            return Err(err("Cannot safely inspect archive members"));
        }
        let is_dir = match bytes[0] {
            b'-' => false,
            b'd' => true,
            b'l' | b'h' => return Err(err("Archives containing links cannot be extracted")),
            _ => return Err(err("Archive contains unsupported special entries")),
        };
        if let Some(member) =
            crate::archive_inspect::member(name, is_dir).map_err(|message| err(&message))?
        {
            members.push(member);
        }
    }
    Ok(members)
}

fn safe_listing_lines(
    program: &str,
    args: &[String],
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<Vec<String>, ArchiveError> {
    let (raw, _, status, truncated) = bounded_listing(program, args, cancelled, 16 * 1024 * 1024)
        .map_err(|message| err(&message))?;
    if truncated || status != 0 {
        return Err(err("Cannot safely inspect archive members"));
    }
    strict_listing_lines(raw)
}

pub(crate) fn strict_listing_lines(raw: Vec<u8>) -> Result<Vec<String>, ArchiveError> {
    if raw.len() >= 16 * 1024 * 1024 || (!raw.is_empty() && raw.last() != Some(&b'\n')) {
        return Err(err("Cannot safely inspect archive members"));
    }
    let text = String::from_utf8(raw).map_err(|_| err("Cannot safely inspect archive members"))?;
    Ok(text.lines().map(str::to_string).collect())
}

fn archive_listing(
    src: &str,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<(Vec<Value>, bool), ArchiveError> {
    let plan = archive_listing_plan(src)?;
    let command = match plan {
        ArchiveListingPlan::SingleFile(name) => {
            return Ok((
                vec![json!({ "name": name, "dir": false, "size": Value::Null })],
                false,
            ));
        }
        ArchiveListingPlan::Command(command) => command,
    };
    for tool in archive_required_tools(command.kind, command.program) {
        require_archive_tool(tool)?;
    }
    let (raw, errors, rc, capture_truncated) =
        bounded_listing(command.program, &command.args, cancelled, 16 * 1024 * 1024)
            .map_err(|message| err(&message))?;
    let lines: Vec<String> = String::from_utf8_lossy(&raw)
        .lines()
        .map(str::to_string)
        .collect();
    let stderr = String::from_utf8_lossy(&errors);
    let (entries, entry_truncated) =
        parse_archive_entries(&lines, command.with_sizes, ARCHIVE_LIST_LIMIT);
    let truncated = capture_truncated || entry_truncated;
    if rc != 0 && entries.is_empty() && !truncated {
        let mut detail = stderr.trim().to_string();
        if detail.is_empty() {
            detail = lines
                .iter()
                .map(|line| line.trim().to_string())
                .find(|line| !line.is_empty())
                .unwrap_or_else(|| format!("Command exited with status {rc}"));
        }
        let mut error = err("List failed");
        error.detail = detail.chars().take(200).collect();
        return Err(error);
    }
    Ok((entries, truncated))
}

pub(crate) fn archive_single_member(
    src: &str,
    kind: &str,
) -> Result<Vec<crate::archive_inspect::Member>, ArchiveError> {
    let name = one_file_name(src, kind);
    let member = crate::archive_inspect::member(&name, false)
        .map_err(|message| err(&message))?
        .ok_or_else(|| err("Archive contains an unsafe path"))?;
    Ok(vec![member])
}

fn archive_member_names(
    src: &str,
    kind: &str,
    cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<Vec<crate::archive_inspect::Member>, ArchiveError> {
    if kind == "gz" || single_file_kind(kind) {
        return archive_single_member(src, kind);
    }
    if crate::archive_inspect::tar_stream_command(src, kind).is_some() {
        return crate::archive_inspect::inspect_local_tar_cancellable(
            src,
            kind,
            ARCHIVE_LIST_LIMIT,
            cancelled.clone(),
        )
        .map_err(|message| err(&message));
    }
    if is_bsdtar_kind(kind) {
        let names = safe_listing_lines("bsdtar", &["-tf".into(), src.into()], cancelled)?;
        let verbose = safe_listing_lines("bsdtar", &["-tvf".into(), src.into()], cancelled)?;
        return parse_safe_bsdtar_listing(&names, &verbose, ARCHIVE_LIST_LIMIT);
    }
    Err(err("Unsupported archive format"))
}

pub async fn api_archive_list(ctx: &Ctx) -> Response {
    run_blocking(ctx, api_archive_list_blocking).await
}

fn api_archive_list_blocking(
    ctx: &Ctx,
    cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Response {
    let path = match ctx.read_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    match archive_listing(&path, cancelled) {
        Ok((entries, truncated)) => ok(json!({
            "archive": path,
            "entries": entries,
            "truncated": truncated
        })),
        Err(error) if error.missing_tool.is_some() => missing_archive_tool(error),
        Err(error) => fail(1, &error.message, json!({ "detail": error.detail })),
    }
}

pub fn archive_named(name: &str, format: &str) -> String {
    let suffix = match format {
        "tar" => ".tar",
        "zip" => ".zip",
        _ => ".tar.gz",
    };
    if name.to_lowercase().ends_with(suffix) {
        name.to_string()
    } else {
        format!("{name}{suffix}")
    }
}

fn archive_source_name(path: &str, parent: &mut Option<String>) -> Result<String, String> {
    let source_parent = parent_path(path).unwrap_or_else(|| "/".to_string());
    let source_name = path_name(path);
    let command_path = join_path(&source_parent, &source_name);
    if command_path.as_str() != path {
        return Err("Invalid archive source path".to_string());
    }
    if parent
        .as_ref()
        .is_some_and(|expected| expected != &source_parent)
    {
        return Err("All archive sources must share one parent directory".to_string());
    }
    let _ = parent.get_or_insert(source_parent);
    Ok(source_name)
}

fn managed_local_status(ctx: &Ctx, state_file: &str, operation: &str) -> Option<Value> {
    let current = tasks::read_state(state_file);
    let want = ctx.params.get("task_id").filter(|id| !id.is_empty());
    let id = match want {
        Some(ref id) if id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit()) => id.clone(),
        Some(_) => return None, // older single-slot identifier
        None => current.as_ref()?.get("task_id")?.as_str()?.to_string(),
    };
    if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let status = match ctx.st.tasks.job_status(&id) {
        Ok(status) => status,
        Err(_) => {
            return Some(json!({"task_id": id, "state": "unknown", "done": true,
            "success": false, "message": "Task status is unknown"}))
        }
    };
    if status["state"] == json!("gone")
        || status["operation"] != json!(operation)
        || !matches!(
            status["executor"].as_str(),
            Some("local_process" | "local_immediate")
        )
    {
        return Some(json!({"task_id": id, "state": "gone", "done": true, "success": false}));
    }
    Some(status)
}

fn local_job_busy(ctx: &Ctx, state_file: &str, rcfile: &str) -> bool {
    let Some(state) = tasks::read_state(state_file) else {
        return tasks::task_running(state_file, rcfile);
    };
    if state["executor"] == json!("local_process") {
        if let Some(id) = state["task_id"].as_str() {
            if let Ok(status) = ctx.st.tasks.job_status(id) {
                if status["done"] == json!(false) {
                    return true;
                }
                // If the service died before recording a PID, do not start a
                // second potentially mutating task without operator review.
                if status["state"] == json!("unknown") && !tasks::task_finished(rcfile) {
                    let pid = state["pid"].as_i64().unwrap_or(0);
                    // An unrecorded PID or a still-live PID with an unverified
                    // identity could be the old worker. Never overlap it.
                    if pid == 0 || tasks::process_alive(pid) {
                        return true;
                    }
                }
                return false;
            }
        }
    }
    tasks::task_running(state_file, rcfile)
}

#[derive(Clone, Copy)]
struct LocalTaskFiles {
    state: &'static str,
    log: &'static str,
    rc: &'static str,
}
const ARCHIVE_FILES: LocalTaskFiles = LocalTaskFiles {
    state: ARCHIVE_STATE_FILE,
    log: ARCHIVE_LOG,
    rc: ARCHIVE_RC,
};
const PACKAGE_FILES: LocalTaskFiles = LocalTaskFiles {
    state: PACKAGE_STATE_FILE,
    log: PACKAGE_LOG,
    rc: PACKAGE_RC,
};
const THUMBNAIL_FILES: LocalTaskFiles = LocalTaskFiles {
    state: THUMBNAIL_STATE_FILE,
    log: THUMBNAIL_LOG,
    rc: THUMBNAIL_RC,
};

fn start_local_process(
    ctx: &Ctx,
    task: Value,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    header: &str,
    files: LocalTaskFiles,
) -> Response {
    let process = crate::task_registry::LocalProcess {
        program: program.to_string(),
        args: args.to_vec(),
        cwd: cwd.map(str::to_string),
        header: header.to_string(),
        legacy_state: files.state,
        legacy_log: files.log,
        legacy_rc: files.rc,
    };
    match ctx.st.tasks.spawn_process(task, process) {
        Ok(task) => ok(task),
        Err(error) => fail(1, &error, Value::Null),
    }
}

pub async fn api_archive_create_start(ctx: &Ctx) -> Response {
    run_blocking(ctx, api_archive_create_start_blocking).await
}

fn api_archive_create_start_blocking(
    ctx: &Ctx,
    cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Response {
    if !tasks::ensure_runtime_dir() {
        return fail(1, "Cannot create runtime directory", Value::Null);
    }
    let _start_guard = match try_start_lock(
        &ARCHIVE_START_LOCK,
        "Another archive task is already running",
    ) {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let dest_dir = match ctx.write_path(
        &ctx.params
            .first_of(&["target_dir", "path"])
            .unwrap_or_default(),
    ) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if !meta::stat(&dest_dir).is_some_and(|info| info.kind == Kind::Directory) {
        return fail(1, "Target is not an existing directory", Value::Null);
    }
    if local_job_busy(ctx, ARCHIVE_STATE_FILE, ARCHIVE_RC) {
        return fail_status(
            StatusCode::CONFLICT,
            1,
            "Another archive task is already running",
            Value::Null,
        );
    }
    let mut name = ctx
        .params
        .first_of(&["output_name", "name"])
        .unwrap_or_default();
    if !paths::valid_component(&name) {
        return fail(1, "Invalid archive name", Value::Null);
    }
    let format = ctx.params.str_or("format", "tar.gz");
    if !["tar", "tar.gz", "zip"].contains(&format.as_str()) {
        return fail(1, "Unsupported archive format", Value::Null);
    }
    name = archive_named(&name, &format);
    let sources = ctx
        .params
        .path_array("sources")
        .or_else(|| ctx.params.path_array("paths"))
        .unwrap_or_default();
    if sources.is_empty() {
        return fail(1, "No source given", Value::Null);
    }
    let mut parent: Option<String> = None;
    let mut rel: Vec<String> = Vec::new();
    let mut checked_sources: Vec<String> = Vec::new();
    for raw in &sources {
        if let Err(error) = ctx.read_tree(raw) {
            return error.into_response();
        }
        let p = match ctx.read_path(raw) {
            Ok(path) if meta::lstat(&path).is_some() => path,
            Ok(_) => return fail(1, &format!("Source not found: {raw}"), Value::Null),
            Err(error) => return error.into_response(),
        };
        let source_name = match archive_source_name(&p, &mut parent) {
            Ok(name) => name,
            Err(message) => return fail(1, &message, Value::Null),
        };
        rel.push(source_name);
        checked_sources.push(paths::canonical(&p).unwrap_or(p));
    }
    let parent = parent.unwrap_or_else(|| "/".to_string());
    let target = match ctx.create_path(&join_path(&dest_dir, &name)) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    let policy_target = paths::canonical_for_policy(&target).unwrap_or_else(|| target.clone());
    for source in &checked_sources {
        if source == &policy_target || paths::is_descendant(source, &policy_target) {
            return fail(
                5,
                "The archive cannot be written inside its own source",
                Value::Null,
            );
        }
    }
    let existing = meta::lstat(&target);
    if existing.is_some() && ctx.params.get("overwrite").as_deref() != Some("1") {
        return fail(
            3,
            "archive already exists",
            json!({
                "output_path": target,
                "target_is_directory": existing.map(|m| m.kind == Kind::Directory).unwrap_or(false)
            }),
        );
    }
    let plan = match archive_create_plan(&format, &target, &rel) {
        Some(plan) => plan,
        None => return fail(1, "Unsupported archive format", Value::Null),
    };
    for tool in archive_required_tools(plan.kind, plan.program) {
        if let Err(error) = require_archive_tool(tool) {
            return missing_archive_tool(error);
        }
    }
    if existing.is_some() {
        if let Err(error) = ctx.write_tree(&target) {
            return error.into_response();
        }
    }
    if let Some(response) = start_cancelled(cancelled) {
        return response;
    }
    let program = plan.program;
    let args = plan.args;
    let header = format!("{program} {}", args.join(" "));
    let task = json!({
        "operation": "archive", "mode": "create", "format": format,
        "command": header.chars().take(4096).collect::<String>(),
        "output_path": target, "target_dir": dest_dir,
        "done": false, "success": false, "state": "running", "started": meta::now_secs()
    });
    if existing.is_some() {
        // Do not remove the old target in the HTTP/preflight path: launching
        // a registry worker can still fail. Perform that side effect only in
        // the scheduled process, whose result can be reconciled by task id.
        let mut wrapper = vec![
            "-c".to_string(),
            "target=$1; shift; rm -rf -- \"$target\" || exit; exec \"$@\"".to_string(),
            "harbor-archive-create".to_string(),
            target.clone(),
            program.to_string(),
        ];
        wrapper.extend(args);
        start_local_process(
            ctx,
            task,
            "/bin/sh",
            &wrapper,
            Some(&parent),
            &header,
            ARCHIVE_FILES,
        )
    } else {
        start_local_process(
            ctx,
            task,
            program,
            &args,
            Some(&parent),
            &header,
            ARCHIVE_FILES,
        )
    }
}

pub async fn api_archive_extract_start(ctx: &Ctx) -> Response {
    run_blocking(ctx, api_archive_extract_start_blocking).await
}

fn api_archive_extract_start_blocking(
    ctx: &Ctx,
    cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Response {
    if !tasks::ensure_runtime_dir() {
        return fail(1, "Cannot create runtime directory", Value::Null);
    }
    let _start_guard = match try_start_lock(
        &ARCHIVE_START_LOCK,
        "Another archive task is already running",
    ) {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let dest_dir = match ctx.create_path(
        &ctx.params
            .first_of(&["target_dir", "destination"])
            .unwrap_or_default(),
    ) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if local_job_busy(ctx, ARCHIVE_STATE_FILE, ARCHIVE_RC) {
        return fail_status(
            StatusCode::CONFLICT,
            1,
            "Another archive task is already running",
            Value::Null,
        );
    }
    let src = match ctx.params.first_of(&["path", "archive", "source"]) {
        Some(raw) => match ctx.read_path(&raw) {
            Ok(path) if meta::lstat(&path).is_some() => path,
            Ok(_) => return fail(1, "Archive not found", Value::Null),
            Err(error) => return error.into_response(),
        },
        None => return fail(1, "Archive not found", Value::Null),
    };
    let members = match parse_archive_members(ctx.params.get("members")) {
        Ok(m) => m,
        Err(e) => return fail(1, &e, Value::Null),
    };
    let ext = paths::file_extension(&src);
    let kind = match archive_kind_for_path(&src) {
        Some(kind) => kind,
        None => return fail(1, "Unsupported archive format", Value::Null),
    };
    let plan = match archive_extract_plan(&src, kind, members.as_deref(), ARCHIVE_SEL_FILE) {
        Ok(plan) => plan,
        Err(error) => return fail(1, &error.message, Value::Null),
    };
    for tool in archive_required_tools(plan.kind, plan.program) {
        if let Err(error) = require_archive_tool(tool) {
            return missing_archive_tool(error);
        }
    }
    let archive_members = match archive_member_names(&src, kind, cancelled) {
        Ok(result) => result,
        Err(error) => return fail(1, &error.message, json!({ "detail": error.detail })),
    };
    let paths_to_extract = match archive_selection_paths(&archive_members, members.as_deref()) {
        Ok(paths) => paths,
        Err(message) => return fail(1, &message, Value::Null),
    };
    let execution_members = match archive_selection_arguments(&archive_members, members.as_deref())
    {
        Ok(names) => names,
        Err(message) => return fail(1, &message, Value::Null),
    };
    // Validate the whole archive, including legacy header aliases: extractors
    // differ on PAX/GNU extensions and selection matching.
    let all_paths = archive_selection_paths(&archive_members, None).unwrap_or_default();
    for member in &all_paths {
        if let Err(error) = ctx.create_path(&join_path(&dest_dir, member)) {
            return error.into_response();
        }
    }
    if let Err(message) = check_local_archive_destinations(&dest_dir, &all_paths) {
        return fail(1, &message, Value::Null);
    }
    let program = plan.program;
    let args = plan.args;
    let shell_redirect = plan.redirect;

    if let Some(response) = start_cancelled(cancelled) {
        return response;
    }
    if !meta::mkdir_p(&dest_dir) {
        return fail(5, "Cannot create the destination directory", Value::Null);
    }
    match meta::stat(&dest_dir) {
        Some(m) if m.kind == Kind::Directory => {}
        _ => return fail(5, "Destination is not a directory", Value::Null),
    }

    if let Some(list) = &execution_members {
        let body = list.join("\n") + "\n";
        if fs::write(ARCHIVE_SEL_FILE, body).is_err() {
            return fail(1, "Write failed", Value::Null);
        }
        let _ = fs::set_permissions(
            ARCHIVE_SEL_FILE,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        );
    }

    if ctx.params.get("overwrite").as_deref() != Some("1") {
        let entries: Vec<String> = match &shell_redirect {
            Some(name) => vec![name.clone()],
            None => paths_to_extract.clone(),
        };
        let clash: Vec<String> = top_levels(&entries)
            .into_iter()
            .filter(|name| meta::lstat(&join_path(&dest_dir, name)).is_some())
            .collect();
        if !clash.is_empty() {
            return fail(
                3,
                "the destination already contains these entries",
                json!({
                    "conflicts": clash,
                    "destination_path": dest_dir,
                    "path": src
                }),
            );
        }
    }

    let (program, args) = match shell_redirect {
        None => (program.to_string(), args),
        Some(out) => (
            "/bin/sh".to_string(),
            vec![
                "-c".to_string(),
                format!(
                    "{program} {} \"$1\" > \"$2\"",
                    if program == "gunzip" { "-c" } else { "-xOf" }
                ),
                "harbor-extract".to_string(),
                src.clone(),
                out,
            ],
        ),
    };

    let header = format!("{} {}", program, args.join(" "));
    let task = json!({
        "operation": "archive", "mode": "extract", "format": ext,
        "command": header.chars().take(4096).collect::<String>(), "path": src,
        "destination_path": dest_dir, "target_dir": dest_dir,
        "done": false, "success": false, "state": "running", "started": meta::now_secs()
    });
    if let Some(response) = start_cancelled(cancelled) {
        return response;
    }
    start_local_process(
        ctx,
        task,
        &program,
        &args,
        Some(&dest_dir),
        &header,
        ARCHIVE_FILES,
    )
}

pub fn parse_archive_members(raw: Option<String>) -> Result<Option<Vec<String>>, String> {
    let raw = match raw {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };
    let value: Value = serde_json::from_str(&raw).map_err(|_| "Invalid name".to_string())?;
    let arr = value.as_array().ok_or_else(|| "Invalid name".to_string())?;
    let mut out = Vec::new();
    for item in arr {
        let name = item.as_str().ok_or_else(|| "Invalid name".to_string())?;
        if !safe_archive_member(name) || name.starts_with('-') {
            return Err("Invalid name".to_string());
        }
        out.push(name.to_string());
    }
    Ok(if out.is_empty() { None } else { Some(out) })
}

fn safe_archive_member(name: &str) -> bool {
    crate::archive_inspect::safe_name(name)
}

pub(crate) fn archive_selection_paths(
    archive_members: &[crate::archive_inspect::Member],
    selected: Option<&[String]>,
) -> Result<Vec<String>, String> {
    let mut paths = Vec::new();
    if let Some(selected) = selected {
        for selected_path in selected {
            if !safe_archive_member(selected_path) {
                return Err("Invalid archive member".into());
            }
            let prefix = format!("{selected_path}/");
            if !archive_members
                .iter()
                .any(|m| m.name == *selected_path || m.name.starts_with(&prefix))
            {
                return Err("Archive member not found".into());
            }
        }
    }
    for member in archive_members {
        let included = selected.is_none_or(|selected| {
            selected
                .iter()
                .any(|path| member.name == *path || member.name.starts_with(&format!("{path}/")))
        });
        if included {
            for name in std::iter::once(&member.name).chain(member.fallback.iter()) {
                if !paths.contains(name) {
                    paths.push(name.clone());
                }
            }
        }
    }
    Ok(paths)
}

// -T expects the archive's original spelling (notably leading './'). Expanding
// selected directories also handles archives that omit explicit dir entries.
pub(crate) fn archive_selection_arguments(
    archive_members: &[crate::archive_inspect::Member],
    selected: Option<&[String]>,
) -> Result<Option<Vec<String>>, String> {
    let Some(selected) = selected else {
        return Ok(None);
    };
    archive_selection_paths(archive_members, Some(selected))?;
    let mut candidates: Vec<_> = archive_members
        .iter()
        .filter(|member| {
            selected
                .iter()
                .any(|path| member.name == *path || member.name.starts_with(&format!("{path}/")))
        })
        .collect();
    candidates.sort_by_key(|member| member.name.len());
    let mut selectors = Vec::new();
    let mut selected_dirs: Vec<&str> = Vec::new();
    for member in candidates {
        if selected_dirs
            .iter()
            .any(|dir| member.name.starts_with(&format!("{dir}/")))
        {
            continue;
        }
        let selector = &member.selector;
        // GNU tar treats '-' lines in -T as options; BSD tar treats glob
        // metacharacters as patterns. Never turn a member into either.
        // Listing a directory and its children together makes GNU tar exit 2
        // ("Not found in archive") after the directory has already been read.
        if selector.starts_with('-') || selector.contains(['*', '?', '[', ']']) {
            return Err("This archive member cannot be selected safely".into());
        }
        if !selectors.contains(selector) {
            selectors.push(selector.clone());
        }
        if member.is_dir && !selected_dirs.contains(&member.name.as_str()) {
            selected_dirs.push(&member.name);
        }
    }
    Ok(Some(selectors))
}

pub(crate) fn archive_destination_paths(
    base: &str,
    names: &[String],
) -> Result<Vec<String>, String> {
    let mut paths = vec![base.to_string()];
    let mut seen = std::collections::HashSet::new();
    for name in names {
        let mut current = base.to_string();
        for part in name
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
        {
            current = join_path(&current, part);
            if seen.insert(current.clone()) {
                if paths.len() >= 16_384 {
                    return Err("Archive is too large to validate safely".into());
                }
                paths.push(current.clone());
            }
        }
    }
    Ok(paths)
}

pub(crate) fn check_local_archive_destinations(base: &str, names: &[String]) -> Result<(), String> {
    for candidate in archive_destination_paths(base, names)? {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("Archive destination contains a symbolic link".into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Cannot safely inspect archive destination".into()),
        }
    }
    Ok(())
}

fn top_levels(names: &[String]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for name in names {
        let top = name.split('/').next().unwrap_or("").to_string();
        if top.is_empty() || seen.iter().any(|s| s == &top) {
            continue;
        }
        seen.push(top);
    }
    seen
}

fn archive_output_lines(text: &str) -> usize {
    text.lines()
        .filter(|line| {
            let s = line.trim();
            !s.is_empty() && !s.starts_with("$ ") && !s.starts_with("-- exit")
        })
        .count()
}

pub async fn api_archive_status(ctx: &Ctx) -> Response {
    let managed = managed_local_status(ctx, ARCHIVE_STATE_FILE, "archive");
    let is_managed = managed.is_some();
    let mut st = match managed.or_else(|| tasks::read_state(ARCHIVE_STATE_FILE)) {
        Some(v) => v,
        None => {
            if !tasks::task_finished(ARCHIVE_RC) {
                return ok(json!({ "state": "idle", "done": true, "success": false }));
            }
            let rc = tasks::task_exit_code(ARCHIVE_RC);
            return ok(json!({
                "state": if rc == 0 { "success" } else { "failed" },
                "done": true,
                "success": rc == 0,
                "exit_code": rc,
                "log": tasks::read_log(ARCHIVE_LOG, 8192)
            }));
        }
    };
    if let Some(want) = ctx.params.get("task_id") {
        if !want.is_empty() && st["task_id"].as_str().map(|s| s != want).unwrap_or(false) {
            return ok(json!({ "task_id": want, "state": "gone", "done": true, "success": false }));
        }
    }
    let done = st["done"].as_bool().unwrap_or(false);
    if !done && !is_managed {
        let finished = tasks::task_finished(ARCHIVE_RC);
        let pid = st["pid"].as_i64().unwrap_or(0);
        if finished || (pid > 0 && !tasks::process_alive(pid)) {
            let rc = tasks::task_exit_code(ARCHIVE_RC);
            st["exit_code"] = json!(rc);
            st["success"] = json!(rc == 0);
            st["state"] = json!(if rc == 0 { "success" } else { "failed" });
            st["done"] = json!(true);
            st["finished"] = json!(meta::now_secs());
            tasks::write_state(ARCHIVE_STATE_FILE, &st);
        }
    }
    let log = if is_managed {
        st["log"].as_str().unwrap_or("").to_string()
    } else {
        tasks::read_log(ARCHIVE_LOG, 8192)
    };
    st["log"] = json!(log.clone());
    let done = st["done"].as_bool().unwrap_or(false);
    let success = st["success"].as_bool().unwrap_or(false);
    if done && success && st["mode"] == json!("extract") && archive_output_lines(&log) == 0 {
        st["success"] = json!(false);
        st["state"] = json!("failed");
        st["message"] = json!("The archive produced no files");
    } else if done && !success && st.get("message").map(|m| m.is_null()).unwrap_or(true) {
        let rc = st["exit_code"].as_i64().unwrap_or(-1);
        st["message"] = json!(if rc < 0 {
            "Archive task ended unexpectedly".to_string()
        } else {
            format!("Command exited with status {rc}")
        });
    }
    ok(st)
}

pub(crate) fn detect_package_manager() -> Option<&'static str> {
    if meta::have_tool("apk") {
        Some("apk")
    } else if meta::have_tool("opkg") {
        Some("opkg")
    } else {
        None
    }
}

fn start_install(
    ctx: &Ctx,
    packages: &[String],
    label: &str,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Response {
    if !tasks::ensure_runtime_dir() {
        return fail(1, "Cannot create runtime directory", Value::Null);
    }
    let _start_guard = match try_start_lock(
        &PACKAGE_START_LOCK,
        "Another installation is already running",
    ) {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    if local_job_busy(ctx, PACKAGE_STATE_FILE, PACKAGE_RC) {
        return fail_status(
            StatusCode::CONFLICT,
            1,
            "Another installation is already running",
            Value::Null,
        );
    }
    let pm = match detect_package_manager() {
        Some(p) => p,
        None => return fail(1, "No supported package manager found", Value::Null),
    };

    let script = if pm == "apk" {
        "apk update; apk add \"$@\""
    } else {
        "opkg update; opkg install \"$@\""
    };
    let mut args: Vec<String> = vec!["-c".into(), script.into(), "harbor-install".into()];
    args.extend(packages.iter().cloned());
    let header = format!("{pm} install {}", packages.join(" "));
    let task = json!({
        "operation": "package_install", "label": label, "packages": packages,
        "package_name": packages.join(" "), "package_type": "repository", "installer": pm,
        "path": packages.join(" "), "state": "running", "done": false, "success": false,
        "started": meta::now_secs()
    });
    if let Some(response) = start_cancelled(cancelled) {
        return response;
    }
    start_local_process(ctx, task, "/bin/sh", &args, None, &header, PACKAGE_FILES)
}

fn start_tool_install(
    ctx: &Ctx,
    tool: &str,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Response {
    if !crate::tools::valid_name(tool) {
        return fail(1, "Invalid tool name", Value::Null);
    }
    if matches!(tool, "ssh" | "sshpass" | "sftp" | "scp" | "timeout") {
        return fail(
            1,
            "SSH uses the built-in russh client; this tool is not installed locally",
            Value::Null,
        );
    }
    let already = crate::remote::local_tool_available(tool);
    if already {
        return ok(crate::tools::installed_tool(tool));
    }
    let packages = crate::tools::packages_for_tool(tool);
    start_install(ctx, &packages, tool, cancelled)
}

pub async fn api_tool_install_start(ctx: &Ctx) -> Response {
    run_blocking(ctx, api_tool_install_start_blocking).await
}

fn api_tool_install_start_blocking(
    ctx: &Ctx,
    cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Response {
    if let Some(tool) = ctx.params.get("tool").filter(|t| !t.is_empty()) {
        return start_tool_install(ctx, &tool, cancelled);
    }
    let raw = ctx.params.get("packages").unwrap_or_default();
    let packages: Vec<String> = if raw.is_empty() {
        Vec::new()
    } else {
        match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|value| value.to_string())
                        .unwrap_or_default()
                })
                .collect(),
            _ => raw
                .split([' ', ','])
                .filter(|s| !s.is_empty())
                .map(|value| value.to_string())
                .collect(),
        }
    };
    if packages.is_empty()
        || packages.len() > 64
        || packages
            .iter()
            .any(|package| !crate::tools::valid_package(package))
    {
        return fail(1, "Invalid package name", Value::Null);
    }
    let label = ctx.params.str_or("label", "tool");
    start_install(ctx, &packages, &label, cancelled)
}

pub async fn api_package_install_start(ctx: &Ctx) -> Response {
    run_blocking(ctx, api_package_install_start_blocking).await
}

fn api_package_install_start_blocking(
    ctx: &Ctx,
    cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Response {
    if !tasks::ensure_runtime_dir() {
        return fail(1, "Cannot create runtime directory", Value::Null);
    }
    let _start_guard = match try_start_lock(
        &PACKAGE_START_LOCK,
        "Another installation is already running",
    ) {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let path = match ctx.read_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if local_job_busy(ctx, PACKAGE_STATE_FILE, PACKAGE_RC) {
        return fail_status(
            StatusCode::CONFLICT,
            1,
            "Another package installation is already running",
            Value::Null,
        );
    }
    match meta::stat(&path) {
        Some(m) if m.kind == Kind::File => {}
        _ => {
            return fail_status(
                StatusCode::BAD_REQUEST,
                1,
                "Package file not found",
                Value::Null,
            )
        }
    }
    let ext = paths::file_extension(&path);
    let (installer, args): (&str, Vec<&str>) = match ext.as_str() {
        "ipk" => ("opkg", vec!["install"]),
        "apk" => ("apk", vec!["add", "--allow-untrusted"]),
        _ => {
            return fail_status(
                StatusCode::BAD_REQUEST,
                1,
                "Unsupported package type",
                Value::Null,
            )
        }
    };
    if !meta::have_tool(installer) {
        return fail(
            1,
            &format!("{installer} is not available on this system"),
            Value::Null,
        );
    }
    let mut command_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    command_args.push(path.clone());
    let header = format!("{installer} {} {path}", args.join(" "));
    let task = json!({
        "operation": "package_install", "path": path, "package_name": path_name(&path),
        "package_type": ext, "installer": installer, "state": "running", "done": false,
        "success": false, "started": meta::now_secs()
    });
    if let Some(response) = start_cancelled(cancelled) {
        return response;
    }
    start_local_process(
        ctx,
        task,
        installer,
        &command_args,
        None,
        &header,
        PACKAGE_FILES,
    )
}

pub async fn api_package_install_status(ctx: &Ctx) -> Response {
    install_status(ctx, PACKAGE_STATE_FILE, PACKAGE_LOG, PACKAGE_RC)
}

fn install_status(ctx: &Ctx, state_file: &str, logfile: &str, rcfile: &str) -> Response {
    let managed = managed_local_status(ctx, state_file, "package_install");
    let is_managed = managed.is_some();
    let mut st = match managed.or_else(|| tasks::read_state(state_file)) {
        Some(v) => v,
        None => {
            if !tasks::task_finished(rcfile) {
                return ok(json!({ "state": "idle", "done": true, "success": false }));
            }
            let rc = tasks::task_exit_code(rcfile);
            return ok(json!({
                "state": if rc == 0 { "success" } else { "failed" },
                "done": true,
                "success": rc == 0,
                "exit_code": rc,
                "message": if rc == 0 { "Installation finished".to_string() } else { format!("Installation failed (exit {rc})") },
                "log": tasks::read_log(logfile, 16384)
            }));
        }
    };
    if let Some(want) = ctx.params.get("task_id") {
        if !want.is_empty() && st["task_id"].as_str().map(|s| s != want).unwrap_or(false) {
            return ok(json!({ "task_id": want, "state": "gone", "done": true, "success": false }));
        }
    }
    let done = st["done"].as_bool().unwrap_or(false);
    if !done && !is_managed {
        let finished = tasks::task_finished(rcfile);
        let pid = st["pid"].as_i64().unwrap_or(0);
        if finished || (pid > 0 && !tasks::process_alive(pid)) {
            let rc = tasks::task_exit_code(rcfile);
            st["exit_code"] = json!(rc);
            st["success"] = json!(rc == 0);
            st["state"] = json!(if rc == 0 { "success" } else { "failed" });
            st["done"] = json!(true);
            st["finished"] = json!(meta::now_secs());
            tasks::write_state(state_file, &st);
        }
    }
    if !is_managed {
        st["log"] = json!(tasks::read_log(logfile, 16384));
    }
    let done = st["done"].as_bool().unwrap_or(false);
    let success = st["success"].as_bool().unwrap_or(false);
    let exit_code = st["exit_code"].as_i64().unwrap_or(-1);
    let has_message = st
        .get("message")
        .map(|m| m.as_str().map(|s| !s.is_empty()).unwrap_or(false))
        .unwrap_or(false);
    if done && !success && exit_code < 0 && st["state"] != json!("unknown") {
        st["message"] = json!("Install task ended unexpectedly");
    } else if !has_message {
        st["message"] = json!(if done {
            if success {
                "Installation finished".to_string()
            } else {
                format!("Installation failed (exit {exit_code})")
            }
        } else {
            "installing...".to_string()
        });
    }
    ok(st)
}

fn thumbnail_jobs(
    ctx: &Ctx,
    items: &[Value],
    prefs: &crate::config::Prefs,
) -> (Vec<(String, String)>, i64) {
    let mut jobs: Vec<(String, String)> = Vec::new();
    let mut cached = 0i64;
    for it in items {
        if it["type"] != json!("file") {
            continue;
        }
        let ext = it["extension"].as_str().unwrap_or("");
        if meta::image_mime(ext).is_none() {
            continue;
        }
        let path = it["path"].as_str().unwrap_or("").to_string();
        // Directory listing is not an authorization grant for each entry:
        // links may point outside the permitted roots or into system folders.
        if ctx.read_path(&path).is_err() {
            continue;
        }
        let st = match meta::stat(&path) {
            Some(m) => m,
            None => continue,
        };
        let cp = match crate::api::fsops::thumbnail_cache_path(&path, &st, prefs) {
            Some(c) => c,
            None => continue,
        };
        if meta::stat(&cp).is_some() {
            cached += 1;
        } else {
            jobs.push((path, cp));
        }
    }
    (jobs, cached)
}

pub async fn api_thumbnail_generate_start(ctx: &Ctx) -> Response {
    run_blocking(ctx, api_thumbnail_generate_start_blocking).await
}

fn api_thumbnail_generate_start_blocking(
    ctx: &Ctx,
    cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Response {
    if !tasks::ensure_runtime_dir() {
        return fail(1, "Cannot create runtime directory", Value::Null);
    }
    let _start_guard = match try_start_lock(
        &THUMBNAIL_START_LOCK,
        "Thumbnail generation is already running",
    ) {
        Ok(guard) => guard,
        Err(response) => return response,
    };
    let dir = match ctx.read_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if !meta::have_tool("gm") {
        return fail_status(
            StatusCode::FAILED_DEPENDENCY,
            2,
            "GraphicsMagick is not installed",
            json!({
                "missing_tool": "gm",
                "package_name": crate::tools::package_for("gm"),
                "installer": detect_package_manager().unwrap_or("opkg"),
                "dependency_missing": true,
                "dependency_preflight": true,
                "path": dir
            }),
        );
    }
    if local_job_busy(ctx, THUMBNAIL_STATE_FILE, THUMBNAIL_RC) {
        return fail_status(
            StatusCode::CONFLICT,
            1,
            "Thumbnail generation is already running",
            Value::Null,
        );
    }
    let prefs = ctx.prefs();
    let cache = match crate::api::fsops::thumbnail_cache_dir(&prefs) {
        Some(c) => c,
        None => return fail(1, "Invalid home directory", Value::Null),
    };
    meta::mkdir_p(&cache);
    let items = match crate::api::fsops::list_directory(&dir, &prefs) {
        Ok(v) => v,
        Err(e) => return fail(2, &e, Value::Null),
    };
    let (jobs, cached) = thumbnail_jobs(ctx, &items, &prefs);
    if jobs.is_empty() {
        let empty = json!({
            "operation": "thumbnail", "state": "running", "done": false, "success": false,
            "path": dir, "directory": dir, "total": 0, "processed": 0, "success_count": 0,
            "failed_count": 0, "cached_count": cached, "current_file": ""
        });
        if let Some(response) = start_cancelled(cancelled) {
            return response;
        }
        return match ctx.st.tasks.record_completed(
            empty,
            THUMBNAIL_STATE_FILE,
            THUMBNAIL_LOG,
            THUMBNAIL_RC,
        ) {
            Ok(task) => ok(task),
            Err(error) => fail(1, &error, Value::Null),
        };
    }

    let manifest_path = "/tmp/harbor_file_pro/harbor_file_pro_thumbnail.json".to_string();
    let manifest = json!({
        "size": crate::api::fsops::THUMBNAIL_SIZE,
        "jobs": jobs.iter().map(|(src, dst)| json!({ "src": src, "dst": dst })).collect::<Vec<_>>()
    });
    if crate::private_file::atomic_replace(
        std::path::Path::new(&tasks::runtime_dir()),
        "harbor_file_pro_thumbnail.json",
        &serde_json::to_vec(&manifest).unwrap_or_default(),
    )
    .is_err()
    {
        return fail(1, "Cannot create thumbnail script", Value::Null);
    }
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/usr/sbin/harbor-core".to_string());
    let args = vec![
        "thumbnail-worker".to_string(),
        manifest_path.clone(),
        THUMBNAIL_LOG.to_string(),
    ];
    let task = json!({
        "operation": "thumbnail", "state": "running", "done": false, "success": false,
        "path": dir, "directory": dir, "total": jobs.len(), "processed": 0,
        "success_count": 0, "failed_count": 0, "cached_count": cached,
        "current_file": "", "started": meta::now_secs()
    });
    if let Some(response) = start_cancelled(cancelled) {
        return response;
    }
    start_local_process(ctx, task, &exe, &args, None, "", THUMBNAIL_FILES)
}

pub async fn api_thumbnail_generate_status(ctx: &Ctx) -> Response {
    let managed = managed_local_status(ctx, THUMBNAIL_STATE_FILE, "thumbnail");
    let is_managed = managed.is_some();
    let mut st = match managed.or_else(|| tasks::read_state(THUMBNAIL_STATE_FILE)) {
        Some(v) => v,
        None => {
            return ok(json!({
                "state": "idle", "done": true, "success": true,
                "total": 0, "processed": 0, "success_count": 0,
                "failed_count": 0, "cached_count": 0, "current_file": ""
            }))
        }
    };
    if let Some(want) = ctx.params.get("task_id") {
        if !want.is_empty() && st["task_id"].as_str().map(|s| s != want).unwrap_or(false) {
            return ok(json!({ "task_id": want, "state": "gone", "done": true, "success": false }));
        }
    }
    let log = if is_managed {
        st["log"].as_str().unwrap_or("").to_string()
    } else {
        tasks::read_log(THUMBNAIL_LOG, 8192)
    };
    let mut okc = 0i64;
    let mut failc = 0i64;
    let mut current = String::new();
    for line in log.lines() {
        if line.starts_with("OK ") {
            okc += 1;
            current.clear();
        } else if line.starts_with("FAIL ") {
            failc += 1;
            current.clear();
        } else if let Some(rest) = line.strip_prefix("BEGIN ") {
            current = rest.to_string();
        }
    }
    st["success_count"] = json!(okc);
    st["failed_count"] = json!(failc);
    st["processed"] = json!(okc + failc);
    st["current_file"] = json!(current);
    st["log"] = json!(log);
    let done = st["done"].as_bool().unwrap_or(false);
    if !done
        && !is_managed
        && (tasks::task_finished(THUMBNAIL_RC) || {
            let pid = st["pid"].as_i64().unwrap_or(0);
            pid > 0 && !tasks::process_alive(pid)
        })
    {
        let rc = tasks::task_exit_code(THUMBNAIL_RC);
        st["current_file"] = json!("");
        st["exit_code"] = json!(rc);
        st["success"] = json!(failc == 0 && rc == 0);
        st["state"] = json!(if failc == 0 && rc == 0 {
            "success"
        } else {
            "failed"
        });
        st["done"] = json!(true);
        st["finished"] = json!(meta::now_secs());
        tasks::write_state(THUMBNAIL_STATE_FILE, &st);
    }
    let done = st["done"].as_bool().unwrap_or(false);
    let success = st["success"].as_bool().unwrap_or(false);
    if done && !success && st["state"] != json!("unknown") {
        let rc = st["exit_code"].as_i64().unwrap_or(-1);
        st["message"] = json!(if rc < 0 {
            "Thumbnail generation ended unexpectedly".to_string()
        } else {
            format!(
                "{failc} of {} thumbnails failed",
                st["total"].as_i64().unwrap_or(0)
            )
        });
    }
    ok(st)
}

#[cfg(test)]
// Fixture tests intentionally serialize shared environment/process state across awaits.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_archive_preflight_returns_busy_without_blocking_async_executor() {
        let _serial = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = scratch();
        fs::create_dir_all(&root).unwrap();
        let st = crate::state::AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            ..Default::default()
        });
        let ctx = Ctx {
            st: st.clone(),
            params: Default::default(),
            method: axum::http::Method::POST,
            headers: Default::default(),
        };
        let guard = ARCHIVE_START_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            api_archive_create_start(&ctx),
        )
        .await
        .expect("archive preflight blocked the async executor");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        drop(guard);
        drop(ctx);
        drop(st);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bounded_archive_listing_handles_large_output_and_cancellation() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        use std::time::{Duration, Instant};
        let flag = Arc::new(AtomicBool::new(false));
        let (stdout, _, rc, truncated) = bounded_listing(
            "/bin/sh",
            &[
                "-c".into(),
                "head -c 200000 /dev/zero | tr '\\0' x; printf '\\n'".into(),
            ],
            &flag,
            400000,
        )
        .unwrap();
        assert_eq!(rc, 0);
        assert!(!truncated);
        assert_eq!(stdout.len(), 200001);
        let (_, _, _, truncated) =
            bounded_listing("/bin/sh", &["-c".into(), "yes a".into()], &flag, 10000).unwrap();
        assert!(truncated);
        let worker_flag = flag.clone();
        let start = Instant::now();
        let worker = std::thread::spawn(move || {
            bounded_listing(
                "/bin/sh",
                &["-c".into(), "exec sleep 30".into()],
                &worker_flag,
                10000,
            )
        });
        std::thread::sleep(Duration::from_millis(100));
        flag.store(true, Ordering::Release);
        assert!(worker.join().unwrap().unwrap_err().contains("cancelled"));
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn inferred_archive_directories_obey_output_limit() {
        let lines = vec![format!(
            "{}/file",
            (0..1000).map(|_| "a").collect::<Vec<_>>().join("/")
        )];
        let (entries, truncated) = parse_archive_entries(&lines, false, 10);
        assert_eq!(entries.len(), 10);
        assert!(truncated);
    }

    #[test]
    fn busybox_shell_overwrite_wrapper_removes_old_target_then_executes() {
        if std::process::Command::new("busybox")
            .arg("true")
            .status()
            .is_err()
        {
            return;
        }
        let root = scratch();
        let src = root.join("source");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("-name"), b"content").unwrap();
        let target = root.join("target.tar");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("old"), b"old").unwrap();
        let plan = archive_create_plan("tar", target.to_str().unwrap(), &["-name".into()]).unwrap();
        let mut cmd = std::process::Command::new("busybox");
        let mut args = vec![
            "sh".to_string(),
            "-c".into(),
            "target=$1; shift; rm -rf -- \"$target\" || exit; exec \"$@\"".into(),
            "harbor-archive-create".into(),
            target.to_string_lossy().into_owned(),
            "busybox".into(),
            "tar".into(),
        ];
        args.extend(plan.args);
        assert!(cmd
            .args(args)
            .current_dir(&src)
            .output()
            .unwrap()
            .status
            .success());
        assert!(target.is_file());
        let entries =
            crate::archive_inspect::inspect_local_tar(target.to_str().unwrap(), "tar", 10).unwrap();
        assert_eq!(entries[0].name, "-name");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn thumbnail_batch_filters_hidden_and_denied_paths() {
        use std::os::unix::fs::symlink;
        let root = scratch();
        let images = root.join("images");
        let outside = root.join("outside");
        fs::create_dir_all(&images).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(images.join("ok.png"), b"a").unwrap();
        fs::write(images.join("blocked.png"), b"b").unwrap();
        fs::write(images.join(".hidden.png"), b"c").unwrap();
        fs::write(outside.join("private.png"), b"d").unwrap();
        symlink(outside.join("private.png"), images.join("link.png")).unwrap();
        let st = crate::state::AppState::new(crate::state::Settings {
            state_dir: root.join("state").to_string_lossy().into_owned(),
            config_path: root.join("config").to_string_lossy().into_owned(),
            root_policy: crate::state::RootPolicy::Denylist,
            excluded_roots: vec![
                images.join("blocked.png").to_string_lossy().into_owned(),
                outside.to_string_lossy().into_owned(),
            ],
            ..Default::default()
        });
        let ctx = Ctx {
            st: st.clone(),
            params: Default::default(),
            method: axum::http::Method::POST,
            headers: Default::default(),
        };
        let prefs = crate::config::Prefs {
            home_dir: root.to_string_lossy().into_owned(),
            show_hidden_files: 0,
            ..Default::default()
        };
        let items = crate::api::fsops::list_directory(images.to_str().unwrap(), &prefs).unwrap();
        assert!(!items
            .iter()
            .any(|item| item["name"] == json!(".hidden.png")));
        let (jobs, cached) = thumbnail_jobs(&ctx, &items, &prefs);
        assert_eq!(cached, 0);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].0, images.join("ok.png").to_string_lossy());
        drop(ctx);
        drop(st);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn archive_sources_with_same_name_in_different_parents_are_rejected() {
        let mut parent = None;
        assert_eq!(
            archive_source_name("/allowed/one/data.txt", &mut parent).unwrap(),
            "data.txt"
        );
        assert!(archive_source_name("/allowed/two/data.txt", &mut parent).is_err());
    }

    #[test]
    fn selecting_archive_directory_includes_all_descendants_for_validation() {
        let members = vec![
            crate::archive_inspect::member("dir/", true)
                .unwrap()
                .unwrap(),
            crate::archive_inspect::member("dir/allowed.txt", false)
                .unwrap()
                .unwrap(),
            crate::archive_inspect::member("dir/blocked/secret.txt", false)
                .unwrap()
                .unwrap(),
            crate::archive_inspect::member("other.txt", false)
                .unwrap()
                .unwrap(),
        ];
        let selected = vec!["dir".to_string()];
        assert_eq!(
            archive_selection_paths(&members, Some(&selected)).unwrap(),
            vec![
                "dir".to_string(),
                "dir/allowed.txt".to_string(),
                "dir/blocked/secret.txt".to_string(),
            ]
        );
    }

    #[test]
    fn archive_members_reject_traversal_and_platform_separators() {
        assert!(safe_archive_member("folder/file.txt"));
        assert!(!safe_archive_member("../secret"));
        assert!(!safe_archive_member("folder/../../secret"));
        assert!(!safe_archive_member("/absolute/path"));
        assert!(!safe_archive_member("folder\\\\secret"));
        assert!(!safe_archive_member(""));
    }

    #[test]
    fn archive_plans_share_bsdtar_for_zip_rar_and_7z() {
        for path in ["/tmp/a.zip", "/tmp/a.rar", "/tmp/a.7z"] {
            let plan = archive_listing_plan(path).unwrap();
            let ArchiveListingPlan::Command(command) = plan else {
                panic!("expected command plan for {path}");
            };
            assert_eq!(command.program, "bsdtar");
            assert_eq!(
                archive_required_tools(command.kind, command.program),
                vec!["bsdtar"]
            );
            let kind = archive_kind_for_path(path).unwrap();
            let extract = archive_extract_plan(path, kind, None, "/tmp/members").unwrap();
            assert_eq!(extract.program, "bsdtar");
        }
    }

    fn scratch() -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("harbor-archive-test-{}", crate::uci::random_hex(8)));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn busybox_tar_available() -> bool {
        std::process::Command::new("busybox")
            .arg("true")
            .status()
            .is_ok_and(|status| status.success())
    }

    fn busybox_tar_supports_minus_t() -> bool {
        let output = std::process::Command::new("busybox")
            .args(["tar", "--help"])
            .output();
        let Ok(output) = output else {
            return false;
        };
        let mut help = String::from_utf8_lossy(&output.stdout).into_owned();
        help.push_str(&String::from_utf8_lossy(&output.stderr));
        help.contains("-T FILE") || help.contains("[-T FILE]")
    }

    #[test]
    fn safe_bsd_listing_rejects_escaped_names_links_specials_and_truncation() {
        let names = vec!["dir/a.txt".into(), "dir/b.txt".into()];
        let verbose = vec![
            "-rw-r--r-- 0 0 0 1 date dir/a.txt".into(),
            "-rw-r--r-- 0 0 0 1 date dir/b.txt".into(),
        ];
        assert_eq!(
            parse_safe_bsdtar_listing(&names, &verbose, 2)
                .unwrap()
                .len(),
            2
        );
        assert!(parse_safe_bsdtar_listing(&names, &verbose[..1], 2).is_err());
        assert!(parse_safe_bsdtar_listing(&names, &verbose, 1).is_err());
        assert!(parse_safe_bsdtar_listing(&["../evil".into()], &verbose[..1], 2).is_err());
        assert!(parse_safe_bsdtar_listing(&["a\\nb".into()], &verbose[..1], 2).is_err());
        assert!(parse_safe_bsdtar_listing(
            &["link".into()],
            &["lrwxrwxrwx 0 0 0 date link -> /etc".into()],
            2
        )
        .is_err());
        assert!(parse_safe_bsdtar_listing(
            &["fifo".into()],
            &["prw-r--r-- 0 0 0 date fifo".into()],
            2
        )
        .is_err());
        assert!(strict_listing_lines(b"one\ntwo".to_vec()).is_err());
        assert!(strict_listing_lines(vec![b'a'; 16 * 1024 * 1024]).is_err());
    }

    #[test]
    fn destination_symlinks_are_refused_even_with_overwrite() {
        use std::os::unix::fs::symlink;
        let base = scratch();
        fs::create_dir_all(base.join("out")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        symlink(base.join("outside"), base.join("out").join("dir")).unwrap();
        assert!(check_local_archive_destinations(
            base.join("out").to_str().unwrap(),
            &["dir/file".into()]
        )
        .is_err());
        fs::remove_file(base.join("out").join("dir")).unwrap();
        assert!(check_local_archive_destinations(
            base.join("out").to_str().unwrap(),
            &["dir/file".into()]
        )
        .is_ok());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn selected_directories_use_actual_archive_names_for_gnu_and_busybox_tar() {
        let base = scratch();
        let src = base.join("src");
        let dest = base.join("out");
        fs::create_dir_all(src.join("dir")).unwrap();
        fs::create_dir_all(src.join("dir2")).unwrap();
        fs::write(src.join("dir/a.txt"), b"a").unwrap();
        fs::write(src.join("dir2/b.txt"), b"b").unwrap();
        let archive = base.join("data.tar");
        assert!(std::process::Command::new("tar")
            .args([
                "-cf",
                archive.to_str().unwrap(),
                "-C",
                src.to_str().unwrap(),
                "."
            ])
            .status()
            .unwrap()
            .success());
        let entries = crate::archive_inspect::inspect_local_tar(
            archive.to_str().unwrap(),
            "tar",
            ARCHIVE_LIST_LIMIT,
        )
        .unwrap();
        let selectors = archive_selection_arguments(&entries, Some(&["dir".into()]))
            .unwrap()
            .unwrap();
        assert_eq!(selectors, vec!["./dir/"]);
        let selection_file = base.join("members");
        fs::write(&selection_file, selectors.join("\n") + "\n").unwrap();
        let plan = archive_extract_plan(
            archive.to_str().unwrap(),
            "tar",
            Some(&selectors),
            selection_file.to_str().unwrap(),
        )
        .unwrap();
        for busybox in [false, true] {
            if busybox && !busybox_tar_available() {
                continue;
            }
            let _ = fs::remove_dir_all(&dest);
            fs::create_dir_all(&dest).unwrap();
            let mut cmd = if busybox {
                let mut c = std::process::Command::new("busybox");
                c.arg("tar");
                c
            } else {
                std::process::Command::new("tar")
            };
            // Ubuntu's BusyBox 1.37 tar has no -T. Member names as operands
            // still prove the archive's original spelling is what we selected.
            if busybox && !busybox_tar_supports_minus_t() {
                cmd.args(["-x", "-v", "-f", archive.to_str().unwrap()]);
                cmd.args(&selectors);
            } else {
                cmd.args(&plan.args);
            }
            let output = cmd
                .current_dir(&dest)
                .env_remove("TAR_OPTIONS")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "extract failed busybox={busybox} args={:?} status={:?}\nstdout:\n{}\nstderr:\n{}",
                plan.args,
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(fs::read(dest.join("dir/a.txt")).unwrap(), b"a");
            assert!(!dest.join("dir2/b.txt").exists());
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn option_like_sources_are_not_treated_as_tar_options() {
        let base = scratch();
        let src = base.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("-danger"), b"data").unwrap();
        let archive = base.join("created.tar");
        let plan =
            archive_create_plan("tar", archive.to_str().unwrap(), &["-danger".into()]).unwrap();
        assert_eq!(plan.args.last().unwrap(), "./-danger");
        assert!(std::process::Command::new(plan.program)
            .args(&plan.args)
            .current_dir(&src)
            .output()
            .unwrap()
            .status
            .success());
        let entries =
            crate::archive_inspect::inspect_local_tar(archive.to_str().unwrap(), "tar", 10)
                .unwrap();
        assert_eq!(entries[0].name, "-danger");
        assert!(parse_archive_members(Some("[\"-danger\"]".into())).is_err());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn selection_rejects_wildcards_and_expands_implicit_directories() {
        let entries = vec![
            crate::archive_inspect::member("./dir/file", false)
                .unwrap()
                .unwrap(),
            crate::archive_inspect::member("./other", false)
                .unwrap()
                .unwrap(),
        ];
        assert_eq!(
            archive_selection_arguments(&entries, Some(&["dir".into()]))
                .unwrap()
                .unwrap(),
            vec!["./dir/file"]
        );
        let wildcard = vec![crate::archive_inspect::member("./x*/file", false)
            .unwrap()
            .unwrap()];
        assert!(archive_selection_arguments(&wildcard, Some(&["x*".into()])).is_err());
        assert!(archive_selection_paths(&entries, Some(&["missing".into()])).is_err());
    }
}
