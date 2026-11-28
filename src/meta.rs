//! Filesystem metadata helpers, MIME classification and small utilities that mirror
//! the previous ucode backend 1:1 (thumbnail cache keys, permission strings, ...).

use serde_json::json;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    Other,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Directory => "directory",
            Kind::Symlink => "link",
            Kind::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Meta {
    pub kind: Kind,
    pub size: i64,
    pub mtime: i64,
    pub mtime_ns: i64,
    pub ctime: i64,
    pub mode: u32,
    pub dev: u64,
    pub ino: u64,
}

fn to_meta(md: &fs::Metadata) -> Meta {
    let ft = md.file_type();
    let kind = if ft.is_symlink() {
        Kind::Symlink
    } else if ft.is_dir() {
        Kind::Directory
    } else if ft.is_file() {
        Kind::File
    } else {
        Kind::Other
    };
    Meta {
        kind,
        size: md.len() as i64,
        mtime: md.mtime(),
        mtime_ns: md.mtime_nsec(),
        ctime: md.ctime(),
        mode: md.mode(),
        dev: md.dev(),
        ino: md.ino(),
    }
}

pub fn lstat(path: &str) -> Option<Meta> {
    fs::symlink_metadata(path).ok().map(|m| to_meta(&m))
}

pub fn stat(path: &str) -> Option<Meta> {
    fs::metadata(path).ok().map(|m| to_meta(&m))
}

pub fn lstat_or_stat(path: &str) -> Option<Meta> {
    lstat(path).or_else(|| stat(path))
}

pub fn perm_string(mode: u32) -> String {
    let bits = ['r', 'w', 'x'];
    let mut out = String::new();
    for i in (0..9).rev() {
        if (mode >> i) & 1 == 1 {
            out.push(bits[(8 - i) % 3]);
        } else {
            out.push('-');
        }
    }
    out
}

pub fn numeric_permissions(mode: u32) -> String {
    format!("{:03o}", mode & 0o777)
}

pub fn mode_string(mode: u32) -> String {
    format!("{:o}", mode & 0o7777)
}

/// Shared listing schema. Filesystem and SSH adapters provide metadata and a
/// raw link target; only this serializer derives display fields and paths.
pub struct ItemView<'a> {
    pub name: &'a str,
    pub path: &'a str,
    pub is_directory: bool,
    pub is_symlink: bool,
    pub size: i64,
    pub mtime: i64,
    pub mode: &'a str,
    pub link_target: Option<&'a str>,
}

pub fn item_json(view: ItemView<'_>) -> serde_json::Value {
    let kind = if view.is_directory {
        "directory"
    } else if view.is_symlink {
        "symlink"
    } else {
        "file"
    };
    let extension = if view.is_directory {
        String::new()
    } else {
        crate::paths::file_extension(view.name)
    };
    let preview = if view.is_directory {
        "none"
    } else {
        classify_preview(view.path, view.name)
    };
    let mode = u32::from_str_radix(view.mode, 8).unwrap_or(0);
    let link = view.link_target.filter(|raw| view.is_symlink && !raw.is_empty()).map(|raw| {
        let absolute = if raw.starts_with('/') { raw.to_string() } else {
            crate::paths::join_path(&crate::paths::parent_path(view.path).unwrap_or_else(|| "/".to_string()), raw)
        };
        json!({ "raw": raw, "path": crate::paths::normalize_path(&absolute).unwrap_or(absolute) })
    });
    let mut value = json!({
        "name": view.name, "path": view.path, "type": kind, "kind": kind,
        "is_symlink": view.is_symlink, "size": if view.is_directory { -1 } else { view.size },
        "mtime": view.mtime, "mode": view.mode, "permissions": perm_string(mode),
        "numeric_permissions": numeric_permissions(mode), "ext": extension, "extension": extension,
        "preview": preview, "link_target": link, "hidden": view.name.starts_with('.')
    });
    if preview == "image" {
        value["thumbnail_available"] = json!(false);
    }
    value
}

pub fn image_mime(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "tif" | "tiff" => "image/tiff",
        "avif" => "image/avif",
        _ => return None,
    })
}

pub fn video_mime(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        "avi" => "video/x-msvideo",
        "ts" => "video/mp2t",
        "flv" => "video/x-flv",
        "ogv" => "video/ogg",
        _ => return None,
    })
}

pub fn audio_mime(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "ogg" => "audio/ogg",
        "m4a" => "audio/mp4",
        "opus" => "audio/opus",
        _ => return None,
    })
}

pub fn is_text_ext(ext: &str) -> bool {
    matches!(
        ext,
        "txt"
            | "log"
            | "conf"
            | "cfg"
            | "ini"
            | "json"
            | "xml"
            | "csv"
            | "lua"
            | "sh"
            | "md"
            | "yaml"
            | "yml"
            | "html"
            | "htm"
            | "css"
            | "js"
    )
}

pub fn is_package_ext(ext: &str) -> bool {
    ext == "ipk" || ext == "apk"
}

pub fn is_document_ext(ext: &str) -> bool {
    matches!(
        ext,
        "doc"
            | "docx"
            | "docm"
            | "dot"
            | "dotx"
            | "dotm"
            | "odt"
            | "ott"
            | "rtf"
            | "xls"
            | "xlsx"
            | "xlsm"
            | "xltx"
            | "ods"
            | "ots"
            | "ppt"
            | "pptx"
            | "pptm"
            | "potx"
            | "odp"
            | "otp"
    )
}

pub fn mime_for(path: &str) -> &'static str {
    let ext = crate::paths::file_extension(path);
    if let Some(m) = image_mime(&ext) {
        return m;
    }
    if let Some(m) = video_mime(&ext) {
        return m;
    }
    if let Some(m) = audio_mime(&ext) {
        return m;
    }
    match ext.as_str() {
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "docm" => "application/vnd.ms-word.document.macroEnabled.12",
        "dotx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        "dotm" => "application/vnd.ms-word.template.macroEnabled.12",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ott" => "application/vnd.oasis.opendocument.text-template",
        "rtf" => "application/rtf",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "xlsm" => "application/vnd.ms-excel.sheet.macroEnabled.12",
        "xltx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "ots" => "application/vnd.oasis.opendocument.spreadsheet-template",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "pptm" => "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
        "potx" => "application/vnd.openxmlformats-officedocument.presentationml.template",
        "odp" => "application/vnd.oasis.opendocument.presentation",
        "otp" => "application/vnd.oasis.opendocument.presentation-template",
        "txt" | "log" | "conf" | "cfg" | "ini" | "md" | "csv" => "text/plain; charset=UTF-8",
        "json" => "application/json",
        "html" | "htm" => "text/html; charset=UTF-8",
        "css" => "text/css",
        "js" => "application/javascript",
        _ => "application/octet-stream",
    }
}

pub fn classify_preview(path: &str, name: &str) -> &'static str {
    let ext = crate::paths::file_extension(name);
    if image_mime(&ext).is_some() {
        return "image";
    }
    if is_text_ext(&ext) {
        return "text";
    }
    if video_mime(&ext).is_some() {
        return "video";
    }
    if audio_mime(&ext).is_some() {
        return "audio";
    }
    if ext == "pdf" {
        return "pdf";
    }
    if is_document_ext(&ext) {
        return "document";
    }
    if is_package_ext(&ext) {
        return "package";
    }
    if ext.is_empty() && (path == "/etc" || path.starts_with("/etc/")) {
        return "text";
    }
    "none"
}

pub fn looks_like_text(buf: &[u8]) -> bool {
    let mut i = 0usize;
    let n = buf.len();
    while i < n {
        let b = buf[i];
        if b == 0 {
            return false;
        }
        if b <= 0x7F {
            i += 1;
            continue;
        }
        let need = if b & 0xE0 == 0xC0 {
            1
        } else if b & 0xF0 == 0xE0 {
            2
        } else if b & 0xF8 == 0xF0 {
            3
        } else {
            return false;
        };
        if i + need >= n {
            break;
        }
        for k in 1..=need {
            if buf[i + k] & 0xC0 != 0x80 {
                return false;
            }
        }
        i += need + 1;
    }
    true
}

/// Known binary/media formats do not require reading the file. Keep this
/// decision common to local and SSH-backed type detection.
pub fn known_content_type(path: &str) -> Option<(&'static str, &'static str)> {
    let ext = crate::paths::file_extension(path);
    if let Some(mime) = image_mime(&ext) {
        return Some(("image", mime));
    }
    if let Some(mime) = video_mime(&ext) {
        return Some(("video", mime));
    }
    if let Some(mime) = audio_mime(&ext) {
        return Some(("audio", mime));
    }
    if ext == "pdf" {
        return Some(("pdf", "application/pdf"));
    }
    if is_package_ext(&ext) {
        return Some(("package", "application/octet-stream"));
    }
    None
}

pub fn sampled_content_type(sample: &[u8]) -> (&'static str, &'static str) {
    if looks_like_text(sample) {
        ("text", "text/plain; charset=UTF-8")
    } else {
        ("binary", "application/octet-stream")
    }
}

pub fn detect_content_type(path: &str) -> (&'static str, &'static str) {
    if let Some(known) = known_content_type(path) {
        return known;
    }
    use std::io::Read;
    match fs::File::open(path) {
        Ok(mut file) => {
            let mut sample = [0u8; 4096];
            let read = file.read(&mut sample).unwrap_or(0);
            sampled_content_type(&sample[..read])
        }
        Err(_) => ("binary", "application/octet-stream"),
    }
}

pub fn have_tool(name: &str) -> bool {
    if name.is_empty() || name.contains('/') {
        return false;
    }
    let mut dirs: Vec<std::path::PathBuf> = std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path)
                .filter(|dir| !dir.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_default();
    for dir in ["/bin", "/usr/bin", "/sbin", "/usr/sbin"] {
        let path = std::path::PathBuf::from(dir);
        if !dirs.contains(&path) {
            dirs.push(path);
        }
    }
    dirs.into_iter().any(|dir| {
        fs::metadata(dir.join(name))
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

pub fn mkdir_p(path: &str) -> bool {
    let n = match crate::paths::normalize_path(path) {
        Some(v) => v,
        None => return false,
    };
    if stat(&n).is_some() {
        return true;
    }
    let mut cur = String::new();
    for seg in n.split('/') {
        if seg.is_empty() {
            continue;
        }
        cur.push('/');
        cur.push_str(seg);
        match stat(&cur) {
            Some(m) => {
                if m.kind != Kind::Directory {
                    return false;
                }
            }
            None => {
                if let Err(e) = fs::create_dir(&cur) {
                    let _ = e;
                    return false;
                }
                let _ = fs::set_permissions(&cur, fs::Permissions::from_mode(0o755));
            }
        }
    }
    true
}

pub fn remove_recursive(path: &str) -> bool {
    let m = match lstat(path) {
        Some(m) => m,
        None => return true,
    };
    if m.kind == Kind::Directory {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let child = entry.file_name().to_string_lossy().into_owned();
                if !remove_recursive(&crate::paths::join_path(path, &child)) {
                    return false;
                }
            }
        }
        return fs::remove_dir(path).is_ok();
    }
    fs::remove_file(path).is_ok()
}

pub fn unique_target(
    dir: &str,
    name: &str,
    reserved: &[String],
    directory: bool,
) -> Option<String> {
    let target = crate::paths::join_path(dir, name);
    if lstat(&target).is_none() && !reserved.iter().any(|r| r == name) {
        return Some(target);
    }
    let (mut base, mut ext) = (name.to_string(), String::new());
    if !directory {
        if let Some(idx) = name.rfind('.') {
            if idx > 0 {
                base = name[..idx].to_string();
                ext = name[idx..].to_string();
            }
        }
    }
    for i in 1..1000 {
        let suffix = format!(" ({i})");
        if ext.len() + suffix.len() >= 255 {
            base = name.to_string();
            ext.clear();
        }
        let keep = base
            .len()
            .min(255usize.saturating_sub(ext.len() + suffix.len()));
        let mut cut = keep;
        while cut > 0 && !base.is_char_boundary(cut) {
            cut -= 1;
        }
        let candidate = format!("{}{}{}", &base[..cut], suffix, ext);
        if !crate::paths::valid_component(&candidate) {
            return None;
        }
        let path = crate::paths::join_path(dir, &candidate);
        if lstat(&path).is_none() && !reserved.iter().any(|r| r == &candidate) {
            return Some(path);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SpaceInfo {
    pub available: Option<u64>,
    pub total: Option<u64>,
    pub used: Option<u64>,
}

#[allow(clippy::unnecessary_cast)] // libc statvfs fields vary between 32-bit and 64-bit targets.
pub fn space_info(path: &str) -> SpaceInfo {
    let c = match std::ffi::CString::new(path) {
        Ok(c) => c,
        Err(_) => return SpaceInfo::default(),
    };
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut buf) };
    if rc != 0 {
        return SpaceInfo::default();
    }
    let frsize = if buf.f_frsize > 0 {
        buf.f_frsize
    } else {
        buf.f_bsize
    } as u64;
    SpaceInfo {
        available: Some(buf.f_bavail as u64 * frsize),
        total: Some(buf.f_blocks as u64 * frsize),
        used: Some((buf.f_blocks as u64 - buf.f_bfree as u64) * frsize),
    }
}

pub const OPERATION_SPACE_MARGIN: u64 = 16 * 1024 * 1024;

pub const HIDDEN_MOUNTS: &[&str] = &["/rom", "/overlay", "/dev"];

pub fn list_drives() -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    let mut seen_mount: Vec<String> = Vec::new();
    let mut seen_name: Vec<String> = Vec::new();
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();

    let mut device_space: std::collections::HashMap<String, SpaceInfo> = Default::default();
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let device = f[0];
        let mount = unescape_mount(f[1]);
        if !(mount == "/" || mount == "/tmp" || device.starts_with("/dev/")) {
            continue;
        }
        if HIDDEN_MOUNTS.contains(&mount.as_str()) || seen_mount.iter().any(|m| m == &mount) {
            continue;
        }
        seen_mount.push(mount.clone());
        let name = drive_name(device, &mount);
        let key = name.to_lowercase();
        if seen_name.iter().any(|n| n == &key) {
            continue;
        }
        seen_name.push(key);
        let space = *device_space
            .entry(device.to_string())
            .or_insert_with(|| space_info(&mount));
        let total_kb = (space.total.unwrap_or(0) / 1024) as i64;
        let used_kb = (space.used.unwrap_or(0) / 1024) as i64;
        let avail_kb = (space.available.unwrap_or(0) / 1024) as i64;
        out.push(drive_entry(device, &mount, total_kb, used_kb, avail_kb));
    }
    if !seen_mount.iter().any(|m| m == "/") {
        out.insert(0, drive_entry("rootfs", "/", 0, 0, 0));
    }
    out
}

pub fn drive_entry(
    device: &str,
    mount: &str,
    total_kb: i64,
    used_kb: i64,
    available_kb: i64,
) -> serde_json::Value {
    json!({
        "name": drive_name(device, mount),
        "path": mount,
        "device": device,
        "total_kb": total_kb,
        "used_kb": used_kb,
        "available_kb": available_kb,
        "usage_percent": used_kb.checked_mul(100).and_then(|v| v.checked_div(total_kb)).unwrap_or(0),
        "mode": "---",
        "total_bytes": total_kb * 1024,
        "available_bytes": available_kb * 1024,
        "used_bytes": used_kb * 1024,
        "is_system": mount == "/"
    })
}

fn unescape_mount(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

pub fn drive_name(device: &str, mount: &str) -> String {
    if mount == "/" {
        return "System Disk".to_string();
    }
    if mount == "/tmp" {
        return "Temporary Space".to_string();
    }
    let name = device.rsplit('/').next().unwrap_or("");
    if name.is_empty() {
        if device.is_empty() {
            mount.to_string()
        } else {
            device.to_string()
        }
    } else {
        name.to_string()
    }
}

pub fn readlink(path: &str) -> Option<String> {
    fs::read_link(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

pub fn read_json(path: &std::path::Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
