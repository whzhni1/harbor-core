//! Directory listing, navigation and the mutating file operations.

use crate::config;
use crate::meta::{self, Kind, Meta};
use crate::paths::{self, join_path, normalize_path, parent_path, path_name};
use crate::reply::{fail, ok, ApiError};
use crate::state::Ctx;
use axum::response::Response;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub fn stat_to_item(name: &str, path: &str, st: Meta, lst: Option<Meta>) -> Value {
    let is_symlink = lst.is_some_and(|m| m.kind == Kind::Symlink);
    let link_target = if is_symlink {
        meta::readlink(path)
    } else {
        None
    };
    let mode = meta::mode_string(st.mode);
    meta::item_json(meta::ItemView {
        name,
        path,
        is_directory: st.kind == Kind::Directory,
        is_symlink,
        size: st.size,
        mtime: st.mtime,
        mode: &mode,
        link_target: link_target.as_deref(),
    })
}

pub fn sort_items(items: &mut [Value]) {
    items.sort_by(|a, b| {
        let ad = if a["type"] == json!("directory") {
            0
        } else {
            1
        };
        let bd = if b["type"] == json!("directory") {
            0
        } else {
            1
        };
        if ad != bd {
            return ad.cmp(&bd);
        }
        let al = a["name"].as_str().unwrap_or("").to_lowercase();
        let bl = b["name"].as_str().unwrap_or("").to_lowercase();
        al.cmp(&bl)
    });
}

pub fn list_directory(path: &str, prefs: &config::Prefs) -> Result<Vec<Value>, String> {
    let st = meta::stat(path).ok_or_else(|| "Path not found".to_string())?;
    if st.kind != Kind::Directory {
        return Err("Not a directory".to_string());
    }
    let entries = fs::read_dir(path).map_err(|_| "Permission denied".to_string())?;
    let mut items = Vec::new();
    let home_cache = thumbnail_cache_dir(prefs);
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if prefs.show_hidden_files != 1 && name.starts_with('.') {
            continue;
        }
        let full = join_path(path, &name);
        let lst = meta::lstat(&full);
        let stf = meta::stat(&full).or(lst);
        let stf = match stf {
            Some(v) => v,
            None => continue,
        };
        let mut item = stat_to_item(&name, &full, stf, lst);
        if prefs.enable_thumbnails == 1 && item["preview"] == json!("image") {
            let available = match &home_cache {
                Some(dir) => {
                    let key = thumbnail_key(&full, &stf);
                    meta::stat(&join_path(dir, &format!("{key}.jpg"))).is_some()
                }
                None => false,
            };
            item["thumbnail_available"] = json!(available);
        }
        items.push(item);
    }
    sort_items(&mut items);
    Ok(items)
}

pub const THUMBNAIL_SIZE: i64 = 256;
pub const THUMBNAIL_CACHE_VERSION: &str = "contain-v2";

pub fn thumbnail_cache_dir(prefs: &config::Prefs) -> Option<String> {
    normalize_path(&join_path(
        &join_path(&prefs.home_dir, ".cache"),
        "pictures",
    ))
}

pub fn thumbnail_key_parts(path: &str, size: i64, mtime: i64) -> String {
    let material = format!(
        "{}\0{}\0{}\0{}\0{}",
        normalize_path(path).unwrap_or_default(),
        size,
        mtime,
        THUMBNAIL_SIZE,
        THUMBNAIL_CACHE_VERSION
    );
    hex::encode(crate::auth::sha256_bytes(material.as_bytes()))
}

pub fn thumbnail_key(path: &str, st: &Meta) -> String {
    thumbnail_key_parts(path, st.size, st.mtime)
}

pub fn thumbnail_cache_path(path: &str, st: &Meta, prefs: &config::Prefs) -> Option<String> {
    let dir = thumbnail_cache_dir(prefs)?;
    Some(join_path(&dir, &format!("{}.jpg", thumbnail_key(path, st))))
}

fn directory_size(ctx: &Ctx, path: &str) -> Response {
    let st = match meta::lstat(path) {
        Some(m) if m.kind == Kind::Directory => m,
        _ => return fail(1, "Not a directory", Value::Null),
    };
    let real = match paths::canonical(path) {
        Some(p) => p,
        None => return fail(1, "Path not found", Value::Null),
    };
    let entries = match fs::read_dir(&real) {
        Ok(e) => e,
        Err(_) => return fail(2, "Permission denied", Value::Null),
    };
    let mut size: i64 = 0;
    let mut files = 0;
    let mut skipped = 0;
    let mut links = 0;
    let mut directories: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        let child = join_path(&real, &name);
        if ctx.read_path(&child).is_err() {
            skipped += 1;
            continue;
        }
        match meta::lstat(&child) {
            None => skipped += 1,
            Some(info) => match info.kind {
                Kind::Directory => directories.push(child),
                Kind::File => {
                    size += info.size;
                    files += 1;
                }
                Kind::Symlink => links += 1,
                Kind::Other => {}
            },
        }
    }
    ok(json!({
        "path": real,
        "size": size,
        "files": files,
        "directories": directories,
        "skipped": skipped,
        "links": links,
        "identity": format!("{}:{}", st.dev, st.ino)
    }))
}

pub async fn api_navigation(ctx: &Ctx) -> Response {
    let prefs = ctx.prefs();
    let uci = ctx.st.uci();
    let bookmarks = config::read_bookmarks(&uci);
    let quick = match config::read_quick_items(&uci) {
        Some(items) => items,
        None => {
            let items = config::default_quick_items(&prefs.home_dir);
            for item in &items {
                meta::mkdir_p(&item.path);
            }
            if let Err(error) = config::write_quick_items(&ctx.st.settings.config_path, &items) {
                eprintln!("Failed to seed quick access items: {error}");
            }
            items
        }
    };
    ok(json!({
        "quick_access": config::quick_access_payload(&quick),
        "bookmarks": config::bookmark_payload(&uci, &bookmarks),
        "bookmark_folders": config::read_bookmark_folders(&uci),
        "fav_expanded": config::read_fav_expanded(&uci),
        "home_dir": prefs.home_dir,
        "folders": list_root_folders(ctx, &prefs),
        "drives": Value::Array(
            meta::list_drives()
                .into_iter()
                .filter(|drive| {
                    drive["path"]
                        .as_str()
                        .is_some_and(|path| ctx.read_path(path).is_ok())
                })
                .collect(),
        )
    }))
}

fn list_item_visible(ctx: &Ctx, item: &Value) -> bool {
    let item_path = item["path"].as_str().unwrap_or("");
    if ctx.read_path(item_path).is_ok() {
        return true;
    }
    if !paths::is_system_path(item_path) {
        return false;
    }
    let policy = ctx.st.root_policy_config();
    let resolved = paths::canonical(item_path).unwrap_or_else(|| item_path.to_string());
    paths::path_allowed_by_policy(
        policy.policy,
        &policy.roots,
        &policy.excluded_roots,
        &resolved,
    )
}

fn list_root_folders(ctx: &Ctx, prefs: &config::Prefs) -> Value {
    if ctx.read_path("/").is_err() {
        return Value::Array(Vec::new());
    }
    let items = list_directory("/", prefs).unwrap_or_default();
    Value::Array(
        items
            .into_iter()
            .filter(|item| item["type"] == json!("directory"))
            .filter(|item| list_item_visible(ctx, item))
            .map(|item| json!({ "name": item["name"], "path": item["path"] }))
            .collect(),
    )
}

pub const LIST_PAGE_MAX: usize = 1000;

pub async fn api_list(ctx: &Ctx) -> Response {
    let path = match ctx.params.first_of(&["path"]) {
        Some(raw) => match ctx.read_path(&raw) {
            Ok(path) => path,
            Err(error) => return error.into_response(),
        },
        None => return fail(1, "Invalid path", Value::Null),
    };
    if ctx.params.get("directory_size").as_deref() == Some("1") {
        return directory_size(ctx, &path);
    }
    let prefs = ctx.prefs();
    let st = meta::stat(&path);
    if let Some(m) = st {
        if m.kind != Kind::Directory {
            let ext = paths::file_extension(&path);
            if crate::api::archops::archive_kind(&path, &ext).is_none() {
                return fail(1, "Not a directory", Value::Null);
            }
            return crate::api::archops::api_archive_list(ctx).await;
        }
    }
    let mut items = match list_directory(&path, &prefs) {
        Ok(v) => v,
        Err(e) => return fail(2, &e, Value::Null),
    };
    items.retain(|item| list_item_visible(ctx, item));
    let total = items.len();
    let offset = ctx.params.int("offset").unwrap_or(0).clamp(0, total as i64) as usize;
    let requested_limit = ctx.params.int("limit").unwrap_or(0);
    let limit = if requested_limit > 0 {
        requested_limit.min(LIST_PAGE_MAX as i64) as usize
    } else {
        LIST_PAGE_MAX
    };
    let paged = offset > 0 || requested_limit > 0 || total > limit;
    if offset > 0 || items.len() > limit {
        items = items.into_iter().skip(offset).take(limit).collect();
    }
    let has_more = offset + items.len() < total;
    let space = meta::space_info(&path);
    let available = space.available.unwrap_or(0);
    let has_space = available >= meta::OPERATION_SPACE_MARGIN;
    ok(json!({
        "path": path,
        "parent": parent_path(&path),
        "available_bytes": available,
        "total_bytes": space.total.unwrap_or(0),
        "used_bytes": space.used.unwrap_or(0),
        "operation_space_margin": meta::OPERATION_SPACE_MARGIN,
        "has_operation_space": has_space,
        "is_system_path": paths::is_system_path(&path),
        "total": total,
        "offset": offset,
        "limit": limit,
        "paged": paged,
        "has_more": has_more,
        "items": items
    }))
}

pub fn create_staging_directory(parent: &str, prefix: &str) -> Option<String> {
    for _ in 0..8 {
        let candidate = join_path(parent, &format!("{prefix}{}", crate::uci::random_hex(16)));
        crate::paths::journal_tmp(&candidate);
        match fs::create_dir(&candidate) {
            Ok(()) => {
                let _ = fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700));
                return Some(candidate);
            }
            Err(_) => {
                meta::lstat(&candidate)?;
            }
        }
    }
    None
}

fn replacement_mode(path: &str, fallback: u32, preserve: bool) -> u32 {
    if !preserve {
        return fallback;
    }
    match meta::lstat(path) {
        Some(m) if m.kind == Kind::File => m.mode & 0o7777,
        _ => fallback,
    }
}

pub fn copy_file(src: &str, dst: &str, preserve_permissions: bool) -> bool {
    let src_st = match meta::lstat(src) {
        Some(m) if m.kind == Kind::File => m,
        _ => return false,
    };
    let mode = replacement_mode(dst, src_st.mode & 0o7777, preserve_permissions);
    let mut input = match fs::File::open(src) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let parent = match parent_path(dst) {
        Some(p) => p,
        None => return false,
    };
    let staging = match create_staging_directory(&parent, ".harbor-copy.") {
        Some(s) => s,
        None => return false,
    };
    let tmp = format!("{staging}/data");
    let mut output = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(src_st.mode & 0o7777)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(_) => {
            let _ = fs::remove_dir(&staging);
            return false;
        }
    };
    let mut buf = vec![0u8; 256 * 1024];
    let mut written: i64 = 0;
    let mut okay = true;
    loop {
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if output.write_all(&buf[..n]).is_err() {
                    okay = false;
                    break;
                }
                written += n as i64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                okay = false;
                break;
            }
        }
    }
    if output.flush().is_err() {
        okay = false;
    }
    drop(output);
    if written != src_st.size {
        okay = false;
    }
    if okay {
        okay = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).is_ok()
            && fs::rename(&tmp, dst).is_ok();
    }
    if !okay {
        let _ = fs::remove_file(&tmp);
    }
    let _ = fs::remove_dir(&staging);
    okay
}

fn transfer_excluded(path: &str, excluded: &[String]) -> bool {
    excluded.iter().any(|skip| {
        path == skip
            || (path.len() > skip.len()
                && path.starts_with(skip.as_str())
                && path.as_bytes()[skip.len()] == b'/')
    })
}

fn copy_recursive(
    ctx: &Ctx,
    src: &str,
    dst: &str,
    preserve_permissions: bool,
    excluded: &[String],
    moving: bool,
) -> Result<(), String> {
    if transfer_excluded(src, excluded) {
        return Ok(());
    }
    let src_checked = ctx.read_path(src).map_err(|_| src.to_string())?;
    let dst_checked = ctx.create_path(dst).map_err(|_| dst.to_string())?;
    let src = src_checked.as_str();
    let dst = dst_checked.as_str();
    let st = match meta::lstat(src) {
        Some(m) => m,
        None => return Err(dst.to_string()),
    };
    let target = meta::lstat(dst);
    if let Some(t) = target {
        if (st.kind == Kind::Directory) != (t.kind == Kind::Directory) {
            return Err(dst.to_string());
        }
    }
    match st.kind {
        Kind::Directory => {
            if target.is_none() {
                if fs::create_dir(dst).is_err() {
                    return Err(dst.to_string());
                }
                let _ = fs::set_permissions(dst, fs::Permissions::from_mode(st.mode & 0o7777));
            }
            let entries = match fs::read_dir(src) {
                Ok(e) => e,
                Err(_) => return Err(src.to_string()),
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                copy_recursive(
                    ctx,
                    &join_path(src, &name),
                    &join_path(dst, &name),
                    preserve_permissions,
                    excluded,
                    moving,
                )?;
            }
            if moving {
                match fs::read_dir(src) {
                    Ok(mut rest) => {
                        if rest.next().is_none() && fs::remove_dir(src).is_err() {
                            return Err(src.to_string());
                        }
                    }
                    Err(_) => return Err(src.to_string()),
                }
            }
            Ok(())
        }
        Kind::Symlink => {
            let link = meta::readlink(src).ok_or_else(|| dst.to_string())?;
            let parent = parent_path(dst).ok_or_else(|| dst.to_string())?;
            let staging = create_staging_directory(&parent, ".harbor-copy.")
                .ok_or_else(|| dst.to_string())?;
            let tmp = format!("{staging}/link");
            let okay =
                std::os::unix::fs::symlink(&link, &tmp).is_ok() && fs::rename(&tmp, dst).is_ok();
            if !okay {
                let _ = fs::remove_file(&tmp);
            }
            let _ = fs::remove_dir(&staging);
            if !okay {
                return Err(dst.to_string());
            }
            if moving && fs::remove_file(src).is_err() {
                return Err(src.to_string());
            }
            Ok(())
        }
        Kind::File => {
            if !copy_file(src, dst, preserve_permissions) {
                return Err(dst.to_string());
            }
            if moving && fs::remove_file(src).is_err() {
                return Err(src.to_string());
            }
            Ok(())
        }
        Kind::Other => Err(dst.to_string()),
    }
}

#[derive(Debug, Default)]
pub struct TransferResult {
    pub ok: bool,
    pub error: Option<String>,
    pub failed_item: Option<String>,
    pub skipped_count: i64,
    pub partial: bool,
}

pub struct TransferRequest<'a> {
    pub src: &'a str,
    pub dest_dir: &'a str,
    pub mode: &'a str,
    pub on_conflict: &'a str,
    pub forced_name: Option<&'a str>,
    pub preserve_permissions: bool,
    pub excluded: &'a [String],
}

pub fn transfer_one(ctx: &Ctx, req: &TransferRequest) -> TransferResult {
    if transfer_excluded(req.src, req.excluded) {
        return TransferResult {
            ok: true,
            error: Some("skipped".into()),
            ..Default::default()
        };
    }
    let st = match meta::lstat(req.src) {
        Some(m) => m,
        None => {
            return TransferResult {
                ok: false,
                error: Some("Source not found".into()),
                ..Default::default()
            }
        }
    };
    if st.kind == Kind::Directory {
        let real_src = paths::canonical(req.src).unwrap_or_else(|| req.src.to_string());
        let real_dst = paths::canonical(req.dest_dir).unwrap_or_else(|| req.dest_dir.to_string());
        if paths::is_descendant(req.src, req.dest_dir) || paths::is_descendant(&real_src, &real_dst)
        {
            return TransferResult {
                ok: false,
                error: Some("Cannot transfer a directory into itself".into()),
                ..Default::default()
            };
        }
    }
    if let Some(name) = req.forced_name {
        if !paths::valid_rename_name(name) {
            return TransferResult {
                ok: false,
                error: Some("Invalid name".into()),
                ..Default::default()
            };
        }
    }
    let name = req
        .forced_name
        .map(|s| s.to_string())
        .unwrap_or_else(|| path_name(req.src));
    let mut target = match ctx.create_path(&join_path(req.dest_dir, &name)) {
        Ok(path) => path,
        Err(error) => {
            let failed = if error.is_system_access_required() {
                join_path(req.dest_dir, &name)
            } else {
                req.src.to_string()
            };
            return TransferResult {
                ok: false,
                error: Some(error.message),
                failed_item: Some(failed),
                ..Default::default()
            };
        }
    };

    if target == req.src
        && req.on_conflict != "skip"
        && !(req.mode == "copy" && req.on_conflict == "rename")
    {
        let message = if st.kind == Kind::Directory {
            "Cannot transfer a directory into itself"
        } else {
            "Target already exists"
        };
        return TransferResult {
            ok: false,
            error: Some(message.into()),
            ..Default::default()
        };
    }

    if let Some(existing) = meta::lstat(&target) {
        match req.on_conflict {
            "skip" => {
                return TransferResult {
                    ok: true,
                    error: Some("skipped".into()),
                    ..Default::default()
                }
            }
            "rename" => {
                if req.forced_name.is_some() {
                    return TransferResult {
                        ok: false,
                        error: Some("Target already exists".into()),
                        failed_item: Some(target),
                        ..Default::default()
                    };
                }
                match meta::unique_target(req.dest_dir, &name, &[], st.kind == Kind::Directory)
                    .and_then(|path| ctx.create_path(&path).ok())
                {
                    Some(path) => target = path,
                    None => {
                        return TransferResult {
                            ok: false,
                            error: Some("Cannot allocate a unique name".into()),
                            ..Default::default()
                        }
                    }
                }
            }
            "overwrite" => {
                let mismatch = (st.kind == Kind::Directory) != (existing.kind == Kind::Directory);
                if mismatch {
                    return TransferResult {
                        ok: false,
                        error: Some("File and directory types conflict".into()),
                        failed_item: Some(target),
                        ..Default::default()
                    };
                }
            }
            _ => {
                return TransferResult {
                    ok: false,
                    error: Some("Target already exists".into()),
                    ..Default::default()
                }
            }
        }
    }

    if st.kind == Kind::Directory && paths::is_descendant(&target, req.src) {
        return TransferResult {
            ok: false,
            error: Some("Cannot transfer a directory into itself".into()),
            ..Default::default()
        };
    }

    let skipped_count = req
        .excluded
        .iter()
        .filter(|skip| paths::is_descendant(req.src, skip))
        .count() as i64;
    if skipped_count > 0 {
        let moving = req.mode == "move";
        let result = copy_recursive(ctx, req.src, &target, req.poserved(), req.excluded, moving);
        return match result {
            Ok(()) => TransferResult {
                ok: true,
                skipped_count,
                partial: moving && meta::lstat(req.src).is_some(),
                ..Default::default()
            },
            Err(failed) => TransferResult {
                ok: false,
                error: Some(if moving {
                    "Move failed".into()
                } else {
                    "Copy failed".into()
                }),
                failed_item: Some(failed),
                skipped_count,
                partial: moving && meta::lstat(req.src).is_some(),
            },
        };
    }

    if req.mode == "move" {
        let source_mode = st.mode & 0o7777;
        let preserve_mode = st.kind == Kind::File
            && replacement_mode(&target, source_mode, req.poserved()) != source_mode;
        if st.kind != Kind::Directory && !preserve_mode && fs::rename(req.src, &target).is_ok() {
            return TransferResult {
                ok: true,
                ..Default::default()
            };
        }
        match copy_recursive(ctx, req.src, &target, req.poserved(), req.excluded, true) {
            Err(failed) => TransferResult {
                ok: false,
                error: Some("Move failed".into()),
                failed_item: Some(failed),
                ..Default::default()
            },
            Ok(()) => {
                if !meta::remove_recursive(req.src) {
                    TransferResult {
                        ok: false,
                        error: Some(
                            "Content copied, but source removal failed; move incomplete".into(),
                        ),
                        failed_item: Some(req.src.to_string()),
                        ..Default::default()
                    }
                } else {
                    TransferResult {
                        ok: true,
                        ..Default::default()
                    }
                }
            }
        }
    } else {
        match copy_recursive(ctx, req.src, &target, req.poserved(), req.excluded, false) {
            Ok(()) => TransferResult {
                ok: true,
                ..Default::default()
            },
            Err(failed) => TransferResult {
                ok: false,
                error: Some("Copy failed".into()),
                failed_item: Some(failed),
                ..Default::default()
            },
        }
    }
}

impl TransferRequest<'_> {
    fn poserved(&self) -> bool {
        self.preserve_permissions
    }
}

pub async fn api_create_directory(ctx: &Ctx) -> Response {
    let parent = match ctx.write_path(
        &ctx.params
            .first_of(&["target_dir", "path"])
            .unwrap_or_default(),
    ) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let name = ctx.params.get("name").unwrap_or_default();
    if !paths::valid_component(&name) {
        return fail(1, "Invalid name", Value::Null);
    }
    let target = match ctx.create_path(&join_path(&parent, &name)) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    if meta::lstat(&target).is_some() {
        return fail(2, "Target already exists", Value::Null);
    }
    match fs::create_dir(&target) {
        Ok(()) => {
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o755));
            ok(json!({ "path": target }))
        }
        Err(_) => fail(3, "Create failed", Value::Null),
    }
}

pub async fn api_create_file(ctx: &Ctx) -> Response {
    let parent = match ctx.write_path(
        &ctx.params
            .first_of(&["target_dir", "path"])
            .unwrap_or_default(),
    ) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let name = ctx.params.get("name").unwrap_or_default();
    if !paths::valid_component(&name) {
        return fail(1, "Invalid name", Value::Null);
    }
    let target = match ctx.create_path(&join_path(&parent, &name)) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    if meta::lstat(&target).is_some() {
        return fail(2, "Target already exists", Value::Null);
    }
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
    {
        Ok(_) => ok(json!({ "path": target })),
        Err(_) => fail(3, "Create failed", Value::Null),
    }
}

pub async fn api_rename(ctx: &Ctx) -> Response {
    let src = match ctx.write_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if src == "/" {
        return fail(1, "Cannot rename root", Value::Null);
    }
    let name = ctx
        .params
        .first_of(&["new_name", "name"])
        .unwrap_or_default();
    if !paths::valid_component(&name) {
        return fail(1, "Invalid name", Value::Null);
    }
    let parent = parent_path(&src).unwrap_or_else(|| "/".to_string());
    let target = match ctx.create_path(&join_path(&parent, &name)) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    if target == src {
        return ok(json!({ "path": target }));
    }
    if meta::lstat(&target).is_some() {
        return fail(2, "Target already exists", Value::Null);
    }
    if let Err(error) = ctx.rename_tree(&src, &target) {
        return error.into_response();
    }
    match fs::rename(&src, &target) {
        Ok(()) => ok(json!({ "path": target })),
        Err(_) => fail(3, "Rename failed", Value::Null),
    }
}

pub async fn api_delete(ctx: &Ctx) -> Response {
    let path = match ctx.write_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if path == "/" {
        return fail(1, "Cannot delete root", Value::Null);
    }
    if meta::lstat(&path).is_none() {
        return fail(2, "Path not found", Value::Null);
    }
    if let Err(error) = ctx.write_tree(&path) {
        return error.into_response();
    }
    if meta::remove_recursive(&path) {
        ok(json!({ "path": path }))
    } else {
        fail(3, "Delete failed", Value::Null)
    }
}

fn read_rename_map(ctx: &Ctx) -> Result<std::collections::HashMap<String, String>, ()> {
    let raw = match ctx.params.get("rename_map") {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(Default::default()),
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(Value::Object(map)) => Ok(map
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect()),
        _ => Err(()),
    }
}

fn rename_key(names: &std::collections::HashMap<String, String>, src: &str) -> String {
    if names.contains_key(src) {
        src.to_string()
    } else {
        path_name(src)
    }
}

fn validate_rename_plan(
    ctx: &Ctx,
    dest: &str,
    sources: &[String],
    names: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let mut seen: Vec<String> = Vec::new();
    for raw in sources {
        let src = ctx.read_path(raw).map_err(|error| error.message)?;
        let key = rename_key(names, &src);
        let custom = names.contains_key(&key);
        let name = if custom {
            names.get(&key).cloned().unwrap_or_default()
        } else {
            path_name(&src)
        };
        let valid = if custom {
            paths::valid_rename_name(&name)
        } else {
            paths::valid_component(&name)
        };
        if !valid {
            return Err(format!("Invalid name: {src}"));
        }
        if seen.iter().any(|s| s == &name)
            || (custom && meta::lstat(&join_path(dest, &name)).is_some())
        {
            return Err(format!("Target already exists: {name}"));
        }
        seen.push(name);
    }
    Ok(())
}

fn do_transfer(ctx: &Ctx, mode: &str, batch: bool) -> Response {
    let dest = match ctx.params.first_of(&["target_dir", "destination", "dest"]) {
        Some(raw) => match ctx.write_path(&raw) {
            Ok(path) => path,
            Err(error) => return error.into_response(),
        },
        None => return fail(1, "Invalid destination", Value::Null),
    };
    match meta::stat(&dest) {
        Some(m) if m.kind == Kind::Directory => {}
        _ => return fail(2, "Destination is not a directory", Value::Null),
    }
    let on_conflict = ctx
        .params
        .first_of(&["conflict_action", "on_conflict"])
        .unwrap_or_else(|| "error".to_string());
    let rename_map = match read_rename_map(ctx) {
        Ok(m) => m,
        Err(_) => return fail(1, "Invalid name", Value::Null),
    };
    let sources: Vec<String> = if batch {
        ctx.params
            .path_array("sources")
            .or_else(|| ctx.params.path_array("paths"))
            .unwrap_or_default()
    } else {
        ctx.params.get("path").into_iter().collect()
    };
    if sources.is_empty() {
        return fail(1, "No source given", Value::Null);
    }
    for source in &sources {
        if let Err(error) = ctx.read_tree(source) {
            return error.into_response();
        }
        if mode == "move" {
            if let Err(error) = ctx.write_tree(source) {
                return error.into_response();
            }
        }
    }

    let mut excluded: Vec<String> = Vec::new();
    if ctx.params.get("exclude_paths").is_some() {
        let raw = match ctx.params.path_array("exclude_paths") {
            Some(v) => v,
            None => return fail(1, "Invalid path", Value::Null),
        };
        for item in raw {
            let path = match ctx.read_path(&item) {
                Ok(path) => path,
                Err(error) => return error.into_response(),
            };
            let mut allowed = false;
            for source in &sources {
                let root = match ctx.read_path(source) {
                    Ok(root) => root,
                    Err(error) => return error.into_response(),
                };
                if paths::is_descendant(&root, &path) {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return fail(1, "Invalid path", Value::Null);
            }
            excluded.push(path);
        }
    }

    if ctx.params.get("rename_map").is_some() && on_conflict == "rename" {
        if let Err(e) = validate_rename_plan(ctx, &dest, &sources, &rename_map) {
            return fail(1, &e, Value::Null);
        }
    }

    let preserve = ctx.params.get("preserve_permissions").as_deref() != Some("0");
    for raw in &sources {
        let src = match ctx.read_path(raw) {
            Ok(path) => path,
            Err(error) => return error.into_response(),
        };
        let key = rename_key(&rename_map, &src);
        let name = rename_map
            .get(&key)
            .cloned()
            .unwrap_or_else(|| path_name(&src));
        if let Err(error) = ctx.create_path(&join_path(&dest, &name)) {
            if error.is_system_access_required() {
                return error.into_response();
            }
        }
    }
    let mut results: Vec<Value> = Vec::new();
    let mut failures = 0;

    for raw in &sources {
        let src = match ctx.read_path(raw) {
            Ok(path) => path,
            Err(error) => return error.into_response(),
        };
        let key = rename_key(&rename_map, &src);
        let forced = rename_map.get(&key).map(|s| s.as_str());
        let rv = transfer_one(
            ctx,
            &TransferRequest {
                src: &src,
                dest_dir: &dest,
                mode,
                on_conflict: &on_conflict,
                forced_name: forced,
                preserve_permissions: preserve,
                excluded: &excluded,
            },
        );
        results.push(json!({
            "path": src,
            "ok": rv.ok,
            "error": rv.error,
            "failed_item": rv.failed_item,
            "partial": rv.partial,
            "skipped_count": rv.skipped_count
        }));
        if !rv.ok {
            if rv.error.as_deref() == Some("System folder operations are disabled") {
                return ApiError::system_blocked_at(rv.failed_item.as_deref().unwrap_or(&dest))
                    .into_response();
            }
            failures += 1;
        }
    }

    if failures > 0 && !batch {
        let message = results
            .first()
            .and_then(|r| r["error"].as_str())
            .unwrap_or("Transfer failed")
            .to_string();
        return fail(3, &message, json!({ "results": results }));
    }
    ok(json!({
        "destination": dest,
        "total": results.len(),
        "failed": failures,
        "results": results
    }))
}

pub async fn api_copy(ctx: &Ctx) -> Response {
    do_transfer(ctx, "copy", false)
}

pub async fn api_move(ctx: &Ctx) -> Response {
    do_transfer(ctx, "move", false)
}

pub async fn api_batch_copy(ctx: &Ctx) -> Response {
    do_transfer(ctx, "copy", true)
}

pub async fn api_batch_move(ctx: &Ctx) -> Response {
    do_transfer(ctx, "move", true)
}

pub async fn api_batch_delete(ctx: &Ctx) -> Response {
    let sources = ctx
        .params
        .path_array("paths")
        .or_else(|| ctx.params.path_array("sources"))
        .unwrap_or_default();
    if sources.is_empty() {
        return fail(1, "No source given", Value::Null);
    }
    let mut results = Vec::new();
    let mut failures = 0;
    for raw in &sources {
        let path = match ctx.write_path(raw) {
            Ok(path) if path != "/" => path,
            Ok(_) => {
                results.push(json!({ "path": raw, "ok": false, "error": "Cannot delete root" }));
                failures += 1;
                continue;
            }
            Err(error) => {
                results.push(json!({ "path": raw, "ok": false, "error": error.message }));
                failures += 1;
                continue;
            }
        };
        if let Err(error) = ctx.write_tree(&path) {
            results.push(json!({ "path": raw, "ok": false, "error": error.message }));
            failures += 1;
            continue;
        }
        let okay = meta::remove_recursive(&path);
        results.push(json!({
            "path": path,
            "ok": okay,
            "error": if okay { Value::Null } else { json!("delete failed") }
        }));
        if !okay {
            failures += 1;
        }
    }
    ok(json!({ "total": results.len(), "failed": failures, "results": results }))
}

pub async fn api_batch_check(ctx: &Ctx) -> Response {
    if let Some(tree) = ctx.params.get("tree_path") {
        let path = match ctx.read_path(&tree) {
            Ok(p) => p,
            Err(error) => return error.into_response(),
        };
        match meta::lstat(&path) {
            Some(m) if m.kind == Kind::Directory => {}
            _ => return fail(1, "Not a directory", Value::Null),
        }
        let entries = match fs::read_dir(&path) {
            Ok(e) => e,
            Err(_) => return fail(2, "List failed", Value::Null),
        };
        let mut children = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "." || name == ".." {
                continue;
            }
            let child = join_path(&path, &name);
            if ctx.read_path(&child).is_err() {
                continue;
            }
            match meta::lstat(&child) {
                Some(info) => children.push(json!({
                    "path": child,
                    "name": name,
                    "type": info.kind.as_str()
                })),
                None => {
                    return fail(2, &format!("List failed: {child}"), Value::Null);
                }
            }
        }
        return ok(json!({ "path": path, "children": children }));
    }

    let dest = match ctx.params.first_of(&["target_dir", "destination", "dest"]) {
        Some(raw) => match ctx.write_path(&raw) {
            Ok(path) => Some(path),
            Err(error) => return error.into_response(),
        },
        None => None,
    };
    let raw_sources = ctx
        .params
        .path_array("sources")
        .or_else(|| ctx.params.path_array("paths"))
        .unwrap_or_default();
    let mut sources = Vec::with_capacity(raw_sources.len());
    for raw in raw_sources {
        match ctx.read_path(&raw) {
            Ok(path) => sources.push(path),
            Err(error) => return error.into_response(),
        }
    }

    if ctx.params.get("suggest_rename").as_deref() == Some("1")
        || ctx.params.get("rename_map").is_some()
    {
        let ok_dest = dest
            .as_deref()
            .and_then(meta::stat)
            .map(|m| m.kind == Kind::Directory)
            .unwrap_or(false);
        if !ok_dest {
            return fail(1, "Destination is not a directory", Value::Null);
        }
    }
    if ctx.params.get("rename_map").is_some() {
        let names = match read_rename_map(ctx) {
            Ok(m) => m,
            Err(_) => return fail(1, "Invalid name", Value::Null),
        };
        let dest_value = dest.clone().unwrap_or_default();
        if let Err(e) = validate_rename_plan(ctx, &dest_value, &sources, &names) {
            return fail(1, &e, Value::Null);
        }
    }
    let mut reserved: Vec<String> = Vec::new();
    let suggest = ctx.params.get("suggest_rename").as_deref() == Some("1");
    if suggest {
        for raw in &sources {
            reserved.push(path_name(raw));
        }
    }

    let mut conflicts = Vec::new();
    let mut rename_names = serde_json::Map::new();
    let mut total_bytes: i64 = 0;
    let mut count = 0;
    for raw in &sources {
        let src = raw.clone();
        let st = match meta::lstat(&src) {
            Some(m) => m,
            None => continue,
        };
        if suggest {
            if let Some(dir) = dest.as_deref() {
                if let Some(target) = meta::unique_target(
                    dir,
                    &path_name(&src),
                    &reserved,
                    st.kind == Kind::Directory,
                ) {
                    let name = path_name(&target);
                    rename_names.insert(src.clone(), json!(name));
                    reserved.push(path_name(&target));
                }
            }
        }
        count += 1;
        total_bytes += if st.kind == Kind::Directory {
            0
        } else {
            st.size
        };
        if let Some(dir) = dest.as_deref() {
            let target = join_path(dir, &path_name(&src));
            if let Err(error) = ctx.create_path(&target) {
                if error.is_system_access_required() {
                    return error.into_response();
                }
            }
            if meta::lstat(&target).is_some() {
                conflicts.push(json!({
                    "path": src,
                    "target": target,
                    "name": path_name(&src),
                    "type": st.kind.as_str()
                }));
            }
        }
    }
    let space = dest.as_deref().map(meta::space_info).unwrap_or_default();
    let has_space = match space.available {
        None => true,
        Some(avail) => avail >= (total_bytes as u64) + meta::OPERATION_SPACE_MARGIN,
    };
    ok(json!({
        "count": count,
        "total_bytes": total_bytes,
        "conflicts": conflicts,
        "rename_names": rename_names,
        "available_bytes": space.available.unwrap_or(0),
        "has_operation_space": has_space
    }))
}

pub async fn api_chmod(ctx: &Ctx) -> Response {
    let path = match ctx.write_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let modestr = ctx.params.get("mode").unwrap_or_default();
    if modestr.is_empty() || modestr.len() > 4 || !modestr.chars().all(|c| ('0'..='7').contains(&c))
    {
        return fail(1, "Invalid mode", Value::Null);
    }
    let mode = u32::from_str_radix(&modestr, 8).unwrap_or(0);
    let recursive = ctx.params.get("recursive").as_deref() == Some("1");
    if !recursive {
        return match fs::set_permissions(&path, fs::Permissions::from_mode(mode)) {
            Ok(()) => ok(json!({ "path": path, "mode": modestr })),
            Err(_) => fail(2, "chmod failed", Value::Null),
        };
    }
    let dir_option = ctx.params.get("recursive_directories");
    if let Some(v) = &dir_option {
        if v != "0" && v != "1" {
            return fail(1, "Invalid value", Value::Null);
        }
    }
    let apply_directories = dir_option.as_deref() != Some("0");
    match meta::lstat(&path) {
        Some(m) if m.kind == Kind::Directory => {}
        _ => return fail(1, "Not a directory", Value::Null),
    }
    let mut pending: Vec<(String, bool)> = vec![(path.clone(), false)];
    let mut seen: Vec<String> = Vec::new();
    let (mut changed, mut skipped, mut failed) = (0i64, 0i64, 0i64);
    let mut failed_path: Option<String> = None;
    while let Some((p, ready)) = pending.pop() {
        if ctx.write_path(&p).is_err() {
            failed += 1;
            continue;
        }
        let st = match meta::lstat(&p) {
            Some(m) => m,
            None => {
                failed += 1;
                failed_path.get_or_insert(p);
                continue;
            }
        };
        if st.kind == Kind::Symlink {
            skipped += 1;
            continue;
        }
        if st.kind == Kind::Directory && !ready {
            let identity = format!("{}:{}", st.dev, st.ino);
            if seen.iter().any(|s| s == &identity) {
                skipped += 1;
                continue;
            }
            seen.push(identity);
            pending.push((p.clone(), true));
            match fs::read_dir(&p) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if name != "." && name != ".." {
                            pending.push((join_path(&p, &name), false));
                        }
                    }
                }
                Err(_) => {
                    failed += 1;
                    failed_path.get_or_insert(p);
                }
            }
            continue;
        }
        if !apply_directories && st.kind != Kind::File {
            skipped += 1;
            continue;
        }
        if fs::set_permissions(&p, fs::Permissions::from_mode(mode)).is_ok() {
            changed += 1;
        } else {
            failed += 1;
            failed_path.get_or_insert(p);
        }
    }
    let result = json!({
        "path": path, "mode": modestr, "changed": changed, "skipped": skipped,
        "failed": failed, "failed_path": failed_path
    });
    if failed > 0 {
        let message = format!(
            "Failed to update some permissions: {}",
            failed_path.unwrap_or_default()
        );
        return fail(2, &message, result);
    }
    ok(result)
}

pub async fn api_detect_type(ctx: &Ctx) -> Response {
    let path = match ctx.read_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let st = match meta::stat(&path) {
        Some(m) => m,
        None => return fail(2, "Path not found", Value::Null),
    };
    if st.kind == Kind::Directory {
        return ok(json!({
            "path": path, "type": "directory", "kind": "directory",
            "mime": Value::Null, "size": -1
        }));
    }
    let (kind, mime) = meta::detect_content_type(&path);
    ok(json!({
        "path": path,
        "type": kind,
        "kind": kind,
        "mime": mime,
        "size": st.size,
        "mtime": st.mtime,
        "numeric_permissions": meta::numeric_permissions(st.mode),
        "editable": ctx.write_path(&path).is_ok()
    }))
}
