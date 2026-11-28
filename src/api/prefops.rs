//! Preferences, bookmarks and favourites.

use crate::config;
use crate::meta;
use crate::paths::normalize_path;
use crate::reply::{fail, fail_status, ok};
use crate::state::Ctx;
use axum::response::Response;
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};

static LAST_DIRECTORY_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub async fn api_preferences(ctx: &Ctx) -> Response {
    let prefs = ctx.prefs();
    let mut out = prefs.to_json();
    let last_directory = ctx
        .read_path(&prefs.last_directory)
        .ok()
        .filter(|path| {
            meta::stat(path).is_some_and(|item| item.kind == crate::meta::Kind::Directory)
        })
        .unwrap_or_default();
    out.insert("last_directory".into(), json!(last_directory));
    ok(Value::Object(out))
}

fn glass_number(value: &str, maximum: i64) -> Option<i64> {
    if !value.chars().all(|c| c.is_ascii_digit()) || value.is_empty() {
        return None;
    }
    let n: i64 = value.parse().ok()?;
    if (0..=maximum).contains(&n) && n.to_string() == value {
        Some(n)
    } else {
        None
    }
}

fn bool01(value: &str) -> bool {
    matches!(value, "0" | "1")
}

fn ranged_i64(value: &str, min: i64, max: i64) -> Option<i64> {
    value
        .parse::<i64>()
        .ok()
        .filter(|number| (min..=max).contains(number))
}

pub async fn api_save_preferences(ctx: &Ctx) -> Response {
    let config_path = ctx.st.settings.config_path.clone();
    let section = ctx.params.str_or("section", "basic");

    if section == "editor" {
        if let Err(e) = ctx.require_post() {
            return e.into_response();
        }
        let mut values: Vec<(String, String)> = Vec::new();
        for key in [
            "editor_auto_indent",
            "editor_auto_wrap",
            "editor_prism",
            "show_line_numbers",
        ] {
            if let Some(v) = ctx.params.get(key) {
                if !bool01(&v) {
                    return fail_status(
                        axum::http::StatusCode::BAD_REQUEST,
                        1,
                        "Invalid editor setting",
                        Value::Null,
                    );
                }
                values.push((key.to_string(), v));
            }
        }
        if !values.is_empty() && config::save_values(&config_path, &values).is_err() {
            eprintln!("Failed to persist editor preferences to {config_path}");
        }
        return api_preferences(ctx).await;
    }

    if section == "terminal" {
        if let Err(e) = ctx.require_post() {
            return e.into_response();
        }
        let mut values: Vec<(String, String)> = Vec::new();
        for (key, min, max) in [
            ("terminal_ping", 5, 600),
            ("terminal_idle", 0, 86_400),
            ("terminal_ring_kb", 16, 4096),
        ] {
            if let Some(raw) = ctx.params.get(key) {
                match ranged_i64(&raw, min, max) {
                    Some(number) => values.push((key.to_string(), number.to_string())),
                    None => {
                        return fail_status(
                            axum::http::StatusCode::BAD_REQUEST,
                            1,
                            "Invalid terminal setting",
                            Value::Null,
                        )
                    }
                }
            }
        }
        if let Some(raw) = ctx.params.get("terminal_replay") {
            if !bool01(&raw) {
                return fail_status(
                    axum::http::StatusCode::BAD_REQUEST,
                    1,
                    "Invalid terminal setting",
                    Value::Null,
                );
            }
            values.push(("terminal_replay".to_string(), raw));
        }
        if !values.is_empty() && config::save_values(&config_path, &values).is_err() {
            eprintln!("Failed to persist terminal preferences to {config_path}");
        }
        return api_preferences(ctx).await;
    }

    if section == "appearance" {
        if let Err(e) = ctx.require_post() {
            return e.into_response();
        }
        let mut values: Vec<(String, String)> = Vec::new();
        if let Some(theme) = ctx.params.get("theme") {
            if !["auto", "dark", "light"].contains(&theme.as_str()) {
                return fail_status(
                    axum::http::StatusCode::BAD_REQUEST,
                    1,
                    "Invalid appearance value",
                    Value::Null,
                );
            }
            values.push(("theme".into(), theme));
        }
        for (key, maximum) in config::GLASS_LIMITS {
            if let Some(raw) = ctx.params.get(key) {
                match glass_number(&raw, *maximum) {
                    Some(n) => values.push(((*key).to_string(), n.to_string())),
                    None => {
                        return fail_status(
                            axum::http::StatusCode::BAD_REQUEST,
                            1,
                            "Invalid appearance value",
                            Value::Null,
                        )
                    }
                }
            }
        }
        if !values.is_empty() && config::save_values(&config_path, &values).is_err() {
            eprintln!("Failed to persist appearance preferences to {config_path}");
        }
        return api_preferences(ctx).await;
    }

    if section == "window" {
        let current = ctx.prefs();
        let mobile = ctx.params.get("window_target").as_deref() == Some("mobile");
        let helper = |value: Option<String>, fallback: i64| -> i64 {
            match value.and_then(|v| v.trim().parse::<i64>().ok()) {
                Some(n) if (100..=8192).contains(&n) => n,
                _ => fallback,
            }
        };
        let w = helper(
            ctx.params.get("window_width"),
            if mobile {
                current.mobile_window_width
            } else {
                current.window_width
            },
        );
        let h = helper(
            ctx.params.get("window_height"),
            if mobile {
                current.mobile_window_height
            } else {
                current.window_height
            },
        );
        let values = if mobile {
            vec![
                ("mobile_window_width".to_string(), w.to_string()),
                ("mobile_window_height".to_string(), h.to_string()),
            ]
        } else {
            vec![
                ("window_width".to_string(), w.to_string()),
                ("window_height".to_string(), h.to_string()),
            ]
        };
        if let Err(e) = config::save_values(&config_path, &values) {
            eprintln!("Failed to persist window preferences to {config_path}: {e}");
        }
        return api_preferences(ctx).await;
    }

    if section == "wallpaper" {
        return crate::api::secops::api_wallpaper_save(ctx).await;
    }

    let mut values: Vec<(String, String)> = Vec::new();
    if let Some(view_mode) = ctx.params.get("view_mode") {
        if (0..=5).contains(&view_mode.parse::<i64>().unwrap_or(-1)) {
            values.push(("view_mode".into(), view_mode));
        }
    }
    for key in [
        "full_width",
        "show_hidden_files",
        "enable_thumbnails",
        "restore_last_directory",
    ] {
        if let Some(v) = ctx.params.get(key) {
            if bool01(&v) {
                values.push((key.to_string(), v));
            }
        }
    }
    if let Some(theme) = ctx.params.get("theme") {
        if ["auto", "dark", "light"].contains(&theme.as_str()) {
            values.push(("theme".into(), theme));
        }
    }
    if let Some(mirror) = ctx.params.get("update_mirror") {
        if ["auto", "gitee", "github", "gitlab", "cloudflare"].contains(&mirror.as_str()) {
            values.push(("update_mirror".into(), mirror));
        }
    }
    if let Some(home) = ctx.params.get("home_dir") {
        if !home.is_empty() {
            let path = match ctx.create_path(&home) {
                Ok(path) if path != "/" => path,
                Ok(_) => return fail(1, "Invalid home directory", Value::Null),
                Err(error) => return error.into_response(),
            };
            if !meta::mkdir_p(&path)
                || !meta::stat(&path).is_some_and(|meta| meta.kind == crate::meta::Kind::Directory)
            {
                return fail(1, "Invalid home directory", Value::Null);
            }
            values.push(("home_dir".into(), path));
        }
    }
    if let Some(map) = ctx.params.get("open_type_map") {
        values.push(("open_type_map".into(), map));
    }
    if values.is_empty() {
        return fail(1, "Nothing to save", Value::Null);
    }
    if let Err(e) = config::save_values(&config_path, &values) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    api_preferences(ctx).await
}

pub async fn api_save_last_directory(ctx: &Ctx) -> Response {
    if let Err(error) = ctx.require_post() {
        return error.into_response();
    }
    let path = match ctx.read_path(&ctx.params.get("path").unwrap_or_default()) {
        Ok(path) => path,
        Err(error) => return error.into_response(),
    };
    if !meta::stat(&path).is_some_and(|item| item.kind == crate::meta::Kind::Directory) {
        return fail(1, "Invalid directory", Value::Null);
    }
    let _guard = match LAST_DIRECTORY_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
    {
        Ok(guard) => guard,
        Err(_) => {
            return fail_status(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                1,
                "Cannot lock last directory setting",
                Value::Null,
            )
        }
    };
    let current = ctx.prefs().last_directory;
    let current_normalized = normalize_path(&current).unwrap_or_default();
    let changed = current_normalized != path;
    if changed {
        let values = [("last_directory".to_string(), path.clone())];
        if let Err(error) = config::save_values(&ctx.st.settings.config_path, &values) {
            return fail(2, &format!("Save failed: {error}"), Value::Null);
        }
    }
    ok(json!({ "last_directory": path, "changed": changed }))
}

pub async fn api_save_show_line_numbers(ctx: &Ctx) -> Response {
    let value = if ctx
        .params
        .first_of(&["value", "show_line_numbers"])
        .as_deref()
        == Some("1")
    {
        "1"
    } else {
        "0"
    };
    let values = [("show_line_numbers".to_string(), value.to_string())];
    if let Err(e) = config::save_values(&ctx.st.settings.config_path, &values) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(json!({ "show_line_numbers": if value == "1" { 1 } else { 0 } }))
}

fn bookmarks_payload(ctx: &Ctx, folders_hint: Option<Vec<String>>) -> Value {
    let uci = ctx.st.uci();
    let list = config::read_bookmarks(&uci);
    let folders = folders_hint.unwrap_or_else(|| config::read_bookmark_folders(&uci));
    json!({
        "bookmarks": config::bookmark_payload(&uci, &list),
        "bookmark_folders": folders,
        "fav_expanded": config::read_fav_expanded(&uci)
    })
}

#[allow(clippy::result_large_err)]
fn check_device(ctx: &Ctx, device_id: &str) -> Result<(), Response> {
    if device_id.is_empty() {
        return Ok(());
    }
    if !device_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(fail(1, "Invalid device", Value::Null));
    }
    let uci = ctx.st.uci();
    match uci.section(device_id) {
        Some(sec) if sec.kind == "remote_device" => Ok(()),
        _ => Err(fail(1, "Invalid device", Value::Null)),
    }
}

struct SavedLink {
    path: String,
    label: String,
    original: Option<String>,
}

#[allow(clippy::result_large_err)]
fn saved_link(ctx: &Ctx) -> Result<SavedLink, Response> {
    let path = ctx
        .params
        .first_of(&["path", "address"])
        .and_then(|v| normalize_path(&v))
        .ok_or_else(|| fail(1, "Invalid path", Value::Null))?;
    let label = config::clean_label(&ctx.params.get("label").unwrap_or_default(), 64);
    let label = if label.is_empty() {
        config::default_label_for(&path)
    } else {
        label
    };
    let original = ctx
        .params
        .first_of(&["original_path", "original", "old_path"])
        .and_then(|v| normalize_path(&v));
    Ok(SavedLink {
        path,
        label,
        original,
    })
}

// Both lists use the same rename/upsert mechanics; their identity rules and
// whether duplicate legacy entries are all updated remain distinct.
fn upsert_link<T>(
    items: &mut Vec<T>,
    path: &str,
    original: Option<&str>,
    matches: impl Fn(&T, &str) -> bool,
    mut update: impl FnMut(&mut T),
    create: impl FnOnce() -> T,
    update_all: bool,
) {
    if let Some(old) = original.filter(|old| *old != path) {
        items.retain(|item| !matches(item, old));
    }
    let mut found = false;
    for item in items.iter_mut() {
        if matches(item, path) {
            update(item);
            found = true;
            if !update_all {
                break;
            }
        }
    }
    if !found {
        items.push(create());
    }
}

// Return None for a missing item and Some(false) at a group boundary. The
// APIs intentionally use different boundary responses for compatibility.
fn move_link<T>(
    items: &mut [T],
    matches: impl Fn(&T) -> bool,
    same_group: impl Fn(&T, &T) -> bool,
    direction: &str,
) -> Option<bool> {
    let index = items.iter().position(matches)?;
    let peers: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| same_group(&items[index], item))
        .map(|(i, _)| i)
        .collect();
    let position = peers.iter().position(|i| *i == index)?;
    let next = if direction == "down" {
        position.checked_add(1)
    } else {
        position.checked_sub(1)
    };
    let Some(other) = next.and_then(|position| peers.get(position)) else {
        return Some(false);
    };
    items.swap(index, *other);
    Some(true)
}

pub async fn api_bookmark_save(ctx: &Ctx) -> Response {
    let device_id = ctx.params.get("device_id").unwrap_or_default();
    if let Err(r) = check_device(ctx, &device_id) {
        return r;
    }
    let SavedLink {
        path,
        label,
        original,
    } = match saved_link(ctx) {
        Ok(link) => link,
        Err(response) => return response,
    };
    let bookmark_label = label.clone();
    let folder = config::clean_label(
        &ctx.params
            .first_of(&["folder", "group"])
            .unwrap_or_default(),
        64,
    );
    let mut list = config::read_bookmarks(&ctx.st.uci());
    upsert_link(
        &mut list,
        &path,
        original.as_deref(),
        |bookmark, candidate| bookmark.path == candidate && bookmark.device_id == device_id,
        |bookmark| {
            bookmark.label = label.clone();
            bookmark.folder = folder.clone();
        },
        || config::Bookmark {
            label: label.clone(),
            path: path.clone(),
            device_id: device_id.clone(),
            folder: folder.clone(),
        },
        true,
    );
    if !folder.is_empty() {
        let uci = ctx.st.uci();
        let mut folders = config::read_bookmark_folders(&uci);
        if !folders.iter().any(|f| f == &folder) {
            folders.push(folder.clone());
            if let Err(e) = config::write_bookmark_folders(&ctx.st.settings.config_path, &folders) {
                return fail(2, &format!("Save failed: {e}"), Value::Null);
            }
        }
    }
    if let Err(e) = config::write_bookmarks(&ctx.st.settings.config_path, &list) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    if device_id.is_empty() {
        if let Some(flag) = ctx.params.get("quick") {
            let mut quick_items = load_quick_items(ctx);
            if let Some(original) = original.as_deref() {
                if original != path {
                    quick_items.retain(|item| item.path != original);
                }
            }
            if flag == "1" {
                if !quick_items.iter().any(|item| item.path == path) {
                    quick_items.push(config::QuickItem {
                        label: bookmark_label,
                        path: path.clone(),
                        icon: "folder".to_string(),
                    });
                }
            } else {
                quick_items.retain(|item| item.path != path);
            }
            if let Err(e) = config::write_quick_items(&ctx.st.settings.config_path, &quick_items) {
                return fail(2, &format!("Save failed: {e}"), Value::Null);
            }
        }
    }
    ok(bookmarks_payload(ctx, None))
}

fn load_quick_items(ctx: &Ctx) -> Vec<config::QuickItem> {
    let uci = ctx.st.uci();
    if let Some(items) = config::read_quick_items(&uci) {
        return items;
    }
    let prefs = ctx.prefs();
    let items = config::default_quick_items(&prefs.home_dir);
    for item in &items {
        meta::mkdir_p(&item.path);
    }
    if let Err(error) = config::write_quick_items(&ctx.st.settings.config_path, &items) {
        eprintln!("Failed to seed quick access items: {error}");
    }
    items
}

pub async fn api_quick_item_save(ctx: &Ctx) -> Response {
    let SavedLink {
        path,
        label,
        original,
    } = match saved_link(ctx) {
        Ok(link) => link,
        Err(response) => return response,
    };
    let mut items = load_quick_items(ctx);
    upsert_link(
        &mut items,
        &path,
        original.as_deref(),
        |item, candidate| item.path == candidate,
        |item| item.label = label.clone(),
        || config::QuickItem {
            label: label.clone(),
            path: path.clone(),
            icon: "folder".to_string(),
        },
        false,
    );
    if let Err(e) = config::write_quick_items(&ctx.st.settings.config_path, &items) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(json!({ "quick_access": config::quick_access_payload(&items) }))
}

pub async fn api_quick_item_delete(ctx: &Ctx) -> Response {
    let path = match normalize_path(&ctx.params.get("path").unwrap_or_default()) {
        Some(p) => p,
        None => return fail(1, "Invalid path", Value::Null),
    };
    let mut items = load_quick_items(ctx);
    let before = items.len();
    items.retain(|item| item.path != path);
    if items.len() == before {
        return fail(1, "Path not found", Value::Null);
    }
    if let Err(e) = config::write_quick_items(&ctx.st.settings.config_path, &items) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(json!({ "quick_access": config::quick_access_payload(&items) }))
}

pub async fn api_quick_item_move(ctx: &Ctx) -> Response {
    let path = match normalize_path(&ctx.params.get("path").unwrap_or_default()) {
        Some(p) => p,
        None => return fail(1, "Invalid path", Value::Null),
    };
    let direction = ctx.params.str_or("direction", "up");
    let mut items = load_quick_items(ctx);
    match move_link(
        &mut items,
        |item| item.path == path,
        |_, _| true,
        &direction,
    ) {
        None => return fail(1, "Path not found", Value::Null),
        Some(false) => return fail(1, "Cannot move", Value::Null),
        Some(true) => (),
    }
    if let Err(e) = config::write_quick_items(&ctx.st.settings.config_path, &items) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(json!({ "quick_access": config::quick_access_payload(&items) }))
}

pub async fn api_bookmark_delete(ctx: &Ctx) -> Response {
    let device_id = ctx.params.get("device_id").unwrap_or_default();
    if let Err(r) = check_device(ctx, &device_id) {
        return r;
    }
    let path = match ctx
        .params
        .first_of(&["path", "address"])
        .and_then(|v| normalize_path(&v))
    {
        Some(p) => p,
        None => return fail(1, "Invalid path", Value::Null),
    };
    let mut list = config::read_bookmarks(&ctx.st.uci());
    list.retain(|b| !(b.path == path && b.device_id == device_id));
    if let Err(e) = config::write_bookmarks(&ctx.st.settings.config_path, &list) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(bookmarks_payload(ctx, None))
}

pub async fn api_bookmark_move(ctx: &Ctx) -> Response {
    let device_id = ctx.params.get("device_id").unwrap_or_default();
    if let Err(r) = check_device(ctx, &device_id) {
        return r;
    }
    let path = match normalize_path(&ctx.params.get("path").unwrap_or_default()) {
        Some(p) => p,
        None => return fail(1, "Invalid path", Value::Null),
    };
    let direction = ctx.params.str_or("direction", "up");
    let mut list = config::read_bookmarks(&ctx.st.uci());
    match move_link(
        &mut list,
        |bookmark| bookmark.path == path && bookmark.device_id == device_id,
        |current, candidate| current.folder == candidate.folder,
        &direction,
    ) {
        None => return fail(1, "Path not found", Value::Null),
        Some(false) => return ok(bookmarks_payload(ctx, None)),
        Some(true) => (),
    }
    if let Err(e) = config::write_bookmarks(&ctx.st.settings.config_path, &list) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(bookmarks_payload(ctx, None))
}

pub async fn api_bookmark_folder_add(ctx: &Ctx) -> Response {
    let name = config::clean_label(
        &ctx.params.first_of(&["name", "folder"]).unwrap_or_default(),
        64,
    );
    if name.is_empty() {
        return fail(1, "Invalid name", Value::Null);
    }
    let uci = ctx.st.uci();
    let mut folders = config::read_bookmark_folders(&uci);
    if !folders.iter().any(|f| f == &name) {
        folders.push(name);
    }
    if let Err(e) = config::write_bookmark_folders(&ctx.st.settings.config_path, &folders) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(bookmarks_payload(ctx, Some(folders)))
}

pub async fn api_bookmark_folder_rename(ctx: &Ctx) -> Response {
    let from = config::clean_label(&ctx.params.get("from").unwrap_or_default(), 64);
    let to = config::clean_label(&ctx.params.get("to").unwrap_or_default(), 64);
    if from.is_empty() || to.is_empty() || from == to {
        return fail(1, "Invalid name", Value::Null);
    }
    let uci = ctx.st.uci();
    let folders: Vec<String> = config::read_bookmark_folders(&uci)
        .into_iter()
        .map(|f| if f == from { to.clone() } else { f })
        .collect();
    if let Err(e) = config::write_bookmark_folders(&ctx.st.settings.config_path, &folders) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    let expanded: Vec<String> = config::read_fav_expanded(&uci)
        .into_iter()
        .map(|f| if f == from { to.clone() } else { f })
        .collect();
    if let Err(e) = config::write_fav_expanded(&ctx.st.settings.config_path, &expanded) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    let mut list = config::read_bookmarks(&uci);
    for b in list.iter_mut() {
        if b.folder == from {
            b.folder = to.clone();
        }
    }
    if let Err(e) = config::write_bookmarks(&ctx.st.settings.config_path, &list) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(bookmarks_payload(ctx, Some(folders)))
}

pub async fn api_bookmark_folder_delete(ctx: &Ctx) -> Response {
    let name = config::clean_label(&ctx.params.get("name").unwrap_or_default(), 64);
    if name.is_empty() {
        return fail(1, "Invalid name", Value::Null);
    }
    let uci = ctx.st.uci();
    let folders: Vec<String> = config::read_bookmark_folders(&uci)
        .into_iter()
        .filter(|f| f != &name)
        .collect();
    if let Err(e) = config::write_bookmark_folders(&ctx.st.settings.config_path, &folders) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    let expanded: Vec<String> = config::read_fav_expanded(&uci)
        .into_iter()
        .filter(|f| f != &name)
        .collect();
    if let Err(e) = config::write_fav_expanded(&ctx.st.settings.config_path, &expanded) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    let mut list = config::read_bookmarks(&uci);
    let mut changed = false;
    for b in list.iter_mut() {
        if b.folder == name {
            b.folder.clear();
            changed = true;
        }
    }
    if changed {
        if let Err(e) = config::write_bookmarks(&ctx.st.settings.config_path, &list) {
            return fail(2, &format!("Save failed: {e}"), Value::Null);
        }
    }
    ok(bookmarks_payload(ctx, Some(folders)))
}

pub async fn api_bookmark_folder_state(ctx: &Ctx) -> Response {
    let name = config::clean_label(&ctx.params.get("name").unwrap_or_default(), 64);
    let expanded = ctx.params.get("expanded").as_deref() == Some("1");
    if name.is_empty() {
        return fail(1, "Invalid name", Value::Null);
    }
    let uci = ctx.st.uci();
    let mut list: Vec<String> = config::read_fav_expanded(&uci)
        .into_iter()
        .filter(|f| f != &name)
        .collect();
    if expanded {
        list.push(name);
    }
    if let Err(e) = config::write_fav_expanded(&ctx.st.settings.config_path, &list) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(bookmarks_payload(ctx, None))
}

pub async fn api_bookmark_folder_move(ctx: &Ctx) -> Response {
    let name = config::clean_label(&ctx.params.get("name").unwrap_or_default(), 64);
    let direction = ctx.params.str_or("direction", "up");
    if name.is_empty() {
        return fail(1, "Invalid name", Value::Null);
    }
    let uci = ctx.st.uci();
    let mut folders = config::read_bookmark_folders(&uci);
    let index = match folders.iter().position(|f| f == &name) {
        Some(i) => i,
        None => return fail(1, "Path not found", Value::Null),
    };
    let target = if direction == "down" {
        index as i64 + 1
    } else {
        index as i64 - 1
    };
    if target < 0 || target as usize >= folders.len() {
        return ok(bookmarks_payload(ctx, Some(folders)));
    }
    folders.swap(index, target as usize);
    if let Err(e) = config::write_bookmark_folders(&ctx.st.settings.config_path, &folders) {
        return fail(2, &format!("Save failed: {e}"), Value::Null);
    }
    ok(bookmarks_payload(ctx, Some(folders)))
}

#[cfg(test)]
mod link_refactor_tests {
    use super::*;

    #[test]
    fn shared_setting_validators_preserve_bounds_and_bool_encoding() {
        assert!(bool01("0"));
        assert!(bool01("1"));
        for invalid in ["", "true", "2", " 1", "01"] {
            assert!(!bool01(invalid));
        }
        assert_eq!(ranged_i64("5", 5, 600), Some(5));
        assert_eq!(ranged_i64("600", 5, 600), Some(600));
        for invalid in ["4", "601", "x", " 5", "99999999999999999999"] {
            assert_eq!(ranged_i64(invalid, 5, 600), None);
        }
    }

    #[test]
    fn upsert_preserves_device_identity_and_legacy_duplicates() {
        let item = |path: &str, device: &str| config::Bookmark {
            label: "old".into(),
            path: path.into(),
            device_id: device.into(),
            folder: "g".into(),
        };
        let mut items = vec![
            item("/old", "a"),
            item("/old", "b"),
            item("/new", "a"),
            item("/new", "a"),
        ];
        upsert_link(
            &mut items,
            "/new",
            Some("/old"),
            |b, p| b.path == p && b.device_id == "a",
            |b| b.label = "updated".into(),
            || item("/new", "a"),
            true,
        );
        assert_eq!(items.len(), 3);
        assert!(items.iter().any(|b| b.path == "/old" && b.device_id == "b"));
        assert!(items
            .iter()
            .filter(|b| b.path == "/new")
            .all(|b| b.label == "updated"));
    }

    #[test]
    fn move_respects_group_boundaries_and_missing_entries() {
        let mut list = vec![("a", "x"), ("b", "y"), ("c", "x")];
        assert_eq!(
            move_link(&mut list, |v| v.0 == "a", |a, b| a.1 == b.1, "down"),
            Some(true)
        );
        assert_eq!(list, vec![("c", "x"), ("b", "y"), ("a", "x")]);
        assert_eq!(
            move_link(&mut list, |v| v.0 == "b", |a, b| a.1 == b.1, "down"),
            Some(false)
        );
        assert_eq!(
            move_link(&mut list, |v| v.0 == "z", |a, b| a.1 == b.1, "up"),
            None
        );
    }
}
