//! Preferences and favourites persisted in `/etc/config/harbor_file_pro`.

use crate::meta;
use crate::paths::{join_path, normalize_path, path_name};
use crate::uci::Uci;
use serde_json::{json, Map, Value};

pub const CONFIG_NAME: &str = "harbor_file_pro";
pub const CONFIG_SECTION: &str = "main";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/config/harbor_file_pro";

pub const GLASS_LIMITS: &[(&str, i64)] = &[
    ("glass_light_transparency", 60),
    ("glass_light_blur", 32),
    ("glass_dark_transparency", 60),
    ("glass_dark_blur", 32),
];

#[derive(Debug, Clone)]
pub struct Prefs {
    pub view_mode: i64,
    pub theme: String,
    pub full_width: i64,
    pub show_hidden_files: i64,
    pub home_dir: String,
    pub enable_thumbnails: i64,
    pub editor_auto_indent: i64,
    pub editor_auto_wrap: i64,
    pub editor_prism: i64,
    pub restore_last_directory: i64,
    pub show_line_numbers: i64,
    pub last_directory: String,
    pub update_mirror: String,
    pub open_type_map: String,
    pub window_width: i64,
    pub window_height: i64,
    pub mobile_window_width: i64,
    pub mobile_window_height: i64,
    pub glass: Vec<(String, i64)>,
    pub wallpaper_enabled: i64,
    pub wallpaper_login_enabled: i64,
    pub wallpaper_mode: String,
    pub wallpaper_id: String,
    pub wallpaper_source: String,
    pub wallpaper_type: String,
    pub system_access_timeout_enabled: i64,
    pub system_access_timeout_minutes: i64,
    pub terminal_ping: i64,
    pub terminal_idle: i64,
    pub terminal_ring_kb: i64,
    pub terminal_replay: i64,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            view_mode: 1,
            theme: "auto".to_string(),
            full_width: 1,
            show_hidden_files: 0,
            home_dir: "/tmp/root".to_string(),
            enable_thumbnails: 1,
            editor_auto_indent: 1,
            editor_auto_wrap: 0,
            editor_prism: 1,
            restore_last_directory: 1,
            show_line_numbers: 1,
            last_directory: String::new(),
            update_mirror: "auto".to_string(),
            open_type_map: String::new(),
            window_width: 820,
            window_height: 620,
            mobile_window_width: 360,
            mobile_window_height: 560,
            wallpaper_enabled: 1,
            wallpaper_login_enabled: 0,
            wallpaper_mode: "fixed".to_string(),
            wallpaper_id: crate::wallpapers::BUILTIN_ID.to_string(),
            wallpaper_source: "builtin".to_string(),
            wallpaper_type: "all".to_string(),
            system_access_timeout_enabled: 1,
            system_access_timeout_minutes: 15,
            terminal_ping: 30,
            terminal_idle: 300,
            terminal_ring_kb: 256,
            terminal_replay: 1,
            glass: GLASS_LIMITS
                .iter()
                .map(|(k, _)| {
                    (
                        k.to_string(),
                        if *k == "glass_light_transparency" || *k == "glass_dark_transparency" {
                            20
                        } else if *k == "glass_light_blur" {
                            16
                        } else {
                            20
                        },
                    )
                })
                .collect(),
        }
    }
}

fn number_bool(value: Option<&str>, fallback: i64) -> i64 {
    match value {
        Some("0") => 0,
        Some("1") => 1,
        _ => fallback,
    }
}

fn setting_int(value: Option<&str>, fallback: i64, min: i64, max: i64) -> i64 {
    value
        .and_then(|raw| raw.parse::<i64>().ok())
        .map(|number| number.clamp(min, max))
        .unwrap_or(fallback)
}

fn dimension(value: Option<&str>, fallback: i64) -> i64 {
    match value.and_then(|v| v.trim().parse::<i64>().ok()) {
        Some(n) if (100..=8192).contains(&n) => n,
        _ => fallback,
    }
}

fn glass_value(value: Option<&str>, fallback: i64, max: i64) -> i64 {
    match value.and_then(|v| v.trim().parse::<i64>().ok()) {
        Some(n) if (0..=max).contains(&n) => n,
        _ => fallback,
    }
}

pub fn sanitize_wallpaper_id(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Some(String::new());
    }
    if crate::wallpapers::is_builtin_id(raw)
        || crate::wallpapers::parse_custom_id(raw).is_some()
        || crate::wallpapers::is_provider_url(raw)
    {
        return Some(raw.to_string());
    }
    None
}

impl Prefs {
    pub fn from_uci(uci: &Uci) -> Prefs {
        let d = Prefs::default();
        let sec = uci.section(CONFIG_SECTION);
        let g = |k: &str| sec.and_then(|s| s.get(k));

        let view_mode = match g("view_mode").and_then(|v| v.parse::<i64>().ok()) {
            Some(n) if (0..=5).contains(&n) => n,
            _ => d.view_mode,
        };
        let theme = match g("theme") {
            Some("auto") | Some("dark") | Some("light") => g("theme").unwrap().to_string(),
            _ => d.theme.clone(),
        };
        let mirror = match g("update_mirror") {
            Some("gitee") | Some("github") | Some("gitlab") | Some("cloudflare") => {
                g("update_mirror").unwrap().to_string()
            }
            _ => d.update_mirror.clone(),
        };
        let home = normalize_path(g("home_dir").unwrap_or(""))
            .filter(|p| p != "/")
            .unwrap_or_else(|| d.home_dir.clone());
        let stored_wallpaper_id = g("wallpaper_id")
            .and_then(sanitize_wallpaper_id)
            .filter(|id| !id.is_empty());
        let wallpaper_id = stored_wallpaper_id
            .clone()
            .unwrap_or_else(|| d.wallpaper_id.clone());
        let wallpaper_enabled = if stored_wallpaper_id.is_some() {
            number_bool(g("wallpaper_enabled"), d.wallpaper_enabled)
        } else {
            d.wallpaper_enabled
        };
        let wallpaper_source = if stored_wallpaper_id.is_none() {
            "builtin".to_string()
        } else {
            match g("wallpaper_source").or_else(|| g("wallpaper_category")) {
                Some(v) if crate::wallpapers::valid_source(v) => v.to_string(),
                _ if crate::wallpapers::is_builtin_id(&wallpaper_id) => "builtin".to_string(),
                _ => d.wallpaper_source.clone(),
            }
        };

        Prefs {
            view_mode,
            theme,
            full_width: number_bool(g("full_width"), d.full_width),
            show_hidden_files: number_bool(g("show_hidden_files"), d.show_hidden_files),
            home_dir: home,
            enable_thumbnails: number_bool(g("enable_thumbnails"), d.enable_thumbnails),
            editor_auto_indent: number_bool(g("editor_auto_indent"), d.editor_auto_indent),
            editor_auto_wrap: number_bool(g("editor_auto_wrap"), d.editor_auto_wrap),
            editor_prism: number_bool(g("editor_prism"), d.editor_prism),
            restore_last_directory: number_bool(
                g("restore_last_directory"),
                d.restore_last_directory,
            ),
            show_line_numbers: number_bool(g("show_line_numbers"), d.show_line_numbers),
            terminal_ping: setting_int(g("terminal_ping"), d.terminal_ping, 5, 600),
            terminal_idle: setting_int(g("terminal_idle"), d.terminal_idle, 0, 86_400),
            terminal_ring_kb: setting_int(g("terminal_ring_kb"), d.terminal_ring_kb, 16, 4096),
            terminal_replay: number_bool(g("terminal_replay"), d.terminal_replay),
            last_directory: g("last_directory").unwrap_or("").to_string(),
            update_mirror: mirror,
            open_type_map: g("open_type_map").unwrap_or("").to_string(),
            window_width: dimension(g("window_width"), d.window_width),
            window_height: dimension(g("window_height"), d.window_height),
            mobile_window_width: dimension(g("mobile_window_width"), d.mobile_window_width),
            mobile_window_height: dimension(g("mobile_window_height"), d.mobile_window_height),
            wallpaper_enabled,
            wallpaper_login_enabled: number_bool(
                g("wallpaper_login_enabled"),
                d.wallpaper_login_enabled,
            ),
            wallpaper_mode: match g("wallpaper_mode") {
                Some("auto") => "auto".to_string(),
                Some("fixed") => "fixed".to_string(),
                _ => d.wallpaper_mode.clone(),
            },
            wallpaper_id,
            wallpaper_source,
            wallpaper_type: match g("wallpaper_type") {
                Some(v) if crate::wallpapers::valid_type(v) => v.to_string(),
                _ => d.wallpaper_type.clone(),
            },
            system_access_timeout_enabled: number_bool(
                g("system_access_timeout_enabled"),
                d.system_access_timeout_enabled,
            ),
            system_access_timeout_minutes: g("system_access_timeout_minutes")
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|v| (1..=10080).contains(v))
                .unwrap_or(d.system_access_timeout_minutes),
            glass: GLASS_LIMITS
                .iter()
                .map(|(k, max)| {
                    let fallback = d
                        .glass
                        .iter()
                        .find(|(dk, _)| dk == k)
                        .map(|(_, v)| *v)
                        .unwrap_or(0);
                    (k.to_string(), glass_value(g(k), fallback, *max))
                })
                .collect(),
        }
    }

    pub fn to_json(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("view_mode".into(), json!(self.view_mode));
        m.insert("theme".into(), json!(self.theme));
        m.insert("full_width".into(), json!(self.full_width));
        m.insert("show_hidden_files".into(), json!(self.show_hidden_files));
        m.insert("home_dir".into(), json!(self.home_dir));
        m.insert("enable_thumbnails".into(), json!(self.enable_thumbnails));
        m.insert("editor_auto_indent".into(), json!(self.editor_auto_indent));
        m.insert("editor_auto_wrap".into(), json!(self.editor_auto_wrap));
        m.insert("editor_prism".into(), json!(self.editor_prism));
        m.insert(
            "restore_last_directory".into(),
            json!(self.restore_last_directory),
        );
        m.insert("show_line_numbers".into(), json!(self.show_line_numbers));
        m.insert("terminal_ping".into(), json!(self.terminal_ping));
        m.insert("terminal_idle".into(), json!(self.terminal_idle));
        m.insert("terminal_ring_kb".into(), json!(self.terminal_ring_kb));
        m.insert("terminal_replay".into(), json!(self.terminal_replay));
        m.insert("last_directory".into(), json!(self.last_directory));
        m.insert("update_mirror".into(), json!(self.update_mirror));
        m.insert("open_type_map".into(), json!(self.open_type_map));
        m.insert("window_width".into(), json!(self.window_width));
        m.insert("window_height".into(), json!(self.window_height));
        m.insert(
            "mobile_window_width".into(),
            json!(self.mobile_window_width),
        );
        m.insert(
            "mobile_window_height".into(),
            json!(self.mobile_window_height),
        );
        m.insert("wallpaper_enabled".into(), json!(self.wallpaper_enabled));
        m.insert(
            "wallpaper_login_enabled".into(),
            json!(self.wallpaper_login_enabled),
        );
        m.insert("wallpaper_mode".into(), json!(self.wallpaper_mode));
        m.insert("wallpaper_id".into(), json!(self.wallpaper_id));
        m.insert("wallpaper_source".into(), json!(self.wallpaper_source));
        m.insert("wallpaper_type".into(), json!(self.wallpaper_type));
        m.insert(
            "system_access_timeout_enabled".into(),
            json!(self.system_access_timeout_enabled),
        );
        m.insert(
            "system_access_timeout_minutes".into(),
            json!(self.system_access_timeout_minutes),
        );
        for (k, v) in &self.glass {
            m.insert(k.clone(), json!(v));
        }
        m
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Bookmark {
    pub label: String,
    pub path: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub folder: String,
}

pub fn load_uci(path: &str) -> Uci {
    Uci::load(path).unwrap_or_else(|| {
        let mut uci = Uci::default();
        uci.ensure_section(CONFIG_NAME, CONFIG_SECTION);
        uci
    })
}

pub fn save_root_policy(
    path: &str,
    policy: crate::state::RootPolicy,
    roots: &[String],
    excluded_roots: &[String],
) -> Result<(), String> {
    let mut uci = if std::path::Path::new(path).exists() {
        Uci::load(path).ok_or_else(|| format!("cannot read {path}"))?
    } else {
        Uci::default()
    };
    if matches!(policy, crate::state::RootPolicy::Allowlist) && roots.is_empty() {
        return Err("root_policy 'allowlist' requires at least one root entry".into());
    }
    if matches!(policy, crate::state::RootPolicy::Denylist) && excluded_roots.is_empty() {
        return Err("root_policy 'denylist' requires at least one exclude_root entry".into());
    }
    {
        let section = uci.ensure_section(CONFIG_NAME, CONFIG_SECTION);
        section.set("root_policy", policy.as_str());
        if roots.is_empty() {
            section.remove("root");
        } else {
            section.set_list("root", roots);
        }
        if excluded_roots.is_empty() {
            section.remove("exclude_root");
        } else {
            section.set_list("exclude_root", excluded_roots);
        }
    }
    uci.save(path)
        .map_err(|error| format!("cannot write {path}: {error}"))?;
    let saved = Uci::load(path).ok_or_else(|| format!("cannot read back {path}"))?;
    let section = saved.section(CONFIG_SECTION);
    let actual_roots = section.map(|s| s.get_all("root")).unwrap_or_default();
    let actual_excluded = section
        .map(|s| s.get_all("exclude_root"))
        .unwrap_or_default();
    let actual_policy = section.and_then(|section| section.get("root_policy"));
    if actual_policy != Some(policy.as_str())
        || actual_roots.as_slice() != roots
        || actual_excluded.as_slice() != excluded_roots
    {
        return Err(format!("Path policy did not persist to {path}"));
    }
    Ok(())
}

/// Persist key/value pairs into the `main` section and verify the write.
pub fn save_values(path: &str, values: &[(String, String)]) -> Result<(), String> {
    let mut uci = load_uci(path);
    {
        let sec = uci.ensure_section(CONFIG_NAME, CONFIG_SECTION);
        sec.remove("allow_system_operations");
        for (k, v) in values {
            sec.set(k, v);
        }
    }
    uci.save(path)
        .map_err(|e| format!("cannot write {path}: {e}"))?;
    let verify = load_uci(path);
    let sec = verify.section(CONFIG_SECTION);
    let mut missing = Vec::new();
    for (k, v) in values {
        let got = sec.and_then(|s| s.get(k)).unwrap_or("");
        if got != v {
            missing.push(k.clone());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("{} did not persist to {path}", missing.join(", ")))
    }
}

pub fn configured_language(path: &str) -> Option<String> {
    let uci = load_uci(path);
    let sec = uci.section(CONFIG_SECTION)?;
    let raw = sec.get("language")?.trim().to_string();
    if raw.is_empty() {
        return None;
    }
    crate::i18n::Lang::supported(&raw).map(|lang| lang.code().to_string())
}

pub fn remove_option(path: &str, key: &str) -> Result<(), String> {
    let mut uci = load_uci(path);
    let present = uci
        .section(CONFIG_SECTION)
        .is_some_and(|sec| sec.get(key).is_some());
    if !present {
        return Ok(());
    }
    if let Some(sec) = uci.section_mut(CONFIG_SECTION) {
        sec.remove(key);
    }
    uci.save(path)
        .map_err(|e| format!("cannot write {path}: {e}"))?;
    let verify = load_uci(path);
    let sec = verify.section(CONFIG_SECTION);
    match sec.and_then(|s| s.get(key)) {
        None => Ok(()),
        Some(_) => Err(format!("{key} did not clear from {path}")),
    }
}

pub fn save_option(path: &str, key: &str, value: &str) -> Result<(), String> {
    let mut uci = load_uci(path);
    {
        let sec = uci.ensure_section(CONFIG_NAME, CONFIG_SECTION);
        sec.set(key, value);
    }
    uci.save(path)
        .map_err(|e| format!("cannot write {path}: {e}"))?;
    let verify = load_uci(path);
    let sec = verify.section(CONFIG_SECTION);
    match sec.and_then(|s| s.get(key)) {
        Some(got) if got == value => Ok(()),
        _ => Err(format!("{key} did not persist to {path}")),
    }
}

#[cfg(test)]
mod remove_option_tests {
    use super::*;

    #[test]
    fn remove_option_clears_language_and_keeps_other_keys() {
        let path = std::env::temp_dir().join(format!(
            "harbor-remove-option-{}.conf",
            crate::uci::random_hex(8)
        ));
        let path = path.to_string_lossy().into_owned();

        save_option(&path, "language", "zh_Hans").unwrap();
        save_option(&path, "dev_mode", "1").unwrap();
        assert_eq!(configured_language(&path).as_deref(), Some("zh_Hans"));

        remove_option(&path, "language").unwrap();
        assert_eq!(configured_language(&path), None);
        let uci = load_uci(&path);
        let section = uci.section(CONFIG_SECTION).unwrap();
        assert_eq!(section.get("dev_mode"), Some("1"));
        assert!(section.get("language").is_none());

        remove_option(&path, "language").unwrap();
        assert_eq!(configured_language(&path), None);
        let _ = std::fs::remove_file(&path);
    }
}

pub fn read_bookmarks(uci: &Uci) -> Vec<Bookmark> {
    let mut out = Vec::new();
    for sec in uci.of_kind("bookmark") {
        let path = match normalize_path(sec.get("path").unwrap_or("")) {
            Some(p) => p,
            None => continue,
        };
        let label = sec
            .get("label")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        out.push(Bookmark {
            label: label.unwrap_or_else(|| path.clone()),
            path: path.clone(),
            device_id: sec.get("device_id").unwrap_or("").to_string(),
            folder: sec.get("folder").unwrap_or("").trim().to_string(),
        });
    }
    out
}

pub fn write_bookmarks(path: &str, list: &[Bookmark]) -> Result<(), String> {
    let mut uci = load_uci(path);
    uci.remove_kind("bookmark");
    for b in list {
        let sec = uci.add_section("bookmark");
        sec.set("label", &b.label);
        sec.set("path", &b.path);
        if !b.device_id.is_empty() {
            sec.set("device_id", &b.device_id);
        }
        if !b.folder.is_empty() {
            sec.set("folder", &b.folder);
        }
    }
    uci.save(path).map_err(|e| e.to_string())
}

pub fn read_bookmark_folders(uci: &Uci) -> Vec<String> {
    uci.of_kind("bookmark_folder")
        .iter()
        .filter_map(|s| {
            let n = s.get("name").unwrap_or("").trim().to_string();
            if n.is_empty() {
                None
            } else {
                Some(n)
            }
        })
        .collect()
}

/// Order-preserving duplicate removal (renaming a folder onto an existing one
/// must not create two entries).
pub fn dedupe_list(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if !item.is_empty() && !out.iter().any(|v| v == item) {
            out.push(item.clone());
        }
    }
    out
}

pub fn write_bookmark_folders(path: &str, folders: &[String]) -> Result<(), String> {
    let mut uci = load_uci(path);
    uci.remove_kind("bookmark_folder");
    for name in dedupe_list(folders).iter() {
        let sec = uci.add_section("bookmark_folder");
        sec.set("name", name);
    }
    uci.save(path).map_err(|e| e.to_string())
}

pub fn read_fav_expanded(uci: &Uci) -> Vec<String> {
    uci.section(CONFIG_SECTION)
        .map(|s| s.get_all("fav_expanded"))
        .unwrap_or_default()
        .into_iter()
        .filter(|v| !v.is_empty())
        .collect()
}

pub fn write_fav_expanded(path: &str, list: &[String]) -> Result<(), String> {
    let mut uci = load_uci(path);
    {
        let sec = uci.ensure_section(CONFIG_NAME, CONFIG_SECTION);
        sec.set_list("fav_expanded", &dedupe_list(list));
    }
    uci.save(path).map_err(|e| e.to_string())
}

pub fn bookmark_payload(uci: &Uci, list: &[Bookmark]) -> Value {
    let items: Vec<Value> = list
        .iter()
        .map(|b| {
            let (exists, device_name) = if b.device_id.is_empty() {
                let st = meta::stat(&b.path);
                (
                    st.map(|m| m.kind == meta::Kind::Directory).unwrap_or(false),
                    String::new(),
                )
            } else {
                let sec = uci.section(&b.device_id);
                let is_device = sec.map(|s| s.kind == "remote_device").unwrap_or(false);
                let name = sec.and_then(|s| s.get("name")).unwrap_or("").to_string();
                (is_device, name)
            };
            json!({
                "label": b.label,
                "path": b.path,
                "device_id": b.device_id,
                "device_name": device_name,
                "folder": b.folder,
                "exists": exists
            })
        })
        .collect();
    Value::Array(items)
}

pub fn clean_label(raw: &str, max: usize) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| (*c as u32) >= 32 && (*c as u32) != 127)
        .collect();
    if cleaned.chars().count() > max {
        cleaned.chars().take(max).collect()
    } else {
        cleaned
    }
}

pub fn default_label_for(path: &str) -> String {
    let name = path_name(path);
    if name.is_empty() {
        path.to_string()
    } else {
        name
    }
}

#[derive(Debug, Clone)]
pub struct QuickItem {
    pub label: String,
    pub path: String,
    pub icon: String,
}

pub fn default_quick_items(home: &str) -> Vec<QuickItem> {
    meta::mkdir_p(home);
    [
        ("Documents", "documents", "documents"),
        ("Pictures", "pictures", "pictures"),
        ("Videos", "videos", "videos"),
        ("Music", "music", "music"),
        ("Downloads", "downloads", "downloads"),
    ]
    .into_iter()
    .map(|(name, dir, icon)| QuickItem {
        label: name.to_string(),
        path: join_path(home, dir),
        icon: icon.to_string(),
    })
    .collect()
}

pub fn read_quick_items(uci: &Uci) -> Option<Vec<QuickItem>> {
    let raw = uci.section(CONFIG_SECTION)?.get("quick_items")?;
    let parsed: Value = serde_json::from_str(raw).ok()?;
    let array = parsed.as_array()?;
    Some(
        array
            .iter()
            .filter_map(|item| {
                let label = item.get("label")?.as_str()?.trim().to_string();
                let path = normalize_path(item.get("path")?.as_str()?)?;
                if label.is_empty() {
                    return None;
                }
                let icon = item
                    .get("icon")
                    .and_then(Value::as_str)
                    .filter(|icon| !icon.is_empty())
                    .unwrap_or("folder")
                    .to_string();
                Some(QuickItem { label, path, icon })
            })
            .collect(),
    )
}

pub fn write_quick_items(path: &str, items: &[QuickItem]) -> Result<(), String> {
    let array = Value::Array(
        items
            .iter()
            .map(|item| json!({ "label": item.label, "path": item.path, "icon": item.icon }))
            .collect(),
    );
    let raw = serde_json::to_string(&array).map_err(|e| e.to_string())?;
    save_values(path, &[("quick_items".to_string(), raw)])
}

pub fn quick_access_payload(items: &[QuickItem]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| {
                let st = meta::stat(&item.path);
                json!({
                    "name": item.label,
                    "path": item.path,
                    "icon": item.icon,
                    "exists": st.map(|m| m.kind == meta::Kind::Directory).unwrap_or(false),
                    "mtime": st.map(|m| m.mtime).unwrap_or(0),
                    "mode": st.map(|m| meta::numeric_permissions(m.mode)).unwrap_or_else(|| "---".to_string())
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod root_policy_persistence_tests {
    use super::save_root_policy;
    use crate::state::{RootPolicy, RootPolicyConfig};
    use crate::uci::Uci;
    use std::fs;

    #[test]
    fn policy_switches_keep_both_ucilist_values_and_explicit_mode() {
        let path = std::env::temp_dir().join(format!(
            "harbor-root-policy-{}.conf",
            crate::uci::random_hex(8)
        ));
        let path = path.to_string_lossy().into_owned();
        let roots = vec!["/mnt/data".to_string()];
        let excluded = vec!["/etc".to_string()];

        save_root_policy(&path, RootPolicy::Unrestricted, &roots, &excluded).unwrap();
        let loaded = Uci::load(&path).unwrap();
        let section = loaded.section(super::CONFIG_SECTION).unwrap();
        assert_eq!(section.get("root_policy"), Some("unrestricted"));
        assert_eq!(section.get_all("root"), roots);
        assert_eq!(section.get_all("exclude_root"), excluded);

        save_root_policy(&path, RootPolicy::Allowlist, &roots, &excluded).unwrap();
        let loaded = Uci::load(&path).unwrap();
        let section = loaded.section(super::CONFIG_SECTION).unwrap();
        assert_eq!(
            RootPolicyConfig::from_uci(
                section.get("root_policy"),
                section.get_all("root"),
                section.get_all("exclude_root")
            )
            .unwrap()
            .policy,
            RootPolicy::Allowlist
        );
        fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod quick_item_persistence_tests {
    use super::*;

    #[test]
    fn quick_items_roundtrip_and_delete_all_keeps_marker() {
        let path =
            std::env::temp_dir().join(format!("harbor-quick-{}.conf", crate::uci::random_hex(8)));
        let path = path.to_str().unwrap();
        let items = vec![
            QuickItem {
                label: "Docs".into(),
                path: "/data/docs".into(),
                icon: "documents".into(),
            },
            QuickItem {
                label: "USB".into(),
                path: "/mnt/usb".into(),
                icon: "folder".into(),
            },
        ];
        write_quick_items(path, &items).unwrap();
        let read = read_quick_items(&load_uci(path)).expect("seeded");
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].label, "Docs");
        assert_eq!(read[0].path, "/data/docs");
        assert_eq!(read[1].icon, "folder");
        write_quick_items(path, &[]).unwrap();
        let read = read_quick_items(&load_uci(path)).expect("marker survives delete-all");
        assert!(read.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unseeded_config_reports_none_and_defaults_are_five() {
        let path = std::env::temp_dir().join(format!(
            "harbor-quick-none-{}.conf",
            crate::uci::random_hex(8)
        ));
        let path = path.to_str().unwrap();
        assert!(read_quick_items(&load_uci(path)).is_none());
        let defaults = default_quick_items("/tmp/root");
        assert_eq!(defaults.len(), 5);
        assert_eq!(defaults[0].label, "Documents");
        assert_eq!(defaults[4].path, "/tmp/root/downloads");
        let _ = std::fs::remove_file(path);
    }
}
