use crate::config::Prefs;
use crate::state::AppState;
use serde_json::{json, Value};
use std::path::PathBuf;

pub const BUILTIN_ID: &str = "builtin:img2";

const BUILTIN_KEYS: &[&str] = &["login", "aurora", "img1", "img2", "ocean", "sunset"];

pub const SOURCES: &[(&str, &str)] = &[
    ("builtin", "Built-in wallpaper"),
    ("uapipro", "UApiPro"),
    ("bing", "Bing Daily"),
    ("openverse", "Openverse"),
    ("custom", "Custom wallpaper"),
];

pub const UAPI_CATEGORIES: &[(&str, &str)] = &[
    ("all", "All"),
    ("acg", "ACG"),
    ("landscape", "Landscape"),
    ("anime", "Anime"),
    ("pc_wallpaper", "PC Wallpaper"),
    ("general_anime", "Anime Art"),
    ("bq", "Memes"),
    ("furry", "Furry"),
];

pub fn builtin_items() -> Vec<Value> {
    BUILTIN_KEYS
        .iter()
        .map(|key| builtin_item_for_key(key))
        .collect()
}

pub fn builtin_item() -> Value {
    builtin_item_for_key("img2")
}

pub fn builtin_item_for_id(id: &str) -> Option<Value> {
    let key = id.strip_prefix("builtin:")?;
    BUILTIN_KEYS
        .contains(&key)
        .then(|| builtin_item_for_key(key))
}

fn builtin_item_for_key(key: &str) -> Value {
    let url = format!("/wallpapers/{key}");
    json!({
        "id": format!("builtin:{key}"),
        "url": url,
        "full": url,
        "thumb": url,
        "title": match key {
            "login" => "Midnight Blue",
            "aurora" => "Northern Lights",
            "img1" => "Neon Horizon",
            "img2" => "Azure Ribbons",
            "ocean" => "Deep Blue Coast",
            "sunset" => "Last Light",
            _ => "Built-in wallpaper"
        },
        "source": "builtin",
        "type": "all"
    })
}

pub fn is_builtin_id(id: &str) -> bool {
    builtin_item_for_id(id).is_some()
}

pub const CUSTOM_LIMIT: usize = 8;
pub const CUSTOM_MAX_BYTES: u64 = 5 * 1024 * 1024;
pub const CUSTOM_EXTS: &[&str] = &["png", "jpg", "jpeg", "gif", "bmp", "webp"];

const CUSTOM_DIR: &str = "wallpaper";

pub fn custom_dir(_st: &AppState) -> PathBuf {
    PathBuf::from("www/harbor-core").join(CUSTOM_DIR)
}

pub fn ensure_custom_dir(st: &AppState) -> Option<PathBuf> {
    let dir = custom_dir(st);
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

pub fn valid_custom_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 96
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return false;
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.is_empty()
                && !stem.ends_with('.')
                && CUSTOM_EXTS.contains(&ext.to_ascii_lowercase().as_str())
        }
        None => false,
    }
}

pub fn custom_id(name: &str) -> String {
    format!("custom:{name}")
}

pub fn parse_custom_id(id: &str) -> Option<&str> {
    let name = id.strip_prefix("custom:")?;
    valid_custom_name(name).then_some(name)
}

pub fn custom_item(name: &str) -> Value {
    let url = format!("/wallpapers/custom/{name}");
    json!({
        "id": custom_id(name),
        "url": url,
        "full": url,
        "thumb": url,
        "title": name,
        "source": "custom",
        "type": "all"
    })
}

pub fn custom_item_for_id(st: &AppState, id: &str) -> Option<Value> {
    let name = parse_custom_id(id)?;
    let meta = std::fs::symlink_metadata(custom_dir(st).join(name)).ok()?;
    meta.is_file().then(|| custom_item(name))
}

pub fn custom_items(st: &AppState) -> Vec<Value> {
    let Ok(entries) = std::fs::read_dir(custom_dir(st)) else {
        return Vec::new();
    };
    let mut entries: Vec<(u64, String)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !valid_custom_name(&name) {
                return None;
            }
            let meta = std::fs::symlink_metadata(entry.path()).ok()?;
            if !meta.is_file() {
                return None;
            }
            let mtime = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0);
            Some((mtime, name))
        })
        .collect();
    entries.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    entries
        .into_iter()
        .take(CUSTOM_LIMIT)
        .map(|(_, name)| custom_item(&name))
        .collect()
}

pub fn svg(key: &str) -> Option<&'static str> {
    crate::web::WALLPAPER_ASSETS
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, markup)| *markup)
}

pub const TYPES: &[(&str, &str, &str)] = &[
    ("all", "All", "wallpaper"),
    ("landscape", "Landscape", "landscape"),
    ("nature", "Nature", "nature"),
    ("people", "People / Beauty", "people+portrait+beauty"),
    ("city", "City", "cityscape"),
    ("animals", "Animals", "wildlife"),
    ("flowers", "Flowers", "flowers"),
    ("abstract", "Abstract", "abstract"),
];

pub fn source_label(id: &str) -> &'static str {
    SOURCES
        .iter()
        .find(|(key, _)| *key == id)
        .map(|(_, label)| *label)
        .unwrap_or("Wallpaper")
}

pub fn valid_source(id: &str) -> bool {
    SOURCES.iter().any(|(key, _)| *key == id)
}

pub fn valid_type(id: &str) -> bool {
    TYPES.iter().any(|(key, _, _)| *key == id) || UAPI_CATEGORIES.iter().any(|(key, _)| *key == id)
}

pub fn type_query(id: &str) -> &'static str {
    TYPES
        .iter()
        .find(|(key, _, _)| *key == id)
        .map(|(_, _, query)| *query)
        .unwrap_or("wallpaper")
}

pub fn is_provider_url(raw: &str) -> bool {
    if raw.len() > 2048 || raw.chars().any(char::is_control) || raw.contains('\\') {
        return false;
    }
    let Some(rest) = raw.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = authority.to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    !(host.is_empty()
        || host.contains(':')
        || !host.contains('.')
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

pub fn page_shell(
    source: &str,
    image_type: &str,
    page: usize,
    count: usize,
    items: Vec<Value>,
    has_more: bool,
) -> Value {
    let page = page.clamp(1, 10_000);
    let count = count.clamp(1, 24);
    let types: Vec<Value> = if source == "openverse" {
        TYPES
            .iter()
            .map(|(id, label, _)| json!({"id": id, "label": label}))
            .collect()
    } else if source == "uapipro" {
        UAPI_CATEGORIES
            .iter()
            .map(|(id, label)| json!({"id": id, "label": label}))
            .collect()
    } else {
        vec![json!({"id": "all", "label": "All"})]
    };
    let sources: Vec<Value> = SOURCES
        .iter()
        .map(|(key, label)| json!({"id": key, "label": label}))
        .collect();
    json!({
        "source": source,
        "type": image_type,
        "page": page,
        "count": count,
        "pages": if has_more { page + 1 } else { page },
        "total": if has_more { page * count + 1 } else { (page - 1) * count + items.len() },
        "has_more": has_more,
        "next_page": if has_more { page + 1 } else { 1 },
        "sources": sources,
        "types": types,
        "items": items,
    })
}

pub fn current(st: &AppState, prefs: &Prefs) -> Value {
    let enabled = prefs.wallpaper_enabled != 0;
    if let Some(mut current) = builtin_item_for_id(&prefs.wallpaper_id) {
        if let Value::Object(values) = &mut current {
            values.insert("enabled".into(), json!(enabled));
            values.insert("mode".into(), json!(prefs.wallpaper_mode));
        }
        return current;
    }
    if prefs.wallpaper_source == "custom" {
        if let Some(mut current) = custom_item_for_id(st, &prefs.wallpaper_id) {
            if let Value::Object(values) = &mut current {
                values.insert("enabled".into(), json!(enabled));
                values.insert("mode".into(), json!(prefs.wallpaper_mode));
            }
            return current;
        }
    }
    if is_provider_url(&prefs.wallpaper_id) {
        return json!({
            "enabled": enabled,
            "mode": prefs.wallpaper_mode,
            "id": prefs.wallpaper_id,
            "title": source_label(&prefs.wallpaper_source),
            "url": prefs.wallpaper_id,
            "thumb": prefs.wallpaper_id,
            "source": prefs.wallpaper_source,
            "type": prefs.wallpaper_type,
        });
    }
    json!({
        "enabled": false,
        "mode": prefs.wallpaper_mode,
        "id": "",
        "url": "",
        "thumb": "",
        "source": prefs.wallpaper_source,
        "type": prefs.wallpaper_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_available_sources_are_listed() {
        assert!(valid_source("builtin"));
        assert!(valid_source("uapipro"));
        assert!(valid_source("bing"));
        assert!(valid_source("openverse"));
        assert!(!valid_source("iciba"));
        assert!(!valid_source("nature"));
    }

    #[test]
    fn built_in_wallpaper_is_the_enabled_default() {
        let prefs = Prefs::default();
        let item = builtin_item();
        assert_eq!(prefs.wallpaper_enabled, 1);
        assert_eq!(prefs.wallpaper_source, "builtin");
        assert_eq!(prefs.wallpaper_id, BUILTIN_ID);
        assert_eq!(
            crate::config::sanitize_wallpaper_id(BUILTIN_ID).as_deref(),
            Some(BUILTIN_ID)
        );
        assert_eq!(item["url"].as_str(), Some("/wallpapers/img2"));
        assert_eq!(item["source"].as_str(), Some("builtin"));
        let catalog = builtin_items();
        assert_eq!(catalog.len(), 6);
        assert!(catalog.iter().any(|entry| entry["id"] == "builtin:login"));
        assert!(catalog.iter().any(|entry| entry["id"] == "builtin:img1"));
        assert!(catalog.iter().any(|entry| entry["id"] == BUILTIN_ID));
        assert!(svg("login").unwrap().contains("#2b6cb0"));
        assert!(svg("alpine").is_none());
        assert!(svg("prism").is_none());
        assert!(builtin_item_for_id("builtin:alpine").is_none());
        assert!(builtin_item_for_id("builtin:prism").is_none());
        assert_eq!(
            builtin_item_for_id("builtin:img1").unwrap()["url"],
            "/wallpapers/img1"
        );
    }

    #[test]
    fn custom_wallpaper_ids_names_and_limits() {
        assert!(valid_source("custom"));
        assert_eq!(CUSTOM_LIMIT, 8);
        assert_eq!(CUSTOM_MAX_BYTES, 5 * 1024 * 1024);
        assert!(valid_custom_name("photo.jpg"));
        assert!(valid_custom_name("Photo_01.PNG"));
        assert!(valid_custom_name("a-b_c.1.jpeg"));
        assert!(!valid_custom_name(".hidden.jpg"));
        assert!(!valid_custom_name("../evil.jpg"));
        assert!(!valid_custom_name("dir/evil.jpg"));
        assert!(!valid_custom_name("dir\\evil.jpg"));
        assert!(!valid_custom_name("evil.svg"));
        assert!(!valid_custom_name("noext"));
        assert!(!valid_custom_name("trailing."));
        assert!(!valid_custom_name(""));
        assert_eq!(parse_custom_id("custom:a.png"), Some("a.png"));
        assert!(parse_custom_id("builtin:img2").is_none());
        assert!(parse_custom_id("custom:../a.png").is_none());
        assert!(parse_custom_id("custom:evil.svg").is_none());
        assert_eq!(custom_id("a.png"), "custom:a.png");
        assert_eq!(custom_item("a.png")["url"], "/wallpapers/custom/a.png");
        assert_eq!(custom_item("a.png")["source"], "custom");
    }

    #[test]
    fn topic_filters_are_known() {
        assert!(valid_type("all"));
        assert!(valid_type("landscape"));
        assert!(valid_type("people"));
        assert!(!valid_type("unknown"));
    }

    #[test]
    fn external_urls_are_https_and_local_hosts_are_rejected() {
        assert!(is_provider_url(
            "https://picsum.photos/seed/example/1920/1080"
        ));
        assert!(is_provider_url("https://www.bing.com/th?id=OHR.test"));
        assert!(is_provider_url(
            "https://live.staticflickr.com/8425/example.jpg"
        ));
        assert!(is_provider_url(
            "https://api.openverse.org/v1/images/example/thumb/"
        ));
        assert!(is_provider_url(
            "https://www.flickr.com/photos/47340307@N05/5802706920"
        ));
        assert!(!is_provider_url("https://user@picsum.photos/image.jpg"));
        assert!(!is_provider_url("http://picsum.photos/1"));
        assert!(is_provider_url(
            "https://picsum.photos.attacker.test/image.jpg"
        ));
        assert!(!is_provider_url("https://localhost/image.jpg"));
        assert!(!is_provider_url("https://localhost./image.jpg"));
        assert!(!is_provider_url("https://192.168.1.1/image.jpg"));
        assert!(!is_provider_url("https://127.0.0.1/image.jpg"));
    }
}
