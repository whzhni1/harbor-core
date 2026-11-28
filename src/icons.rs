//! Icon registry.
//!
//! Every icon is addressed by a **key** from the driver table, never by a path:
//! the UI calls `HF.icon_url('folder')` / `HF.icon('folder')`, the backend knows
//! the key -> SVG table and also serves one sprite document so a key can be
//! rendered inline (`<use href="/assets/icons.svg#hf-folder">`) with the current
//! text colour.
//!
//! `web/icon-driver.json` is the single source of truth: it maps each key to raw
//! SVG markup, which `build.rs` embeds directly into the daemon. No per-icon SVG
//! files are generated or maintained.

#[path = "../build_support/icon_assets.rs"]
mod icon_assets;
use crate::web::{ICON_ASSETS, ICON_FALLBACK_KEY};
use std::sync::OnceLock;

pub const FALLBACK_KEY: &str = ICON_FALLBACK_KEY;

pub fn keys() -> impl Iterator<Item = &'static str> {
    ICON_ASSETS.iter().map(|(key, _)| *key)
}

#[cfg(test)]
pub fn has(key: &str) -> bool {
    ICON_ASSETS
        .binary_search_by(|(name, _)| (*name).cmp(normalize(key).as_str()))
        .is_ok()
}

#[cfg(test)]
pub fn raw_svg(key: &str) -> &'static str {
    let normalized = normalize(key);
    ICON_ASSETS
        .binary_search_by(|(name, _)| (*name).cmp(normalized.as_str()))
        .map(|index| ICON_ASSETS[index].1)
        .unwrap_or_else(|_| {
            let fallback = ICON_ASSETS
                .binary_search_by(|(name, _)| (*name).cmp(FALLBACK_KEY))
                .expect("fallback icon must be embedded");
            ICON_ASSETS[fallback].1
        })
}

#[cfg(test)]
pub fn normalize(raw: &str) -> String {
    let trimmed = raw.trim();
    let trimmed = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix(".svg").unwrap_or(trimmed);
    trimmed.to_ascii_lowercase()
}

pub fn sprite() -> Option<&'static str> {
    static SPRITE: OnceLock<Option<String>> = OnceLock::new();
    SPRITE
        .get_or_init(|| icon_assets::sprite(ICON_ASSETS))
        .as_deref()
}

pub(crate) fn render_template(text: &str) -> Option<String> {
    icon_assets::render_template(text, ICON_ASSETS)
}

#[cfg(test)]
fn to_symbol(key: &str, text: &str) -> Option<String> {
    icon_assets::to_symbol(key, text)
}

pub fn manifest() -> serde_json::Value {
    let items: Vec<serde_json::Value> = keys()
        .map(|key| {
            serde_json::json!({
                "key": key,
                "sprite": format!("/assets/icons.svg#hf-{key}"),
            })
        })
        .collect();
    serde_json::json!({
        "count": items.len(),
        "fallback": FALLBACK_KEY,
        "sprite": "assets/icons.svg",
        "icons": items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_keys() {
        assert_eq!(normalize("folder"), "folder");
        assert_eq!(normalize("folder.svg"), "folder");
        assert_eq!(normalize("assets/icons/folder.svg"), "folder");
        assert_eq!(normalize(" Folder "), "folder");
    }

    #[test]
    fn resolves_known_and_unknown_keys() {
        assert!(has("folder"));
        assert!(!has("definitely-not-an-icon"));
        assert!(raw_svg("folder").contains("<svg"));
        assert_eq!(raw_svg("definitely-not-an-icon"), raw_svg("file"));
    }

    #[test]
    fn sprite_contains_every_key() {
        let sprite = sprite().expect("icons are bundled");
        for key in keys() {
            assert!(
                sprite.contains(&format!("id=\"hf-{key}\"")),
                "{key} missing"
            );
        }
        assert!(sprite.starts_with("<svg"));
        assert!(!sprite.contains("<svg xmlns") || sprite.matches("<svg").count() == 1);
    }

    #[test]
    fn embedded_frontend_icons_are_generated_from_the_driver() {
        let html = crate::web::ASSETS
            .iter()
            .find(|(name, _, _)| *name == "index.html")
            .unwrap()
            .1;
        let html = std::str::from_utf8(html).unwrap();
        let js = crate::web::ASSETS
            .iter()
            .find(|(name, _, _)| *name == "icons-data.js")
            .unwrap()
            .1;
        let js = std::str::from_utf8(js).unwrap();
        assert!(!html.contains("__HARBOR_ICON_"));
        for (key, svg) in ICON_ASSETS {
            assert!(
                html.contains(&format!("id=\"hf-{key}\"")),
                "missing sprite {key}"
            );
            assert!(js.contains(&format!("\"{key}\"")), "missing manifest {key}");
            assert!(
                js.contains(&icon_assets::data_uri(svg)),
                "stale manifest {key}"
            );
        }
        let svg = r#"<svg viewBox="0 0 24 24" fill="none"><path d="M1 1"/></svg>"#;
        assert!(to_symbol("test", svg).unwrap().contains("fill=\"none\""));
    }

    #[test]
    fn symbol_keeps_viewbox() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>"#;
        let symbol = to_symbol("demo", std::str::from_utf8(svg).unwrap()).unwrap();
        assert!(symbol.starts_with("<symbol id=\"hf-demo\" viewBox=\"0 0 24 24\">"));
        assert!(symbol.ends_with("</symbol>"));
    }
}
