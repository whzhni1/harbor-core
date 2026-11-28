//! Server-side message localisation.
//!
//! The catalogs are compiled from the very gettext files the LuCI plugin ships,
//! so a translated string lives in exactly one place and the Rust backend never
//! hardcodes a user-visible language. English is the msgid, hence the default:
//! anything without a translation is returned verbatim.
//!
//! Request language resolution order: `?lang=` query/form parameter, the
//! `harbor_lang` cookie set by the web UI, then `Accept-Language`.

use std::future::Future;

include!(concat!(env!("OUT_DIR"), "/i18n_gen.rs"));

pub const DEFAULT_CODE: &str = "en";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lang(&'static str);

impl Default for Lang {
    fn default() -> Self {
        Lang(DEFAULT_CODE)
    }
}

impl Lang {
    pub fn code(self) -> &'static str {
        self.0
    }

    pub fn is_default(self) -> bool {
        self.0 == DEFAULT_CODE
    }

    pub fn parse(raw: &str) -> Lang {
        let tag = raw.trim().replace('-', "_");
        if tag.is_empty() {
            return Lang::default();
        }
        let lowered = tag.to_ascii_lowercase();
        if let Some((code, _)) = LANGS.iter().find(|(c, _)| c.eq_ignore_ascii_case(&lowered)) {
            return Lang(code);
        }
        let base = lowered.split('_').next().unwrap_or("");
        if base == DEFAULT_CODE {
            return Lang::default();
        }

        if let Some((code, _)) = LANGS
            .iter()
            .find(|(c, _)| c.to_ascii_lowercase().starts_with(&format!("{base}_")))
            .or_else(|| LANGS.iter().find(|(c, _)| c.eq_ignore_ascii_case(base)))
        {
            return Lang(code);
        }
        Lang::default()
    }

    pub fn supported(raw: &str) -> Option<Lang> {
        let tag = raw.trim().replace('-', "_");
        if tag.is_empty() {
            return None;
        }
        let lowered = tag.to_ascii_lowercase();
        if let Some((code, _)) = LANGS.iter().find(|(c, _)| c.eq_ignore_ascii_case(&lowered)) {
            return Some(Lang(code));
        }
        let base = lowered.split('_').next().unwrap_or("");
        if base == DEFAULT_CODE {
            return Some(Lang::default());
        }
        if LANGS
            .iter()
            .any(|(c, _)| c.to_ascii_lowercase().starts_with(&format!("{base}_")))
            || LANGS.iter().any(|(c, _)| c.eq_ignore_ascii_case(base))
        {
            return Some(Lang::parse(raw));
        }
        None
    }

    pub fn negotiate(header: &str) -> Lang {
        let mut best: Option<(f32, Lang)> = None;
        for part in header.split(',') {
            let mut pieces = part.split(';');
            let tag = pieces.next().unwrap_or("").trim();
            if tag.is_empty() || tag == "*" {
                continue;
            }
            let quality = pieces
                .find_map(|p| p.trim().strip_prefix("q="))
                .and_then(|q| q.trim().parse::<f32>().ok())
                .unwrap_or(1.0);
            let lang = match Lang::supported(tag) {
                Some(lang) => lang,
                None => continue,
            };
            if best.map(|(q, _)| quality > q).unwrap_or(true) {
                best = Some((quality, lang));
            }
        }
        best.map(|(_, l)| l).unwrap_or_default()
    }

    pub fn catalog(self) -> &'static [(&'static str, &'static str)] {
        CATALOG
            .iter()
            .find(|(code, _)| *code == self.0)
            .map(|(_, entries)| *entries)
            .unwrap_or(&[])
    }
}

pub fn available() -> impl Iterator<Item = (&'static str, &'static str)> {
    LANGS.iter().copied()
}

tokio::task_local! {
    static CURRENT: Lang;
}

pub fn current() -> Lang {
    CURRENT.try_with(|l| *l).unwrap_or_default()
}

pub async fn scope<F: Future>(lang: Lang, future: F) -> F::Output {
    CURRENT.scope(lang, future).await
}

pub fn lang_for(headers: &axum::http::HeaderMap, params: &crate::params::Params) -> Lang {
    if let Some(raw) = params.first_of(&["lang", "locale"]) {
        return Lang::parse(&raw);
    }
    if let Some(raw) = cookie(headers, "harbor_lang") {
        return Lang::parse(&raw);
    }
    if let Some(raw) = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
    {
        return Lang::negotiate(raw);
    }
    Lang::default()
}

fn cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

pub fn translate(message: &str) -> String {
    translate_in(current(), message)
}

pub fn translate_in(lang: Lang, message: &str) -> String {
    if lang.is_default() || message.is_empty() {
        return message.to_string();
    }
    let catalog = lang.catalog();
    if let Ok(index) = catalog.binary_search_by(|(id, _)| (*id).cmp(message)) {
        return catalog[index].1.to_string();
    }

    let templates: &[(&str, &str)] = TEMPLATES
        .iter()
        .find(|(code, _)| *code == lang.0)
        .map(|(_, list)| *list)
        .unwrap_or(&[]);
    if let Some(translation) = templates
        .iter()
        .find_map(|(id, tr)| fill_template(id, tr, message))
    {
        return translation;
    }
    message.to_string()
}

fn fill_template(template: &str, translation: &str, message: &str) -> Option<String> {
    let segments: Vec<&str> = template.split("%s").collect();
    if segments.len() < 2 {
        return None;
    }
    let mut rest = message;
    let mut captured: Vec<&str> = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        if index == 0 {
            rest = rest.strip_prefix(segment)?;
            continue;
        }
        if index == segments.len() - 1 {
            if segment.is_empty() {
                captured.push(rest);
            } else {
                let cut = rest.strip_suffix(segment)?;
                captured.push(cut);
            }
            rest = "";
            continue;
        }
        let position = rest.find(segment)?;
        captured.push(&rest[..position]);
        rest = &rest[position + segment.len()..];
    }
    let mut rendered = String::with_capacity(translation.len() + message.len());
    let mut parts = translation.split("%s");
    if let Some(first) = parts.next() {
        rendered.push_str(first);
    }
    for (index, part) in parts.enumerate() {
        match captured.get(index) {
            Some(value) => rendered.push_str(value),
            None => rendered.push_str("%s"),
        }
        rendered.push_str(part);
    }
    Some(rendered)
}

pub fn catalog_json(lang: Lang) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (id, tr) in lang.catalog() {
        map.insert(
            (*id).to_string(),
            serde_json::Value::String((*tr).to_string()),
        );
    }
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_language_tags() {
        assert_eq!(Lang::parse("zh-CN").code(), "zh_Hans");
        assert_eq!(Lang::parse("zh").code(), "zh_Hans");
        assert_eq!(Lang::parse("en-GB").code(), "en");
        assert_eq!(Lang::parse("").code(), "en");
    }

    #[test]
    fn negotiates_q_values() {
        assert_eq!(Lang::negotiate("en;q=0.8, zh-CN;q=0.9").code(), "zh_Hans");
        assert_eq!(Lang::negotiate("en-US,en;q=0.9").code(), "en");
        assert_eq!(Lang::negotiate("en;q=0.9, zh-CN;q=0.8").code(), "en");
        assert_eq!(Lang::negotiate("fr, de").code(), "en");
        assert_eq!(Lang::negotiate("zh-CN,zh;q=0.9,en;q=0.8").code(), "zh_Hans");
        assert_eq!(Lang::negotiate("zh-Hant-TW").code(), "zh_Hans");
    }

    #[test]
    fn translates_exact_and_templated_messages() {
        let zh = Lang::parse("zh_Hans");
        assert_eq!(
            translate_in(Lang::default(), "Invalid path"),
            "Invalid path"
        );
        assert_eq!(translate_in(zh, "Invalid path"), "无效的路径");

        let rendered = translate_in(zh, "Save failed: EPERM");
        assert!(rendered.contains("EPERM"), "{rendered}");
        assert!(!rendered.starts_with("Save failed"), "{rendered}");
    }

    #[test]
    fn template_helper_handles_multiple_placeholders() {
        let out = fill_template(
            "%s is not available on this system",
            "%s 在此系统上不可用",
            "gm is not available on this system",
        );
        assert_eq!(out.as_deref(), Some("gm 在此系统上不可用"));
    }
}
