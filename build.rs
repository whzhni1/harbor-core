use std::collections::BTreeMap;
use std::env;

#[path = "build_support/asset_version.rs"]
mod asset_version;
#[path = "build_support/icon_assets.rs"]
mod icon_assets;
use std::fs;
use std::path::{Path, PathBuf};

fn mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=UTF-8",
        "js" => "application/javascript; charset=UTF-8",
        "css" => "text/css; charset=UTF-8",
        "json" => "application/json; charset=UTF-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=UTF-8",
        "map" => "application/json",
        _ => "application/octet-stream",
    }
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (PathBuf, &'static str)>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, out);
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if rel.is_empty() {
            continue;
        }
        out.insert(rel.clone(), (path.clone(), mime_for(&rel)));
    }
}

fn unquote(raw: &str) -> String {
    let bytes: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == '\\' && i + 1 < bytes.len() {
            let n = bytes[i + 1];
            out.push(match n {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                other => other,
            });
            i += 2;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn parse_po(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut msgid: Option<String> = None;
    let mut msgstr: Option<String> = None;
    let mut mode = 0u8;

    let flush = |msgid: &mut Option<String>,
                 msgstr: &mut Option<String>,
                 out: &mut Vec<(String, String)>| {
        if let (Some(id), Some(tr)) = (msgid.take(), msgstr.take()) {
            let id = id.trim().to_string();
            if !id.is_empty() && !tr.trim().is_empty() {
                out.push((id, tr));
            }
        } else {
            msgid.take();
            msgstr.take();
        }
    };

    for raw in text.lines() {
        let line = raw.trim_start();
        if let Some(rest) = line.strip_prefix("msgid ") {
            flush(&mut msgid, &mut msgstr, &mut out);
            msgid = Some(unquote(rest.trim().trim_matches('"')));
            mode = 1;
        } else if let Some(rest) = line.strip_prefix("msgstr ") {
            msgstr = Some(unquote(rest.trim().trim_matches('"')));
            mode = 2;
        } else if line.starts_with('"') && line.len() >= 2 {
            let chunk = unquote(line.trim().trim_matches('"'));
            match mode {
                1 => {
                    if let Some(id) = msgid.as_mut() {
                        id.push_str(&chunk);
                    }
                }
                2 => {
                    if let Some(tr) = msgstr.as_mut() {
                        tr.push_str(&chunk);
                    }
                }
                _ => {}
            }
        } else if line.starts_with('#') {
            continue;
        } else if line.trim().is_empty() {
            flush(&mut msgid, &mut msgstr, &mut out);
            mode = 0;
        }
    }
    flush(&mut msgid, &mut msgstr, &mut out);
    out
}

fn language_name(code: &str) -> &'static str {
    match code {
        "zh_Hans" | "zh_CN" => "简体中文",
        "zh_Hant" | "zh_TW" | "zh_HK" => "繁體中文",
        "en" => "English",
        "ja" => "日本語",
        "ko" => "한국어",
        "de" => "Deutsch",
        "fr" => "Français",
        "es" => "Español",
        "pt" | "pt_BR" => "Português",
        "ru" => "Русский",
        _ => "",
    }
}

fn collect_languages(roots: &[PathBuf]) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut langs: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        println!("cargo:rerun-if-changed={}", root.display());
        let entries = match fs::read_dir(root) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let lang = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if lang.is_empty() {
                continue;
            }
            println!("cargo:rerun-if-changed={}", dir.display());
            let catalog = langs.entry(lang).or_default();
            let files = match fs::read_dir(&dir) {
                Ok(f) => f,
                Err(_) => continue,
            };
            for file in files.flatten() {
                let path = file.path();
                if path.extension().map(|e| e != "po").unwrap_or(true) {
                    continue;
                }
                println!("cargo:rerun-if-changed={}", path.display());
                if let Ok(text) = fs::read_to_string(&path) {
                    for (id, tr) in parse_po(&text) {
                        catalog.insert(id, tr);
                    }
                }
            }
        }
    }
    langs
}

fn rust_str(value: &str) -> String {
    format!("{:?}", value)
}

fn template_weight(msgid: &str) -> usize {
    msgid.replace("%s", "").chars().count()
}

fn main() {
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=HARBOR_BUILD_TARGET={target}");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let assets = manifest.join("assets");
    println!("cargo:rerun-if-changed=assets");
    println!("cargo:rerun-if-changed=build_support/asset_version.rs");

    println!("cargo:rerun-if-changed=build_support/icon_assets.rs");
    let icon_table_path = manifest.join("web/icon-driver.json");
    println!("cargo:rerun-if-changed={}", icon_table_path.display());
    let icon_table: serde_json::Value = serde_json::from_slice(
        &fs::read(&icon_table_path).expect("cannot read web/icon-driver.json"),
    )
    .expect("invalid web/icon-driver.json");
    let icon_object = icon_table
        .get("icons")
        .and_then(serde_json::Value::as_object)
        .expect("web/icon-driver.json must contain an icons object");
    let fallback = icon_table
        .get("fallback")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("file");
    if !icon_object.contains_key(fallback) {
        panic!("icon fallback {fallback:?} is missing from web/icon-driver.json");
    }
    let mut icons: Vec<(&String, &str)> = icon_object
        .iter()
        .map(|(key, value)| {
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
            {
                panic!("invalid icon key {key:?} in web/icon-driver.json");
            }
            let svg = value
                .as_str()
                .filter(|svg| svg.contains("<svg") && svg.contains("</svg>"))
                .unwrap_or_else(|| panic!("icon {key:?} must contain raw SVG markup"));
            (key, svg)
        })
        .collect();
    icons.sort_by(|a, b| a.0.cmp(b.0));

    let icon_refs: Vec<(&str, &str)> = icons
        .iter()
        .map(|(key, svg)| (key.as_str(), *svg))
        .collect();
    let mut uris = serde_json::Map::new();
    let mut viewboxes = serde_json::Map::new();
    for (key, svg) in &icon_refs {
        uris.insert(
            (*key).to_string(),
            serde_json::Value::String(icon_assets::data_uri(svg)),
        );
        let viewbox = icon_assets::viewbox(svg)
            .unwrap_or_else(|| panic!("invalid SVG viewBox for icon {key:?}"));
        viewboxes.insert((*key).to_string(), serde_json::Value::String(viewbox));
    }
    let manifest_js = format!(
        "/* Generated from web/icon-driver.json. */\nwindow.HARBOR_ICONS = {};\n",
        serde_json::json!({
            "fallback": fallback, "icons": uris, "viewbox": viewboxes, "sprite": "inline"
        })
    );

    let mut files: BTreeMap<String, (PathBuf, &'static str)> = BTreeMap::new();
    if assets.is_dir() {
        walk(&assets, &assets, &mut files);
    }
    let asset_version = asset_version::asset_version();
    let staged_root = PathBuf::from(env::var("OUT_DIR").unwrap()).join("static-assets");
    fs::create_dir_all(&staged_root).unwrap();
    let generated_manifest = staged_root.join("icons-data.js");
    fs::write(&generated_manifest, manifest_js).unwrap();
    files.insert(
        "icons-data.js".into(),
        (generated_manifest, mime_for("icons-data.js")),
    );
    for (rel, (source, _)) in files.iter_mut() {
        println!("cargo:rerun-if-changed={}", source.display());
        if !rel.ends_with(".html") && rel.as_str() != "app-config.js" {
            continue;
        }
        let text = match fs::read_to_string(&*source) {
            Ok(text)
                if text.contains("__HARBOR_ASSET_VERSION__")
                    || text.contains("__HARBOR_PKG_VERSION__")
                    || text.contains("__HARBOR_ICON_") =>
            {
                text
            }
            _ => continue,
        };
        let staged = staged_root.join(rel);
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let generated = asset_version::substitute(&text, &asset_version);
        let generated = if generated.contains("__HARBOR_ICON_") {
            icon_assets::render_template(&generated, &icon_refs)
                .unwrap_or_else(|| panic!("invalid or unknown icon placeholder in {rel}"))
        } else {
            generated
        };
        fs::write(&staged, generated).unwrap();
        *source = staged;
    }

    for (rel, (path, _)) in files.iter() {
        let bytes = fs::read(path)
            .unwrap_or_else(|error| panic!("cannot read asset {}: {error}", path.display()));
        if let Some(placeholder) = asset_version::find_placeholder(&bytes) {
            panic!(
                "asset {rel} still contains {placeholder}; add it to the replacement set in build_support/asset_version.rs"
            );
        }
    }

    let ui_rev = asset_version.clone();

    let mut code = String::new();
    code.push_str("// @generated by build.rs - do not edit\n");
    code.push_str(&format!("pub static UI_REV: &str = {:?};\n", ui_rev));
    code.push_str("pub static ASSETS: &[(&str, &[u8], &str)] = &[\n");
    for (rel, (path, mime)) in &files {
        code.push_str(&format!(
            "    ({:?}, include_bytes!({:?}), {:?}),\n",
            rel,
            path.to_string_lossy(),
            mime
        ));
    }
    code.push_str("];\n");
    code.push_str(&format!(
        "pub static ASSET_COUNT: usize = {};\n",
        files.len()
    ));

    code.push_str(&format!(
        "\npub const ICON_FALLBACK_KEY: &str = {:?};\n",
        fallback
    ));
    code.push_str("\npub static ICON_ASSETS: &[(&str, &str)] = &[\n");
    for (key, svg) in &icons {
        code.push_str(&format!("    ({:?}, {:?}),\n", key, svg));
    }
    code.push_str("];\n");
    code.push_str(&format!(
        "#[allow(dead_code)]\npub static ICON_COUNT: usize = {};\n",
        icons.len()
    ));

    let wallpaper_object = icon_table
        .get("wallpapers")
        .and_then(serde_json::Value::as_object)
        .expect("web/icon-driver.json must contain a wallpapers object");
    if !wallpaper_object.contains_key("login") {
        panic!("web/icon-driver.json must define the login background wallpaper");
    }
    let mut wallpapers: Vec<(&String, &str)> = wallpaper_object
        .iter()
        .map(|(key, value)| {
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
            {
                panic!("invalid wallpaper key {key:?} in web/icon-driver.json");
            }
            let svg = value
                .get("svg")
                .and_then(serde_json::Value::as_str)
                .filter(|svg| svg.contains("<svg") && svg.contains("</svg>"))
                .unwrap_or_else(|| panic!("wallpaper {key:?} must contain raw SVG markup"));
            (key, svg)
        })
        .collect();
    wallpapers.sort_by(|a, b| a.0.cmp(b.0));
    code.push_str("\npub static WALLPAPER_ASSETS: &[(&str, &str)] = &[\n");
    for (key, svg) in &wallpapers {
        code.push_str(&format!("    ({:?}, {:?}),\n", key, svg));
    }
    code.push_str("];\n");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("assets_gen.rs");
    fs::write(out, code).unwrap();
    if files.is_empty() {
        println!("cargo:warning=no static web assets found under assets/");
    }

    let roots = vec![manifest.join("i18n"), manifest.join("web").join("po")];
    let mut langs = collect_languages(&roots);
    langs.entry("en".to_string()).or_default();
    let mut code = String::new();
    code.push_str("// @generated by build.rs - do not edit\n");
    code.push_str("pub static LANGS: &[(&str, &str)] = &[\n");
    for (lang, catalog) in &langs {
        code.push_str(&format!(
            "    ({}, {}),\n",
            rust_str(lang),
            rust_str(language_name(lang))
        ));
        let _ = catalog;
    }
    code.push_str("];\n\n");

    code.push_str("pub static CATALOG: &[(&str, &[(&str, &str)])] = &[\n");
    for (lang, catalog) in &langs {
        code.push_str(&format!("    ({}, &[\n", rust_str(lang)));
        for (id, tr) in catalog {
            code.push_str(&format!("        ({}, {}),\n", rust_str(id), rust_str(tr)));
        }
        code.push_str("    ]),\n");
    }
    code.push_str("];\n\n");

    code.push_str("pub static TEMPLATES: &[(&str, &[(&str, &str)])] = &[\n");
    for (lang, catalog) in &langs {
        let mut templates: Vec<(&String, &String)> =
            catalog.iter().filter(|(id, _)| id.contains("%s")).collect();
        templates.sort_by_key(|(id, _)| std::cmp::Reverse(template_weight(id)));
        code.push_str(&format!("    ({}, &[\n", rust_str(lang)));
        for (id, tr) in templates {
            code.push_str(&format!("        ({}, {}),\n", rust_str(id), rust_str(tr)));
        }
        code.push_str("    ]),\n");
    }
    code.push_str("];\n");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("i18n_gen.rs");
    fs::write(out, code).unwrap();
    if langs.is_empty() {
        println!("cargo:warning=no gettext catalogs found; messages stay untranslated");
    } else {
        let total: usize = langs.values().map(|c| c.len()).sum();
        println!(
            "cargo:warning=i18n: {} languages / {} strings",
            langs.len(),
            total
        );
    }
}
