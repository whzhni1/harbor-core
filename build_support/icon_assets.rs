//! Shared build-time/runtime icon rendering from `web/icon-driver.json`.

pub const SPRITE_PLACEHOLDER: &str = "__HARBOR_ICON_SPRITE__";

fn svg_parts(text: &str) -> Option<(&str, &str)> {
    let start = text.find("<svg")?;
    let end = text[start..].find('>')? + start;
    let close = text.rfind("</svg>")?;
    if close < end {
        return None;
    }
    Some((&text[start + 4..end], &text[end + 1..close]))
}

// The driver is trusted build input; accept normal single- or double-quoted
// XML attributes, while preserving their literal values in the symbol.
fn attributes(mut input: &str) -> Option<Vec<(&str, &str, &str)>> {
    let mut out = Vec::new();
    loop {
        input = input.trim_start();
        if input.is_empty() {
            return Some(out);
        }
        let name_end = input.find(|c: char| c.is_whitespace() || c == '=')?;
        let name = &input[..name_end];
        if name.is_empty() {
            return None;
        }
        input = input[name_end..]
            .trim_start()
            .strip_prefix('=')?
            .trim_start();
        let quote = input.chars().next()?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        let rest = &input[1..];
        let end = rest.find(quote)?;
        let value = &rest[..end];
        let original = &input[..end + 2];
        out.push((name, value, original));
        input = &rest[end + 1..];
    }
}

pub fn viewbox(text: &str) -> Option<String> {
    let (tag, _) = svg_parts(text)?;
    let attrs = attributes(tag)?;
    if let Some((_, value, _)) = attrs.iter().find(|(name, _, _)| *name == "viewBox") {
        return Some((*value).to_string());
    }
    let dimension = |name: &str| -> Option<f64> {
        attrs
            .iter()
            .find(|(key, _, _)| *key == name)?
            .1
            .trim()
            .trim_end_matches("px")
            .parse::<f64>()
            .ok()
    };
    Some(format!(
        "0 0 {} {}",
        dimension("width")?,
        dimension("height")?
    ))
}

pub fn to_symbol(key: &str, text: &str) -> Option<String> {
    let (tag, body) = svg_parts(text)?;
    let attrs = attributes(tag)?;
    let viewbox = viewbox(text)?;
    let mut extra = String::new();
    for (name, _, original) in attrs {
        if matches!(
            name,
            "id" | "viewBox" | "width" | "height" | "xmlns" | "version"
        ) || name.starts_with("xmlns:")
        {
            continue;
        }
        extra.push(' ');
        extra.push_str(name);
        extra.push('=');
        extra.push_str(original);
    }
    Some(format!(
        "<symbol id=\"hf-{key}\" viewBox=\"{viewbox}\"{extra}>{body}</symbol>"
    ))
}

pub fn sprite(icons: &[(&str, &str)]) -> Option<String> {
    if icons.is_empty() {
        return None;
    }
    let mut output = String::from("<svg class=\"hf-icon-sprite\" xmlns=\"http://www.w3.org/2000/svg\" style=\"display:none\" aria-hidden=\"true\" focusable=\"false\">");
    for (key, svg) in icons {
        output.push_str(&to_symbol(key, svg)?);
    }
    output.push_str("</svg>");
    Some(output)
}

pub fn data_uri(svg: &str) -> String {
    use std::fmt::Write;
    let mut uri = String::from("data:image/svg+xml;charset=utf-8,");
    for byte in svg.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            uri.push(byte as char);
        } else {
            write!(&mut uri, "%{byte:02X}").expect("writing a string cannot fail");
        }
    }
    uri
}

pub fn render_template(text: &str, icons: &[(&str, &str)]) -> Option<String> {
    let mut output = text.replace(SPRITE_PLACEHOLDER, &sprite(icons)?);
    for (key, svg) in icons {
        let marker = format!("__HARBOR_ICON_URI_{key}__");
        if output.contains(&marker) {
            output = output.replace(&marker, &data_uri(svg));
        }
    }
    if output.contains("__HARBOR_ICON_") {
        None
    } else {
        Some(output)
    }
}
