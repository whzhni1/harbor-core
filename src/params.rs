//! Request parameter handling: query string + urlencoded body, matching how the
//! LuCI frontend sends data (`GET` in the query string, `POST` as form body).

use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct Params {
    map: HashMap<String, Vec<String>>,
}

fn urldecode(input: &str, plus_as_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn urldecode_path(input: &str) -> String {
    urldecode(input, false)
}

impl Params {
    pub fn set(&mut self, key: &str, value: &str) {
        self.map.insert(key.to_string(), vec![value.to_string()]);
    }

    pub fn parse(query: &str) -> Params {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let mut it = pair.splitn(2, '=');
            let k = urldecode(it.next().unwrap_or(""), true);
            let v = urldecode(it.next().unwrap_or(""), true);
            if k.is_empty() {
                continue;
            }
            map.entry(k).or_default().push(v);
        }
        Params { map }
    }

    pub fn merge(&mut self, other: Params) {
        for (k, mut v) in other.map {
            self.map.entry(k).or_default().append(&mut v);
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.map.get(key).and_then(|v| v.last()).cloned()
    }

    pub fn first_of(&self, keys: &[&str]) -> Option<String> {
        for k in keys {
            if let Some(v) = self.get(k) {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        None
    }

    pub fn str_or(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or_else(|| default.to_string())
    }

    pub fn int(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.trim().parse::<i64>().ok())
    }

    pub fn json_array(&self, key: &str) -> Option<Vec<String>> {
        let raw = self.get(key)?;
        let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let arr = value.as_array()?;
        Some(
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
        )
    }

    pub fn path_array(&self, key: &str) -> Option<Vec<String>> {
        self.get(key)?;
        self.json_array(key).or_else(|| {
            let raw = self.get(key).unwrap_or_default();
            if raw.is_empty() {
                return None;
            }

            Some(
                raw.split([',', '\n'])
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            )
        })
    }
}

pub fn parse_form(body: &[u8], limit: usize) -> Option<Params> {
    if body.len() > limit {
        return None;
    }
    let text = String::from_utf8_lossy(body);
    Some(Params::parse(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_body_decodes_download_fields_and_obeys_limit() {
        let form = parse_form(
            b"mode=download&path=%2Fmnt%2FMy+Files%2Fa.txt&filename=a%2Bb.txt",
            128,
        )
        .unwrap();
        assert_eq!(form.get("mode").as_deref(), Some("download"));
        assert_eq!(form.get("path").as_deref(), Some("/mnt/My Files/a.txt"));
        assert_eq!(form.get("filename").as_deref(), Some("a+b.txt"));
        assert!(parse_form(b"too long", 3).is_none());
    }
}
