//! Minimal UCI reader/writer so `/etc/config/harbor_file_pro` stays byte-compatible
//! with what LuCI and the previous ucode backend produced.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Section {
    pub kind: String,
    pub name: String,

    pub options: Vec<(String, String)>,

    pub list_keys: Vec<String>,
}

impl Section {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, key: &str) -> Vec<String> {
        self.options
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    }

    pub fn set(&mut self, key: &str, value: &str) {
        if let Some(slot) = self.options.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value.to_string();
        } else {
            self.options.push((key.to_string(), value.to_string()));
        }
    }

    pub fn set_list(&mut self, key: &str, values: &[String]) {
        self.options.retain(|(k, _)| k != key);
        if !self.list_keys.iter().any(|k| k == key) {
            self.list_keys.push(key.to_string());
        }
        for v in values {
            self.options.push((key.to_string(), v.clone()));
        }
    }

    pub fn remove(&mut self, key: &str) {
        self.options.retain(|(k, _)| k != key);
        self.list_keys.retain(|k| k != key);
    }
}

#[derive(Debug, Clone, Default)]
pub struct Uci {
    pub sections: Vec<Section>,
}

fn split_tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut has_token = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == '\\' {
                    if let Some(next) = chars.next() {
                        if next == q || next == '\\' {
                            cur.push(next);
                        } else {
                            cur.push('\\');
                            cur.push(next);
                        }
                    }
                } else if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                    has_token = true;
                } else if c.is_whitespace() {
                    if has_token || !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                        has_token = false;
                    }
                } else {
                    cur.push(c);
                    has_token = true;
                }
            }
        }
    }
    if has_token || !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn escape(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

impl Uci {
    pub fn parse(text: &str) -> Uci {
        let mut uci = Uci::default();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let tokens = split_tokens(line);
            if tokens.is_empty() {
                continue;
            }
            match tokens[0].as_str() {
                "config" => {
                    let kind = tokens.get(1).cloned().unwrap_or_default();
                    let name = tokens
                        .get(2)
                        .cloned()
                        .unwrap_or_else(|| format!("cfg{}", random_hex(6)));
                    uci.sections.push(Section {
                        kind,
                        name,
                        options: Vec::new(),
                        list_keys: Vec::new(),
                    });
                }
                "option" | "list" => {
                    if uci.sections.is_empty() {
                        continue;
                    }
                    let key = match tokens.get(1) {
                        Some(k) => k.clone(),
                        None => continue,
                    };
                    let value = tokens.get(2).cloned().unwrap_or_default();
                    let section = uci.sections.last_mut().unwrap();
                    if tokens[0] == "list" && !section.list_keys.iter().any(|k| k == &key) {
                        section.list_keys.push(key.clone());
                    }
                    section.options.push((key, value));
                }
                _ => {}
            }
        }
        uci
    }

    pub fn load(path: &str) -> Option<Uci> {
        let text = std::fs::read_to_string(path).ok()?;
        Some(Uci::parse(&text))
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn section_mut(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.name == name)
    }

    pub fn of_kind(&self, kind: &str) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.kind == kind).collect()
    }

    pub fn ensure_section(&mut self, kind: &str, name: &str) -> &mut Section {
        if self.section(name).is_none() {
            self.sections.insert(
                0,
                Section {
                    kind: kind.to_string(),
                    name: name.to_string(),
                    options: Vec::new(),
                    list_keys: Vec::new(),
                },
            );
        }
        self.section_mut(name).unwrap()
    }

    pub fn remove_kind(&mut self, kind: &str) {
        self.sections.retain(|s| s.kind != kind);
    }

    pub fn add_section(&mut self, kind: &str) -> &mut Section {
        let name = format!("cfg{}", random_hex(6));
        self.sections.push(Section {
            kind: kind.to_string(),
            name,
            options: Vec::new(),
            list_keys: Vec::new(),
        });
        self.sections.last_mut().unwrap()
    }

    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for (i, s) in self.sections.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&format!("config {} {}\n", s.kind, escape(&s.name)));
            let mut seen: HashMap<&str, usize> = HashMap::new();
            for (k, v) in &s.options {
                let count = seen.entry(k.as_str()).or_insert(0);
                *count += 1;
                let keyword = if s.list_keys.iter().any(|lk| lk == k) || *count > 1 {
                    "list"
                } else {
                    "option"
                };
                out.push_str(&format!("\t{keyword} {k} {}\n", escape(v)));
            }
        }
        out
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let tmp = format!("{path}.harbor-tmp");
        crate::paths::journal_tmp(&tmp);
        std::fs::write(&tmp, self.serialize())?;
        std::fs::rename(&tmp, path)?;
        let config = std::path::Path::new(path)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let _ = std::process::Command::new("uci")
            .args(["commit", &config])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        Ok(())
    }
}

pub fn random_hex(bytes: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return hex::encode(buf);
        }
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut out = String::new();
    for i in 0..bytes * 2 {
        out.push(char::from_digit(((nanos >> (i % 16)) as u32) % 16, 16).unwrap_or('0'));
    }
    out
}
