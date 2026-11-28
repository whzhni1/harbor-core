//! Secrets at rest.
//!
//! Two different kinds of secret, handled differently on purpose:
//!
//! * the **login password** is one-way: PBKDF2-SHA256 with a per-install salt, so
//!   it can only be verified, never recovered (`auth::hash_password`);
//! * **remote SSH passwords and TOTP secrets** must be *used* later, so they have
//!   to be reversible. They are never written in clear text: the store keeps them
//!   ChaCha20-Poly1305 encrypted under a key derived from `/etc/harbor/secret`
//!   (0600, created on first boot). Copying the box's config away is then useless
//!   without that file, and even with it the plaintext never touches disk.
//!
//! The file format is deliberately boring and self-describing:
//!
//! ```text
//! HARBOR-SECRETS-1
//! <base64(nonce || ciphertext || tag)>
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const MAGIC: &str = "HARBOR-SECRETS-1";
const AAD: &[u8] = b"harbor-core/secrets/v1";

type HmacSha256 = Hmac<Sha256>;

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let key = if salt.is_empty() {
        vec![0u8; 32]
    } else {
        salt.to_vec()
    };
    let mut extract =
        <HmacSha256 as Mac>::new_from_slice(&key).expect("hmac accepts any key length");
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut previous: Vec<u8> = Vec::new();
    let mut written = 0usize;
    let mut counter = 1u8;
    while written < out.len() {
        let mut expand =
            <HmacSha256 as Mac>::new_from_slice(&prk).expect("hmac accepts any key length");
        expand.update(&previous);
        expand.update(info);
        expand.update(&[counter]);
        previous = expand.finalize().into_bytes().to_vec();
        let take = (out.len() - written).min(previous.len());
        out[written..written + take].copy_from_slice(&previous[..take]);
        written += take;
        counter = counter.wrapping_add(1);
    }
}

pub fn content_key(daemon_secret: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    hkdf_sha256(daemon_secret, AAD, AAD, &mut key);
    key
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    getrandom(&mut nonce)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| "encryption failed".to_string())?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ciphertext);
    Ok(format!("{MAGIC}\n{}\n", base64_encode(&blob)))
}

pub fn decrypt(key: &[u8; 32], document: &str) -> Result<Vec<u8>, String> {
    let mut lines = document.lines();
    if lines.next().map(str::trim) != Some(MAGIC) {
        return Err("unsupported secret store version".to_string());
    }
    let body = lines
        .next()
        .ok_or_else(|| "truncated secret store".to_string())?;
    let blob =
        base64_decode(body.trim()).ok_or_else(|| "invalid secret store encoding".to_string())?;
    if blob.len() < 13 {
        return Err("truncated secret store".to_string());
    }
    let (nonce, ciphertext) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| {
            "cannot decrypt the secret store (was /etc/harbor/secret replaced?)".to_string()
        })
}

fn getrandom(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    let mut file = fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
    file.read_exact(buf).map_err(|e| e.to_string())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

#[derive(Debug, Default)]
pub struct SecretStore {
    path: PathBuf,
    key: [u8; 32],
    entries: BTreeMap<String, String>,
    dirty: bool,
    usable: bool,
}

impl SecretStore {
    pub fn open(state_dir: &str, daemon_secret: &[u8]) -> SecretStore {
        let path = Path::new(state_dir).join("secrets.enc");
        let key = content_key(daemon_secret);
        let (entries, usable) = match fs::read_to_string(&path) {
            Ok(text) => match decrypt(&key, &text) {
                Ok(bytes) => (parse_entries(&bytes), true),
                Err(error) => {
                    eprintln!("harbor-core: {error}");
                    (BTreeMap::new(), false)
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (BTreeMap::new(), true),
            Err(_) => (BTreeMap::new(), false),
        };
        SecretStore {
            path,
            key,
            entries,
            dirty: false,
            usable,
        }
    }

    pub fn get(&self, id: &str) -> Option<&str> {
        self.entries.get(id).map(|s| s.as_str())
    }

    pub fn has(&self, id: &str) -> bool {
        self.entries.get(id).map(|s| !s.is_empty()).unwrap_or(false)
    }

    pub fn set(&mut self, id: &str, password: &str) {
        if password.is_empty() {
            if self.entries.remove(id).is_some() {
                self.dirty = true;
            }
            return;
        }
        if self.entries.get(id).map(|s| s.as_str()) != Some(password) {
            self.entries.insert(id.to_string(), password.to_string());
            self.dirty = true;
        }
    }

    pub fn remove(&mut self, id: &str) {
        if self.entries.remove(id).is_some() {
            self.dirty = true;
        }
    }

    #[allow(dead_code)]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn save(&mut self) -> Result<(), String> {
        if !self.dirty {
            return Ok(());
        }
        if !self.usable {
            return Err("secret store is unavailable or cannot be decrypted".to_string());
        }
        let payload = render_entries(&self.entries);
        let document = encrypt(&self.key, payload.as_bytes())?;
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let tmp = self.path.with_extension("enc.tmp");
        fs::write(&tmp, document).map_err(|e| e.to_string())?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &self.path).map_err(|e| e.to_string())?;
        self.dirty = false;
        Ok(())
    }
}

fn render_entries(entries: &BTreeMap<String, String>) -> String {
    let mut out = String::from("harbor-secrets\t1\n");
    for (id, password) in entries {
        out.push_str(id);
        out.push('\t');
        out.push_str(password);
        out.push('\n');
    }
    out
}

fn parse_entries(bytes: &[u8]) -> BTreeMap<String, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut entries = BTreeMap::new();
    for line in text.lines().skip(1) {
        if let Some((id, password)) = line.split_once('\t') {
            if !id.is_empty() && !password.is_empty() {
                entries.insert(id.to_string(), password.to_string());
            }
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut out = [0u8; 42];
        hkdf_sha256(&ikm, &salt, &info, &mut out);
        assert_eq!(
            hex::encode(out),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn round_trips_and_rejects_tampering() {
        let key = content_key(b"unit-test-secret");
        let document = encrypt(&key, b"harbor-secrets\t1\n".as_ref()).unwrap();
        assert_eq!(decrypt(&key, &document).unwrap(), b"harbor-secrets\t1\n");

        let mut bytes = document.clone().into_bytes();
        let index = bytes.len() - 8;
        bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
        assert!(decrypt(&key, &String::from_utf8_lossy(&bytes)).is_err());
        assert!(decrypt(&content_key(b"other"), &document).is_err());
    }

    #[test]
    fn store_persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("harbor-secrets-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.to_string_lossy().into_owned();
        let mut store = SecretStore::open(&path, b"daemon-secret");
        store.set("cfg123", "s3cret pass");
        store.save().unwrap();
        assert_eq!(
            fs::metadata(dir.join("secrets.enc"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let reopened = SecretStore::open(&path, b"daemon-secret");
        assert_eq!(reopened.get("cfg123"), Some("s3cret pass"));

        let other = SecretStore::open(&path, b"another-secret");
        assert_eq!(other.get("cfg123"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_store_is_not_overwritten() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("harbor-secrets-invalid-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("secrets.enc"), b"invalid store").unwrap();
        let mut store = SecretStore::open(dir.to_str().unwrap(), b"daemon-secret");
        store.set("totp", "secret");
        assert!(store.save().is_err());
        assert_eq!(fs::read(dir.join("secrets.enc")).unwrap(), b"invalid store");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn plaintext_never_appears_in_the_file() {
        let key = content_key(b"daemon-secret");
        let document = encrypt(&key, b"harbor-secrets\t1\ncfg1\tSup3rSecret\n").unwrap();
        assert!(!document.contains("Sup3rSecret"));
    }
}
