use crate::auth;
use crate::reply::{fail_status, ok};
use crate::state::AppState;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{json, Value};
use std::fs;

pub const DEFAULT_USERNAME: &str = "admin";
pub const MIN_PASSWORD: usize = 6;
pub const MAX_PASSWORD: usize = 128;
pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_PERIOD: u64 = 30;
pub const TOTP_ISSUER: &str = "Harbor File Pro";

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn write_private(state_dir: &str, name: &str, value: &str) -> std::io::Result<()> {
    crate::private_file::atomic_replace(std::path::Path::new(state_dir), name, value.as_bytes())
}

fn remove(state_dir: &str, name: &str) -> std::io::Result<()> {
    match fs::remove_file(format!("{state_dir}/{name}")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn username_file(st: &AppState) -> String {
    format!("{}/username", st.settings.state_dir)
}

fn totp_store_key(pending: bool) -> &'static str {
    if pending {
        "__harbor_auth_totp_pending__"
    } else {
        "__harbor_auth_totp_active__"
    }
}

pub(crate) fn secret_store(st: &AppState) -> crate::crypto::SecretStore {
    crate::crypto::SecretStore::open(&st.settings.state_dir, &st.secret)
}

fn read_totp_secret(st: &AppState, pending: bool) -> Option<String> {
    secret_store(st)
        .get(totp_store_key(pending))
        .map(str::to_string)
}

pub fn username(st: &AppState) -> String {
    read_trimmed(&username_file(st)).unwrap_or_else(|| DEFAULT_USERNAME.to_string())
}

pub fn is_custom_username(st: &AppState) -> bool {
    username(st) != DEFAULT_USERNAME
}

pub fn valid_username(name: &str) -> bool {
    let len = name.chars().count();
    (2..=32).contains(&len)
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '@')
}

pub fn matches_user(st: &AppState, candidate: &str) -> bool {
    candidate.trim().eq_ignore_ascii_case(&username(st))
}

pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

pub fn base32_decode(raw: &str) -> Option<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for ch in raw.chars() {
        if ch == '=' || ch == ' ' {
            continue;
        }
        let value = match ch.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

pub fn generate_secret() -> String {
    base32_encode(&auth::random_bytes(20))
}

pub fn is_enabled(st: &AppState) -> bool {
    read_totp_secret(st, false).is_some()
}

pub fn verify_active_code(st: &AppState, code: &str) -> bool {
    read_totp_secret(st, false)
        .map(|secret| verify_code(&secret, code))
        .unwrap_or(false)
}

pub fn pending_secret(st: &AppState) -> Option<String> {
    read_totp_secret(st, true)
}

fn build_totp(secret: &str) -> Option<totp_rs::TOTP> {
    let bytes = base32_decode(secret)?;
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        TOTP_DIGITS as usize,
        1,
        TOTP_PERIOD,
        bytes,
    )
    .ok()
}

pub fn verify_code(secret: &str, code: &str) -> bool {
    let code = code.trim().replace(' ', "");
    if code.len() != TOTP_DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    match build_totp(secret) {
        Some(totp) => totp.check_current(&code).unwrap_or(false),
        None => false,
    }
}

pub fn otpauth_url(secret: &str, account: &str) -> String {
    fn encode(raw: &str) -> String {
        let mut out = String::new();
        for byte in raw.as_bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(*byte as char)
                }
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    }
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}&algorithm=SHA1&digits={}&period={}",
        encode(TOTP_ISSUER),
        encode(account),
        encode(TOTP_ISSUER),
        TOTP_DIGITS,
        TOTP_PERIOD
    )
}

pub fn set_password(st: &AppState, password: &str) -> Result<(), ()> {
    st.set_password(password).map_err(|_| ())
}

pub fn initialize_password(st: &AppState, password: &str) -> Result<(), &'static str> {
    if st.password_hash().is_some() {
        return Err("Authentication is already initialized");
    }
    if password_problem(password).is_some() {
        return Err("Password does not satisfy the password policy");
    }
    st.set_password(password)
        .map_err(|_| "Cannot store the password")
}

pub fn check_password(st: &AppState, password: &str) -> bool {
    match st.password_hash() {
        Some(hash) => auth::verify_password(password, &hash),

        None => password.is_empty(),
    }
}

pub fn set_username(st: &AppState, name: &str) -> Result<(), ()> {
    write_private(&st.settings.state_dir, "username", name.trim()).map_err(|_| ())
}

pub fn set_pending_secret(st: &AppState, secret: &str) -> Result<(), ()> {
    let mut store = secret_store(st);
    store.set(totp_store_key(true), secret);
    store.save().map_err(|_| ())
}

pub fn clear_pending_totp(st: &AppState) -> std::io::Result<()> {
    let mut store = secret_store(st);
    store.remove(totp_store_key(true));
    store.save().map_err(std::io::Error::other)
}

pub fn promote_pending(st: &AppState) -> Result<(), ()> {
    let secret = pending_secret(st).ok_or(())?;
    let mut store = secret_store(st);
    store.set(totp_store_key(false), &secret);
    store.remove(totp_store_key(true));
    store.save().map_err(|_| ())
}

pub fn clear_totp(st: &AppState) -> std::io::Result<()> {
    let mut store = secret_store(st);
    store.remove(totp_store_key(false));
    store.remove(totp_store_key(true));
    store.save().map_err(std::io::Error::other)
}

pub fn reset_auth_dir(state_dir: &str) -> std::io::Result<()> {
    let daemon_secret = crate::state::load_or_create_secret(state_dir)?;
    let mut store = crate::crypto::SecretStore::open(state_dir, &daemon_secret);
    store.remove(totp_store_key(false));
    store.remove(totp_store_key(true));
    store.save().map_err(std::io::Error::other)?;
    let key = auth::random_bytes(32);
    crate::private_file::atomic_replace(std::path::Path::new(state_dir), "auth.key", &key)?;
    clear_auth_files(state_dir)
}

fn clear_auth_files(state_dir: &str) -> std::io::Result<()> {
    remove(state_dir, "username")?;
    remove(state_dir, "password")
}

pub fn state_json(st: &AppState) -> Value {
    json!({
        "username": username(st),
        "default_username": DEFAULT_USERNAME,
        "custom_username": is_custom_username(st),
        "password_set": st.password_hash().is_some(),
        "totp_enabled": is_enabled(st),
        "totp_pending": pending_secret(st).is_some(),
        "totp_digits": TOTP_DIGITS,
        "totp_period": TOTP_PERIOD,
        "totp_issuer": TOTP_ISSUER,
        "min_password": MIN_PASSWORD,
        "max_password": MAX_PASSWORD,
    })
}

fn bad(message: &str) -> Response {
    fail_status(StatusCode::BAD_REQUEST, 1, message, Value::Null)
}

fn denied(message: &str) -> Response {
    fail_status(StatusCode::FORBIDDEN, 1, message, Value::Null)
}

fn password_problem(password: &str) -> Option<&'static str> {
    let len = password.chars().count();
    if len < MIN_PASSWORD {
        Some("The new password is too short")
    } else if len > MAX_PASSWORD {
        Some("The new password is too long")
    } else if password.trim().is_empty() {
        Some("The new password must not be blank")
    } else {
        None
    }
}

#[allow(clippy::result_large_err)]
fn require_current_password(st: &AppState, current: &str) -> std::result::Result<(), Response> {
    if st.password_hash().is_none() && current.is_empty() {
        return Ok(());
    }
    if check_password(st, current) {
        Ok(())
    } else {
        Err(denied("The current password is not correct"))
    }
}

pub async fn api_state(st: &AppState) -> Response {
    ok(state_json(st))
}

pub async fn api_change_password(
    st: &AppState,
    current: &str,
    new_password: &str,
    confirm: Option<&str>,
) -> Response {
    if let Err(response) = require_current_password(st, current) {
        return response;
    }
    if let Some(problem) = password_problem(new_password) {
        return bad(problem);
    }
    if let Some(confirm) = confirm {
        if confirm != new_password {
            return bad("The two passwords do not match");
        }
    }
    if check_password(st, new_password) && st.password_hash().is_some() {
        return bad("The new password must be different from the current one");
    }
    if set_password(st, new_password).is_err() {
        return fail_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "Cannot store the new password",
            Value::Null,
        );
    }
    let mut body = state_json(st);
    if let Value::Object(map) = &mut body {
        map.insert("changed".into(), json!("password"));
    }
    ok(body)
}

pub async fn api_change_username(st: &AppState, current: &str, name: &str) -> Response {
    if let Err(response) = require_current_password(st, current) {
        return response;
    }
    let name = name.trim();
    if !valid_username(name) {
        return bad(
            "Usernames may only use letters, digits, dot, dash, underscore or @ (2-32 characters)",
        );
    }
    if let Err(()) = set_username(st, name) {
        return fail_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "Cannot store the username",
            Value::Null,
        );
    }
    let mut body = state_json(st);
    if let Value::Object(map) = &mut body {
        map.insert("changed".into(), json!("username"));
    }
    ok(body)
}

pub async fn api_change_account(
    st: &AppState,
    current: &str,
    requested_username: Option<&str>,
    new_password: Option<&str>,
    confirm: Option<&str>,
) -> Response {
    if let Err(response) = require_current_password(st, current) {
        return response;
    }

    let old_username = username(st);
    let username = requested_username
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .filter(|name| *name != old_username.as_str());
    if let Some(name) = username {
        if !valid_username(name) {
            return bad(
                "Usernames may only use letters, digits, dot, dash, underscore or @ (2-32 characters)",
            );
        }
    }

    let new_password = new_password.filter(|password| !password.is_empty());
    if let Some(password) = new_password {
        if let Some(problem) = password_problem(password) {
            return bad(problem);
        }
        if confirm != Some(password) {
            return bad("The two passwords do not match");
        }
        if check_password(st, password) && st.password_hash().is_some() {
            return bad("The new password must be different from the current one");
        }
    } else if confirm.is_some_and(|value| !value.is_empty()) {
        return bad("The two passwords do not match");
    }

    if username.is_none() && new_password.is_none() {
        return bad("Nothing to save");
    }

    if let Some(name) = username {
        if set_username(st, name).is_err() {
            return fail_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
                "Cannot store the username",
                Value::Null,
            );
        }
    }
    if let Some(password) = new_password {
        if set_password(st, password).is_err() {
            if username.is_some() {
                let _ = set_username(st, &old_username);
            }
            return fail_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
                "Cannot store the new password",
                Value::Null,
            );
        }
    }

    let mut body = state_json(st);
    if let Value::Object(map) = &mut body {
        map.insert("changed".into(), json!("account"));
    }
    ok(body)
}

pub async fn api_totp_setup(st: &AppState, current: &str) -> Response {
    if let Err(response) = require_current_password(st, current) {
        return response;
    }
    let secret = generate_secret();
    if set_pending_secret(st, &secret).is_err() {
        return fail_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "Cannot store the second factor",
            Value::Null,
        );
    }
    ok(json!({
        "secret": secret,
        "otpauth_url": otpauth_url(&secret, &username(st)),
        "issuer": TOTP_ISSUER,
        "account": username(st),
        "digits": TOTP_DIGITS,
        "period": TOTP_PERIOD,
        "state": state_json(st)
    }))
}

pub async fn api_totp_cancel(st: &AppState) -> Response {
    if clear_pending_totp(st).is_err() {
        return fail_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "Cannot cancel the second-factor setup",
            Value::Null,
        );
    }
    ok(state_json(st))
}

pub async fn api_totp_enable(st: &AppState, code: &str) -> Response {
    let secret = match pending_secret(st) {
        Some(secret) => secret,
        None => return bad("Start the two-factor setup again"),
    };
    if !verify_code(&secret, code) {
        return bad("That code is not valid");
    }
    if promote_pending(st).is_err() {
        return fail_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "Cannot store the second factor",
            Value::Null,
        );
    }
    let mut body = state_json(st);
    if let Value::Object(map) = &mut body {
        map.insert("changed".into(), json!("totp"));
    }
    ok(body)
}

pub async fn api_totp_disable(st: &AppState, password: &str, code: &str) -> Response {
    if let Err(response) = require_current_password(st, password) {
        return response;
    }
    if is_enabled(st) && !verify_active_code(st, code) {
        return bad("That code is not valid");
    }
    if clear_totp(st).is_err() {
        return fail_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "Cannot disable the second factor",
            Value::Null,
        );
    }
    let mut body = state_json(st);
    if let Value::Object(map) = &mut body {
        map.insert("changed".into(), json!("totp"));
    }
    ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn reset_rotates_auth_key_and_preserves_credential_encryption_key() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("harbor-reset-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        let daemon_secret = vec![9u8; 32];
        fs::write(dir.join("secret"), hex::encode(&daemon_secret)).unwrap();
        let mut store = crate::crypto::SecretStore::open(dir.to_str().unwrap(), &daemon_secret);
        store.set(totp_store_key(false), "active-totp");
        store.set(totp_store_key(true), "pending-totp");
        store.set("device-test", "ssh-password");
        store.save().unwrap();
        crate::private_file::atomic_replace(&dir, "auth.key", &[7; 32]).unwrap();
        crate::private_file::atomic_replace(&dir, "username", b"keeper").unwrap();
        crate::private_file::atomic_replace(&dir, "password", b"hash").unwrap();

        reset_auth_dir(dir.to_str().unwrap()).unwrap();

        let rotated_key = fs::read(dir.join("auth.key")).unwrap();
        assert_eq!(rotated_key.len(), 32);
        assert_ne!(rotated_key, vec![7; 32]);
        assert_eq!(
            fs::read_to_string(dir.join("secret")).unwrap(),
            hex::encode(&daemon_secret)
        );
        let store = crate::crypto::SecretStore::open(dir.to_str().unwrap(), &daemon_secret);
        assert_eq!(store.get(totp_store_key(false)), None);
        assert_eq!(store.get(totp_store_key(true)), None);
        assert_eq!(store.get("device-test"), Some("ssh-password"));
        assert_eq!(
            fs::metadata(dir.join("auth.key")).unwrap().mode() & 0o777,
            0o600
        );
        for name in ["username", "password"] {
            assert!(!dir.join(name).exists());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn base32_roundtrip() {
        for len in [8usize, 16, 20, 32] {
            let raw = auth::random_bytes(len);
            let encoded = base32_encode(&raw);
            assert!(
                encoded
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
                "unexpected base32 alphabet: {encoded}"
            );
            assert_eq!(base32_decode(&encoded).unwrap(), raw);
        }
        assert_eq!(base32_encode(b"hello"), "NBSWY3DP");
    }

    #[test]
    fn totp_codes_verify_and_reject() {
        let secret = generate_secret();
        let code = build_totp(&secret)
            .expect("TOTP parameters")
            .generate_current()
            .expect("current code");
        assert_eq!(code.len(), 6);
        assert!(verify_code(&secret, &code));
        assert!(verify_code(&secret, &format!(" {code} ")));
        assert!(!verify_code(&secret, "abcdef"));
        let other = generate_secret();

        let wrong = if code == "000000" { "111111" } else { "000000" };
        assert!(!verify_code(&other, wrong));
    }

    #[test]
    fn otpauth_url_is_authenticator_ready() {
        let url = otpauth_url("JBSWY3DPEHPK3PXP", "admin");
        assert!(url.starts_with("otpauth://totp/Harbor%20File%20Pro:admin?"));
        assert!(url.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(url.contains("issuer=Harbor%20File%20Pro"));
        assert!(url.contains("digits=6"));
        assert!(url.contains("period=30"));
    }

    #[test]
    fn username_rules() {
        assert!(valid_username("admin"));
        assert!(valid_username("file.keeper_01"));
        assert!(!valid_username("a"));
        assert!(!valid_username("-root"));
        assert!(!valid_username("two words"));
        assert!(!valid_username("with/slash"));
        assert!(!valid_username(&"x".repeat(33)));
    }

    #[test]
    fn password_rules() {
        assert!(password_problem("harbor123").is_none());
        assert!(password_problem("12345").is_some());
        assert!(password_problem(&"x".repeat(MAX_PASSWORD + 1)).is_some());
        assert!(password_problem("      ").is_some());
    }
}
