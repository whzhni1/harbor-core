use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const COOKIE_NAME: &str = "harbor_session";
const PBKDF2_ROUNDS: u32 = 310_000;
const PBKDF2_MIN_VERIFY_ROUNDS: u32 = 10_000;
const PBKDF2_MAX_VERIFY_ROUNDS: u32 = 1_000_000;

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buf))
        .expect("operating system CSPRNG unavailable");
    buf
}

fn pbkdf2(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(password).expect("hmac key");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = mac.finalize_reset().into_bytes();
    let mut out = u;
    for _ in 1..rounds {
        mac.update(&u);
        u = mac.finalize_reset().into_bytes();
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= b;
        }
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

pub fn hash_password(password: &str) -> String {
    let salt = random_bytes(16);
    let hash = pbkdf2(password.as_bytes(), &salt, PBKDF2_ROUNDS);
    format!(
        "pbkdf2-sha256${}${}${}",
        PBKDF2_ROUNDS,
        hex::encode(salt),
        hex::encode(hash)
    )
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2-sha256" {
        return false;
    }
    let rounds: u32 = match parts[1].parse() {
        Ok(v) if (PBKDF2_MIN_VERIFY_ROUNDS..=PBKDF2_MAX_VERIFY_ROUNDS).contains(&v) => v,
        _ => return false,
    };
    let salt = match hex::decode(parts[2]) {
        Ok(v) if v.len() == 16 => v,
        _ => return false,
    };
    let expected = match hex::decode(parts[3]) {
        Ok(v) if v.len() == 32 => v,
        _ => return false,
    };
    let computed = pbkdf2(password.as_bytes(), &salt, rounds);
    constant_time_eq(&computed, &expected)
}

pub fn password_needs_rehash(stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2-sha256" {
        return true;
    }
    !matches!(parts[1].parse::<u32>(), Ok(rounds) if rounds >= PBKDF2_ROUNDS)
}

pub fn sign_token(secret: &[u8], payload: &Value) -> String {
    let raw = serde_json::to_vec(payload).unwrap_or_default();
    let body = URL_SAFE_NO_PAD.encode(&raw);
    let sig = hmac_sha256(secret, body.as_bytes());
    format!("{body}.{}", hex::encode(sig))
}

pub fn verify_token(secret: &[u8], token: &str, now: i64) -> Option<Value> {
    let (body, sig_hex) = token.split_once('.')?;
    let sig = hex::decode(sig_hex).ok()?;
    let expected = hmac_sha256(secret, body.as_bytes());
    if !constant_time_eq(&sig, &expected) {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(body).ok()?;
    let payload: Value = serde_json::from_slice(&raw).ok()?;
    let expiry = payload.get("exp").and_then(|v| v.as_i64())?;
    let issued = payload.get("iat").and_then(|v| v.as_i64())?;
    if expiry <= now || issued > now.saturating_add(60) || issued >= expiry {
        return None;
    }
    Some(payload)
}

pub fn make_session(secret: &[u8], username: &str, ttl: i64, perm: &str) -> (String, String, i64) {
    let now = crate::meta::now_secs();
    let exp = now.saturating_add(ttl.max(1));
    let sid = hex::encode(random_bytes(16));
    let payload = json!({
        "username": username,
        "exp": exp,
        "iat": now,
        "sid": sid,
        "perm": perm
    });
    (sign_token(secret, &payload), sid, exp)
}

#[derive(Clone, Copy)]
struct SessionRecord {
    last_seen: i64,
    expires: i64,
}

pub struct Sessions {
    idle: i64,
    seen: std::sync::Mutex<std::collections::HashMap<String, SessionRecord>>,
}

impl Sessions {
    pub fn new(idle: i64) -> Sessions {
        Sessions {
            idle: idle.max(0),
            seen: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, SessionRecord>> {
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn register(&self, id: &str, now: i64, expires: i64) -> bool {
        if id.is_empty() || expires <= now {
            return false;
        }
        let mut sessions = self.slot();
        if sessions.len() >= 4_096 {
            let idle = self.idle;
            sessions.retain(|_, record| {
                now < record.expires && (idle <= 0 || now.saturating_sub(record.last_seen) < idle)
            });
            if sessions.len() >= 4_096 {
                return false;
            }
        }
        let _ = sessions.insert(
            id.to_string(),
            SessionRecord {
                last_seen: now,
                expires,
            },
        );
        true
    }

    pub fn touch(&self, id: &str, now: i64) -> bool {
        if id.is_empty() {
            return false;
        }
        let mut sessions = self.slot();
        let record = match sessions.get(id).copied() {
            Some(record) => record,
            None => return false,
        };
        if now >= record.expires
            || (self.idle > 0 && now.saturating_sub(record.last_seen) >= self.idle)
        {
            let _ = sessions.remove(id);
            return false;
        }
        let _ = sessions.insert(
            id.to_string(),
            SessionRecord {
                last_seen: now,
                expires: record.expires,
            },
        );
        true
    }

    pub fn forget(&self, id: &str) {
        let _ = self.slot().remove(id);
    }

    pub fn len(&self) -> usize {
        self.slot().len()
    }
}

pub struct LoginFailureResult {
    pub remaining_attempts: u32,
    pub locked_until: Option<i64>,
    pub is_permanent: bool,
}

#[derive(Clone, Copy)]
struct LoginFailure {
    failures: u32,
    blocked_until: i64,
}

pub struct LoginLimiter {
    attempts: std::sync::Mutex<std::collections::HashMap<String, LoginFailure>>,
}

impl LoginLimiter {
    const THRESHOLD: u32 = 3;
    const LOCKOUT_STEPS: [i64; 3] = [30, 60, 180];

    pub fn new() -> LoginLimiter {
        LoginLimiter {
            attempts: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, LoginFailure>> {
        self.attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn blocked_until(&self, key: &str, now: i64) -> Option<i64> {
        let attempts = self.slot();
        let failure = attempts.get(key).copied()?;
        if now < failure.blocked_until {
            return Some(failure.blocked_until);
        }
        None
    }

    pub fn record_failure(&self, key: &str, now: i64) -> Option<LoginFailureResult> {
        let mut attempts = self.slot();
        if !attempts.contains_key(key) && attempts.len() >= 4_096 {
            attempts.retain(|_, record| record.blocked_until > now);
            if attempts.len() >= 4_096 {
                if let Some(oldest) = attempts
                    .iter()
                    .min_by_key(|(_, record)| record.blocked_until)
                    .map(|(key, _)| key.clone())
                {
                    let _ = attempts.remove(&oldest);
                }
            }
        }
        let failure = attempts.entry(key.to_string()).or_insert(LoginFailure {
            failures: 0,
            blocked_until: 0,
        });
        failure.failures = failure.failures.saturating_add(1);
        if failure.failures < Self::THRESHOLD {
            return Some(LoginFailureResult {
                remaining_attempts: Self::THRESHOLD - failure.failures,
                locked_until: None,
                is_permanent: false,
            });
        }
        let lockout_level = ((failure.failures - 1) / Self::THRESHOLD) as usize;
        if lockout_level >= Self::LOCKOUT_STEPS.len() {
            failure.blocked_until = i64::MAX;
            return Some(LoginFailureResult {
                remaining_attempts: 0,
                locked_until: Some(i64::MAX),
                is_permanent: true,
            });
        }
        let lockout = Self::LOCKOUT_STEPS[lockout_level];
        failure.blocked_until = now.saturating_add(lockout);
        Some(LoginFailureResult {
            remaining_attempts: 0,
            locked_until: Some(failure.blocked_until),
            is_permanent: false,
        })
    }

    pub fn record_success(&self, key: &str) {
        let _ = self.slot().remove(key);
    }
}

pub fn parse_cookies(header: Option<&str>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(raw) = header {
        for part in raw.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                out.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    out
}

pub fn cookie_value(header: Option<&str>, name: &str) -> Option<String> {
    parse_cookies(header)
        .into_iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
}

pub fn cookie_ttl(absolute_ttl: i64, idle_ttl: i64) -> i64 {
    let absolute_ttl = absolute_ttl.max(1);
    if idle_ttl > 0 {
        absolute_ttl.min(idle_ttl)
    } else {
        absolute_ttl
    }
}

pub fn session_cookie(value: &str, ttl: i64, secure: bool) -> String {
    let mut cookie =
        format!("{COOKIE_NAME}={value}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
}

pub fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_sha256_test_vector() {
        assert_eq!(
            hex::encode(pbkdf2(b"password", b"salt", 1)),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn password_verifier_bounds_parameters() {
        let salt = "00112233445566778899aabbccddeeff";
        let digest = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert!(!verify_password(
            "password",
            &format!("pbkdf2-sha256$1000001${salt}${digest}")
        ));
        assert!(!verify_password(
            "password",
            &format!("pbkdf2-sha256$12000$00${digest}")
        ));
    }

    #[test]
    fn weak_password_hashes_are_marked_for_upgrade() {
        assert!(password_needs_rehash("pbkdf2-sha256$12000$0011$0011"));
        assert!(!password_needs_rehash("pbkdf2-sha256$310000$0011$0011"));
    }

    #[test]
    fn cookie_lifetime_never_exceeds_absolute_or_idle_limit() {
        assert_eq!(cookie_ttl(43_200, 7_200), 7_200);
        assert_eq!(cookie_ttl(3_600, 7_200), 3_600);
        assert_eq!(cookie_ttl(3_600, 0), 3_600);
    }

    #[test]
    fn session_claims_include_username_and_absolute_times() {
        let key = [9u8; 32];
        let (token, sid, exp) = make_session(&key, "alice", 3_600, "session");
        let payload = verify_token(&key, &token, crate::meta::now_secs()).unwrap();
        assert_eq!(
            payload.get("username").and_then(Value::as_str),
            Some("alice")
        );
        assert_eq!(payload.get("exp").and_then(Value::as_i64), Some(exp));
        assert!(payload.get("iat").and_then(Value::as_i64).is_some());
        assert_eq!(
            payload.get("sid").and_then(Value::as_str),
            Some(sid.as_str())
        );
    }

    #[test]
    fn token_expires_at_exp_boundary_and_requires_claims() {
        let key = [3u8; 32];
        let valid = sign_token(
            &key,
            &json!({ "username": "alice", "iat": 50, "exp": 100, "sid": "s", "perm": "session" }),
        );
        assert!(verify_token(&key, &valid, 99).is_some());
        assert!(verify_token(&key, &valid, 100).is_none());
        let missing = sign_token(&key, &json!({ "iat": 50, "sid": "s" }));
        assert!(verify_token(&key, &missing, 99).is_none());
    }

    #[test]
    fn idle_sessions_expire_after_the_window() {
        let sessions = Sessions::new(60);
        assert!(sessions.register("abc", 1_000, 2_000));
        assert!(sessions.touch("abc", 1_000));
        assert!(sessions.touch("abc", 1_050));
        assert!(sessions.touch("abc", 1_100));
        assert!(!sessions.touch("abc", 1_160));
        assert!(!sessions.touch("abc", 1_161));
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn zero_idle_still_enforces_absolute_expiry() {
        let sessions = Sessions::new(0);
        assert!(sessions.register("abc", 1_000, 2_000));
        assert!(sessions.touch("abc", 1_999));
        assert!(!sessions.touch("abc", 2_000));
    }

    #[test]
    fn unknown_and_forgotten_sessions_are_rejected() {
        let sessions = Sessions::new(60);
        assert!(!sessions.touch("unknown", 1_000));
        assert!(sessions.register("abc", 1_000, 2_000));
        sessions.forget("abc");
        assert!(!sessions.touch("abc", 1_001));
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn login_limiter_three_failures_then_lockout() {
        let limiter = LoginLimiter::new();
        assert_eq!(
            limiter
                .record_failure("192.0.2.1", 1_000)
                .unwrap()
                .remaining_attempts,
            2
        );
        assert_eq!(
            limiter
                .record_failure("192.0.2.1", 1_000)
                .unwrap()
                .remaining_attempts,
            1
        );
        let r = limiter.record_failure("192.0.2.1", 1_000).unwrap();
        assert_eq!(r.remaining_attempts, 0);
        assert_eq!(r.locked_until, Some(1_030));
        assert!(!r.is_permanent);
        assert_eq!(limiter.blocked_until("192.0.2.1", 1_029), Some(1_030));
        assert_eq!(limiter.blocked_until("192.0.2.1", 1_030), None);
        let r = limiter.record_failure("192.0.2.1", 1_031).unwrap();
        assert_eq!(r.locked_until, Some(1_091));
        assert!(!r.is_permanent);
        limiter.record_success("192.0.2.1");
        assert_eq!(limiter.blocked_until("192.0.2.1", 1_032), None);
    }

    #[test]
    fn login_limiter_permanent_after_three_lockouts() {
        let limiter = LoginLimiter::new();
        let mut now = 1_000;
        for _ in 0..3 {
            limiter.record_failure("192.0.2.2", now);
        }
        assert_eq!(limiter.blocked_until("192.0.2.2", now), Some(1_030));
        now = 1_031;
        for _ in 0..3 {
            limiter.record_failure("192.0.2.2", now);
        }
        assert_eq!(limiter.blocked_until("192.0.2.2", now), Some(1_091));
        now = 1_092;
        for _ in 0..3 {
            limiter.record_failure("192.0.2.2", now);
        }
        assert_eq!(limiter.blocked_until("192.0.2.2", now), Some(1_272));
        now = 1_273;
        for _ in 0..3 {
            limiter.record_failure("192.0.2.2", now);
        }
        let r = limiter.record_failure("192.0.2.2", now).unwrap();
        assert!(r.is_permanent);
        assert_eq!(r.locked_until, Some(i64::MAX));
        assert_eq!(limiter.blocked_until("192.0.2.2", now), Some(i64::MAX));
        let later = i64::MAX - 100;
        assert_eq!(limiter.blocked_until("192.0.2.2", later), Some(i64::MAX));
        limiter.record_success("192.0.2.2");
        assert_eq!(limiter.blocked_until("192.0.2.2", now), None);
    }
}
