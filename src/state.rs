//! Daemon wide state: settings, secrets, request context helpers.

use crate::auth;
use crate::config::{self, Prefs};
use crate::meta;
use crate::params::Params;
use crate::paths;
use crate::reply::{ApiError, ApiResult};
use crate::uci::Uci;
use axum::http::{HeaderMap, Method};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootPolicy {
    Unrestricted,
    Allowlist,
    Denylist,
}

impl RootPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            RootPolicy::Unrestricted => "unrestricted",
            RootPolicy::Allowlist => "allowlist",
            RootPolicy::Denylist => "denylist",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub config_path: String,
    pub state_dir: String,
    pub listen: String,
    pub session_ttl: i64,
    pub session_idle: i64,
    pub session_sliding: bool,
    pub root_policy: RootPolicy,
    pub roots: Vec<String>,
    pub excluded_roots: Vec<String>,
    pub root_policy_cli_override: bool,
    pub secure_cookie: bool,
    pub version: String,
    pub workers: usize,
    pub max_connections: usize,
    pub max_transfers: usize,
    pub request_timeout: u64,
    pub body_idle_timeout: u64,
    pub chunk_size: u64,
    pub chunk_limit: u64,
    pub upload_session_hours: u64,
    pub transfer_history: usize,
    pub dev_mode: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            config_path: config::DEFAULT_CONFIG_PATH.to_string(),
            state_dir: "/etc/harbor".to_string(),
            listen: "0.0.0.0:9700".to_string(),
            session_ttl: 12 * 3600,
            session_idle: 2 * 3600,
            session_sliding: true,
            root_policy: RootPolicy::Unrestricted,
            roots: Vec::new(),
            excluded_roots: Vec::new(),
            root_policy_cli_override: false,
            secure_cookie: false,
            version: env!("CARGO_PKG_VERSION").to_string(),
            workers: 0,
            max_connections: 16,
            max_transfers: 4,
            request_timeout: 60,
            body_idle_timeout: 30,
            chunk_size: 1024 * 1024,
            chunk_limit: 16 * 1024 * 1024,
            upload_session_hours: 24,
            transfer_history: 64,
            dev_mode: false,
        }
    }
}

#[derive(Clone, Copy)]
struct SystemGrant {
    last_seen: i64,
    timeout_secs: i64,
}

pub struct SystemAccess {
    grants: Mutex<HashMap<(String, String, String), SystemGrant>>,
}

impl SystemAccess {
    pub fn new() -> Self {
        Self {
            grants: Mutex::new(HashMap::new()),
        }
    }

    pub fn grant(&self, session_id: &str, device_id: &str, scope: &str, timeout_secs: i64) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.insert(
                (
                    session_id.to_string(),
                    device_id.to_string(),
                    scope.to_string(),
                ),
                SystemGrant {
                    last_seen: meta::now_secs(),
                    timeout_secs: timeout_secs.max(0),
                },
            );
        }
    }

    pub fn allowed(&self, session_id: &str, device_id: &str, scope: &str) -> bool {
        let now = meta::now_secs();
        let exact = (
            session_id.to_string(),
            device_id.to_string(),
            scope.to_string(),
        );
        let all = (
            session_id.to_string(),
            device_id.to_string(),
            "*".to_string(),
        );
        let Ok(mut grants) = self.grants.lock() else {
            return false;
        };
        for key in [exact, all] {
            let valid = grants
                .get(&key)
                .map(|grant| {
                    grant.timeout_secs == 0
                        || now.saturating_sub(grant.last_seen) < grant.timeout_secs
                })
                .unwrap_or(false);
            if valid {
                if let Some(grant) = grants.get_mut(&key) {
                    grant.last_seen = now;
                }
                return true;
            }
            grants.remove(&key);
        }
        false
    }

    /// Authorize both the user-visible name and the resolved target. A symlink
    /// can cross two protected system roots, so checking only the first scope
    /// would allow a grant for one root to access another.
    pub fn missing_path<'a>(
        &self,
        session_id: Option<&str>,
        device_id: &str,
        original: &'a str,
        actual: &'a str,
    ) -> Option<&'a str> {
        [original, actual].into_iter().find(|path| {
            paths::system_path_scope(path).is_some_and(|scope| {
                !session_id.is_some_and(|id| self.allowed(id, device_id, &scope))
            })
        })
    }

    pub fn paths_allowed(
        &self,
        session_id: Option<&str>,
        device_id: &str,
        original: &str,
        actual: &str,
    ) -> bool {
        self.missing_path(session_id, device_id, original, actual)
            .is_none()
    }

    pub fn revoke(&self, session_id: &str, device_id: &str) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.retain(|key, _| key.0.as_str() != session_id || key.1.as_str() != device_id);
        }
    }

    pub fn revoke_session(&self, session_id: &str) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.retain(|key, _| key.0.as_str() != session_id);
        }
    }

    pub fn revoke_device(&self, device_id: &str) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.retain(|key, _| key.1.as_str() != device_id);
        }
    }

    pub fn retain_scope(&self, session_id: &str, device_id: &str, scope: &str) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.retain(|key, _| {
                key.0.as_str() != session_id
                    || key.1.as_str() != device_id
                    || key.2.as_str() == scope
                    || key.2.as_str() == "*"
            });
        }
    }

    pub fn revoke_scope(&self, session_id: &str, device_id: &str, scope: &str) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.remove(&(
                session_id.to_string(),
                device_id.to_string(),
                scope.to_string(),
            ));
        }
    }

    pub fn clear(&self) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.clear();
        }
    }
}

#[derive(Debug, Clone)]
pub struct RootPolicyConfig {
    pub policy: RootPolicy,
    pub roots: Vec<String>,
    pub excluded_roots: Vec<String>,
}

impl RootPolicyConfig {
    pub fn from_uci(
        explicit_policy: Option<&str>,
        roots: Vec<String>,
        excluded_roots: Vec<String>,
    ) -> Result<Self, String> {
        let policy = match explicit_policy {
            Some("allowlist") => RootPolicy::Allowlist,
            Some("denylist") => RootPolicy::Denylist,
            Some("unrestricted") => RootPolicy::Unrestricted,
            Some(value) => return Err(format!("Invalid root_policy '{value}'")),
            None if !roots.is_empty() || !excluded_roots.is_empty() => {
                return Err("root_policy must be set when root lists are configured".into());
            }
            None => RootPolicy::Unrestricted,
        };
        match policy {
            RootPolicy::Allowlist if roots.is_empty() => {
                return Err("root_policy 'allowlist' requires at least one root entry".into());
            }
            RootPolicy::Denylist if excluded_roots.is_empty() => {
                return Err(
                    "root_policy 'denylist' requires at least one exclude_root entry".into(),
                );
            }
            _ => {}
        }
        Ok(Self {
            policy,
            roots,
            excluded_roots,
        })
    }
}

pub struct AppState {
    pub settings: Settings,
    root_policy: std::sync::RwLock<RootPolicyConfig>,
    pub secret: Vec<u8>,
    pub started: i64,
    pub tasks: std::sync::Arc<crate::task_registry::TaskRegistry>,
    pub limits: crate::limits::Limits,
    pub sessions: crate::auth::Sessions,
    pub login_limiter: crate::auth::LoginLimiter,
    pub editor_io: tokio::sync::Semaphore,
    pub system_access: SystemAccess,
    pub terminal: std::sync::Arc<crate::terminal::Registry>,
}

impl Drop for AppState {
    fn drop(&mut self) {
        crate::ssh::close_all_sessions();
    }
}

impl AppState {
    pub fn new(settings: Settings) -> Arc<AppState> {
        ensure_auth_key(&settings.state_dir).expect("cannot load or create authentication key");
        let secret = load_or_create_secret(&settings.state_dir)
            .expect("cannot load or create daemon secret");
        let tasks = std::sync::Arc::new(crate::task_registry::TaskRegistry::new(
            settings.transfer_history,
        ));
        let limits = crate::limits::Limits::new(settings.max_connections, settings.max_transfers);
        let sessions = crate::auth::Sessions::new(settings.session_idle);
        let login_limiter = crate::auth::LoginLimiter::new();
        let root_policy = RootPolicyConfig {
            policy: settings.root_policy,
            roots: settings.roots.clone(),
            excluded_roots: settings.excluded_roots.clone(),
        };
        Arc::new(AppState {
            settings,
            root_policy: std::sync::RwLock::new(root_policy),
            secret,
            started: meta::now_secs(),
            tasks,
            limits,
            sessions,
            login_limiter,
            editor_io: tokio::sync::Semaphore::new(2),
            system_access: SystemAccess::new(),
            terminal: Default::default(),
        })
    }

    pub fn root_policy_config(&self) -> RootPolicyConfig {
        self.root_policy
            .read()
            .map(|config| config.clone())
            .unwrap_or_else(|_| RootPolicyConfig {
                policy: self.settings.root_policy,
                roots: self.settings.roots.clone(),
                excluded_roots: self.settings.excluded_roots.clone(),
            })
    }

    pub fn set_root_policy_config(&self, config: RootPolicyConfig) -> Result<(), ()> {
        let mut current = self.root_policy.write().map_err(|_| ())?;
        *current = config;
        Ok(())
    }

    pub fn uci(&self) -> Uci {
        config::load_uci(&self.settings.config_path)
    }

    pub fn prefs(&self) -> Prefs {
        Prefs::from_uci(&self.uci())
    }

    fn session_identity(&self, headers: &HeaderMap) -> Option<(String, String)> {
        let key = self.auth_key()?;
        let now = meta::now_secs();
        let token = auth::cookie_value(
            headers
                .get(axum::http::header::COOKIE)
                .and_then(|v| v.to_str().ok()),
            auth::COOKIE_NAME,
        )?;
        let payload = auth::verify_token(&key, &token, now)?;
        let perm = payload.get("perm").and_then(|v| v.as_str())?;
        if perm != "session" && perm != "write" {
            return None;
        }
        let id = payload.get("sid").and_then(|v| v.as_str())?;
        let username = payload.get("username").and_then(|v| v.as_str())?;
        if id.is_empty() || username.is_empty() || !self.sessions.touch(id, now) {
            return None;
        }
        Some((id.to_string(), username.to_string()))
    }

    pub fn session_id(&self, headers: &HeaderMap) -> Option<String> {
        self.session_identity(headers).map(|(id, _)| id)
    }

    pub fn session_username(&self, headers: &HeaderMap) -> Option<String> {
        self.session_identity(headers).map(|(_, username)| username)
    }

    pub fn system_access_allowed(&self, headers: &HeaderMap, device_id: &str, path: &str) -> bool {
        // Only local paths are resolved on this host. Remote callers should
        // resolve on the device and use SystemAccess::paths_allowed instead.
        let actual = if device_id.is_empty() {
            paths::canonical_for_policy(path).unwrap_or_else(|| path.to_string())
        } else {
            path.to_string()
        };
        let session = self.session_id(headers);
        self.system_access
            .paths_allowed(session.as_deref(), device_id, path, &actual)
    }

    pub fn auth_key(&self) -> Option<Vec<u8>> {
        let key = fs::read(format!("{}/auth.key", self.settings.state_dir)).ok()?;
        (key.len() == 32).then_some(key)
    }

    pub fn rotate_auth_key(&self) -> std::io::Result<()> {
        let key = auth::random_bytes(32);
        crate::private_file::atomic_replace(
            std::path::Path::new(&self.settings.state_dir),
            "auth.key",
            &key,
        )
    }

    pub fn password_hash(&self) -> Option<String> {
        fs::read_to_string(self.password_file())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn password_file(&self) -> String {
        format!("{}/password", self.settings.state_dir)
    }

    pub fn set_password(&self, password: &str) -> std::io::Result<()> {
        let hash = auth::hash_password(password);
        crate::private_file::atomic_replace(
            std::path::Path::new(&self.settings.state_dir),
            "password",
            hash.as_bytes(),
        )
    }
}

fn ensure_auth_key(state_dir: &str) -> std::io::Result<()> {
    let dir = std::path::Path::new(state_dir);
    let _lock = crate::private_file::lock_initialization(dir)?;
    match crate::private_file::read_private(dir, "auth.key", 32) {
        Ok(key) if key.len() == 32 => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid authentication key length",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::private_file::atomic_replace(dir, "auth.key", &auth::random_bytes(32))
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn load_or_create_secret(state_dir: &str) -> std::io::Result<Vec<u8>> {
    let dir = std::path::Path::new(state_dir);
    let _lock = crate::private_file::lock_initialization(dir)?;
    match crate::private_file::read_private(dir, "secret", 4096) {
        Ok(raw) => {
            let text = std::str::from_utf8(&raw).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid daemon secret")
            })?;
            let bytes = hex::decode(text.trim()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid daemon secret")
            })?;
            if bytes.len() < 16 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid daemon secret length",
                ));
            }
            Ok(bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let secret = auth::random_bytes(32);
            crate::private_file::atomic_replace(dir, "secret", hex::encode(&secret).as_bytes())?;
            Ok(secret)
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone)]
pub struct Ctx {
    pub st: Arc<AppState>,
    pub params: Params,
    pub method: Method,
    pub headers: HeaderMap,
}

impl Ctx {
    pub fn prefs(&self) -> Prefs {
        self.st.prefs()
    }

    pub fn is_post(&self) -> bool {
        self.method == Method::POST || self.method == Method::PUT || self.method == Method::PATCH
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    pub fn require_post(&self) -> ApiResult<()> {
        if self.is_post() {
            Ok(())
        } else {
            Err(ApiError::new(
                axum::http::StatusCode::METHOD_NOT_ALLOWED,
                1,
                "POST required",
            ))
        }
    }

    fn checked_path(&self, value: &str) -> ApiResult<String> {
        let path = paths::normalize_path(value).ok_or_else(ApiError::invalid_path)?;
        let policy_path = paths::canonical_for_policy(&path).ok_or_else(ApiError::invalid_path)?;
        if let Some(missing) = self.st.system_access.missing_path(
            self.st.session_id(&self.headers).as_deref(),
            "",
            &path,
            &policy_path,
        ) {
            return Err(ApiError::system_blocked_at(missing));
        }
        self.enforce_roots(&policy_path)?;
        Ok(path)
    }

    /// Resolve and authorize a path that will be read. The target may be
    /// missing; its nearest existing ancestor is still policy-checked.
    pub fn read_path(&self, value: &str) -> ApiResult<String> {
        self.checked_path(value)
    }

    /// Resolve and authorize an existing or replacement target for mutation.
    pub fn write_path(&self, value: &str) -> ApiResult<String> {
        self.checked_path(value)
    }

    /// Resolve and authorize a path intended to be newly created. Unlike a
    /// parent-only check, this checks the full prospective path against policy.
    pub fn create_path(&self, value: &str) -> ApiResult<String> {
        self.checked_path(value)
    }

    pub fn read_tree(&self, value: &str) -> ApiResult<()> {
        self.walk_checked(value, None, false)
    }

    pub fn write_tree(&self, value: &str) -> ApiResult<()> {
        self.walk_checked(value, None, true)
    }

    pub fn rename_tree(&self, source: &str, destination: &str) -> ApiResult<()> {
        self.walk_checked(source, Some(destination), true)
    }

    // Do not follow directory symlinks during traversal; checked_path still
    // resolves each node for policy, including every prospective rename target.
    fn walk_checked(&self, root: &str, destination: Option<&str>, write: bool) -> ApiResult<()> {
        let source = if write {
            self.write_path(root)?
        } else {
            self.read_path(root)?
        };
        let destination = destination.map(|path| self.create_path(path)).transpose()?;
        let mut pending = vec![(source, destination)];
        while let Some((source, destination)) = pending.pop() {
            let source = if write {
                self.write_path(&source)?
            } else {
                self.read_path(&source)?
            };
            if let Some(destination) = &destination {
                self.create_path(destination)?;
            }
            let Some(info) = crate::meta::lstat(&source) else {
                return Err(ApiError::new(
                    axum::http::StatusCode::NOT_FOUND,
                    1,
                    "Path not found",
                ));
            };
            if info.kind != crate::meta::Kind::Directory {
                continue;
            }
            let entries = std::fs::read_dir(&source).map_err(|_| {
                ApiError::new(
                    axum::http::StatusCode::FORBIDDEN,
                    1,
                    "Cannot inspect directory",
                )
            })?;
            for entry in entries {
                let entry = entry.map_err(|_| {
                    ApiError::new(
                        axum::http::StatusCode::FORBIDDEN,
                        1,
                        "Cannot inspect directory",
                    )
                })?;
                let name = entry.file_name().to_string_lossy().into_owned();
                pending.push((
                    paths::join_path(&source, &name),
                    destination.as_ref().map(|dir| paths::join_path(dir, &name)),
                ));
            }
        }
        Ok(())
    }

    fn enforce_roots(&self, path: &str) -> ApiResult<()> {
        let policy = self.st.root_policy_config();
        if paths::path_allowed_by_policy(policy.policy, &policy.roots, &policy.excluded_roots, path)
        {
            Ok(())
        } else {
            Err(ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                1,
                paths::root_policy_error(policy.policy),
            ))
        }
    }

    pub fn upload_base(&self, dir: &str, _prefs: &Prefs) -> bool {
        paths::is_valid_upload_base(
            &self.st,
            dir,
            self.st.system_access_allowed(&self.headers, "", dir),
        )
    }
}

#[cfg(test)]
mod secret_tests {
    use super::load_or_create_secret;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn secret_is_created_atomically_with_private_permissions_and_reused() {
        let dir = std::env::temp_dir().join(format!("harbor-state-secret-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let secret = load_or_create_secret(dir.to_str().unwrap()).unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(dir.join("secret")).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_or_create_secret(dir.to_str().unwrap()).unwrap(),
            secret
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn process_init_test_child() {
        let Ok(root) = std::env::var("HARBOR_TEST_PROCESS_INIT_ROOT") else {
            return;
        };
        let root = std::path::Path::new(&root);
        fs::write(root.join(format!("ready-{}", std::process::id())), b"ready").unwrap();
        let start = std::time::Instant::now();
        while !root.join("go").exists() {
            assert!(start.elapsed() < std::time::Duration::from_secs(15));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let path = root.join("state");
        let path_str = path.to_str().unwrap();
        super::ensure_auth_key(path_str).unwrap();
        let secret = load_or_create_secret(path_str).unwrap();
        println!(
            "PROCESS_CREDENTIALS:{}:{}",
            hex::encode(secret),
            hex::encode(fs::read(path.join("auth.key")).unwrap())
        );
    }

    #[test]
    fn credential_initialization_is_consistent_across_processes() {
        let root = std::env::temp_dir().join(format!(
            "harbor-state-process-{}",
            crate::uci::random_hex(8)
        ));
        fs::create_dir(&root).unwrap();
        let mut children = Vec::new();
        for _ in 0..12 {
            children.push(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "state::secret_tests::process_init_test_child",
                        "--nocapture",
                    ])
                    .env("HARBOR_TEST_PROCESS_INIT_ROOT", &root)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
        let start = std::time::Instant::now();
        while fs::read_dir(&root)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("ready-")
            })
            .count()
            < 12
        {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "credential children failed to start"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        fs::write(root.join("go"), b"go").unwrap();
        let mut observed = Vec::new();
        for child in children {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            let marker = text
                .split("PROCESS_CREDENTIALS:")
                .nth(1)
                .expect("missing credentials marker");
            observed.push(marker.lines().next().unwrap().to_string());
        }
        assert!(
            observed.iter().all(|value| value == &observed[0]),
            "processes did not observe the same secret and auth key: {observed:?}"
        );
        let state = root.join("state");
        let original_secret = fs::read(state.join("secret")).unwrap();
        let original_auth = fs::read(state.join("auth.key")).unwrap();
        // Existing owner-owned, non-private legacy files are tightened, not rotated.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(state.join("secret"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(state.join("auth.key"), fs::Permissions::from_mode(0o644)).unwrap();
        super::ensure_auth_key(state.to_str().unwrap()).unwrap();
        load_or_create_secret(state.to_str().unwrap()).unwrap();
        assert_eq!(fs::read(state.join("secret")).unwrap(), original_secret);
        assert_eq!(fs::read(state.join("auth.key")).unwrap(), original_auth);
        for file in ["secret", "auth.key"] {
            assert_eq!(
                fs::metadata(state.join(file)).unwrap().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::metadata(state).unwrap().mode() & 0o777, 0o700);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_initialization_uses_one_secret_and_key() {
        let dir =
            std::env::temp_dir().join(format!("harbor-state-race-{}", crate::uci::random_hex(8)));
        let path = dir.to_string_lossy().into_owned();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    super::ensure_auth_key(&path).unwrap();
                    load_or_create_secret(&path).unwrap()
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(results.iter().all(|value| value == &results[0]));
        assert_eq!(fs::read(dir.join("auth.key")).unwrap().len(), 32);
        assert_eq!(load_or_create_secret(&path).unwrap(), results[0]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn existing_secret_rejects_symlinks_hardlinks_and_linked_state_dir() {
        use std::os::unix::fs::symlink;
        let root =
            std::env::temp_dir().join(format!("harbor-state-links-{}", crate::uci::random_hex(8)));
        fs::create_dir_all(root.join("state")).unwrap();
        let outside = root.join("other");
        fs::write(&outside, hex::encode([9u8; 32])).unwrap();
        let state = root.join("state");
        let path = state.to_str().unwrap();
        symlink(&outside, state.join("secret")).unwrap();
        assert!(load_or_create_secret(path).is_err());
        fs::remove_file(state.join("secret")).unwrap();
        fs::hard_link(&outside, state.join("secret")).unwrap();
        assert!(load_or_create_secret(path).is_err());
        fs::remove_file(state.join("secret")).unwrap();
        symlink(&outside, state.join("auth.key")).unwrap();
        assert!(super::ensure_auth_key(path).is_err());
        symlink(&state, root.join("linked-state")).unwrap();
        assert!(load_or_create_secret(root.join("linked-state").to_str().unwrap()).is_err());
        assert_eq!(fs::read_to_string(outside).unwrap(), hex::encode([9u8; 32]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_existing_secret_is_not_silently_rotated() {
        let dir = std::env::temp_dir().join(format!(
            "harbor-state-invalid-secret-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("secret"), "not-hex").unwrap();
        assert_eq!(
            load_or_create_secret(dir.to_str().unwrap())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(fs::read_to_string(dir.join("secret")).unwrap(), "not-hex");
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod system_access_tests {
    use super::SystemAccess;

    #[test]
    fn symlinks_require_both_original_and_resolved_system_scopes() {
        let access = SystemAccess::new();
        assert!(access.paths_allowed(None, "", "/tmp/a", "/tmp/b"));
        assert!(!access.paths_allowed(None, "", "/bin/a", "/usr/bin/a"));
        access.grant("s", "", "/bin", 0);
        assert!(!access.paths_allowed(Some("s"), "", "/bin/a", "/usr/bin/a"));
        access.grant("s", "", "/usr", 0);
        assert!(access.paths_allowed(Some("s"), "", "/bin/a", "/usr/bin/a"));
        assert!(!access.paths_allowed(Some("s"), "other-device", "/bin/a", "/usr/bin/a"));
        access.revoke("s", "");
        access.grant("s", "", "*", 0);
        assert!(access.paths_allowed(Some("s"), "", "/bin/a", "/usr/bin/a"));
    }

    #[test]
    fn all_scope_grant_unlocks_every_system_root_for_one_device() {
        let access = SystemAccess::new();
        access.grant("session-a", "", "*", 0);
        assert!(access.allowed("session-a", "", "/etc"));
        assert!(access.allowed("session-a", "", "/usr"));
        access.retain_scope("session-a", "", "/etc");
        assert!(access.allowed("session-a", "", "/proc"));
        assert!(!access.allowed("session-a", "device-a", "/etc"));
    }

    #[test]
    fn grants_are_scoped_and_revocable() {
        let access = SystemAccess::new();
        access.grant("session-a", "", "/bin", 0);
        access.grant("session-a", "device-a", "/usr/bin", 0);
        access.grant("session-b", "", "/bin", 0);
        assert!(access.allowed("session-a", "", "/bin"));
        assert!(!access.allowed("session-a", "", "/proc"));
        assert!(access.allowed("session-a", "device-a", "/usr/bin"));
        access.revoke("session-a", "");
        assert!(!access.allowed("session-a", "", "/bin"));
        access.revoke_session("session-a");
        assert!(!access.allowed("session-a", "device-a", "/usr/bin"));
        access.grant("session-a", "", "/bin", 0);
        access.grant("session-a", "", "/usr/bin", 0);
        access.retain_scope("session-a", "", "/usr/bin");
        assert!(!access.allowed("session-a", "", "/bin"));
        assert!(access.allowed("session-a", "", "/usr/bin"));
        access.grant("session-a", "", "/bin", 0);
        access.revoke_scope("session-a", "", "/bin");
        assert!(!access.allowed("session-a", "", "/bin"));
        assert!(access.allowed("session-b", "", "/bin"));
    }
}
