//! russh transport: one Handle per device, SFTP for listing and file IO, exec for the rest.

mod auth;
mod exec;
mod pool;
mod runtime;
pub mod sftp;
mod terminal;

pub use auth::probe_host_key;
pub use exec::{
    capture_bounded, run_args, run_args_cancelled, run_args_once, spawn_download, spawn_upload,
    ByteStream,
};
pub use pool::pool_snapshot;
pub use terminal::{open_pty_login, PtySession};

use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct Target {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub host_key: String,
    pub idle_timeout_secs: u64,
    pub max_sessions: usize,
}

impl Default for Target {
    fn default() -> Self {
        Target {
            id: String::new(),
            host: String::new(),
            port: 22,
            username: String::new(),
            password: None,
            host_key: String::new(),
            idle_timeout_secs: 300,
            max_sessions: 4,
        }
    }
}

#[derive(Clone)]
pub struct Workspace {
    #[cfg_attr(not(test), allow(dead_code))]
    path: PathBuf,
}

impl Workspace {
    #[cfg(test)]
    pub fn ignored() -> Workspace {
        Workspace {
            path: PathBuf::from("/tmp/harbor_file_pro"),
        }
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn shared(root: &str, key: &str) -> Result<Workspace, String> {
        let path = Path::new(root).join(key);
        crate::tasks::ensure_private_dir(Path::new(root))
            .map_err(|_| "Unsafe runtime directory".to_string())?;
        crate::tasks::ensure_private_dir(&path)
            .map_err(|_| "Unsafe runtime directory".to_string())?;
        Ok(Workspace { path })
    }
}

pub fn reset_control(target: &Target) {
    runtime::block_on(pool::drop_key(target));
}

pub fn close_device_sessions(device_id: &str) {
    runtime::block_on(pool::close_device(device_id));
}

pub fn close_all_sessions() {
    runtime::block_on(pool::close_all());
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub const SCRIPT_EXEC_LIMIT: usize = 6000;

pub fn script_exec_len(script: &str) -> usize {
    6 + shell_quote(script).len()
}

pub fn chunk_script(lines: &[String]) -> Vec<String> {
    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();
    for line in lines {
        if current.is_empty() {
            current = line.clone();
            continue;
        }
        let candidate = format!("{current}\n{line}");
        if script_exec_len(&candidate) > SCRIPT_EXEC_LIMIT {
            chunks.push(std::mem::take(&mut current));
            current = line.clone();
        } else {
            current = candidate;
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

pub struct Output {
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
    pub stdout_read_failed: bool,
    pub stderr: Vec<u8>,
    pub status: Option<i32>,
    pub timed_out: bool,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == Some(0) && !self.timed_out
    }

    pub fn stderr_tail(&self, limit: usize) -> String {
        let text = String::from_utf8_lossy(&self.stderr).trim().to_string();
        if text.chars().count() <= limit {
            return text;
        }
        let skip = text.chars().count() - limit;
        text.chars().skip(skip).collect()
    }
}

#[cfg(test)]
pub(crate) static E2E_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn e2e_target(id: &str, idle_secs: u64) -> Option<Target> {
    let port = match std::env::var("HARBOR_E2E_SSH_PORT") {
        Ok(value) => value.parse::<u16>().expect("invalid HARBOR_E2E_SSH_PORT"),
        Err(_) => {
            eprintln!("SSH E2E not configured (HARBOR_E2E_SSH_PORT), skipped");
            return None;
        }
    };
    let username = std::env::var("HARBOR_E2E_SSH_USER").expect("missing HARBOR_E2E_SSH_USER");
    let password =
        std::env::var("HARBOR_E2E_SSH_PASSWORD").expect("missing HARBOR_E2E_SSH_PASSWORD");
    let host = std::env::var("HARBOR_E2E_SSH_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let mut target = Target {
        id: id.into(),
        host,
        port,
        username,
        password: Some(password),
        host_key: String::new(),
        idle_timeout_secs: idle_secs,
        max_sessions: 4,
    };
    match probe_host_key(&target, &Workspace::ignored()) {
        Ok((key, _)) => target.host_key = key,
        Err(error) => panic!("configured SSH E2E server is not reachable: {error}"),
    }
    Some(target)
}

#[cfg(test)]
pub(crate) fn e2e_state(
    target: &Target,
    allowed_root: &str,
) -> (Arc<crate::state::AppState>, PathBuf) {
    let root = std::env::temp_dir().join(format!("harbor-e2e-state-{}", crate::uci::random_hex(8)));
    std::fs::create_dir_all(&root).unwrap();
    let config_path = root.join("config");
    let mut config = crate::uci::Uci::default();
    {
        let section = config.ensure_section("remote_device", &target.id);
        section.set("name", "disposable SSH fixture");
        section.set("host", &target.host);
        section.set("port", &target.port.to_string());
        section.set("username", &target.username);
        section.set("revision", "e2e");
        section.set("host_key", &target.host_key);
    }
    config.ensure_section("harbor_file_pro", "main");
    std::fs::write(&config_path, config.serialize()).unwrap();
    let settings = crate::state::Settings {
        state_dir: root.join("state").to_string_lossy().into_owned(),
        config_path: config_path.to_string_lossy().into_owned(),
        root_policy: crate::state::RootPolicy::Allowlist,
        roots: vec![allowed_root.into()],
        ..Default::default()
    };
    let state = crate::state::AppState::new(settings);
    let mut secrets = crate::security::secret_store(&state);
    secrets.set(&target.id, target.password.as_deref().unwrap_or(""));
    secrets.save().unwrap();
    (state, root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_russh_exec_printf() {
        let _guard = E2E_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let target = e2e_target("cfg-e2e-exec", 60).expect("HARBOR_E2E_SSH_PORT");
        let output = crate::ssh::run_args(
            &target,
            &Workspace::ignored(),
            "printf 'harbor-exec-ok\\n'",
            &[],
            Some(15),
            4096,
        )
        .expect("russh exec");
        assert!(
            output.ok(),
            "status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("harbor-exec-ok"),
            "stdout={:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn script_exec_len_matches_command_line() {
        let script = "echo hi";
        assert_eq!(
            script_exec_len(script),
            format!("sh -c {}", shell_quote(script)).len()
        );
    }

    #[test]
    fn script_chunks_stay_under_exec_limit() {
        let lines: Vec<String> = (0..500)
            .map(|i| {
                format!(
                    "rm -rf {}",
                    shell_quote(&format!("/mnt/storage/downloads/backup_{i:04}.tar.gz"))
                )
            })
            .collect();
        let chunks = chunk_script(&lines);
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(script_exec_len(chunk) <= SCRIPT_EXEC_LIMIT);
        }
        assert_eq!(chunks.join("\n"), lines.join("\n"));
    }

    #[test]
    fn chunk_script_keeps_atomic_lines_whole() {
        let huge = format!("rm -rf {}", shell_quote(&"/".repeat(7000)));
        let lines = vec![huge.clone(), "rm -rf /tmp/x".to_string()];
        let chunks = chunk_script(&lines);
        assert_eq!(chunks, vec![huge, "rm -rf /tmp/x".to_string()]);
    }
}
