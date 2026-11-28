//! Long running background jobs (archive, extraction, package install, thumbnails).
//!
//! State, log and exit-code files keep the exact layout of the ucode backend so a
//! downgrade (or a LuCI page reading them) still works.

use serde_json::Value;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

pub fn runtime_dir() -> String {
    "/tmp/harbor_file_pro".to_string()
}

// The parent must itself be trusted (or be the sticky system /tmp). Open
// without following a final symlink and check ownership *before* chmod; an
// attacker must not be able to point a privileged daemon at their directory.
fn open_owned_dir(path: &Path, expected_uid: u32) -> std::io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.uid() != expected_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "runtime directory has an unsafe owner",
        ));
    }
    Ok(file)
}

pub(crate) fn check_private_dir(path: &Path) -> std::io::Result<()> {
    let file = open_owned_dir(path, unsafe { libc::geteuid() })?;
    if file.metadata()?.mode() & 0o7777 != 0o700 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "runtime directory is not private",
        ));
    }
    Ok(())
}

pub(crate) fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    let file = open_owned_dir(path, unsafe { libc::geteuid() })?;
    file.set_permissions(fs::Permissions::from_mode(0o700))?;
    if file.metadata()?.mode() & 0o7777 != 0o700 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cannot secure runtime directory",
        ));
    }
    Ok(())
}

pub(crate) fn create_private_dir(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    ensure_private_dir(path)
}

pub fn ensure_runtime_dir() -> bool {
    ensure_private_dir(Path::new(&runtime_dir())).is_ok()
}

/// Legacy task links and resumable-upload leases share one runtime directory.
/// Prevent multiple daemons from manipulating those resources concurrently.
pub(crate) fn lock_runtime_instance() -> std::io::Result<fs::File> {
    lock_runtime_instance_at(Path::new(&runtime_dir()))
}

fn lock_runtime_instance_at(dir: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::io::AsRawFd;
    ensure_private_dir(dir)?;
    let path = dir.join("daemon.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unsafe daemon lock file",
        ));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "another Harbor daemon owns the shared runtime",
            ));
        }
        return Err(error);
    }
    Ok(file)
}

pub(crate) fn ensure_remote_dir() -> std::io::Result<()> {
    ensure_private_dir(Path::new(&runtime_dir()))?;
    ensure_private_dir(Path::new(crate::remote::REMOTE_ROOT))
}

pub fn read_state(file: &str) -> Option<Value> {
    let raw = fs::read_to_string(file).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn write_state(file: &str, value: &Value) -> bool {
    if !ensure_runtime_dir() {
        return false;
    }
    let tmp = format!("{file}.tmp");
    let text = match serde_json::to_string(value) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if fs::write(&tmp, text).is_err() {
        return false;
    }
    fs::rename(&tmp, file).is_ok()
}

pub fn process_alive(pid: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
    match stat.ok().and_then(|value| {
        value
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.chars().next())
    }) {
        Some('Z' | 'X') => false,
        Some(_) => true,
        None => fs::metadata(format!("/proc/{pid}")).is_ok(),
    }
}

pub fn task_running(file: &str, rcfile: &str) -> bool {
    if task_finished(rcfile) {
        return false;
    }
    match read_state(file) {
        Some(state) => {
            let done = state.get("done").and_then(|v| v.as_bool()).unwrap_or(false);
            let pid = state.get("pid").and_then(|v| v.as_i64()).unwrap_or(0);
            !done && pid > 0 && process_alive(pid)
        }
        None => false,
    }
}

pub fn task_exit_code(rcfile: &str) -> i64 {
    fs::read_to_string(rcfile)
        .ok()
        .and_then(|t| t.trim().parse::<i64>().ok())
        .unwrap_or(-1)
}

pub fn task_finished(rcfile: &str) -> bool {
    fs::read_to_string(rcfile)
        .ok()
        .map(|t| t.trim().parse::<i64>().is_ok())
        .unwrap_or(false)
}

pub fn truncate_log(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut start = text.len() - limit;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    format!("...{}", &text[start..])
}

pub fn read_log(path: &str, limit: usize) -> String {
    truncate_log(&fs::read_to_string(path).unwrap_or_default(), limit)
}

pub fn spawn_logged(
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    log: &str,
    rc: &str,
    header: &str,
) -> Option<i64> {
    if !ensure_runtime_dir() {
        return None;
    }
    let _ = fs::remove_file(rc);

    const SCRIPT: &str = r#"
log="$1"; rc="$2"; header="$3"; shift 3
{
  if [ -n "$header" ]; then printf '$ %s\n' "$header"; fi
  "$@"
} >"$log" 2>&1
code=$?
{
  printf '\n'
  printf -- '-- exit %s\n' "$code"
} >>"$log"
printf '%s' "$code" >"$rc"
exit 0
"#;
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(SCRIPT)
        .arg("harbor-task")
        .arg(log)
        .arg(rc)
        .arg(header)
        .arg(program);
    for a in args {
        cmd.arg(a);
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let pid = child.id() as i64;
    let _ = std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
    Some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn process_lock_test_child() {
        let Ok(dir) = std::env::var("HARBOR_TEST_PROCESS_LOCK_DIR") else {
            return;
        };
        match std::env::var("HARBOR_TEST_PROCESS_LOCK_ACTION")
            .unwrap()
            .as_str()
        {
            "hold" => {
                let _lock = lock_runtime_instance_at(Path::new(&dir)).unwrap();
                fs::write(Path::new(&dir).join("ready"), b"ready").unwrap();
                let start = std::time::Instant::now();
                while !Path::new(&dir).join("release").exists() {
                    assert!(
                        start.elapsed() < std::time::Duration::from_secs(15),
                        "lock release timed out"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            "busy" => assert_eq!(
                lock_runtime_instance_at(Path::new(&dir))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::AddrInUse
            ),
            "free" => {
                let _lock = lock_runtime_instance_at(Path::new(&dir)).unwrap();
            }
            _ => panic!("invalid lock test action"),
        }
    }

    #[test]
    fn runtime_lock_is_exclusive_across_processes_and_released_on_exit() {
        let dir =
            std::env::temp_dir().join(format!("harbor-process-lock-{}", crate::uci::random_hex(8)));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let child = |action: &str| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "tasks::tests::process_lock_test_child",
                    "--nocapture",
                ])
                .env("HARBOR_TEST_PROCESS_LOCK_DIR", &dir)
                .env("HARBOR_TEST_PROCESS_LOCK_ACTION", action);
            command
        };
        let mut holder = child("hold").spawn().unwrap();
        let start = std::time::Instant::now();
        while !dir.join("ready").exists() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "lock holder did not start"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            fs::metadata(&dir).unwrap().mode() & 0o777,
            0o700,
            "legacy owned directory tightened"
        );
        assert_eq!(
            fs::metadata(dir.join("daemon.lock")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(child("busy").status().unwrap().success());
        // An ungraceful daemon death must also release the advisory lock.
        holder.kill().unwrap();
        holder.wait().unwrap();
        assert!(child("free").status().unwrap().success());
        fs::remove_file(dir.join("daemon.lock")).unwrap();
        let outside = dir.join("outside");
        fs::write(&outside, b"keep").unwrap();
        symlink(&outside, dir.join("daemon.lock")).unwrap();
        assert!(lock_runtime_instance_at(&dir).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        fs::remove_file(dir.join("daemon.lock")).unwrap();
        fs::hard_link(&outside, dir.join("daemon.lock")).unwrap();
        assert!(lock_runtime_instance_at(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_directories_reject_symlinks_files_and_wrong_owners() {
        let root =
            std::env::temp_dir().join(format!("harbor-private-dir-{}", crate::uci::random_hex(8)));
        fs::create_dir(&root).unwrap();
        let real = root.join("real");
        create_private_dir(&real).unwrap();
        assert_eq!(fs::metadata(&real).unwrap().mode() & 0o7777, 0o700);
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_private_dir(&real).is_err());
        ensure_private_dir(&real).unwrap();
        assert!(check_private_dir(&real).is_ok());
        let uid = unsafe { libc::geteuid() };
        assert!(open_owned_dir(&real, uid.wrapping_add(1)).is_err());
        let link = root.join("link");
        symlink(&real, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
        assert!(check_private_dir(&link).is_err());
        assert_eq!(fs::metadata(&real).unwrap().mode() & 0o7777, 0o700);
        let regular = root.join("file");
        fs::write(&regular, b"unchanged").unwrap();
        assert!(ensure_private_dir(&regular).is_err());
        assert_eq!(fs::read(&regular).unwrap(), b"unchanged");
        assert!(create_private_dir(&real).is_err());
        // Optional true cross-UID fixture for environments able to provision one.
        if let Ok(foreign) = std::env::var("HARBOR_TEST_FOREIGN_DIR") {
            let foreign = Path::new(&foreign);
            let before = fs::symlink_metadata(foreign).unwrap();
            assert_ne!(
                before.uid(),
                uid,
                "foreign directory must have another owner"
            );
            assert!(ensure_private_dir(foreign).is_err());
            assert!(check_private_dir(foreign).is_err());
            assert_eq!(
                fs::symlink_metadata(foreign).unwrap().mode(),
                before.mode(),
                "must not chmod a foreign directory"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
