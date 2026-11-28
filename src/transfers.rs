#[cfg(test)]
use crate::task_registry::TaskRegistry as Registry;
pub use crate::task_registry::{Status, Task as Transfer};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;

pub fn upload_dir() -> String {
    format!("{}/uploads", crate::tasks::runtime_dir())
}

pub fn ensure_upload_dir() -> Option<String> {
    let dir = upload_dir();
    let path = std::path::Path::new(&dir);
    if !crate::tasks::ensure_runtime_dir() || crate::tasks::ensure_private_dir(path).is_err() {
        return None;
    }
    Some(dir)
}

pub(crate) fn upload_dir_is_private() -> bool {
    crate::tasks::check_private_dir(std::path::Path::new(&crate::tasks::runtime_dir())).is_ok()
        && crate::tasks::check_private_dir(std::path::Path::new(&upload_dir())).is_ok()
}

fn staging_root_is_private(root: &std::path::Path) -> bool {
    let Some(parent) = root.parent() else {
        return false;
    };
    root.file_name() == Some(std::ffi::OsStr::new("uploads"))
        && parent.file_name() == Some(std::ffi::OsStr::new(".harbor_file_pro"))
        && crate::tasks::check_private_dir(parent).is_ok()
        && crate::tasks::check_private_dir(root).is_ok()
}

pub(crate) fn staging_session_is_private(path: &std::path::Path, id: &std::ffi::OsStr) -> bool {
    path.file_name() == Some(id)
        && path.parent().is_some_and(staging_root_is_private)
        && crate::tasks::check_private_dir(path).is_ok()
}

fn ensure_staging_root(mount: &str) -> Option<std::path::PathBuf> {
    let parent = std::path::Path::new(mount).join(".harbor_file_pro");
    crate::tasks::ensure_private_dir(&parent).ok()?;
    let root = parent.join("uploads");
    crate::tasks::ensure_private_dir(&root).ok()?;
    Some(root)
}

fn unescape_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn mount_entries() -> Vec<(String, String, String)> {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mut entries = Vec::new();
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let mount = unescape_mount(fields[1]);
        if !mount.starts_with('/')
            || entries
                .iter()
                .any(|entry: &(String, String, String)| entry.0 == mount)
        {
            continue;
        }
        entries.push((mount, fields[2].to_string(), fields[3].to_string()));
    }
    entries
}

fn upload_mount_allowed(mount: &str, fs_type: &str, options: &str) -> bool {
    if mount == "/" || mount == "/tmp" || options.split(',').any(|option| option == "ro") {
        return false;
    }
    if [
        "tmpfs",
        "ramfs",
        "devtmpfs",
        "proc",
        "sysfs",
        "squashfs",
        "cgroup",
        "cgroup2",
        "overlay",
        "overlayfs",
        "rootfs",
    ]
    .contains(&fs_type)
    {
        return false;
    }
    !["/proc", "/sys", "/dev", "/run", "/rom", "/overlay"]
        .iter()
        .any(|prefix| mount == *prefix || mount.starts_with(&format!("{prefix}/")))
}

fn device_id(path: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|metadata| metadata.dev())
}

pub fn select_upload_staging_root(
    total_size: u64,
    chunk_size: u64,
    target_dir: &str,
) -> Option<String> {
    let entries = mount_entries();
    let target_device = device_id(target_dir);
    let margin = crate::meta::OPERATION_SPACE_MARGIN;
    let mut candidates: Vec<(String, u64)> = entries
        .iter()
        .filter(|(mount, fs_type, options)| upload_mount_allowed(mount, fs_type, options))
        .filter_map(|(mount, _, _)| {
            crate::meta::space_info(mount)
                .available
                .map(|available| (mount.clone(), available))
        })
        .collect();
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.1));
    candidates.push((
        "/tmp".to_string(),
        crate::meta::space_info("/tmp").available.unwrap_or(0),
    ));

    for (mount, available) in candidates {
        let same_filesystem = target_device.is_some_and(|device| device_id(&mount) == Some(device));
        let transient_chunk = if same_filesystem {
            chunk_size.min(total_size)
        } else {
            0
        };
        let needed = total_size
            .saturating_add(transient_chunk)
            .saturating_add(margin);
        if available < needed {
            continue;
        }
        let Some(root) = ensure_staging_root(&mount) else {
            continue;
        };
        let root = root.to_string_lossy().into_owned();
        if crate::meta::space_info(&root)
            .available
            .is_some_and(|free| free >= needed)
        {
            return Some(root);
        }
    }
    None
}

fn modified_secs(path: &std::path::Path) -> Option<i64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs() as i64)
}

fn upload_staging_roots() -> Vec<std::path::PathBuf> {
    let mut roots: Vec<std::path::PathBuf> = mount_entries()
        .into_iter()
        .filter(|(mount, fs_type, options)| upload_mount_allowed(mount, fs_type, options))
        .map(|(mount, _, _)| std::path::PathBuf::from(format!("{mount}/.harbor_file_pro/uploads")))
        .collect();
    roots.push(std::path::PathBuf::from("/tmp/.harbor_file_pro/uploads"));
    roots.sort();
    roots.dedup();
    roots
}

fn purge_session(path: &std::path::Path) -> bool {
    let meta_path = path.join("meta.json");
    if let Ok(raw) = std::fs::read_to_string(&meta_path) {
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            let session_name = path.file_name();
            if let Some(staging) = value.get("staging_dir").and_then(Value::as_str) {
                let staging = std::path::Path::new(staging);
                let valid_stage =
                    session_name.is_some_and(|name| staging_session_is_private(staging, name));
                if valid_stage {
                    let _ = std::fs::remove_dir_all(staging);
                }
            }
            if value.get("phase").and_then(Value::as_str) != Some("published") {
                if let (Some(id), Some(target_dir)) = (
                    session_name.and_then(std::ffi::OsStr::to_str),
                    value.get("dir").and_then(Value::as_str),
                ) {
                    use std::os::unix::fs::MetadataExt;
                    let temp =
                        std::path::Path::new(target_dir).join(format!(".harbor-upload-{id}.part"));
                    if std::fs::symlink_metadata(&temp).is_ok_and(|m| {
                        m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.nlink() == 1
                    }) {
                        let _ = std::fs::remove_file(temp);
                    }
                }
            }
        }
    }
    std::fs::remove_dir_all(path).is_ok()
}

pub fn destroy_upload_session(id: &str) -> bool {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte.is_ascii_hexdigit());
    if !valid {
        return false;
    }
    if !upload_dir_is_private() {
        return false;
    }
    let path = std::path::Path::new(&upload_dir()).join(id);
    if crate::tasks::check_private_dir(&path).is_err() {
        return false;
    }
    purge_session(&path)
}

pub fn remove_empty_staging_roots() {
    for root in upload_staging_roots() {
        if !staging_root_is_private(&root) {
            continue;
        }
        if std::fs::read_dir(&root)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false)
        {
            let _ = std::fs::remove_dir(&root);
            if let Some(parent) = root.parent() {
                let _ = std::fs::remove_dir(parent);
            }
        }
    }
}

pub fn clean_orphan_staging(max_age_hours: u64) {
    let dir = upload_dir();
    if !upload_dir_is_private() {
        return;
    }
    let cutoff = crate::meta::now_secs()
        - (max_age_hours.max(1).min(i64::MAX as u64) as i64).saturating_mul(3600);
    let mut removed = 0;
    for root in upload_staging_roots() {
        if !staging_root_is_private(&root) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if crate::tasks::check_private_dir(&path).is_err() {
                continue;
            }
            let metadata_dir = std::path::Path::new(&dir).join(entry.file_name());
            // An existing metadata directory may belong to another instance,
            // or to an init currently creating its meta.json; never touch it.
            if !matches!(std::fs::symlink_metadata(metadata_dir), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound)
            {
                continue;
            }
            if modified_secs(&path).is_some_and(|stamp| stamp < cutoff)
                && std::fs::remove_dir_all(&path).is_ok()
            {
                removed += 1;
            }
        }
    }
    remove_empty_staging_roots();
    if removed > 0 {
        eprintln!("harbor-core: removed {removed} orphan upload staging area(s)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_progress_and_terminal_states() {
        let registry = Registry::new(16);
        let transfer = registry.create("upload", "/mnt/a.bin", 100);
        transfer.set_status(Status::Running);
        transfer.add(40);
        let value = transfer.json();
        assert_eq!(value["transferred"], 40);
        assert_eq!(value["remaining"], 60);
        assert_eq!(value["status"], "running");
        transfer.set_status(Status::Completed);
        assert_eq!(transfer.status(), Status::Completed);
        transfer.set_status(Status::Running);
        assert_eq!(transfer.status(), Status::Completed);
    }

    #[test]
    fn cancellation_sticks() {
        let registry = Registry::new(16);
        let transfer = registry.create("download", "/mnt/b.bin", 10);
        assert!(registry.cancel(&transfer.id));
        assert!(transfer.cancelled());
        assert_eq!(
            transfer.status(),
            Status::Queued,
            "request is not completion"
        );
        assert_eq!(transfer.json()["cancel_requested"], true);
        assert_eq!(transfer.json()["cancelable"], false);
        transfer.finish_download(Status::Completed, None);
        assert_eq!(transfer.status(), Status::Cancelled);
        assert!(!registry.cancel(&transfer.id));
        assert!(!registry.cancel("missing"));
    }

    #[test]
    fn history_is_bounded() {
        let registry = Registry::new(8);
        for index in 0..32 {
            let transfer = registry.create("upload", &format!("/mnt/{index}"), 1);
            transfer.set_status(Status::Completed);
        }
        assert!(registry.list().len() <= 8);
    }

    #[test]
    fn active_transfers_are_never_evicted_but_new_uploads_have_admission_limit() {
        let registry = Registry::new(8);
        let mut ids = Vec::new();
        for index in 0..256 {
            ids.push(
                registry
                    .create("download", &format!("/mnt/{index}"), 1)
                    .id
                    .clone(),
            );
        }
        assert_eq!(registry.active(), 256);
        assert!(ids.iter().all(|id| registry.get(id).is_some()));
        assert_eq!(registry.list().len(), 256);
        assert!(registry.try_create_upload("/mnt/new", 1).is_none());
        for id in &ids {
            registry.get(id).unwrap().set_status(Status::Completed);
        }
        assert!(registry.try_create_upload("/mnt/new", 1).is_some());
        assert!(registry.list().len() <= 9);
    }

    #[test]
    fn staging_cleanup_refuses_symlink_and_nonprivate_directories() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let sandbox = std::env::temp_dir().join(format!(
            "harbor-staging-safety-{}",
            crate::uci::random_hex(8)
        ));
        std::fs::create_dir(&sandbox).unwrap();
        let root = ensure_staging_root(sandbox.to_str().unwrap()).unwrap();
        let session = root.join("123-abcdef");
        crate::tasks::create_private_dir(&session).unwrap();
        assert!(staging_session_is_private(
            &session,
            std::ffi::OsStr::new("123-abcdef")
        ));
        assert!(!staging_session_is_private(
            &session,
            std::ffi::OsStr::new("another")
        ));
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!staging_root_is_private(&root));
        ensure_staging_root(sandbox.to_str().unwrap()).unwrap();
        let metadata = sandbox.join("metadata");
        std::fs::create_dir(&metadata).unwrap();
        let meta_session = metadata.join("123-abcdef");
        std::fs::create_dir(&meta_session).unwrap();
        let outside = sandbox.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("marker"), b"keep").unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        symlink(&outside, &root).unwrap();
        assert!(!staging_root_is_private(&root));
        assert!(ensure_staging_root(sandbox.to_str().unwrap()).is_none());
        std::fs::write(
            meta_session.join("meta.json"),
            json!({"staging_dir":root.join("123-abcdef")}).to_string(),
        )
        .unwrap();
        assert!(purge_session(&meta_session));
        assert_eq!(std::fs::read(outside.join("marker")).unwrap(), b"keep");
        std::fs::remove_dir_all(sandbox).unwrap();
    }

    #[test]
    fn upload_staging_excludes_root_and_system_mounts() {
        assert!(!upload_mount_allowed("/", "ext4", "rw"));
        assert!(!upload_mount_allowed("/overlay", "overlay", "rw"));
        assert!(!upload_mount_allowed("/mnt/data", "rootfs", "rw"));
        assert!(!upload_mount_allowed("/tmp", "tmpfs", "rw"));
        assert!(upload_mount_allowed("/mnt/usb", "vfat", "rw"));
    }
}
