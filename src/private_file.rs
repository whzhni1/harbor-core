use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

pub fn atomic_replace(state_dir: &Path, name: &str, contents: &[u8]) -> io::Result<()> {
    let name_path = Path::new(name);
    if name.is_empty()
        || name_path.components().count() != 1
        || !matches!(name_path.components().next(), Some(Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private state filename must be a single normal path component",
        ));
    }

    fs::create_dir_all(state_dir)?;
    crate::tasks::ensure_private_dir(state_dir)?;
    let destination = state_dir.join(name);
    let (temp_path, mut file) = create_temp(state_dir, name)?;
    let write_result = (|| {
        file.write_all(contents)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.sync_all()
    })();
    drop(file);

    let result = write_result.and_then(|()| {
        fs::rename(&temp_path, &destination)?;
        OpenOptions::new().read(true).open(state_dir)?.sync_all()
    });
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

/// Serialize credential initialization across processes without ever locking
/// a symlink or a file owned by someone else. The caller must keep the
/// returned handle open for the complete read-or-create operation.
pub(crate) fn lock_initialization(state_dir: &Path) -> io::Result<fs::File> {
    fs::create_dir_all(state_dir)?;
    crate::tasks::ensure_private_dir(state_dir)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_dir.join(".init.lock"))?;
    check_private_regular(&file)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn check_private_regular(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file has an unsafe type, owner, or link count",
        ));
    }
    Ok(())
}

pub(crate) fn read_private(state_dir: &Path, name: &str, limit: u64) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_dir.join(name))?;
    check_private_regular(&file)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private file is too large",
        ));
    }
    Ok(bytes)
}

fn create_temp(state_dir: &Path, name: &str) -> io::Result<(PathBuf, fs::File)> {
    for _ in 0..128 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(".{name}.{}.{}.tmp", std::process::id(), id);
        let temp_path = state_dir.join(temp_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique private temporary file",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn test_dir() -> PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("harbor-private-file-{}-{id}", std::process::id()))
    }

    #[test]
    fn atomically_replaces_file_with_private_mode() {
        let dir = test_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("password");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        atomic_replace(&dir, "password", b"new secret").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new secret");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_nonlocal_filenames() {
        let dir = test_dir();
        assert_eq!(
            atomic_replace(&dir, "../password", b"secret")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!dir.exists());
    }
}
