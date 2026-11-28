use crate::ssh::exec;
use crate::ssh::Target;
use russh_sftp::client::fs::Metadata;
use russh_sftp::protocol::FileType;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub fn ensure_mode(attrs: &mut Metadata, mode: u32) {
    attrs.permissions = Some(mode);
}

pub fn is_symlink_meta(meta: &Metadata) -> bool {
    meta.is_symlink() || meta.file_type() == FileType::Symlink
}

pub fn mode_bits(meta: &Metadata) -> u32 {
    meta.permissions.unwrap_or(0) & 0o777
}

pub fn is_regular_file(meta: &Metadata) -> bool {
    !is_symlink_meta(meta) && meta.file_type() == FileType::File
}

pub fn is_directory(meta: &Metadata) -> bool {
    !is_symlink_meta(meta) && (meta.file_type() == FileType::Dir || meta.is_dir())
}

fn uid_cache() -> &'static Mutex<HashMap<String, u32>> {
    static CACHE: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub async fn our_uid(target: &Target) -> Result<u32, super::SftpError> {
    if let Some(uid) = uid_cache()
        .lock()
        .ok()
        .and_then(|cache| cache.get(&target.id).copied())
    {
        return Ok(uid);
    }
    let output = exec::run_script(target, "id -u", Some(15), 64)
        .await
        .map_err(super::SftpError::Message)?;
    let uid = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|_| super::SftpError::Message("Cannot read remote uid".into()))?;
    if let Ok(mut cache) = uid_cache().lock() {
        cache.insert(target.id.clone(), uid);
    }
    Ok(uid)
}

pub fn owned_private(meta: &Metadata, uid: u32, mode: u32) -> bool {
    meta.uid == Some(uid) && mode_bits(meta) == mode
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingDirStatus {
    Accept,
    Reject,
}

pub fn staging_dir_status(meta: &Metadata, uid: u32) -> StagingDirStatus {
    if is_symlink_meta(meta) || !is_directory(meta) || !owned_private(meta, uid, 0o700) {
        StagingDirStatus::Reject
    } else {
        StagingDirStatus::Accept
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempFileDecision {
    Resume { size: u64 },
    Truncate,
    Reject,
}

pub fn decide_temp_file(
    meta: &Metadata,
    uid: u32,
    nlink_is_one: bool,
    resume_size: Option<u64>,
) -> TempFileDecision {
    if is_symlink_meta(meta) || !owned_private(meta, uid, 0o600) || !nlink_is_one {
        return TempFileDecision::Reject;
    }
    let size = meta.size.unwrap_or(0);
    match resume_size {
        Some(expected) if size > expected => TempFileDecision::Truncate,
        Some(_) => TempFileDecision::Resume { size },
        None => TempFileDecision::Truncate,
    }
}

pub fn dest_conflict(exists: bool, overwrite: bool) -> bool {
    exists && !overwrite
}

pub fn preserved_mode(meta: &Metadata) -> Option<u32> {
    is_regular_file(meta).then(|| mode_bits(meta))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFDIR: u32 = 0o040000;
    const IFREG: u32 = 0o100000;
    const IFLNK: u32 = 0o120000;

    fn meta(uid: u32, perm: u32, size: u64) -> Metadata {
        Metadata {
            uid: Some(uid),
            permissions: Some(perm),
            size: Some(size),
            ..Default::default()
        }
    }

    #[test]
    fn owned_private_requires_matching_uid_and_mode() {
        let dir = meta(1000, IFDIR | 0o700, 0);
        assert!(owned_private(&dir, 1000, 0o700));
        assert!(!owned_private(&dir, 1001, 0o700));
        assert!(!owned_private(&dir, 1000, 0o755));
        assert!(!owned_private(&meta(1000, IFREG | 0o600, 4), 1000, 0o700));
    }

    #[test]
    fn sftp_staging_rejects_symlinks_and_nonprivate_files() {
        let uid = 1000;
        assert_eq!(
            staging_dir_status(&meta(uid, IFLNK | 0o777, 0), uid),
            StagingDirStatus::Reject
        );
        assert_eq!(
            staging_dir_status(&meta(uid, IFDIR | 0o755, 0), uid),
            StagingDirStatus::Reject
        );
        assert_eq!(
            staging_dir_status(&meta(uid, IFREG | 0o700, 0), uid),
            StagingDirStatus::Reject
        );
        assert_eq!(
            staging_dir_status(&meta(uid, IFDIR | 0o700, 0), uid),
            StagingDirStatus::Accept
        );
        assert_eq!(
            decide_temp_file(&meta(uid, IFLNK | 0o777, 8), uid, true, Some(8)),
            TempFileDecision::Reject
        );
        assert_eq!(
            decide_temp_file(&meta(uid, IFREG | 0o644, 8), uid, true, Some(8)),
            TempFileDecision::Reject
        );
        assert_eq!(
            decide_temp_file(&meta(0, IFREG | 0o600, 8), uid, true, Some(8)),
            TempFileDecision::Reject
        );
        assert_eq!(
            decide_temp_file(&meta(uid, IFREG | 0o600, 8), uid, false, Some(8)),
            TempFileDecision::Reject
        );
    }

    #[test]
    fn upload_resumes_partial_file() {
        let meta = meta(7, IFREG | 0o600, 12);
        assert_eq!(
            decide_temp_file(&meta, 7, true, Some(40)),
            TempFileDecision::Resume { size: 12 }
        );
        assert_eq!(
            decide_temp_file(&meta, 7, true, Some(12)),
            TempFileDecision::Resume { size: 12 }
        );
    }

    #[test]
    fn truncates_oversized_partial() {
        assert_eq!(
            decide_temp_file(&meta(7, IFREG | 0o600, 50), 7, true, Some(40)),
            TempFileDecision::Truncate
        );
    }

    #[test]
    fn reports_zero_on_fresh_file() {
        // A missing temp body is created empty; staged size is 0.
        assert_eq!(
            decide_temp_file(&meta(7, IFREG | 0o600, 0), 7, true, Some(40)),
            TempFileDecision::Resume { size: 0 }
        );
    }

    #[test]
    fn rejects_conflicts_without_overwrite() {
        assert!(dest_conflict(true, false));
        assert!(!dest_conflict(true, true));
        assert!(!dest_conflict(false, false));
        assert!(!dest_conflict(false, true));
    }

    #[test]
    fn allows_overwrite_and_cleans_stale_partials() {
        assert_eq!(
            decide_temp_file(&meta(7, IFREG | 0o600, 20), 7, true, None),
            TempFileDecision::Truncate
        );
        assert_eq!(preserved_mode(&meta(7, IFREG | 0o640, 20)), Some(0o640));
        assert_eq!(preserved_mode(&meta(7, IFLNK | 0o777, 20)), None);
        assert_eq!(preserved_mode(&meta(7, IFDIR | 0o700, 0)), None);
    }
}
