use super::{mode_octal, open_session, SftpError};
use crate::paths::valid_component;
use crate::ssh::exec;
use crate::ssh::{runtime, Target};
use russh_sftp::protocol::FileType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpKind {
    File,
    Directory,
    Symlink,
    DirectoryLink,
    Special,
}

impl SftpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SftpKind::File => "file",
            SftpKind::Directory => "directory",
            SftpKind::Symlink => "symlink",
            SftpKind::DirectoryLink => "directory_link",
            SftpKind::Special => "special",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirItem {
    pub name: String,
    pub kind: SftpKind,
    pub size: i64,
    pub mtime: i64,
    pub mode: String,
    pub is_symlink: bool,
    pub link_target: String,
}

#[derive(Debug, Clone)]
pub struct DirListing {
    pub physical: String,
    pub items: Vec<DirItem>,
    pub available_bytes: i64,
    pub total_bytes: i64,
    pub used_bytes: i64,
    pub drives_raw: String,
}

pub fn list_dir(target: &Target, path: &str, capacity: bool) -> Result<DirListing, SftpError> {
    runtime::block_on(list_dir_async(target, path, capacity))
}

async fn list_dir_async(
    target: &Target,
    path: &str,
    capacity: bool,
) -> Result<DirListing, SftpError> {
    let (_lease, sftp) = open_session(target).await?;
    let physical = sftp
        .canonicalize(path)
        .await
        .map_err(|error| SftpError::Message(error.to_string()))?
        .to_string();
    let (available_bytes, total_bytes, used_bytes) = match sftp.fs_info(&physical).await {
        Ok(Some(info)) => {
            let fr = if info.fragment_size == 0 {
                1024
            } else {
                info.fragment_size
            };
            let total = info.blocks.saturating_mul(fr) as i64;
            let available = info.blocks_avail.saturating_mul(fr) as i64;
            let used = total.saturating_sub(available);
            (available, total, used)
        }
        _ => capacity_from_df(target, &physical).await,
    };
    let drives_raw = df_table(target).await;
    let mut items = Vec::new();
    if !capacity {
        let dir = sftp
            .read_dir(&physical)
            .await
            .map_err(|error| SftpError::Message(error.to_string()))?;
        for entry in dir {
            let name = entry.file_name().to_string();
            if !valid_component(&name) {
                continue;
            }
            let path = format!("{}/{}", physical.trim_end_matches('/'), name);
            let listed = entry.metadata();
            let lstat = if listed.permissions.is_none()
                && listed.size.is_none()
                && listed.mtime.is_none()
            {
                match sftp.symlink_metadata(&path).await {
                    Ok(meta) => meta,
                    Err(error) if super::is_unsupported(&error) => listed,
                    Err(_) => listed,
                }
            } else {
                listed
            };
            let is_link = lstat.file_type() == FileType::Symlink || lstat.is_symlink();
            let (kind, meta, link_target) = if is_link {
                let target_raw = sftp
                    .read_link(&path)
                    .await
                    .map(|value| value.to_string())
                    .unwrap_or_default();
                match sftp.metadata(&path).await {
                    Ok(followed) if followed.file_type() == FileType::Dir || followed.is_dir() => {
                        (SftpKind::DirectoryLink, followed, target_raw)
                    }
                    Ok(followed) => (SftpKind::Symlink, followed, target_raw),
                    Err(_) => (SftpKind::Symlink, lstat, target_raw),
                }
            } else {
                let kind = match lstat.file_type() {
                    FileType::Dir => SftpKind::Directory,
                    FileType::File => SftpKind::File,
                    FileType::Other => SftpKind::Special,
                    FileType::Symlink => SftpKind::Symlink,
                };
                (kind, lstat, String::new())
            };
            items.push(DirItem {
                name,
                kind,
                size: meta.size.unwrap_or(0) as i64,
                mtime: meta.mtime.unwrap_or(0) as i64,
                mode: mode_octal(meta.permissions),
                is_symlink: is_link,
                link_target,
            });
        }
        items.sort_by(|a, b| {
            let a_dir = matches!(a.kind, SftpKind::Directory | SftpKind::DirectoryLink);
            let b_dir = matches!(b.kind, SftpKind::Directory | SftpKind::DirectoryLink);
            b_dir
                .cmp(&a_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.name.cmp(&b.name))
        });
    }
    let _ = sftp.close().await;
    Ok(DirListing {
        physical,
        items,
        available_bytes,
        total_bytes,
        used_bytes,
        drives_raw,
    })
}

async fn capacity_from_df(target: &Target, path: &str) -> (i64, i64, i64) {
    let script = format!("df -Pk {}", crate::ssh::shell_quote(path));
    match exec_text(target, &script).await {
        Ok(text) => parse_df_line(text.lines().nth(1).unwrap_or("")),
        Err(_) => (0, 0, 0),
    }
}

async fn df_table(target: &Target) -> String {
    exec_text(target, "df -Pk")
        .await
        .map(|text| text.lines().skip(1).collect::<Vec<_>>().join("\n"))
        .unwrap_or_default()
}

async fn exec_text(target: &Target, script: &str) -> Result<String, String> {
    let output = exec::run_script(target, script, Some(30), 64 * 1024).await?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn parse_df_line(line: &str) -> (i64, i64, i64) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let kib = |index: usize| -> i64 {
        fields
            .get(index)
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0)
            * 1024
    };
    (kib(3), kib(1), kib(2))
}
