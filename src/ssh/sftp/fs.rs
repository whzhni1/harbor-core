use super::{open_session, SftpError};
use crate::ssh::{runtime, Target};
use russh_sftp::client::fs::Metadata;
use russh_sftp::protocol::FileType;

#[derive(Debug, Clone)]
pub struct RemoteMeta {
    pub kind: String,
}

pub fn stat(target: &Target, path: &str) -> Result<RemoteMeta, SftpError> {
    runtime::block_on(stat_async(target, path))
}

async fn stat_async(target: &Target, path: &str) -> Result<RemoteMeta, SftpError> {
    let (_lease, sftp) = open_session(target).await?;
    let lstat = sftp
        .symlink_metadata(path)
        .await
        .map_err(|error| SftpError::Message(error.to_string()))?;
    let is_link = lstat.file_type() == FileType::Symlink || lstat.is_symlink();
    let meta = if is_link {
        sftp.metadata(path).await.unwrap_or(lstat.clone())
    } else {
        lstat.clone()
    };
    let kind = if meta.file_type() == FileType::Dir || meta.is_dir() {
        "directory"
    } else if is_link {
        "symlink"
    } else if meta.file_type() == FileType::File {
        "file"
    } else {
        "special"
    }
    .to_string();
    let _ = sftp.close().await;
    Ok(RemoteMeta { kind })
}

pub fn mkdir(target: &Target, path: &str, mode: u32) -> Result<(), SftpError> {
    runtime::block_on(async {
        let (_lease, sftp) = open_session(target).await?;
        sftp.create_dir(path)
            .await
            .map_err(|error| SftpError::Message(error.to_string()))?;
        let attrs = Metadata {
            permissions: Some(mode),
            ..Default::default()
        };
        let _ = sftp.set_metadata(path, attrs).await;
        let _ = sftp.close().await;
        Ok(())
    })
}

pub fn remove_file(target: &Target, path: &str) -> Result<(), SftpError> {
    runtime::block_on(async {
        let (_lease, sftp) = open_session(target).await?;
        sftp.remove_file(path)
            .await
            .map_err(|error| SftpError::Message(error.to_string()))?;
        let _ = sftp.close().await;
        Ok(())
    })
}

pub fn rename_exclusive(target: &Target, from: &str, to: &str) -> Result<(), SftpError> {
    runtime::block_on(async {
        let (_lease, sftp) = open_session(target).await?;
        if sftp.symlink_metadata(to).await.is_ok() {
            let _ = sftp.close().await;
            return Err(SftpError::Message("target already exists".into()));
        }
        let result = sftp
            .rename(from, to)
            .await
            .map_err(|error| SftpError::Message(error.to_string()));
        let _ = sftp.close().await;
        result
    })
}

pub async fn commit_rename(target: &Target, from: &str, to: &str) -> Result<(), SftpError> {
    let (_lease, sftp) = open_session(target)
        .await
        .map_err(|error| SftpError::Unknown(error.message()))?;
    let result = match sftp.posix_rename(from, to).await {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => match sftp.rename(from, to).await {
            Ok(()) => Ok(()),
            Err(_) => {
                // Dest may already be gone after this remove. A later failure
                // cannot prove the previous target is intact.
                let _ = sftp.remove_file(to).await;
                match sftp.rename(from, to).await {
                    Ok(()) => Ok(()),
                    Err(error) => Err(SftpError::Unknown(error.to_string())),
                }
            }
        },
    };
    let _ = sftp.close().await;
    result
}

pub fn chmod(target: &Target, path: &str, mode: u32) -> Result<(), SftpError> {
    runtime::block_on(async {
        let (_lease, sftp) = open_session(target).await?;
        let attrs = Metadata {
            permissions: Some(mode),
            ..Default::default()
        };
        sftp.set_metadata(path, attrs)
            .await
            .map_err(|error| SftpError::Message(error.to_string()))?;
        let _ = sftp.close().await;
        Ok(())
    })
}
