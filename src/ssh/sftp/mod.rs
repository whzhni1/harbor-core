//! SFTP sessions are opened per operation on a pooled russh Handle.

mod download;
mod fs;
mod list;
mod staging;
mod upload;

pub use download::open_range;
pub use fs::{chmod, mkdir, remove_file, rename_exclusive, stat};
pub use list::list_dir;
pub use upload::{commit_upload, spawn_upload_stream};

use super::pool;
use super::runtime;
use super::Target;
use russh::ChannelMsg;
use russh_sftp::client::{Config, SftpSession};
use std::time::Duration;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpStatus {
    Ready,
    Missing,
    Disabled,
}

#[derive(Debug)]
pub enum SftpError {
    Message(String),
    Missing,
    Disabled,
    TimedOut,
    Unknown(String),
}

impl SftpError {
    pub fn message(&self) -> String {
        match self {
            SftpError::Message(text) | SftpError::Unknown(text) => text.clone(),
            SftpError::Missing | SftpError::Disabled => {
                "sftp subsystem is not available; install openssh-sftp-server".into()
            }
            SftpError::TimedOut => "SFTP request timed out".into(),
        }
    }
}

impl From<SftpError> for String {
    fn from(error: SftpError) -> Self {
        error.message()
    }
}

pub fn sftp_config() -> Config {
    Config {
        max_concurrent_writes: 16,
        max_write_packet_len: 32768,
        request_timeout_secs: 30,
        ..Config::default()
    }
}

pub async fn open_session(target: &Target) -> Result<(pool::ChannelGuard, SftpSession), SftpError> {
    let lease = pool::lease(target)
        .await
        .map_err(|error| SftpError::Message(error.to_string()))?;
    let mut channel = lease
        .open_session()
        .await
        .map_err(|error| SftpError::Message(error.to_string()))?;
    match timeout(
        Duration::from_secs(15),
        channel.request_subsystem(true, "sftp"),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(SftpError::Missing),
        Err(_) => return Err(SftpError::TimedOut),
    }
    let wait = timeout(Duration::from_secs(15), async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => return Ok(()),
                Some(ChannelMsg::Failure) | None => return Err(SftpError::Missing),
                Some(_) => {}
            }
        }
    });
    match wait.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err(SftpError::TimedOut),
    }
    let session = match timeout(
        Duration::from_secs(15),
        SftpSession::new_with_config(channel.into_stream(), sftp_config()),
    )
    .await
    {
        Ok(Ok(session)) => session,
        Ok(Err(_)) => return Err(SftpError::Disabled),
        Err(_) => return Err(SftpError::TimedOut),
    };
    Ok((lease, session))
}

pub fn ensure_sftp(target: &Target) -> Result<SftpStatus, String> {
    runtime::block_on(async {
        match open_session(target).await {
            Ok((_lease, session)) => {
                let _ = session.close().await;
                Ok(SftpStatus::Ready)
            }
            Err(SftpError::Missing) => Ok(SftpStatus::Missing),
            Err(SftpError::Disabled) => Ok(SftpStatus::Disabled),
            Err(error) => Err(error.message()),
        }
    })
}

pub(crate) fn is_unsupported(error: &russh_sftp::client::error::Error) -> bool {
    match error {
        russh_sftp::client::error::Error::Status(status) => {
            status.status_code == russh_sftp::protocol::StatusCode::OpUnsupported
        }
        other => other
            .to_string()
            .to_ascii_lowercase()
            .contains("unsupported"),
    }
}

pub(crate) fn mode_octal(permissions: Option<u32>) -> String {
    format!("{:o}", permissions.unwrap_or(0) & 0o7777)
}
