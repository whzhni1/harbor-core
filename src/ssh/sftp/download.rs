use super::{open_session, SftpError};
use crate::ssh::{runtime, Target};
use russh_sftp::client::fs::File;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncSeekExt, ReadBuf};

pub struct RangeBody {
    file: File,
    remaining: u64,
    _session: SftpSession,
    _lease: crate::ssh::pool::ChannelGuard,
}

impl AsyncRead for RangeBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.remaining == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut scratch = [0u8; 32 * 1024];
        let max = buf
            .remaining()
            .min(self.remaining as usize)
            .min(scratch.len());
        if max == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut inner = ReadBuf::new(&mut scratch[..max]);
        match Pin::new(&mut self.file).poll_read(cx, &mut inner) {
            Poll::Ready(Ok(())) => {
                let filled = inner.filled().len();
                buf.put_slice(&scratch[..filled]);
                self.remaining = self.remaining.saturating_sub(filled as u64);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

pub fn open_range(
    target: &Target,
    path: &str,
    offset: u64,
    len: u64,
) -> Result<RangeBody, SftpError> {
    runtime::block_on(open_range_async(target, path, offset, len))
}

async fn open_range_async(
    target: &Target,
    path: &str,
    offset: u64,
    len: u64,
) -> Result<RangeBody, SftpError> {
    let (lease, sftp) = open_session(target).await?;
    let mut file = sftp
        .open_with_flags(path, OpenFlags::READ)
        .await
        .map_err(|error| SftpError::Message(error.to_string()))?;
    if offset > 0 {
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|error| SftpError::Message(error.to_string()))?;
    }
    Ok(RangeBody {
        file,
        remaining: len,
        _session: sftp,
        _lease: lease,
    })
}
