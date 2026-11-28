use super::fs::commit_rename;
use super::{open_session, SftpError};
use crate::ssh::exec;
use crate::ssh::{runtime, Target};
use russh_sftp::client::fs::{File, Metadata};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::io::Write;
use std::pin::Pin;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

pub struct UploadSink {
    session: Option<SftpSession>,
    file: Option<File>,
    _lease: crate::ssh::pool::ChannelGuard,
    pub staged: u64,
    pub temp_file: String,
    pub dest: String,
}

impl UploadSink {
    pub fn write_all(&mut self, data: &[u8]) -> Result<(), String> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| "Upload is already closed".to_string())?;
        runtime::block_on(async { Pin::new(file).write_all(data).await })
            .map_err(|error| error.to_string())?;
        self.staged = self.staged.saturating_add(data.len() as u64);
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), String> {
        runtime::block_on(async {
            if let Some(file) = self.file.take() {
                file.sync_all().await.map_err(|error| error.to_string())?;
                file.close().await.map_err(|error| error.to_string())?;
            }
            if let Some(session) = self.session.take() {
                let _ = session.close().await;
            }
            Ok::<(), String>(())
        })
    }
}

impl Write for UploadSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_all(buf).map_err(std::io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for UploadSink {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            runtime::spawn(async move {
                let _ = file.close().await;
            });
        }
    }
}

pub fn open_upload(
    target: &Target,
    dir: &str,
    name: &str,
    temp_dir: &str,
    overwrite: bool,
    resume_size: Option<u64>,
) -> Result<UploadSink, SftpError> {
    runtime::block_on(open_upload_async(
        target,
        dir,
        name,
        temp_dir,
        overwrite,
        resume_size,
    ))
}

async fn open_upload_async(
    target: &Target,
    dir: &str,
    name: &str,
    temp_dir: &str,
    overwrite: bool,
    resume_size: Option<u64>,
) -> Result<UploadSink, SftpError> {
    let (lease, sftp) = open_session(target).await?;
    let dest = format!("{}/{}", dir.trim_end_matches('/'), name);
    if super::staging::dest_conflict(sftp.try_exists(&dest).await.unwrap_or(false), overwrite) {
        let _ = sftp.close().await;
        return Err(SftpError::Message("upload target already exists".into()));
    }
    let _ = sftp.create_dir(dir).await;
    match sftp.symlink_metadata(temp_dir).await {
        Ok(meta) => {
            let uid = super::staging::our_uid(target).await?;
            if super::staging::staging_dir_status(&meta, uid)
                == super::staging::StagingDirStatus::Reject
            {
                return Err(SftpError::Message("invalid upload staging path".into()));
            }
        }
        Err(_) => {
            sftp.create_dir(temp_dir)
                .await
                .map_err(|error| SftpError::Message(error.to_string()))?;
            let mut attrs = Metadata::default();
            super::staging::ensure_mode(&mut attrs, 0o700);
            let _ = sftp.set_metadata(temp_dir, attrs).await;
        }
    }
    let temp_file = format!("{}/body", temp_dir.trim_end_matches('/'));
    let mut staged = 0u64;
    if sftp.try_exists(&temp_file).await.unwrap_or(false) {
        let meta = sftp
            .symlink_metadata(&temp_file)
            .await
            .map_err(|error| SftpError::Message(error.to_string()))?;
        let uid = super::staging::our_uid(target).await?;
        let nlink = nlink_is_one(target, &temp_file).await;
        match super::staging::decide_temp_file(&meta, uid, nlink, resume_size) {
            super::staging::TempFileDecision::Reject => {
                return Err(SftpError::Message("invalid upload staging path".into()));
            }
            super::staging::TempFileDecision::Truncate => {
                let flags = OpenFlags::WRITE | OpenFlags::TRUNCATE | OpenFlags::CREATE;
                let file = sftp
                    .open_with_flags(&temp_file, flags)
                    .await
                    .map_err(|error| SftpError::Message(error.to_string()))?;
                let _ = file.close().await;
                staged = 0;
            }
            super::staging::TempFileDecision::Resume { size } => staged = size,
        }
    } else {
        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE;
        let file = sftp
            .open_with_flags(&temp_file, flags)
            .await
            .map_err(|error| SftpError::Message(error.to_string()))?;
        let mut attrs = Metadata::default();
        super::staging::ensure_mode(&mut attrs, 0o600);
        let _ = sftp.set_metadata(&temp_file, attrs).await;
        let _ = file.close().await;
    }
    let flags = OpenFlags::READ | OpenFlags::WRITE;
    let mut file = sftp
        .open_with_flags(&temp_file, flags)
        .await
        .map_err(|error| SftpError::Message(error.to_string()))?;
    if staged > 0 {
        file.seek(std::io::SeekFrom::Start(staged))
            .await
            .map_err(|error| SftpError::Message(error.to_string()))?;
    }
    Ok(UploadSink {
        session: Some(sftp),
        file: Some(file),
        _lease: lease,
        staged,
        temp_file,
        dest,
    })
}

async fn nlink_is_one(target: &Target, path: &str) -> bool {
    let script = format!("stat -c '%h' {}", crate::ssh::shell_quote(path));
    exec::run_script(target, &script, Some(15), 4096)
        .await
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        })
        == Some(1)
}

pub fn spawn_upload_stream(
    target: &Target,
    dir: &str,
    name: &str,
    temp_dir: &str,
    overwrite: bool,
    resume_size: Option<u64>,
) -> Result<(crate::ssh::ByteStream, u64), SftpError> {
    let mut sink = open_upload(target, dir, name, temp_dir, overwrite, resume_size)?;
    let staged = sink.staged;
    let dest = sink.dest.clone();
    let temp_file = sink.temp_file.clone();
    let (stdin_r, stdin_w) = unix_pipe().map_err(SftpError::Message)?;
    let (stdout_r, mut stdout_w) = unix_pipe().map_err(SftpError::Message)?;
    let (stderr_r, stderr_w) = unix_pipe().map_err(SftpError::Message)?;
    let _ = writeln!(stdout_w, "READY {staged}");
    drop(stdout_w);
    drop(stderr_w);
    let exit = std::sync::Arc::new((
        std::sync::Mutex::new(None::<i32>),
        std::sync::Condvar::new(),
    ));
    let closing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let exit_out = std::sync::Arc::clone(&exit);
    let closing_out = std::sync::Arc::clone(&closing);
    runtime::spawn_attached("harbor-sftp-upload", move || {
        use std::io::Read;
        use std::os::unix::io::AsRawFd;
        let mut stdin = stdin_r;
        let fd = stdin.as_raw_fd();
        let mut buf = [0u8; 32 * 1024];
        let mut code = 0i32;
        loop {
            if closing_out.load(std::sync::atomic::Ordering::Relaxed) {
                code = 1;
                break;
            }
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, 200) };
            if rc < 0 {
                code = 1;
                break;
            }
            if rc == 0 {
                continue;
            }
            if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                code = 1;
                break;
            }
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if sink.write_all(&buf[..n]).is_err() {
                        code = 1;
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    code = 1;
                    break;
                }
            }
        }
        if code == 0 && sink.finish().is_err() {
            code = 1;
        }
        if let Ok(mut guard) = exit_out.0.lock() {
            *guard = Some(code);
            exit_out.1.notify_all();
        }
        let _ = dest;
        let _ = temp_file;
    })
    .map_err(|error| SftpError::Message(error.to_string()))?;
    Ok((
        crate::ssh::ByteStream::from_pipes(stdin_w, stdout_r, stderr_r, exit, closing),
        staged,
    ))
}

fn unix_pipe() -> Result<(std::fs::File, std::fs::File), String> {
    use std::os::fd::{FromRawFd, RawFd};
    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err("Cannot create pipe".to_string());
    }
    Ok(unsafe {
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        )
    })
}

pub fn commit_upload(
    target: &Target,
    temp_file: &str,
    dest: &str,
    staged: u64,
    overwrite: bool,
    preserve: bool,
) -> Result<(), SftpError> {
    runtime::block_on(async {
        // Bytes are already on the staging file. Any transport failure from
        // here on can mean the destination was published; report unknown.
        let (_lease, sftp) = open_session(target)
            .await
            .map_err(|error| SftpError::Unknown(error.message()))?;
        let meta = sftp
            .metadata(temp_file)
            .await
            .map_err(|error| SftpError::Unknown(error.to_string()))?;
        if meta.size.unwrap_or(0) != staged {
            let _ = sftp.close().await;
            return Err(SftpError::Message("upload size does not match".into()));
        }
        if preserve {
            if let Ok(existing) = sftp.symlink_metadata(dest).await {
                if let Some(mode) = super::staging::preserved_mode(&existing) {
                    let mut attrs = Metadata::default();
                    super::staging::ensure_mode(&mut attrs, mode);
                    let _ = sftp.set_metadata(temp_file, attrs).await;
                }
            }
        }
        if overwrite {
            let _ = sftp.close().await;
            return commit_rename(target, temp_file, dest).await;
        }
        if sftp.symlink_metadata(dest).await.is_ok() {
            let _ = sftp.close().await;
            return Err(SftpError::Message("upload target already exists".into()));
        }
        let result = sftp
            .rename(temp_file, dest)
            .await
            .map_err(|error| SftpError::Unknown(error.to_string()));
        let _ = sftp.close().await;
        result
    })
}
