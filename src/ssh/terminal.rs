use super::pool;
use super::runtime;
use super::Target;
use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct PtySession {
    pub input: File,
    pub output: File,
    resize: mpsc::UnboundedSender<(u32, u32)>,
    closing: Arc<AtomicBool>,
    _lease: pool::ChannelGuard,
}

impl PtySession {
    pub fn write_input(&self, data: &[u8]) -> std::io::Result<()> {
        let mut input = self.input.try_clone()?;
        input.write_all(data)?;
        input.flush()
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.resize.send((cols as u32, rows as u32));
    }

    pub fn kill(&self) {
        self.closing.store(true, Ordering::Relaxed);
    }
}

async fn wait_channel_success(channel: &mut Channel<Msg>, what: &str) -> Result<(), String> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => {
                return Err(format!("Remote SSH {what} request was refused"));
            }
            Some(ChannelMsg::Close) | None => {
                return Err(format!("SSH channel closed before {what} started"));
            }
            Some(_) => {}
        }
    }
}

fn unix_pipe() -> Result<(File, File), String> {
    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err("Cannot create pipe".to_string());
    }
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

#[cfg(test)]
pub fn open_pty(target: &Target, cols: u16, rows: u16) -> Result<PtySession, String> {
    runtime::block_on(open_pty_async(target, cols, rows, false))
}

pub fn open_pty_login(target: &Target, cols: u16, rows: u16) -> Result<PtySession, String> {
    runtime::block_on(open_pty_async(target, cols, rows, true))
}

async fn request_session_pty(
    channel: &mut Channel<Msg>,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let modes = [
        (russh::Pty::ECHO, 1),
        (russh::Pty::ECHOE, 1),
        (russh::Pty::ECHOK, 1),
        (russh::Pty::ECHONL, 0),
        (russh::Pty::ICANON, 1),
        (russh::Pty::ICRNL, 1),
        (russh::Pty::IEXTEN, 1),
        (russh::Pty::ISIG, 1),
        (russh::Pty::IUTF8, 1),
        (russh::Pty::OPOST, 1),
        (russh::Pty::ONLCR, 1),
        (russh::Pty::CS8, 1),
        (russh::Pty::TTY_OP_ISPEED, 38400),
        (russh::Pty::TTY_OP_OSPEED, 38400),
    ];
    channel
        .request_pty(
            true,
            "xterm-256color",
            cols as u32,
            rows as u32,
            0,
            0,
            &modes,
        )
        .await
        .map_err(|error| error.to_string())?;
    wait_channel_success(channel, "PTY").await
}

async fn open_pty_async(
    target: &Target,
    cols: u16,
    rows: u16,
    login: bool,
) -> Result<PtySession, String> {
    let lease = pool::lease_terminal(target).await?;
    let mut channel = lease.open_session().await?;
    request_session_pty(&mut channel, cols, rows).await?;
    let mut started_login = false;
    if login {
        started_login = channel.exec(true, "/bin/login").await.is_ok()
            && wait_channel_success(&mut channel, "login").await.is_ok();
        if !started_login {
            drop(channel);
            channel = lease.open_session().await?;
            request_session_pty(&mut channel, cols, rows).await?;
        }
    }
    if !started_login {
        channel
            .request_shell(true)
            .await
            .map_err(|error| error.to_string())?;
        wait_channel_success(&mut channel, "shell").await?;
    }
    let (out_r, out_w) = unix_pipe()?;
    let (in_r, in_w) = unix_pipe()?;
    let (resize_tx, mut resize_rx) = mpsc::unbounded_channel::<(u32, u32)>();
    let closing = Arc::new(AtomicBool::new(false));
    let closing_task = Arc::clone(&closing);
    runtime::spawn_attached("harbor-ssh-pty", move || {
        runtime::block_on(pump_pty(channel, in_r, out_w, &mut resize_rx, closing_task));
    })
    .map_err(|_| "Cannot start SSH terminal".to_string())?;
    Ok(PtySession {
        input: in_w,
        output: out_r,
        resize: resize_tx,
        closing,
        _lease: lease,
    })
}

async fn pump_pty(
    channel: Channel<Msg>,
    mut stdin: File,
    mut stdout: File,
    resize: &mut mpsc::UnboundedReceiver<(u32, u32)>,
    closing: Arc<AtomicBool>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut read_half, write_half) = channel.split();
    let mut writer = write_half.make_writer();
    let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let stdin_thread = std::thread::Builder::new()
        .name("harbor-ssh-pty-in".into())
        .spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stdin_tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
        .expect("ssh pty stdin thread");
    let mut reader = read_half.make_reader();
    let mut buf = [0u8; 8192];
    loop {
        if closing.load(Ordering::Relaxed) {
            let _ = write_half.close().await;
            break;
        }
        tokio::select! {
            size = resize.recv() => {
                if let Some((cols, rows)) = size {
                    let _ = write_half.window_change(cols, rows, 0, 0).await;
                } else {
                    break;
                }
            }
            chunk = stdin_rx.recv() => {
                match chunk {
                    Some(chunk) => {
                        if writer.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            n = reader.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stdout.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = stdout.flush();
                    }
                }
            }
        }
    }
    drop(stdout);
    let _ = stdin_thread.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::Duration;

    fn read_pty(reader: &mut File, deadline: std::time::Instant) -> Vec<u8> {
        use std::os::fd::AsRawFd;
        let mut collected = Vec::new();
        let mut buf = [0u8; 4096];
        while std::time::Instant::now() < deadline {
            let remain = deadline.saturating_duration_since(std::time::Instant::now());
            let mut pfd = libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut pfd, 1, remain.as_millis() as i32) };
            if n <= 0 {
                break;
            }
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => collected.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        collected
    }

    #[ignore = "needs HARBOR_E2E_SSH_PORT"]
    #[test]
    fn e2e_russh_pty_runs_a_remote_command() {
        let _guard = crate::ssh::E2E_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let target = crate::ssh::e2e_target("cfg-e2e-pty", 60).expect("HARBOR_E2E_SSH_PORT");
        let pty = open_pty(&target, 80, 24).expect("russh PTY");
        let mut reader = pty.output.try_clone().expect("pty stdout");
        let mut bytes = read_pty(
            &mut reader,
            std::time::Instant::now() + Duration::from_secs(2),
        );
        pty.write_input(b"printf harbor-pty-ok\r")
            .expect("pty stdin");
        bytes.extend(read_pty(
            &mut reader,
            std::time::Instant::now() + Duration::from_secs(3),
        ));
        pty.kill();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !bytes.is_empty(),
            "russh PTY produced no output from the remote shell"
        );
        assert!(
            text.contains("harbor-pty-ok"),
            "remote PTY accepted a command, output was {text:?}"
        );
    }
}
