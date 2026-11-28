use super::pool;
use super::runtime;
use super::{Output, Target, Workspace};
use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tokio::time::timeout;

pub fn remote_command(script: &str, args: &[String]) -> String {
    let mut line = format!("sh -c {}", super::shell_quote(script));
    if !args.is_empty() {
        line.push_str(" sh");
        for arg in args {
            line.push(' ');
            line.push_str(&super::shell_quote(arg));
        }
    }
    line
}

pub fn capture_bounded(mut reader: impl Read, limit: usize) -> (Vec<u8>, bool, bool) {
    let mut captured = Vec::new();
    let mut truncated = false;
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return (captured, truncated, false),
            Ok(n) => {
                let keep = n.min(limit.saturating_sub(captured.len()));
                captured.extend_from_slice(&buffer[..keep]);
                truncated |= keep != n;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return (captured, truncated, true),
        }
    }
}

struct RunOptions {
    timeout: Option<u64>,
    limit: usize,
    cancelled: Option<Arc<AtomicBool>>,
    retry: bool,
}

pub fn run_args(
    target: &Target,
    _workspace: &Workspace,
    script: &str,
    args: &[String],
    timeout_secs: Option<u64>,
    limit: usize,
) -> Result<Output, String> {
    run_inner(
        target,
        script,
        args,
        RunOptions {
            timeout: timeout_secs,
            limit,
            cancelled: None,
            retry: true,
        },
    )
}

pub fn run_args_once(
    target: &Target,
    _workspace: &Workspace,
    script: &str,
    args: &[String],
    timeout_secs: Option<u64>,
    limit: usize,
) -> Result<Output, String> {
    run_inner(
        target,
        script,
        args,
        RunOptions {
            timeout: timeout_secs,
            limit,
            cancelled: None,
            retry: false,
        },
    )
}

pub fn run_args_cancelled(
    target: &Target,
    _workspace: &Workspace,
    script: &str,
    args: &[String],
    timeout_secs: Option<u64>,
    limit: usize,
    cancelled: Arc<AtomicBool>,
) -> Result<Output, String> {
    run_inner(
        target,
        script,
        args,
        RunOptions {
            timeout: timeout_secs,
            limit,
            cancelled: Some(cancelled),
            retry: true,
        },
    )
}

fn run_inner(
    target: &Target,
    script: &str,
    args: &[String],
    options: RunOptions,
) -> Result<Output, String> {
    runtime::block_on(run_inner_async(target, script, args, options))
}

pub(crate) async fn run_script(
    target: &Target,
    script: &str,
    timeout_secs: Option<u64>,
    limit: usize,
) -> Result<Output, String> {
    run_inner_async(
        target,
        script,
        &[],
        RunOptions {
            timeout: timeout_secs,
            limit,
            cancelled: None,
            retry: true,
        },
    )
    .await
}

async fn run_inner_async(
    target: &Target,
    script: &str,
    args: &[String],
    options: RunOptions,
) -> Result<Output, String> {
    let command = remote_command(script, args);
    let mut retries = 0u8;
    loop {
        if options
            .cancelled
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            return Err("SSH command cancelled".to_string());
        }
        match run_once(target, &command, &options).await {
            Ok(output) => {
                let lost = output.status.is_none() && !output.timed_out;
                if options.retry && retries < 1 && lost {
                    retries += 1;
                    pool::drop_key(target).await;
                    continue;
                }
                return Ok(output);
            }
            Err(error) if options.retry && retries < 1 && is_lost(&error) => {
                retries += 1;
                pool::drop_key(target).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_lost(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("connection")
        || lower.contains("closed")
        || lower.contains("reset")
        || lower.contains("broken pipe")
        || lower.contains("senderror")
}

async fn run_once(target: &Target, command: &str, options: &RunOptions) -> Result<Output, String> {
    let lease = pool::lease(target).await?;
    let mut channel = lease.open_session().await?;
    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    let collect = collect_output(&mut channel, options.limit, options.cancelled.clone());
    let output = if let Some(seconds) = options.timeout {
        match timeout(Duration::from_secs(seconds), collect).await {
            Ok(result) => result?,
            Err(_) => {
                // Close only stops local reads. The remote process may become an
                // orphan, same as killing a local ssh client did.
                let _ = channel.close().await;
                Output {
                    stdout: Vec::new(),
                    stdout_truncated: false,
                    stdout_read_failed: false,
                    stderr: Vec::new(),
                    status: None,
                    timed_out: true,
                }
            }
        }
    } else {
        collect.await?
    };
    Ok(output)
}

async fn collect_output(
    channel: &mut Channel<Msg>,
    limit: usize,
    cancelled: Option<Arc<AtomicBool>>,
) -> Result<Output, String> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut truncated = false;
    let mut status = None;
    let mut tick = tokio::time::interval(Duration::from_millis(40));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if cancelled.as_ref().is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                    // Close only stops local reads. The remote process may become an
                    // orphan, same as killing a local ssh client did.
                    let _ = channel.close().await;
                    return Err("SSH command cancelled".to_string());
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        let keep = (limit.saturating_sub(stdout.len())).min(data.len());
                        stdout.extend_from_slice(&data[..keep]);
                        truncated |= keep != data.len();
                    }
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                        let keep = (64 * 1024usize).saturating_sub(stderr.len()).min(data.len());
                        stderr.extend_from_slice(&data[..keep]);
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        status = Some(exit_status as i32);
                    }
                    Some(ChannelMsg::Eof) => {}
                    Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
            }
        }
    }
    Ok(Output {
        stdout,
        stdout_truncated: truncated,
        stdout_read_failed: false,
        stderr,
        status,
        timed_out: false,
    })
}

fn unix_pipe() -> Result<(File, File), String> {
    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err("Cannot create pipe".to_string());
    }
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

enum Backend {
    Process {
        child: Mutex<Child>,
        group: bool,
    },
    Remote {
        exit: Arc<(Mutex<Option<i32>>, Condvar)>,
        closing: Arc<AtomicBool>,
        _lease: Option<pool::ChannelGuard>,
    },
}

pub struct ByteStream {
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
    backend: Backend,
}

#[derive(Clone)]
pub struct AbortHandle {
    process: Option<(u32, bool)>,
    closing: Option<Arc<AtomicBool>>,
}

fn kill_process_group(pid: u32) {
    if pid <= 1 {
        return;
    }
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
        libc::kill(pid as i32, libc::SIGKILL);
    }
    // After the session leader is reaped, kill(-pgid) can miss members that
    // were reparented to init. Sweep /proc for leftover pgrp/session mates.
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(member) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if member <= 1 {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{member}/stat")) else {
            continue;
        };
        let Some(rest) = stat.rsplit_once(')').map(|(_, rest)| rest) else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let _state = fields.next();
        let _ppid = fields.next();
        let pgrp = fields.next().and_then(|value| value.parse::<u32>().ok());
        let session = fields.next().and_then(|value| value.parse::<u32>().ok());
        if pgrp == Some(pid) || session == Some(pid) {
            unsafe {
                libc::kill(member as i32, libc::SIGKILL);
            }
        }
    }
}

impl AbortHandle {
    pub fn abort(&self) {
        if let Some((pid, group)) = self.process {
            if pid > 1 {
                if group {
                    kill_process_group(pid);
                } else {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
            }
        }
        if let Some(flag) = &self.closing {
            flag.store(true, Ordering::Relaxed);
        }
    }
}

pub struct StreamOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: i32,
}

impl StreamOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

impl ByteStream {
    pub fn from_child(mut child: Child, group: bool) -> Result<Self, String> {
        Ok(ByteStream {
            stdin: child.stdin.take().map(into_file),
            stdout: child.stdout.take().map(into_file),
            stderr: child.stderr.take().map(into_file),
            backend: Backend::Process {
                child: Mutex::new(child),
                group,
            },
        })
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        match &self.backend {
            Backend::Process { child, .. } => child
                .lock()
                .map_err(|_| std::io::Error::other("lock"))?
                .try_wait()
                .map(|status| status.and_then(|s| s.code())),
            Backend::Remote { exit, .. } => Ok(*exit.0.lock().unwrap_or_else(|e| e.into_inner())),
        }
    }

    pub fn wait(&mut self) -> std::io::Result<i32> {
        match &self.backend {
            Backend::Process { child, .. } => child
                .lock()
                .map_err(|_| std::io::Error::other("lock"))?
                .wait()
                .map(|status| status.code().unwrap_or(-1)),
            Backend::Remote { exit, .. } => {
                let (lock, cv) = &**exit;
                let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                while guard.is_none() {
                    guard = cv.wait(guard).unwrap_or_else(|e| e.into_inner());
                }
                Ok((*guard).unwrap_or(-1))
            }
        }
    }

    pub fn abort_handle(&self) -> AbortHandle {
        match &self.backend {
            Backend::Process { child, group } => AbortHandle {
                process: Some((child.lock().map(|child| child.id()).unwrap_or(0), *group)),
                closing: None,
            },
            Backend::Remote { closing, .. } => AbortHandle {
                process: None,
                closing: Some(Arc::clone(closing)),
            },
        }
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        match &self.backend {
            Backend::Process { child, group } => {
                let mut child = child.lock().map_err(|_| std::io::Error::other("lock"))?;
                if *group {
                    kill_process_group(child.id());
                }
                let _ = child.kill();
                Ok(())
            }
            Backend::Remote { closing, .. } => {
                closing.store(true, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub fn id(&self) -> u32 {
        match &self.backend {
            Backend::Process { child, .. } => child.lock().map(|c| c.id()).unwrap_or(0),
            Backend::Remote { .. } => 0,
        }
    }

    pub fn wait_with_output(mut self) -> std::io::Result<StreamOutput> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut pipe) = self.stdout.take() {
            let _ = pipe.read_to_end(&mut stdout);
        }
        if let Some(mut pipe) = self.stderr.take() {
            let _ = pipe.read_to_end(&mut stderr);
        }
        drop(self.stdin.take());
        let status = self.wait()?;
        Ok(StreamOutput {
            stdout,
            stderr,
            status,
        })
    }
}

fn into_file<T: IntoRawFd>(value: T) -> File {
    unsafe { File::from_raw_fd(value.into_raw_fd()) }
}

impl ByteStream {
    pub fn from_pipes(
        stdin: File,
        stdout: File,
        stderr: File,
        exit: Arc<(Mutex<Option<i32>>, Condvar)>,
        closing: Arc<AtomicBool>,
    ) -> Self {
        ByteStream {
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
            backend: Backend::Remote {
                exit,
                closing,
                _lease: None,
            },
        }
    }
}

pub fn spawn_download(
    target: &Target,
    _workspace: &Workspace,
    script: &str,
) -> Result<ByteStream, String> {
    spawn_stream(target, script, false)
}

pub fn spawn_upload(
    target: &Target,
    _workspace: &Workspace,
    script: &str,
) -> Result<ByteStream, String> {
    spawn_stream(target, script, true)
}

fn spawn_stream(target: &Target, script: &str, with_stdin: bool) -> Result<ByteStream, String> {
    runtime::block_on(spawn_stream_async(target, script, with_stdin))
}

async fn spawn_stream_async(
    target: &Target,
    script: &str,
    with_stdin: bool,
) -> Result<ByteStream, String> {
    let lease = pool::lease(target).await?;
    let channel = lease.open_session().await?;
    let command = remote_command(script, &[]);
    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    let (stdout_r, stdout_w) = unix_pipe()?;
    let (stderr_r, stderr_w) = unix_pipe()?;
    let (stdin_r, stdin_w) = if with_stdin {
        let (r, w) = unix_pipe()?;
        (Some(r), Some(w))
    } else {
        (None, None)
    };
    let exit = Arc::new((Mutex::new(None::<i32>), Condvar::new()));
    let closing = Arc::new(AtomicBool::new(false));
    let exit_out = Arc::clone(&exit);
    let closing_out = Arc::clone(&closing);
    runtime::spawn_attached("harbor-ssh-exec", move || {
        runtime::block_on(pump_channel(
            channel,
            stdin_r,
            stdout_w,
            stderr_w,
            exit_out,
            closing_out,
        ));
    })
    .map_err(|_| "Cannot start SSH stream".to_string())?;
    Ok(ByteStream {
        stdin: stdin_w,
        stdout: Some(stdout_r),
        stderr: Some(stderr_r),
        backend: Backend::Remote {
            exit,
            closing,
            _lease: Some(lease),
        },
    })
}

async fn pump_channel(
    mut channel: Channel<Msg>,
    stdin: Option<File>,
    mut stdout: File,
    mut stderr: File,
    exit: Arc<(Mutex<Option<i32>>, Condvar)>,
    closing: Arc<AtomicBool>,
) {
    // Read-only exec still needs channel EOF. Remote tar/cat otherwise wait
    // forever on an open stdin, which hung e2e_tar_streams.
    if stdin.is_none() {
        let _ = channel.eof().await;
    }
    let stdin_task = stdin.map(|mut stdin| {
        let mut writer = channel.make_writer();
        runtime::spawn_attached("harbor-ssh-stdin", move || {
            use tokio::io::AsyncWriteExt;
            let mut buf = [0u8; 32 * 1024];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => {
                        runtime::block_on(async {
                            let _ = writer.shutdown().await;
                        });
                        break;
                    }
                    Ok(n) => {
                        let chunk = buf[..n].to_vec();
                        runtime::block_on(async {
                            let _ = writer.write_all(&chunk).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        })
        .expect("ssh stdin thread")
    });
    let mut status = None;
    loop {
        if closing.load(Ordering::Relaxed) {
            let _ = channel.close().await;
            break;
        }
        match timeout(Duration::from_millis(200), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                let _ = stdout.write_all(&data);
            }
            Ok(Some(ChannelMsg::ExtendedData { data, ext: 1 })) => {
                let _ = stderr.write_all(&data);
            }
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                status = Some(exit_status as i32);
            }
            Ok(Some(ChannelMsg::Eof)) => {
                let _ = stdout.flush();
            }
            Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
            Ok(Some(_)) => {}
            Err(_) => {}
        }
    }
    drop(stdout);
    drop(stderr);
    if let Some(task) = stdin_task {
        join_stdin(task, closing.load(Ordering::Relaxed));
    }
    let (lock, cv) = &*exit;
    if let Ok(mut guard) = lock.lock() {
        *guard = Some(status.unwrap_or(0));
        cv.notify_all();
    }
}

fn join_stdin(task: std::thread::JoinHandle<()>, abandon: bool) {
    if abandon {
        return;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("harbor-ssh-stdin-join".into())
        .spawn(move || {
            let _ = task.join();
            let _ = tx.send(());
        });
    let _ = rx.recv_timeout(Duration::from_secs(2));
}
