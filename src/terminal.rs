use crate::reply::fail_status;
use crate::state::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

const MAX_SESSIONS: usize = 16;
const REAPER_TICK: Duration = Duration::from_secs(30);

enum SpawnSpec {
    Local,
    Remote {
        target: crate::ssh::Target,
        cols: u16,
        rows: u16,
    },
}

#[derive(Deserialize)]
pub struct WsParams {
    session: Option<String>,
    device: Option<String>,
    path: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug, PartialEq)]
enum Control {
    Resize { cols: u16, rows: u16 },
    Close,
    Ping,
}

enum StreamMsg {
    Data(Vec<u8>),
    Exit,
}

struct Shared {
    ring: VecDeque<u8>,
    subscribers: Vec<UnboundedSender<StreamMsg>>,
    attached: usize,
    detached_at: Option<Instant>,
    exited: bool,
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(value) => value,
        Err(poisoned) => poisoned.into_inner(),
    }
}

enum SessionIo {
    Local {
        master: Mutex<Box<dyn MasterPty + Send>>,
        writer: Mutex<Box<dyn Write + Send>>,
        child: Mutex<Box<dyn Child + Send + Sync>>,
    },
    Remote(crate::ssh::PtySession),
}

pub struct Session {
    io: SessionIo,
    shared: Arc<Mutex<Shared>>,
}

impl Session {
    fn write_input(&self, data: &[u8]) -> std::io::Result<()> {
        match &self.io {
            SessionIo::Local { writer, .. } => {
                let mut writer = guard(writer);
                writer.write_all(data)?;
                writer.flush()
            }
            SessionIo::Remote(pty) => pty.write_input(data),
        }
    }

    fn resize(&self, cols: u16, rows: u16) {
        match &self.io {
            SessionIo::Local { master, .. } => {
                let _ = guard(master).resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                });
            }
            SessionIo::Remote(pty) => pty.resize(cols, rows),
        }
    }

    fn detach(&self, sender: &UnboundedSender<StreamMsg>) {
        let mut shared = guard(&self.shared);
        shared
            .subscribers
            .retain(|entry| !entry.same_channel(sender));
        shared.attached = shared.attached.saturating_sub(1);
        if shared.attached == 0 {
            shared.detached_at = Some(Instant::now());
        }
    }

    fn kill(&self) {
        match &self.io {
            SessionIo::Local { child, .. } => {
                let _ = guard(child).kill();
            }
            SessionIo::Remote(pty) => pty.kill(),
        }
    }
}

pub struct Registry {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    reaper_started: AtomicBool,
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            sessions: Mutex::new(HashMap::new()),
            reaper_started: AtomicBool::new(false),
        }
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        for session in guard(&self.sessions).values() {
            session.kill();
        }
    }
}

fn remove_session(registry: &Arc<Registry>, id: &str) {
    if let Some(session) = guard(&registry.sessions).remove(id) {
        session.kill();
    }
}

fn reap_registry(registry: &Arc<Registry>, idle_secs: u64) {
    let mut sessions = guard(&registry.sessions);
    let expired: Vec<String> = sessions
        .iter()
        .filter(|(_, session)| {
            let shared = guard(&session.shared);
            if shared.attached != 0 {
                return false;
            }
            if shared.exited {
                return true;
            }
            if idle_secs == 0 {
                return false;
            }
            shared
                .detached_at
                .map(|at| at.elapsed() > Duration::from_secs(idle_secs))
                .unwrap_or(false)
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        if let Some(session) = sessions.remove(&id) {
            session.kill();
        }
    }
}

fn ensure_reaper(registry: &Arc<Registry>, st: Arc<AppState>) {
    if registry.reaper_started.swap(true, Ordering::Relaxed) {
        return;
    }
    let registry = Arc::clone(registry);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REAPER_TICK).await;
            let idle = st.prefs().terminal_idle.max(0) as u64;
            reap_registry(&registry, idle);
        }
    });
}

fn attach_session(
    registry: &Arc<Registry>,
    id: &str,
    spec: SpawnSpec,
    cols: u16,
    rows: u16,
    ring_cap: usize,
    idle_secs: u64,
) -> Result<Arc<Session>, String> {
    let mut sessions = guard(&registry.sessions);
    if let Some(session) = sessions.get(id) {
        let exited = guard(&session.shared).exited;
        if !exited {
            return Ok(Arc::clone(session));
        }
        sessions.remove(id);
    }
    if sessions.len() >= MAX_SESSIONS {
        drop(sessions);
        reap_registry(registry, idle_secs);
        sessions = guard(&registry.sessions);
        if sessions.len() >= MAX_SESSIONS {
            return Err("Too many terminal sessions".to_string());
        }
    }
    let session = spawn_session(registry, id, spec, cols, rows, ring_cap)?;
    sessions.insert(id.to_string(), Arc::clone(&session));
    Ok(session)
}

fn spawn_session(
    registry: &Arc<Registry>,
    id: &str,
    spec: SpawnSpec,
    cols: u16,
    rows: u16,
    ring_cap: usize,
) -> Result<Arc<Session>, String> {
    let shared = Arc::new(Mutex::new(Shared {
        ring: VecDeque::new(),
        subscribers: Vec::new(),
        attached: 0,
        detached_at: Some(Instant::now()),
        exited: false,
    }));
    let weak = Arc::downgrade(registry);
    let thread_id = id.to_string();
    if let SpawnSpec::Remote { target, cols, rows } = spec {
        let pty = crate::ssh::open_pty_login(&target, cols, rows)?;
        let reader = pty
            .output
            .try_clone()
            .map_err(|error| format!("PTY reader error: {error}"))?;
        let session = Arc::new(Session {
            io: SessionIo::Remote(pty),
            shared: Arc::clone(&shared),
        });
        std::thread::spawn(move || {
            reader_loop(thread_id, weak, Box::new(reader), shared, ring_cap)
        });
        return Ok(session);
    }
    let pair = native_pty_system()
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("PTY error: {error}"))?;
    let SpawnSpec::Local = spec else {
        return Err("Terminal session kind mismatch".to_string());
    };
    let builder = build_command()?;
    let child = pair
        .slave
        .spawn_command(builder)
        .map_err(|error| format!("Shell start failed: {error}"))?;
    drop(pair.slave);
    let writer = pair
        .master
        .take_writer()
        .map_err(|error| format!("PTY writer error: {error}"))?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| format!("PTY reader error: {error}"))?;
    let session = Arc::new(Session {
        io: SessionIo::Local {
            master: Mutex::new(pair.master),
            writer: Mutex::new(writer),
            child: Mutex::new(child),
        },
        shared: Arc::clone(&shared),
    });
    std::thread::spawn(move || reader_loop(thread_id, weak, reader, shared, ring_cap));
    Ok(session)
}

fn reader_loop(
    id: String,
    registry: std::sync::Weak<Registry>,
    mut reader: Box<dyn Read + Send>,
    shared: Arc<Mutex<Shared>>,
    ring_cap: usize,
) {
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => {
                let chunk = buffer[..size].to_vec();
                let mut state = guard(&shared);
                ring_push(&mut state.ring, &chunk, ring_cap);
                for sender in state.subscribers.iter() {
                    let _ = sender.send(StreamMsg::Data(chunk.clone()));
                }
            }
            Err(_) => break,
        }
    }
    let subscribers: Vec<UnboundedSender<StreamMsg>> = {
        let mut state = guard(&shared);
        state.exited = true;
        state.subscribers.clone()
    };
    for sender in subscribers {
        let _ = sender.send(StreamMsg::Exit);
    }
    if let Some(registry) = registry.upgrade() {
        remove_session(&registry, &id);
    }
}

fn ring_push(ring: &mut VecDeque<u8>, chunk: &[u8], cap: usize) {
    if cap == 0 {
        return;
    }
    ring.extend(chunk.iter().copied());
    let overflow = ring.len().saturating_sub(cap);
    if overflow > 0 {
        ring.drain(..overflow);
    }
}

fn parse_control(text: &str) -> Option<Control> {
    let value: Value = serde_json::from_str(text).ok()?;
    match value.get("type").and_then(Value::as_str)? {
        "resize" => {
            let cols = value.get("cols").and_then(Value::as_u64)?;
            let rows = value.get("rows").and_then(Value::as_u64)?;
            Some(Control::Resize {
                cols: (cols as u16).clamp(2, 500),
                rows: (rows as u16).clamp(2, 300),
            })
        }
        "close" => Some(Control::Close),
        "ping" => Some(Control::Ping),
        _ => None,
    }
}

pub fn valid_session_id(id: &str) -> bool {
    let length = id.len();
    (8..=64).contains(&length)
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn login_shell() -> CommandBuilder {
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .filter(|value| PathBuf::from(value).exists())
        .unwrap_or_else(|| "/bin/sh".to_string());
    let mut command = CommandBuilder::new(shell);
    command.arg("-l");
    command
}

fn build_command() -> Result<CommandBuilder, String> {
    let mut builder =
        if unsafe { libc::geteuid() } == 0 && std::path::Path::new("/bin/login").exists() {
            CommandBuilder::new("/bin/login")
        } else {
            login_shell()
        };
    for (key, value) in std::env::vars() {
        builder.env(key, value);
    }
    builder.env("TERM", "xterm-256color");
    builder.env("COLORTERM", "truecolor");
    Ok(builder)
}

fn remote_target(st: &AppState, device_id: &str) -> Result<crate::ssh::Target, String> {
    let device =
        crate::remote::find_device(st, device_id).ok_or_else(|| "Device not found".to_string())?;
    crate::remote::ensure_trusted(st, &device).map_err(|error| error.message)?;
    Ok(crate::remote::authenticated_target(st, &device))
}

pub async fn ws_endpoint(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<WsParams>,
    ws: WebSocketUpgrade,
) -> Response {
    if st.session_id(&headers).is_none() {
        return fail_status(StatusCode::UNAUTHORIZED, 401, "Unauthorized", Value::Null);
    }
    let id = params.session.as_deref().unwrap_or_default();
    if !valid_session_id(id) {
        return fail_status(StatusCode::BAD_REQUEST, 1, "Invalid session", Value::Null);
    }
    let cols = params.cols.unwrap_or(80).clamp(2, 500);
    let rows = params.rows.unwrap_or(300).clamp(2, 300);
    let device = params
        .device
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let prefs = st.prefs();
    let _ = params.path.as_deref();
    let ping = prefs.terminal_ping.clamp(5, 600) as u64;
    let idle = prefs.terminal_idle.max(0) as u64;
    let ring_cap = if prefs.terminal_replay == 1 {
        prefs.terminal_ring_kb.clamp(16, 4096) as usize * 1024
    } else {
        0
    };
    let spec = match device {
        Some(device_id) => match remote_target(&st, device_id) {
            Ok(target) => SpawnSpec::Remote { target, cols, rows },
            Err(message) => {
                return fail_status(StatusCode::SERVICE_UNAVAILABLE, 1, &message, Value::Null)
            }
        },
        None => SpawnSpec::Local,
    };
    let session = match attach_session(&st.terminal, id, spec, cols, rows, ring_cap, idle) {
        Ok(session) => session,
        Err(message) => {
            return fail_status(StatusCode::SERVICE_UNAVAILABLE, 1, &message, Value::Null)
        }
    };
    ensure_reaper(&st.terminal, Arc::clone(&st));
    ws.on_upgrade(move |socket| ws_loop(session, socket, ping))
        .into_response()
}

async fn ws_loop(session: Arc<Session>, socket: WebSocket, ping_secs: u64) {
    let (mut socket_tx, mut socket_rx) = socket.split();
    let (out_tx, mut out_rx) = unbounded_channel::<StreamMsg>();
    let (replay, exited) = {
        let mut shared = guard(&session.shared);
        shared.subscribers.push(out_tx.clone());
        shared.attached += 1;
        shared.detached_at = None;
        let replay: Vec<u8> = shared.ring.iter().copied().collect();
        (replay, shared.exited)
    };
    if !replay.is_empty()
        && socket_tx
            .send(Message::Binary(replay.into()))
            .await
            .is_err()
    {
        session.detach(&out_tx);
        return;
    }
    if exited {
        let _ = socket_tx
            .send(Message::Text(r#"{"type":"exit"}"#.into()))
            .await;
        session.detach(&out_tx);
        return;
    }
    let ping_interval = Duration::from_secs(ping_secs);
    let rx_limit = std::cmp::max(Duration::from_secs(60), ping_interval * 5 / 2);
    let mut ping = tokio::time::interval(ping_interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_seen = Instant::now();
    loop {
        tokio::select! {
            incoming = socket_rx.next() => match incoming {
                Some(Ok(Message::Binary(data))) => {
                    last_seen = Instant::now();
                    let _ = session.write_input(&data);
                }
                Some(Ok(Message::Text(text))) => {
                    last_seen = Instant::now();
                    match parse_control(&text) {
                        Some(Control::Resize { cols, rows }) => session.resize(cols, rows),
                        Some(Control::Close) => break,
                        Some(Control::Ping) => {}
                        None => {}
                    }
                }
                Some(Ok(Message::Ping(data))) => {
                    last_seen = Instant::now();
                    if socket_tx.send(Message::Pong(data)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Pong(_))) => {
                    last_seen = Instant::now();
                }
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
            },
            outgoing = out_rx.recv() => match outgoing {
                Some(StreamMsg::Data(chunk)) => {
                    if socket_tx.send(Message::Binary(chunk.into())).await.is_err() {
                        break;
                    }
                }
                Some(StreamMsg::Exit) => {
                    let _ = socket_tx.send(Message::Text(r#"{"type":"exit"}"#.into())).await;
                    break;
                }
                None => break,
            },
            _ = ping.tick() => {
                if last_seen.elapsed() > rx_limit {
                    break;
                }
                if socket_tx.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
        }
    }
    session.detach(&out_tx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_is_capped_from_the_front() {
        let mut ring: VecDeque<u8> = VecDeque::new();
        ring_push(&mut ring, &[1u8; 100], 1024);
        ring_push(&mut ring, &[2u8; 1024], 1024);
        assert_eq!(ring.len(), 1024);
        assert_eq!(ring.front().copied(), Some(2u8));
        assert_eq!(ring.back().copied(), Some(2u8));
    }

    #[test]
    fn ring_keeps_small_chunks_intact() {
        let mut ring: VecDeque<u8> = VecDeque::new();
        ring_push(&mut ring, b"hello", 1024);
        assert_eq!(ring.iter().copied().collect::<Vec<u8>>(), b"hello");
    }

    #[test]
    fn ring_disabled_when_cap_zero() {
        let mut ring: VecDeque<u8> = VecDeque::new();
        ring_push(&mut ring, b"hello", 1024);
        ring_push(&mut ring, b"world", 0);
        assert_eq!(ring.iter().copied().collect::<Vec<u8>>(), b"hello");
    }

    #[test]
    fn control_messages_parse() {
        assert_eq!(
            parse_control(r#"{"type":"resize","cols":120,"rows":40}"#),
            Some(Control::Resize {
                cols: 120,
                rows: 40
            })
        );
        assert_eq!(parse_control(r#"{"type":"close"}"#), Some(Control::Close));
        assert_eq!(parse_control(r#"{"type":"ping"}"#), Some(Control::Ping));
        assert_eq!(
            parse_control(r#"{"type":"resize","cols":0,"rows":0}"#),
            Some(Control::Resize { cols: 2, rows: 2 })
        );
        assert_eq!(parse_control("not json"), None);
        assert_eq!(parse_control(r#"{"type":"other"}"#), None);
    }

    #[test]
    fn session_ids_are_validated() {
        assert!(valid_session_id("term-abc_123456"));
        assert!(!valid_session_id("short"));
        assert!(!valid_session_id("bad id with spaces"));
        assert!(!valid_session_id(&"x".repeat(80)));
        assert!(!valid_session_id("../../../etc"));
    }

    #[test]
    fn local_command_prefers_login_shell() {
        let builder = build_command().unwrap();
        assert_eq!(
            builder.get_env("TERM"),
            Some(std::ffi::OsStr::new("xterm-256color"))
        );
        let program = builder.get_argv()[0].to_string_lossy().to_string();
        if unsafe { libc::geteuid() } == 0 && std::path::Path::new("/bin/login").exists() {
            assert_eq!(program, "/bin/login");
        } else {
            assert!(
                program.ends_with("sh") || program.ends_with("bash") || program.ends_with("zsh")
            );
            assert_eq!(
                builder
                    .get_argv()
                    .get(1)
                    .map(|a| a.to_string_lossy().to_string())
                    .as_deref(),
                Some("-l")
            );
        }
    }
}
