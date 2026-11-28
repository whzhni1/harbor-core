use super::auth::{self, ClientHandler};
use super::Target;
use russh::client::Handle;
use russh::client::Msg;
use russh::Channel;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

pub struct Live {
    pub handle: AsyncMutex<Handle<ClientHandler>>,
    pub exec: Arc<Semaphore>,
    pub term: Arc<Semaphore>,
    pub max: usize,
    pub last_used: Mutex<Instant>,
    pub idle: Duration,
    pub device_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
}

impl Live {
    pub fn is_closed(&self) -> bool {
        self.handle
            .try_lock()
            .map(|handle| handle.is_closed())
            .unwrap_or(false)
    }

    fn free_permits(&self) -> usize {
        if Arc::ptr_eq(&self.exec, &self.term) {
            self.exec.available_permits()
        } else {
            self.exec.available_permits() + self.term.available_permits()
        }
    }

    fn idle_expired(&self) -> bool {
        if self.free_permits() != self.max {
            return false;
        }
        self.last_used
            .lock()
            .map(|at| at.elapsed() > self.idle)
            .unwrap_or(false)
    }
}

struct Pool {
    live: HashMap<String, Arc<Live>>,
    pending: HashMap<String, broadcast::Sender<Result<Arc<Live>, String>>>,
}

fn pool_state() -> &'static AsyncMutex<Pool> {
    static POOL: OnceLock<AsyncMutex<Pool>> = OnceLock::new();
    POOL.get_or_init(|| {
        AsyncMutex::new(Pool {
            live: HashMap::new(),
            pending: HashMap::new(),
        })
    })
}

pub fn pool_key(target: &Target) -> String {
    let password = target.password.as_deref().unwrap_or("");
    let value = format!(
        "{}|{}|{}|{}|{}|{}",
        target.id, target.host, target.port, target.username, target.host_key, password
    );
    hex::encode(crate::auth::sha256_bytes(value.as_bytes()))
}

fn take_stale(pool: &mut Pool) -> Vec<Arc<Live>> {
    let stale: Vec<String> = pool
        .live
        .iter()
        .filter(|(_, live)| live.is_closed() || live.idle_expired())
        .map(|(key, _)| key.clone())
        .collect();
    stale
        .into_iter()
        .filter_map(|key| pool.live.remove(&key))
        .collect()
}

async fn disconnect_live(live: Arc<Live>) {
    if let Ok(handle) = live.handle.try_lock() {
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
    }
}

pub async fn session(target: &Target) -> Result<Arc<Live>, String> {
    let key = pool_key(target);
    loop {
        let mut pool = pool_state().lock().await;
        let stale = take_stale(&mut pool);
        if !stale.is_empty() {
            drop(pool);
            for live in stale {
                disconnect_live(live).await;
            }
            continue;
        }
        if let Some(live) = pool.live.get(&key) {
            if !live.is_closed() && !live.idle_expired() {
                return Ok(Arc::clone(live));
            }
            if let Some(live) = pool.live.remove(&key) {
                drop(pool);
                disconnect_live(live).await;
                continue;
            }
        }
        if let Some(tx) = pool.pending.get(&key) {
            let mut rx = tx.subscribe();
            drop(pool);
            return rx
                .recv()
                .await
                .map_err(|_| "SSH connection cancelled".to_string())?;
        }
        let (tx, _rx) = broadcast::channel(1);
        pool.pending.insert(key.clone(), tx.clone());
        drop(pool);
        let result = connect_live(target).await;
        let mut pool = pool_state().lock().await;
        pool.pending.remove(&key);
        if let Ok(live) = &result {
            pool.live.insert(key.clone(), Arc::clone(live));
        }
        let _ = tx.send(result.clone());
        return result;
    }
}

async fn connect_live(target: &Target) -> Result<Arc<Live>, String> {
    let handle = auth::connect_authenticated(target).await?;
    let max = target.max_sessions.clamp(1, 16);
    let (exec, term) = if max == 1 {
        let shared = Arc::new(Semaphore::new(1));
        (Arc::clone(&shared), shared)
    } else {
        (
            Arc::new(Semaphore::new(max - 1)),
            Arc::new(Semaphore::new(1)),
        )
    };
    Ok(Arc::new(Live {
        handle: AsyncMutex::new(handle),
        exec,
        term,
        max,
        last_used: Mutex::new(Instant::now()),
        idle: Duration::from_secs(target.idle_timeout_secs.max(30)),
        device_id: target.id.clone(),
        host: target.host.clone(),
        port: target.port,
        username: target.username.clone(),
    }))
}

pub struct ChannelGuard {
    pub live: Arc<Live>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ChannelGuard {
    fn drop(&mut self) {
        if let Ok(mut at) = self.live.last_used.lock() {
            *at = Instant::now();
        }
    }
}

impl ChannelGuard {
    pub async fn open_session(&self) -> Result<Channel<Msg>, String> {
        if let Ok(mut at) = self.live.last_used.lock() {
            *at = Instant::now();
        }
        let handle = self.live.handle.lock().await;
        handle
            .channel_open_session()
            .await
            .map_err(|error| error.to_string())
    }
}

pub async fn lease(target: &Target) -> Result<ChannelGuard, String> {
    lease_from(target, false).await
}

pub async fn lease_terminal(target: &Target) -> Result<ChannelGuard, String> {
    lease_from(target, true).await
}

async fn lease_from(target: &Target, terminal: bool) -> Result<ChannelGuard, String> {
    let live = session(target).await?;
    let sem = if terminal {
        Arc::clone(&live.term)
    } else {
        Arc::clone(&live.exec)
    };
    let permit = sem
        .acquire_owned()
        .await
        .map_err(|_| "SSH session closed".to_string())?;
    Ok(ChannelGuard {
        live,
        _permit: permit,
    })
}

pub async fn drop_key(target: &Target) {
    let key = pool_key(target);
    let mut pool = pool_state().lock().await;
    if let Some(live) = pool.live.remove(&key) {
        drop(pool);
        disconnect_live(live).await;
    }
}

pub async fn close_device(device_id: &str) {
    let mut pool = pool_state().lock().await;
    let keys: Vec<String> = pool
        .live
        .iter()
        .filter(|(_, live)| live.device_id == device_id)
        .map(|(key, _)| key.clone())
        .collect();
    let mut dropped = Vec::new();
    for key in keys {
        if let Some(live) = pool.live.remove(&key) {
            dropped.push(live);
        }
    }
    drop(pool);
    for live in dropped {
        disconnect_live(live).await;
    }
}

pub async fn close_all() {
    let mut pool = pool_state().lock().await;
    let dropped: Vec<Arc<Live>> = pool.live.drain().map(|(_, live)| live).collect();
    drop(pool);
    for live in dropped {
        disconnect_live(live).await;
    }
}

pub fn pool_snapshot() -> Vec<serde_json::Value> {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return super::runtime::block_on(pool_snapshot_async());
    };
    let _ = handle;
    super::runtime::block_on(pool_snapshot_async())
}

async fn pool_snapshot_async() -> Vec<serde_json::Value> {
    let pool = pool_state().lock().await;
    let now = Instant::now();
    pool.live
        .values()
        .map(|live| {
            let idle_secs = live
                .last_used
                .lock()
                .map(|at| now.duration_since(*at).as_secs())
                .unwrap_or(0);
            json!({
                "device_id": live.device_id,
                "host": live.host,
                "port": live.port,
                "username": live.username,
                "active": live.max.saturating_sub(live.free_permits()),
                "idle_secs": idle_secs,
                "idle_limit_secs": live.idle.as_secs(),
            })
        })
        .collect()
}
