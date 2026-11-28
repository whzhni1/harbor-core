use serde_json::{json, Value};
use std::any::Any;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Counter(Mutex<u64>);

impl Counter {
    pub fn new(value: u64) -> Counter {
        Counter(Mutex::new(value))
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, u64> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn load(&self, _order: Ordering) -> u64 {
        *self.slot()
    }

    pub fn store(&self, value: u64, _order: Ordering) {
        *self.slot() = value;
    }

    pub fn fetch_add(&self, delta: u64, _order: Ordering) -> u64 {
        let mut slot = self.slot();
        let previous = *slot;
        *slot = previous.saturating_add(delta);
        previous
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Unknown,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Queued => "queued",
            Status::Running => "running",
            Status::Completed => "completed",
            Status::Failed => "failed",
            Status::Cancelled => "cancelled",
            Status::Unknown => "unknown",
        }
    }

    pub fn terminal(&self) -> bool {
        matches!(
            self,
            Status::Completed | Status::Failed | Status::Cancelled | Status::Unknown
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Transfer,
    Session,
    Job,
}

/// A session's activity gate prevents simultaneous chunks, finish, or reap.
/// It is protected by the same per-task mutex as the session resource.
pub(crate) struct SessionActivity {
    pub(crate) busy: bool,
    pub(crate) touched: Instant,
    idle: Duration,
}
impl SessionActivity {
    pub(crate) fn new(idle: Duration) -> Self {
        Self {
            busy: false,
            touched: Instant::now(),
            idle,
        }
    }
    fn begin(&mut self) -> bool {
        if self.busy {
            return false;
        }
        self.busy = true;
        self.touched = Instant::now();
        true
    }
    fn finish(&mut self) {
        self.busy = false;
        self.touched = Instant::now();
    }
    fn expired(&self, now: Instant) -> bool {
        !self.busy && now.saturating_duration_since(self.touched) > self.idle
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionCleanup {
    Interrupted,
    Aborted,
    Expired,
    Shutdown,
}

/// Session resources are private and cannot leak credentials through JSON.
/// The cleanup hook is executed outside the registry's global mutex.
pub(crate) trait SessionResource: Any + Send {
    const ASYNC_CLEANUP: bool = false;
    fn activity(&self) -> &SessionActivity;
    fn activity_mut(&mut self) -> &mut SessionActivity;
    fn progress(&self) -> u64;
    fn cleanup(&mut self, _reason: SessionCleanup) {}
}

struct SessionHolder {
    value: Option<Box<dyn Any + Send>>,
    expired: fn(&dyn Any, Instant) -> bool,
    cleanup: fn(&mut dyn Any, SessionCleanup),
}
impl SessionHolder {
    fn new<T: SessionResource>(value: T) -> Self {
        Self {
            value: Some(Box::new(value)),
            expired: |v, now| {
                v.downcast_ref::<T>()
                    .is_some_and(|v| v.activity().expired(now))
            },
            cleanup: |v, reason| {
                if let Some(v) = v.downcast_mut::<T>() {
                    v.cleanup(reason);
                }
            },
        }
    }
    fn into_value<T: SessionResource>(mut self) -> Option<T> {
        let value = self.value.take()?;
        match value.downcast::<T>() {
            Ok(value) => Some(*value),
            Err(value) => {
                self.value = Some(value);
                None
            }
        }
    }
    fn cleanup_for(&mut self, reason: SessionCleanup) {
        if let Some(mut value) = self.value.take() {
            (self.cleanup)(value.as_mut(), reason);
        }
    }
}
impl Drop for SessionHolder {
    fn drop(&mut self) {
        self.cleanup_for(SessionCleanup::Shutdown);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionError {
    Missing,
    Busy,
}

pub(crate) struct SessionLease<T: SessionResource> {
    registry: Arc<TaskRegistry>,
    id: String,
    finished: bool,
    marker: std::marker::PhantomData<T>,
}
impl<T: SessionResource> SessionLease<T> {
    pub(crate) fn finish(&mut self) {
        let _ = self
            .registry
            .with_session::<T, _>(&self.id, |session| session.activity_mut().finish());
        self.finished = true;
    }
    pub(crate) fn discard(&mut self, reason: SessionCleanup) {
        self.registry.discard_session::<T>(&self.id, reason);
        self.finished = true;
    }
}
impl<T: SessionResource> Drop for SessionLease<T> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let registry = self.registry.clone();
        let id = self.id.clone();
        if T::ASYNC_CLEANUP {
            std::thread::spawn(move || {
                registry.discard_session::<T>(&id, SessionCleanup::Interrupted);
            });
        } else {
            registry.discard_session::<T>(&id, SessionCleanup::Interrupted);
        }
    }
}

/// Cooperative cancellation with an atomic point-of-no-return. Once `seal`
/// wins, cancellation is refused; once a request wins, `seal` cannot publish.
#[derive(Default)]
pub(crate) struct JobControl {
    inner: Mutex<JobControlState>,
}
#[derive(Default)]
struct JobControlState {
    requested: bool,
    closed: bool,
}
impl JobControl {
    pub(crate) fn request(&self) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        if state.closed {
            return false;
        }
        state.requested = true;
        true
    }
    pub(crate) fn requested(&self) -> bool {
        self.inner
            .lock()
            .map(|state| state.requested)
            .unwrap_or(true)
    }
    fn accepting(&self) -> bool {
        self.inner
            .lock()
            .map(|state| !state.closed && !state.requested)
            .unwrap_or(false)
    }
    pub(crate) fn seal(&self) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        if state.closed || state.requested {
            return false;
        }
        state.closed = true;
        true
    }
    fn finish(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.closed = true;
        }
    }
}

pub struct Task {
    pub id: String,
    pub kind: String,
    pub path: String,
    pub total: Counter,
    pub done: Counter,
    status: Mutex<Status>,
    cancel: AtomicBool,
    cancel_notify: tokio::sync::Notify,
    message: Mutex<Option<String>>,
    pub created: i64,
    started: Instant,
    role: Role,
    session: Mutex<Option<SessionHolder>>,
    upload_session: Mutex<Option<String>>,
    job_control: Option<Arc<JobControl>>,
}

impl Task {
    pub fn status(&self) -> Status {
        self.status.lock().map(|s| *s).unwrap_or(Status::Failed)
    }

    pub fn set_status(&self, status: Status) {
        if let Ok(mut current) = self.status.lock() {
            if current.terminal() {
                return;
            }
            *current = status;
        }
    }

    /// Authoritative persisted evidence (such as an rc file or a durable
    /// publication marker) may resolve an earlier unknown outcome.
    pub(crate) fn resolve_status(&self, status: Status) {
        if let Ok(mut current) = self.status.lock() {
            if !current.terminal() || *current == Status::Unknown {
                *current = status;
            }
        }
    }

    pub fn add(&self, bytes: u64) {
        self.done.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn set_total(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    /// Downloads are stopped asynchronously: a request only signals the
    /// producer. Upload sessions call this after their serialized, durable
    /// abort, so their existing immediate terminal transition is preserved.
    pub fn cancel(&self) -> bool {
        if self.role != Role::Transfer {
            return false;
        }
        let Ok(mut current) = self.status.lock() else {
            return false;
        };
        if current.terminal() {
            return false;
        }
        self.cancel.store(true, Ordering::Release);
        if self.kind != "download" {
            *current = Status::Cancelled;
        }
        drop(current);
        self.cancel_notify.notify_one();
        true
    }

    pub(crate) async fn wait_cancelled(&self) {
        loop {
            let notification = self.cancel_notify.notified();
            if self.cancelled() {
                return;
            }
            notification.await;
        }
    }

    /// Called only after the download source and transfer permit are released
    /// and, for SSH, the local child has been reaped. This lock arbitrates a
    /// completion/cancellation race; unknown cleanup is never called cancelled.
    pub(crate) fn finish_download(&self, status: Status, message: Option<String>) {
        if self.role != Role::Transfer || self.kind != "download" {
            return;
        }
        let Ok(mut current) = self.status.lock() else {
            return;
        };
        if current.terminal() {
            return;
        }
        let status = if status != Status::Unknown && self.cancelled() {
            Status::Cancelled
        } else {
            status
        };
        if let Ok(mut slot) = self.message.lock() {
            *slot = if status == Status::Cancelled {
                None
            } else {
                message
            };
        }
        *current = status;
    }

    pub fn is_transfer(&self) -> bool {
        self.role == Role::Transfer
    }
    pub fn is_job(&self) -> bool {
        self.role == Role::Job
    }
    fn request_job_cancel(&self) -> bool {
        let Ok(status) = self.status.lock() else {
            return false;
        };
        if status.terminal() || self.role != Role::Job {
            return false;
        }
        self.job_control
            .as_ref()
            .is_some_and(|control| control.request())
    }
    pub fn bind_upload_session(&self, id: &str) {
        if let Ok(mut slot) = self.upload_session.lock() {
            *slot = Some(id.to_string());
        }
    }
    pub fn upload_session(&self) -> Option<String> {
        self.upload_session
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }

    pub fn fail(&self, message: impl Into<String>) {
        if let Ok(mut slot) = self.message.lock() {
            *slot = Some(message.into());
        }
        if let Ok(mut current) = self.status.lock() {
            if !current.terminal() {
                *current = Status::Failed;
            }
        }
    }

    pub fn json(&self) -> Value {
        let total = self.total.load(Ordering::Relaxed);
        let done = self.done.load(Ordering::Relaxed);
        let elapsed = self.started.elapsed().as_secs_f64();
        let status = self.status();
        let cancel_requested = if self.role == Role::Transfer {
            self.cancelled()
        } else {
            self.job_control
                .as_ref()
                .is_some_and(|control| control.requested())
        };
        let speed = if elapsed > 0.05 {
            (done as f64 / elapsed) as u64
        } else {
            0
        };
        json!({
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "status": status.as_str(),
            "total": total,
            "transferred": done,
            "remaining": total.saturating_sub(done),
            "percent": if total == 0 { 100.0 } else { (done as f64 * 100.0 / total as f64).min(100.0) },
            "speed_bps": speed,
            "message": self.message.lock().ok().and_then(|m| m.clone()),
            "created_at": self.created,
            "cancelable": !status.terminal() && ((self.role == Role::Transfer && !cancel_requested) ||
                self.job_control.as_ref().is_some_and(|control| control.accepting())),
            "cancel_requested": cancel_requested,
        })
    }
}

pub struct TaskRegistry {
    map: Mutex<BTreeMap<String, Arc<Task>>>,
    history: usize,
    reaper_started: AtomicBool,
}

impl TaskRegistry {
    pub fn new(history: usize) -> TaskRegistry {
        TaskRegistry {
            map: Mutex::new(BTreeMap::new()),
            history: history.clamp(8, 4096),
            reaper_started: AtomicBool::new(false),
        }
    }

    fn new_transfer(kind: &'static str, path: &str, total: u64) -> Arc<Task> {
        let id = format!("{}-{}", crate::meta::now_secs(), crate::uci::random_hex(12));
        Arc::new(Task {
            id,
            kind: kind.to_string(),
            path: path.to_string(),
            total: Counter::new(total),
            done: Counter::new(0),
            status: Mutex::new(Status::Queued),
            cancel: AtomicBool::new(false),
            cancel_notify: tokio::sync::Notify::new(),
            message: Mutex::new(None),
            created: crate::meta::now_secs(),
            started: Instant::now(),
            role: Role::Transfer,
            session: Mutex::new(None),
            upload_session: Mutex::new(None),
            job_control: None,
        })
    }

    pub fn create(&self, kind: &'static str, path: &str, total: u64) -> Arc<Task> {
        let transfer = Self::new_transfer(kind, path, total);
        if let Ok(mut map) = self.map.lock() {
            map.insert(transfer.id.clone(), transfer.clone());
            trim(&mut map, self.history);
        }
        transfer
    }

    /// Cap admission, not active history eviction. This is used for persisted
    /// upload sessions, which can otherwise be created without transferring.
    pub(crate) fn try_create_upload(&self, path: &str, total: u64) -> Option<Arc<Task>> {
        let mut map = self.map.lock().ok()?;
        let limit = self
            .history
            .saturating_mul(4)
            .max(self.history.saturating_add(64));
        if map
            .values()
            .filter(|task| task.role == Role::Transfer && !task.status().terminal())
            .count()
            >= limit
        {
            return None;
        }
        let transfer = Self::new_transfer("upload", path, total);
        map.insert(transfer.id.clone(), transfer.clone());
        trim(&mut map, self.history);
        Some(transfer)
    }

    /// Reattach a persistent chunk upload after a daemon restart. Session
    /// metadata remains authoritative; cancelled/terminal records are never
    /// silently revived over an existing task.
    pub(crate) fn restore_upload(
        &self,
        id: &str,
        path: &str,
        total: u64,
        done: u64,
        created: i64,
        session_id: &str,
    ) -> Option<Arc<Task>> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return None;
        }
        let mut map = self.map.lock().ok()?;
        if let Some(task) = map.get(id) {
            return (task.role == Role::Transfer && task.kind == "upload" && task.path == path)
                .then(|| task.clone());
        }
        let task = Arc::new(Task {
            id: id.to_string(),
            kind: "upload".to_string(),
            path: path.to_string(),
            total: Counter::new(total),
            done: Counter::new(done.min(total)),
            status: Mutex::new(Status::Running),
            cancel: AtomicBool::new(false),
            cancel_notify: tokio::sync::Notify::new(),
            message: Mutex::new(None),
            created,
            started: Instant::now(),
            role: Role::Transfer,
            session: Mutex::new(None),
            upload_session: Mutex::new(Some(session_id.to_string())),
            job_control: None,
        });
        map.insert(id.to_string(), task.clone());
        trim(&mut map, self.history);
        Some(task)
    }

    pub fn get(&self, id: &str) -> Option<Arc<Task>> {
        self.map.lock().ok()?.get(id).cloned()
    }

    pub fn list(&self) -> Vec<Value> {
        let mut entries: Vec<_> = match self.map.lock() {
            Ok(map) => map
                .values()
                .filter(|t| t.role != Role::Session)
                .cloned()
                .collect(),
            Err(_) => return Vec::new(),
        };
        for entry in &entries {
            if entry.role == Role::Job {
                let _ = self.job_status(&entry.id);
            }
        }
        entries.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| b.id.cmp(&a.id)));
        let mut terminal = 0usize;
        entries
            .into_iter()
            .filter_map(|entry| {
                if entry.status().terminal() {
                    terminal += 1;
                    if terminal > self.history {
                        return None;
                    }
                }
                Some(entry.json())
            })
            .collect()
    }

    pub fn active(&self) -> usize {
        let entries: Vec<_> = match self.map.lock() {
            Ok(map) => map
                .values()
                .filter(|t| t.role != Role::Session)
                .cloned()
                .collect(),
            Err(_) => return 0,
        };
        entries
            .into_iter()
            .filter(|entry| {
                if entry.role == Role::Job {
                    let _ = self.job_status(&entry.id);
                }
                !entry.status().terminal()
            })
            .count()
    }

    pub fn cancel(&self, id: &str) -> bool {
        match self.get(id) {
            Some(transfer) if transfer.role == Role::Transfer => transfer.cancel(),
            _ => false,
        }
    }

    pub(crate) fn request_job_cancel(&self, id: &str) -> bool {
        self.get(id).is_some_and(|task| task.request_job_cancel())
    }

    /// Register a live session in the same registry as transfers and jobs.
    /// The payload remains private and is never serialized into task listings.
    pub(crate) fn insert_session<T: SessionResource>(
        &self,
        id: String,
        kind: &'static str,
        path: &str,
        total: u64,
        value: T,
    ) -> Result<(), T> {
        let mut map = match self.map.lock() {
            Ok(map) => map,
            Err(_) => return Err(value),
        };
        if map.contains_key(&id) {
            return Err(value);
        }
        let progress = value.progress();
        let entry = Arc::new(Task {
            id: id.clone(),
            kind: kind.to_string(),
            path: path.to_string(),
            total: Counter::new(total),
            done: Counter::new(progress),
            status: Mutex::new(Status::Running),
            cancel: AtomicBool::new(false),
            cancel_notify: tokio::sync::Notify::new(),
            message: Mutex::new(None),
            created: crate::meta::now_secs(),
            started: Instant::now(),
            role: Role::Session,
            session: Mutex::new(Some(SessionHolder::new(value))),
            upload_session: Mutex::new(None),
            job_control: None,
        });
        map.insert(id, entry);
        Ok(())
    }

    pub(crate) fn with_session<T: SessionResource, R>(
        &self,
        id: &str,
        apply: impl FnOnce(&mut T) -> R,
    ) -> Option<R> {
        let entry = self.get(id)?;
        if entry.role != Role::Session {
            return None;
        }
        let mut holder = entry.session.lock().ok()?;
        let value = holder.as_mut()?.value.as_deref_mut()?.downcast_mut::<T>()?;
        let result = apply(value);
        entry.done.store(value.progress(), Ordering::Relaxed);
        Some(result)
    }

    /// Fast admission check for an async request. A slow filesystem or SSH
    /// write can hold the resource lock in a blocking worker; never wait for
    /// that lock on a Tokio worker thread.
    pub(crate) fn try_with_session<T: SessionResource, R>(
        &self,
        id: &str,
        apply: impl FnOnce(&mut T) -> R,
    ) -> Result<R, SessionError> {
        let entry = self.get(id).ok_or(SessionError::Missing)?;
        if entry.role != Role::Session {
            return Err(SessionError::Missing);
        }
        let mut holder = match entry.session.try_lock() {
            Ok(holder) => holder,
            Err(std::sync::TryLockError::WouldBlock) => return Err(SessionError::Busy),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(SessionError::Missing),
        };
        let value = holder
            .as_mut()
            .and_then(|h| h.value.as_deref_mut())
            .and_then(|v| v.downcast_mut::<T>())
            .ok_or(SessionError::Missing)?;
        let result = apply(value);
        entry.done.store(value.progress(), Ordering::Relaxed);
        Ok(result)
    }

    pub(crate) fn acquire_session<T: SessionResource>(
        self: &Arc<Self>,
        id: &str,
    ) -> Result<SessionLease<T>, SessionError> {
        match self.try_with_session::<T, _>(id, |session| session.activity_mut().begin()) {
            Err(error) => Err(error),
            Ok(false) => Err(SessionError::Busy),
            Ok(true) => Ok(SessionLease {
                registry: self.clone(),
                id: id.to_string(),
                finished: false,
                marker: std::marker::PhantomData,
            }),
        }
    }

    /// Taking the payload and testing `busy` is a single critical section.
    pub(crate) fn take_session<T: SessionResource>(
        &self,
        id: &str,
        require_idle: bool,
    ) -> Result<T, SessionError> {
        let entry = self.get(id).ok_or(SessionError::Missing)?;
        if entry.role != Role::Session {
            return Err(SessionError::Missing);
        }
        let mut slot = if require_idle {
            match entry.session.try_lock() {
                Ok(slot) => slot,
                Err(std::sync::TryLockError::WouldBlock) => return Err(SessionError::Busy),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(SessionError::Missing),
            }
        } else {
            entry.session.lock().map_err(|_| SessionError::Missing)?
        };
        let value = slot
            .as_mut()
            .and_then(|h| h.value.as_deref_mut())
            .and_then(|v| v.downcast_mut::<T>())
            .ok_or(SessionError::Missing)?;
        if require_idle && value.activity().busy {
            return Err(SessionError::Busy);
        }
        let value = slot
            .take()
            .and_then(|h| h.into_value::<T>())
            .ok_or(SessionError::Missing)?;
        // No path acquires the per-session lock while holding the map lock.
        if let Ok(mut map) = self.map.lock() {
            if map
                .get(id)
                .is_some_and(|current| Arc::ptr_eq(current, &entry))
            {
                map.remove(id);
            }
        }
        Ok(value)
    }

    /// Replace a session resource without ever exposing a gap in its id.
    /// Used when an upload moves from accepting chunks to a finishing receipt.
    pub(crate) fn replace_session<T: SessionResource, U: SessionResource>(
        &self,
        id: &str,
        make: impl FnOnce(&T) -> U,
    ) -> Result<T, SessionError> {
        let entry = self.get(id).ok_or(SessionError::Missing)?;
        if entry.role != Role::Session {
            return Err(SessionError::Missing);
        }
        let mut slot = match entry.session.try_lock() {
            Ok(slot) => slot,
            Err(std::sync::TryLockError::WouldBlock) => return Err(SessionError::Busy),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(SessionError::Missing),
        };
        let replacement = {
            let current = slot
                .as_ref()
                .and_then(|h| h.value.as_deref())
                .and_then(|v| v.downcast_ref::<T>())
                .ok_or(SessionError::Missing)?;
            if current.activity().busy {
                return Err(SessionError::Busy);
            }
            make(current)
        };
        let progress = replacement.progress();
        let previous = slot
            .replace(SessionHolder::new(replacement))
            .ok_or(SessionError::Missing)?;
        let previous = previous.into_value::<T>().ok_or(SessionError::Missing)?;
        entry.done.store(progress, Ordering::Relaxed);
        Ok(previous)
    }

    /// Keep the registry entry as a tombstone until cleanup has finished.
    /// Otherwise a concurrent request can restore the same persistent id in
    /// the gap between map removal and filesystem cleanup, and the old
    /// cleanup can erase that newly-live session's data.
    pub(crate) fn discard_session<T: SessionResource>(&self, id: &str, reason: SessionCleanup) {
        let Some(entry) = self.get(id) else {
            return;
        };
        if entry.role != Role::Session {
            return;
        }
        let Ok(mut slot) = entry.session.lock() else {
            return;
        };
        if !slot
            .as_ref()
            .and_then(|h| h.value.as_deref())
            .is_some_and(|v| v.is::<T>())
        {
            return;
        }
        let mut holder = slot.take();
        drop(slot);
        if let Some(holder) = &mut holder {
            holder.cleanup_for(reason);
        }
        drop(holder);
        self.remove_session_entry(&entry);
    }

    /// Remove a stale gate only if no operation has acquired it. The entry
    /// remains a tombstone until its cleanup has completed.
    pub(crate) fn discard_idle_session<T: SessionResource>(
        &self,
        id: &str,
        reason: SessionCleanup,
    ) -> bool {
        let Some(entry) = self.get(id) else {
            return false;
        };
        if entry.role != Role::Session {
            return false;
        }
        let Ok(mut slot) = entry.session.try_lock() else {
            return false;
        };
        let Some(value) = slot
            .as_mut()
            .and_then(|holder| holder.value.as_deref_mut())
            .and_then(|value| value.downcast_mut::<T>())
        else {
            return false;
        };
        if value.activity().busy {
            return false;
        }
        let mut holder = slot.take();
        drop(slot);
        if let Some(holder) = &mut holder {
            holder.cleanup_for(reason);
        }
        drop(holder);
        self.remove_session_entry(&entry);
        true
    }

    fn remove_session_entry(&self, entry: &Arc<Task>) {
        if let Ok(mut map) = self.map.lock() {
            if map
                .get(&entry.id)
                .is_some_and(|current| Arc::ptr_eq(current, entry))
            {
                map.remove(&entry.id);
            }
        }
    }

    pub(crate) fn reap_idle_sessions(&self) {
        let entries: Vec<_> = match self.map.lock() {
            Ok(map) => map
                .values()
                .filter(|entry| entry.role == Role::Session)
                .cloned()
                .collect(),
            Err(_) => return,
        };
        let now = Instant::now();
        for entry in entries {
            let mut slot = match entry.session.try_lock() {
                Ok(slot) => slot,
                Err(_) => continue,
            };
            let expired = slot.as_ref().is_some_and(|holder| {
                holder
                    .value
                    .as_deref()
                    .is_some_and(|value| (holder.expired)(value, now))
            });
            if !expired {
                continue;
            }
            let mut holder = slot.take();
            drop(slot);
            if let Some(holder) = &mut holder {
                holder.cleanup_for(SessionCleanup::Expired);
            }
            drop(holder); // cleanup can block; never hold the registry lock
            self.remove_session_entry(&entry);
        }
    }

    pub(crate) fn start_reaper(self: &Arc<Self>) {
        if self.reaper_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let registry = Arc::downgrade(self);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(30));
            match registry.upgrade() {
                Some(registry) => registry.reap_idle_sessions(),
                None => break,
            }
        });
    }

    pub fn remove(&self, id: &str) -> bool {
        match self.map.lock() {
            Ok(mut map) => map.remove(id).is_some(),
            Err(_) => false,
        }
    }
}

fn trim(map: &mut BTreeMap<String, Arc<Task>>, history: usize) {
    // A running transfer must remain addressable for status and cancellation.
    // Limit only completed history; admission limits bound new upload sessions.
    while map
        .values()
        .filter(|t| t.role == Role::Transfer && t.status().terminal())
        .count()
        > history
    {
        let victim = map
            .values()
            .filter(|t| t.role == Role::Transfer && t.status().terminal())
            .min_by_key(|t| t.created)
            .map(|t| t.id.clone());
        match victim {
            Some(id) => {
                map.remove(&id);
            }
            None => return,
        }
    }
}

/// A background executor reports structured failures through the same state
/// machine as transfers. `outcome_unknown` is preserved for SSH side effects.
#[derive(Debug)]
pub(crate) struct JobFailure {
    pub code: i64,
    pub message: String,
    pub data: Value,
}
impl JobFailure {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
            data: Value::Null,
        }
    }
    pub(crate) fn unknown(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
            data: json!({"outcome_unknown": true}),
        }
    }
}
impl From<crate::remote::RemoteError> for JobFailure {
    fn from(error: crate::remote::RemoteError) -> Self {
        Self {
            code: error.code,
            message: error.message,
            data: error.data,
        }
    }
}

fn job_instance() -> &'static str {
    static INSTANCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    INSTANCE.get_or_init(|| crate::uci::random_hex(16)).as_str()
}

pub(crate) fn update_job_fields(dir: &std::path::Path, fields: &Value) -> Result<(), String> {
    let mut state = crate::meta::read_json(&dir.join("state")).ok_or("Cannot read task state")?;
    let destination = state.as_object_mut().ok_or("Invalid task state")?;
    let updates = fields.as_object().ok_or("Invalid task update")?;
    for (key, value) in updates {
        destination.insert(key.clone(), value.clone());
    }
    write_job_state(dir, &state)
}

fn write_job_state(dir: &std::path::Path, state: &Value) -> Result<(), String> {
    crate::private_file::atomic_replace(dir, "state", state.to_string().as_bytes())
        .map_err(|_| "Cannot write task state".to_string())
}

fn persist_job_result(
    entry: &Task,
    dir: &std::path::Path,
    state: &Value,
    terminal: Status,
    write: impl FnOnce(&std::path::Path, &Value) -> Result<(), String>,
) {
    if write(dir, state).is_ok() {
        if terminal == Status::Failed {
            if let Ok(mut message) = entry.message.lock() {
                *message = Some(
                    state["message"]
                        .as_str()
                        .unwrap_or("Task failed")
                        .to_string(),
                );
            }
        }
        entry.resolve_status(terminal);
    } else {
        if let Ok(mut message) = entry.message.lock() {
            *message = Some(
                "Task finished but its result could not be stored; inspect before retrying".into(),
            );
        }
        // A reader may already have observed the replaced final state if the
        // failure was only the subsequent directory sync. Do not overwrite
        // such authoritative terminal evidence.
        entry.set_status(Status::Unknown);
    }
}

pub(crate) fn write_progress(dir: &std::path::Path, bytes: u64, total: u64, phase: &str) {
    write_progress_file(dir, bytes, total, phase, None);
}

pub(crate) fn write_progress_file(
    dir: &std::path::Path,
    bytes: u64,
    total: u64,
    phase: &str,
    path: Option<&str>,
) {
    let body = match path.map(str::trim).filter(|value| !value.is_empty()) {
        Some(path) => format!("{bytes} {total} {phase}\n{path}"),
        None => format!("{bytes} {total} {phase}"),
    };
    let _ = crate::private_file::atomic_replace(dir, "progress", body.as_bytes());
}

fn progress_parts(text: &str) -> Option<(u64, u64, String, Option<String>)> {
    let (first, rest) = match text.split_once('\n') {
        Some((first, rest)) => (first, rest),
        None => (text, ""),
    };
    let mut parts = first.split_whitespace();
    let bytes = parts.next()?.parse().ok()?;
    let total = parts.next()?.parse().ok()?;
    let phase = parts.next().unwrap_or("copying").to_string();
    let path = rest
        .lines()
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    Some((bytes, total, phase, path))
}

fn tail_file(path: &std::path::Path, limit: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    let start = file.metadata().ok()?.len().saturating_sub(limit);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut data = Vec::new();
    file.take(limit).read_to_end(&mut data).ok()?;
    Some(String::from_utf8_lossy(&data).into_owned())
}

impl TaskRegistry {
    /// Execute a single background callback. State is persisted before the
    /// callback starts; unfinished in-process jobs become unknown on restart.
    pub(crate) fn spawn_job(
        self: &Arc<Self>,
        state: Value,
        worker: impl FnOnce(std::path::PathBuf) -> Result<(), JobFailure> + Send + 'static,
    ) -> Result<String, String> {
        self.spawn_job_prepared(state, |_| Ok(None), worker)
    }

    fn spawn_job_prepared(
        self: &Arc<Self>,
        state: Value,
        prepare: impl FnOnce(&std::path::Path) -> Result<Option<LegacyPublication>, String>,
        worker: impl FnOnce(std::path::PathBuf) -> Result<(), JobFailure> + Send + 'static,
    ) -> Result<String, String> {
        self.spawn_job_with_launcher(state, prepare, worker, None, |callback| {
            std::thread::Builder::new()
                .name("harbor-task".into())
                .spawn(callback)
                .map(|_| ())
        })
    }

    /// A request is only an intent, not proof the worker stopped. The worker
    /// must check `requested()` at safe boundaries and call `seal()` before
    /// the first irreversible final publication; it must never publish if
    /// `seal()` returns false. Unsupported executors use `spawn_job` instead.
    pub(crate) fn spawn_cancellable_job(
        self: &Arc<Self>,
        state: Value,
        worker: impl FnOnce(std::path::PathBuf, Arc<JobControl>) -> Result<(), JobFailure>
            + Send
            + 'static,
    ) -> Result<String, String> {
        let control = Arc::new(JobControl::default());
        let for_worker = Arc::clone(&control);
        self.spawn_job_with_launcher(
            state,
            |_| Ok(None),
            move |dir| worker(dir, for_worker),
            Some(control),
            |callback| {
                std::thread::Builder::new()
                    .name("harbor-task".into())
                    .spawn(callback)
                    .map(|_| ())
            },
        )
    }

    fn spawn_job_with_launcher(
        self: &Arc<Self>,
        mut state: Value,
        prepare: impl FnOnce(&std::path::Path) -> Result<Option<LegacyPublication>, String>,
        worker: impl FnOnce(std::path::PathBuf) -> Result<(), JobFailure> + Send + 'static,
        control: Option<Arc<JobControl>>,
        launch: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
    ) -> Result<String, String> {
        use std::path::Path;
        crate::tasks::ensure_remote_dir().map_err(|_| "Unsafe runtime directory".to_string())?;
        let task_id = crate::uci::random_hex(16);
        let dir = Path::new(crate::remote::REMOTE_ROOT).join(&task_id);
        crate::tasks::create_private_dir(&dir).map_err(|_| "Cannot create task".to_string())?;
        let Some(map) = state.as_object_mut() else {
            let _ = std::fs::remove_dir_all(&dir);
            return Err("Invalid task state".to_string());
        };
        map.insert("task_id".into(), json!(task_id));
        map.entry("started")
            .or_insert(json!(crate::meta::now_secs()));
        map.entry("done").or_insert(json!(false));
        map.entry("success").or_insert(json!(false));
        map.entry("state").or_insert(json!("running"));
        map.insert("worker_instance".into(), json!(job_instance()));
        map.insert("cancelable".into(), json!(control.is_some()));
        map.insert("cancel_requested".into(), json!(false));
        let mut publication = match write_job_state(&dir, &state).and_then(|()| prepare(&dir)) {
            Ok(publication) => publication,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(error);
            }
        };
        let kind = state["operation"].as_str().unwrap_or("job").to_string();
        let path = state["path"]
            .as_str()
            .or_else(|| state["output_path"].as_str())
            .unwrap_or("")
            .to_string();
        let entry = Arc::new(Task {
            id: task_id.clone(),
            kind,
            path,
            total: Counter::new(state["total"].as_u64().unwrap_or(0)),
            done: Counter::new(0),
            status: Mutex::new(Status::Running),
            cancel: AtomicBool::new(false),
            cancel_notify: tokio::sync::Notify::new(),
            message: Mutex::new(None),
            created: crate::meta::now_secs(),
            started: Instant::now(),
            role: Role::Job,
            session: Mutex::new(None),
            upload_session: Mutex::new(None),
            job_control: control,
        });
        if let Ok(mut map) = self.map.lock() {
            map.insert(task_id.clone(), entry.clone());
            while map
                .values()
                .filter(|t| t.role == Role::Job && t.status().terminal())
                .count()
                > self.history
            {
                let victim = map
                    .values()
                    .filter(|t| t.role == Role::Job && t.status().terminal())
                    .min_by_key(|t| t.created)
                    .map(|t| t.id.clone());
                if let Some(victim) = victim {
                    map.remove(&victim);
                } else {
                    break;
                }
            }
        } else {
            drop(publication); // restore legacy paths before deleting the target directory
            let _ = std::fs::remove_dir_all(&dir);
            return Err("Task registry is unavailable".into());
        }
        let initial = state;
        let path = dir.clone();
        let result = launch(Box::new(move || {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker(path.clone())))
                    .unwrap_or_else(|_| {
                        Err(JobFailure::unknown(
                            "Task ended unexpectedly; its outcome is unknown",
                        ))
                    });
            if let Some(control) = &entry.job_control {
                control.finish();
            }
            let mut state = crate::meta::read_json(&path.join("state")).unwrap_or(initial);
            state["cancelable"] = json!(false);
            state["cancel_requested"] = json!(entry
                .job_control
                .as_ref()
                .is_some_and(|control| control.requested()));
            state["done"] = json!(true);
            state["success"] = json!(result.is_ok());
            state["finished"] = json!(crate::meta::now_secs());
            state["state"] = json!(if result.is_ok() { "success" } else { "failed" });
            state["exit_code"] = json!(if result.is_ok() { 0 } else { 1 });
            let terminal = match result {
                Ok(()) => Status::Completed,
                Err(error) => {
                    let terminal = if error.data["outcome_unknown"] == json!(true) {
                        state["state"] = json!("unknown");
                        state["exit_code"] = Value::Null;
                        Status::Unknown
                    } else if error.data["cancelled"] == json!(true) {
                        state["state"] = json!("cancelled");
                        state["exit_code"] = Value::Null;
                        Status::Cancelled
                    } else {
                        if let Some(code) = error.data["exit_code"].as_i64() {
                            state["exit_code"] = json!(code);
                        }
                        Status::Failed
                    };
                    state["error"] = json!(error.message);
                    state["message"] = json!(error.message);
                    state["failure_code"] = json!(error.code);
                    if !error.data.is_null() {
                        state["failure_data"] = error.data;
                    }
                    terminal
                }
            };
            // A live entry is not terminal until final state has either been
            // persisted or the failure to persist has been recorded as
            // unknown. This prevents history trimming from losing the worker
            // before its result is available.
            persist_job_result(&entry, &path, &state, terminal, write_job_state);
            let _ = std::fs::write(
                path.join("result"),
                if state["success"] == json!(true) {
                    "0\n"
                } else {
                    "1\n"
                },
            );
        }));
        if result.is_err() {
            if let Ok(mut map) = self.map.lock() {
                map.remove(&task_id);
            }
            drop(publication);
            let _ = std::fs::remove_dir_all(&dir);
            return Err("Cannot start task worker".into());
        }
        if let Some(publication) = &mut publication {
            publication.commit();
        }
        Ok(task_id)
    }

    pub(crate) fn job_status(&self, task_id: &str) -> Result<Value, String> {
        use std::path::Path;
        if task_id.len() != 32 || !task_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid task ID".into());
        }
        crate::tasks::ensure_remote_dir().map_err(|_| "Unsafe runtime directory".to_string())?;
        let dir = Path::new(crate::remote::REMOTE_ROOT).join(task_id);
        if !dir.exists() {
            return Ok(json!({ "state": "gone", "done": true }));
        }
        crate::tasks::check_private_dir(&dir).map_err(|_| "Unsafe task directory".to_string())?;
        let attached = self.get(task_id).filter(|entry| entry.role == Role::Job);
        let mut state = match crate::meta::read_json(&dir.join("state")) {
            Some(value) if value.is_object() && value["done"].is_boolean() => value,
            _ if attached
                .as_ref()
                .is_some_and(|entry| !entry.status().terminal()) =>
            {
                // A transient read/corrupt state is not evidence that the live
                // worker stopped. Let polling retry and retain cancellation.
                return Err("Cannot read task state; the worker may still be running".into());
            }
            _ => json!({ "state": "unknown", "done": true, "success": false }),
        };
        let mut authoritative_terminal = state["done"] == json!(true);
        let attached_terminal = attached
            .as_ref()
            .is_none_or(|entry| entry.status().terminal());
        if state["done"] == json!(false) && attached_terminal {
            // The worker may have atomically replaced the state after the
            // first read and then become terminal (or been trimmed). Reread
            // before concluding that a final result could not be persisted.
            if let Some(current) = crate::meta::read_json(&dir.join("state")) {
                if current["done"] == json!(true) {
                    state = current;
                    authoritative_terminal = true;
                }
            }
        }
        if state["done"] == json!(false) {
            let rcfile = dir.join("rc");
            let local = state["executor"] == json!("local_process");
            if local && crate::tasks::task_finished(&rcfile.to_string_lossy()) {
                // rc is written after the child finishes, even if the monitor
                // could not persist its final JSON or the daemon restarted.
                let rc = crate::tasks::task_exit_code(&rcfile.to_string_lossy());
                state["done"] = json!(true);
                state["success"] = json!(rc == 0);
                state["state"] = json!(if rc == 0 { "success" } else { "failed" });
                state["exit_code"] = json!(rc);
                authoritative_terminal = true;
            } else if state["worker_instance"].as_str() != Some(job_instance()) {
                if local && process_matches(&state) {
                    // A detached local process survived the daemon; continue
                    // polling its private rc file rather than replaying it.
                    state["state"] = json!("running");
                } else {
                    state["done"] = json!(true);
                    state["success"] = json!(false);
                    state["state"] = json!("unknown");
                    state["message"] = json!("Task status is unknown after service restart");
                }
            } else if local
                && state["pid"].as_i64().unwrap_or(0) > 0
                && !crate::tasks::process_alive(state["pid"].as_i64().unwrap_or(0))
            {
                state["done"] = json!(true);
                state["success"] = json!(false);
                state["state"] = json!("unknown");
                state["message"] = json!("Task process ended without an exit result");
            } else if !(local && process_matches(&state)) && attached_terminal {
                // A worker whose final state could not be persisted, or whose
                // in-memory entry is gone, must not appear to run forever.
                // Its external side effects may still be unresolved.
                state["done"] = json!(true);
                state["success"] = json!(false);
                state["state"] = json!("unknown");
                state["exit_code"] = Value::Null;
                state["message"] =
                    json!("Task result could not be confirmed; inspect before retrying");
                if !state["failure_data"].is_object() {
                    state["failure_data"] = json!({});
                }
                state["failure_data"]["outcome_unknown"] = json!(true);
            }
        }
        // Only an attached, live worker can honor a cooperative request.
        // Persisted jobs after restart are never advertised as cancellable.
        let live_control = attached
            .as_ref()
            .and_then(|entry| entry.job_control.clone());
        state["cancelable"] = json!(
            state["done"] == json!(false)
                && live_control
                    .as_ref()
                    .is_some_and(|control| control.accepting())
        );
        if let Some(control) = &live_control {
            state["cancel_requested"] = json!(control.requested());
        }
        let progress = std::fs::read_to_string(dir.join("progress")).unwrap_or_default();
        if let Some((bytes, total, phase, path)) = progress_parts(&progress) {
            state["bytes"] = json!(bytes);
            state["total"] = json!(total);
            state["phase"] = json!(phase);
            if let Some(path) = path {
                state["current_file"] = json!(path);
            }
            if total > 0 {
                state["percent"] =
                    json!(((bytes.min(total) as f64) * 100.0 / total as f64).round() as i64);
            }
            if let Some(entry) = self.get(task_id).filter(|entry| entry.role == Role::Job) {
                entry.done.store(bytes, Ordering::Relaxed);
                entry.total.store(total, Ordering::Relaxed);
            }
        }
        if let Some(log) = tail_file(&dir.join("log"), 16384) {
            state["log"] = json!(log);
        }
        if let Some(entry) = self.get(task_id).filter(|entry| entry.role == Role::Job) {
            if let Some(processed) = state["processed"].as_u64() {
                entry.done.store(processed, Ordering::Relaxed);
            }
            if let Some(total) = state["total"].as_u64() {
                entry.total.store(total, Ordering::Relaxed);
            }
            if state["done"] == json!(true) && authoritative_terminal {
                if state["state"] == json!("unknown") {
                    entry.set_status(Status::Unknown);
                } else if state["state"] == json!("cancelled") {
                    entry.resolve_status(Status::Cancelled);
                } else if state["success"] == json!(true) {
                    entry.resolve_status(Status::Completed);
                } else {
                    entry.resolve_status(Status::Failed);
                    if let Ok(mut message) = entry.message.lock() {
                        *message = Some(
                            state["message"]
                                .as_str()
                                .unwrap_or("Task failed")
                                .to_string(),
                        );
                    }
                }
            }
        }
        if let Some(entry) = attached.as_ref() {
            let elapsed = entry.started.elapsed().as_secs_f64();
            state["elapsed"] = json!((elapsed * 10.0).round() / 10.0);
        }
        Ok(state)
    }
}

/// Specification for a local process job. Compatibility links let older
/// clients continue reading the familiar single-slot state/log/rc paths.
pub(crate) struct LocalProcess {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub header: String,
    pub legacy_state: &'static str,
    pub legacy_log: &'static str,
    pub legacy_rc: &'static str,
}

fn process_start_token(pid: i64) -> Option<String> {
    if pid <= 0 || !crate::tasks::process_alive(pid) {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Everything after `) ` starts at field 3; starttime is field 22.
    let start = stat.rsplit_once(") ")?.1.split_whitespace().nth(19)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    Some(format!("{}:{}", boot.trim(), start))
}

fn process_matches(state: &Value) -> bool {
    let Some(expected) = state["process_start"].as_str() else {
        return false;
    };
    let pid = state["pid"].as_i64().unwrap_or(0);
    process_start_token(pid).as_deref() == Some(expected)
}

/// Compatibility paths are published transactionally. Old files remain in
/// the same directory until the registry entry and worker thread exist; a
/// dropped guard restores them if either step fails.
struct LegacyPublication {
    links: Vec<(
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        bool,
        bool,
    )>,
    committed: bool,
}
impl LegacyPublication {
    fn commit(&mut self) {
        self.committed = true;
        for (_, temp, backup, had_old, _) in &self.links {
            let _ = std::fs::remove_file(temp);
            if *had_old {
                let _ = std::fs::remove_file(backup);
            }
        }
    }
}
impl Drop for LegacyPublication {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for (path, temp, backup, had_old, installed) in self.links.iter().rev() {
            if *installed {
                let _ = std::fs::remove_file(path);
            }
            if *had_old {
                let _ = std::fs::rename(backup, path);
            }
            let _ = std::fs::remove_file(temp);
        }
    }
}

fn publish_legacy_links(
    dir: &std::path::Path,
    links: [(&str, &str); 3],
) -> Result<LegacyPublication, String> {
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    let nonce = crate::uci::random_hex(8);
    let mut publication = LegacyPublication {
        links: Vec::new(),
        committed: false,
    };
    for (index, (legacy, name)) in links.iter().enumerate() {
        let path = PathBuf::from(legacy);
        let parent = path.parent().ok_or("Invalid legacy task path")?;
        let temp = parent.join(format!(".task-link-{nonce}-{index}"));
        let backup = parent.join(format!(".task-backup-{nonce}-{index}"));
        symlink(dir.join(name), &temp)
            .map_err(|_| "Cannot prepare task compatibility links".to_string())?;
        publication.links.push((path, temp, backup, false, false));
    }
    for (path, temp, backup, had_old, installed) in &mut publication.links {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() || meta.file_type().is_symlink() => {
                std::fs::rename(&path, &backup)
                    .map_err(|_| "Cannot publish task compatibility links".to_string())?;
                *had_old = true;
            }
            Ok(_) => return Err("Cannot publish task compatibility links".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("Cannot publish task compatibility links".into()),
        }
        std::fs::rename(&temp, &path)
            .map_err(|_| "Cannot publish task compatibility links".to_string())?;
        *installed = true;
    }
    Ok(publication)
}

impl TaskRegistry {
    pub(crate) fn spawn_process(
        self: &Arc<Self>,
        mut state: Value,
        process: LocalProcess,
    ) -> Result<Value, String> {
        state["executor"] = json!("local_process");
        state["pid"] = json!(0);
        let links = [
            (process.legacy_state, "state"),
            (process.legacy_log, "log"),
            (process.legacy_rc, "rc"),
        ];
        let fallback = state.clone();
        let id = self.spawn_job_prepared(
            state,
            move |dir| publish_legacy_links(dir, links).map(Some),
            move |dir| {
                let log = dir.join("log").to_string_lossy().into_owned();
                let rcfile = dir.join("rc").to_string_lossy().into_owned();
                let pid = crate::tasks::spawn_logged(
                    &process.program,
                    &process.args,
                    process.cwd.as_deref(),
                    &log,
                    &rcfile,
                    &process.header,
                )
                .ok_or_else(|| JobFailure::new("Cannot start task process"))?;
                let identity = process_start_token(pid);
                update_job_fields(&dir, &json!({"pid": pid, "process_start": identity})).map_err(
                    |_| {
                        JobFailure::unknown(
                            "Process started but its identity could not be recorded",
                        )
                    },
                )?;
                loop {
                    if crate::tasks::task_finished(&rcfile) {
                        let rc = crate::tasks::task_exit_code(&rcfile);
                        return if rc == 0 {
                            Ok(())
                        } else {
                            Err(JobFailure {
                                code: 1,
                                message: format!("Command exited with status {rc}"),
                                data: json!({"exit_code": rc}),
                            })
                        };
                    }
                    if !crate::tasks::process_alive(pid)
                        || identity.as_ref().is_some_and(|expected| {
                            process_start_token(pid).as_ref() != Some(expected)
                        })
                    {
                        if crate::tasks::task_finished(&rcfile) {
                            continue;
                        }
                        return Err(JobFailure::unknown(
                            "Task process ended without an exit result",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            },
        )?;
        // Starting the worker is the point of no return; failure to read its
        // status must not make the caller believe no work was scheduled.
        self.job_status(&id).or_else(|_| {
            let mut status = fallback;
            status["task_id"] = json!(id);
            status["state"] = json!("running");
            status["done"] = json!(false);
            status["success"] = json!(false);
            Ok(status)
        })
    }
}

impl TaskRegistry {
    pub(crate) fn record_completed(
        self: &Arc<Self>,
        mut state: Value,
        legacy_state: &'static str,
        legacy_log: &'static str,
        legacy_rc: &'static str,
    ) -> Result<Value, String> {
        state["executor"] = json!("local_immediate");
        state["state"] = json!("running");
        state["done"] = json!(false);
        state["success"] = json!(false);
        let links = [
            (legacy_state, "state"),
            (legacy_log, "log"),
            (legacy_rc, "rc"),
        ];
        let id = self.spawn_job_prepared(
            state,
            move |dir| publish_legacy_links(dir, links).map(Some),
            |dir| {
                crate::private_file::atomic_replace(&dir, "rc", b"0")
                    .map_err(|_| JobFailure::new("Cannot persist task completion"))?;
                Ok(())
            },
        )?;
        // This executor has no side effects and performs no blocking work.
        for _ in 0..200 {
            let status = self.job_status(&id)?;
            if status["done"] == json!(true) {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.job_status(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_dir() -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("harbor-job-registry-{}", crate::uci::random_hex(8)));
        std::fs::create_dir(&path).unwrap();
        path
    }
    fn leak(path: &std::path::Path) -> &'static str {
        Box::leak(path.to_string_lossy().into_owned().into_boxed_str())
    }
    fn wait_until(mut f: impl FnMut() -> Option<Value>) -> Value {
        for _ in 0..300 {
            if let Some(result) = f() {
                return result;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("task did not reach the expected state")
    }

    #[test]
    fn cancellation_request_and_publication_barrier_cannot_both_win() {
        for _ in 0..200 {
            let control = Arc::new(JobControl::default());
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let worker = control.clone();
            let begin = barrier.clone();
            let thread = std::thread::spawn(move || {
                begin.wait();
                worker.seal()
            });
            barrier.wait();
            let requested = control.request();
            let sealed = thread.join().unwrap();
            assert_ne!(requested, sealed, "request and publication cannot both win");
            if requested {
                assert!(control.requested());
                assert!(!control.seal());
            } else {
                assert!(!control.requested());
                assert!(!control.request());
            }
        }
    }

    #[test]
    fn cancellable_jobs_are_pending_until_worker_confirms_and_after_barrier_refuse_requests() {
        let registry = Arc::new(TaskRegistry::new(16));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let id = registry
            .spawn_cancellable_job(json!({"operation":"copy"}), move |_, control| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                if control.requested() {
                    return Err(JobFailure {
                        code: 1,
                        message: "cancelled before publication".into(),
                        data: json!({"cancelled":true}),
                    });
                }
                assert!(control.seal());
                Ok(())
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(registry.job_status(&id).unwrap()["cancelable"], true);
        assert!(registry.request_job_cancel(&id));
        let pending = registry.job_status(&id).unwrap();
        assert_eq!(pending["done"], false);
        assert_eq!(pending["cancel_requested"], true);
        assert_eq!(pending["cancelable"], false);
        assert_eq!(registry.get(&id).unwrap().status(), Status::Running);
        assert!(
            registry.request_job_cancel(&id),
            "a repeated pending request is idempotent"
        );
        release_tx.send(()).unwrap();
        let done = wait_until(|| {
            let value = registry.job_status(&id).unwrap();
            (value["done"] == json!(true)).then_some(value)
        });
        assert_eq!(done["state"], "cancelled");
        assert_eq!(done["success"], false);
        assert_eq!(done["cancel_requested"], true);
        assert_eq!(registry.get(&id).unwrap().status(), Status::Cancelled);
        assert!(!registry.request_job_cancel(&id));
        let (sealed_tx, sealed_rx) = std::sync::mpsc::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let sealed = registry
            .spawn_cancellable_job(json!({"operation":"copy"}), move |_, control| {
                assert!(control.seal());
                sealed_tx.send(()).unwrap();
                finish_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
        sealed_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(registry.job_status(&sealed).unwrap()["cancelable"], false);
        assert!(!registry.request_job_cancel(&sealed));
        finish_tx.send(()).unwrap();
        let status = wait_until(|| {
            let value = registry.job_status(&sealed).unwrap();
            (value["done"] == json!(true)).then_some(value)
        });
        assert_eq!(status["success"], true);
        for id in [id, sealed] {
            let _ =
                std::fs::remove_dir_all(std::path::Path::new(crate::remote::REMOTE_ROOT).join(id));
        }
    }

    #[test]
    fn unreadable_state_does_not_mark_a_live_worker_terminal_or_remove_it() {
        let registry = Arc::new(TaskRegistry::new(16));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let id = registry
            .spawn_cancellable_job(json!({"operation":"copy"}), move |_, control| {
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                assert!(control.requested());
                Err(JobFailure {
                    code: 1,
                    message: "cancelled".into(),
                    data: json!({"cancelled":true}),
                })
            })
            .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let dir = std::path::Path::new(crate::remote::REMOTE_ROOT).join(&id);
        std::fs::write(dir.join("state"), b"invalid JSON").unwrap();
        assert!(
            registry.job_status(&id).is_err(),
            "the polling client must retry"
        );
        assert_eq!(registry.get(&id).unwrap().status(), Status::Running);
        assert!(
            registry.request_job_cancel(&id),
            "the live worker must remain cancellable"
        );
        release_tx.send(()).unwrap();
        let status = wait_until(|| {
            registry
                .job_status(&id)
                .ok()
                .filter(|value| value["done"] == json!(true))
        });
        assert_eq!(status["state"], "cancelled");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unpersisted_job_result_is_unknown_not_forever_running_and_durable_state_resolves_it() {
        crate::tasks::ensure_remote_dir().unwrap();
        let registry = Arc::new(TaskRegistry::new(16));
        for terminal in [Status::Completed, Status::Cancelled] {
            let id = crate::uci::random_hex(16);
            let dir = std::path::Path::new(crate::remote::REMOTE_ROOT).join(&id);
            crate::tasks::create_private_dir(&dir).unwrap();
            let initial = json!({"task_id":id,"worker_instance":job_instance(),"done":false,"state":"running","staging_path":"/test/stage"});
            write_job_state(&dir, &initial).unwrap();
            let mut entry = TaskRegistry::new_transfer("download", "/test", 0);
            let inner = Arc::get_mut(&mut entry).unwrap();
            inner.id = id.clone();
            inner.role = Role::Job;
            entry.set_status(Status::Running);
            registry
                .map
                .lock()
                .unwrap()
                .insert(id.clone(), entry.clone());
            let final_state = json!({"task_id":id,"worker_instance":job_instance(),"done":true,
                "success":terminal == Status::Completed,
                "state":if terminal == Status::Completed { "success" } else { "cancelled" }});
            persist_job_result(&entry, &dir, &final_state, terminal, |_, _| {
                Err("injected persistence failure".into())
            });
            assert_eq!(entry.status(), Status::Unknown);
            let status = registry.job_status(&id).unwrap();
            assert_eq!(status["state"], "unknown");
            assert_eq!(status["done"], true);
            assert_eq!(status["failure_data"]["outcome_unknown"], true);
            assert_eq!(status["staging_path"], "/test/stage");
            // If a later successful write (or a rename followed by a failed
            // directory sync) provides final evidence, it resolves unknown.
            write_job_state(&dir, &final_state).unwrap();
            let resolved = registry.job_status(&id).unwrap();
            assert_eq!(resolved["state"], final_state["state"]);
            assert_eq!(entry.status(), terminal);
            registry.remove(&id);
            write_job_state(&dir, &initial).unwrap();
            assert_eq!(
                registry.job_status(&id).unwrap()["state"],
                "unknown",
                "an untracked job cannot appear to run forever"
            );
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn cancellation_request_does_not_mask_preflight_failure_or_worker_panic() {
        let registry = Arc::new(TaskRegistry::new(16));
        for panic_worker in [false, true] {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let id = registry
                .spawn_cancellable_job(json!({"operation":"copy"}), move |_, _| {
                    ready_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    if panic_worker {
                        panic!("injected cancellable worker failure");
                    }
                    Err(JobFailure {
                        code: 1,
                        message: "missing tool".into(),
                        data: json!({"preflight_safe":true,"missing_tool":"tar"}),
                    })
                })
                .unwrap();
            ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(registry.request_job_cancel(&id));
            release_tx.send(()).unwrap();
            let status = wait_until(|| {
                let value = registry.job_status(&id).unwrap();
                (value["done"] == json!(true)).then_some(value)
            });
            assert_eq!(status["cancel_requested"], true);
            assert_eq!(status["success"], false);
            assert_eq!(
                status["state"],
                if panic_worker { "unknown" } else { "failed" }
            );
            if panic_worker {
                assert_eq!(status["failure_data"]["outcome_unknown"], true);
            } else {
                assert_eq!(status["failure_data"]["preflight_safe"], true);
            }
            let _ =
                std::fs::remove_dir_all(std::path::Path::new(crate::remote::REMOTE_ROOT).join(id));
        }
    }

    #[test]
    fn process_jobs_share_registry_and_survive_status_reader_restart() {
        let root = temp_dir();
        let registry = Arc::new(TaskRegistry::new(16));
        let paths = [root.join("state.json"), root.join("log"), root.join("rc")];
        let process = |script: &str| LocalProcess {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            cwd: None,
            header: "test".into(),
            legacy_state: leak(&paths[0]),
            legacy_log: leak(&paths[1]),
            legacy_rc: leak(&paths[2]),
        };
        let started = registry
            .spawn_process(
                json!({"operation":"test"}),
                process("printf hello; sleep 1; exit 0"),
            )
            .unwrap();
        let id = started["task_id"].as_str().unwrap().to_string();
        assert!(registry.get(&id).is_some());
        let running = wait_until(|| {
            let status = registry.job_status(&id).unwrap();
            (status["process_start"].as_str().is_some() && status["pid"].as_i64().unwrap_or(0) > 0)
                .then_some(status)
        });
        assert_eq!(running["state"], json!("running"));
        assert!(std::fs::symlink_metadata(&paths[0])
            .unwrap()
            .file_type()
            .is_symlink());
        let dir = std::path::Path::new(crate::remote::REMOTE_ROOT).join(&id);
        update_job_fields(&dir, &json!({"worker_instance":"a-different-process"})).unwrap();
        assert_eq!(
            registry.job_status(&id).unwrap()["state"],
            json!("running"),
            "live pid and start token must survive restart"
        );
        let done = wait_until(|| {
            let status = registry.job_status(&id).unwrap();
            (status["done"] == json!(true)).then_some(status)
        });
        assert_eq!(done["success"], json!(true));
        assert!(done["log"].as_str().unwrap().contains("hello"));
        // Simulate a daemon crash after the child wrote rc but before the
        // worker persisted its final state. The result is recovered, not rerun.
        update_job_fields(
            &dir,
            &json!({"done":false,"success":false,"state":"running","worker_instance":"old"}),
        )
        .unwrap();
        let recovered = TaskRegistry::new(16).job_status(&id).unwrap();
        assert_eq!(recovered["success"], json!(true));
        assert_eq!(recovered["exit_code"], json!(0));
        let failed = registry
            .spawn_process(json!({"operation":"test"}), process("printf bad; exit 7"))
            .unwrap();
        let fail_id = failed["task_id"].as_str().unwrap().to_string();
        let failed = wait_until(|| {
            let status = registry.job_status(&fail_id).unwrap();
            (status["done"] == json!(true)).then_some(status)
        });
        assert_eq!(failed["state"], json!("failed"));
        assert_eq!(failed["exit_code"], json!(7));
        assert!(failed["log"].as_str().unwrap().contains("bad"));
        assert!(
            registry.job_status(&id).unwrap()["log"]
                .as_str()
                .unwrap()
                .contains("hello"),
            "old task log must not be overwritten"
        );
        for id in [&id, &fail_id] {
            let _ =
                std::fs::remove_dir_all(std::path::Path::new(crate::remote::REMOTE_ROOT).join(id));
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_publication_failure_restores_prior_files_and_never_runs_worker() {
        let root = temp_dir();
        let registry = Arc::new(TaskRegistry::new(8));
        let state = root.join("state");
        let log = root.join("log");
        let rc = root.join("rc");
        std::fs::write(&state, b"old state").unwrap();
        std::fs::create_dir(&log).unwrap();
        let marker = root.join("executed");
        let process = LocalProcess {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), format!("touch {}", marker.display())],
            cwd: None,
            header: String::new(),
            legacy_state: leak(&state),
            legacy_log: leak(&log),
            legacy_rc: leak(&rc),
        };
        assert!(registry
            .spawn_process(json!({"operation":"test"}), process)
            .is_err());
        assert_eq!(std::fs::read(&state).unwrap(), b"old state");
        assert!(log.is_dir());
        assert!(!marker.exists());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_paths_are_restored_when_registry_or_worker_launch_fails() {
        let root = temp_dir();
        let state = root.join("state");
        let log = root.join("log");
        let rc = root.join("rc");
        for (path, bytes) in [
            (&state, b"old state".as_slice()),
            (&log, b"old log".as_slice()),
            (&rc, b"7".as_slice()),
        ] {
            std::fs::write(path, bytes).unwrap();
        }
        let links = [
            (leak(&state), "state"),
            (leak(&log), "log"),
            (leak(&rc), "rc"),
        ];
        let registry = Arc::new(TaskRegistry::new(8));
        let marker = root.join("executed");
        let worker_marker = marker.clone();
        let result = registry.spawn_job_with_launcher(
            json!({"operation":"test"}),
            move |dir| publish_legacy_links(dir, links).map(Some),
            move |_| {
                std::fs::write(worker_marker, b"bad").unwrap();
                Ok(())
            },
            None,
            |_| Err(std::io::Error::other("injected thread launch failure")),
        );
        assert!(result.is_err());
        assert!(!marker.exists());
        assert_eq!(std::fs::read(&state).unwrap(), b"old state");
        assert_eq!(std::fs::read(&log).unwrap(), b"old log");
        assert_eq!(std::fs::read(&rc).unwrap(), b"7");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 3);
        assert_eq!(registry.active(), 0);
        // A poisoned map occurs after publication too; its failure must roll
        // back the same way and must never launch the process.
        let poisoned = Arc::new(TaskRegistry::new(8));
        let poison_clone = poisoned.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison_clone.map.lock().unwrap();
            panic!("injected registry failure");
        })
        .join();
        let process = LocalProcess {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), format!("touch {}", marker.display())],
            cwd: None,
            header: String::new(),
            legacy_state: leak(&state),
            legacy_log: leak(&log),
            legacy_rc: leak(&rc),
        };
        assert!(poisoned
            .spawn_process(json!({"operation":"test"}), process)
            .is_err());
        assert_eq!(std::fs::read(&state).unwrap(), b"old state");
        assert_eq!(std::fs::read(&log).unwrap(), b"old log");
        assert_eq!(std::fs::read(&rc).unwrap(), b"7");
        assert!(!marker.exists());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 3);
        let _ = std::fs::remove_dir_all(root);
    }

    struct DummySession {
        activity: SessionActivity,
        bytes: u64,
        cleanups: Arc<AtomicUsize>,
    }
    impl SessionResource for DummySession {
        fn activity(&self) -> &SessionActivity {
            &self.activity
        }
        fn activity_mut(&mut self) -> &mut SessionActivity {
            &mut self.activity
        }
        fn progress(&self) -> u64 {
            self.bytes
        }
        fn cleanup(&mut self, _reason: SessionCleanup) {
            self.cleanups.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn locked_session_returns_busy_without_blocking_other_sessions() {
        let registry = Arc::new(TaskRegistry::new(8));
        let cleanups = Arc::new(AtomicUsize::new(0));
        for id in ["slow", "other"] {
            registry
                .insert_session(
                    id.into(),
                    "test_upload",
                    "/test",
                    1,
                    DummySession {
                        activity: SessionActivity::new(Duration::from_secs(10)),
                        bytes: 0,
                        cleanups: cleanups.clone(),
                    },
                )
                .unwrap_or_else(|_| panic!("cannot insert"));
        }
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_registry = registry.clone();
        let worker = std::thread::spawn(move || {
            worker_registry.with_session::<DummySession, _>("slow", |_| {
                locked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        });
        locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let now = Instant::now();
        assert_eq!(
            registry.try_with_session::<DummySession, _>("slow", |_| ()),
            Err(SessionError::Busy)
        );
        assert!(matches!(
            registry.acquire_session::<DummySession>("slow"),
            Err(SessionError::Busy)
        ));
        assert!(matches!(
            registry.take_session::<DummySession>("slow", true),
            Err(SessionError::Busy)
        ));
        registry.reap_idle_sessions();
        let mut other = registry.acquire_session::<DummySession>("other").unwrap();
        other.finish();
        assert!(
            now.elapsed() < Duration::from_millis(200),
            "busy admission must not wait for I/O"
        );
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        registry.discard_session::<DummySession>("slow", SessionCleanup::Aborted);
        registry.discard_session::<DummySession>("other", SessionCleanup::Aborted);
        assert_eq!(cleanups.load(Ordering::SeqCst), 2);
    }

    struct BlockingCleanup {
        activity: SessionActivity,
        started: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }
    impl SessionResource for BlockingCleanup {
        fn activity(&self) -> &SessionActivity {
            &self.activity
        }
        fn activity_mut(&mut self) -> &mut SessionActivity {
            &mut self.activity
        }
        fn progress(&self) -> u64 {
            0
        }
        fn cleanup(&mut self, _reason: SessionCleanup) {
            let _ = self.started.send(());
            let _ = self.release.recv_timeout(Duration::from_secs(5));
        }
    }
    #[test]
    fn cleanup_retains_tombstone_until_filesystem_deletion_finishes() {
        for reap in [true, false] {
            let registry = Arc::new(TaskRegistry::new(8));
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let mut activity = SessionActivity::new(Duration::from_secs(1));
            activity.touched = Instant::now() - Duration::from_secs(2);
            registry
                .insert_session(
                    "persistent".into(),
                    "test",
                    "/tmp",
                    0,
                    BlockingCleanup {
                        activity,
                        started: started_tx,
                        release: release_rx,
                    },
                )
                .unwrap_or_else(|_| panic!("cannot insert session"));
            let worker_registry = registry.clone();
            let worker = std::thread::spawn(move || {
                if reap {
                    worker_registry.reap_idle_sessions();
                } else {
                    worker_registry
                        .discard_session::<BlockingCleanup>("persistent", SessionCleanup::Expired);
                }
            });
            started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(
                registry.get("persistent").is_some(),
                "tombstone must block restore"
            );
            assert!(registry
                .insert_session(
                    "persistent".into(),
                    "test",
                    "/tmp",
                    0,
                    DummySession {
                        activity: SessionActivity::new(Duration::from_secs(1)),
                        bytes: 0,
                        cleanups: Arc::new(AtomicUsize::new(0)),
                    }
                )
                .is_err());
            release_tx.send(()).unwrap();
            worker.join().unwrap();
            assert!(registry.get("persistent").is_none());
            registry
                .insert_session(
                    "persistent".into(),
                    "test",
                    "/tmp",
                    0,
                    DummySession {
                        activity: SessionActivity::new(Duration::from_secs(1)),
                        bytes: 0,
                        cleanups: Arc::new(AtomicUsize::new(0)),
                    },
                )
                .unwrap_or_else(|_| panic!("completed cleanup must permit a new registration"));
        }
    }

    #[test]
    fn session_leases_progress_reap_and_cleanup_share_the_task_entry() {
        let registry = Arc::new(TaskRegistry::new(8));
        let cleanups = Arc::new(AtomicUsize::new(0));
        registry
            .insert_session(
                "session".into(),
                "test_upload",
                "/test",
                10,
                DummySession {
                    activity: SessionActivity::new(Duration::from_secs(1)),
                    bytes: 0,
                    cleanups: cleanups.clone(),
                },
            )
            .unwrap_or_else(|_| panic!("cannot insert"));
        let mut lease = registry.acquire_session::<DummySession>("session").unwrap();
        assert!(matches!(
            registry.acquire_session::<DummySession>("session"),
            Err(SessionError::Busy)
        ));
        assert!(matches!(
            registry.take_session::<DummySession>("session", true),
            Err(SessionError::Busy)
        ));
        registry.with_session::<DummySession, _>("session", |s| {
            s.bytes = 4;
            s.activity.touched = Instant::now() - Duration::from_secs(2);
        });
        assert_eq!(
            registry
                .get("session")
                .unwrap()
                .done
                .load(Ordering::Relaxed),
            4
        );
        registry.reap_idle_sessions();
        assert!(registry.get("session").is_some());
        lease.finish();
        registry.with_session::<DummySession, _>("session", |s| {
            s.activity.touched = Instant::now() - Duration::from_secs(2)
        });
        registry.reap_idle_sessions();
        assert!(registry.get("session").is_none());
        assert_eq!(cleanups.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn progress_file_keeps_phase_and_optional_current_path() {
        let root =
            std::env::temp_dir().join(format!("harbor-progress-{}", crate::uci::random_hex(8)));
        std::fs::create_dir_all(&root).unwrap();
        write_progress(&root, 3, 9, "copying");
        let plain = std::fs::read_to_string(root.join("progress")).unwrap();
        assert_eq!(progress_parts(&plain), Some((3, 9, "copying".into(), None)));
        write_progress_file(&root, 4, 9, "verifying", Some("dir/file.txt"));
        let with_path = std::fs::read_to_string(root.join("progress")).unwrap();
        assert_eq!(
            progress_parts(&with_path),
            Some((4, 9, "verifying".into(), Some("dir/file.txt".into())))
        );
        write_progress(&root, 9, 9, "complete");
        let done = std::fs::read_to_string(root.join("progress")).unwrap();
        assert!(done.ends_with(" complete"), "{done}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
