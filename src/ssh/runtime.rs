use std::cell::Cell;
use std::future::Future;
use std::sync::OnceLock;
use tokio::runtime::{Handle, Runtime};

thread_local! {
    static ATTACHED: Cell<bool> = const { Cell::new(false) };
}

/// Production uses the axum runtime (`Handle::try_current`). Tests/CLI without
/// one get a process-wide runtime so russh pumps (PTY, streams) outlive the
/// sync facade call. Never construct a second runtime when axum is already in
/// the thread.
fn fallback_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("harbor-ssh")
            .build()
            .expect("ssh runtime")
    })
}

fn current_or_fallback() -> Handle {
    Handle::try_current().unwrap_or_else(|_| fallback_runtime().handle().clone())
}

/// Drive `fut` on the process Tokio runtime.
///
/// Production uses the axum multi-thread runtime. Sync facades re-enter it with
/// `block_in_place` + `Handle::block_on`. Dedicated pump threads started by
/// `spawn_attached` are not workers, so they `Handle::block_on` directly.
pub fn block_on<T>(fut: impl Future<Output = T>) -> T {
    match Handle::try_current() {
        Ok(handle) if ATTACHED.with(Cell::get) => handle.block_on(fut),
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
        Err(_) => fallback_runtime().block_on(fut),
    }
}

pub fn spawn<F>(fut: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    drop(current_or_fallback().spawn(fut));
}

/// Run `f` on a dedicated OS thread that stays attached to the current runtime
/// so russh handles created here can be `.await`ed there.
pub fn spawn_attached<F>(name: &str, f: F) -> std::io::Result<std::thread::JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    let handle = current_or_fallback();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            ATTACHED.with(|flag| flag.set(true));
            let _guard = handle.enter();
            f();
        })
}
