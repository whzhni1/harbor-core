#[cfg(target_has_atomic = "64")]
pub use std::sync::atomic::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
use std::sync::atomic::Ordering;

#[cfg(not(target_has_atomic = "64"))]
pub struct AtomicU64(std::sync::Mutex<u64>);

#[cfg(not(target_has_atomic = "64"))]
impl AtomicU64 {
    pub const fn new(value: u64) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, u64> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn load(&self, _: Ordering) -> u64 {
        *self.lock()
    }

    #[allow(dead_code)]
    pub fn store(&self, value: u64, _: Ordering) {
        *self.lock() = value;
    }

    pub fn fetch_add(&self, amount: u64, _: Ordering) -> u64 {
        let mut slot = self.lock();
        let previous = *slot;
        *slot = previous.wrapping_add(amount);
        previous
    }

    pub fn fetch_sub(&self, amount: u64, _: Ordering) -> u64 {
        let mut slot = self.lock();
        let previous = *slot;
        *slot = previous.wrapping_sub(amount);
        previous
    }

    pub fn compare_exchange_weak(
        &self,
        current: u64,
        new: u64,
        _: Ordering,
        _: Ordering,
    ) -> Result<u64, u64> {
        let mut slot = self.lock();
        if *slot == current {
            *slot = new;
            Ok(current)
        } else {
            Err(*slot)
        }
    }
}
