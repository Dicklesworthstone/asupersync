//! Internal synchronization facade over `parking_lot` or `std::sync`.
//!
//! When the `parking_lot` feature is enabled (all default/desktop profiles),
//! this re-exports `parking_lot`'s primitives directly. When `parking_lot` is
//! disabled (e.g. `slim-runtime-profile`), it provides thin non-poisoning
//! wrappers around `std::sync` so the runtime compiles with zero external
//! lock-crate dependencies.

#[cfg(feature = "full-concurrency")]
pub use parking_lot::{
    Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, WaitTimeoutResult,
};

#[cfg(not(feature = "full-concurrency"))]
mod std_impl {
    use std::fmt;
    use std::ops::{Deref, DerefMut};
    use std::sync::{PoisonError, TryLockError};
    use std::time::{Duration, Instant};

    /// Non-poisoning wrapper around `std::sync::Mutex`.
    pub struct Mutex<T: ?Sized> {
        inner: std::sync::Mutex<T>,
    }

    /// Guard returned by [`Mutex::lock`] and [`Mutex::try_lock`].
    pub struct MutexGuard<'a, T: ?Sized + 'a> {
        inner: Option<std::sync::MutexGuard<'a, T>>,
    }

    impl<T> Mutex<T> {
        #[inline]
        pub const fn new(value: T) -> Self {
            Self {
                inner: std::sync::Mutex::new(value),
            }
        }

        #[inline]
        #[allow(dead_code)]
        pub fn into_inner(self) -> T {
            self.inner
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl<T: ?Sized> Mutex<T> {
        #[inline]
        pub fn lock(&self) -> MutexGuard<'_, T> {
            MutexGuard {
                inner: Some(self.inner.lock().unwrap_or_else(PoisonError::into_inner)),
            }
        }

        #[inline]
        pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
            match self.inner.try_lock() {
                Ok(guard) => Some(MutexGuard { inner: Some(guard) }),
                Err(TryLockError::Poisoned(poisoned)) => Some(MutexGuard {
                    inner: Some(poisoned.into_inner()),
                }),
                Err(TryLockError::WouldBlock) => None,
            }
        }

        #[allow(dead_code)]
        pub fn try_lock_for(&self, timeout: Duration) -> Option<MutexGuard<'_, T>> {
            if let Some(guard) = self.try_lock() {
                return Some(guard);
            }
            if timeout.is_zero() {
                return None;
            }
            let deadline = Instant::now() + timeout;
            let mut spins = 0u32;
            loop {
                if spins < 8 {
                    std::thread::yield_now();
                    spins += 1;
                } else {
                    let now = Instant::now();
                    if now >= deadline {
                        return self.try_lock();
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
                if let Some(guard) = self.try_lock() {
                    return Some(guard);
                }
                if Instant::now() >= deadline {
                    return None;
                }
            }
        }

        #[inline]
        #[allow(dead_code)]
        pub fn get_mut(&mut self) -> &mut T {
            self.inner.get_mut().unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl<T: Default> Default for Mutex<T> {
        #[inline]
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.inner.fmt(f)
        }
    }

    impl<T: ?Sized> Deref for MutexGuard<'_, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            self.inner.as_ref().expect("mutex guard active")
        }
    }

    impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut T {
            self.inner.as_mut().expect("mutex guard active")
        }
    }

    impl<T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&**self, f)
        }
    }

    impl<T: ?Sized + fmt::Display> fmt::Display for MutexGuard<'_, T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(&**self, f)
        }
    }

    /// Non-poisoning wrapper around `std::sync::RwLock`.
    pub struct RwLock<T: ?Sized> {
        inner: std::sync::RwLock<T>,
    }

    /// Shared read guard returned by [`RwLock::read`].
    pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
        inner: std::sync::RwLockReadGuard<'a, T>,
    }

    /// Exclusive write guard returned by [`RwLock::write`].
    pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
        inner: std::sync::RwLockWriteGuard<'a, T>,
    }

    impl<T> RwLock<T> {
        #[inline]
        pub const fn new(value: T) -> Self {
            Self {
                inner: std::sync::RwLock::new(value),
            }
        }

        #[inline]
        #[allow(dead_code)]
        pub fn into_inner(self) -> T {
            self.inner
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl<T: ?Sized> RwLock<T> {
        #[inline]
        pub fn read(&self) -> RwLockReadGuard<'_, T> {
            RwLockReadGuard {
                inner: self.inner.read().unwrap_or_else(PoisonError::into_inner),
            }
        }

        #[inline]
        #[allow(dead_code)]
        pub fn read_recursive(&self) -> RwLockReadGuard<'_, T> {
            self.read()
        }

        #[inline]
        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            RwLockWriteGuard {
                inner: self.inner.write().unwrap_or_else(PoisonError::into_inner),
            }
        }

        #[inline]
        #[allow(dead_code)]
        pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
            match self.inner.try_read() {
                Ok(guard) => Some(RwLockReadGuard { inner: guard }),
                Err(TryLockError::Poisoned(poisoned)) => Some(RwLockReadGuard {
                    inner: poisoned.into_inner(),
                }),
                Err(TryLockError::WouldBlock) => None,
            }
        }

        #[inline]
        #[allow(dead_code)]
        pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
            match self.inner.try_write() {
                Ok(guard) => Some(RwLockWriteGuard { inner: guard }),
                Err(TryLockError::Poisoned(poisoned)) => Some(RwLockWriteGuard {
                    inner: poisoned.into_inner(),
                }),
                Err(TryLockError::WouldBlock) => None,
            }
        }

        #[inline]
        #[allow(dead_code)]
        pub fn get_mut(&mut self) -> &mut T {
            self.inner.get_mut().unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl<T: Default> Default for RwLock<T> {
        #[inline]
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLock<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.inner.fmt(f)
        }
    }

    impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            &self.inner
        }
    }

    impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLockReadGuard<'_, T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&**self, f)
        }
    }

    impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            &self.inner
        }
    }

    impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut T {
            &mut self.inner
        }
    }

    impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLockWriteGuard<'_, T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&**self, f)
        }
    }

    /// Result returned by [`Condvar::wait_for`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WaitTimeoutResult(bool);

    impl WaitTimeoutResult {
        #[inline]
        #[allow(dead_code)]
        pub const fn timed_out(self) -> bool {
            self.0
        }
    }

    /// Condition variable matching `parking_lot::Condvar`'s non-poisoning API.
    pub struct Condvar {
        inner: std::sync::Condvar,
    }

    impl Condvar {
        #[inline]
        pub const fn new() -> Self {
            Self {
                inner: std::sync::Condvar::new(),
            }
        }

        #[inline]
        pub fn notify_one(&self) {
            self.inner.notify_one();
        }

        #[inline]
        pub fn notify_all(&self) {
            self.inner.notify_all();
        }

        #[inline]
        #[allow(dead_code)]
        pub fn wait<T>(&self, guard: &mut MutexGuard<'_, T>) {
            let std_guard = guard.inner.take().expect("mutex guard active");
            let returned = self
                .inner
                .wait(std_guard)
                .unwrap_or_else(PoisonError::into_inner);
            guard.inner = Some(returned);
        }

        #[inline]
        #[allow(dead_code)]
        pub fn wait_for<T>(
            &self,
            guard: &mut MutexGuard<'_, T>,
            timeout: Duration,
        ) -> WaitTimeoutResult {
            let std_guard = guard.inner.take().expect("mutex guard active");
            let (returned, wait_res) = self
                .inner
                .wait_timeout(std_guard, timeout)
                .unwrap_or_else(PoisonError::into_inner);
            guard.inner = Some(returned);
            WaitTimeoutResult(wait_res.timed_out())
        }
    }

    impl Default for Condvar {
        #[inline]
        fn default() -> Self {
            Self::new()
        }
    }

    impl fmt::Debug for Condvar {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.inner.fmt(f)
        }
    }
}

#[cfg(not(feature = "full-concurrency"))]
pub use std_impl::{
    Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, WaitTimeoutResult,
};
