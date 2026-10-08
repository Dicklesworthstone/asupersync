//! Task-local storage: values bound to one future while it runs.
//!
//! [`task_local!`](crate::task_local) declares a [`LocalKey`]. A value is
//! bound with [`LocalKey::scope`], which wraps a future: while that future is
//! polled the value is visible through [`LocalKey::with`] and
//! [`LocalKey::get`], from any code the future calls, on whichever worker
//! thread polls it. Outside the scope the key is unset again.
//!
//! The usual uses are request-scoped context that should not be threaded
//! through every signature: a request or trace id, the authenticated tenant,
//! a logging span. The semantics match `tokio::task_local!`, so code that
//! uses it ports unchanged:
//!
//! - The value belongs to the wrapped future, not to the task that polls it.
//!   A task spawned inside the scope does not see it; wrap the child's future
//!   in its own `scope` (for example `KEY.scope(KEY.get(), child)`) to pass
//!   it on.
//! - Scopes nest. An inner scope of the same key shadows the outer value until
//!   the inner future completes.
//! - The wrapped future is dropped inside its scope, so its destructors can
//!   still read the value.
//!
//! ```
//! use asupersync::runtime::RuntimeBuilder;
//!
//! asupersync::task_local! {
//!     static REQUEST_ID: u64;
//! }
//!
//! async fn log_line(message: &str) -> String {
//!     format!("[{}] {message}", REQUEST_ID.get())
//! }
//!
//! let runtime = RuntimeBuilder::current_thread().build().unwrap();
//! let line = runtime.block_on(REQUEST_ID.scope(7, async { log_line("served").await }));
//! assert_eq!(line, "[7] served");
//! assert!(REQUEST_ID.try_get().is_err());
//! ```

use pin_project::{pin_project, pinned_drop};
use std::cell::RefCell;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Declares one or more task-local keys.
///
/// Each `static NAME: Type;` becomes a [`LocalKey<Type>`](crate::runtime::task_local::LocalKey).
/// Bind a value with [`LocalKey::scope`] (around a future) or
/// [`LocalKey::sync_scope`] (around a closure); see the
/// [module documentation](crate::runtime::task_local).
///
/// ```
/// asupersync::task_local! {
///     /// The tenant the current request acts for.
///     pub static TENANT: String;
///     static ATTEMPT: u32;
/// }
///
/// let tenant = TENANT.sync_scope("acme".to_owned(), || TENANT.get());
/// assert_eq!(tenant, "acme");
/// ```
#[macro_export]
macro_rules! task_local {
    () => {};

    ($(#[$attr:meta])* $vis:vis static $name:ident: $t:ty; $($rest:tt)*) => {
        $crate::__task_local_inner!($(#[$attr])* $vis $name, $t);
        $crate::task_local!($($rest)*);
    };

    ($(#[$attr:meta])* $vis:vis static $name:ident: $t:ty) => {
        $crate::__task_local_inner!($(#[$attr])* $vis $name, $t);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __task_local_inner {
    ($(#[$attr:meta])* $vis:vis $name:ident, $t:ty) => {
        $(#[$attr])*
        $vis static $name: $crate::runtime::task_local::LocalKey<$t> = {
            ::std::thread_local! {
                static __ASUPERSYNC_TASK_LOCAL: ::std::cell::RefCell<::std::option::Option<$t>> =
                    const { ::std::cell::RefCell::new(::std::option::Option::None) };
            }
            $crate::runtime::task_local::LocalKey::__new(__ASUPERSYNC_TASK_LOCAL)
        };
    };
}

/// A task-local key, declared with [`task_local!`](crate::task_local).
pub struct LocalKey<T: 'static> {
    inner: std::thread::LocalKey<RefCell<Option<T>>>,
}

/// The key has no value: the caller is not inside a scope of it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AccessError {
    _private: (),
}

impl fmt::Debug for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessError")
    }
}

impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("task-local value not set")
    }
}

impl std::error::Error for AccessError {}

enum ScopeError {
    /// `scope` was entered from inside `with` on the same key.
    Borrowed,
    /// The thread's storage is being destroyed.
    Destroyed,
}

impl ScopeError {
    #[track_caller]
    fn panic(&self) -> ! {
        match self {
            Self::Borrowed => {
                panic!("cannot enter a task-local scope while the task-local value is borrowed")
            }
            Self::Destroyed => panic!(
                "cannot enter a task-local scope during or after destruction of the thread's storage"
            ),
        }
    }
}

impl<T: 'static> LocalKey<T> {
    #[doc(hidden)]
    pub const fn __new(inner: std::thread::LocalKey<RefCell<Option<T>>>) -> Self {
        Self { inner }
    }

    /// Runs `future` with this key bound to `value`.
    ///
    /// The value is visible while the returned future is polled, including
    /// inside its destructor, and is dropped with it.
    pub fn scope<F: Future>(&'static self, value: T, future: F) -> TaskLocalFuture<T, F> {
        TaskLocalFuture {
            local: self,
            slot: Some(value),
            future: Some(future),
        }
    }

    /// Runs `f` with this key bound to `value`, for synchronous code.
    ///
    /// # Panics
    ///
    /// Panics when called from inside [`Self::with`] on the same key.
    #[track_caller]
    pub fn sync_scope<F, R>(&'static self, value: T, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let mut slot = Some(value);
        match self.scope_inner(&mut slot, f) {
            Ok(result) => result,
            Err(error) => error.panic(),
        }
    }

    /// Calls `f` with a reference to the bound value.
    ///
    /// # Panics
    ///
    /// Panics when the key has no value here; [`Self::try_with`] reports that
    /// instead.
    #[track_caller]
    pub fn with<F, R>(&'static self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        match self.try_with(f) {
            Ok(result) => result,
            Err(_) => panic!("cannot access a task-local value outside a scope that sets it"),
        }
    }

    /// Calls `f` with a reference to the bound value, or reports that the key
    /// has none here.
    pub fn try_with<F, R>(&'static self, f: F) -> Result<R, AccessError>
    where
        F: FnOnce(&T) -> R,
    {
        // `f` runs while the value is borrowed: a nested `with` on this key
        // works, and a nested `scope` panics rather than replacing the value
        // under the borrow.
        self.inner
            .try_with(|cell| {
                let value = cell.try_borrow().ok()?;
                value.as_ref().map(f)
            })
            .ok()
            .flatten()
            .ok_or(AccessError { _private: () })
    }

    /// Swaps `slot` into the key for the duration of `f`, then swaps it back,
    /// also when `f` panics.
    fn scope_inner<F, R>(&'static self, slot: &mut Option<T>, f: F) -> Result<R, ScopeError>
    where
        F: FnOnce() -> R,
    {
        struct Restore<'a, T: 'static> {
            local: &'static LocalKey<T>,
            slot: &'a mut Option<T>,
        }

        impl<T: 'static> Drop for Restore<'_, T> {
            fn drop(&mut self) {
                // The swap-in below succeeded, so the storage exists and no
                // borrow of it outlives `f`.
                let _ = self.local.inner.try_with(|cell| {
                    if let Ok(mut current) = cell.try_borrow_mut() {
                        std::mem::swap(self.slot, &mut *current);
                    }
                });
            }
        }

        self.inner
            .try_with(|cell| {
                cell.try_borrow_mut()
                    .map(|mut current| std::mem::swap(slot, &mut *current))
                    .map_err(|_| ScopeError::Borrowed)
            })
            .map_err(|_| ScopeError::Destroyed)??;

        let restore = Restore { local: self, slot };
        let result = f();
        drop(restore);
        Ok(result)
    }
}

impl<T: Clone + 'static> LocalKey<T> {
    /// A clone of the bound value.
    ///
    /// # Panics
    ///
    /// Panics when the key has no value here; [`Self::try_get`] reports that
    /// instead.
    #[track_caller]
    pub fn get(&'static self) -> T {
        self.with(Clone::clone)
    }

    /// A clone of the bound value, or [`AccessError`] outside a scope.
    pub fn try_get(&'static self) -> Result<T, AccessError> {
        self.try_with(Clone::clone)
    }
}

impl<T: 'static> fmt::Debug for LocalKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("LocalKey { .. }")
    }
}

/// A future running with a task-local value bound; returned by
/// [`LocalKey::scope`].
#[pin_project(PinnedDrop)]
pub struct TaskLocalFuture<T: 'static, F> {
    local: &'static LocalKey<T>,
    slot: Option<T>,
    #[pin]
    future: Option<F>,
}

impl<T: 'static, F> TaskLocalFuture<T, F> {
    /// Takes the bound value out of this future.
    ///
    /// Returns `None` when it was already taken. Taking it before the future
    /// completes leaves the key unset for the rest of the future's polls.
    pub fn take_value(self: Pin<&mut Self>) -> Option<T> {
        self.project().slot.take()
    }
}

impl<T: 'static, F: Future> Future for TaskLocalFuture<T, F> {
    type Output = F::Output;

    #[track_caller]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut future = this.future;
        let polled = this.local.scope_inner(this.slot, || {
            let inner = future.as_mut().as_pin_mut()?;
            let poll = inner.poll(cx);
            if poll.is_ready() {
                // Dropped inside the scope, like a future dropped early.
                future.set(None);
            }
            Some(poll)
        });
        match polled {
            Ok(Some(poll)) => poll,
            Ok(None) => panic!("`TaskLocalFuture` polled after completion"),
            Err(error) => error.panic(),
        }
    }
}

#[pinned_drop]
impl<T: 'static, F> PinnedDrop for TaskLocalFuture<T, F> {
    fn drop(self: Pin<&mut Self>) {
        let this = self.project();
        if std::mem::needs_drop::<F>() && this.future.is_some() {
            // Drop the unfinished future inside its scope so its destructors
            // see the value. If the scope cannot be entered (a borrow is
            // live, or the thread is exiting) it is dropped outside it.
            let mut future = this.future;
            let _ = this.local.scope_inner(this.slot, || future.set(None));
        }
    }
}

impl<T: fmt::Debug + 'static, F> fmt::Debug for TaskLocalFuture<T, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskLocalFuture")
            .field("value", &self.slot)
            .finish_non_exhaustive()
    }
}
