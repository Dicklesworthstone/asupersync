//! Asupersync context bridge for compatibility futures.
//!
//! Provides [`AsupersyncRuntime`], which keeps an explicit Asupersync [`Cx`]
//! installed while a closure or future is polled.
//!
//! This module does **not** start or enter a Tokio runtime and does not make
//! `tokio::runtime::Handle::current()` available. A dependency that requires
//! Tokio runtime context must remain behind an independently owned Tokio
//! runtime boundary.

use std::future::{Future, poll_fn};
use std::task::Poll;

use asupersync::Cx;
use asupersync::types::RegionId;

use crate::CancellationMode;
use crate::cancel::{CancelAware, CancelResult};

/// A scoped carrier for an Asupersync [`Cx`].
///
/// This type is not a Tokio runtime handle. It installs only Asupersync's
/// current-`Cx` binding; it neither implements Tokio's runtime handle
/// interface nor makes `tokio::runtime::Handle::current()` succeed.
#[derive(Debug, Clone)]
pub struct AsupersyncRuntime {
    cx: Cx,
    region_id: RegionId,
}

impl AsupersyncRuntime {
    /// Create a new `AsupersyncRuntime` bound to the given context.
    #[must_use]
    pub fn new(cx: &Cx) -> Self {
        Self {
            cx: cx.clone(),
            region_id: cx.region_id(),
        }
    }

    /// Access the underlying Asupersync context captured by this runtime.
    #[must_use]
    pub const fn cx(&self) -> &Cx {
        &self.cx
    }

    /// Return the region that owns tasks spawned through this runtime.
    #[must_use]
    pub const fn region_id(&self) -> RegionId {
        self.region_id
    }

    /// Run a synchronous closure with this bridge's `Cx` installed as current.
    ///
    /// This changes only [`Cx::current`]. It does not enter a Tokio runtime.
    pub fn enter<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _cx_guard = asupersync::Cx::set_current(Some(self.cx.clone()));
        f()
    }
}

/// Run an async future factory with `Cx` installed on every poll.
///
/// Returns `None` once cancellation is observed before the future completes,
/// even if the wrapped future reports `Ready` on the first poll after that
/// cancellation becomes visible to the adapter.
///
/// This function does not install Tokio runtime context. The wrapped future
/// must be independently runnable on the caller's executor; futures that call
/// `tokio::runtime::Handle::current()` still require a separately owned and
/// entered Tokio runtime.
pub async fn with_tokio_context<F, Fut, T>(cx: &Cx, f: F) -> Option<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    if cx.is_cancel_requested() {
        return None;
    }

    let runtime = AsupersyncRuntime::new(cx);
    let future = runtime.enter(f);
    let mut future = std::pin::pin!(CancelAware::new(future, CancellationMode::BestEffort));

    poll_fn(move |poll_cx| {
        runtime.enter(|| {
            let cancellation_observed_before_poll = cx.is_cancel_requested();
            if cancellation_observed_before_poll {
                future.as_mut().request_cancel();
            }

            match future.as_mut().poll(poll_cx) {
                Poll::Ready(CancelResult::Completed(value)) => {
                    // Cancellation can become visible while the wrapped future
                    // is running this poll. Fail closed if it was observed
                    // either before or immediately after the poll completes.
                    if cancellation_observed_before_poll || cx.is_cancel_requested() {
                        let _ = value;
                        Poll::Ready(None)
                    } else {
                        Poll::Ready(Some(value))
                    }
                }
                Poll::Ready(CancelResult::CancellationIgnored(value)) => {
                    let _ = value;
                    Poll::Ready(None)
                }
                Poll::Ready(CancelResult::Cancelled) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        })
    })
    .await
}

/// Run a synchronous closure while preserving any current `Cx` binding.
pub fn with_tokio_context_sync<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    if let Some(cx) = Cx::current() {
        AsupersyncRuntime::new(&cx).enter(f)
    } else {
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::types::CancelKind;
    use futures_lite::future::block_on;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    #[test]
    fn test_asupersync_runtime_creation() {
        let cx = Cx::for_testing();
        let rt = AsupersyncRuntime::new(&cx);
        assert_eq!(rt.region_id(), cx.region_id());
        assert_eq!(rt.cx().region_id(), cx.region_id());
    }

    #[test]
    fn test_enter_installs_current_cx() {
        let cx = Cx::for_testing();
        let rt = AsupersyncRuntime::new(&cx);
        let region = rt.enter(|| Cx::current().expect("current cx").region_id());
        assert_eq!(region, cx.region_id());
    }

    #[test]
    fn test_with_tokio_context_returns_value() {
        let cx = Cx::for_testing();
        let region = block_on(with_tokio_context(&cx, || async {
            Cx::current().expect("current cx").region_id()
        }));
        assert_eq!(region, Some(cx.region_id()));
    }

    #[test]
    fn test_with_tokio_context_returns_none_when_cancelled() {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let result = block_on(with_tokio_context(&cx, || async { 42_u8 }));
        assert_eq!(result, None);
    }

    #[test]
    fn test_with_tokio_context_returns_none_when_cancel_observed_before_ready() {
        struct CancelThenReady {
            cx: Cx,
            polled_once: bool,
        }

        impl Future for CancelThenReady {
            type Output = u8;

            fn poll(mut self: Pin<&mut Self>, poll_cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.polled_once {
                    Poll::Ready(42)
                } else {
                    self.polled_once = true;
                    self.cx.cancel_fast(CancelKind::User);
                    poll_cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }

        let cx = Cx::for_testing();
        let future_cx = cx.clone();
        let result = block_on(with_tokio_context(&cx, move || CancelThenReady {
            cx: future_cx,
            polled_once: false,
        }));
        assert_eq!(result, None);
    }

    #[test]
    fn test_with_tokio_context_returns_none_when_cancel_requested_during_ready_poll() {
        struct CancelAndReady {
            cx: Cx,
        }

        impl Future for CancelAndReady {
            type Output = u8;

            fn poll(self: Pin<&mut Self>, _poll_cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.cx.cancel_fast(CancelKind::User);
                Poll::Ready(42)
            }
        }

        let cx = Cx::for_testing();
        let future_cx = cx.clone();
        let result = block_on(with_tokio_context(&cx, move || CancelAndReady {
            cx: future_cx,
        }));
        assert_eq!(result, None);
    }

    #[test]
    fn test_with_tokio_context_sync_preserves_current_cx() {
        let cx = Cx::for_testing();
        let _cx_guard = Cx::set_current(Some(cx.clone()));
        let region = with_tokio_context_sync(|| Cx::current().expect("current cx").region_id());
        assert_eq!(region, cx.region_id());
    }
}
