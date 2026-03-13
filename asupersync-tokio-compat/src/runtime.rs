//! Tokio runtime context bridge.
//!
//! Provides [`AsupersyncRuntime`], the keystone primitive that implements
//! Tokio's runtime handle interface using Asupersync's executor.
//!
//! This does NOT start a Tokio runtime. It intercepts Tokio runtime
//! operations and routes them to Asupersync equivalents.

use std::future::{Future, poll_fn};
use std::task::Poll;

use asupersync::Cx;
use asupersync::types::RegionId;

use crate::CancellationMode;
use crate::cancel::{CancelAware, CancelResult};

/// A Tokio-compatible runtime handle backed by Asupersync's executor.
///
/// This does NOT start a Tokio runtime. It intercepts Tokio runtime
/// operations and routes them to Asupersync equivalents.
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

    /// Run a synchronous closure with this runtime's `Cx` installed as current.
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
/// Returns `None` when cancellation is observed before the future completes.
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
            if cx.is_cancel_requested() {
                future.as_mut().request_cancel();
            }

            match future.as_mut().poll(poll_cx) {
                Poll::Ready(
                    CancelResult::Completed(value) | CancelResult::CancellationIgnored(value),
                ) => Poll::Ready(Some(value)),
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
    fn test_with_tokio_context_sync_preserves_current_cx() {
        let cx = Cx::for_testing();
        let _cx_guard = Cx::set_current(Some(cx.clone()));
        let region = with_tokio_context_sync(|| Cx::current().expect("current cx").region_id());
        assert_eq!(region, cx.region_id());
    }
}
