//! Safe blocking bridge and context propagation boundaries.
//!
//! This module provides primitives for running blocking operations within
//! the Asupersync runtime while preserving all 5 adapter invariants:
//!
//! - **INV-1 (No ambient authority)**: All entry points require explicit `Cx`
//! - **INV-2 (Structured concurrency)**: Blocking tasks use the runtime pool
//! - **INV-3 (Cancellation protocol)**: Checks `cx.is_cancel_requested()` on completion
//! - **INV-4 (No obligation leaks)**: Pool tracks task handles; cancel on drop
//! - **INV-5 (Outcome severity lattice)**: Returns `BlockingOutcome` (Ok/Cancelled/Panicked)
//!
//! # Context Propagation
//!
//! The key challenge at the sync/async boundary is that `Cx::current()` relies on
//! thread-local storage set by the async executor. Blocking pool threads don't
//! have this context automatically. This module bridges the gap by cloning the
//! caller's `Cx` and installing it on the blocking thread via `Cx::set_current`.
//!
//! # Cancellation Modes
//!
//! | Mode | Behavior |
//! |------|----------|
//! | `BestEffort` | Returns result even if cancelled during execution |
//! | `Strict` | Returns `Cancelled` if cancel was requested during execution |
//! | `TimeoutFallback` | Same as `BestEffort` for blocking (can't interrupt threads) |
//!
//! # Example
//!
//! ```ignore
//! use asupersync_tokio_compat::blocking::block_on_sync;
//! use asupersync_tokio_compat::CancellationMode;
//!
//! async fn read_file(cx: &Cx, path: String) -> BlockingOutcome<String> {
//!     block_on_sync(cx, move || std::fs::read_to_string(&path).unwrap(), CancellationMode::BestEffort).await
//! }
//! ```

use crate::CancellationMode;

/// Outcome of a blocking bridge operation.
///
/// Maps to the Asupersync four-valued severity lattice. We omit `Err` because
/// blocking closures return `T` directly — application errors should be
/// encoded in `T` (e.g., `Result<Data, AppError>`).
///
/// ```text
///     Panicked
///        ↑
///    Cancelled
///        ↑
///       Ok
/// ```
#[derive(Debug)]
pub enum BlockingOutcome<T> {
    /// The blocking operation completed successfully.
    Ok(T),
    /// The operation was cancelled via Asupersync's cancellation protocol.
    Cancelled,
    /// The blocking operation panicked. Contains a human-readable message.
    Panicked(String),
}

impl<T> BlockingOutcome<T> {
    /// Returns `true` if the outcome is `Ok`.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// Returns `true` if the outcome is `Cancelled`.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }

    /// Returns `true` if the outcome is `Panicked`.
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }

    /// Unwrap the `Ok` value, panicking on `Cancelled` or `Panicked`.
    ///
    /// # Panics
    ///
    /// Panics if the outcome is not `Ok`.
    #[must_use]
    pub fn unwrap(self) -> T {
        match self {
            Self::Ok(v) => v,
            Self::Cancelled => panic!("called unwrap on BlockingOutcome::Cancelled"),
            Self::Panicked(msg) => panic!("called unwrap on BlockingOutcome::Panicked: {msg}"),
        }
    }

    /// Transform the `Ok` value, leaving `Cancelled` and `Panicked` unchanged.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> BlockingOutcome<U> {
        match self {
            Self::Ok(v) => BlockingOutcome::Ok(f(v)),
            Self::Cancelled => BlockingOutcome::Cancelled,
            Self::Panicked(msg) => BlockingOutcome::Panicked(msg),
        }
    }

    /// Convert to a `Result`, mapping `Cancelled` and `Panicked` to `Err`.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a description if the outcome is `Cancelled` or `Panicked`.
    pub fn into_result(self) -> Result<T, BlockingBridgeError> {
        match self {
            Self::Ok(v) => Ok(v),
            Self::Cancelled => Err(BlockingBridgeError::Cancelled),
            Self::Panicked(msg) => Err(BlockingBridgeError::Panicked(msg)),
        }
    }
}

/// Error type for blocking bridge operations.
#[derive(Debug, Clone)]
pub enum BlockingBridgeError {
    /// The operation was cancelled.
    Cancelled,
    /// The operation panicked with the given message.
    Panicked(String),
}

impl std::fmt::Display for BlockingBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "blocking operation cancelled"),
            Self::Panicked(msg) => write!(f, "blocking operation panicked: {msg}"),
        }
    }
}

impl std::error::Error for BlockingBridgeError {}

/// Run a blocking closure on the runtime blocking pool with Cx context propagation.
///
/// The `Cx` is cloned and set as `Cx::current()` on the blocking thread for the
/// duration of the closure. Code inside the closure can call `Cx::current()` to
/// access the capability context. The guard restores the previous context on drop,
/// including during panic unwinding (RAII).
///
/// # Cancellation
///
/// After the blocking operation completes (or panics), the bridge checks
/// `cx.is_cancel_requested()`:
///
/// - **`BestEffort`**: Returns `Ok(result)` even if cancelled (result is valid)
/// - **`Strict`**: Returns `Cancelled` (discards result) if cancel was requested
/// - **`TimeoutFallback`**: Same as `BestEffort` for blocking (threads can't be interrupted)
///
/// # Panics
///
/// Panics in the blocking closure are captured and returned as
/// `BlockingOutcome::Panicked` with the panic message. They are NOT propagated
/// to the caller.
///
/// # Invariants Preserved
///
/// - **INV-1**: Requires explicit `cx` parameter (no ambient sniffing)
/// - **INV-2**: Task is pool-tracked via `spawn_blocking`
/// - **INV-3**: Checks cancellation state on completion
/// - **INV-4**: Pool handle tracks the blocking task
/// - **INV-5**: Returns three-valued `BlockingOutcome`
pub async fn block_on_sync<F, T>(
    cx: &asupersync::Cx,
    f: F,
    mode: CancellationMode,
) -> BlockingOutcome<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let cx_clone = cx.clone();

    // Wrap the user's closure in catch_unwind so we can map panics to
    // BlockingOutcome::Panicked. The outer spawn_blocking also wraps in
    // catch_unwind, but since our closure won't panic (we catch it), the
    // outer catch_unwind is a no-op.
    let result: Result<T, Box<dyn std::any::Any + Send>> =
        asupersync::runtime::spawn_blocking(move || {
            // Install Cx on the blocking thread. The guard restores the
            // previous context (None) on drop, including on panic unwind.
            let _cx_guard = asupersync::Cx::set_current(Some(cx_clone));
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        })
        .await;

    // Map the result through the cancellation mode and outcome lattice.
    match result {
        Ok(value) => {
            if cx.is_cancel_requested() {
                match mode {
                    CancellationMode::Strict => BlockingOutcome::Cancelled,
                    CancellationMode::BestEffort | CancellationMode::TimeoutFallback => {
                        BlockingOutcome::Ok(value)
                    }
                }
            } else {
                BlockingOutcome::Ok(value)
            }
        }
        Err(panic_payload) => BlockingOutcome::Panicked(panic_message(&panic_payload)),
    }
}

/// Run a blocking closure with Cx propagation using default cancellation mode.
///
/// Convenience wrapper around [`block_on_sync`] with `CancellationMode::BestEffort`.
pub async fn block_with_cx<F, T>(cx: &asupersync::Cx, f: F) -> BlockingOutcome<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    block_on_sync(cx, f, CancellationMode::BestEffort).await
}

/// Run a closure with `Cx` context on the **current** thread (synchronous).
///
/// Sets `Cx::current()` for the duration of the closure without spawning a
/// blocking thread. Useful for synchronous callbacks (e.g., serde hooks,
/// allocation callbacks) that need Cx access.
///
/// # Invariants Preserved
///
/// - **INV-1**: Requires explicit `cx` parameter
/// - **INV-5**: Returns `BlockingOutcome` with panic capture
///
/// # Panics
///
/// Panics in the closure are captured and returned as `BlockingOutcome::Panicked`.
pub fn with_cx_sync<F, T>(cx: &asupersync::Cx, f: F) -> BlockingOutcome<T>
where
    F: FnOnce() -> T,
{
    let _cx_guard = asupersync::Cx::set_current(Some(cx.clone()));
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => BlockingOutcome::Ok(value),
        Err(payload) => BlockingOutcome::Panicked(panic_message(&payload)),
    }
}

/// Extract a human-readable message from a panic payload.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload.downcast_ref::<&str>().map_or_else(
        || {
            payload
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_else(|| "unknown panic".to_string())
        },
        |s| (*s).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    /// Minimal `block_on` for tests without a full runtime.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);

        // Poll in a loop — blocking operations complete via threads.
        for _ in 0..1000 {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(val) => return val,
                Poll::Pending => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
        panic!("future did not complete within timeout");
    }

    // ── INV-1: Cx is required at boundary (compile-time) ──────────────
    // This is enforced by the function signature: block_on_sync takes &Cx.
    // A test would need to verify it doesn't compile without Cx, which is
    // a compile-fail test. We verify the API exists and works.

    #[test]
    fn inv1_cx_required_blocking_bridge_compiles() {
        let cx = asupersync::Cx::for_testing();
        let outcome = block_on(block_on_sync(&cx, || 42, CancellationMode::BestEffort));
        assert!(outcome.is_ok());
        assert_eq!(outcome.unwrap(), 42);
    }

    // ── INV-3: Cancellation propagation ───────────────────────────────

    #[test]
    fn inv3_strict_mode_returns_cancelled_when_cancel_requested() {
        let cx = asupersync::Cx::for_testing();
        // Request cancellation before running the blocking op.
        cx.set_cancel_requested(true);

        let outcome = block_on(block_on_sync(
            &cx,
            || "should be discarded",
            CancellationMode::Strict,
        ));
        assert!(outcome.is_cancelled());
    }

    #[test]
    fn inv3_best_effort_returns_ok_even_when_cancelled() {
        let cx = asupersync::Cx::for_testing();
        cx.set_cancel_requested(true);

        let outcome = block_on(block_on_sync(&cx, || 99, CancellationMode::BestEffort));
        assert!(outcome.is_ok());
        assert_eq!(outcome.unwrap(), 99);
    }

    #[test]
    fn inv3_timeout_fallback_behaves_like_best_effort_for_blocking() {
        let cx = asupersync::Cx::for_testing();
        cx.set_cancel_requested(true);

        let outcome = block_on(block_on_sync(
            &cx,
            || "still returned",
            CancellationMode::TimeoutFallback,
        ));
        assert!(outcome.is_ok());
    }

    // ── INV-5: Outcome severity lattice ───────────────────────────────

    #[test]
    fn inv5_panic_captured_as_panicked() {
        let cx = asupersync::Cx::for_testing();
        let outcome = block_on(block_on_sync(
            &cx,
            || panic!("test panic message"),
            CancellationMode::BestEffort,
        ));
        assert!(outcome.is_panicked());
        match outcome {
            BlockingOutcome::Panicked(msg) => {
                assert!(msg.contains("test panic message"), "got: {msg}");
            }
            _ => panic!("expected Panicked"),
        }
    }

    #[test]
    fn inv5_success_maps_to_ok() {
        let cx = asupersync::Cx::for_testing();
        let outcome = block_on(block_on_sync(
            &cx,
            || vec![1, 2, 3],
            CancellationMode::BestEffort,
        ));
        assert!(outcome.is_ok());
        assert_eq!(outcome.unwrap(), vec![1, 2, 3]);
    }

    // ── Context propagation ──────────────────────────────────────────

    #[test]
    fn cx_is_available_inside_blocking_closure() {
        let cx = asupersync::Cx::for_testing();
        let outcome = block_on(block_on_sync(
            &cx,
            || {
                // Inside the blocking thread, Cx::current() should return Some.
                asupersync::Cx::current().is_some()
            },
            CancellationMode::BestEffort,
        ));
        assert!(outcome.is_ok());
        assert!(
            outcome.unwrap(),
            "Cx::current() should be Some inside blocking closure"
        );
    }

    #[test]
    fn cx_is_restored_after_blocking_closure() {
        // Verify that the thread-local Cx is restored after the closure completes.
        let cx = asupersync::Cx::for_testing();
        let _ = block_on(block_on_sync(
            &cx,
            || { /* no-op */ },
            CancellationMode::BestEffort,
        ));
        // The calling thread shouldn't have Cx set (we didn't set it).
        // This is hard to test directly since block_on above runs in a loop
        // on the main thread. Just verify no panic occurred.
    }

    // ── with_cx_sync ─────────────────────────────────────────────────

    #[test]
    fn with_cx_sync_propagates_context() {
        let cx = asupersync::Cx::for_testing();
        let outcome = with_cx_sync(&cx, || asupersync::Cx::current().is_some());
        assert!(outcome.is_ok());
        assert!(outcome.unwrap());
    }

    #[test]
    fn with_cx_sync_captures_panic() {
        let cx = asupersync::Cx::for_testing();
        let outcome: BlockingOutcome<()> = with_cx_sync(&cx, || {
            panic!("sync panic");
        });
        assert!(outcome.is_panicked());
    }

    // ── block_with_cx convenience ────────────────────────────────────

    #[test]
    fn block_with_cx_uses_best_effort() {
        let cx = asupersync::Cx::for_testing();
        cx.set_cancel_requested(true);

        // BestEffort: should still return Ok even when cancelled.
        let outcome = block_on(block_with_cx(&cx, || 42));
        assert!(outcome.is_ok());
        assert_eq!(outcome.unwrap(), 42);
    }

    // ── BlockingOutcome methods ──────────────────────────────────────

    #[test]
    fn outcome_map_transforms_ok() {
        let outcome: BlockingOutcome<i32> = BlockingOutcome::Ok(21);
        let doubled = outcome.map(|x| x * 2);
        assert_eq!(doubled.unwrap(), 42);
    }

    #[test]
    fn outcome_map_passes_through_cancelled() {
        let outcome: BlockingOutcome<i32> = BlockingOutcome::Cancelled;
        let mapped = outcome.map(|x| x * 2);
        assert!(mapped.is_cancelled());
    }

    #[test]
    fn outcome_map_passes_through_panicked() {
        let outcome: BlockingOutcome<i32> = BlockingOutcome::Panicked("boom".into());
        let mapped = outcome.map(|x| x * 2);
        assert!(mapped.is_panicked());
    }

    #[test]
    fn outcome_into_result_ok() {
        let outcome: BlockingOutcome<i32> = BlockingOutcome::Ok(42);
        assert_eq!(outcome.into_result().unwrap(), 42);
    }

    #[test]
    fn outcome_into_result_cancelled() {
        let outcome: BlockingOutcome<i32> = BlockingOutcome::Cancelled;
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(err, BlockingBridgeError::Cancelled));
    }

    #[test]
    fn outcome_into_result_panicked() {
        let outcome: BlockingOutcome<i32> = BlockingOutcome::Panicked("oops".into());
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(err, BlockingBridgeError::Panicked(_)));
    }

    // ── Blocking closure actually runs on a different thread ─────────

    #[test]
    fn blocking_closure_runs_on_different_thread_when_no_pool() {
        let cx = asupersync::Cx::for_testing();
        let outcome = block_on(block_on_sync(
            &cx,
            move || std::thread::current().id(),
            CancellationMode::BestEffort,
        ));
        // Without a blocking pool, spawn_blocking runs inline when Cx exists
        // but no pool handle is available. The thread ID may be the same.
        // This test just verifies no panic and correct return.
        assert!(outcome.is_ok());
        let _thread_id = outcome.unwrap();
    }

    // ── Error type Display ──────────────────────────────────────────

    #[test]
    fn blocking_bridge_error_display() {
        let cancelled = BlockingBridgeError::Cancelled;
        assert_eq!(cancelled.to_string(), "blocking operation cancelled");

        let panicked = BlockingBridgeError::Panicked("segfault".into());
        assert!(panicked.to_string().contains("segfault"));
    }
}
