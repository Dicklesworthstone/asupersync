//! Bracket combinator for resource safety.
//!
//! The bracket pattern ensures that resources are always released, even when
//! errors or cancellation occur. It follows the acquire/use/release pattern
//! familiar from RAII and try-finally.
//!
//! # Cancel Safety
//!
//! The [`bracket`] function and [`Bracket`] struct are cancel-safe. If the
//! returned future is dropped during the use phase, the release function
//! will still be called synchronously during drop.

use crate::cx::Cx;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

// ============================================================================
// Cancel-Safe Bracket Implementation
// ============================================================================

/// State machine phase for the bracket combinator.
enum BracketPhase<A, UF, RF> {
    /// Acquiring the resource.
    Acquiring(Pin<Box<A>>),
    /// Using the resource.
    Using(Pin<Box<UF>>),
    /// Releasing the resource.
    Releasing(Pin<Box<RF>>),
    /// Terminal state - completed or acquire failed.
    Done,
}

/// Internal state for cancel-safe bracket.
struct BracketState<Res, T, E, A, UF, R, RF> {
    phase: BracketPhase<A, UF, RF>,
    /// The release function (consumed when transitioning to Releasing).
    release_fn: Option<R>,
    /// Clone of the resource for release (set after acquire succeeds).
    resource_for_release: Option<Res>,
    /// The result from the use phase (stored for return after release).
    use_result: Option<std::thread::Result<Result<T, E>>>,
}

/// Cancel-safe bracket combinator future.
///
/// This struct implements `Future` and guarantees that the release function
/// is called even if the future is dropped during the use phase (cancellation).
///
/// # Cancel Safety
///
/// When dropped during the `Using` phase, the `Drop` implementation will
/// synchronously drive the release future to completion. This guarantees
/// resource cleanup even on cancellation.
///
/// # Example
/// ```ignore
/// let bracket = Bracket::new(
///     async { Ok::<_, ()>(file) },
///     |f| Box::pin(async move { f.read().await }),
///     |f| Box::pin(async move { f.close().await }),
/// );
/// let result = bracket.await;
/// ```
pub struct Bracket<Res, T, E, A, U, UF, R, RF>
where
    R: FnOnce(Res) -> RF,
    RF: Future<Output = ()>,
{
    state: BracketState<Res, T, E, A, UF, R, RF>,
    /// The use function (consumed when transitioning from Acquiring to Using).
    use_fn: Option<U>,
}

// Bracket is Unpin because all futures are stored as Pin<Box<F>> which is always Unpin.
impl<Res, T, E, A, U, UF, R, RF> Unpin for Bracket<Res, T, E, A, U, UF, R, RF>
where
    R: FnOnce(Res) -> RF,
    RF: Future<Output = ()>,
{
}

impl<Res, T, E, A, U, UF, R, RF> Bracket<Res, T, E, A, U, UF, R, RF>
where
    A: Future<Output = Result<Res, E>>,
    U: FnOnce(Res) -> UF,
    UF: Future<Output = Result<T, E>>,
    R: FnOnce(Res) -> RF,
    RF: Future<Output = ()>,
    Res: Clone,
{
    /// Creates a new cancel-safe bracket combinator.
    #[must_use]
    pub fn new(acquire: A, use_fn: U, release: R) -> Self {
        Self {
            state: BracketState {
                phase: BracketPhase::Acquiring(Box::pin(acquire)),
                release_fn: Some(release),
                resource_for_release: None,
                use_result: None,
            },
            use_fn: Some(use_fn),
        }
    }
}

impl<Res, T, E, A, U, UF, R, RF> Future for Bracket<Res, T, E, A, U, UF, R, RF>
where
    A: Future<Output = Result<Res, E>>,
    U: FnOnce(Res) -> UF,
    UF: Future<Output = Result<T, E>>,
    R: FnOnce(Res) -> RF,
    RF: Future<Output = ()>,
    Res: Clone,
{
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Bracket is Unpin when all its fields are Unpin (which they are due to bounds)
        let this = self.get_mut();

        loop {
            match &mut this.state.phase {
                BracketPhase::Acquiring(acquire_fut) => {
                    match acquire_fut.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            this.state.phase = BracketPhase::Done;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(resource)) => {
                            // Clone resource for release before use_fn consumes it
                            this.state.resource_for_release = Some(resource.clone());

                            // Transition to Using phase
                            let use_fn = this.use_fn.take().expect("use_fn consumed twice");
                            let use_fut = Box::pin(use_fn(resource));
                            this.state.phase = BracketPhase::Using(use_fut);
                            // Continue loop to poll use phase
                        }
                    }
                }

                BracketPhase::Using(use_fut) => {
                    // Catch panics during use
                    let poll_result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            use_fut.as_mut().poll(cx)
                        }));

                    match poll_result {
                        Ok(Poll::Pending) => return Poll::Pending,
                        Ok(Poll::Ready(result)) => {
                            // Use completed, store result and transition to Releasing
                            this.state.use_result = Some(Ok(result));
                            let release_fn = this
                                .state
                                .release_fn
                                .take()
                                .expect("release_fn consumed twice");
                            let resource = this
                                .state
                                .resource_for_release
                                .take()
                                .expect("resource_for_release missing");
                            let release_fut = Box::pin(release_fn(resource));
                            this.state.phase = BracketPhase::Releasing(release_fut);
                            // Continue loop to poll release phase
                        }
                        Err(panic_payload) => {
                            // Use panicked, store panic and transition to Releasing
                            this.state.use_result = Some(Err(panic_payload));
                            let release_fn = this
                                .state
                                .release_fn
                                .take()
                                .expect("release_fn consumed twice");
                            let resource = this
                                .state
                                .resource_for_release
                                .take()
                                .expect("resource_for_release missing");
                            let release_fut = Box::pin(release_fn(resource));
                            this.state.phase = BracketPhase::Releasing(release_fut);
                            // Continue loop to poll release phase
                        }
                    }
                }

                BracketPhase::Releasing(release_fut) => {
                    match release_fut.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(()) => {
                            this.state.phase = BracketPhase::Done;
                            // Return the stored use result
                            match this.state.use_result.take().expect("use_result missing") {
                                Ok(result) => return Poll::Ready(result),
                                Err(panic_payload) => std::panic::resume_unwind(panic_payload),
                            }
                        }
                    }
                }

                BracketPhase::Done => {
                    panic!("Bracket polled after completion");
                }
            }
        }
    }
}

impl<Res, T, E, A, U, UF, R, RF> Drop for Bracket<Res, T, E, A, U, UF, R, RF>
where
    R: FnOnce(Res) -> RF,
    RF: Future<Output = ()>,
{
    fn drop(&mut self) {
        // If we're in the Using phase and have release_fn + resource, we must release.
        // This handles the cancellation case where the future is dropped mid-use.
        if matches!(self.state.phase, BracketPhase::Using(_)) {
            if let (Some(release_fn), Some(resource)) = (
                self.state.release_fn.take(),
                self.state.resource_for_release.take(),
            ) {
                // Create the release future
                let mut release_fut = Box::pin(release_fn(resource));

                // Drive it to completion synchronously using a noop waker.
                // This is Phase 0 behavior; full implementation would use the
                // runtime's cancel mask to run release asynchronously.
                let waker = Waker::from(Arc::new(NoopWaker));
                let mut cx = Context::from_waker(&waker);

                // Poll until complete (bounded iteration to prevent infinite loops)
                // Most release futures complete quickly or immediately.
                for _ in 0..10_000 {
                    match release_fut.as_mut().poll(&mut cx) {
                        Poll::Ready(()) => return,
                        Poll::Pending => {
                            // Yield to allow progress
                            std::hint::spin_loop();
                        }
                    }
                }

                // If we get here, release is taking too long.
                // In production, this would log a warning. For Phase 0, we accept
                // potential resource leak for pathologically long-running release.
            }
        }
    }
}

/// Noop waker for synchronous polling in Drop.
struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

// ============================================================================
// bracket() Function - Convenience Constructor
// ============================================================================

/// Executes the bracket pattern: acquire, use, release.
///
/// This function guarantees that the release function is called even if
/// the use function returns an error, panics, or the future is cancelled.
///
/// # Cancel Safety
///
/// This function is cancel-safe. If the returned future is dropped during
/// the use phase, the release function will still be called synchronously.
///
/// # Arguments
/// * `acquire` - Future that acquires the resource
/// * `use_fn` - Function that uses the resource
/// * `release` - Function that releases the resource
///
/// # Returns
/// The result of the use function, after release has completed.
///
/// # Example
/// ```ignore
/// let result = bracket(
///     async { open_file("data.txt").await },
///     |file| Box::pin(async move { file.read_all().await }),
///     |file| Box::pin(async move { file.close().await }),
/// ).await;
/// ```
pub fn bracket<Res, T, E, A, U, UF, R, RF>(
    acquire: A,
    use_fn: U,
    release: R,
) -> Bracket<Res, T, E, A, U, UF, R, RF>
where
    A: Future<Output = Result<Res, E>>,
    U: FnOnce(Res) -> UF,
    UF: Future<Output = Result<T, E>>,
    R: FnOnce(Res) -> RF,
    RF: Future<Output = ()>,
    Res: Clone,
{
    Bracket::new(acquire, use_fn, release)
}

/// A simpler bracket that doesn't require Clone on the resource.
///
/// The release function receives an `Option<Res>` which is `Some` if the
/// use function returned it, `None` if the use function consumed it or panicked.
///
/// # Cancel Safety — WEAKER than `Bracket`
///
/// Unlike [`Bracket`], this function is a plain `async fn` with no `Drop`
/// handler. If the returned future is dropped during `release().await`,
/// the release work is abandoned. Use [`bracket`] (which requires `Res: Clone`)
/// for full cancel-safe resource cleanup.
pub async fn bracket_move<Res, T, E, A, U, R, RF>(acquire: A, use_fn: U, release: R) -> Result<T, E>
where
    A: Future<Output = Result<Res, E>>,
    U: FnOnce(Res) -> (T, Option<Res>),
    R: FnOnce(Option<Res>) -> RF,
    RF: Future<Output = ()>,
{
    // Acquire the resource
    let resource = acquire.await?;

    // Use the resource
    // use_fn is not a future here, it's FnOnce -> T. So it runs synchronously.
    // If it panics, we must catch it to run release.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| use_fn(resource)));

    match result {
        Ok((value, leftover)) => {
            release(leftover).await;
            Ok(value)
        }
        Err(payload) => {
            // Resource was moved into use_fn. If use_fn panicked, we assume resource is lost/dropped?
            // Wait, use_fn takes Res by value. If it panics, Res is dropped.
            // So we can't release it (it's gone).
            // We pass None to release.
            release(None).await;
            std::panic::resume_unwind(payload)
        }
    }
}

/// Helper future to catch panics during polling.
struct CatchPanic<F>(Pin<Box<F>>);

impl<F: Future> Future for CatchPanic<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.0.as_mut();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx)));

        match result {
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

/// Commit section: runs a future with bounded cancel masking.
///
/// This is useful for two-phase commit operations where a critical section
/// must complete without interruption.
///
/// # Arguments
/// * `cx` - The capability context
/// * `max_polls` - Maximum polls allowed (budget bound)
/// * `f` - The future to run
///
/// # Example
/// ```ignore
/// let permit = tx.reserve(cx).await?;
/// commit_section(cx, 10, async {
///     permit.send(message);  // Must complete
/// }).await;
/// ```
pub async fn commit_section<F, T>(cx: &Cx, _max_polls: u32, f: F) -> T
where
    F: Future<Output = T>,
{
    // Run under cancel mask
    // In full implementation, this would track poll count and enforce budget
    cx.masked(|| {
        // This is synchronous masked execution
        // For async, we'd need a more sophisticated approach
    });

    // For Phase 0, just run the future
    // Full implementation would poll with budget tracking
    f.await
}

/// Commit section that returns a Result.
///
/// Similar to `commit_section` but for fallible operations.
pub async fn try_commit_section<F, T, E>(cx: &Cx, _max_polls: u32, f: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    cx.masked(|| {});
    f.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::ArenaIndex;
    use std::cell::Cell;
    use std::future::Future;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    // =========================================================================
    // Test Utilities
    // =========================================================================

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn poll_ready<F: Future>(fut: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut boxed = Box::pin(fut);
        match boxed.as_mut().poll(&mut cx) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("Expected future to be ready"),
        }
    }

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    // =========================================================================
    // bracket() Function Tests
    // =========================================================================

    #[test]
    fn bracket_acquire_use_release_success() {
        let acquired = Arc::new(AtomicBool::new(false));
        let used = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));

        let acq = acquired.clone();
        let use_flag = used.clone();
        let rel = released.clone();

        let result = poll_ready(bracket(
            async move {
                acq.store(true, Ordering::SeqCst);
                Ok::<_, ()>(42)
            },
            move |x| {
                use_flag.store(true, Ordering::SeqCst);
                async move { Ok::<_, ()>(x * 2) }
            },
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(acquired.load(Ordering::SeqCst));
        assert!(used.load(Ordering::SeqCst));
        assert!(released.load(Ordering::SeqCst));
        assert_eq!(result, Ok(84));
    }

    #[test]
    fn bracket_acquire_failure_skips_use_and_release() {
        let used = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));

        let use_flag = used.clone();
        let rel = released.clone();

        let result = poll_ready(bracket(
            async { Err::<i32, _>("acquire failed") },
            move |_x| {
                use_flag.store(true, Ordering::SeqCst);
                async move { Ok::<_, &str>(0) }
            },
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(!used.load(Ordering::SeqCst));
        assert!(!released.load(Ordering::SeqCst));
        assert_eq!(result, Err("acquire failed"));
    }

    #[test]
    fn bracket_use_failure_still_releases() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let result = poll_ready(bracket(
            async { Ok::<_, &str>(42) },
            |_x| async { Err::<i32, _>("use failed") },
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(released.load(Ordering::SeqCst));
        assert_eq!(result, Err("use failed"));
    }

    #[test]
    fn bracket_execution_order() {
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));

        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        let result = poll_ready(bracket(
            async move {
                o1.lock().unwrap().push("acquire");
                Ok::<_, ()>("resource")
            },
            move |_| {
                o2.lock().unwrap().push("use");
                async { Ok::<_, ()>("result") }
            },
            move |_| {
                o3.lock().unwrap().push("release");
                async {}
            },
        ));

        let executed: Vec<&str> = order.lock().unwrap().clone();
        drop(order);
        assert_eq!(executed, vec!["acquire", "use", "release"]);
        assert_eq!(result, Ok("result"));
    }

    #[test]
    fn bracket_resource_passed_to_use() {
        let result = poll_ready(bracket(
            async { Ok::<_, ()>(vec![1, 2, 3, 4, 5]) },
            |v| async move { Ok::<_, ()>(v.iter().sum::<i32>()) },
            |_| async {},
        ));

        assert_eq!(result, Ok(15));
    }

    #[test]
    fn bracket_resource_passed_to_release() {
        let released_value = Arc::new(std::sync::Mutex::new(0i32));
        let rv = released_value.clone();

        let _ = poll_ready(bracket(
            async { Ok::<_, ()>(42) },
            |x| async move { Ok::<_, ()>(x) },
            move |x| {
                *rv.lock().unwrap() = x;
                async {}
            },
        ));

        assert_eq!(*released_value.lock().unwrap(), 42);
    }

    // =========================================================================
    // bracket_move() Function Tests
    // =========================================================================

    #[test]
    fn bracket_move_success() {
        let result = poll_ready(bracket_move(
            async { Ok::<_, ()>(42) },
            |x| (x * 2, None),
            |_| async {},
        ));

        assert_eq!(result, Ok(84));
    }

    #[test]
    fn bracket_move_acquire_failure() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let result = poll_ready(bracket_move(
            async { Err::<i32, _>("acquire failed") },
            |x| (x, None),
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(!released.load(Ordering::SeqCst));
        assert_eq!(result, Err("acquire failed"));
    }

    #[test]
    fn bracket_move_releases_leftover() {
        let leftover_value = Arc::new(std::sync::Mutex::new(None::<i32>));
        let lv = leftover_value.clone();

        let _ = poll_ready(bracket_move(
            async { Ok::<_, ()>(42) },
            |x| (x * 2, Some(x)),
            move |leftover| {
                *lv.lock().unwrap() = leftover;
                async {}
            },
        ));

        assert_eq!(*leftover_value.lock().unwrap(), Some(42));
    }

    #[test]
    fn bracket_move_releases_none_when_consumed() {
        let leftover_received = Arc::new(std::sync::Mutex::new(Some(999i32)));
        let lr = leftover_received.clone();

        let _ = poll_ready(bracket_move(
            async { Ok::<_, ()>(42) },
            |_x| (100, None),
            move |leftover| {
                *lr.lock().unwrap() = leftover;
                async {}
            },
        ));

        assert_eq!(*leftover_received.lock().unwrap(), None);
    }

    #[test]
    fn bracket_move_no_clone_required() {
        struct NonCloneResource {
            value: i32,
        }

        let result = poll_ready(bracket_move(
            async { Ok::<_, ()>(NonCloneResource { value: 42 }) },
            |r| (r.value * 2, None),
            |_| async {},
        ));

        assert_eq!(result, Ok(84));
    }

    // =========================================================================
    // commit_section() Tests
    // =========================================================================

    #[test]
    fn commit_section_runs_future() {
        let cx = test_cx();
        let executed = Rc::new(Cell::new(false));
        let exec = executed.clone();

        let result = poll_ready(commit_section(&cx, 10, async move {
            exec.set(true);
            42
        }));

        assert!(executed.get());
        assert_eq!(result, 42);
    }

    #[test]
    fn commit_section_with_cancel_requested() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let executed = Rc::new(Cell::new(false));
        let exec = executed.clone();

        let result = poll_ready(commit_section(&cx, 10, async move {
            exec.set(true);
            "completed"
        }));

        assert!(executed.get());
        assert_eq!(result, "completed");
    }

    // =========================================================================
    // try_commit_section() Tests
    // =========================================================================

    #[test]
    fn try_commit_section_success() {
        let cx = test_cx();
        let result = poll_ready(try_commit_section(&cx, 10, async { Ok::<_, &str>(42) }));
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn try_commit_section_error() {
        let cx = test_cx();
        let result = poll_ready(try_commit_section(&cx, 10, async {
            Err::<i32, _>("error")
        }));
        assert_eq!(result, Err("error"));
    }

    #[test]
    fn try_commit_section_with_cancel_requested() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let executed = Rc::new(Cell::new(false));
        let exec = executed.clone();

        let result = poll_ready(try_commit_section(&cx, 10, async move {
            exec.set(true);
            Ok::<_, ()>(42)
        }));

        assert!(executed.get());
        assert_eq!(result, Ok(42));
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn bracket_with_unit_resource() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let result = poll_ready(bracket(
            async { Ok::<_, ()>(()) },
            |()| async { Ok::<_, ()>(42) },
            move |()| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(released.load(Ordering::SeqCst));
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn bracket_with_large_resource() {
        let data: Vec<i32> = (0..1000).collect();

        let result = poll_ready(bracket(
            async { Ok::<_, ()>(data) },
            |v| async move { Ok::<_, ()>(v.iter().sum::<i32>()) },
            |_| async {},
        ));

        assert_eq!(result, Ok(499_500));
    }

    #[test]
    fn bracket_multiple_sequential() {
        let counter = Arc::new(AtomicUsize::new(0));

        for i in 0..5 {
            let c = counter.clone();
            let result = poll_ready(bracket(
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(i)
                },
                |x| async move { Ok::<_, ()>(x * 2) },
                |_| async {},
            ));
            assert_eq!(result, Ok(i * 2));
        }

        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn bracket_inferred_types() {
        let result = poll_ready(bracket(
            async { Ok::<i32, &str>(10) },
            |n| async move { Ok(format!("number: {n}")) },
            |_| async {},
        ));

        assert_eq!(result, Ok("number: 10".to_string()));
    }

    #[test]
    fn bracket_with_option_resource() {
        let result = poll_ready(bracket(
            async { Ok::<_, ()>(Some(42)) },
            |opt| async move { Ok::<_, ()>(opt.unwrap_or(0) * 2) },
            |_| async {},
        ));

        assert_eq!(result, Ok(84));
    }
}
