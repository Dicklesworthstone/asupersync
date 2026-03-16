//! Bracket combinator for resource safety.
//!
//! The bracket pattern runs explicit acquire/use/release logic and makes a
//! bounded best-effort attempt to drive release during drop if cancellation
//! interrupts the normal path. It follows the acquire/use/release pattern
//! familiar from RAII and try-finally.
//!
//! # Cancel Safety
//!
//! The [`bracket`] function and [`Bracket`] struct try to run release
//! synchronously during drop if the returned future is cancelled during the
//! use or release phases. Release futures that can make progress under a
//! noop waker complete during this drop path; futures that require external
//! wakeups may not finish before the bounded drop loop gives up.

use crate::cx::Cx;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

/// Error returned by [`Bracket`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BracketError<E> {
    /// The inner acquire or use function returned an error.
    Inner(E),
    /// The future was polled after it had already returned a terminal result.
    PolledAfterCompletion,
}

impl<E: std::fmt::Display> std::fmt::Display for BracketError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(err) => write!(f, "bracket inner error: {err}"),
            Self::PolledAfterCompletion => {
                write!(f, "bracket future polled after completion")
            }
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for BracketError<E> {}

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
/// This struct implements `Future` and runs explicit acquire/use/release
/// phases, with bounded best-effort drop-time cleanup if cancellation interrupts
/// the normal path.
///
/// # Cancel Safety
///
/// When dropped during the `Using` or `Releasing` phases, the `Drop`
/// implementation makes a bounded best-effort attempt to synchronously
/// drive the release future to completion. Immediately-progressable release
/// futures are cleaned up even on cancellation; externally-woken release
/// futures may still outlive that bounded drop loop.
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

// Bracket is Unpin because its pinned state lives behind Pin<Box<_>> and the
// remaining fields are not self-referential.
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

    fn transition_to_releasing(&mut self) -> std::thread::Result<()> {
        let release_fn = self
            .state
            .release_fn
            .take()
            .expect("release_fn consumed twice");
        let resource = self
            .state
            .resource_for_release
            .take()
            .expect("resource_for_release missing");

        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| release_fn(resource))) {
            Ok(release_fut) => {
                self.state.phase = BracketPhase::Releasing(Box::pin(release_fut));
                Ok(())
            }
            Err(payload) => {
                self.state.phase = BracketPhase::Done;
                Err(payload)
            }
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
    type Output = Result<T, BracketError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Bracket is Unpin when all its fields are Unpin (which they are due to bounds)
        let this = self.get_mut();

        loop {
            match &mut this.state.phase {
                BracketPhase::Acquiring(acquire_fut) => {
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        acquire_fut.as_mut().poll(cx)
                    })) {
                        Err(panic_payload) => {
                            this.state.phase = BracketPhase::Done;
                            std::panic::resume_unwind(panic_payload);
                        }
                        Ok(Poll::Pending) => return Poll::Pending,
                        Ok(Poll::Ready(Err(e))) => {
                            this.state.phase = BracketPhase::Done;
                            return Poll::Ready(Err(BracketError::Inner(e)));
                        }
                        Ok(Poll::Ready(Ok(resource))) => {
                            // Clone resource for release before use_fn consumes it
                            this.state.resource_for_release = Some(resource.clone());

                            // Transition to Using phase
                            let use_fn = this.use_fn.take().expect("use_fn consumed twice");
                            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                use_fn(resource)
                            })) {
                                Ok(use_fut) => {
                                    this.state.phase = BracketPhase::Using(Box::pin(use_fut));
                                }
                                Err(panic_payload) => {
                                    this.state.use_result = Some(Err(panic_payload));
                                    if let Err(release_panic) = this.transition_to_releasing() {
                                        std::panic::resume_unwind(release_panic);
                                    }
                                }
                            }
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
                            if let Err(release_panic) = this.transition_to_releasing() {
                                std::panic::resume_unwind(release_panic);
                            }
                            // Continue loop to poll release phase
                        }
                        Err(panic_payload) => {
                            // Use panicked, store panic and transition to Releasing
                            this.state.use_result = Some(Err(panic_payload));
                            if let Err(release_panic) = this.transition_to_releasing() {
                                std::panic::resume_unwind(release_panic);
                            }
                            // Continue loop to poll release phase
                        }
                    }
                }

                BracketPhase::Releasing(release_fut) => {
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        release_fut.as_mut().poll(cx)
                    })) {
                        Err(panic_payload) => {
                            this.state.phase = BracketPhase::Done;
                            std::panic::resume_unwind(panic_payload);
                        }
                        Ok(Poll::Pending) => return Poll::Pending,
                        Ok(Poll::Ready(())) => {
                            this.state.phase = BracketPhase::Done;
                            // Return the stored use result
                            match this.state.use_result.take().expect("use_result missing") {
                                Ok(result) => {
                                    return Poll::Ready(result.map_err(BracketError::Inner));
                                }
                                Err(panic_payload) => std::panic::resume_unwind(panic_payload),
                            }
                        }
                    }
                }

                BracketPhase::Done => {
                    return Poll::Ready(Err(BracketError::PolledAfterCompletion));
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
        let mut release_panic: Option<Box<dyn std::any::Any + Send>> = None;
        // Determine the release future to drive:
        // - Using phase: resource acquired but use not complete; construct release future.
        // - Releasing phase: release already started but not complete; drive existing future.
        // We replace the phase with Done so that `use_fut` is dropped BEFORE the release
        // future is created and polled. This ensures resources (like locks) held by
        // the use phase are released before the cleanup phase attempts to run.
        let release_fut: Option<Pin<Box<RF>>> =
            match std::mem::replace(&mut self.state.phase, BracketPhase::Done) {
                BracketPhase::Acquiring(_) | BracketPhase::Using(_) => {
                    // Cancel before release starts: construct the release future
                    // from the saved resource clone if one exists.
                    if let (Some(release_fn), Some(resource)) = (
                        self.state.release_fn.take(),
                        self.state.resource_for_release.take(),
                    ) {
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            release_fn(resource)
                        })) {
                            Ok(fut) => Some(Box::pin(fut)),
                            Err(payload) => {
                                release_panic = Some(payload);
                                None
                            }
                        }
                    } else {
                        None
                    }
                }
                BracketPhase::Releasing(fut) => {
                    // Cancel during release: extract the in-progress release future.
                    Some(fut)
                }
                BracketPhase::Done => None,
            };

        if let Some(payload) = release_panic {
            if !std::thread::panicking() {
                std::panic::resume_unwind(payload);
            }
            return;
        }

        if let Some(mut release_fut) = release_fut {
            // Drive it to completion synchronously using a noop waker.
            // This is Phase 0 behavior; full implementation would use the
            // runtime's cancel mask to run release asynchronously.
            let waker = Waker::from(Arc::new(NoopWaker));
            let mut cx = Context::from_waker(&waker);

            // Poll until complete (bounded iteration to prevent infinite loops)
            // Most release futures complete quickly or immediately.
            for _ in 0..10_000 {
                let poll_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    release_fut.as_mut().poll(&mut cx)
                }));
                match poll_result {
                    Ok(Poll::Ready(())) => {
                        if !std::thread::panicking() {
                            if let Some(Err(payload)) = self.state.use_result.take() {
                                std::panic::resume_unwind(payload);
                            }
                        }
                        return;
                    }
                    Err(payload) => {
                        if !std::thread::panicking() {
                            std::panic::resume_unwind(payload);
                        }
                        return;
                    }
                    Ok(Poll::Pending) => {
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
/// This function runs the release function on the normal completion path,
/// and makes a bounded best-effort drop-time cleanup attempt if the future
/// is cancelled after acquire succeeds.
///
/// # Cancel Safety
///
/// This function attempts synchronous release during drop when cancellation
/// interrupts the use or release phases. Release futures that can complete
/// under the bounded noop-waker drop loop will be cleaned up; release
/// futures that require external wakeups may not finish in that path.
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

/// Commit section: runs a future with bounded cancel masking.
///
/// This is useful for two-phase commit operations where a short critical
/// section needs a bounded window of cancellation masking.
///
/// The future is polled with cancellation masked for at most `max_polls`
/// polls. Once that masked budget is exhausted, subsequent polls run
/// unmasked so cancellation-aware checkpoints can observe pending cancel
/// requests instead of deferring them forever.
///
/// # Arguments
/// * `cx` - The capability context
/// * `max_polls` - Maximum number of polls that keep cancellation masked
/// * `f` - The future to run
///
/// # Example
/// ```ignore
/// let permit = tx.reserve(cx).await?;
/// commit_section(cx, 10, async {
///     permit.send(message);  // Keep this section short
/// }).await;
/// ```
pub async fn commit_section<F, T>(cx: &Cx, max_polls: u32, f: F) -> T
where
    F: Future<Output = T>,
{
    let mut future = Box::pin(f);
    let mut masked_polls = 0u32;
    std::future::poll_fn(|task_cx| {
        if masked_polls < max_polls {
            masked_polls = masked_polls.saturating_add(1);
            cx.masked(|| future.as_mut().poll(task_cx))
        } else {
            future.as_mut().poll(task_cx)
        }
    })
    .await
}

/// Commit section that returns a Result.
///
/// Similar to `commit_section` but for fallible operations.
///
/// `max_polls` bounds how many polls run under cancellation masking before
/// later polls proceed unmasked.
pub async fn try_commit_section<F, T, E>(cx: &Cx, max_polls: u32, f: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let mut future = Box::pin(f);
    let mut masked_polls = 0u32;
    std::future::poll_fn(|task_cx| {
        if masked_polls < max_polls {
            masked_polls = masked_polls.saturating_add(1);
            cx.masked(|| future.as_mut().poll(task_cx))
        } else {
            future.as_mut().poll(task_cx)
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::ArenaIndex;
    use parking_lot::Mutex;
    use std::cell::Cell;
    use std::future::Future;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
            Poll::Pending => unreachable!("Expected future to be ready"),
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
        assert_eq!(result, Err(BracketError::Inner("acquire failed")));
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
        assert_eq!(result, Err(BracketError::Inner("use failed")));
    }

    #[test]
    fn bracket_execution_order() {
        let order = Arc::new(Mutex::new(Vec::new()));

        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        let result = poll_ready(bracket(
            async move {
                o1.lock().push("acquire");
                Ok::<_, ()>("resource")
            },
            move |_| {
                o2.lock().push("use");
                async { Ok::<_, ()>("result") }
            },
            move |_| {
                o3.lock().push("release");
                async {}
            },
        ));

        let executed: Vec<&str> = order.lock().clone();
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
        let released_value = Arc::new(Mutex::new(0i32));
        let rv = released_value.clone();

        let _ = poll_ready(bracket(
            async { Ok::<_, ()>(42) },
            |x| async move { Ok::<_, ()>(x) },
            move |x| {
                *rv.lock() = x;
                async {}
            },
        ));

        assert_eq!(*released_value.lock(), 42);
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
        let leftover_value = Arc::new(Mutex::new(None::<i32>));
        let lv = leftover_value.clone();

        let _ = poll_ready(bracket_move(
            async { Ok::<_, ()>(42) },
            |x| (x * 2, Some(x)),
            move |leftover| {
                *lv.lock() = leftover;
                async {}
            },
        ));

        assert_eq!(*leftover_value.lock(), Some(42));
    }

    #[test]
    fn bracket_move_releases_none_when_consumed() {
        let leftover_received = Arc::new(Mutex::new(Some(999i32)));
        let lr = leftover_received.clone();

        let _ = poll_ready(bracket_move(
            async { Ok::<_, ()>(42) },
            |_x| (100, None),
            move |leftover| {
                *lr.lock() = leftover;
                async {}
            },
        ));

        assert_eq!(*leftover_received.lock(), None);
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

    struct PendingThenCheckpoint<'a> {
        cx: &'a Cx,
        first_poll: bool,
    }

    impl Future for PendingThenCheckpoint<'_> {
        type Output = Result<(), crate::Error>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.first_poll {
                self.first_poll = false;
                Poll::Pending
            } else {
                Poll::Ready(self.cx.checkpoint())
            }
        }
    }

    struct PendingThenCheckpointResult<'a> {
        cx: &'a Cx,
        first_poll: bool,
        value: i32,
    }

    impl Future for PendingThenCheckpointResult<'_> {
        type Output = Result<i32, crate::Error>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.first_poll {
                self.first_poll = false;
                Poll::Pending
            } else {
                Poll::Ready(self.cx.checkpoint().map(|()| self.value))
            }
        }
    }

    #[test]
    fn commit_section_masks_checkpoint_on_later_polls() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(commit_section(
            &cx,
            10,
            PendingThenCheckpoint {
                cx: &cx,
                first_poll: true,
            },
        ));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));

        let second = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(second, Poll::Ready(Ok(()))), "{second:?}");
    }

    #[test]
    fn commit_section_unmasks_after_max_polls() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(commit_section(
            &cx,
            1,
            PendingThenCheckpoint {
                cx: &cx,
                first_poll: true,
            },
        ));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));

        let second = fut.as_mut().poll(&mut task_cx);
        match second {
            Poll::Ready(Err(err)) => assert!(err.is_cancelled(), "{err:?}"),
            other => panic!("expected cancelled result after masked poll budget, got {other:?}"),
        }
    }

    #[test]
    fn commit_section_zero_max_polls_never_masks() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let cx_clone = cx.clone();
        let result = poll_ready(commit_section(&cx, 0, async move { cx_clone.checkpoint() }));

        assert!(
            matches!(result, Err(ref err) if err.is_cancelled()),
            "{result:?}"
        );
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

    #[test]
    fn try_commit_section_masks_checkpoint_on_later_polls() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(try_commit_section(
            &cx,
            10,
            PendingThenCheckpointResult {
                cx: &cx,
                first_poll: true,
                value: 42,
            },
        ));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));

        let second = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(second, Poll::Ready(Ok(42))), "{second:?}");
    }

    #[test]
    fn try_commit_section_unmasks_after_max_polls() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(try_commit_section(
            &cx,
            1,
            PendingThenCheckpointResult {
                cx: &cx,
                first_poll: true,
                value: 42,
            },
        ));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));

        let second = fut.as_mut().poll(&mut task_cx);
        match second {
            Poll::Ready(Err(err)) => assert!(err.is_cancelled(), "{err:?}"),
            other => panic!("expected cancelled result after masked poll budget, got {other:?}"),
        }
    }

    #[test]
    fn try_commit_section_zero_max_polls_never_masks() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let cx_clone = cx.clone();
        let result = poll_ready(try_commit_section(&cx, 0, async move {
            cx_clone.checkpoint().map(|()| 42)
        }));

        assert!(
            matches!(result, Err(ref err) if err.is_cancelled()),
            "{result:?}"
        );
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

    // =========================================================================
    // Drop-during-Releasing Regression Test
    // =========================================================================

    /// A release future that returns Pending on the first poll, then Ready
    /// on the second. Simulates a release that needs multiple polls.
    struct TwoPollRelease {
        done: bool,
        flag: Arc<AtomicBool>,
    }

    impl Future for TwoPollRelease {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            if self.done {
                self.flag.store(true, Ordering::SeqCst);
                Poll::Ready(())
            } else {
                self.done = true;
                Poll::Pending
            }
        }
    }

    struct PanicOnPollUse;

    impl Future for PanicOnPollUse {
        type Output = Result<(), ()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("use future panicked before release completed");
        }
    }

    /// Regression: if the bracket future is dropped while the release future
    /// is in progress (Releasing phase returns Pending then the bracket is
    /// dropped), the Drop handler must drive the release future to completion.
    /// Previously, the Drop handler only covered the Using phase, leaving the
    /// release abandoned if cancelled during Releasing.
    #[test]
    fn bracket_drop_during_releasing_drives_release_to_completion() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(42_i32) },
            |x| async move { Ok::<_, ()>(x) },
            move |_| TwoPollRelease {
                done: false,
                flag: rel,
            },
        ));

        // First poll: acquire succeeds, use succeeds, release returns Pending.
        // Bracket is now in the Releasing phase.
        let poll1 = fut.as_mut().poll(&mut cx);
        assert!(
            poll1.is_pending(),
            "release future should return Pending on first poll"
        );
        assert!(!released.load(Ordering::SeqCst), "release not yet complete");

        // Drop the bracket while in Releasing phase.
        // The Drop handler must drive the release future to completion.
        drop(fut);

        assert!(
            released.load(Ordering::SeqCst),
            "release must complete even when bracket is dropped during Releasing phase"
        );
    }

    #[test]
    fn bracket_drop_during_releasing_preserves_stored_use_panic() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(42_i32) },
            |_x| PanicOnPollUse,
            move |_| TwoPollRelease {
                done: false,
                flag: rel,
            },
        ));

        let poll1 = fut.as_mut().poll(&mut cx);
        assert!(
            poll1.is_pending(),
            "panicking use future should still leave bracket pending until release finishes"
        );
        assert!(!released.load(Ordering::SeqCst), "release not yet complete");

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(fut)));
        assert!(
            panic.is_err(),
            "drop must rethrow the stored use panic after completing release"
        );
        assert!(
            released.load(Ordering::SeqCst),
            "drop should still finish the release future before rethrowing the use panic"
        );
    }

    struct NeverReadyUse;

    impl Future for NeverReadyUse {
        type Output = Result<(), ()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    struct PanicOnSecondPollRelease {
        first_poll: bool,
    }

    impl Future for PanicOnSecondPollRelease {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.first_poll {
                self.first_poll = false;
                Poll::Pending
            } else {
                panic!("release future panicked during drop");
            }
        }
    }

    #[test]
    fn bracket_drop_during_using_propagates_release_constructor_panic() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(42_i32) },
            |_| NeverReadyUse,
            |_| -> std::future::Ready<()> { panic!("release constructor panicked during drop") },
        ));

        assert!(
            matches!(fut.as_mut().poll(&mut cx), Poll::Pending),
            "use future should still be pending before cancellation"
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(fut)));
        assert!(
            panic.is_err(),
            "drop should surface release constructor panics when not already unwinding"
        );
    }

    #[test]
    fn bracket_drop_during_releasing_propagates_release_poll_panic() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(42_i32) },
            |x| async move { Ok::<_, ()>(x) },
            |_| PanicOnSecondPollRelease { first_poll: true },
        ));

        assert!(
            matches!(fut.as_mut().poll(&mut cx), Poll::Pending),
            "release future should be pending before drop drives it again"
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(fut)));
        assert!(
            panic.is_err(),
            "drop should surface release future panics when not already unwinding"
        );
    }

    struct PanicAcquireFuture;

    impl Future for PanicAcquireFuture {
        type Output = Result<i32, &'static str>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("acquire future panicked");
        }
    }

    struct ImmediatePanicRelease;

    impl Future for ImmediatePanicRelease {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("release future panicked during normal poll");
        }
    }

    struct PollCountingUse {
        polls: Arc<AtomicUsize>,
    }

    impl Future for PollCountingUse {
        type Output = Result<i32, &'static str>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(42))
        }
    }

    #[test]
    fn bracket_use_fn_panic_marks_future_done_after_unwind_is_caught() {
        let acquire_polls = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            PollCountingStream {
                polls: acquire_polls.clone(),
            },
            |_| -> std::future::Ready<Result<i32, &'static str>> {
                panic!("use_fn panicked during transition")
            },
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fut.as_mut().poll(&mut cx);
        }));
        assert!(first.is_err(), "use_fn panic must still propagate");
        assert!(
            released.load(Ordering::SeqCst),
            "release must run before the panic escapes"
        );
        assert_eq!(acquire_polls.load(Ordering::SeqCst), 1);

        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
        assert_eq!(acquire_polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bracket_release_constructor_panic_marks_future_done_after_unwind_is_caught() {
        let use_polls = Arc::new(AtomicUsize::new(0));
        let use_polls_for_future = use_polls.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, &'static str>(42_i32) },
            move |_| PollCountingUse {
                polls: use_polls_for_future,
            },
            |_| -> std::future::Ready<()> { panic!("release constructor panicked") },
        ));

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fut.as_mut().poll(&mut cx);
        }));
        assert!(
            first.is_err(),
            "release constructor panic must still propagate"
        );
        assert_eq!(use_polls.load(Ordering::SeqCst), 1);

        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
        assert_eq!(use_polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bracket_acquire_panic_marks_future_done_after_unwind_is_caught() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            PanicAcquireFuture,
            |x| async move { Ok::<_, &'static str>(x) },
            |_| async {},
        ));

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fut.as_mut().poll(&mut cx);
        }));
        assert!(first.is_err(), "acquire panic must still propagate");

        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
    }

    #[test]
    fn bracket_release_poll_panic_marks_future_done_after_unwind_is_caught() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, &'static str>(42_i32) },
            |x| async move { Ok::<_, &'static str>(x) },
            |_| ImmediatePanicRelease,
        ));

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fut.as_mut().poll(&mut cx);
        }));
        assert!(first.is_err(), "release poll panic must still propagate");

        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
    }

    // =========================================================================
    // Repoll-after-completion Regression Test
    // =========================================================================

    #[derive(Debug)]
    struct PollCountingStream {
        polls: Arc<AtomicUsize>,
    }

    impl Future for PollCountingStream {
        type Output = Result<i32, &'static str>;
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(42))
        }
    }

    /// Regression: polling a `Bracket` after it has returned a terminal result
    /// must return `Err(BracketError::PolledAfterCompletion)` without touching
    /// upstream (acquire/use/release) futures.
    #[test]
    fn bracket_repoll_after_completion_returns_error_without_repolling_upstream() {
        let acquire_polls = Arc::new(AtomicUsize::new(0));
        let ap = acquire_polls.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            PollCountingStream { polls: ap },
            |x| async move { Ok::<_, &str>(x * 2) },
            |_| async {},
        ));

        // First poll: completes normally.
        let first = fut.as_mut().poll(&mut cx);
        assert_eq!(first, Poll::Ready(Ok(84)));
        assert_eq!(acquire_polls.load(Ordering::SeqCst), 1);

        // Second poll: must return PolledAfterCompletion.
        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
        // Acquire stream must NOT have been polled again.
        assert_eq!(acquire_polls.load(Ordering::SeqCst), 1);
    }
}
