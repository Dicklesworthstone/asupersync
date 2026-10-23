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
//! wakeups fail closed if they exhaust the bounded drop loop.

use crate::cx::Cx;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

const DROP_RELEASE_POLL_BUDGET: usize = 10_000;

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
/// futures fail closed if they exhaust that bounded drop loop.
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
        // A completed or panicked future may still hold locks until Drop.
        // Retire it before invoking the release constructor, not merely before
        // polling the release future.
        let previous_phase = std::mem::replace(&mut self.state.phase, BracketPhase::Done);
        let retirement =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(previous_phase)));

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
                // Install cleanup even if retiring the old future panicked:
                // Bracket::drop can then drive release during the unwind.
                retirement
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

                            // Retire acquire before the use constructor can touch
                            // resources still held by the completed future.
                            let use_fn = this.use_fn.take().expect("use_fn consumed twice");
                            let acquire_phase =
                                std::mem::replace(&mut this.state.phase, BracketPhase::Done);
                            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                drop(acquire_phase);
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
                unfinished @ (BracketPhase::Acquiring(_) | BracketPhase::Using(_)) => {
                    // A `_` pattern left the future in the match temporary,
                    // alive until this statement ended, so release_fn ran
                    // while the use future still held what it had taken.
                    drop(unfinished);
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
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);

            // Poll until complete (bounded iteration to prevent infinite loops)
            // Most release futures complete quickly or immediately.
            for _ in 0..DROP_RELEASE_POLL_BUDGET {
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

            if !std::thread::panicking() {
                if let Some(Err(payload)) = self.state.use_result.take() {
                    std::panic::resume_unwind(payload);
                }
                panic!(
                    "bracket release future did not complete within drop-time cleanup poll budget"
                );
            }
            return;
        }

        // Ensure we don't swallow a use-phase panic if release times out or is absent.
        if !std::thread::panicking() {
            if let Some(Err(payload)) = self.state.use_result.take() {
                std::panic::resume_unwind(payload);
            }
        }
    }
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
/// futures that require external wakeups fail closed if they exhaust that
/// bounded cleanup budget.
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
#[path = "bracket_inline_tests.rs"]
mod tests;
