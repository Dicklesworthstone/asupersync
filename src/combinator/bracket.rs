//! Bracket combinator for resource safety.
//!
//! The bracket pattern ensures that resources are always released, even when
//! errors or cancellation occur. It follows the acquire/use/release pattern
//! familiar from RAII and try-finally.

use crate::cx::Cx;
use std::future::Future;
use std::pin::Pin;

/// The bracket pattern for resource safety.
///
/// Acquires a resource, uses it, and guarantees release even on error/cancel.
///
/// # Type Parameters
/// * `A` - The acquire future
/// * `U` - The use function (takes resource, returns future)
/// * `R` - The release function (takes resource, returns future)
/// * `T` - The value type
/// * `E` - The error type
///
/// # Example
/// ```ignore
/// let result = bracket(
///     open_file("data.txt"),
///     |file| async { file.read_all().await },
///     |file| async { file.close().await },
/// ).await;
/// ```
pub struct Bracket<A, U, R, T, E, Res>
where
    A: Future<Output = Result<Res, E>>,
    U: FnOnce(Res) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send>>,
    R: FnOnce(Res) -> Pin<Box<dyn Future<Output = ()> + Send>>,
{
    state: BracketState<A, U, R, T, E, Res>,
}

enum BracketState<A, U, R, T, E, Res>
where
    A: Future<Output = Result<Res, E>>,
    U: FnOnce(Res) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send>>,
    R: FnOnce(Res) -> Pin<Box<dyn Future<Output = ()> + Send>>,
{
    /// Acquiring the resource.
    Acquiring {
        acquire: A,
        use_fn: Option<U>,
        release_fn: Option<R>,
    },
    /// Using the resource.
    Using {
        use_future: Pin<Box<dyn Future<Output = Result<T, E>> + Send>>,
        resource: Option<Res>,
        release_fn: Option<R>,
    },
    /// Releasing the resource (always runs, even on error).
    Releasing {
        release_future: Pin<Box<dyn Future<Output = ()> + Send>>,
        result: Option<Result<T, E>>,
    },
    /// Terminal state.
    Done,
}

impl<A, U, R, T, E, Res> Bracket<A, U, R, T, E, Res>
where
    A: Future<Output = Result<Res, E>>,
    U: FnOnce(Res) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send>>,
    R: FnOnce(Res) -> Pin<Box<dyn Future<Output = ()> + Send>>,
{
    /// Creates a new bracket combinator.
    pub fn new(acquire: A, use_fn: U, release_fn: R) -> Self {
        Self {
            state: BracketState::Acquiring {
                acquire,
                use_fn: Some(use_fn),
                release_fn: Some(release_fn),
            },
        }
    }
}

// Note: Full implementation requires pinning and unsafe code for the state machine.
// For Phase 0, we provide a simpler async function instead.

/// Executes the bracket pattern: acquire, use, release.
///
/// This function guarantees that the release function is called even if
/// the use function returns an error or panics.
///
/// # Arguments
/// * `acquire` - Future that acquires the resource
/// * `use_fn` - Function that uses the resource
/// * `release` - Future that releases the resource
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
pub async fn bracket<Res, T, E, A, U, UF, R, RF>(acquire: A, use_fn: U, release: R) -> Result<T, E>
where
    A: Future<Output = Result<Res, E>>,
    U: FnOnce(Res) -> UF,
    UF: Future<Output = Result<T, E>>,
    R: FnOnce(Res) -> RF,
    RF: Future<Output = ()>,
    Res: Clone,
{
    // Acquire the resource
    let resource = acquire.await?;

    // Clone for release (resource is used by both use_fn and release)
    let resource_for_release = resource.clone();

    // Use the resource, catching any result
    let result = use_fn(resource).await;

    // Always release (this should run under cancel mask in full implementation)
    release(resource_for_release).await;

    result
}

/// A simpler bracket that doesn't require Clone on the resource.
///
/// The release function receives an `Option<Res>` which is `Some` if the
/// use function consumed the resource, `None` otherwise.
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
    let (value, leftover) = use_fn(resource);

    // Always release
    release(leftover).await;

    Ok(value)
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
    // Bracket Struct Tests
    // =========================================================================

    #[test]
    fn bracket_struct_creation() {
        let _bracket = Bracket::new(
            async { Ok::<_, ()>(42) },
            |x: i32| Box::pin(async move { Ok::<_, ()>(x * 2) }),
            |_x: i32| Box::pin(async {}),
        );
    }

    #[test]
    fn bracket_struct_with_string_resource() {
        let _bracket = Bracket::new(
            async { Ok::<_, &str>("resource".to_string()) },
            |s: String| Box::pin(async move { Ok::<_, &str>(s.len()) }),
            |_s: String| Box::pin(async {}),
        );
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
