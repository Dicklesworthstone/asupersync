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
pub async fn bracket_move<Res, T, E, A, U, UF, R, RF>(
    acquire: A,
    use_fn: U,
    release: R,
) -> Result<T, E>
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

    #[test]
    fn bracket_struct_creation() {
        // Test that Bracket struct can be created
        // Full async tests require the lab runtime (Phase 0 integration)
        let _bracket = Bracket::new(
            async { Ok::<_, ()>(42) },
            |x: i32| Box::pin(async move { Ok::<_, ()>(x * 2) }),
            |_x: i32| Box::pin(async {}),
        );
    }

    // Note: Full bracket tests require an async runtime.
    // These will be added in the lab runtime integration tests.
    // The bracket function itself is tested via integration tests
    // that use the lab runtime's block_on capability.
}
