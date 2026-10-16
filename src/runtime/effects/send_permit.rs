//! Two-phase send permit for cancel-safe network operations.

use std::marker::PhantomData;

/// A permit for cancel-safe network send operations.
///
/// This implements the two-phase commit pattern for network sends:
/// 1. Reserve space in the send queue (get permit)
/// 2. Commit data through the permit, or abort to cancel
///
/// # Cancel-Safety
///
/// - Dropping the permit before commit releases the reserved space
/// - After commit, the operation may not be cancel-safe (same as underlying send)
/// - Use for operations where uncommitted sends should be discarded
///
/// # Example
///
/// ```ignore
/// let permit = stream.reserve_send().await?;
/// permit.commit(data)?; // Or permit.abort() to cancel
/// ```
#[must_use = "SendPermit must be consumed via commit() or abort()"]
pub struct SendPermit<T> {
    /// Callback to commit the send operation
    commit_fn: Option<Box<dyn FnOnce(&[u8]) -> Result<(), T> + Send + Sync>>,
    /// Callback to abort the send operation (release reservation)
    abort_fn: Option<Box<dyn FnOnce() + Send + Sync>>,
    /// Phantom data for the error type
    _marker: PhantomData<T>,
}

impl<T> SendPermit<T> {
    /// Create a new send permit with commit and abort callbacks.
    pub fn new<F, A>(commit_fn: F, abort_fn: A) -> Self
    where
        F: FnOnce(&[u8]) -> Result<(), T> + Send + Sync + 'static,
        A: FnOnce() + Send + Sync + 'static,
    {
        Self {
            commit_fn: Some(Box::new(commit_fn)),
            abort_fn: Some(Box::new(abort_fn)),
            _marker: PhantomData,
        }
    }

    /// Commit the send operation with the given data.
    ///
    /// This consumes the permit and executes the underlying send.
    /// Returns an error if the send fails.
    ///
    /// # Cancel-Safety
    ///
    /// Once commit is called, the operation follows the cancel-safety
    /// properties of the underlying transport (typically not cancel-safe).
    pub fn commit(mut self, data: &[u8]) -> Result<(), T> {
        if let Some(commit_fn) = self.commit_fn.take() {
            match commit_fn(data) {
                Ok(()) => {
                    self.abort_fn = None;
                    Ok(())
                }
                Err(error) => {
                    if let Some(abort_fn) = self.abort_fn.take() {
                        abort_fn();
                    }
                    Err(error)
                }
            }
        } else {
            // Permit was already used or aborted
            panic!("SendPermit already consumed")
        }
    }

    /// Abort the send operation, releasing the reserved space.
    ///
    /// This is equivalent to dropping the permit, but is more explicit.
    /// The rollback callback runs before unused commit captures are dropped,
    /// so a capture destructor panic cannot skip the rollback attempt.
    /// Callback and destructor panics still propagate to the caller.
    pub fn abort(self) {
        // Keep explicit abort and implicit cancellation on the same path.
        // Drop takes the rollback callback before invoking it, then Rust drops
        // the unused commit closure. Clearing commit_fn first could unwind
        // after disarming rollback but before releasing the reservation.
        drop(self);
    }
}

impl<T> Drop for SendPermit<T> {
    fn drop(&mut self) {
        // If permit is dropped without commit, abort the operation
        if let Some(abort_fn) = self.abort_fn.take() {
            abort_fn();
        }
    }
}

#[cfg(test)]
#[path = "send_permit_inline_tests.rs"]
mod tests;
