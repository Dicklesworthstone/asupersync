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
    pub fn abort(mut self) {
        if let Some(abort_fn) = self.abort_fn.take() {
            self.commit_fn = None;
            abort_fn();
        }
        // If already committed/aborted, this is a no-op
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
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_permit_commit() {
        let committed = Arc::new(Mutex::new(Vec::new()));
        let committed_clone = Arc::clone(&committed);
        let aborted = Arc::new(Mutex::new(false));
        let aborted_clone = Arc::clone(&aborted);

        let permit = SendPermit::new(
            move |data: &[u8]| {
                committed_clone.lock().unwrap().extend_from_slice(data);
                Ok::<(), ()>(())
            },
            move || {
                *aborted_clone.lock().unwrap() = true;
            },
        );

        assert!(permit.commit(b"test data").is_ok());
        assert_eq!(*committed.lock().unwrap(), b"test data");
        assert!(!*aborted.lock().unwrap());
    }

    #[test]
    fn test_permit_abort() {
        let committed = Arc::new(Mutex::new(Vec::new()));
        let committed_clone = Arc::clone(&committed);
        let aborted = Arc::new(Mutex::new(false));
        let aborted_clone = Arc::clone(&aborted);

        let permit = SendPermit::new(
            move |data: &[u8]| {
                committed_clone.lock().unwrap().extend_from_slice(data);
                Ok::<(), ()>(())
            },
            move || {
                *aborted_clone.lock().unwrap() = true;
            },
        );

        permit.abort();
        assert!(committed.lock().unwrap().is_empty());
        assert!(*aborted.lock().unwrap());
    }

    #[test]
    fn test_permit_commit_error_aborts_reservation() {
        let abort_count = Arc::new(Mutex::new(0usize));
        let abort_count_clone = Arc::clone(&abort_count);

        let permit = SendPermit::new(
            move |data: &[u8]| {
                assert_eq!(data, b"too large");
                Err::<(), &'static str>("send queue rejected commit")
            },
            move || {
                *abort_count_clone.lock().unwrap() += 1;
            },
        );

        assert_eq!(
            permit.commit(b"too large"),
            Err("send queue rejected commit")
        );
        assert_eq!(*abort_count.lock().unwrap(), 1);
    }

    #[test]
    fn test_permit_drop_aborts() {
        let committed = Arc::new(Mutex::new(Vec::new()));
        let committed_clone = Arc::clone(&committed);
        let aborted = Arc::new(Mutex::new(false));
        let aborted_clone = Arc::clone(&aborted);

        {
            let _permit = SendPermit::new(
                move |data: &[u8]| {
                    committed_clone.lock().unwrap().extend_from_slice(data);
                    Ok::<(), ()>(())
                },
                move || {
                    *aborted_clone.lock().unwrap() = true;
                },
            );
            // permit dropped here
        }

        assert!(committed.lock().unwrap().is_empty());
        assert!(*aborted.lock().unwrap());
    }
}
