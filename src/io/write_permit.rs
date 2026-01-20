//! Cancel-safe write permit pattern.
//!
//! The `WritePermit` provides a two-phase commit pattern for cancel-safe writes.
//! Data is staged in a buffer and only written when `commit()` is called.
//! If the permit is dropped without committing, staged data is discarded.

use crate::io::{AsyncWrite, AsyncWriteExt};
use std::io;
use std::marker::PhantomData;

/// A permit for cancel-safe writes.
///
/// Data staged via `stage()` is buffered locally. When `commit()` is called,
/// the data is written to the underlying writer. If the permit is dropped
/// without committing, the staged data is discarded (explicit abort).
///
/// # Cancel-Safety
///
/// - Dropping the permit before commit discards all staged data
/// - After commit starts, partial writes may occur (same as `write_all`)
/// - Use for operations where uncommitted writes should be discarded
///
/// # Example
///
/// ```ignore
/// let mut permit = WritePermit::new(&mut writer);
/// permit.stage(b"hello ");
/// permit.stage(b"world");
/// permit.commit().await?; // Writes "hello world"
/// ```
pub struct WritePermit<'a, W: ?Sized> {
    writer: &'a mut W,
    data: Option<Vec<u8>>,
    _marker: PhantomData<&'a mut W>,
}

impl<'a, W> WritePermit<'a, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    /// Create a new write permit for the given writer.
    pub fn new(writer: &'a mut W) -> Self {
        Self {
            writer,
            data: Some(Vec::new()),
            _marker: PhantomData,
        }
    }

    /// Create a new write permit with pre-allocated capacity.
    pub fn with_capacity(writer: &'a mut W, capacity: usize) -> Self {
        Self {
            writer,
            data: Some(Vec::with_capacity(capacity)),
            _marker: PhantomData,
        }
    }

    /// Stage data for writing.
    ///
    /// The data is buffered locally and will only be written
    /// to the underlying writer when `commit()` is called.
    pub fn stage(&mut self, data: &[u8]) {
        if let Some(ref mut buf) = self.data {
            buf.extend_from_slice(data);
        }
    }

    /// Returns the amount of data currently staged.
    #[must_use]
    pub fn staged_len(&self) -> usize {
        self.data.as_ref().map_or(0, Vec::len)
    }

    /// Returns whether any data has been staged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.as_ref().is_none_or(Vec::is_empty)
    }

    /// Clear all staged data without writing.
    pub fn clear(&mut self) {
        if let Some(ref mut buf) = self.data {
            buf.clear();
        }
    }

    /// Commit the staged data to the writer.
    ///
    /// This consumes the permit and writes all staged data.
    /// Returns an error if the write fails.
    ///
    /// # Cancel-Safety
    ///
    /// Once commit is called, partial writes may occur. The commit
    /// operation itself is NOT cancel-safe (same as `write_all`).
    pub async fn commit(mut self) -> io::Result<()> {
        // Take the data to prevent drop from seeing it
        if let Some(data) = self.data.take() {
            if !data.is_empty() {
                self.writer.write_all(&data).await?;
            }
        }

        Ok(())
    }

    /// Abort the write operation, discarding all staged data.
    ///
    /// This is equivalent to dropping the permit, but is more explicit.
    pub fn abort(self) {
        // Data is dropped
        drop(self);
    }
}

impl<W: ?Sized> Drop for WritePermit<'_, W> {
    fn drop(&mut self) {
        // Data is discarded if not committed
        // This is intentional for cancel-safety
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    fn poll_ready<F: Future>(mut fut: Pin<&mut F>) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..32 {
            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return output;
            }
        }
        panic!("future did not resolve");
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn commit_writes_data() {
        init_test("commit_writes_data");
        let mut output = Vec::new();
        let result = {
            let mut permit = WritePermit::new(&mut output);
            permit.stage(b"hello ");
            permit.stage(b"world");

            let staged_len = permit.staged_len();
            crate::assert_with_log!(staged_len == 11, "staged_len", 11, staged_len);
            let empty = permit.is_empty();
            crate::assert_with_log!(!empty, "not empty", false, empty);

            let mut fut = Box::pin(permit.commit());
            poll_ready(fut.as_mut())
        };

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "commit ok", true, ok);
        crate::assert_with_log!(output == b"hello world", "output", b"hello world", output);
        crate::test_complete!("commit_writes_data");
    }

    #[test]
    fn abort_discards_data() {
        init_test("abort_discards_data");
        let mut output = Vec::new();
        {
            let mut permit = WritePermit::new(&mut output);
            permit.stage(b"this should be discarded");
            permit.abort();
        }
        let empty = output.is_empty();
        crate::assert_with_log!(empty, "output empty", true, empty);
        crate::test_complete!("abort_discards_data");
    }

    #[test]
    fn drop_discards_data() {
        init_test("drop_discards_data");
        let mut output = Vec::new();
        {
            let mut permit = WritePermit::new(&mut output);
            permit.stage(b"this should be discarded");
            // permit is dropped here
        }
        let empty = output.is_empty();
        crate::assert_with_log!(empty, "output empty", true, empty);
        crate::test_complete!("drop_discards_data");
    }

    #[test]
    fn clear_removes_staged_data() {
        init_test("clear_removes_staged_data");
        let mut output = Vec::new();
        let result = {
            let mut permit = WritePermit::new(&mut output);
            permit.stage(b"hello");
            let staged_len = permit.staged_len();
            crate::assert_with_log!(staged_len == 5, "staged_len", 5, staged_len);

            permit.clear();
            let empty = permit.is_empty();
            crate::assert_with_log!(empty, "empty", true, empty);
            let staged_len = permit.staged_len();
            crate::assert_with_log!(staged_len == 0, "staged_len", 0, staged_len);

            let mut fut = Box::pin(permit.commit());
            poll_ready(fut.as_mut())
        };

        let ok = result.is_ok();
        crate::assert_with_log!(ok, "commit ok", true, ok);
        let empty = output.is_empty();
        crate::assert_with_log!(empty, "output empty", true, empty);
        crate::test_complete!("clear_removes_staged_data");
    }

    #[test]
    fn with_capacity_preallocates() {
        init_test("with_capacity_preallocates");
        let mut output = Vec::new();
        let permit = WritePermit::with_capacity(&mut output, 1024);
        let empty = permit.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        crate::test_complete!("with_capacity_preallocates");
    }
}
