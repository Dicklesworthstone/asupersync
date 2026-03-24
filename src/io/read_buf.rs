//! Read buffer for async reads.
//!
//! This is a safe subset of `std::io::ReadBuf`, tailored for Asupersync.
//! It assumes the provided buffer is fully initialized.

/// Buffer for reading data.
pub struct ReadBuf<'a> {
    buf: &'a mut [u8],
    filled: usize,
    initialized: usize,
}

impl<'a> ReadBuf<'a> {
    /// Creates a new `ReadBuf` wrapping the given buffer.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        let initialized = buf.len();
        Self {
            buf,
            filled: 0,
            initialized,
        }
    }

    /// Returns the filled portion of the buffer.
    #[must_use]
    pub fn filled(&self) -> &[u8] {
        &self.buf[..self.filled]
    }

    /// Returns the filled portion of the buffer as mutable.
    #[must_use]
    pub fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.filled]
    }

    /// Returns the unfilled portion of the buffer.
    #[must_use]
    pub fn unfilled(&mut self) -> &mut [u8] {
        &mut self.buf[self.filled..self.initialized]
    }

    /// Copies a slice into the unfilled portion.
    pub fn put_slice(&mut self, src: &[u8]) {
        assert!(src.len() <= self.remaining(), "ReadBuf overflow");
        let dst = &mut self.unfilled()[..src.len()];
        dst.copy_from_slice(src);
        self.filled += src.len();
    }

    /// Advances the filled cursor by `n` bytes.
    pub fn advance(&mut self, n: usize) {
        assert!(n <= self.remaining(), "ReadBuf overflow");
        self.filled += n;
    }

    /// Returns remaining capacity.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.initialized.saturating_sub(self.filled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{self, AssertUnwindSafe};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
        if let Some(message) = payload.downcast_ref::<&str>() {
            return (*message).to_owned();
        }
        if let Some(message) = payload.downcast_ref::<String>() {
            return message.clone();
        }
        "<non-string panic payload>".to_owned()
    }

    #[test]
    fn read_buf_put_and_advance() {
        init_test("read_buf_put_and_advance");
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);

        read_buf.put_slice(&[1, 2, 3]);
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == [1, 2, 3], "filled", &[1, 2, 3], filled);
        let remaining = read_buf.remaining();
        crate::assert_with_log!(remaining == 5, "remaining", 5, remaining);

        read_buf.advance(2);
        let len = read_buf.filled().len();
        crate::assert_with_log!(len == 5, "filled len", 5, len);
        crate::test_complete!("read_buf_put_and_advance");
    }

    #[test]
    fn read_buf_advance_rejects_oversized_step_without_wrapping() {
        init_test("read_buf_advance_rejects_oversized_step_without_wrapping");
        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        read_buf.put_slice(&[1, 2, 3]);

        let panic = panic::catch_unwind(AssertUnwindSafe(|| {
            read_buf.advance(usize::MAX);
        }))
        .expect_err("advance must fail closed on oversized step");
        let message = panic_message(panic.as_ref());
        crate::assert_with_log!(
            message.contains("ReadBuf overflow"),
            "panic message",
            true,
            message.contains("ReadBuf overflow")
        );
        let len = read_buf.filled().len();
        crate::assert_with_log!(len == 3, "filled len", 3, len);
        crate::test_complete!("read_buf_advance_rejects_oversized_step_without_wrapping");
    }
}
