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
    #[inline]
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
    #[inline]
    pub fn filled(&self) -> &[u8] {
        &self.buf[..self.filled]
    }

    /// Returns the filled portion of the buffer as mutable.
    #[must_use]
    #[inline]
    pub fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.filled]
    }

    /// Returns the unfilled portion of the buffer.
    #[must_use]
    #[inline]
    pub fn unfilled(&mut self) -> &mut [u8] {
        &mut self.buf[self.filled..self.initialized]
    }

    /// Copies a slice into the unfilled portion.
    #[inline]
    pub fn put_slice(&mut self, src: &[u8]) {
        assert!(src.len() <= self.remaining(), "ReadBuf overflow");
        let dst = &mut self.unfilled()[..src.len()];
        dst.copy_from_slice(src);
        self.filled += src.len();
    }

    /// Advances the filled cursor by `n` bytes.
    #[inline]
    pub fn advance(&mut self, n: usize) {
        assert!(n <= self.remaining(), "ReadBuf overflow");
        self.filled += n;
    }

    /// Returns remaining capacity.
    #[must_use]
    #[inline]
    pub fn remaining(&self) -> usize {
        self.initialized.saturating_sub(self.filled)
    }
}

#[cfg(test)]
#[path = "copy_read_contract_tests.rs"]
mod copy_read_contract_tests;

#[cfg(test)]
#[path = "buf_reader_read_contract_tests.rs"]
mod buf_reader_read_contract_tests;

#[cfg(test)]
#[path = "read_adapter_contract_tests.rs"]
mod read_adapter_contract_tests;

#[cfg(test)]
#[path = "read_buf_inline_tests.rs"]
mod tests;
