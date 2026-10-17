//! Take adapter for limiting bytes read from a Buf.

use super::Buf;

/// A `Buf` adapter that limits the bytes read.
///
/// Created by [`Buf::take()`].
///
/// # Examples
///
/// ```
/// use asupersync::bytes::Buf;
///
/// let buf: &[u8] = &[1, 2, 3, 4, 5];
/// let mut take = buf.take(3);
///
/// assert_eq!(take.remaining(), 3);
///
/// let mut dst = [0u8; 3];
/// take.copy_to_slice(&mut dst);
/// assert_eq!(dst, [1, 2, 3]);
/// ```
#[derive(Debug)]
pub struct Take<T> {
    inner: T,
    limit: usize,
}

impl<T> Take<T> {
    /// Create a new `Take`.
    #[inline]
    pub(crate) fn new(inner: T, limit: usize) -> Self {
        Self { inner, limit }
    }

    /// Consumes this `Take`, returning the underlying buffer.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Gets a reference to the underlying buffer.
    ///
    /// The reader position of the returned reference may not be the same
    /// as that of the buffer passed to [`Buf::take()`].
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Gets a mutable reference to the underlying buffer.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns the maximum number of bytes that can be read.
    #[inline]
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Sets the maximum number of bytes that can be read.
    ///
    /// Note: this does not reset the position of the inner buffer.
    #[inline]
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }
}

impl<T: Buf> Buf for Take<T> {
    #[inline]
    fn remaining(&self) -> usize {
        std::cmp::min(self.inner.remaining(), self.limit)
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        let chunk = self.inner.chunk();
        let len = std::cmp::min(chunk.len(), self.limit);
        &chunk[..len]
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        let remaining = self.remaining();
        assert!(
            cnt <= remaining,
            "advance out of bounds: cnt={cnt}, remaining={remaining}, limit={}",
            self.limit
        );
        self.inner.advance(cnt);
        self.limit -= cnt;
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> crate::bytes::Bytes {
        let remaining = self.remaining();
        assert!(
            len <= remaining,
            "cannot copy {} bytes with {} remaining",
            len,
            remaining
        );
        let ret = self.inner.copy_to_bytes(len);
        self.limit -= len;
        ret
    }
}

#[cfg(test)]
#[path = "take_inline_tests.rs"]
mod tests;
