//! Limit adapter for limiting bytes written to a BufMut.

use super::BufMut;

/// A `BufMut` adapter that limits the bytes written.
///
/// Created by [`BufMut::limit()`].
///
/// # Examples
///
/// ```
/// use asupersync::bytes::BufMut;
///
/// let mut limit = Vec::new().limit(3);
///
/// // This would panic without the limit adapter on an infinite buffer.
/// // With limit, we can only write 3 bytes.
/// limit.put_slice(&[1u8, 2, 3]);
///
/// let buf = limit.into_inner();
/// assert_eq!(buf, vec![1u8, 2, 3]);
/// ```
#[derive(Debug)]
pub struct Limit<T> {
    inner: T,
    limit: usize,
}

impl<T> Limit<T> {
    /// Create a new `Limit`.
    #[inline]
    pub(crate) fn new(inner: T, limit: usize) -> Self {
        Self { inner, limit }
    }

    /// Consumes this `Limit`, returning the underlying buffer.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Gets a reference to the underlying buffer.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Gets a mutable reference to the underlying buffer.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns the maximum number of bytes that can be written.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Sets the maximum number of bytes that can be written.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }
}

impl<T: BufMut> BufMut for Limit<T> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        std::cmp::min(self.inner.remaining_mut(), self.limit)
    }

    #[inline]
    fn direct_remaining_mut(&self) -> usize {
        std::cmp::min(self.inner.direct_remaining_mut(), self.limit)
    }

    fn chunk_mut(&mut self) -> &mut [u8] {
        let remaining = self.direct_remaining_mut();
        let chunk = self.inner.chunk_mut();
        let len = std::cmp::min(chunk.len(), remaining);
        &mut chunk[..len]
    }

    fn advance_mut(&mut self, cnt: usize) {
        let remaining = self.direct_remaining_mut();
        assert!(
            cnt <= remaining,
            "advance_mut out of bounds: cnt={cnt}, direct_remaining={remaining}, limit={}",
            self.limit
        );
        self.inner.advance_mut(cnt);
        self.limit -= cnt;
    }

    fn put_slice(&mut self, src: &[u8]) {
        let remaining = self.remaining_mut();
        assert!(
            src.len() <= remaining,
            "put_slice out of bounds: len={}, remaining={remaining}, limit={}",
            src.len(),
            self.limit
        );
        self.inner.put_slice(src);
        self.limit -= src.len();
    }
}

#[cfg(test)]
#[path = "limit_inline_tests.rs"]
mod tests;
