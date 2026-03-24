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
    pub(crate) fn new(inner: T, limit: usize) -> Self {
        Self { inner, limit }
    }

    /// Consumes this `Limit`, returning the underlying buffer.
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
    fn remaining_mut(&self) -> usize {
        std::cmp::min(self.inner.remaining_mut(), self.limit)
    }

    fn chunk_mut(&mut self) -> &mut [u8] {
        let remaining = self.remaining_mut();
        let chunk = self.inner.chunk_mut();
        let len = std::cmp::min(chunk.len(), remaining);
        assert!(
            remaining == 0 || len > 0,
            "chunk_mut returned empty with remaining_mut() > 0; inner buffer does not expose direct writable space"
        );
        &mut chunk[..len]
    }

    fn advance_mut(&mut self, cnt: usize) {
        let remaining = self.remaining_mut();
        assert!(
            cnt <= remaining,
            "advance_mut out of bounds: cnt={cnt}, remaining={remaining}, limit={}",
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
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_limit_remaining_mut() {
        init_test("test_limit_remaining_mut");
        let mut data = [0u8; 10];
        let buf: &mut [u8] = &mut data;
        let limit = Limit::new(buf, 5);
        let remaining = limit.remaining_mut();
        crate::assert_with_log!(remaining == 5, "remaining", 5, remaining);
        crate::test_complete!("test_limit_remaining_mut");
    }

    #[test]
    fn test_limit_remaining_mut_when_inner_smaller() {
        init_test("test_limit_remaining_mut_when_inner_smaller");
        let mut data = [0u8; 3];
        let buf: &mut [u8] = &mut data;
        let limit = Limit::new(buf, 10);
        let remaining = limit.remaining_mut();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        crate::test_complete!("test_limit_remaining_mut_when_inner_smaller");
    }

    #[test]
    fn test_limit_put_slice() {
        init_test("test_limit_put_slice");
        let mut data = [0u8; 10];
        {
            let buf: &mut [u8] = &mut data;
            let mut limit = Limit::new(buf, 5);
            limit.put_slice(&[1, 2, 3]);
            let remaining = limit.remaining_mut();
            crate::assert_with_log!(remaining == 2, "remaining", 2, remaining);
        }
        let ok = data[..5] == [1, 2, 3, 0, 0];
        crate::assert_with_log!(ok, "data", &[1, 2, 3, 0, 0], &data[..5]);
        crate::test_complete!("test_limit_put_slice");
    }

    #[test]
    fn test_limit_advance_mut_when_limit_exceeds_inner_remaining() {
        init_test("test_limit_advance_mut_when_limit_exceeds_inner_remaining");
        let mut data = [0u8; 3];
        let buf: &mut [u8] = &mut data;
        let mut limit = Limit::new(buf, 10);

        limit.advance_mut(3);

        let remaining = limit.remaining_mut();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        crate::test_complete!("test_limit_advance_mut_when_limit_exceeds_inner_remaining");
    }

    #[test]
    #[should_panic(expected = "advance_mut out of bounds")]
    fn test_limit_advance_mut_panics_when_count_exceeds_effective_remaining() {
        let mut data = [0u8; 3];
        let buf: &mut [u8] = &mut data;
        let mut limit = Limit::new(buf, 10);
        limit.advance_mut(4);
    }

    #[test]
    fn test_limit_put_slice_when_limit_exceeds_inner_remaining() {
        init_test("test_limit_put_slice_when_limit_exceeds_inner_remaining");
        let mut data = [0u8; 3];
        {
            let buf: &mut [u8] = &mut data;
            let mut limit = Limit::new(buf, 10);
            limit.put_slice(&[1, 2, 3]);
            let remaining = limit.remaining_mut();
            crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        }
        let ok = data == [1, 2, 3];
        crate::assert_with_log!(ok, "data", [1, 2, 3], data);
        crate::test_complete!("test_limit_put_slice_when_limit_exceeds_inner_remaining");
    }

    #[test]
    #[should_panic(expected = "chunk_mut returned empty with remaining_mut() > 0")]
    fn test_limit_chunk_mut_panics_when_inner_cannot_expose_direct_space() {
        let mut limit = Limit::new(Vec::new(), 3);
        let _ = limit.chunk_mut();
    }

    #[test]
    #[should_panic(expected = "put_slice out of bounds")]
    fn test_limit_put_slice_panics_when_len_exceeds_effective_remaining() {
        let mut data = [0u8; 3];
        let buf: &mut [u8] = &mut data;
        let mut limit = Limit::new(buf, 10);
        limit.put_slice(&[1, 2, 3, 4]);
    }

    #[test]
    fn test_limit_accessors() {
        init_test("test_limit_accessors");
        let mut data = [0u8; 10];
        let buf: &mut [u8] = &mut data;
        let mut limit = Limit::new(buf, 5);

        let current = Limit::limit(&limit);
        crate::assert_with_log!(current == 5, "limit", 5, current);
        limit.set_limit(3);
        let current = Limit::limit(&limit);
        crate::assert_with_log!(current == 3, "limit", 3, current);
        crate::test_complete!("test_limit_accessors");
    }

    #[test]
    fn test_limit_into_inner() {
        init_test("test_limit_into_inner");
        let mut data = [0u8; 10];
        let buf: &mut [u8] = &mut data;
        let limit = Limit::new(buf, 5);
        let inner = limit.into_inner();
        let len = inner.len();
        crate::assert_with_log!(len == 10, "len", 10, len);
        crate::test_complete!("test_limit_into_inner");
    }
}
