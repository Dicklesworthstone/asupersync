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
    pub(crate) fn new(inner: T, limit: usize) -> Self {
        Self { inner, limit }
    }

    /// Consumes this `Take`, returning the underlying buffer.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Gets a reference to the underlying buffer.
    ///
    /// The reader position of the returned reference may not be the same
    /// as that of the buffer passed to [`Buf::take()`].
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Gets a mutable reference to the underlying buffer.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns the maximum number of bytes that can be read.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Sets the maximum number of bytes that can be read.
    ///
    /// Note: this does not reset the position of the inner buffer.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }
}

impl<T: Buf> Buf for Take<T> {
    fn remaining(&self) -> usize {
        std::cmp::min(self.inner.remaining(), self.limit)
    }

    fn chunk(&self) -> &[u8] {
        let chunk = self.inner.chunk();
        let len = std::cmp::min(chunk.len(), self.limit);
        &chunk[..len]
    }

    fn advance(&mut self, cnt: usize) {
        assert!(
            cnt <= self.limit,
            "advance out of bounds: cnt={cnt}, limit={}",
            self.limit
        );
        self.inner.advance(cnt);
        self.limit -= cnt;
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
    fn test_take_remaining() {
        init_test("test_take_remaining");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let take = Take::new(buf, 3);
        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        crate::test_complete!("test_take_remaining");
    }

    #[test]
    fn test_take_remaining_when_inner_smaller() {
        init_test("test_take_remaining_when_inner_smaller");
        let buf: &[u8] = &[1, 2];
        let take = Take::new(buf, 10);
        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 2, "remaining", 2, remaining);
        crate::test_complete!("test_take_remaining_when_inner_smaller");
    }

    #[test]
    fn test_take_chunk() {
        init_test("test_take_chunk");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let take = Take::new(buf, 3);
        let chunk = take.chunk();
        crate::assert_with_log!(chunk == &[1, 2, 3], "chunk", &[1, 2, 3], chunk);
        crate::test_complete!("test_take_chunk");
    }

    #[test]
    fn test_take_advance() {
        init_test("test_take_advance");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let mut take = Take::new(buf, 3);

        take.advance(2);
        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 1, "remaining", 1, remaining);
        let chunk = take.chunk();
        crate::assert_with_log!(chunk == &[3], "chunk", &[3], chunk);
        crate::test_complete!("test_take_advance");
    }

    #[test]
    fn test_take_copy_to_slice() {
        init_test("test_take_copy_to_slice");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let mut take = Take::new(buf, 3);

        let mut dst = [0u8; 3];
        take.copy_to_slice(&mut dst);
        let ok = dst == [1, 2, 3];
        crate::assert_with_log!(ok, "dst", [1, 2, 3], dst);
        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        crate::test_complete!("test_take_copy_to_slice");
    }

    #[test]
    fn test_take_limit() {
        init_test("test_take_limit");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let mut take = Take::new(buf, 3);
        let limit = take.limit();
        crate::assert_with_log!(limit == 3, "limit", 3, limit);

        take.set_limit(5);
        let limit = take.limit();
        crate::assert_with_log!(limit == 5, "limit", 5, limit);
        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 5, "remaining", 5, remaining);
        crate::test_complete!("test_take_limit");
    }

    #[test]
    fn test_take_into_inner() {
        init_test("test_take_into_inner");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let take = Take::new(buf, 3);
        let inner = take.into_inner();
        let ok = inner == &[1, 2, 3, 4, 5];
        crate::assert_with_log!(ok, "inner", &[1, 2, 3, 4, 5], inner);
        crate::test_complete!("test_take_into_inner");
    }

    #[test]
    fn test_take_get_ref() {
        init_test("test_take_get_ref");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let take = Take::new(buf, 3);
        let got = *take.get_ref();
        crate::assert_with_log!(
            got == &[1, 2, 3, 4, 5][..],
            "get_ref",
            &[1, 2, 3, 4, 5][..],
            got
        );
        crate::test_complete!("test_take_get_ref");
    }
}
