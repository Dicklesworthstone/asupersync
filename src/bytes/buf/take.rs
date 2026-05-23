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
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use proptest::prelude::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn drain_to_vec(mut buf: impl Buf) -> Vec<u8> {
        let mut out = vec![0u8; buf.remaining()];
        buf.copy_to_slice(&mut out);
        out
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
        crate::assert_with_log!(chunk == [1, 2, 3], "chunk", &[1, 2, 3], chunk);
        crate::test_complete!("test_take_chunk");
    }

    #[test]
    fn take_zero_limit_hides_inner_without_advancing() {
        init_test("take_zero_limit_hides_inner_without_advancing");
        let buf: &[u8] = &[1, 2, 3];
        let mut take = Take::new(buf, 0);

        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        let chunk = take.chunk();
        crate::assert_with_log!(chunk.is_empty(), "chunk empty", true, chunk.is_empty());

        take.advance(0);
        let inner = take.into_inner();
        crate::assert_with_log!(inner == [1, 2, 3], "inner", &[1, 2, 3], inner);
        crate::test_complete!("take_zero_limit_hides_inner_without_advancing");
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
        crate::assert_with_log!(chunk == [3], "chunk", &[3], chunk);
        crate::test_complete!("test_take_advance");
    }

    #[test]
    fn test_take_advance_when_limit_exceeds_inner_remaining() {
        init_test("test_take_advance_when_limit_exceeds_inner_remaining");
        let buf: &[u8] = &[1, 2];
        let mut take = Take::new(buf, 10);

        take.advance(2);

        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        let chunk = take.chunk();
        crate::assert_with_log!(chunk.is_empty(), "chunk empty", true, chunk.is_empty());
        crate::test_complete!("test_take_advance_when_limit_exceeds_inner_remaining");
    }

    #[test]
    #[should_panic(expected = "advance out of bounds")]
    fn test_take_advance_panics_when_count_exceeds_effective_remaining() {
        let buf: &[u8] = &[1, 2];
        let mut take = Take::new(buf, 10);
        take.advance(3);
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

    proptest! {
        #[test]
        fn take_metamorphic_nested_limits_match_min_limit(
            payload in prop::collection::vec(any::<u8>(), 0..96),
            outer_limit in 0usize..128,
            inner_limit in 0usize..128,
            read_steps in prop::collection::vec(0usize..64, 0..64),
        ) {
            let effective_len = payload.len().min(outer_limit).min(inner_limit);
            let expected = &payload[..effective_len];

            let mut nested = Take::new(Take::new(payload.as_slice(), outer_limit), inner_limit);
            let mut flat = Take::new(payload.as_slice(), outer_limit.min(inner_limit));
            let mut observed = Vec::with_capacity(effective_len);

            prop_assert_eq!(nested.remaining(), effective_len);
            prop_assert_eq!(flat.remaining(), effective_len);

            for raw_step in read_steps {
                if !nested.has_remaining() {
                    break;
                }

                prop_assert_eq!(nested.remaining(), flat.remaining());
                let read_len = 1 + raw_step % nested.remaining();

                let mut nested_bytes = vec![0u8; read_len];
                nested.copy_to_slice(&mut nested_bytes);

                let mut flat_bytes = vec![0u8; read_len];
                flat.copy_to_slice(&mut flat_bytes);

                prop_assert_eq!(
                    nested_bytes.as_slice(),
                    flat_bytes.as_slice(),
                    "nested Take limits must match the equivalent minimum limit",
                );
                observed.extend_from_slice(&nested_bytes);
                prop_assert_eq!(nested.remaining(), flat.remaining());
                prop_assert_eq!(&expected[..observed.len()], observed.as_slice());
            }

            let final_len = nested.remaining();
            prop_assert_eq!(final_len, flat.remaining());

            let mut nested_tail = vec![0u8; final_len];
            nested.copy_to_slice(&mut nested_tail);

            let mut flat_tail = vec![0u8; final_len];
            flat.copy_to_slice(&mut flat_tail);

            prop_assert_eq!(
                nested_tail.as_slice(),
                flat_tail.as_slice(),
                "nested Take limits must match flat Take tails",
            );
            observed.extend_from_slice(&nested_tail);
            prop_assert_eq!(observed.as_slice(), expected);
            prop_assert_eq!(nested.remaining(), 0);
            prop_assert_eq!(flat.remaining(), 0);
        }

        #[test]
        fn take_metamorphic_segmented_advance_matches_single_advance(
            payload in prop::collection::vec(any::<u8>(), 0..128),
            limit in 0usize..160,
            advance_steps in prop::collection::vec(0usize..96, 0..64),
        ) {
            let effective_len = payload.len().min(limit);
            let expected = &payload[..effective_len];

            let mut segmented = Take::new(payload.as_slice(), limit);
            let mut total_advanced = 0usize;
            for raw_step in advance_steps {
                if !segmented.has_remaining() {
                    break;
                }

                let step = raw_step % (segmented.remaining() + 1);
                segmented.advance(step);
                total_advanced += step;
                prop_assert_eq!(
                    segmented.remaining(),
                    effective_len - total_advanced,
                    "segmented advances must reduce remaining by the admitted count",
                );
            }

            let mut single = Take::new(payload.as_slice(), limit);
            single.advance(total_advanced);

            prop_assert_eq!(
                segmented.remaining(),
                single.remaining(),
                "many advances and one equivalent advance must leave the same remaining length",
            );
            prop_assert_eq!(
                segmented.chunk(),
                single.chunk(),
                "many advances and one equivalent advance must expose the same next chunk",
            );
            let segmented_tail = drain_to_vec(segmented);
            prop_assert_eq!(
                segmented_tail.as_slice(),
                &expected[total_advanced..],
                "segmented advances must leave the expected limited suffix",
            );
            let single_tail = drain_to_vec(single);
            prop_assert_eq!(
                single_tail.as_slice(),
                &expected[total_advanced..],
                "single advance must leave the expected limited suffix",
            );
        }
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
    fn test_take_set_limit_reopens_without_rewinding_inner() {
        init_test("test_take_set_limit_reopens_without_rewinding_inner");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let mut take = Take::new(buf, 2);

        let mut prefix = [0u8; 2];
        take.copy_to_slice(&mut prefix);
        crate::assert_with_log!(prefix == [1, 2], "prefix", [1, 2], prefix);
        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);

        take.set_limit(2);
        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 2, "remaining", 2, remaining);
        let chunk = take.chunk();
        crate::assert_with_log!(chunk == [3, 4], "chunk", &[3, 4], chunk);

        let mut next = [0u8; 2];
        take.copy_to_slice(&mut next);
        crate::assert_with_log!(next == [3, 4], "next", [3, 4], next);

        let inner = take.into_inner();
        crate::assert_with_log!(inner == [5], "inner", &[5], inner);
        crate::test_complete!("test_take_set_limit_reopens_without_rewinding_inner");
    }

    #[test]
    fn test_take_set_limit_shrinks_window_without_advancing_inner() {
        init_test("test_take_set_limit_shrinks_window_without_advancing_inner");
        let buf: &[u8] = &[1, 2, 3, 4, 5, 6];
        let mut take = Take::new(buf, 5);

        take.advance(1);
        take.set_limit(2);

        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 2, "remaining", 2, remaining);
        let chunk = take.chunk();
        crate::assert_with_log!(chunk == [2, 3], "chunk", &[2, 3], chunk);

        take.advance(2);
        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        let inner = take.into_inner();
        crate::assert_with_log!(inner == [4, 5, 6], "inner", &[4, 5, 6], inner);
        crate::test_complete!("test_take_set_limit_shrinks_window_without_advancing_inner");
    }

    #[test]
    fn test_take_set_limit_to_zero_closes_window_without_advancing_inner() {
        init_test("test_take_set_limit_to_zero_closes_window_without_advancing_inner");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let mut take = Take::new(buf, 4);

        take.advance(1);
        take.set_limit(0);

        let remaining = take.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        let chunk = take.chunk();
        crate::assert_with_log!(chunk.is_empty(), "chunk empty", true, chunk.is_empty());

        let inner = take.into_inner();
        crate::assert_with_log!(inner == [2, 3, 4, 5], "inner", &[2, 3, 4, 5], inner);
        crate::test_complete!("test_take_set_limit_to_zero_closes_window_without_advancing_inner");
    }

    #[test]
    fn test_take_into_inner() {
        init_test("test_take_into_inner");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let take = Take::new(buf, 3);
        let inner = take.into_inner();
        let ok = inner == [1, 2, 3, 4, 5];
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
