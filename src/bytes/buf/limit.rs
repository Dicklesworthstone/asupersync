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
    use crate::bytes::BytesMut;
    use proptest::prelude::*;

    fn append_if_room(buf: &mut impl BufMut, src: &[u8]) {
        assert!(buf.has_remaining_mut());
        assert!(buf.remaining_mut() >= src.len());
        buf.put_slice(src);
    }

    fn put_via_direct_window_or_append(buf: &mut impl BufMut, src: &[u8]) {
        assert!(buf.remaining_mut() >= src.len());

        if buf.direct_remaining_mut() == 0 {
            buf.put_slice(src);
            return;
        }

        let mut offset = 0;
        while offset < src.len() {
            let direct_remaining = buf.direct_remaining_mut();
            assert!(direct_remaining > 0);
            let chunk = buf.chunk_mut();
            assert!(!chunk.is_empty());
            assert!(chunk.len() <= direct_remaining);
            let count = chunk.len().min(src.len() - offset);
            chunk[..count].copy_from_slice(&src[offset..offset + count]);
            buf.advance_mut(count);
            offset += count;
        }
    }

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
    fn growable_limits_preserve_logical_capacity_and_guarded_appends() {
        init_test("growable_limits_preserve_logical_capacity_and_guarded_appends");

        let mut bytes = BytesMut::new().limit(3);
        assert_eq!(bytes.remaining_mut(), 3);
        assert_eq!(bytes.direct_remaining_mut(), 0);
        assert!(bytes.has_remaining_mut());
        append_if_room(&mut bytes, b"abc");
        assert_eq!(bytes.remaining_mut(), 0);
        assert_eq!(bytes.into_inner().as_ref(), b"abc");

        let mut vec = Vec::new().limit(3);
        assert_eq!(vec.remaining_mut(), 3);
        assert_eq!(vec.direct_remaining_mut(), 0);
        assert!(vec.has_remaining_mut());
        append_if_room(&mut vec, b"abc");
        assert_eq!(vec.remaining_mut(), 0);
        assert_eq!(vec.into_inner().as_slice(), b"abc");

        crate::test_complete!("growable_limits_preserve_logical_capacity_and_guarded_appends");
    }

    #[test]
    fn generic_direct_writer_falls_back_for_append_only_buffers() {
        init_test("generic_direct_writer_falls_back_for_append_only_buffers");

        let mut bytes = BytesMut::new();
        put_via_direct_window_or_append(&mut bytes, b"bytes");
        assert_eq!(bytes.as_ref(), b"bytes");

        let mut vec = Vec::new();
        put_via_direct_window_or_append(&mut vec, b"vec");
        assert_eq!(vec.as_slice(), b"vec");

        let mut limited_bytes = BytesMut::new().limit(3);
        put_via_direct_window_or_append(&mut limited_bytes, b"abc");
        assert_eq!(limited_bytes.into_inner().as_ref(), b"abc");

        let mut limited_vec = Vec::new().limit(3);
        put_via_direct_window_or_append(&mut limited_vec, b"abc");
        assert_eq!(limited_vec.into_inner().as_slice(), b"abc");

        let mut direct = [0u8; 3];
        {
            let mut slice: &mut [u8] = &mut direct;
            put_via_direct_window_or_append(&mut slice, b"abc");
        }
        assert_eq!(direct, *b"abc");

        crate::test_complete!("generic_direct_writer_falls_back_for_append_only_buffers");
    }

    #[test]
    fn test_limit_zero_limit_exposes_no_direct_space_without_advancing_inner() {
        init_test("test_limit_zero_limit_exposes_no_direct_space_without_advancing_inner");
        let mut data = [0u8; 4];
        {
            let buf: &mut [u8] = &mut data;
            let mut limit = Limit::new(buf, 0);

            let remaining = limit.remaining_mut();
            crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);

            let chunk = limit.chunk_mut();
            crate::assert_with_log!(chunk.is_empty(), "chunk empty", true, chunk.is_empty());

            limit.advance_mut(0);
            limit.put_slice(&[]);

            let inner = limit.into_inner();
            let inner_len = inner.len();
            crate::assert_with_log!(inner_len == 4, "inner len", 4, inner_len);
        }

        crate::assert_with_log!(data == [0, 0, 0, 0], "data", [0, 0, 0, 0], data);
        crate::test_complete!(
            "test_limit_zero_limit_exposes_no_direct_space_without_advancing_inner"
        );
    }

    proptest! {
        #[test]
        fn limit_metamorphic_chunked_put_matches_single_put(
            payload in prop::collection::vec(any::<u8>(), 0..96),
            capacity in 0usize..96,
            limit in 0usize..96,
            split_at in 0usize..96,
        ) {
            let write_len = payload.len().min(capacity).min(limit);
            let payload = &payload[..write_len];

            let mut single = vec![0xAA; capacity];
            let single_remaining = {
                let buf: &mut [u8] = &mut single;
                let mut limited = Limit::new(buf, limit);
                limited.put_slice(payload);
                limited.remaining_mut()
            };

            let mut chunked = vec![0xAA; capacity];
            let chunked_remaining = {
                let split_at = split_at.min(write_len);
                let buf: &mut [u8] = &mut chunked;
                let mut limited = Limit::new(buf, limit);
                limited.put_slice(&payload[..split_at]);
                limited.put_slice(&payload[split_at..]);
                limited.remaining_mut()
            };

            prop_assert_eq!(
                chunked.as_slice(),
                single.as_slice(),
                "chunked writes through Limit must match one-shot writes",
            );
            prop_assert_eq!(
                chunked_remaining,
                single_remaining,
                "chunking must not change effective remaining capacity",
            );
            prop_assert_eq!(
                &single[..write_len],
                payload,
                "Limit must write exactly the admitted payload prefix",
            );
            prop_assert!(
                single[write_len..].iter().all(|byte| *byte == 0xAA),
                "Limit must not write past the admitted payload prefix",
            );
        }

        #[test]
        fn limit_metamorphic_set_limit_after_prefix_matches_fresh_suffix_limit(
            prefix in prop::collection::vec(any::<u8>(), 0..96),
            suffix in prop::collection::vec(any::<u8>(), 0..96),
            initial_limit in 0usize..96,
            suffix_limit in 0usize..96,
        ) {
            let prefix_len = prefix.len().min(initial_limit);
            let suffix_len = suffix.len().min(suffix_limit);

            let mut staged = Limit::new(Vec::new(), initial_limit);
            staged.put_slice(&prefix[..prefix_len]);
            staged.set_limit(suffix_limit);
            staged.put_slice(&suffix[..suffix_len]);
            let staged_remaining = staged.remaining_mut();
            let staged = staged.into_inner();

            let mut suffix_only = Limit::new(Vec::new(), suffix_limit);
            suffix_only.put_slice(&suffix[..suffix_len]);
            let suffix_remaining = suffix_only.remaining_mut();

            let mut expected = prefix[..prefix_len].to_vec();
            expected.extend_from_slice(&suffix_only.into_inner());

            prop_assert_eq!(
                staged,
                expected,
                "resetting Limit after a prefix write must only constrain later suffix writes",
            );
            prop_assert_eq!(
                staged_remaining,
                suffix_remaining,
                "remaining capacity after reset must match a fresh suffix-limited buffer",
            );
        }
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
    fn test_limit_chunk_mut_is_empty_when_inner_cannot_expose_direct_space() {
        let mut limit = Limit::new(Vec::new(), 3);
        assert_eq!(limit.remaining_mut(), 3);
        assert_eq!(limit.direct_remaining_mut(), 0);
        assert!(limit.has_remaining_mut());
        assert!(limit.chunk_mut().is_empty());
        limit.advance_mut(0);
    }

    #[test]
    fn nested_limits_bound_logical_and_direct_capacity_independently() {
        init_test("nested_limits_bound_logical_and_direct_capacity_independently");

        let mut append_only = BytesMut::new().limit(6).limit(3);
        assert_eq!(append_only.remaining_mut(), 3);
        assert_eq!(append_only.direct_remaining_mut(), 0);
        append_only.put_slice(b"abc");
        assert_eq!(append_only.remaining_mut(), 0);
        assert_eq!(append_only.into_inner().into_inner().as_ref(), b"abc");

        let mut direct = [0u8; 8];
        {
            let inner = (&mut direct[..]).limit(6);
            let mut outer = inner.limit(3);
            assert_eq!(outer.remaining_mut(), 3);
            assert_eq!(outer.direct_remaining_mut(), 3);
            put_via_direct_window_or_append(&mut outer, b"abc");
            assert_eq!(outer.remaining_mut(), 0);
            assert_eq!(outer.direct_remaining_mut(), 0);
        }
        assert_eq!(&direct[..3], b"abc");

        crate::test_complete!("nested_limits_bound_logical_and_direct_capacity_independently");
    }

    #[test]
    fn over_limit_append_panics_before_mutating_growable_inner() {
        init_test("over_limit_append_panics_before_mutating_growable_inner");
        let mut limit = BytesMut::new().limit(3);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            limit.put_slice(b"abcd");
        }));

        assert!(result.is_err());
        assert!(limit.get_ref().is_empty());
        assert_eq!(limit.limit(), 3);
        crate::test_complete!("over_limit_append_panics_before_mutating_growable_inner");
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
    fn test_limit_set_limit_after_write_shrinks_window_without_rewinding_inner() {
        init_test("test_limit_set_limit_after_write_shrinks_window_without_rewinding_inner");
        let mut data = [0u8; 6];
        {
            let buf: &mut [u8] = &mut data;
            let mut limit = Limit::new(buf, 5);

            limit.put_slice(&[1, 2]);
            let remaining = limit.remaining_mut();
            crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);

            limit.set_limit(1);
            let remaining = limit.remaining_mut();
            crate::assert_with_log!(remaining == 1, "remaining", 1, remaining);

            limit.put_slice(&[3]);
            let remaining = limit.remaining_mut();
            crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);

            let inner = limit.into_inner();
            let len = inner.len();
            crate::assert_with_log!(len == 3, "len", 3, len);
        }

        crate::assert_with_log!(data == [1, 2, 3, 0, 0, 0], "data", [1, 2, 3, 0, 0, 0], data);
        crate::test_complete!(
            "test_limit_set_limit_after_write_shrinks_window_without_rewinding_inner"
        );
    }

    #[test]
    fn test_limit_set_limit_to_zero_closes_window_without_advancing_inner() {
        init_test("test_limit_set_limit_to_zero_closes_window_without_advancing_inner");
        let mut data = [0u8; 5];
        {
            let buf: &mut [u8] = &mut data;
            let mut limit = Limit::new(buf, 4);

            limit.put_slice(&[1, 2]);
            limit.set_limit(0);

            let remaining = limit.remaining_mut();
            crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
            let chunk = limit.chunk_mut();
            crate::assert_with_log!(chunk.is_empty(), "chunk empty", true, chunk.is_empty());

            limit.put_slice(&[]);
            let inner = limit.into_inner();
            let len = inner.len();
            crate::assert_with_log!(len == 3, "len", 3, len);
        }

        crate::assert_with_log!(data == [1, 2, 0, 0, 0], "data", [1, 2, 0, 0, 0], data);
        crate::test_complete!("test_limit_set_limit_to_zero_closes_window_without_advancing_inner");
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
