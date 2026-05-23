//! Chain adapter for chaining two Buf implementations.

use super::Buf;

/// A `Buf` that chains two buffers together.
///
/// Created by [`Buf::chain()`].
///
/// # Examples
///
/// ```
/// use asupersync::bytes::Buf;
///
/// let a: &[u8] = &[1, 2, 3];
/// let b: &[u8] = &[4, 5, 6];
///
/// let mut chain = a.chain(b);
/// assert_eq!(chain.remaining(), 6);
///
/// let mut dst = [0u8; 6];
/// chain.copy_to_slice(&mut dst);
/// assert_eq!(dst, [1, 2, 3, 4, 5, 6]);
/// ```
#[derive(Debug)]
pub struct Chain<T, U> {
    a: T,
    b: U,
}

impl<T, U> Chain<T, U> {
    /// Create a new `Chain` from two buffers.
    #[inline]
    pub(crate) fn new(a: T, b: U) -> Self {
        Self { a, b }
    }

    /// Gets a reference to the first buffer.
    #[inline]
    #[must_use]
    pub fn first_ref(&self) -> &T {
        &self.a
    }

    /// Gets a mutable reference to the first buffer.
    #[inline]
    pub fn first_mut(&mut self) -> &mut T {
        &mut self.a
    }

    /// Gets a reference to the second buffer.
    #[inline]
    #[must_use]
    pub fn last_ref(&self) -> &U {
        &self.b
    }

    /// Gets a mutable reference to the second buffer.
    #[inline]
    pub fn last_mut(&mut self) -> &mut U {
        &mut self.b
    }

    /// Consumes this `Chain`, returning the underlying buffers.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> (T, U) {
        (self.a, self.b)
    }
}

impl<T: Buf, U: Buf> Buf for Chain<T, U> {
    #[inline]
    fn remaining(&self) -> usize {
        self.a.remaining().saturating_add(self.b.remaining())
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        if self.a.has_remaining() {
            self.a.chunk()
        } else {
            self.b.chunk()
        }
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        let a_rem = self.a.remaining();

        if cnt <= a_rem {
            self.a.advance(cnt);
        } else {
            // Drain all of a
            if a_rem > 0 {
                self.a.advance(a_rem);
            }
            cnt -= a_rem;

            // Advance b
            self.b.advance(cnt);
        }
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

    #[derive(Debug)]
    struct VirtualBuf {
        remaining: usize,
        chunk: &'static [u8],
    }

    impl VirtualBuf {
        fn new(remaining: usize, chunk: &'static [u8]) -> Self {
            Self { remaining, chunk }
        }
    }

    impl Buf for VirtualBuf {
        fn remaining(&self) -> usize {
            self.remaining
        }

        fn chunk(&self) -> &[u8] {
            let visible = self.remaining.min(self.chunk.len());
            &self.chunk[..visible]
        }

        fn advance(&mut self, cnt: usize) {
            assert!(cnt <= self.remaining, "advanced past end of virtual buffer");
            self.remaining -= cnt;
        }
    }

    fn drain_to_vec(mut buf: impl Buf) -> Vec<u8> {
        let mut out = vec![0u8; buf.remaining()];
        buf.copy_to_slice(&mut out);
        out
    }

    #[test]
    fn test_chain_remaining() {
        init_test("test_chain_remaining");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let chain = Chain::new(a, b);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 6, "remaining", 6, remaining);
        crate::test_complete!("test_chain_remaining");
    }

    #[test]
    fn chain_remaining_saturates_when_segments_exceed_usize_max() {
        init_test("chain_remaining_saturates_when_segments_exceed_usize_max");
        let a = VirtualBuf::new(usize::MAX - 2, b"a");
        let b = VirtualBuf::new(7, b"b");
        let chain = Chain::new(a, b);

        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == usize::MAX, "remaining", usize::MAX, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == b"a", "chunk", b"a", chunk);
        crate::test_complete!("chain_remaining_saturates_when_segments_exceed_usize_max");
    }

    #[test]
    fn test_chain_chunk() {
        init_test("test_chain_chunk");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let chain = Chain::new(a, b);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [1, 2, 3], "chunk", &[1, 2, 3], chunk);
        crate::test_complete!("test_chain_chunk");
    }

    #[test]
    fn chain_empty_first_buffer_reads_second_without_consuming() {
        init_test("chain_empty_first_buffer_reads_second_without_consuming");
        let a: &[u8] = &[];
        let b: &[u8] = &[7, 8, 9];
        let mut chain = Chain::new(a, b);

        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [7, 8, 9], "chunk", &[7, 8, 9], chunk);

        chain.advance(0);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 3, "remaining after zero", 3, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [7, 8, 9], "chunk after zero", &[7, 8, 9], chunk);

        chain.advance(3);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 0, "remaining after drain", 0, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk.is_empty(), "empty chunk", true, chunk.is_empty());
        crate::test_complete!("chain_empty_first_buffer_reads_second_without_consuming");
    }

    #[test]
    fn test_chain_advance() {
        init_test("test_chain_advance");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let mut chain = Chain::new(a, b);

        chain.advance(2);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 4, "remaining", 4, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [3], "chunk", &[3], chunk);

        chain.advance(1);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [4, 5, 6], "chunk", &[4, 5, 6], chunk);

        chain.advance(2);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 1, "remaining", 1, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [6], "chunk", &[6], chunk);
        crate::test_complete!("test_chain_advance");
    }

    #[test]
    #[should_panic]
    fn test_chain_advance_panics_when_count_exceeds_total_remaining() {
        let a: &[u8] = &[1, 2];
        let b: &[u8] = &[3];
        let mut chain = Chain::new(a, b);

        chain.advance(4);
    }

    #[test]
    fn test_chain_copy_to_slice() {
        init_test("test_chain_copy_to_slice");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let mut chain = Chain::new(a, b);

        let mut dst = [0u8; 6];
        chain.copy_to_slice(&mut dst);
        let ok = dst == [1, 2, 3, 4, 5, 6];
        crate::assert_with_log!(ok, "dst", [1, 2, 3, 4, 5, 6], dst);
        crate::test_complete!("test_chain_copy_to_slice");
    }

    proptest! {
        #[test]
        fn chain_metamorphic_nested_associativity_matches_flat_bytes(
            a in prop::collection::vec(any::<u8>(), 0..33),
            b in prop::collection::vec(any::<u8>(), 0..33),
            c in prop::collection::vec(any::<u8>(), 0..33),
            read_steps in prop::collection::vec(0usize..64, 0..64),
        ) {
            let mut expected = Vec::with_capacity(a.len() + b.len() + c.len());
            expected.extend_from_slice(&a);
            expected.extend_from_slice(&b);
            expected.extend_from_slice(&c);

            let mut left_nested = Chain::new(
                Chain::new(a.as_slice(), b.as_slice()),
                c.as_slice(),
            );
            let mut right_nested = Chain::new(
                a.as_slice(),
                Chain::new(b.as_slice(), c.as_slice()),
            );
            let mut observed = Vec::with_capacity(expected.len());

            prop_assert_eq!(left_nested.remaining(), expected.len());
            prop_assert_eq!(right_nested.remaining(), expected.len());

            for raw_step in read_steps {
                if !left_nested.has_remaining() {
                    break;
                }

                prop_assert_eq!(left_nested.remaining(), right_nested.remaining());
                let read_len = 1 + raw_step % left_nested.remaining();

                let mut left_bytes = vec![0u8; read_len];
                left_nested.copy_to_slice(&mut left_bytes);

                let mut right_bytes = vec![0u8; read_len];
                right_nested.copy_to_slice(&mut right_bytes);

                prop_assert_eq!(
                    left_bytes.as_slice(),
                    right_bytes.as_slice(),
                    "nested Chain shapes must emit identical segmented reads",
                );
                observed.extend_from_slice(&left_bytes);
                prop_assert_eq!(left_nested.remaining(), right_nested.remaining());
                prop_assert_eq!(&expected[..observed.len()], observed.as_slice());
            }

            let final_len = left_nested.remaining();
            prop_assert_eq!(final_len, right_nested.remaining());

            let mut left_tail = vec![0u8; final_len];
            left_nested.copy_to_slice(&mut left_tail);

            let mut right_tail = vec![0u8; final_len];
            right_nested.copy_to_slice(&mut right_tail);

            prop_assert_eq!(
                left_tail.as_slice(),
                right_tail.as_slice(),
                "nested Chain shapes must emit identical tails",
            );
            observed.extend_from_slice(&left_tail);
            prop_assert_eq!(observed.as_slice(), expected.as_slice());
            prop_assert_eq!(left_nested.remaining(), 0);
            prop_assert_eq!(right_nested.remaining(), 0);
        }

        #[test]
        fn chain_metamorphic_segmented_advance_matches_single_advance(
            a in prop::collection::vec(any::<u8>(), 0..64),
            b in prop::collection::vec(any::<u8>(), 0..64),
            advance_steps in prop::collection::vec(0usize..96, 0..64),
        ) {
            let mut expected = Vec::with_capacity(a.len() + b.len());
            expected.extend_from_slice(&a);
            expected.extend_from_slice(&b);

            let mut segmented = Chain::new(a.as_slice(), b.as_slice());
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
                    expected.len() - total_advanced,
                    "segmented advances must reduce remaining by exactly the advanced count",
                );
            }

            let mut single = Chain::new(a.as_slice(), b.as_slice());
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
                "segmented advances must leave the expected concatenated suffix",
            );
            let single_tail = drain_to_vec(single);
            prop_assert_eq!(
                single_tail.as_slice(),
                &expected[total_advanced..],
                "single advance must leave the expected concatenated suffix",
            );
        }
    }

    #[test]
    fn test_chain_getters() {
        init_test("test_chain_getters");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let mut chain = Chain::new(a, b);

        let first = *chain.first_ref();
        crate::assert_with_log!(first == &[1, 2, 3][..], "first", &[1, 2, 3][..], first);
        let last = *chain.last_ref();
        crate::assert_with_log!(last == &[4, 5, 6][..], "last", &[4, 5, 6][..], last);

        // Advance and check
        chain.advance(4);
        let first = *chain.first_ref();
        crate::assert_with_log!(first == b"", "first", b"", first);
        let last = *chain.last_ref();
        crate::assert_with_log!(last == &[5, 6][..], "last", &[5, 6][..], last);
        crate::test_complete!("test_chain_getters");
    }

    #[test]
    fn test_chain_into_inner() {
        init_test("test_chain_into_inner");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let chain = Chain::new(a, b);

        let (a_out, b_out) = chain.into_inner();
        let ok = a_out == [1, 2, 3];
        crate::assert_with_log!(ok, "a_out", &[1, 2, 3], a_out);
        let ok = b_out == [4, 5, 6];
        crate::assert_with_log!(ok, "b_out", &[4, 5, 6], b_out);
        crate::test_complete!("test_chain_into_inner");
    }
}
