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
    fn read_buf_zero_capacity_accepts_empty_progress_only() {
        init_test("read_buf_zero_capacity_accepts_empty_progress_only");
        let mut buf = [];
        let mut read_buf = ReadBuf::new(&mut buf);

        let remaining = read_buf.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        let filled_empty = read_buf.filled().is_empty();
        crate::assert_with_log!(filled_empty, "filled empty", true, filled_empty);
        let unfilled_empty = read_buf.unfilled().is_empty();
        crate::assert_with_log!(unfilled_empty, "unfilled empty", true, unfilled_empty);

        read_buf.put_slice(&[]);
        read_buf.advance(0);

        let remaining = read_buf.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        let filled_empty = read_buf.filled().is_empty();
        crate::assert_with_log!(filled_empty, "filled empty", true, filled_empty);

        let panic = panic::catch_unwind(AssertUnwindSafe(|| {
            read_buf.put_slice(&[1]);
        }))
        .expect_err("zero-capacity ReadBuf must reject non-empty put_slice");
        let message = panic_message(panic.as_ref());
        crate::assert_with_log!(
            message.contains("ReadBuf overflow"),
            "put_slice panic message",
            true,
            message.contains("ReadBuf overflow")
        );

        let panic = panic::catch_unwind(AssertUnwindSafe(|| {
            read_buf.advance(1);
        }))
        .expect_err("zero-capacity ReadBuf must reject non-zero advance");
        let message = panic_message(panic.as_ref());
        crate::assert_with_log!(
            message.contains("ReadBuf overflow"),
            "advance panic message",
            true,
            message.contains("ReadBuf overflow")
        );

        let remaining = read_buf.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        let filled_empty = read_buf.filled().is_empty();
        crate::assert_with_log!(filled_empty, "filled empty", true, filled_empty);
        crate::test_complete!("read_buf_zero_capacity_accepts_empty_progress_only");
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

    proptest! {
        #[test]
        fn read_buf_metamorphic_chunked_put_matches_single_put(
            payload in prop::collection::vec(any::<u8>(), 0..96),
            capacity in 0usize..96,
            split_at in 0usize..96,
        ) {
            let write_len = payload.len().min(capacity);
            let payload = &payload[..write_len];

            let mut single_storage = vec![0xAA; capacity];
            let (single_filled, single_remaining) = {
                let mut single = ReadBuf::new(&mut single_storage);
                single.put_slice(payload);
                (single.filled().to_vec(), single.remaining())
            };

            let mut chunked_storage = vec![0xAA; capacity];
            let (chunked_filled, chunked_remaining) = {
                let split_at = split_at.min(write_len);
                let mut chunked = ReadBuf::new(&mut chunked_storage);
                chunked.put_slice(&payload[..split_at]);
                chunked.put_slice(&payload[split_at..]);
                (chunked.filled().to_vec(), chunked.remaining())
            };

            prop_assert_eq!(
                chunked_filled.as_slice(),
                single_filled.as_slice(),
                "chunked ReadBuf writes must match one-shot writes",
            );
            prop_assert_eq!(
                chunked_remaining,
                single_remaining,
                "chunking must not change remaining capacity",
            );
            prop_assert_eq!(single_filled.as_slice(), payload);
            prop_assert_eq!(&single_storage[..write_len], payload);
            prop_assert_eq!(&chunked_storage[..write_len], payload);
            prop_assert!(
                single_storage[write_len..].iter().all(|byte| *byte == 0xAA),
                "one-shot write must not touch unwritten tail",
            );
            prop_assert!(
                chunked_storage[write_len..].iter().all(|byte| *byte == 0xAA),
                "chunked write must not touch unwritten tail",
            );
        }

        #[test]
        fn read_buf_metamorphic_advance_matches_put_of_preinitialized_tail(
            initial_storage in prop::collection::vec(any::<u8>(), 0..128),
            prefix in prop::collection::vec(any::<u8>(), 0..128),
            advance_len in 0usize..128,
        ) {
            let capacity = initial_storage.len();
            let prefix_len = prefix.len().min(capacity);
            let advance_len = advance_len.min(capacity - prefix_len);
            let advanced_tail = &initial_storage[prefix_len..prefix_len + advance_len];

            let mut advanced_storage = initial_storage.clone();
            let (advanced_filled, advanced_remaining) = {
                let mut advanced = ReadBuf::new(&mut advanced_storage);
                advanced.put_slice(&prefix[..prefix_len]);
                advanced.advance(advance_len);
                (advanced.filled().to_vec(), advanced.remaining())
            };

            let mut explicit_storage = initial_storage.clone();
            let (explicit_filled, explicit_remaining) = {
                let mut explicit = ReadBuf::new(&mut explicit_storage);
                explicit.put_slice(&prefix[..prefix_len]);
                explicit.put_slice(advanced_tail);
                (explicit.filled().to_vec(), explicit.remaining())
            };

            let mut expected = prefix[..prefix_len].to_vec();
            expected.extend_from_slice(advanced_tail);

            prop_assert_eq!(
                advanced_filled.as_slice(),
                expected.as_slice(),
                "advance must expose the preinitialized backing bytes after the written prefix",
            );
            prop_assert_eq!(
                advanced_filled.as_slice(),
                explicit_filled.as_slice(),
                "advancing over initialized bytes must match explicitly putting the same bytes",
            );
            prop_assert_eq!(
                advanced_remaining,
                explicit_remaining,
                "advance and explicit put must leave identical remaining capacity",
            );
        }
    }

    #[test]
    fn read_buf_filled_mut_changes_only_filled_prefix() {
        init_test("read_buf_filled_mut_changes_only_filled_prefix");
        let mut buf = [0u8; 6];
        let mut read_buf = ReadBuf::new(&mut buf);
        read_buf.put_slice(&[1, 2, 3]);

        {
            let filled = read_buf.filled_mut();
            crate::assert_with_log!(filled.len() == 3, "filled len", 3, filled.len());
            filled[1] = 9;
        }

        let filled = read_buf.filled();
        crate::assert_with_log!(filled == [1, 9, 3], "filled", &[1, 9, 3], filled);
        let remaining = read_buf.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);

        {
            let unfilled = read_buf.unfilled();
            crate::assert_with_log!(unfilled == [0, 0, 0], "unfilled", &[0, 0, 0], unfilled);
        }
        crate::test_complete!("read_buf_filled_mut_changes_only_filled_prefix");
    }

    #[test]
    fn read_buf_put_slice_rejects_overflow_without_advancing() {
        init_test("read_buf_put_slice_rejects_overflow_without_advancing");
        let mut buf = [0u8; 4];
        let mut read_buf = ReadBuf::new(&mut buf);
        read_buf.put_slice(&[1, 2]);

        let panic = panic::catch_unwind(AssertUnwindSafe(|| {
            read_buf.put_slice(&[3, 4, 5]);
        }))
        .expect_err("put_slice must fail closed when source exceeds remaining capacity");
        let message = panic_message(panic.as_ref());
        crate::assert_with_log!(
            message.contains("ReadBuf overflow"),
            "panic message",
            true,
            message.contains("ReadBuf overflow")
        );
        let filled = read_buf.filled();
        crate::assert_with_log!(filled == [1, 2], "filled preserved", &[1, 2], filled);
        let remaining = read_buf.remaining();
        crate::assert_with_log!(remaining == 2, "remaining preserved", 2, remaining);
        crate::test_complete!("read_buf_put_slice_rejects_overflow_without_advancing");
    }

    #[test]
    fn read_buf_unfilled_tracks_remaining_tail() {
        init_test("read_buf_unfilled_tracks_remaining_tail");
        let mut buf = [0u8; 6];
        let mut read_buf = ReadBuf::new(&mut buf);
        read_buf.put_slice(&[1, 2]);

        {
            let unfilled = read_buf.unfilled();
            crate::assert_with_log!(unfilled.len() == 4, "unfilled len", 4, unfilled.len());
            unfilled[0] = 9;
        }

        read_buf.advance(1);
        let filled = read_buf.filled();
        crate::assert_with_log!(
            filled == [1, 2, 9],
            "advanced unfilled byte",
            &[1, 2, 9],
            filled
        );
        let remaining = read_buf.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        crate::test_complete!("read_buf_unfilled_tracks_remaining_tail");
    }
}
