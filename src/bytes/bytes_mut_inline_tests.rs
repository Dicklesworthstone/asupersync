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

    #[test]
    fn test_bytes_mut_new() {
        init_test("test_bytes_mut_new");
        let b = BytesMut::new();
        let empty = b.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        let len = b.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("test_bytes_mut_new");
    }

    /// br-asupersync-i5w8lh: into_vec moves out the underlying Vec<u8>
    /// without copying. Verify the returned Vec contains exactly the
    /// bytes that were in the BytesMut, including for non-trivial
    /// payloads (binary, embedded nulls, large) that would catch any
    /// wrong-slice or truncation regression.
    #[test]
    fn into_vec_returns_underlying_bytes_unchanged() {
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");
        let v = b.into_vec();
        assert_eq!(v.as_slice(), b"hello world");
        assert_eq!(v.len(), 11);

        // Non-trivial payload: binary data with embedded nulls.
        let mut b = BytesMut::new();
        b.put_slice(&[0x00, 0xFF, 0x42, 0x00, 0x99, 0x00]);
        let v = b.into_vec();
        assert_eq!(v.as_slice(), &[0x00, 0xFF, 0x42, 0x00, 0x99, 0x00]);

        // Empty BytesMut -> empty Vec, no allocation surprises.
        let b = BytesMut::new();
        let v = b.into_vec();
        assert!(v.is_empty());

        // Large payload: 1 MiB of patterned bytes — verify the move
        // preserves every byte (catches off-by-one slice bugs).
        let mut b = BytesMut::with_capacity(1024 * 1024);
        for i in 0..(1024 * 1024) {
            b.put_u8((i & 0xFF) as u8);
        }
        let v = b.into_vec();
        assert_eq!(v.len(), 1024 * 1024);
        for (i, byte) in v.iter().enumerate().take(1024 * 1024) {
            assert_eq!(*byte, (i & 0xFF) as u8, "mismatch at byte {i}");
        }
    }

    /// br-asupersync-i5w8lh: into_vec preserves bytes even after
    /// split_to. The HTTP/1 codec hot path exercises split_to followed
    /// by into_vec on the resulting BytesMut; this test mirrors that
    /// flow directly to lock in the contract.
    #[test]
    fn into_vec_after_split_to_preserves_payload_slice() {
        let mut buf = BytesMut::new();
        buf.put_slice(b"head\x00\x01\x02tail");
        // Split off the first 7 bytes (b"head\x00\x01\x02").
        let head = buf.split_to(7);
        let v = head.into_vec();
        assert_eq!(v.as_slice(), b"head\x00\x01\x02");
        // The remaining buf should hold the suffix unchanged.
        assert_eq!(&buf[..], b"tail");
    }

    #[test]
    fn test_bytes_mut_with_capacity() {
        init_test("test_bytes_mut_with_capacity");
        let b = BytesMut::with_capacity(100);
        let empty = b.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        let cap_ok = b.capacity() >= 100;
        crate::assert_with_log!(cap_ok, "capacity >= 100", true, cap_ok);
        crate::test_complete!("test_bytes_mut_with_capacity");
    }

    #[test]
    fn test_bytes_mut_put_slice() {
        init_test("test_bytes_mut_put_slice");
        let mut b = BytesMut::new();
        b.put_slice(b"hello");
        b.put_slice(b" ");
        b.put_slice(b"world");

        let ok = &b[..] == b"hello world";
        crate::assert_with_log!(ok, "contents", b"hello world", &b[..]);
        crate::test_complete!("test_bytes_mut_put_slice");
    }

    #[test]
    fn test_bytes_mut_reserve_and_grow() {
        init_test("test_bytes_mut_reserve_and_grow");
        let mut b = BytesMut::new();

        // Small write
        b.put_slice(b"hello");
        let len = b.len();
        crate::assert_with_log!(len == 5, "len", 5, len);

        // Reserve more
        b.reserve(1000);
        let cap_ok = b.capacity() >= 1005;
        crate::assert_with_log!(cap_ok, "capacity >= 1005", true, cap_ok);

        // Data should be preserved
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "contents", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_reserve_and_grow");
    }

    #[test]
    fn test_bytes_mut_freeze() {
        init_test("test_bytes_mut_freeze");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");

        let frozen = b.freeze();
        let ok = &frozen[..] == b"hello world";
        crate::assert_with_log!(ok, "frozen", b"hello world", &frozen[..]);

        // Should be able to clone cheaply
        let clone = frozen.clone();
        drop(frozen);
        let ok = &clone[..] == b"hello world";
        crate::assert_with_log!(ok, "clone", b"hello world", &clone[..]);
        crate::test_complete!("test_bytes_mut_freeze");
    }

    #[test]
    fn test_bytes_mut_split_off() {
        init_test("test_bytes_mut_split_off");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");

        let world = b.split_off(6);

        let ok = &b[..] == b"hello ";
        crate::assert_with_log!(ok, "left", b"hello ", &b[..]);
        let ok = &world[..] == b"world";
        crate::assert_with_log!(ok, "right", b"world", &world[..]);
        crate::test_complete!("test_bytes_mut_split_off");
    }

    #[test]
    fn test_bytes_mut_split_to() {
        init_test("test_bytes_mut_split_to");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");

        let hello = b.split_to(6);

        let ok = &hello[..] == b"hello ";
        crate::assert_with_log!(ok, "left", b"hello ", &hello[..]);
        let ok = &b[..] == b"world";
        crate::assert_with_log!(ok, "right", b"world", &b[..]);
        crate::test_complete!("test_bytes_mut_split_to");
    }

    #[test]
    fn bytes_mut_split_to_advances_suffix_without_memmove() {
        init_test("bytes_mut_split_to_advances_suffix_without_memmove");
        let mut b = BytesMut::with_capacity(64);
        b.put_slice(b"abcdefghijklmnop");

        let expected_suffix_ptr = b[4..].as_ptr();
        let head = b.split_to(4);

        crate::assert_with_log!(&head[..] == b"abcd", "head", b"abcd", &head[..]);
        crate::assert_with_log!(&b[..] == b"efghijklmnop", "suffix", b"efghijklmnop", &b[..]);
        let suffix_ptr_preserved = std::ptr::eq(b.as_ptr(), expected_suffix_ptr);
        crate::assert_with_log!(
            suffix_ptr_preserved,
            "suffix pointer preserved",
            true,
            suffix_ptr_preserved
        );
        crate::test_complete!("bytes_mut_split_to_advances_suffix_without_memmove");
    }

    #[test]
    fn bytes_mut_split_to_all_reclaims_front_capacity_for_reuse() {
        init_test("bytes_mut_split_to_all_reclaims_front_capacity_for_reuse");
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"abcd");
        let original_capacity = b.capacity();

        let head = b.split_to(4);

        crate::assert_with_log!(&head[..] == b"abcd", "head", b"abcd", &head[..]);
        crate::assert_with_log!(b.is_empty(), "buffer empty", true, b.is_empty());
        let capacity_reused = b.capacity() >= original_capacity;
        crate::assert_with_log!(capacity_reused, "capacity reused", true, capacity_reused);

        b.put_slice(b"xy");
        crate::assert_with_log!(&b[..] == b"xy", "rewritten", b"xy", &b[..]);
        let capacity_still_reused = b.capacity() >= original_capacity;
        crate::assert_with_log!(
            capacity_still_reused,
            "capacity still reused",
            true,
            capacity_still_reused
        );
        crate::test_complete!("bytes_mut_split_to_all_reclaims_front_capacity_for_reuse");
    }

    /// A full buffer consumed and refilled in small steps (a write buffer
    /// draining to a slow peer) used to move all of its live bytes to the
    /// front for every append, because each move freed only one step.
    #[test]
    fn bytes_mut_small_advance_then_append_does_not_move_the_buffer_each_time() {
        init_test("bytes_mut_small_advance_then_append_does_not_move_the_buffer_each_time");
        const FULL: usize = 64 * 1024;
        const STEP: usize = 16;
        let mut b = BytesMut::with_capacity(FULL);
        b.resize(FULL, 0);
        let mut expected: std::collections::VecDeque<u8> = std::iter::repeat_n(0, FULL).collect();
        let mut moves = 0usize;
        for round in 0..1000usize {
            let before = b.as_ptr();
            b.advance(STEP);
            let byte = u8::try_from(round % 251).unwrap_or(0);
            b.put_slice(&[byte; STEP]);
            if b.as_ptr() != before.wrapping_add(STEP) {
                moves += 1;
            }
            expected.drain(..STEP);
            expected.extend(std::iter::repeat_n(byte, STEP));
        }
        crate::assert_with_log!(
            moves <= 1,
            "the live bytes moved at most once",
            "<=1",
            moves
        );
        let contents_kept = b.iter().copied().eq(expected.iter().copied());
        crate::assert_with_log!(contents_kept, "contents", true, contents_kept);
        crate::test_complete!(
            "bytes_mut_small_advance_then_append_does_not_move_the_buffer_each_time"
        );
    }

    #[test]
    fn bytes_mut_advance_matches_split_to_remainder() {
        init_test("bytes_mut_advance_matches_split_to_remainder");
        // `advance(n)` must leave `self` in the exact state `split_to(n)` does,
        // just without materializing the discarded head. Prove parity across
        // partial, full, and repeated advances plus front-capacity reclaim.
        for n in 0..=11usize {
            let mut via_split = BytesMut::from(&b"hello world"[..]);
            let _head = via_split.split_to(n);
            let mut via_advance = BytesMut::from(&b"hello world"[..]);
            via_advance.advance(n);
            crate::assert_with_log!(
                via_split[..] == via_advance[..],
                "advance leaves same remainder as split_to",
                &via_split[..],
                &via_advance[..]
            );
            crate::assert_with_log!(
                via_split.len() == via_advance.len(),
                "advance leaves same len",
                via_split.len(),
                via_advance.len()
            );
        }

        // Full drain reclaims the front so the backing Vec is reusable.
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"abcd");
        let cap = b.capacity();
        b.advance(4);
        crate::assert_with_log!(
            b.is_empty(),
            "fully advanced buffer is empty",
            true,
            b.is_empty()
        );
        crate::assert_with_log!(
            b.capacity() >= cap,
            "front capacity reclaimed",
            true,
            b.capacity() >= cap
        );
        b.put_slice(b"xyz");
        crate::assert_with_log!(
            &b[..] == b"xyz",
            "reusable after full advance",
            b"xyz",
            &b[..]
        );

        // Incremental advances (the codec-flush pattern) drain in order.
        let mut stream = BytesMut::from(&b"abcdefgh"[..]);
        stream.advance(3);
        crate::assert_with_log!(
            &stream[..] == b"defgh",
            "after advance(3)",
            b"defgh",
            &stream[..]
        );
        stream.advance(2);
        crate::assert_with_log!(
            &stream[..] == b"fgh",
            "after advance(2)",
            b"fgh",
            &stream[..]
        );
        stream.advance(3);
        crate::assert_with_log!(stream.is_empty(), "fully drained", true, stream.is_empty());
        crate::test_complete!("bytes_mut_advance_matches_split_to_remainder");
    }

    #[test]
    fn bytes_mut_clone_copies_only_active_view() {
        init_test("bytes_mut_clone_copies_only_active_view");
        const SUFFIX: &[u8] = b"tail";

        for prefix_len in [0, 1, 4096] {
            let mut source = BytesMut::with_capacity(prefix_len + SUFFIX.len());
            source.resize(prefix_len, b'p');
            source.put_slice(SUFFIX);
            source.advance(prefix_len);

            assert_eq!(source.start, prefix_len);
            assert_eq!(source.data.len(), prefix_len + SUFFIX.len());

            let mut cloned = source.clone();
            assert_eq!(&cloned[..], SUFFIX);
            assert_eq!(cloned.start, 0, "clone must normalize its active offset");
            assert_eq!(
                cloned.data.len(),
                source.len(),
                "clone backing must contain only the logical value"
            );
            assert_eq!(cloned.data.as_slice(), SUFFIX);

            cloned[0] = b'X';
            assert_eq!(&source[..], SUFFIX, "clone must remain mutably independent");
            assert_ne!(cloned[0], source[0]);
        }

        crate::test_complete!("bytes_mut_clone_copies_only_active_view");
    }

    #[test]
    #[should_panic(expected = "advance out of bounds")]
    fn bytes_mut_advance_past_len_panics() {
        let mut b = BytesMut::from(&b"abc"[..]);
        b.advance(4);
    }

    #[test]
    fn bytes_mut_freeze_and_into_vec_discard_consumed_prefix() {
        init_test("bytes_mut_freeze_and_into_vec_discard_consumed_prefix");
        let mut frozen_tail = BytesMut::from(&b"headerbody"[..]);
        let header = frozen_tail.split_to(6);
        crate::assert_with_log!(&header[..] == b"header", "header", b"header", &header[..]);
        let frozen = frozen_tail.freeze();
        crate::assert_with_log!(&frozen[..] == b"body", "frozen tail", b"body", &frozen[..]);

        let mut vec_tail = BytesMut::from(&b"prefixpayload"[..]);
        let prefix = vec_tail.split_to(6);
        crate::assert_with_log!(&prefix[..] == b"prefix", "prefix", b"prefix", &prefix[..]);
        let vec = vec_tail.into_vec();
        crate::assert_with_log!(
            vec.as_slice() == b"payload",
            "vec tail",
            b"payload",
            vec.as_slice()
        );
        crate::test_complete!("bytes_mut_freeze_and_into_vec_discard_consumed_prefix");
    }

    #[test]
    fn bytes_mut_split_parts_are_mutably_independent() {
        init_test("bytes_mut_split_parts_are_mutably_independent");

        let mut middle = BytesMut::from(&b"alpha|beta|gamma"[..]);
        let mut prefix = middle.split_to(6);
        let mut suffix = middle.split_off(5);

        prefix[0] = b'A';
        middle[0] = b'B';
        suffix[0] = b'G';

        crate::assert_with_log!(
            &prefix[..] == b"Alpha|",
            "prefix isolated",
            b"Alpha|",
            &prefix[..]
        );
        crate::assert_with_log!(
            &middle[..] == b"Beta|",
            "middle isolated",
            b"Beta|",
            &middle[..]
        );
        crate::assert_with_log!(
            &suffix[..] == b"Gamma",
            "suffix isolated",
            b"Gamma",
            &suffix[..]
        );
        crate::test_complete!("bytes_mut_split_parts_are_mutably_independent");
    }

    proptest! {
        #[test]
        fn bytes_mut_metamorphic_slice_matches_split_extraction(
            data in prop::collection::vec(any::<u8>(), 0..128),
            start in 0usize..128,
            end in 0usize..128,
        ) {
            let bytes = BytesMut::from(data.as_slice());
            let len = bytes.len();
            let start = start.min(len);
            let end = end.min(len);
            let (start, end) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };

            let direct = bytes.slice(start..end).to_vec();

            let mut split_view = bytes.clone();
            let _prefix = split_view.split_to(start);
            let middle = split_view.split_to(end - start);

            prop_assert_eq!(
                &middle[..],
                direct.as_slice(),
                "direct slicing and split-based extraction must expose identical contiguous bytes",
            );
            prop_assert_eq!(
                &middle[..],
                &data[start..end],
                "both extraction paths must match the original contiguous source slice",
            );
        }

        #[test]
        fn bytes_mut_metamorphic_split_recombine_preserves_payload(
            data in prop::collection::vec(any::<u8>(), 0..192),
            first_split in 0usize..192,
            middle_len in 0usize..192,
        ) {
            let original = BytesMut::from(data.as_slice());
            let len = original.len();
            let first_split = first_split.min(len);
            let middle_len = middle_len.min(len - first_split);

            let mut middle = original.clone();
            let prefix = middle.split_to(first_split);
            let suffix = middle.split_off(middle_len);

            prop_assert_eq!(prefix.len(), first_split);
            prop_assert_eq!(middle.len(), middle_len);
            prop_assert_eq!(suffix.len(), len - first_split - middle_len);

            prop_assert_eq!(&prefix[..], &data[..first_split]);
            prop_assert_eq!(
                &middle[..],
                &data[first_split..first_split + middle_len],
            );
            prop_assert_eq!(&suffix[..], &data[first_split + middle_len..]);

            let prefix_frozen = prefix.clone().freeze();
            let middle_frozen = middle.clone().freeze();
            let suffix_frozen = suffix.clone().freeze();

            let mut recombined = BytesMut::with_capacity(len);
            recombined.put_slice(&prefix_frozen);
            recombined.put_slice(&middle_frozen);
            recombined.put_slice(&suffix_frozen);

            prop_assert_eq!(
                &recombined[..],
                data.as_slice(),
                "split_to/split_off parts must recombine into the original byte order",
            );
            prop_assert_eq!(
                &recombined.freeze()[..],
                data.as_slice(),
                "freezing recombined split parts must preserve the original payload",
            );
        }
    }

    #[test]
    fn test_bytes_mut_resize() {
        init_test("test_bytes_mut_resize");
        let mut b = BytesMut::new();
        b.put_slice(b"hello");

        // Grow
        b.resize(10, b'!');
        let ok = &b[..] == b"hello!!!!!";
        crate::assert_with_log!(ok, "grown", b"hello!!!!!", &b[..]);

        // Shrink
        b.resize(5, 0);
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "shrunk", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_resize");
    }

    #[test]
    fn test_bytes_mut_truncate() {
        init_test("test_bytes_mut_truncate");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");
        b.truncate(5);
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "truncate", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_truncate");
    }

    #[test]
    fn test_bytes_mut_clear() {
        init_test("test_bytes_mut_clear");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");
        b.clear();
        let empty = b.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        crate::test_complete!("test_bytes_mut_clear");
    }

    #[test]
    fn test_bytes_mut_from_vec() {
        init_test("test_bytes_mut_from_vec");
        let v = vec![1u8, 2, 3];
        let b: BytesMut = v.into();
        let ok = b[..] == [1, 2, 3];
        crate::assert_with_log!(ok, "from vec", &[1, 2, 3], &b[..]);
        crate::test_complete!("test_bytes_mut_from_vec");
    }

    #[test]
    fn test_bytes_mut_from_slice() {
        init_test("test_bytes_mut_from_slice");
        let b: BytesMut = b"hello".as_slice().into();
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "from slice", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_from_slice");
    }

    #[test]
    fn test_bytes_mut_from_string() {
        init_test("test_bytes_mut_from_string");
        let s = String::from("hello");
        let b: BytesMut = s.into();
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "from string", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_from_string");
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_bytes_mut_split_off_panic() {
        init_test("test_bytes_mut_split_off_panic");
        let mut b = BytesMut::new();
        b.put_slice(b"hello");
        let _bad = b.split_off(100);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_bytes_mut_split_to_panic() {
        init_test("test_bytes_mut_split_to_panic");
        let mut b = BytesMut::new();
        b.put_slice(b"hello");
        let _bad = b.split_to(100);
    }

    // --- Audit tests (SapphireHill, 2026-02-15) ---

    #[test]
    fn set_len_zeros_new_bytes() {
        init_test("set_len_zeros_new_bytes");
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"abc");
        b.set_len(8);
        // Bytes beyond the original "abc" must be zero-filled.
        let ok = &b[..] == b"abc\0\0\0\0\0";
        crate::assert_with_log!(ok, "zero-filled", b"abc\0\0\0\0\0", &b[..]);
        crate::test_complete!("set_len_zeros_new_bytes");
    }

    #[test]
    fn set_len_overwrites_spare_capacity_writes() {
        init_test("set_len_overwrites_spare_capacity_writes");
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"abc");
        // Write 0xFF into spare capacity via the raw spare slice.
        let spare = b.spare_capacity_mut();
        spare[0].write(0xFF);
        spare[1].write(0xFF);
        // set_len uses resize(len, 0) which zeroes new positions.
        b.set_len(5);
        let ok = b[3] == 0 && b[4] == 0;
        crate::assert_with_log!(ok, "zeroed, not 0xFF", true, ok);
        crate::test_complete!("set_len_overwrites_spare_capacity_writes");
    }

    #[test]
    fn set_len_shrink_preserves_data() {
        init_test("set_len_shrink_preserves_data");
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"hello world");
        b.set_len(5);
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "shrunk", b"hello", &b[..]);
        crate::test_complete!("set_len_shrink_preserves_data");
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn set_len_panics_beyond_capacity() {
        init_test("set_len_panics_beyond_capacity");
        let mut b = BytesMut::with_capacity(4);
        b.set_len(5);
    }

    #[test]
    fn logical_append_capacity_is_distinct_from_direct_window() {
        init_test("logical_append_capacity_is_distinct_from_direct_window");
        let mut b = BytesMut::with_capacity(16);
        let remaining = b.remaining_mut();
        crate::assert_with_log!(
            remaining == usize::MAX,
            "logical remaining",
            usize::MAX,
            remaining
        );
        let direct_remaining = b.direct_remaining_mut();
        crate::assert_with_log!(
            direct_remaining == 0,
            "direct remaining",
            0,
            direct_remaining
        );
        let has_remaining = b.has_remaining_mut();
        crate::assert_with_log!(has_remaining, "has logical remaining", true, has_remaining);
        let chunk = b.chunk_mut();
        let ok = chunk.is_empty();
        crate::assert_with_log!(ok, "chunk_mut empty", true, ok);
        // advance_mut(0) must not panic.
        b.advance_mut(0);
        b.put_slice(b"abc");
        let remaining = b.remaining_mut();
        crate::assert_with_log!(
            remaining == usize::MAX - 3,
            "logical remaining after append",
            usize::MAX - 3,
            remaining
        );
        crate::test_complete!("logical_append_capacity_is_distinct_from_direct_window");
    }

    #[test]
    #[should_panic(expected = "unsupported")]
    fn advance_mut_nonzero_panics() {
        init_test("advance_mut_nonzero_panics");
        let mut b = BytesMut::with_capacity(16);
        b.advance_mut(1);
    }
