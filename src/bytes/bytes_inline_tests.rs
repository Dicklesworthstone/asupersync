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
    fn test_bytes_new() {
        init_test("test_bytes_new");
        let b = Bytes::new();
        let empty = b.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        let len = b.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("test_bytes_new");
    }

    #[test]
    fn test_bytes_from_static() {
        init_test("test_bytes_from_static");
        let b = Bytes::from_static(b"hello world");
        let len = b.len();
        crate::assert_with_log!(len == 11, "len", 11, len);
        let ok = &b[..] == b"hello world";
        crate::assert_with_log!(ok, "contents", b"hello world", &b[..]);
        crate::test_complete!("test_bytes_from_static");
    }

    #[test]
    fn test_bytes_copy_from_slice() {
        init_test("test_bytes_copy_from_slice");
        let data = vec![1u8, 2, 3, 4, 5];
        let b = Bytes::copy_from_slice(&data);
        let len = b.len();
        crate::assert_with_log!(len == 5, "len", 5, len);
        let ok = b[..] == data[..];
        crate::assert_with_log!(ok, "contents", &data[..], &b[..]);
        crate::test_complete!("test_bytes_copy_from_slice");
    }

    #[test]
    fn test_bytes_clone_is_cheap() {
        init_test("test_bytes_clone_is_cheap");
        let b1 = Bytes::copy_from_slice(&vec![0u8; 1_000_000]);
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _b2 = b1.clone();
        }
        let elapsed = start.elapsed();
        // Should be very fast (reference counting)
        let fast = elapsed.as_millis() < 50;
        crate::assert_with_log!(fast, "clone fast", true, fast);
        crate::test_complete!("test_bytes_clone_is_cheap");
    }

    #[test]
    fn test_bytes_slice() {
        init_test("test_bytes_slice");
        let b = Bytes::from_static(b"hello world");

        let hello = b.slice(0..5);
        let ok = &hello[..] == b"hello";
        crate::assert_with_log!(ok, "hello", b"hello", &hello[..]);

        let world = b.slice(6..);
        let ok = &world[..] == b"world";
        crate::assert_with_log!(ok, "world", b"world", &world[..]);

        let middle = b.slice(3..8);
        let ok = &middle[..] == b"lo wo";
        crate::assert_with_log!(ok, "middle", b"lo wo", &middle[..]);
        crate::test_complete!("test_bytes_slice");
    }

    #[test]
    fn test_bytes_split_off() {
        init_test("test_bytes_split_off");
        let mut b = Bytes::from_static(b"hello world");
        let world = b.split_off(6);

        let ok = &b[..] == b"hello ";
        crate::assert_with_log!(ok, "left", b"hello ", &b[..]);
        let ok = &world[..] == b"world";
        crate::assert_with_log!(ok, "world", b"world", &world[..]);
        crate::test_complete!("test_bytes_split_off");
    }

    #[test]
    fn test_bytes_split_to() {
        init_test("test_bytes_split_to");
        let mut b = Bytes::from_static(b"hello world");
        let hello = b.split_to(6);

        let ok = &hello[..] == b"hello ";
        crate::assert_with_log!(ok, "left", b"hello ", &hello[..]);
        let ok = &b[..] == b"world";
        crate::assert_with_log!(ok, "world", b"world", &b[..]);
        crate::test_complete!("test_bytes_split_to");
    }

    #[test]
    fn test_bytes_truncate() {
        init_test("test_bytes_truncate");
        let mut b = Bytes::from_static(b"hello world");
        b.truncate(5);
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "truncate", b"hello", &b[..]);

        // Truncate to larger has no effect
        b.truncate(100);
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "truncate unchanged", b"hello", &b[..]);
        crate::test_complete!("test_bytes_truncate");
    }

    #[test]
    fn test_bytes_clear() {
        init_test("test_bytes_clear");
        let mut b = Bytes::from_static(b"hello world");
        b.clear();
        let empty = b.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        crate::test_complete!("test_bytes_clear");
    }

    #[test]
    fn test_bytes_from_vec() {
        init_test("test_bytes_from_vec");
        let v = vec![1u8, 2, 3];
        let b: Bytes = v.into();
        let ok = b[..] == [1, 2, 3];
        crate::assert_with_log!(ok, "from vec", &[1, 2, 3], &b[..]);
        crate::test_complete!("test_bytes_from_vec");
    }

    #[test]
    fn test_bytes_from_string() {
        init_test("test_bytes_from_string");
        let s = String::from("hello");
        let b: Bytes = s.into();
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "from string", b"hello", &b[..]);
        crate::test_complete!("test_bytes_from_string");
    }

    #[test]
    #[should_panic(expected = "slice bounds out of range")]
    fn test_bytes_slice_panic() {
        init_test("test_bytes_slice_panic");
        let b = Bytes::from_static(b"hello");
        let _bad = b.slice(0..100);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_bytes_split_off_panic() {
        init_test("test_bytes_split_off_panic");
        let mut b = Bytes::from_static(b"hello");
        let _bad = b.split_off(100);
    }

    // =========================================================================
    // Wave 32: Data-type trait coverage
    // =========================================================================

    #[test]
    fn bytes_debug() {
        let b = Bytes::from_static(b"hi");
        let dbg = format!("{b:?}");
        assert!(dbg.contains("Bytes"));
        assert!(dbg.contains("len"));
    }

    #[test]
    fn bytes_default() {
        let b = Bytes::default();
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn bytes_hash() {
        use std::collections::HashSet;
        let a = Bytes::from_static(b"hello");
        let b = Bytes::copy_from_slice(b"hello");
        let c = Bytes::from_static(b"world");
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(c);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn bytes_partial_eq_vec() {
        let b = Bytes::from_static(b"hello");
        let v = b"hello".to_vec();
        assert!(b == v);
    }

    #[test]
    fn bytes_as_ref() {
        let b = Bytes::from_static(b"hello");
        let r: &[u8] = b.as_ref();
        assert_eq!(r, b"hello");
    }

    #[test]
    fn bytes_from_static_slice() {
        let b: Bytes = (b"test" as &'static [u8]).into();
        assert_eq!(&b[..], b"test");
    }

    #[test]
    fn bytes_from_str() {
        let b: Bytes = "hello".into();
        assert_eq!(&b[..], b"hello");
    }

    #[test]
    fn bytes_cursor_debug_clone() {
        let b = Bytes::from_static(b"hello");
        let cursor = BytesCursor::new(b);
        let dbg = format!("{cursor:?}");
        assert!(dbg.contains("BytesCursor"));
        let cloned = cursor;
        assert_eq!(cloned.position(), 0);
    }

    #[test]
    fn bytes_cursor_position() {
        let b = Bytes::from_static(b"hello");
        let mut cursor = BytesCursor::new(b);
        assert_eq!(cursor.position(), 0);
        cursor.set_position(3);
        assert_eq!(cursor.position(), 3);
    }

    #[test]
    fn bytes_cursor_get_ref_into_inner() {
        let b = Bytes::from_static(b"hello");
        let cursor = BytesCursor::new(b.clone());
        assert_eq!(cursor.get_ref(), &b);
        let inner = cursor.into_inner();
        assert_eq!(&inner[..], b"hello");
    }

    struct DefaultCopyCursor(BytesCursor);

    impl Buf for DefaultCopyCursor {
        fn remaining(&self) -> usize {
            self.0.remaining()
        }

        fn chunk(&self) -> &[u8] {
            self.0.chunk()
        }

        fn advance(&mut self, cnt: usize) {
            self.0.advance(cnt);
        }
    }

    #[test]
    fn bytes_cursor_zero_copy_empty_past_end_matches_default() {
        let cases = [
            ("static", Bytes::from_static(b"abc")),
            ("shared", Bytes::copy_from_slice(b"abc")),
            ("empty", Bytes::new()),
        ];

        for (backing, bytes) in cases {
            let end = bytes.len();
            for position in [end, end.saturating_add(1), usize::MAX] {
                let mut optimized = BytesCursor::new(bytes.clone());
                optimized.set_position(position);
                let mut default = DefaultCopyCursor(BytesCursor::new(bytes.clone()));
                default.0.set_position(position);

                let expected = default.copy_to_bytes(0);
                let actual = optimized.copy_to_bytes(0);

                assert_eq!(actual, expected, "backing={backing}, position={position}");
                assert!(actual.is_empty(), "backing={backing}, position={position}");
                assert_eq!(
                    optimized.position(),
                    position,
                    "backing={backing}, position={position}"
                );
                assert_eq!(
                    default.0.position(),
                    position,
                    "default backing={backing}, position={position}"
                );
                assert_eq!(optimized.remaining(), 0);
                assert!(optimized.chunk().is_empty());
            }
        }
    }

    #[test]
    fn bytes_cursor_zero_copy_positive_behavior_is_unchanged() {
        let mut cursor = Bytes::copy_from_slice(b"abcd").reader();
        cursor.set_position(1);
        assert_eq!(&cursor.copy_to_bytes(2)[..], b"bc");
        assert_eq!(cursor.position(), 3);

        cursor.set_position(usize::MAX);
        let underflow =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cursor.copy_to_bytes(1)));
        assert!(underflow.is_err());
        assert_eq!(cursor.position(), usize::MAX);
    }

    #[test]
    fn bytes_cursor_buf_trait() {
        let b = Bytes::from_static(b"hello");
        let mut cursor = b.reader();
        assert_eq!(cursor.remaining(), 5);
        assert_eq!(cursor.chunk(), b"hello");
        cursor.advance(3);
        assert_eq!(cursor.remaining(), 2);
        assert_eq!(cursor.chunk(), b"lo");
    }

    #[test]
    fn test_bytes_equality() {
        init_test("test_bytes_equality");
        let b1 = Bytes::from_static(b"hello");
        let b2 = Bytes::copy_from_slice(b"hello");
        let ok = b1 == b2;
        crate::assert_with_log!(ok, "b1 == b2", b2, b1);
        let ok = b1 == b"hello"[..];
        crate::assert_with_log!(ok, "b1 == slice", b"hello".as_slice(), b1);
        let ok = b"hello"[..] == b1;
        crate::assert_with_log!(ok, "slice == b1", b1, b"hello".as_slice());
        crate::test_complete!("test_bytes_equality");
    }

    fn shared_arc_ptr(bytes: &Bytes) -> *const Vec<u8> {
        match &bytes.data {
            BytesInner::Shared(arc) => Arc::as_ptr(arc),
            _ => panic!("expected shared bytes backing"),
        }
    }

    #[test]
    fn bytes_conformance_clone_preserves_shared_backing_and_full_view() {
        let original = Bytes::copy_from_slice(b"conformance");
        let clone = original.clone();

        assert!(std::ptr::eq(
            shared_arc_ptr(&original),
            shared_arc_ptr(&clone)
        ));
        assert_eq!(original.start, 0);
        assert_eq!(clone.start, 0);
        assert_eq!(original.len, b"conformance".len());
        assert_eq!(clone.len, b"conformance".len());
        assert_eq!(&original[..], b"conformance");
        assert_eq!(&clone[..], b"conformance");
    }

    #[test]
    fn bytes_conformance_slice_preserves_backing_with_adjusted_offsets() {
        let original = Bytes::copy_from_slice(b"grpc-frame");
        let slice = original.slice(5..10);

        assert!(std::ptr::eq(
            shared_arc_ptr(&original),
            shared_arc_ptr(&slice)
        ));
        assert_eq!(original.start, 0);
        assert_eq!(slice.start, 5);
        assert_eq!(original.len, b"grpc-frame".len());
        assert_eq!(slice.len, 5);
        assert_eq!(&slice[..], b"frame");
        assert_eq!(&original[..], b"grpc-frame");
    }

    #[test]
    fn bytes_conformance_split_to_keeps_prefix_and_suffix_on_same_backing() {
        let mut working = Bytes::copy_from_slice(b"wire-format");
        let witness = working.clone();
        let prefix = working.split_to(5);

        assert!(std::ptr::eq(
            shared_arc_ptr(&witness),
            shared_arc_ptr(&prefix)
        ));
        assert!(std::ptr::eq(
            shared_arc_ptr(&witness),
            shared_arc_ptr(&working)
        ));
        assert_eq!(prefix.start, 0);
        assert_eq!(prefix.len, 5);
        assert_eq!(working.start, 5);
        assert_eq!(working.len, b"wire-format".len() - 5);
        assert_eq!(&prefix[..], b"wire-");
        assert_eq!(&working[..], b"format");
        assert_eq!(&witness[..], b"wire-format");
    }

    #[test]
    fn bytes_conformance_split_off_keeps_tail_view_on_same_backing() {
        let mut working = Bytes::copy_from_slice(b"task-region");
        let witness = working.clone();
        let tail = working.split_off(5);

        assert!(std::ptr::eq(
            shared_arc_ptr(&witness),
            shared_arc_ptr(&tail)
        ));
        assert!(std::ptr::eq(
            shared_arc_ptr(&witness),
            shared_arc_ptr(&working)
        ));
        assert_eq!(working.start, 0);
        assert_eq!(working.len, 5);
        assert_eq!(tail.start, 5);
        assert_eq!(tail.len, b"task-region".len() - 5);
        assert_eq!(&working[..], b"task-");
        assert_eq!(&tail[..], b"region");
        assert_eq!(&witness[..], b"task-region");
    }

    proptest! {
        #[test]
        fn metamorphic_slice_matches_split_extraction(
            data in prop::collection::vec(any::<u8>(), 0..128),
            start in 0usize..128,
            end in 0usize..128,
        ) {
            let bytes = Bytes::copy_from_slice(&data);
            let len = bytes.len();
            let start = start.min(len);
            let end = end.min(len);
            let (start, end) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };

            let direct = bytes.slice(start..end);

            let mut split_view = bytes.clone();
            let _prefix = split_view.split_to(start);
            let middle = split_view.split_to(end - start);

            prop_assert_eq!(
                &direct[..],
                &middle[..],
                "direct slicing and split-based extraction must expose identical contiguous bytes",
            );
            prop_assert_eq!(
                &direct[..],
                &data[start..end],
                "both extraction paths must match the original contiguous source slice",
            );
        }

        #[test]
        fn metamorphic_split_recombine_preserves_payload(
            data in prop::collection::vec(any::<u8>(), 0..192),
            first_split in 0usize..192,
            middle_len in 0usize..192,
        ) {
            let bytes = Bytes::copy_from_slice(&data);
            let witness = bytes.clone();
            let len = bytes.len();
            let first_split = first_split.min(len);
            let middle_len = middle_len.min(len - first_split);

            let mut middle = bytes.clone();
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
            prop_assert_eq!(&witness[..], data.as_slice());

            let mut recombined = Vec::with_capacity(len);
            recombined.extend_from_slice(&prefix);
            recombined.extend_from_slice(&middle);
            recombined.extend_from_slice(&suffix);

            prop_assert_eq!(
                recombined.as_slice(),
                data.as_slice(),
                "split_to/split_off views must recombine into the original byte order",
            );
        }
    }

    #[test]
    fn bytes_conformance_clone_shares_data() {
        let data = b"hello world";
        let original = Bytes::copy_from_slice(data);
        let clone1 = original.clone();
        let clone2 = original.clone();

        assert_eq!(&original[..], data);
        assert_eq!(&clone1[..], data);
        assert_eq!(&clone2[..], data);

        // Verify pointer equality of the underlying slice to confirm sharing
        assert_eq!(
            shared_arc_ptr(&original),
            shared_arc_ptr(&clone1),
            "clones must share the same backing allocation"
        );
    }

    #[test]
    fn bytes_conformance_truncate_and_clear() {
        let mut b = Bytes::copy_from_slice(b"hello world");

        b.truncate(5);
        assert_eq!(&b[..], b"hello");

        b.truncate(10); // no-op since len is already 5
        assert_eq!(&b[..], b"hello");

        b.clear();
        assert_eq!(&b[..], b"");
        assert!(b.is_empty());
    }

    #[test]
    fn bytes_conformance_nested_slicing() {
        let mut b = Bytes::copy_from_slice(b"the quick brown fox jumps over the lazy dog");

        // "quick brown fox jumps over the lazy dog"
        let mut part1 = b.split_off(4);
        assert_eq!(&b[..], b"the ");

        // "quick brown fox"
        let part2 = part1.split_to(15);
        assert_eq!(&part2[..], b"quick brown fox");

        // "brown"
        let brown = part2.slice(6..11);
        assert_eq!(&brown[..], b"brown");

        // "fox jumps over"
        let mut fox = part1.slice(0..15);
        assert_eq!(&fox[..], b" jumps over the");

        // "over"
        let over = fox.split_off(7);
        assert_eq!(&fox[..], b" jumps ");
        assert_eq!(&over[..], b"over the");

        // Verify all point to the original allocation
        assert_eq!(shared_arc_ptr(&b), shared_arc_ptr(&part2));
        assert_eq!(shared_arc_ptr(&b), shared_arc_ptr(&brown));
    }

    #[test]
    #[should_panic(expected = "slice bounds out of range")]
    fn bytes_conformance_slice_out_of_bounds() {
        let b = Bytes::copy_from_slice(b"hello");
        let _ = b.slice(0..10);
    }

    #[test]
    #[should_panic(expected = "split_to out of bounds")]
    fn bytes_conformance_split_to_out_of_bounds() {
        let mut b = Bytes::copy_from_slice(b"hello");
        let _ = b.split_to(10);
    }

    #[test]
    #[should_panic(expected = "split_off out of bounds")]
    fn bytes_conformance_split_off_out_of_bounds() {
        let mut b = Bytes::copy_from_slice(b"hello");
        let _ = b.split_off(10);
    }
