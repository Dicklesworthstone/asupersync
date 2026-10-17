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
    fn test_buf_slice_remaining() {
        init_test("test_buf_slice_remaining");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let remaining = buf.remaining();
        crate::assert_with_log!(remaining == 5, "remaining", 5, remaining);
        crate::test_complete!("test_buf_slice_remaining");
    }

    #[test]
    fn test_buf_slice_get_u8() {
        init_test("test_buf_slice_get_u8");
        let mut buf: &[u8] = &[1, 2, 3, 4, 5];
        let v = buf.get_u8();
        crate::assert_with_log!(v == 1, "get_u8", 1, v);
        let v = buf.get_u8();
        crate::assert_with_log!(v == 2, "get_u8", 2, v);
        let remaining = buf.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        crate::test_complete!("test_buf_slice_get_u8");
    }

    #[test]
    fn test_buf_get_u16() {
        init_test("test_buf_get_u16");
        let mut buf: &[u8] = &[0x12, 0x34];
        let v = buf.get_u16();
        crate::assert_with_log!(v == 0x1234, "get_u16", 0x1234, v);
        crate::test_complete!("test_buf_get_u16");
    }

    #[test]
    fn test_buf_get_u16_le() {
        init_test("test_buf_get_u16_le");
        let mut buf: &[u8] = &[0x34, 0x12];
        let v = buf.get_u16_le();
        crate::assert_with_log!(v == 0x1234, "get_u16_le", 0x1234, v);
        crate::test_complete!("test_buf_get_u16_le");
    }

    #[test]
    fn test_buf_get_u32() {
        init_test("test_buf_get_u32");
        let mut buf: &[u8] = &[0x12, 0x34, 0x56, 0x78];
        let v = buf.get_u32();
        crate::assert_with_log!(v == 0x1234_5678, "get_u32", 0x1234_5678, v);
        crate::test_complete!("test_buf_get_u32");
    }

    #[test]
    fn test_buf_get_u64() {
        init_test("test_buf_get_u64");
        let mut buf: &[u8] = &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let v = buf.get_u64();
        crate::assert_with_log!(
            v == 0x1234_5678_9ABC_DEF0,
            "get_u64",
            0x1234_5678_9ABC_DEF0u64,
            v
        );
        crate::test_complete!("test_buf_get_u64");
    }

    proptest! {
        #[test]
        fn buf_metamorphic_fragmented_numeric_reads_match_contiguous(
            bytes in any::<[u8; 8]>(),
            split_at in 0usize..9,
        ) {
            let split_at = split_at.min(bytes.len());

            let mut contiguous: &[u8] = &bytes;
            let mut fragmented = bytes[..split_at].chain(&bytes[split_at..]);
            prop_assert_eq!(fragmented.get_u16(), contiguous.get_u16());
            prop_assert_eq!(fragmented.remaining(), contiguous.remaining());

            let mut contiguous: &[u8] = &bytes;
            let mut fragmented = bytes[..split_at].chain(&bytes[split_at..]);
            prop_assert_eq!(fragmented.get_u16_le(), contiguous.get_u16_le());
            prop_assert_eq!(fragmented.remaining(), contiguous.remaining());

            let mut contiguous: &[u8] = &bytes;
            let mut fragmented = bytes[..split_at].chain(&bytes[split_at..]);
            prop_assert_eq!(fragmented.get_u32(), contiguous.get_u32());
            prop_assert_eq!(fragmented.remaining(), contiguous.remaining());

            let mut contiguous: &[u8] = &bytes;
            let mut fragmented = bytes[..split_at].chain(&bytes[split_at..]);
            prop_assert_eq!(fragmented.get_u32_le(), contiguous.get_u32_le());
            prop_assert_eq!(fragmented.remaining(), contiguous.remaining());

            let mut contiguous: &[u8] = &bytes;
            let mut fragmented = bytes[..split_at].chain(&bytes[split_at..]);
            prop_assert_eq!(fragmented.get_u64(), contiguous.get_u64());
            prop_assert_eq!(fragmented.remaining(), contiguous.remaining());

            let mut contiguous: &[u8] = &bytes;
            let mut fragmented = bytes[..split_at].chain(&bytes[split_at..]);
            prop_assert_eq!(fragmented.get_u64_le(), contiguous.get_u64_le());
            prop_assert_eq!(fragmented.remaining(), contiguous.remaining());
        }
    }

    #[test]
    fn buf_conformance_fragmented_extended_numeric_reads_match_contiguous() {
        init_test("buf_conformance_fragmented_extended_numeric_reads_match_contiguous");
        let bytes = [
            0x80, 0x01, 0x7f, 0x02, 0xaa, 0x55, 0x13, 0x37, 0xde, 0xad, 0xbe, 0xef, 0x42, 0x24,
            0x00, 0xff,
        ];
        macro_rules! assert_fragmented_eq {
            ($split_at:expr, $getter:ident, $label:literal) => {{
                let mut contiguous: &[u8] = &bytes;
                let mut fragmented = bytes[..$split_at].chain(&bytes[$split_at..]);
                let expected = contiguous.$getter();
                let actual = fragmented.$getter();
                crate::assert_with_log!(actual == expected, $label, expected, actual);
            }};
        }
        macro_rules! assert_fragmented_bits_eq {
            ($split_at:expr, $getter:ident, $label:literal) => {{
                let mut contiguous: &[u8] = &bytes;
                let mut fragmented = bytes[..$split_at].chain(&bytes[$split_at..]);
                let expected = contiguous.$getter().to_bits();
                let actual = fragmented.$getter().to_bits();
                crate::assert_with_log!(actual == expected, $label, expected, actual);
            }};
        }

        for split_at in 0..=bytes.len() {
            assert_fragmented_eq!(split_at, get_i16, "fragmented i16 matches contiguous");
            assert_fragmented_eq!(split_at, get_i16_le, "fragmented i16_le matches contiguous");
            assert_fragmented_eq!(split_at, get_i32, "fragmented i32 matches contiguous");
            assert_fragmented_eq!(split_at, get_i32_le, "fragmented i32_le matches contiguous");
            assert_fragmented_eq!(split_at, get_i64, "fragmented i64 matches contiguous");
            assert_fragmented_eq!(split_at, get_i64_le, "fragmented i64_le matches contiguous");
            assert_fragmented_eq!(split_at, get_u128, "fragmented u128 matches contiguous");
            assert_fragmented_eq!(
                split_at,
                get_i128_le,
                "fragmented i128_le matches contiguous"
            );
            assert_fragmented_bits_eq!(split_at, get_f32, "fragmented f32 bits match contiguous");
            assert_fragmented_bits_eq!(
                split_at,
                get_f64_le,
                "fragmented f64_le bits match contiguous"
            );
        }

        crate::test_complete!("buf_conformance_fragmented_extended_numeric_reads_match_contiguous");
    }

    #[test]
    fn test_buf_copy_to_slice() {
        init_test("test_buf_copy_to_slice");
        let mut buf: &[u8] = &[1, 2, 3, 4, 5];
        let mut dst = [0u8; 3];
        buf.copy_to_slice(&mut dst);
        let ok = dst == [1, 2, 3];
        crate::assert_with_log!(ok, "dst", [1, 2, 3], dst);
        let remaining = buf.remaining();
        crate::assert_with_log!(remaining == 2, "remaining", 2, remaining);
        crate::test_complete!("test_buf_copy_to_slice");
    }

    #[test]
    fn test_buf_get_f32() {
        init_test("test_buf_get_f32");
        let mut buf = Vec::new();
        let expected = std::f32::consts::PI;
        buf.extend_from_slice(&expected.to_be_bytes());
        let mut slice: &[u8] = &buf;
        let val = slice.get_f32();
        let ok = (val - expected).abs() < 0.0001;
        crate::assert_with_log!(ok, "f32", true, ok);
        crate::test_complete!("test_buf_get_f32");
    }

    #[test]
    fn test_buf_get_f64() {
        init_test("test_buf_get_f64");
        let mut buf = Vec::new();
        buf.extend_from_slice(&std::f64::consts::PI.to_be_bytes());
        let mut slice: &[u8] = &buf;
        let val = slice.get_f64();
        let ok = (val - std::f64::consts::PI).abs() < 1e-10;
        crate::assert_with_log!(ok, "f64", true, ok);
        crate::test_complete!("test_buf_get_f64");
    }

    #[test]
    #[should_panic(expected = "buffer underflow")]
    fn test_buf_underflow() {
        let mut buf: &[u8] = &[1];
        buf.get_u16();
    }

    #[test]
    fn test_buf_cursor() {
        init_test("test_buf_cursor");
        let data = vec![1u8, 2, 3, 4, 5];
        let mut cursor = std::io::Cursor::new(data);
        let remaining = cursor.remaining();
        crate::assert_with_log!(remaining == 5, "remaining", 5, remaining);
        let v = cursor.get_u8();
        crate::assert_with_log!(v == 1, "get_u8", 1, v);
        let remaining = cursor.remaining();
        crate::assert_with_log!(remaining == 4, "remaining", 4, remaining);
        crate::test_complete!("test_buf_cursor");
    }

    #[test]
    fn test_cursor_logical_start_clamps_past_end_positions() {
        init_test("test_cursor_logical_start_clamps_past_end_positions");
        for position in [3, 1_u64 << 32, (1_u64 << 32) + 1, u64::MAX] {
            let start = cursor_logical_start(position, 3);
            crate::assert_with_log!(start == 3, "logical start", 3, start);
        }
        crate::test_complete!("test_cursor_logical_start_clamps_past_end_positions");
    }

    #[test]
    fn test_buf_cursor_wide_positions_do_not_replay_data() {
        fn assert_fail_closed<T>(cursor: &mut std::io::Cursor<T>, position: u64)
        where
            std::io::Cursor<T>: Buf,
        {
            cursor.set_position(position);
            let initial_remaining = cursor.remaining();
            assert_eq!(initial_remaining, 0, "position {position}");
            assert!(cursor.chunk().is_empty(), "position {position}");
            assert!(!cursor.has_remaining(), "position {position}");
            cursor.advance(0);
            assert_eq!(cursor.position(), position);
        }

        init_test("test_buf_cursor_wide_positions_do_not_replay_data");
        let data = [1u8, 2, 3];
        for position in [1_u64 << 32, (1_u64 << 32) + 1, u64::MAX] {
            let mut slice_cursor = std::io::Cursor::new(data.as_slice());
            assert_fail_closed(&mut slice_cursor, position);

            let mut vec_cursor = std::io::Cursor::new(data.to_vec());
            assert_fail_closed(&mut vec_cursor, position);
        }
        crate::test_complete!("test_buf_cursor_wide_positions_do_not_replay_data");
    }

    #[test]
    fn test_buf_cursor_position_past_end_is_empty_and_stable() {
        init_test("test_buf_cursor_position_past_end_is_empty_and_stable");
        let data: &[u8] = &[1, 2, 3];
        let mut cursor = std::io::Cursor::new(data);
        cursor.set_position(9);

        let remaining = cursor.remaining();
        crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
        let chunk_empty = cursor.chunk().is_empty();
        crate::assert_with_log!(chunk_empty, "chunk empty", true, chunk_empty);
        let has_remaining = cursor.has_remaining();
        crate::assert_with_log!(!has_remaining, "has remaining", false, has_remaining);

        cursor.advance(0);
        let position = cursor.position();
        crate::assert_with_log!(position == 9, "position", 9, position);
        crate::test_complete!("test_buf_cursor_position_past_end_is_empty_and_stable");
    }

    #[test]
    fn test_roundtrip_all_integers() {
        init_test("test_roundtrip_all_integers");
        // Write all types
        let mut write_buf = Vec::new();
        write_buf.extend_from_slice(&0x12u8.to_be_bytes());
        write_buf.extend_from_slice(&(-5i8).to_be_bytes());
        write_buf.extend_from_slice(&0x1234u16.to_be_bytes());
        write_buf.extend_from_slice(&0x5678u16.to_le_bytes());
        write_buf.extend_from_slice(&(-1000i16).to_be_bytes());
        write_buf.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        write_buf.extend_from_slice(&0x9ABC_DEF0u32.to_le_bytes());
        write_buf.extend_from_slice(&(-100_000i32).to_be_bytes());
        write_buf.extend_from_slice(&0x1234_5678_9ABC_DEF0u64.to_be_bytes());
        write_buf.extend_from_slice(&0xFEDC_BA98_7654_3210u64.to_le_bytes());

        // Read all types
        let mut read: &[u8] = &write_buf;
        let v = read.get_u8();
        crate::assert_with_log!(v == 0x12, "u8", 0x12, v);
        let v = read.get_i8();
        crate::assert_with_log!(v == -5, "i8", -5, v);
        let v = read.get_u16();
        crate::assert_with_log!(v == 0x1234, "u16", 0x1234, v);
        let v = read.get_u16_le();
        crate::assert_with_log!(v == 0x5678, "u16_le", 0x5678, v);
        let v = read.get_i16();
        crate::assert_with_log!(v == -1000, "i16", -1000, v);
        let v = read.get_u32();
        crate::assert_with_log!(v == 0x1234_5678, "u32", 0x1234_5678, v);
        let v = read.get_u32_le();
        crate::assert_with_log!(v == 0x9ABC_DEF0, "u32_le", 0x9ABC_DEF0u32, v);
        let v = read.get_i32();
        crate::assert_with_log!(v == -100_000, "i32", -100_000, v);
        let v = read.get_u64();
        crate::assert_with_log!(
            v == 0x1234_5678_9ABC_DEF0,
            "u64",
            0x1234_5678_9ABC_DEF0u64,
            v
        );
        let v = read.get_u64_le();
        crate::assert_with_log!(
            v == 0xFEDC_BA98_7654_3210,
            "u64_le",
            0xFEDC_BA98_7654_3210u64,
            v
        );
        crate::test_complete!("test_roundtrip_all_integers");
    }

    struct EmptyChunkBuf(usize);

    impl Buf for EmptyChunkBuf {
        fn remaining(&self) -> usize {
            self.0
        }
        fn chunk(&self) -> &[u8] {
            &[]
        }
        fn advance(&mut self, cnt: usize) {
            self.0 -= cnt;
        }
    }

    /// Runs `body` on a helper thread and re-raises its panic here. Without
    /// the empty-chunk guard the copy loops on `advance(0)` forever, so a
    /// regression must fail the test at the deadline instead of hanging it.
    fn panic_within_deadline(body: impl FnOnce() + Send + 'static) {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
            let _ = sender.send(result);
        });
        match receiver.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(payload)) => std::panic::resume_unwind(payload),
            Err(_) => panic!("the copy spun on an empty chunk instead of panicking"),
        }
    }

    #[test]
    #[should_panic(expected = "chunk returned empty with remaining() > 0")]
    fn test_copy_to_slice_panics_on_empty_chunk() {
        panic_within_deadline(|| {
            let mut buf = EmptyChunkBuf(10);
            let mut dst = [0u8; 5];
            buf.copy_to_slice(&mut dst);
        });
    }

    #[test]
    #[should_panic(expected = "chunk returned empty with remaining() > 0")]
    fn test_copy_to_bytes_panics_on_empty_chunk() {
        panic_within_deadline(|| {
            let mut buf = EmptyChunkBuf(10);
            let _ = buf.copy_to_bytes(5);
        });
    }
