    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::Buf;
    use super::*;
    use proptest::prelude::*;

    struct FragmentedBufMut {
        bytes: Vec<u8>,
        written: usize,
        max_chunk: usize,
    }

    impl FragmentedBufMut {
        fn new(capacity: usize, max_chunk: usize) -> Self {
            Self {
                bytes: vec![0; capacity],
                written: 0,
                max_chunk: max_chunk.max(1),
            }
        }

        fn written(&self) -> &[u8] {
            &self.bytes[..self.written]
        }
    }

    impl BufMut for FragmentedBufMut {
        fn remaining_mut(&self) -> usize {
            self.bytes.len() - self.written
        }

        fn chunk_mut(&mut self) -> &mut [u8] {
            let start = self.written;
            let end = start + self.remaining_mut().min(self.max_chunk);
            &mut self.bytes[start..end]
        }

        fn advance_mut(&mut self, cnt: usize) {
            assert!(
                cnt <= self.remaining_mut(),
                "advance_mut out of bounds: cnt={cnt}, remaining={}",
                self.remaining_mut()
            );
            self.written += cnt;
        }
    }

    fn write_numeric_sequence(buf: &mut impl BufMut, values: &[u64]) {
        for &value in values {
            let value16 = value as u16;
            let value32 = value as u32;
            buf.put_u16(value16);
            buf.put_u16_le(value16);
            buf.put_u32(value32);
            buf.put_u32_le(value32);
            buf.put_u64(value);
            buf.put_u64_le(value);
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_buf_mut_vec_put_u8() {
        init_test("test_buf_mut_vec_put_u8");
        let mut buf = Vec::new();
        buf.put_u8(42);
        buf.put_u8(43);
        let ok = buf == vec![42, 43];
        crate::assert_with_log!(ok, "buf", vec![42, 43], buf);
        crate::test_complete!("test_buf_mut_vec_put_u8");
    }

    #[test]
    fn test_buf_mut_vec_put_u16() {
        init_test("test_buf_mut_vec_put_u16");
        let mut buf = Vec::new();
        buf.put_u16(0x1234);
        let ok = buf == vec![0x12, 0x34];
        crate::assert_with_log!(ok, "buf", vec![0x12, 0x34], buf);
        crate::test_complete!("test_buf_mut_vec_put_u16");
    }

    #[test]
    fn test_buf_mut_vec_put_u16_le() {
        init_test("test_buf_mut_vec_put_u16_le");
        let mut buf = Vec::new();
        buf.put_u16_le(0x1234);
        let ok = buf == vec![0x34, 0x12];
        crate::assert_with_log!(ok, "buf", vec![0x34, 0x12], buf);
        crate::test_complete!("test_buf_mut_vec_put_u16_le");
    }

    #[test]
    fn test_buf_mut_vec_put_u32() {
        init_test("test_buf_mut_vec_put_u32");
        let mut buf = Vec::new();
        buf.put_u32(0x1234_5678);
        let ok = buf == vec![0x12, 0x34, 0x56, 0x78];
        crate::assert_with_log!(ok, "buf", vec![0x12, 0x34, 0x56, 0x78], buf);
        crate::test_complete!("test_buf_mut_vec_put_u32");
    }

    #[test]
    fn test_buf_mut_vec_put_slice() {
        init_test("test_buf_mut_vec_put_slice");
        let mut buf = Vec::new();
        buf.put_slice(b"hello");
        buf.put_slice(b" world");
        let ok = buf == b"hello world";
        crate::assert_with_log!(ok, "buf", b"hello world", buf);
        crate::test_complete!("test_buf_mut_vec_put_slice");
    }

    #[test]
    fn test_buf_mut_vec_separates_logical_and_direct_capacity() {
        init_test("test_buf_mut_vec_separates_logical_and_direct_capacity");
        let mut buf = Vec::new();

        let remaining = buf.remaining_mut();
        crate::assert_with_log!(
            remaining == usize::MAX,
            "logical remaining",
            usize::MAX,
            remaining
        );
        let direct_remaining = buf.direct_remaining_mut();
        crate::assert_with_log!(
            direct_remaining == 0,
            "direct remaining",
            0,
            direct_remaining
        );
        let chunk_empty = buf.chunk_mut().is_empty();
        crate::assert_with_log!(chunk_empty, "chunk empty", true, chunk_empty);
        buf.advance_mut(0);
        buf.put_slice(b"abc");
        let remaining = buf.remaining_mut();
        crate::assert_with_log!(
            remaining == usize::MAX - 3,
            "logical remaining after append",
            usize::MAX - 3,
            remaining
        );

        crate::test_complete!("test_buf_mut_vec_separates_logical_and_direct_capacity");
    }

    #[test]
    fn test_buf_mut_vec_put_f32() {
        init_test("test_buf_mut_vec_put_f32");
        let mut buf = Vec::new();
        let expected = std::f32::consts::PI;
        buf.put_f32(expected);

        // Verify by reading back
        let mut read: &[u8] = &buf;
        let val = read.get_f32();
        let ok = (val - expected).abs() < 0.0001;
        crate::assert_with_log!(ok, "f32", true, ok);
        crate::test_complete!("test_buf_mut_vec_put_f32");
    }

    #[test]
    fn test_buf_mut_vec_put_f64() {
        init_test("test_buf_mut_vec_put_f64");
        let mut buf = Vec::new();
        buf.put_f64(std::f64::consts::PI);

        // Verify by reading back
        let mut read: &[u8] = &buf;
        let val = read.get_f64();
        let ok = (val - std::f64::consts::PI).abs() < 1e-10;
        crate::assert_with_log!(ok, "f64", true, ok);
        crate::test_complete!("test_buf_mut_vec_put_f64");
    }

    #[test]
    fn test_buf_mut_slice() {
        init_test("test_buf_mut_slice");
        let mut data = [0u8; 10];
        let mut buf: &mut [u8] = &mut data;

        buf.put_u16(0x1234);
        buf.put_u16(0x5678);

        let ok = data[0..4] == [0x12, 0x34, 0x56, 0x78];
        crate::assert_with_log!(ok, "data", [0x12, 0x34, 0x56, 0x78], data[0..4].to_vec());
        crate::test_complete!("test_buf_mut_slice");
    }

    #[test]
    fn test_buf_mut_slice_exact_fill_exhausts_writable_window() {
        init_test("test_buf_mut_slice_exact_fill_exhausts_writable_window");
        let mut data = [0u8; 4];
        {
            let mut buf: &mut [u8] = &mut data;
            let remaining = buf.remaining_mut();
            crate::assert_with_log!(remaining == 4, "remaining", 4, remaining);

            buf.put_slice(&[1, 2, 3, 4]);

            let remaining = buf.remaining_mut();
            crate::assert_with_log!(remaining == 0, "remaining", 0, remaining);
            let chunk_empty = buf.chunk_mut().is_empty();
            crate::assert_with_log!(chunk_empty, "chunk empty", true, chunk_empty);
            let has_remaining = buf.has_remaining_mut();
            crate::assert_with_log!(!has_remaining, "has remaining", false, has_remaining);

            buf.advance_mut(0);
            let remaining = buf.remaining_mut();
            crate::assert_with_log!(remaining == 0, "remaining after noop", 0, remaining);
        }

        crate::assert_with_log!(data == [1, 2, 3, 4], "data", [1, 2, 3, 4], data);
        crate::test_complete!("test_buf_mut_slice_exact_fill_exhausts_writable_window");
    }

    #[test]
    fn test_roundtrip_all_types() {
        init_test("test_roundtrip_all_types");
        let mut buf = Vec::new();
        let expected_f32 = std::f32::consts::PI;

        buf.put_u8(0x12);
        buf.put_i8(-5);
        buf.put_u16(0x1234);
        buf.put_u16_le(0x5678);
        buf.put_i16(-1000);
        buf.put_u32(0x1234_5678);
        buf.put_u32_le(0x9ABC_DEF0);
        buf.put_i32(-100_000);
        buf.put_u64(0x1234_5678_9ABC_DEF0);
        buf.put_u64_le(0xFEDC_BA98_7654_3210);
        buf.put_f32(expected_f32);
        let expected = std::f64::consts::E;
        buf.put_f64(expected);

        let mut read: &[u8] = &buf;

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
        let ok = (read.get_f32() - expected_f32).abs() < 0.0001;
        crate::assert_with_log!(ok, "f32", true, ok);
        let ok = (read.get_f64() - expected).abs() < 1e-9;
        crate::assert_with_log!(ok, "f64", true, ok);
        crate::test_complete!("test_roundtrip_all_types");
    }

    proptest! {
        #[test]
        fn buf_mut_metamorphic_fragmented_numeric_writes_match_vec(
            values in proptest::collection::vec(any::<u64>(), 0..64),
            max_chunk in 1usize..=8,
        ) {
            let bytes_per_value = 2 + 2 + 4 + 4 + 8 + 8;
            let capacity = values.len() * bytes_per_value;

            let mut vec_writer = Vec::new();
            write_numeric_sequence(&mut vec_writer, &values);

            let mut fragmented = FragmentedBufMut::new(capacity, max_chunk);
            write_numeric_sequence(&mut fragmented, &values);

            prop_assert_eq!(
                fragmented.written(),
                vec_writer.as_slice(),
                "fragmented BufMut with max_chunk={} must match Vec output",
                max_chunk
            );
            prop_assert_eq!(fragmented.remaining_mut(), 0);
        }
    }
