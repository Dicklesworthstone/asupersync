    use super::*;

    #[test]
    fn test_varint_encoding_lengths() {
        let cases = [
            (0, 1),
            (63, 1),
            (64, 2),
            (16383, 2),
            (16384, 4),
            (1073741823, 4),
            (1073741824, 8),
            (VARINT_MAX, 8),
        ];

        for (value, expected_len) in cases {
            let varint = VarInt::new(value).expect("test value should be valid");
            assert_eq!(varint.encoded_len(), expected_len, "value={value}");
        }
    }

    #[test]
    fn test_varint_roundtrip() {
        let values = [
            0, 1, 63, 64, 127, 128, 16383, 16384, 65535, 65536, 1073741823, 1073741824, VARINT_MAX,
        ];

        for &value in &values {
            let mut buf = BytesMut::new();
            let varint = VarInt::new(value).expect("test value should be valid");
            varint.encode(&mut buf).expect("encoding should succeed");

            let decoded = VarInt::decode(&mut buf)
                .expect("decoding should succeed")
                .expect("should have decoded a varint");
            assert_eq!(decoded.value(), value, "value={value}");
        }
    }

    #[test]
    fn test_varint_partial_decode() {
        let varint = VarInt::new(16384).expect("test value should be valid"); // 4-byte encoding
        let mut buf = BytesMut::new();
        varint.encode(&mut buf).expect("encoding should succeed");

        // Try decoding with partial data
        let mut partial = buf.split_to(2); // Only first 2 bytes
        assert!(
            VarInt::decode(&mut partial)
                .expect("partial decode should not error")
                .is_none()
        );

        // Complete with remaining bytes
        partial.put_slice(&buf);
        let decoded = VarInt::decode(&mut partial)
            .expect("decoding should succeed")
            .expect("should have decoded a varint");
        assert_eq!(decoded.value(), 16384);
    }

    #[test]
    fn prefix_decode_preserves_suffix_and_waits_for_every_boundary() {
        for value in [0, 63, 64, 16383, 16384, 1073741823, 1073741824, VARINT_MAX] {
            let varint = VarInt::new(value).unwrap();
            let mut encoded = BytesMut::new();
            varint.encode(&mut encoded).unwrap();
            let length = encoded.len();
            for split in 0..length {
                assert!(VarInt::decode_prefix(&encoded[..split]).unwrap().is_none());
            }
            encoded.extend_from_slice(b"untouched suffix");
            assert_eq!(
                VarInt::decode_prefix(&encoded).unwrap(),
                Some((varint, length))
            );
            assert_eq!(encoded.len(), length + b"untouched suffix".len());
            assert_eq!(VarInt::decode(&mut encoded).unwrap(), Some(varint));
            assert_eq!(encoded.as_ref(), b"untouched suffix");
        }
    }

    #[test]
    fn test_varint_too_large() {
        assert!(VarInt::new(VARINT_MAX + 1).is_err());
        assert!(VarInt::new(u64::MAX).is_err());
    }

    #[test]
    fn test_varint_rejects_non_canonical_encodings() {
        let cases: &[&[u8]] = &[
            &[0x40, 0x00],                                     // 0 encoded in two bytes
            &[0x80, 0x00, 0x00, 0x3f],                         // 63 encoded in four bytes
            &[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00], // 16384 encoded in eight bytes
        ];

        for &encoded in cases {
            let mut buf = BytesMut::from(encoded);
            let before = buf.clone();

            assert!(VarInt::decode(&mut buf).is_err());
            assert_eq!(buf, before);
        }
    }

    #[test]
    fn test_varint_peek_len() {
        let test_cases = [
            (VarInt::new(0).expect("test value should be valid"), 1),
            (VarInt::new(64).expect("test value should be valid"), 2),
            (VarInt::new(16384).expect("test value should be valid"), 4),
            (
                VarInt::new(1073741824).expect("test value should be valid"),
                8,
            ),
        ];

        for (varint, expected_len) in test_cases {
            let mut buf = BytesMut::new();
            varint.encode(&mut buf).expect("encoding should succeed");

            assert_eq!(
                VarInt::peek_len(&buf).expect("buffer should have varint"),
                expected_len
            );
        }
    }
