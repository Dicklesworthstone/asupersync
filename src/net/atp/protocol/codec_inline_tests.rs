    use super::*;
    use crate::net::atp::protocol::transcript::TranscriptHasher;

    fn raw_extension_frame(extensions: &[(u16, &[u8])], payload: &[u8]) -> BytesMut {
        let mut wire = BytesMut::new();
        for value in [
            u64::from(ProtocolVersion::V0.0),
            FrameType::Capabilities as u64,
            payload.len() as u64,
            extensions.len() as u64,
        ] {
            VarInt::new(value).unwrap().encode(&mut wire).unwrap();
        }
        for (id, data) in extensions {
            VarInt::new(u64::from(*id))
                .unwrap()
                .encode(&mut wire)
                .unwrap();
            VarInt::new(data.len() as u64)
                .unwrap()
                .encode(&mut wire)
                .unwrap();
            wire.put_slice(data);
        }
        wire.put_slice(payload);
        wire
    }

    #[test]
    fn extension_encoding_is_canonical_across_permutations_and_hash_seeds() {
        let entries: [(u16, &[u8]); 3] = [(0, b""), (64, b"a"), (u16::MAX, b"z")];
        let permutations = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        // Fixed protocol bytes, independent of the map iteration order or codec.
        let expected = [
            0, 3, 1, 3, 0, 0, 0x40, 0x40, 1, b'a', 0x80, 0, 0xff, 0xff, 1, b'z', b'p',
        ];
        assert_eq!(raw_extension_frame(&entries, b"p").as_ref(), expected);
        let mut expected_transcript = None;
        for sample in 0..16 {
            for order in permutations {
                let mut frame =
                    Frame::new(ProtocolVersion::V0, FrameType::Capabilities, b"p".to_vec())
                        .unwrap();
                for index in order {
                    let (id, data) = entries[index];
                    frame.header.extensions.insert(id, data.to_vec());
                }
                let encoded = frame.to_wire_bytes().unwrap();
                assert_eq!(encoded, expected, "sample={sample}, order={order:?}");
                let mut buffer = BytesMut::from(encoded.as_slice());
                let decoded = AtpFrameCodec::new().decode(&mut buffer).unwrap().unwrap();
                assert!(buffer.is_empty());
                assert_eq!(decoded.header.extensions, frame.header.extensions);
                assert_eq!(decoded.payload(), b"p");
                let mut transcript = TranscriptHasher::new();
                transcript.update_frame(&decoded);
                let hash = transcript.finalize();
                assert_eq!(*expected_transcript.get_or_insert(hash), hash);
            }
        }
        // A deliberately unsorted legacy encoder must fail the canonical-byte
        // oracle even though its unique extension values remain decodable.
        let unsorted = raw_extension_frame(&[entries[2], entries[0], entries[1]], b"p");
        assert_ne!(unsorted.as_ref(), expected);
    }

    #[test]
    fn historical_unsorted_extensions_decode_at_every_split_with_the_same_transcript() {
        let entries: [(u16, &[u8]); 3] = [(u16::MAX, b"z"), (64, b"a"), (0, b"")];
        let wire = raw_extension_frame(&entries, b"payload");
        let header_len = wire.len() - b"payload".len();
        let canonical_wire = raw_extension_frame(&[entries[2], entries[1], entries[0]], b"payload");
        let canonical = AtpFrameCodec::new()
            .decode(&mut canonical_wire.clone())
            .unwrap()
            .unwrap();
        let mut transcript = TranscriptHasher::new();
        transcript.update_frame(&canonical);
        let expected_hash = transcript.finalize();

        for split in 0..wire.len() {
            let mut codec = AtpFrameCodec::new();
            let mut buffer = BytesMut::from(&wire[..split]);
            assert!(
                codec.decode(&mut buffer).unwrap().is_none(),
                "split={split}"
            );
            if split < header_len {
                assert_eq!(buffer.as_ref(), &wire[..split], "partial header consumed");
            }
            buffer.extend_from_slice(&wire[split..]);
            let decoded = codec.decode(&mut buffer).unwrap().unwrap();
            assert_eq!(decoded.header.extensions, canonical.header.extensions);
            assert_eq!(decoded.payload(), b"payload");
            assert!(buffer.is_empty());
            let mut transcript = TranscriptHasher::new();
            transcript.update_frame(&decoded);
            assert_eq!(transcript.finalize(), expected_hash, "split={split}");
            assert_eq!(decoded.to_wire_bytes().unwrap(), canonical_wire.as_ref());
        }
    }

    #[test]
    fn duplicate_extension_ids_refuse_without_consuming_input() {
        for id in [0, 63, 64, 16383, 16384, u16::MAX] {
            for second in [b"first".as_slice(), b"different".as_slice(), b"".as_slice()] {
                let wire = raw_extension_frame(&[(id, b"first"), (id, second)], b"payload");
                let mut codec = AtpFrameCodec::new();
                let mut buffer = wire.clone();
                let error = codec.decode(&mut buffer).unwrap_err();
                assert!(
                    matches!(error, FrameError::InvalidFormat(ref message)
                        if message == &format!("Duplicate extension ID {id}")),
                    "id={id}, second={second:?}, error={error:?}",
                );
                assert_eq!(buffer.as_ref(), wire.as_ref(), "invalid frame consumed");

                // Error handling must not leave the decoder expecting a payload.
                let mut valid = raw_extension_frame(&[(id, second)], b"next");
                let decoded = codec.decode(&mut valid).unwrap().unwrap();
                assert_eq!(decoded.header.extensions.get(&id).unwrap(), second);
                assert_eq!(decoded.payload(), b"next");
                assert!(valid.is_empty());
            }
        }
    }

    #[test]
    fn empty_and_single_extension_wire_bytes_remain_compatible() {
        for entries in [Vec::new(), vec![(7, b"ext".as_slice())]] {
            let wire = raw_extension_frame(&entries, b"data");
            let mut buffer = wire.clone();
            let frame = AtpFrameCodec::new().decode(&mut buffer).unwrap().unwrap();
            assert_eq!(frame.to_wire_bytes().unwrap(), wire.as_ref());
            assert!(buffer.is_empty());
        }
    }

    #[test]
    fn eof_rejects_every_truncated_frame_prefix_including_consumed_header() {
        let frame = Frame::new(
            ProtocolVersion::V0,
            FrameType::ObjectData,
            b"payload".to_vec(),
        )
        .unwrap();
        let wire = frame.to_wire_bytes().unwrap();
        let header_len = frame.header.encoded_len();
        for split in 1..wire.len() {
            // Cover EOF both on the first decode and after an ordinary read
            // has moved the complete header into the codec's private state.
            for decode_before_eof in [false, true] {
                let mut codec = AtpFrameCodec::new();
                let mut buffer = BytesMut::from(&wire[..split]);
                if decode_before_eof {
                    assert!(codec.decode(&mut buffer).unwrap().is_none());
                    if split == header_len {
                        assert!(buffer.is_empty(), "header must already be consumed");
                        assert!(matches!(codec.decode_state, DecodeState::Payload { .. }));
                    }
                }
                assert!(
                    matches!(
                        codec.decode_eof(&mut buffer),
                        Err(FrameError::UnexpectedEof)
                    ),
                    "split={split}, decode_before_eof={decode_before_eof}",
                );
                // EOF failure does not discard the partial payload or header;
                // explicit decoder reuse can still supply the missing bytes.
                buffer.extend_from_slice(&wire[split..]);
                assert_eq!(codec.decode_eof(&mut buffer).unwrap(), Some(frame.clone()));
                assert!(codec.decode_eof(&mut buffer).unwrap().is_none());
            }
        }
    }

    #[test]
    fn total_frame_size_refusal_preserves_input_and_decoder_state() {
        let mut frame =
            Frame::new(ProtocolVersion::V0, FrameType::ObjectData, vec![42; 8]).unwrap();
        frame.header.extensions.insert(7, b"extension".to_vec());
        let wire = frame.to_wire_bytes().unwrap();
        let limit = wire.len() as u64 - 1;
        for split in frame.header.encoded_len()..=wire.len() {
            let mut codec = AtpFrameCodec::with_max_frame_size(limit);
            let mut buffer = BytesMut::from(&wire[..split]);
            assert!(matches!(
                codec.decode(&mut buffer),
                Err(FrameError::FrameTooLarge { size, max })
                    if size == wire.len() as u64 && max == limit
            ));
            assert_eq!(buffer.as_ref(), &wire[..split], "split={split}");
            assert!(matches!(codec.decode_state, DecodeState::Header));

            // A separate valid frame remains decodable without a reset.
            let valid = Frame::new(ProtocolVersion::V0, FrameType::KeepAlive, vec![]).unwrap();
            let mut next = BytesMut::from(valid.to_wire_bytes().unwrap().as_slice());
            assert_eq!(codec.decode(&mut next).unwrap(), Some(valid));
            assert!(next.is_empty());
        }
    }

    #[test]
    fn test_frame_roundtrip() {
        let mut codec = AtpFrameCodec::new();

        // Create a test frame
        let payload = b"Hello, ATP!".to_vec();
        let frame = Frame::new(ProtocolVersion::V0, FrameType::Handshake, payload.clone()).unwrap();

        // Encode
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        // Decode
        let decoded = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.version(), frame.version());
        assert_eq!(decoded.frame_type(), frame.frame_type());
        assert_eq!(decoded.payload(), frame.payload());
    }

    #[test]
    fn test_partial_frame_decode() {
        let mut codec = AtpFrameCodec::new();

        // Create and encode a frame
        let payload = vec![0u8; 1000]; // Large payload
        let frame = Frame::new(ProtocolVersion::V0, FrameType::ObjectData, payload).unwrap();

        let mut encoded = BytesMut::new();
        codec.encode(frame.clone(), &mut encoded).unwrap();

        // Split encoded data into chunks for partial-read decoding.
        let total_len = encoded.len();
        let chunk_size = 100;

        let mut decoder = AtpFrameCodec::new();
        let mut decode_buf = BytesMut::new();

        for chunk_start in (0..total_len).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(total_len);
            let chunk = encoded.slice(chunk_start..chunk_end);
            decode_buf.extend_from_slice(chunk);

            // Try to decode
            match decoder.decode(&mut decode_buf).unwrap() {
                Some(decoded_frame) => {
                    // Should only succeed on the final chunk
                    assert!(chunk_end >= total_len);
                    assert_eq!(decoded_frame.payload(), frame.payload());
                    break;
                }
                None => {
                    // Should need more data
                    assert!(chunk_end < total_len);
                }
            }
        }
    }

    #[test]
    fn test_frame_with_extensions() {
        let mut codec = AtpFrameCodec::new();

        let mut frame = Frame::new(
            ProtocolVersion::V0,
            FrameType::Capabilities,
            b"capability_data".to_vec(),
        )
        .unwrap();

        // Add some extensions
        frame.header.extensions.insert(1, b"ext1".to_vec());
        frame.header.extensions.insert(2, b"extension2".to_vec());

        // Roundtrip
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.header.extensions, frame.header.extensions);
    }

    #[test]
    fn test_frame_size_limits() {
        let mut codec = AtpFrameCodec::with_max_frame_size(100);

        // Frame that's too large
        let large_payload = vec![0u8; 200];
        let large_frame =
            Frame::new(ProtocolVersion::V0, FrameType::ObjectData, large_payload).unwrap();

        let mut buf = BytesMut::new();
        let result = codec.encode(large_frame, &mut buf);

        assert!(matches!(result, Err(FrameError::FrameTooLarge { .. })));
    }

    #[test]
    fn test_decode_honors_custom_frame_size_limit() {
        let frame = Frame::new(ProtocolVersion::V0, FrameType::ObjectData, vec![0u8; 80]).unwrap();

        let mut encoded = BytesMut::new();
        AtpFrameCodec::new().encode(frame, &mut encoded).unwrap();

        let max_frame_size = u64::try_from(encoded.len() - 1).unwrap();
        let mut decoder = AtpFrameCodec::with_max_frame_size(max_frame_size);
        let result = decoder.decode(&mut encoded);

        assert!(matches!(result, Err(FrameError::FrameTooLarge { .. })));
    }

    #[test]
    fn test_decode_accepts_frames_above_default_when_limit_raised() {
        // Regression: `decode_header` previously bounded the payload length
        // against the hardcoded `MAX_FRAME_SIZE` (1 MiB) constant instead of
        // the codec's configured `max_frame_size`. A codec configured ABOVE
        // the default could therefore encode frames it then refused to decode
        // (an encode/decode asymmetry). A frame whose payload exceeds the 1 MiB
        // const but stays within the raised limit must round-trip.
        let payload_len = usize::try_from(MAX_FRAME_SIZE).unwrap() + 4096;
        let limit = MAX_FRAME_SIZE + 1024 * 1024; // 2 MiB configured limit
        let frame = Frame::new(
            ProtocolVersion::V0,
            FrameType::ObjectData,
            vec![0xABu8; payload_len],
        )
        .unwrap();

        let mut codec = AtpFrameCodec::with_max_frame_size(limit);
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        let decoded = codec
            .decode(&mut buf)
            .unwrap()
            .expect("frame within the configured limit must decode");
        assert_eq!(decoded.payload().len(), payload_len);
    }

    #[test]
    fn test_encode_rejects_payload_length_mismatch() {
        let mut codec = AtpFrameCodec::new();
        let mut frame = Frame::new(ProtocolVersion::V0, FrameType::ObjectData, vec![1, 2]).unwrap();
        frame.header.payload_length = VarInt::new(1).unwrap();

        let mut buf = BytesMut::new();
        let result = codec.encode(frame, &mut buf);

        assert!(matches!(result, Err(FrameError::InvalidFormat(_))));
    }

    #[test]
    fn test_encode_rejects_extension_limit_violations() {
        let mut codec = AtpFrameCodec::new();
        let mut oversized_ext =
            Frame::new(ProtocolVersion::V0, FrameType::Capabilities, Vec::new()).unwrap();
        oversized_ext
            .header
            .extensions
            .insert(1, vec![0u8; (MAX_EXTENSION_SIZE + 1) as usize]);

        let mut buf = BytesMut::new();
        let result = codec.encode(oversized_ext, &mut buf);
        assert!(matches!(result, Err(FrameError::ExtensionTooLarge { .. })));

        let mut too_many_ext =
            Frame::new(ProtocolVersion::V0, FrameType::Capabilities, Vec::new()).unwrap();
        for ext_id in 0..=MAX_EXTENSION_COUNT {
            too_many_ext
                .header
                .extensions
                .insert(ext_id as u16, Vec::new());
        }

        let result = codec.encode(too_many_ext, &mut buf);
        assert!(matches!(result, Err(FrameError::InvalidFormat(_))));
    }

    #[test]
    fn test_invalid_varint_encoding_is_not_treated_as_partial_header() {
        let mut buf = BytesMut::from(&[0x40, 0x00][..]); // non-canonical zero version
        let mut codec = AtpFrameCodec::new();
        let result = codec.decode(&mut buf);

        assert!(matches!(
            result,
            Err(FrameError::VarInt(VarIntError::InvalidEncoding))
        ));
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = BytesMut::new();

        // Manually encode frame with invalid version
        VarInt::new(999).unwrap().encode(&mut buf).unwrap(); // Invalid version
        VarInt::new(FrameType::Handshake as u64)
            .unwrap()
            .encode(&mut buf)
            .unwrap();
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // payload length
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // extension count

        let mut codec = AtpFrameCodec::new();
        let result = codec.decode(&mut buf);

        assert!(matches!(result, Err(FrameError::UnsupportedVersion(999))));
    }

    #[test]
    fn test_unknown_frame_type() {
        let mut buf = BytesMut::new();

        // Manually encode frame with unknown frame type
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // Valid version
        VarInt::new(9999).unwrap().encode(&mut buf).unwrap(); // Invalid frame type
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // payload length
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // extension count

        let mut codec = AtpFrameCodec::new();
        let result = codec.decode(&mut buf);

        assert!(matches!(result, Err(FrameError::UnknownFrameType(9999))));
    }

    #[test]
    fn test_malformed_frame_validation_bypass_prevention() {
        let mut buf = BytesMut::new();

        // Test 1: Extension ID that would overflow u16 (DoS vulnerability)
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // Valid version
        VarInt::new(FrameType::Handshake as u64)
            .unwrap()
            .encode(&mut buf)
            .unwrap(); // Valid frame type
        VarInt::new(0).unwrap().encode(&mut buf).unwrap(); // payload length
        VarInt::new(1).unwrap().encode(&mut buf).unwrap(); // 1 extension
        VarInt::new(0x10000).unwrap().encode(&mut buf).unwrap(); // Extension ID > u16::MAX
        VarInt::new(4).unwrap().encode(&mut buf).unwrap(); // Extension length
        buf.put_slice(b"data"); // Extension data

        let mut codec = AtpFrameCodec::new();
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(FrameError::InvalidFormat(_))));

        // Test 2: Encodable extension length above the ATP limit.
        let mut buf2 = BytesMut::new();
        VarInt::new(0).unwrap().encode(&mut buf2).unwrap(); // Valid version
        VarInt::new(FrameType::Handshake as u64)
            .unwrap()
            .encode(&mut buf2)
            .unwrap(); // Valid frame type
        VarInt::new(0).unwrap().encode(&mut buf2).unwrap(); // payload length
        VarInt::new(1).unwrap().encode(&mut buf2).unwrap(); // 1 extension
        VarInt::new(1).unwrap().encode(&mut buf2).unwrap(); // Valid extension ID
        VarInt::new(MAX_EXTENSION_SIZE + 1)
            .unwrap()
            .encode(&mut buf2)
            .unwrap(); // Extension length exceeds ATP limit

        let mut codec2 = AtpFrameCodec::new();
        let result2 = codec2.decode(&mut buf2);
        assert!(matches!(
            result2,
            Err(FrameError::ExtensionTooLarge { .. } | FrameError::InvalidFormat(_))
        ));

        // Test 3: Version that would truncate (DoS vulnerability)
        let mut buf3 = BytesMut::new();
        VarInt::new(0x100000000u64)
            .unwrap()
            .encode(&mut buf3)
            .unwrap(); // Version > u32::MAX
        VarInt::new(FrameType::Handshake as u64)
            .unwrap()
            .encode(&mut buf3)
            .unwrap(); // Valid frame type
        VarInt::new(0).unwrap().encode(&mut buf3).unwrap(); // payload length
        VarInt::new(0).unwrap().encode(&mut buf3).unwrap(); // extension count

        let mut codec3 = AtpFrameCodec::new();
        let result3 = codec3.decode(&mut buf3);
        assert!(matches!(result3, Err(FrameError::UnsupportedVersion(_))));
    }
