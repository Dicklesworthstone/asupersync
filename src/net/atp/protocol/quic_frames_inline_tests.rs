    use super::*;

    #[test]
    fn test_varint_decode_spans_every_noncontiguous_boundary() {
        for value in [64, 16_384, 1_073_741_824] {
            let expected = VarInt::new(value).unwrap();
            let mut encoded = BytesMut::new();
            expected.encode(&mut encoded).unwrap();

            for split in 1..encoded.len() {
                let mut fragmented = (&encoded[..split]).chain(&encoded[split..]);
                let decoded = VarInt::decode_from_buf(&mut fragmented).unwrap();

                assert_eq!(decoded, Some(expected), "value={value}, split={split}");
                assert_eq!(fragmented.remaining(), 0, "value={value}, split={split}");
            }
        }
    }

    #[test]
    fn test_varint_decode_leaves_fragmented_incomplete_input_unconsumed() {
        let expected = VarInt::new(16_384).unwrap();
        let mut encoded = BytesMut::new();
        expected.encode(&mut encoded).unwrap();
        let truncated = &encoded[..encoded.len() - 1];
        let mut fragmented = (&truncated[..1]).chain(&truncated[1..]);
        let remaining = fragmented.remaining();

        assert_eq!(VarInt::decode_from_buf(&mut fragmented).unwrap(), None);
        assert_eq!(fragmented.remaining(), remaining);
    }

    #[test]
    fn test_frame_decode_accepts_varint_split_across_chunks() {
        let frame = QuicFrame::MaxData {
            maximum_data: VarInt::new(16_384).unwrap(),
        };
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded).unwrap();
        let first_frame_len = encoded.len();
        QuicFrame::Ping.encode(&mut encoded).unwrap();

        for split in 2..first_frame_len {
            let mut fragmented = (&encoded[..split]).chain(&encoded[split..]);
            let decoded = QuicFrame::decode(&mut fragmented).unwrap().unwrap();

            assert_eq!(decoded, frame, "split={split}");
            assert_eq!(
                QuicFrame::decode(&mut fragmented).unwrap().unwrap(),
                QuicFrame::Ping,
                "split={split}"
            );
            assert_eq!(fragmented.remaining(), 0, "split={split}");
        }
    }

    #[test]
    fn test_ping_frame() {
        let frame = QuicFrame::Ping;
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_max_data_frame() {
        let frame = QuicFrame::MaxData {
            maximum_data: VarInt::new(1024).unwrap(),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_stream_frame_with_offset_and_length() {
        let frame = QuicFrame::Stream {
            stream_id: VarInt::new(4).unwrap(),
            offset: Some(VarInt::new(1000).unwrap()),
            data: Bytes::from_static(b"Hello, QUIC!"),
            fin: true,
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_path_challenge_frame() {
        let frame = QuicFrame::PathChallenge {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_connection_close_quic() {
        let frame = QuicFrame::ConnectionClose {
            error_code: VarInt::new(10).unwrap(),
            frame_type: Some(VarInt::new(0x06).unwrap()), // CRYPTO frame
            reason_phrase: Bytes::from_static(b"Handshake failed"),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_ack_frame_simple() {
        let frame = QuicFrame::Ack {
            largest_acknowledged: VarInt::new(100).unwrap(),
            ack_delay: VarInt::new(50).unwrap(),
            ack_range_count: VarInt::new(0).unwrap(),
            first_ack_range: VarInt::new(10).unwrap(),
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_crypto_frame() {
        let frame = QuicFrame::Crypto {
            offset: VarInt::new(0).unwrap(),
            data: Bytes::from_static(b"TLS handshake data"),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_crypto_frame_overflow_rejected() {
        let mut buf = BytesMut::new();
        QuicFrameType::Crypto.to_varint().encode_to_buf(&mut buf).unwrap();
        VarInt::new(VARINT_MAX).unwrap().encode_to_buf(&mut buf).unwrap();
        VarInt::new(1).unwrap().encode_to_buf(&mut buf).unwrap();
        buf.put_u8(0x42);

        let mut decode_buf = buf.freeze().reader();
        let result = QuicFrame::decode(&mut decode_buf);
        assert!(matches!(result, Err(QuicFrameError::InvalidFormat(_))));
    }

    #[test]
    fn test_frame_type_parsing() {
        assert_eq!(
            QuicFrameType::from_varint(VarInt::new(0x01).unwrap()).unwrap(),
            QuicFrameType::Ping
        );
        assert_eq!(
            QuicFrameType::from_varint(VarInt::new(0x1a).unwrap()).unwrap(),
            QuicFrameType::PathChallenge
        );
        assert!(QuicFrameType::is_stream_frame(0x08));
        assert!(QuicFrameType::is_stream_frame(0x0f));
        assert!(!QuicFrameType::is_stream_frame(0x10));
        // Both DATAGRAM type bytes (LEN bit unset/set) map to the same kind.
        assert_eq!(
            QuicFrameType::from_varint(VarInt::new(0x30).unwrap()).unwrap(),
            QuicFrameType::Datagram
        );
        assert_eq!(
            QuicFrameType::from_varint(VarInt::new(0x31).unwrap()).unwrap(),
            QuicFrameType::Datagram
        );
    }

    #[test]
    fn test_datagram_frame_round_trip() {
        let frame = QuicFrame::Datagram {
            data: Bytes::from_static(b"raptorq-symbol-payload"),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        // Encoded with the LEN bit set (type 0x31) so it is self-delimiting.
        assert_eq!(buf.as_ref()[0], 0x31);

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_datagram_frame_empty_payload_round_trips() {
        let frame = QuicFrame::Datagram { data: Bytes::new() };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_datagram_frame_no_length_consumes_rest_of_packet() {
        // A 0x30 DATAGRAM (no LEN bit) carries its payload to the end of the
        // packet; decode must surface exactly the remaining bytes.
        let mut buf = BytesMut::new();
        VarInt::new(0x30).unwrap().encode_to_buf(&mut buf).unwrap();
        buf.put_slice(b"tail-bytes");

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(
            decoded,
            QuicFrame::Datagram {
                data: Bytes::from_static(b"tail-bytes"),
            }
        );
    }

    #[test]
    fn test_datagram_length_prefixed_leaves_trailing_frame() {
        // A 0x31 DATAGRAM is self-delimiting: a trailing PING must still decode.
        let datagram = QuicFrame::Datagram {
            data: Bytes::from_static(b"symbol"),
        };
        let mut buf = BytesMut::new();
        datagram.encode(&mut buf).unwrap();
        QuicFrame::Ping.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        assert_eq!(
            QuicFrame::decode(&mut decode_buf).unwrap().unwrap(),
            datagram
        );
        assert_eq!(
            QuicFrame::decode(&mut decode_buf).unwrap().unwrap(),
            QuicFrame::Ping
        );
    }

    #[test]
    fn test_new_connection_id_frame_roundtrip() {
        let cid = ConnectionId::new(b"test-cid-1234").unwrap();
        let frame = QuicFrame::NewConnectionId {
            sequence_number: VarInt::from_u64_unchecked(1),
            retire_prior_to: VarInt::from_u64_unchecked(0),
            connection_id: cid,
            stateless_reset_token: [0x42; 16],
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_new_connection_id_retire_prior_to_validation() {
        let cid = ConnectionId::new(b"test-cid").unwrap();
        let frame = QuicFrame::NewConnectionId {
            sequence_number: VarInt::from_u64_unchecked(1),
            retire_prior_to: VarInt::from_u64_unchecked(2), // invalid: retire_prior_to > sequence_number
            connection_id: cid,
            stateless_reset_token: [0x42; 16],
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let err = QuicFrame::decode(&mut decode_buf).unwrap_err();
        assert!(matches!(err, QuicFrameError::InvalidFormat(_)));
    }

    #[test]
    fn test_retire_connection_id_frame_roundtrip() {
        let frame = QuicFrame::RetireConnectionId {
            sequence_number: VarInt::from_u64_unchecked(5),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    /// Every length-prefixed frame refuses a length past the bytes left. The
    /// length here has low 32 bits of 1: on a 32-bit target an `as usize`
    /// cast truncated it to one byte, which fits.
    #[test]
    fn length_prefixed_frames_refuse_a_length_past_the_remaining_bytes() {
        let length = VarInt::new((1 << 32) + 1).unwrap();
        // (frame, type byte, the varint fields before its length)
        let cases: [(&str, u8, &[u64]); 6] = [
            ("CRYPTO", 0x06, &[0]),
            ("NEW_TOKEN", 0x07, &[]),
            ("STREAM with LEN", 0x0a, &[4]),
            ("CONNECTION_CLOSE", 0x1c, &[1, 0]),
            ("application CONNECTION_CLOSE", 0x1d, &[1]),
            ("DATAGRAM with LEN", 0x31, &[]),
        ];
        for (label, frame_type, fields) in cases {
            let mut encoded = BytesMut::new();
            encoded.put_u8(frame_type);
            for &field in fields {
                VarInt::new(field).unwrap().encode(&mut encoded).unwrap();
            }
            length.encode(&mut encoded).unwrap();
            encoded.put_u8(0xab);
            let mut buf: &[u8] = &encoded;
            assert!(
                matches!(
                    QuicFrame::decode(&mut buf),
                    Err(QuicFrameError::UnexpectedEof)
                ),
                "{label}"
            );
        }
    }
