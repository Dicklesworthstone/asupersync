    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    fn roundtrip(packet: &Packet) {
        let encoded = encode_packet(packet, DEFAULT_MTU).expect("encode");
        assert_eq!(encoded.gossip_dropped, 0);
        let decoded = decode_packet(&encoded.bytes).expect("decode");
        assert_eq!(&decoded, packet);
    }

    #[test]
    fn payload_roundtrips() {
        roundtrip(&Packet::new(Payload::Ping { seq: 7 }));
        roundtrip(&Packet::new(Payload::Ack { seq: 9 }));
        roundtrip(&Packet::new(Payload::PingReq {
            seq: 11,
            target: node("node-b"),
        }));
        roundtrip(&Packet::new(Payload::Nack { seq: 13 }));
    }

    #[test]
    fn gossip_roundtrips() {
        let packet = Packet {
            payload: Payload::Ping { seq: 1 },
            gossip: vec![
                Rumor::alive(node("a"), 3),
                Rumor::suspect(node("b"), 5, node("c")),
                Rumor::confirm(node("d"), 7, node("e")),
                Rumor::leave(node("f"), 9),
            ],
        };
        roundtrip(&packet);
    }

    #[test]
    fn mtu_budget_truncates_gossip_tail() {
        let mut gossip = Vec::new();
        for i in 0..50 {
            gossip.push(Rumor::alive(node(&format!("node-{i}")), i));
        }
        let packet = Packet {
            payload: Payload::Ping { seq: 1 },
            gossip,
        };
        // A tiny MTU admits the payload + only a few rumors.
        let encoded = encode_packet(&packet, 64).expect("encode");
        assert!(encoded.bytes.len() <= 64);
        assert!(encoded.gossip_included < 50);
        assert_eq!(
            encoded.gossip_included + encoded.gossip_dropped,
            packet.gossip.len()
        );
        // What survived decodes cleanly (a prefix of the gossip).
        let decoded = decode_packet(&encoded.bytes).expect("decode");
        assert_eq!(decoded.gossip.len(), encoded.gossip_included);
        assert_eq!(decoded.payload, Payload::Ping { seq: 1 });
    }

    #[test]
    fn payload_exceeding_mtu_errors() {
        let packet = Packet::new(Payload::PingReq {
            seq: 1,
            target: node("a-very-long-node-identifier-that-will-not-fit"),
        });
        assert_eq!(encode_packet(&packet, 8), Err(WireError::PayloadExceedsMtu));
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert_eq!(decode_packet(&[]), Err(WireError::UnexpectedEof));
        assert_eq!(decode_packet(&[9, 0]), Err(WireError::UnknownVersion(9)));
        // Version ok, unknown payload tag.
        assert_eq!(
            decode_packet(&[WIRE_VERSION, 99]),
            Err(WireError::UnknownPayloadTag(99))
        );
        // Truncated mid-payload (ping tag but no u64 seq).
        assert_eq!(
            decode_packet(&[WIRE_VERSION, 0, 1, 2]),
            Err(WireError::UnexpectedEof)
        );
    }

    #[test]
    fn decode_caps_gossip_capacity_to_remaining_bytes() {
        // Off-wire allocation-amplification guard: a tiny datagram claiming the
        // maximum gossip count (u16::MAX) must NOT eagerly reserve ~65535 rumor
        // slots. The pre-allocation is bounded by remaining bytes / MIN_RUMOR_BYTES
        // (here 0), so the decode fails cleanly at EOF with no giant allocation
        // and no panic — pre-fix this forced a ~4 MiB reservation per 12-byte
        // packet.
        let mut dgram = vec![WIRE_VERSION, 0]; // version + Ping tag
        dgram.extend_from_slice(&0u64.to_le_bytes()); // seq
        dgram.extend_from_slice(&u16::MAX.to_le_bytes()); // gossip count = 65535
        assert_eq!(dgram.len(), 12);
        assert_eq!(decode_packet(&dgram), Err(WireError::UnexpectedEof));
    }

    #[test]
    fn determinism() {
        let packet = Packet {
            payload: Payload::Ack { seq: 42 },
            gossip: vec![Rumor::suspect(node("x"), 2, node("y"))],
        };
        let a = encode_packet(&packet, DEFAULT_MTU).expect("a");
        let b = encode_packet(&packet, DEFAULT_MTU).expect("b");
        assert_eq!(a, b);
    }
