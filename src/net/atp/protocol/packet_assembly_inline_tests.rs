    use super::*;
    use crate::net::atp::protocol::varint::VarInt;

    #[test]
    fn test_packet_constraints_budget() {
        let constraints = PacketConstraints::new()
            .with_congestion_window(1000)
            .with_mtu(1200);

        // Should be limited by congestion window
        assert_eq!(constraints.available_packet_budget(), 1000);
    }

    #[test]
    fn test_frame_prioritization() {
        let ping = PrioritizedFrame::new(QuicFrame::Ping);
        let close = PrioritizedFrame::new(QuicFrame::ConnectionClose {
            error_code: VarInt::new(0).unwrap(),
            frame_type: None,
            reason_phrase: Bytes::from_static(b"test"),
        });

        assert!(close.priority > ping.priority);
        assert!(close.ack_eliciting);
        assert!(ping.retransmittable); // PING is retransmittable
    }

    #[test]
    fn test_packet_assembly() {
        let mut assembler = PacketAssembler::new(
            PacketConstraints::new()
                .with_packet_number_space(PacketNumberSpace::ApplicationData)
                .without_anti_amplification(),
        );

        // Add some frames
        assembler.add_quic_frame(QuicFrame::Ping);
        assembler.add_quic_frame(QuicFrame::MaxData {
            maximum_data: VarInt::new(1024).unwrap(),
        });

        let packet = assembler.assemble_packet().unwrap().unwrap();
        assert_eq!(packet.frames.len(), 2);
        assert!(packet.ack_eliciting);
        assert_eq!(assembler.pending_frame_count(), 0);
    }

    #[test]
    fn test_packet_assembly_priority_buckets_preserve_order() {
        let mut assembler = PacketAssembler::new(
            PacketConstraints::new()
                .with_packet_number_space(PacketNumberSpace::ApplicationData)
                .without_anti_amplification(),
        );

        assembler.add_frame(PrioritizedFrame::new(QuicFrame::Ping).with_priority(10));
        assembler.add_frame(
            PrioritizedFrame::new(QuicFrame::MaxData {
                maximum_data: VarInt::new(1024).unwrap(),
            })
            .with_priority(10),
        );
        assembler.add_frame(
            PrioritizedFrame::new(QuicFrame::ConnectionClose {
                error_code: VarInt::new(0).unwrap(),
                frame_type: None,
                reason_phrase: Bytes::from_static(b"test"),
            })
            .with_priority(20),
        );

        assert_eq!(assembler.pending_frame_count(), 3);

        let packet = assembler.assemble_packet().unwrap().unwrap();
        assert!(matches!(
            packet.frames[0],
            QuicFrame::ConnectionClose { .. }
        ));
        assert!(matches!(packet.frames[1], QuicFrame::Ping));
        assert!(matches!(packet.frames[2], QuicFrame::MaxData { .. }));
        assert_eq!(assembler.pending_frame_count(), 0);
    }

    #[test]
    fn test_packet_number_space_filtering() {
        let mut assembler = PacketAssembler::new(
            PacketConstraints::new().with_packet_number_space(PacketNumberSpace::Initial),
        );

        // Add frames - some allowed in Initial space, some not
        assembler.add_quic_frame(QuicFrame::Ping); // Allowed
        assembler.add_quic_frame(QuicFrame::Stream {
            stream_id: VarInt::new(0).unwrap(),
            offset: None,
            data: Bytes::from_static(b"test"),
            fin: false,
        }); // Not allowed in Initial space
        assembler.add_quic_frame(QuicFrame::Crypto {
            offset: VarInt::new(0).unwrap(),
            data: Bytes::from_static(b"handshake"),
        }); // Allowed

        let packet = assembler.assemble_packet().unwrap().unwrap();

        // Initial packets may be padded to the transport minimum, so filter
        // padding before checking packet-number-space frame filtering.
        let non_padding_frames: Vec<_> = packet
            .frames
            .iter()
            .filter(|frame| !matches!(frame, QuicFrame::Padding { .. }))
            .collect();
        assert_eq!(non_padding_frames.len(), 2);
        assert!(matches!(non_padding_frames[0], QuicFrame::Crypto { .. })); // Higher priority
        assert!(matches!(non_padding_frames[1], QuicFrame::Ping));
        assert_eq!(assembler.pending_frame_count(), 1);

        assembler.set_constraints(
            PacketConstraints::new()
                .with_packet_number_space(PacketNumberSpace::ApplicationData)
                .without_anti_amplification(),
        );
        let app_packet = assembler.assemble_packet().unwrap().unwrap();
        assert!(matches!(app_packet.frames[0], QuicFrame::Stream { .. }));
        assert_eq!(assembler.pending_frame_count(), 0);
    }

    #[test]
    fn test_oversized_high_priority_frame_does_not_block_lower_priority_frame() {
        let mut assembler = PacketAssembler::new(
            PacketConstraints::new()
                .with_packet_number_space(PacketNumberSpace::ApplicationData)
                .without_anti_amplification(),
        );

        assembler.add_frame(
            PrioritizedFrame::new(QuicFrame::Padding {
                length: DEFAULT_IPV4_MTU,
            })
            .with_priority(250),
        );
        assembler.add_frame(PrioritizedFrame::new(QuicFrame::Ping));

        let packet = assembler.assemble_packet().unwrap().unwrap();
        assert_eq!(packet.frames, vec![QuicFrame::Ping]);
        assert_eq!(assembler.pending_frame_count(), 1);
    }

    #[test]
    fn test_initial_packet_waits_for_padding_budget_without_dropping_frame() {
        let mut assembler = PacketAssembler::new(
            PacketConstraints::new()
                .with_congestion_window(MIN_INITIAL_PACKET_SIZE - 1)
                .with_mtu(2000),
        );

        assembler.add_quic_frame(QuicFrame::Ping);

        assert!(assembler.assemble_packet().unwrap().is_none());
        assert_eq!(assembler.pending_frame_count(), 1);
    }

    #[test]
    fn test_anti_amplification_padding() {
        let mut assembler = PacketAssembler::new(
            PacketConstraints::new()
                .with_packet_number_space(PacketNumberSpace::Initial)
                .with_mtu(2000), // Large MTU
        );

        assembler.add_quic_frame(QuicFrame::Ping); // Small frame

        let packet = assembler.assemble_packet().unwrap().unwrap();

        // Should have padding added to meet minimum size
        let has_padding = packet
            .frames
            .iter()
            .any(|f| matches!(f, QuicFrame::Padding { .. }));
        assert!(has_padding);
        assert_eq!(packet.estimated_size(), MIN_INITIAL_PACKET_SIZE);
    }
