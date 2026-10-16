    use super::*;
    use crate::cx::cap;
    use crate::net::atp::protocol::packet_assembly::{
        PacketAssembler, PacketConstraints, PacketNumberSpace,
    };

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn assert_stream_id(outcome: Outcome<StreamId, StreamError>, context: &str) -> StreamId {
        match outcome {
            Outcome::Ok(stream_id) => stream_id,
            other => panic!("{context}: expected stream id, got {other:?}"),
        }
    }

    #[test]
    fn close_stream_keeps_fin_schedulable_when_previously_blocked() {
        let cx = test_cx();
        let mut manager = StreamManager::new(false);
        let stream_id = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Data),
            "open client bidirectional stream",
        );

        assert!(manager.mark_stream_blocked(stream_id).is_ok());
        assert!(manager.next_scheduled_stream().is_none());

        assert!(manager.close_stream(&cx, stream_id).is_ok());
        assert_eq!(manager.next_scheduled_stream(), Some(stream_id));
    }

    #[test]
    fn close_stream_does_not_reschedule_after_fin_is_drained() {
        let cx = test_cx();
        let mut manager = StreamManager::new(false);
        let stream_id = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Data),
            "open client bidirectional stream",
        );

        assert!(manager.close_stream(&cx, stream_id).is_ok());
        assert_eq!(manager.next_scheduled_stream(), Some(stream_id));

        let Some(stream) = manager.get_stream_mut(stream_id) else {
            panic!("test stream should remain registered until both halves close");
        };
        let Some((offset, data, fin)) = stream.get_send_data(1024) else {
            panic!("close should produce a FIN-only frame");
        };
        assert_eq!(offset, 0);
        assert!(data.is_empty());
        assert!(fin);

        assert!(manager.close_stream(&cx, stream_id).is_ok());
        assert!(manager.next_scheduled_stream().is_none());
    }

    #[test]
    fn queued_stream_bytes_drain_into_quic_frames_and_packet_bytes() {
        let cx = test_cx();
        let mut manager = StreamManager::new(false);
        let data_stream = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Data),
            "open data stream",
        );
        let control_stream = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Control),
            "open control stream",
        );

        assert!(
            manager
                .queue_stream_data(&cx, data_stream, Bytes::from_static(b"abcdef"), true)
                .is_ok()
        );
        assert!(
            manager
                .queue_stream_data(&cx, control_stream, Bytes::from_static(b"go"), false)
                .is_ok()
        );

        let frames = match manager.drain_quic_stream_frames(3, 3) {
            Outcome::Ok(frames) => frames,
            other => panic!("stream frames should drain cleanly, got {other:?}"),
        };

        assert_eq!(frames.len(), 3);
        assert!(matches!(
            &frames[0],
            QuicFrame::Stream {
                stream_id,
                offset: None,
                data,
                fin: false
            } if stream_id.value() == control_stream.id && data.as_ref() == b"go"
        ));
        assert!(matches!(
            &frames[1],
            QuicFrame::Stream {
                stream_id,
                offset: None,
                data,
                fin: false
            } if stream_id.value() == data_stream.id && data.as_ref() == b"abc"
        ));
        assert!(matches!(
            &frames[2],
            QuicFrame::Stream {
                stream_id,
                offset: Some(offset),
                data,
                fin: true
            } if stream_id.value() == data_stream.id
                && offset.value() == 3
                && data.as_ref() == b"def"
        ));
        assert!(manager.next_scheduled_stream().is_none());

        let mut assembler = PacketAssembler::new(
            PacketConstraints::new()
                .with_packet_number_space(PacketNumberSpace::ApplicationData)
                .without_anti_amplification(),
        );
        for frame in frames {
            assembler.add_quic_frame(frame);
        }

        let packet = assembler
            .assemble_packet()
            .expect("packet assembly should not fail")
            .expect("queued stream frames should produce one packet");
        assert_eq!(packet.frames.len(), 3);
        assert!(packet.ack_eliciting);
        assert!(packet.retransmittable);

        let encoded = packet.encode_frames().expect("encode assembled frames");
        assert!(
            encoded.len() > b"abcdefgo".len(),
            "encoded packet payload should include QUIC frame metadata"
        );
    }

    #[test]
    fn empty_non_fin_send_does_not_emit_stream_frame() {
        let cx = test_cx();
        let mut manager = StreamManager::new(false);
        let stream_id = assert_stream_id(
            manager.open_stream(&cx, true, StreamPriority::Data),
            "open stream",
        );

        assert!(
            manager
                .queue_stream_data(&cx, stream_id, Bytes::new(), false)
                .is_ok()
        );

        let frames = match manager.drain_quic_stream_frames(2, 16) {
            Outcome::Ok(frames) => frames,
            other => panic!("empty non-FIN drain should not fail, got {other:?}"),
        };

        assert!(frames.is_empty());
        assert!(manager.next_scheduled_stream().is_none());
    }
