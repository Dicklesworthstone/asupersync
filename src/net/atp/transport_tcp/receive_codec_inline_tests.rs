use super::*;
use crate::net::atp::protocol::frames::ProtocolVersion;

fn entry(size: u64) -> ManifestEntry {
    ManifestEntry {
        index: 0,
        rel_path: String::from("stream.bin"),
        size,
        sha256_hex: String::new(),
        metadata: None,
        members: Vec::new(),
    }
}

#[test]
fn buffered_chunks_decode_in_bounded_wire_order_before_completion() {
    let runtime = crate::runtime::RuntimeBuilder::multi_thread()
        .build()
        .unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().unwrap();
        let (_peer, stream) = crate::io::duplex(1024);
        let mut transport = FrameTransport::new(stream);
        let offer = codec::local_offer(codec::CompressionMode::Zstd, 1024).unwrap();
        let accept = codec::negotiate(&transport.decode, &offer).unwrap();
        assert_eq!(accept.decode_slots, MAX_DECODE_SLOTS);
        transport.chunk_codec = Some(accept);

        let entries = [entry(5 * 1024)];
        let mut states = [StagedEntryReceive::new("unused".into())];
        for byte in 0_u8..5 {
            let (record, encoded) = codec::compress_chunk(&accept, &[byte; 1024]).unwrap();
            let frame =
                super::super::compressed_data_frame(0, u64::from(byte) * 1024, record, &encoded)
                    .unwrap();
            transport
                .rbuf
                .extend_from_slice(&frame.to_wire_bytes().unwrap());
        }
        let complete =
            Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectComplete, vec![]).unwrap();
        transport
            .rbuf
            .extend_from_slice(&complete.to_wire_bytes().unwrap());
        let trailing = [0xff; 3];
        transport.rbuf.extend_from_slice(&trailing);
        let mut queue = DecodeQueue::default();
        for byte in 0_u8..5 {
            let (frame, raw) = queue
                .next(
                    &cx,
                    &mut transport,
                    &entries,
                    &states,
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            assert_eq!(parse_data_frame(&frame).unwrap().1, u64::from(byte) * 1024);
            assert_eq!(raw.unwrap(), [byte; 1024]);
            if byte == 0 {
                assert_eq!(queue.slots.len(), usize::from(MAX_DECODE_SLOTS) - 1);
                assert!(
                    queue
                        .slots
                        .iter()
                        .all(|slot| matches!(slot, Slot::Decoding(..)))
                );
            }
            states[0].bytes_written += 1024;
        }
        let (end, raw) = queue
            .next(
                &cx,
                &mut transport,
                &entries,
                &states,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(end.frame_type(), FrameType::ObjectComplete);
        assert!(raw.is_none());
        assert_eq!(&transport.rbuf[..], trailing);
    }));
}

#[test]
fn incomplete_next_frame_does_not_delay_staging_or_lose_the_partial_payload() {
    let runtime = crate::runtime::RuntimeBuilder::multi_thread()
        .build()
        .unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().unwrap();
        let (_peer, stream) = crate::io::duplex(1024);
        let mut transport = FrameTransport::new(stream);
        let offer = codec::local_offer(codec::CompressionMode::Zstd, 1024).unwrap();
        let accept = codec::negotiate(&transport.decode, &offer).unwrap();
        transport.chunk_codec = Some(accept);
        let entries = [entry(2048)];
        let mut states = [StagedEntryReceive::new("unused".into())];
        let mut queue = DecodeQueue::default();
        let (record, encoded) = codec::compress_chunk(&accept, &[1; 1024]).unwrap();
        let first = super::super::compressed_data_frame(0, 0, record, &encoded).unwrap();
        let second = super::super::compressed_data_frame(0, 1024, record, &encoded)
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        let last = second.len() - 1;
        transport
            .rbuf
            .extend_from_slice(&first.to_wire_bytes().unwrap());
        transport.rbuf.extend_from_slice(&second[..last]);
        let (_, bytes) = queue
            .next(
                &cx,
                &mut transport,
                &entries,
                &states,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(bytes.unwrap(), [1; 1024]);
        assert!(queue.slots.is_empty());
        states[0].bytes_written = 1024;
        transport.rbuf.extend_from_slice(&second[last..]);
        let (frame, bytes) = queue
            .next(
                &cx,
                &mut transport,
                &entries,
                &states,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(parse_data_frame(&frame).unwrap().1, 1024);
        assert_eq!(bytes.unwrap(), [1; 1024]);
    }));
}

#[test]
fn caller_cancellation_interrupts_a_pending_decode_join() {
    let runtime = crate::runtime::RuntimeBuilder::multi_thread()
        .build()
        .unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().unwrap();
        let (release, gate) = std::sync::mpsc::channel::<()>();
        let job = cx
            .spawn_blocking_drained(move |_| {
                let _ = gate.recv();
                Ok(Vec::new())
            })
            .unwrap();
        let frame = Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectData, vec![]).unwrap();
        let mut queue = DecodeQueue::default();
        queue.slots.push_back(Slot::Decoding(Arc::new(frame), job));
        let caller = Cx::for_testing();
        caller.cancel_with_reason(crate::types::CancelReason::user("stop waiting for decode"));
        let (_peer, stream) = crate::io::duplex(1024);
        let mut transport = FrameTransport::new(stream);
        let outcome = futures_lite::future::poll_once(queue.next(
            &caller,
            &mut transport,
            &[],
            &[],
            Duration::from_secs(5),
        ))
        .await;
        drop(release);
        assert!(matches!(outcome, Some(Err(TransportError::Cancelled))));
    }));
}

#[test]
fn ahead_of_order_and_oversized_chunks_do_not_reach_workers() {
    let runtime = crate::runtime::RuntimeBuilder::multi_thread()
        .build()
        .unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().unwrap();
        let offer = codec::local_offer(codec::CompressionMode::Zstd, 1024).unwrap();
        let accept = codec::negotiate(&codec::local_decode_capability(1024), &offer).unwrap();
        let (record, encoded) = codec::compress_chunk(&accept, &[0; 1024]).unwrap();
        let entries = [entry(1024)];
        let states = [StagedEntryReceive::new("unused".into())];
        for (offset, mut next) in [(1, None), (0, Some((0, 1024))), (1024, Some((0, 1024)))] {
            let frame = super::super::compressed_data_frame(0, offset, record, &encoded).unwrap();
            let mut queue = DecodeQueue::default();
            assert!(!queue.enqueue(&cx, frame, accept, &entries, &states, &mut next));
            assert!(matches!(queue.slots.pop_front(), Some(Slot::Wire(Ok(_)))));
        }
        let mut queue = DecodeQueue::default();
        let valid = super::super::compressed_data_frame(0, 0, record, &encoded).unwrap();
        assert!(queue.enqueue(&cx, valid, accept, &entries, &states, &mut None));
        let Slot::Decoding(_, mut job) = queue.slots.pop_front().unwrap() else {
            panic!("a valid chunk should reach the pool")
        };
        assert_eq!(job.join().await.unwrap().unwrap(), [0; 1024]);
    }));
}
