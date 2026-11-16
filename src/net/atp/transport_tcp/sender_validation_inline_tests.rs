    use super::*;
    use crate::net::atp::transport_common::{DeltaManifestWire, DeltaObjectRequest};

    fn manifest(with_delta: bool) -> TransferManifest {
        TransferManifest {
            transfer_id: "t".into(),
            root_name: "r".into(),
            is_directory: true,
            total_bytes: 0,
            merkle_root_hex: "11".repeat(32),
            metadata_root_hex: None,
            directory_metadata: None,
            entries: Vec::new(),
            delta_manifest: with_delta.then(|| DeltaManifestWire {
                schema: "schema".into(),
                tree_id: "tree".into(),
                chunk_size: 4096,
                total_size_bytes: 0,
                merkle_root_hex: "22".repeat(32),
                chunks: Vec::new(),
            }),
        }
    }

    fn full_request(manifest: &TransferManifest) -> DeltaObjectRequest {
        DeltaObjectRequest::full(
            manifest
                .delta_manifest
                .as_ref()
                .map_or("", |delta| delta.merkle_root_hex.as_str()),
            None,
            "fallback",
        )
    }

    fn receipt() -> ReceiveReceipt {
        ReceiveReceipt {
            committed: true,
            bytes_received: 0,
            files: 0,
            sha_ok: true,
            merkle_ok: true,
            symbols_accepted: 0,
            feedback_rounds: 0,
            decode_count: 0,
            decode_micros: 0,
            reason: None,
            committed_paths: Vec::new(),
        }
    }

    #[test]
    fn sender_chunk_size_is_bounded_by_raw_frame_capacity() {
        let mut config = TransferConfig::default();
        validate_config(&config).unwrap();
        config.chunk_size = 0;
        assert!(validate_config(&config).is_err());
        config.chunk_size = usize::try_from(MAX_FRAME_SIZE).unwrap();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn request_root_is_bound_to_sent_delta_manifest() {
        for with_delta in [false, true] {
            let manifest = manifest(with_delta);
            let request = full_request(&manifest);
            validate_request(&manifest, &request).unwrap();
            let mut wrong = request;
            wrong.sender_merkle_root_hex = "ff".repeat(32);
            assert!(validate_request(&manifest, &wrong).is_err());
        }
    }

    #[test]
    fn noop_requires_matching_roots_and_no_missing_data() {
        let manifest = manifest(true);
        let mut request = full_request(&manifest);
        request.mode = DeltaWireMode::AlreadyInSync;
        request.receiver_merkle_root_hex = Some(request.sender_merkle_root_hex.clone());
        validate_request(&manifest, &request).unwrap();

        request.missing_bytes = 1;
        assert!(validate_request(&manifest, &request).is_err());
    }

    #[test]
    fn full_mode_rejects_range_instructions() {
        let manifest = manifest(true);
        let mut request = full_request(&manifest);
        request.missing_chunks.push(
            manifest
                .delta_manifest
                .as_ref()
                .and_then(|delta| delta.chunks.first())
                .cloned()
                .unwrap_or_else(|| crate::net::atp::transport_common::DeltaChunkWire {
                    index: 0,
                    entry_index: 0,
                    rel_path: "x".into(),
                    entry_offset: 0,
                    stream_offset: 0,
                    size_bytes: 1,
                    content_id_hex: "00".repeat(32),
                }),
        );
        assert!(validate_request(&manifest, &request).is_err());
    }

    #[test]
    fn receipt_requires_integrity_flags_and_exact_counts() {
        let manifest = manifest(false);
        validate_receipt(&manifest, 0, &receipt()).unwrap();

        let mut bad = receipt();
        bad.sha_ok = false;
        assert!(validate_receipt(&manifest, 0, &bad).is_err());

        let mut bad = receipt();
        bad.bytes_received = 1;
        assert!(validate_receipt(&manifest, 0, &bad).is_err());

        let mut bad = receipt();
        bad.files = 1;
        assert!(validate_receipt(&manifest, 0, &bad).is_err());
    }

    #[test]
    fn negative_receipt_preserves_peer_reason() {
        let manifest = manifest(false);
        let mut bad = receipt();
        bad.committed = false;
        bad.reason = Some("per-entry SHA-256 mismatch".into());
        assert!(matches!(
            validate_receipt(&manifest, 0, &bad),
            Err(TransportError::Integrity(message))
                if message == "per-entry SHA-256 mismatch"
        ));
    }

    fn delta_fixture() -> (TransferManifest, DeltaObjectRequest) {
        use crate::atp::object::ContentId;
        use crate::net::atp::transport_common::DeltaChunkWire;
        use crate::net::atp::transport_tcp::ManifestEntry;

        let mut manifest = manifest(true);
        manifest.total_bytes = 6;
        manifest.entries.push(ManifestEntry {
            index: 0,
            rel_path: "x".into(),
            size: 6,
            sha256_hex: "33".repeat(32),
            metadata: None,
            members: Vec::new(),
        });
        let delta = manifest.delta_manifest.as_mut().unwrap();
        delta.total_size_bytes = 6;
        // The same content occurs at two distinct locations. Both locations
        // cost bytes when requested; content deduplication must not undercount.
        delta.chunks = (0_u32..2)
            .map(|index| DeltaChunkWire {
                index,
                entry_index: 0,
                rel_path: "x".into(),
                entry_offset: u64::from(index) * 3,
                stream_offset: u64::from(index) * 3,
                size_bytes: 3,
                content_id_hex: ContentId::from_bytes(b"abc").to_hex(),
            })
            .collect();
        let mut request = full_request(&manifest);
        request.mode = DeltaWireMode::DeltaChunks;
        request.missing_chunks = manifest.delta_manifest.as_ref().unwrap().chunks.clone();
        request.missing_bytes = 6;
        (manifest, request)
    }

    #[test]
    fn delta_byte_count_matches_locations_not_unique_content_ids() {
        let (manifest, request) = delta_fixture();
        validate_request(&manifest, &request).unwrap();
        let mut reversed = request.clone();
        reversed.missing_chunks.reverse();
        validate_request(&manifest, &reversed).unwrap();

        let mut subset = request;
        subset.missing_chunks.truncate(1);
        subset.missing_bytes = 3;
        validate_request(&manifest, &subset).unwrap();
        // No payload can be legitimate when all chunks can be reused at new
        // locations. This is not the AlreadyInSync mode or a fabricated count.
        subset.missing_chunks.clear();
        subset.missing_bytes = 0;
        validate_request(&manifest, &subset).unwrap();
    }

    #[test]
    fn fabricated_missing_bytes_cannot_be_repeated_as_a_successful_receipt() {
        let (manifest, request) = delta_fixture();
        for claimed in [0, 1, 3, 5, 7, u64::MAX] {
            let mut forged = request.clone();
            forged.missing_bytes = claimed;
            let mut proof = receipt();
            proof.files = 1;
            proof.bytes_received = claimed;
            // Previously the send loop returned this peer-selected number,
            // allowing the receipt to "confirm" it. The receipt alone cannot
            // expose that circular comparison; negotiation must refuse first.
            validate_receipt(&manifest, claimed, &proof).unwrap();
            assert!(matches!(
                validate_request(&manifest, &forged),
                Err(TransportError::Frame(message))
                    if message == format!(
                        "delta ObjectRequest declares {claimed} missing bytes but requests 6"
                    )
            ));
        }
    }

    #[test]
    fn delta_byte_sum_overflow_fails_instead_of_saturating_or_wrapping() {
        let (manifest, mut request) = delta_fixture();
        request.missing_chunks[0].size_bytes = u64::MAX;
        request.missing_chunks[1].size_bytes = 1;
        for claimed in [0, u64::MAX] {
            request.missing_bytes = claimed;
            assert!(matches!(
                validate_request(&manifest, &request),
                Err(TransportError::Frame(message))
                    if message == "delta ObjectRequest byte count overflows u64"
            ));
        }
    }

    #[test]
    fn complete_delta_descriptors_are_bound_to_the_advertised_manifest() {
        let (manifest, request) = delta_fixture();
        for field in 0..7 {
            let mut altered = request.clone();
            let chunk = &mut altered.missing_chunks[0];
            match field {
                0 => chunk.index = 19,
                1 => chunk.entry_index = 1,
                2 => chunk.rel_path = "other".into(),
                3 => chunk.entry_offset = 1,
                4 => chunk.stream_offset = 1,
                5 => {
                    chunk.size_bytes = 2;
                    altered.missing_bytes = 5;
                }
                6 => chunk.content_id_hex = "44".repeat(32),
                _ => unreachable!(),
            }
            assert!(matches!(
                validate_request(&manifest, &altered),
                Err(TransportError::Frame(message))
                    if message == "delta ObjectRequest asks for a chunk outside the sender manifest"
            ));
        }
    }

    #[test]
    fn duplicate_delta_locations_are_refused_even_with_matching_byte_totals() {
        let (manifest, mut request) = delta_fixture();
        request.missing_chunks[1] = request.missing_chunks[0].clone();
        assert!(matches!(
            validate_request(&manifest, &request),
            Err(TransportError::Frame(message))
                if message == "delta ObjectRequest contains duplicate missing chunks"
        ));
    }

    #[test]
    fn excessive_delta_chunk_count_is_refused_before_set_allocation() {
        let (manifest, mut request) = delta_fixture();
        request.missing_chunks.push(request.missing_chunks[0].clone());
        request.missing_bytes = 9;
        assert!(matches!(
            validate_request(&manifest, &request),
            Err(TransportError::Frame(message))
                if message == "delta ObjectRequest contains more chunks than the sender manifest"
        ));
    }

    // Scripted peers speak the existing JSON and binary protocol directly.
    // They deliberately do not call the Merkle negotiation helpers, so these
    // tests catch a new peer accidentally making an old peer opt in.
    mod merkle_interop {
        use super::*;
        use super::super::super::{
            ATP_TCP_PROTOCOL, Cx, Frame, FrameType, Hello, HelloAck, ManifestEntry,
            STAGING_SEQ, SendReport, TcpListener, data_frame, hex_encode, json_frame,
            parse_data_frame, parse_json, receive_once, send_path, transfer_id_hex,
        };
        use crate::bytes::BytesMut;
        use crate::codec::Decoder;
        use crate::net::atp::protocol::codec::AtpFrameCodec;
        use crate::net::atp::transport_common::{flat_merkle_root_from_slices, merkle};
        use crate::sync::atomic::Ordering;
        use sha2::{Digest, Sha256};
        use std::io::{Read, Write};
        use std::net::{Shutdown, SocketAddr};
        use std::path::PathBuf;
        use std::time::{Duration, Instant};

        const DEADLINE: Duration = Duration::from_secs(15);
        const PAYLOAD: &[u8] = b"ATP legacy interoperability\0with real file bytes\n";

        struct ScriptedPeer {
            stream: std::net::TcpStream,
            codec: AtpFrameCodec,
            buffered: BytesMut,
        }

        impl ScriptedPeer {
            fn new(stream: std::net::TcpStream) -> Self {
                stream.set_nonblocking(false).expect("blocking peer");
                stream
                    .set_read_timeout(Some(DEADLINE))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(DEADLINE))
                    .expect("write timeout");
                Self {
                    stream,
                    codec: AtpFrameCodec::new(),
                    buffered: BytesMut::new(),
                }
            }

            fn recv(&mut self) -> Frame {
                loop {
                    if let Some(frame) =
                        self.codec.decode(&mut self.buffered).expect("decode frame")
                    {
                        return frame;
                    }
                    let mut bytes = [0_u8; 4096];
                    let count = self.stream.read(&mut bytes).expect("read peer frame");
                    assert_ne!(count, 0, "peer closed before its next frame");
                    self.buffered.extend_from_slice(&bytes[..count]);
                }
            }

            fn send(&mut self, frame: &Frame) {
                self.stream
                    .write_all(&frame.to_wire_bytes().expect("encode frame"))
                    .expect("write peer frame");
            }

            fn finish(mut self) {
                // Keep the read half alive until the real sender consumes its
                // receipt and closes, including when receipt validation fails.
                let _ = self.stream.shutdown(Shutdown::Write);
                let mut tail = [0_u8; 256];
                while matches!(self.stream.read(&mut tail), Ok(count) if count != 0) {}
            }
        }

        fn scratch_root(label: &str) -> PathBuf {
            let root = std::env::temp_dir().join(format!(
                "atp-merkle-{label}-{}-{}",
                std::process::id(),
                STAGING_SEQ.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir_all(&root).expect("create test directory");
            root.canonicalize().expect("canonical test directory")
        }

        fn config() -> TransferConfig {
            TransferConfig {
                chunk_size: 17,
                enable_delta: false,
                idle_timeout: DEADLINE,
                accept_timeout: DEADLINE,
                ..TransferConfig::default()
            }
        }

        #[derive(Clone, Copy)]
        enum ProofMode {
            Legacy,
            Missing,
            Truncated,
            Wrong,
        }

        fn new_sender_to_scripted_receiver(
            mode: ProofMode,
        ) -> Result<SendReport, TransportError> {
            let root = scratch_root("sender");
            let source = root.join("payload.bin");
            std::fs::write(&source, PAYLOAD).expect("source bytes");
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind old peer");
            let address = listener.local_addr().expect("old peer address");
            listener.set_nonblocking(true).expect("bounded accept");
            let receiver = std::thread::spawn(move || {
                let deadline = Instant::now() + DEADLINE;
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "sender never connected");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("accept sender: {error}"),
                    }
                };
                let mut peer = ScriptedPeer::new(stream);
                let hello_frame = peer.recv();
                assert_eq!(hello_frame.frame_type(), FrameType::Handshake);
                let hello: Hello = parse_json(&hello_frame).expect("legacy hello JSON");
                assert_eq!(hello.protocol, ATP_TCP_PROTOCOL);
                assert_eq!(
                    hello_frame
                        .header
                        .extensions
                        .get(&merkle::MERKLE_V2_OFFER_EXTENSION),
                    Some(&vec![1, 2]),
                );
                let mut ack = json_frame(
                    FrameType::HandshakeAck,
                    &HelloAck {
                        accepted: true,
                        peer_id: "scripted-receiver".into(),
                        reason: None,
                    },
                )
                .expect("legacy ack JSON");
                if !matches!(mode, ProofMode::Legacy) {
                    ack.header.extensions
                        .insert(merkle::MERKLE_V2_ACCEPT_EXTENSION, vec![1, 2]);
                }
                peer.send(&ack);

                let manifest_frame = peer.recv();
                assert_eq!(manifest_frame.frame_type(), FrameType::ObjectManifest);
                let manifest: TransferManifest =
                    parse_json(&manifest_frame).expect("legacy manifest JSON");
                let old_root = flat_merkle_root_from_slices([("payload.bin", PAYLOAD)]);
                assert_eq!(manifest.merkle_root_hex, old_root);
                assert_eq!(
                    manifest.transfer_id,
                    transfer_id_hex(&old_root, PAYLOAD.len() as u64, 1),
                );
                let v2_record = manifest_frame
                    .header
                    .extensions
                    .get(&merkle::MERKLE_V2_ROOT_EXTENSION);
                if matches!(mode, ProofMode::Legacy) {
                    assert!(
                        v2_record.is_none(),
                        "unaccepted v2 root reached an old receiver",
                    );
                } else {
                    let record = v2_record.expect("negotiated manifest commitment");
                    assert_eq!(record.len(), 34);
                    assert_eq!(&record[..2], &[1, 2]);
                }
                peer.send(
                    &json_frame(FrameType::ObjectRequest, &full_request(&manifest))
                        .expect("request"),
                );

                let mut received = Vec::new();
                loop {
                    let frame = peer.recv();
                    if frame.frame_type() == FrameType::ObjectComplete {
                        break;
                    }
                    assert_eq!(frame.frame_type(), FrameType::ObjectData);
                    let (index, offset, bytes) =
                        parse_data_frame(&frame).expect("legacy raw data");
                    assert_eq!(index, 0);
                    assert_eq!(offset, received.len() as u64);
                    received.extend_from_slice(bytes);
                }
                assert_eq!(received, PAYLOAD);
                let mut success = receipt();
                success.bytes_received = received.len() as u64;
                success.files = 1;
                let mut proof =
                    json_frame(FrameType::Proof, &success).expect("legacy proof JSON");
                match mode {
                    ProofMode::Legacy | ProofMode::Missing => {}
                    ProofMode::Truncated => {
                        proof.header.extensions
                            .insert(merkle::MERKLE_V2_ROOT_EXTENSION, vec![1, 2, 0]);
                    }
                    ProofMode::Wrong => {
                        let mut record = v2_record.expect("v2 manifest root").clone();
                        record[2] ^= 1;
                        proof.header.extensions
                            .insert(merkle::MERKLE_V2_ROOT_EXTENSION, record);
                    }
                }
                peer.send(&proof);
                peer.finish();
            });

            let runtime = crate::runtime::RuntimeBuilder::multi_thread()
                .build()
                .expect("sender runtime");
            let sent = runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("sender context");
                send_path(&cx, address, &source, config(), "new-sender").await
            }));
            receiver.join().expect("scripted receiver");
            std::fs::remove_dir_all(&root).expect("remove sender scratch");
            sent
        }

        #[test]
        fn new_sender_interoperates_with_legacy_receiver_without_v2_extensions() {
            let sent =
                new_sender_to_scripted_receiver(ProofMode::Legacy).expect("legacy transfer");
            assert!(sent.receipt.committed);
            assert_eq!(sent.bytes_sent, PAYLOAD.len() as u64);
            assert_eq!(sent.files, 1);
        }

        #[test]
        fn negotiated_sender_rejects_missing_malformed_and_wrong_v2_proof() {
            for mode in [ProofMode::Missing, ProofMode::Truncated, ProofMode::Wrong] {
                let result = new_sender_to_scripted_receiver(mode);
                match mode {
                    ProofMode::Missing | ProofMode::Truncated => {
                        assert!(matches!(result, Err(TransportError::Frame(_))));
                    }
                    ProofMode::Wrong => {
                        assert!(matches!(result, Err(TransportError::Integrity(_))));
                    }
                    ProofMode::Legacy => unreachable!(),
                }
            }
        }

        #[test]
        fn legacy_sender_interoperates_with_new_receiver_without_v2_extensions() {
            let root = scratch_root("receiver");
            let destination = root.join("inbox");
            std::fs::create_dir_all(&destination).expect("destination");
            let old_root = flat_merkle_root_from_slices([("payload.bin", PAYLOAD)]);
            let old_transfer_id = transfer_id_hex(&old_root, PAYLOAD.len() as u64, 1);
            let expected_id = old_transfer_id.clone();
            let (address_tx, address_rx) = std::sync::mpsc::channel::<SocketAddr>();
            let sender = std::thread::spawn(move || {
                let address = address_rx
                    .recv_timeout(DEADLINE)
                    .expect("new receiver address");
                let mut peer = ScriptedPeer::new(
                    std::net::TcpStream::connect_timeout(&address, DEADLINE)
                        .expect("connect new receiver"),
                );
                peer.send(
                    &json_frame(
                        FrameType::Handshake,
                        &Hello {
                            protocol: ATP_TCP_PROTOCOL,
                            role: "sender".into(),
                            peer_id: "old-sender".into(),
                        },
                    )
                    .expect("old hello"),
                );
                let ack = peer.recv();
                assert_eq!(ack.frame_type(), FrameType::HandshakeAck);
                assert!(parse_json::<HelloAck>(&ack).expect("ack JSON").accepted);
                assert!(
                    !ack.header
                        .extensions
                        .contains_key(&merkle::MERKLE_V2_ACCEPT_EXTENSION),
                );

                let manifest = TransferManifest {
                    transfer_id: old_transfer_id,
                    root_name: "payload.bin".into(),
                    is_directory: false,
                    total_bytes: PAYLOAD.len() as u64,
                    merkle_root_hex: old_root,
                    metadata_root_hex: None,
                    directory_metadata: None,
                    entries: vec![ManifestEntry {
                        index: 0,
                        rel_path: "payload.bin".into(),
                        size: PAYLOAD.len() as u64,
                        sha256_hex: hex_encode(&Sha256::digest(PAYLOAD)),
                        metadata: None,
                        members: Vec::new(),
                    }],
                    delta_manifest: None,
                };
                peer.send(
                    &json_frame(FrameType::ObjectManifest, &manifest).expect("old manifest"),
                );
                let request_frame = peer.recv();
                assert_eq!(request_frame.frame_type(), FrameType::ObjectRequest);
                let request: DeltaObjectRequest =
                    parse_json(&request_frame).expect("old request JSON");
                assert_eq!(request.mode, DeltaWireMode::FullObject);
                assert_eq!(request.sender_merkle_root_hex, "");
                peer.send(&data_frame(0, 0, PAYLOAD).expect("old data"));
                peer.send(
                    &Frame::empty(FrameType::ObjectComplete).expect("old completion"),
                );
                let proof = peer.recv();
                assert_eq!(proof.frame_type(), FrameType::Proof);
                assert!(
                    !proof.header
                        .extensions
                        .contains_key(&merkle::MERKLE_V2_ROOT_EXTENSION),
                );
                let received: ReceiveReceipt = parse_json(&proof).expect("old proof JSON");
                assert!(received.committed && received.sha_ok && received.merkle_ok);
                assert_eq!(received.bytes_received, PAYLOAD.len() as u64);
                assert_eq!(received.files, 1);
            });
            let dest = destination.clone();
            let runtime = crate::runtime::RuntimeBuilder::multi_thread()
                .build()
                .expect("receiver runtime");
            let received = runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("receiver context");
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind new receiver");
                address_tx
                    .send(listener.local_addr().expect("receiver address"))
                    .expect("publish address");
                receive_once(&cx, &listener, &dest, config(), "new-receiver").await
            }));
            sender.join().expect("scripted sender");
            let received = received.expect("legacy transfer");
            assert!(received.committed);
            assert_eq!(received.transfer_id, expected_id);
            assert_eq!(
                std::fs::read(destination.join("payload.bin")).expect("committed file"),
                PAYLOAD,
            );
            std::fs::remove_dir_all(&root).expect("remove receiver scratch");
        }
    }
