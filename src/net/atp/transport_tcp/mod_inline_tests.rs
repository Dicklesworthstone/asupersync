    use super::*;

    /// Test scratch dir whose path has no symlinked ancestors.
    ///
    /// macOS `$TMPDIR` lives under `/var`, and `/var -> /private/var` is an
    /// OS-level symlink. The ATP destination traversal defense correctly
    /// rejects any symlinked ancestor, so scratch roots are canonicalized
    /// before paths are handed to transfers.
    fn canonical_test_root(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "{}-{}-{}",
            name,
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create test root");
        base.canonicalize().expect("canonicalize test root")
    }

    #[test]
    fn content_delta_accepts_only_ordinary_windows_file_attributes() {
        for attributes in [None, Some(0), Some(0x0000_0020)] {
            assert!(metadata_is_content_delta_compatible(&EntryMetadata {
                windows_attributes: attributes,
                ..EntryMetadata::default()
            }));
        }

        for attributes in [0x0000_0001, 0x0000_0002, 0x0000_0004, 0x0000_2000] {
            assert!(!metadata_is_content_delta_compatible(&EntryMetadata {
                windows_attributes: Some(attributes),
                ..EntryMetadata::default()
            }));
        }
    }

    #[test]
    fn content_delta_accepts_committed_regular_file_metadata() {
        assert!(metadata_is_content_delta_compatible(&EntryMetadata {
            unix_mode: Some(0o644),
            mtime_unix_secs: Some(1),
            mtime_nanos: Some(2),
            uid: Some(1000),
            gid: Some(1000),
            ..EntryMetadata::default()
        }));
    }

    #[test]
    fn content_delta_rejects_structural_or_unreplayed_metadata() {
        assert!(!metadata_is_content_delta_compatible(&EntryMetadata {
            xattrs: BTreeMap::from([("user.test".to_string(), b"value".to_vec())]),
            ..EntryMetadata::default()
        }));
        assert!(!metadata_is_content_delta_compatible(&EntryMetadata {
            hardlink_target: Some("primary.bin".to_string()),
            ..EntryMetadata::default()
        }));
        assert!(!metadata_is_content_delta_compatible(&EntryMetadata {
            file_kind: FileKind::Symlink,
            symlink_target: Some("target.bin".to_string()),
            ..EntryMetadata::default()
        }));
    }

    #[test]
    fn unchanged_content_requires_receiver_metadata_to_match_sender() {
        let expected = EntryMetadata {
            mtime_unix_secs: Some(10),
            mtime_nanos: Some(20),
            windows_attributes: Some(0x0000_0020),
            ..EntryMetadata::default()
        };
        let entries = vec![ManifestEntry {
            index: 0,
            rel_path: "payload.bin".to_string(),
            size: 0,
            sha256_hex: hex_encode(&Sha256::digest([])),
            metadata: Some(expected.clone()),
            members: Vec::new(),
        }];
        let matching = BTreeMap::from([("payload.bin".to_string(), expected.clone())]);
        assert!(receiver_metadata_matches_sender(&entries, &matching));

        let mut changed = expected;
        changed.mtime_nanos = Some(21);
        let mismatched = BTreeMap::from([("payload.bin".to_string(), changed)]);
        assert!(!receiver_metadata_matches_sender(&entries, &mismatched));
    }

    #[cfg(windows)]
    #[test]
    fn delta_metadata_comparison_ignores_unmaterializable_unix_fields_on_windows() {
        let expected = EntryMetadata {
            unix_mode: Some(0o640),
            uid: Some(1000),
            gid: Some(1000),
            ..EntryMetadata::default()
        };
        let observed = EntryMetadata {
            windows_attributes: Some(0x0000_0020),
            ..EntryMetadata::default()
        };
        assert!(receiver_materializable_metadata_matches(
            &expected, &observed
        ));

        let expected_directories = DirectoryMetadataManifest {
            root: Some(EntryMetadata {
                file_kind: FileKind::Directory,
                unix_mode: Some(0o750),
                ..EntryMetadata::default()
            }),
            entries: Vec::new(),
        };
        assert!(receiver_directory_metadata_matches_sender(
            Some(&expected_directories),
            None
        ));
    }

    #[cfg(unix)]
    #[test]
    fn delta_metadata_comparison_ignores_unmaterializable_windows_fields_on_unix() {
        let expected = EntryMetadata {
            windows_attributes: Some(0x0000_0020),
            ..EntryMetadata::default()
        };
        let observed = EntryMetadata {
            unix_mode: Some(0o640),
            uid: Some(1000),
            gid: Some(1000),
            ..EntryMetadata::default()
        };
        assert!(receiver_materializable_metadata_matches(
            &expected, &observed
        ));

        let expected_directories = DirectoryMetadataManifest {
            root: Some(EntryMetadata {
                file_kind: FileKind::Directory,
                windows_attributes: Some(0x0000_0002),
                ..EntryMetadata::default()
            }),
            entries: Vec::new(),
        };
        assert!(receiver_directory_metadata_matches_sender(
            Some(&expected_directories),
            None
        ));
    }

    #[test]
    fn flat_graph_is_deterministic_and_order_independent() {
        let a = vec![
            ("a.txt".to_string(), b"alpha".to_vec()),
            ("b.txt".to_string(), b"bravo".to_vec()),
        ];
        let b = vec![
            ("b.txt".to_string(), b"bravo".to_vec()),
            ("a.txt".to_string(), b"alpha".to_vec()),
        ];
        let (_, ra) = build_flat_graph(&a);
        let (_, rb) = build_flat_graph(&b);
        assert_eq!(ra, rb, "merkle root must be independent of entry order");
        assert_eq!(ra.len(), 64, "sha-256 hex root is 64 chars");
    }

    #[test]
    fn borrowed_flat_merkle_root_matches_owned_graph_with_duplicate_content() {
        let entries = vec![
            ("b.txt".to_string(), b"same".to_vec()),
            ("a.txt".to_string(), b"same".to_vec()),
            ("c.txt".to_string(), b"different".to_vec()),
        ];
        let borrowed_root = flat_merkle_root_from_slices(
            entries
                .iter()
                .map(|(rel_path, bytes)| (rel_path.as_str(), bytes.as_slice())),
        );
        let (_, owned_root) = build_flat_graph(&entries);
        assert_eq!(
            borrowed_root, owned_root,
            "borrowed receive-side hashing must preserve the owned ObjectGraph contract"
        );
    }

    #[test]
    fn flat_graph_detects_content_change() {
        let a = vec![("x".to_string(), b"one".to_vec())];
        let b = vec![("x".to_string(), b"two".to_vec())];
        assert_ne!(build_flat_graph(&a).1, build_flat_graph(&b).1);
    }

    #[test]
    fn flat_graph_detects_path_change() {
        let a = vec![("x".to_string(), b"same".to_vec())];
        let b = vec![("y".to_string(), b"same".to_vec())];
        assert_ne!(build_flat_graph(&a).1, build_flat_graph(&b).1);
    }

    #[test]
    fn data_frame_roundtrips() {
        let frame = data_frame(7, 256, b"payload-bytes").unwrap();
        let (index, offset, chunk) = parse_data_frame(&frame).unwrap();
        assert_eq!(index, 7);
        assert_eq!(offset, 256);
        assert_eq!(chunk, b"payload-bytes");
    }

    #[test]
    fn data_frame_rejects_short_header() {
        let frame = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectData,
            vec![0, 1, 2],
        )
        .unwrap();
        assert!(parse_data_frame(&frame).is_err());
    }

    #[test]
    fn manifest_json_roundtrips() {
        let delta_manifest = DeltaManifestWire {
            schema: ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(),
            tree_id: "data".to_string(),
            chunk_size: 64 * 1024,
            total_size_bytes: 9,
            merkle_root_hex: "11".repeat(32),
            chunks: vec![DeltaChunkWire {
                index: 0,
                entry_index: 0,
                rel_path: "a/b.txt".to_string(),
                entry_offset: 0,
                stream_offset: 0,
                size_bytes: 9,
                content_id_hex: "22".repeat(32),
            }],
        };
        let manifest = TransferManifest {
            transfer_id: "abc".to_string(),
            root_name: "data".to_string(),
            is_directory: true,
            total_bytes: 9,
            merkle_root_hex: "00".repeat(32),
            metadata_root_hex: None,
            directory_metadata: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a/b.txt".to_string(),
                size: 9,
                sha256_hex: "ff".repeat(32),
                metadata: None,
                members: Vec::new(),
            }],
            delta_manifest: Some(delta_manifest),
        };
        let json = serde_json::to_vec(&manifest).unwrap();
        assert!(
            !String::from_utf8_lossy(&json).contains("directory_metadata"),
            "absent directory metadata must preserve the legacy wire shape"
        );
        let back: TransferManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn delta_object_request_uses_live_tcp_object_request_frame() {
        let request = DeltaObjectRequest {
            mode: DeltaWireMode::AlreadyInSync,
            fallback_reason: None,
            sender_merkle_root_hex: "33".repeat(32),
            receiver_merkle_root_hex: Some("44".repeat(32)),
            missing_bytes: 0,
            shared_chunks: 1,
            stale_chunks: 0,
            missing_chunks: Vec::new(),
        };

        let frame = json_frame(FrameType::ObjectRequest, &request).expect("frame delta request");
        assert_eq!(frame.frame_type(), FrameType::ObjectRequest);
        let decoded: DeltaObjectRequest = parse_json(&frame).expect("parse delta request frame");
        assert_eq!(decoded, request);
    }

    #[test]
    fn json_frame_rejects_oversized_manifest_with_actionable_error() {
        let manifest = TransferManifest {
            transfer_id: "abc".to_string(),
            root_name: "x".repeat(usize::try_from(MAX_FRAME_SIZE).unwrap()),
            is_directory: true,
            total_bytes: 0,
            merkle_root_hex: "00".repeat(32),
            metadata_root_hex: None,
            directory_metadata: None,
            entries: Vec::new(),
            delta_manifest: None,
        };
        assert!(matches!(
            json_frame(FrameType::ObjectManifest, &manifest),
            Err(TransportError::Frame(msg))
                if msg.contains("ObjectManifest")
                    && msg.contains("split or chunk")
                    && msg.contains("max")
        ));
    }

    #[test]
    fn transfer_config_defaults_bound_accept_and_idle_waits() {
        let cfg = TransferConfig::default();
        assert_eq!(cfg.idle_timeout, DEFAULT_IDLE_TIMEOUT);
        assert_eq!(cfg.accept_timeout, DEFAULT_ACCEPT_TIMEOUT);
        assert_eq!(cfg.max_active_connections, DEFAULT_MAX_ACTIVE_CONNECTIONS);
        assert!(!cfg.idle_timeout.is_zero());
        assert!(!cfg.accept_timeout.is_zero());
        assert!(cfg.max_active_connections > 0);
    }

    #[test]
    fn timeout_error_names_operation_and_duration() {
        let err = TransportError::Timeout {
            operation: "receive frame",
            timeout: Duration::from_secs(60),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("receive frame"));
        assert!(rendered.contains("60s"));
    }

    #[test]
    fn send_path_rejects_zero_idle_timeout_before_connecting() {
        let cx = Cx::for_testing();
        let cfg = TransferConfig {
            idle_timeout: Duration::ZERO,
            ..TransferConfig::default()
        };
        let addr = "127.0.0.1:9".parse().unwrap();
        let result =
            futures_lite::future::block_on(send_path(&cx, addr, Path::new(file!()), cfg, "sender"));

        assert!(matches!(
            result,
            Err(TransportError::Timeout {
                operation: "connect",
                timeout,
            }) if timeout.is_zero()
        ));
    }

    #[test]
    fn receive_task_join_error_preserves_cancellation() {
        let err = receive_task_join_error(crate::runtime::JoinError::Cancelled(
            crate::types::CancelReason::parent_cancelled(),
        ));
        assert!(matches!(err, TransportError::Cancelled));
    }

    /// Passes a receive's reads and writes through to its TCP stream. Once
    /// `committed` exists in the destination, the receiver's next write is its
    /// receipt. Before passing that write through, the stream aborts the
    /// receive task the way `serve`'s stop path does. With `park_receipt`, the
    /// receipt write then never completes and registers no wakeup, like a
    /// socket whose peer has stopped reading.
    struct AbortAtReceipt {
        stream: TcpStream,
        committed: PathBuf,
        receive: std::sync::Arc<parking_lot::Mutex<Option<ReceiveTaskHandle>>>,
        receive_cx: Cx,
        aborted_before_receipt: std::sync::Arc<std::sync::atomic::AtomicBool>,
        park_receipt: bool,
    }

    impl crate::io::AsyncRead for AbortAtReceipt {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_read(task, buf)
        }
    }

    impl crate::io::AsyncWrite for AbortAtReceipt {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if !this.aborted_before_receipt.load(Ordering::Acquire) && this.committed.exists() {
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                loop {
                    if let Some(receive) = this.receive.lock().as_ref() {
                        receive.abort_with_reason(crate::types::CancelReason::parent_cancelled());
                        break;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the test never published the receive task's handle"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                this.aborted_before_receipt
                    .store(this.receive_cx.is_cancel_requested(), Ordering::Release);
            }
            if this.park_receipt && this.aborted_before_receipt.load(Ordering::Acquire) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut this.stream).poll_write(task, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(task)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(task)
        }
    }

    /// What [`stop_at_receipt`] observed.
    struct StoppedAtReceipt {
        joined: Result<Result<ReceiveReport, TransportError>, crate::runtime::JoinError>,
        aborted_before_receipt: bool,
        receive_time: Duration,
        sent: Result<SendReport, TransportError>,
        committed: PathBuf,
        payload: Vec<u8>,
    }

    /// A real sender (`send_path`) transfers one file over loopback TCP to a
    /// receive task whose stream is an [`AbortAtReceipt`], which aborts the task
    /// at its receipt (and, with `park_receipt`, never delivers it).
    fn stop_at_receipt(label: &str, park_receipt: bool) -> StoppedAtReceipt {
        const DEADLINE: Duration = Duration::from_secs(30);
        let root = canonical_test_root(label);
        let source = root.join("payload.bin");
        let payload: Vec<u8> = (0..70_001u32)
            .map(|index| u8::try_from(index % 251).expect("below 251"))
            .collect();
        std::fs::write(&source, &payload).expect("write the source file");
        let dest = root.join("inbox");
        std::fs::create_dir_all(&dest).expect("create the destination");
        let committed = dest.join("payload.bin");

        let (addr_tx, addr_rx) = std::sync::mpsc::channel::<SocketAddr>();
        let sender = std::thread::spawn(move || {
            let addr = addr_rx.recv_timeout(DEADLINE).expect("receiver address");
            let runtime = crate::runtime::RuntimeBuilder::multi_thread()
                .build()
                .expect("sender runtime");
            // A sender whose receipt never comes gives up after its idle
            // timeout, so keep that short of the test's deadline.
            let config = TransferConfig {
                idle_timeout: Duration::from_secs(10),
                ..TransferConfig::default()
            };
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("sender cx");
                send_path(&cx, addr, &source, config, "sender").await
            }))
        });

        let runtime = crate::runtime::RuntimeBuilder::multi_thread()
            .build()
            .expect("receiver runtime");
        let committed_path = committed.clone();
        let (joined, aborted_before_receipt, receive_time) =
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("receiver cx");
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                addr_tx
                    .send(listener.local_addr().expect("listener address"))
                    .expect("publish the listener address");
                let (stream, peer) =
                    with_transport_timeout(&cx, DEADLINE, "accept", listener.accept())
                        .await
                        .expect("accept the sender");
                let receive = std::sync::Arc::new(parking_lot::Mutex::new(None));
                let aborted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let receive_slot = std::sync::Arc::clone(&receive);
                let aborted_witness = std::sync::Arc::clone(&aborted);
                let handle = cx
                    .spawn(move |child| async move {
                        let stream = AbortAtReceipt {
                            stream,
                            committed: committed_path,
                            receive: receive_slot,
                            receive_cx: child.clone(),
                            aborted_before_receipt: aborted_witness,
                            park_receipt,
                        };
                        receive_on_transport(
                            &child,
                            FrameTransport::new(stream),
                            peer,
                            &dest,
                            TransferConfig::default(),
                            "receiver",
                        )
                        .await
                    })
                    .expect("spawn the receive task");
                let started = std::time::Instant::now();
                *receive.lock() = Some(handle);
                let deadline = started + DEADLINE;
                while !receive
                    .lock()
                    .as_ref()
                    .is_some_and(crate::runtime::TaskHandle::is_finished)
                {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the receive task did not finish within {DEADLINE:?}"
                    );
                    crate::time::sleep(cx.now(), Duration::from_millis(5)).await;
                }
                let receive_time = started.elapsed();
                let mut handle = receive.lock().take().expect("the receive task's handle");
                (
                    handle.join(&cx).await,
                    aborted.load(Ordering::Acquire),
                    receive_time,
                )
            }));
        let sent = sender.join().expect("sender thread");
        StoppedAtReceipt {
            joined,
            aborted_before_receipt,
            receive_time,
            sent,
            committed,
            payload,
        }
    }

    /// A stop (the receive task's abort, as `serve` issues it) that lands after
    /// the files are committed must not turn the transfer into a failure on
    /// both sides: the receipt still reaches the sender, and joining the
    /// receive task yields the committed report.
    #[test]
    fn a_stop_after_the_commit_still_sends_the_receipt_and_reports_the_transfer() {
        let run = stop_at_receipt("atp-tcp-stop-at-receipt", false);
        assert!(
            run.aborted_before_receipt,
            "the receive task must be aborted after its commit and before its receipt"
        );
        let report = match run.joined {
            Ok(Ok(report)) => report,
            other => panic!("the receive committed its files, so it must report them: {other:?}"),
        };
        assert!(report.committed);
        assert_eq!(report.committed_paths, vec![run.committed.clone()]);
        let sent = run.sent.expect("the sender holds the receiver's receipt");
        assert!(sent.receipt.committed);
        assert_eq!(
            std::fs::read(&run.committed).expect("read the committed file"),
            run.payload
        );
    }

    /// The receipt is sent with the stop held off, but a peer that has stopped
    /// reading must not hold the stop for an idle_timeout (60 s by default) per
    /// frame. The receive ends RECEIPT_STOP_GRACE after the stop, as cancelled;
    /// its files stay committed.
    #[test]
    fn a_stop_ends_a_receipt_the_peer_does_not_read_after_the_grace() {
        let run = stop_at_receipt("atp-tcp-stop-at-unread-receipt", true);
        assert!(
            run.aborted_before_receipt,
            "the receive task must be aborted after its commit and before its receipt"
        );
        assert!(
            run.receive_time < RECEIPT_STOP_GRACE + Duration::from_secs(8),
            "a stop waited {:?} for an unread receipt",
            run.receive_time
        );
        assert!(
            matches!(
                run.joined,
                Ok(Err(TransportError::Cancelled)) | Err(crate::runtime::JoinError::Cancelled(_))
            ),
            "an undelivered receipt must end the receive as cancelled: {:?}",
            run.joined
        );
        assert!(
            run.sent.is_err(),
            "the sender never received the receipt: {:?}",
            run.sent
        );
        assert_eq!(
            std::fs::read(&run.committed).expect("read the committed file"),
            run.payload
        );
    }

    /// Passes a receive's reads and writes through to its TCP stream and
    /// counts the bytes read: what actually crossed the wire to the receiver.
    #[cfg(feature = "zstd")]
    struct CountingStream {
        stream: TcpStream,
        read: std::sync::Arc<AtomicU64>,
    }

    #[cfg(feature = "zstd")]
    impl crate::io::AsyncRead for CountingStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let before = buf.filled().len();
            let polled = std::pin::Pin::new(&mut this.stream).poll_read(task, buf);
            let read = (buf.filled().len() - before) as u64;
            this.read.fetch_add(read, Ordering::AcqRel);
            polled
        }
    }

    #[cfg(feature = "zstd")]
    impl crate::io::AsyncWrite for CountingStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_write(task, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(task)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(task)
        }
    }

    /// What [`transfer_with_options`] observed.
    #[cfg(feature = "zstd")]
    struct OptionsTransfer {
        sent: Result<SendReport, TransportError>,
        received: Result<ReceiveReport, TransportError>,
        /// Bytes the receiver read off the socket.
        wire_bytes: u64,
        /// The committed file's bytes (empty if it is missing).
        committed: Vec<u8>,
    }

    /// Rewrites one data frame on its way to the receiver.
    #[cfg(feature = "zstd")]
    type Tamper = Box<dyn FnOnce(Frame) -> Frame + Send>;

    /// Hands a receive the frames read from `stream`, with the first data
    /// frame replaced by `tamper`'s: a sender that turns hostile once the
    /// handshake is over.
    #[cfg(feature = "zstd")]
    struct TamperingStream<S> {
        stream: S,
        codec: AtpFrameCodec,
        incoming: BytesMut,
        outgoing: Vec<u8>,
        served: usize,
        tamper: Option<Tamper>,
    }

    #[cfg(feature = "zstd")]
    impl<S: crate::io::AsyncRead + Unpin> crate::io::AsyncRead for TamperingStream<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            loop {
                if this.served < this.outgoing.len() {
                    let count = buf.remaining().min(this.outgoing.len() - this.served);
                    buf.put_slice(&this.outgoing[this.served..this.served + count]);
                    this.served += count;
                    return std::task::Poll::Ready(Ok(()));
                }
                this.outgoing.clear();
                this.served = 0;
                while let Some(mut frame) = this
                    .codec
                    .decode(&mut this.incoming)
                    .map_err(|error| std::io::Error::other(error.to_string()))?
                {
                    if frame.frame_type() == FrameType::ObjectData
                        && let Some(tamper) = this.tamper.take()
                    {
                        frame = tamper(frame);
                    }
                    let bytes = frame
                        .to_wire_bytes()
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    this.outgoing.extend_from_slice(&bytes);
                }
                if !this.outgoing.is_empty() {
                    continue;
                }
                let mut bytes = [0_u8; 16 * 1024];
                let mut read = crate::io::ReadBuf::new(&mut bytes);
                match std::pin::Pin::new(&mut this.stream).poll_read(task, &mut read) {
                    std::task::Poll::Ready(Ok(())) if read.filled().is_empty() => {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    std::task::Poll::Ready(Ok(())) => {
                        this.incoming.extend_from_slice(read.filled());
                    }
                    other => return other,
                }
            }
        }
    }

    #[cfg(feature = "zstd")]
    impl<S: crate::io::AsyncWrite + Unpin> crate::io::AsyncWrite for TamperingStream<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_write(task, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(task)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            task: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(task)
        }
    }

    /// A real sender (`send_path_with_options`) transfers `payload` as
    /// `<root>/payload.bin` over loopback TCP to `receive_on_transport`
    /// committing into `<root>/inbox`. `receiver_decode` replaces what the
    /// receiver can decode; an empty capability makes it behave like a
    /// receiver that predates compression, which never answers an offer.
    #[cfg(feature = "zstd")]
    fn transfer_with_options(
        root: &Path,
        payload: &[u8],
        options: SendOptions,
        receiver_decode: Option<DecodeCapability>,
    ) -> OptionsTransfer {
        transfer_through(root, payload, options, receiver_decode, None)
    }

    /// [`transfer_with_options`], with the sender's first data frame
    /// rewritten by `tamper` on its way to the receiver.
    #[cfg(feature = "zstd")]
    fn transfer_through(
        root: &Path,
        payload: &[u8],
        options: SendOptions,
        receiver_decode: Option<DecodeCapability>,
        tamper: Option<Tamper>,
    ) -> OptionsTransfer {
        let source = root.join("payload.bin");
        std::fs::write(&source, payload).expect("write the source file");
        let dest = root.join("inbox");
        std::fs::create_dir_all(&dest).expect("create the destination");
        let (sent, received, wire_bytes, _) =
            run_options_transfer(source, &dest, options, receiver_decode, tamper);
        OptionsTransfer {
            sent,
            received,
            wire_bytes,
            committed: std::fs::read(dest.join("payload.bin")).unwrap_or_default(),
        }
    }

    /// One transfer of `source` (a file or a directory) into `dest` over real
    /// TCP: the sender result, the receiver result, the bytes the receiver
    /// read off the socket, and every progress tick the sender reported.
    #[cfg(feature = "zstd")]
    fn run_options_transfer(
        source: std::path::PathBuf,
        dest: &Path,
        options: SendOptions,
        receiver_decode: Option<DecodeCapability>,
        tamper: Option<Tamper>,
    ) -> (
        Result<SendReport, TransportError>,
        Result<ReceiveReport, TransportError>,
        u64,
        Vec<(u64, u64)>,
    ) {
        const DEADLINE: Duration = Duration::from_secs(60);
        let ticks = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender_ticks = std::sync::Arc::clone(&ticks);
        let (addr_tx, addr_rx) = std::sync::mpsc::channel::<SocketAddr>();
        let sender = std::thread::spawn(move || {
            let addr = addr_rx.recv_timeout(DEADLINE).expect("receiver address");
            let runtime = crate::runtime::RuntimeBuilder::multi_thread()
                .build()
                .expect("sender runtime");
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("sender cx");
                send_path_with_options(
                    &cx,
                    addr,
                    &source,
                    TransferConfig::default(),
                    "sender",
                    &FilterSet::new(),
                    options,
                    move |sent, total| {
                        sender_ticks
                            .lock()
                            .expect("progress ticks")
                            .push((sent, total));
                    },
                )
                .await
            }))
        });

        let wire = std::sync::Arc::new(AtomicU64::new(0));
        let read = std::sync::Arc::clone(&wire);
        let dest_dir = dest.to_path_buf();
        let runtime = crate::runtime::RuntimeBuilder::multi_thread()
            .build()
            .expect("receiver runtime");
        let received = runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("receiver cx");
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            addr_tx
                .send(listener.local_addr().expect("listener address"))
                .expect("publish the listener address");
            let (stream, peer) = with_transport_timeout(&cx, DEADLINE, "accept", listener.accept())
                .await
                .expect("accept the sender");
            let counting = CountingStream { stream, read };
            if let Some(tamper) = tamper {
                let transport = FrameTransport::new(TamperingStream {
                    stream: counting,
                    codec: AtpFrameCodec::new(),
                    incoming: BytesMut::new(),
                    outgoing: Vec::new(),
                    served: 0,
                    tamper: Some(tamper),
                });
                return receive_on_transport(
                    &cx,
                    transport,
                    peer,
                    &dest_dir,
                    TransferConfig::default(),
                    "receiver",
                )
                .await;
            }
            let mut transport = FrameTransport::new(counting);
            if let Some(decode) = receiver_decode {
                transport.decode = decode;
            }
            receive_on_transport(
                &cx,
                transport,
                peer,
                &dest_dir,
                TransferConfig::default(),
                "receiver",
            )
            .await
        }));
        let sent = sender.join().expect("sender thread");
        let ticks = ticks.lock().expect("progress ticks").clone();
        (sent, received, wire.load(Ordering::Acquire), ticks)
    }

    /// Text-like bytes: words from a small vocabulary, several chunks long.
    #[cfg(feature = "zstd")]
    fn compressible_payload(seed: u64, len: usize) -> Vec<u8> {
        const WORDS: [&str; 8] = [
            "region ",
            "obligation ",
            "cancel ",
            "scope ",
            "budget ",
            "trace ",
            "join ",
            "spawn\n",
        ];
        let mut state = seed;
        let mut out = Vec::with_capacity(len + 16);
        while out.len() < len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            out.extend_from_slice(WORDS[usize::try_from(state >> 61).expect("3 bits")].as_bytes());
        }
        out.truncate(len);
        out
    }

    #[cfg(feature = "zstd")]
    fn assert_delivered(run: &OptionsTransfer, payload: &[u8], what: &str) {
        assert!(
            run.sent.is_ok(),
            "{what}: sender failed: {:?}",
            run.sent.as_ref().err()
        );
        assert!(
            run.received.is_ok(),
            "{what}: receiver failed: {:?}",
            run.received.as_ref().err()
        );
        assert!(
            run.committed == payload,
            "{what}: committed bytes differ from the source"
        );
    }

    /// The receive path refuses a compressed chunk on a session that
    /// negotiated no codec, before decoding anything, and passes an
    /// unmarked payload through untouched.
    #[test]
    fn a_compressed_chunk_without_a_negotiated_codec_is_refused() {
        let mut frame = data_frame(0, 0, b"not really compressed").expect("data frame");
        let mut scratch = Vec::new();
        let (_, _, payload) = parse_data_frame(&frame).expect("parse");
        assert_eq!(
            raw_chunk(&frame, None, 100, payload, &mut scratch).expect("raw payload"),
            b"not really compressed"
        );
        frame.header.extensions.insert(
            codec::CHUNK_CODEC_EXTENSION,
            codec::ChunkCodec::new(codec::WireCodec::Zstd, 21).to_bytes(),
        );
        let (_, _, payload) = parse_data_frame(&frame).expect("parse");
        let refused = raw_chunk(&frame, None, 100, payload, &mut scratch);
        assert!(
            matches!(&refused, Err(TransportError::Frame(message)) if message.contains("without a negotiated codec")),
            "{refused:?}"
        );
        assert!(scratch.is_empty(), "nothing was decoded");
    }

    /// A compressed data frame is never larger on the wire than the raw frame
    /// for the same chunk, whatever the chunk's size and compressibility, so
    /// a chunk that fits a frame raw also fits compressed.
    #[cfg(feature = "zstd")]
    #[test]
    fn a_compressed_frame_is_never_larger_than_the_raw_frame() {
        let offer = codec::local_offer(CompressionMode::Zstd, DEFAULT_CHUNK_SIZE).unwrap();
        let accept = codec::negotiate(
            &codec::local_decode_capability(MAX_COMPRESSED_CHUNK_RAW),
            &offer,
        )
        .unwrap();
        let mut state = 3_u64;
        let mut compressed_frames = 0;
        for len in [1_usize, 16, 17, 30, 64, 100, 300, 1000, 5000, 70_000] {
            for noise_every in [1_usize, 2, 7, 64, 1000] {
                let chunk: Vec<u8> = (0..len)
                    .map(|i| {
                        state = state
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        if i % noise_every == 0 {
                            state.to_be_bytes()[0]
                        } else {
                            u8::try_from(i % 7).unwrap()
                        }
                    })
                    .collect();
                let raw = data_frame(0, 0, &chunk).unwrap().to_wire_bytes().unwrap();
                let mut entry = EntryCompression::new(CompressionMode::Zstd, "chunk.bin");
                let frame = chunk_frame(Some(&accept), &mut entry, 0, 0, &chunk).unwrap();
                if frame
                    .header
                    .extensions
                    .contains_key(&codec::CHUNK_CODEC_EXTENSION)
                {
                    compressed_frames += 1;
                }
                let framed = frame.to_wire_bytes().unwrap();
                assert!(
                    framed.len() <= raw.len(),
                    "len {len}, noise every {noise_every}: {} > {}",
                    framed.len(),
                    raw.len()
                );
            }
        }
        assert!(compressed_frames > 10, "some chunks were compressed");
    }

    /// Runs the sender's batched first pass (br-asupersync-dfdwyt) over
    /// `root`, as send_path_with_options does: the walk, the one-task
    /// metadata capture, then batched hashing.
    fn first_pass(
        root: &Path,
        config: &TransferConfig,
    ) -> (
        Vec<SourceEntry>,
        Vec<EntryMetadata>,
        Result<Vec<Option<ContentDigest>>, TransportError>,
    ) {
        crate::util::future::block_on(async {
            let cx = Cx::for_testing();
            let (_, _, entries) = collect_entries_with_policy(root, &config.metadata_policy)
                .await
                .expect("walk the tree");
            let metadatas = capture_entry_metadata(&cx, &entries, config)
                .await
                .expect("capture metadata");
            let mut buf = vec![0_u8; config.chunk_size.max(1)];
            let hashed = hash_content_entries(&cx, &entries, &metadatas, config, &mut buf).await;
            (entries, metadatas, hashed)
        })
    }

    /// The batched first pass gives every content entry the digest of its
    /// bytes, across both batch bounds (more than HASH_BATCH_FILES files, one
    /// file past HASH_BATCH_BYTES), and none to zero-content entries: a
    /// symlink and the second name of a hardlink (br-asupersync-dfdwyt).
    #[test]
    fn the_batched_first_pass_hashes_every_content_entry_once() {
        let root = canonical_test_root("atp-tcp-first-pass").join("tree");
        let mut files: Vec<(String, Vec<u8>)> = (0..150_usize)
            .map(|index| {
                let len = (index * 37) % 1_500;
                let bytes = (0..len)
                    .map(|byte| u8::try_from((byte * 31 + index) % 251).unwrap())
                    .collect();
                (format!("d{}/f{index:03}.bin", index % 4), bytes)
            })
            .collect();
        let big: Vec<u8> = (0..(9 << 20)).map(|byte| (byte % 253) as u8).collect();
        files.push(("big.bin".to_string(), big));
        for (rel, bytes) in &files {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
            std::fs::write(&path, bytes).expect("write a tree file");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("big.bin", root.join("link")).expect("symlink");
            std::fs::hard_link(root.join("d0/f000.bin"), root.join("zz_alias.bin"))
                .expect("hardlink");
        }
        let config = TransferConfig {
            preserve_hardlinks: true,
            ..TransferConfig::default()
        };
        let (entries, metadatas, hashed) = first_pass(&root, &config);
        let hashed = hashed.expect("hash the tree");
        let expected: std::collections::HashMap<&str, &Vec<u8>> = files
            .iter()
            .map(|(rel, bytes)| (rel.as_str(), bytes))
            .collect();
        let mut failures = Vec::new();
        for ((entry, metadata), digest) in entries.iter().zip(&metadatas).zip(&hashed) {
            let rel = entry.rel_path.as_str();
            match (expected.get(rel), digest) {
                (Some(bytes), Some((size, content_id, sha))) => {
                    let want_sha: [u8; 32] = Sha256::digest(bytes).into();
                    if *size != bytes.len() as u64
                        || *sha != want_sha
                        || *content_id != ObjectId::content(ContentId::from_bytes(bytes))
                    {
                        failures.push(format!("{rel}: wrong digest"));
                    }
                }
                (Some(_), None) => failures.push(format!("{rel}: not hashed")),
                (None, Some(_)) => failures.push(format!("{rel}: zero-content entry hashed")),
                (None, None) => {}
            }
            if rel == "zz_alias.bin" && metadata.hardlink_target.as_deref() != Some("d0/f000.bin") {
                failures.push(format!(
                    "{rel}: hardlink target {:?}",
                    metadata.hardlink_target
                ));
            }
        }
        let hashed_count = hashed.iter().filter(|digest| digest.is_some()).count();
        if hashed_count != files.len() {
            failures.push(format!(
                "{hashed_count} entries hashed for {} files",
                files.len()
            ));
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// The batched first pass refuses an oversized tree at the first file
    /// that takes the running total past max_transfer_bytes, with that total,
    /// as the per-file pass did. That file lies in the second hashing batch.
    #[test]
    fn the_batched_first_pass_refuses_an_oversized_tree_at_the_crossing_file() {
        let root = canonical_test_root("atp-tcp-first-pass-limit").join("tree");
        for index in 0..200_usize {
            let path = root.join(format!("f{index:03}.bin"));
            std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
            std::fs::write(&path, vec![7_u8; 600]).expect("write a file");
        }
        let config = TransferConfig {
            max_transfer_bytes: 600 * 100 + 1,
            ..TransferConfig::default()
        };
        let (_, _, hashed) = first_pass(&root, &config);
        assert!(
            matches!(
                hashed,
                Err(TransportError::TooLarge {
                    size: 60_600,
                    max: 60_001
                })
            ),
            "{hashed:?}"
        );
        // The pass opened exactly the files through the crossing one
        // (f000..=f100) and none after it.
        let mut opened: Vec<String> = FIRST_PASS_OPENS
            .lock()
            .expect("open log")
            .iter()
            .filter_map(|path| path.strip_prefix(&root).ok())
            .map(|rel| rel.to_string_lossy().into_owned())
            .collect();
        opened.sort();
        let expected: Vec<String> = (0..=100_usize)
            .map(|index| format!("f{index:03}.bin"))
            .collect();
        assert_eq!(opened, expected);
    }

    /// A first-pass hashing task reads at most HASH_BATCH_BYTES (plus one
    /// read) even inside one large file, and the next tasks resume that file
    /// where it stopped, so a dropped transfer stops reading within one task.
    /// The resumed digest equals a direct one (br-asupersync-dfdwyt).
    #[test]
    fn a_hashing_task_stops_inside_a_large_file_and_the_next_resumes_it() {
        use crate::net::atp::transport_common::streaming::SyncFileHash;

        let root = canonical_test_root("atp-tcp-first-pass-bound");
        std::fs::create_dir_all(&root).expect("create root");
        let large: Vec<u8> = (0..(20_usize << 20))
            .map(|byte| u8::try_from((byte * 7 + byte / 4099) % 251).unwrap())
            .collect();
        std::fs::write(root.join("large.bin"), &large).expect("write the large file");
        std::fs::write(root.join("small.bin"), b"small").expect("write the small file");
        let jobs = vec![(0, root.join("large.bin")), (1, root.join("small.bin"))];
        let mut buf = vec![0_u8; 1 << 20];

        let (done, next, open) =
            hash_task(&jobs, 0, None, &mut buf, 0, u64::MAX).expect("first task");
        assert!(done.is_empty(), "the first task finished a file: {done:?}");
        assert_eq!(next, 0, "the first task moved past the large file");
        let open: SyncFileHash = open.expect("the first task returns the large file open");
        let first_task_bytes = open.size();
        assert!(
            (HASH_BATCH_BYTES..=HASH_BATCH_BYTES + (1 << 20)).contains(&first_task_bytes),
            "the first task read {first_task_bytes} bytes"
        );

        let (mut digests, mut next, mut open) = (Vec::new(), next, Some(open));
        let mut tasks = 1;
        while next < jobs.len() {
            let (done, after, still_open) =
                hash_task(&jobs, next, open.take(), &mut buf, 0, u64::MAX).expect("next task");
            digests.extend(done);
            next = after;
            open = still_open;
            tasks += 1;
        }
        assert_eq!(
            tasks, 3,
            "20 MiB in 8 MiB tasks, the small file in the last"
        );
        let large_sha: [u8; 32] = Sha256::digest(&large).into();
        assert_eq!(
            digests,
            vec![
                (
                    0,
                    (
                        large.len() as u64,
                        ObjectId::content(ContentId::from_bytes(&large)),
                        large_sha,
                    ),
                ),
                (
                    1,
                    (
                        5,
                        ObjectId::content(ContentId::from_bytes(b"small")),
                        Sha256::digest(b"small").into(),
                    ),
                ),
            ]
        );
    }

    /// With the default options a sender makes no offer, so its handshake is
    /// byte-for-byte what senders before compression sent.
    #[test]
    fn default_send_options_make_no_offer() {
        assert_eq!(SendOptions::default(), SendOptions::new());
        assert_eq!(
            codec::local_offer(SendOptions::new().compression, DEFAULT_CHUNK_SIZE),
            None
        );
    }

    /// Compression end to end over real TCP: the same compressible file
    /// crosses the wire in a fraction of its size with zstd and in full
    /// without, and both commits are byte-identical (the receiver verified
    /// the raw SHA-256 and merkle root before committing).
    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_chunks_shrink_the_wire_and_commit_identical_bytes() {
        // Four full chunks and a short one: enough to cross chunk boundaries,
        // small enough that the unoptimized test build does not starve the
        // wall-clock-bounded tests running beside it.
        let payload = compressible_payload(1, 4 * DEFAULT_CHUNK_SIZE + 17);
        let zstd = transfer_with_options(
            &canonical_test_root("atp-tcp-zstd-on"),
            &payload,
            SendOptions::new().with_compression(CompressionMode::Zstd),
            None,
        );
        assert_delivered(&zstd, &payload, "zstd");
        let off = transfer_with_options(
            &canonical_test_root("atp-tcp-zstd-off"),
            &payload,
            SendOptions::new(),
            None,
        );
        assert_delivered(&off, &payload, "off");
        let len = payload.len() as u64;
        assert!(
            off.wire_bytes > len,
            "raw: {} wire bytes for {len}",
            off.wire_bytes
        );
        assert!(
            zstd.wire_bytes < len / 4,
            "zstd: {} wire bytes for {len}",
            zstd.wire_bytes
        );
    }

    /// A receiver that cannot decode (like one that predates compression)
    /// sends no accept, and a sender that offered zstd then sends every
    /// chunk raw.
    #[cfg(feature = "zstd")]
    #[test]
    fn a_receiver_without_a_codec_gets_raw_chunks() {
        let payload = compressible_payload(2, 300_000);
        let run = transfer_with_options(
            &canonical_test_root("atp-tcp-zstd-old-receiver"),
            &payload,
            SendOptions::new().with_compression(CompressionMode::Zstd),
            Some(DecodeCapability::new(0, 0, 0)),
        );
        assert_delivered(&run, &payload, "receiver without a codec");
        assert!(
            run.wire_bytes > payload.len() as u64,
            "{} wire bytes",
            run.wire_bytes
        );
    }

    /// Chunks that do not shrink go raw on a compressed session.
    #[cfg(feature = "zstd")]
    #[test]
    fn incompressible_chunks_go_raw_on_a_zstd_session() {
        let mut state = 9_u64;
        let payload: Vec<u8> = (0..300_000)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                state.to_be_bytes()[0]
            })
            .collect();
        let run = transfer_with_options(
            &canonical_test_root("atp-tcp-zstd-noise"),
            &payload,
            SendOptions::new().with_compression(CompressionMode::Zstd),
            None,
        );
        assert_delivered(&run, &payload, "noise");
        assert!(
            run.wire_bytes > payload.len() as u64,
            "{} wire bytes",
            run.wire_bytes
        );
    }

    /// Chunks compressed one at a time or four at a time on the blocking
    /// pool arrive the same: both runs of a multi-chunk file commit its exact
    /// bytes and cross the wire compressed (br-asupersync-t1fblr.25). Six
    /// chunks keep the unoptimized build's compression work small next to
    /// the wall-clock-bounded tests that run beside it.
    #[cfg(feature = "zstd")]
    #[test]
    fn parallel_compression_delivers_the_file_in_order() {
        let payload = compressible_payload(5, 5 * DEFAULT_CHUNK_SIZE + 333);
        let len = payload.len() as u64;
        for parallelism in [1, 4] {
            let run = transfer_with_options(
                &canonical_test_root(&format!("atp-tcp-zstd-parallel-{parallelism}")),
                &payload,
                SendOptions::new()
                    .with_compression(CompressionMode::Zstd)
                    .with_compression_parallelism(parallelism),
                None,
            );
            assert_delivered(&run, &payload, "parallel");
            assert!(
                run.wire_bytes < len / 4,
                "parallelism {parallelism}: {} wire bytes for {len}",
                run.wire_bytes
            );
        }
        assert_eq!(SendOptions::new().compression_parallelism, 4);
    }

    /// A tree of many small files, an empty one, noise and a multi-chunk
    /// file shares one compression pipeline across files: every file
    /// arrives byte-for-byte, the tree crosses compressed, and progress is
    /// still one tick per file, carrying that file's size, then the total
    /// (br-asupersync-t1fblr.25).
    #[cfg(feature = "zstd")]
    #[test]
    fn a_compressed_tree_arrives_whole_with_one_progress_tick_per_file() {
        let root = canonical_test_root("atp-tcp-zstd-tree");
        let tree = root.join("tree");
        let mut files: Vec<(String, Vec<u8>)> = (0..24_u64)
            .map(|seed| {
                let len = usize::try_from(3_000 + seed * 700).unwrap();
                (
                    format!("dir{}/file{seed:02}.txt", seed % 3),
                    compressible_payload(seed + 10, len),
                )
            })
            .collect();
        files.push(("empty.txt".to_string(), Vec::new()));
        let mut state = 17_u64;
        let noise = (0..20_000)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                state.to_be_bytes()[0]
            })
            .collect();
        files.push(("noise.bin".to_string(), noise));
        files.push((
            "big/log.txt".to_string(),
            compressible_payload(99, 2 * DEFAULT_CHUNK_SIZE + 77),
        ));
        for (rel, bytes) in &files {
            let path = tree.join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
            std::fs::write(&path, bytes).expect("write a tree file");
        }
        let dest = root.join("inbox");
        std::fs::create_dir_all(&dest).expect("create the destination");
        let (sent, received, wire, ticks) = run_options_transfer(
            tree,
            &dest,
            SendOptions::new()
                .with_compression(CompressionMode::Zstd)
                .with_compression_parallelism(4),
            None,
            None,
        );
        assert!(sent.is_ok(), "sender failed: {:?}", sent.err());
        assert!(received.is_ok(), "receiver failed: {:?}", received.err());
        for (rel, bytes) in &files {
            let committed = std::fs::read(dest.join("tree").join(rel)).expect("committed file");
            assert!(committed == *bytes, "{rel} differs");
        }
        let total: u64 = files.iter().map(|(_, bytes)| bytes.len() as u64).sum();
        assert!(wire < total / 2, "{wire} wire bytes for {total}");
        // One tick per file, each adding that file's size, then the total.
        assert_eq!(ticks.len(), files.len() + 1, "{ticks:?}");
        assert_eq!(ticks.last(), Some(&(total, total)));
        let mut steps: Vec<u64> = ticks[..files.len()]
            .iter()
            .scan(0, |previous, &(done, all)| {
                assert_eq!(all, total);
                assert!(done >= *previous, "progress went back: {ticks:?}");
                let step = done - *previous;
                *previous = done;
                Some(step)
            })
            .collect();
        let mut sizes: Vec<u64> = files.iter().map(|(_, bytes)| bytes.len() as u64).collect();
        steps.sort_unstable();
        sizes.sort_unstable();
        assert_eq!(steps, sizes);
    }

    /// Auto compresses what pays and skips what is already compressed: a
    /// compressible file shrinks as it does under Zstd, while the same bytes
    /// behind a gzip signature cross raw (br-asupersync-t1fblr.24).
    #[cfg(feature = "zstd")]
    #[test]
    fn auto_compresses_text_and_sends_signed_formats_raw() {
        let payload = compressible_payload(4, 2 * DEFAULT_CHUNK_SIZE + 5);
        let auto = SendOptions::new().with_compression(CompressionMode::Auto);
        let text = transfer_with_options(
            &canonical_test_root("atp-tcp-auto-text"),
            &payload,
            auto,
            None,
        );
        assert_delivered(&text, &payload, "auto text");
        let len = payload.len() as u64;
        assert!(
            text.wire_bytes < len / 4,
            "auto text: {} wire bytes for {len}",
            text.wire_bytes
        );
        let mut gzip = payload;
        gzip[..2].copy_from_slice(&[0x1F, 0x8B]);
        let signed =
            transfer_with_options(&canonical_test_root("atp-tcp-auto-gzip"), &gzip, auto, None);
        assert_delivered(&signed, &gzip, "auto gzip");
        assert!(
            signed.wire_bytes > len,
            "auto gzip: {} wire bytes for {len}",
            signed.wire_bytes
        );
    }

    /// A delta resync on a compressed session: the second transfer of a
    /// changed file sends only the changed chunks, compressed, and commits
    /// the new bytes. The same resync without compression costs more wire.
    #[cfg(feature = "zstd")]
    #[test]
    fn delta_chunks_are_compressed_and_commit_the_new_bytes() {
        let first = compressible_payload(3, 1024 * 1024);
        let mut second = first.clone();
        let middle = second.len() / 2;
        let changed = compressible_payload(4, 150_000);
        second[middle..middle + changed.len()].copy_from_slice(&changed);
        let mut wire = Vec::new();
        for (label, options) in [
            (
                "atp-tcp-delta-zstd",
                SendOptions::new().with_compression(CompressionMode::Zstd),
            ),
            ("atp-tcp-delta-raw", SendOptions::new()),
        ] {
            let root = canonical_test_root(label);
            let initial = transfer_with_options(&root, &first, options, None);
            assert_delivered(&initial, &first, label);
            let resync = transfer_with_options(&root, &second, options, None);
            assert_delivered(&resync, &second, label);
            wire.push(resync.wire_bytes);
        }
        let (zstd, raw) = (wire[0], wire[1]);
        assert!(
            raw < second.len() as u64 / 2,
            "the raw resync was a delta: {raw}"
        );
        assert!(zstd < raw / 2, "compressed delta {zstd} vs raw delta {raw}");
    }

    #[cfg(feature = "zstd")]
    fn tamper(rewrite: impl FnOnce(Frame) -> Frame + Send + 'static) -> Tamper {
        Box::new(rewrite)
    }

    /// `frame`, a data frame, with its chunk replaced by `chunk` and a codec
    /// record claiming that `chunk` is zstd decoding to `raw_len` bytes.
    #[cfg(feature = "zstd")]
    fn claimed_chunk(frame: &Frame, raw_len: u32, chunk: &[u8]) -> Frame {
        let (index, offset, _) = parse_data_frame(frame).expect("a data frame");
        let mut claimed = data_frame(index, offset, chunk).expect("a data frame");
        claimed.header.extensions.insert(
            codec::CHUNK_CODEC_EXTENSION,
            codec::ChunkCodec::new(codec::WireCodec::Zstd, raw_len).to_bytes(),
        );
        claimed
    }

    /// A zstd frame of `blocks` RLE blocks of 128 KiB: a few dozen bytes
    /// that decode to `blocks` times 128 KiB. Its window is
    /// `1 << window_log`; it declares `content_size` when given one.
    #[cfg(feature = "zstd")]
    fn rle_bomb(window_log: u8, content_size: Option<u32>, blocks: u32) -> Vec<u8> {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd];
        frame.push(if content_size.is_some() { 0x80 } else { 0 });
        frame.push((window_log - 10) << 3);
        if let Some(size) = content_size {
            frame.extend_from_slice(&size.to_le_bytes());
        }
        for block in 1..=blocks {
            let header = ((128 * 1024) << 3) | (1 << 1) | u32::from(block == blocks);
            frame.extend_from_slice(&header.to_le_bytes()[..3]);
            frame.push(b'a');
        }
        frame
    }

    /// A sender that turns hostile after the handshake. Each rewrite of its
    /// first data frame is refused with its own typed error before anything
    /// is committed, and the inbox is left empty: no file, no staging.
    #[cfg(feature = "zstd")]
    #[test]
    fn a_hostile_sender_is_refused_before_anything_is_committed() {
        // One 50 000-byte chunk, which a zstd session sends compressed.
        let payload = compressible_payload(5, 50_000);
        let zstd = SendOptions::new().with_compression(CompressionMode::Zstd);
        let cases: Vec<(&str, SendOptions, Tamper, &str)> = vec![
            (
                "a bomb that declares its size",
                zstd,
                tamper(|frame| claimed_chunk(&frame, 50_000, &rle_bomb(17, Some(8 << 17), 8))),
                "output exceeds the decode limit",
            ),
            (
                "a bomb that declares the claimed size",
                zstd,
                tamper(|frame| claimed_chunk(&frame, 50_000, &rle_bomb(17, Some(50_000), 8))),
                "content size mismatch",
            ),
            (
                "a bomb that declares no size",
                zstd,
                tamper(|frame| claimed_chunk(&frame, 50_000, &rle_bomb(17, None, 8))),
                "does not declare its content size",
            ),
            (
                "a raw length past what the entry lacks",
                zstd,
                tamper(|frame| {
                    let chunk = parse_data_frame(&frame).expect("a data frame").2.to_vec();
                    claimed_chunk(&frame, 50_001, &chunk)
                }),
                "chunk raw length 50001 exceeds the limit 50000",
            ),
            (
                "a raw length short of the frame's content",
                zstd,
                tamper(|frame| {
                    let chunk = parse_data_frame(&frame).expect("a data frame").2.to_vec();
                    claimed_chunk(&frame, 49_999, &chunk)
                }),
                "output exceeds the decode limit",
            ),
            (
                "a window past the negotiated one",
                zstd,
                tamper(|frame| claimed_chunk(&frame, 50_000, &rle_bomb(19, Some(50_000), 1))),
                "window exceeds the decode limit",
            ),
            (
                "a truncated frame",
                zstd,
                tamper(|frame| {
                    let chunk = parse_data_frame(&frame).expect("a data frame").2.to_vec();
                    claimed_chunk(&frame, 50_000, &chunk[..chunk.len() / 2])
                }),
                "input truncated",
            ),
            (
                "garbage",
                zstd,
                tamper(|frame| claimed_chunk(&frame, 50_000, b"garbage, not a zstd frame")),
                "not a Zstandard frame",
            ),
            (
                "a record naming another codec",
                zstd,
                tamper(|mut frame| {
                    let record = frame
                        .header
                        .extensions
                        .get_mut(&codec::CHUNK_CODEC_EXTENSION)
                        .expect("a compressed chunk");
                    record[1] = 9;
                    frame
                }),
                "does not match the negotiated codec",
            ),
            (
                "a compressed chunk on a session without a codec",
                SendOptions::new(),
                tamper(|frame| {
                    let chunk = parse_data_frame(&frame).expect("a data frame").2.to_vec();
                    let params = asupersync_zstd::EncodeParams::new(asupersync_zstd::Level::Fast);
                    let raw_len = u32::try_from(chunk.len()).expect("one chunk");
                    let compressed = asupersync_zstd::encode_all(&chunk, &params);
                    claimed_chunk(&frame, raw_len, &compressed)
                }),
                "compressed chunk without a negotiated codec",
            ),
        ];
        let mut wrong = Vec::new();
        for (number, (what, options, rewrite, expected)) in cases.into_iter().enumerate() {
            let root = canonical_test_root(&format!("atp-tcp-hostile-{number}"));
            let run = transfer_through(&root, &payload, options, None, Some(rewrite));
            let left: Vec<_> = std::fs::read_dir(root.join("inbox"))
                .expect("read the inbox")
                .map(|entry| entry.expect("an inbox entry").file_name())
                .collect();
            let refused = matches!(
                &run.received,
                Err(TransportError::Frame(message)) if message.contains(expected)
            );
            if !refused || !left.is_empty() {
                wrong.push(format!("{what}: {:?}, inbox {left:?}", run.received));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// A refused transfer leaves nothing in the way: the same transfer, sent
    /// cleanly into the same inbox, commits.
    #[cfg(feature = "zstd")]
    #[test]
    fn a_clean_retry_commits_after_a_refused_transfer() {
        let payload = compressible_payload(6, 50_000);
        let zstd = SendOptions::new().with_compression(CompressionMode::Zstd);
        let root = canonical_test_root("atp-tcp-refused-then-clean");
        let bomb = tamper(|frame| claimed_chunk(&frame, 50_000, &rle_bomb(17, None, 8)));
        let refused = transfer_through(&root, &payload, zstd, None, Some(bomb));
        assert!(refused.received.is_err(), "{:?}", refused.received);
        assert!(refused.committed.is_empty());
        let retry = transfer_with_options(&root, &payload, zstd, None);
        assert_delivered(&retry, &payload, "the retry");
    }

    #[test]
    fn metadata_apply_error_is_best_effort_not_commit_fatal() {
        let cx = Cx::for_testing();
        let meta = EntryMetadata {
            unix_mode: Some(0o600),
            ..Default::default()
        };
        let missing = Path::new("/asupersync-tcp-metadata-best-effort-missing-file");

        futures_lite::future::block_on(apply_entry_metadata_best_effort(&cx, missing, &meta));
    }

    #[test]
    fn join_relative_rejects_traversal() {
        let base = Path::new("/tmp/inbox/data");
        assert!(join_relative(base, "../escape").is_err());
        assert!(join_relative(base, "ok/sub/file.txt").is_ok());
        assert_eq!(
            join_relative(base, "ok/sub/file.txt").unwrap(),
            Path::new("/tmp/inbox/data/ok/sub/file.txt")
        );
    }

    #[test]
    fn safe_base_for_root_name_contains_hostile_inputs() {
        let dest = Path::new("/tmp/inbox");
        // Legitimate single-component name is preserved.
        assert_eq!(
            safe_base_for_root_name(dest, "payload").unwrap(),
            Path::new("/tmp/inbox/payload")
        );
        // Hostile names fail closed instead of being silently rewritten.
        assert!(safe_base_for_root_name(dest, "/etc/cron.d/evil").is_err());
        assert!(safe_base_for_root_name(dest, "../../etc/passwd").is_err());
        assert!(safe_base_for_root_name(dest, "").is_err());
        assert!(safe_base_for_root_name(dest, "/").is_err());
        assert!(safe_base_for_root_name(dest, "..").is_err());
        assert!(safe_base_for_root_name(dest, "NUL.txt").is_err());
    }

    fn manifest_with(entries: Vec<ManifestEntry>, total_bytes: u64) -> TransferManifest {
        TransferManifest {
            transfer_id: "t".to_string(),
            root_name: "r".to_string(),
            is_directory: true,
            total_bytes,
            merkle_root_hex: "0".repeat(64),
            metadata_root_hex: None,
            directory_metadata: None,
            entries,
            delta_manifest: None,
        }
    }

    fn refresh_manifest_metadata_commitment(manifest: &mut TransferManifest) {
        manifest.metadata_root_hex = transfer_manifest_metadata_commitment(manifest);
    }

    fn entry(index: u32, size: u64) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: format!("f{index}"),
            size,
            sha256_hex: "0".repeat(64),
            metadata: None,
            members: Vec::new(),
        }
    }

    #[test]
    fn validate_manifest_accepts_sane_bounds() {
        let m = manifest_with(vec![entry(0, 100), entry(1, 200)], 300);
        assert!(validate_manifest(&m, &TransferConfig::default()).is_ok());
    }

    #[test]
    fn validate_manifest_rejects_noncanonical_bare_metadata_block() {
        let mut bare = entry(0, 1);
        bare.metadata = Some(EntryMetadata::default());
        assert!(matches!(
            validate_manifest(&manifest_with(vec![bare], 1), &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("non-canonical bare metadata")
        ));
    }

    #[test]
    fn validate_manifest_rejects_entry_size_sum_overflow() {
        let manifest = manifest_with(vec![entry(0, u64::MAX), entry(1, 1)], u64::MAX);
        let config = TransferConfig {
            max_transfer_bytes: u64::MAX,
            ..TransferConfig::default()
        };
        assert!(matches!(
            validate_manifest(&manifest, &config),
            Err(TransportError::Frame(message)) if message.contains("overflow")
        ));
    }

    #[test]
    fn validate_manifest_rejects_hardlink_metadata_that_differs_from_primary() {
        let mut primary = entry(0, 4);
        primary.rel_path = "primary.bin".to_string();
        primary.metadata = Some(EntryMetadata {
            unix_mode: Some(0o644),
            ..EntryMetadata::default()
        });
        let mut alias = entry(1, 0);
        alias.rel_path = "alias.bin".to_string();
        alias.sha256_hex = sha256_hex(b"");
        alias.metadata = Some(EntryMetadata {
            unix_mode: Some(0o644),
            hardlink_target: Some("primary.bin".to_string()),
            ..EntryMetadata::default()
        });
        let mut valid = manifest_with(vec![primary, alias], 4);
        let config = TransferConfig {
            preserve_hardlinks: true,
            ..TransferConfig::default()
        };
        refresh_manifest_metadata_commitment(&mut valid);
        validate_manifest(&valid, &config).expect("hardlink alias with primary metadata validates");

        valid.entries[1]
            .metadata
            .as_mut()
            .expect("alias metadata")
            .unix_mode = Some(0o600);
        refresh_manifest_metadata_commitment(&mut valid);
        assert!(matches!(
            validate_manifest(&valid, &config),
            Err(TransportError::Frame(message)) if message.contains("metadata different from primary")
        ));
    }

    #[test]
    fn validate_manifest_rejects_windows_path_aliases_before_staging() {
        for rel_path in ["NUL.txt", "dir/COM1.log", "trailing.", "trailing "] {
            let mut manifest_entry = entry(0, 10);
            manifest_entry.rel_path = rel_path.to_string();
            let manifest = manifest_with(vec![manifest_entry], 10);
            assert!(
                validate_manifest(&manifest, &TransferConfig::default()).is_err(),
                "Windows-unsafe path {rel_path:?} must fail closed"
            );
        }

        let mut entries = vec![entry(0, 10), entry(1, 20)];
        entries[0].rel_path = "Docs/Readme.txt".to_string();
        entries[1].rel_path = "docs/README.TXT".to_string();
        let manifest = manifest_with(entries, 30);
        assert!(matches!(
            validate_manifest(&manifest, &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("case collision")
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn per_entry_guard_rejects_replaced_destination_directory_ancestor() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let outside = temp.path().join("outside");
        let pivot = temp.path().join("pivot");
        std::fs::create_dir(&outside).expect("create outside directory");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &pivot).expect("create directory symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&outside, &pivot).expect("create directory symlink");

        let base = pivot.join("payload");
        let out_path = base.join("file.bin");
        let error = futures_lite::future::block_on(reject_entry_destination_link_prefixes(
            &base, &out_path, None, false,
        ))
        .expect_err("outer destination junction must fail closed");
        assert!(matches!(
            error,
            TransportError::Source(message) if message.contains("symlink or reparse point")
        ));
        assert!(!outside.join("payload/file.bin").exists());
    }

    #[cfg(unix)]
    #[test]
    fn regular_entry_commit_rejects_replaced_destination_directory_ancestor() {
        let temp = tempfile::tempdir().expect("temporary directory");
        // Canonical, so only the planted link can trip the guard.
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let outside = root.join("outside");
        let pivot = root.join("pivot");
        std::fs::create_dir(&outside).expect("create outside directory");
        std::os::unix::fs::symlink(&outside, &pivot).expect("create directory symlink");
        let staged = root.join("staged.part");
        std::fs::write(&staged, b"payload").expect("write staged file");

        let base = pivot.join("payload");
        let out_path = base.join("dir/file.bin");
        let mut parent_syncs = DeferredParentSyncs::default();
        let error = futures_lite::future::block_on(commit_regular_entry(
            &Cx::for_testing(),
            &base,
            &out_path,
            &staged,
            None,
            &mut parent_syncs,
        ))
        .expect_err("outer destination symlink must fail closed");
        assert!(matches!(
            error,
            TransportError::Source(message) if message.contains("symlink or reparse point")
        ));
        // Refused before its parent is created through the link.
        assert!(!outside.join("payload").exists());
        assert!(staged.exists(), "a refused commit keeps the staged file");
    }

    #[cfg(unix)]
    #[test]
    fn regular_entry_commit_installs_the_staged_file_with_its_metadata() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("temporary directory");
        // Canonical, so no symlinked ancestor of the temp dir trips the guard.
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let base = root.join("dest");
        let out_path = base.join("a/b/file.bin");
        let staged = root.join("staged.part");
        std::fs::write(&staged, b"payload").expect("write staged file");
        let metadata = EntryMetadata {
            unix_mode: Some(0o640),
            mtime_unix_secs: Some(1_000_000_000),
            ..EntryMetadata::default()
        };
        let mut parent_syncs = DeferredParentSyncs::default();
        futures_lite::future::block_on(commit_regular_entry(
            &Cx::for_testing(),
            &base,
            &out_path,
            &staged,
            Some(&metadata),
            &mut parent_syncs,
        ))
        .expect("commit a plain regular file");

        assert_eq!(
            std::fs::read(&out_path).expect("read committed file"),
            b"payload"
        );
        assert!(!staged.exists(), "the staged file is renamed into place");
        let committed = std::fs::metadata(&out_path).expect("committed file metadata");
        assert_eq!(committed.permissions().mode() & 0o7777, 0o640);
        assert_eq!(
            committed.modified().expect("committed mtime"),
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000)
        );
        futures_lite::future::block_on(parent_syncs.sync()).expect("sync the recorded parent");
    }

    #[test]
    fn a_whole_staging_file_is_written_by_one_call_and_never_replaces_a_file() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let path = temp.path().join("0");
        futures_lite::future::block_on(write_whole_staging_file(&path, b"payload"))
            .expect("stage a whole file");
        assert_eq!(
            std::fs::read(&path).expect("read the staged file"),
            b"payload"
        );

        let error = futures_lite::future::block_on(write_whole_staging_file(&path, b"other"))
            .expect_err("a staging file is always created new");
        assert!(
            matches!(&error, TransportError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists),
            "{error:?}"
        );
        assert_eq!(
            std::fs::read(&path).expect("read the staged file"),
            b"payload"
        );
    }

    /// A file that fits one data frame is staged by one blocking call and a
    /// longer one through its open staging file. Both commit the source's
    /// bytes, on either side of the one-frame boundary.
    #[cfg(feature = "zstd")]
    #[test]
    fn files_on_both_sides_of_the_one_frame_boundary_commit_identical_bytes() {
        for (name, len) in [
            ("small", 1000),
            ("one-frame", DEFAULT_CHUNK_SIZE),
            ("two-frames", DEFAULT_CHUNK_SIZE + 1),
        ] {
            let payload = compressible_payload(7, len);
            let run = transfer_with_options(
                &canonical_test_root(&format!("atp-tcp-whole-{name}")),
                &payload,
                SendOptions::new(),
                None,
            );
            assert_delivered(&run, &payload, name);
        }
    }

    /// dfdwyt DF4: plain regular files commit in batches across batch
    /// boundaries, a hardlink to a batched file still finds its primary
    /// committed, and every file lands with its own bytes.
    #[cfg(unix)]
    #[test]
    fn batched_regular_commits_cross_batch_boundaries_and_flush_before_a_hardlink() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let dest_dir = root.join("dest");
        let staging = root.join("staging");
        std::fs::create_dir_all(&dest_dir).expect("create the destination");
        std::fs::create_dir_all(&staging).expect("create the staging dir");
        let count = 2 * REGULAR_COMMIT_BATCH + 2;
        let rel = |index: usize| format!("d{}/f{index:03}.bin", index % 3);
        let mut entries = Vec::new();
        let mut staging_paths = Vec::new();
        for index in 0..count {
            let staged = staging.join(index.to_string());
            std::fs::write(&staged, format!("file {index}")).expect("write a staged file");
            entries.push(named_entry(
                u32::try_from(index).expect("index"),
                &rel(index),
            ));
            staging_paths.push(staged);
        }
        let mut alias = named_entry(u32::try_from(count).expect("index"), "zz_alias.bin");
        alias.metadata = Some(EntryMetadata {
            hardlink_target: Some(rel(0)),
            ..EntryMetadata::default()
        });
        entries.push(alias);
        staging_paths.push(staging.join("unused-alias-staging"));
        let manifest = manifest_with(entries, 0);

        let committed = futures_lite::future::block_on(commit_verified_staging(
            &Cx::for_testing(),
            &dest_dir,
            &manifest,
            &TransferConfig::default(),
            &staging_paths,
        ))
        .expect("commit the tree");

        assert_eq!(committed.len(), count + 1);
        let base = dest_dir.join("r");
        for index in 0..count {
            assert_eq!(
                std::fs::read_to_string(base.join(rel(index))).expect("read a committed file"),
                format!("file {index}")
            );
        }
        let primary = std::fs::metadata(base.join(rel(0))).expect("primary metadata");
        let linked = std::fs::metadata(base.join("zz_alias.bin")).expect("alias metadata");
        assert_eq!(
            primary.ino(),
            linked.ino(),
            "the alias is a hardlink to the primary"
        );
    }

    /// dfdwyt DF4: a commit batch stops at its first failure. The files
    /// before it stay committed and recorded; the files after it are not
    /// touched.
    #[cfg(unix)]
    #[test]
    fn a_regular_commit_batch_stops_at_its_first_failure() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let base = root.join("dest");
        let file = |name: &str, staged: Option<&[u8]>| {
            let staging_path = root.join(format!("{name}.part"));
            if let Some(bytes) = staged {
                std::fs::write(&staging_path, bytes).expect("write a staged file");
            }
            RegularCommit {
                out_path: base.join(name),
                staging_path,
                metadata: None,
            }
        };
        let files = vec![
            file("a.bin", Some(b"a")),
            file("b.bin", None),
            file("c.bin", Some(b"c")),
        ];
        let mut parent_syncs = DeferredParentSyncs::default();
        let mut committed = Vec::new();

        let error = futures_lite::future::block_on(commit_regular_entries(
            &Cx::for_testing(),
            &base,
            files,
            &mut parent_syncs,
            &mut committed,
        ))
        .expect_err("b.bin has no staged file");

        assert!(
            error.to_string().contains("wrong filesystem kind"),
            "{error}"
        );
        assert_eq!(committed, vec![base.join("a.bin")]);
        assert_eq!(std::fs::read(base.join("a.bin")).expect("read a.bin"), b"a");
        assert!(
            !base.join("c.bin").exists(),
            "a file after the failure is not committed"
        );
        assert!(
            root.join("c.bin.part").exists(),
            "its staged file is untouched"
        );
        futures_lite::future::block_on(parent_syncs.sync()).expect("sync the recorded parent");
    }

    #[cfg(unix)]
    #[test]
    fn empty_root_and_topology_only_trees_sync_before_restrictive_directory_metadata() {
        use std::os::unix::fs::PermissionsExt as _;

        for topology_only in [false, true] {
            let temp = tempfile::tempdir().expect("temporary directory");
            let root = temp.path().canonicalize().expect("canonical root");
            let destination = root.join("new/receive");
            let directory_metadata = EntryMetadata {
                file_kind: FileKind::Directory,
                unix_mode: Some(0),
                ..EntryMetadata::default()
            };
            let entries = if topology_only {
                let mut empty = named_entry(0, "a/b/empty");
                empty.metadata = Some(directory_metadata.clone());
                vec![empty]
            } else {
                Vec::new()
            };
            let mut manifest = manifest_with(entries, 0);
            manifest.directory_metadata = Some(DirectoryMetadataManifest {
                root: Some(directory_metadata.clone()),
                entries: if topology_only {
                    ["a", "a/b"]
                        .into_iter()
                        .map(|rel_path| DirectoryMetadataEntry {
                            rel_path: rel_path.to_string(),
                            metadata: directory_metadata.clone(),
                        })
                        .collect()
                } else {
                    Vec::new()
                },
            });
            let staged = if topology_only {
                vec![root.join("unused-topology-staging")]
            } else {
                Vec::new()
            };
            let committed = futures_lite::future::block_on(commit_verified_staging(
                &Cx::for_testing(),
                &destination,
                &manifest,
                &TransferConfig::default(),
                &staged,
            ))
            .expect("empty-directory commit syncs before restrictive metadata");
            let base = destination.join("r");
            let leaf = if topology_only { base.join("a/b/empty") } else { base.clone() };
            assert_eq!(committed, vec![leaf.clone()]);
            let paths = if topology_only {
                vec![base.clone(), base.join("a"), base.join("a/b"), leaf.clone()]
            } else {
                vec![base]
            };
            // Restore parents before inspecting descendants, so this also
            // exercises the non-root case where mode 000 blocks traversal.
            for path in paths {
                assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0);
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            assert_eq!(std::fs::read_dir(leaf).unwrap().count(), 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn empty_directory_commit_paths_refuse_success_when_directory_sync_fails() {
        let temp = tempfile::tempdir().expect("temporary directory");
        for topology in 0..3 {
            let directory_metadata = EntryMetadata {
                file_kind: FileKind::Directory,
                ..EntryMetadata::default()
            };
            let mut manifest = manifest_with(Vec::new(), 0);
            manifest.root_name = "sys".to_string();
            if topology == 1 {
                manifest.directory_metadata = Some(DirectoryMetadataManifest {
                    root: None,
                    entries: vec![DirectoryMetadataEntry {
                        rel_path: "net".to_string(),
                        metadata: directory_metadata.clone(),
                    }],
                });
            } else if topology == 2 {
                let mut entry = named_entry(0, "net");
                entry.metadata = Some(directory_metadata);
                manifest.entries.push(entry);
            }
            let staged = if topology == 2 {
                vec![temp.path().join("unused-topology-staging")]
            } else {
                Vec::new()
            };
            // These directories already exist. No procfs files or metadata
            // are changed; its unsupported fsync must prevent success first.
            let error = futures_lite::future::block_on(commit_verified_staging(
                &Cx::for_testing(),
                Path::new("/proc"),
                &manifest,
                &TransferConfig::default(),
                &staged,
            ))
            .expect_err("an empty-directory transfer cannot acknowledge an unsynced name");
            let expected = if topology == 0 { "/proc/sys:" } else { "/proc/sys/net:" };
            assert!(error.to_string().contains(expected), "case {topology}: {error}");
            assert!(error.to_string().contains("sync committed directory"));
        }
    }

    fn directory_metadata_entry(rel_path: &str) -> DirectoryMetadataEntry {
        DirectoryMetadataEntry {
            rel_path: rel_path.to_string(),
            metadata: EntryMetadata {
                file_kind: FileKind::Directory,
                unix_mode: Some(0o755),
                ..EntryMetadata::default()
            },
        }
    }

    #[test]
    fn validate_manifest_accepts_nested_directory_metadata_without_counting_it_as_files() {
        let mut payload = named_entry(0, "a/b/payload.bin");
        payload.sha256_hex = sha256_hex(b"");
        let mut manifest = manifest_with(vec![payload], 0);
        manifest.directory_metadata = Some(DirectoryMetadataManifest {
            root: Some(EntryMetadata {
                file_kind: FileKind::Directory,
                unix_mode: Some(0o755),
                ..EntryMetadata::default()
            }),
            entries: vec![
                directory_metadata_entry("a"),
                directory_metadata_entry("a/b"),
            ],
        });
        refresh_manifest_metadata_commitment(&mut manifest);

        validate_manifest(&manifest, &TransferConfig::default())
            .expect("nested directory metadata must validate");
        assert_eq!(manifest.entries.len(), 1);
    }

    #[test]
    fn validate_manifest_rejects_noncanonical_empty_directory_metadata_block() {
        let mut manifest = manifest_with(Vec::new(), 0);
        manifest.directory_metadata = Some(DirectoryMetadataManifest::default());
        assert!(matches!(
            validate_manifest(&manifest, &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("non-canonical empty")
        ));
    }

    #[test]
    fn validate_manifest_rejects_unsafe_or_non_directory_directory_metadata() {
        let mut payload = named_entry(0, "a/b/payload.bin");
        payload.sha256_hex = sha256_hex(b"");
        let mut valid = manifest_with(vec![payload], 0);
        valid.directory_metadata = Some(DirectoryMetadataManifest {
            root: Some(EntryMetadata {
                file_kind: FileKind::Directory,
                unix_mode: Some(0o755),
                ..EntryMetadata::default()
            }),
            entries: vec![
                directory_metadata_entry("a"),
                directory_metadata_entry("a/b"),
            ],
        });
        refresh_manifest_metadata_commitment(&mut valid);

        let mut no_fidelity = valid.clone();
        no_fidelity
            .directory_metadata
            .as_mut()
            .and_then(|metadata| metadata.root.as_mut())
            .expect("root metadata")
            .unix_mode = None;
        refresh_manifest_metadata_commitment(&mut no_fidelity);
        assert!(matches!(
            validate_manifest(&no_fidelity, &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("no fidelity fields")
        ));

        let mut wrong_root_kind = valid.clone();
        wrong_root_kind
            .directory_metadata
            .as_mut()
            .and_then(|metadata| metadata.root.as_mut())
            .expect("root metadata")
            .file_kind = FileKind::Regular;
        refresh_manifest_metadata_commitment(&mut wrong_root_kind);
        assert!(matches!(
            validate_manifest(&wrong_root_kind, &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("non-directory kind")
        ));

        let mut unsorted = valid.clone();
        unsorted
            .directory_metadata
            .as_mut()
            .expect("directory metadata")
            .entries
            .reverse();
        refresh_manifest_metadata_commitment(&mut unsorted);
        assert!(matches!(
            validate_manifest(&unsorted, &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("strictly increasing")
        ));

        let mut case_alias = valid.clone();
        case_alias
            .directory_metadata
            .as_mut()
            .expect("directory metadata")
            .entries[0]
            .rel_path = "A".to_string();
        refresh_manifest_metadata_commitment(&mut case_alias);
        assert!(matches!(
            validate_manifest(&case_alias, &TransferConfig::default()),
            Err(TransportError::Frame(message))
                if message.contains("not represented") || message.contains("case-colliding")
        ));

        let mut file_alias = valid.clone();
        file_alias
            .directory_metadata
            .as_mut()
            .expect("directory metadata")
            .entries
            .push(directory_metadata_entry("a/b/payload.bin"));
        refresh_manifest_metadata_commitment(&mut file_alias);
        assert!(matches!(
            validate_manifest(&file_alias, &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("aliases logical content")
        ));

        let mut explicit_directory = entry(0, 0);
        explicit_directory.rel_path = "empty".to_string();
        explicit_directory.sha256_hex = sha256_hex(b"");
        explicit_directory.metadata = Some(directory_metadata_entry("empty").metadata);
        let mut duplicate_explicit = manifest_with(vec![explicit_directory], 0);
        duplicate_explicit.directory_metadata = Some(DirectoryMetadataManifest {
            root: Some(EntryMetadata {
                file_kind: FileKind::Directory,
                unix_mode: Some(0o755),
                ..EntryMetadata::default()
            }),
            entries: vec![directory_metadata_entry("empty")],
        });
        refresh_manifest_metadata_commitment(&mut duplicate_explicit);
        assert!(matches!(
            validate_manifest(&duplicate_explicit, &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("aliases logical content")
        ));

        let mut orphan = valid;
        orphan
            .directory_metadata
            .as_mut()
            .expect("directory metadata")
            .entries
            .push(directory_metadata_entry("orphan"));
        refresh_manifest_metadata_commitment(&mut orphan);
        assert!(matches!(
            validate_manifest(&orphan, &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("not represented")
        ));
    }

    #[test]
    fn directory_metadata_tamper_breaks_the_shared_metadata_commitment() {
        let mut payload = named_entry(0, "nested/payload.bin");
        payload.sha256_hex = sha256_hex(b"");
        let mut manifest = manifest_with(vec![payload], 0);
        manifest.directory_metadata = Some(DirectoryMetadataManifest {
            root: Some(EntryMetadata {
                file_kind: FileKind::Directory,
                windows_attributes: Some(0x0000_0002),
                ..EntryMetadata::default()
            }),
            entries: vec![directory_metadata_entry("nested")],
        });
        refresh_manifest_metadata_commitment(&mut manifest);
        validate_manifest(&manifest, &TransferConfig::default())
            .expect("untampered directory metadata validates");

        manifest
            .directory_metadata
            .as_mut()
            .and_then(|metadata| metadata.root.as_mut())
            .expect("root metadata")
            .windows_attributes = Some(0x0000_0003);
        assert!(matches!(
            validate_manifest(&manifest, &TransferConfig::default()),
            Err(TransportError::Frame(message)) if message.contains("commitment mismatch")
        ));
    }

    #[test]
    fn directory_metadata_apply_rejects_a_stable_regular_file_leaf() {
        let mut payload = named_entry(0, "nested/payload.bin");
        payload.sha256_hex = sha256_hex(b"");
        let mut manifest = manifest_with(vec![payload], 0);
        manifest.directory_metadata = Some(DirectoryMetadataManifest {
            root: None,
            entries: vec![directory_metadata_entry("nested")],
        });
        refresh_manifest_metadata_commitment(&mut manifest);
        validate_manifest(&manifest, &TransferConfig::default())
            .expect("directory metadata manifest");

        let base = canonical_test_root("atp-directory-kind-guard");
        let wrong_kind = base.join("nested");
        std::fs::write(&wrong_kind, b"must remain a regular file")
            .expect("write wrong-kind destination leaf");

        let error = futures_lite::future::block_on(apply_directory_metadata_best_effort(
            &Cx::for_testing(),
            &base,
            &manifest,
        ))
        .expect_err("directory metadata must not be applied to a regular file");
        assert!(matches!(
            error,
            TransportError::Source(message) if message.contains("not a directory")
        ));
        assert_eq!(
            std::fs::read(&wrong_kind).expect("read preserved regular file"),
            b"must remain a regular file"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn validate_manifest_rejects_lying_entry_size() {
        // total_bytes is small but a single entry declares u64::MAX — the
        // pre-fix code would `Vec::with_capacity(u64::MAX as usize)` and abort.
        let m = manifest_with(vec![entry(0, u64::MAX)], 10);
        assert!(matches!(
            validate_manifest(&m, &TransferConfig::default()),
            Err(TransportError::TooLarge { .. })
        ));
    }

    fn symlink_entry(index: u32, rel: &str, target: &str) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: rel.to_string(),
            size: 0,
            sha256_hex: sha256_hex(b""),
            metadata: Some(EntryMetadata {
                file_kind: FileKind::Symlink,
                symlink_target: Some(target.to_string()),
                symlink_target_info: Some(SymlinkTargetInfo {
                    kind: Some(SymlinkTargetKind::File),
                    semantics: SymlinkTargetSemantics::PortableRelative,
                }),
                ..Default::default()
            }),
            members: Vec::new(),
        }
    }

    #[test]
    fn validate_manifest_enforces_symlink_containment_and_receiver_policy() {
        let mut contained = manifest_with(vec![symlink_entry(0, "dir/link", "../target")], 0);
        refresh_manifest_metadata_commitment(&mut contained);
        validate_manifest(&contained, &TransferConfig::default())
            .expect("contained portable symlink validates");

        for target in ["../../escape", "/rooted", r"C:\escape", r"..\escape"] {
            let mut rejected = manifest_with(vec![symlink_entry(0, "dir/link", target)], 0);
            refresh_manifest_metadata_commitment(&mut rejected);
            assert!(
                matches!(
                    validate_manifest(&rejected, &TransferConfig::default()),
                    Err(TransportError::Frame(ref message))
                        if message.contains("invalid metadata")
                ),
                "unsafe symlink target {target:?} must fail before staging"
            );
        }

        let portable_receiver = TransferConfig {
            metadata_policy: MetadataPolicy::portable(),
            ..TransferConfig::default()
        };
        assert!(matches!(
            validate_manifest(&contained, &portable_receiver),
            Err(TransportError::Frame(ref message))
                if message.contains("denied by receiver metadata policy")
        ));
    }

    fn named_entry(index: u32, rel: &str) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: rel.to_string(),
            size: 0,
            sha256_hex: "0".repeat(64),
            metadata: None,
            members: Vec::new(),
        }
    }

    #[test]
    fn reject_symlink_traversal_blocks_entries_nested_under_a_symlink() {
        // A file written through a manifest-declared symlink would escape dest.
        let bad = manifest_with(
            vec![symlink_entry(0, "x", "/etc"), named_entry(1, "x/payload")],
            0,
        );
        assert!(
            matches!(
                reject_symlink_traversal(&bad),
                Err(TransportError::Source(_))
            ),
            "entry nested under a symlink must be rejected"
        );

        // Nested symlink-under-symlink is also rejected.
        let bad2 = manifest_with(
            vec![symlink_entry(0, "a", "/x"), symlink_entry(1, "a/b", "/y")],
            0,
        );
        assert!(reject_symlink_traversal(&bad2).is_err());
    }

    #[test]
    fn reject_symlink_traversal_allows_siblings_and_links_without_nesting() {
        // "xy" is a sibling of symlink "x", not nested under it; a normal link
        // with no entries beneath it is fine.
        let ok = manifest_with(
            vec![
                symlink_entry(0, "x", "data.txt"),
                named_entry(1, "xy"),
                named_entry(2, "data.txt"),
            ],
            0,
        );
        assert!(reject_symlink_traversal(&ok).is_ok());
        // No symlinks at all: trivially ok.
        let plain = manifest_with(vec![entry(0, 10), entry(1, 20)], 30);
        assert!(reject_symlink_traversal(&plain).is_ok());
    }

    #[test]
    fn validate_manifest_rejects_declared_sum_over_limit() {
        let cfg = TransferConfig {
            max_transfer_bytes: 1000,
            ..TransferConfig::default()
        };
        let m = manifest_with(vec![entry(0, 600), entry(1, 600)], 1200);
        assert!(matches!(
            validate_manifest(&m, &cfg),
            Err(TransportError::TooLarge { .. })
        ));
    }

    #[test]
    fn validate_manifest_rejects_single_file_with_multiple_entries() {
        let mut m = manifest_with(vec![entry(0, 10), entry(1, 20)], 30);
        m.is_directory = false;
        assert!(matches!(
            validate_manifest(&m, &TransferConfig::default()),
            Err(TransportError::Frame(msg)) if msg.contains("single-file transfer")
        ));
    }

    #[test]
    fn validate_manifest_rejects_duplicate_relative_paths() {
        let mut entries = vec![entry(0, 10), entry(1, 20)];
        entries[1].rel_path = entries[0].rel_path.clone();
        let m = manifest_with(entries, 30);
        assert!(matches!(
            validate_manifest(&m, &TransferConfig::default()),
            Err(TransportError::Frame(msg)) if msg.contains("duplicate manifest rel_path")
        ));
    }

    #[test]
    fn validate_manifest_rejects_nonsequential_indexes() {
        let m = manifest_with(vec![entry(0, 10), entry(7, 20)], 30);
        assert!(matches!(
            validate_manifest(&m, &TransferConfig::default()),
            Err(TransportError::Frame(msg)) if msg.contains("does not match position")
        ));
    }

    #[test]
    fn validate_manifest_rejects_unsafe_relative_paths() {
        for rel_path in [
            "",
            "/abs",
            "../escape",
            "a/../escape",
            "a//b",
            "a\\b",
            "c:drive",
        ] {
            let mut e = entry(0, 10);
            e.rel_path = rel_path.to_string();
            let m = manifest_with(vec![e], 10);
            assert!(
                matches!(
                    validate_manifest(&m, &TransferConfig::default()),
                    Err(TransportError::Source(msg)) if msg.contains("unsafe manifest rel_path")
                ),
                "rel_path {rel_path:?} should fail closed"
            );
        }
    }

    #[test]
    fn sha256_hex_is_lowercase_64() {
        let h = sha256_hex(b"hello world");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Known SHA-256("hello world").
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn empty_directory_metadata_is_deferred_until_after_update_mirror_cleanup() {
        fn directory_metadata(readonly: bool, mtime_unix_secs: i64) -> EntryMetadata {
            let mut metadata = EntryMetadata {
                file_kind: FileKind::Directory,
                mtime_unix_secs: Some(mtime_unix_secs),
                mtime_nanos: Some(0),
                ..EntryMetadata::default()
            };
            #[cfg(unix)]
            {
                metadata.unix_mode = Some(if readonly { 0o555 } else { 0o755 });
            }
            #[cfg(windows)]
            {
                const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
                metadata.windows_attributes =
                    Some(if readonly { FILE_ATTRIBUTE_READONLY } else { 0 });
            }
            metadata
        }

        let base = canonical_test_root("atp-directory-mirror-order");
        let dest_dir = base.join("dest");
        let transfer_root = dest_dir.join("r");
        let empty_dir = transfer_root.join("empty");
        let stale_child = empty_dir.join("stale.txt");

        let mut empty_entry = entry(0, 0);
        empty_entry.rel_path = "empty".to_string();
        empty_entry.sha256_hex = sha256_hex(b"");
        empty_entry.metadata = Some(directory_metadata(false, 1_700_010_000));
        let mut manifest = manifest_with(vec![empty_entry], 0);
        manifest.directory_metadata = Some(DirectoryMetadataManifest {
            root: Some(directory_metadata(false, 1_700_010_100)),
            entries: Vec::new(),
        });
        refresh_manifest_metadata_commitment(&mut manifest);
        let config = TransferConfig {
            metadata_policy: MetadataPolicy::full_preservation(),
            mirror_policy: MirrorPolicy {
                enabled: true,
                max_delete_fraction: 1.0,
            },
            ..TransferConfig::default()
        };
        validate_manifest(&manifest, &config).expect("initial empty-directory manifest");

        let first_committed = futures_lite::future::block_on(commit_verified_staging(
            &Cx::for_testing(),
            &dest_dir,
            &manifest,
            &config,
            &[base.join("unused-first-staging")],
        ))
        .expect("initial empty-directory commit");
        assert_eq!(first_committed, vec![empty_dir.clone()]);
        std::fs::write(&stale_child, b"delete on update").expect("create stale child");

        manifest.entries[0].metadata = Some(directory_metadata(true, 1_700_020_000));
        manifest
            .directory_metadata
            .as_mut()
            .expect("root directory metadata")
            .root = Some(directory_metadata(true, 1_700_020_100));
        refresh_manifest_metadata_commitment(&mut manifest);
        validate_manifest(&manifest, &config).expect("updated empty-directory manifest");

        let second_committed = futures_lite::future::block_on(commit_verified_staging(
            &Cx::for_testing(),
            &dest_dir,
            &manifest,
            &config,
            &[base.join("unused-second-staging")],
        ))
        .expect("mirror must remove stale child before applying readonly metadata");
        assert_eq!(second_committed, vec![empty_dir.clone()]);
        assert!(
            !stale_child.exists(),
            "stale child must be removed during the update pass"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::symlink_metadata(&empty_dir)
                    .expect("empty directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o555
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
            assert_ne!(
                std::fs::symlink_metadata(&empty_dir)
                    .expect("empty directory metadata")
                    .file_attributes()
                    & FILE_ATTRIBUTE_READONLY,
                0
            );
        }

        let writable = directory_metadata(false, 1_700_020_100);
        futures_lite::future::block_on(async {
            apply_entry_metadata(&empty_dir, &writable)
                .await
                .expect("restore empty-directory metadata");
            apply_entry_metadata(&transfer_root, &writable)
                .await
                .expect("restore root-directory metadata");
        });
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn staging_dir_guard_reclaims_on_hard_drop_unless_disarmed() {
        let base = std::env::temp_dir().join(format!("atp-staging-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // An armed guard reclaims the staging dir when dropped without a
        // cooperative cleanup (the hard-future-drop backstop path).
        let armed = base.join("armed");
        std::fs::create_dir_all(&armed).expect("create armed staging dir");
        drop(StagingDirGuard::new(armed.clone()));
        assert!(
            !armed.exists(),
            "armed StagingDirGuard must reclaim the staging dir on drop"
        );

        // A disarmed guard leaves the directory in place (the cooperative path
        // already removed it asynchronously, so the backstop must not run).
        let disarmed = base.join("disarmed");
        std::fs::create_dir_all(&disarmed).expect("create disarmed staging dir");
        let mut guard = StagingDirGuard::new(disarmed.clone());
        guard.disarm();
        drop(guard);
        assert!(
            disarmed.exists(),
            "disarmed StagingDirGuard must leave the staging dir in place"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn staging_create_results_own_cleanup_before_async_delivery() {
        let base = std::env::temp_dir().join(format!(
            "atp-staging-create-guard-{}-{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create staging guard test root");

        let dir = base.join("owned-dir");
        let dir_guard = StagingDirGuard::create(dir.clone()).expect("create guarded staging dir");
        assert!(dir.is_dir());
        drop(dir_guard);
        assert!(
            !dir.exists(),
            "an undelivered directory-create result must reclaim its directory"
        );

        let file = base.join("owned-file");
        let file_guard =
            StagingFileGuard::create(file.clone()).expect("create guarded staging file");
        assert!(file.is_file());
        drop(file_guard);
        assert!(
            !file.exists(),
            "an undelivered file-create result must reclaim its file"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn directory_metadata_preserves_root_and_nested_windows_attributes_and_mtime_on_update() {
        use std::os::windows::fs::MetadataExt as _;
        use std::time::UNIX_EPOCH;

        const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
        const ATTRIBUTE_MASK: u32 = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN;

        fn metadata(attributes: u32, mtime_unix_secs: i64) -> EntryMetadata {
            EntryMetadata {
                file_kind: FileKind::Directory,
                mtime_unix_secs: Some(mtime_unix_secs),
                mtime_nanos: Some(0),
                windows_attributes: Some(attributes),
                ..EntryMetadata::default()
            }
        }

        fn assert_directory_metadata(path: &Path, attributes: u32, mtime_unix_secs: u64) {
            let observed = std::fs::symlink_metadata(path).expect("directory metadata");
            assert!(
                observed.is_dir(),
                "{} must remain a directory",
                path.display()
            );
            assert_eq!(observed.file_attributes() & ATTRIBUTE_MASK, attributes);
            assert_eq!(
                observed
                    .modified()
                    .expect("directory modified time")
                    .duration_since(UNIX_EPOCH)
                    .expect("post-epoch directory modified time")
                    .as_secs(),
                mtime_unix_secs
            );
        }

        let base = std::env::temp_dir().join(format!(
            "atp-windows-directory-metadata-{}-{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create directory metadata test root");
        let source_root = base.join("source-r");
        let source_nested = source_root.join("nested");
        let source_file = source_nested.join("payload.bin");
        std::fs::create_dir_all(&source_nested).expect("create source directory tree");
        let dest_dir = base.join("dest");
        let root = dest_dir.join("r");
        let nested = root.join("nested");
        let destination_file = nested.join("payload.bin");
        let config = TransferConfig {
            metadata_policy: MetadataPolicy::full_preservation(),
            ..TransferConfig::default()
        };

        let first_bytes = b"first directory metadata pass";
        std::fs::write(&source_file, first_bytes).expect("write first source file");
        futures_lite::future::block_on(async {
            apply_entry_metadata(
                &source_nested,
                &metadata(
                    FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN,
                    1_700_000_100,
                ),
            )
            .await
            .expect("set initial nested source metadata");
            apply_entry_metadata(
                &source_root,
                &metadata(
                    FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN,
                    1_700_000_000,
                ),
            )
            .await
            .expect("set initial root source metadata");
        });
        let first_directory_metadata = futures_lite::future::block_on(
            capture_directory_metadata_manifest(&source_root, &config.metadata_policy),
        )
        .expect("capture initial source directory metadata");
        let mut payload = named_entry(0, "nested/payload.bin");
        payload.size = u64::try_from(first_bytes.len()).expect("payload length");
        payload.sha256_hex = sha256_hex(first_bytes);
        let mut manifest = manifest_with(vec![payload], first_bytes.len() as u64);
        manifest.directory_metadata = Some(first_directory_metadata);
        refresh_manifest_metadata_commitment(&mut manifest);
        validate_manifest(&manifest, &config).expect("initial directory metadata manifest");

        let first_staging = base.join("first-staging");
        std::fs::write(&first_staging, first_bytes).expect("write first staging file");
        let first_committed = futures_lite::future::block_on(commit_verified_staging(
            &Cx::for_testing(),
            &dest_dir,
            &manifest,
            &config,
            &[first_staging],
        ))
        .expect("commit initial directory metadata");
        assert_eq!(first_committed, vec![destination_file.clone()]);
        assert_eq!(
            std::fs::read(&destination_file).expect("first payload"),
            first_bytes
        );
        assert_directory_metadata(
            &root,
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN,
            1_700_000_000,
        );
        assert_directory_metadata(
            &nested,
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN,
            1_700_000_100,
        );

        let second_bytes = b"updated directory metadata pass";
        std::fs::write(&source_file, second_bytes).expect("write updated source file");
        futures_lite::future::block_on(async {
            apply_entry_metadata(
                &source_nested,
                &metadata(FILE_ATTRIBUTE_HIDDEN, 1_700_001_100),
            )
            .await
            .expect("set updated nested source metadata");
            apply_entry_metadata(
                &source_root,
                &metadata(FILE_ATTRIBUTE_HIDDEN, 1_700_001_000),
            )
            .await
            .expect("set updated root source metadata");
        });
        manifest.entries[0].size = u64::try_from(second_bytes.len()).expect("payload length");
        manifest.entries[0].sha256_hex = sha256_hex(second_bytes);
        manifest.total_bytes = second_bytes.len() as u64;
        manifest.directory_metadata = Some(
            futures_lite::future::block_on(capture_directory_metadata_manifest(
                &source_root,
                &config.metadata_policy,
            ))
            .expect("capture updated source directory metadata"),
        );
        refresh_manifest_metadata_commitment(&mut manifest);
        validate_manifest(&manifest, &config).expect("updated directory metadata manifest");

        let second_staging = base.join("second-staging");
        std::fs::write(&second_staging, second_bytes).expect("write second staging file");
        let second_committed = futures_lite::future::block_on(commit_verified_staging(
            &Cx::for_testing(),
            &dest_dir,
            &manifest,
            &config,
            &[second_staging],
        ))
        .expect("commit updated directory metadata");
        assert_eq!(second_committed, vec![destination_file.clone()]);
        assert_eq!(
            std::fs::read(&destination_file).expect("updated payload"),
            second_bytes
        );
        assert_directory_metadata(&root, FILE_ATTRIBUTE_HIDDEN, 1_700_001_000);
        assert_directory_metadata(&nested, FILE_ATTRIBUTE_HIDDEN, 1_700_001_100);

        let clear = metadata(0, 1_700_001_100);
        futures_lite::future::block_on(async {
            apply_entry_metadata(&nested, &clear)
                .await
                .expect("clear nested attributes");
            apply_entry_metadata(&root, &clear)
                .await
                .expect("clear root attributes");
            apply_entry_metadata(&source_nested, &clear)
                .await
                .expect("clear source nested attributes");
            apply_entry_metadata(&source_root, &clear)
                .await
                .expect("clear source root attributes");
        });
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn fifo_opt_in_does_not_replace_existing_file_on_windows() {
        let base = std::env::temp_dir().join(format!(
            "atp-windows-fifo-preserve-{}-{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&base);
        let dest_dir = base.join("dest");
        let existing = dest_dir.join("r").join("fifo");
        std::fs::create_dir_all(existing.parent().expect("existing file parent"))
            .expect("create destination root");
        std::fs::write(&existing, b"keep-existing-bytes").expect("write existing destination");

        let mut fifo = entry(0, 0);
        fifo.rel_path = "fifo".to_string();
        fifo.metadata = Some(EntryMetadata {
            file_kind: FileKind::Fifo,
            unix_mode: Some(0o644),
            ..EntryMetadata::default()
        });
        let manifest = manifest_with(vec![fifo], 0);
        let config = TransferConfig {
            allow_special_files: true,
            ..TransferConfig::default()
        };
        let staging_paths = vec![base.join("unused-staging")];
        let cx = Cx::for_testing();

        let committed = futures_lite::future::block_on(commit_verified_staging(
            &cx,
            &dest_dir,
            &manifest,
            &config,
            &staging_paths,
        ))
        .expect("unsupported FIFO must be skipped without a commit error");

        assert!(committed.is_empty());
        assert_eq!(
            std::fs::read(&existing).expect("read preserved destination"),
            b"keep-existing-bytes"
        );
        let metadata = std::fs::metadata(&existing).expect("preserved destination metadata");
        assert!(metadata.is_file());

        let _ = std::fs::remove_dir_all(&base);
    }

/// The sender picks the delta chunk size, so a receiver bounds how many chunks
/// it splits its existing destination into: past its budget it falls back to
/// a full transfer before building the chunks (asupersync-9avoui F1).
#[test]
fn a_baseline_finer_than_the_chunk_budget_falls_back_to_a_full_transfer() {
    let root = canonical_test_root("delta-baseline-budget");
    std::fs::write(root.join("data"), vec![7u8; 100]).expect("write the existing destination");
    let manifest = TransferManifest {
        transfer_id: "budget".to_string(),
        root_name: "data".to_string(),
        is_directory: false,
        total_bytes: 100,
        merkle_root_hex: "00".repeat(32),
        metadata_root_hex: None,
        directory_metadata: None,
        entries: Vec::new(),
        delta_manifest: None,
    };
    let runtime = crate::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("test runtime");
    let scan = |chunk_size: usize| {
        let (root, manifest) = (root.clone(), manifest.clone());
        runtime.block_on(runtime.handle().spawn(async move {
            let delta = DeltaManifestWire {
                schema: ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(),
                tree_id: "data".to_string(),
                chunk_size,
                total_size_bytes: 100,
                merkle_root_hex: "11".repeat(32),
                chunks: Vec::new(),
            };
            let config = TransferConfig::default();
            build_receiver_delta_baseline(&root, &manifest, &delta, &config, 8)
                .await
                .expect("scan the existing destination")
                .map(|baseline| baseline.manifest.chunks.len())
        }))
    };
    // 100 one-byte chunks exceed a budget of 8: no baseline, a full transfer.
    assert_eq!(scan(1), None);
    // Two 64-byte chunks fit.
    assert_eq!(scan(64), Some(2));
}
