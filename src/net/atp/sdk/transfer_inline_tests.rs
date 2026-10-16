    use super::*;
    use crate::cx::Cx;
    use crate::net::atp::protocol::{
        CapabilityAction, CapabilityGrant, CapabilityGrantId, CapabilityScope, PeerId,
        ProtocolError, SessionContextKind,
    };
    use crate::net::atp::sdk::{AtpSdk, SdkMode, SessionConfig, SessionOptions};

    fn granted_direct_options(config: &SessionConfig, peer: PeerId, label: &str) -> SessionOptions {
        SessionOptions::direct(peer).with_grants(vec![CapabilityGrant::new(
            CapabilityGrantId::from_label(label),
            peer,
            config.local_peer,
            [CapabilityAction::Read, CapabilityAction::Write],
            CapabilityScope::for_context(SessionContextKind::Direct),
        )])
    }

    fn reachable_daemon_endpoint() -> (std::net::TcpListener, String) {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback daemon placeholder");
        let endpoint = listener
            .local_addr()
            .expect("read loopback daemon placeholder address")
            .to_string();
        (listener, endpoint)
    }

    async fn daemon_delegated_session(cx: &Cx, label: &str) -> (std::net::TcpListener, AtpSession) {
        let (listener, endpoint) = reachable_daemon_endpoint();
        let config = SessionConfig::default();
        let peer = PeerId::from_label(label);
        let session_options = granted_direct_options(&config, peer, label);
        let sdk = AtpSdk::new_in_process(config);
        let mut session = sdk.open_session(cx, session_options).await.unwrap();
        session.mode = SdkMode::DaemonDelegated {
            daemon_endpoint: endpoint,
            auth_token: Some("token".to_string()),
        };
        (listener, session)
    }

    #[test]
    fn transfer_request_construction() {
        let source = TransferSource::Object {
            data: vec![1, 2, 3, 4],
            content_type: Some("text/plain".to_string()),
        };
        let destination = TransferDestination::File {
            path: PathBuf::from("/tmp/test.txt"),
        };
        let request = TransferRequest {
            source: source.clone(),
            destination: destination.clone(),
            options: TransferOptions::default(),
        };

        assert_eq!(request.source, source);
        assert_eq!(request.destination, destination);
    }

    #[test]
    fn in_process_send_object_fails_closed_after_source_validation() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let peer = PeerId::from_label("test_peer");
            let session_options = granted_direct_options(&config, peer, "send-fail-closed");
            let sdk = AtpSdk::new_in_process(config);
            let cx = Cx::for_testing();

            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let source = TransferSource::Object {
                data: vec![0u8; 1024],
                content_type: Some("application/octet-stream".to_string()),
            };
            let destination = TransferDestination::Object {
                object_id: "test_object".to_string(),
            };
            let request = TransferRequest {
                source,
                destination,
                options: TransferOptions::default(),
            };

            let result = session.send_object(&cx, request).await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "in-process SDK send must not fabricate an active transfer: {result:?}"
            );
        });
    }

    #[test]
    fn in_process_send_file_fails_closed_but_missing_file_still_validates_first() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("send_file_peer");
            let session = sdk
                .open_session(&cx, granted_direct_options(&config, peer, "send-file"))
                .await
                .unwrap();

            let valid_request = TransferRequest {
                source: TransferSource::File {
                    path: PathBuf::from("src/net/atp/sdk/transfer.rs"),
                },
                destination: TransferDestination::Object {
                    object_id: "transfer-rs".to_string(),
                },
                options: TransferOptions::default(),
            };
            let result = session.send_object(&cx, valid_request).await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "valid file send must fail closed without a worker: {result:?}"
            );

            let missing_request = TransferRequest {
                source: TransferSource::File {
                    path: PathBuf::from("__asupersync_missing_sdk_send_source__"),
                },
                destination: TransferDestination::Stream,
                options: TransferOptions::default(),
            };
            let result = session.send_object(&cx, missing_request).await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Disk(DiskError::FileNotFound))
                ),
                "missing source must be rejected before fail-closed send: {result:?}"
            );
        });
    }

    #[test]
    fn in_process_sync_tree_and_stream_buffer_fail_closed() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("send_wrapper_peer");
            let session = sdk
                .open_session(&cx, granted_direct_options(&config, peer, "send-wrappers"))
                .await
                .unwrap();

            let result = session
                .sync_tree(
                    &cx,
                    Path::new("src/net/atp/sdk"),
                    "/remote/sdk",
                    TransferOptions::default(),
                )
                .await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "sync_tree must not fabricate transfer success: {result:?}"
            );

            let result = session
                .stream_large_buffer(
                    &cx,
                    vec![1, 2, 3, 4],
                    TransferDestination::Object {
                        object_id: "buffer".to_string(),
                    },
                    TransferOptions::default(),
                )
                .await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "stream_large_buffer must not fabricate transfer success: {result:?}"
            );
        });
    }

    #[test]
    fn active_transfer_cancel_is_idempotent_for_real_transfer_handles() {
        let (mut lab, root) = owned_worker_tests::lab(0x53_0001);
        let (_release, mut receive) = crate::channel::oneshot::channel::<()>();
        let mut transfer =
            owned_worker_tests::admit(&mut lab, root, move |cx, _reporter| async move {
                assert!(matches!(
                    receive.recv(&cx).await,
                    Err(crate::channel::oneshot::RecvError::Cancelled)
                ));
                AtpOutcome::Cancelled(cx.cancel_reason().expect("actual worker cancellation"))
            });
        futures_lite::future::block_on(async {
            let cancel_result = transfer.cancel().await;
            assert!(cancel_result.is_ok());
            let repeated_cancel_result = transfer.cancel().await;
            assert!(repeated_cancel_result.is_ok());
        });
        lab.run_until_idle();
        let terminal = transfer.terminal().unwrap();
        assert!(
            matches!(&terminal.worker_join, Err(JoinError::Cancelled(reason))
            if reason.message.as_deref() == Some("ATP transfer cancelled"))
        );
        assert_eq!(terminal.outcome, terminal.worker_outcome.clone().unwrap());
        owned_worker_tests::clean(&mut lab, root, transfer.worker.task_id());
    }

    #[test]
    fn receive_without_transport_fails_closed() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("receive_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "receive-fail-closed"),
                )
                .await
                .unwrap();

            let result = session
                .receive_object(&cx, TransferDestination::Stream, TransferOptions::default())
                .await;
            match result {
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented)) => {}
                other => panic!("receive must fail closed without a real transport: {other:?}"), // ubs:ignore
            }
        });
    }

    #[test]
    fn daemon_delegated_transfer_stubs_use_asup_e701_when_endpoint_is_reachable() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let (_listener, session) = daemon_delegated_session(&cx, "daemon-transfer-stubs").await;

            let request = TransferRequest {
                source: TransferSource::Object {
                    data: vec![1, 2, 3, 4],
                    content_type: Some("application/octet-stream".to_string()),
                },
                destination: TransferDestination::Object {
                    object_id: "daemon-object".to_string(),
                },
                options: TransferOptions::default(),
            };
            assert!(
                matches!(
                    session.send_object(&cx, request).await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated send stub must report ASUP-E701"
            );

            assert!(
                matches!(
                    session
                        .receive_object(
                            &cx,
                            TransferDestination::Stream,
                            TransferOptions::default(),
                        )
                        .await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated receive stub must report ASUP-E701"
            );

            let transfer_id = TransferId::new("daemon-transfer");
            assert!(
                matches!(
                    session
                        .resume_transfer(&cx, &transfer_id, "1:2:data_transfer")
                        .await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated resume stub must report ASUP-E701"
            );
            assert!(
                matches!(
                    session
                        .cancel_transfer(&cx, &transfer_id, Some("user requested".to_string()))
                        .await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated cancel stub must report ASUP-E701"
            );
            assert!(
                matches!(
                    session
                        .verify_object(&cx, Path::new("src/net/atp/sdk/transfer.rs"), None)
                        .await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated verify stub must report ASUP-E701"
            );
        });
    }

    #[test]
    fn resume_without_active_transfer_fails_closed() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("resume_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "resume-fail-closed"),
                )
                .await
                .unwrap();
            let transfer_id = TransferId::new("missing-transfer");

            let result = session
                .resume_transfer(&cx, &transfer_id, "1:2:data_transfer")
                .await;
            match result {
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented)) => {}
                other => panic!("resume must fail closed without active transfer state: {other:?}"), // ubs:ignore
            }
        });
    }

    #[test]
    fn session_cancel_without_active_transfer_fails_closed() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("cancel_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "cancel-fail-closed"),
                )
                .await
                .unwrap();
            let transfer_id = TransferId::new("missing-transfer");

            let result = session
                .cancel_transfer(&cx, &transfer_id, Some("user requested".to_string()))
                .await;
            match result {
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented)) => {}
                other => panic!("session cancel must not fabricate success: {other:?}"), // ubs:ignore
            }
        });
    }

    #[test]
    fn detached_object_signature_is_session_bound_and_constant_time_checked() {
        futures_lite::future::block_on(async {
            use hmac::{Hmac, KeyInit, Mac};
            use sha2::{Digest, Sha256};

            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("signature_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "signature-verification"),
                )
                .await
                .unwrap();

            let object = b"authenticated object payload";
            let mut hasher = Sha256::new();
            hasher.update(object);
            let hash: [u8; 32] = hasher.finalize().into();
            // Reconstruct the legacy sidecar using only public getters and
            // protocol constants, without calling either production key/tag
            // helper. This pins compatibility and demonstrates why a matching
            // v1 checksum is not evidence of authenticated object authorship.
            let public_material = [
                session.session_id().as_bytes().as_slice(),
                session.local_peer().as_bytes().as_slice(),
                session.remote_peer().as_bytes().as_slice(),
                session.transfer_nonce().as_bytes().as_slice(),
                session.transcript_hash().as_bytes().as_slice(),
            ]
            .concat();
            let mut extract =
                Hmac::<Sha256>::new_from_slice(b"asupersync-atp-sdk-object-signature-key-v1")
                    .unwrap();
            extract.update(&public_material);
            let mut expand =
                Hmac::<Sha256>::new_from_slice(&extract.finalize().into_bytes()).unwrap();
            expand.update(b"session-bound-object-verification\x01");
            let mut attacker_mac =
                Hmac::<Sha256>::new_from_slice(&expand.finalize().into_bytes()).unwrap();
            attacker_mac.update(b"asupersync::net::atp::sdk::object-signature::v1");
            attacker_mac.update(session.session_id().as_bytes());
            attacker_mac.update(&32u64.to_be_bytes());
            attacker_mac.update(&hash);
            attacker_mac.update(&(object.len() as u64).to_be_bytes());
            let signature: [u8; 32] = attacker_mac.finalize().into_bytes().into();
            assert_eq!(
                signature,
                session.compute_detached_object_signature(&hash, object.len() as u64)
            );
            let envelope = serde_json::json!({
                "algorithm": OBJECT_SIGNATURE_ALGORITHM,
                "session_id_hex": hex::encode(session.session_id().as_bytes()),
                "hash_hex": hex::encode(hash),
                "size_bytes": object.len() as u64,
                "signature_hex": hex::encode(signature),
            });
            let payload = serde_json::to_vec(&envelope).unwrap();

            assert!(session.verify_detached_object_signature_payload(
                &payload,
                &hash,
                object.len() as u64
            ));

            let mut tampered = envelope;
            tampered["signature_hex"] = serde_json::Value::String(hex::encode([0xAAu8; 32]));
            let tampered_payload = serde_json::to_vec(&tampered).unwrap();
            assert!(!session.verify_detached_object_signature_payload(
                &tampered_payload,
                &hash,
                object.len() as u64
            ));
        });
    }

    #[test]
    fn verify_object_missing_detached_signature_is_integrity_only() {
        futures_lite::future::block_on(async {
            use sha2::{Digest, Sha256};

            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("unsigned_object_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "unsigned-object-verification"),
                )
                .await
                .unwrap();

            let object_path = Path::new("src/net/atp/sdk/transfer.rs");
            assert!(
                !detached_object_signature_path(object_path).exists(),
                "fixture must not carry a detached signature"
            );
            let object = std::fs::read(object_path).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&object);
            let expected_hash: [u8; 32] = hasher.finalize().into();

            let result = session
                .verify_object(&cx, object_path, Some(&expected_hash[..]))
                .await;
            let verification = match result {
                AtpOutcome::Ok(verification) => verification,
                other => panic!("verify_object should return verification data: {other:?}"),
            };

            assert!(verification.integrity_check_passed);
            assert_eq!(verification.signature_valid, None);
            assert!(
                !verification.verified,
                "missing detached signatures must not be treated as authenticated"
            );
        });
    }

    #[test]
    fn verify_object_decides_integrity_by_hash_alone() {
        // asupersync-bi2462.127: a file ending in zero bytes at a 512-byte
        // multiple (every tar archive) failed even with a matching hash, and an
        // empty file failed unless its path contained "empty".
        use sha2::{Digest, Sha256};

        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("hash_only_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "hash-only-verification"),
                )
                .await
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let mut archive = vec![0x5a_u8; 512];
            archive.extend_from_slice(&[0_u8; 1024]);
            let tar_path = dir.path().join("bundle.tar");
            std::fs::write(&tar_path, &archive).unwrap();
            let zero_path = dir.path().join("zero.bin");
            std::fs::write(&zero_path, b"").unwrap();

            for (path, bytes) in [(&tar_path, &archive[..]), (&zero_path, &[][..])] {
                let expected: [u8; 32] = Sha256::digest(bytes).into();
                match session.verify_object(&cx, path, Some(&expected[..])).await {
                    AtpOutcome::Ok(verification) => {
                        assert!(verification.integrity_check_passed, "{}", path.display());
                        assert_eq!(verification.hash, expected.to_vec());
                        assert_eq!(verification.size_bytes, u64::try_from(bytes.len()).unwrap());
                    }
                    other => panic!("verify_object {}: {other:?}", path.display()),
                }
            }

            let expected: [u8; 32] = Sha256::digest(&archive).into();
            let mut tampered = archive.clone();
            tampered[3] ^= 1;
            std::fs::write(&tar_path, &tampered).unwrap();
            match session
                .verify_object(&cx, &tar_path, Some(&expected[..]))
                .await
            {
                AtpOutcome::Ok(verification) => assert!(!verification.integrity_check_passed),
                other => panic!("tampered verify_object: {other:?}"),
            }

            let cancelled = Cx::for_testing();
            cancelled.set_cancel_reason(CancelReason::user("verify cancelled"));
            assert!(matches!(
                session
                    .verify_object(&cancelled, &tar_path, Some(&expected[..]))
                    .await,
                AtpOutcome::Cancelled(_)
            ));
        });
    }

    #[test]
    fn directory_size_uses_real_filesystem_metadata() {
        fn std_directory_size(path: &Path) -> u64 {
            let mut total = 0u64;
            let mut stack = vec![path.to_path_buf()];
            while let Some(path) = stack.pop() {
                for entry in std::fs::read_dir(path).unwrap() {
                    // ubs:ignore
                    let entry = entry.unwrap();
                    let metadata = entry.metadata().unwrap();
                    if metadata.is_file() {
                        total += metadata.len();
                    } else if metadata.is_dir() {
                        stack.push(entry.path()); // ubs:ignore - controlled test env
                    }
                }
            }
            total
        }

        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("size_peer");
            let session = sdk
                .open_session(&cx, granted_direct_options(&config, peer, "directory-size"))
                .await
                .unwrap();
            let path = PathBuf::from("src/net/atp/sdk");
            let source = TransferSource::Directory {
                path: path.clone(),
                follow_symlinks: false,
            };

            let size = session.calculate_transfer_size(&source).await.unwrap();
            assert_eq!(size, std_directory_size(&path));
            assert_ne!(size, 1024 * 1024);
        });
    }

    #[test]
    fn transfer_size_metadata_failure_is_not_reported_as_zero() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("size_error_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "directory-size-error"),
                )
                .await
                .unwrap();
            let source = TransferSource::File {
                path: PathBuf::from("__asupersync_missing_size_source__"),
            };

            match session.calculate_transfer_size(&source).await {
                AtpOutcome::Err(AtpError::Disk(DiskError::IoError)) => {}
                other => panic!("metadata failure must remain an error, got {other:?}"), // ubs:ignore
            }
        });
    }

    // Actual scheduled worker lifecycle tests. These fixtures do not perform
    // an authenticated ATP transfer or validate a protocol commit; the public
    // session operations above remain explicitly unavailable until wired.
    mod owned_worker_tests {
        use super::*;
        use crate::channel::oneshot;
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::{Budget, RegionId, TaskId};
        use std::sync::atomic::AtomicUsize;
        use std::task::Wake;

        pub(super) fn lab(seed: u64) -> (LabRuntime, RegionId) {
            let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(4096));
            let root = lab.state.create_root_region(Budget::INFINITE);
            (lab, root)
        }

        pub(super) fn admit<F, Fut>(
            lab: &mut LabRuntime,
            root: RegionId,
            worker: F,
        ) -> ActiveTransfer
        where
            F: FnOnce(Cx, TransferProgressReporter) -> Fut + Send + 'static,
            Fut: Future<Output = AtpOutcome<TransferProgress>> + Send + 'static,
        {
            let published = Arc::new(parking_lot::Mutex::new(None));
            let slot = Arc::clone(&published);
            let coordinator: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let cx = Cx::current().expect("actual ATP admission coordinator");
                let mut transfer = ActiveTransfer::spawn_worker(
                    &cx,
                    &cx.scope(),
                    TransferId::new("owned-worker"),
                    TransferOptions::default(),
                    worker,
                )
                .expect("actual scoped runtime admission");
                assert_eq!(transfer.state(), ActiveTransferState::Pending);
                *slot.lock() = Some(transfer);
            });
            let (id, mut joined) = lab
                .state
                .create_task(root, Budget::INFINITE, coordinator)
                .unwrap();
            lab.scheduler.lock().schedule(id, 0);
            assert!(lab.run_until_idle() < 4096);
            assert_eq!(joined.try_join(), Ok(Some(())));
            let transfer = published.lock().take().expect("admitted transfer owner");
            assert_ne!(transfer.worker.task_id(), id);
            transfer
        }

        pub(super) fn clean(lab: &mut LabRuntime, root: RegionId, worker: TaskId) {
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            assert_eq!(lab.state.live_task_count(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert_eq!(lab.state.region(root).unwrap().pending_spawn_count(), 0);
            let trace = lab.state.trace_handle().snapshot();
            for kind in [
                crate::trace::TraceEventKind::Spawn,
                crate::trace::TraceEventKind::Complete,
            ] {
                assert_eq!(trace.iter().filter(|event| {
                    event.kind == kind
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                            if task == worker && region == root)
                }).count(), 1, "actual full worker ID {worker:?} {kind:?}");
            }
            let effects = lab.state.cancel_request(
                root,
                &CancelReason::user("ATP worker test complete"),
                None,
            );
            let (tasks, wakes) = effects.into_parts();
            assert!(tasks.is_empty());
            wakes.dispatch();
            lab.state.advance_region_state(root);
            assert!(lab.state.region(root).is_none());
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            eprintln!(
                "ATP owned worker cleanup worker={worker:?} root={root:?} live_tasks={} pending_obligations={} root_retained={}",
                lab.state.live_task_count(),
                lab.state.pending_obligation_count(),
                lab.state.region(root).is_some()
            );
        }

        fn progress(bytes: u64, phase: TransferPhase) -> TransferProgress {
            TransferProgress {
                transfer_id: TransferId::new("owned-worker"),
                bytes_transferred: bytes,
                total_bytes: 65,
                speed_bytes_per_sec: 0,
                eta_ms: None,
                phase,
                active_paths: 1,
                repair_symbols_active: false,
            }
        }

        #[derive(Default)]
        struct WakeCount(AtomicUsize);

        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        struct Dropped(Arc<AtomicUsize>);

        impl Drop for Dropped {
            fn drop(&mut self) {
                assert_eq!(self.0.fetch_add(1, Ordering::SeqCst), 0);
            }
        }

        #[test]
        fn owned_transfer_delayed_coalesced_progress_preserves_joined_terminal() {
            let (mut lab, root) = lab(0x53_0010);
            let (start, mut first) = oneshot::channel::<()>();
            let (middle, mut next) = oneshot::channel::<()>();
            let (finish, mut cleanup) = oneshot::channel::<()>();
            let drops = Arc::new(AtomicUsize::new(0));
            let resource = Dropped(Arc::clone(&drops));
            let mut transfer = admit(&mut lab, root, move |cx, reporter| async move {
                let _resource = resource;
                first.recv(&cx).await.unwrap();
                for bytes in 1..=64 {
                    assert_eq!(
                        reporter.report(progress(bytes, TransferPhase::DataTransfer)),
                        Ok(bytes)
                    );
                }
                next.recv(&cx).await.unwrap();
                assert_eq!(
                    reporter.report(progress(65, TransferPhase::Finalization)),
                    Ok(65)
                );
                cleanup.recv(&cx).await.unwrap();
                AtpOutcome::Ok(progress(65, TransferPhase::Completed))
            });
            let worker = transfer.worker.task_id();
            assert_eq!(transfer.state(), ActiveTransferState::Running);
            let wake = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wake));
            {
                let mut first_update = Box::pin(transfer.next_progress_snapshot());
                assert!(
                    first_update
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
            }
            assert_eq!(wake.0.load(Ordering::SeqCst), 0);
            for _ in 0..3 {
                assert!(!futures_lite::future::block_on(transfer.is_complete()));
                assert!(transfer.terminal().is_none());
            }
            start.send_blocking(()).unwrap();
            assert!(lab.run_until_idle() < 4096);
            assert!(
                wake.0.load(Ordering::SeqCst) > 0,
                "actual progress wakes a registered Pending observer"
            );
            for _ in 0..3 {
                assert!(!futures_lite::future::block_on(transfer.is_complete()));
            }
            let snapshot =
                futures_lite::future::block_on(transfer.next_progress_snapshot()).unwrap();
            assert_eq!((snapshot.sequence, snapshot.skipped), (64, 63));
            assert_eq!(snapshot.progress, progress(64, TransferPhase::DataTransfer));
            assert!(transfer.shared.lock().pending.is_none());
            middle.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert!(!futures_lite::future::block_on(transfer.is_complete()));
            let snapshot =
                futures_lite::future::block_on(transfer.next_progress_snapshot()).unwrap();
            assert_eq!((snapshot.sequence, snapshot.skipped), (65, 0));
            assert_eq!(snapshot.progress.phase, TransferPhase::Finalization);
            let wake_before = wake.0.load(Ordering::SeqCst);
            {
                let mut waiting = Box::pin(transfer.wait_for_terminal());
                assert!(
                    waiting
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
            }
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            finish.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert!(wake.0.load(Ordering::SeqCst) > wake_before);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            for _ in 0..3 {
                assert!(futures_lite::future::block_on(transfer.is_complete()));
            }
            let terminal = transfer.terminal().unwrap().clone();
            assert_eq!(terminal.worker_join, Ok(()));
            assert_eq!(
                terminal.outcome,
                AtpOutcome::Ok(progress(65, TransferPhase::Completed))
            );
            assert_eq!(terminal.worker_outcome, Some(terminal.outcome.clone()));
            assert!(futures_lite::future::block_on(transfer.cancel()).is_ok());
            assert_eq!(
                transfer.terminal(),
                Some(&terminal),
                "late cancellation cannot rewrite a joined success"
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                Some(progress(65, TransferPhase::Completed))
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                None
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress_snapshot()),
                None
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.wait_for_terminal()),
                &terminal
            );
            assert_eq!(transfer.state(), ActiveTransferState::Terminal);
            clean(&mut lab, root, worker);
        }

        #[test]
        fn owned_transfer_full_or_absent_progress_never_substitutes_for_worker_completion() {
            for report_updates in [false, true] {
                let (mut lab, root) = lab(0x53_0020 + u64::from(report_updates));
                let (release, mut gate) = oneshot::channel::<()>();
                let drops = Arc::new(AtomicUsize::new(0));
                let resource = Dropped(Arc::clone(&drops));
                let transfer = admit(&mut lab, root, move |cx, reporter| async move {
                    let _resource = resource;
                    if report_updates {
                        for bytes in 1..=65 {
                            reporter
                                .report(progress(bytes, TransferPhase::DataTransfer))
                                .unwrap();
                        }
                    }
                    drop(reporter);
                    gate.recv(&cx).await.unwrap();
                    AtpOutcome::Ok(progress(65, TransferPhase::Completed))
                });
                let worker = transfer.worker.task_id();
                let shared = Arc::clone(&transfer.shared);
                assert_eq!(shared.lock().sequence, if report_updates { 65 } else { 0 });
                assert_eq!(shared.lock().pending.is_some(), report_updates);
                let wake = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&wake));
                let mut completion = Box::pin(transfer.wait_for_completion());
                assert!(
                    completion
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                assert_eq!(
                    lab.run_until_idle(),
                    0,
                    "lost reporter/full slot cannot self-spin or terminate a live worker"
                );
                release.send_blocking(()).unwrap();
                lab.run_until_idle();
                assert!(wake.0.load(Ordering::SeqCst) > 0);
                assert_eq!(
                    completion.as_mut().poll(&mut Context::from_waker(&waker)),
                    Poll::Ready(Some(progress(65, TransferPhase::Completed)))
                );
                drop(completion);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert!(shared.lock().closed);
                assert!(shared.lock().pending.is_none());
                clean(&mut lab, root, worker);
            }
        }

        struct TerminalWorker {
            cx: Cx,
            gate: oneshot::Receiver<()>,
            outcome: Option<AtpOutcome<TransferProgress>>,
            drops: Arc<AtomicUsize>,
            mode: u8,
        }

        impl Future for TerminalWorker {
            type Output = AtpOutcome<TransferProgress>;

            fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.gate.poll_recv_uninterruptible(ctx).is_pending() {
                    return Poll::Pending;
                }
                assert!(!matches!(self.mode, 1 | 5), "ATP primary worker poll panic");
                Poll::Ready(self.outcome.take().expect("worker returns once"))
            }
        }

        impl Drop for TerminalWorker {
            fn drop(&mut self) {
                assert_eq!(self.drops.fetch_add(1, Ordering::SeqCst), 0);
                if matches!(self.mode, 2 | 4 | 5) {
                    self.cx.cancel_with(
                        crate::types::CancelKind::User,
                        Some("ATP worker capture retired"),
                    );
                }
                assert!(!matches!(self.mode, 3 | 5), "ATP worker destructor panic");
            }
        }

        #[test]
        fn owned_transfer_actual_worker_retirement_and_canonical_severity_are_independent() {
            for mode in 0_u8..10 {
                let (mut lab, root) = lab(0x53_0030 + u64::from(mode));
                let (release, gate) = oneshot::channel::<()>();
                let drops = Arc::new(AtomicUsize::new(0));
                let worker_drops = Arc::clone(&drops);
                let mut final_progress = progress(65, TransferPhase::Completed);
                match mode {
                    6 => final_progress.transfer_id = TransferId::new("wrong-worker"),
                    7 => final_progress.phase = TransferPhase::Finalization,
                    8 => final_progress.bytes_transferred = 64,
                    _ => {}
                }
                let returned = match mode {
                    2 => AtpOutcome::Panicked(PanicPayload::new("ATP encoded worker panic")),
                    9 => AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
                    _ => AtpOutcome::Ok(final_progress),
                };
                let expected_return = returned.clone();
                let mut transfer = admit(&mut lab, root, move |cx, reporter| {
                    drop(reporter);
                    TerminalWorker {
                        cx,
                        gate,
                        outcome: Some(returned),
                        drops: worker_drops,
                        mode,
                    }
                });
                let worker = transfer.worker.task_id();
                assert!(transfer.terminal().is_none());
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                let wake = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&wake));
                {
                    let mut waiting = Box::pin(transfer.next_progress());
                    assert!(
                        waiting
                            .as_mut()
                            .poll(&mut Context::from_waker(&waker))
                            .is_pending()
                    );
                }
                assert_eq!(lab.run_until_idle(), 0);
                assert!(!futures_lite::future::block_on(transfer.is_complete()));
                release.send_blocking(()).unwrap();
                lab.run_until_idle();
                assert!(wake.0.load(Ordering::SeqCst) > 0);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                let terminal = transfer.terminal().expect("actual worker joined").clone();
                if matches!(mode, 2 | 4 | 5) {
                    let Err(JoinError::Cancelled(reason)) = &terminal.worker_join else {
                        panic!(
                            "canonical runtime cancellation must survive user cleanup: {terminal:?}"
                        )
                    };
                    assert_eq!(reason.kind(), crate::types::CancelKind::User);
                    assert_eq!(
                        reason.message.as_deref(),
                        Some("ATP worker capture retired")
                    );
                    assert!(reason.cause.is_none());
                    if mode == 4 {
                        assert_eq!(terminal.outcome, AtpOutcome::Cancelled(reason.clone()));
                        assert_eq!(terminal.worker_outcome, Some(expected_return.clone()));
                    }
                } else {
                    assert_eq!(terminal.worker_join, Ok(()));
                }
                match mode {
                    0 | 9 => assert_eq!(terminal.outcome, expected_return),
                    1 | 5 => assert_eq!(
                        terminal.outcome,
                        AtpOutcome::Panicked(PanicPayload::new("ATP primary worker poll panic"))
                    ),
                    2 => assert_eq!(terminal.outcome, expected_return),
                    3 => assert_eq!(
                        terminal.outcome,
                        AtpOutcome::Panicked(PanicPayload::new("ATP worker destructor panic"))
                    ),
                    4 => {}
                    6..=8 => {
                        assert_eq!(terminal.worker_outcome, Some(expected_return.clone()));
                        assert_eq!(
                            terminal.outcome,
                            AtpOutcome::Err(AtpError::Protocol(
                                ProtocolError::SessionStateMismatch
                            ))
                        );
                    }
                    _ => unreachable!(),
                }
                if matches!(mode, 1 | 2 | 5) {
                    assert_eq!(terminal.worker_outcome, Some(terminal.outcome.clone()));
                }
                if mode == 3 {
                    assert_eq!(terminal.worker_outcome, Some(expected_return.clone()));
                }
                assert_eq!(
                    terminal.cleanup_panic,
                    matches!(mode, 3 | 5)
                        .then(|| { PanicPayload::new("ATP worker destructor panic") })
                );
                for _ in 0..3 {
                    assert!(futures_lite::future::block_on(transfer.is_complete()));
                    assert_eq!(transfer.terminal(), Some(&terminal));
                }
                let final_progress = futures_lite::future::block_on(transfer.next_progress());
                if mode == 0 {
                    assert_eq!(final_progress, Some(progress(65, TransferPhase::Completed)));
                } else {
                    assert_eq!(
                        final_progress, None,
                        "an error without observations cannot manufacture successful progress"
                    );
                }
                assert_eq!(transfer.terminal(), Some(&terminal));
                clean(&mut lab, root, worker);
                eprintln!(
                    "ATP owned worker mode={mode} worker={worker:?} terminal={terminal:?} drops=1"
                );
            }
        }

        #[test]
        fn owned_transfer_cancel_waits_for_real_cleanup_and_drop_requests_worker_cancel() {
            for drop_owner in [false, true] {
                let (mut lab, root) = lab(0x53_0050 + u64::from(drop_owner));
                let (_never, mut pending) = oneshot::channel::<()>();
                let (release, mut cleanup) = oneshot::channel::<()>();
                let seen = Arc::new(parking_lot::Mutex::new(None));
                let worker_seen = Arc::clone(&seen);
                let drops = Arc::new(AtomicUsize::new(0));
                let resource = Dropped(Arc::clone(&drops));
                let mut transfer = admit(&mut lab, root, move |cx, reporter| async move {
                    let _resource = resource;
                    reporter
                        .report(progress(12, TransferPhase::DataTransfer))
                        .unwrap();
                    assert_eq!(pending.recv(&cx).await, Err(oneshot::RecvError::Cancelled));
                    let reason = cx.cancel_reason().expect("actual worker cancel");
                    *worker_seen.lock() = Some(reason.clone());
                    // Required cleanup is deliberately uninterruptible, and
                    // owns its actual channel registration while held.
                    cleanup.recv_uninterruptible().await.unwrap();
                    AtpOutcome::Cancelled(reason)
                });
                let worker = transfer.worker.task_id();
                if drop_owner {
                    drop(transfer);
                    lab.run_until_idle();
                    assert_eq!(
                        seen.lock().as_ref().unwrap().message.as_deref(),
                        Some("ATP transfer handle dropped")
                    );
                    assert_eq!(drops.load(Ordering::SeqCst), 0);
                    assert_eq!(lab.state.live_task_count(), 1);
                    assert_eq!(lab.run_until_idle(), 0);
                    release.send_blocking(()).unwrap();
                    lab.run_until_idle();
                } else {
                    assert!(futures_lite::future::block_on(transfer.cancel()).is_ok());
                    lab.run_until_idle();
                    let reason = seen.lock().clone().expect("worker observed cancellation");
                    assert_eq!(reason.message.as_deref(), Some("ATP transfer cancelled"));
                    assert_eq!(drops.load(Ordering::SeqCst), 0);
                    assert_eq!(lab.state.live_task_count(), 1);
                    for _ in 0..3 {
                        assert!(!futures_lite::future::block_on(transfer.is_complete()));
                    }
                    let wake = Arc::new(WakeCount::default());
                    let waker = Waker::from(Arc::clone(&wake));
                    {
                        let mut waiting = Box::pin(transfer.wait_for_terminal());
                        assert!(
                            waiting
                                .as_mut()
                                .poll(&mut Context::from_waker(&waker))
                                .is_pending()
                        );
                    }
                    assert_eq!(lab.run_until_idle(), 0);
                    release.send_blocking(()).unwrap();
                    lab.run_until_idle();
                    assert!(wake.0.load(Ordering::SeqCst) > 0);
                    let terminal = transfer.terminal().unwrap().clone();
                    assert_eq!(
                        terminal.worker_join,
                        Err(JoinError::Cancelled(reason.clone()))
                    );
                    assert_eq!(
                        terminal.worker_outcome,
                        Some(AtpOutcome::Cancelled(reason.clone()))
                    );
                    assert_eq!(terminal.outcome, AtpOutcome::Cancelled(reason));
                    // Repeated completion queries did not consume the update.
                    assert_eq!(
                        futures_lite::future::block_on(transfer.next_progress()),
                        Some(progress(12, TransferPhase::DataTransfer))
                    );
                    assert_eq!(
                        futures_lite::future::block_on(transfer.next_progress()),
                        Some(progress(12, TransferPhase::Cancelled))
                    );
                    assert_eq!(
                        futures_lite::future::block_on(transfer.next_progress()),
                        None
                    );
                    assert_eq!(transfer.terminal(), Some(&terminal));
                }
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                clean(&mut lab, root, worker);
            }
        }

        #[test]
        fn owned_transfer_reporter_refuses_false_terminal_and_preserves_public_traits() {
            fn public_traits<T: Send + Sync + Unpin + std::fmt::Debug>() {}
            public_traits::<ActiveTransfer>();
            public_traits::<TransferProgressReporter>();
            let cx = Cx::for_testing();
            let refused = ActiveTransfer::spawn_worker(
                &cx,
                &cx.scope(),
                TransferId::new("no-runtime"),
                TransferOptions::default(),
                |_, _| async { panic!("an unavailable runtime must not run a worker") },
            );
            assert!(matches!(refused, Err(SpawnError::RuntimeUnavailable)));

            let (mut lab, root) = lab(0x53_0060);
            let (release, mut gate) = oneshot::channel::<()>();
            let reporter_slot = Arc::new(parking_lot::Mutex::new(None));
            let publication = Arc::clone(&reporter_slot);
            let mut transfer = admit(&mut lab, root, move |cx, reporter| async move {
                *publication.lock() = Some(reporter.clone());
                gate.recv(&cx).await.unwrap();
                AtpOutcome::Err(AtpError::Disk(DiskError::IoError))
            });
            let worker = transfer.worker.task_id();
            let reporter = reporter_slot.lock().take().unwrap();
            let mut wrong = progress(1, TransferPhase::DataTransfer);
            wrong.transfer_id = TransferId::new("other-transfer");
            assert_eq!(
                reporter.report(wrong),
                Err(TransferProgressError::IdentityMismatch)
            );
            for phase in [
                TransferPhase::Completed,
                TransferPhase::Failed,
                TransferPhase::Cancelled,
            ] {
                assert_eq!(
                    reporter.report(progress(65, phase)),
                    Err(TransferProgressError::TerminalPhase)
                );
            }
            assert_eq!(
                reporter.report(progress(66, TransferPhase::DataTransfer)),
                Err(TransferProgressError::InvalidByteCount)
            );
            assert_eq!(transfer.shared.lock().sequence, 0);
            assert!(transfer.shared.lock().pending.is_none());
            assert!(!futures_lite::future::block_on(transfer.is_complete()));
            let mut unknown_size = progress(3, TransferPhase::DataTransfer);
            unknown_size.total_bytes = 0;
            assert_eq!(reporter.report(unknown_size), Ok(1));
            assert_eq!(
                reporter.report(progress(2, TransferPhase::DataTransfer)),
                Ok(2)
            );
            assert!(!futures_lite::future::block_on(transfer.is_complete()));
            release.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert!(transfer.terminal().is_some());
            assert_eq!(
                reporter.report(progress(3, TransferPhase::DataTransfer)),
                Err(TransferProgressError::Closed)
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                Some(progress(2, TransferPhase::DataTransfer))
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                Some(progress(2, TransferPhase::Failed))
            );
            assert_eq!(
                transfer.terminal().unwrap().outcome,
                AtpOutcome::Err(AtpError::Disk(DiskError::IoError))
            );
            drop(transfer);
            assert_eq!(
                reporter.report(progress(3, TransferPhase::DataTransfer)),
                Err(TransferProgressError::Closed)
            );
            clean(&mut lab, root, worker);
        }

        #[test]
        fn owned_transfer_cancel_before_admission_never_enters_worker_factory() {
            cancelled_before_admission(false);
        }

        #[test]
        fn owned_transfer_unadmitted_factory_drop_panic_preserves_join_and_cleanup() {
            cancelled_before_admission(true);
        }

        struct UnstartedFactoryCapture {
            drops: Arc<AtomicUsize>,
            panic_on_drop: bool,
        }

        impl Drop for UnstartedFactoryCapture {
            fn drop(&mut self) {
                assert_eq!(self.drops.fetch_add(1, Ordering::SeqCst), 0);
                assert!(!self.panic_on_drop, "ATP unadmitted factory capture panic");
            }
        }

        fn cancelled_before_admission(panic_on_drop: bool) {
            let (mut lab, root) = lab(0x53_0070);
            let calls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let resource = UnstartedFactoryCapture {
                drops: Arc::clone(&drops),
                panic_on_drop,
            };
            let worker_calls = Arc::clone(&calls);
            let publication = Arc::new(parking_lot::Mutex::new(None));
            let slot = Arc::clone(&publication);
            let (release, mut close) = oneshot::channel::<()>();
            let coordinator: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let cx = Cx::current().expect("actual pre-admission coordinator");
                let child = cx
                    .open_child_region(crate::cx::ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let mut transfer = ActiveTransfer::spawn_worker(
                    child.cx(),
                    &child.cx().scope(),
                    TransferId::new("owned-worker"),
                    TransferOptions::default(),
                    move |_, _| {
                        worker_calls.fetch_add(1, Ordering::SeqCst);
                        drop(resource);
                        std::future::ready(AtpOutcome::Ok(progress(65, TransferPhase::Completed)))
                    },
                )
                .unwrap();
                assert_eq!(transfer.state(), ActiveTransferState::Pending);
                assert!(transfer.cancel().await.is_ok());
                assert!(!transfer.is_complete().await);
                *slot.lock() = Some((transfer, child.region_id()));
                close.recv(&cx).await.unwrap();
                child.close().await.unwrap();
            });
            let (parent, mut joined) = lab
                .state
                .create_task(root, Budget::INFINITE, coordinator)
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            // Each actual Lab step drains earlier requests before polling the
            // coordinator. Stop immediately after it publishes the new request,
            // before the following step can admit that request.
            let mut request = None;
            for _ in 0..8 {
                lab.step_for_test();
                request = publication.lock().take();
                if request.is_some() {
                    break;
                }
            }
            let (mut transfer, child) = request.expect("real queued spawn before admission");
            let provisional = transfer.worker.task_id();
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert_eq!(transfer.state(), ActiveTransferState::Pending);
            assert_eq!(lab.state.region(child).unwrap().pending_spawn_count(), 1);
            assert!(lab.state.task(provisional).is_none());

            // This is the actual runtime cancellation transition, not a forged
            // Cx/TaskRecord or a direct invocation of a denial completion slot.
            // Parent cancellation closes admission before the queued worker is
            // drained. It is stronger than the handle's earlier User request.
            let reason = CancelReason::new(crate::types::CancelKind::ParentCancelled);
            let (tasks, wakes) = lab.state.cancel_request(child, &reason, None).into_parts();
            assert!(tasks.is_empty(), "no worker has been admitted to cancel");
            wakes.dispatch();
            assert!(lab.run_until_idle() < 4096);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(!transfer.shared.lock().started);
            let terminal = transfer
                .terminal()
                .expect("actual unadmitted cancellation")
                .clone();
            assert_eq!(terminal.worker_outcome, None);
            let cleanup_panic =
                panic_on_drop.then(|| PanicPayload::new("ATP unadmitted factory capture panic"));
            assert_eq!(terminal.cleanup_panic, cleanup_panic);
            assert_eq!(
                terminal.worker_join,
                Err(JoinError::Cancelled(reason.clone()))
            );
            assert_eq!(
                terminal.outcome,
                cleanup_panic.map_or_else(|| AtpOutcome::Cancelled(reason), AtpOutcome::Panicked,)
            );
            assert!(futures_lite::future::block_on(transfer.is_complete()));
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                None
            );
            assert_eq!(transfer.terminal(), Some(&terminal));
            let trace = lab.state.trace_handle().snapshot();
            for (kind, count) in [
                (crate::trace::TraceEventKind::TaskSpawnEnqueued, 1),
                (crate::trace::TraceEventKind::Spawn, 0),
                (crate::trace::TraceEventKind::Complete, 0),
            ] {
                assert_eq!(trace.iter().filter(|event| {
                    event.kind == kind
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                            if task == provisional && region == child)
                }).count(), count, "actual denied request {provisional:?} {kind:?}");
            }
            release.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert_eq!(joined.try_join(), Ok(Some(())));
            assert!(lab.state.region(child).is_none());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            clean(&mut lab, root, parent);
            eprintln!(
                "ATP pre-admission cancellation request={provisional:?} child={child:?} terminal={terminal:?} factory_calls={} capture_drops={}",
                calls.load(Ordering::SeqCst),
                drops.load(Ordering::SeqCst)
            );
        }

        #[test]
        fn owned_transfer_factory_construction_panic_retires_its_capture_once() {
            let (mut lab, root) = lab(0x53_0080);
            let calls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let worker_calls = Arc::clone(&calls);
            let resource = Dropped(Arc::clone(&drops));
            let mut transfer = admit(
                &mut lab,
                root,
                move |_, _| -> std::future::Ready<AtpOutcome<TransferProgress>> {
                    let _resource = resource;
                    worker_calls.fetch_add(1, Ordering::SeqCst);
                    panic!("ATP worker factory construction panic");
                },
            );
            let worker = transfer.worker.task_id();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            let terminal = transfer
                .terminal()
                .expect("actual factory-panic worker joined")
                .clone();
            let panic =
                AtpOutcome::Panicked(PanicPayload::new("ATP worker factory construction panic"));
            assert_eq!(terminal.worker_outcome, Some(panic.clone()));
            assert_eq!(
                terminal.cleanup_panic, None,
                "no worker future was constructed"
            );
            assert_eq!(
                terminal.worker_join,
                Ok(()),
                "the adapter caught the factory panic"
            );
            assert_eq!(terminal.outcome, panic);
            for _ in 0..3 {
                assert!(futures_lite::future::block_on(transfer.is_complete()));
                assert_eq!(transfer.terminal(), Some(&terminal));
            }
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                None
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.wait_for_terminal()),
                &terminal
            );
            clean(&mut lab, root, worker);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }
