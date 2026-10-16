    use super::*;
    use crate::net::atp::sdk::{SessionConfig, TransferPolicy};

    fn client(capacity: u32) -> NativeTransferClient {
        AtpSdk::new_in_process(SessionConfig {
            max_concurrent_transfers: capacity,
            ..SessionConfig::default()
        })
        .native_transfers(QuicConfig::default().use_transport_authenticated_symbols())
        .unwrap()
    }

    #[test]
    fn rejected_reports_retain_partial_publication_evidence() {
        use crate::net::atp::transport_quic::ReceiveReceipt;

        let receipt = ReceiveReceipt {
            committed: true,
            bytes_received: 17,
            files: 1,
            sha_ok: true,
            merkle_ok: true,
            symbols_accepted: 3,
            feedback_rounds: 1,
            decode_count: 1,
            decode_micros: 7,
            reason: None,
            committed_paths: vec!["partial.bin".to_string()],
        };
        let report = SendReport {
            transfer_id: "actual-native-id".to_string(),
            bytes_sent: 17,
            files: 1,
            symbols_sent: 4,
            feedback_rounds: 1,
            merkle_root_hex: "retained-root".to_string(),
            receipt,
            peer: "127.0.0.1:1234".parse().unwrap(),
        };
        assert!(committed_send(report.clone()).is_ok());
        for (committed, sha_ok, merkle_ok) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let mut rejected = report.clone();
            rejected.receipt.committed = committed;
            rejected.receipt.sha_ok = sha_ok;
            rejected.receipt.merkle_ok = merkle_ok;
            rejected.receipt.reason = Some("peer-side failure".to_string());
            let original = rejected.clone();
            match committed_send(rejected) {
                Err(NativeTransferError::UncommittedSend(retained)) => {
                    assert_eq!(retained.receipt, original.receipt);
                    assert_eq!(retained.transfer_id, original.transfer_id);
                    assert_eq!(retained.merkle_root_hex, original.merkle_root_hex);
                    assert_eq!(retained.peer, original.peer);
                }
                other => panic!("invalid receipt was accepted or discarded: {other:?}"),
            }
        }

        let received = ReceiveReport {
            transfer_id: "partially-published".to_string(),
            bytes_received: 17,
            files: 1,
            committed: false,
            symbols_accepted: 3,
            feedback_rounds: 1,
            decode_count: 1,
            decode_micros: 7,
            committed_paths: vec![PathBuf::from("partial.bin")],
            peer: report.peer,
        };
        match committed_receive(received) {
            Err(NativeTransferError::UncommittedReceive(retained)) => {
                assert_eq!(retained.transfer_id, "partially-published");
                assert_eq!(retained.committed_paths, vec![PathBuf::from("partial.bin")]);
                assert_eq!(retained.bytes_received, 17);
            }
            other => panic!("partial receive report was accepted or discarded: {other:?}"),
        }
    }

    #[test]
    fn native_size_limits_never_relax_either_policy() {
        let sdk =
            AtpSdk::new_in_process(SessionConfig::default()).with_transfer_policy(TransferPolicy {
                max_transfer_size_bytes: 2048,
                max_chunk_size_bytes: 512,
                ..TransferPolicy::default()
            });
        for (bytes, chunk, expected_bytes, expected_chunk) in
            [(4096, 1024, 2048, 512), (1024, 256, 1024, 256)]
        {
            let config = QuicConfig {
                max_transfer_bytes: bytes,
                chunk_size: chunk,
                ..QuicConfig::default().use_transport_authenticated_symbols()
            };
            let native = sdk.native_transfers(config).unwrap();
            assert_eq!(native.shared.config.max_transfer_bytes, expected_bytes);
            assert_eq!(native.shared.config.chunk_size, expected_chunk);
            assert_eq!(native.active_transfers(), 0);
        }
    }

    #[test]
    fn native_admission_is_shared_across_clones_and_released_on_drop() {
        let client = client(2);
        let clone = client.clone();
        let first = client.admit().unwrap();
        let second = clone.admit().unwrap();
        assert_eq!(client.active_transfers(), 2);
        assert_eq!(clone.active_transfers(), 2);
        assert!(matches!(
            clone.admit(),
            Err(NativeTransferError::CapacityExceeded { limit: 2 })
        ));
        assert_eq!(client.active_transfers(), 2);
        drop(first);
        let replacement = clone.admit().unwrap();
        drop(second);
        assert_eq!(client.active_transfers(), 1);
        drop(replacement);
        assert_eq!(client.active_transfers(), 0);
    }

    #[test]
    fn native_admission_survives_cross_thread_ownership_and_unwind() {
        let client = client(1);
        let permit = client.admit().unwrap();
        let clone = client.clone();
        std::thread::spawn(move || {
            assert!(matches!(
                clone.admit(),
                Err(NativeTransferError::CapacityExceeded { limit: 1 })
            ));
            drop(permit);
        })
        .join()
        .unwrap();
        assert_eq!(client.active_transfers(), 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = client.admit().unwrap();
            panic!("exercise native admission cleanup");
        }));
        assert!(result.is_err());
        assert_eq!(client.active_transfers(), 0);
        drop(client.admit().unwrap());
    }

    #[test]
    fn native_configuration_refuses_invalid_limits_and_daemon_mode() {
        let sdk = AtpSdk::new_in_process(SessionConfig {
            max_concurrent_transfers: 0,
            ..SessionConfig::default()
        });
        assert!(matches!(
            sdk.native_transfers(QuicConfig::default()),
            Err(NativeTransferError::InvalidLimit(
                "max_concurrent_transfers"
            ))
        ));
        for (bytes, chunk, field) in [
            (0, 512, "max_transfer_size_bytes"),
            (2048, 0, "max_chunk_size_bytes"),
        ] {
            let sdk = AtpSdk::new_in_process(SessionConfig::default()).with_transfer_policy(
                TransferPolicy {
                    max_transfer_size_bytes: bytes,
                    max_chunk_size_bytes: chunk,
                    ..TransferPolicy::default()
                },
            );
            assert!(matches!(
                sdk.native_transfers(QuicConfig::default()),
                Err(NativeTransferError::InvalidLimit(actual)) if actual == field
            ));
        }
        let sdk = AtpSdk::new_daemon_delegated(
            SessionConfig::default(),
            "unused.invalid:1".to_string(),
            None,
        );
        assert!(matches!(
            sdk.native_transfers(QuicConfig::default()),
            Err(NativeTransferError::UnsupportedMode)
        ));
    }

    #[test]
    fn native_adapter_does_not_supply_missing_authentication() {
        let sdk = AtpSdk::new_in_process(SessionConfig::default());
        assert!(matches!(
            sdk.native_transfers(QuicConfig::default()),
            Err(NativeTransferError::Transport(QuicTransportError::Config(
                _
            )))
        ));
        let client = client(1);
        let cx = Cx::for_testing();
        let remote = "127.0.0.1:9".parse().unwrap();
        futures_lite::future::block_on(async {
            assert!(matches!(
                client
                    .send_path(&cx, remote, Path::new("unused-source"))
                    .await,
                Err(NativeTransferError::MissingClientTls)
            ));
            assert!(matches!(
                client
                    .bind_receiver(
                        &cx,
                        "127.0.0.1:0".parse().unwrap(),
                        "unused-destination",
                        QuicReceiveOptions::default(),
                    )
                    .await,
                Err(NativeTransferError::MissingServerTls)
            ));
        });
        assert_eq!(client.active_transfers(), 0);
    }
