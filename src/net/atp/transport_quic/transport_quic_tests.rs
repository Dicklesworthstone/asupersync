#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn required_unix_regular_metadata_rejects_mode_and_subsecond_mtime_drift() {
        let expected = EntryMetadata {
            file_kind: FileKind::Regular,
            unix_mode: Some(0o640),
            mtime_unix_secs: Some(1_600_000_123),
            mtime_nanos: Some(456_789_123),
            ..EntryMetadata::default()
        };
        verify_quic_required_unix_regular_metadata(Path::new("payload.bin"), &expected, &expected)
            .expect("exact Unix regular-file metadata must pass");

        let mut mode_drift = expected.clone();
        mode_drift.unix_mode = Some(0o600);
        let mode_error = verify_quic_required_unix_regular_metadata(
            Path::new("payload.bin"),
            &expected,
            &mode_drift,
        )
        .expect_err("mode drift must fail closed");
        assert!(mode_error.contains("field mode"), "{mode_error}");

        let mut mtime_drift = expected.clone();
        mtime_drift.mtime_nanos = Some(456_789_122);
        let mtime_error = verify_quic_required_unix_regular_metadata(
            Path::new("payload.bin"),
            &expected,
            &mtime_drift,
        )
        .expect_err("subsecond mtime drift must fail closed");
        assert!(mtime_error.contains("field mtime"), "{mtime_error}");

        let unrequired = EntryMetadata::default();
        verify_quic_required_unix_regular_metadata(
            Path::new("portable.bin"),
            &unrequired,
            &mode_drift,
        )
        .expect("omitted fidelity fields impose no exact requirement");

        let mut directory = expected.clone();
        directory.file_kind = FileKind::Directory;
        verify_quic_required_unix_regular_metadata(
            Path::new("directory"),
            &directory,
            &EntryMetadata::default(),
        )
        .expect("regular-file verifier must not widen to directories");
    }

    #[test]
    fn quic_receive_options_are_default_off_and_traced_within_field_budget() {
        let default_options = QuicReceiveOptions::new();
        assert_eq!(default_options, QuicReceiveOptions::default());
        assert!(!default_options.sparse_files());
        let sparse_options = default_options.with_sparse_files(true);
        assert!(sparse_options.sparse_files());
        #[cfg(unix)]
        sparse_options
            .validate()
            .expect("Unix admits sparse reconstruction attempts");
        #[cfg(not(unix))]
        assert!(matches!(
            sparse_options.validate(),
            Err(QuicTransportError::Config(_))
        ));

        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_diagnostic_context(crate::observability::DiagnosticContext::new());
        cx.set_log_collector(collector.clone());
        trace_config_summary(
            &cx,
            "receive_once",
            &QuicConfig::default(),
            "receiver",
            Some(&sparse_options),
        );

        let entries = collector.peek();
        let config = entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.transport.config")
            .expect("QUIC receive config trace");
        assert_eq!(config.get_field("sparse_files"), Some("true"));
        assert!(config.field_count() <= 12);
    }

    /// Test scratch dir whose path has no symlinked ancestors.
    ///
    /// macOS `$TMPDIR` lives under `/var`, and `/var -> /private/var` is an
    /// OS-level symlink. The ATP destination traversal defense correctly
    /// rejects any symlinked ancestor, so scratch roots are handed to the
    /// transfer at their canonical (`/private/var/...`) spelling instead.
    struct CanonTempDir {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    impl CanonTempDir {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    fn canon_tempdir() -> CanonTempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().canonicalize().expect("canonicalize temp dir");
        CanonTempDir { _dir: dir, path }
    }
    use crate::net::atp::protocol::frames::{Frame, ProtocolVersion};
    use crate::net::quic_native::{
        DEFAULT_MAX_PACKET_BYTES, NativeQuicConnectionConfig, PacketNumberSpace, QuicConnection,
        QuicPathStats, QuicTransportMachine, SentPacketMeta, StreamDirection, StreamRole,
        establish_loopback, pump_app_data, pump_until_idle,
    };
    use crate::trace::{TraceBufferHandle, TraceData};

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        futures_lite::future::block_on(fut)
    }

    /// asupersync-wlbrlr: a relative destination root's `ancestors()` walk
    /// ends at the empty path; the post-create symlink pass must skip it
    /// instead of failing the receive with a spurious NotFound.
    #[test]
    fn prepare_quic_destination_root_accepts_a_relative_path() {
        // `tempfile` absolutizes a relative parent, so the relative path is
        // built by hand under the package-local `target/` (cargo runs the
        // test binary from the package root; `target/` is ignored by git).
        let parent = std::path::PathBuf::from("target").join(format!(
            "quic-relative-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos())
        ));
        std::fs::create_dir_all(&parent).expect("relative parent dir");
        let dest = parent.join("nested").join("dest");
        assert!(dest.is_relative(), "{}", dest.display());

        let relative = block_on(prepare_quic_destination_root(&dest));
        let created = dest.is_dir();
        let absolute = block_on(prepare_quic_destination_root(
            &std::env::current_dir().expect("cwd").join(&dest),
        ));
        let _ = std::fs::remove_dir_all(&parent);

        relative.expect("a relative destination root is prepared like an absolute one");
        assert!(created, "destination root created: {}", dest.display());
        absolute.expect("the absolute spelling of the same root is prepared too");
    }

    fn trusted_quic_config() -> QuicConfig {
        QuicConfig::default().allow_unauthenticated_for_trusted_transport()
    }

    #[test]
    fn native_symbol_drain_batch_matches_receiver_pump_width() {
        assert_eq!(NATIVE_SYMBOL_DRAIN_BATCH, 512);
    }

    #[test]
    fn native_block_drain_consumes_more_than_one_symbol_batch_per_call() {
        let (cx, _client, server_api) = established_pair();
        let mut server = server_api.inner().clone();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 128,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 21))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let object_id = decoders[0].object_id;
        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            entries[0].1.clone(),
            SymbolKind::Source,
        );
        let datagram =
            native_symbol_datagram(&symbol, transfer_tag(&manifest.transfer_id), 0, None)
                .expect("symbol datagram");
        let total_datagrams = NATIVE_SYMBOL_DRAIN_BATCH + 7;
        let frames = (0..total_datagrams)
            .map(
                |_| crate::net::atp::protocol::quic_frames::QuicFrame::Datagram {
                    data: datagram.clone(),
                },
            )
            .collect::<Vec<_>>();
        let mut payload = BytesMut::new();
        NativeQuicConnection::encode_frames(&frames, &mut payload).expect("encode frames");
        server
            .process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 0, &payload, 1_000)
            .expect("queue inbound datagrams");
        assert_eq!(server.pending_datagram_count(), total_datagrams);

        let mut decode_stats = QuicDecodeStats::default();
        let (observed, accepted, _completed) = block_on(drain_native_symbol_datagrams_with_blocks(
            &cx,
            &mut server,
            &manifest,
            &mut decoders,
            &config,
            &mut decode_stats,
            0,
            None,
            NativeSymbolDrainMode::ReadyOnly,
            usize::MAX,
        ))
        .expect("drain queued native symbols");

        assert_eq!(
            observed,
            u64::try_from(total_datagrams).unwrap_or(u64::MAX),
            "native receiver must drain every queued DATAGRAM, not only the first batch"
        );
        assert_eq!(
            server.pending_datagram_count(),
            0,
            "single receiver drain should leave no buffered DATAGRAMs"
        );
        assert!(
            accepted > 0,
            "at least the first source symbol should reach the decoder"
        );
    }

    #[test]
    fn native_block_drain_honors_batch_limit_for_socket_interleave() {
        let (cx, _client, server_api) = established_pair();
        let mut server = server_api.inner().clone();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 128,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 31))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let object_id = decoders[0].object_id;
        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            entries[0].1.clone(),
            SymbolKind::Source,
        );
        let datagram =
            native_symbol_datagram(&symbol, transfer_tag(&manifest.transfer_id), 0, None)
                .expect("symbol datagram");
        let total_datagrams = NATIVE_SYMBOL_DRAIN_BATCH + 7;
        let frames = (0..total_datagrams)
            .map(
                |_| crate::net::atp::protocol::quic_frames::QuicFrame::Datagram {
                    data: datagram.clone(),
                },
            )
            .collect::<Vec<_>>();
        let mut payload = BytesMut::new();
        NativeQuicConnection::encode_frames(&frames, &mut payload).expect("encode frames");
        server
            .process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 0, &payload, 1_000)
            .expect("queue inbound datagrams");

        let mut decode_stats = QuicDecodeStats::default();
        let (observed, _accepted, _completed) =
            block_on(drain_native_symbol_datagrams_with_blocks(
                &cx,
                &mut server,
                &manifest,
                &mut decoders,
                &config,
                &mut decode_stats,
                0,
                None,
                NativeSymbolDrainMode::ReadyOnly,
                1,
            ))
            .expect("drain one native symbol batch");

        assert_eq!(observed, NATIVE_SYMBOL_DRAIN_BATCH as u64);
        assert_eq!(
            server.pending_datagram_count(),
            total_datagrams - NATIVE_SYMBOL_DRAIN_BATCH,
            "batch-limited receiver drain must leave later DATAGRAMs queued for the next socket poll turn"
        );
    }

    #[test]
    fn quic_sender_aimd_halves_rate_on_receiver_observed_loss() {
        let manifest = sample_manifest();
        let config = trusted_quic_config();
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut encoders = Vec::new();
        let mut state = QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, 100);
        let initial_rate = state.aimd_rate_bps;

        state.observe_need_more(&QuicNeedMore {
            pending: vec![0],
            round_symbols_observed: Some(98),
            round_symbols_accepted: Some(98),
            round_loss_fraction: Some(0.25),
            ..QuicNeedMore::default()
        });

        assert_eq!(state.last_round_loss_fraction, 0.25);
        assert_eq!(state.aimd_rate_bps, initial_rate / 2);
        assert_eq!(
            state.next_round_config().bwlimit_bps,
            Some(initial_rate / 2)
        );
    }

    #[test]
    fn quic_sender_aimd_additively_increases_on_clean_feedback() {
        let manifest = sample_manifest();
        let config = trusted_quic_config();
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut encoders = Vec::new();
        let mut state = QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, 200);
        state.aimd_rate_bps = 4 * 1024 * 1024;
        state.aimd_feedback_seen = true;

        state.observe_need_more(&QuicNeedMore {
            pending: vec![0],
            round_symbols_observed: Some(200),
            round_symbols_accepted: Some(200),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        });

        assert_eq!(state.last_round_loss_fraction, 0.0);
        assert_eq!(
            state.aimd_rate_bps,
            4 * 1024 * 1024 + QUIC_AIMD_ADDITIVE_INCREASE_BYTES_PER_S
        );
    }

    fn auth_quic_config(seed: u64) -> QuicConfig {
        QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(seed))
    }

    fn established_pair() -> (Cx<crate::cx::cap::All>, QuicConnection, QuicConnection) {
        let cx = Cx::for_testing();
        let mut client = QuicConnection::client(NativeQuicConnectionConfig::default());
        let mut server = QuicConnection::server(NativeQuicConnectionConfig::default());
        client.record_verified_server_identity();
        establish_loopback(&cx, &mut client, &mut server).expect("loopback establishes");
        (cx, client, server)
    }

    fn cancelled_test_cx() -> Cx<crate::cx::cap::All> {
        let cx = Cx::for_testing();
        cx.set_cancel_reason(crate::types::CancelReason::user(
            "transport_quic cancellation test",
        ));
        cx
    }

    fn pump_native_until_idle(
        cx: &Cx,
        from: &mut NativeQuicConnection,
        to: &mut NativeQuicConnection,
        next_packet_number: &mut u64,
        max_packet_bytes: usize,
        now_micros: u64,
    ) -> Result<usize, QuicTransportError> {
        let mut total = 0usize;
        for _ in 0..32 {
            let frames =
                from.generate_frames(cx, PacketNumberSpace::ApplicationData, max_packet_bytes)?;
            if frames.is_empty() {
                return Ok(total);
            }
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload)?;
            let packet_number = *next_packet_number;
            *next_packet_number = (*next_packet_number).saturating_add(1);
            to.process_packet_payload(
                cx,
                PacketNumberSpace::ApplicationData,
                packet_number,
                &payload,
                now_micros,
            )?;
            from.on_generated_frames_delivered(&frames)?;
            total = total.saturating_add(frames.len());
        }
        Err(QuicTransportError::Quic(
            "native pump did not drain within iteration cap".to_string(),
        ))
    }

    fn sample_manifest() -> TransferManifest {
        TransferManifest {
            transfer_id: "transfer42".to_string(),
            root_name: "data".to_string(),
            is_directory: true,
            total_bytes: 9,
            merkle_root_hex: "00".repeat(32),
            metadata_root_hex: None,
            directory_metadata: None,
            delta_manifest: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a/b.txt".to_string(),
                size: 9,
                sha256_hex: "ff".repeat(32),
                metadata: None,
                members: Vec::new(),
            }],
        }
    }

    /// `validate_quic_manifest` must reject an off-wire `transfer_id` that is not a
    /// bounded alphanumeric token, before it can steer the receiver's staging path
    /// / `remove_dir_all` outside the destination (directory traversal). See
    /// `asupersync-my6ocy`; mirrors the transport_tcp `validate_manifest` guard.
    #[test]
    fn validate_quic_manifest_rejects_unsafe_transfer_id() {
        let config = trusted_quic_config();

        // A legitimate alphanumeric transfer_id passes the guard.
        assert!(validate_quic_manifest(&sample_manifest(), &config).is_ok());

        // Traversal / separator / control / whitespace / empty tokens fail closed.
        for bad in [
            "x/../../../../tmp/pwn",
            "..",
            "a/b",
            "a\\b",
            "with space",
            "tab\there",
            "",
        ] {
            let mut manifest = sample_manifest();
            manifest.transfer_id = bad.to_string();
            assert!(
                matches!(
                    validate_quic_manifest(&manifest, &config),
                    Err(QuicTransportError::Source(_))
                ),
                "transfer_id {bad:?} must be rejected fail-closed",
            );
        }

        // Over-length (>64) is rejected even when alphanumeric.
        let mut too_long = sample_manifest();
        too_long.transfer_id = "a".repeat(65);
        assert!(matches!(
            validate_quic_manifest(&too_long, &config),
            Err(QuicTransportError::Source(_))
        ));

        // The 64-char boundary alphanumeric token is accepted.
        let mut boundary = sample_manifest();
        boundary.transfer_id = "a".repeat(64);
        assert!(validate_quic_manifest(&boundary, &config).is_ok());
    }

    #[test]
    fn validate_quic_manifest_rejects_entry_size_sum_overflow() {
        let mut manifest = sample_manifest();
        manifest.total_bytes = u64::MAX;
        manifest.entries[0].size = u64::MAX;
        manifest.entries.push(ManifestEntry {
            index: 1,
            rel_path: "overflow.bin".to_string(),
            size: 1,
            sha256_hex: "0".repeat(64),
            metadata: None,
            members: Vec::new(),
        });
        let config = QuicConfig {
            max_transfer_bytes: u64::MAX,
            ..trusted_quic_config()
        };
        assert!(matches!(
            validate_quic_manifest(&manifest, &config),
            Err(QuicTransportError::Source(message)) if message.contains("overflow")
        ));
    }

    #[test]
    fn validate_quic_manifest_rejects_noncanonical_bare_metadata_blocks() {
        let mut bare_entry = sample_manifest();
        bare_entry.entries[0].metadata = Some(EntryMetadata::default());
        assert!(matches!(
            validate_quic_manifest(&bare_entry, &trusted_quic_config()),
            Err(QuicTransportError::Source(message)) if message.contains("non-canonical bare metadata")
        ));

        let mut bare_member = quic_manifest_with_metadata(vec![quic_packed_entry(
            0,
            0,
            &[("a.bin", b"a"), ("b.bin", b"b")],
        )]);
        bare_member.entries[0].members[0].metadata = Some(EntryMetadata::default());
        assert!(matches!(
            validate_quic_manifest(&bare_member, &trusted_quic_config()),
            Err(QuicTransportError::Source(message)) if message.contains("non-canonical bare metadata")
        ));
    }

    fn quic_manifest_with_metadata(entries: Vec<ManifestEntry>) -> TransferManifest {
        let mut manifest = TransferManifest {
            transfer_id: "transfer42".to_string(),
            root_name: "data".to_string(),
            is_directory: true,
            total_bytes: entries
                .iter()
                .fold(0u64, |acc, entry| acc.saturating_add(entry.size)),
            merkle_root_hex: "00".repeat(32),
            metadata_root_hex: None,
            directory_metadata: None,
            delta_manifest: None,
            entries,
        };
        manifest.metadata_root_hex = manifest_metadata_commitment(&manifest);
        manifest
    }

    fn quic_directory_metadata_entry(rel_path: &str) -> DirectoryMetadataEntry {
        DirectoryMetadataEntry {
            rel_path: rel_path.to_string(),
            metadata: EntryMetadata {
                file_kind: FileKind::Directory,
                unix_mode: Some(0o755),
                ..Default::default()
            },
        }
    }

    fn with_quic_directory_metadata(
        mut manifest: TransferManifest,
        directory_metadata: DirectoryMetadataManifest,
    ) -> TransferManifest {
        manifest.directory_metadata = Some(directory_metadata);
        manifest.metadata_root_hex = manifest_metadata_commitment(&manifest);
        manifest
    }

    #[test]
    fn validate_quic_directory_metadata_requires_canonical_strict_ancestors() {
        let config = trusted_quic_config();
        let valid = with_quic_directory_metadata(
            sample_manifest(),
            DirectoryMetadataManifest {
                root: None,
                entries: vec![quic_directory_metadata_entry("a")],
            },
        );
        validate_quic_manifest(&valid, &config).expect("strict ancestor metadata validates");

        let mut nested = sample_manifest();
        nested.entries[0].rel_path = "a/b/c.txt".to_string();
        let reversed = with_quic_directory_metadata(
            nested,
            DirectoryMetadataManifest {
                root: None,
                entries: vec![
                    quic_directory_metadata_entry("a/b"),
                    quic_directory_metadata_entry("a"),
                ],
            },
        );
        let error = validate_quic_manifest(&reversed, &config)
            .expect_err("reversed directory metadata must fail closed");
        assert!(
            matches!(error, QuicTransportError::Source(message) if message.contains("strict lexicographic"))
        );

        let explicit_directory = quic_manifest_with_metadata(vec![ManifestEntry {
            index: 0,
            rel_path: "empty".to_string(),
            size: 0,
            sha256_hex: sha256_hex(b""),
            metadata: Some(EntryMetadata {
                file_kind: FileKind::Directory,
                unix_mode: Some(0o755),
                ..Default::default()
            }),
            members: Vec::new(),
        }]);
        let duplicate = with_quic_directory_metadata(
            explicit_directory,
            DirectoryMetadataManifest {
                root: None,
                entries: vec![quic_directory_metadata_entry("empty")],
            },
        );
        let error = validate_quic_manifest(&duplicate, &config)
            .expect_err("explicit directory leaf cannot be committed twice");
        assert!(
            matches!(error, QuicTransportError::Source(message) if message.contains("not represented"))
        );
    }

    #[test]
    fn validate_quic_directory_metadata_rejects_empty_fidelity_records() {
        let config = trusted_quic_config();
        let empty_root = with_quic_directory_metadata(
            sample_manifest(),
            DirectoryMetadataManifest {
                root: Some(EntryMetadata {
                    file_kind: FileKind::Directory,
                    ..Default::default()
                }),
                entries: Vec::new(),
            },
        );
        let error = validate_quic_manifest(&empty_root, &config)
            .expect_err("empty-fidelity root must fail closed");
        assert!(
            matches!(error, QuicTransportError::Source(message) if message.contains("no fidelity fields"))
        );

        let empty_entry = with_quic_directory_metadata(
            sample_manifest(),
            DirectoryMetadataManifest {
                root: None,
                entries: vec![DirectoryMetadataEntry {
                    rel_path: "a".to_string(),
                    metadata: EntryMetadata {
                        file_kind: FileKind::Directory,
                        ..Default::default()
                    },
                }],
            },
        );
        let error = validate_quic_manifest(&empty_entry, &config)
            .expect_err("empty-fidelity nested record must fail closed");
        assert!(
            matches!(error, QuicTransportError::Source(message) if message.contains("no fidelity fields"))
        );
    }

    #[test]
    fn validate_quic_manifest_rejects_hardlink_metadata_that_differs_from_primary() {
        let primary = ManifestEntry {
            index: 0,
            rel_path: "primary.bin".to_string(),
            size: 4,
            sha256_hex: "0".repeat(64),
            metadata: Some(EntryMetadata {
                unix_mode: Some(0o644),
                ..Default::default()
            }),
            members: Vec::new(),
        };
        let alias = ManifestEntry {
            index: 1,
            rel_path: "alias.bin".to_string(),
            size: 0,
            sha256_hex: sha256_hex(b""),
            metadata: Some(EntryMetadata {
                unix_mode: Some(0o644),
                hardlink_target: Some("primary.bin".to_string()),
                ..Default::default()
            }),
            members: Vec::new(),
        };
        let valid = quic_manifest_with_metadata(vec![primary, alias]);
        let config = QuicConfig {
            preserve_hardlinks: true,
            ..trusted_quic_config()
        };
        validate_quic_manifest(&valid, &config)
            .expect("hardlink alias with primary metadata validates");

        let mut different = valid;
        different.entries[1]
            .metadata
            .as_mut()
            .expect("alias metadata")
            .unix_mode = Some(0o600);
        different.metadata_root_hex = manifest_metadata_commitment(&different);
        assert!(matches!(
            validate_quic_manifest(&different, &config),
            Err(QuicTransportError::Source(message)) if message.contains("metadata different from primary")
        ));
    }

    fn quic_symlink_entry(index: u32, rel: &str, target: &str) -> ManifestEntry {
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
    fn validate_quic_manifest_enforces_symlink_containment_and_receiver_policy() {
        let contained =
            quic_manifest_with_metadata(vec![quic_symlink_entry(0, "dir/link", "../target")]);
        validate_quic_manifest(&contained, &trusted_quic_config())
            .expect("contained portable symlink validates");

        for target in ["../../escape", "/rooted", r"C:\escape", r"..\escape"] {
            let rejected =
                quic_manifest_with_metadata(vec![quic_symlink_entry(0, "dir/link", target)]);
            assert!(
                matches!(
                    validate_quic_manifest(&rejected, &trusted_quic_config()),
                    Err(QuicTransportError::Source(ref message))
                        if message.contains("invalid metadata")
                ),
                "unsafe symlink target {target:?} must fail before staging"
            );
        }

        let portable_receiver = QuicConfig {
            metadata_policy: MetadataPolicy::portable(),
            ..trusted_quic_config()
        };
        assert!(matches!(
            validate_quic_manifest(&contained, &portable_receiver),
            Err(QuicTransportError::Source(ref message))
                if message.contains("denied by receiver metadata policy")
        ));
    }

    fn quic_empty_regular_entry(index: u32, rel: &str) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: rel.to_string(),
            size: 0,
            sha256_hex: sha256_hex(b""),
            metadata: None,
            members: Vec::new(),
        }
    }

    fn quic_packed_entry(index: u32, pack: u32, members: &[(&str, &[u8])]) -> ManifestEntry {
        let mut packed = Vec::new();
        let mut offset = 0u64;
        let mut all = Vec::new();
        for (rel, bytes) in members {
            packed.push(PackedMember {
                rel_path: (*rel).to_string(),
                offset,
                len: bytes.len() as u64,
                sha256_hex: sha256_hex(bytes),
                metadata: None,
            });
            offset += bytes.len() as u64;
            all.extend_from_slice(bytes);
        }
        ManifestEntry {
            index,
            rel_path: format!(".atp-pack-{pack}"),
            size: offset,
            sha256_hex: sha256_hex(&all),
            metadata: None,
            members: packed,
        }
    }

    #[test]
    fn validate_quic_manifest_accepts_contiguous_pack_and_rejects_gaps_and_dups() {
        let config = trusted_quic_config();
        let good = quic_manifest_with_metadata(vec![quic_packed_entry(
            0,
            0,
            &[("dir/a.txt", b"aaaa"), ("dir/b.txt", b"bb")],
        )]);
        validate_quic_manifest(&good, &config).expect("contiguous pack validates");

        // Non-contiguous member offsets fail closed.
        let mut gap = good.clone();
        gap.entries[0].members[1].offset += 1;
        assert!(matches!(
            validate_quic_manifest(&gap, &config),
            Err(QuicTransportError::Source(ref message)) if message.contains("not contiguous")
        ));

        // Members must cover the entry span exactly.
        let mut short = good.clone();
        short.entries[0].size += 1;
        assert!(matches!(
            validate_quic_manifest(&short, &config),
            Err(QuicTransportError::Source(ref message)) if message.contains("do not cover")
        ));

        // A member path duplicating an entry path fails closed.
        let dup = quic_manifest_with_metadata(vec![
            quic_empty_regular_entry(0, "dir/a.txt"),
            quic_packed_entry(1, 0, &[("dir/a.txt", b"aaaa"), ("dir/b.txt", b"bb")]),
        ]);
        assert!(matches!(
            validate_quic_manifest(&dup, &config),
            Err(QuicTransportError::Source(ref message)) if message.contains("duplicate")
        ));

        // Member paths nested under a symlink entry fail closed.
        let through_link = quic_manifest_with_metadata(vec![
            quic_symlink_entry(0, "link", "target"),
            quic_packed_entry(1, 0, &[("link/evil.txt", b"aaaa"), ("dir/b.txt", b"bb")]),
        ]);
        assert!(matches!(
            validate_quic_manifest(&through_link, &config),
            Err(QuicTransportError::Source(ref message)) if message.contains("nested under symlink")
        ));
    }

    #[test]
    fn validate_quic_manifest_rejects_entries_nested_under_manifest_symlink() {
        let config = trusted_quic_config();
        let bad = quic_manifest_with_metadata(vec![
            quic_symlink_entry(0, "link", "target"),
            quic_empty_regular_entry(1, "link/payload.txt"),
        ]);

        assert!(
            matches!(
                validate_quic_manifest(&bad, &config),
                Err(QuicTransportError::Source(ref message))
                    if message.contains("nested under symlink")
            ),
            "QUIC manifest must reject writes through declared symlink entries"
        );

        let nested_symlink = quic_manifest_with_metadata(vec![
            quic_symlink_entry(0, "a", "target-a"),
            quic_symlink_entry(1, "a/b", "target-b"),
        ]);
        assert!(
            matches!(
                validate_quic_manifest(&nested_symlink, &config),
                Err(QuicTransportError::Source(ref message))
                    if message.contains("nested under symlink")
            ),
            "nested symlink entries must fail closed before commit"
        );
    }

    #[test]
    fn validate_quic_manifest_allows_symlink_siblings_and_plain_entries() {
        let config = trusted_quic_config();
        let sibling = quic_manifest_with_metadata(vec![
            quic_symlink_entry(0, "link", "target.txt"),
            quic_empty_regular_entry(1, "link-sibling/payload.txt"),
        ]);
        assert!(
            validate_quic_manifest(&sibling, &config).is_ok(),
            "component-aligned symlink guard must not reject sibling prefixes"
        );

        let plain = quic_manifest_with_metadata(vec![
            quic_empty_regular_entry(0, "link/payload.txt"),
            quic_empty_regular_entry(1, "link-sibling/payload.txt"),
        ]);
        assert!(validate_quic_manifest(&plain, &config).is_ok());
    }

    fn sample_receipt() -> ReceiveReceipt {
        ReceiveReceipt {
            committed: true,
            bytes_received: 9,
            files: 1,
            sha_ok: true,
            merkle_ok: true,
            symbols_accepted: 0,
            feedback_rounds: 0,
            decode_count: 0,
            decode_micros: 0,
            reason: None,
            committed_paths: vec!["/dest/a/b.txt".to_string()],
        }
    }

    fn varied_bytes(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| {
                let i = u64::try_from(i).unwrap_or(u64::MAX);
                let mixed = i
                    .wrapping_mul(37)
                    .wrapping_add(u64::from(seed).wrapping_mul(11))
                    % 251;
                u8::try_from(mixed).unwrap_or(0)
            })
            .collect()
    }

    fn quic_decode_width_fixture_entry(size: u64) -> QuicEntryDecoder {
        QuicEntryDecoder {
            index: 0,
            object_id: ObjectId::new(0x5155_4943, size),
            size,
            pipeline: None,
            complete: false,
            data: Vec::new(),
            pending_decodes: Vec::new(),
        }
    }

    fn quic_decode_width_fixture_decoder(
        index: u32,
        size: u64,
        config: &QuicConfig,
    ) -> QuicEntryDecoder {
        let object_id = ObjectId::new(0x5155_4943 + u64::from(index), size);
        let mut pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: config.symbol_size,
            max_block_size: config.max_block_size,
            repair_overhead: config.repair_overhead,
            min_overhead: 0,
            max_buffered_symbols: 0,
            block_timeout: Duration::from_secs(0),
            verify_auth: false,
        });
        pipeline
            .set_object_params(object_params_for(
                object_id,
                size,
                config.symbol_size,
                config.max_block_size,
            ))
            .expect("fixture object params fit QUIC decode geometry");
        QuicEntryDecoder {
            index,
            object_id,
            size,
            pipeline: Some(pipeline),
            complete: false,
            data: Vec::new(),
            pending_decodes: Vec::new(),
        }
    }

    fn drive_in_memory_loopback_transfer(
        cx: &Cx,
        sender: &mut QuicConnection,
        receiver: &mut QuicConnection,
        entries: &[(String, Vec<u8>)],
        config: QuicConfig,
    ) -> Result<QuicConnectionTransferOutcome, QuicTransportError> {
        let config = effective_quic_config_for_entries(&config, entries)?;
        let symbol_auth = config.symbol_auth_context()?;
        let symbol_auth_enabled = symbol_auth.is_some();
        let manifest = manifest_from_entries("payload", true, entries);
        let mut sender_control = QuicFrameTransport::open(cx, sender)?;
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_sender_hello(
            cx,
            sender,
            &mut sender_control,
            &config,
            "sender-peer",
            symbol_auth_enabled,
        )?;
        pump_until_idle(cx, sender, receiver, DEFAULT_MAX_PACKET_BYTES, 5_000)
            .expect("deliver sender hello");
        receive_sender_hello_and_ack(
            cx,
            receiver,
            &mut receiver_control,
            &config,
            "receiver-peer",
            symbol_auth_enabled,
        )?;
        pump_until_idle(cx, receiver, sender, DEFAULT_MAX_PACKET_BYTES, 5_001)
            .expect("deliver sender hello ack");
        let ack = receive_sender_hello_ack(cx, sender, &mut sender_control)?;
        assert_eq!(ack.peer_id, "receiver-peer");

        let mut encoders = encoders_from_entries(&manifest, entries, &config)?;
        let symbols_sent = send_manifest_symbols_complete(
            cx,
            sender,
            &mut sender_control,
            &manifest,
            &mut encoders,
            &config,
        )?;
        pump_until_idle(cx, sender, receiver, DEFAULT_MAX_PACKET_BYTES, 5_002)
            .expect("deliver manifest, symbols, and object-complete");

        let received_manifest = receive_manifest(cx, receiver, &mut receiver_control)?;
        if received_manifest != manifest {
            return Err(QuicTransportError::Integrity(
                "receiver decoded a different manifest".to_string(),
            ));
        }
        let mut decoders = decoders_from_manifest(&received_manifest, &config)?;
        let symbols_accepted =
            drain_symbol_datagrams(receiver, &received_manifest, &mut decoders, &config)?;
        receive_object_complete(cx, receiver, &mut receiver_control)?;
        assemble_completed_entries(&mut decoders);
        let pending = pending_entries(&decoders);
        if pending.is_empty() {
            let receipt = verify_in_memory_receipt(&received_manifest, &decoders);
            send_proof(cx, receiver, &mut receiver_control, &receipt)?;
        } else {
            send_need_more(
                cx,
                receiver,
                &mut receiver_control,
                &QuicNeedMore {
                    pending,
                    repair_blocks: Vec::new(),
                    source_symbols: source_symbol_requests(
                        &decoders,
                        MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND,
                    ),
                    ..QuicNeedMore::default()
                },
            )?;
        }
        pump_until_idle(cx, receiver, sender, DEFAULT_MAX_PACKET_BYTES, 5_003)
            .expect("deliver proof");

        let peer = "127.0.0.1:4433".parse().expect("peer addr");
        let (send_report, symbols_sent) = {
            let mut feedback =
                QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, symbols_sent);
            let report = block_on(handle_sender_feedback_or_proof(
                cx,
                sender,
                &mut sender_control,
                &mut feedback,
            ))?
            .ok_or_else(|| {
                QuicTransportError::Integrity(
                    "sender received repair feedback in no-repair loopback transfer".to_string(),
                )
            })?;
            (report, feedback.symbols_sent)
        };
        let receipt = send_report.receipt.clone();
        pump_until_idle(cx, sender, receiver, DEFAULT_MAX_PACKET_BYTES, 5_004)
            .expect("deliver close");
        let close =
            next_control_frame(cx, receiver, &mut receiver_control, "receive sender close")?;
        if close.frame_type() != FrameType::Close {
            return Err(QuicTransportError::Unexpected {
                got: close.frame_type(),
                expected: "Close",
            });
        }

        Ok(QuicConnectionTransferOutcome {
            manifest,
            send_report,
            receipt,
            symbols_sent,
            symbols_accepted,
        })
    }

    #[test]
    fn default_config_requires_explicit_symbol_auth_posture() {
        let err = QuicConfig::default()
            .validate()
            .expect_err("default config must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Config(m) if m.contains("symbol authentication posture")
        ));
        assert!(trusted_quic_config().validate().is_ok());
        assert!(auth_quic_config(7).validate().is_ok());
        assert_eq!(
            QuicConfig::default()
                .use_transport_authenticated_symbols()
                .symbol_auth_mode(),
            QuicSymbolAuthMode::TransportAuthenticated
        );
    }

    #[test]
    fn default_config_uses_published_constants() {
        let c = QuicConfig::default();
        assert_eq!(c.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(c.symbol_size, DEFAULT_SYMBOL_SIZE);
        assert_eq!(c.max_block_size, DEFAULT_MAX_BLOCK_SIZE);
        assert_eq!(c.max_block_size, usize::from(DEFAULT_SYMBOL_SIZE) * 512);
        assert_eq!(c.max_datagram_size, DEFAULT_MAX_DATAGRAM_SIZE);
        assert_eq!(c.max_transfer_bytes, DEFAULT_MAX_TRANSFER_BYTES);
        assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(360));
        assert_eq!(c.idle_timeout, DEFAULT_IDLE_TIMEOUT);
        assert_eq!(c.handshake_timeout, DEFAULT_HANDSHAKE_TIMEOUT);
        assert_eq!(c.accept_timeout, DEFAULT_ACCEPT_TIMEOUT);
        assert_eq!(c.max_active_connections, DEFAULT_MAX_ACTIVE_CONNECTIONS);
        assert_eq!(c.max_feedback_rounds, DEFAULT_MAX_FEEDBACK_ROUNDS);
        assert_eq!(c.datagram_fanout, DEFAULT_DATAGRAM_FANOUT);
        assert_eq!(
            c.max_spray_symbols_per_flush,
            DEFAULT_MAX_SPRAY_SYMBOLS_PER_FLUSH
        );
        assert_eq!(
            c.symbol_auth_mode(),
            QuicSymbolAuthMode::MissingAuthenticationContext
        );
    }

    #[test]
    fn quic_streaming_parallel_decode_returns_byte_identical_block() {
        let cx = Cx::for_testing();
        let config = QuicConfig {
            symbol_size: 1024,
            max_block_size: 32 * 1024,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let object_size = QUIC_PARALLEL_DECODE_MIN_ENTRY_BYTES;
        let mut decoder = quic_decode_width_fixture_decoder(7, object_size, &config);
        let entry_width = quic_entry_decode_width_budget(
            &decoder,
            &config,
            QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER,
        );
        assert!(
            entry_width > 1,
            "fixture must exercise the gated parallel decode path"
        );

        let block = varied_bytes(config.max_block_size, 91);
        let mut encoder = encoding_pipeline(&config);
        let repair_symbols = encoder
            .encode_single_block_repair_range(decoder.object_id, 0, &block, 0, 48)
            .collect::<Result<Vec<_>, _>>()
            .expect("single-block repair symbols encode");

        let mut decode_stats = QuicDecodeStats::default();
        let mut completed = Vec::new();
        let mut accepted_symbols = 0usize;
        for encoded in repair_symbols {
            let (accepted, decoded) = feed_authenticated_symbol_take_block_deferred(
                &cx,
                &mut decoder,
                AuthenticatedSymbol::new_unauthenticated(encoded.into_symbol()),
                &config,
                &mut decode_stats,
                true,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER,
            )
            .expect("QUIC streaming decoder accepts repair symbol");
            if accepted {
                accepted_symbols += 1;
            }
            if let Some(decoded) = decoded {
                completed.push(decoded);
                break;
            }
        }
        assert!(
            accepted_symbols >= config.max_block_size / usize::from(config.symbol_size),
            "fixture must feed at least K symbols before decode"
        );
        completed.extend(
            block_on(join_all_quic_decodes_with_blocks(
                &cx,
                std::slice::from_mut(&mut decoder),
                &config,
                &mut decode_stats,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER,
            ))
            .expect("pending QUIC decode jobs join"),
        );

        assert_eq!(completed.len(), 1, "only block 0 should complete");
        assert_eq!(completed[0].entry, 7);
        assert_eq!(completed[0].sbn, 0);
        assert_eq!(completed[0].data, block);
        assert_eq!(decode_stats.decode_count, 1);
        assert!(
            decoder.pending_decodes.is_empty(),
            "decode join must leave no queued blocking jobs"
        );
        assert!(
            !decoder.complete,
            "one decoded block must not mark the multi-block logical entry complete"
        );
    }

    #[test]
    fn quic_decode_width_gate_keeps_tiny_entries_inline_and_50m_wide() {
        let config = trusted_quic_config();
        let tiny_size = 1024 * 1024;
        let tiny = quic_decode_width_fixture_entry(tiny_size);
        assert!(!quic_should_parallel_decode_entry(&tiny, &config));
        assert_eq!(
            quic_entry_decode_width_budget(
                &tiny,
                &config,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
            ),
            0,
            "tiny encrypted entries should stay on the inline decode path"
        );
        assert_eq!(
            quic_entry_decode_width_budget_for_geometry(
                tiny_size,
                config.max_block_size,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
            ),
            0,
            "tiny encrypted geometry should not open a decode fanout window"
        );

        let size_50m = 50 * 1024 * 1024;
        let config_50m = effective_quic_config_for_largest_entry(&config, size_50m)
            .expect("50M fixture must fit default QUIC geometry");
        let blocks_50m =
            block_count_for_len(size_50m as u64, &config_50m).expect("50M block count");
        assert!(quic_should_parallel_decode_entry_geometry(
            size_50m as u64,
            config_50m.max_block_size
        ));
        let dec_50m = quic_decode_width_fixture_entry(size_50m as u64);
        assert!(
            quic_should_parallel_decode_entry(&dec_50m, &config_50m),
            "50M encrypted bulk geometry should be eligible for receiver decode fanout"
        );
        let capped_width_50m = blocks_50m
            .min(QUIC_MAX_PENDING_DECODE_JOBS_PER_ENTRY)
            .min(QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER);
        assert!(
            blocks_50m > capped_width_50m,
            "fixture must exceed the fanout caps so the clamp is exercised"
        );
        assert_eq!(
            quic_entry_decode_width_budget(
                &dec_50m,
                &config_50m,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
            ),
            capped_width_50m,
            "50M encrypted bulk geometry should open decode slots up to the fanout caps"
        );
        assert_eq!(
            quic_entry_decode_width_budget_for_geometry(
                size_50m as u64,
                config_50m.max_block_size,
                QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER
            ),
            capped_width_50m,
            "50M encrypted bulk geometry should open the same fanout as the decoder helper"
        );
        assert_eq!(
            quic_transfer_decode_width(std::slice::from_ref(&dec_50m), &config_50m),
            QUIC_MAX_PENDING_DECODE_JOBS_PER_TRANSFER,
            "eligible encrypted bulk transfers should open the transfer-wide decode window"
        );
    }

    #[test]
    fn quic_default_symbol_size_is_the_largest_that_validates() {
        let fits = QuicConfig {
            symbol_size: QUIC_DEFAULT_SYMBOL_SIZE,
            ..trusted_quic_config()
        };
        fits.validate()
            .expect("QUIC_DEFAULT_SYMBOL_SIZE must fit one datagram");
        assert_eq!(
            usize::from(QUIC_DEFAULT_SYMBOL_SIZE) + AUTH_ENVELOPE_HEADER_LEN,
            QuicConfig::default().max_datagram_size,
            "QUIC_DEFAULT_SYMBOL_SIZE must track max_datagram_size minus the envelope header"
        );
        let too_big = QuicConfig {
            symbol_size: QUIC_DEFAULT_SYMBOL_SIZE + 1,
            ..trusted_quic_config()
        };
        assert!(
            too_big.validate().is_err(),
            "one byte past the datagram budget must fail closed"
        );
    }

    #[test]
    fn quic_block_sizer_honors_multimegabyte_configs() {
        let config = QuicConfig {
            max_block_size: 8 * 1024 * 1024,
            ..trusted_quic_config()
        };
        let effective = effective_quic_config_for_largest_entry(&config, 10 * 1024 * 1024)
            .expect("normal 10MiB entry fits the multi-MiB QUIC plan");

        assert_eq!(effective.max_block_size, 8 * 1024 * 1024);

        let params = object_params_for(
            entry_object_id("quic-multimeg-blocks", 0),
            10 * 1024 * 1024,
            effective.symbol_size,
            effective.max_block_size,
        );
        assert_eq!(params.symbols_per_block, 8192);
        assert_eq!(params.source_blocks, 2);
    }

    #[test]
    fn quic_default_geometry_keeps_50m_to_k512_blocks() {
        let config =
            effective_quic_config_for_largest_entry(&trusted_quic_config(), 50 * 1024 * 1024)
                .expect("50MiB fixture must fit default QUIC geometry");

        assert_eq!(config.max_block_size, 512 * 1024);
        assert_eq!(
            block_count_for_len(50 * 1024 * 1024, &config).expect("block count"),
            100
        );
    }

    #[test]
    fn validate_rejects_zero_symbol_size() {
        let c = QuicConfig {
            symbol_size: 0,
            ..trusted_quic_config()
        };
        assert!(matches!(
            c.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("symbol_size")
        ));
    }

    #[test]
    fn validate_rejects_datagram_smaller_than_symbol() {
        let c = QuicConfig {
            symbol_size: 2000,
            max_datagram_size: 1200,
            ..trusted_quic_config()
        };
        assert!(matches!(
            c.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("max_datagram_size")
        ));
    }

    #[test]
    fn validate_requires_room_for_envelope_header() {
        // The raw symbol fits the datagram, but symbol + the (authenticated)
        // envelope header does not -> must still fail closed; the header is not
        // free, so checking only symbol_size <= max_datagram_size is too lax.
        let c = QuicConfig {
            symbol_size: 1199,
            max_datagram_size: 1200,
            ..trusted_quic_config()
        };
        assert!(usize::from(c.symbol_size) < c.max_datagram_size);
        assert!(usize::from(c.symbol_size) + AUTH_ENVELOPE_HEADER_LEN > c.max_datagram_size);
        assert!(matches!(
            c.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("envelope header")
        ));
    }

    #[test]
    fn validate_rejects_repair_overhead_below_one_and_nan() {
        let low = QuicConfig {
            repair_overhead: 0.5,
            ..trusted_quic_config()
        };
        assert!(matches!(
            low.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("repair_overhead")
        ));
        let nan = QuicConfig {
            repair_overhead: f64::NAN,
            ..trusted_quic_config()
        };
        assert!(matches!(
            nan.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("repair_overhead")
        ));
    }

    #[test]
    fn validate_rejects_zero_datagram_fanout() {
        let c = QuicConfig {
            datagram_fanout: 0,
            ..trusted_quic_config()
        };
        assert!(matches!(
            c.validate(),
            Err(QuicTransportError::Config(m)) if m.contains("datagram_fanout")
        ));
    }

    #[test]
    fn validate_rejects_invalid_spray_pacing_knobs() {
        for c in [
            QuicConfig {
                bwlimit_bps: Some(0),
                ..trusted_quic_config()
            },
            QuicConfig {
                max_spray_symbols_per_flush: 0,
                ..trusted_quic_config()
            },
            QuicConfig {
                responsiveness_pressure: f64::NAN,
                ..trusted_quic_config()
            },
            QuicConfig {
                responsiveness_pressure: -0.1,
                ..trusted_quic_config()
            },
            QuicConfig {
                responsiveness_pressure: 1.1,
                ..trusted_quic_config()
            },
        ] {
            assert!(matches!(c.validate(), Err(QuicTransportError::Config(_))));
        }
    }

    fn quic_path_estimate(loss: f64, bw: f64) -> QuicPathEstimate {
        QuicPathEstimate {
            rtt_s: 0.075,
            loss_p_hat: loss,
            loss_p_bar: loss,
            bw_median_bps: bw,
            bw_trough_bps: bw * 0.7,
            enc_symbols_per_s: 2_000_000.0,
            dec_symbols_per_s: 1_500_000.0,
            coding_ref_k: 1024,
            coding_gamma: 1.5,
            samples: 8,
        }
    }

    #[test]
    fn quic_adaptive_controller_is_deterministic_given_seed() {
        let run = || {
            let mut controller = QuicAdaptiveController::new(QuicAdaptivePolicy::default(), 0xA7A7);
            controller.update_estimate(quic_path_estimate(0.02, 12_000_000.0));
            let mut trajectory = Vec::new();
            for _ in 0..24 {
                let plan = controller
                    .next_block_plan(DEFAULT_SYMBOL_SIZE)
                    .expect("enough evidence activates the controller");
                let quic_arm =
                    QuicAdaptiveArm::from_block_plan(plan).expect("valid controller arm");
                trajectory.push((
                    quic_arm.k,
                    quic_arm.repair_overhead,
                    quic_arm.datagram_fanout,
                ));
                controller.observe(
                    u64::from(plan.k),
                    u64::from(plan.k),
                    0.01,
                    u64::from(plan.k) * u64::from(DEFAULT_SYMBOL_SIZE),
                );
            }
            trajectory
        };

        assert_eq!(run(), run(), "same seed and rewards must replay exactly");
    }

    #[test]
    fn quic_adaptive_arm_rejects_invalid_controller_output() {
        assert!(matches!(
            QuicAdaptiveArm::from_block_plan(QuicAdaptiveBlockPlan {
                k: 0,
                overhead: 0.1,
                fanout: 1,
            }),
            Err(QuicTransportError::Config(m)) if m.contains('k')
        ));
        assert!(matches!(
            QuicAdaptiveArm::from_block_plan(QuicAdaptiveBlockPlan {
                k: 128,
                overhead: f64::NAN,
                fanout: 1,
            }),
            Err(QuicTransportError::Config(m)) if m.contains("overhead")
        ));
        assert!(matches!(
            QuicAdaptiveArm::from_block_plan(QuicAdaptiveBlockPlan {
                k: 128,
                overhead: 0.1,
                fanout: 0,
            }),
            Err(QuicTransportError::Config(m)) if m.contains("fanout")
        ));
    }

    #[test]
    fn quic_adaptive_arm_applies_to_loopback_transfer_config() {
        let plan = QuicAdaptiveBlockPlan {
            k: 2,
            overhead: 0.25,
            fanout: 3,
        };
        let config = apply_quic_adaptive_block_plan(
            QuicConfig {
                symbol_size: 128,
                ..trusted_quic_config()
            },
            plan,
        )
        .expect("adaptive plan applies to QUIC config");

        assert_eq!(config.max_block_size, 256);
        assert_eq!(config.repair_overhead, 1.25);
        assert_eq!(config.datagram_fanout, 3);

        let (cx, mut sender, mut receiver) = established_pair();
        let entries = vec![("adaptive.txt".to_string(), varied_bytes(192, 17))];
        let outcome =
            drive_in_memory_loopback_transfer(&cx, &mut sender, &mut receiver, &entries, config)
                .expect("adapted QUIC config drives the existing loopback transfer");

        assert!(outcome.receipt.committed);
        assert_eq!(outcome.send_report.files, 1);
        assert_eq!(outcome.send_report.bytes_sent, 192);
        assert!(
            outcome.symbols_sent >= 3,
            "source symbols plus adaptive repair should be sprayed"
        );
    }

    #[test]
    fn quic_rate_matched_adaptation_applies_calibrated_fec_and_raw_pacing_cap() {
        let config = QuicConfig {
            symbol_size: 1024,
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };
        let policy = QuicAdaptivePolicy {
            min_samples_to_activate: 1,
            max_overhead: 0.50,
            ..QuicAdaptivePolicy::default()
        };
        let decision = quic_adaptive_rate_matched_pacing_decision(
            &config,
            &quic_path_estimate(0.05, 24_000_000.0),
            pacing_signal(0.050, 16 * 1024 * 1024, 0.05),
            &policy,
            8,
        )
        .expect("activated estimate yields a QUIC adaptive pacing decision");

        assert!(!decision.rate_plan.cold_start);
        assert!(
            decision.rate_plan.block.overhead > 0.05,
            "lossy path should request calibrated repair overhead"
        );
        assert_eq!(
            decision.config.repair_overhead,
            1.0 + decision.rate_plan.block.overhead
        );
        assert_eq!(
            decision.config.max_block_size,
            usize::from(config.symbol_size)
                * usize::try_from(decision.rate_plan.block.k).expect("test k fits usize")
        );
        assert_eq!(
            decision.config.datagram_fanout,
            decision.rate_plan.block.fanout
        );
        assert_eq!(
            decision.config.bwlimit_bps,
            Some(adaptive_raw_pacing_bytes_per_s(&config, decision.rate_plan))
        );
        assert!(
            decision.spray.pacing_rate_bps <= decision.config.bwlimit_bps.unwrap(),
            "spray pacer must honor the raw rate-matched cap"
        );
    }

    #[test]
    fn quic_rate_matched_adaptation_preserves_operator_bwlimit() {
        let config = QuicConfig {
            bwlimit_bps: Some(128 * 1024),
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };
        let policy = QuicAdaptivePolicy {
            min_samples_to_activate: 1,
            ..QuicAdaptivePolicy::default()
        };
        let decision = quic_adaptive_rate_matched_pacing_decision(
            &config,
            &quic_path_estimate(0.01, 64_000_000.0),
            pacing_signal(0.025, 64 * 1024 * 1024, 0.0),
            &policy,
            8,
        )
        .expect("operator-capped adaptation should be valid");

        assert_eq!(decision.config.bwlimit_bps, Some(128 * 1024));
        assert_eq!(
            decision.spray.limiter,
            QuicSprayPacingLimiter::BandwidthLimit
        );
        assert!(decision.spray.pacing_rate_bps <= 128 * 1024);
    }

    #[test]
    fn quic_rate_matched_adaptation_cold_starts_without_changing_geometry() {
        let config = trusted_quic_config();
        let decision = quic_adaptive_rate_matched_pacing_decision(
            &config,
            &QuicPathEstimate::unknown(),
            pacing_signal(0.050, 256 * 1024, 0.0),
            &QuicAdaptivePolicy::default(),
            4,
        )
        .expect("thin evidence should still produce a bounded pacing cap");

        assert!(decision.rate_plan.cold_start);
        assert_eq!(decision.config.max_block_size, config.max_block_size);
        assert_eq!(decision.config.repair_overhead, config.repair_overhead);
        assert_eq!(decision.config.datagram_fanout, config.datagram_fanout);
        assert_eq!(decision.config.bwlimit_bps, Some(8 * 1024 * 1024));
    }

    #[test]
    fn quic_path_signal_from_a6_stats_carries_rtt_cwnd_and_loss() {
        let signal = quic_path_signal_from_stats(QuicPathStats {
            smoothed_rtt_micros: Some(75_000),
            latest_rtt_micros: Some(80_000),
            rttvar_micros: Some(5_000),
            congestion_window_bytes: 96_000,
            bytes_in_flight: 24_000,
            pto_count: 1,
            packets_acked: 90,
            packets_lost: 10,
            loss_rate: 0.10,
        });

        assert!((signal.smoothed_rtt_s - 0.075).abs() < f64::EPSILON);
        assert_eq!(signal.congestion_window_bytes, 96_000);
        assert!((signal.loss_rate - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn quic_path_signal_from_transport_uses_recovery_loss_counters() {
        let mut transport = QuicTransportMachine::new();
        transport
            .begin_handshake()
            .expect("transport begins handshake");
        transport.on_established().expect("transport establishes");
        // All four packets leave just before the ACK arrives so that only the
        // packet threshold (pn 1 + 3 <= 4) declares loss: the RTT sample
        // taken from this same ACK (16 ms if the packets were spread over
        // 1..=4 ms) would otherwise also expire the older packets by the time
        // threshold, and this test is about the recovery counters, not the
        // threshold arithmetic.
        for packet_number in 1..=4 {
            transport.on_packet_sent(SentPacketMeta {
                space: PacketNumberSpace::ApplicationData,
                packet_number,
                bytes: 1_200,
                ack_eliciting: true,
                in_flight: true,
                time_sent_micros: 19_000,
            });
        }

        let event = transport.on_ack_received(PacketNumberSpace::ApplicationData, &[4], 0, 20_000);
        assert_eq!(event.acked_packets, 1);
        assert_eq!(event.lost_packets, 1);

        let signal = quic_path_signal_from_transport(&transport);
        assert!((signal.loss_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(
            signal.congestion_window_bytes,
            transport.congestion_window_bytes()
        );
        assert!(signal.smoothed_rtt_s > 0.0);
    }

    #[test]
    fn quic_adaptive_controller_consumes_a6_path_stats_and_shifts_arm() {
        fn train(stats: QuicPathStats) -> usize {
            let mut policy = QuicAdaptivePolicy {
                arm_grid_k: vec![512, 8192],
                arm_grid_fanout: vec![1],
                exp3_eta: 0.30,
                min_samples_to_activate: 1,
                ..QuicAdaptivePolicy::default()
            };
            policy.max_overhead = 0.50;

            let mut controller = QuicAdaptiveController::new(policy, 23);
            controller.update_estimate(QuicPathEstimate {
                samples: 8,
                dec_symbols_per_s: 50_000_000.0,
                ..quic_path_estimate(0.02, 20_000_000.0)
            });
            let mut large_selected_late = 0usize;
            let trials = 700usize;
            for t in 0..trials {
                let plan = controller
                    .next_block_plan(DEFAULT_SYMBOL_SIZE)
                    .expect("controller activates");
                if t >= trials - 200 && plan.k == 8192 {
                    large_selected_late += 1;
                }
                let wall_s = if plan.k == 8192 { 0.004 } else { 0.006 };
                observe_quic_adaptive_path_stats(
                    &mut controller,
                    u64::from(plan.k),
                    u64::from(plan.k),
                    wall_s,
                    u64::from(plan.k) * u64::from(DEFAULT_SYMBOL_SIZE),
                    DEFAULT_SYMBOL_SIZE,
                    stats,
                );
            }
            large_selected_late
        }

        let clean_large = train(QuicPathStats {
            smoothed_rtt_micros: Some(10_000),
            latest_rtt_micros: Some(10_000),
            rttvar_micros: Some(1_000),
            congestion_window_bytes: 64 * 1024 * 1024,
            bytes_in_flight: 0,
            pto_count: 0,
            packets_acked: 999,
            packets_lost: 1,
            loss_rate: 0.001,
        });
        let lossy_large = train(QuicPathStats {
            smoothed_rtt_micros: Some(50_000),
            latest_rtt_micros: Some(50_000),
            rttvar_micros: Some(10_000),
            congestion_window_bytes: 512 * 1024,
            bytes_in_flight: 128 * 1024,
            pto_count: 2,
            packets_acked: 75,
            packets_lost: 25,
            loss_rate: 0.25,
        });

        assert!(
            clean_large > 140,
            "clean/high-cwnd A6 stats should learn the large arm, got {clean_large}/200"
        );
        assert!(
            lossy_large < 80,
            "lossy/small-cwnd A6 stats should shift away from the large arm, got {lossy_large}/200"
        );
    }

    fn pacing_signal(rtt_s: f64, cwnd_bytes: u64, loss_rate: f64) -> QuicPathSignalSample {
        QuicPathSignalSample {
            smoothed_rtt_s: rtt_s,
            congestion_window_bytes: cwnd_bytes,
            loss_rate,
        }
    }

    #[test]
    fn quic_spray_pacing_uses_token_bucket_not_cwnd_gate() {
        let config = QuicConfig {
            symbol_size: 1024,
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };

        let small_cwnd =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 16_000, 0.0));
        let large_cwnd =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 1_048_576, 0.0));
        assert_eq!(
            small_cwnd.max_burst_symbols, large_cwnd.max_burst_symbols,
            "NewReno cwnd is telemetry only for ATP-QUIC data-plane admission: small={small_cwnd:?} large={large_cwnd:?}"
        );
        assert_eq!(
            small_cwnd.pacing_rate_bps, large_cwnd.pacing_rate_bps,
            "token-bucket rate must not collapse to the native QUIC cwnd floor"
        );
        assert!(
            large_cwnd.cwnd_symbols > small_cwnd.cwnd_symbols,
            "cwnd telemetry should still reflect the sampled native QUIC path"
        );

        let high_rtt =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.080, 1_048_576, 0.0));
        assert_ne!(
            high_rtt.limiter,
            QuicSprayPacingLimiter::PathRateMatch,
            "MATRIX-143: RTT alone must not pin clean encrypted round 0 below the ramp"
        );
        assert_eq!(high_rtt.pacing_rate_bps, large_cwnd.pacing_rate_bps);

        let lossy =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 1_048_576, 0.40));
        assert_eq!(lossy.limiter, QuicSprayPacingLimiter::LossBackoff);
        assert!(lossy.congestion_loss_rate > 0.0);
        assert!(lossy.pacing_rate_bps < large_cwnd.pacing_rate_bps);
        assert!(lossy.max_burst_symbols < large_cwnd.max_burst_symbols);

        let bwlimited = quic_spray_pacing_decision_from_config(
            &QuicConfig {
                bwlimit_bps: Some(128 * 1024),
                max_spray_symbols_per_flush: 64,
                ..config.clone()
            },
            pacing_signal(0.050, 1_048_576, 0.0),
        );
        assert_eq!(bwlimited.limiter, QuicSprayPacingLimiter::BandwidthLimit);
        assert!(bwlimited.pacing_rate_bps <= 128 * 1024);
        assert_eq!(bwlimited.max_burst_symbols, 1);
        assert!(
            bwlimited.pause_after_burst >= Duration::from_millis(8),
            "128 KiB/s cap should force a real post-flush pause: {bwlimited:?}"
        );

        let pressured = quic_spray_pacing_decision_from_config(
            &QuicConfig {
                responsiveness_pressure: 0.90,
                max_spray_symbols_per_flush: 64,
                ..config
            },
            pacing_signal(0.050, 1_048_576, 0.0),
        );
        assert_eq!(
            pressured.limiter,
            QuicSprayPacingLimiter::ResponsivenessBackoff
        );
        assert!(pressured.pacing_rate_bps < large_cwnd.pacing_rate_bps);
        assert!(pressured.max_burst_symbols < large_cwnd.max_burst_symbols);
    }

    #[test]
    fn quic_round0_loss_target_seeds_datagram_pacing_before_feedback() {
        let config = QuicConfig {
            symbol_size: 1024,
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };
        let clean =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 1_048_576, 0.0));

        let good_config = QuicConfig {
            round0_loss_target: QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET,
            ..config.clone()
        };
        let good = quic_spray_pacing_decision_from_config(
            &good_config,
            pacing_signal(0.050, 1_048_576, 0.0),
        );
        assert!(
            (good.path_loss_rate - QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET).abs()
                <= f64::EPSILON,
            "GOOD encrypted should carry the configured loss hint into pacing telemetry"
        );
        assert_eq!(
            good.pacing_rate_bps, clean.pacing_rate_bps,
            "GOOD/0.1% must stay on the near-clean source-stream envelope, not the lossy DATAGRAM cap"
        );

        let bad_config = QuicConfig {
            round0_loss_target: 0.02,
            ..config.clone()
        };
        let bad = quic_spray_pacing_decision_from_config(
            &bad_config,
            pacing_signal(0.050, 1_048_576, 0.0),
        );
        assert!((bad.path_loss_rate - 0.02).abs() <= f64::EPSILON);
        assert!(
            bad.pacing_rate_bps <= QUIC_RATE_MATCHED_BAD_LINK_PACING_BPS,
            "bad/2% encrypted round 0 must enter the bad-link cap before NeedMore feedback: {bad:?}"
        );
        assert!(
            bad.pacing_rate_bps > QUIC_RATE_MATCHED_BROKEN_LINK_PACING_BPS,
            "bad/2% should not inherit the narrower broken/10% cap: {bad:?}"
        );

        let broken_config = QuicConfig {
            round0_loss_target: 0.10,
            ..config
        };
        let broken = quic_spray_pacing_decision_from_config(
            &broken_config,
            pacing_signal(0.050, 1_048_576, 0.0),
        );
        assert!((broken.path_loss_rate - 0.10).abs() <= f64::EPSILON);
        assert_eq!(broken.limiter, QuicSprayPacingLimiter::PathRateMatch);
        assert!(
            broken.fec_loss_budget >= 0.20,
            "broken/10% encrypted round 0 must account for proactive FEC budget: {broken:?}"
        );
        assert!(
            broken.pacing_rate_bps <= QUIC_RATE_MATCHED_BROKEN_LINK_PACING_BPS,
            "broken/10% encrypted round 0 must pace near the 10 mbit pipe before sender-side AIMD feedback: {broken:?}"
        );
        assert!(
            !quic_round0_clean_ramp_enabled(&broken_config, &broken, true),
            "configured lossy encrypted cells must not re-enter the clean datagram ramp"
        );
    }

    #[test]
    fn quic_round0_loss_target_for_broken_link_seeds_bounded_repair() {
        let config = QuicConfig {
            symbol_size: 1200,
            max_block_size: 512 * 1024,
            repair_overhead: 1.0,
            round0_loss_target: 0.10,
            ..trusted_quic_config()
        };

        let overhead = quic_round0_loss_target_repair_overhead(&config);
        let block_k =
            usize::try_from(quic_fixed_block_k(&config)).expect("test block size fits usize");
        let repair_symbols = initial_repair_per_block(config.max_block_size, &config);

        assert!(
            overhead > 1.20,
            "broken/10% encrypted round 0 should receive proactive FEC"
        );
        assert!(
            overhead <= 1.0 + QUIC_ROUND0_TARGET_REPAIR_MAX_OVERHEAD,
            "round-0 target loss must stay within the bounded FEC envelope"
        );
        assert!(
            repair_symbols >= block_k / 5,
            "broken/10% encrypted round 0 should seed at least 20% repair: repair={repair_symbols}, k={block_k}"
        );
    }

    #[test]
    fn quic_round0_loss_target_preserves_near_clean_source_stream_budget() {
        let config = QuicConfig {
            symbol_size: 1200,
            max_block_size: 512 * 1024,
            repair_overhead: 1.0,
            round0_loss_target: QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET,
            ..trusted_quic_config()
        };

        assert_eq!(quic_round0_loss_target_repair_overhead(&config), 1.0);
        assert_eq!(initial_repair_per_block(config.max_block_size, &config), 0);
    }

    #[test]
    fn quic_round0_loss_target_respects_explicit_repair_overhead_floor() {
        let config = QuicConfig {
            symbol_size: 1200,
            max_block_size: 512 * 1024,
            repair_overhead: 1.35,
            round0_loss_target: 0.02,
            ..trusted_quic_config()
        };

        assert!(quic_round0_loss_target_repair_overhead(&config) >= 1.35);
    }

    #[test]
    fn quic_spray_pacing_counts_authenticated_envelope_bytes() {
        let symbol_size = 1024usize;
        let datagram_bytes = symbol_size + AUTH_ENVELOPE_HEADER_LEN;
        let config = QuicConfig {
            symbol_size: u16::try_from(symbol_size).expect("test symbol size fits"),
            max_datagram_size: datagram_bytes,
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };

        let decision = quic_spray_pacing_decision_from_config(
            &config,
            pacing_signal(0.050, u64::try_from((datagram_bytes * 2) - 1).unwrap(), 0.0),
        );

        assert_eq!(
            decision.cwnd_symbols, 1,
            "cwnd symbol accounting must use the QUIC symbol envelope size, not raw RaptorQ payload bytes"
        );
    }

    #[test]
    fn quic_round0_clean_ramp_requires_clean_source_round() {
        let config = trusted_quic_config();
        let clean =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 1_048_576, 0.0));
        let bad_rtt =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.080, 1_048_576, 0.0));

        assert!(quic_round0_clean_ramp_enabled(&config, &clean, true));
        assert!(!quic_round0_clean_ramp_enabled(&config, &clean, false));
        assert!(
            quic_round0_clean_ramp_enabled(&config, &bad_rtt, true),
            "MATRIX-143: clean encrypted round 0 must ramp even with high handshake RTT"
        );
        assert_eq!(
            quic_round0_clean_ramp_max_pacing_bps(&bad_rtt),
            QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS
        );
        let good_target = QuicConfig {
            round0_loss_target: 0.001,
            ..config.clone()
        };
        assert!(
            !quic_round0_clean_ramp_enabled(&good_target, &clean, true),
            "Bug A: the DATAGRAM clean ramp must not engage once the configured target has any loss"
        );

        for blocked in [
            QuicConfig {
                debug_drop_one_in: 7,
                ..config.clone()
            },
            QuicConfig {
                bwlimit_bps: Some(8 * 1024 * 1024),
                ..config.clone()
            },
            QuicConfig {
                repair_overhead: 1.01,
                ..config.clone()
            },
            QuicConfig {
                datagram_fanout: 2,
                ..config.clone()
            },
            QuicConfig {
                round0_loss_target: 0.02,
                ..config.clone()
            },
            QuicConfig {
                round0_loss_target: 0.10,
                ..config.clone()
            },
        ] {
            assert!(
                !quic_round0_clean_ramp_enabled(&blocked, &clean, true),
                "clean ramp must stay off for debug loss, operator caps, repair-heavy, fanout, and bad-link configs"
            );
        }

        let lossy =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 1_048_576, 0.001));
        assert!(
            !quic_round0_clean_ramp_enabled(&config, &lossy, true),
            "observed path loss must block the clean ramp"
        );
    }

    #[test]
    fn quic_reliable_source_stream_defaults_until_extreme_loss() {
        let config = trusted_quic_config();
        let clean =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 1_048_576, 0.0));
        let good_config = QuicConfig {
            round0_loss_target: QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET,
            ..config.clone()
        };
        let good = quic_spray_pacing_decision_from_config(
            &good_config,
            pacing_signal(0.050, 1_048_576, 0.001),
        );
        let bad_config = QuicConfig {
            round0_loss_target: 0.02,
            ..config.clone()
        };
        let bad = quic_spray_pacing_decision_from_config(
            &bad_config,
            pacing_signal(0.080, 512 * 1024, 0.0),
        );
        let broken_config = QuicConfig {
            round0_loss_target: 0.10,
            ..config.clone()
        };
        let broken = quic_spray_pacing_decision_from_config(
            &broken_config,
            pacing_signal(0.200, 256 * 1024, 0.0),
        );
        let extreme_config = QuicConfig {
            round0_loss_target: QUIC_RELIABLE_SOURCE_STREAM_MAX_LOSS_TARGET + 0.01,
            ..config.clone()
        };
        let extreme = quic_spray_pacing_decision_from_config(
            &extreme_config,
            pacing_signal(0.200, 256 * 1024, 0.0),
        );
        let extreme_observed = quic_spray_pacing_decision_from_config(
            &config,
            pacing_signal(
                0.050,
                1_048_576,
                QUIC_RELIABLE_SOURCE_STREAM_MAX_LOSS_TARGET + 0.01,
            ),
        );

        assert!((0.0..=f64::EPSILON).contains(&config.round0_loss_target));
        assert!(clean.path_loss_rate <= f64::EPSILON);
        assert!(quic_near_clean_source_stream_enabled(&config, &clean));
        assert!(quic_reliable_source_stream_eligible(1024, &config, &clean));
        assert!(quic_near_clean_source_stream_enabled(&good_config, &good));
        assert!(!(0.0..=f64::EPSILON).contains(&good_config.round0_loss_target));
        assert!(quic_reliable_source_stream_eligible(
            1024,
            &good_config,
            &good
        ));
        assert!(quic_reliable_source_stream_eligible(
            50 * 1024 * 1024,
            &bad_config,
            &bad
        ));
        assert!(quic_reliable_source_stream_eligible(
            50 * 1024 * 1024,
            &broken_config,
            &broken
        ));
        let mut maxed_clean = clean;
        maxed_clean.pacing_rate_bps = QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS;
        assert!(!quic_round0_clean_ramp_enabled(&config, &maxed_clean, true));
        assert!(
            quic_reliable_source_stream_eligible(1024, &config, &maxed_clean),
            "reliable stream selection must not depend on DATAGRAM ramp headroom"
        );
        assert!(!quic_reliable_source_stream_eligible(0, &config, &clean));
        assert!(!quic_reliable_source_stream_eligible(
            QUIC_RELIABLE_SOURCE_STREAM_MAX_BYTES + 1,
            &config,
            &clean
        ));
        assert!(
            !quic_near_clean_source_stream_enabled(&bad_config, &bad),
            "bad/broken stream bulk must not re-enter the clean source-stream pacing ceiling"
        );
        assert!(!quic_reliable_source_stream_eligible(
            50 * 1024 * 1024,
            &extreme_config,
            &extreme
        ));
        assert!(!quic_reliable_source_stream_eligible(
            50 * 1024 * 1024,
            &config,
            &extreme_observed
        ));

        for blocked in [
            QuicConfig {
                debug_drop_one_in: 11,
                ..config.clone()
            },
            QuicConfig {
                bwlimit_bps: Some(8 * 1024 * 1024),
                ..config.clone()
            },
            QuicConfig {
                datagram_fanout: 2,
                ..config.clone()
            },
        ] {
            let decision = quic_spray_pacing_decision_from_config(
                &blocked,
                pacing_signal(0.050, 1_048_576, 0.0),
            );
            assert!(
                !quic_reliable_source_stream_loss_enabled(&blocked, &decision),
                "source stream must stay off when the config selects debug loss, operator pacing, or fanout DATAGRAM behavior"
            );
        }
    }

    #[test]
    fn quic_round0_clean_ramp_additively_updates_rate_and_pause() {
        let config = QuicConfig {
            max_spray_symbols_per_flush: 54,
            ..trusted_quic_config()
        };
        let mut pacing =
            quic_spray_pacing_decision_from_config(&config, pacing_signal(0.050, 256 * 1024, 0.0));
        let datagram_frame_bytes = usize::from(config.symbol_size) + AUTH_ENVELOPE_HEADER_LEN;
        let mut ramp = QuicRound0CleanPacingRamp::new(QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS);
        let start_rate = pacing.pacing_rate_bps;
        let step_datagrams = QUIC_ROUND0_CLEAN_RAMP_STEP_BYTES
            .div_ceil(u64::try_from(datagram_frame_bytes).expect("test frame size fits"));

        ramp.sent_datagrams = step_datagrams.saturating_sub(1);
        let first = ramp
            .observe_datagram(&mut pacing, datagram_frame_bytes)
            .expect("first clean-ramp step");
        assert_eq!(first.old_rate_bps, start_rate);
        assert_eq!(
            first.new_rate_bps,
            start_rate + QUIC_ROUND0_CLEAN_RAMP_ADD_BYTES_PER_S
        );
        assert_eq!(pacing.pacing_rate_bps, first.new_rate_bps);
        assert_eq!(
            pacing.pause_after_burst,
            pacing_pause_for_bytes(
                u64::try_from(pacing.max_burst_symbols)
                    .expect("test burst fits")
                    .saturating_mul(
                        u64::try_from(datagram_frame_bytes).expect("test frame size fits")
                    ),
                pacing.pacing_rate_bps,
            )
        );

        while pacing.pacing_rate_bps < QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS {
            ramp.sent_datagrams = ramp
                .next_step_bytes
                .div_ceil(u64::try_from(datagram_frame_bytes).expect("test frame size fits"))
                .saturating_sub(1);
            let _ = ramp
                .observe_datagram(&mut pacing, datagram_frame_bytes)
                .expect("clean ramp should keep stepping until max");
        }
        assert_eq!(
            pacing.pacing_rate_bps,
            QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS
        );
    }

    #[test]
    fn quic_spray_pacing_trace_emits_stable_epoch_fields() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_diagnostic_context(crate::observability::DiagnosticContext::new());
        cx.set_log_collector(collector.clone());

        // Keep the observed loss (and the round0 seed) below
        // QUIC_RATE_MATCHED_BAD_LINK_LOSS_MIN and machine pressure at zero so
        // no loss-matched pacing cap or responsiveness throttle engages and
        // the user bwlimit is the genuine binding constraint.
        let signal = pacing_signal(0.025, 512 * 1024, 0.0);
        let decision = quic_spray_pacing_decision_from_config(
            &QuicConfig {
                bwlimit_bps: Some(2 * 1024 * 1024),
                max_spray_symbols_per_flush: 16,
                responsiveness_pressure: 0.0,
                ..trusted_quic_config()
            },
            signal,
        );
        decision.trace_epoch(&cx, 7);

        let entries = collector.peek();
        let entry = entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.spray.pacing_epoch")
            .expect("spray pacing trace entry");
        assert_eq!(entry.get_field("epoch"), Some("7"));
        let expected_burst = decision.max_burst_symbols.to_string();
        assert_eq!(
            entry.get_field("max_burst_symbols"),
            Some(expected_burst.as_str())
        );
        assert_eq!(entry.get_field("limiter"), Some("bandwidth_limit"));
        assert!(entry.get_field("pause_after_burst_micros").is_some());
        assert!(entry.get_field("pacing_rate_bps").is_some());

        // With observed loss above the FEC loss budget the congestion-loss
        // backoff outranks every other limiter in the classification ladder,
        // so the trace label must flip to "loss".
        let lossy = quic_spray_pacing_decision_from_config(
            &QuicConfig {
                bwlimit_bps: Some(2 * 1024 * 1024),
                max_spray_symbols_per_flush: 16,
                responsiveness_pressure: 0.0,
                ..trusted_quic_config()
            },
            pacing_signal(0.025, 512 * 1024, 0.125),
        );
        lossy.trace_epoch(&cx, 8);
        let entries = collector.peek();
        let lossy_entry = entries
            .iter()
            .find(|entry| {
                entry.message() == "atp_quic.spray.pacing_epoch"
                    && entry.get_field("epoch") == Some("8")
            })
            .expect("lossy spray pacing trace entry");
        assert_eq!(lossy_entry.get_field("limiter"), Some("loss"));
    }

    #[test]
    fn d1_quic_effective_datagram_fanout_is_bounded_by_config_and_cpu() {
        let config = QuicConfig {
            datagram_fanout: 8,
            max_active_connections: 4,
            ..trusted_quic_config()
        };

        assert_eq!(quic_effective_datagram_fanout(&config, 64), 4);
        assert_eq!(quic_effective_datagram_fanout(&config, 2), 2);
        assert_eq!(quic_effective_datagram_fanout(&config, 0), 1);

        let single_connection_config = QuicConfig {
            datagram_fanout: 8,
            max_active_connections: 0,
            ..trusted_quic_config()
        };
        assert_eq!(
            quic_effective_datagram_fanout(&single_connection_config, 64),
            1,
            "zero max_active_connections is normalized to the existing single-connection behavior"
        );
    }

    #[test]
    fn d1_quic_spray_pacing_uses_effective_fanout_bound() {
        let config = QuicConfig {
            datagram_fanout: 8,
            max_active_connections: 4,
            symbol_size: 1024,
            max_spray_symbols_per_flush: 64,
            ..trusted_quic_config()
        };
        let signal = pacing_signal(0.050, 64 * 1024, 0.0);

        let config_bound = quic_spray_pacing_decision_from_config(&config, signal);
        let cpu_bound = quic_spray_pacing_decision_from_config_with_cpu(&config, signal, 2);

        assert_eq!(
            config_bound.cwnd_share_symbols,
            config_bound.cwnd_symbols / 4,
            "default config path should clamp fanout to max_active_connections"
        );
        assert_eq!(
            cpu_bound.cwnd_share_symbols,
            cpu_bound.cwnd_symbols / 2,
            "explicit CPU path should clamp fanout to available parallelism"
        );
        assert!(
            cpu_bound.pacing_rate_bps > config_bound.pacing_rate_bps,
            "fewer effective lanes should give each lane a larger safe pacing share"
        );
    }

    #[test]
    fn d1_quic_block_interleaving_scheduler_feeds_every_lane_and_block() {
        let blocks = [
            QuicFanoutBlock {
                entry: 0,
                sbn: 0,
                symbols: 2,
            },
            QuicFanoutBlock {
                entry: 0,
                sbn: 1,
                symbols: 2,
            },
            QuicFanoutBlock {
                entry: 1,
                sbn: 0,
                symbols: 2,
            },
        ];

        let slots = QuicBlockInterleavingScheduler::new(&blocks, 3).collect::<Vec<_>>();
        assert_eq!(
            slots
                .iter()
                .map(|slot| {
                    (
                        slot.connection,
                        slot.entry,
                        slot.sbn,
                        slot.symbol_index_in_block,
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (0, 0, 0, 0),
                (1, 0, 1, 0),
                (2, 1, 0, 0),
                (0, 0, 0, 1),
                (1, 0, 1, 1),
                (2, 1, 0, 1),
            ],
            "scheduler must interleave blocks before returning to the same block"
        );

        let mut per_connection = [0usize; 3];
        let mut per_block = std::collections::BTreeMap::<(u32, u8), usize>::new();
        for slot in slots {
            per_connection[slot.connection] += 1;
            *per_block.entry((slot.entry, slot.sbn)).or_default() += 1;
        }
        assert_eq!(per_connection, [2, 2, 2]);
        assert_eq!(per_block.get(&(0, 0)), Some(&2));
        assert_eq!(per_block.get(&(0, 1)), Some(&2));
        assert_eq!(per_block.get(&(1, 0)), Some(&2));
    }

    #[test]
    fn d1_quic_block_interleaving_scheduler_skips_empty_blocks_and_clamps_zero_lanes() {
        let blocks = [
            QuicFanoutBlock {
                entry: 0,
                sbn: 0,
                symbols: 0,
            },
            QuicFanoutBlock {
                entry: 7,
                sbn: 2,
                symbols: 1,
            },
        ];
        let scheduler = QuicBlockInterleavingScheduler::new(&blocks, 0);
        assert_eq!(scheduler.connection_count(), 1);
        assert!(!scheduler.is_empty());

        let slots = scheduler.collect::<Vec<_>>();
        assert_eq!(
            slots,
            vec![QuicFanoutSymbolSlot {
                connection: 0,
                entry: 7,
                sbn: 2,
                symbol_index_in_block: 0,
            }]
        );

        assert!(QuicBlockInterleavingScheduler::new(&[], 4).is_empty());
    }

    #[test]
    fn d1_quic_fanout_spray_plan_counts_lanes_and_synthetic_scaling() {
        let config = QuicConfig {
            datagram_fanout: 4,
            max_active_connections: 4,
            ..trusted_quic_config()
        };
        let blocks = [
            QuicFanoutBlock {
                entry: 0,
                sbn: 0,
                symbols: 4,
            },
            QuicFanoutBlock {
                entry: 0,
                sbn: 1,
                symbols: 4,
            },
            QuicFanoutBlock {
                entry: 1,
                sbn: 0,
                symbols: 4,
            },
        ];

        let two_lane = quic_plan_fanout_spray(&config, 2, &blocks);
        let four_lane = quic_plan_fanout_spray(&config, 4, &blocks);

        assert_eq!(two_lane.connection_count, 2);
        assert_eq!(four_lane.connection_count, 4);
        assert_eq!(two_lane.total_symbols, 12);
        assert_eq!(four_lane.total_symbols, 12);
        assert_eq!(two_lane.per_connection_symbols, vec![6, 6]);
        assert_eq!(four_lane.per_connection_symbols, vec![3, 3, 3, 3]);
        assert!(
            four_lane
                .per_connection_symbols
                .iter()
                .all(|symbols| *symbols > 0),
            "all effective fan-out lanes should receive symbol work"
        );

        let two_lane_rounds = two_lane
            .per_connection_symbols
            .iter()
            .copied()
            .max()
            .unwrap_or(0);
        let four_lane_rounds = four_lane
            .per_connection_symbols
            .iter()
            .copied()
            .max()
            .unwrap_or(0);
        assert!(
            four_lane_rounds < two_lane_rounds,
            "synthetic same-workload completion rounds should improve with more lanes"
        );
    }

    #[test]
    fn d1_quic_fanout_dispatch_groups_slots_by_connection() {
        let config = QuicConfig {
            datagram_fanout: 3,
            max_active_connections: 3,
            ..trusted_quic_config()
        };
        let blocks = [
            QuicFanoutBlock {
                entry: 0,
                sbn: 0,
                symbols: 3,
            },
            QuicFanoutBlock {
                entry: 1,
                sbn: 0,
                symbols: 3,
            },
        ];

        let dispatch = quic_plan_fanout_dispatch(&config, 3, &blocks, &[]);

        assert_eq!(dispatch.connection_count, 3);
        assert_eq!(dispatch.total_symbols, 6);
        assert_eq!(dispatch.batches.len(), 3);
        assert!(!dispatch.is_empty());
        for batch in &dispatch.batches {
            assert_eq!(batch.logical_connection, batch.physical_connection);
            assert_eq!(batch.migration_generation, 0);
            assert_eq!(batch.symbol_count(), 2);
            assert!(
                batch
                    .slots
                    .iter()
                    .all(|slot| slot.connection == batch.logical_connection),
                "dispatch batches must preserve the scheduler's logical lane"
            );
        }
    }

    #[test]
    fn d1_quic_fanout_dispatch_remaps_migrated_physical_connection_only() {
        let config = QuicConfig {
            datagram_fanout: 2,
            max_active_connections: 2,
            ..trusted_quic_config()
        };
        let blocks = [QuicFanoutBlock {
            entry: 7,
            sbn: 3,
            symbols: 4,
        }];
        let dispatch = quic_plan_fanout_dispatch(
            &config,
            2,
            &blocks,
            &[
                QuicFanoutLaneBinding {
                    logical_connection: 1,
                    physical_connection: 9,
                    migration_generation: 2,
                },
                QuicFanoutLaneBinding {
                    logical_connection: 99,
                    physical_connection: 99,
                    migration_generation: 99,
                },
            ],
        );

        assert_eq!(dispatch.connection_count, 2);
        assert_eq!(dispatch.total_symbols, 4);
        assert_eq!(dispatch.batches[0].physical_connection, 0);
        assert_eq!(dispatch.batches[0].migration_generation, 0);
        assert_eq!(dispatch.batches[1].physical_connection, 9);
        assert_eq!(dispatch.batches[1].migration_generation, 2);
        assert_eq!(dispatch.batches[0].symbol_count(), 2);
        assert_eq!(dispatch.batches[1].symbol_count(), 2);

        for batch in &dispatch.batches {
            for slot in &batch.slots {
                assert_eq!(slot.connection, batch.logical_connection);
                assert_eq!(slot.entry, 7);
                assert_eq!(slot.sbn, 3);
            }
        }
    }

    #[test]
    fn d1_quic_initial_fanout_blocks_match_round_zero_source_and_repair_geometry() {
        let config = QuicConfig {
            symbol_size: 100,
            max_datagram_size: 160,
            max_block_size: 250,
            repair_overhead: 1.20,
            ..trusted_quic_config()
        };
        let manifest = manifest_from_entries(
            "payload",
            false,
            &[
                ("alpha.bin".to_string(), vec![1_u8; 500]),
                ("empty.bin".to_string(), Vec::new()),
            ],
        );

        let blocks =
            quic_initial_fanout_blocks_for_manifest(&manifest, &config).expect("initial blocks");

        assert_eq!(
            blocks,
            vec![
                QuicFanoutBlock {
                    entry: 0,
                    sbn: 0,
                    symbols: 4,
                },
                QuicFanoutBlock {
                    entry: 0,
                    sbn: 1,
                    symbols: 4,
                },
            ],
            "each 250-byte block has three source symbols plus one proactive repair symbol"
        );
    }

    #[test]
    fn d1_quic_initial_fanout_dispatch_uses_manifest_geometry_and_migration_bindings() {
        let config = QuicConfig {
            datagram_fanout: 3,
            max_active_connections: 3,
            symbol_size: 128,
            max_block_size: 256,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let manifest = manifest_from_entries(
            "payload",
            false,
            &[("alpha.bin".to_string(), vec![7_u8; 768])],
        );

        let dispatch = quic_plan_initial_fanout_dispatch(
            &config,
            3,
            &manifest,
            &[QuicFanoutLaneBinding {
                logical_connection: 2,
                physical_connection: 7,
                migration_generation: 3,
            }],
        )
        .expect("dispatch plan");

        assert_eq!(dispatch.connection_count, 3);
        assert_eq!(dispatch.total_symbols, 6);
        assert_eq!(
            dispatch
                .batches
                .iter()
                .map(QuicFanoutConnectionBatch::symbol_count)
                .collect::<Vec<_>>(),
            vec![2, 2, 2],
            "three 256-byte blocks with two source symbols each should feed every lane evenly"
        );
        assert_eq!(dispatch.batches[2].physical_connection, 7);
        assert_eq!(dispatch.batches[2].migration_generation, 3);
    }

    #[test]
    fn d1_quic_fanout_dispatch_trace_emits_logical_physical_and_total_fields() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_diagnostic_context(crate::observability::DiagnosticContext::new());
        cx.set_log_collector(collector.clone());
        let plan = QuicFanoutDispatchPlan {
            connection_count: 2,
            total_symbols: 5,
            batches: vec![
                QuicFanoutConnectionBatch {
                    logical_connection: 0,
                    physical_connection: 0,
                    migration_generation: 0,
                    slots: vec![QuicFanoutSymbolSlot {
                        connection: 0,
                        entry: 1,
                        sbn: 0,
                        symbol_index_in_block: 0,
                    }],
                },
                QuicFanoutConnectionBatch {
                    logical_connection: 1,
                    physical_connection: 9,
                    migration_generation: 4,
                    slots: vec![
                        QuicFanoutSymbolSlot {
                            connection: 1,
                            entry: 1,
                            sbn: 0,
                            symbol_index_in_block: 1,
                        };
                        4
                    ],
                },
            ],
        };

        trace_quic_fanout_dispatch_plan(&cx, 13, &plan);

        let entries = collector
            .peek()
            .into_iter()
            .filter(|entry| entry.message() == "atp_quic.spray.fanout_dispatch")
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].get_field("round"), Some("13"));
        assert_eq!(entries[0].get_field("logical_connection"), Some("0"));
        assert_eq!(entries[0].get_field("physical_connection"), Some("0"));
        assert_eq!(entries[0].get_field("symbols"), Some("1"));
        assert_eq!(entries[0].get_field("total_symbols"), Some("5"));
        assert_eq!(entries[1].get_field("logical_connection"), Some("1"));
        assert_eq!(entries[1].get_field("physical_connection"), Some("9"));
        assert_eq!(entries[1].get_field("migration_generation"), Some("4"));
        assert_eq!(entries[1].get_field("symbols"), Some("4"));
    }

    #[test]
    fn d1_quic_fanout_spray_counts_trace_emits_per_connection_fields() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_diagnostic_context(crate::observability::DiagnosticContext::new());
        cx.set_log_collector(collector.clone());

        trace_quic_fanout_spray_counts(&cx, 11, &[3, 5, 8]);

        let entries = collector
            .peek()
            .into_iter()
            .filter(|entry| entry.message() == "atp_quic.spray.fanout_connection")
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].get_field("round"), Some("11"));
        assert_eq!(entries[0].get_field("connection"), Some("0"));
        assert_eq!(entries[0].get_field("connections"), Some("3"));
        assert_eq!(entries[0].get_field("symbols"), Some("3"));
        assert_eq!(entries[1].get_field("connection"), Some("1"));
        assert_eq!(entries[1].get_field("symbols"), Some("5"));
        assert_eq!(entries[2].get_field("connection"), Some("2"));
        assert_eq!(entries[2].get_field("symbols"), Some("8"));
    }

    #[test]
    fn quic_effective_block_size_preserves_explicit_large_blocks() {
        let config = QuicConfig {
            max_block_size: 8 * 1024 * 1024,
            ..trusted_quic_config()
        };
        let entries = vec![("large.bin".to_string(), vec![7_u8; 1024 * 1024])];

        let transfer_config =
            effective_quic_config_for_entries(&config, &entries).expect("sized config");

        assert_eq!(transfer_config.max_block_size, 8 * 1024 * 1024);
    }

    #[test]
    fn quic_prepare_source_manifest_carries_effective_block_geometry() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let file = temp.path().join("payload.bin");
        std::fs::write(&file, varied_bytes(1024 * 1024, 19)).expect("write payload");
        let config = QuicConfig {
            chunk_size: 31 * 1024,
            max_block_size: 8 * 1024 * 1024,
            ..trusted_quic_config()
        };

        let prepared = block_on(prepare_source_manifest(&cx, &file, &config))
            .expect("source manifest prepares");
        let transfer_config = prepared.effective_config(&config);

        assert_eq!(prepared.max_block_size, 8 * 1024 * 1024);
        assert_eq!(transfer_config.max_block_size, 8 * 1024 * 1024);
        assert_eq!(
            block_count_for_len(prepared.manifest.entries[0].size, &transfer_config)
                .expect("block count"),
            1
        );
    }

    #[test]
    fn validate_rejects_zero_timeouts() {
        for c in [
            QuicConfig {
                idle_timeout: Duration::ZERO,
                ..trusted_quic_config()
            },
            QuicConfig {
                handshake_timeout: Duration::ZERO,
                ..trusted_quic_config()
            },
            QuicConfig {
                accept_timeout: Duration::ZERO,
                ..trusted_quic_config()
            },
        ] {
            assert!(matches!(c.validate(), Err(QuicTransportError::Config(_))));
        }
    }

    #[test]
    fn not_implemented_error_names_operation_and_bead() {
        let e = QuicTransportError::NotImplemented {
            operation: "send_path",
            wired_by: "asupersync-arq-quic-epic-b0k8qo.2.2 (B2: QUIC sender coroutine)",
        };
        let rendered = e.to_string();
        assert!(rendered.contains("send_path"));
        assert!(rendered.contains("b0k8qo.2.2"));
        assert!(rendered.contains("failing closed"));
    }

    #[test]
    fn quic_frame_transport_round_trips_canonical_atp_frames() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let stream = tx.stream();
        let mut rx = QuicFrameTransport::for_stream(stream);

        let hello = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::Handshake,
            b"hello".to_vec(),
        )
        .expect("handshake frame");
        let manifest = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectManifest,
            b"manifest-json".to_vec(),
        )
        .expect("manifest frame");

        tx.send(&cx, &mut client, &hello).expect("send hello");
        tx.send(&cx, &mut client, &manifest).expect("send manifest");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_000,
        )
        .expect("pump control bytes");

        let got_hello = rx
            .try_recv(&cx, &mut server)
            .expect("decode hello")
            .expect("hello frame available");
        assert_eq!(got_hello.frame_type(), FrameType::Handshake);
        assert_eq!(got_hello.payload(), b"hello");

        let got_manifest = rx
            .try_recv(&cx, &mut server)
            .expect("decode manifest")
            .expect("manifest frame available");
        assert_eq!(got_manifest.frame_type(), FrameType::ObjectManifest);
        assert_eq!(got_manifest.payload(), b"manifest-json");
        assert!(
            rx.try_recv(&cx, &mut server)
                .expect("empty control stream")
                .is_none()
        );
    }

    #[test]
    fn native_frame_transport_missing_stream_reads_as_eof() {
        let (cx, _client, server) = established_pair();
        let mut native_server = server.inner().clone();
        let mut rx = NativeQuicFrameTransport::for_stream(first_client_bidi_stream());

        let frame = rx
            .try_recv(&cx, &mut native_server)
            .expect("missing local stream behaves like EOF");
        assert!(frame.is_none());
    }

    #[test]
    fn quic_frame_transport_buffers_partial_frame_until_complete() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let first_client_bidi = crate::net::quic_native::StreamId::local(
            StreamRole::Client,
            StreamDirection::Bidirectional,
            0,
        );
        assert_eq!(tx.stream(), first_client_bidi);
        let mut rx = QuicFrameTransport::for_stream(first_client_bidi);

        let frame = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectManifest,
            vec![0xA5; 4096],
        )
        .expect("large manifest frame");
        tx.send(&cx, &mut client, &frame).expect("send large frame");

        let moved = pump_app_data(&cx, &mut client, &mut server, 256, 2_000)
            .expect("pump one partial packet");
        assert!(moved > 0);
        assert!(
            rx.try_recv(&cx, &mut server)
                .expect("partial frame is buffered")
                .is_none(),
            "partial control-frame bytes must not decode early"
        );

        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_001,
        )
        .expect("pump remaining frame bytes");
        let got = rx
            .try_recv(&cx, &mut server)
            .expect("decode complete frame")
            .expect("complete frame available");
        assert_eq!(got.frame_type(), FrameType::ObjectManifest);
        assert_eq!(got.payload(), &[0xA5; 4096]);
    }

    #[test]
    fn quic_frame_transport_round_trips_typed_json_control_payloads() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let stream = tx.stream();
        let mut rx = QuicFrameTransport::for_stream(stream);
        let manifest = sample_manifest();

        tx.send_json(&cx, &mut client, FrameType::ObjectManifest, &manifest)
            .expect("send manifest JSON frame");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_000,
        )
        .expect("pump control bytes");

        let got = rx
            .try_recv_json::<TransferManifest>(
                &cx,
                &mut server,
                FrameType::ObjectManifest,
                "ObjectManifest",
            )
            .expect("receive manifest JSON frame")
            .expect("manifest available");
        assert_eq!(got, manifest);
        assert!(
            rx.try_recv_json::<TransferManifest>(
                &cx,
                &mut server,
                FrameType::ObjectManifest,
                "ObjectManifest",
            )
            .expect("empty control stream")
            .is_none()
        );
    }

    #[test]
    fn quic_frame_transport_rejects_unexpected_json_control_frame_type() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let stream = tx.stream();
        let mut rx = QuicFrameTransport::for_stream(stream);
        let receipt = sample_receipt();

        tx.send_json(&cx, &mut client, FrameType::Proof, &receipt)
            .expect("send proof JSON frame");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_000,
        )
        .expect("pump control bytes");

        let err = rx
            .try_recv_json::<TransferManifest>(
                &cx,
                &mut server,
                FrameType::ObjectManifest,
                "ObjectManifest",
            )
            .expect_err("wrong frame type must fail closed");
        match err {
            QuicTransportError::Unexpected { got, expected } => {
                assert_eq!(got, FrameType::Proof);
                assert_eq!(expected, "ObjectManifest");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn quic_frame_transport_rejects_malformed_json_control_payload() {
        let (cx, mut client, mut server) = established_pair();
        let mut tx = QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let stream = tx.stream();
        let mut rx = QuicFrameTransport::for_stream(stream);
        let bad = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectManifest,
            b"not-json".to_vec(),
        )
        .expect("malformed JSON frame");

        tx.send(&cx, &mut client, &bad)
            .expect("send malformed JSON frame");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_000,
        )
        .expect("pump control bytes");

        let err = rx
            .try_recv_json::<TransferManifest>(
                &cx,
                &mut server,
                FrameType::ObjectManifest,
                "ObjectManifest",
            )
            .expect_err("malformed JSON must fail closed");
        assert!(matches!(err, QuicTransportError::Control(message) if !message.is_empty()));
    }

    #[test]
    fn quic_control_payloads_round_trip_as_json_frames() {
        let hello = QuicHello {
            protocol: ATP_QUIC_PROTOCOL,
            role: "sender".to_string(),
            peer_id: "peer-a".to_string(),
            symbol_size: DEFAULT_SYMBOL_SIZE,
            max_block_size: u64::try_from(DEFAULT_MAX_BLOCK_SIZE).unwrap_or(u64::MAX),
            symbol_auth: true,
            source_stream: false,
            source_stream_id: None,
            total_bytes: 0,
            delta_transfer_nonce: None,
        };
        let hello_frame = json_frame(FrameType::Handshake, &hello).expect("hello frame");
        assert_eq!(hello_frame.version(), ProtocolVersion::CURRENT);
        assert_eq!(hello_frame.frame_type(), FrameType::Handshake);
        assert_eq!(
            parse_json::<QuicHello>(&hello_frame).expect("parse hello"),
            hello
        );

        let ack = QuicHelloAck {
            accepted: false,
            peer_id: "peer-b".to_string(),
            source_stream: false,
            source_stream_recv_window: None,
            reason: Some("unsupported protocol".to_string()),
            delta_transfer_nonce: None,
            delta_receiver_nonce: None,
            delta_destination_root: None,
        };
        let ack_frame = json_frame(FrameType::HandshakeAck, &ack).expect("ack frame");
        assert_eq!(ack_frame.frame_type(), FrameType::HandshakeAck);
        assert_eq!(
            parse_json::<QuicHelloAck>(&ack_frame).expect("parse ack"),
            ack
        );

        let need_more = QuicNeedMore {
            pending: vec![0, 2, 7],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 2,
                sbn: 1,
                symbols: 3,
            }],
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 2,
                sbn: 1,
                esi: 15,
            }],
            ..QuicNeedMore::default()
        };
        let feedback_frame =
            json_frame(FrameType::ObjectRequest, &need_more).expect("feedback frame");
        assert_eq!(feedback_frame.frame_type(), FrameType::ObjectRequest);
        assert_eq!(
            parse_json::<QuicNeedMore>(&feedback_frame).expect("parse feedback"),
            need_more
        );
        assert_eq!(
            feedback_frame.payload(),
            br#"{"pending":[0,2,7],"repair_blocks":[{"entry":2,"sbn":1,"symbols":3}],"source_symbols":[{"entry":2,"sbn":1,"esi":15}]}"#
        );

        let keepalive = Frame::empty(FrameType::KeepAlive).expect("keepalive frame");
        assert_eq!(keepalive.version(), ProtocolVersion::CURRENT);
        assert_eq!(keepalive.frame_type(), FrameType::KeepAlive);
        assert!(keepalive.payload().is_empty());
    }

    fn delta_test_config() -> QuicConfig {
        QuicConfig {
            chunk_size: 4,
            enable_delta: true,
            metadata_policy: MetadataPolicy::portable(),
            ..trusted_quic_config()
        }
        .with_delta_control_auth(SecurityContext::for_testing(0xD3_17_A0))
    }

    fn prepare_delta_test_source(
        cx: &Cx,
        root: &Path,
        bytes: &[u8],
    ) -> (PathBuf, QuicConfig, QuicPreparedSource) {
        let source = root.join("payload.bin");
        std::fs::write(&source, bytes).expect("write QUIC delta source");
        let config = delta_test_config();
        let prepared = block_on(prepare_source_manifest(cx, &source, &config))
            .expect("prepare QUIC delta source");
        (source, config, prepared)
    }

    fn delta_test_handshake(dest: &Path) -> QuicDeltaHandshakeContext {
        let sender_nonce = TransferNonce::new([0x11; 32]);
        let receiver_nonce = TransferNonce::new([0x22; 32]);
        QuicDeltaHandshakeContext {
            sender_nonce,
            receiver_nonce,
            destination_root: quic_delta_destination_root_commitment(
                &SecurityContext::for_testing(0xD3_17_A0),
                receiver_nonce,
                dest,
            )
            .expect("bind delta destination root"),
        }
    }

    #[test]
    fn quic_delta_manifest_attaches_and_rejects_source_drift() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("tempdir");
        let original = b"abcdefghijklmnop";
        let (source, config, prepared) = prepare_delta_test_source(&cx, temp.path(), original);
        let delta = prepared
            .manifest
            .delta_manifest
            .as_ref()
            .expect("eligible source carries delta manifest");

        assert_eq!(delta.chunk_size, 4);
        assert_eq!(
            delta.total_size_bytes,
            u64::try_from(original.len()).unwrap_or(u64::MAX)
        );
        assert_eq!(delta.chunks.len(), 4);
        assert!(delta.chunks.iter().all(|chunk| chunk.size_bytes == 4));
        validate_quic_delta_manifest(&prepared.manifest).expect("delta manifest validates");
        let transport_auth_only = QuicConfig {
            chunk_size: 4,
            enable_delta: true,
            metadata_policy: MetadataPolicy::portable(),
            ..trusted_quic_config()
        };
        let full_only = block_on(prepare_source_manifest(&cx, &source, &transport_auth_only))
            .expect("prepare transport-auth-only source");
        assert!(
            full_only.manifest.delta_manifest.is_none(),
            "server-authenticated TLS without a shared client key must not expose delta state"
        );
        let mut malformed_manifest = prepared.manifest.clone();
        malformed_manifest
            .delta_manifest
            .as_mut()
            .expect("delta manifest")
            .chunks[0]
            .size_bytes = 3;
        assert!(validate_quic_delta_manifest(&malformed_manifest).is_err());
        let mut too_many_chunks = prepared.manifest.clone();
        let template = too_many_chunks
            .delta_manifest
            .as_ref()
            .and_then(|delta| delta.chunks.first())
            .expect("delta chunk")
            .clone();
        too_many_chunks
            .delta_manifest
            .as_mut()
            .expect("delta manifest")
            .chunks = vec![template; 4_097];
        assert!(matches!(
            validate_quic_delta_manifest(&too_many_chunks),
            Err(QuicTransportError::Source(message)) if message.contains("too many chunks")
        ));
        block_on(validate_quic_prepared_delta_source_unchanged(
            &cx, &prepared, &config,
        ))
        .expect("unchanged source revalidates");

        std::fs::write(&source, b"ponmlkjihgfedcba").expect("mutate source at same length");
        assert!(matches!(
            block_on(validate_quic_prepared_delta_source_unchanged(
                &cx, &prepared, &config
            )),
            Err(QuicTransportError::Source(message)) if message.contains("changed")
        ));
    }

    #[test]
    fn quic_delta_receiver_requests_noop_only_for_live_exact_destination() {
        let cx = Cx::for_testing();
        let temp = canon_tempdir();
        let source_root = temp.path().join("source");
        let dest = temp.path().join("dest");
        std::fs::create_dir_all(&source_root).expect("source dir");
        std::fs::create_dir_all(&dest).expect("dest dir");
        let original = b"abcdefghijklmnop";
        let (_source, config, prepared) = prepare_delta_test_source(&cx, &source_root, original);
        let destination = dest.join(&prepared.manifest.root_name);
        std::fs::write(&destination, original).expect("write matching destination");
        let session = derive_quic_delta_session(
            delta_test_handshake(&dest),
            "sender",
            "receiver",
            &prepared.manifest,
        )
        .expect("derive delta session");

        let request = block_on(build_quic_receiver_delta_request(
            &cx,
            &dest,
            &config,
            session,
            &prepared.manifest,
        ))
        .expect("build exact destination request");
        assert_eq!(
            validate_quic_delta_request(&request, session, &prepared.manifest)
                .expect("validate exact destination request"),
            DeltaWireMode::AlreadyInSync
        );

        std::fs::write(&destination, b"ponmlkjihgfedcba")
            .expect("mutate destination at same length");
        let changed = block_on(build_quic_receiver_delta_request(
            &cx,
            &dest,
            &config,
            session,
            &prepared.manifest,
        ))
        .expect("changed destination safely falls back");
        assert_eq!(
            validate_quic_delta_request(&changed, session, &prepared.manifest)
                .expect("validate full fallback"),
            DeltaWireMode::FullObject
        );

        let cancelled = cancelled_test_cx();
        assert!(matches!(
            block_on(build_quic_receiver_delta_request(
                &cancelled,
                &dest,
                &config,
                session,
                &prepared.manifest,
            )),
            Err(QuicTransportError::Cancelled)
        ));
    }

    #[test]
    fn quic_delta_bindings_reject_replay_and_noncanonical_payloads() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("tempdir");
        let (_source, _config, prepared) =
            prepare_delta_test_source(&cx, temp.path(), b"abcdefghijklmnop");
        let handshake = delta_test_handshake(temp.path());
        let ack = QuicHelloAck {
            accepted: true,
            peer_id: "receiver".to_string(),
            source_stream: false,
            source_stream_recv_window: None,
            reason: None,
            delta_transfer_nonce: Some(handshake.sender_nonce),
            delta_receiver_nonce: Some(handshake.receiver_nonce),
            delta_destination_root: Some(handshake.destination_root),
        };
        assert_eq!(
            validate_quic_delta_ack(Some(handshake.sender_nonce), &ack).expect("valid delta ack"),
            Some(handshake)
        );
        let declined_ack = QuicHelloAck {
            delta_transfer_nonce: None,
            delta_receiver_nonce: None,
            delta_destination_root: None,
            ..ack.clone()
        };
        assert_eq!(
            validate_quic_delta_ack(Some(handshake.sender_nonce), &declined_ack)
                .expect("a receiver may decline the offered delta challenge"),
            None
        );
        let mut partial_ack = ack;
        partial_ack.delta_receiver_nonce = None;
        assert!(validate_quic_delta_ack(Some(handshake.sender_nonce), &partial_ack).is_err());
        let session =
            derive_quic_delta_session(handshake, "sender", "receiver", &prepared.manifest)
                .expect("derive delta session");
        let control_auth = SecurityContext::for_testing(0xD3_17_A0);
        let envelope =
            make_quic_delta_manifest_envelope(&control_auth, session, &prepared.manifest)
                .expect("authenticate receiver-challenged delta manifest");
        json_frame(FrameType::ObjectManifest, &envelope)
            .expect("authenticated delta manifest remains frame-bounded");
        validate_quic_delta_manifest_envelope(&control_auth, session, &envelope)
            .expect("valid live client proof");

        let exact_root = temp.path().join("single-chunk");
        std::fs::create_dir_all(&exact_root).expect("single-chunk source dir");
        let (_source, _config, exact_prepared) =
            prepare_delta_test_source(&cx, &exact_root, b"abcd");
        let exact_session = derive_quic_delta_session(
            delta_test_handshake(&exact_root),
            "sender",
            "receiver",
            &exact_prepared.manifest,
        )
        .expect("derive single-chunk delta session");
        let mut exact_tamper = make_quic_delta_manifest_envelope(
            &control_auth,
            exact_session,
            &exact_prepared.manifest,
        )
        .expect("authenticate single-chunk manifest");
        exact_tamper
            .manifest
            .delta_manifest
            .as_mut()
            .expect("single-chunk delta manifest")
            .chunk_size = 8;
        validate_quic_delta_manifest(&exact_tamper.manifest)
            .expect("larger terminal chunk geometry remains semantically valid");
        assert!(
            validate_quic_delta_manifest_envelope(&control_auth, exact_session, &exact_tamper,)
                .is_err(),
            "the client tag must authenticate every typed manifest field"
        );
        let attacker = SecurityContext::for_testing(0xA7_7A_C0);
        assert!(
            validate_quic_delta_manifest_envelope(&attacker, session, &envelope).is_err(),
            "a client without the shared key must not reach destination probing"
        );
        let permissive = SecurityContext::for_testing_with_mode(
            0xD3_17_A0,
            crate::security::AuthMode::Permissive,
        );
        assert!(
            make_quic_delta_manifest_envelope(&permissive, session, &prepared.manifest).is_err()
        );
        let mut tampered_envelope = envelope.clone();
        tampered_envelope.client_auth_tag[0] ^= 1;
        assert!(
            validate_quic_delta_manifest_envelope(&control_auth, session, &tampered_envelope)
                .is_err()
        );
        let mut envelope_value = serde_json::to_value(&envelope).expect("envelope JSON");
        envelope_value
            .as_object_mut()
            .expect("envelope object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<QuicDeltaManifestEnvelope>(envelope_value).is_err());
        let mut nested_manifest_value =
            serde_json::to_value(&envelope).expect("nested manifest JSON");
        nested_manifest_value
            .get_mut("manifest")
            .and_then(|manifest| manifest.get_mut("entries"))
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|entries| entries.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .expect("manifest entry object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<QuicDeltaManifestEnvelope>(nested_manifest_value).is_err()
        );
        let mut nested_metadata_value =
            serde_json::to_value(&envelope).expect("nested metadata JSON");
        nested_metadata_value
            .get_mut("manifest")
            .and_then(|manifest| manifest.get_mut("entries"))
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|entries| entries.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .expect("manifest entry object")
            .insert(
                "metadata".to_string(),
                serde_json::json!({"file_kind": "regular", "unexpected": true}),
            );
        assert!(
            serde_json::from_value::<QuicDeltaManifestEnvelope>(nested_metadata_value).is_err()
        );
        let delta = prepared.manifest.delta_manifest.as_ref().expect("delta");
        let request = make_quic_delta_request(
            session,
            &prepared.manifest,
            DeltaObjectRequest {
                mode: DeltaWireMode::AlreadyInSync,
                fallback_reason: None,
                sender_merkle_root_hex: delta.merkle_root_hex.clone(),
                receiver_merkle_root_hex: Some(delta.merkle_root_hex.clone()),
                missing_bytes: 0,
                shared_chunks: u64::try_from(delta.chunks.len()).unwrap_or(u64::MAX),
                stale_chunks: 0,
                missing_chunks: Vec::new(),
            },
        );
        assert_eq!(
            validate_quic_delta_request(&request, session, &prepared.manifest)
                .expect("valid request"),
            DeltaWireMode::AlreadyInSync
        );

        let replay_session = derive_quic_delta_session(
            QuicDeltaHandshakeContext {
                receiver_nonce: TransferNonce::new([0x33; 32]),
                ..handshake
            },
            "sender",
            "receiver",
            &prepared.manifest,
        )
        .expect("derive replay session");
        assert!(
            validate_quic_delta_manifest_envelope(&control_auth, replay_session, &envelope)
                .is_err()
        );
        assert!(validate_quic_delta_request(&request, replay_session, &prepared.manifest).is_err());
        let mut wrong_destination = request.clone();
        wrong_destination.destination_root[0] ^= 1;
        assert!(
            validate_quic_delta_request(&wrong_destination, session, &prepared.manifest).is_err()
        );
        let mut wrong_transfer = request.clone();
        wrong_transfer.transfer_id.push('0');
        assert!(validate_quic_delta_request(&wrong_transfer, session, &prepared.manifest).is_err());
        let mut wrong_sequence = request.clone();
        wrong_sequence.control_seq = 9;
        assert!(validate_quic_delta_request(&wrong_sequence, session, &prepared.manifest).is_err());
        let mut malformed = request.clone();
        malformed.request.missing_bytes = 1;
        assert!(validate_quic_delta_request(&malformed, session, &prepared.manifest).is_err());

        let mut value = serde_json::to_value(&request).expect("request JSON");
        value
            .as_object_mut()
            .expect("request object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<QuicDeltaObjectRequest>(value).is_err());
        let mut nested_value = serde_json::to_value(&request).expect("nested request JSON");
        nested_value
            .get_mut("request")
            .and_then(serde_json::Value::as_object_mut)
            .expect("inner request object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<QuicDeltaObjectRequest>(nested_value).is_err());
    }

    #[test]
    fn quic_delta_proof_requires_canonical_zero_byte_receipt() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("tempdir");
        let (_source, _config, prepared) =
            prepare_delta_test_source(&cx, temp.path(), b"abcdefghijklmnop");
        let session = derive_quic_delta_session(
            delta_test_handshake(temp.path()),
            "sender",
            "receiver",
            &prepared.manifest,
        )
        .expect("derive delta session");
        let receipt = ReceiveReceipt {
            committed: true,
            bytes_received: 0,
            files: 1,
            sha_ok: true,
            merkle_ok: true,
            symbols_accepted: 0,
            feedback_rounds: 0,
            decode_count: 0,
            decode_micros: 0,
            reason: None,
            committed_paths: vec!["/dest/payload.bin".to_string()],
        };
        let proof = make_quic_delta_proof(session, &prepared.manifest, receipt.clone());
        assert_eq!(
            validate_quic_delta_proof(proof.clone(), session, &prepared.manifest)
                .expect("canonical proof"),
            receipt
        );

        let mut wrong_session = proof.clone();
        wrong_session.session_id = SessionId::from_digest([0x44; 32]);
        assert!(validate_quic_delta_proof(wrong_session, session, &prepared.manifest).is_err());
        let mut wrong_destination = proof.clone();
        wrong_destination.destination_root[0] ^= 1;
        assert!(validate_quic_delta_proof(wrong_destination, session, &prepared.manifest).is_err());
        let mut wrong_transfer = proof.clone();
        wrong_transfer.transfer_id.push('0');
        assert!(validate_quic_delta_proof(wrong_transfer, session, &prepared.manifest).is_err());
        let mut wrong_sequence = proof.clone();
        wrong_sequence.control_seq = 9;
        assert!(validate_quic_delta_proof(wrong_sequence, session, &prepared.manifest).is_err());
        let mut outer_value = serde_json::to_value(&proof).expect("proof JSON");
        outer_value
            .as_object_mut()
            .expect("proof object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<QuicDeltaProof>(outer_value).is_err());
        let mut nested_value = serde_json::to_value(&proof).expect("proof receipt JSON");
        nested_value
            .get_mut("receipt")
            .and_then(serde_json::Value::as_object_mut)
            .expect("proof receipt object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<QuicDeltaProof>(nested_value).is_err());

        let mut noncanonical = proof;
        noncanonical.receipt.decode_count = 1;
        assert!(validate_quic_delta_proof(noncanonical, session, &prepared.manifest).is_err());
    }

    #[test]
    fn quic_control_need_more_defaults_missing_source_symbols() {
        let frame = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectRequest,
            br#"{"pending":[3,5]}"#.to_vec(),
        )
        .expect("need-more frame");

        let need = parse_json::<QuicNeedMore>(&frame).expect("parse legacy need-more shape");
        assert_eq!(need.pending, vec![3, 5]);
        assert!(need.repair_blocks.is_empty());
        assert!(need.source_symbols.is_empty());
    }

    #[test]
    fn quic_control_manifest_helper_round_trips() {
        let (cx, mut client, mut server) = established_pair();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());
        let manifest = sample_manifest();

        send_manifest(&cx, &mut client, &mut sender_control, &manifest).expect("send manifest");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_100,
        )
        .expect("deliver manifest");

        let got = receive_manifest(&cx, &mut server, &mut receiver_control)
            .expect("receive manifest helper");
        assert_eq!(got, manifest);
    }

    #[test]
    fn quic_control_round_marker_feedback_proof_and_close_helpers_round_trip() {
        let (cx, mut client, mut server) = established_pair();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_object_complete(&cx, &mut client, &mut sender_control, 7)
            .expect("send object-complete");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_200,
        )
        .expect("deliver object-complete");
        let complete = receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receive object-complete");
        assert_eq!(complete.round_symbols_sent, 7);

        let need = QuicNeedMore {
            pending: vec![1, 3],
            repair_blocks: Vec::new(),
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 3,
                sbn: 2,
                esi: 99,
            }],
            round_symbols_observed: Some(5),
            round_loss_fraction: Some(0.25),
            round_symbols_accepted: Some(4),
            ..QuicNeedMore::default()
        };
        send_need_more(&cx, &mut server, &mut receiver_control, &need).expect("send need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            2_201,
        )
        .expect("deliver need-more");
        match receive_proof_or_need_more(&cx, &mut client, &mut sender_control)
            .expect("receive need-more")
        {
            QuicControlReply::NeedMore(got) => assert_eq!(got, need),
            QuicControlReply::Proof(other) => panic!("unexpected proof: {other:?}"),
        }

        let receipt = sample_receipt();
        send_proof(&cx, &mut server, &mut receiver_control, &receipt).expect("send proof");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            2_202,
        )
        .expect("deliver proof");
        match receive_proof_or_need_more(&cx, &mut client, &mut sender_control)
            .expect("receive proof")
        {
            QuicControlReply::Proof(got) => assert_eq!(got, receipt),
            QuicControlReply::NeedMore(other) => panic!("unexpected need-more: {other:?}"),
        }

        send_close(&cx, &mut client, &mut sender_control).expect("send close");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_203,
        )
        .expect("deliver close");
        let close = next_control_frame(&cx, &mut server, &mut receiver_control, "receive close")
            .expect("receive close");
        assert_eq!(close.frame_type(), FrameType::Close);
    }

    #[test]
    fn quic_control_reply_helper_rejects_unexpected_frame() {
        let (cx, mut client, mut server) = established_pair();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());
        let manifest = sample_manifest();

        send_manifest(&cx, &mut client, &mut sender_control, &manifest).expect("send manifest");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            2_300,
        )
        .expect("deliver manifest");

        let err = receive_proof_or_need_more(&cx, &mut server, &mut receiver_control)
            .expect_err("manifest is not a sender feedback reply");
        match err {
            QuicTransportError::Unexpected { got, expected } => {
                assert_eq!(got, FrameType::ObjectManifest);
                assert_eq!(expected, "Proof | ObjectRequest");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn quic_prepare_source_manifest_hashes_files_with_streaming_digests() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("nested")).expect("create nested dir");
        let alpha = varied_bytes(257, 31);
        let beta = varied_bytes(513, 37);
        std::fs::write(root.join("alpha.bin"), &alpha).expect("write alpha");
        std::fs::write(root.join("nested/beta.bin"), &beta).expect("write beta");

        let config = QuicConfig {
            chunk_size: 17,
            max_transfer_bytes: 2_048,
            ..trusted_quic_config()
        };
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("source manifest prepares");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = std::fs::metadata(
                prepared
                    .pack_tempdir
                    .as_ref()
                    .expect("packed source retains its tempdir")
                    .path(),
            )
            .expect("QUIC pack tempdir metadata")
            .permissions()
            .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "QUIC pack tempdir exposed group/other permissions"
            );
        }

        assert_eq!(prepared.manifest.root_name, "payload");
        assert!(prepared.manifest.is_directory);
        assert_eq!(prepared.manifest.total_bytes, 770);
        // Two small files coalesce into one packed entry; the merkle root and
        // per-member digests stay LOGICAL (per-file), invariant to packing.
        assert_eq!(prepared.manifest.entries.len(), 1);
        let pack = &prepared.manifest.entries[0];
        assert_eq!(pack.rel_path, ".atp-pack-0");
        assert_eq!(pack.size, 770);
        assert_eq!(pack.members.len(), 2);
        assert_eq!(pack.members[0].rel_path, "alpha.bin");
        assert_eq!(pack.members[1].rel_path, "nested/beta.bin");
        assert_eq!(pack.members[0].sha256_hex, sha256_hex(&alpha));
        assert_eq!(pack.members[1].sha256_hex, sha256_hex(&beta));
        assert_eq!(pack.members[1].offset, 257);
        assert_eq!(
            prepared.manifest.merkle_root_hex,
            flat_merkle_root_from_slices([
                ("alpha.bin", alpha.as_slice()),
                ("nested/beta.bin", beta.as_slice()),
            ])
        );
        let mut concat = alpha.clone();
        concat.extend_from_slice(&beta);
        assert_eq!(pack.sha256_hex, sha256_hex(&concat));

        assert_eq!(prepared.entries.len(), 1);
        assert_eq!(prepared.entries[0].index, 0);
        assert_eq!(prepared.entries[0].rel_path, ".atp-pack-0");
        assert_eq!(prepared.entries[0].size, 770);
        assert_eq!(
            prepared.entries[0].object_id,
            entry_object_id(&prepared.manifest.transfer_id, 0)
        );
        assert_eq!(prepared.entries[0].sha256_hex, pack.sha256_hex);
    }

    #[test]
    fn quic_pack_container_name_does_not_collide_with_logical_member() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(&root).expect("create payload root");
        std::fs::write(root.join(".atp-pack-0"), b"legitimate-user-file")
            .expect("write pack-shaped user file");
        std::fs::write(root.join("neighbor.bin"), b"packable-neighbor")
            .expect("write packable neighbor");
        let config = trusted_quic_config();

        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("prepare source with pack-shaped file name");
        assert_eq!(prepared.manifest.entries.len(), 1);
        assert_eq!(prepared.manifest.entries[0].rel_path, ".atp-pack-0");
        assert!(
            prepared.manifest.entries[0]
                .members
                .iter()
                .any(|member| member.rel_path == ".atp-pack-0")
        );
        validate_quic_manifest(&prepared.manifest, &config)
            .expect("internal pack name must not occupy logical path namespace");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn quic_prepare_source_manifest_keeps_hardlink_primary_out_of_pack() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(&root).expect("create payload root");
        let primary = root.join("a-primary.bin");
        std::fs::write(&primary, b"shared-hardlink-content").expect("write primary");
        std::fs::write(root.join("b-regular.bin"), b"packable-neighbor")
            .expect("write regular neighbor");
        std::fs::hard_link(&primary, root.join("c-secondary.bin"))
            .expect("create hardlink secondary");
        let config = QuicConfig {
            preserve_hardlinks: true,
            ..trusted_quic_config()
        };

        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("hardlink source manifest prepares");
        validate_quic_manifest(&prepared.manifest, &config)
            .expect("sender hardlink manifest must pass receiver preflight");

        let primary_entry = prepared
            .manifest
            .entries
            .iter()
            .find(|entry| entry.rel_path == "a-primary.bin")
            .expect("plain primary entry");
        assert!(primary_entry.members.is_empty());
        assert_eq!(
            primary_entry
                .metadata
                .as_ref()
                .and_then(|m| m.hardlink_target.as_ref()),
            None
        );
        let secondary_entry = prepared
            .manifest
            .entries
            .iter()
            .find(|entry| entry.rel_path == "c-secondary.bin")
            .expect("hardlink secondary entry");
        assert_eq!(
            secondary_entry
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.hardlink_target.as_deref()),
            Some("a-primary.bin")
        );
    }

    #[cfg(unix)]
    #[test]
    fn quic_decoded_sparse_commit_covers_regular_and_packed_members() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let sparse_bytes = |len: usize, marker: &[u8]| {
            let mut bytes = vec![0u8; len];
            bytes[..marker.len()].copy_from_slice(marker);
            let tail = len.checked_sub(marker.len()).expect("marker fits fixture");
            bytes[tail..].copy_from_slice(marker);
            bytes
        };
        let regular = sparse_bytes(2 * 1024 * 1024, b"regular-managed");
        let packed_a = sparse_bytes(512 * 1024, b"packed-managed-a");
        let packed_b = sparse_bytes(512 * 1024, b"packed-managed-b");
        let logical_entries = vec![
            ("regular.bin".to_string(), regular.clone()),
            ("packed-a.bin".to_string(), packed_a.clone()),
            ("packed-b.bin".to_string(), packed_b.clone()),
        ];
        let mut manifest = manifest_from_entries("payload", true, &logical_entries);
        let regular_entry = manifest.entries[0].clone();
        manifest.entries = vec![
            regular_entry,
            quic_packed_entry(
                1,
                0,
                &[
                    ("packed-a.bin", packed_a.as_slice()),
                    ("packed-b.bin", packed_b.as_slice()),
                ],
            ),
        ];
        let dest = canon_tempdir();
        let metadata_probe = dest.path().join("metadata-probe");
        std::fs::write(&metadata_probe, b"probe").expect("write metadata probe");
        std::fs::set_permissions(&metadata_probe, std::fs::Permissions::from_mode(0o640))
            .expect("set metadata probe mode");
        std::fs::File::open(&metadata_probe)
            .expect("open metadata probe")
            .set_times(
                std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + Duration::new(1_600_000_321, 654_321_987),
                ),
            )
            .expect("set metadata probe mtime");
        let observed_probe = std::fs::metadata(&metadata_probe).expect("metadata probe");
        let required_metadata = EntryMetadata {
            file_kind: FileKind::Regular,
            unix_mode: Some(observed_probe.permissions().mode() & 0o7777),
            mtime_unix_secs: Some(observed_probe.mtime()),
            mtime_nanos: Some(
                u32::try_from(observed_probe.mtime_nsec()).expect("probe nanos are canonical"),
            ),
            ..EntryMetadata::default()
        };
        manifest.entries[0].metadata = Some(required_metadata.clone());
        for member in &mut manifest.entries[1].members {
            member.metadata = Some(required_metadata.clone());
        }
        manifest.metadata_root_hex = manifest_metadata_commitment(&manifest);

        let mut packed = packed_a.clone();
        packed.extend_from_slice(&packed_b);
        let decoders = vec![
            QuicEntryDecoder {
                index: 0,
                object_id: entry_object_id(&manifest.transfer_id, 0),
                size: u64::try_from(regular.len()).expect("regular size fits u64"),
                pipeline: None,
                complete: true,
                data: regular.clone(),
                pending_decodes: Vec::new(),
            },
            QuicEntryDecoder {
                index: 1,
                object_id: entry_object_id(&manifest.transfer_id, 1),
                size: u64::try_from(packed.len()).expect("pack size fits u64"),
                pipeline: None,
                complete: true,
                data: packed,
                pending_decodes: Vec::new(),
            },
        ];

        let cx = Cx::for_testing();
        let (receipt, committed_paths) = block_on(commit_decoded_entries_with_options(
            &cx,
            dest.path(),
            &manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &trusted_quic_config(),
            &QuicReceiveOptions::new().with_sparse_files(true),
        ))
        .expect("commit sparse decoded entries");
        assert!(receipt.committed && receipt.sha_ok && receipt.merkle_ok);
        assert_eq!(receipt.files, 3);
        let root = dest.path().join("payload");
        let expected_paths = vec![
            root.join("regular.bin"),
            root.join("packed-a.bin"),
            root.join("packed-b.bin"),
        ];
        assert_eq!(committed_paths, expected_paths);
        assert_eq!(
            receipt.committed_paths,
            expected_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
        );

        for (name, expected) in [
            ("regular.bin", regular),
            ("packed-a.bin", packed_a),
            ("packed-b.bin", packed_b),
        ] {
            let path = root.join(name);
            assert_eq!(
                std::fs::read(&path).expect("read sparse decoded commit"),
                expected,
                "decoded sparse commit must preserve logical bytes for {name}"
            );
            let metadata = std::fs::metadata(&path).expect("sparse decoded metadata");
            assert_eq!(
                metadata.len(),
                u64::try_from(expected.len()).expect("expected size fits u64")
            );
            assert!(
                metadata.blocks().saturating_mul(512) < metadata.len() / 2,
                "decoded sparse commit must allocate below half its logical size for {name}"
            );
            assert_eq!(
                metadata.permissions().mode() & 0o7777,
                required_metadata.unix_mode.expect("required mode")
            );
            assert_eq!(
                (metadata.mtime(), metadata.mtime_nsec()),
                (
                    required_metadata.mtime_unix_secs.expect("required mtime"),
                    i64::from(required_metadata.mtime_nanos.expect("required nanos"))
                ),
                "managed QUIC commit must preserve exact mode and subsecond mtime for {name}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn quic_decoded_regular_commit_replaces_stale_readonly_destination() {
        let cx = Cx::for_testing();
        let dest = tempfile::tempdir().expect("destination temp dir");
        let out_path = dest.path().join("payload/alpha.bin");
        std::fs::create_dir_all(out_path.parent().expect("output parent"))
            .expect("create destination parent");
        std::fs::write(&out_path, b"stale").expect("write stale destination");
        let mut permissions = std::fs::metadata(&out_path)
            .expect("stale destination metadata")
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&out_path, permissions).expect("make stale destination read-only");

        let bytes = b"replacement-content".to_vec();
        let entries = vec![("alpha.bin".to_string(), bytes.clone())];
        let manifest = manifest_from_entries("payload", true, &entries);
        let decoders = vec![QuicEntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size: u64::try_from(bytes.len()).expect("payload size fits u64"),
            pipeline: None,
            complete: true,
            data: bytes.clone(),
            pending_decodes: Vec::new(),
        }];

        let (receipt, _) = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &trusted_quic_config(),
        ))
        .expect("commit over read-only destination");
        assert!(receipt.committed);
        assert_eq!(std::fs::read(&out_path).expect("read replacement"), bytes);
    }

    #[cfg(windows)]
    #[test]
    fn quic_decoded_pack_replaces_stale_readonly_members() {
        let cx = Cx::for_testing();
        let source = tempfile::tempdir().expect("source temp dir");
        let root = source.path().join("payload");
        std::fs::create_dir_all(&root).expect("create payload root");
        let alpha = varied_bytes(1_021, 89);
        let beta = varied_bytes(2_039, 97);
        let alpha_source = root.join("alpha.bin");
        std::fs::write(&alpha_source, &alpha).expect("write alpha source");
        let mut source_permissions = std::fs::metadata(&alpha_source)
            .expect("alpha source metadata")
            .permissions();
        source_permissions.set_readonly(true);
        std::fs::set_permissions(&alpha_source, source_permissions)
            .expect("make packed source member read-only");
        std::fs::write(root.join("beta.bin"), &beta).expect("write beta source");
        let config = trusted_quic_config();
        let prepared =
            block_on(prepare_source_manifest(&cx, &root, &config)).expect("prepare packed source");
        assert_eq!(prepared.manifest.entries.len(), 1);
        let pack = &prepared.manifest.entries[0];
        assert_eq!(pack.members.len(), 2);
        assert!(pack.members.iter().any(|member| {
            member.rel_path == "alpha.bin"
                && member
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.windows_attributes)
                    .is_some_and(|attributes| attributes & 1 != 0)
        }));

        let dest = tempfile::tempdir().expect("destination temp dir");
        let dest_root = dest.path().join("payload");
        std::fs::create_dir_all(&dest_root).expect("create destination root");
        for name in ["alpha.bin", "beta.bin"] {
            let path = dest_root.join(name);
            std::fs::write(&path, b"stale").expect("write stale member");
            let mut permissions = std::fs::metadata(&path)
                .expect("stale member metadata")
                .permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(&path, permissions).expect("make member read-only");
        }
        let mut packed = alpha.clone();
        packed.extend_from_slice(&beta);
        let decoders = vec![QuicEntryDecoder {
            index: pack.index,
            object_id: entry_object_id(&prepared.manifest.transfer_id, pack.index),
            size: pack.size,
            pipeline: None,
            complete: true,
            data: packed,
            pending_decodes: Vec::new(),
        }];

        let (receipt, _) = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &prepared.manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &config,
        ))
        .expect("commit packed members over read-only destinations");
        assert!(receipt.committed);
        assert_eq!(
            std::fs::read(dest_root.join("alpha.bin")).expect("read alpha"),
            alpha
        );
        assert_eq!(
            std::fs::read(dest_root.join("beta.bin")).expect("read beta"),
            beta
        );
        assert!(
            std::fs::metadata(dest_root.join("alpha.bin"))
                .expect("received alpha metadata")
                .permissions()
                .readonly(),
            "packed member must receive its deferred read-only attribute"
        );

        for path in [alpha_source, dest_root.join("alpha.bin")] {
            let mut permissions = std::fs::metadata(&path)
                .expect("read-only cleanup metadata")
                .permissions();
            permissions.set_readonly(false);
            std::fs::set_permissions(path, permissions).expect("clear read-only for cleanup");
        }
    }

    #[test]
    fn quic_prepare_source_manifest_preserves_explicit_empty_directory_entry() {
        let cx = Cx::for_testing();
        let temp = canon_tempdir();
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("empty")).expect("create empty dir");
        let dest = canon_tempdir();

        let config = trusted_quic_config();
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("empty directory marker prepares");
        assert_eq!(prepared.manifest.root_name, "payload");
        assert!(prepared.manifest.is_directory);
        assert_eq!(prepared.manifest.total_bytes, 0);
        assert_eq!(prepared.manifest.entries.len(), 1);
        let entry = &prepared.manifest.entries[0];
        assert_eq!(entry.rel_path, "empty");
        assert_eq!(entry.size, 0);
        assert_eq!(entry.sha256_hex, sha256_hex(b""));
        let metadata = entry.metadata.as_ref().expect("directory metadata");
        assert!(matches!(metadata.file_kind, FileKind::Directory));
        assert!(prepared.manifest.metadata_root_hex.is_some());

        let decoders =
            decoders_from_manifest(&prepared.manifest, &config).expect("decoders from manifest");
        let (receipt, committed_paths) = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &prepared.manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &config,
        ))
        .expect("commit empty directory entry");
        assert!(receipt.committed);
        assert_eq!(committed_paths.len(), 1);
        assert!(dest.path().join("payload/empty").is_dir());
    }

    #[test]
    fn quic_prepare_source_manifest_preserves_empty_directory_root() {
        let cx = Cx::for_testing();
        let temp = canon_tempdir();
        let root = temp.path().join("payload");
        std::fs::create_dir_all(&root).expect("create empty root");
        let dest = canon_tempdir();

        let config = trusted_quic_config();
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("empty directory root prepares");
        assert_eq!(prepared.manifest.root_name, "payload");
        assert!(prepared.manifest.is_directory);
        assert_eq!(prepared.manifest.total_bytes, 0);
        assert!(prepared.manifest.entries.is_empty());
        assert!(prepared.manifest.directory_metadata.is_some());
        assert!(prepared.manifest.metadata_root_hex.is_some());

        let decoders =
            decoders_from_manifest(&prepared.manifest, &config).expect("decoders from manifest");
        let (receipt, committed_paths) = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &prepared.manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &config,
        ))
        .expect("commit empty directory root");
        assert!(receipt.committed);
        assert_eq!(committed_paths.len(), 1);
        assert!(dest.path().join("payload").is_dir());
    }

    #[test]
    fn quic_prepare_source_manifest_enforces_transfer_size_ceiling() {
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let file = temp.path().join("payload.bin");
        std::fs::write(&file, b"12345").expect("write file");
        let config = QuicConfig {
            chunk_size: 2,
            max_transfer_bytes: 4,
            ..trusted_quic_config()
        };

        let err = block_on(prepare_source_manifest(&cx, &file, &config))
            .expect_err("oversize source must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::TooLarge { size: 5, max: 4 }
        ));
    }

    #[test]
    fn quic_connection_level_transfer_reaches_proof_over_control_and_datagrams() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..trusted_quic_config()
        };
        let entries = vec![
            ("alpha.bin".to_string(), varied_bytes(384, 3)),
            ("nested/beta.bin".to_string(), varied_bytes(900, 7)),
        ];

        let outcome =
            drive_in_memory_loopback_transfer(&cx, &mut client, &mut server, &entries, config)
                .expect("connection-level transfer reaches proof");

        assert!(outcome.receipt.committed);
        assert!(outcome.receipt.sha_ok);
        assert!(outcome.receipt.merkle_ok);
        assert_eq!(outcome.receipt.bytes_received, 1_284);
        assert_eq!(outcome.receipt.files, 2);
        assert_eq!(outcome.manifest.entries.len(), 2);
        assert_eq!(
            outcome.send_report.transfer_id,
            outcome.manifest.transfer_id
        );
        assert_eq!(outcome.send_report.bytes_sent, outcome.manifest.total_bytes);
        assert_eq!(outcome.send_report.files, 2);
        assert_eq!(
            outcome.send_report.merkle_root_hex,
            outcome.manifest.merkle_root_hex
        );
        assert_eq!(
            outcome.send_report.receipt.committed_paths,
            outcome.receipt.committed_paths
        );
        assert!(
            outcome.symbols_sent > 0,
            "sender must emit QUIC DATAGRAM symbols"
        );
        assert!(
            outcome.symbols_accepted > 0,
            "receiver must feed decoded QUIC DATAGRAM symbols"
        );
        assert!(
            outcome
                .receipt
                .committed_paths
                .contains(&"/quic-memory/payload/nested/beta.bin".to_string())
        );
    }

    #[test]
    fn quic_connection_level_transfer_verifies_symbol_auth_tags() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..auth_quic_config(0xA7_51)
        };
        let entries = vec![
            ("alpha.bin".to_string(), varied_bytes(384, 53)),
            ("nested/beta.bin".to_string(), varied_bytes(640, 59)),
        ];
        let expected_source_symbols = entries
            .iter()
            .map(|(_, bytes)| bytes.len().div_ceil(usize::from(config.symbol_size)))
            .sum::<usize>();

        let outcome =
            drive_in_memory_loopback_transfer(&cx, &mut client, &mut server, &entries, config)
                .expect("authenticated QUIC loopback transfer reaches proof");

        assert!(outcome.receipt.committed);
        assert_eq!(outcome.send_report.bytes_sent, 1_024);
        assert_eq!(
            outcome.symbols_accepted,
            u64::try_from(expected_source_symbols).unwrap_or(u64::MAX)
        );
        assert!(outcome.symbols_sent >= outcome.symbols_accepted);
    }

    #[test]
    fn quic_symbol_auth_rejects_bad_tag_before_decode() {
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            ..auth_quic_config(0x00BA_D7A6)
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 61))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let symbol = Symbol::from_slice(
            SymbolId::new(decoders[0].object_id, 0, 0),
            &entries[0].1,
            SymbolKind::Source,
        );
        let bad_tag = *AuthenticationTag::zero().as_bytes();
        let envelope = symbol_to_envelope(
            &symbol,
            transfer_tag(&manifest.transfer_id),
            decoders[0].index,
            Some(bad_tag),
        );
        let symbol_auth = config
            .symbol_auth_context()
            .expect("auth config should be valid")
            .expect("auth context should be present");

        let err = verified_authenticated_symbol_from_envelope(
            &envelope,
            decoders[0].object_id,
            Some(&symbol_auth),
        )
        .expect_err("bad auth tag must fail closed before decoder feed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message)
                if message.contains("authentication failed")
        ));
        assert!(!decoders[0].complete);
    }

    #[test]
    fn quic_prepared_source_loopback_transfer_reaches_proof_from_disk_files() {
        let (cx, mut client, mut server) = established_pair();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("nested")).expect("create nested dir");
        let alpha = varied_bytes(384, 41);
        let beta = varied_bytes(640, 43);
        std::fs::write(root.join("alpha.bin"), &alpha).expect("write alpha");
        std::fs::write(root.join("nested/beta.bin"), &beta).expect("write beta");
        let config = QuicConfig {
            chunk_size: 31,
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..trusted_quic_config()
        };
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("source manifest prepares from disk");
        let transfer_config = prepared.effective_config(&config);
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &transfer_config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            7_000,
        )
        .expect("deliver sender hello");
        receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &transfer_config,
            "receiver-peer",
            false,
        )
        .expect("receiver accepts hello");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            7_001,
        )
        .expect("deliver hello ack");
        receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives ack");

        let symbols_sent = block_on(send_prepared_source_manifest_symbols_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &prepared,
            &transfer_config,
        ))
        .expect("prepared source sends manifest and symbols");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            7_002,
        )
        .expect("deliver prepared source transfer");

        let received_manifest = receive_manifest(&cx, &mut server, &mut receiver_control)
            .expect("receiver decodes manifest");
        assert_eq!(received_manifest, prepared.manifest);
        let mut decoders =
            decoders_from_manifest(&received_manifest, &transfer_config).expect("decoders");
        let symbols_accepted = drain_symbol_datagrams(
            &mut server,
            &received_manifest,
            &mut decoders,
            &transfer_config,
        )
        .expect("receiver drains symbols");
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees object complete");
        assemble_completed_entries(&mut decoders);
        assert!(
            pending_entries(&decoders).is_empty(),
            "prepared source symbols should decode without repair feedback"
        );
        let receipt = verify_in_memory_receipt(&received_manifest, &decoders);
        assert!(receipt.committed);
        send_proof(&cx, &mut server, &mut receiver_control, &receipt).expect("send proof");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            7_003,
        )
        .expect("deliver proof");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let report = receive_proof_close_and_report(
            &cx,
            &mut client,
            &mut sender_control,
            &prepared.manifest,
            peer,
        )
        .expect("sender receives proof report");
        assert_eq!(report.transfer_id, prepared.manifest.transfer_id);
        assert_eq!(report.bytes_sent, 1_024);
        assert_eq!(report.files, 2);
        assert_eq!(report.receipt.bytes_received, 1_024);
        assert!(symbols_sent > 0);
        assert!(symbols_accepted > 0);
        // The two small files ride one packed entry; the report still counts
        // logical files above.
        assert_eq!(prepared.entries.len(), 1);
        assert_eq!(prepared.entries[0].rel_path, ".atp-pack-0");
        assert_eq!(
            prepared.manifest.entries[0].members[0].rel_path,
            "alpha.bin"
        );
        assert_eq!(
            prepared.manifest.entries[0].members[1].rel_path,
            "nested/beta.bin"
        );
    }

    #[test]
    fn quic_prepared_source_feedback_retransmits_source_symbol_from_disk_file() {
        let (cx, mut client, mut server) = established_pair();
        let temp = tempfile::tempdir().expect("temp dir");
        let source = temp.path().join("payload.bin");
        let bytes = varied_bytes(4 * 1024, 53);
        std::fs::write(&source, &bytes).expect("write source");
        let config = QuicConfig {
            chunk_size: 23,
            symbol_size: 16,
            max_block_size: 4 * 1024,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let prepared = block_on(prepare_source_manifest(&cx, &source, &config))
            .expect("source manifest prepares from disk");
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            7_100,
        )
        .expect("deliver sender hello");
        receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect("receiver accepts hello");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            7_101,
        )
        .expect("deliver hello ack");
        receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives ack");

        let mut encoders = block_on(encoders_from_prepared_source(&cx, &prepared, &config))
            .expect("file-backed encoders");
        let symbol_auth = config.symbol_auth_context().expect("symbol auth context");
        send_manifest(&cx, &mut client, &mut sender_control, &prepared.manifest)
            .expect("send manifest");
        let pending_all = encoders
            .iter()
            .map(|entry| entry.index)
            .collect::<std::collections::BTreeSet<_>>();
        let initial_sent = block_on(spray_streaming_symbol_round(
            &cx,
            &mut client,
            &prepared.manifest,
            &mut encoders,
            &pending_all,
            &config,
            symbol_auth.as_ref(),
            true,
        ))
        .expect("send file-backed source-only round");
        assert_eq!(initial_sent, 256);
        send_object_complete(&cx, &mut client, &mut sender_control, initial_sent)
            .expect("send object complete");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            7_102,
        )
        .expect("deliver prepared source transfer");

        let dropped = server.recv_datagram().expect("drop one source datagram");
        assert!(!dropped.is_empty());
        let received_manifest = receive_manifest(&cx, &mut server, &mut receiver_control)
            .expect("receiver decodes manifest");
        assert_eq!(received_manifest, prepared.manifest);
        let mut decoders = decoders_from_manifest(&received_manifest, &config).expect("decoders");
        let accepted_before =
            drain_symbol_datagrams(&mut server, &received_manifest, &mut decoders, &config)
                .expect("receiver drains surviving source symbols");
        assert_eq!(accepted_before, 255);
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees initial object complete");
        assemble_completed_entries(&mut decoders);
        let pending = pending_entries(&decoders);
        assert_eq!(pending, vec![0]);
        let need = QuicNeedMore {
            pending,
            repair_blocks: Vec::new(),
            source_symbols: source_symbol_requests(
                &decoders,
                MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND,
            ),
            ..QuicNeedMore::default()
        };
        assert_eq!(
            need.source_symbols,
            vec![QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: 0,
            }]
        );
        send_need_more(&cx, &mut server, &mut receiver_control, &need).expect("send need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            7_103,
        )
        .expect("deliver need-more");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut feedback = QuicSenderFeedbackState::new(
            &prepared.manifest,
            &mut encoders,
            &config,
            peer,
            initial_sent,
        );
        let report = block_on(handle_sender_feedback_or_proof(
            &cx,
            &mut client,
            &mut sender_control,
            &mut feedback,
        ))
        .expect("sender handles file-backed need-more");
        assert!(report.is_none());
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(feedback.symbols_sent, 257);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            7_104,
        )
        .expect("deliver source retransmit");

        let source_envelope = recv_symbol_envelope(&mut server, false)
            .expect("source retransmit envelope parses")
            .expect("source retransmit datagram delivered");
        assert!(!source_envelope.is_repair);
        assert_eq!(source_envelope.entry, 0);
        assert_eq!(source_envelope.sbn, 0);
        assert_eq!(source_envelope.esi, 0);
        let source_symbol =
            authenticated_symbol_from_envelope(&source_envelope, decoders[0].object_id, false)
                .expect("source symbol");
        assert!(feed_authenticated_symbol(&mut decoders[0], source_symbol).expect("feed source"));
        let accepted_extra =
            drain_symbol_datagrams(&mut server, &received_manifest, &mut decoders, &config)
                .expect("receiver drains any extra feedback symbols");
        assert_eq!(accepted_extra, 0);
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees repair object complete");
        assemble_completed_entries(&mut decoders);
        assert!(
            pending_entries(&decoders).is_empty(),
            "file-backed source retransmit should complete the decoder"
        );
        let receipt = verify_in_memory_receipt(&received_manifest, &decoders);
        assert!(receipt.committed);
        assert_eq!(receipt.bytes_received, bytes.len() as u64);
    }

    #[test]
    fn native_sender_body_transfers_prepared_source_and_receives_proof() {
        let (cx, client, server) = established_pair();
        let mut native_client = client.inner().clone();
        let mut native_server = server.inner().clone();
        let temp = canon_tempdir();
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("nested")).expect("create nested dir");
        let alpha = varied_bytes(384, 67);
        let beta = varied_bytes(640, 71);
        std::fs::write(root.join("alpha.bin"), &alpha).expect("write alpha");
        std::fs::write(root.join("nested/beta.bin"), &beta).expect("write beta");
        // A bandwidth limit keeps this transfer on the datagram-spray tier:
        // without it, transport-authenticated transfers are eligible for the
        // reliable source-stream tier, the sender offers the stream in its
        // hello, and receive_native_sender_hello_and_ack auto-accepts it —
        // this harness receiver only speaks the spray protocol. The stream
        // tier has its own coverage (native_link unit tests + the transport
        // auth e2e suite).
        let config = QuicConfig {
            chunk_size: 29,
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            bwlimit_bps: Some(64 * 1024 * 1024),
            ..trusted_quic_config()
        };
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("source manifest prepares from disk");
        let transfer_config = prepared.effective_config(&config);
        let mut receiver_control = NativeQuicFrameTransport::for_stream(first_client_bidi_stream());
        let mut client_to_server_pn = 0u64;
        let mut server_to_client_pn = 0u64;
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let dest = canon_tempdir();
        let mut receiver_committed = false;

        let report = block_on(send_prepared_source_over_established_native_connection(
            &cx,
            &mut native_client,
            peer,
            &prepared,
            &transfer_config,
            "sender-peer",
            |drive_point, sender| {
                match drive_point {
                    NativeSenderDrivePoint::HelloSent => {
                        pump_native_until_idle(
                            &cx,
                            sender,
                            &mut native_server,
                            &mut client_to_server_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_000,
                        )?;
                        let hello = receive_native_sender_hello_and_ack(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                            &transfer_config,
                            "receiver-peer",
                            false,
                        )?;
                        assert_eq!(hello.peer_id, "sender-peer");
                        pump_native_until_idle(
                            &cx,
                            &mut native_server,
                            sender,
                            &mut server_to_client_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_001,
                        )?;
                    }
                    NativeSenderDrivePoint::ObjectCompleteSent => {
                        assert!(!receiver_committed, "receiver should commit only once");
                        pump_native_until_idle(
                            &cx,
                            sender,
                            &mut native_server,
                            &mut client_to_server_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_002,
                        )?;

                        let received_manifest = receive_native_manifest(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                        )?;
                        assert_eq!(received_manifest, prepared.manifest);
                        let mut decoders =
                            decoders_from_manifest(&received_manifest, &transfer_config)?;
                        let symbols_accepted = drain_native_symbol_datagrams(
                            &mut native_server,
                            &received_manifest,
                            &mut decoders,
                            &transfer_config,
                        )?;
                        receive_native_object_complete(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                        )?;
                        let decode_stats = assemble_completed_entries(&mut decoders);
                        assert!(
                            pending_entries(&decoders).is_empty(),
                            "prepared native source symbols should decode without repair feedback"
                        );

                        let (receipt, committed_paths) = block_on(commit_decoded_entries(
                            &cx,
                            dest.path(),
                            &received_manifest,
                            &decoders,
                            symbols_accepted,
                            0,
                            decode_stats,
                            &transfer_config,
                        ))?;
                        assert!(receipt.committed);
                        assert_eq!(committed_paths.len(), 2);
                        assert_eq!(
                            std::fs::read(dest.path().join("payload/alpha.bin"))
                                .expect("read alpha"),
                            alpha
                        );
                        assert_eq!(
                            std::fs::read(dest.path().join("payload/nested/beta.bin"))
                                .expect("read beta"),
                            beta
                        );
                        assert!(symbols_accepted > 0);

                        send_native_proof(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                            &receipt,
                        )?;
                        pump_native_until_idle(
                            &cx,
                            &mut native_server,
                            sender,
                            &mut server_to_client_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_003,
                        )?;
                        receiver_committed = true;
                    }
                }
                Ok(())
            },
        ))
        .expect("native established sender body returns proof report");

        assert!(receiver_committed);
        assert_eq!(report.transfer_id, prepared.manifest.transfer_id);
        assert_eq!(report.bytes_sent, 1_024);
        assert_eq!(report.files, 2);
        assert!(report.receipt.committed);

        pump_native_until_idle(
            &cx,
            &mut native_client,
            &mut native_server,
            &mut client_to_server_pn,
            DEFAULT_MAX_PACKET_BYTES,
            8_004,
        )
        .expect("deliver native close");
        let close = next_native_control_frame(
            &cx,
            &mut native_server,
            &mut receiver_control,
            "receive native close",
        )
        .expect("native receiver sees close");
        assert_eq!(close.frame_type(), FrameType::Close);
    }

    #[test]
    fn native_sender_body_streams_clean_source_and_receives_proof() {
        let (cx, client, server) = established_pair();
        let mut native_client = client.inner().clone();
        let mut native_server = server.inner().clone();
        let temp = canon_tempdir();
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("nested")).expect("create nested dir");
        let alpha = varied_bytes(384, 73);
        let beta = varied_bytes(640, 79);
        std::fs::write(root.join("alpha.bin"), &alpha).expect("write alpha");
        std::fs::write(root.join("nested/beta.bin"), &beta).expect("write beta");
        let config = QuicConfig {
            chunk_size: 29,
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("source manifest prepares from disk");
        let transfer_config = prepared.effective_config(&config);
        let mut receiver_control = NativeQuicFrameTransport::for_stream(first_client_bidi_stream());
        let mut source_stream = None;
        let mut client_to_server_pn = 0u64;
        let mut server_to_client_pn = 0u64;
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let dest = canon_tempdir();
        let mut receiver_committed = false;

        let report = block_on(send_prepared_source_over_established_native_connection(
            &cx,
            &mut native_client,
            peer,
            &prepared,
            &transfer_config,
            "sender-peer",
            |drive_point, sender| {
                match drive_point {
                    NativeSenderDrivePoint::HelloSent => {
                        pump_native_until_idle(
                            &cx,
                            sender,
                            &mut native_server,
                            &mut client_to_server_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_100,
                        )?;
                        let hello = receive_native_sender_hello_and_ack(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                            &transfer_config,
                            "receiver-peer",
                            false,
                        )?;
                        assert_eq!(hello.peer_id, "sender-peer");
                        assert!(hello.source_stream);
                        let stream = source_stream_from_hello(&hello)?
                            .expect("clean source stream id must be advertised");
                        assert_ne!(stream, first_client_bidi_stream());
                        source_stream = Some(stream);
                        pump_native_until_idle(
                            &cx,
                            &mut native_server,
                            sender,
                            &mut server_to_client_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_101,
                        )?;
                    }
                    NativeSenderDrivePoint::ObjectCompleteSent => {
                        assert!(!receiver_committed, "receiver should commit only once");
                        pump_native_until_idle(
                            &cx,
                            sender,
                            &mut native_server,
                            &mut client_to_server_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_102,
                        )?;

                        let received_manifest = receive_native_manifest(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                        )?;
                        assert_eq!(received_manifest, prepared.manifest);
                        let mut decoders =
                            decoders_from_manifest(&received_manifest, &transfer_config)?;
                        let streamed = block_on(receive_native_source_stream_entries(
                            &cx,
                            &mut native_server,
                            source_stream.expect("source stream negotiated"),
                            &received_manifest,
                            &mut decoders,
                            &transfer_config,
                        ))?;
                        assert_eq!(streamed, received_manifest.total_bytes);
                        let complete = receive_native_object_complete(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                        )?;
                        assert_eq!(complete.round_symbols_sent, 0);
                        assert!(
                            pending_entries(&decoders).is_empty(),
                            "streamed source bytes should mark every decoder complete"
                        );

                        let (receipt, committed_paths) = block_on(commit_decoded_entries(
                            &cx,
                            dest.path(),
                            &received_manifest,
                            &decoders,
                            0,
                            0,
                            QuicDecodeStats::default(),
                            &transfer_config,
                        ))?;
                        assert!(receipt.committed);
                        assert_eq!(committed_paths.len(), 2);
                        assert_eq!(
                            std::fs::read(dest.path().join("payload/alpha.bin"))
                                .expect("read alpha"),
                            alpha
                        );
                        assert_eq!(
                            std::fs::read(dest.path().join("payload/nested/beta.bin"))
                                .expect("read beta"),
                            beta
                        );

                        send_native_proof(
                            &cx,
                            &mut native_server,
                            &mut receiver_control,
                            &receipt,
                        )?;
                        pump_native_until_idle(
                            &cx,
                            &mut native_server,
                            sender,
                            &mut server_to_client_pn,
                            DEFAULT_MAX_PACKET_BYTES,
                            8_103,
                        )?;
                        receiver_committed = true;
                    }
                }
                Ok(())
            },
        ))
        .expect("native clean source stream returns proof report");

        assert!(receiver_committed);
        assert_eq!(report.transfer_id, prepared.manifest.transfer_id);
        assert_eq!(report.bytes_sent, 1_024);
        assert_eq!(report.files, 2);
        assert_eq!(report.symbols_sent, 0);
        assert_eq!(report.feedback_rounds, 0);
        assert!(report.receipt.committed);

        pump_native_until_idle(
            &cx,
            &mut native_client,
            &mut native_server,
            &mut client_to_server_pn,
            DEFAULT_MAX_PACKET_BYTES,
            8_104,
        )
        .expect("deliver native close");
        let close = next_native_control_frame(
            &cx,
            &mut native_server,
            &mut receiver_control,
            "receive native close",
        )
        .expect("native receiver sees close");
        assert_eq!(close.frame_type(), FrameType::Close);
    }

    #[test]
    fn quic_targeted_repair_symbols_requests_exact_deficit_without_loss() {
        assert_eq!(quic_targeted_repair_symbols(0, None, 0), 0);
        assert_eq!(quic_targeted_repair_symbols(1, None, 0), 1);
        assert_eq!(quic_targeted_repair_symbols(512, None, 0), 512);
        assert_eq!(quic_targeted_repair_symbols(10, None, 12), 10);
        assert_eq!(quic_targeted_repair_symbols(10, None, 4), 4);
        assert_eq!(
            quic_targeted_repair_symbols(MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND, None, 0),
            MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND
        );
    }

    #[test]
    fn quic_targeted_repair_symbols_compensates_raw_deficit_for_round_loss() {
        assert_eq!(quic_loss_compensated_repair_target_symbols(1, None), 1);
        assert_eq!(quic_loss_compensated_repair_target_symbols(1, Some(0.0)), 1);
        assert_eq!(
            quic_loss_compensated_repair_target_symbols(1, Some(0.001)),
            2,
            "good-regime 0.1% loss still needs one spare repair for a one-symbol residual"
        );
        assert_eq!(
            quic_targeted_repair_symbols(1, Some(0.10), 0),
            2,
            "broken-link repair must over-provision the raw deficit for another lossy repair round"
        );
        assert_eq!(
            quic_targeted_repair_symbols(100, Some(0.02), 0),
            104,
            "bad-link repair must over-provision a large raw deficit instead of re-requesting it bare"
        );
        assert_eq!(
            quic_targeted_repair_symbols(100, Some(0.10), 0),
            115,
            "broken-link repair must size large deficits by deficit/(1-loss)+margin"
        );
        assert_eq!(
            quic_targeted_repair_symbols(100, Some(0.10), 110),
            110,
            "feedback round budget caps the loss-compensated target"
        );
        assert_eq!(
            quic_targeted_repair_symbols(1, Some(0.10), 1),
            1,
            "feedback round budget can still cap one-symbol repair over-provisioning"
        );
    }

    #[test]
    fn quic_repair_feedback_rounds_escalate_sparse_residuals_after_common_path() {
        assert_eq!(
            quic_targeted_repair_symbols_for_round(1, Some(0.001), 0, 1, 512),
            9,
            "the first encrypted-good repair round sends capacity-matched loss*K plus margin"
        );
        assert_eq!(
            quic_targeted_repair_symbols_for_round(54, Some(0.001), 0, 1, 512),
            62,
            "one lost coalesced packet gets enough first-round block repair slack to avoid RTT trickle"
        );
        assert_eq!(
            quic_targeted_repair_symbols_for_round(1, Some(0.001), 0, 1, 64),
            2,
            "small blocks keep the normal loss-compensated sparse repair path"
        );
        assert_eq!(
            quic_targeted_repair_symbols_for_round(1, Some(0.0), 0, 1, 512),
            1,
            "clean first repair remains exact-deficit"
        );
        assert_eq!(
            quic_targeted_repair_symbols_for_round(1, None, 0, 2, 512),
            1,
            "the normal two-round encrypted-good path keeps exact sparse repair"
        );
        assert_eq!(
            quic_targeted_repair_symbols_for_round(1, None, 0, 3, 512),
            2,
            "the first residual round adds one fresh repair symbol"
        );
        assert_eq!(
            quic_targeted_repair_symbols_for_round(1, None, 0, 6, 512),
            9,
            "continued residual rounds double extra fresh repair before the cap"
        );
        assert_eq!(
            quic_targeted_repair_symbols_for_round(1, None, 0, 9, 512),
            65,
            "long residual loops hit the per-block escalation cap instead of spinning exact-deficit"
        );
        assert_eq!(
            quic_targeted_repair_symbols_for_round(1, None, 4, 9, 512),
            4,
            "the per-round symbol budget still caps escalated repair"
        );
    }

    #[test]
    fn quic_broken_link_repair_requests_are_path_rate_capped() {
        let config = QuicConfig {
            symbol_size: 1024,
            max_block_size: 512 * 1024,
            round0_loss_target: 0.10,
            ..trusted_quic_config()
        };
        let cap = quic_repair_symbol_round_cap(&config, Some(0.90));
        assert_eq!(
            cap, 2_304,
            "10 mbit-class broken-link repair cap should admit two seconds of 1KiB symbols"
        );

        let manifest = TransferManifest {
            transfer_id: "repair-budget".to_string(),
            root_name: "payload".to_string(),
            is_directory: false,
            total_bytes: 50 * 1024 * 1024,
            merkle_root_hex: "00".repeat(32),
            metadata_root_hex: None,
            directory_metadata: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "large.bin".to_string(),
                size: 50 * 1024 * 1024,
                sha256_hex: "00".repeat(32),
                metadata: None,
                members: Vec::new(),
            }],
            delta_manifest: None,
        };
        let decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let (requests, accounting) =
            block_repair_requests_with_accounting(&decoders, &config, cap, Some(0.90), 1);

        assert_eq!(accounting.requested_repair_symbols, cap as u64);
        assert!(
            accounting.request_gap_to_target_symbols > 0,
            "capped NeedMore must leave unrequested deficit for later paced rounds"
        );
        assert!(
            requests.len() < 100,
            "broken-link NeedMore must not spray all K512 blocks in one feedback round"
        );
    }

    #[test]
    fn quic_bounded_k256_repair_feedback_round_recovers_after_source_loss() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 16,
            max_block_size: 4 * 1024,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        assert_eq!(config.max_block_size / usize::from(config.symbol_size), 256);
        let entries = vec![("alpha.bin".to_string(), varied_bytes(4 * 1024, 47))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_000,
        )
        .expect("deliver sender hello");
        receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect("receiver accepts hello");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_001,
        )
        .expect("deliver hello ack");
        receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives ack");

        let mut encoders = encoders_from_entries(&manifest, &entries, &config).expect("encoders");
        let initial_sent = send_manifest_symbols_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &manifest,
            &mut encoders,
            &config,
        )
        .expect("send source-only round");
        assert_eq!(initial_sent, 256);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_002,
        )
        .expect("deliver source-only round");

        let dropped = server.recv_datagram().expect("drop one source datagram");
        assert!(!dropped.is_empty());
        let received_manifest = receive_manifest(&cx, &mut server, &mut receiver_control)
            .expect("receiver decodes manifest");
        let mut decoders = decoders_from_manifest(&received_manifest, &config).expect("decoders");
        let accepted_before =
            drain_symbol_datagrams(&mut server, &received_manifest, &mut decoders, &config)
                .expect("receiver drains surviving source symbols");
        assert_eq!(accepted_before, 255);
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees initial object complete");
        assemble_completed_entries(&mut decoders);
        let pending = pending_entries(&decoders);
        assert_eq!(pending, vec![0]);
        let need = QuicNeedMore {
            pending,
            repair_blocks: block_repair_requests(
                &decoders,
                &config,
                MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
                None,
            ),
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let expected_repair_symbols = u32::try_from(quic_targeted_repair_symbols(
            1,
            None,
            MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
        ))
        .unwrap_or(u32::MAX);
        assert_eq!(
            need.repair_blocks,
            vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: expected_repair_symbols,
            }],
            "receiver should request exactly the missing repair deficit"
        );
        send_need_more(&cx, &mut server, &mut receiver_control, &need).expect("send need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_003,
        )
        .expect("deliver need-more");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut feedback =
            QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, initial_sent);
        let report = block_on(handle_sender_feedback_or_proof(
            &cx,
            &mut client,
            &mut sender_control,
            &mut feedback,
        ))
        .expect("sender handles need-more");
        assert!(report.is_none());
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(
            feedback.symbols_sent,
            initial_sent + u64::from(need.repair_blocks[0].symbols)
        );
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_004,
        )
        .expect("deliver repair round");

        let repair_envelope = recv_symbol_envelope(&mut server, false)
            .expect("repair envelope parses")
            .expect("targeted repair datagram delivered");
        assert!(repair_envelope.is_repair);
        assert_eq!(repair_envelope.entry, 0);
        assert_eq!(repair_envelope.sbn, 0);
        assert!(repair_envelope.esi >= 256);
        let repair_symbol =
            authenticated_symbol_from_envelope(&repair_envelope, decoders[0].object_id, false)
                .expect("repair symbol");
        assert!(repair_symbol.symbol().kind().is_repair());
        assert!(feed_authenticated_symbol(&mut decoders[0], repair_symbol).expect("feed repair"));
        let accepted_extra =
            drain_symbol_datagrams(&mut server, &received_manifest, &mut decoders, &config)
                .expect("receiver drains any extra feedback symbols");
        assert_eq!(accepted_extra, 0);
        receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees repair object complete");
        assemble_completed_entries(&mut decoders);
        assert!(
            pending_entries(&decoders).is_empty(),
            "repair round should converge after a dropped source symbol"
        );
        let receipt = verify_in_memory_receipt(&received_manifest, &decoders);
        assert!(receipt.committed);
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
        send_proof(&cx, &mut server, &mut receiver_control, &receipt).expect("send proof");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_005,
        )
        .expect("deliver proof");

        let report = block_on(handle_sender_feedback_or_proof(
            &cx,
            &mut client,
            &mut sender_control,
            &mut feedback,
        ))
        .expect("sender receives proof report")
        .expect("proof completes transfer");
        assert_eq!(report.transfer_id, manifest.transfer_id);
        assert_eq!(report.receipt.bytes_received, 4 * 1024);
        assert_eq!(report.files, 1);
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(
            feedback.symbols_sent,
            initial_sent + u64::from(need.repair_blocks[0].symbols)
        );
    }

    #[test]
    fn quic_sender_keeps_serving_exact_targeted_repair_rounds() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            max_feedback_rounds: 1,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(512, 53))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut encoders = encoders_from_entries(&manifest, &entries, &config).expect("encoders");
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut feedback = QuicSenderFeedbackState::new(&manifest, &mut encoders, &config, peer, 0);

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_198,
        )
        .expect("deliver sender hello");
        receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect("receiver accepts hello");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_199,
        )
        .expect("deliver hello ack");
        receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives hello ack");

        let first = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: 2,
            }],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        send_need_more(&cx, &mut server, &mut receiver_control, &first)
            .expect("send first need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_200,
        )
        .expect("deliver first need-more");
        assert!(
            block_on(handle_sender_feedback_or_proof(
                &cx,
                &mut client,
                &mut sender_control,
                &mut feedback,
            ))
            .expect("sender serves first targeted repair")
            .is_none()
        );
        assert_eq!(feedback.feedback_rounds, 1);
        assert_eq!(feedback.symbols_sent, 2);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_201,
        )
        .expect("deliver first repair response");
        let first_complete = receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees first repair completion");
        assert_eq!(first_complete.round, 1);
        assert_eq!(first_complete.round_symbols_sent, 2);

        let second = QuicNeedMore {
            feedback_round: 2,
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: 3,
            }],
            source_symbols: Vec::new(),
            round_symbols_observed: Some(2),
            round_symbols_accepted: Some(2),
            round_loss_fraction: Some(0.0),
            repair_base_deficit_symbols: None,
            repair_loss_compensated_target_symbols: None,
            repair_request_gap_to_target_symbols: None,
            ..QuicNeedMore::default()
        };
        send_need_more(&cx, &mut server, &mut receiver_control, &second)
            .expect("send second need-more");
        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            8_202,
        )
        .expect("deliver second need-more");
        assert!(
            block_on(handle_sender_feedback_or_proof(
                &cx,
                &mut client,
                &mut sender_control,
                &mut feedback,
            ))
            .expect("sender keeps serving targeted repair")
            .is_none()
        );
        assert_eq!(feedback.feedback_rounds, 2);
        assert_eq!(feedback.symbols_sent, 5);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            8_203,
        )
        .expect("deliver second repair response");
        let second_complete = receive_object_complete(&cx, &mut server, &mut receiver_control)
            .expect("receiver sees second repair completion");
        assert_eq!(second_complete.round, 2);
        assert_eq!(second_complete.round_symbols_sent, 3);

        let mut repair_envelopes = Vec::new();
        while let Some(envelope) =
            recv_symbol_envelope(&mut server, false).expect("repair envelope parses")
        {
            repair_envelopes.push(envelope);
        }
        assert_eq!(repair_envelopes.len(), 5);
        assert!(
            repair_envelopes
                .iter()
                .all(|envelope| envelope.is_repair && envelope.entry == 0 && envelope.sbn == 0)
        );
        let repair_esis = repair_envelopes
            .iter()
            .map(|envelope| envelope.esi)
            .collect::<Vec<_>>();
        assert_eq!(repair_esis, vec![4, 5, 6, 7, 8]);
    }

    #[test]
    fn receive_connection_commits_established_native_quic_transfer() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..trusted_quic_config()
        };
        let entries = vec![
            ("alpha.bin".to_string(), varied_bytes(384, 23)),
            ("nested/beta.bin".to_string(), varied_bytes(640, 29)),
        ];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        send_manifest(&cx, &mut client, &mut sender_control, &manifest).expect("send manifest");
        let mut encoders = encoders_from_entries(&manifest, &entries, &config).expect("encoders");
        let symbol_auth = config.symbol_auth_context().expect("auth posture");
        let sent = spray_initial_symbols(
            &cx,
            &mut client,
            &manifest,
            &mut encoders,
            &config,
            symbol_auth.as_ref(),
        )
        .expect("spray");
        assert!(sent > 0);
        send_object_complete(&cx, &mut client, &mut sender_control, sent).expect("send complete");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            6_000,
        )
        .expect("deliver accepted connection payload");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let temp = canon_tempdir();
        let report = block_on(receive_connection(
            &cx,
            server.inner().clone(),
            peer,
            temp.path(),
            config,
            "receiver-peer",
        ))
        .expect("receive connection commits");

        assert!(report.committed);
        assert_eq!(report.transfer_id, manifest.transfer_id);
        assert_eq!(report.bytes_received, 1_024);
        assert_eq!(report.files, 2);
        assert_eq!(report.peer, peer);
        assert_eq!(
            std::fs::read(temp.path().join("payload/alpha.bin")).expect("read alpha"),
            entries[0].1
        );
        assert_eq!(
            std::fs::read(temp.path().join("payload/nested/beta.bin")).expect("read beta"),
            entries[1].1
        );
    }

    #[test]
    fn receive_connection_observes_cancel_before_native_body() {
        let (_setup_cx, _client, server) = established_pair();
        let cx = cancelled_test_cx();
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let temp = tempfile::tempdir().expect("temp dir");

        let err = block_on(receive_connection(
            &cx,
            server.inner().clone(),
            peer,
            temp.path(),
            trusted_quic_config(),
            "receiver-peer",
        ))
        .expect_err("cancelled receive must fail closed");

        assert!(matches!(err, QuicTransportError::Cancelled));
        assert!(
            std::fs::read_dir(temp.path())
                .expect("dest dir still readable")
                .next()
                .is_none(),
            "cancelled receive must not commit files"
        );
    }

    #[test]
    fn native_sender_body_observes_cancel_before_driving_peer() {
        let (setup_cx, client, _server) = established_pair();
        let mut native_client = client.inner().clone();
        let config = trusted_quic_config();
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(&root).expect("create payload root");
        std::fs::write(root.join("alpha.bin"), varied_bytes(256, 83)).expect("write alpha");
        let prepared = block_on(prepare_source_manifest(&setup_cx, &root, &config))
            .expect("source manifest prepares from disk");
        let cx = cancelled_test_cx();
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut driver_called = false;

        let err = block_on(send_prepared_source_over_established_native_connection(
            &cx,
            &mut native_client,
            peer,
            &prepared,
            &config,
            "sender-peer",
            |_point, _conn| {
                driver_called = true;
                Ok(())
            },
        ))
        .expect_err("cancelled sender must fail closed");

        assert!(matches!(err, QuicTransportError::Cancelled));
        assert!(!driver_called, "cancelled sender must not drive peer I/O");
    }

    #[test]
    fn native_established_sender_body_returns_report_after_receiver_proof() {
        let (cx, client, server) = established_pair();
        let mut native_client = client.inner().clone();
        let mut native_server = server.inner().clone();
        let config = QuicConfig {
            chunk_size: 17,
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.25,
            ..trusted_quic_config()
        };
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("payload");
        std::fs::create_dir_all(root.join("nested")).expect("create nested dir");
        let alpha = varied_bytes(384, 67);
        let beta = varied_bytes(640, 71);
        std::fs::write(root.join("alpha.bin"), &alpha).expect("write alpha");
        std::fs::write(root.join("nested/beta.bin"), &beta).expect("write beta");
        let prepared = block_on(prepare_source_manifest(&cx, &root, &config))
            .expect("source manifest prepares from disk");
        let transfer_config = prepared.effective_config(&config);
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let mut client_packet_number = 0u64;
        let mut server_packet_number = 0u64;
        let mut receiver_control: Option<NativeQuicFrameTransport> = None;
        let mut receiver_manifest: Option<TransferManifest> = None;
        let mut receiver_decoders: Option<Vec<QuicEntryDecoder>> = None;
        let receiver_aggregator = primary_quic_receive_aggregator("native-test-peer");
        let mut symbols_accepted = 0u64;
        let mut feedback_rounds = 0u32;
        let mut decode_stats = QuicDecodeStats::default();
        let mut proof_sent = false;

        let report = block_on(send_prepared_source_over_established_native_connection(
            &cx,
            &mut native_client,
            peer,
            &prepared,
            &transfer_config,
            "sender-peer",
            |point, sender_conn| {
                match point {
                    NativeSenderDrivePoint::HelloSent => {
                        let moved = pump_native_until_idle(
                            &cx,
                            sender_conn,
                            &mut native_server,
                            &mut client_packet_number,
                            DEFAULT_MAX_PACKET_BYTES,
                            6_300,
                        )?;
                        assert!(moved > 0);
                        let control = receiver_control.get_or_insert_with(|| {
                            NativeQuicFrameTransport::for_stream(first_client_bidi_stream())
                        });
                        receive_native_sender_hello_and_ack(
                            &cx,
                            &mut native_server,
                            control,
                            &transfer_config,
                            "receiver-peer",
                            false,
                        )?;
                        let moved = pump_native_until_idle(
                            &cx,
                            &mut native_server,
                            sender_conn,
                            &mut server_packet_number,
                            DEFAULT_MAX_PACKET_BYTES,
                            6_301,
                        )?;
                        assert!(moved > 0);
                    }
                    NativeSenderDrivePoint::ObjectCompleteSent => {
                        let moved = pump_native_until_idle(
                            &cx,
                            sender_conn,
                            &mut native_server,
                            &mut client_packet_number,
                            DEFAULT_MAX_PACKET_BYTES,
                            6_302 + u64::from(feedback_rounds),
                        )?;
                        assert!(moved > 0);
                        let control = receiver_control
                            .as_mut()
                            .expect("receiver control opened after hello");
                        if receiver_manifest.is_none() {
                            let manifest =
                                receive_native_manifest(&cx, &mut native_server, control)?;
                            assert_eq!(manifest, prepared.manifest);
                            receiver_decoders =
                                Some(decoders_from_manifest(&manifest, &transfer_config)?);
                            receiver_manifest = Some(manifest);
                        }
                        let manifest = receiver_manifest
                            .as_ref()
                            .expect("receiver manifest initialized");
                        let decoders = receiver_decoders
                            .as_mut()
                            .expect("receiver decoders initialized");
                        match block_on(receive_native_symbol_round(
                            &cx,
                            &mut native_server,
                            control,
                            manifest,
                            decoders,
                            &transfer_config,
                            &receiver_aggregator,
                            &mut symbols_accepted,
                            &mut feedback_rounds,
                            &mut decode_stats,
                        ))? {
                            Some(_) => {
                                let moved = pump_native_until_idle(
                                    &cx,
                                    &mut native_server,
                                    sender_conn,
                                    &mut server_packet_number,
                                    DEFAULT_MAX_PACKET_BYTES,
                                    6_400 + u64::from(feedback_rounds),
                                )?;
                                assert!(moved > 0);
                            }
                            None => {
                                assert!(!proof_sent, "proof should be sent exactly once");
                                let receipt = verify_in_memory_receipt(manifest, decoders);
                                assert!(receipt.committed);
                                assert!(receipt.sha_ok);
                                assert!(receipt.merkle_ok);
                                send_native_proof(&cx, &mut native_server, control, &receipt)?;
                                let moved = pump_native_until_idle(
                                    &cx,
                                    &mut native_server,
                                    sender_conn,
                                    &mut server_packet_number,
                                    DEFAULT_MAX_PACKET_BYTES,
                                    6_500,
                                )?;
                                assert!(moved > 0);
                                proof_sent = true;
                            }
                        }
                    }
                }
                Ok(())
            },
        ))
        .expect("native established sender reaches proof");

        assert_eq!(report.transfer_id, prepared.manifest.transfer_id);
        assert_eq!(report.bytes_sent, 1_024);
        assert_eq!(report.files, 2);
        assert_eq!(report.peer, peer);
        assert!(report.receipt.committed);
        assert_eq!(report.receipt.bytes_received, 1_024);
        assert!(symbols_accepted > 0);

        let moved = pump_native_until_idle(
            &cx,
            &mut native_client,
            &mut native_server,
            &mut client_packet_number,
            DEFAULT_MAX_PACKET_BYTES,
            6_600,
        )
        .expect("deliver sender close");
        assert!(moved > 0);
        let close = next_native_control_frame(
            &cx,
            &mut native_server,
            receiver_control.as_mut().expect("receiver control"),
            "receive sender close",
        )
        .expect("receiver sees sender close");
        assert_eq!(close.frame_type(), FrameType::Close);
    }

    #[test]
    fn native_receive_rounds_commit_after_targeted_repair_request() {
        let (cx, mut client, mut server) = established_pair();
        let collector = crate::observability::LogCollector::new(16)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            max_feedback_rounds: 2,
            ..trusted_quic_config()
        };
        let payload_entries = vec![("alpha.bin".to_string(), varied_bytes(384, 47))];
        let manifest = manifest_from_entries("payload", true, &payload_entries);
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        let mut encoders =
            encoders_from_entries(&manifest, &payload_entries, &config).expect("encoders");
        let initial_sent = send_manifest_symbols_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &manifest,
            &mut encoders,
            &config,
        )
        .expect("send source-only round");
        assert_eq!(initial_sent, 3);
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            6_200,
        )
        .expect("deliver initial transfer payload");

        let mut native_server = server.inner().clone();
        let dropped = native_server
            .recv_datagram()
            .expect("drop one source datagram");
        assert!(!dropped.is_empty());
        let mut receiver_control = NativeQuicFrameTransport::for_stream(first_client_bidi_stream());
        receive_native_sender_hello_and_ack(
            &cx,
            &mut native_server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect("native receiver accepts hello");
        let received_manifest =
            receive_native_manifest(&cx, &mut native_server, &mut receiver_control)
                .expect("native receiver decodes manifest");
        assert_eq!(received_manifest, manifest);
        let mut decoders = decoders_from_manifest(&received_manifest, &config).expect("decoders");
        let receiver_aggregator = primary_quic_receive_aggregator("native-test-peer");
        let mut symbols_accepted = 0u64;
        let mut feedback_rounds = 0u32;
        let mut decode_stats = QuicDecodeStats::default();
        let need = match block_on(receive_native_symbol_round(
            &cx,
            &mut native_server,
            &mut receiver_control,
            &received_manifest,
            &mut decoders,
            &config,
            &receiver_aggregator,
            &mut symbols_accepted,
            &mut feedback_rounds,
            &mut decode_stats,
        ))
        .expect("initial native receive round asks for repair")
        {
            Some(need) => need,
            None => panic!("dropped source symbol should require repair"),
        };
        assert_eq!(symbols_accepted, 2);
        assert_eq!(feedback_rounds, 1);
        assert_eq!(need.pending, vec![0]);
        let expected_round_loss = receiver_round_loss_fraction(2, initial_sent);
        let expected_repair_symbols = u32::try_from(quic_targeted_repair_symbols_for_round(
            1,
            expected_round_loss,
            MAX_REPAIR_SYMBOLS_PER_FEEDBACK_ROUND,
            feedback_rounds,
            config.max_block_size / usize::from(config.symbol_size),
        ))
        .unwrap_or(u32::MAX);
        assert_eq!(
            need.repair_blocks,
            vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: expected_repair_symbols,
            }],
            "receiver should loss-compensate the fresh repair deficit"
        );
        assert!(need.source_symbols.is_empty());
        assert_eq!(need.round_symbols_observed, Some(2));
        assert_eq!(need.round_symbols_accepted, Some(2));
        assert_eq!(need.round_loss_fraction, expected_round_loss);
        assert_eq!(need.repair_base_deficit_symbols, Some(1));
        assert_eq!(
            need.repair_loss_compensated_target_symbols,
            Some(u64::from(expected_repair_symbols))
        );
        assert_eq!(need.repair_request_gap_to_target_symbols, Some(0));
        let trace_entries = collector.peek();
        let need_more_trace = trace_entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.receive.need_more")
            .expect("need-more trace emitted before feedback is sent");
        assert_eq!(
            need_more_trace.level(),
            crate::observability::LogLevel::Trace
        );
        assert_eq!(need_more_trace.get_field("round"), Some("1"));
        assert_eq!(need_more_trace.get_field("pending"), Some("1"));
        assert_eq!(need_more_trace.get_field("block_requests"), Some("1"));
        let expected_repair_symbols = need.repair_blocks[0].symbols.to_string();
        assert_eq!(
            need_more_trace.get_field("repair_symbols"),
            Some(expected_repair_symbols.as_str())
        );
        assert_eq!(need_more_trace.get_field("source_requests"), Some("0"));
        assert_eq!(need_more_trace.get_field("symbols_accepted"), Some("2"));
        assert_eq!(need_more_trace.get_field("repair_base_deficit"), Some("1"));
        let expected_target = expected_repair_symbols.to_string();
        assert_eq!(
            need_more_trace.get_field("repair_loss_compensated_target"),
            Some(expected_target.as_str())
        );
        assert_eq!(
            need_more_trace.get_field("repair_request_gap_to_target"),
            Some("0")
        );

        let symbol_auth = config.symbol_auth_context().expect("auth posture");
        let repair_sent = block_on(send_repair_round_and_object_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &received_manifest,
            &mut encoders,
            &need,
            need.feedback_round,
            &config,
            symbol_auth.as_ref(),
        ))
        .expect("sender sends requested repair symbols");
        assert_eq!(repair_sent, u64::from(need.repair_blocks[0].symbols));
        let mut native_client = client.inner().clone();
        let mut client_packet_number = 0u64;
        let moved = pump_native_until_idle(
            &cx,
            &mut native_client,
            &mut native_server,
            &mut client_packet_number,
            DEFAULT_MAX_PACKET_BYTES,
            6_201,
        )
        .expect("deliver repair payload to receiver-owned native connection");
        assert!(moved > 0);

        assert!(matches!(
            block_on(receive_native_symbol_round(
                &cx,
                &mut native_server,
                &mut receiver_control,
                &received_manifest,
                &mut decoders,
                &config,
                &receiver_aggregator,
                &mut symbols_accepted,
                &mut feedback_rounds,
                &mut decode_stats,
            ))
            .expect("repair native receive round converges"),
            None
        ));
        assert_eq!(symbols_accepted, 3);
        assert_eq!(feedback_rounds, 1);

        let temp = canon_tempdir();
        let (receipt, committed_paths) = block_on(commit_decoded_entries(
            &cx,
            temp.path(),
            &received_manifest,
            &decoders,
            symbols_accepted,
            feedback_rounds,
            decode_stats,
            &config,
        ))
        .expect("commit decoded repair result");
        assert!(receipt.committed);
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
        assert_eq!(receipt.bytes_received, 384);
        assert_eq!(committed_paths.len(), 1);
        assert_eq!(
            std::fs::read(temp.path().join("payload/alpha.bin")).expect("read alpha"),
            payload_entries[0].1
        );
    }

    #[test]
    fn receive_connection_exhausts_native_repair_round_budget() {
        let (cx, mut client, mut server) = established_pair();
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            max_feedback_rounds: 1,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(384, 47))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        let mut encoders = encoders_from_entries(&manifest, &entries, &config).expect("encoders");
        send_manifest_symbols_complete(
            &cx,
            &mut client,
            &mut sender_control,
            &manifest,
            &mut encoders,
            &config,
        )
        .expect("send source-only round");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            6_100,
        )
        .expect("deliver initial transfer payload");

        let dropped = server.recv_datagram().expect("drop one source datagram");
        assert!(!dropped.is_empty());
        send_object_complete(&cx, &mut client, &mut sender_control, 0)
            .expect("send empty second round marker");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            6_101,
        )
        .expect("deliver second object-complete marker");

        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer addr");
        let temp = tempfile::tempdir().expect("temp dir");
        let err = block_on(receive_connection(
            &cx,
            server.inner().clone(),
            peer,
            temp.path(),
            config,
            "receiver-peer",
        ))
        .expect_err("receiver should exhaust repair feedback budget");

        assert!(matches!(
            err,
            QuicTransportError::NoConvergence {
                rounds: 1,
                pending: 1,
            }
        ));
    }

    #[test]
    fn quic_receiver_aggregator_deduplicates_symbols_across_paths_before_decoder() {
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 128,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 21))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let cx = Cx::for_testing();
        let trace = TraceBufferHandle::new(4);
        cx.set_trace_buffer(trace.clone());
        let object_id = decoders[0].object_id;
        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, 0),
            entries[0].1.clone(),
            SymbolKind::Source,
        );
        let aggregator = primary_quic_receive_aggregator("quic-path-a");
        let secondary_path = PathId::new(2);
        aggregator.paths().register(TransportPath::new(
            secondary_path,
            "quic-secondary",
            "quic-path-b",
        ));

        let first = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbol.clone()),
            QuicReceiveAggregation::new(&aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, Time::ZERO)
                .with_trace(&cx),
        )
        .expect("first path symbol reaches decoder");
        let duplicate = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbol),
            QuicReceiveAggregation::new(&aggregator, secondary_path, Time::ZERO).with_trace(&cx),
        )
        .expect("duplicate path symbol is handled");

        assert_eq!(first, 1, "first path delivers one symbol");
        assert_eq!(duplicate, 0, "duplicate path is suppressed pre-decoder");
        let aggregate_traces = trace
            .snapshot()
            .iter()
            .filter(|event| {
                matches!(
                    &event.data,
                    TraceData::Message(message)
                        if message == "atp_quic.receive.aggregate_symbol"
                )
            })
            .count();
        assert_eq!(
            aggregate_traces, 2,
            "accepted and duplicate path decisions should be traced"
        );
        let stats = aggregator.stats();
        assert_eq!(stats.total_processed, 2);
        assert_eq!(stats.dedup.unique_symbols, 1);
        assert_eq!(stats.dedup.duplicates_detected, 1);
        assert_eq!(stats.paths.total_received, 2);
        assert_eq!(stats.paths.total_duplicates, 1);

        assemble_completed_entries(&mut decoders);
        assert!(
            decoders[0].complete,
            "unique symbol should decode the object"
        );
        assert_eq!(decoders[0].data, entries[0].1);
        let receipt = verify_in_memory_receipt(&manifest, &decoders);
        assert!(receipt.committed);
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
    }

    #[test]
    fn quic_receiver_aggregator_releases_reordered_symbols_before_decoder() {
        let config = QuicConfig {
            symbol_size: 64,
            max_block_size: 192,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(192, 33))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut decoders = decoders_from_manifest(&manifest, &config).expect("decoders");
        let object_id = decoders[0].object_id;
        let symbols = entries[0]
            .1
            .chunks_exact(usize::from(config.symbol_size))
            .enumerate()
            .map(|(esi, payload)| {
                Symbol::new(
                    SymbolId::new(object_id, 0, u32::try_from(esi).expect("esi fits")),
                    payload.to_vec(),
                    SymbolKind::Source,
                )
            })
            .collect::<Vec<_>>();
        let aggregator = MultipathAggregator::new(AggregatorConfig {
            reorder: ReordererConfig {
                immediate_delivery: false,
                max_buffer_per_object: 4,
                max_sequence_gap: 4,
                ..ReordererConfig::default()
            },
            ..AggregatorConfig::default()
        });
        let secondary_path = PathId::new(2);
        aggregator.paths().register(TransportPath::new(
            QUIC_PRIMARY_RECEIVE_PATH_ID,
            "quic-primary",
            "quic-path-a",
        ));
        aggregator.paths().register(TransportPath::new(
            secondary_path,
            "quic-secondary",
            "quic-path-b",
        ));

        let seq0 = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbols[0].clone()),
            QuicReceiveAggregation::new(&aggregator, QUIC_PRIMARY_RECEIVE_PATH_ID, Time::ZERO),
        )
        .expect("first source symbol reaches decoder");
        let seq2 = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbols[2].clone()),
            QuicReceiveAggregation::new(&aggregator, secondary_path, Time::from_millis(1)),
        )
        .expect("out-of-order source symbol is buffered");
        let seq1 = feed_aggregated_symbol_for_entry(
            &mut decoders,
            0,
            AuthenticatedSymbol::new_unauthenticated(symbols[1].clone()),
            QuicReceiveAggregation::new(
                &aggregator,
                QUIC_PRIMARY_RECEIVE_PATH_ID,
                Time::from_millis(2),
            ),
        )
        .expect("gap-fill source symbol releases buffered symbol");

        assert_eq!(seq0, 1, "in-order symbol reaches decoder immediately");
        assert_eq!(seq2, 0, "gap symbol is held by the reorder window");
        assert_eq!(seq1, 2, "gap fill releases itself and buffered seq2");
        let stats = aggregator.stats();
        assert_eq!(stats.paths.total_received, 3);
        assert_eq!(stats.reorder.symbols_buffered, 0);
        assert_eq!(stats.reorder.in_order_deliveries, 2);
        assert_eq!(stats.reorder.reordered_deliveries, 1);

        assemble_completed_entries(&mut decoders);
        assert!(
            decoders[0].complete,
            "reordered source symbols should decode the object"
        );
        assert_eq!(decoders[0].data, entries[0].1);
        let receipt = verify_in_memory_receipt(&manifest, &decoders);
        assert!(receipt.committed);
        assert!(receipt.sha_ok);
        assert!(receipt.merkle_ok);
    }

    #[test]
    fn quic_receiver_feedback_synthesizes_missing_source_symbol_requests() {
        let config = QuicConfig {
            symbol_size: 128,
            max_block_size: 512,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };
        let entries = vec![("alpha.bin".to_string(), varied_bytes(384, 13))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let decoders = decoders_from_manifest(&manifest, &config).expect("decoders");

        let first_two = source_symbol_requests(&decoders, 2);
        assert_eq!(
            first_two,
            vec![
                QuicSourceSymbolRequest {
                    entry: 0,
                    sbn: 0,
                    esi: 0,
                },
                QuicSourceSymbolRequest {
                    entry: 0,
                    sbn: 0,
                    esi: 1,
                },
            ]
        );

        let all = source_symbol_requests(&decoders, 0);
        assert_eq!(all.len(), 3);
        assert_eq!(
            all[2],
            QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: 2,
            }
        );
    }

    #[test]
    fn quic_sender_rejects_oversized_source_symbol_feedback() {
        let config = trusted_quic_config();
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 21))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let mut source_symbols =
            Vec::with_capacity(MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND + 1);
        for esi in 0..=MAX_SOURCE_SYMBOL_REQUESTS_PER_FEEDBACK_ROUND {
            source_symbols.push(QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: u32::try_from(esi).unwrap_or(u32::MAX),
            });
        }
        let need = QuicNeedMore {
            pending: vec![0],
            repair_blocks: Vec::new(),
            source_symbols,
            ..QuicNeedMore::default()
        };

        let err = validate_need_more_feedback(&manifest, &config, &need)
            .expect_err("oversized peer feedback should fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message)
                if message.contains("source symbols") && message.contains("max")
        ));
    }

    #[test]
    fn quic_sender_validates_targeted_repair_feedback() {
        let config = trusted_quic_config();
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 23))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let repair = QuicBlockRepairRequest {
            entry: 0,
            sbn: 0,
            symbols: 3,
        };
        let valid = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![repair],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let pending =
            validate_need_more_feedback(&manifest, &config, &valid).expect("valid repair request");
        assert!(pending.contains(&0));

        let mixed = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![repair],
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: 0,
            }],
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &mixed)
            .expect_err("mixed source and repair feedback must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message)
                if message.contains("both fresh repair blocks")
        ));

        let zero = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                symbols: 0,
                ..repair
            }],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &zero)
            .expect_err("zero-symbol repair request must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message) if message.contains("zero repair symbols")
        ));

        let invalid_block = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest { sbn: 1, ..repair }],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &invalid_block)
            .expect_err("out-of-range repair block request must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message) if message.contains("repair block 1 outside")
        ));

        let duplicate = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![repair, repair],
            source_symbols: Vec::new(),
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &duplicate)
            .expect_err("duplicate repair block request must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message) if message.contains("duplicate repair block")
        ));
    }

    #[test]
    fn quic_sender_rejects_duplicate_source_symbol_feedback() {
        let config = trusted_quic_config();
        let entries = vec![("alpha.bin".to_string(), varied_bytes(128, 22))];
        let manifest = manifest_from_entries("payload", true, &entries);
        let duplicate = QuicSourceSymbolRequest {
            entry: 0,
            sbn: 0,
            esi: 0,
        };
        let need = QuicNeedMore {
            pending: vec![0],
            repair_blocks: Vec::new(),
            source_symbols: vec![duplicate, duplicate],
            ..QuicNeedMore::default()
        };

        let err = validate_need_more_feedback(&manifest, &config, &need)
            .expect_err("duplicate peer feedback should fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message)
                if message.contains("duplicate source symbol")
        ));

        let invalid_esi = QuicNeedMore {
            pending: vec![0],
            repair_blocks: Vec::new(),
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 0,
                sbn: 0,
                esi: 1,
            }],
            ..QuicNeedMore::default()
        };
        let err = validate_need_more_feedback(&manifest, &config, &invalid_esi)
            .expect_err("out-of-range source ESI request must fail closed");
        assert!(matches!(
            err,
            QuicTransportError::Integrity(message) if message.contains("source request esi 1 outside")
        ));
    }

    #[test]
    fn quic_source_symbol_request_rebuilds_exact_source_payload() {
        let config = QuicConfig {
            symbol_size: 512,
            max_block_size: 1024,
            ..trusted_quic_config()
        };
        let bytes: Vec<u8> = (0..1500).map(|i| (i % 251) as u8).collect();
        let enc = QuicEntryEncoder::memory(
            7,
            entry_object_id("source-request", 7),
            bytes.clone(),
            &config,
        );

        let first_block_tail = source_symbol_for_request(
            &enc,
            QuicSourceSymbolRequest {
                entry: 7,
                sbn: 0,
                esi: 1,
            },
            &config,
        )
        .expect("source symbol");
        assert!(first_block_tail.kind().is_source());
        assert_eq!(first_block_tail.sbn(), 0);
        assert_eq!(first_block_tail.esi(), 1);
        assert_eq!(first_block_tail.data(), &bytes[512..1024]);

        let final_block = source_symbol_for_request(
            &enc,
            QuicSourceSymbolRequest {
                entry: 7,
                sbn: 1,
                esi: 0,
            },
            &config,
        )
        .expect("final source symbol");
        assert_eq!(&final_block.data()[..476], &bytes[1024..]);
        assert!(final_block.data()[476..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn quic_control_handshake_accepts_matching_sender() {
        let (cx, mut client, mut server) = established_pair();
        let config = trusted_quic_config();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        send_sender_hello(
            &cx,
            &mut client,
            &mut sender_control,
            &config,
            "sender-peer",
            false,
        )
        .expect("send hello");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            3_000,
        )
        .expect("deliver hello");

        let hello = receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect("receiver accepts hello");
        assert_eq!(hello.protocol, ATP_QUIC_PROTOCOL);
        assert_eq!(hello.peer_id, "sender-peer");
        assert_eq!(hello.symbol_size, DEFAULT_SYMBOL_SIZE);
        assert_eq!(
            hello.max_block_size,
            u64::try_from(DEFAULT_MAX_BLOCK_SIZE).unwrap_or(u64::MAX)
        );

        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            3_001,
        )
        .expect("deliver ack");
        let ack = receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect("sender receives accepted ack");
        assert!(ack.accepted);
        assert_eq!(ack.peer_id, "receiver-peer");
        assert!(ack.reason.is_none());
    }

    #[test]
    fn quic_control_handshake_accepts_clean_source_stream_id() {
        let config = trusted_quic_config();
        let source_stream = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 1);
        let hello = sender_hello_with_source_stream(
            "sender-peer",
            &config,
            false,
            Some(source_stream),
            9,
            None,
        );

        assert_eq!(
            source_stream_from_hello(&hello).expect("valid source stream"),
            Some(source_stream)
        );
        assert!(
            reject_hello_reason(&hello, &config, false).is_none(),
            "client-initiated source stream must be accepted when the rest of the hello matches"
        );
    }

    #[test]
    fn quic_control_handshake_rejects_invalid_source_stream_ids() {
        let config = trusted_quic_config();
        let mut hello = sender_hello_with_source_stream(
            "sender-peer",
            &config,
            false,
            Some(StreamId::local(
                StreamRole::Client,
                StreamDirection::Bidirectional,
                1,
            )),
            9,
            None,
        );

        hello.source_stream = true;
        hello.source_stream_id = None;
        assert!(matches!(
            source_stream_from_hello(&hello),
            Err(QuicTransportError::HandshakeRejected(reason))
                if reason.contains("source_stream_id")
        ));

        hello.source_stream = false;
        hello.source_stream_id =
            Some(StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 1).0);
        assert!(matches!(
            source_stream_from_hello(&hello),
            Err(QuicTransportError::HandshakeRejected(reason))
                if reason.contains("source_stream=false")
        ));

        hello.source_stream = true;
        hello.source_stream_id = Some(first_client_bidi_stream().0);
        assert!(matches!(
            source_stream_from_hello(&hello),
            Err(QuicTransportError::HandshakeRejected(reason))
                if reason.contains("control stream")
        ));

        hello.source_stream_id =
            Some(StreamId::local(StreamRole::Server, StreamDirection::Bidirectional, 0).0);
        assert!(matches!(
            source_stream_from_hello(&hello),
            Err(QuicTransportError::HandshakeRejected(reason))
                if reason.contains("client-initiated")
        ));

        hello.source_stream_id =
            Some(StreamId::local(StreamRole::Client, StreamDirection::Unidirectional, 0).0);
        assert!(matches!(
            source_stream_from_hello(&hello),
            Err(QuicTransportError::HandshakeRejected(reason))
                if reason.contains("bidirectional")
        ));
    }

    #[test]
    fn quic_control_handshake_rejects_wrong_protocol_and_reports_reason() {
        let (cx, mut client, mut server) = established_pair();
        let config = trusted_quic_config();
        let mut sender_control =
            QuicFrameTransport::open(&cx, &mut client).expect("open control stream");
        let mut receiver_control = QuicFrameTransport::for_stream(sender_control.stream());

        let bad_hello = QuicHello {
            protocol: ATP_QUIC_PROTOCOL + 99,
            role: "sender".to_string(),
            peer_id: "sender-peer".to_string(),
            symbol_size: config.symbol_size,
            max_block_size: u64::try_from(config.max_block_size).unwrap_or(u64::MAX),
            symbol_auth: false,
            source_stream: false,
            source_stream_id: None,
            total_bytes: 0,
            delta_transfer_nonce: None,
        };
        let frame = json_frame(FrameType::Handshake, &bad_hello).expect("bad hello frame");
        sender_control
            .send(&cx, &mut client, &frame)
            .expect("send bad hello");
        pump_until_idle(
            &cx,
            &mut client,
            &mut server,
            DEFAULT_MAX_PACKET_BYTES,
            4_000,
        )
        .expect("deliver bad hello");

        let err = receive_sender_hello_and_ack(
            &cx,
            &mut server,
            &mut receiver_control,
            &config,
            "receiver-peer",
            false,
        )
        .expect_err("receiver rejects wrong protocol");
        assert!(matches!(
            err,
            QuicTransportError::HandshakeRejected(reason)
                if reason.contains("unsupported protocol")
        ));

        pump_until_idle(
            &cx,
            &mut server,
            &mut client,
            DEFAULT_MAX_PACKET_BYTES,
            4_001,
        )
        .expect("deliver rejected ack");
        let err = receive_sender_hello_ack(&cx, &mut client, &mut sender_control)
            .expect_err("sender sees rejected ack");
        assert!(matches!(
            err,
            QuicTransportError::HandshakeRejected(reason)
                if reason.contains("unsupported protocol")
        ));
    }

    #[test]
    fn quic_control_handshake_rejects_encoding_layout_mismatch() {
        let config = trusted_quic_config();
        let mut bad_hello = QuicHello {
            protocol: ATP_QUIC_PROTOCOL,
            role: "sender".to_string(),
            peer_id: "sender-peer".to_string(),
            symbol_size: config.symbol_size.saturating_div(2).max(1),
            max_block_size: u64::try_from(config.max_block_size).unwrap_or(u64::MAX),
            symbol_auth: false,
            source_stream: false,
            source_stream_id: None,
            total_bytes: 0,
            delta_transfer_nonce: None,
        };

        let reason = reject_hello_reason(&bad_hello, &config, false)
            .expect("symbol size mismatch must reject at handshake");
        assert!(
            reason.contains("symbol_size") && reason.contains(&config.symbol_size.to_string()),
            "{reason}"
        );

        bad_hello.symbol_size = config.symbol_size;
        bad_hello.max_block_size = u64::try_from(config.max_block_size / 2).unwrap_or(1).max(1);
        let reason = reject_hello_reason(&bad_hello, &config, false)
            .expect("non-aligned / below-floor sender block size must reject at handshake");
        // Post-E802 (br-asupersync-j73ili) the receiver bounded-accepts the sender's block size
        // instead of demanding equality; config.max_block_size/2 is both non-symbol-aligned and
        // below the receiver floor, so it is rejected with the new semantics.
        assert!(
            reason.contains("max_block_size")
                && (reason.contains("not a multiple of symbol_size")
                    || reason.contains("below the receiver floor")),
            "{reason}"
        );
    }

    #[test]
    fn quic_control_handshake_adopts_sender_scaled_block_size() {
        let config = trusted_quic_config();
        // A sender transferring a large entry scales its block size UP to keep the per-object
        // source-block count bounded; the receiver must adopt that (symbol-aligned, within cap)
        // rather than reject it (ASUP-E802 / br-asupersync-j73ili).
        let scaled = effective_quic_max_block_size_for_largest_entry(&config, 512 * 1024 * 1024)
            .expect("large-entry scaled block size");
        assert!(
            scaled > config.max_block_size,
            "a large entry must scale the block size above the configured default"
        );
        let mut hello = QuicHello {
            protocol: ATP_QUIC_PROTOCOL,
            role: "sender".to_string(),
            peer_id: "sender-peer".to_string(),
            symbol_size: config.symbol_size,
            max_block_size: u64::try_from(scaled).unwrap_or(u64::MAX),
            symbol_auth: false,
            source_stream: false,
            source_stream_id: None,
            total_bytes: 512 * 1024 * 1024,
            delta_transfer_nonce: None,
        };
        assert!(
            reject_hello_reason(&hello, &config, false).is_none(),
            "receiver must adopt a symbol-aligned sender-scaled block size within cap"
        );

        // Over the memory-bounding cap → rejected (bounded, no unbounded decode buffers).
        let over = quic_symbol_aligned_block_size(&config, MAX_QUIC_ADOPTED_BLOCK_SIZE + 1)
            .expect("aligned over-cap value");
        hello.max_block_size = u64::try_from(over).unwrap_or(u64::MAX);
        let reason = reject_hello_reason(&hello, &config, false)
            .expect("over-cap sender block size must reject");
        assert!(
            reason.contains("exceeds the maximum adopted block size"),
            "{reason}"
        );

        // Non-symbol-aligned → rejected.
        hello.max_block_size = u64::try_from(config.max_block_size).unwrap_or(u64::MAX) + 1;
        let reason = reject_hello_reason(&hello, &config, false)
            .expect("non-aligned sender block size must reject");
        assert!(reason.contains("not a multiple of symbol_size"), "{reason}");
    }

    #[test]
    fn parse_json_rejects_wrong_payload_shape() {
        let frame = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectRequest,
            b"not-json".to_vec(),
        )
        .expect("malformed json frame");

        assert!(matches!(
            parse_json::<QuicNeedMore>(&frame),
            Err(QuicTransportError::Control(message)) if !message.is_empty()
        ));
    }

    #[test]
    fn quic_entry_object_id_and_transfer_tag_are_deterministic() {
        let first_object = entry_object_id("transfer-1", 0);
        assert_eq!(first_object, entry_object_id("transfer-1", 0));
        assert_ne!(first_object, entry_object_id("transfer-1", 1));
        assert_ne!(first_object, entry_object_id("transfer-2", 0));

        let first_tag = transfer_tag("transfer-1");
        assert_eq!(first_tag, transfer_tag("transfer-1"));
        assert_ne!(first_tag, transfer_tag("transfer-2"));
        assert_ne!(first_tag, 0);
    }

    #[test]
    fn timeout_error_names_operation_and_duration() {
        let e = QuicTransportError::Timeout {
            operation: "receive frame",
            timeout: Duration::from_secs(60),
        };
        let rendered = e.to_string();
        assert!(rendered.contains("receive frame"));
        assert!(rendered.contains("60s"));
    }

    #[test]
    fn too_large_error_names_sizes() {
        let e = QuicTransportError::TooLarge { size: 99, max: 10 };
        let rendered = e.to_string();
        assert!(rendered.contains("99"));
        assert!(rendered.contains("10"));
    }

    #[test]
    fn streaming_error_maps_to_source() {
        let e: QuicTransportError = StreamingError::new("boom".to_string()).into();
        assert!(matches!(e, QuicTransportError::Source(m) if m.contains("boom")));
    }

    #[test]
    fn send_path_rejects_missing_source_before_connect() {
        let cx = Cx::for_testing();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = block_on(send_path(
            &cx,
            addr,
            Path::new("/nonexistent/source"),
            trusted_quic_config(),
            "sender",
        ));
        assert!(matches!(result, Err(QuicTransportError::Source(_))));
    }

    #[test]
    fn send_path_valid_source_fails_closed_without_client_tls() {
        // A valid source preflights fine, but a real QUIC connection cannot be
        // opened without client TLS trust (server name + roots) — or, on a build
        // without the `tls` feature, without any native handshake at all. Either
        // way send_path must fail closed with a typed Config error rather than
        // fabricate a transfer.
        let cx = Cx::for_testing();
        let temp = tempfile::tempdir().expect("temp dir");
        let source = temp.path().join("payload.bin");
        std::fs::write(&source, b"payload").expect("write source");
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = block_on(send_path(
            &cx,
            addr,
            &source,
            trusted_quic_config(),
            "sender",
        ));
        assert!(
            matches!(result, Err(QuicTransportError::Config(_))),
            "expected a fail-closed Config error, got {result:?}"
        );
    }

    #[test]
    fn send_path_valid_source_traces_initial_fanout_dispatch_before_client_tls() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(16)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_diagnostic_context(crate::observability::DiagnosticContext::new());
        cx.set_log_collector(collector.clone());
        let temp = tempfile::tempdir().expect("temp dir");
        let source = temp.path().join("payload.bin");
        std::fs::write(&source, varied_bytes(768, 31)).expect("write source");
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let config = QuicConfig {
            datagram_fanout: 3,
            max_active_connections: 3,
            symbol_size: 128,
            max_datagram_size: 192,
            max_block_size: 256,
            repair_overhead: 1.0,
            ..trusted_quic_config()
        };

        let result = block_on(send_path(&cx, addr, &source, config, "sender"));

        assert!(
            matches!(result, Err(QuicTransportError::Config(_))),
            "valid-source send_path should still fail closed without client TLS, got {result:?}"
        );
        let dispatch_entries = collector
            .peek()
            .into_iter()
            .filter(|entry| entry.message() == "atp_quic.spray.fanout_dispatch")
            .collect::<Vec<_>>();
        assert_eq!(dispatch_entries.len(), 3);
        assert_eq!(
            dispatch_entries
                .iter()
                .map(|entry| entry.get_field("symbols"))
                .collect::<Vec<_>>(),
            vec![Some("2"), Some("2"), Some("2")],
            "round-0 preflight should keep all three configured QUIC fan-out lanes fed"
        );
        assert!(
            dispatch_entries
                .iter()
                .all(|entry| entry.get_field("total_symbols") == Some("6"))
        );
    }

    #[test]
    fn send_path_rejects_invalid_config_before_not_implemented() {
        let cx = Cx::for_testing();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let cfg = QuicConfig {
            idle_timeout: Duration::ZERO,
            ..trusted_quic_config()
        };
        let result = block_on(send_path(&cx, addr, Path::new("/x"), cfg, "sender"));
        assert!(matches!(result, Err(QuicTransportError::Config(_))));
    }

    #[test]
    fn receive_connection_rejects_missing_control_stream_without_scaffold_success() {
        use crate::net::quic_native::NativeQuicConnectionConfig;
        let cx = Cx::for_testing();
        let conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = block_on(receive_connection(
            &cx,
            conn,
            peer,
            Path::new("/tmp"),
            trusted_quic_config(),
            "receiver",
        ));
        match result {
            Ok(report) => panic!("missing control stream must not fake success: {report:?}"),
            Err(QuicTransportError::NotImplemented {
                operation: "receive_connection",
                ..
            }) => panic!("receive_connection should be wired past the B1 scaffold"),
            Err(_) => {}
        }
    }

    #[test]
    fn quic_receiver_rejects_unsafe_manifest_root_names() {
        let dest = Path::new("dest");
        assert_eq!(
            quic_safe_base_for_root_name(dest, "payload").expect("safe root"),
            dest.join("payload")
        );

        for root_name in [
            ".",
            "..",
            "../payload",
            "nested/payload",
            "/tmp/payload",
            "payload\\evil",
            "C:payload",
            "NUL.txt",
            "trailing.",
            "trailing ",
        ] {
            match quic_safe_base_for_root_name(dest, root_name) {
                Err(QuicTransportError::Source(message)) => {
                    assert!(
                        message.contains("root_name"),
                        "source error should name root_name for {root_name:?}: {message}"
                    );
                }
                other => panic!("unsafe root_name {root_name:?} must fail closed, got {other:?}"),
            }
        }
    }

    #[test]
    fn quic_receiver_rejects_unsafe_manifest_relative_paths() {
        let base = Path::new("base");
        assert_eq!(
            quic_join_relative(base, "nested/file.bin").expect("safe relative path"),
            base.join("nested").join("file.bin")
        );

        for rel_path in [
            "",
            ".",
            "../file.bin",
            "/abs/file.bin",
            "nested/../file.bin",
            "nested/./file.bin",
            "nested//file.bin",
            "nested\\file.bin",
            "C:file.bin",
            "nested/NUL.txt",
            "nested/trailing.",
            "nested/trailing ",
        ] {
            match quic_join_relative(base, rel_path) {
                Err(QuicTransportError::Source(message)) => {
                    assert!(
                        message.contains("unsafe path"),
                        "source error should name unsafe path for {rel_path:?}: {message}"
                    );
                }
                other => panic!("unsafe rel_path {rel_path:?} must fail closed, got {other:?}"),
            }
        }
    }

    #[test]
    fn quic_manifest_rejects_case_colliding_windows_paths() {
        let manifest = quic_manifest_with_metadata(vec![
            quic_empty_regular_entry(0, "Docs/Readme.txt"),
            quic_empty_regular_entry(1, "docs/README.TXT"),
        ]);
        assert!(matches!(
            validate_quic_manifest(&manifest, &trusted_quic_config()),
            Err(QuicTransportError::Source(message)) if message.contains("case collision")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn quic_fifo_commit_applies_selected_metadata_without_skip() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt as _, PermissionsExt};

        let cx = Cx::for_testing();
        let trace = TraceBufferHandle::new(8);
        cx.set_trace_buffer(trace.clone());
        let dest = tempfile::tempdir().expect("destination temp dir");
        let out_path = dest.path().join("payload/named-pipe");

        let entries = vec![("named-pipe".to_string(), Vec::new())];
        let mut manifest = manifest_from_entries("payload", true, &entries);
        manifest.entries[0].metadata = Some(EntryMetadata {
            file_kind: FileKind::Fifo,
            unix_mode: Some(0o640),
            mtime_unix_secs: Some(1),
            mtime_nanos: Some(123_456_789),
            ..EntryMetadata::default()
        });
        manifest.metadata_root_hex = manifest_metadata_commitment(&manifest);
        let decoders = vec![QuicEntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size: 0,
            pipeline: None,
            complete: true,
            data: Vec::new(),
            pending_decodes: Vec::new(),
        }];
        let config = QuicConfig {
            allow_special_files: true,
            ..trusted_quic_config()
        };

        let (receipt, committed_paths) = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &config,
        ))
        .expect("FIFO metadata commit succeeds");

        assert!(receipt.committed);
        assert_eq!(committed_paths, vec![out_path.clone()]);
        let metadata = std::fs::symlink_metadata(&out_path).expect("FIFO metadata");
        assert!(metadata.file_type().is_fifo());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
        assert_eq!((metadata.mtime(), metadata.mtime_nsec()), (1, 123_456_789));
        assert!(trace.snapshot().iter().all(|event| {
            !matches!(
                &event.data,
                TraceData::Message(message) if message == "atp_quic_metadata_skipped"
            )
        }));
    }

    #[cfg(windows)]
    #[test]
    fn quic_unsupported_fifo_never_deletes_existing_windows_file() {
        let cx = Cx::for_testing();
        let dest = tempfile::tempdir().expect("destination temp dir");
        let out_path = dest.path().join("payload/named-pipe");
        std::fs::create_dir_all(out_path.parent().expect("output parent"))
            .expect("create destination parent");
        std::fs::write(&out_path, b"must-survive").expect("write existing destination");

        let entries = vec![("named-pipe".to_string(), Vec::new())];
        let mut manifest = manifest_from_entries("payload", true, &entries);
        manifest.entries[0].metadata = Some(EntryMetadata {
            file_kind: FileKind::Fifo,
            ..EntryMetadata::default()
        });
        manifest.metadata_root_hex = manifest_metadata_commitment(&manifest);
        let decoders = vec![QuicEntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size: 0,
            pipeline: None,
            complete: true,
            data: Vec::new(),
            pending_decodes: Vec::new(),
        }];
        let config = QuicConfig {
            allow_special_files: true,
            ..trusted_quic_config()
        };

        let (receipt, committed_paths) = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &config,
        ))
        .expect("unsupported FIFO is skipped without mutation");
        assert!(receipt.committed);
        assert!(committed_paths.is_empty());
        assert_eq!(
            std::fs::read(&out_path).expect("read preserved destination"),
            b"must-survive"
        );
    }

    #[cfg(unix)]
    #[test]
    fn quic_commit_rejects_existing_destination_symlink_prefix() {
        let cx = Cx::for_testing();
        let dest = tempfile::tempdir().expect("dest dir");
        let outside = tempfile::tempdir().expect("outside dir");
        let base = dest.path().join("payload");
        std::fs::create_dir_all(&base).expect("create destination base");
        std::os::unix::fs::symlink(outside.path(), base.join("link"))
            .expect("create pre-existing destination symlink");

        let bytes = b"must stay inside destination".to_vec();
        let entries = vec![("link/payload.txt".to_string(), bytes.clone())];
        let manifest = manifest_from_entries("payload", true, &entries);
        let decoders = vec![QuicEntryDecoder {
            index: 0,
            object_id: entry_object_id(&manifest.transfer_id, 0),
            size: u64::try_from(bytes.len()).expect("bytes length fits u64"),
            pipeline: None,
            complete: true,
            data: bytes,
            pending_decodes: Vec::new(),
        }];

        let err = block_on(commit_decoded_entries(
            &cx,
            dest.path(),
            &manifest,
            &decoders,
            0,
            0,
            QuicDecodeStats::default(),
            &trusted_quic_config(),
        ))
        .expect_err("commit must reject pre-existing symlink ancestors");
        assert!(
            matches!(err, QuicTransportError::Source(ref message) if message.contains("existing symlink")),
            "expected existing-symlink source error, got {err:?}"
        );
        assert!(
            !outside.path().join("payload.txt").exists(),
            "commit must not follow a destination symlink outside dest_dir"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn quic_per_write_guard_rejects_replaced_destination_directory_ancestor() {
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
        let error = block_on(reject_quic_destination_symlink_prefix(&base, &out_path))
            .expect_err("outer destination junction must fail closed");
        assert!(matches!(
            error,
            QuicTransportError::Source(message) if message.contains("symlink or reparse point")
        ));
        assert!(!outside.join("payload/file.bin").exists());
    }

    #[test]
    fn reused_manifest_json_roundtrips() {
        let manifest = TransferManifest {
            transfer_id: "abc".to_string(),
            root_name: "data".to_string(),
            is_directory: true,
            total_bytes: 9,
            merkle_root_hex: "00".repeat(32),
            // J1 (b0k8qo.11.1, LilacPine): shared manifest gained an optional
            // metadata commitment + per-entry metadata; portable transfers leave
            // them None. Additive cross-edit to keep HEAD compiling.
            metadata_root_hex: None,
            directory_metadata: None,
            delta_manifest: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a/b.txt".to_string(),
                size: 9,
                sha256_hex: "ff".repeat(32),
                metadata: None,
                members: Vec::new(),
            }],
        };
        let json = serde_json::to_vec(&manifest).unwrap();
        let back: TransferManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn reused_receipt_json_roundtrips() {
        let receipt = ReceiveReceipt {
            committed: true,
            bytes_received: 42,
            files: 1,
            sha_ok: true,
            merkle_ok: true,
            symbols_accepted: 3,
            feedback_rounds: 1,
            decode_count: 1,
            decode_micros: 7,
            reason: None,
            committed_paths: vec!["/dest/a.txt".to_string()],
        };
        let json = serde_json::to_vec(&receipt).unwrap();
        let back: ReceiveReceipt = serde_json::from_slice(&json).unwrap();
        assert_eq!(receipt, back);
    }
}
