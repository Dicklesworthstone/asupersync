    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use asupersync::atp::doctor::build_platform_doctor_document;
    use asupersync::atp::sdk::{StreamEarlyUsabilityState, StreamFinalCommitState};
    use asupersync::atp::stream_object::ConsumptionPolicy;
    use asupersync::observability::{TaskRegionCountWire, TaskStateInfo};
    use asupersync::trace::{TraceMetadata, TraceWriter};
    use clap::Parser;
    use insta::{assert_json_snapshot, assert_snapshot};
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;

    #[derive(Clone, Default)]
    struct SharedWrite {
        inner: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedWrite {
        fn contents(&self) -> String {
            String::from_utf8(self.inner.lock().expect("lock shared write").clone())
                .expect("shared write content should be utf8")
        }
    }

    #[cfg(all(feature = "remote-service", unix))]
    fn valid_remote_probe_file_config() -> RemoteProbeFileConfig {
        RemoteProbeFileConfig {
            schema_version: REMOTE_PROBE_CONFIG_SCHEMA_VERSION,
            protocol: REMOTE_SERVICE_PROTOCOL.to_string(),
            bootstrap_endpoints: vec!["127.0.0.1:7443".to_string(), "127.0.0.1:7444".to_string()],
            server_name: "remote.example.test".to_string(),
            server_ca_bundle: PathBuf::from("server-ca.crt"),
            client_certificate_chain: PathBuf::from("client.crt"),
            client_private_key: PathBuf::from("client.key"),
            server_spki_sha256: vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()],
            origin_node: "origin-a".to_string(),
            max_frame_bytes: 64 * 1024,
            connect_timeout_ms: 1_000,
            tls_handshake_timeout_ms: 2_000,
            attempt_timeout_ms: 5_000,
            completion_timeout_ms: 30_000,
            max_attempts: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
            lease_ms: 30_000,
            full_jitter: false,
            tcp_nodelay: true,
        }
    }

    #[cfg(all(feature = "remote-service", unix))]
    #[test]
    fn remote_probe_config_validation_fails_closed() {
        let path = Path::new("remote-probe.toml");
        let mut config = valid_remote_probe_file_config();
        validate_remote_probe_config(path, &config).expect("baseline probe config should validate");

        config.bootstrap_endpoints.clear();
        let error = validate_remote_probe_config(path, &config)
            .expect_err("empty bootstrap endpoints must fail closed");
        assert!(error.detail.contains("at least one socket address"));

        config = valid_remote_probe_file_config();
        config.bootstrap_endpoints[1] = config.bootstrap_endpoints[0].clone();
        let error = validate_remote_probe_config(path, &config)
            .expect_err("duplicate bootstrap endpoints must fail closed");
        assert!(error.detail.contains("duplicate bootstrap endpoint"));

        config = valid_remote_probe_file_config();
        config.server_spki_sha256 = vec!["not-base64".to_string()];
        let error = validate_remote_probe_config(path, &config)
            .expect_err("invalid server pins must fail closed");
        assert!(error.detail.contains("invalid server SPKI pin"));

        config = valid_remote_probe_file_config();
        config.lease_ms = 0;
        let error = validate_remote_probe_config(path, &config)
            .expect_err("zero probe lease must fail closed");
        assert!(error.detail.contains("lease_ms must be nonzero"));

        config = valid_remote_probe_file_config();
        config.completion_timeout_ms = 0;
        let error = validate_remote_probe_config(path, &config)
            .expect_err("zero completion timeout must fail closed");
        assert!(
            error
                .detail
                .contains("completion_timeout_ms must be nonzero")
        );

        config = valid_remote_probe_file_config();
        config.tls_handshake_timeout_ms = config.attempt_timeout_ms + 1;
        let error = validate_remote_probe_config(path, &config)
            .expect_err("unreachable TLS timeout must fail closed");
        assert!(
            error
                .detail
                .contains("tls_handshake_timeout_ms must not exceed attempt_timeout_ms")
        );

        config = valid_remote_probe_file_config();
        config.initial_backoff_ms = config.max_backoff_ms + 1;
        let error = validate_remote_probe_config(path, &config)
            .expect_err("inverted backoff bounds must fail closed");
        assert!(
            error
                .detail
                .contains("initial_backoff_ms must not exceed max_backoff_ms")
        );
    }

    #[cfg(all(feature = "remote-service", unix))]
    #[test]
    fn remote_probe_config_rejects_unknown_toml_fields() {
        let raw = r#"
schema_version = 1
protocol = "3.0"
bootstrap_endpoints = ["127.0.0.1:7443"]
server_name = "remote.example.test"
server_ca_bundle = "server-ca.crt"
client_certificate_chain = "client.crt"
client_private_key = "client.key"
server_spki_sha256 = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
origin_node = "origin-a"
max_frame_bytes = 65536
connect_timeout_ms = 1000
tls_handshake_timeout_ms = 2000
attempt_timeout_ms = 5000
completion_timeout_ms = 30000
max_attempts = 2
initial_backoff_ms = 10
max_backoff_ms = 100
lease_ms = 30000
full_jitter = false
tcp_nodelay = true
ambient_discovery = true
"#;
        let error = toml::from_str::<RemoteProbeFileConfig>(raw)
            .expect_err("unknown remote probe fields must be rejected");
        assert!(error.to_string().contains("unknown field"));
    }

    impl Write for SharedWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner
                .lock()
                .expect("lock shared write")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn temp_transfer_reference(contents: &[u8]) -> (NamedTempFile, String) {
        let file = NamedTempFile::new().expect("transfer source temp file");
        fs::write(file.path(), contents).expect("write transfer source");
        let reference = file.path().to_string_lossy().into_owned();
        (file, reference)
    }

    fn sample_task_console_snapshot() -> TaskConsoleWireSnapshot {
        let summary = TaskSummaryWire {
            total_tasks: 2,
            created: 0,
            running: 2,
            cancelling: 0,
            completed: 0,
            stuck_count: 0,
            by_region: vec![TaskRegionCountWire {
                region_id: asupersync::RegionId::new_for_test(3, 0),
                task_count: 2,
            }],
        };
        let task_a = TaskDetailsWire {
            id: asupersync::TaskId::new_for_test(1, 0),
            region_id: asupersync::RegionId::new_for_test(3, 0),
            state: TaskStateInfo::Running,
            phase: "Running".to_string(),
            poll_count: 4,
            polls_remaining: 16,
            created_at: Time::from_nanos(10),
            age_nanos: 100,
            time_since_last_poll_nanos: Some(5),
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };
        let task_b = TaskDetailsWire {
            id: asupersync::TaskId::new_for_test(9, 0),
            region_id: asupersync::RegionId::new_for_test(3, 0),
            state: TaskStateInfo::Running,
            phase: "Running".to_string(),
            poll_count: 2,
            polls_remaining: 18,
            created_at: Time::from_nanos(8),
            age_nanos: 120,
            time_since_last_poll_nanos: None,
            wake_pending: true,
            obligations: vec![],
            waiters: vec![],
        };
        TaskConsoleWireSnapshot::new(Time::from_nanos(88), summary, vec![task_b, task_a])
    }

    fn make_sample_trace() -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp file");
        let mut writer = TraceWriter::create(file.path()).expect("create writer");
        let metadata = TraceMetadata::new(42).with_description("cli test");
        writer.write_metadata(&metadata).expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 42 })
            .expect("write event");
        writer
            .write_event(&ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 1_000_000,
            })
            .expect("write event");
        writer.finish().expect("finish");
        file
    }

    fn parse_jsonl_values(payload: &str) -> Vec<serde_json::Value> {
        payload
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("parse jsonl entry"))
            .collect()
    }

    #[test]
    fn trace_info_reports_counts() {
        let file = make_sample_trace();
        let info = trace_info(file.path()).expect("trace info");
        assert_eq!(info.event_count, 2);
        assert_eq!(info.duration_nanos, Some(1_000_000));
    }

    #[test]
    fn trace_events_filtering() {
        let file = make_sample_trace();
        let rows = trace_events(file.path(), 0, None, &["rng".to_string()]).expect("trace events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "RngSeed");
    }

    #[test]
    fn trace_events_filtering_accepts_kebab_case_kind_names() {
        let file = make_sample_trace();
        let rows = trace_events(file.path(), 0, None, &["time-advanced".to_string()])
            .expect("trace events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "TimeAdvanced");
    }

    #[test]
    fn trace_events_filtering_accepts_kebab_case_exact_seed_name() {
        let file = make_sample_trace();
        let rows =
            trace_events(file.path(), 0, None, &["rng-seed".to_string()]).expect("trace events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "RngSeed");
    }

    #[test]
    fn trace_events_zero_limit_returns_no_rows() {
        let file = make_sample_trace();
        let rows = trace_events(file.path(), 0, Some(0), &[]).expect("trace events");
        assert!(rows.is_empty());
    }

    #[test]
    fn trace_verify_valid() {
        let file = make_sample_trace();
        let out = trace_verify(file.path(), false, false, false).expect("trace verify");
        assert!(out.valid);
    }

    #[test]
    fn trace_diff_detects_divergence() {
        let file_a = make_sample_trace();
        let file_b = NamedTempFile::new().expect("create temp file");
        let mut writer = TraceWriter::create(file_b.path()).expect("create writer");
        let metadata = TraceMetadata::new(7);
        writer.write_metadata(&metadata).expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 7 })
            .expect("write event");
        writer.finish().expect("finish");

        let diff = trace_diff(file_a.path(), file_b.path()).expect("trace diff");
        assert!(diff.diverged);
    }

    #[test]
    fn trace_compress_rewrites_trace_as_lz4() {
        let input = make_sample_trace();
        let output_dir = tempfile::tempdir().expect("tempdir");
        let output_path = output_dir.path().join("compressed.trace");

        let summary = trace_compress(input.path(), &output_path, 1).expect("trace compress");
        assert_eq!(summary.source_compression, "none");
        assert_eq!(summary.target_compression, "lz4(level=1)");
        assert_eq!(summary.event_count, 2);

        let reader = TraceReader::open(&output_path).expect("open compressed reader");
        assert!(reader.is_compressed());
        assert_eq!(reader.compression(), CompressionMode::Lz4 { level: 1 });
        let events = reader.load_all().expect("load compressed events");
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], ReplayEvent::RngSeed { seed: 42 }));
    }

    #[test]
    fn trace_compress_rejects_existing_output() {
        let input = make_sample_trace();
        let output = NamedTempFile::new().expect("create temp output");

        let err = trace_compress(input.path(), output.path(), 1).expect_err("existing output");
        assert_eq!(err.error_type, "output_exists");
    }

    #[test]
    fn trace_export_json_array() {
        let file = make_sample_trace();
        let mut buf = Vec::new();
        {
            let mut reader = TraceReader::open(file.path()).expect("open reader");
            write!(buf, "[").expect("write");
            let mut first = true;
            while let Some(event) = reader.read_event().expect("read event") {
                if !first {
                    write!(buf, ",").expect("write");
                }
                first = false;
                serde_json::to_writer(&mut buf, &event).expect("serialize");
            }
            write!(buf, "]").expect("write");
        }
        let parsed: Vec<ReplayEvent> = serde_json::from_slice(&buf).expect("parse json");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn lab_replay_args_parse_extended_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "lab",
            "replay",
            "examples/scenarios/smoke_happy_path.yaml",
            "--seed",
            "77",
            "--artifact-pointer",
            "artifacts/replay/failure-77.json",
            "--artifact-output",
            "artifacts/replay/report.json",
            "--window-start",
            "8",
            "--window-events",
            "12",
            "--json",
        ])
        .expect("parse replay args");

        let Command::Lab(LabArgs {
            command: LabCommand::Replay(args),
        }) = cli.command
        else {
            panic!("expected lab replay command");
        };

        assert_eq!(args.seed, Some(77));
        assert_eq!(
            args.artifact_pointer.as_deref(),
            Some("artifacts/replay/failure-77.json")
        );
        assert_eq!(
            args.artifact_output.as_deref(),
            Some(Path::new("artifacts/replay/report.json"))
        );
        assert_eq!(args.window_start, 8);
        assert_eq!(args.window_events, Some(12));
        assert!(args.json);
    }

    #[test]
    fn atp_replay_args_parse_artifact_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "atp",
            "replay",
            "--trace-file",
            "artifacts/transfer.atp-trace",
            "--manifest",
            "artifacts/manifest",
            "--journal-digest",
            "artifacts/journal.digest",
            "--evidence-ledger",
            "artifacts/evidence-ledger.json",
            "--pathlog",
            "artifacts/pathlog",
            "--quiclog",
            "artifacts/quiclog",
            "--repairlog",
            "artifacts/repairlog",
            "--validate-oracles",
            "--oracle",
            "manifest_integrity",
            "--oracle",
            "journal_consistency",
            "--minimize",
            "--reduction-target",
            "0.8",
        ])
        .expect("parse atp replay args");

        let Command::Atp(AtpArgs {
            command: AtpCommand::Replay(args),
        }) = cli.command
        else {
            panic!("expected atp replay command");
        };

        assert_eq!(
            args.trace_file.as_path(),
            Path::new("artifacts/transfer.atp-trace")
        );
        assert_eq!(args.manifest.as_path(), Path::new("artifacts/manifest"));
        assert_eq!(
            args.journal_digest.as_path(),
            Path::new("artifacts/journal.digest")
        );
        assert_eq!(
            args.evidence_ledger.as_path(),
            Path::new("artifacts/evidence-ledger.json")
        );
        assert_eq!(args.pathlog.as_path(), Path::new("artifacts/pathlog"));
        assert_eq!(args.quiclog.as_path(), Path::new("artifacts/quiclog"));
        assert_eq!(args.repairlog.as_path(), Path::new("artifacts/repairlog"));
        assert!(args.validate_oracles);
        assert_eq!(
            args.oracles,
            vec![
                "manifest_integrity".to_string(),
                "journal_consistency".to_string()
            ]
        );
        assert!(args.minimize);
        assert_eq!(args.reduction_target, 0.8);
    }

    #[test]
    fn atp_early_usability_args_parse_report_path() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "atp",
            "early-usability",
            "--report",
            "artifacts/early-usability.json",
        ])
        .expect("parse atp early-usability args");

        let Command::Atp(AtpArgs {
            command: AtpCommand::EarlyUsability(args),
        }) = cli.command
        else {
            panic!("expected atp early-usability command");
        };

        assert_eq!(
            args.report.as_path(),
            Path::new("artifacts/early-usability.json")
        );
    }

    #[test]
    fn atp_status_args_parse_explain_telemetry_and_current_settings()
    -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "asupersync",
            "atp",
            "status",
            "--telemetry",
            "artifacts/atp-telemetry.json",
            "--explain",
            "--current-in-flight-bytes",
            "4096",
            "--current-stream-count",
            "2",
            "--current-chunk-size-bytes",
            "1024",
            "--current-repair-symbols-per-second",
            "8",
        ])?;

        let args = match cli.command {
            Command::Atp(AtpArgs {
                command: AtpCommand::Status(args),
            }) => args,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "expected atp status command",
                )
                .into());
            }
        };

        assert_eq!(
            args.telemetry.as_path(),
            Path::new("artifacts/atp-telemetry.json")
        );
        assert!(args.explain);
        assert_eq!(args.in_flight_bytes, 4096);
        assert_eq!(args.stream_count, 2);
        assert_eq!(args.chunk_size_bytes, 1024);
        assert_eq!(args.repair_symbols_per_second, 8);
        Ok(())
    }

    #[test]
    fn atp_status_explain_reports_bottlenecks_and_next_settings()
    -> Result<(), Box<dyn std::error::Error>> {
        let file = NamedTempFile::new()?;
        let mut telemetry =
            AtpAutotuneTelemetry::new("trace-status", "workload-status").with_sample_count(16);
        telemetry.loss_permille = Some(100);
        telemetry.send_buffer_queued_bytes = Some(32 * 1_048_576);
        fs::write(file.path(), serde_json::to_vec(&telemetry)?)?;

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        let defaults = AtpAutotuneSettings::default();
        atp_status(
            &AtpStatusArgs {
                telemetry: file.path().to_path_buf(),
                explain: true,
                in_flight_bytes: defaults.in_flight_bytes,
                stream_count: defaults.stream_count,
                chunk_size_bytes: defaults.chunk_size_bytes,
                repair_symbols_per_second: defaults.repair_symbols_per_second,
            },
            &mut output,
        )?;

        let rendered = capture.contents();
        assert!(rendered.contains("ATP Status"));
        assert!(rendered.contains("Trace ID: trace-status"));
        assert!(rendered.contains("Workload ID: workload-status"));
        assert!(rendered.contains("Reason: hold_or_backoff_on_pressure"));
        assert!(rendered.contains("Status: degraded"));
        assert!(rendered.contains("Outcome: PressureBackoff"));
        assert!(rendered.contains("Confidence: fail_closed"));
        assert!(rendered.contains("Fail closed: true"));
        assert!(rendered.contains("- knob in_flight_bytes: Decrease"));
        assert!(rendered.contains("- knob repair_symbols_per_second: Increase"));
        assert!(rendered.contains("network_loss"));
        assert!(rendered.contains("send_buffer_pressure"));
        assert!(rendered.contains("atp.autotune.loss_permille"));
        assert!(rendered.contains("Next settings:"));
        assert!(rendered.contains("Repair mode:"));
        assert!(rendered.contains("Repair action:"));
        assert!(rendered.contains("Repair ROI:"));
        Ok(())
    }

    #[test]
    fn atp_status_accepts_trace_scoped_metric_sample_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let file = NamedTempFile::new()?;
        let report = AtpAutotuneTelemetryReport::new("trace-samples", "workload-samples")
            .with_sample_count(16)
            .with_sample(asupersync::atp::AtpAutotuneMetric::LossPermille, 100)
            .with_sample(
                asupersync::atp::AtpAutotuneMetric::SendBufferQueuedBytes,
                32 * 1_048_576,
            );
        fs::write(file.path(), serde_json::to_vec(&report)?)?;

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        let defaults = AtpAutotuneSettings::default();
        atp_status(
            &AtpStatusArgs {
                telemetry: file.path().to_path_buf(),
                explain: true,
                in_flight_bytes: defaults.in_flight_bytes,
                stream_count: defaults.stream_count,
                chunk_size_bytes: defaults.chunk_size_bytes,
                repair_symbols_per_second: defaults.repair_symbols_per_second,
            },
            &mut output,
        )?;

        let rendered = capture.contents();
        assert!(rendered.contains("Trace ID: trace-samples"));
        assert!(rendered.contains("Workload ID: workload-samples"));
        assert!(rendered.contains("Samples: 16"));
        assert!(rendered.contains("Status: degraded"));
        assert!(rendered.contains("network_loss"));
        assert!(rendered.contains("send_buffer_pressure"));
        assert!(rendered.contains("atp.autotune.send_buffer_queued_bytes"));
        Ok(())
    }

    #[test]
    fn atp_early_usability_renders_stream_report_fields_separately() {
        let file = NamedTempFile::new().expect("create report file");
        let report = StreamEarlyUsabilityReport {
            stream_id: "stream-early".to_string(),
            usable_state: StreamEarlyUsabilityState::VerifiedPrefixAvailable,
            final_commit_state: StreamFinalCommitState::Pending,
            consumption_policy: ConsumptionPolicy::VerifiedOnly,
            verified_prefix_ranges: vec![ByteRange::new(0, 4096)],
            policy_exposed_prefix: Some(ByteRange::new(0, 4096)),
            verified_prefix_end: 4096,
            policy_prefix_end: 4096,
            total_bytes: 8192,
            bytes_sent: 4096,
            safety_caveats: vec![
                "final manifest not committed; expose early bytes separately".to_string(),
            ],
        };
        fs::write(
            file.path(),
            serde_json::to_vec(&report).expect("serialize stream report"),
        )
        .expect("write stream report");

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        atp_early_usability(
            &AtpEarlyUsabilityArgs {
                report: file.path().to_path_buf(),
            },
            &mut output,
        )
        .expect("render stream early usability report");

        let rendered = capture.contents();
        assert!(rendered.contains("Type: stream"));
        assert!(rendered.contains("Usable state: VerifiedPrefixAvailable"));
        assert!(rendered.contains("Final commit state: Pending"));
        assert!(rendered.contains("Verified prefix ranges: 0..4096 (4096 bytes)"));
        assert!(rendered.contains("Policy exposed prefix: 0..4096 (4096 bytes)"));
        assert!(rendered.contains("final manifest not committed"));
    }

    #[test]
    fn atp_early_usability_renders_directory_report_fields_separately() {
        let file = NamedTempFile::new().expect("create report file");
        let report = DirectoryEarlyUsabilityReport {
            schema_version: "asupersync.atp.directory_early_usability.v1".to_string(),
            usability_state:
                asupersync::atp::sync::DirectoryEarlyUsabilityState::SmallFilesAvailable,
            final_commit_state: asupersync::atp::sync::DirectoryFinalCommitState::Pending,
            manifest_tree_root: "tree-root".to_string(),
            replay_pointer: "replay:directory".to_string(),
            metadata_paths: vec!["README.md".to_string(), "model.bin".to_string()],
            small_file_paths: vec!["README.md".to_string()],
            withheld_content_paths: vec!["model.bin".to_string()],
            entries: Vec::new(),
            safety_caveats: vec![
                "final directory commit not complete; expose early entries separately".to_string(),
            ],
        };
        fs::write(
            file.path(),
            serde_json::to_vec(&report).expect("serialize directory report"),
        )
        .expect("write directory report");

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        atp_early_usability(
            &AtpEarlyUsabilityArgs {
                report: file.path().to_path_buf(),
            },
            &mut output,
        )
        .expect("render directory early usability report");

        let rendered = capture.contents();
        assert!(rendered.contains("Type: directory"));
        assert!(rendered.contains("Usable state: SmallFilesAvailable"));
        assert!(rendered.contains("Final commit state: Pending"));
        assert!(rendered.contains("Replay pointer: replay:directory"));
        assert!(rendered.contains("Small files:"));
        assert!(rendered.contains("  - README.md"));
        assert!(rendered.contains("Withheld content:"));
        assert!(rendered.contains("  - model.bin"));
        assert!(rendered.contains("final directory commit not complete"));
    }

    #[test]
    fn atp_replay_replays_emitted_crashpack_artifacts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut trace = asupersync::trace::TraceBuffer::new(4);
        trace.push(asupersync::trace::TraceEvent::user_trace(
            1,
            Time::from_nanos(1),
            "ATP violation: manifest_integrity",
        ));
        let crashpack = asupersync::lab::crashpack::CrashpackBuilder::new()
            .with_oracle_result(asupersync::lab::crashpack::TransferOracleResult {
                oracle_name: "manifest_integrity".to_string(),
                violations: vec![asupersync::lab::crashpack::TransferViolation {
                    violation_type: "manifest_integrity".to_string(),
                    description: "manifest integrity failed".to_string(),
                    severity: asupersync::lab::crashpack::ViolationSeverity::High,
                    evidence: std::collections::BTreeMap::new(),
                }],
                stats: asupersync::lab::oracle::OracleStats {
                    entities_tracked: 1,
                    events_recorded: 1,
                },
                passed: false,
            })
            .with_trace(trace)
            .with_seed("lab-seed", 7)
            .build()
            .expect("crashpack builds");
        crashpack
            .emit_atp_trace(temp.path())
            .expect("crashpack emits replay artifacts");

        let args = AtpReplayArgs {
            trace_file: temp.path().join("transfer.atp-trace"),
            manifest: temp.path().join("manifest"),
            journal_digest: temp.path().join("journal.digest"),
            evidence_ledger: temp.path().join("evidence-ledger.json"),
            pathlog: temp.path().join("pathlog"),
            quiclog: temp.path().join("quiclog"),
            repairlog: temp.path().join("repairlog"),
            validate_oracles: true,
            oracles: vec!["manifest_integrity".to_string()],
            minimize: true,
            reduction_target: 0.8,
        };
        let writer = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Json, writer.clone());

        atp_replay(&args, &mut output).expect("atp replay succeeds");

        let values = parse_jsonl_values(&writer.contents());
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["replay_successful"], true);
        assert_eq!(values[0]["original_violations"], 1);
        assert_eq!(
            values[0]["requested_oracles"],
            serde_json::json!(["manifest_integrity"])
        );

        // The human report names what was checked; nothing is re-executed.
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        atp_replay(&args, &mut output).expect("atp replay succeeds");
        let rendered = capture.contents();
        assert!(
            rendered.starts_with("ATP Replay: verified: the recorded trace witnesses every recorded violation (not re-executed)"),
            "{rendered}"
        );
        assert!(!rendered.contains("reproduced"), "{rendered}");
    }

    #[test]
    fn trace_compress_args_parse_level_and_output() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "trace",
            "compress",
            "input.trace",
            "output.trace",
            "--level",
            "4",
        ])
        .expect("parse trace compress args");

        let Command::Trace(TraceArgs {
            command: TraceCommand::Compress(args),
        }) = cli.command
        else {
            panic!("expected trace compress command");
        };

        assert_eq!(args.input, PathBuf::from("input.trace"));
        assert_eq!(args.output, PathBuf::from("output.trace"));
        assert_eq!(args.level, 4);
    }

    #[test]
    fn trace_migrate_args_preserve_distinct_source_and_destination() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "trace",
            "migrate",
            "legacy-v2.trace",
            "current-v3.trace",
        ])
        .expect("parse trace migrate args");

        let Command::Trace(TraceArgs {
            command: TraceCommand::Migrate(args),
        }) = cli.command
        else {
            panic!("expected trace migrate command");
        };

        assert_eq!(args.input, PathBuf::from("legacy-v2.trace"));
        assert_eq!(args.output, PathBuf::from("current-v3.trace"));
    }

    #[test]
    fn trace_migration_and_checksum_errors_remain_machine_readable() {
        let destination = Path::new("current-v3.trace");
        let exists = trace_file_error(destination, TraceFileError::MigrationDestinationExists);
        assert_eq!(exists.error_type, "migration_destination_exists");
        assert_eq!(
            exists.context.get("path"),
            Some(&serde_json::json!("current-v3.trace"))
        );

        let checksum = trace_file_error(
            Path::new("damaged.trace"),
            TraceFileError::ChecksumMismatch {
                section: "event stream",
            },
        );
        assert_eq!(checksum.error_type, "checksum_mismatch");
        assert!(checksum.detail.contains("event stream"));
    }

    #[test]
    fn lab_differential_args_parse_profile_and_selection() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "lab",
            "differential",
            "--profile",
            "calibration",
            "--scenario",
            "calibration.cancellation.cleanup_missing,phase1.cancel.protocol.drain_finalize",
            "--seed",
            "77",
            "--out-dir",
            "artifacts/diff",
            "--json",
        ])
        .expect("parse differential args");

        let Command::Lab(LabArgs {
            command: LabCommand::Differential(args),
        }) = cli.command
        else {
            panic!("expected lab differential command");
        };

        assert_eq!(args.profile, LabDifferentialProfile::Calibration);
        assert_eq!(
            args.scenarios,
            vec![
                "calibration.cancellation.cleanup_missing".to_string(),
                "phase1.cancel.protocol.drain_finalize".to_string()
            ]
        );
        assert_eq!(args.seed, 77);
        assert_eq!(args.out_dir, PathBuf::from("artifacts/diff"));
        assert!(args.json);
    }

    #[test]
    fn lab_differential_profile_manifest_command_parses() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "lab",
            "differential-profile-manifest",
            "--json",
        ])
        .expect("parse differential profile manifest command");

        let Command::Lab(LabArgs {
            command: LabCommand::DifferentialProfileManifest(args),
        }) = cli.command
        else {
            panic!("expected lab differential-profile-manifest command");
        };

        assert!(args.json);
    }

    #[test]
    fn effective_output_format_prefers_lab_json_subcommands() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "--format",
            "tsv",
            "lab",
            "differential-profile-manifest",
            "--json",
        ])
        .expect("parse lab manifest command with explicit format");

        let format =
            effective_output_format(&cli.command, cli.common.to_common_args().output_format());

        assert_eq!(format, OutputFormat::JsonPretty);
    }

    #[test]
    fn load_scenario_parse_error_is_user_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("invalid.yaml");
        fs::write(&path, "schema_version: [").expect("write malformed scenario");

        let err = load_scenario(&path).expect_err("malformed yaml should fail");
        assert_eq!(err.error_type, "scenario_parse_error");
        assert_eq!(err.exit_code, ExitCode::USER_ERROR);
    }

    #[test]
    fn scenario_runner_error_unknown_oracle_is_user_error() {
        let err = scenario_runner_error(
            asupersync::lab::scenario_runner::ScenarioRunnerError::UnknownOracle(
                "not-real".to_string(),
            ),
        );

        assert_eq!(err.error_type, "unknown_oracle");
        assert_eq!(err.exit_code, ExitCode::USER_ERROR);
    }

    #[test]
    fn scenario_runner_error_replay_divergence_preserves_stable_code() {
        use asupersync::lab::scenario_runner::{ScenarioRunnerError, TraceCertificateSnapshot};

        let err = scenario_runner_error(ScenarioRunnerError::ReplayDivergence {
            seed: 17,
            first: TraceCertificateSnapshot {
                event_hash: 10,
                schedule_hash: 20,
                steps: 30,
                trace_fingerprint: 40,
            },
            second: TraceCertificateSnapshot {
                event_hash: 11,
                schedule_hash: 21,
                steps: 31,
                trace_fingerprint: 41,
            },
        });

        assert_eq!(err.error_type, "replay_divergence");
        assert_eq!(err.title, REPLAY_DIVERGENCE_TITLE);
        assert!(err.title.starts_with("[ASUP-E401]"));
        assert_eq!(err.exit_code, ExitCode::DETERMINISM_FAILURE);
    }

    #[test]
    fn lab_validate_json_uses_output_writer_and_user_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("invalid_scenario.yaml");
        fs::write(
            &path,
            r#"schema_version: 1
id: invalid-scenario
lab:
  worker_count: 0
"#,
        )
        .expect("write invalid scenario");

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::JsonPretty, capture.clone());
        let args = LabValidateArgs {
            scenario: path,
            json: true,
        };

        let err = lab_validate(&args, &mut output).expect_err("invalid scenario should fail");
        let written = capture.contents();

        assert_eq!(err.error_type, "scenario_invalid");
        assert_eq!(err.exit_code, ExitCode::USER_ERROR);
        assert!(written.contains("\"valid\": false"));
        assert!(written.contains("\"errors\""));
    }

    #[test]
    fn lab_run_output_flags_empty_runs_and_reports_participant_bindings() {
        let temp = tempfile::tempdir().expect("tempdir");
        let empty = temp.path().join("empty.yaml");
        fs::write(&empty, "id: empty-run\n").expect("write empty scenario");
        let bound = temp.path().join("bound.yaml");
        fs::write(
            &bound,
            "id: bound-run\nparticipants:\n  - name: alice\n    role: sender\n  - name: bob\n    role: receiver\n  - name: carol\n    role: coordinator\n",
        )
        .expect("write bound scenario");

        let run_with = |path: &Path, format: OutputFormat, json: bool| {
            let capture = SharedWrite::default();
            let mut output = Output::with_writer(format, capture.clone());
            let args = LabRunArgs {
                scenario: path.to_path_buf(),
                seed: None,
                json,
            };
            let passed = lab_run(&args, &mut output).is_ok();
            (passed, capture.contents())
        };
        let run = |path: &Path, format: OutputFormat| run_with(path, format, false);

        let (passed, human) = run(&empty, OutputFormat::Human);
        assert!(passed, "{human}");
        let lines: Vec<&str> = human.lines().collect();
        assert_eq!(lines[2], "Steps: 0 (no workload ran)", "{human}");
        assert_eq!(lines[3], "Faults injected: 0", "{human}");
        assert!(!human.contains("Participants:"), "{human}");
        let (_, json) = run(&empty, OutputFormat::Json);
        assert!(!json.contains("participant_bindings"), "{json}");
        // `--json` writes the full result, plus whether anything ran.
        let (_, full) = run_with(&empty, OutputFormat::Json, true);
        let value: serde_json::Value = serde_json::from_str(full.trim()).expect("lab run --json");
        assert_eq!(value["workload_ran"], false, "{full}");
        assert!(value.get("participant_bindings").is_none(), "{full}");
        let (_, full) = run_with(&bound, OutputFormat::Json, true);
        let value: serde_json::Value = serde_json::from_str(full.trim()).expect("lab run --json");
        assert_eq!(value["workload_ran"], true, "{full}");
        assert_eq!(value["participant_bindings"]["bound"][0]["name"], "alice");

        let (passed, human) = run(&bound, OutputFormat::Human);
        assert!(passed, "{human}");
        let lines: Vec<&str> = human.lines().collect();
        assert!(lines[2].starts_with("Steps: "), "{human}");
        assert!(!lines[2].ends_with("(no workload ran)"), "{human}");
        assert_eq!(
            lines[3], "Participants: 2 bound (sender, receiver), 1 unbound (coordinator)",
            "{human}"
        );
        assert_eq!(lines[4], "Faults injected: 0", "{human}");
        let (_, json) = run(&bound, OutputFormat::Json);
        let value: serde_json::Value = serde_json::from_str(json.trim()).expect("lab run JSON");
        assert_eq!(value["participant_bindings"]["bound"][0]["name"], "alice");
        assert_eq!(
            value["participant_bindings"]["unbound"][0]["role"],
            "coordinator"
        );
        assert_eq!(value["participant_bindings"]["implicit_sink"], false);
    }

    #[test]
    fn lab_differential_profile_manifest_covers_operator_vocabulary() {
        let manifest = lab_differential_profile_manifest();
        assert_eq!(
            manifest.schema_version,
            LAB_DIFFERENTIAL_PROFILE_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(
            manifest.direct_cli_profiles,
            vec![
                "smoke".to_string(),
                "phase1-core".to_string(),
                "calibration".to_string()
            ]
        );

        let profile_ids = manifest
            .operator_profiles
            .iter()
            .map(|profile| profile.profile_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            profile_ids,
            vec![
                "smoke",
                "phase1-core",
                "calibration",
                "repro-targeted",
                "nightly-stress"
            ]
        );

        let repro = manifest
            .operator_profiles
            .iter()
            .find(|profile| profile.profile_id == "repro-targeted")
            .expect("repro-targeted profile present");
        assert_eq!(repro.support_status, "shipped");
        assert_eq!(repro.cli_profile.as_deref(), Some("phase1-core"));
        assert!(
            repro.invocation_recipe.contains("--scenario <scenario-id>"),
            "repro-targeted must preserve scenario-scoped replay recipe"
        );

        let nightly = manifest
            .operator_profiles
            .iter()
            .find(|profile| profile.profile_id == "nightly-stress")
            .expect("nightly-stress profile present");
        assert_eq!(nightly.support_status, "shipped");
        assert_eq!(nightly.cli_profile.as_deref(), Some("phase1-core"));
        assert_eq!(nightly.dependency_bead, None);
        assert_eq!(nightly.tier_binding, "T5 stress_nightly");
        assert_eq!(nightly.scenario_pack, "rotating_seed_phase1_core_pack");
        assert!(
            nightly
                .invocation_recipe
                .contains("--seed-count <count> --seed-stride <stride> --rotation-date <date>"),
            "nightly-stress recipe must expose rotating-seed controls"
        );
        assert_eq!(
            nightly.required_artifacts,
            vec![
                "runner_summary.json".to_string(),
                "operator_summary.txt".to_string(),
                "artifact_index.json".to_string(),
                "differential_event_log.jsonl".to_string(),
                "nightly_stress_manifest.json".to_string(),
                "nightly_stress_summary.txt".to_string(),
                "retained_divergence_artifacts/".to_string()
            ]
        );
        assert_eq!(
            nightly.scenario_ids,
            vec![
                "phase1.cancel.protocol.drain_finalize".to_string(),
                "phase1.cancel.protocol.before_first_poll".to_string(),
                "phase1.cancel.protocol.child_await".to_string(),
                "phase1.cancel.protocol.cleanup_budget".to_string(),
                "phase1.combinator.race.one_loser".to_string(),
                "phase1.channel.reserve_send.commit".to_string(),
                "phase1.channel.reserve_send.abort_visible".to_string(),
                "phase1.region.close.quiescent".to_string(),
                "phase1.sync.semaphore.cancel_recovery".to_string()
            ]
        );
    }

    #[test]
    fn resolve_replay_window_clamps_to_available_events() {
        let window = resolve_replay_window(5, 7, Some(4));
        assert_eq!(window.start, 5);
        assert_eq!(window.requested_events, 4);
        assert_eq!(window.resolved_events, 0);
        assert_eq!(window.end_exclusive, 5);
        assert_eq!(window.total_events, 5);
    }

    #[test]
    fn build_replay_rerun_commands_include_seed_and_window() {
        let args = LabReplayArgs {
            scenario: PathBuf::from("examples/scenarios/smoke_happy_path.yaml"),
            seed: Some(91),
            artifact_pointer: Some("artifacts/replay/pinned.json".to_string()),
            artifact_output: Some(PathBuf::from("artifacts/replay/output.json")),
            window_start: 3,
            window_events: Some(9),
            json: false,
        };

        let commands = build_replay_rerun_commands(&args, 91);
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("--seed 91"));
        assert!(commands[0].contains("--window-start 3"));
        assert!(commands[0].contains("--window-events 9"));
        assert!(commands[0].contains("--artifact-pointer artifacts/replay/pinned.json"));
        assert!(commands[0].contains("--artifact-output artifacts/replay/output.json"));
        assert!(commands[1].contains("asupersync lab run"));
    }

    #[test]
    fn build_replay_rerun_commands_shell_escape_paths() {
        let args = LabReplayArgs {
            scenario: PathBuf::from("examples/scenarios/with space.yaml"),
            seed: Some(91),
            artifact_pointer: Some("artifacts/replay/pinned report.json".to_string()),
            artifact_output: Some(PathBuf::from("artifacts/replay/output report.json")),
            window_start: 0,
            window_events: None,
            json: false,
        };

        let commands = build_replay_rerun_commands(&args, 91);
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("asupersync lab replay 'examples/scenarios/with space.yaml'"));
        assert!(commands[0].contains("--artifact-pointer 'artifacts/replay/pinned report.json'"));
        assert!(commands[0].contains("--artifact-output 'artifacts/replay/output report.json'"));
        assert_eq!(
            commands[1],
            "asupersync lab run 'examples/scenarios/with space.yaml' --seed 91"
        );
    }

    #[test]
    fn build_differential_rerun_commands_shell_escape_out_dir() {
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Smoke,
            scenarios: vec!["phase1.channel.reserve_send.commit".to_string()],
            seed: 91,
            out_dir: PathBuf::from("artifacts/diff reports"),
            json: false,
        };

        let commands = build_differential_rerun_commands(
            &args,
            "phase1.channel.reserve_send.commit",
            Path::new("unused"),
        );
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("--profile smoke"));
        assert!(commands[0].contains("--scenario phase1.channel.reserve_send.commit"));
        assert!(commands[0].contains("--out-dir 'artifacts/diff reports'"));
        assert!(commands[1].contains("--out-dir 'artifacts/diff reports'"));
    }

    fn replay_artifact_test_report() -> LabReplayOutput {
        LabReplayOutput {
            scenario: "examples/scenarios/smoke_happy_path.yaml".to_string(),
            scenario_id: "smoke-happy-path".to_string(),
            deterministic: true,
            seed: 42,
            event_hash: 100,
            schedule_hash: 200,
            trace_fingerprint: 300,
            steps: 400,
            replay_events: 2,
            window: ReplayWindowSummary {
                start: 0,
                requested_events: 2,
                resolved_events: 2,
                end_exclusive: 2,
                total_events: 2,
            },
            provenance: ReplayProvenance {
                scenario_path: "examples/scenarios/smoke_happy_path.yaml".to_string(),
                artifact_pointer: Some("artifacts/replay/report.json".to_string()),
                rerun_commands: vec![
                    "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 42"
                        .to_string(),
                    "asupersync lab run examples/scenarios/smoke_happy_path.yaml --seed 42"
                        .to_string(),
                ],
            },
            divergence: None,
        }
    }

    #[test]
    fn write_replay_artifact_persists_json_report() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output_path = temp.path().join("replay/report.json");
        let report = replay_artifact_test_report();

        write_replay_artifact(&output_path, &report).expect("write replay artifact");
        let saved = fs::read_to_string(&output_path).expect("read replay artifact");
        assert!(saved.contains("\"scenario_id\": \"smoke-happy-path\""));
        assert!(saved.contains("\"rerun_commands\""));
    }

    #[test]
    fn write_replay_artifact_preserves_existing_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output_path = temp.path().join("replay/report.json");
        fs::create_dir_all(output_path.parent().expect("replay parent"))
            .expect("create replay parent");
        fs::write(&output_path, b"existing replay evidence")
            .expect("write existing replay evidence");

        let error = write_replay_artifact(&output_path, &replay_artifact_test_report())
            .expect_err("existing replay artifact must not be replaced");

        assert_eq!(error.error_type, "artifact_output_error");
        assert_eq!(
            error.title,
            "Failed to commit replay artifact without replacing an existing file"
        );
        assert_eq!(
            fs::read_to_string(&output_path).expect("read preserved replay evidence"),
            "existing replay evidence"
        );
    }

    #[test]
    fn lab_differential_smoke_profile_writes_summary_and_logs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Smoke,
            scenarios: vec!["phase1.channel.reserve_send.commit".to_string()],
            seed: 91,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run differential smoke profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        assert!(Path::new(&scenario.summary_path).exists());
        assert!(Path::new(&scenario.event_log_path).exists());
        assert!(Path::new(&scenario.lab_normalized_path).exists());
        assert!(Path::new(&scenario.live_normalized_path).exists());
        assert!(Path::new(&report.runner_summary_path).exists());
        assert!(Path::new(&report.operator_summary_path).exists());
        assert!(Path::new(&report.artifact_index_path).exists());
        assert!(Path::new(&report.aggregate_event_log_path).exists());

        let operator_summary =
            fs::read_to_string(&report.operator_summary_path).expect("read operator summary");
        let expected_operator_summary = format!(
            concat!(
                "Differential operator summary\n",
                "Profile: smoke\n",
                "Evidence grade: t2_dual_run_smoke\n",
                "Confidence label: baseline_signal\n",
                "Runtime cost: fast\n",
                "Operator intent: Fast shared signal for the semantic-core smoke surface.\n",
                "Status: pass\n",
                "Root seed: 91\n",
                "Exit semantics: {}\n",
                "Scenario pack: phase1.channel.reserve_send.commit\n",
                "Scenarios: 1 (pass=1, expected_divergence=0, unexpected_divergence=0, missing_expected_divergence=0)\n",
                "Artifacts:\n",
                "  runner_summary: {}\n",
                "  operator_summary: {}\n",
                "  artifact_index: {}\n",
                "  aggregate_event_log: {}\n",
                "Scenario results:\n",
                "- pass phase1.channel.reserve_send.commit [{}] provisional=pass final=not_applicable summary={}\n",
                "  event_log: {}\n",
                "  lab_normalized: {}\n",
                "  live_normalized: {}\n",
                "  replay:\n",
                "    asupersync lab differential --profile smoke --scenario phase1.channel.reserve_send.commit --seed 91 --out-dir {}\n",
                "    scripts/run_lab_live_differential.sh --profile smoke --scenario phase1.channel.reserve_send.commit --seed 91 --out-dir {}\n",
            ),
            lab_differential_exit_semantics(),
            report.runner_summary_path,
            report.operator_summary_path,
            report.artifact_index_path,
            report.aggregate_event_log_path,
            scenario.seed_lineage_id,
            scenario.summary_path,
            scenario.event_log_path,
            scenario.lab_normalized_path,
            scenario.live_normalized_path,
            args.out_dir.display(),
            args.out_dir.display(),
        );
        assert_eq!(operator_summary, expected_operator_summary);

        let human = report.human_format();
        assert_eq!(human, operator_summary);
        assert!(human.contains("final=not_applicable"));
        assert!(!human.contains("final=pending"));
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_channel_abort_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.channel.reserve_send.abort_visible".to_string()],
            seed: 144,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run channel abort profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["resource_surface"]["counters"]["committed_messages"],
            0
        );
        assert_eq!(
            lab_normalized["semantics"]["resource_surface"]["counters"]["aborted_reservations"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["receiver_observed_messages"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["aborted"],
            1
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_cancel_before_first_poll_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.cancel.protocol.before_first_poll".to_string()],
            seed: 2112,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run before-first-poll cancellation");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["cancellation"]["checkpoint_observed"],
            false
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["pre_poll_cancel_requests"],
            1
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_cancel_during_child_await_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.cancel.protocol.child_await".to_string()],
            seed: 2330,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run child-await cancellation");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["drained_losers"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["awaited_children"],
            1
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_combinator_one_loser_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.combinator.race.one_loser".to_string()],
            seed: 2446,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run combinator one-loser profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["status"],
            "complete"
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["expected_losers"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["drained_losers"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["winner_index"],
            0
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_cleanup_budget_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.cancel.protocol.cleanup_budget".to_string()],
            seed: 2552,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run cleanup-budget cancellation");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["cleanup_budget_ticks"],
            2
        );
        assert_eq!(
            live_normalized["semantics"]["cancellation"]["cleanup_completed"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["cancellation"]["finalization_completed"],
            true
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_quiescent_region_close_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.region.close.quiescent".to_string()],
            seed: 3131,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run quiescent region-close profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);

        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["region_close"]["quiescent"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["live_children"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["finalizers_pending"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["close_completed"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["balanced"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["committed"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["aborted"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["nested_children"],
            2
        );
    }

    #[test]
    fn semaphore_cancel_recovery_observations_align_between_live_and_lab_helpers() {
        let live = live_semaphore_cancel_recovery_observation();
        let lab = lab_semaphore_cancel_recovery_observation(3551);

        assert_eq!(live, lab);
        assert_eq!(live.cancelled_waiters, 1);
        assert_eq!(live.recovered_acquisitions, 1);
        assert_eq!(live.available_after_cancel, 1);
        assert_eq!(live.final_available_permits, 1);
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_sync_semaphore_cancel_recovery_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.sync.semaphore.cancel_recovery".to_string()],
            seed: 3551,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run sync semaphore differential profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);

        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["cancelled_waiters"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["recovered_acquisitions"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["available_after_cancel"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["final_available_permits"],
            1
        );
        assert_eq!(
            lab_normalized["semantics"]["resource_surface"]["counters"],
            live_normalized["semantics"]["resource_surface"]["counters"]
        );
    }

    #[test]
    fn lab_differential_calibration_profile_retains_expected_divergence_bundle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.cancellation.cleanup_missing".to_string()],
            seed: 5150,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run differential calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(Path::new(&scenario.summary_path).exists());
        assert!(Path::new(&scenario.event_log_path).exists());
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for calibration divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for calibration divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .repro_manifest_path
                    .as_deref()
                    .expect("repro manifest must exist for calibration divergence")
            )
            .exists()
        );
    }

    #[test]
    fn lab_differential_calibration_profile_covers_combinator_loser_not_drained() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.combinator.loser_not_drained".to_string()],
            seed: 5224,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run combinator loser-not-drained profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(scenario.observed_provisional_class, "hard_contract_break");
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for combinator divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for combinator divergence")
            )
            .exists()
        );

        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["loser_drain"]["status"],
            "complete"
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["status"],
            "incomplete"
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["expected_losers"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["drained_losers"],
            0
        );

        let event_log =
            fs::read_to_string(&scenario.event_log_path).expect("read combinator event log");
        assert!(event_log.contains("\"provisional_class\":\"hard_contract_break\""));
        assert!(event_log.contains("\"final_policy_class\":\"runtime_semantic_bug\""));
        assert!(event_log.contains("\"lab_loser_drain\":\"complete\""));
        assert!(event_log.contains("\"live_loser_drain\":\"incomplete\""));
    }

    #[test]
    fn lab_differential_calibration_profile_covers_cleanup_budget_exhaustion() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.cancellation.cleanup_budget_exhausted".to_string()],
            seed: 5252,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run cleanup-budget calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(scenario.observed_provisional_class, "hard_contract_break");
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );

        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["cleanup_budget_exhausted"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["quiescent"],
            false
        );
    }

    #[test]
    fn lab_differential_calibration_profile_covers_comparator_mismatch_and_report_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.comparator.resource_counter_mismatch".to_string()],
            seed: 8080,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run comparator calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(
            scenario.observed_provisional_class,
            "semantic_mismatch_admitted_surface"
        );
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert_eq!(
            scenario.expected_provisional_class.as_deref(),
            Some("semantic_mismatch_admitted_surface")
        );
        assert_eq!(scenario.expected_final_policy_class, None);
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for comparator mismatch")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for comparator mismatch")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .repro_manifest_path
                    .as_deref()
                    .expect("repro manifest must exist for comparator mismatch")
            )
            .exists()
        );

        let summary = fs::read_to_string(&scenario.summary_path).expect("read comparator summary");
        assert!(summary.contains("\"description\":"));
        assert!(summary.contains("\"status\": \"expected_divergence\""));
        assert!(
            summary
                .contains("\"expected_provisional_class\": \"semantic_mismatch_admitted_surface\"")
        );
        assert!(summary.contains("\"expected_final_policy_class\": null"));
        assert!(summary.contains("\"attempt_count\": 4"));
        assert!(summary.contains("\"rerun_count\": 3"));
        assert!(summary.contains("\"policy_summary\":"));

        let event_log =
            fs::read_to_string(&scenario.event_log_path).expect("read comparator event log");
        assert!(event_log.contains("\"provisional_class\":\"semantic_mismatch_admitted_surface\""));
        assert!(event_log.contains("\"final_policy_class\":\"runtime_semantic_bug\""));
        assert!(event_log.contains("\"attempt_index\":0"));
        assert!(event_log.contains("\"attempt_index\":1"));
        assert!(event_log.contains("\"attempt_index\":2"));
        assert!(event_log.contains("\"attempt_index\":3"));
        assert!(event_log.contains("\"attempt_kind\":\"deterministic_lab_replay\""));
        assert!(event_log.contains("\"attempt_kind\":\"live_confirmation\""));
        assert!(event_log.contains("\"rerun_count\":3"));

        let operator_summary =
            fs::read_to_string(&report.operator_summary_path).expect("read operator summary");
        assert!(operator_summary.contains("Evidence grade: t4_negative_control"));
        assert!(operator_summary.contains("Confidence label: guardrail_validation"));
        assert!(operator_summary.contains(
            "Operator intent: Intentional divergence lane that proves classifier and artifact retention behavior."
        ));
        assert!(operator_summary.contains("final=runtime_semantic_bug"));
        assert!(operator_summary.contains("repro_manifest:"));
        assert!(operator_summary.contains(
            "asupersync lab differential --profile calibration --scenario calibration.comparator.resource_counter_mismatch --seed 8080"
        ));

        let artifact_index: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&report.artifact_index_path).expect("read artifact index"),
        )
        .expect("parse artifact index");
        assert_eq!(
            artifact_index["schema_version"],
            LAB_DIFFERENTIAL_ARTIFACT_INDEX_SCHEMA_VERSION
        );
        assert_eq!(artifact_index["profile"], "calibration");
        assert_eq!(artifact_index["evidence_grade"], "t4_negative_control");
        assert_eq!(artifact_index["confidence_label"], "guardrail_validation");
        assert_eq!(artifact_index["runtime_cost"], "medium");
        assert_eq!(
            artifact_index["operator_intent"],
            "Intentional divergence lane that proves classifier and artifact retention behavior."
        );
        assert_eq!(
            artifact_index["exit_semantics"],
            lab_differential_exit_semantics()
        );
        assert_eq!(artifact_index["scenario_count"], 1);
        assert_eq!(
            artifact_index["operator_summary_path"].as_str(),
            Some(report.operator_summary_path.as_str())
        );
        assert_eq!(
            artifact_index["runner_summary_path"].as_str(),
            Some(report.runner_summary_path.as_str())
        );
        assert_eq!(
            artifact_index["aggregate_event_log_path"].as_str(),
            Some(report.aggregate_event_log_path.as_str())
        );

        let scenarios = artifact_index["scenarios"]
            .as_array()
            .expect("artifact index scenarios");
        assert_eq!(scenarios.len(), 1);
        let indexed = &scenarios[0];
        assert_eq!(
            indexed["scenario_id"],
            "calibration.comparator.resource_counter_mismatch"
        );
        assert_eq!(indexed["status"], "expected_divergence");
        assert_eq!(
            indexed["observed_provisional_class"],
            "semantic_mismatch_admitted_surface"
        );
        assert_eq!(
            indexed["observed_final_policy_class"],
            "runtime_semantic_bug"
        );
        assert_eq!(
            indexed["summary_path"].as_str(),
            Some(scenario.summary_path.as_str())
        );
        assert_eq!(
            indexed["event_log_path"].as_str(),
            Some(scenario.event_log_path.as_str())
        );
        assert_eq!(
            indexed["lab_normalized_path"].as_str(),
            Some(scenario.lab_normalized_path.as_str())
        );
        assert_eq!(
            indexed["live_normalized_path"].as_str(),
            Some(scenario.live_normalized_path.as_str())
        );
        assert_eq!(
            indexed["repro_manifest_path"],
            scenario
                .repro_manifest_path
                .as_deref()
                .expect("repro manifest path present")
        );
        assert!(
            indexed["repro_commands"]
                .as_array()
                .expect("repro commands array")
                .len()
                >= 2
        );

        let human = report.human_format();
        assert!(human.contains("provisional=semantic_mismatch_admitted_surface"));
        assert!(human.contains("final=runtime_semantic_bug"));
        assert!(human.contains("summary="));
    }

    #[test]
    fn lab_differential_calibration_profile_covers_channel_visibility_mismatch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.channel.commit_visibility_mismatch".to_string()],
            seed: 9090,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run channel calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(
            scenario.observed_provisional_class,
            "semantic_mismatch_admitted_surface"
        );
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for channel mismatch")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for channel mismatch")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .repro_manifest_path
                    .as_deref()
                    .expect("repro manifest must exist for channel mismatch")
            )
            .exists()
        );

        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["resource_surface"]["counters"]["committed_messages"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["committed_messages"],
            1
        );
        assert_eq!(
            lab_normalized["semantics"]["obligation_balance"]["aborted"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["committed"],
            1
        );
    }

    #[test]
    fn lab_differential_calibration_profile_covers_obligation_leak_detection() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.obligation.leak_detected".to_string()],
            seed: 9170,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run obligation calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(scenario.observed_provisional_class, "hard_contract_break");
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for obligation divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for obligation divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .repro_manifest_path
                    .as_deref()
                    .expect("repro manifest must exist for obligation divergence")
            )
            .exists()
        );

        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["obligation_balance"]["balanced"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["balanced"],
            false
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["reserved"],
            2
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["committed"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["aborted"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["leaked"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["reserved_slots"],
            2
        );

        let event_log =
            fs::read_to_string(&scenario.event_log_path).expect("read obligation event log");
        assert!(event_log.contains("\"provisional_class\":\"hard_contract_break\""));
        assert!(event_log.contains("\"final_policy_class\":\"runtime_semantic_bug\""));
    }

    #[test]
    fn lab_differential_calibration_profile_covers_non_quiescent_region_close() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.region.close.non_quiescent".to_string()],
            seed: 9191,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run region-close calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(scenario.observed_provisional_class, "hard_contract_break");
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for region-close divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for region-close divergence")
            )
            .exists()
        );

        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["region_close"]["quiescent"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["quiescent"],
            false
        );
        assert_eq!(
            lab_normalized["semantics"]["region_close"]["live_children"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["live_children"],
            1
        );

        let event_log =
            fs::read_to_string(&scenario.event_log_path).expect("read region-close event log");
        assert!(event_log.contains("\"provisional_class\":\"hard_contract_break\""));
        assert!(event_log.contains("\"final_policy_class\":\"runtime_semantic_bug\""));
    }

    #[test]
    fn lab_differential_calibration_profile_counts_pass_and_divergence_variants() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: Vec::new(),
            seed: 6060,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run full calibration profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 8);
        assert_eq!(report.pass_count, 1);
        assert_eq!(report.expected_divergence_count, 7);
        assert_eq!(report.unexpected_divergence_count, 0);
        assert_eq!(report.missing_expected_divergence_count, 0);
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.combinator.loser_not_drained"
                && scenario.observed_provisional_class == "hard_contract_break"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.comparator.resource_counter_mismatch"
                && scenario.observed_provisional_class == "semantic_mismatch_admitted_surface"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.channel.commit_visibility_mismatch"
                && scenario.observed_provisional_class == "semantic_mismatch_admitted_surface"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.cancellation.cleanup_missing"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.cancellation.cleanup_budget_exhausted"
                && scenario.observed_provisional_class == "hard_contract_break"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.region.close.non_quiescent"
                && scenario.observed_provisional_class == "hard_contract_break"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
    }

    #[test]
    fn doctor_evidence_timeline_contract_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "doctor", "evidence-timeline-contract"])
            .expect("parse doctor evidence-timeline-contract");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::EvidenceTimelineContract,
        }) = cli.command
        else {
            panic!("expected doctor evidence-timeline-contract command");
        };
    }

    #[test]
    fn atp_doctor_platform_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "atp", "doctor", "--platform"])
            .expect("parse atp doctor --platform");

        let Command::Atp(AtpArgs {
            command: AtpCommand::Doctor(args),
        }) = cli.command
        else {
            panic!("expected atp doctor command");
        };
        assert!(args.platform);
    }

    #[test]
    fn atp_doctor_requires_platform_selector() {
        let mut output = Output::with_writer(OutputFormat::Json, Vec::<u8>::new());
        let err = atp_doctor(&AtpDoctorArgs { platform: false }, &mut output)
            .expect_err("missing selector should fail");

        assert_eq!(err.error_type, "invalid_argument");
    }

    #[test]
    fn atp_platform_doctor_human_output_has_stable_sections() {
        let provider =
            asupersync::atp::platform::DeterministicLabPlatformProvider::fully_supported();
        let payload = AtpPlatformDoctorOutput::new(build_platform_doctor_document(&provider));
        let rendered = payload.human_format();

        assert!(rendered.contains("Schema: asupersync.atp.doctor.platform.v1"));
        assert!(rendered.contains("Filesystem:"));
        assert!(rendered.contains("Network:"));
        assert!(rendered.contains("Service:"));
        assert!(rendered.contains("Degradation policy:"));
        assert!(rendered.contains("Structured probe logs: 11"));
    }

    #[test]
    fn atp_platform_doctor_json_output_has_stable_contract() {
        let provider =
            asupersync::atp::platform::DeterministicLabPlatformProvider::conservative_degradation();
        let payload = AtpPlatformDoctorOutput::new(build_platform_doctor_document(&provider));
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Json, capture.clone());

        output.write(&payload).expect("write atp platform payload");
        output.flush().expect("flush atp platform payload");
        let json: serde_json::Value =
            serde_json::from_str(capture.contents().trim()).expect("parse atp platform json");

        assert_eq!(json["schema_version"], "asupersync.atp.doctor.platform.v1");
        assert_eq!(
            json["report"]["degradation_policy"]["disk_writer_mode"],
            "contiguous-verified-quarantine"
        );
        assert!(
            json["logs"]
                .as_array()
                .expect("logs array")
                .iter()
                .any(|entry| entry["capability"] == "service_manager"
                    && entry["probe_source"] == "skipped")
        );
    }

    #[test]
    fn doctor_evidence_timeline_smoke_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "doctor", "evidence-timeline-smoke"])
            .expect("parse doctor evidence-timeline-smoke");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::EvidenceTimelineSmoke,
        }) = cli.command
        else {
            panic!("expected doctor evidence-timeline-smoke command");
        };
    }

    #[test]
    fn doctor_canonical_d3_commands_parse() {
        let scan = Cli::try_parse_from(["asupersync", "doctor", "scan", "--root", ".", "--json"])
            .expect("parse doctor scan");
        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::Scan(scan_args),
        }) = scan.command
        else {
            panic!("expected doctor scan command");
        };
        assert_eq!(scan_args.root, PathBuf::from("."));
        assert!(scan_args.json);

        let explain = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "explain",
            "--bundle",
            "artifacts/doctor/bundle.json",
            "--json",
        ])
        .expect("parse doctor explain");
        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::Explain(explain_args),
        }) = explain.command
        else {
            panic!("expected doctor explain command");
        };
        assert_eq!(
            explain_args.bundle,
            PathBuf::from("artifacts/doctor/bundle.json")
        );
        assert!(explain_args.json);

        let recipe_list = Cli::try_parse_from(["asupersync", "doctor", "recipe-list", "--json"])
            .expect("parse doctor recipe-list");
        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::RecipeList(recipe_args),
        }) = recipe_list.command
        else {
            panic!("expected doctor recipe-list command");
        };
        assert!(recipe_args.json);

        let validate = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "validate-fixture",
            "--fixture-id",
            "happy_path",
            "--json",
        ])
        .expect("parse doctor validate-fixture");
        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::ValidateFixture(validate_args),
        }) = validate.command
        else {
            panic!("expected doctor validate-fixture command");
        };
        assert_eq!(validate_args.fixture_id, "happy_path");
        assert!(validate_args.json);

        let report = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "report",
            "--fixture-id",
            "happy_path",
            "--json",
        ])
        .expect("parse doctor report");
        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::Report(report_args),
        }) = report.command
        else {
            panic!("expected doctor report command");
        };
        assert_eq!(report_args.fixture_id, "happy_path");
        assert!(report_args.json);
    }

    #[test]
    fn effective_output_format_prefers_doctor_json_subcommands() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "--format",
            "human",
            "doctor",
            "report",
            "--fixture-id",
            "happy_path",
            "--json",
        ])
        .expect("parse doctor report json command");

        let format =
            effective_output_format(&cli.command, cli.common.to_common_args().output_format());

        assert_eq!(format, OutputFormat::JsonPretty);
    }

    #[test]
    fn doctor_report_command_emits_checked_json_schema() {
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Json, capture.clone());
        let args = DoctorReportArgs {
            fixture_id: "happy_path".to_string(),
            json: true,
        };

        doctor_report(&args, &mut output).expect("doctor report command");
        output.flush().expect("flush report output");
        let json: serde_json::Value =
            serde_json::from_str(capture.contents().trim()).expect("parse doctor report json");

        assert_eq!(json["schema_version"], "doctor-cli-report-v1");
        assert_eq!(json["fixture_id"], "happy_path");
        assert_eq!(json["validation_status"], "passed");
        assert_eq!(json["report"]["schema_version"], "doctor-core-report-v1");
        assert_eq!(json["report"]["summary"]["status"], "healthy");
        assert!(
            json["rerun_commands"]
                .as_array()
                .expect("rerun commands array")
                .iter()
                .any(|command| command
                    .as_str()
                    .is_some_and(|value| value.contains("rch exec")))
        );
    }

    #[test]
    fn doctor_validate_fixture_rejects_unknown_fixture_id() {
        let mut output = Output::with_writer(OutputFormat::Json, Vec::<u8>::new());
        let args = DoctorValidateFixtureArgs {
            fixture_id: "missing_fixture".to_string(),
            json: true,
        };

        let err = doctor_validate_fixture(&args, &mut output).expect_err("unknown fixture fails");

        assert_eq!(err.error_type, "doctor_unknown_fixture");
        assert_eq!(err.exit_code, ExitCode::USER_ERROR);
        assert!(err.detail.contains("happy_path"));
    }

    #[test]
    fn doctor_scenario_coverage_pack_contract_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "doctor", "scenario-coverage-pack-contract"])
            .expect("parse doctor scenario-coverage-pack-contract");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::ScenarioCoveragePackContract,
        }) = cli.command
        else {
            panic!("expected doctor scenario-coverage-pack-contract command");
        };
    }

    #[test]
    fn doctor_scenario_coverage_pack_smoke_command_parses() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "scenario-coverage-pack-smoke",
            "--selection-mode",
            "retry",
            "--seed",
            "seed-007",
        ])
        .expect("parse doctor scenario-coverage-pack-smoke");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::ScenarioCoveragePackSmoke(args),
        }) = cli.command
        else {
            panic!("expected doctor scenario-coverage-pack-smoke command");
        };
        assert_eq!(args.selection_mode, "retry");
        assert_eq!(args.seed, "seed-007");
    }

    #[test]
    fn doctor_stress_soak_contract_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "doctor", "stress-soak-contract"])
            .expect("parse doctor stress-soak-contract");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::StressSoakContract,
        }) = cli.command
        else {
            panic!("expected doctor stress-soak-contract command");
        };
    }

    #[test]
    fn doctor_stress_soak_smoke_command_parses() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "stress-soak-smoke",
            "--profile-mode",
            "fast",
            "--seed",
            "seed-5150",
        ])
        .expect("parse doctor stress-soak-smoke");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::StressSoakSmoke(args),
        }) = cli.command
        else {
            panic!("expected doctor stress-soak-smoke command");
        };
        assert_eq!(args.profile_mode, "fast");
        assert_eq!(args.seed, "seed-5150");
    }

    #[test]
    fn doctor_report_export_args_parse_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "report-export",
            "--fixture-id",
            "advanced_failure_path",
            "--out-dir",
            "target/e2e-results/doctor_report_export",
            "--format",
            "json,markdown",
        ])
        .expect("parse doctor report-export args");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::ReportExport(args),
        }) = cli.command
        else {
            panic!("expected doctor report-export command");
        };

        assert_eq!(args.fixture_id.as_deref(), Some("advanced_failure_path"));
        assert_eq!(
            args.out_dir,
            PathBuf::from("target/e2e-results/doctor_report_export")
        );
        assert_eq!(
            args.formats,
            vec![
                DoctorReportExportFormat::Json,
                DoctorReportExportFormat::Markdown
            ]
        );
    }

    #[test]
    fn doctor_package_cli_args_parse_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "package-cli",
            "--source-binary",
            "target/release/asupersync",
            "--out-dir",
            "target/e2e-results/doctor_cli_package",
            "--binary-name",
            "doctor_asupersync",
            "--default-profile",
            "ci",
            "--smoke",
        ])
        .expect("parse doctor package-cli args");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::PackageCli(args),
        }) = cli.command
        else {
            panic!("expected doctor package-cli command");
        };
        assert_eq!(
            args.source_binary.as_deref(),
            Some(Path::new("target/release/asupersync"))
        );
        assert_eq!(
            args.out_dir,
            PathBuf::from("target/e2e-results/doctor_cli_package")
        );
        assert_eq!(args.binary_name, "doctor_asupersync");
        assert_eq!(args.default_profile, DoctorPackageProfile::Ci);
        assert!(args.smoke);
    }

    #[test]
    fn doctor_task_console_view_command_parses() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "task-console-view",
            "--snapshot",
            "artifacts/task_console.json",
            "--max-tasks",
            "32",
            "--allow-schema-mismatch",
        ])
        .expect("parse doctor task-console-view args");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::TaskConsoleView(args),
        }) = cli.command
        else {
            panic!("expected doctor task-console-view command");
        };
        assert_eq!(args.snapshot, PathBuf::from("artifacts/task_console.json"));
        assert_eq!(args.max_tasks, 32);
        assert!(args.allow_schema_mismatch);
    }

    #[test]
    fn build_task_console_view_output_truncates_tasks() {
        let snapshot = sample_task_console_snapshot();
        let view =
            build_task_console_view_output(snapshot, Path::new("fixtures/task_console.json"), 1);
        assert!(view.schema_matches_expected);
        assert_eq!(view.source_snapshot, "fixtures/task_console.json");
        assert_eq!(view.total_tasks, 2);
        assert_eq!(view.shown_tasks, 1);
        assert!(view.truncated);
    }

    #[test]
    fn doctor_task_console_view_rejects_schema_mismatch_by_default() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("task_console_snapshot.json");
        let mut snapshot = sample_task_console_snapshot();
        snapshot.schema_version = "asupersync.task_console_wire.experimental".to_string();
        fs::write(
            &path,
            snapshot.to_json().expect("serialize task console snapshot"),
        )
        .expect("write task console snapshot");

        let args = DoctorTaskConsoleViewArgs {
            snapshot: path,
            max_tasks: 8,
            allow_schema_mismatch: false,
        };
        let mut output = Output::with_writer(OutputFormat::Json, std::io::Cursor::new(Vec::new()));
        let err =
            doctor_task_console_view(&args, &mut output).expect_err("schema mismatch should fail");
        assert_eq!(err.error_type, "doctor_task_console_schema_error");
        assert!(err.detail.contains(TASK_CONSOLE_WIRE_SCHEMA_V1));
    }

    #[test]
    fn doctor_package_template_materialization_is_deterministic() {
        let temp = tempfile::tempdir().expect("tempdir");
        let first = materialize_doctor_package_templates(temp.path(), "doctor_asupersync")
            .expect("materialize first");
        let second = materialize_doctor_package_templates(temp.path(), "doctor_asupersync")
            .expect("materialize second");

        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        assert_eq!(
            first
                .iter()
                .map(|entry| entry.artifact.profile.clone())
                .collect::<Vec<_>>(),
            vec!["ci".to_string(), "local".to_string()]
        );
        assert_eq!(
            first
                .iter()
                .map(|entry| entry.artifact.command_preview.clone())
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|entry| entry.artifact.command_preview.clone())
                .collect::<Vec<_>>()
        );
        for entry in &first {
            let raw = fs::read_to_string(&entry.artifact.path).expect("read materialized template");
            let parsed = parse_doctor_package_config(&raw).expect("template parse");
            assert_eq!(
                parsed.schema_version,
                DOCTOR_CLI_PACKAGE_CONFIG_SCHEMA_VERSION
            );
            assert_eq!(parsed.profile, entry.artifact.profile);
            assert!(entry.artifact.command_preview.contains("--format"));
            assert!(entry.artifact.command_preview.contains("--color"));
            assert!(
                entry
                    .artifact
                    .command_preview
                    .contains("doctor report-contract")
            );
        }
    }

    #[test]
    fn render_doctor_packaged_command_includes_cli_flags() {
        let config = doctor_package_config_template(DoctorPackageProfile::Ci, "doctor_asupersync");
        let command = render_doctor_packaged_command(&config, "doctor_asupersync");
        assert_eq!(
            command,
            "doctor_asupersync --format json --color never doctor report-contract"
        );
    }

    #[test]
    fn format_timestamp_matches_rfc3339_utc_vector() {
        assert_eq!(
            format_timestamp(1_577_836_800_000_000_000),
            Some("2020-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn parse_doctor_package_config_rejects_invalid_profile() {
        let mut config =
            doctor_package_config_template(DoctorPackageProfile::Local, "doctor_asupersync");
        config.profile = "prod".to_string();
        let raw = serde_json::to_string(&config).expect("serialize config");
        let err = parse_doctor_package_config(&raw).expect_err("invalid profile should fail");
        assert!(err.contains("profile must be one of: local, ci"));
    }

    #[test]
    fn parse_doctor_package_config_rejects_invalid_output_format() {
        let mut config =
            doctor_package_config_template(DoctorPackageProfile::Local, "doctor_asupersync");
        config.output_format = "xml".to_string();
        let raw = serde_json::to_string(&config).expect("serialize config");
        let err = parse_doctor_package_config(&raw).expect_err("invalid format should fail");
        assert!(err.contains("output_format must be one of"));
    }

    #[test]
    fn resolve_install_smoke_binary_path_handles_relative_paths() {
        let cwd = std::env::current_dir().expect("cwd");
        let rel_dir = cwd.join("target/test-temp-doctor-package");
        fs::create_dir_all(&rel_dir).expect("create rel dir");
        let rel_binary = PathBuf::from("target/test-temp-doctor-package/doctor_asupersync");
        fs::write(&rel_binary, b"fixture-binary").expect("write rel binary");

        let resolved = resolve_install_smoke_binary_path(&rel_binary, "doctor_package_smoke_error")
            .expect("canonicalize relative smoke path");
        assert!(resolved.is_absolute());
        assert_eq!(
            resolved,
            fs::canonicalize(&rel_binary).expect("canonicalize reference")
        );
    }

    #[test]
    fn select_advanced_fixtures_for_report_export_rejects_unknown_fixture() {
        let args = DoctorReportExportArgs {
            fixture_id: Some("missing-fixture".to_string()),
            out_dir: PathBuf::from("target/e2e-results/doctor_report_export"),
            formats: vec![DoctorReportExportFormat::Json],
        };
        let err = select_advanced_fixtures_for_report_export(&args)
            .expect_err("missing fixture should fail");
        assert_eq!(err.error_type, "invalid_argument");
        assert!(err.title.contains("Unknown --fixture-id value"));
    }

    #[test]
    fn export_advanced_report_fixture_is_deterministic() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle
            .fixtures
            .iter()
            .find(|entry| entry.fixture_id == "advanced_failure_path")
            .expect("fixture exists")
            .clone();
        let formats = vec![
            DoctorReportExportFormat::Markdown,
            DoctorReportExportFormat::Json,
        ];
        let temp = tempfile::tempdir().expect("tempdir");

        let first = export_advanced_report_fixture(&bundle, &fixture, &formats, temp.path())
            .expect("first export");
        let second = export_advanced_report_fixture(&bundle, &fixture, &formats, temp.path())
            .expect("second export");

        assert_eq!(first.output_files, second.output_files);
        assert_eq!(
            first.remediation_outcome_count,
            second.remediation_outcome_count
        );
        assert_eq!(first.validation_status, "valid");
        assert_eq!(second.validation_status, "valid");
        assert_eq!(first.output_files.len(), 2);

        let first_json = first
            .output_files
            .iter()
            .find(|path| path.ends_with(".json"))
            .expect("json path");
        let first_md = first
            .output_files
            .iter()
            .find(|path| path.ends_with(".md"))
            .expect("markdown path");
        let second_json = second
            .output_files
            .iter()
            .find(|path| path.ends_with(".json"))
            .expect("json path");
        let second_md = second
            .output_files
            .iter()
            .find(|path| path.ends_with(".md"))
            .expect("markdown path");

        let first_json_payload = fs::read_to_string(first_json).expect("read first json");
        let second_json_payload = fs::read_to_string(second_json).expect("read second json");
        assert_eq!(first_json_payload, second_json_payload);

        let first_md_payload = fs::read_to_string(first_md).expect("read first markdown");
        let second_md_payload = fs::read_to_string(second_md).expect("read second markdown");
        assert_eq!(first_md_payload, second_md_payload);
    }

    #[test]
    fn report_export_document_snapshot_is_stable() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle
            .fixtures
            .iter()
            .find(|entry| entry.fixture_id == "advanced_failure_path")
            .expect("fixture exists");
        let document = build_report_export_document(&bundle, fixture).expect("document");
        assert_json_snapshot!(
            document,
            @r###"
        {
          "schema_version": "doctor-report-export-v1",
          "fixture_id": "advanced_failure_path",
          "report_id": "doctor-report-failure-v1",
          "core_contract_version": "doctor-core-report-v1",
          "extension_contract_version": "doctor-advanced-report-v1",
          "summary": {
            "status": "failed",
            "overall_outcome": "failed",
            "total_findings": 2,
            "critical_findings": 1
          },
          "findings": [
            {
              "finding_id": "finding-001",
              "title": "Obligation leak during shutdown path",
              "severity": "critical",
              "status": "open",
              "evidence_refs": [
                "evidence-001"
              ],
              "command_refs": [
                "command-001"
              ]
            },
            {
              "finding_id": "finding-002",
              "title": "Replay mismatch for cancellation timeline",
              "severity": "high",
              "status": "in_progress",
              "evidence_refs": [
                "evidence-002"
              ],
              "command_refs": [
                "command-002"
              ]
            }
          ],
          "evidence_links": [
            {
              "evidence_id": "evidence-001",
              "source": "structured_log",
              "artifact_pointer": "artifacts/run-doctor-failure/doctor/core-report/finding-001.json",
              "replay_pointer": "rch exec -- cargo test -p asupersync -- obligation_leak",
              "outcome_class": "failed",
              "franken_trace_id": "trace-franken-failure-001"
            },
            {
              "evidence_id": "evidence-002",
              "source": "trace",
              "artifact_pointer": "artifacts/run-doctor-failure/doctor/core-report/trace-002.json",
              "replay_pointer": "asupersync trace verify artifacts/run-doctor-failure/trace-002.bin",
              "outcome_class": "failed",
              "franken_trace_id": "trace-franken-failure-002"
            }
          ],
          "command_provenance": [
            {
              "command_id": "command-001",
              "command": "rch exec -- cargo test -p asupersync obligation_leak -- --nocapture",
              "tool": "rch",
              "exit_code": 101,
              "outcome_class": "failed"
            },
            {
              "command_id": "command-002",
              "command": "asupersync trace verify artifacts/run-doctor-failure/trace-002.bin",
              "tool": "asupersync",
              "exit_code": 2,
              "outcome_class": "failed"
            }
          ],
          "remediation_outcomes": [
            {
              "delta_id": "delta-001",
              "finding_id": "finding-001",
              "previous_status": "open",
              "next_status": "in_progress",
              "delta_outcome": "failed",
              "mapped_taxonomy_class": "remediation_safety",
              "mapped_taxonomy_dimension": "recovery_planning",
              "verification_evidence_refs": [
                "evidence-001"
              ]
            }
          ],
          "trust_transitions": [
            {
              "transition_id": "trust-001",
              "stage": "post-remediation-attempt",
              "previous_score": 82,
              "next_score": 44,
              "outcome_class": "failed",
              "mapped_taxonomy_severity": "error",
              "rationale": "Critical finding persisted after first remediation pass."
            }
          ],
          "collaboration_trail": [
            {
              "entry_id": "collab-001",
              "channel": "agent_mail",
              "actor": "ChartreuseBrook",
              "action": "requested remediation follow-up",
              "thread_id": "br-2b4jj.5.9",
              "message_ref": "mail-advanced-001",
              "bead_ref": "asupersync-2b4jj.5.9",
              "mapped_taxonomy_narrative": "Remediation safety remained degraded after failed verification."
            }
          ],
          "troubleshooting_playbooks": [
            {
              "playbook_id": "playbook-001",
              "title": "Critical remediation retry loop",
              "trigger_taxonomy_class": "remediation_safety",
              "trigger_taxonomy_severity": "error",
              "ordered_steps": [
                "capture_fresh_evidence",
                "reproduce_failure_with_rch",
                "stage_patch_and_verify"
              ],
              "command_refs": [
                "command-001"
              ],
              "evidence_refs": [
                "evidence-001"
              ]
            }
          ],
          "provenance": {
            "run_id": "run-doctor-failure",
            "scenario_id": "doctor-core-report-failure",
            "trace_id": "trace-doctor-failure",
            "seed": "1337",
            "generated_by": "doctor_asupersync",
            "generated_at": "2026-02-26T06:00:00Z"
          }
        }
        "###
        );
    }

    #[test]
    fn report_export_markdown_snapshot_is_stable() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle
            .fixtures
            .iter()
            .find(|entry| entry.fixture_id == "advanced_failure_path")
            .expect("fixture exists");
        let document = build_report_export_document(&bundle, fixture).expect("document");
        let markdown = render_doctor_report_markdown(&document);
        assert_snapshot!(
            markdown,
            @r###"
        # Doctor Diagnostics Export: advanced_failure_path

        - Schema: doctor-report-export-v1
        - Core contract: doctor-core-report-v1
        - Extension contract: doctor-advanced-report-v1
        - Report ID: doctor-report-failure-v1
        - Run ID: run-doctor-failure
        - Scenario ID: doctor-core-report-failure
        - Trace ID: trace-doctor-failure
        - Seed: 1337

        ## Summary

        - Status: failed
        - Outcome: failed
        - Total findings: 2
        - Critical findings: 1

        ## Findings

        - `finding-001` Obligation leak during shutdown path (severity=critical, status=open)
          - evidence_refs: evidence-001
          - command_refs: command-001
        - `finding-002` Replay mismatch for cancellation timeline (severity=high, status=in_progress)
          - evidence_refs: evidence-002
          - command_refs: command-002

        ## Evidence Links

        - `evidence-001` source=structured_log outcome=failed artifact=artifacts/run-doctor-failure/doctor/core-report/finding-001.json replay=rch exec -- cargo test -p asupersync -- obligation_leak
        - `evidence-002` source=trace outcome=failed artifact=artifacts/run-doctor-failure/doctor/core-report/trace-002.json replay=asupersync trace verify artifacts/run-doctor-failure/trace-002.bin

        ## Command Provenance

        - `command-001` [rch] exit=101 outcome=failed command=`rch exec -- cargo test -p asupersync obligation_leak -- --nocapture`
        - `command-002` [asupersync] exit=2 outcome=failed command=`asupersync trace verify artifacts/run-doctor-failure/trace-002.bin`

        ## Remediation Outcomes

        - `delta-001` finding=finding-001 open -> in_progress outcome=failed class=remediation_safety dimension=recovery_planning
          - verification_evidence_refs: evidence-001

        ## Trust Transitions

        - `trust-001` stage=post-remediation-attempt 82 -> 44 outcome=failed severity=error rationale=Critical finding persisted after first remediation pass.

        ## Collaboration Trail

        - `collab-001` channel=agent_mail actor=ChartreuseBrook action=requested remediation follow-up thread=br-2b4jj.5.9 message=mail-advanced-001 bead=asupersync-2b4jj.5.9

        ## Troubleshooting Playbooks

        - `playbook-001` Critical remediation retry loop (class=remediation_safety, severity=error)
          - ordered_steps: capture_fresh_evidence -> reproduce_failure_with_rch -> stage_patch_and_verify
          - command_refs: command-001
          - evidence_refs: evidence-001
        "###
        );
    }

    #[test]
    fn render_doctor_report_markdown_includes_required_sections() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle
            .fixtures
            .iter()
            .find(|entry| entry.fixture_id == "advanced_failure_path")
            .expect("fixture exists");
        let document = build_report_export_document(&bundle, fixture).expect("document");
        let markdown = render_doctor_report_markdown(&document);
        let section_headings = markdown
            .lines()
            .filter(|line| line.starts_with("## "))
            .collect::<Vec<_>>()
            .join("\n");

        assert_snapshot!(
            section_headings,
            @r###"
        ## Summary
        ## Findings
        ## Evidence Links
        ## Command Provenance
        ## Remediation Outcomes
        ## Trust Transitions
        ## Collaboration Trail
        ## Troubleshooting Playbooks
        "###
        );
    }

    #[test]
    fn doctor_franken_export_args_parse_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "franken-export",
            "--report",
            "artifacts/doctor/core-report.json",
            "--fixture-id",
            "baseline_failure_path",
            "--out-dir",
            "target/e2e-results/doctor_frankensuite_export",
        ])
        .expect("parse doctor franken-export args");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::FrankenExport(args),
        }) = cli.command
        else {
            panic!("expected doctor franken-export command");
        };

        assert_eq!(
            args.report.as_deref(),
            Some(Path::new("artifacts/doctor/core-report.json"))
        );
        assert_eq!(args.fixture_id.as_deref(), Some("baseline_failure_path"));
        assert_eq!(
            args.out_dir,
            PathBuf::from("target/e2e-results/doctor_frankensuite_export")
        );
    }

    #[test]
    fn export_core_report_to_franken_artifacts_is_deterministic() {
        let fixture = core_diagnostics_report_bundle()
            .fixtures
            .into_iter()
            .find(|candidate| candidate.fixture_id == "baseline_failure_path")
            .expect("fixture exists");
        let temp = tempfile::tempdir().expect("tempdir");

        let first = export_core_report_to_franken_artifacts(
            fixture.fixture_id.as_str(),
            &fixture.report,
            temp.path(),
        )
        .expect("first export");
        let second = export_core_report_to_franken_artifacts(
            fixture.fixture_id.as_str(),
            &fixture.report,
            temp.path(),
        )
        .expect("second export");

        assert_eq!(first.evidence_count, second.evidence_count);
        assert_eq!(first.decision_count, second.decision_count);

        let first_evidence = fs::read_to_string(&first.evidence_jsonl).expect("first evidence");
        let second_evidence = fs::read_to_string(&second.evidence_jsonl).expect("second evidence");
        assert_eq!(first_evidence, second_evidence);

        let first_decision = fs::read_to_string(&first.decision_json).expect("first decision");
        let second_decision = fs::read_to_string(&second.decision_json).expect("second decision");
        assert_eq!(first_decision, second_decision);
    }

    #[test]
    fn franken_export_snapshot_is_stable() {
        let fixture = core_diagnostics_report_bundle()
            .fixtures
            .into_iter()
            .find(|candidate| candidate.fixture_id == "baseline_failure_path")
            .expect("fixture exists");
        let temp = tempfile::tempdir().expect("tempdir");
        let artifact = export_core_report_to_franken_artifacts(
            fixture.fixture_id.as_str(),
            &fixture.report,
            temp.path(),
        )
        .expect("export");

        let evidence = fs::read_to_string(&artifact.evidence_jsonl).expect("read evidence");
        let decision = fs::read_to_string(&artifact.decision_json).expect("read decision");
        let evidence_entries = parse_jsonl_values(&evidence);
        let decision_entries: serde_json::Value =
            serde_json::from_str(&decision).expect("parse decision payload");

        assert_json_snapshot!(
            serde_json::json!({
                "evidence": evidence_entries,
                "decision": decision_entries,
            }),
            @r###"
        {
          "evidence": [
            {
              "a": "hold",
              "c": "structured_log",
              "cal": 0.68,
              "cel": 0.3,
              "el": {
                "hold": 0.3,
                "promote": 0.45
              },
              "fb": true,
              "p": [
                0.55,
                0.45
              ],
              "tf": [
                [
                  "evidence_id",
                  1.0
                ],
                [
                  "outcome_class",
                  0.8
                ]
              ],
              "ts": 16358360581643888801
            },
            {
              "a": "hold",
              "c": "trace",
              "cal": 0.68,
              "cel": 0.3,
              "el": {
                "hold": 0.3,
                "promote": 0.45
              },
              "fb": true,
              "p": [
                0.55,
                0.45
              ],
              "tf": [
                [
                  "evidence_id",
                  1.0
                ],
                [
                  "outcome_class",
                  0.8
                ]
              ],
              "ts": 16358360581664031791
            }
          ],
          "decision": [
            {
              "action_chosen": "hold_release",
              "calibration_score": 0.55,
              "contract_name": "doctor-core-diagnostics",
              "decision_id": "d4ab0c92e4bf980b88fb7b1d73e79239",
              "expected_loss": 0.17,
              "expected_loss_by_action": {
                "continue_investigation": 0.2975,
                "hold_release": 0.17,
                "promote_fix": 0.4675
              },
              "fallback_active": true,
              "posterior_snapshot": [
                0.35,
                0.65
              ],
              "trace_id": "1548473d85174633375fbb6754396275",
              "ts_unix_ms": 8649082491939616561
            },
            {
              "action_chosen": "continue_investigation",
              "calibration_score": 0.55,
              "contract_name": "doctor-core-diagnostics",
              "decision_id": "d4ab0c92e1bf980b88fb7b1d73e78e88",
              "expected_loss": 0.22749999999999998,
              "expected_loss_by_action": {
                "continue_investigation": 0.22749999999999998,
                "hold_release": 0.13,
                "promote_fix": 0.35750000000000004
              },
              "fallback_active": true,
              "posterior_snapshot": [
                0.35,
                0.65
              ],
              "trace_id": "1548473d82174633375fbb6754395ec4",
              "ts_unix_ms": 8649082491972460351
            }
          ]
        }
        "###
        );
    }

    #[test]
    fn validate_exportable_core_report_rejects_unsupported_schema_version() {
        let mut report = core_diagnostics_report_bundle()
            .fixtures
            .into_iter()
            .next()
            .expect("fixture exists")
            .report;
        report.schema_version = "doctor-core-report-v0".to_string();

        let err = validate_exportable_core_report(&report).expect_err("expected version error");
        assert_eq!(err.error_type, "doctor_export_error");
        assert!(err.detail.contains("doctor-core-report-v0"));
    }

    #[test]
    fn load_core_report_rejects_malformed_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("malformed_core_report.json");
        fs::write(&path, "{ not-json ").expect("write malformed");

        let err = load_core_report(&path).expect_err("expected parse failure");
        assert_eq!(err.error_type, "doctor_export_error");
        assert!(err.title.contains("parse core diagnostics report JSON"));
    }

    #[test]
    fn atp_get_dry_run_produces_receive_plan() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_transfer, transfer_id) = temp_transfer_reference(b"dry-run transfer");
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());

        let args = AtpGetArgs {
            transfer_id,
            destination: Some(temp.path().to_path_buf()),
            dry_run: true,
            policy: "allow-listed".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: Some(1000),
            accept: false,
            verbose: true,
            progress: false,
            explain: false,
        };

        let result = atp_get(&args, &mut output);
        assert!(result.is_ok(), "atp get dry-run should succeed");

        output.flush().expect("flush output");
        let output_str = capture.contents();
        assert!(
            output_str.contains("Receive Plan:"),
            "should contain receive plan"
        );
        assert!(output_str.contains("decision"), "should show decision");
        assert!(
            output_str.contains("expected_bytes"),
            "should show expected bytes"
        );
    }

    #[test]
    fn atp_get_deny_policy_rejects_transfer() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_transfer, transfer_id) = temp_transfer_reference(b"deny transfer");
        let mut output = Output::with_writer(OutputFormat::Human, Vec::<u8>::new());

        let args = AtpGetArgs {
            transfer_id,
            destination: Some(temp.path().to_path_buf()),
            dry_run: false,
            policy: "deny".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };

        let result = atp_get(&args, &mut output);
        assert!(result.is_err(), "deny policy should reject transfer");

        let err = result.unwrap_err();
        assert_eq!(err.error_type, "receive_denied");
    }

    #[test]
    fn atp_get_json_output_contains_plan_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_transfer, transfer_id) = temp_transfer_reference(b"json transfer");
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Json, capture.clone());

        let args = AtpGetArgs {
            transfer_id,
            destination: Some(temp.path().to_path_buf()),
            dry_run: true,
            policy: "allow-listed".to_string(),
            allow_overwrite: true,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };

        let result = atp_get(&args, &mut output);
        assert!(result.is_ok(), "json output should succeed");

        output.flush().expect("flush output");
        let output_str = capture.contents();
        let json: serde_json::Value =
            serde_json::from_str(output_str.trim()).expect("output should be valid JSON");

        assert!(
            json.get("decision").is_some(),
            "should contain decision field"
        );
        assert!(
            json.get("sender_identity").is_some(),
            "should contain sender identity"
        );
        assert!(
            json.get("object_graph_summary").is_some(),
            "should contain object graph"
        );
        assert!(
            json.get("destination").is_some(),
            "should contain destination plan"
        );
        assert!(
            json.get("storage").is_some(),
            "should contain storage preflight"
        );
        assert!(
            json.get("plan_digest").is_some(),
            "should contain plan digest"
        );
    }

    #[test]
    fn atp_get_quarantine_policy_shows_appropriate_message() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_transfer, transfer_id) = temp_transfer_reference(b"quarantine transfer");
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());

        let args = AtpGetArgs {
            transfer_id,
            destination: Some(temp.path().to_path_buf()),
            dry_run: false,
            policy: "quarantine-only".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: true,
            verbose: false,
            progress: false,
            explain: false,
        };

        // The plan decision is reported honestly, but executing a pull is not
        // wired in v1, so the command must fail closed afterwards.
        let err = atp_get(&args, &mut output).expect_err("get execution must fail closed");
        assert_eq!(err.error_type, "atp_not_implemented");

        output.flush().expect("flush output");
        let output_str = capture.contents();
        assert!(
            output_str.contains("quarantined"),
            "should mention quarantine"
        );
    }

    #[test]
    fn parse_destination_policy_handles_all_variants() {
        let temp = tempfile::tempdir().expect("tempdir");

        // Test deny policy
        let deny_args = AtpGetArgs {
            transfer_id: "test".to_string(),
            destination: None,
            dry_run: true,
            policy: "deny".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };
        let policy = parse_destination_policy(&deny_args).expect("deny policy should parse");
        assert!(matches!(policy, DestinationPolicy::Deny));

        // Test allow-listed policy with flags
        let allow_args = AtpGetArgs {
            transfer_id: "test".to_string(),
            destination: Some(temp.path().to_path_buf()),
            dry_run: true,
            policy: "allow-listed".to_string(),
            allow_overwrite: true,
            allow_symlinks: true,
            allow_executables: true,
            max_bytes: Some(1000),
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };
        let policy =
            parse_destination_policy(&allow_args).expect("allow-listed policy should parse");
        if let DestinationPolicy::AllowListed {
            allow_overwrite,
            allow_symlinks,
            allow_executables,
            max_bytes,
            ..
        } = policy
        {
            assert!(allow_overwrite, "should allow overwrite");
            assert!(allow_symlinks, "should allow symlinks");
            assert!(allow_executables, "should allow executables");
            assert_eq!(max_bytes, Some(1000), "should set max bytes");
        } else {
            panic!("expected AllowListed policy");
        }

        // Test invalid policy
        let invalid_args = AtpGetArgs {
            transfer_id: "test".to_string(),
            destination: None,
            dry_run: true,
            policy: "invalid-policy".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };
        let result = parse_destination_policy(&invalid_args);
        assert!(result.is_err(), "invalid policy should error");
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "invalid_policy");
    }

    #[test]
    fn atp_get_args_parsing_works() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "atp",
            "get",
            "transfer-123",
            "/dest/path",
            "--dry-run",
            "--policy=allow-listed",
            "--allow-overwrite",
            "--allow-symlinks",
            "--max-bytes=500000",
            "--accept",
            "--verbose",
        ])
        .expect("valid args should parse");

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Get(args),
        }) = cli.command
        {
            assert_eq!(args.transfer_id, "transfer-123");
            assert_eq!(args.destination, Some(PathBuf::from("/dest/path")));
            assert!(args.dry_run);
            assert_eq!(args.policy, "allow-listed");
            assert!(args.allow_overwrite);
            assert!(args.allow_symlinks);
            assert_eq!(args.max_bytes, Some(500000));
            assert!(args.accept);
            assert!(args.verbose);
        } else {
            panic!("expected atp get command");
        }
    }

    #[test]
    fn atp_send_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "send",
            "/source/path",
            "peer:dest",
            "--dry-run",
            "--profile",
            "media",
            "--streams",
            "8",
            "--verbose",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Send(args),
        }) = cli.command
        {
            assert_eq!(args.source, PathBuf::from("/source/path"));
            assert_eq!(args.target, "peer:dest");
            assert!(args.dry_run);
            assert_eq!(args.profile, "media");
            assert_eq!(args.streams, 8);
            assert!(args.verbose);
        } else {
            panic!("expected atp send command");
        }
    }

    #[test]
    fn atp_sync_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "sync",
            "/source/dir",
            "peer:/target/dir",
            "--allow-updates",
            "--verbose",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Sync(args),
        }) = cli.command
        {
            assert_eq!(args.source, PathBuf::from("/source/dir"));
            assert_eq!(args.target, "peer:/target/dir");
            assert!(args.allow_updates);
            assert!(args.verbose);
        } else {
            panic!("expected atp sync command");
        }
    }

    #[test]
    fn atp_mirror_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "mirror",
            "/source/dir",
            "peer:/target/dir",
            "--allow-deletes",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Mirror(args),
        }) = cli.command
        {
            assert_eq!(args.source, PathBuf::from("/source/dir"));
            assert_eq!(args.target, "peer:/target/dir");
            assert!(args.allow_deletes);
            assert!(!args.verbose);
        } else {
            panic!("expected atp mirror command");
        }
    }

    #[test]
    fn atp_share_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "share",
            "/file/to/share",
            "--expires",
            "7200",
            "--max-downloads",
            "5",
            "--policy",
            "open",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Share(args),
        }) = cli.command
        {
            assert_eq!(args.source, PathBuf::from("/file/to/share"));
            assert_eq!(args.expires_seconds, 7200);
            assert_eq!(args.max_downloads, 5);
            assert_eq!(args.policy, "open");
        } else {
            panic!("expected atp share command");
        }
    }

    #[test]
    fn atp_inbox_list_parsing_works() {
        let cli = Cli::parse_from(["asupersync", "atp", "inbox", "list"]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Inbox(args),
        }) = cli.command
        {
            assert!(matches!(args.command, AtpInboxCommand::List));
        } else {
            panic!("expected atp inbox list command");
        }
    }

    #[test]
    fn atp_inbox_accept_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "inbox",
            "accept",
            "transfer-456",
            "/destination/path",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Inbox(args),
        }) = cli.command
        {
            if let AtpInboxCommand::Accept {
                transfer_id,
                destination,
            } = args.command
            {
                assert_eq!(transfer_id, "transfer-456");
                assert_eq!(destination, Some(PathBuf::from("/destination/path")));
            } else {
                panic!("expected inbox accept command");
            }
        } else {
            panic!("expected atp inbox command");
        }
    }

    #[test]
    fn atp_resume_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "resume",
            "transfer-789",
            "--force",
            "--verbose",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Resume(args),
        }) = cli.command
        {
            assert_eq!(args.transfer_id, "transfer-789");
            assert!(args.force);
            assert!(args.verbose);
        } else {
            panic!("expected atp resume command");
        }
    }

    #[test]
    fn atp_cancel_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "cancel",
            "transfer-abc",
            "--reason",
            "user_cancellation",
            "--force",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Cancel(args),
        }) = cli.command
        {
            assert_eq!(args.transfer_id, "transfer-abc");
            assert_eq!(args.reason, "user_cancellation");
            assert!(args.force);
        } else {
            panic!("expected atp cancel command");
        }
    }

    #[test]
    fn atp_send_output_format_works() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpSendArgs {
            source: PathBuf::from("Cargo.toml"),
            target: "peer:test".to_string(),
            dry_run: true,
            profile: "bulk".to_string(),
            streams: 4,
            verbose: false,
            progress: false,
            explain: false,
            allow_plaintext: false,
        };

        atp_send(&args, &mut output).expect("atp send should work");
    }

    #[test]
    fn atp_share_fails_closed_until_share_tokens_are_real() {
        use std::fs;

        // Create a temporary test file
        let test_file = "/tmp/atp_test_file";
        fs::write(test_file, "test content").expect("Failed to create test file");

        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpShareArgs {
            source: PathBuf::from(test_file),
            expires_seconds: 3600,
            max_downloads: 1,
            policy: "peers-only".to_string(),
            capabilities: vec!["read".to_string()],
            quota_bytes: 0,
            peer_id: None,
            destination_policy: "auto".to_string(),
            single_use: false,
            revocable: false,
        };

        // Nothing can redeem a locally minted share code; the command must not
        // fabricate one (br-asupersync-qk02uw).
        let err = atp_share(&args, &mut output).expect_err("atp share must fail closed");
        assert_eq!(err.error_type, "atp_not_implemented");

        // Clean up test file
        let _ = fs::remove_file(test_file);
    }

    #[test]
    fn atp_share_still_validates_capabilities_before_failing_closed() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpShareArgs {
            source: PathBuf::from("Cargo.toml"),
            expires_seconds: 3600,
            max_downloads: 1,
            policy: "peers-only".to_string(),
            capabilities: vec!["teleport".to_string()],
            quota_bytes: 0,
            peer_id: None,
            destination_policy: "auto".to_string(),
            single_use: false,
            revocable: false,
        };

        let err = atp_share(&args, &mut output).expect_err("invalid capability must error");
        assert_eq!(err.error_type, "invalid_argument");
    }

    #[test]
    fn atp_pair_initiate_fails_closed() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpPairArgs {
            command: AtpPairCommand::Initiate {
                peer_hint: Some("test_peer".to_string()),
                confirmation_method: "visual".to_string(),
                timeout_seconds: 300,
            },
        };

        // Pairing was pure security theater (locally fabricated session ids and
        // confirmation phrases, no peer contact); it must fail closed.
        let err = atp_pair(&args, &mut output).expect_err("pair initiate must fail closed");
        assert_eq!(err.error_type, "atp_not_implemented");
    }

    #[test]
    fn atp_pair_confirm_fails_closed() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpPairArgs {
            command: AtpPairCommand::Confirm {
                pairing_token: "atp://pair/pair_1234567890abcdef/method:visual/timeout:300"
                    .to_string(),
                confirmation_phrase: "Ocean Blue Mountain".to_string(),
            },
        };

        let err = atp_pair(&args, &mut output).expect_err("pair confirm must fail closed");
        assert_eq!(err.error_type, "atp_not_implemented");
    }

    #[test]
    fn atp_pair_list_fails_closed() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpPairArgs {
            command: AtpPairCommand::List { detailed: false },
        };

        let err = atp_pair(&args, &mut output).expect_err("pair list must fail closed");
        assert_eq!(err.error_type, "atp_not_implemented");
    }

    #[test]
    fn atp_seed_fails_closed() {
        use std::fs;

        // Create a temporary test file
        let test_file = "/tmp/atp_seed_test_file";
        fs::write(test_file, "seed test content").expect("Failed to create test file");

        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpSeedArgs {
            source: PathBuf::from(test_file),
            policy: "peers-only".to_string(),
            ttl_seconds: 3600,
            max_size_bytes: 0,
            priority: "normal".to_string(),
            relay_enabled: true,
            tags: vec!["test".to_string(), "fixture".to_string()],
            verify_integrity: true,
        };

        // Content seeding needs a running atpd cache/relay; reporting content
        // as seeded without one is fabrication.
        let err = atp_seed(&args, &mut output).expect_err("atp seed must fail closed");
        assert_eq!(err.error_type, "atp_not_implemented");

        // Clean up test file
        let _ = fs::remove_file(test_file);
    }

    #[test]
    fn atp_send_explain_fails_closed_before_touching_the_network() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpSendArgs {
            source: PathBuf::from("Cargo.toml"),
            target: "peer:destination".to_string(),
            dry_run: false,
            profile: "bulk".to_string(),
            streams: 4,
            verbose: false,
            progress: true,
            explain: true,
            allow_plaintext: false,
        };

        // --explain used to print hardcoded QUIC/RTT/loss numbers; until real
        // decision reporting exists it must fail closed, and it must do so
        // before any resolution/connection attempt (this target is bogus).
        let err = atp_send(&args, &mut output).expect_err("send --explain must fail closed");
        assert_eq!(err.error_type, "atp_not_implemented");
    }

    fn assert_atp_not_implemented(result: Result<(), CliError>, context: &str) {
        let err = result.expect_err(context);
        assert_eq!(err.error_type, "atp_not_implemented");
        assert!(
            err.title.contains("[ASUP-E701]"),
            "{context} should carry the operator-facing ASUP-E701 token"
        );
    }

    #[test]
    fn atp_sync_mirror_watch_fail_closed_instead_of_fake_success() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let sync = AtpSyncArgs {
            source: PathBuf::from("Cargo.toml"),
            target: "peer:/dst".to_string(),
            dry_run: false,
            allow_updates: true,
            verbose: true,
            progress: true,
            explain: false,
        };
        assert_atp_not_implemented(atp_sync(&sync, &mut output), "sync must fail closed");

        let mirror = AtpMirrorArgs {
            source: PathBuf::from("Cargo.toml"),
            target: "peer:/dst".to_string(),
            dry_run: false,
            allow_deletes: true,
            verbose: true,
            progress: true,
            explain: false,
        };
        assert_atp_not_implemented(atp_mirror(&mirror, &mut output), "mirror must fail closed");

        let watch = AtpWatchArgs {
            source: PathBuf::from("Cargo.toml"),
            target: "peer:/dst".to_string(),
            debounce_seconds: 1,
            mode: "sync-only".to_string(),
            verbose: true,
        };
        assert_atp_not_implemented(atp_watch(&watch, &mut output), "watch must fail closed");
    }

    #[test]
    fn atp_inbox_resume_cancel_status_and_bench_fail_closed() {
        let mut output = Output::new(OutputFormat::JsonPretty);

        let inbox_list = AtpInboxArgs {
            command: AtpInboxCommand::List,
        };
        assert_atp_not_implemented(
            atp_inbox(&inbox_list, &mut output),
            "inbox list must fail closed",
        );

        let inbox_accept = AtpInboxArgs {
            command: AtpInboxCommand::Accept {
                transfer_id: "transfer-123".to_string(),
                destination: Some(PathBuf::from("target/inbox")),
            },
        };
        assert_atp_not_implemented(
            atp_inbox(&inbox_accept, &mut output),
            "inbox accept must fail closed",
        );

        let resume = AtpResumeArgs {
            transfer_id: "transfer-123".to_string(),
            force: true,
            verbose: true,
        };
        assert_atp_not_implemented(atp_resume(&resume, &mut output), "resume must fail closed");

        let cancel = AtpCancelArgs {
            transfer_id: "transfer-123".to_string(),
            reason: "test".to_string(),
            force: true,
        };
        assert_atp_not_implemented(atp_cancel(&cancel, &mut output), "cancel must fail closed");

        let status = AtpTransferStatusArgs {
            transfer_id: Some("transfer-123".to_string()),
            explain: true,
            watch: false,
            interval_seconds: 1,
        };
        assert_atp_not_implemented(
            atp_transfer_status(&status, &mut output),
            "transfer-status must fail closed",
        );

        let bench = AtpBenchArgs {
            profile: "throughput".to_string(),
            duration_seconds: 1,
            output_dir: PathBuf::from("target/atp-bench-results"),
            concurrency: 1,
            transfer_size: 1024,
            detailed: true,
        };
        assert_atp_not_implemented(atp_bench(&bench, &mut output), "bench must fail closed");
    }

    /// asupersync-bi2462.128: `atp serve` used to create a directory literally
    /// named `~` in the working directory for its default `--data-dir ~/.atp`.
    #[test]
    fn atp_data_dir_tilde_resolves_from_home_not_the_working_directory() {
        let home = Path::new("/home/atp-user");
        let cli = Cli::parse_from(["asupersync", "atp", "serve"]);
        let Command::Atp(AtpArgs {
            command: AtpCommand::Serve(args),
        }) = cli.command
        else {
            panic!("expected atp serve");
        };
        assert_eq!(
            expand_home(&args.data_dir, Some(home)).expect("default expands"),
            home.join(".atp")
        );
        assert_eq!(
            expand_home(Path::new("~"), Some(home)).expect("bare tilde"),
            home.to_path_buf()
        );
        for unchanged in ["/srv/atp", "data/atp", "~alice/atp"] {
            assert_eq!(
                expand_home(Path::new(unchanged), Some(home)).expect("no expansion"),
                PathBuf::from(unchanged)
            );
        }
        let err = expand_home(Path::new("~/.atp"), None).expect_err("HOME unset");
        assert_eq!(err.error_type, "home_unset");
    }

    #[test]
    fn atp_serve_does_not_report_listening_when_bind_fails() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve test port");
        let listen = occupied.local_addr().expect("read local addr").to_string();
        let temp = tempfile::tempdir().expect("tempdir");
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        let args = AtpServeArgs {
            profile: "full".to_string(),
            listen,
            data_dir: temp.path().join("atp"),
            daemon: false,
            allow_plaintext: false,
        };

        let err = atp_serve(&args, &mut output).expect_err("occupied port must fail");

        assert_eq!(err.error_type, "atp_serve_bind_failed");
        assert!(
            capture.contents().is_empty(),
            "serve must not report listening before bind succeeds"
        );
    }

    /// asupersync-bi2462.126: the plaintext ATP-over-TCP listener is refused off
    /// loopback (including the default 0.0.0.0) unless the operator opts in, and the
    /// refusal happens before any directory is created or port is bound.
    #[test]
    fn atp_serve_refuses_plaintext_off_loopback_without_the_opt_in() {
        let temp = tempfile::tempdir().expect("tempdir");
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        let cli = Cli::parse_from(["asupersync", "atp", "serve"]);
        let Command::Atp(AtpArgs {
            command: AtpCommand::Serve(mut args),
        }) = cli.command
        else {
            panic!("expected atp serve");
        };
        assert_eq!(args.listen, "0.0.0.0:8080");
        assert!(!args.allow_plaintext);
        args.data_dir = temp.path().join("atp");

        let err = atp_serve(&args, &mut output).expect_err("default listen must be refused");
        assert_eq!(err.error_type, "atp_plaintext_refused");
        assert!(
            capture.contents().is_empty(),
            "nothing reported as listening"
        );
        assert!(
            !temp.path().join("atp").exists(),
            "refusal precedes creating the inbox directory"
        );

        let cli = Cli::parse_from(["asupersync", "atp", "serve", "--allow-plaintext"]);
        let Command::Atp(AtpArgs {
            command: AtpCommand::Serve(args),
        }) = cli.command
        else {
            panic!("expected atp serve");
        };
        assert!(args.allow_plaintext);
    }

    /// asupersync-bi2462.126: `asupersync atp send` is plaintext ATP-over-TCP too.
    /// A non-loopback target is refused before any connection unless opted in.
    #[test]
    fn atp_send_refuses_plaintext_off_loopback_without_the_opt_in() {
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        // TEST-NET-1 is unroutable: a send that got past the refusal would
        // block in connect instead of returning at once.
        let cli = Cli::parse_from(["asupersync", "atp", "send", "Cargo.toml", "192.0.2.1:9"]);
        let Command::Atp(AtpArgs {
            command: AtpCommand::Send(args),
        }) = cli.command
        else {
            panic!("expected atp send");
        };
        assert!(!args.allow_plaintext);

        let err = atp_send(&args, &mut output).expect_err("non-loopback target must be refused");
        assert_eq!(err.error_type, "atp_plaintext_refused");
        assert!(capture.contents().is_empty(), "nothing reported as sent");

        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "send",
            "Cargo.toml",
            "192.0.2.1:9",
            "--allow-plaintext",
        ]);
        let Command::Atp(AtpArgs {
            command: AtpCommand::Send(args),
        }) = cli.command
        else {
            panic!("expected atp send");
        };
        assert!(args.allow_plaintext);
    }

    /// asupersync-bi2462.73: `asupersync atp serve` and `asupersync atp send`
    /// move a real file over loopback through both handlers. `serve` reports
    /// the port it bound, so `--listen 127.0.0.1:0` is usable.
    #[test]
    fn atp_serve_and_send_move_a_file_over_loopback() {
        fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
            for entry in std::fs::read_dir(dir).ok()?.flatten() {
                let path = entry.path();
                let found = if path.is_dir() {
                    find_file(&path, name)
                } else {
                    path.file_name()
                        .is_some_and(|file| file == name)
                        .then_some(path)
                };
                if found.is_some() {
                    return found;
                }
            }
            None
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("payload.bin");
        let payload: Vec<u8> = (0..300_000u32)
            .map(|index| u8::try_from(index % 251).expect("below 251"))
            .collect();
        std::fs::write(&source, &payload).expect("write source");
        let data_dir = temp.path().join("atp");

        let serve_capture = SharedWrite::default();
        let serve_writer = serve_capture.clone();
        let serve_args = AtpServeArgs {
            profile: "full".to_string(),
            listen: "127.0.0.1:0".to_string(),
            data_dir: data_dir.clone(),
            daemon: false,
            allow_plaintext: false,
        };
        // The serve loop runs until the test process exits. Its own stop handle
        // keeps the CLI's SIGINT/SIGTERM handlers out of the test process
        // (br-asupersync-ylvfod).
        std::thread::spawn(move || {
            let mut output = Output::with_writer(OutputFormat::StreamJson, serve_writer);
            let stop = Arc::new(AtpServeStop::default());
            let _ = atp_serve_with_stop(&serve_args, &mut output, Some(stop));
        });
        let mut status = None;
        for _ in 0..1500 {
            let text = serve_capture.contents();
            if text.ends_with('\n') && text.contains("listen_address") {
                status = Some(text);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let status = status.expect("serve reports that it is listening within 30 s");
        let status: serde_json::Value =
            serde_json::from_str(status.trim()).expect("serve status is one JSON object");
        assert_eq!(status["message"], "listening", "{status}");
        let target = status["listen_address"]
            .as_str()
            .expect("listen address is a string")
            .to_string();
        let port = target
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .expect("listen address ends in a port");
        assert_ne!(port, 0, "serve must report the port it bound, got {target}");

        let send_capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::StreamJson, send_capture.clone());
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "send",
            source.to_str().expect("temp path is UTF-8"),
            &target,
        ]);
        let Command::Atp(AtpArgs {
            command: AtpCommand::Send(args),
        }) = cli.command
        else {
            panic!("expected atp send");
        };
        atp_send(&args, &mut output).expect("send to the loopback listener");
        let result: serde_json::Value = serde_json::from_str(send_capture.contents().trim())
            .expect("send result is one JSON object");
        assert_eq!(result["status"], "committed", "{result}");
        assert_eq!(result["committed"], true, "{result}");
        assert_eq!(result["sha_ok"], true, "{result}");
        assert_eq!(result["merkle_ok"], true, "{result}");
        assert_eq!(result["files"], 1, "{result}");
        assert_eq!(result["bytes_sent"], payload.len(), "{result}");

        let received = find_file(&data_dir.join("inbox"), "payload.bin")
            .expect("the committed file is under the serve inbox");
        let bytes = std::fs::read(&received).expect("read the committed file");
        assert!(
            bytes == payload,
            "{} holds {} bytes that differ from the {}-byte source",
            received.display(),
            bytes.len(),
            payload.len()
        );
    }

    /// asupersync-ylvfod: a stop request cancels the serve loop, which returns
    /// Ok and reports `stopped` after `listening`, without signals.
    #[test]
    fn atp_serve_stop_request_ends_the_loop_with_a_stopped_status() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let data_dir = std::env::temp_dir().join(format!(
            "asupersync-atp-serve-stop-{}-{nanos}",
            std::process::id()
        ));
        let capture = SharedWrite::default();
        let writer = capture.clone();
        let stop = Arc::new(AtpServeStop::default());
        let serve_stop = Arc::clone(&stop);
        let args = AtpServeArgs {
            profile: "full".to_string(),
            listen: "127.0.0.1:0".to_string(),
            data_dir: data_dir.clone(),
            daemon: false,
            allow_plaintext: false,
        };
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut output = Output::with_writer(OutputFormat::StreamJson, writer);
            let _ = done_tx.send(atp_serve_with_stop(&args, &mut output, Some(serve_stop)));
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !capture.contents().ends_with('\n') {
            assert!(
                std::time::Instant::now() < deadline,
                "serve did not report listening within 30 s"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        stop.request();
        let result = done_rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("serve returns within 20 s of the stop request");
        let error = result.err().map(|error| (error.error_type, error.detail));
        assert_eq!(error, None, "a requested stop is a clean exit");
        let lines: Vec<serde_json::Value> = capture
            .contents()
            .lines()
            .map(|line| serde_json::from_str(line).expect("status line is JSON"))
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0]["message"], "listening", "{lines:?}");
        assert_eq!(lines[1]["message"], "stopped", "{lines:?}");
        assert_eq!(lines[0]["listen_address"], lines[1]["listen_address"]);
        let inbox: Vec<_> = std::fs::read_dir(data_dir.join("inbox"))
            .expect("serve created its inbox")
            .collect();
        assert!(inbox.is_empty(), "an idle stop leaves the inbox empty");
    }

    #[test]
    fn atp_transfer_status_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "transfer-status",
            "transfer-123",
            "--explain",
            "--watch",
            "--interval",
            "5",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::TransferStatus(args),
        }) = cli.command
        {
            assert_eq!(args.transfer_id, Some("transfer-123".to_string()));
            assert!(args.explain);
            assert!(args.watch);
            assert_eq!(args.interval_seconds, 5);
        } else {
            panic!("expected atp transfer-status command");
        }
    }

    #[test]
    fn atp_progress_update_formatting_works() {
        // 512 KiB of 1 MiB — binary units, received printed once, then total.
        let progress = AtpProgressUpdate::new("test_123", "file.dat", 524_288, 1_048_576);
        let human_output = progress.human_format();

        assert!(human_output.contains("receiving"));
        assert!(human_output.contains("file.dat"));
        assert!(human_output.contains("512.0 KB"));
        assert!(human_output.contains("1.0 MB"));
        assert!(human_output.contains("50%"));
    }

    #[test]
    fn atp_explain_report_structure_works() {
        let explain = AtpExplainReport::new("test_explain");
        let human_output = explain.human_format();

        assert!(human_output.contains("Explain Report"));
        assert!(human_output.contains("Path:"));
        assert!(human_output.contains("Scheduler:"));
        assert!(human_output.contains("Repair:"));
        assert!(human_output.contains("Disk:"));
    }

    #[test]
    fn format_bytes_function_works() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn progress_bar_creation_works() {
        assert_eq!(create_progress_bar(0), "░".repeat(20));
        assert_eq!(
            create_progress_bar(50),
            format!("{}{}", "█".repeat(10), "░".repeat(10))
        );
        assert_eq!(create_progress_bar(100), "█".repeat(20));
    }

    #[test]
    fn progress_chunks_handles_u64_max_without_overflow() {
        let chunks = progress_chunks(u64::MAX);

        assert_eq!(chunks[0], 0);
        assert_eq!(chunks[1], u64::MAX / 4);
        assert_eq!(chunks[2], u64::MAX / 2);
        assert_eq!(
            chunks[3],
            u64::try_from((u128::from(u64::MAX) * 3) / 4).unwrap()
        );
        assert_eq!(chunks[4], u64::MAX);
    }

    #[test]
    fn atp_progress_percentage_handles_large_values() {
        let progress = AtpProgressUpdate::new("large", "huge.bin", u64::MAX, u64::MAX);

        assert!(progress.human_format().contains("100%"));
    }

    #[test]
    fn progress_bar_clamps_overfull_percentages() {
        assert_eq!(create_progress_bar(101), "█".repeat(20));
        assert_eq!(create_progress_bar(u8::MAX), "█".repeat(20));
    }

    #[test]
    fn atp_share_revocation_url_handles_short_share_codes() {
        let args = AtpShareArgs {
            source: PathBuf::from("short"),
            expires_seconds: 60,
            max_downloads: 1,
            policy: "peers-only".to_string(),
            capabilities: vec!["read".to_string()],
            quota_bytes: 0,
            peer_id: None,
            destination_policy: "auto".to_string(),
            single_use: false,
            revocable: true,
        };
        let output = AtpShareOutput::new(&args, "short".to_string());

        assert!(
            output
                .revocation_url
                .as_deref()
                .is_some_and(|url| url.starts_with("atp://revoke/"))
        );
    }

    #[test]
    fn atp_bench_fails_closed_without_writing_model_results() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output_dir = temp.path().join("atp-bench-results");
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpBenchArgs {
            profile: "throughput".to_string(),
            duration_seconds: 1,
            output_dir: output_dir.clone(),
            concurrency: 2,
            transfer_size: 1024,
            detailed: true,
        };

        let err = atp_bench(&args, &mut output).expect_err("atp bench must fail closed");

        assert_eq!(err.error_type, "atp_not_implemented");
        assert!(
            !output_dir.exists(),
            "model-derived benchmark reports must not be written"
        );
    }

    #[test]
    fn benchmark_profiles_keep_zero_duration_throughput_finite() {
        for profile in ["throughput", "latency", "repair", "stress", "mixed"] {
            let result = AtpBenchResults::for_profile(profile, 0, 8, u64::MAX, false);

            assert_eq!(result.throughput_mbps, 0.0);
            assert!(result.throughput_mbps.is_finite());
        }
    }

    #[test]
    fn timeline_window_rejects_negative_bounds() {
        assert!(parse_timeline_window_nanos(Some("-1:5")).is_err());
        assert!(parse_timeline_window_nanos(Some("1:-5")).is_err());
    }

    #[test]
    fn csv_escape_field_uses_rfc_compatible_quotes() {
        assert_eq!(csv_escape_field("plain"), "plain");
        assert_eq!(csv_escape_field("a,b"), "\"a,b\"");
        assert_eq!(csv_escape_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_escape_field("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn atp_transfer_status_fails_closed_without_daemon_state() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpTransferStatusArgs {
            transfer_id: None,
            explain: false,
            watch: false,
            interval_seconds: 2,
        };

        // There is no daemon connection to query, so printing an (always
        // empty) transfer list would be fabricated status.
        let err =
            atp_transfer_status(&args, &mut output).expect_err("transfer status must fail closed");
        assert_eq!(err.error_type, "atp_not_implemented");
    }
