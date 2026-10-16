    use super::*;
    use crate::test_logging::{Interest, TestLogLevel};
    use std::time::Duration;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_ndjson_event_from_task_spawn() {
        init_test("test_ndjson_event_from_task_spawn");
        let record = LogRecord {
            elapsed: Duration::from_micros(1234),
            event: TestEvent::TaskSpawn {
                task_id: 42,
                name: Some("worker".into()),
            },
        };
        let ctx = TestContext::new("ndjson_test", 0xDEAD_BEEF).with_subsystem("scheduler");

        let ndjson = NdjsonEvent::from_record(&record, Some(&ctx));
        assert_eq!(ndjson.v, NDJSON_SCHEMA_VERSION);
        assert_eq!(ndjson.ts_us, 1234);
        assert_eq!(ndjson.level, "INFO");
        assert_eq!(ndjson.category, "task");
        assert_eq!(ndjson.event, "TaskSpawn");
        assert_eq!(ndjson.test_id.as_deref(), Some("ndjson_test"));
        assert_eq!(ndjson.seed, Some(0xDEAD_BEEF));
        assert_eq!(ndjson.subsystem.as_deref(), Some("scheduler"));
        assert_eq!(
            ndjson
                .data
                .get("task_id")
                .and_then(serde_json::Value::as_u64),
            Some(42)
        );
        assert_eq!(
            ndjson.data.get("name").and_then(|v| v.as_str()),
            Some("worker")
        );

        // Verify it produces valid JSON
        let json_line = ndjson.to_json_line();
        let parsed: serde_json::Value = serde_json::from_str(&json_line).expect("valid JSON");
        assert_eq!(parsed["v"], 1);
        assert_eq!(parsed["event"], "TaskSpawn");
        crate::test_complete!("test_ndjson_event_from_task_spawn");
    }

    #[test]
    fn test_ndjson_event_without_context() {
        init_test("test_ndjson_event_without_context");
        let record = LogRecord {
            elapsed: Duration::from_millis(5),
            event: TestEvent::ReactorPoll {
                timeout: None,
                events_returned: 3,
                duration: Duration::from_micros(100),
            },
        };

        let ndjson = NdjsonEvent::from_record(&record, None);
        assert!(ndjson.test_id.is_none());
        assert!(ndjson.seed.is_none());
        assert!(ndjson.subsystem.is_none());
        assert_eq!(ndjson.category, "reactor");
        assert_eq!(ndjson.event, "ReactorPoll");

        let json_line = ndjson.to_json_line();
        let parsed: serde_json::Value = serde_json::from_str(&json_line).expect("valid JSON");
        assert!(parsed.get("test_id").is_none());
        assert!(parsed.get("seed").is_none());
        crate::test_complete!("test_ndjson_event_without_context");
    }

    #[test]
    fn test_ndjson_logger_captures_and_exports() {
        init_test("test_ndjson_logger_captures_and_exports");
        let ctx = TestContext::new("ndjson_export", 0x42).with_subsystem("io");
        let logger = NdjsonLogger::enabled(TestLogLevel::Trace, Some(ctx));

        logger.log(TestEvent::IoRead {
            token: 5,
            bytes: 1024,
            would_block: false,
        });
        logger.log(TestEvent::IoWrite {
            token: 5,
            bytes: 512,
            would_block: false,
        });
        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });

        let ndjson_output = logger.to_ndjson();
        let lines: Vec<&str> = ndjson_output.trim().lines().collect();
        assert_eq!(lines.len(), 3, "should have 3 NDJSON lines");

        // Verify each line is valid JSON with correct schema version
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            assert_eq!(parsed["v"], 1);
            assert_eq!(parsed["test_id"], "ndjson_export");
            assert_eq!(parsed["seed"], 0x42);
        }

        // Verify event ordering
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "IoRead");
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["event"], "IoWrite");
        crate::test_complete!("test_ndjson_logger_captures_and_exports");
    }

    #[test]
    fn test_trace_file_naming() {
        init_test("test_trace_file_naming");
        assert_eq!(
            trace_file_name("scheduler", "cancel_drain", 0xDEAD_BEEF),
            "scheduler_cancel_drain_00000000deadbeef.trace"
        );
        assert_eq!(
            ndjson_file_name("obligation", "leak_check", 42),
            "obligation_leak_check_000000000000002a.ndjson"
        );
        crate::test_complete!("test_trace_file_naming");
    }

    #[test]
    fn test_artifact_bundle_dir_layout() {
        init_test("test_artifact_bundle_dir_layout");
        let base = std::path::Path::new("/tmp/test-artifacts");
        let dir = artifact_bundle_dir(base, "cancel_test", 0xCAFE);
        assert_eq!(
            dir,
            std::path::PathBuf::from("/tmp/test-artifacts/cancel_test/000000000000cafe")
        );
        crate::test_complete!("test_artifact_bundle_dir_layout");
    }

    #[test]
    #[allow(unsafe_code)]
    fn test_write_artifact_bundle_roundtrip() {
        init_test("test_write_artifact_bundle_roundtrip");

        let _guard = crate::test_utils::env_lock();
        let tmp = tempfile::TempDir::new().expect("create temp dir");
        // SAFETY: tests serialize env access with test_utils::env_lock.
        unsafe { std::env::set_var("ASUPERSYNC_TEST_ARTIFACTS_DIR", tmp.path()) };

        let ctx = TestContext::new("bundle_test", 0xBEEF)
            .with_subsystem("scheduler")
            .with_invariant("quiescence");

        let logger = NdjsonLogger::enabled(TestLogLevel::Info, Some(ctx.clone()));
        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: Some("test_task".into()),
        });
        logger.log(TestEvent::TaskComplete {
            task_id: 1,
            outcome: "ok",
        });

        let manifest = ReproManifest::from_context(&ctx, true)
            .with_env_snapshot()
            .with_phases(vec!["setup".to_string(), "exercise".to_string()]);

        let bundle_path =
            write_artifact_bundle(&manifest, Some(&logger), None).expect("write bundle");

        // Verify files exist
        assert!(bundle_path.join("manifest.json").exists());
        assert!(bundle_path.join("events.ndjson").exists());

        // Verify manifest content
        let manifest_str = std::fs::read_to_string(bundle_path.join("manifest.json")).unwrap();
        let loaded: ReproManifest = serde_json::from_str(&manifest_str).unwrap();
        assert_eq!(loaded.seed, 0xBEEF);
        assert_eq!(loaded.scenario_id, "bundle_test");
        assert!(loaded.passed);

        // Verify NDJSON content
        let ndjson_str = std::fs::read_to_string(bundle_path.join("events.ndjson")).unwrap();
        let lines: Vec<&str> = ndjson_str.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "TaskSpawn");

        // SAFETY: tests serialize env access with test_utils::env_lock.
        unsafe { std::env::remove_var("ASUPERSYNC_TEST_ARTIFACTS_DIR") };
        crate::test_complete!("test_write_artifact_bundle_roundtrip");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_all_event_types_produce_valid_ndjson() {
        init_test("test_all_event_types_produce_valid_ndjson");
        let events = vec![
            TestEvent::ReactorPoll {
                timeout: None,
                events_returned: 0,
                duration: Duration::from_micros(10),
            },
            TestEvent::ReactorWake { source: "waker" },
            TestEvent::ReactorRegister {
                token: 1,
                interest: Interest {
                    readable: true,
                    writable: false,
                },
                source_type: "tcp",
            },
            TestEvent::ReactorDeregister { token: 1 },
            TestEvent::IoRead {
                token: 1,
                bytes: 100,
                would_block: false,
            },
            TestEvent::IoWrite {
                token: 2,
                bytes: 200,
                would_block: true,
            },
            TestEvent::IoConnect {
                addr: "127.0.0.1:8080".into(),
                result: "success",
            },
            TestEvent::IoAccept {
                local: "0.0.0.0:9090".into(),
                peer: "192.168.1.1:54321".into(),
            },
            TestEvent::WakerWake {
                token: 10,
                task_id: 1,
            },
            TestEvent::WakerClone { token: 11 },
            TestEvent::WakerDrop { token: 12 },
            TestEvent::TaskPoll {
                task_id: 1,
                result: "ready",
            },
            TestEvent::TaskSpawn {
                task_id: 2,
                name: Some("bg".into()),
            },
            TestEvent::TaskComplete {
                task_id: 1,
                outcome: "ok",
            },
            TestEvent::TimerScheduled {
                deadline: Duration::from_secs(5),
                task_id: 99,
            },
            TestEvent::TimerFired { task_id: 99 },
            TestEvent::RegionCreate {
                region_id: 1,
                parent_id: Some(0),
            },
            TestEvent::RegionStateChange {
                region_id: 1,
                from_state: "open",
                to_state: "closing",
            },
            TestEvent::RegionClose {
                region_id: 1,
                task_count: 3,
                duration: Duration::from_millis(100),
            },
            TestEvent::ObligationCreate {
                obligation_id: 50,
                kind: "permit",
                holder_id: 1,
            },
            TestEvent::ObligationResolve {
                obligation_id: 50,
                resolution: "commit",
            },
            TestEvent::Custom {
                category: "test",
                message: "hello".into(),
            },
            TestEvent::Error {
                category: "test",
                message: "oops".into(),
            },
            TestEvent::Warn {
                category: "test",
                message: "hmm".into(),
            },
        ];

        for event in events {
            let record = LogRecord {
                elapsed: Duration::from_micros(100),
                event,
            };
            let ndjson = NdjsonEvent::from_record(&record, None);
            let line = ndjson.to_json_line();
            let _parsed: serde_json::Value =
                serde_json::from_str(&line).expect("all events must produce valid JSON");
        }
        crate::test_complete!("test_all_event_types_produce_valid_ndjson");
    }
