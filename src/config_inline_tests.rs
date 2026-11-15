    use super::*;

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct SampleDocumentConfig {
        zeta: u32,
        alpha: String,
        freeform: serde_json::Value,
    }

    #[test]
    fn versioned_config_document_has_recursive_canonical_golden() {
        let mut freeform = serde_json::Map::new();
        freeform.insert("z".to_owned(), serde_json::json!(2));
        freeform.insert("a".to_owned(), serde_json::json!([{"y": 1, "b": 2}]));
        let document = VersionedConfigDocument::new(SampleDocumentConfig {
            zeta: 9,
            alpha: "first".to_owned(),
            freeform: serde_json::Value::Object(freeform),
        });

        assert_eq!(
            document.to_canonical_json().expect("canonical JSON"),
            r#"{"config":{"alpha":"first","freeform":{"a":[{"b":2,"y":1}],"z":2},"zeta":9},"schema_version":1}"#
        );
    }

    #[test]
    fn versioned_config_document_migrates_missing_v1_and_ignores_unknown_fields() {
        let document = VersionedConfigDocument::<SampleDocumentConfig>::from_json(
            r#"{
                "future_envelope_field": "ignored",
                "config": {
                    "zeta": 9,
                    "alpha": "first",
                    "freeform": {},
                    "future_config_field": true
                }
            }"#,
        )
        .expect("missing schema version must migrate to v1");

        assert_eq!(document.schema_version, CONFIG_DOCUMENT_SCHEMA_VERSION);
        assert_eq!(document.config.zeta, 9);
        assert!(!document.to_canonical_json().unwrap().contains("future_"));
    }

    #[test]
    fn versioned_config_document_rejects_unsupported_schema_on_read_and_write() {
        let read_error = VersionedConfigDocument::<SampleDocumentConfig>::from_json(
            r#"{"schema_version":2,"config":{"zeta":9,"alpha":"first","freeform":{}}}"#,
        )
        .expect_err("unsupported input schema must fail closed");
        assert!(matches!(
            read_error,
            ConfigDocumentError::UnsupportedSchemaVersion {
                observed: 2,
                supported: 1
            }
        ));

        let mut document = VersionedConfigDocument::new(SampleDocumentConfig {
            zeta: 9,
            alpha: "first".to_owned(),
            freeform: serde_json::json!({}),
        });
        document.schema_version = 2;
        assert!(matches!(
            document.to_canonical_json(),
            Err(ConfigDocumentError::UnsupportedSchemaVersion {
                observed: 2,
                supported: 1
            })
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(any(not(feature = "slim-runtime-profile"), feature = "service-protocols"))]
    mod native_server_config_tests {
        use super::*;
        use std::net::SocketAddr;

        #[test]
        fn server_config_default_valid() {
            let config = ServerConfig::default();
            assert!(config.validate().is_ok());
        }

        #[test]
        fn server_config_profiles_valid() {
            for profile in [
                ServerProfile::Development,
                ServerProfile::Testing,
                ServerProfile::Production,
            ] {
                let config = ServerConfig::from_profile(profile);
                assert!(config.validate().is_ok(), "Profile {profile:?} invalid");
            }
        }

        #[test]
        fn server_config_builder() {
            let config = ServerConfig::default()
                .bind_addr(SocketAddr::from(([127, 0, 0, 1], 9090)))
                .shutdown_timeout(Duration::from_secs(60))
                .worker_threads(Some(4));

            assert_eq!(config.bind_addr.port(), 9090);
            assert_eq!(config.shutdown_timeout, Duration::from_secs(60));
            assert_eq!(config.worker_threads, Some(4));
            assert!(config.validate().is_ok());
        }

        #[test]
        fn server_config_validation_errors() {
            let config = ServerConfig::default().shutdown_timeout(Duration::from_millis(10));
            assert!(matches!(
                config.validate(),
                Err(ConfigError::TimeoutTooShort)
            ));

            let config = ServerConfig::default().worker_threads(Some(0));
            assert!(matches!(
                config.validate(),
                Err(ConfigError::InvalidParallelism)
            ));
        }

        #[test]
        fn server_config_testing_profile() {
            let config = ServerConfig::from_profile(ServerProfile::Testing);
            assert_eq!(config.bind_addr.port(), 0); // OS-assigned port
            assert_eq!(config.worker_threads, Some(1));
            assert_eq!(config.listener.max_connections, Some(10));
        }

        #[test]
        fn server_config_production_profile() {
            let config = ServerConfig::from_profile(ServerProfile::Production);
            assert_eq!(config.bind_addr.port(), 8080);
            assert_eq!(config.listener.max_connections, Some(50_000));
            assert_eq!(config.http.max_body_size, 8 * 1024 * 1024);
        }

        #[test]
        fn server_config_resolves_http_and_shutdown_precedence_without_mutating_inputs() {
            fn clock() -> crate::types::Time {
                crate::types::Time::from_nanos(73)
            }

            let config = ServerConfig::default()
                .http(
                    Http1Config::default()
                        .max_body_size(123)
                        .max_headers_size(456)
                        .keep_alive(false)
                        .max_requests(Some(7)),
                )
                .listener(
                    Http1ListenerConfig::default()
                        .http_config(Http1Config::default().max_body_size(999))
                        .max_connections(Some(3))
                        .drain_timeout(Duration::from_secs(9))
                        .hard_drain_timeout(Duration::from_secs(20))
                        .lb_compat_keep_socket(true)
                        .time_getter(clock),
                )
                .shutdown_timeout(Duration::from_secs(4));

            let resolved = config.listener_config().expect("valid server config");
            assert_eq!(resolved.http_config.max_body_size, 123);
            assert_eq!(resolved.http_config.max_headers_size, 456);
            assert_eq!(resolved.http_config.max_requests_per_connection, Some(7));
            assert!(!resolved.http_config.keep_alive);
            assert_eq!(resolved.max_connections, Some(3));
            assert!(resolved.lb_compat_keep_socket);
            assert_eq!((resolved.time_getter)(), clock());
            assert_eq!(resolved.drain_timeout, Duration::from_secs(4));
            assert_eq!(resolved.hard_drain_timeout, Duration::from_secs(4));
            assert_eq!(config.listener.http_config.max_body_size, 999);
            assert_eq!(config.listener.drain_timeout, Duration::from_secs(9));
            assert_eq!(config.listener.hard_drain_timeout, Duration::from_secs(20));

            let shorter_soft = config.listener(
                Http1ListenerConfig::default().drain_timeout(Duration::from_secs(1)),
            );
            let resolved = shorter_soft.listener_config().unwrap();
            assert_eq!(resolved.drain_timeout, Duration::from_secs(1));
            assert_eq!(resolved.hard_drain_timeout, Duration::from_secs(4));
        }

        #[test]
        fn server_config_binding_refuses_invalid_or_unauthorized_contexts() {
            use crate::cx::{Cx, cap};
            use crate::http::h1::types::Response;

            let runtime = crate::runtime::RuntimeBuilder::current_thread()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let cx = Cx::current().expect("runtime context");
                // Occupy a concrete address: invalid configuration must be
                // rejected before the bind can instead report AddrInUse.
                let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let invalid = ServerConfig::default()
                    .bind_addr(occupied.local_addr().unwrap())
                    .worker_threads(Some(0));
                assert!(matches!(
                    invalid.runtime_builder(),
                    Err(ConfigError::InvalidParallelism)
                ));
                assert!(matches!(
                    invalid.listener_config(),
                    Err(ConfigError::InvalidParallelism)
                ));
                let result = invalid
                    .bind_http1(&cx, |_| async { Response::new(200, "OK", Vec::new()) })
                    .await;
                assert_eq!(
                    result.err().expect("invalid config").kind(),
                    std::io::ErrorKind::InvalidInput
                );

                let config = ServerConfig::from_profile(ServerProfile::Testing);
                let restricted = cx.restrict::<cap::None>();
                let result = config
                    .bind_http1(&restricted, |_| async { Response::new(200, "OK", Vec::new()) })
                    .await;
                let error = result.err().expect("explicit context must control binding");
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(
                    error.get_ref().unwrap().downcast_ref::<crate::cx::IoCapabilityDenied>().is_some()
                );

                let cancelled = Cx::for_testing();
                cancelled.set_cancel_requested(true);
                let result = config
                    .bind_http1(&cancelled, |_| async { Response::new(200, "OK", Vec::new()) })
                    .await;
                assert_eq!(
                    result.err().expect("cancelled binding").kind(),
                    std::io::ErrorKind::Interrupted
                );
                assert!(crate::cx::io_gate::require_ambient_io("test after refusal").is_ok());
            });
        }

        #[test]
        fn server_config_native_listener_enforces_http_limits_and_drains() {
            use crate::cx::Cx;
            use crate::http::h1::server::HostPolicy;
            use crate::http::h1::types::Response;
            use crate::io::{AsyncReadExt, AsyncWriteExt};
            use crate::net::tcp::stream::TcpStream;
            use crate::sync::atomic::{AtomicUsize, Ordering};
            use std::sync::Arc;

            for workers in [1, 2] {
                let config = ServerConfig::from_profile(ServerProfile::Testing)
                    .worker_threads(Some(workers))
                    .http(
                        Http1Config::default()
                            .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                            .max_body_size(3)
                            .keep_alive(false),
                    );
                let runtime = config
                    .runtime_builder()
                    .unwrap()
                    .build()
                    .expect("server runtime");
                assert_eq!(runtime.config().worker_threads, workers);
                let runtime_handle = runtime.handle();
                runtime.block_on(async {
                    let cx = Cx::current().expect("runtime context");
                    let calls = Arc::new(AtomicUsize::new(0));
                    let handler_calls = Arc::clone(&calls);
                    let listener = config
                        .bind_http1(&cx, move |_request| {
                            handler_calls.fetch_add(1, Ordering::SeqCst);
                            async { Response::new(200, "OK", b"accepted".to_vec()) }
                        })
                        .await
                        .expect("configured bind");
                    let address = listener.local_addr().unwrap();
                    assert_eq!(address.ip(), config.bind_addr.ip());
                    assert_ne!(address.port(), 0);
                    let manager = listener.connection_manager().clone();
                    let shutdown = listener.shutdown_signal();
                    let serving = runtime_handle
                        .try_spawn(async move {
                            let serving_cx = Cx::current().expect("serving context");
                            listener.run_owned_in(&serving_cx).await
                        })
                        .expect("listener task");

                    let requests: [(&[u8], &[u8]); 3] = [
                        (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc", b"HTTP/1.1 200"),
                        (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd", b"HTTP/1.1 413"),
                        (b"GET / HTTP/1.1\r\nHost: forbidden.example\r\nConnection: close\r\n\r\n", b"HTTP/1.1 421"),
                    ];
                    for (request, status) in requests {
                        let response = crate::time::timeout(cx.now(), Duration::from_secs(5), async {
                            let mut stream = TcpStream::connect(address).await.expect("connect");
                            stream.write_all(request).await.expect("request");
                            let mut response = Vec::new();
                            stream.read_to_end(&mut response).await.expect("response");
                            response
                        })
                        .await
                        .expect("bounded response");
                        assert!(
                            response.starts_with(status),
                            "workers={workers}: {}",
                            String::from_utf8_lossy(&response)
                        );
                    }
                    assert_eq!(
                        calls.load(Ordering::SeqCst),
                        1,
                        "refusals must not reach the handler"
                    );
                    assert!(shutdown.begin_drain(config.shutdown_timeout));
                    let stats = crate::time::timeout(cx.now(), Duration::from_secs(5), serving)
                        .await
                        .expect("bounded listener drain")
                        .expect("listener result");
                    assert_eq!(stats.force_closed, 0);
                    assert_eq!(manager.active_count(), 0);
                    assert_eq!(shutdown.phase(), crate::server::shutdown::ShutdownPhase::Stopped);
                });
            }
        }

        #[test]
        fn server_profile_debug_clone_copy_eq() {
            let p = ServerProfile::Development;
            let cloned = p;
            let copied = p;
            assert_eq!(cloned, copied);
            assert_ne!(p, ServerProfile::Production);
        }

        #[test]
        fn server_config_debug_clone() {
            let config = ServerConfig::default();
            let dbg = format!("{config:?}");
            assert!(dbg.contains("ServerConfig"));

            let cloned = config.clone();
            assert_eq!(cloned.bind_addr, config.bind_addr);
        }
    }

    #[test]
    fn default_config_valid() {
        let config = RaptorQConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn profile_configs_valid() {
        for profile in [
            RuntimeProfile::Development,
            RuntimeProfile::Testing,
            RuntimeProfile::Staging,
            RuntimeProfile::Production,
            RuntimeProfile::HighThroughput,
            RuntimeProfile::LowLatency,
        ] {
            let config = profile.to_config();
            assert!(config.validate().is_ok(), "Profile {profile:?} invalid");
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn env_override_symbol_size() {
        let _guard = crate::test_utils::env_lock();
        // SAFETY: tests serialize env access with test_utils::env_lock.
        unsafe { std::env::set_var("RAPTORQ_ENCODING_SYMBOL_SIZE", "512") };
        let config = ConfigLoader::default().load().unwrap();
        assert_eq!(config.encoding.symbol_size, 512);
        // SAFETY: tests serialize env access with test_utils::env_lock.
        unsafe { std::env::remove_var("RAPTORQ_ENCODING_SYMBOL_SIZE") };
    }

    #[test]
    fn file_loading_minimal() {
        let input = r"
[encoding]
symbol_size = 512
repair_overhead = 1.2

[timeouts]
default_timeout_ms = 5000
";
        let base = RuntimeProfile::Development.to_config();
        let config = parse_config(input, base).unwrap();
        assert_eq!(config.encoding.symbol_size, 512);
        assert!((config.encoding.repair_overhead - 1.2).abs() < f64::EPSILON);
        assert_eq!(config.timeouts.default_timeout, Duration::from_secs(5));
    }

    fn runtime_config_toml_fixture() -> &'static str {
        r#"
[encoding]
repair_overhead = 1.25
max_block_size = 4096
symbol_size = 512
encoding_parallelism = 3
decoding_parallelism = 5

[transport]
max_paths = 3
health_check_interval_ms = 2500
dead_path_backoff_initial_ms = 125
dead_path_backoff_max_ms = 5000
dead_path_backoff_multiplier = 1.75
max_symbols_in_flight = 64
path_strategy = "latency_weighted"
experiment_gate = "multipath_preview"
coding_policy = "raptorq_fec_preview"

[resources]
max_symbol_buffer_memory = 2097152
max_encoding_ops = 6
max_decoding_ops = 7
symbol_pool_size = 128

[timeouts]
default_timeout_ms = 5000
encoding_timeout_ms = 6000
decoding_timeout_ms = 7000
path_timeout_ms = 8000
quorum_timeout_ms = 9000

[observability]
log_level = "warn"
trace_all_symbols = false
sample_rate = 0.25
max_spans = 33
max_log_entries = 44
include_timestamps = false
metrics_enabled = true

[security]
auth_mode = "permissive"
auth_key_seed = 12345
reject_unauthenticated = false
"#
    }

    fn duration_ms(duration: Duration) -> u64 {
        u64::try_from(duration.as_millis()).expect("test durations fit u64")
    }

    fn path_strategy_toml_value(strategy: &PathSelectionStrategy) -> &'static str {
        match strategy {
            PathSelectionStrategy::RoundRobin => "round_robin",
            PathSelectionStrategy::LatencyWeighted => "latency_weighted",
            PathSelectionStrategy::Adaptive(_) => "adaptive",
            PathSelectionStrategy::Random => "random",
        }
    }

    fn experiment_gate_toml_value(gate: ExperimentalTransportGate) -> &'static str {
        match gate {
            ExperimentalTransportGate::Disabled => "disabled",
            ExperimentalTransportGate::MultipathPreview => "multipath_preview",
        }
    }

    fn coding_policy_toml_value(policy: TransportCodingPolicy) -> &'static str {
        match policy {
            TransportCodingPolicy::Disabled => "disabled",
            TransportCodingPolicy::RaptorQFecPreview => "raptorq_fec_preview",
            TransportCodingPolicy::RlncPreview => "rlnc_preview",
        }
    }

    fn auth_mode_toml_value(mode: AuthMode) -> &'static str {
        match mode {
            AuthMode::Strict => "strict",
            AuthMode::Permissive => "permissive",
            AuthMode::Disabled => "disabled",
        }
    }

    #[allow(clippy::too_many_lines)]
    fn render_runtime_config_toml_for_snapshot(config: &RaptorQConfig) -> String {
        format!(
            "[encoding]\n\
             repair_overhead = {:.2}\n\
             max_block_size = {}\n\
             symbol_size = {}\n\
             encoding_parallelism = {}\n\
             decoding_parallelism = {}\n\
             \n\
             [transport]\n\
             max_paths = {}\n\
             health_check_interval_ms = {}\n\
             dead_path_backoff_initial_ms = {}\n\
             dead_path_backoff_max_ms = {}\n\
             dead_path_backoff_multiplier = {:.2}\n\
             max_symbols_in_flight = {}\n\
             path_strategy = \"{}\"\n\
             experiment_gate = \"{}\"\n\
             coding_policy = \"{}\"\n\
             \n\
             [resources]\n\
             max_symbol_buffer_memory = {}\n\
             max_encoding_ops = {}\n\
             max_decoding_ops = {}\n\
             symbol_pool_size = {}\n\
             \n\
             [timeouts]\n\
             default_timeout_ms = {}\n\
             encoding_timeout_ms = {}\n\
             decoding_timeout_ms = {}\n\
             path_timeout_ms = {}\n\
             quorum_timeout_ms = {}\n\
             \n\
             [observability]\n\
             log_level = \"{}\"\n\
             trace_all_symbols = {}\n\
             sample_rate = {:.2}\n\
             max_spans = {}\n\
             max_log_entries = {}\n\
             include_timestamps = {}\n\
             metrics_enabled = {}\n\
             \n\
             [security]\n\
             auth_mode = \"{}\"\n\
             auth_key_seed = {}\n\
             reject_unauthenticated = {}\n",
            config.encoding.repair_overhead,
            config.encoding.max_block_size,
            config.encoding.symbol_size,
            config.encoding.encoding_parallelism,
            config.encoding.decoding_parallelism,
            config.transport.max_paths,
            duration_ms(config.transport.health_check_interval),
            duration_ms(config.transport.dead_path_backoff.initial_delay),
            duration_ms(config.transport.dead_path_backoff.max_delay),
            config.transport.dead_path_backoff.multiplier,
            config.transport.max_symbols_in_flight,
            path_strategy_toml_value(&config.transport.path_strategy),
            experiment_gate_toml_value(config.transport.experiment_gate),
            coding_policy_toml_value(config.transport.coding_policy),
            config.resources.max_symbol_buffer_memory,
            config.resources.max_encoding_ops,
            config.resources.max_decoding_ops,
            config.resources.symbol_pool_size,
            duration_ms(config.timeouts.default_timeout),
            duration_ms(config.timeouts.encoding_timeout),
            duration_ms(config.timeouts.decoding_timeout),
            duration_ms(config.timeouts.path_timeout),
            duration_ms(config.timeouts.quorum_timeout),
            config.observability.log_level().as_str_lower(),
            config.observability.trace_all_symbols(),
            config.observability.sample_rate(),
            config.observability.max_spans(),
            config.observability.max_log_entries(),
            config.observability.include_timestamps(),
            config.observability.metrics_enabled(),
            auth_mode_toml_value(config.security.auth_mode),
            config
                .security
                .auth_key_seed
                .expect("snapshot fixture sets auth key seed"),
            config.security.reject_unauthenticated,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn config_summary_for_snapshot(config: &RaptorQConfig) -> serde_json::Value {
        let aggregator = config.transport.aggregator_config();
        serde_json::json!({
            "encoding": {
                "repair_overhead": config.encoding.repair_overhead,
                "max_block_size": config.encoding.max_block_size,
                "symbol_size": config.encoding.symbol_size,
                "encoding_parallelism": config.encoding.encoding_parallelism,
                "decoding_parallelism": config.encoding.decoding_parallelism,
            },
            "transport": {
                "max_paths": config.transport.max_paths,
                "health_check_interval_ms": duration_ms(config.transport.health_check_interval),
                "dead_path_backoff": {
                    "initial_ms": duration_ms(config.transport.dead_path_backoff.initial_delay),
                    "max_ms": duration_ms(config.transport.dead_path_backoff.max_delay),
                    "multiplier": config.transport.dead_path_backoff.multiplier,
                },
                "max_symbols_in_flight": config.transport.max_symbols_in_flight,
                "path_strategy": path_strategy_toml_value(&config.transport.path_strategy),
                "experiment_gate": experiment_gate_toml_value(config.transport.experiment_gate),
                "coding_policy": coding_policy_toml_value(config.transport.coding_policy),
                "aggregator_effective_policy": {
                    "path_policy": format!("{:?}", aggregator.path_policy),
                    "experiment_gate": aggregator.experiment_gate.gate_id(),
                    "coding_policy": aggregator.coding_policy.policy_id(),
                },
            },
            "resources": {
                "max_symbol_buffer_memory": config.resources.max_symbol_buffer_memory,
                "max_encoding_ops": config.resources.max_encoding_ops,
                "max_decoding_ops": config.resources.max_decoding_ops,
                "symbol_pool_size": config.resources.symbol_pool_size,
            },
            "timeouts_ms": {
                "default": duration_ms(config.timeouts.default_timeout),
                "encoding": duration_ms(config.timeouts.encoding_timeout),
                "decoding": duration_ms(config.timeouts.decoding_timeout),
                "path": duration_ms(config.timeouts.path_timeout),
                "quorum": duration_ms(config.timeouts.quorum_timeout),
            },
            "observability": {
                "log_level": config.observability.log_level().as_str_lower(),
                "trace_all_symbols": config.observability.trace_all_symbols(),
                "sample_rate": config.observability.sample_rate(),
                "max_spans": config.observability.max_spans(),
                "max_log_entries": config.observability.max_log_entries(),
                "include_timestamps": config.observability.include_timestamps(),
                "metrics_enabled": config.observability.metrics_enabled(),
            },
            "security": {
                "auth_mode": auth_mode_toml_value(config.security.auth_mode),
                "auth_key_seed": config.security.auth_key_seed,
                "reject_unauthenticated": config.security.reject_unauthenticated,
            },
        })
    }

    #[test]
    fn runtime_config_toml_roundtrip_canonical_shape() {
        let fixture = runtime_config_toml_fixture();
        let parsed = parse_config(fixture, RuntimeProfile::Testing.to_config()).unwrap();
        parsed.validate().unwrap();

        let canonical_toml = render_runtime_config_toml_for_snapshot(&parsed);
        let reparsed = parse_config(&canonical_toml, RuntimeProfile::Testing.to_config()).unwrap();
        reparsed.validate().unwrap();

        let parsed_summary = config_summary_for_snapshot(&parsed);
        let reparsed_summary = config_summary_for_snapshot(&reparsed);
        assert_eq!(parsed_summary, reparsed_summary);

        insta::assert_json_snapshot!(
            "runtime_config_toml_roundtrip_canonical_shape",
            serde_json::json!({
                "input_toml": fixture.trim(),
                "canonical_toml": canonical_toml.trim_end(),
                "config": parsed_summary,
            })
        );
    }

    #[test]
    fn invalid_repair_overhead() {
        let mut config = RaptorQConfig::default();
        config.encoding.repair_overhead = 0.5;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRepairOverhead)
        ));
    }

    /// Regression: NaN and Infinity must be rejected for repair_overhead.
    /// NaN passes `< 1.0` check (all NaN comparisons are false) but would
    /// produce 0 repair symbols; Infinity would cause resource exhaustion.
    #[test]
    fn repair_overhead_rejects_nan_and_infinity() {
        let mut config = RaptorQConfig::default();

        config.encoding.repair_overhead = f64::NAN;
        assert!(
            matches!(config.validate(), Err(ConfigError::InvalidRepairOverhead)),
            "NaN must be rejected"
        );

        config.encoding.repair_overhead = f64::INFINITY;
        assert!(
            matches!(config.validate(), Err(ConfigError::InvalidRepairOverhead)),
            "Infinity must be rejected"
        );

        config.encoding.repair_overhead = f64::NEG_INFINITY;
        assert!(
            matches!(config.validate(), Err(ConfigError::InvalidRepairOverhead)),
            "Negative infinity must be rejected"
        );
    }

    /// Invariant: validation rejects symbol_size < 8.
    #[test]
    fn invalid_symbol_size() {
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 4;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidSymbolSize)
        ));
    }

    /// Invariant: validation rejects max_block_size == 0.
    #[test]
    fn invalid_max_block_size() {
        let mut config = RaptorQConfig::default();
        config.encoding.max_block_size = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidMaxBlockSize)
        ));
    }

    /// Invariant: validation rejects zero parallelism.
    #[test]
    fn invalid_parallelism_encoding() {
        let mut config = RaptorQConfig::default();
        config.encoding.encoding_parallelism = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidParallelism)
        ));
    }

    /// Invariant: validation rejects insufficient memory budget.
    #[test]
    fn insufficient_memory() {
        let mut config = RaptorQConfig::default();
        config.resources.max_symbol_buffer_memory = 512;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InsufficientMemory)
        ));
    }

    /// Invariant: validation rejects too-short timeouts.
    #[test]
    fn timeout_too_short() {
        let mut config = RaptorQConfig::default();
        config.timeouts.default_timeout = Duration::from_millis(10);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::TimeoutTooShort)
        ));
    }

    /// Invariant: ConfigError Display renders all variants.
    #[test]
    fn config_error_display() {
        let err = ConfigError::InvalidRepairOverhead;
        assert!(format!("{err}").contains("repair_overhead"));

        let err = ConfigError::InvalidSymbolSize;
        assert!(format!("{err}").contains("symbol_size"));

        let err = ConfigError::InvalidMaxBlockSize;
        assert!(format!("{err}").contains("max_block_size"));

        let err = ConfigError::InvalidParallelism;
        assert!(format!("{err}").contains("parallelism"));

        let err = ConfigError::InsufficientMemory;
        assert!(format!("{err}").contains("memory"));

        let err = ConfigError::TimeoutTooShort;
        assert!(format!("{err}").contains("timeout"));

        let err = ConfigError::InvalidSampleRate(1.5);
        assert!(format!("{err}").contains("sample_rate"));
    }

    // Pure data-type tests (wave 16 – CyanBarn)

    #[test]
    fn config_error_debug() {
        let err = ConfigError::InvalidRepairOverhead;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidRepairOverhead"));
    }

    #[test]
    fn config_error_display_io() {
        let err = ConfigError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(err.to_string().contains("I/O"));
    }

    #[test]
    fn config_error_display_parse() {
        let err = ConfigError::Parse("bad value".into());
        assert!(err.to_string().contains("parse error"));
    }

    #[test]
    fn config_error_display_invalid_override() {
        let err = ConfigError::InvalidOverride("BAD_KEY".into());
        assert!(err.to_string().contains("BAD_KEY"));
    }

    #[test]
    fn config_error_source() {
        use std::error::Error;

        let err = ConfigError::InvalidRepairOverhead;
        assert!(err.source().is_none());

        // ConfigError has a blanket Error impl with no source override.
        let err = ConfigError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(err.source().is_none());
    }

    #[test]
    fn config_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let config_err = ConfigError::from(io_err);
        assert!(matches!(config_err, ConfigError::Io(_)));
    }

    #[test]
    fn raptorq_config_debug_clone() {
        let config = RaptorQConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("RaptorQConfig"));

        let cloned = config.clone();
        assert_eq!(cloned.encoding.symbol_size, config.encoding.symbol_size);
    }

    #[test]
    fn encoding_config_default() {
        let enc = EncodingConfig::default();
        assert!((enc.repair_overhead - 1.05).abs() < f64::EPSILON);
        assert_eq!(enc.symbol_size, 256);
        assert_eq!(enc.encoding_parallelism, 2);
    }

    #[test]
    fn transport_config_default() {
        let tc = TransportConfig::default();
        assert_eq!(tc.max_paths, 4);
        assert_eq!(tc.max_symbols_in_flight, 256);
        assert_eq!(tc.experiment_gate, ExperimentalTransportGate::Disabled);
        assert_eq!(tc.coding_policy, TransportCodingPolicy::Disabled);
    }

    #[test]
    fn backoff_config_debug_clone_default() {
        let bc = BackoffConfig::default();
        let dbg = format!("{bc:?}");
        assert!(dbg.contains("BackoffConfig"));

        let cloned = bc;
        assert_eq!(cloned.initial_delay, Duration::from_millis(100));
        assert_eq!(cloned.max_delay, Duration::from_secs(10));
    }

    #[test]
    fn adaptive_config_debug_clone_default() {
        let ac = AdaptiveConfig::default();
        let dbg = format!("{ac:?}");
        assert!(dbg.contains("AdaptiveConfig"));

        let cloned = ac;
        assert_eq!(cloned.min_samples, 16);
    }

    #[test]
    fn path_selection_strategy_debug_clone() {
        let s = PathSelectionStrategy::RoundRobin;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("RoundRobin"));

        let s = PathSelectionStrategy::Adaptive(AdaptiveConfig::default());
        let cloned = s;
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("Adaptive"));
    }

    #[test]
    fn transport_config_aggregator_config_is_fail_closed_by_default() {
        let transport = TransportConfig::default();
        let aggregator = transport.aggregator_config();
        assert_eq!(aggregator.path_policy, PathSelectionPolicy::RoundRobin);
        assert_eq!(
            aggregator.experiment_gate,
            ExperimentalTransportGate::Disabled
        );
        assert_eq!(aggregator.coding_policy, TransportCodingPolicy::Disabled);
    }

    #[test]
    fn transport_config_aggregator_config_maps_preview_fields() {
        let transport = TransportConfig {
            path_strategy: PathSelectionStrategy::LatencyWeighted,
            experiment_gate: ExperimentalTransportGate::MultipathPreview,
            coding_policy: TransportCodingPolicy::RaptorQFecPreview,
            ..TransportConfig::default()
        };

        let aggregator = transport.aggregator_config();
        assert_eq!(
            aggregator.path_policy,
            PathSelectionPolicy::BestQuality { count: 1 }
        );
        assert_eq!(
            aggregator.experiment_gate,
            ExperimentalTransportGate::MultipathPreview
        );
        assert_eq!(
            aggregator.coding_policy,
            TransportCodingPolicy::RaptorQFecPreview
        );
    }

    #[test]
    fn parse_transport_preview_fields() {
        let mut transport = TransportConfig::default();
        apply_transport_kv(&mut transport, "experiment_gate", "multipath_preview").unwrap();
        apply_transport_kv(&mut transport, "coding_policy", "rlnc_preview").unwrap();

        assert_eq!(
            transport.experiment_gate,
            ExperimentalTransportGate::MultipathPreview
        );
        assert_eq!(transport.coding_policy, TransportCodingPolicy::RlncPreview);
    }

    #[test]
    fn resource_config_debug_clone_default() {
        let rc = ResourceConfig::default();
        let dbg = format!("{rc:?}");
        assert!(dbg.contains("ResourceConfig"));

        let cloned = rc;
        assert_eq!(cloned.max_encoding_ops, 8);
    }

    #[test]
    fn timeout_config_debug_clone_default() {
        let tc = TimeoutConfig::default();
        let dbg = format!("{tc:?}");
        assert!(dbg.contains("TimeoutConfig"));

        let cloned = tc;
        assert_eq!(cloned.default_timeout, Duration::from_secs(30));
    }

    #[test]
    fn security_config_debug_clone_default() {
        let sc = SecurityConfig::default();
        let dbg = format!("{sc:?}");
        assert!(dbg.contains("SecurityConfig"));

        let cloned = sc;
        assert!(cloned.reject_unauthenticated);
        assert!(cloned.auth_key_seed.is_none());
    }

    #[test]
    fn runtime_profile_custom() {
        let config = RaptorQConfig::default();
        let profile = RuntimeProfile::Custom(Box::new(config.clone()));
        let expanded = profile.to_config();
        assert_eq!(expanded.encoding.symbol_size, config.encoding.symbol_size);
    }

    #[test]
    fn runtime_profile_debug_clone() {
        let p = RuntimeProfile::Development;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Development"));

        let cloned = p;
        let dbg2 = format!("{cloned:?}");
        assert!(dbg2.contains("Development"));
    }

    #[test]
    fn config_loader_debug_clone_default() {
        let loader = ConfigLoader::new();
        let dbg = format!("{loader:?}");
        assert!(dbg.contains("ConfigLoader"));

        let cloned = loader;
        let dbg2 = format!("{cloned:?}");
        assert!(dbg2.contains("ConfigLoader"));

        let default_loader = ConfigLoader::default();
        let dbg3 = format!("{default_loader:?}");
        assert!(dbg3.contains("ConfigLoader"));
    }

    #[test]
    fn config_loader_builder_chain() {
        let loader = ConfigLoader::new()
            .profile(RuntimeProfile::Testing)
            .override_value("encoding.symbol_size", "128");

        let dbg = format!("{loader:?}");
        assert!(dbg.contains("Testing"));
    }
