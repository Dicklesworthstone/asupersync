    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget};
    use futures_lite::future;
    use std::ffi::OsStr;
    #[cfg(any(unix, windows))]
    use std::ffi::OsString;
    use std::io::{self, Write};
    use std::process::{Command, Output};
    use std::sync::mpsc;
    use std::time::Duration;

    const LOGGING_CHILD_CASE_ENV: &str = "ASUPERSYNC_LOGGING_CHILD_CASE";
    const LOGGING_CHILD_TEST: &str = "test_utils::tests::logging_fresh_process_child";
    const ASUPERSYNC_DEBUG_MARKER: &str = "ASUPERSYNC_DEBUG_MARKER_7MF9BT";
    const TOKENIZERS_TRACE_MARKER: &str = "TOKENIZERS_TRACE_MARKER_7MF9BT";
    const TOKENIZERS_LOG_MARKER: &str = "TOKENIZERS_LOG_MARKER_7MF9BT";
    const FALLBACK_MARKER: &str = "invalid RUST_LOG; using deterministic test logging fallback";
    const RAW_RUN_TEST_MARKER: &str = "RAW_NO_SUBSCRIBER_RUN_TEST_MARKER_OE2RHS";
    const RAW_RUN_TEST_WITH_CX_MARKER: &str = "RAW_NO_SUBSCRIBER_RUN_TEST_WITH_CX_MARKER_OE2RHS";
    const RAW_LAB_MARKER: &str = "RAW_NO_SUBSCRIBER_LAB_MARKER_OE2RHS";
    const OFF_AFTER_NESTED_MARKER: &str = "OFF_AFTER_NESTED_MARKER_OE2RHS";
    const UNPROPAGATED_DEFAULT_MARKER: &str = "UNPROPAGATED_DEFAULT_MARKER_OE2RHS";
    const PROPAGATED_OFF_MARKER: &str = "PROPAGATED_OFF_MARKER_OE2RHS";
    const LOGGING_GIT_REVISION_ENV: &str = "ASUPERSYNC_LOGGING_GIT_REVISION";
    const LOGGING_STRICT_RECEIPT_ENV: &str = "ASUPERSYNC_LOGGING_STRICT_RECEIPT";

    #[derive(Clone, Default)]
    struct CaptureWriter {
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    struct CaptureGuard {
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl CaptureWriter {
        fn text(&self) -> String {
            let bytes = self.bytes.lock().expect("capture mutex was poisoned");
            String::from_utf8(bytes.clone()).expect("tracing output must be UTF-8")
        }

        fn len(&self) -> usize {
            self.bytes.lock().expect("capture mutex was poisoned").len()
        }
    }

    impl Write for CaptureGuard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .expect("capture mutex was poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for CaptureWriter {
        type Writer = CaptureGuard;

        fn make_writer(&'writer self) -> Self::Writer {
            CaptureGuard {
                bytes: Arc::clone(&self.bytes),
            }
        }
    }

    fn capture_dispatch(filter: &str) -> (Dispatch, CaptureWriter) {
        let writer = CaptureWriter::default();
        let config = TestLogConfig::try_new(filter).expect("test filter must be valid");
        (test_dispatch(&config, writer.clone()), writer)
    }

    fn emit_filter_probe_events() {
        tracing::debug!(
            target: "asupersync::logging_contract",
            "{ASUPERSYNC_DEBUG_MARKER}"
        );
        tracing::trace!(
            target: "tokenizers::normalizer",
            "{TOKENIZERS_TRACE_MARKER}"
        );
        tracing_log::log::trace!(
            target: "tokenizers::normalizer",
            "{TOKENIZERS_LOG_MARKER}"
        );
    }

    fn combined_output(output: &Output) -> String {
        let mut bytes = output.stdout.clone();
        bytes.extend_from_slice(&output.stderr);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn active_logging_features() -> Vec<&'static str> {
        macro_rules! feature_states {
            ($($feature:literal),+ $(,)?) => {
                [$(($feature, cfg!(feature = $feature))),+]
            };
        }

        feature_states![
            "default",
            "nightly-outcome-try",
            "messaging-fabric",
            "waker-profiling",
            "runtime-metrics",
            "wasm-browser-preview",
            "wasm-runtime",
            "browser-io",
            "browser-trace",
            "deterministic-mode",
            "native-runtime",
            "wasm-browser-dev",
            "wasm-browser-prod",
            "wasm-browser-deterministic",
            "wasm-browser-minimal",
            "test-internals",
            "legacy-internal-test-harnesses",
            "serialization-golden-harnesses",
            "real-service-e2e",
            "channel-mpsc-select-e2e",
            "h3-websocket-e2e",
            "raptorq-roundtrip-e2e",
            "obligation-cleanup-e2e",
            "metrics",
            "tracing-integration",
            "proc-macros",
            "tower",
            "trace-compression",
            "debug-server",
            "config-file",
            "dependency-ledger",
            "lock-metrics",
            "obligation-leak-detection",
            "io-uring",
            "tls",
            "tls-native-roots",
            "tls-webpki-roots",
            "cli",
            "atp-cli",
            "sqlite",
            "postgres",
            "mysql",
            "quic",
            "http3",
            "tailscale-path-provider",
            "tokio-compat",
            "kafka",
            "ci-cross-platform",
            "compression",
            "simd-intrinsics",
            "loom-tests",
            "cancel-correctness-oracle",
            "lab-stack-traces",
            "benchmark-adapters",
            "criterion-benches",
            "atpd-daemon",
            "fuzz",
        ]
        .into_iter()
        .filter_map(|(feature, active)| active.then_some(feature))
        .collect()
    }

    fn logging_profile() -> &'static str {
        if cfg!(debug_assertions) {
            "test"
        } else {
            "release"
        }
    }

    fn valid_git_revision(value: &str) -> Option<&str> {
        let value = value.trim();
        (value.len() >= 7
            && value.len() <= 64
            && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(value)
    }

    fn repository_git_revision() -> Option<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(env!("CARGO_MANIFEST_DIR"))
            .args(["rev-parse", "--verify", "HEAD"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let value = std::str::from_utf8(&output.stdout).ok()?;
        valid_git_revision(value).map(str::to_string)
    }

    fn logging_git_revision() -> String {
        let repository_revision = repository_git_revision();
        let strict_receipt = match std::env::var(LOGGING_STRICT_RECEIPT_ENV) {
            Ok(value) => {
                assert_eq!(value, "1", "strict logging receipt flag must equal 1");
                true
            }
            Err(std::env::VarError::NotPresent) => false,
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("strict logging receipt flag must be Unicode")
            }
        };
        match std::env::var(LOGGING_GIT_REVISION_ENV) {
            Ok(value) => {
                let requested = valid_git_revision(&value)
                    .expect("logging git revision override must be a hexadecimal revision");
                if let Some(repository_revision) = &repository_revision {
                    assert_eq!(
                        requested, repository_revision,
                        "logging git revision override does not match checked-out HEAD"
                    );
                }
                requested.to_string()
            }
            Err(std::env::VarError::NotPresent) => {
                if strict_receipt {
                    panic!("strict logging receipt requires an explicit hexadecimal git revision");
                }
                repository_revision.unwrap_or_else(|| "unavailable".to_string())
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("logging git revision override must be Unicode")
            }
        }
    }

    fn logging_replay_command(git_revision: &str, features: &[&str]) -> String {
        let default_active = features.contains(&"default");
        let explicit_features = features
            .iter()
            .copied()
            .filter(|feature| *feature != "default")
            .collect::<Vec<_>>()
            .join(",");

        let mut feature_args = if default_active {
            String::new()
        } else {
            " --no-default-features".to_string()
        };
        if !explicit_features.is_empty() {
            feature_args.push_str(" --features ");
            feature_args.push_str(&explicit_features);
        }
        let profile_arg = if cfg!(debug_assertions) {
            ""
        } else {
            " --release"
        };

        format!(
            "RCH_REQUIRE_REMOTE=1 rch exec --base {git_revision} --clean-overlay --no-overlay -- env CARGO_TARGET_DIR=\"${{RCH_TARGET_BASE:-${{TMPDIR:-/tmp}}}}/rch_target_test_log_empty_off_receipt\" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' {LOGGING_STRICT_RECEIPT_ENV}=1 {LOGGING_GIT_REVISION_ENV}={git_revision} cargo test -p asupersync --lib{profile_arg}{feature_args} test_utils::tests::logging_fresh_process_contract_matrix -- --exact --nocapture --test-threads=1"
        )
    }

    fn logging_filter_classification(case: &str) -> &'static str {
        match case {
            "unset-rust-log" => "safe-default-absent",
            "valid-rust-log" => "explicit-valid",
            "empty-rust-log" => "safe-default-invalid-empty",
            "malformed-rust-log" => "safe-default-invalid-parse",
            "non-unicode-rust-log" => "safe-default-invalid-non-unicode",
            "explicit-off" => "explicit-off",
            "raw-no-subscriber" => "ambient-no-subscriber",
            "off-nested-enabled" => "explicit-off-with-explicit-inner",
            "thread-propagation" => "mixed-thread-propagation",
            "public-global-subscriber" => "explicit-global",
            "explicit-log-bridge" => "explicit-global-log-bridge",
            "globals-untouched" => "mixed-safe-default-and-explicit-off",
            "preexisting-global" => "preexisting-global-trace",
            "panic-restoration" => "mixed-scoped-panic-restoration",
            _ => "unknown",
        }
    }

    fn byte_line_count(bytes: &[u8]) -> usize {
        bytes.iter().filter(|byte| **byte == b'\n').count()
            + usize::from(bytes.last().is_some_and(|byte| *byte != b'\n'))
    }

    fn observed_output_marker_occurrences(text: &str) -> usize {
        [
            ASUPERSYNC_DEBUG_MARKER,
            TOKENIZERS_TRACE_MARKER,
            TOKENIZERS_LOG_MARKER,
            RAW_RUN_TEST_MARKER,
            RAW_RUN_TEST_WITH_CX_MARKER,
            RAW_LAB_MARKER,
            OFF_AFTER_NESTED_MARKER,
            UNPROPAGATED_DEFAULT_MARKER,
            PROPAGATED_OFF_MARKER,
        ]
        .into_iter()
        .map(|marker| text.matches(marker).count())
        .sum()
    }

    fn run_logging_child(case: &str, rust_log: Option<&OsStr>) -> Output {
        let mut command = Command::new(
            std::env::current_exe().expect("current test executable must be available"),
        );
        command
            .arg(LOGGING_CHILD_TEST)
            .arg("--exact")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(LOGGING_CHILD_CASE_ENV, case)
            .env_remove("RUST_LOG");
        if let Some(rust_log) = rust_log {
            command.env("RUST_LOG", rust_log);
        }
        command
            .output()
            .expect("fresh-process logging test failed to launch")
    }

    #[cfg(unix)]
    fn non_unicode_rust_log() -> OsString {
        use std::os::unix::ffi::OsStringExt;

        OsString::from_vec(b"secret-prefix-\xff-secret-suffix".to_vec())
    }

    #[cfg(windows)]
    fn non_unicode_rust_log() -> OsString {
        use std::os::windows::ffi::OsStringExt;

        OsString::from_wide(&[
            b's' as u16,
            b'e' as u16,
            b'c' as u16,
            b'r' as u16,
            b'e' as u16,
            b't' as u16,
            0xD800,
        ])
    }

    fn assert_child_passed(git_revision: &str, case: &str, output: &Output) -> String {
        let text = combined_output(output);
        let features = active_logging_features();
        let features_text = if features.is_empty() {
            "none".to_string()
        } else {
            features.join(",")
        };
        let (receipt_admission, replay_command) = if valid_git_revision(git_revision).is_some() {
            ("admitted", logging_replay_command(git_revision, &features))
        } else {
            (
                "non-admitted",
                "unavailable: a hexadecimal git revision is required".to_string(),
            )
        };
        let exit_status = output.status.code().unwrap_or(-1);
        let line_count = byte_line_count(&output.stdout) + byte_line_count(&output.stderr);
        let byte_count = output.stdout.len() + output.stderr.len();
        let output_marker_count = observed_output_marker_occurrences(&text);

        eprintln!(
            "ASUPERSYNC_LOGGING_RECEIPT admission={receipt_admission:?} case={case:?} git_revision={git_revision:?} features={features_text:?} profile={:?} profile_scope=\"standard-cargo-test\" filter_classification={:?} exit_status={exit_status} line_count={line_count} byte_count={byte_count} observed_output_marker_occurrences={output_marker_count} capture_scope=\"child-stdout-stderr-probe-markers\" replay_command={replay_command:?}",
            logging_profile(),
            logging_filter_classification(case),
        );
        assert!(
            output.status.success(),
            "fresh-process logging case {case:?} failed with {:?}:\n{text}",
            output.status.code()
        );
        assert!(
            line_count < 10_000,
            "fresh-process logging case {case:?} exceeded the line cap"
        );
        assert!(
            byte_count < 8 * 1024 * 1024,
            "fresh-process logging case {case:?} exceeded the byte cap"
        );
        if case == "explicit-off" {
            assert_eq!(
                output_marker_count, 0,
                "explicit OFF emitted probe records to child output:\n{text}"
            );
        }
        text
    }

    fn release_logging_workers(
        ready: &mpsc::Receiver<&'static str>,
        expected: [&'static str; 2],
        go: [mpsc::Sender<()>; 2],
    ) {
        let mut observed = Vec::with_capacity(2);
        for _ in 0..2 {
            observed.push(
                ready
                    .recv_timeout(Duration::from_secs(10))
                    .expect("logging worker did not reach the overlap gate"),
            );
        }
        for worker in expected {
            assert!(
                observed.contains(&worker),
                "logging worker {worker:?} did not reach the overlap gate: {observed:?}"
            );
        }
        for sender in go {
            sender
                .send(())
                .expect("logging worker exited before overlap release");
        }
    }

    fn assert_single_fallback(case: &str, text: &str, reason: &str) {
        assert_eq!(
            text.matches(FALLBACK_MARKER).count(),
            1,
            "fresh-process logging case {case:?} must emit one fallback diagnostic:\n{text}"
        );
        let diagnostic = text
            .lines()
            .find(|line| line.contains(FALLBACK_MARKER))
            .expect("fallback diagnostic line must exist");
        assert!(
            diagnostic.len() < 512,
            "fallback diagnostic must remain bounded: {diagnostic:?}"
        );
        assert!(
            diagnostic.contains(reason),
            "fallback diagnostic omitted reason {reason:?}: {diagnostic:?}"
        );
        assert!(
            text.contains(ASUPERSYNC_DEBUG_MARKER),
            "fallback did not apply the safe default:\n{text}"
        );
        assert!(
            !text.contains(TOKENIZERS_TRACE_MARKER),
            "fallback admitted third-party TRACE:\n{text}"
        );
    }

    #[test]
    fn test_log_config_rejects_empty_and_preserves_typed_parse_source() {
        for filter in ["", " ", "\n\t "] {
            let error = TestLogConfig::try_new(filter).expect_err("empty filter must fail");
            assert!(matches!(&error, TestLogConfigError::Empty));
            assert_eq!(error.to_string(), "test log filter must not be empty");
            assert!(std::error::Error::source(&error).is_none());
        }

        let raw = format!("asupersync=not-a-level,{}", "secret".repeat(1024));
        let error = TestLogConfig::try_new(&raw).expect_err("malformed filter must fail");
        assert!(matches!(&error, TestLogConfigError::Parse(_)));
        assert_eq!(error.to_string(), "test log filter is invalid");
        assert!(std::error::Error::source(&error).is_some());
        assert!(!error.to_string().contains("secret"));
        assert!(error.to_string().len() < 64);

        let mut source = std::error::Error::source(&error);
        while let Some(current) = source {
            let rendered = current.to_string();
            assert!(!rendered.contains("secret"));
            assert!(rendered.len() < 512, "unbounded error source: {rendered:?}");
            source = current.source();
        }
    }

    #[test]
    fn test_log_config_accepts_trimmed_nonempty_policies() {
        for (input, expected) in [
            (" off ", "off"),
            ("error", "error"),
            ("warn", "warn"),
            ("my_crate=debug", "my_crate=debug"),
            ("trace", "trace"),
        ] {
            let config = TestLogConfig::try_new(input).expect("policy must be valid");
            assert_eq!(config.effective_filter(), expected);
            assert!(!config.used_rust_log_fallback());
        }
    }

    // Bead: asupersync-7mf9bt
    // Scenario: an ambient scoped dispatcher must remain authoritative before,
    // during future polling, during LabRuntime construction, and afterward.
    // Seed: DEFAULT_TEST_SEED.
    // Artifact: the in-memory capture is asserted for every lifecycle marker.
    #[test]
    fn logging_helpers_preserve_existing_scoped_dispatcher() {
        let (dispatch, writer) = capture_dispatch("trace");

        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "asupersync::logging_contract", "scoped-before");
            run_test(|| async {
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "scoped-run-test-polled"
                );
            });
            run_test_with_cx(|_cx| async {
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "scoped-run-test-with-cx-polled"
                );
            });
            lab_with_config(|_lab| {
                tracing::info!(target: "asupersync::logging_contract", "scoped-lab");
            });
            tracing::info!(target: "asupersync::logging_contract", "scoped-after");
        });

        let text = writer.text();
        for marker in [
            "scoped-before",
            "scoped-run-test-polled",
            "scoped-run-test-with-cx-polled",
            "scoped-lab",
            "scoped-after",
        ] {
            assert!(text.contains(marker), "missing {marker:?} in:\n{text}");
        }
    }

    // Bead: asupersync-test-log-empty-off-authority-oe2rhs
    // Scenario: explicit OFF authority covers runtime construction, future
    // polling, cancellation-by-drop, helper cleanup, and dispatcher restoration.
    #[test]
    fn logging_disabled_scope_covers_runtime_lifecycle_and_restores() {
        struct PendingTraceFuture;

        impl Future for PendingTraceFuture {
            type Output = ();

            fn poll(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "off-pending-future-polled"
                );
                std::task::Poll::Pending
            }
        }

        impl Drop for PendingTraceFuture {
            fn drop(&mut self) {
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "off-pending-future-dropped"
                );
            }
        }

        let (outer_dispatch, outer_writer) = capture_dispatch("trace");
        tracing::dispatcher::with_default(&outer_dispatch, || {
            tracing::info!(target: "asupersync::logging_contract", "off-outer-before");
            let bytes_before_off = outer_writer.len();

            let value = with_test_logging_disabled(|| {
                assert!(tracing::dispatcher::get_default(|dispatch| {
                    !dispatch.is::<tracing::subscriber::NoSubscriber>()
                }));
                assert!(!tracing::enabled!(
                    target: "asupersync::logging_contract",
                    tracing::Level::TRACE
                ));
                tracing::info!(target: "asupersync::logging_contract", "off-direct");

                run_test(|| async {
                    tracing::info!(target: "asupersync::logging_contract", "off-run-test");
                });
                run_test_with_cx(|_cx| async {
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "off-run-test-with-cx"
                    );

                    let mut pending = std::pin::pin!(PendingTraceFuture);
                    let waker = std::task::Waker::noop();
                    let mut task_cx = std::task::Context::from_waker(waker);
                    assert!(pending.as_mut().poll(&mut task_cx).is_pending());
                });
                lab_with_config(|_lab| {
                    tracing::info!(target: "asupersync::logging_contract", "off-lab");
                });
                42
            });

            assert_eq!(value, 42);
            assert_eq!(
                outer_writer.len(),
                bytes_before_off,
                "the outer sink received records from the OFF scope"
            );

            let explicitly_enabled = with_test_logging_disabled(|| {
                let explicitly_enabled = with_test_logging(&TestLogConfig::trace(), || {
                    tracing::enabled!(
                        target: "asupersync::logging_contract",
                        tracing::Level::TRACE
                    )
                });
                assert!(!tracing::enabled!(
                    target: "asupersync::logging_contract",
                    tracing::Level::TRACE
                ));
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "{OFF_AFTER_NESTED_MARKER}"
                );
                explicitly_enabled
            });
            assert!(
                explicitly_enabled,
                "an explicit inner policy must override OFF"
            );

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                with_test_logging_disabled(|| panic!("OFF restoration probe"));
            }));
            assert!(panic.is_err());
            tracing::info!(target: "asupersync::logging_contract", "off-outer-after");
        });

        let text = outer_writer.text();
        assert!(text.contains("off-outer-before"));
        assert!(text.contains("off-outer-after"));
        for marker in [
            "off-direct",
            "off-run-test",
            "off-run-test-with-cx",
            "off-pending-future-polled",
            "off-pending-future-dropped",
            "off-lab",
            OFF_AFTER_NESTED_MARKER,
        ] {
            assert!(
                !text.contains(marker),
                "OFF leaked {marker:?} into:\n{text}"
            );
        }
    }

    // Bead: asupersync-test-log-empty-off-authority-oe2rhs
    // Scenario: explicit per-thread enabled and OFF dispatchers remain isolated.
    #[test]
    fn logging_enabled_and_disabled_threads_do_not_cross_contaminate() {
        let (enabled_dispatch, enabled_writer) = capture_dispatch("trace");
        let (disabled_dispatch, disabled_writer) = capture_dispatch("off");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (enabled_go_tx, enabled_go_rx) = mpsc::channel();
        let (disabled_go_tx, disabled_go_rx) = mpsc::channel();

        let enabled_ready = ready_tx.clone();
        let enabled = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&enabled_dispatch, || {
                run_test(|| async move {
                    enabled_ready
                        .send("enabled")
                        .expect("enabled worker could not report readiness");
                    enabled_go_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("enabled worker was not released");
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "enabled-thread-marker"
                    );
                });
            });
        });

        let disabled_ready = ready_tx;
        let disabled = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&disabled_dispatch, || {
                run_test(|| async move {
                    disabled_ready
                        .send("disabled")
                        .expect("disabled worker could not report readiness");
                    disabled_go_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("disabled worker was not released");
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "disabled-thread-marker"
                    );
                });
            });
        });

        release_logging_workers(
            &ready_rx,
            ["enabled", "disabled"],
            [enabled_go_tx, disabled_go_tx],
        );

        enabled.join().expect("enabled logging thread panicked");
        disabled.join().expect("disabled logging thread panicked");

        let enabled_text = enabled_writer.text();
        assert!(enabled_text.contains("enabled-thread-marker"));
        assert!(!enabled_text.contains("disabled-thread-marker"));
        assert_eq!(disabled_writer.len(), 0, "OFF thread emitted a record");
    }

    // Bead: asupersync-7mf9bt
    // Scenario: two concurrent current-thread runtimes inherit only their
    // caller's thread-scoped dispatcher.
    // Seed: no scheduler randomness; a bounded gate forces overlapping execution.
    // Artifact: two independent in-memory sinks with cross-contamination checks.
    #[test]
    fn logging_concurrent_runtimes_keep_distinct_sinks() {
        let (dispatch_a, writer_a) = capture_dispatch("trace");
        let (dispatch_b, writer_b) = capture_dispatch("trace");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (go_a_tx, go_a_rx) = mpsc::channel();
        let (go_b_tx, go_b_rx) = mpsc::channel();

        let ready_a = ready_tx.clone();
        let thread_a = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch_a, || {
                run_test(|| async move {
                    ready_a
                        .send("runtime-a")
                        .expect("runtime A could not report readiness");
                    go_a_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("runtime A was not released");
                    tracing::info!(target: "asupersync::logging_contract", "runtime-a-only");
                });
            });
        });

        let ready_b = ready_tx;
        let thread_b = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch_b, || {
                run_test(|| async move {
                    ready_b
                        .send("runtime-b")
                        .expect("runtime B could not report readiness");
                    go_b_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("runtime B was not released");
                    tracing::info!(target: "asupersync::logging_contract", "runtime-b-only");
                });
            });
        });

        release_logging_workers(&ready_rx, ["runtime-a", "runtime-b"], [go_a_tx, go_b_tx]);

        thread_a.join().expect("runtime A thread panicked");
        thread_b.join().expect("runtime B thread panicked");

        let text_a = writer_a.text();
        let text_b = writer_b.text();
        assert!(
            text_a.contains("runtime-a-only"),
            "runtime A output:\n{text_a}"
        );
        assert!(
            !text_a.contains("runtime-b-only"),
            "runtime B leaked into runtime A output:\n{text_a}"
        );
        assert!(
            text_b.contains("runtime-b-only"),
            "runtime B output:\n{text_b}"
        );
        assert!(
            !text_b.contains("runtime-a-only"),
            "runtime A leaked into runtime B output:\n{text_b}"
        );
    }

    // Bead: asupersync-7mf9bt
    // Scenario: TRACE remains available only through an explicit filter.
    // Seed: not applicable.
    // Artifact: captured third-party-target tracing event.
    #[test]
    fn logging_explicit_trace_filter_is_opt_in() {
        let writer = CaptureWriter::default();
        let config = TestLogConfig::trace();
        let dispatch = test_dispatch(&config, writer.clone());

        tracing::dispatcher::with_default(&dispatch, emit_filter_probe_events);

        let text = writer.text();
        assert!(
            text.contains(TOKENIZERS_TRACE_MARKER),
            "explicit TRACE did not capture tracing event:\n{text}"
        );
        assert!(
            !text.contains(TOKENIZERS_LOG_MARKER),
            "a log record crossed into tracing without the explicit bridge:\n{text}"
        );
    }

    // Bead: asupersync-7mf9bt
    // Scenario: process-global subscriber/logger state must be tested in fresh
    // processes because successful installation is irreversible.
    // Seed: DEFAULT_TEST_SEED for the LabRuntime case.
    // Command: current test binary, exact child test, nocapture, one test thread.
    // Artifact: captured child stdout/stderr.
    #[test]
    fn logging_fresh_process_contract_matrix() {
        let git_revision = logging_git_revision();

        let unset = run_logging_child("unset-rust-log", None);
        let unset_text = assert_child_passed(&git_revision, "unset-rust-log", &unset);
        assert!(
            unset_text.contains(ASUPERSYNC_DEBUG_MARKER),
            "safe default suppressed Asupersync DEBUG:\n{unset_text}"
        );
        assert!(
            !unset_text.contains(TOKENIZERS_TRACE_MARKER),
            "safe default admitted third-party tracing TRACE:\n{unset_text}"
        );
        assert!(
            !unset_text.contains(TOKENIZERS_LOG_MARKER),
            "runtime helper implicitly installed LogTracer:\n{unset_text}"
        );
        assert_eq!(unset_text.matches(FALLBACK_MARKER).count(), 0);

        let valid = run_logging_child(
            "valid-rust-log",
            Some(OsStr::new("warn,tokenizers::normalizer=trace")),
        );
        let valid_text = assert_child_passed(&git_revision, "valid-rust-log", &valid);
        assert!(
            valid_text.contains(TOKENIZERS_TRACE_MARKER),
            "valid RUST_LOG was not honored:\n{valid_text}"
        );
        assert!(
            !valid_text.contains(ASUPERSYNC_DEBUG_MARKER),
            "valid RUST_LOG was replaced by the safe fallback:\n{valid_text}"
        );
        assert!(
            !valid_text.contains(TOKENIZERS_LOG_MARKER),
            "valid RUST_LOG implicitly enabled the global log bridge:\n{valid_text}"
        );
        assert_eq!(valid_text.matches(FALLBACK_MARKER).count(), 0);

        let empty = run_logging_child("empty-rust-log", Some(OsStr::new(" \t ")));
        let empty_text = assert_child_passed(&git_revision, "empty-rust-log", &empty);
        assert_single_fallback("empty-rust-log", &empty_text, "empty");

        let malformed_raw = format!(
            "asupersync=definitely-not-a-level,{}",
            "secret-filter-value".repeat(64)
        );
        let malformed = run_logging_child("malformed-rust-log", Some(OsStr::new(&malformed_raw)));
        let malformed_text = assert_child_passed(&git_revision, "malformed-rust-log", &malformed);
        assert_single_fallback("malformed-rust-log", &malformed_text, "parse");
        assert!(!malformed_text.contains("secret-filter-value"));

        #[cfg(any(unix, windows))]
        {
            let non_unicode_raw = non_unicode_rust_log();
            let non_unicode =
                run_logging_child("non-unicode-rust-log", Some(non_unicode_raw.as_os_str()));
            let non_unicode_text =
                assert_child_passed(&git_revision, "non-unicode-rust-log", &non_unicode);
            assert_single_fallback("non-unicode-rust-log", &non_unicode_text, "non_unicode");
            assert!(!non_unicode_text.contains("secret-prefix"));
        }

        let explicit_off = run_logging_child("explicit-off", None);
        let explicit_off_text = assert_child_passed(&git_revision, "explicit-off", &explicit_off);
        for marker in [ASUPERSYNC_DEBUG_MARKER, TOKENIZERS_TRACE_MARKER] {
            assert!(
                !explicit_off_text.contains(marker),
                "explicit OFF emitted {marker:?}:\n{explicit_off_text}"
            );
        }

        let raw_no_subscriber = run_logging_child("raw-no-subscriber", None);
        let raw_no_subscriber_text =
            assert_child_passed(&git_revision, "raw-no-subscriber", &raw_no_subscriber);
        for marker in [
            RAW_RUN_TEST_MARKER,
            RAW_RUN_TEST_WITH_CX_MARKER,
            RAW_LAB_MARKER,
        ] {
            assert!(
                raw_no_subscriber_text.contains(marker),
                "raw NoSubscriber did not trigger safe default for {marker:?}:\n{raw_no_subscriber_text}"
            );
        }

        let nested_enabled = run_logging_child("off-nested-enabled", None);
        let nested_enabled_text =
            assert_child_passed(&git_revision, "off-nested-enabled", &nested_enabled);
        assert!(
            nested_enabled_text.contains(TOKENIZERS_TRACE_MARKER),
            "explicit enabled scope did not override OFF:\n{nested_enabled_text}"
        );
        assert!(
            !nested_enabled_text.contains(OFF_AFTER_NESTED_MARKER),
            "nested enabled scope did not restore OFF:\n{nested_enabled_text}"
        );

        let thread_propagation = run_logging_child("thread-propagation", None);
        let thread_propagation_text =
            assert_child_passed(&git_revision, "thread-propagation", &thread_propagation);
        assert!(
            thread_propagation_text.contains(UNPROPAGATED_DEFAULT_MARKER),
            "unpropagated worker did not use the safe default:\n{thread_propagation_text}"
        );
        assert!(
            !thread_propagation_text.contains(PROPAGATED_OFF_MARKER),
            "explicitly propagated OFF emitted a record:\n{thread_propagation_text}"
        );

        let public_global = run_logging_child("public-global-subscriber", None);
        let public_global_text =
            assert_child_passed(&git_revision, "public-global-subscriber", &public_global);
        assert!(public_global_text.contains(TOKENIZERS_TRACE_MARKER));

        for case in [
            "globals-untouched",
            "preexisting-global",
            "panic-restoration",
            "explicit-log-bridge",
        ] {
            let output = run_logging_child(case, None);
            let _text = assert_child_passed(&git_revision, case, &output);
        }
    }

    // This test is invoked directly by `logging_fresh_process_contract_matrix`.
    // Its cases intentionally make irreversible process-global changes.
    #[test]
    fn logging_fresh_process_child() {
        let Ok(case) = std::env::var(LOGGING_CHILD_CASE_ENV) else {
            return;
        };

        match case.as_str() {
            "unset-rust-log"
            | "valid-rust-log"
            | "empty-rust-log"
            | "malformed-rust-log"
            | "non-unicode-rust-log" => {
                run_test(|| async {
                    emit_filter_probe_events();
                });
            }
            "explicit-off" => {
                with_test_logging_disabled(|| {
                    emit_filter_probe_events();
                    run_test(|| async { emit_filter_probe_events() });
                    run_test_with_cx(|_cx| async { emit_filter_probe_events() });
                    lab_with_config(|_lab| emit_filter_probe_events());
                });
            }
            "raw-no-subscriber" => {
                let raw_no_subscriber = Dispatch::new(tracing::subscriber::NoSubscriber::default());
                tracing::dispatcher::with_default(&raw_no_subscriber, || {
                    run_test(|| async {
                        tracing::debug!(
                            target: "asupersync::logging_contract",
                            "{RAW_RUN_TEST_MARKER}"
                        );
                    });
                    run_test_with_cx(|_cx| async {
                        tracing::debug!(
                            target: "asupersync::logging_contract",
                            "{RAW_RUN_TEST_WITH_CX_MARKER}"
                        );
                    });
                    lab_with_config(|_lab| {
                        tracing::debug!(
                            target: "asupersync::logging_contract",
                            "{RAW_LAB_MARKER}"
                        );
                    });
                });
            }
            "off-nested-enabled" => {
                with_test_logging_disabled(|| {
                    with_test_logging(&TestLogConfig::trace(), emit_filter_probe_events);
                    assert!(!tracing::enabled!(
                        target: "asupersync::logging_contract",
                        tracing::Level::TRACE
                    ));
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "{OFF_AFTER_NESTED_MARKER}"
                    );
                });
            }
            "globals-untouched" => {
                run_test(|| async {});
                run_test_with_cx(|_cx| async {});
                lab_with_config(|_lab| {});
                with_test_logging_disabled(|| {
                    run_test(|| async {});
                    run_test_with_cx(|_cx| async {});
                    lab_with_config(|_lab| {});
                });

                tracing::dispatcher::set_global_default(Dispatch::new(
                    tracing::subscriber::NoSubscriber::default(),
                ))
                .expect("runtime helpers mutated the global tracing subscriber");

                struct NoopLogger;
                impl tracing_log::log::Log for NoopLogger {
                    fn enabled(&self, _metadata: &tracing_log::log::Metadata<'_>) -> bool {
                        false
                    }

                    fn log(&self, _record: &tracing_log::log::Record<'_>) {}

                    fn flush(&self) {}
                }
                static NOOP_LOGGER: NoopLogger = NoopLogger;
                tracing_log::log::set_logger(&NOOP_LOGGER)
                    .expect("runtime helpers mutated the global log logger");
            }
            "preexisting-global" => {
                let (dispatch, writer) = capture_dispatch("trace");
                tracing::dispatcher::set_global_default(dispatch)
                    .expect("fresh process must accept the test global subscriber");

                tracing::info!(
                    target: "asupersync::logging_contract",
                    "preexisting-global-before"
                );
                run_test(|| async {
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "preexisting-global-run-test"
                    );
                });
                run_test_with_cx(|_cx| async {
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "preexisting-global-run-test-with-cx"
                    );
                });
                lab_with_config(|_lab| {
                    tracing::info!(
                        target: "asupersync::logging_contract",
                        "preexisting-global-lab"
                    );
                });
                tracing::info!(
                    target: "asupersync::logging_contract",
                    "preexisting-global-after"
                );

                let text = writer.text();
                for marker in [
                    "preexisting-global-before",
                    "preexisting-global-run-test",
                    "preexisting-global-run-test-with-cx",
                    "preexisting-global-lab",
                    "preexisting-global-after",
                ] {
                    assert!(
                        text.contains(marker),
                        "global subscriber missed {marker:?}:\n{text}"
                    );
                }
            }
            "panic-restoration" => {
                let cases: [Box<dyn FnOnce() + std::panic::UnwindSafe>; 3] = [
                    Box::new(|| run_test(|| async { panic!("run_test panic probe") })),
                    Box::new(|| {
                        run_test_with_cx(|_cx| async { panic!("run_test_with_cx panic probe") });
                    }),
                    Box::new(|| {
                        lab_with_config(|_lab| panic!("lab_with_config panic probe"));
                    }),
                ];

                for panic_case in cases {
                    let result = std::panic::catch_unwind(panic_case);
                    assert!(result.is_err(), "panic probe unexpectedly returned");
                    let restored = tracing::dispatcher::get_default(|dispatch| {
                        dispatch.is::<tracing::subscriber::NoSubscriber>()
                    });
                    assert!(restored, "scoped dispatcher leaked after panic");
                }
            }
            "thread-propagation" => {
                with_test_logging_disabled(|| {
                    let disabled_dispatch =
                        tracing::dispatcher::get_default(|dispatch| dispatch.clone());

                    let unpropagated = std::thread::spawn(|| {
                        assert!(tracing::dispatcher::get_default(|dispatch| {
                            dispatch.is::<tracing::subscriber::NoSubscriber>()
                        }));
                        run_test(|| async {
                            tracing::debug!(
                                target: "asupersync::logging_contract",
                                "{UNPROPAGATED_DEFAULT_MARKER}"
                            );
                        });
                    });
                    unpropagated
                        .join()
                        .expect("unpropagated logging worker panicked");

                    let propagated = std::thread::spawn(move || {
                        tracing::dispatcher::with_default(&disabled_dispatch, || {
                            assert!(tracing::dispatcher::get_default(|dispatch| {
                                !dispatch.is::<tracing::subscriber::NoSubscriber>()
                            }));
                            run_test(|| async {
                                tracing::debug!(
                                    target: "asupersync::logging_contract",
                                    "{PROPAGATED_OFF_MARKER}"
                                );
                            });
                        });
                    });
                    propagated
                        .join()
                        .expect("explicitly propagated logging worker panicked");
                });
            }
            "public-global-subscriber" => {
                install_global_test_subscriber(&TestLogConfig::trace())
                    .expect("fresh process must accept explicit global subscriber");
                emit_filter_probe_events();
                run_test(|| async { emit_filter_probe_events() });
            }
            "explicit-log-bridge" => {
                let (dispatch, writer) = capture_dispatch("trace");
                install_global_test_log_bridge()
                    .expect("fresh process must accept explicit LogTracer installation");
                tracing::dispatcher::with_default(&dispatch, || {
                    tracing::trace!(
                        target: "tokenizers::normalizer",
                        "{TOKENIZERS_TRACE_MARKER}"
                    );
                    tracing_log::log::trace!(
                        target: "tokenizers::normalizer",
                        "{TOKENIZERS_LOG_MARKER}"
                    );
                });

                let text = writer.text();
                assert!(
                    text.contains(TOKENIZERS_TRACE_MARKER),
                    "explicit bridge case lost tracing record:\n{text}"
                );
                assert!(
                    text.contains(TOKENIZERS_LOG_MARKER),
                    "explicit LogTracer bridge lost log record:\n{text}"
                );
            }
            other => panic!("unknown fresh-process logging case {other:?}"),
        }
    }

    #[test]
    fn assert_completes_within_uses_wall_time_when_no_runtime_is_active() {
        // Ensure the wall clock origin is initialized and has advanced beyond the timeout.
        let _t0 = crate::time::wall_now();
        std::thread::sleep(Duration::from_millis(50));

        // This should not spuriously time out in standalone mode.
        let value = future::block_on(assert_completes_within(
            Duration::from_millis(10),
            "standalone immediate future",
            || std::future::ready(7_u8),
        ));
        assert_eq!(value, 7);
    }

    #[test]
    fn lab_with_config_exposes_a_usable_lab_runtime() {
        let (seed, value) = lab_with_config(|runtime| {
            let seed = runtime.config().seed;
            let value = LabRuntimeTarget::block_on(runtime, async { 42_u8 });
            (seed, value)
        });

        assert_eq!(seed, DEFAULT_TEST_SEED);
        assert_eq!(value, 42);
    }
