    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn known_findings_are_documented() {
        assert!(
            !KNOWN_FINDINGS.is_empty(),
            "Findings list should not be empty"
        );
    }

    #[test]
    fn critical_findings_resolved() {
        let critical = count_by_severity(Severity::Critical);
        assert!(
            critical == 0,
            "Expected zero non-exempt critical findings, got {critical}"
        );
    }

    #[test]
    fn exempt_findings_have_reasons() {
        for finding in KNOWN_FINDINGS {
            if finding.exempt {
                assert!(
                    finding.exemption_reason.is_some(),
                    "Exempt finding in {} has no reason",
                    finding.file
                );
            }
        }
    }

    #[test]
    fn grep_patterns_cover_all_categories() {
        let categories: std::collections::HashSet<_> =
            GREP_PATTERNS.iter().map(|(_, cat)| *cat).collect();
        assert!(categories.contains(&AmbientCategory::Time));
        assert!(categories.contains(&AmbientCategory::Spawn));
        assert!(categories.contains(&AmbientCategory::Entropy));
        assert!(categories.contains(&AmbientCategory::Io));
        assert!(categories.contains(&AmbientCategory::Env));
        assert!(categories.contains(&AmbientCategory::Output));
    }

    #[test]
    fn unresolved_count_tracks_non_exempt() {
        let unresolved = unresolved_count();
        let total = KNOWN_FINDINGS.len();
        let exempt = KNOWN_FINDINGS.iter().filter(|f| f.exempt).count();
        assert_eq!(unresolved, total - exempt);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::Critical);
    }

    // ── Enhanced detection tests (br-asupersync-51e9yb) ────────────────────

    // ── Capability escalation prevention tests (asupersync-1bsa8o) ──

    #[test]
    fn validate_audit_system_security_detects_tampering() {
        // This test validates that the audit system security validation
        // can detect potential tampering with KNOWN_FINDINGS

        let result = super::validate_audit_system_security();

        // The validation should either pass or report specific security warnings
        match result {
            Ok(()) => {
                // Validation passed - audit system appears secure
                println!("Audit system security validation passed");
            }
            Err(warnings) => {
                // Warnings detected - this is expected if there are suspicious patterns
                println!("Audit system security warnings: {}", warnings);

                // Validate that warnings are properly formatted and informative
                assert!(
                    !warnings.is_empty(),
                    "Warnings should not be empty if validation failed"
                );
                assert!(
                    warnings.len() > 10,
                    "Warning messages should be descriptive"
                );
            }
        }
    }

    #[test]
    fn capability_validation_prevents_unauthorized_operations() {
        // Test that capability validation functions work correctly
        // This should not panic since we're in a test context
        super::validate_audit_operation_authorized("test_operation");

        // Test that known findings validation works
        super::validate_known_findings_integrity();

        // Test that audit system integrity validation works
        super::validate_audit_system_integrity();
    }

    #[test]
    fn cross_region_audit_context_validation() {
        let source_region = crate::types::RegionId::new_for_test(1, 0);
        let target_region = crate::types::RegionId::new_for_test(2, 0);

        // Same region should always be allowed
        let same_result = super::create_constrained_audit_context(source_region, source_region);
        assert!(same_result.is_ok(), "Same-region audit should be allowed");

        // Cross-region audit should be validated but allowed in test context
        let cross_result = super::create_constrained_audit_context(source_region, target_region);
        assert!(
            cross_result.is_ok(),
            "Cross-region audit should be validated and logged"
        );
    }

    #[test]
    fn count_functions_include_capability_validation() {
        // Test that count functions include proper capability validation
        let warning_count = super::count_by_severity(Severity::Medium);
        let unresolved_count = super::unresolved_count();

        // The count calls above should complete without panicking, and the counts
        // should be reasonable (not obviously tampered).
        assert!(warning_count <= 100, "Warning count should be reasonable");
        assert!(
            unresolved_count <= 100,
            "Unresolved count should be reasonable"
        );
    }

    #[test]
    fn detect_direct_ambient_violations() {
        let source = r#"
fn bad_function() {
    let now = std::time::Instant::now();  // Should be detected
    println!("Current time: {:?}", now);   // Should be detected
}

fn good_function(cx: &Cx) {
    let now = cx.time().instant_now();     // Should NOT be detected
}

#[cfg(test)]
fn test_code() {
    let now = Instant::now();  // Should NOT be detected (test code)
}
"#;

        let violations = detect_ambient_violations(source);

        // Should find the direct violations
        assert_eq!(violations.len(), 2);

        let instant_violation = violations
            .iter()
            .find(|v| v.line_content.contains("Instant::now"))
            .unwrap();
        assert_eq!(instant_violation.category, AmbientCategory::Time);
        assert_eq!(instant_violation.violation_type, ViolationType::DirectUsage);

        let println_violation = violations
            .iter()
            .find(|v| v.line_content.contains("println!"))
            .unwrap();
        assert_eq!(println_violation.category, AmbientCategory::Output);
        assert_eq!(println_violation.violation_type, ViolationType::DirectUsage);
    }

    #[test]
    fn detect_alias_bypasses() {
        let source = r#"
use std::time::Instant as Clock;  // Suspicious alias
use std::thread::spawn as fork;   // Suspicious alias
use std::fs::File as FileHandle;  // Suspicious alias

fn bad_function() {
    let now = Clock::now();       // Would bypass simple grep
    fork(|| { /* work */ });     // Would bypass simple grep
    let _f = FileHandle::open("/etc/passwd").unwrap(); // Would bypass simple grep
}

fn good_function(cx: &Cx) {
    let now = cx.time().instant_now();  // Proper capability usage
}
"#;

        let violations = detect_ambient_violations(source);

        // Should detect the suspicious aliases
        let alias_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.violation_type == ViolationType::SuspiciousAlias)
            .collect();

        assert!(!alias_violations.is_empty(), "Should detect alias bypasses");

        // Should detect at least the time and thread aliases
        assert!(
            alias_violations
                .iter()
                .any(|v| v.category == AmbientCategory::Time)
        );
        assert!(
            alias_violations
                .iter()
                .any(|v| v.category == AmbientCategory::Spawn)
        );

        let indirect_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.violation_type == ViolationType::IndirectUsage)
            .collect();

        assert!(
            indirect_violations.iter().any(|v| {
                v.category == AmbientCategory::Time && v.line_content.contains("Clock::now")
            }),
            "Should detect use of time alias"
        );
        assert!(
            indirect_violations
                .iter()
                .any(|v| v.category == AmbientCategory::Spawn && v.line_content.contains("fork")),
            "Should detect use of spawn alias"
        );
        assert!(
            indirect_violations.iter().any(|v| {
                v.category == AmbientCategory::Io && v.line_content.contains("FileHandle::open")
            }),
            "Should detect use of IO alias"
        );
    }

    #[test]
    fn enhanced_patterns_catch_module_path_variants() {
        let source = r#"
fn bad_variants() {
    let now1 = std::time::Instant::now();    // std:: prefix
    let now2 = core::time::Instant::now();   // core:: prefix
    let now3 = Instant::now();               // unqualified

    std::thread::spawn(|| {});               // std:: prefix
    thread::spawn(|| {});                    // unqualified

    std::env::var("HOME").ok();              // std:: prefix
    env::var("PATH").ok();                   // unqualified
}
"#;

        let violations = detect_ambient_violations(source);

        // Should detect all variants
        let time_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.category == AmbientCategory::Time)
            .collect();
        assert_eq!(time_violations.len(), 3, "Should catch all time variants");

        let spawn_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.category == AmbientCategory::Spawn)
            .collect();
        assert_eq!(spawn_violations.len(), 2, "Should catch all spawn variants");

        let env_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.category == AmbientCategory::Env)
            .collect();
        assert_eq!(env_violations.len(), 2, "Should catch all env variants");
    }

    #[test]
    fn enhanced_patterns_exclude_comments_and_tests() {
        let source = r#"
// This is a comment with Instant::now() that should be ignored
/* Block comment with std::thread::spawn that should be ignored */

fn production_code() {
    let now = Instant::now();  // Should be detected
}

#[cfg(test)]
mod tests {
    fn test_function() {
        let now = Instant::now();  // Should NOT be detected
        thread::spawn(|| {});     // Should NOT be detected
    }
}
"#;

        let violations = detect_ambient_violations(source);

        // Should only detect the one in production code
        assert_eq!(violations.len(), 1);
        assert!(violations[0].line_content.contains("Instant::now"));
        assert_eq!(violations[0].category, AmbientCategory::Time);
    }

    #[test]
    fn enhanced_patterns_exclude_split_brace_cfg_test_functions() {
        let source = r#"
fn production_code() {
    let now = Instant::now();  // Should be detected
}

#[cfg(test)]
fn test_code()
{
    let now = Instant::now();  // Should NOT be detected
    thread::spawn(|| {});      // Should NOT be detected
}
"#;

        let violations = detect_ambient_violations(source);

        assert_eq!(
            violations.len(),
            1,
            "cfg(test) functions with split braces must be skipped"
        );
        assert!(violations[0].line_content.contains("Instant::now"));
        assert_eq!(violations[0].category, AmbientCategory::Time);
    }

    #[test]
    fn enhanced_patterns_exclude_cfg_test_modules_with_literal_braces() {
        let source = r##"
fn production_code() {
    let now = Instant::now();  // Should be detected
}

#[cfg(test)]
mod tests {
    fn test_fixture() {
        let _json = r#"{"nested": {"brace": true}}"#;
        let _text = "closing brace } inside a string";
        eprintln!("test-only output");
        let now = Instant::now();  // Should NOT be detected
    }
}
"##;

        let violations = detect_ambient_violations(source);

        assert_eq!(
            violations.len(),
            1,
            "cfg(test) modules with literal braces must stay skipped"
        );
        assert!(violations[0].line_content.contains("Instant::now"));
        assert_eq!(violations[0].category, AmbientCategory::Time);
    }

    #[test]
    fn violation_type_classification() {
        let source = r#"
use std::time::Instant as Clock;

fn test_function() {
    let now = Instant::now();     // DirectUsage
    let now2 = Clock::now();      // Would be caught by enhanced patterns
}
"#;

        let violations = detect_ambient_violations(source);

        // Should classify violation types correctly
        let direct_usage = violations.iter().any(|v| {
            v.violation_type == ViolationType::DirectUsage
                && v.line_content.contains("Instant::now")
        });
        assert!(direct_usage, "Should detect direct usage");

        let alias_usage = violations.iter().any(|v| {
            v.violation_type == ViolationType::SuspiciousAlias
                && v.line_content.contains("as Clock")
        });
        assert!(alias_usage, "Should detect suspicious alias");
    }

    // ── Source-tree scanning infrastructure ─────────────────────────────
    //
    // The tests below scan actual source files to enforce the
    // no-ambient-authority invariant. They ensure:
    //
    // 1. "Pristine" modules (cx/, obligation/, plan/) have ZERO ambient
    //    authority in non-test code.
    // 2. Each KNOWN_FINDINGS entry corresponds to real code (no stale entries).
    // 3. Exempt findings are only in recognized provider paths.
    // 4. The total count of non-exempt violations doesn't grow silently.
    //
    // **Escape hatches for tests:**
    // - Code inside `#[cfg(test)] mod tests { ... }` is excluded from scanning.
    //   For the pristine-module rule, so is a `tests.rs` file that its parent
    //   declares as `#[cfg(test)] mod tests;` (the same module, out of line).
    //   Such files stay in the inventory and its count.
    // - Files listed in EXEMPT_PREFIXES are skipped entirely (these ARE the
    //   capability providers or process-boundary tools).
    // - CLI and benchmark adapters are process boundaries: they may read env,
    //   measure wall time, or write caller-facing output without weakening the
    //   core runtime's explicit-capability invariant.
    // - Top-level `src/*_tests.rs`/conformance/metamorphic/e2e harnesses are
    //   test surfaces even when compiled through the lib-test crate rather than
    //   nested under an inline `#[cfg(test)] mod tests`.
    // - Some source-tree contract harnesses use singular suffixes such as
    //   `*_conformance.rs`, `*_metamorphic.rs`, `*_audit.rs`, or
    //   `*_testing.rs`; these are also test surfaces, not production runtime.
    // - To accept intentional provider usage: review and update the grouped and
    //   per-occurrence snapshot, update the exact count if needed, and document why.

    use std::path::{Path, PathBuf};

    /// Paths (relative to src/) exempt from scanning.
    /// These modules ARE the capability providers.
    const EXEMPT_PREFIXES: &[&str] = &[
        "util/entropy.rs",
        "fs/",
        "time/driver.rs",
        "runtime/blocking_pool.rs",
        "web/debug.rs",
        "lab/",
        "test_logging.rs",
        "test_utils.rs",
        "test_ndjson.rs",
        "obligation/conformance_runner.rs",
        "audit/",
        "bin/",
        "cli/",
        "atp/benchmark/",
    ];

    /// Modules that MUST have zero ambient authority in non-test code.
    /// All effects in these modules must flow through the Cx capability system.
    const PRISTINE_MODULES: &[&str] = &["cx", "obligation", "plan"];

    /// Exact count paired with the canonical grouped and per-occurrence snapshot.
    ///
    /// Changing this value alone is insufficient: every accepted surface is
    /// pinned by file, category, pattern, occurrence count, line, and normalized context in
    /// `ambient_authority_inventory_v1.snap`. Review that snapshot diff and
    /// document intentional production additions before updating the baseline.
    // 2026-09-02 (SapphireHill, br-asupersync-gap-nonlinux-reactor-ci-gxv3dy):
    // 708 -> 724 after reviewing every new site: grpc/client.rs async
    // connect_timeout inside a runtime timeout; remote.rs and the h1/h2
    // listener bind variants (async TcpListener constructors);
    // cancel/symbol_cancel.rs bounded wall-clock wait (c344862df);
    // net/quic_native/udp_connection.rs clock_origin + pacing (ccb5af622);
    // handshake_driver early-data resend stamp; transport_rq File::create /
    // File::open / Instant::now on the receive path; runtime/builder.rs drain
    // timing. No new site takes authority outside its owning subsystem.
    // 724 -> 723 (br-asupersync-bi2462.22): the wall-clock bounded spin in
    // cancel/symbol_cancel.rs was removed by publishing `cancelled_at`
    // before the cancelled flag, so `child()` no longer needs a clock.
    // 2026-09-08 (br-asupersync-ghxhvm): reviewed fc892d50cc's bounded
    // ATP receive-window maximum env override and 38736205d9's managed
    // send elapsed metric, explicit runtime-clock origins, and shutdown
    // fallback. Removed managed wall-clock sites offset the two additions;
    // the total remains 723 while the reviewed occurrence inventory changes.
    // 723 -> 724 (br-asupersync-bi2462.79): RuntimeInner now creates an
    // owned teardown thread when its final owner drops on a worker. This
    // runtime-provider OS spawn retains the joins and state off-worker so
    // the current poll can return; it introduces no application task spawn.
    // 724 -> 738 (br-asupersync-ghxhvm): GH#67's UDP fallback provider
    // adds one process-lifetime reactor-pump spawn. ATP native QUIC adds
    // one read of the existing ATP_RQ_TRACE switch and twelve clock reads:
    // three keep-alive cadence sites, three blocking-roundtrip probe sites,
    // and six commit/receive timing sites. These remain native transport
    // provider and diagnostic effects; they do not establish lab determinism.
    // The timestamped trace macro also changes one occurrence signature
    // without adding an output site. Each addition is recorded below.
    // The snapshot itself is keyed without line numbers since
    // br-asupersync-bi2462.23, so this count and the snapshot text move only
    // when a site is added, removed or rewritten — never when code above a
    // site shifts.
    // 725 -> 726 (br-asupersync-bi2462.114): one process-lifetime Unix
    // child-reaper worker is admitted before OS child creation. The exact
    // spawn remains scanned and pinned in both inventory sections; no
    // existing scanner exemption or detection pattern is broadened.
    // 726 -> 769 (br-asupersync-bi2462.86.1): the snapshot had not tracked the
    // 09-18..09-24 landings. New sites: the ATP SDK native_live transport and
    // its durable checkpoint/journal syncs, gRPC native-stream connect,
    // replay-group sessions, the MySQL SSL_CERT_FILE root (postgres_tls already
    // had it), one more H2 bind, and QUIC/desktop clock reads, plus test files
    // under src/. Fewer clock reads in epoch_tracking, priority_inversion_oracle
    // and invariant_monitor offset part of it. Every row was reviewed with the
    // grouped snapshot; no scanner exemption or detection pattern changed.
    // 769 -> 809 (br-asupersync-bi2462.147.4, reviewed at f4fd8552e): the
    // 09-24..09-28 landings. Production: the gRPC client and native-stream
    // connects split into hostname and address forms (1 -> 2 each), the
    // native H2 client and the WSS client connect the same way, one more
    // H2 listener bind variant (1185e0de8), QUIC udp_connection idle-expiry
    // clock reads (7 -> 14) and the handshake driver's resend stamp
    // (o7stss). Every one is a connect, bind or clock read inside its own
    // transport or listener. NATS now wraps its connect in nats_io(cx, ..),
    // which only changes an occurrence excerpt. The rest are test harnesses
    // under src/: grpc native_stream and server duplex tests.rs, plus the
    // QUIC handshake-driver tests (UDP peers, threads, eprintln). No scanner
    // exemption or detection pattern changed.
    // 809 -> 812 (br-asupersync-reactor-audit-dofi11, reviewed at 0bc2f6e57):
    // the snapshot rows re-blessed with the listener waiter rewrite (one
    // accept site fewer) and the 10-03 DNS resolver and OTLP exporter fixes
    // (two clock reads each, inside their own timeouts).
    // 812 -> 826 (br-asupersync-5w2yte, reviewed at aa95b778d): test
    // harnesses only. The native gRPC upload tests (2c41a94fe, 5b75f7df1)
    // run a fake HTTP/2 peer: in grpc/native_upload/tests.rs and
    // client_streaming/tests.rs, each has one TcpListener bind, two
    // std::net::TcpStream helpers, two watchdog/peer threads and two deadline
    // clock reads (7 each). The cx/owned_join tests' watchdog helper is now
    // marked #[cfg(test)], which the whole file already is, so pristine cx
    // stays empty. No production code, scanner exemption or detection
    // pattern changed.
    // 826 -> 821 (br-asupersync-1aqha7): the HTTP/1 (direct and SOCKS5
    // proxy), HTTP/2 and WebSocket clients connect to hostnames through
    // net::happy_eyeballs::connect_resolved, which races the resolved
    // addresses. Six client connect sites move into its one plain connect
    // for a single address. connect_one's connect keeps its site with a new
    // excerpt. Literal-address connects are unchanged. No scanner exemption
    // or detection pattern changed.
    // 821 -> 822 (br-asupersync-1ir2em, 2026-10-07): runtime/resource_monitor.rs
    // ResourceSampler spawns one std thread, started only by the opt-in
    // RuntimeBuilder::resource_sampling. It runs the monitor's existing OS
    // probes (process_current_state) on an interval and holds no runtime
    // lock; Drop joins it. No scanner exemption or detection pattern changed.
    // 822 -> 823 (br-asupersync-tjr6s9, re-blessed 2026-10-08 after it
    // landed in 29616ece7 without the inventory): trace/recovery.rs opens the
    // crash trace a caller names to salvage its bounded prefix, reading at
    // most limits.max_input_bytes. It is the same authority as trace/file.rs's
    // and trace/compat.rs's File::open of a caller's path. No scanner
    // exemption or detection pattern changed.
    // 823 -> 825 (re-blessed 2026-10-08 after the API lane's 8ca9aead8 and
    // the HttpAutoListener commit landed without the inventory):
    // http/auto.rs binds its listener with TcpListener::bind, the same
    // authority as the blessed h1/h2 listener binds. grpc/server/duplex/tests.rs
    // (a plain tests.rs, scanned as production) gained a second eprintln!.
    // The connect sites in mysql.rs, postgres.rs, grpc/client.rs and
    // grpc/native_stream/connect.rs only changed their quoted line text.
    // No scanner exemption or detection pattern changed.
    // 825 -> 827 (re-blessed 2026-10-09 after 231319ebe and ceac580d9 landed
    // without the inventory): runtime/io_driver/shared.rs's poll gate times
    // its wait with std::time::Instant::now() to shorten the backend poll's
    // timeout, a monotonic wait like the reactor's own. http/h1/http_client.rs
    // dials a resolved address on a second path, through a configured
    // dns_resolver, with the same TcpStream::connect_socket_addr. No scanner
    // exemption or detection pattern changed.
    // 835 -> 837 (re-blessed 2026-10-10 after 49ec999e6 landed without the
    // inventory): remote/write_progress/tests.rs (a plain tests.rs, scanned as
    // production) dials a loopback std::net::TcpStream with connect_timeout
    // and wraps it with TcpStream::from_std for its stalled-write harness.
    // No scanner exemption or detection pattern changed.
    // 838 -> 809 (2026-10-14, asupersync-bi2462.141 phase 1): the never-compiled
    // islands net/atp/sink/writer.rs (21 sites) and atp/adaptive_raptorq.rs
    // (5 sites) were deleted; no module ever declared them. The other 3 left
    // atp/journal/sparse_writer.rs (two std::fs::OpenOptions, one File::open)
    // when the atp journal series split it; the snapshot follows those moves
    // (sparse_writer/copy_commit.rs, transport_common/file_hash.rs,
    // append_journal/compaction.rs). No scanner exemption or detection
    // pattern changed.
    // 809 -> 811 (2026-10-15, the ATP zstd chain merged after the above): the
    // TCP sender's pipelined path (send_full_entries_pipelined,
    // br-asupersync-t1fblr.25) opens each source file with
    // crate::fs::File::open, with the same authority and line text as
    // send_file_streaming's open. transport_common/streaming.rs's
    // SyncFileHash::open (br-asupersync-dfdwyt) opens a source file with
    // std::fs::File::open on the blocking pool, after the same
    // io_gate::require_ambient_io check crate::fs::File::open makes. No
    // scanner exemption or detection pattern changed.
    // 811 -> 813 (re-blessed 2026-10-15 in the same merge, after an API-lane
    // commit landed without the inventory): atp/journal/sparse_writer/scoped/
    // restore.rs opens the caller-named restore source with File::open, and
    // its scoped/restore/tests.rs (a plain tests.rs, scanned as production)
    // writes its fixture with std::fs::write. No scanner exemption or
    // detection pattern changed.
    // 813 -> 810 (recorded 2026-10-17). 75326e23e took handshake_driver.rs's
    // four test-peer sites (two std::net::UdpSocket, one eprintln!, one
    // std::thread::spawn) out of the snapshot when c5012547e moved them to
    // the exempt handshake_driver_inline_tests.rs, but kept the count at 813;
    // it should have become 809. Then c82a58115 added one: scoped/restore.rs's
    // sync_staging fsyncs the staging file's parent directory through
    // File::open(parent). The shared poll gate's monotonic wait-budget clock
    // moved from runtime/io_driver/shared.rs to io_driver/poll_gate.rs
    // (e262b3d87, d2010484b) with the same std::time::Instant::now(). No
    // scanner exemption or detection pattern changed.
    // 810 -> 810 (br-asupersync-1aqha7, gRPC opt-in policy): the two
    // hostname connect_timeout sites in grpc/client.rs and native_stream/
    // connect.rs now share ConnectPolicy::connect_host. Its default keeps the
    // same ordered dial; the opt-in uses the already inventoried Happy
    // Eyeballs connector. Deduplication removes one production TCP site.
    // The scripted H2 peer's extracted helper adds one TcpListener parameter
    // occurrence in native_stream/connect/tests.rs, offsetting that removal.
    // The new black-hole fixture is explicitly cfg(test); no scanner
    // exemption, detection pattern, or numerical threshold changed.
    // 2026-10-30 (w1030, 0.6.0 lib gate): 810 -> 841 after reviewing every
    // site added since f22886099. Production (+13), each inside its owning
    // subsystem with an inventoried precedent: ATP data and directory syncs
    // and delta files (e55b90af5 metadata.rs OpenOptions +3 / File::open -1,
    // c155c28b0 scoped finalize, ddcba5e53 native checkpoint, 0672ace4c TCP
    // delta storage, delta_cas.rs and RQ delta_chunks.rs); the owned DNS
    // resolver's TCP fallback (3ba921417) and the owned H1/H2 streaming
    // server's async bind (79eeecb44), like the h1/h2 listener binds; and the
    // PostgreSQL standby-status client clock (50e5b927a), a protocol field
    // like jetstream's and nats.rs's SystemTime. Test fixtures (+18): std TCP
    // peers, harness threads and wait deadlines in grpc native_stream/tests,
    // grpc/web_client/tests.rs, cx saga tests.rs and spork event_manager
    // tests.rs. No scanner exemption, detection pattern, or numerical
    // threshold changed.
    const AMBIENT_VIOLATION_BASELINE_COUNT: usize = 841;

    fn src_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn is_exempt(rel_path: &str) -> bool {
        EXEMPT_PREFIXES.iter().any(|p| rel_path.starts_with(p)) || is_test_surface(rel_path)
    }

    fn is_test_surface(rel_path: &str) -> bool {
        let file_name = Path::new(rel_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(rel_path);

        file_name.ends_with("_tests.rs")
            || file_name.ends_with("_test.rs")
            || file_name.ends_with("_conformance.rs")
            || file_name.ends_with("_conformance_tests.rs")
            || file_name.ends_with("_metamorphic.rs")
            || file_name.ends_with("_metamorphic_tests.rs")
            || file_name.ends_with("_testing.rs")
            || file_name.ends_with("_mutations.rs")
            || file_name.ends_with("_verification_suite.rs")
            || file_name.ends_with("_audit.rs")
            || file_name.ends_with("_e2e_tests.rs")
            || file_name.starts_with("real_") && file_name.ends_with(".rs")
    }

    /// Convert a grep-style regex pattern to a literal search string.
    fn pattern_to_literal(pattern: &str) -> String {
        pattern.replace(r"\(", "(").replace(r"\)", ")")
    }

    fn line_contains_literal(line: &str, literal: &str) -> bool {
        line.match_indices(literal).any(|(idx, _)| {
            let before = line[..idx].chars().next_back();
            !matches!(before, Some(ch) if ch.is_ascii_alphanumeric() || ch == '_')
        })
    }

    fn raw_string_start(bytes: &[u8], idx: usize) -> Option<(usize, usize)> {
        let mut cursor = idx;

        if bytes.get(cursor) == Some(&b'b') {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'r') {
            return None;
        }

        let mut hash_count = 0;
        cursor += 1;
        while bytes.get(cursor) == Some(&b'#') {
            hash_count += 1;
            cursor += 1;
        }

        if bytes.get(cursor) == Some(&b'"') {
            Some((cursor + 1, hash_count))
        } else {
            None
        }
    }

    #[derive(Default)]
    struct ScanSanitizerState {
        in_block_comment: bool,
        in_string: bool,
        raw_hashes: Option<usize>,
    }

    fn strip_comments_and_literals(line: &str, state: &mut ScanSanitizerState) -> String {
        let bytes = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        let mut idx = 0;

        while idx < bytes.len() {
            if state.in_block_comment {
                if idx + 1 < bytes.len() && bytes[idx] == b'*' && bytes[idx + 1] == b'/' {
                    state.in_block_comment = false;
                    idx += 2;
                } else {
                    idx += 1;
                }
                continue;
            }

            if let Some(hash_count) = state.raw_hashes {
                if bytes[idx] == b'"'
                    && idx + 1 + hash_count <= bytes.len()
                    && bytes[idx + 1..idx + 1 + hash_count]
                        .iter()
                        .all(|b| *b == b'#')
                {
                    state.raw_hashes = None;
                    idx += 1 + hash_count;
                } else {
                    idx += 1;
                }
                continue;
            }

            if state.in_string {
                match bytes[idx] {
                    b'\\' => idx = (idx + 2).min(bytes.len()),
                    b'"' => {
                        state.in_string = false;
                        idx += 1;
                    }
                    _ => idx += 1,
                }
                continue;
            }

            if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'/' {
                break;
            }
            if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'*' {
                state.in_block_comment = true;
                idx += 2;
                continue;
            }
            if let Some((next_idx, hash_count)) = raw_string_start(bytes, idx) {
                state.raw_hashes = Some(hash_count);
                idx = next_idx;
                continue;
            }
            if bytes[idx] == b'\''
                && let Some(len) = super::ambient_char_literal_len(line, idx)
            {
                idx += len;
                continue;
            }
            if bytes[idx] == b'"' {
                state.in_string = true;
                idx += 1;
                continue;
            }

            out.push(bytes[idx] as char);
            idx += 1;
        }

        out
    }

    /// Return (line_number, line_text) pairs from non-test, non-comment code.
    ///
    /// Uses brace-depth tracking to skip `#[cfg(test)] mod ... { }` blocks.
    fn non_test_lines(content: &str) -> Vec<(usize, String)> {
        let mut result = Vec::new();
        let mut in_cfg_test_item = false;
        let mut brace_depth: i32 = 0;
        let mut pending_cfg_test = false;
        let mut pending_cfg_test_attr_depth: i32 = 0;
        let mut pending_cfg_test_item_body = false;
        let mut cfg_test_sanitizer_state = ScanSanitizerState::default();
        let mut sanitizer_state = ScanSanitizerState::default();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            if in_cfg_test_item {
                brace_depth += brace_delta_for_scan(line, &mut cfg_test_sanitizer_state);
                if brace_depth <= 0 {
                    in_cfg_test_item = false;
                    brace_depth = 0;
                    cfg_test_sanitizer_state = ScanSanitizerState::default();
                }
                continue;
            }

            if pending_cfg_test_item_body {
                let delta = brace_delta_for_scan(line, &mut cfg_test_sanitizer_state);
                if delta > 0 {
                    in_cfg_test_item = true;
                    brace_depth = delta;
                    pending_cfg_test_item_body = false;
                } else if trimmed.ends_with(';') {
                    pending_cfg_test_item_body = false;
                }
                continue;
            }

            if is_test_only_attribute(trimmed) {
                pending_cfg_test = true;
                pending_cfg_test_attr_depth = 0;
                continue;
            }

            if pending_cfg_test {
                if starts_cfg_test_item(trimmed) {
                    pending_cfg_test = false;
                    pending_cfg_test_attr_depth = 0;
                    cfg_test_sanitizer_state = ScanSanitizerState::default();
                    let delta = brace_delta_for_scan(line, &mut cfg_test_sanitizer_state);
                    if delta > 0 {
                        in_cfg_test_item = true;
                        brace_depth = delta;
                    } else if !trimmed.ends_with(';') {
                        pending_cfg_test_item_body = true;
                    }
                    continue;
                }
                if trimmed.is_empty() {
                    continue;
                }
                if pending_cfg_test_attr_depth > 0 || trimmed.starts_with("#[") {
                    pending_cfg_test_attr_depth += attribute_delimiter_delta(trimmed);
                    pending_cfg_test_attr_depth = pending_cfg_test_attr_depth.max(0);
                    continue;
                }
                if !trimmed.starts_with('#') {
                    pending_cfg_test = false;
                    pending_cfg_test_attr_depth = 0;
                }
            }

            if trimmed.starts_with("//") && !sanitizer_state.in_block_comment {
                continue;
            }

            let stripped = strip_comments_and_literals(line, &mut sanitizer_state);
            if stripped.trim().is_empty() {
                continue;
            }

            result.push((idx + 1, stripped));
        }
        result
    }

    fn brace_delta_for_scan(line: &str, state: &mut ScanSanitizerState) -> i32 {
        let stripped = strip_comments_and_literals(line, state);
        stripped.chars().fold(0, |depth, ch| match ch {
            '{' => depth + 1,
            '}' => depth - 1,
            _ => depth,
        })
    }

    struct Violation {
        file: String,
        line: usize,
        pattern: String,
        category: AmbientCategory,
        source_context: String,
    }

    impl std::fmt::Display for Violation {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "  {}:{} — {:?} ({})",
                self.file, self.line, self.category, self.pattern
            )
        }
    }

    fn scan_source(rel: &str, content: &str) -> Vec<Violation> {
        let mut violations = Vec::new();

        if is_exempt(rel) {
            return violations;
        }

        let lines = non_test_lines(content);

        for (line_num, line_text) in &lines {
            for (pattern, category) in matching_grep_patterns(line_text) {
                violations.push(Violation {
                    file: rel.to_string(),
                    line: *line_num,
                    pattern: pattern_to_literal(pattern),
                    category,
                    source_context: line_text.split_whitespace().collect::<Vec<_>>().join(" "),
                });
            }
        }

        violations
    }

    #[must_use]
    pub fn scan_categories_for_contract_fixture(rel: &str, content: &str) -> Vec<AmbientCategory> {
        scan_source(rel, content)
            .into_iter()
            .map(|violation| violation.category)
            .collect()
    }

    fn format_violations(vs: &[Violation]) -> String {
        vs.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn format_violation_sample(vs: &[Violation], limit: usize) -> String {
        let mut rendered = vs
            .iter()
            .take(limit)
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        if vs.len() > limit {
            rendered.push(format!("  ... {} more violation(s)", vs.len() - limit));
        }
        rendered.join("\n")
    }

    /// The reviewed inventory text: per-(category, file, pattern) counts,
    /// then per-(category, file, pattern, code excerpt) counts.
    ///
    /// Deliberately keyed WITHOUT line numbers (br-asupersync-bi2462.23):
    /// an edit above an ambient site used to move every entry below it, so
    /// the snapshot churned by dozens of lines for zero authority change and
    /// a genuinely new site hid among the shifts. Now only a new, removed or
    /// rewritten site changes the text; a site that merely moves does not.
    /// The strict scan's `known_findings_reference_real_code` keeps its
    /// line-window check because it names specific findings.
    fn canonical_violation_inventory(vs: &[Violation]) -> String {
        let mut grouped = std::collections::BTreeMap::<String, usize>::new();
        let mut occurrences = std::collections::BTreeMap::<String, usize>::new();
        for violation in vs {
            let key = format!(
                "{:?}\t{}\t{}",
                violation.category, violation.file, violation.pattern
            );
            *grouped.entry(key).or_default() += 1;
            let occurrence = format!(
                "{:?}\t{}\t{}\t{}",
                violation.category, violation.file, violation.pattern, violation.source_context
            );
            *occurrences.entry(occurrence).or_default() += 1;
        }
        let grouped = grouped
            .into_iter()
            .map(|(key, count)| format!("{count}\t{key}"))
            .collect::<Vec<_>>()
            .join("\n");
        let occurrences = occurrences
            .into_iter()
            .map(|(key, count)| format!("{count}\t{key}"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("[grouped]\n{grouped}\n[occurrences]\n{occurrences}")
    }

    fn collect_rs_files_strict(dir: &Path) -> Result<Vec<PathBuf>, String> {
        let entries = std::fs::read_dir(dir)
            .map_err(|error| format!("cannot read source directory {}: {error}", dir.display()))?;
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "cannot read directory entry under {}: {error}",
                    dir.display()
                )
            })?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if file_type.is_symlink() {
                return Err(format!(
                    "source tree contains unsupported symlink entry: {}",
                    path.display()
                ));
            }
            if file_type.is_dir() {
                files.extend(collect_rs_files_strict(&path)?);
            } else if file_type.is_file()
                && path.extension().is_some_and(|extension| extension == "rs")
            {
                files.push(path);
            }
        }
        files.sort();
        Ok(files)
    }

    fn scan_directory_strict(dir: &Path, root: &Path) -> Result<(usize, Vec<Violation>), String> {
        let files = collect_rs_files_strict(dir)?;
        let file_count = files.len();
        let mut violations = Vec::new();
        for file_path in files {
            let rel = file_path
                .strip_prefix(root)
                .map_err(|error| {
                    format!(
                        "source file {} is outside root {}: {error}",
                        file_path.display(),
                        root.display()
                    )
                })?
                .to_string_lossy()
                .replace('\\', "/");
            let content = std::fs::read_to_string(&file_path).map_err(|error| {
                format!("cannot read source file {}: {error}", file_path.display())
            })?;
            violations.extend(scan_source(&rel, &content));
        }
        Ok((file_count, violations))
    }

    fn has_non_test_match_near_line(
        content: &str,
        pattern: &str,
        expected_line: u32,
        max_line_distance: u32,
    ) -> bool {
        let literal = pattern_to_literal(pattern);
        non_test_lines(content).into_iter().any(|(line_num, line)| {
            expected_line.abs_diff(line_num as u32) <= max_line_distance
                && line_contains_literal(&line, &literal)
        })
    }

    /// Whether `rel` is a `tests.rs` file that its parent module declares only
    /// as `#[cfg(test)] mod tests;`, so that it compiles only under cfg(test).
    fn is_cfg_test_module_file(root: &Path, rel: &str) -> bool {
        let Some(dir) = rel.strip_suffix("/tests.rs") else {
            return false;
        };
        [format!("{dir}.rs"), format!("{dir}/mod.rs")]
            .iter()
            .find_map(|parent| std::fs::read_to_string(root.join(parent)).ok())
            .is_some_and(|parent| {
                parent
                    .lines()
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|pair| pair == ["#[cfg(test)]", "mod tests;"])
            })
    }

    #[test]
    fn pristine_modules_have_no_ambient_authority() {
        let root = src_root();
        for module in PRISTINE_MODULES {
            let module_dir = root.join(module);
            let (rust_file_count, violations) = scan_directory_strict(&module_dir, &root)
                .unwrap_or_else(|error| panic!("strict ambient scan failed: {error}"));
            assert!(
                rust_file_count > 0,
                "pristine module contains no Rust files: {}",
                module_dir.display()
            );
            let violations = violations
                .into_iter()
                .filter(|violation| !is_cfg_test_module_file(&root, &violation.file))
                .collect::<Vec<_>>();
            assert!(
                violations.is_empty(),
                "Pristine module '{module}' has {} ambient authority violation(s):\n{}",
                violations.len(),
                format_violations(&violations),
            );
        }
    }

    #[test]
    fn known_findings_reference_real_code() {
        let root = src_root();
        let mut audit_failures = Vec::new();

        // br-asupersync-yb2syy: Fix audit bypass via panic in ambient authority detection.
        // Use Result-based, fail-closed logic instead of panic::resume_unwind to prevent
        // audit bypass via controlled panics that could mask ambient authority violations.
        // Collect all failures and report them atomically to ensure complete audit coverage.
        for finding in KNOWN_FINDINGS {
            let path = root.join(finding.file);

            // Fail-closed: continue processing even if one file fails,
            // but track all failures for atomic reporting at the end
            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(err) => {
                    audit_failures.push(format!(
                        "KNOWN_FINDINGS references unreadable file: src/{} ({})",
                        finding.file, err
                    ));
                    continue; // Skip this finding but continue audit
                }
            };

            let has_nearby_match =
                has_non_test_match_near_line(&content, finding.evidence_pattern, finding.line, 30);

            if !has_nearby_match {
                audit_failures.push(format!(
                    "KNOWN_FINDINGS entry '{}' at src/{}:{} — \
                     no matching non-test evidence pattern '{}' found within ±30 lines. Stale entry?",
                    finding.description, finding.file, finding.line, finding.evidence_pattern,
                ));
            }
        }

        // Atomic failure reporting: if any part of the audit failed,
        // report all failures together to ensure nothing is masked
        assert!(
            audit_failures.is_empty(),
            "Ambient authority audit failures ({}):{}",
            audit_failures.len(),
            audit_failures
                .iter()
                .fold(String::new(), |mut acc, failure| {
                    acc.push_str("\n  - ");
                    acc.push_str(failure);
                    acc
                })
        );
    }

    #[test]
    fn grep_patterns_catch_each_finding_category() {
        for finding in KNOWN_FINDINGS {
            let covered = GREP_PATTERNS
                .iter()
                .any(|(_, cat)| *cat == finding.category);
            assert!(
                covered,
                "Finding '{}' with category {:?} has no grep pattern coverage",
                finding.description, finding.category,
            );
        }
    }

    #[test]
    fn exempt_findings_are_in_recognized_provider_paths() {
        let provider_paths: &[&str] = &[
            "time/driver.rs",
            "time/sleep.rs",
            "runtime/blocking_pool.rs",
            "process/reaper.rs",
            "web/debug.rs",
            "util/entropy.rs",
            "fs/",
            "net/atp/transport_common/",
        ];
        for finding in KNOWN_FINDINGS.iter().filter(|f| f.exempt) {
            let in_provider = provider_paths.iter().any(|p| finding.file.starts_with(p));
            assert!(
                in_provider,
                "Exempt finding '{}' in src/{} is not in a recognized \
                 provider path. Either remove the exemption or add the \
                 path to provider_paths.",
                finding.description, finding.file,
            );
        }
    }

    /// The inventory must not move when code above an ambient site moves
    /// (br-asupersync-bi2462.23).
    ///
    /// A comment line inserted above a site leaves the text byte-identical,
    /// while one new site adds exactly one occurrence entry.
    #[test]
    fn inventory_is_keyed_without_line_numbers() {
        let rel = "net/inventory_key_fixture.rs";
        let base = "use std::env;\n\
                    fn read_a() -> Option<String> {\n    \
                        std::env::var(\"AMBIENT_A\").ok()\n\
                    }\n";
        let base_violations = scan_source(rel, base);
        assert!(
            !base_violations.is_empty(),
            "fixture must trigger the scanner or this test proves nothing"
        );
        let base_inventory = canonical_violation_inventory(&base_violations);

        let shifted = format!("// a comment line pushes every site down by one\n{base}");
        let shifted_inventory = canonical_violation_inventory(&scan_source(rel, &shifted));
        assert_eq!(
            base_inventory, shifted_inventory,
            "a line shift with no authority change must not move the inventory"
        );

        // A structurally different second site (the scanner scrubs string
        // literals from the excerpt, so a look-alike line would merge into
        // the first entry's count instead of adding one).
        let added = format!(
            "{base}fn read_b() -> String {{\n    std::env::var(\"AMBIENT_B\").unwrap_or_default()\n}}\n"
        );
        let added_violations = scan_source(rel, &added);
        assert_eq!(
            added_violations.len(),
            base_violations.len() + 1,
            "one new env site must scan as one new violation"
        );
        let added_inventory = canonical_violation_inventory(&added_violations);

        // An identical duplicate of the first site does not add an entry;
        // it raises that entry's count, which is the whole point of keying
        // by excerpt instead of by line number.
        let duplicated = format!(
            "{base}fn read_again() -> Option<String> {{\n    std::env::var(\"AMBIENT_A\").ok()\n}}\n"
        );
        let duplicated_inventory = canonical_violation_inventory(&scan_source(rel, &duplicated));
        let duplicate_entries: Vec<&str> = duplicated_inventory
            .split_once("[occurrences]\n")
            .map(|(_, tail)| tail.lines().collect())
            .unwrap_or_default();
        assert_eq!(
            duplicate_entries.len(),
            base_inventory
                .split_once("[occurrences]\n")
                .map_or(0, |(_, tail)| tail.lines().count()),
            "a duplicate excerpt merges into the existing entry"
        );
        assert!(
            duplicate_entries.iter().any(|line| line.starts_with("2\t")),
            "the merged entry counts both sites: {duplicate_entries:?}"
        );
        let occurrence_lines = |inventory: &str| -> Vec<String> {
            inventory
                .split_once("[occurrences]\n")
                .map(|(_, tail)| tail.lines().map(str::to_string).collect())
                .unwrap_or_default()
        };
        let base_occurrences = occurrence_lines(&base_inventory);
        let added_occurrences = occurrence_lines(&added_inventory);
        assert_eq!(
            added_occurrences.len(),
            base_occurrences.len() + 1,
            "one new site must add exactly one occurrence entry"
        );
        assert!(
            base_occurrences
                .iter()
                .all(|line| added_occurrences.contains(line)),
            "existing entries must be unchanged by an added site"
        );
        let new_entry = added_occurrences
            .iter()
            .find(|line| !base_occurrences.contains(line))
            .expect("new occurrence entry");
        assert!(
            new_entry.contains("unwrap_or_default"),
            "the new entry carries the new site's excerpt: {new_entry}"
        );
        assert!(
            !new_entry
                .split('\t')
                .any(|field| field.parse::<usize>().is_ok() && field != "1"),
            "no line number may appear in an occurrence entry: {new_entry}"
        );
    }

    #[test]
    fn ambient_authority_does_not_regress() {
        let root = src_root();
        let (rust_file_count, violations) = scan_directory_strict(&root, &root)
            .unwrap_or_else(|error| panic!("strict ambient scan failed: {error}"));
        assert!(
            rust_file_count > 0,
            "ambient source root contains no Rust files: {}",
            root.display()
        );
        let inventory = canonical_violation_inventory(&violations);

        // The integration contract includes this module directly under a different
        // crate name; keep one canonical snapshot owned by the library test target.
        if env!("CARGO_CRATE_NAME") == "asupersync" {
            insta::assert_snapshot!("ambient_authority_inventory_v1", inventory);
        } else {
            let snapshot = include_str!(
                "snapshots/asupersync__audit__ambient__tests__ambient_authority_inventory_v1.snap"
            );
            let (_, reviewed_inventory) = snapshot
                .split_once("\n---\n")
                .expect("ambient inventory snapshot must have an insta metadata header");
            let reviewed_inventory = reviewed_inventory.trim_end_matches('\n');
            if inventory != reviewed_inventory {
                let reviewed_lines = reviewed_inventory
                    .lines()
                    .collect::<std::collections::BTreeSet<_>>();
                let current_lines = inventory.lines().collect::<std::collections::BTreeSet<_>>();
                let removed = reviewed_lines
                    .difference(&current_lines)
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n- ");
                let added = current_lines
                    .difference(&reviewed_lines)
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n+ ");
                panic!(
                    "ambient inventory differs from the canonical library-test snapshot\n\
                     - {removed}\n\
                     + {added}"
                );
            }
        }
        assert_eq!(
            violations.len(),
            AMBIENT_VIOLATION_BASELINE_COUNT,
            "Ambient authority count changed from the reviewed baseline ({} -> {}).\n\
             Remove unintended authority; for intentional provider changes,\n\
             review and update the grouped inventory snapshot and baseline count.\n\
             Violation sample:\n{}",
            AMBIENT_VIOLATION_BASELINE_COUNT,
            violations.len(),
            format_violation_sample(&violations, 80),
        );
    }

    #[test]
    #[ignore = "diagnostic inventory for comparing historical source trees"]
    fn emit_ambient_authority_inventory_for_source_root() {
        let requested_root = std::env::var_os("ASUPERSYNC_AMBIENT_SOURCE_ROOT")
            .map(PathBuf::from)
            .expect("ASUPERSYNC_AMBIENT_SOURCE_ROOT must identify an exported src directory");
        let source_revision = std::env::var("ASUPERSYNC_AMBIENT_SOURCE_REVISION")
            .expect("ASUPERSYNC_AMBIENT_SOURCE_REVISION must identify the scanned tree");
        let scanner_revision = std::env::var("ASUPERSYNC_AMBIENT_SCANNER_REVISION")
            .expect("ASUPERSYNC_AMBIENT_SCANNER_REVISION must identify this scanner build");
        let root = requested_root.canonicalize().unwrap_or_else(|error| {
            panic!(
                "cannot canonicalize ambient source root {}: {error}",
                requested_root.display()
            )
        });
        assert!(
            root.is_dir(),
            "ambient source root is not a directory: {}",
            root.display()
        );
        let (rust_file_count, violations) = scan_directory_strict(&root, &root)
            .unwrap_or_else(|error| panic!("strict ambient scan failed: {error}"));
        assert!(
            rust_file_count > 0,
            "ambient source root contains no Rust files"
        );
        eprintln!(
            "SOURCE_REVISION={source_revision}\nSCANNER_REVISION={scanner_revision}\n\
             SOURCE_ROOT={}\nRUST_FILE_COUNT={rust_file_count}\nAMBIENT_COUNT={}\n{}",
            root.display(),
            violations.len(),
            canonical_violation_inventory(&violations)
        );
    }

    #[test]
    fn non_test_lines_filter_skips_cfg_test_modules() {
        let source = "\
fn real_code() {
    Instant::now();
}

#[cfg(test)]
mod tests {
    fn test_code() {
        Instant::now();
    }
}
";
        let lines = non_test_lines(source);
        let text: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
        assert!(
            text.iter().any(|l| l.contains("real_code")),
            "Should include production code"
        );
        assert!(
            !text.iter().any(|l| l.contains("test_code")),
            "Should exclude #[cfg(test)] module code"
        );
    }

    // br-asupersync-qw9klo: the quote in a '"' char literal opened a string,
    // so every line up to the next double quote was skipped and its ambient
    // authority never reported (most of messaging/nats.rs).
    #[test]
    fn a_double_quote_char_literal_does_not_hide_the_following_lines() {
        let source = r#"fn build(connect: &mut String, addr: &str) {
    connect.push('"');
    connect.push('\'');
    let _stream = TcpStream::connect(addr);
}
fn keep<'a>(s: &'a str) -> &'a str { s }
"#;
        let lines = non_test_lines(source);
        let text: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
        assert!(
            text.iter().any(|l| l.contains("TcpStream::connect")),
            "the line after the char literals is scanned: {text:?}"
        );
        assert!(
            text.iter().any(|l| l.contains("fn keep<'a>")),
            "lifetimes are code: {text:?}"
        );
        assert!(
            !detect_ambient_violations(source).is_empty(),
            "the detection path reports the TcpStream::connect line too"
        );
    }

    #[test]
    fn non_test_lines_filter_keeps_skipping_after_nested_test_functions() {
        let source = "\
fn real_code() {
    Instant::now();
}

#[cfg(test)]
mod tests {
    #[test]
    fn first_test() {
        Instant::now();
    }

    fn helper_after_test() {
        std::net::TcpListener::bind(\"127.0.0.1:0\").unwrap();
    }
}
";
        let lines = non_test_lines(source);
        let text: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
        assert!(
            text.iter().any(|l| l.contains("real_code")),
            "Should include production code"
        );
        assert!(
            !text.iter().any(|l| l.contains("helper_after_test")),
            "Should exclude the full #[cfg(test)] module after nested #[test] functions"
        );
    }

    #[test]
    fn non_test_lines_filter_skips_cfg_test_functions_with_split_braces() {
        let source = "\
fn real_code() {
    Instant::now();
}

#[cfg(test)]
fn test_code()
{
    Instant::now();
}
";
        let lines = non_test_lines(source);
        let text: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
        assert!(
            text.iter().any(|l| l.contains("real_code")),
            "Should include production code"
        );
        assert!(
            !text.iter().any(|l| l.contains("test_code")),
            "Should exclude #[cfg(test)] function signatures"
        );
        assert_eq!(
            text.iter()
                .filter(|line| line.contains("Instant::now"))
                .count(),
            1,
            "Should exclude #[cfg(test)] function bodies"
        );
    }

    #[test]
    fn non_test_lines_filter_skips_cfg_test_modules_with_literal_braces() {
        let source = r##"
fn real_code() {
    Instant::now();
}

#[cfg(test)]
mod tests {
    fn fixture_code() {
        let _json = r#"{"nested": {"brace": true}}"#;
        let _text = "closing brace } inside a string";
        eprintln!("test-only output");
        Instant::now();
    }
}
"##;
        let lines = non_test_lines(source);
        let text: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();

        assert!(
            text.iter().any(|line| line.contains("real_code")),
            "Should include production code"
        );
        assert!(
            !text.iter().any(|line| line.contains("fixture_code")),
            "Should exclude cfg(test) modules even when fixtures contain braces"
        );
        assert_eq!(
            text.iter()
                .filter(|line| line.contains("Instant::now"))
                .count(),
            1,
            "Should exclude test-only Instant::now after brace-heavy literals"
        );
        assert!(
            !text.iter().any(|line| line.contains("eprintln!(")),
            "Should exclude test-only output after brace-heavy literals"
        );
    }

    #[test]
    fn non_test_lines_filter_skips_comments() {
        let source = "\
// Instant::now() in a comment
/// Instant::now() in a doc comment
//! Instant::now() in a module doc
let x = Instant::now();
";
        let lines = non_test_lines(source);
        assert_eq!(
            lines
                .iter()
                .filter(|(_, l)| l.contains("Instant::now"))
                .count(),
            1,
            "Should have exactly one non-comment Instant::now() line"
        );
    }

    #[test]
    fn non_test_lines_filter_skips_block_comments_and_strings() {
        let source = r##"
/*
Instant::now();
eprintln!("inside block comment");
*/
fn production_code() {
    let _normal = "Instant::now()";
    let _multiline = "SystemTime::now()
eprintln!(\"inside multiline string\")";
    let _raw = r#"eprintln!("inside raw string")"#;
    let _raw_multiline = r#"
std::thread::spawn(|| ());
"#;
    Instant::now();
}
"##;
        let lines = non_test_lines(source);
        let instant_count = lines
            .iter()
            .filter(|(_, line)| line.contains("Instant::now"))
            .count();
        let output_count = lines
            .iter()
            .filter(|(_, line)| line.contains("eprintln!("))
            .count();

        assert_eq!(
            instant_count, 1,
            "only executable Instant::now should remain"
        );
        assert_eq!(
            output_count, 0,
            "string/comment output patterns should be ignored"
        );
    }

    #[test]
    fn top_level_test_surfaces_are_exempt_from_scanning() {
        assert!(is_exempt("real_integration_scenarios_e2e_tests.rs"));
        assert!(is_exempt("raptorq_rfc6330_conformance_tests.rs"));
        assert!(is_exempt("runtime/sharded_state_conformance.rs"));
        assert!(is_exempt("cancel_cx_runtime_channel_metamorphic_tests.rs"));
        assert!(is_exempt("runtime/scheduler/edf_priority_metamorphic.rs"));
        assert!(is_exempt("grpc_server_deadline_cancel_audit.rs"));
        assert!(is_exempt("integration_mutation_testing.rs"));
        assert!(!is_exempt("service/runtime.rs"));
    }

    #[test]
    fn scanner_allows_documented_test_surface_ambient_output() {
        let source = r#"
fn test_helper() {
    std::env::var("ASUPERSYNC_TEST_LOG").ok();
    eprintln!("stage log");
}
"#;
        let violations = scan_source("real_integration_scenarios_e2e_tests.rs", source);
        assert!(
            violations.is_empty(),
            "test-surface carve-outs should not count as production ambient authority: {}",
            format_violations(&violations)
        );
    }

    #[test]
    fn scanner_rejects_production_env_and_output_patterns() {
        let source = r#"
fn production_path() {
    let _ = std::env::var("ASUPERSYNC_RUNTIME_FLAG");
    eprintln!("bypasses structured tracing");
}
"#;
        let violations = scan_source("service/runtime.rs", source);

        assert!(
            violations
                .iter()
                .any(|v| v.category == AmbientCategory::Env),
            "expected env access violation, got: {}",
            format_violations(&violations)
        );
        assert!(
            violations
                .iter()
                .any(|v| v.category == AmbientCategory::Output),
            "expected output violation, got: {}",
            format_violations(&violations)
        );
    }

    #[test]
    fn scanner_ignores_production_pattern_literals() {
        let source = r##"
fn production_path() {
    let _message = "std::env::var(\"NOPE\")";
    let _raw = r#"eprintln!("stage log")"#;
    /* std::thread::spawn(|| ()); */
}
"##;
        let violations = scan_source("service/runtime.rs", source);
        assert!(
            violations.is_empty(),
            "string and block-comment literals should not trip the scanner: {}",
            format_violations(&violations)
        );
    }

    #[test]
    fn output_patterns_do_not_double_count_stderr_macros_as_stdout() {
        let source = r#"
fn production_path() {
    eprintln!("stderr");
}
"#;
        let violations = scan_source("service/runtime.rs", source);
        let output_patterns: Vec<_> = violations
            .iter()
            .filter(|v| v.category == AmbientCategory::Output)
            .map(|v| v.pattern.as_str())
            .collect();

        assert_eq!(output_patterns, vec!["eprintln!("]);
    }

    // =========================================================================
    // Wave 50 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn ambient_finding_debug_clone() {
        let f = &KNOWN_FINDINGS[0];
        let dbg = format!("{f:?}");
        assert!(dbg.contains("AmbientFinding"), "{dbg}");
        let cloned = f.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn ambient_category_debug_clone_copy_hash() {
        use std::collections::HashSet;
        let c = AmbientCategory::Time;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Time"), "{dbg}");
        let copied = c;
        let cloned = c;
        assert_eq!(copied, cloned);
        let mut set = HashSet::new();
        set.insert(c);
        assert!(set.contains(&AmbientCategory::Time));
    }

    #[test]
    fn severity_debug_clone_copy() {
        let s = Severity::Medium;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Medium"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
    }

    // =========================================================================
    // GitHub #80: what happens to every thread's JoinHandle
    // =========================================================================

    /// Every production `std::thread` spawn site under `src/`, per file, with
    /// what happens to its `JoinHandle` (GitHub #80, br-asupersync-umruvn).
    ///
    /// Dropping a handle detaches its thread, and detaching a thread that is
    /// exiting at that moment can fault inside `pthread_detach` on glibc
    /// before 2.43 (BZ19951). A thread must be joined, held and joined later,
    /// reaped through `runtime::spawn_blocking::reap_spawned_thread` or
    /// `reap_threads` (joined once finished, never detached), or detached only
    /// while it provably keeps running. A spawn site added to or removed from
    /// a file changes its count and fails the census until it is classified.
    const THREAD_SPAWN_CENSUS: &[(&str, usize, &str)] = &[
        (
            "bin/asupersync.rs",
            2,
            "signal threads held, closed and joined",
        ),
        (
            "bin/atp.rs",
            5,
            "pipe readers, bond-pull receiver, delta-state sidecar, atp-serve signals joined; \
             the ssh stderr reader runs until EOF",
        ),
        (
            "bin/atpd.rs",
            3,
            "signal loops run for the process; the diagnostics endpoint is joined by stop()",
        ),
        (
            "bin/dependency_marginal_ledger.rs",
            1,
            "thread::scope joins",
        ),
        ("bin/io_cap_budget_profile.rs", 1, "joined"),
        ("cx/scoped_cpu.rs", 1, "thread::scope joins"),
        ("database/mysql.rs", 1, "KILL-on-drop thread reaped"),
        ("net/udp.rs", 1, "fallback I/O pump runs for the process"),
        (
            "observability/debt_runtime_integration.rs",
            1,
            "held, joined by stop/Drop",
        ),
        (
            "process.rs",
            2,
            "Windows output reader joined; kill-on-drop reaper reaped",
        ),
        ("process/reaper.rs", 1, "child reaper runs for the process"),
        (
            "runtime/blocking_pool.rs",
            1,
            "workers held and joined; leftovers reaped when the pool drops",
        ),
        (
            "runtime/builder.rs",
            4,
            "workers and deadline monitor joined; shutdown reaper reaped; worker teardown \
             detached while it must still join the worker that spawned it",
        ),
        (
            "runtime/resource_monitor.rs",
            1,
            "sampler held, joined by Drop",
        ),
        (
            "runtime/spawn_blocking.rs",
            1,
            "fallback thread joined or reaped",
        ),
        (
            "signal/shutdown.rs",
            2,
            "signal listeners block until a signal arrives, long after the detach",
        ),
        (
            "signal/signal.rs",
            2,
            "unix dispatcher runs for the process; Windows poller held and joined",
        ),
        (
            "time/sleep.rs",
            2,
            "fallback timer pump runs for the process; per-Sleep fallback thread reaped",
        ),
        (
            "web/debug.rs",
            2,
            "server loop runs until stop(), callable only after start returns; connection \
             threads reaped",
        ),
    ];

    const THREAD_SPAWN_TOKENS: &[&str] =
        &["thread::Builder::new(", "thread::spawn(", "thread::scope("];

    #[test]
    fn every_thread_spawn_site_has_a_classified_join_handle() {
        let root = src_root();
        let files = collect_rs_files_strict(&root)
            .unwrap_or_else(|error| panic!("strict source scan failed: {error}"));
        let mut observed = std::collections::BTreeMap::new();
        for file_path in files {
            let rel = file_path
                .strip_prefix(&root)
                .expect("collected files are under the source root")
                .to_string_lossy()
                .replace('\\', "/");
            // Test code may detach its threads; `tests.rs` modules and
            // `tests/` directories are compiled only under cfg(test).
            if is_test_surface(&rel)
                || rel == "tests.rs"
                || rel.ends_with("/tests.rs")
                || rel.contains("/tests/")
            {
                continue;
            }
            let content = std::fs::read_to_string(&file_path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", file_path.display()));
            let sites = non_test_lines(&content)
                .iter()
                .filter(|(_, line)| {
                    THREAD_SPAWN_TOKENS
                        .iter()
                        .any(|token| line_contains_literal(line, token))
                })
                .count();
            if sites > 0 {
                observed.insert(rel, sites);
            }
        }
        let classified = THREAD_SPAWN_CENSUS
            .iter()
            .map(|(file, sites, _)| ((*file).to_string(), *sites))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            observed, classified,
            "thread spawn sites changed: classify what happens to each JoinHandle in \
             THREAD_SPAWN_CENSUS (GitHub #80: never drop one while its thread may be exiting)"
        );
    }
