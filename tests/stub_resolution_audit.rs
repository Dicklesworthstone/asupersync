#![allow(clippy::items_after_statements)]
//! Structural probes for the placeholder/stub resolution epic (v2ofj7).
//!
//! Each test verifies that a specific resolution invariant holds.
//! Run all probes: `cargo test --test stub_resolution_audit`
//!
//! Probe naming: `probe_NN_description` where NN maps to the disposition matrix surface.

use std::fs;
use std::path::Path;
use std::process::Command;

fn read_source(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("could not read {path}: {err}"))
}

fn walk_rs_files(dir: &Path) -> Vec<std::path::PathBuf> {
    fn inner(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                inner(&path, files);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    inner(dir, &mut files);
    files
}

fn path_is_git_ignored(path: &Path) -> bool {
    Command::new("git")
        .args(["check-ignore", "-q", "--"])
        .arg(path)
        .status()
        .is_ok_and(|status| status.success())
}

// ── Probe 01: No stray binaries in src/ (Surface #14) ──────────────────

#[test]
fn probe_01_no_stray_binaries_in_src() {
    fn walk(dir: &Path, bad_exts: &[&str], violations: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, bad_exts, violations);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                // Structural probes should stay stable across local worktrees.
                // Ignore gitignored scratch outputs, but keep flagging real
                // non-ignored binary artifacts inside source-owned trees.
                if path_is_git_ignored(&path) {
                    continue;
                }
                if bad_exts.contains(&ext) {
                    violations.push(path.display().to_string());
                }
            }
        }
    }

    let bad_exts = ["out", "exe", "o", "so", "dylib"];
    let mut violations = Vec::new();
    walk(Path::new("src"), &bad_exts, &mut violations);
    walk(Path::new("tests"), &bad_exts, &mut violations);
    assert!(
        violations.is_empty(),
        "Stray binaries found: {violations:?}"
    );
    eprintln!("[PASS] No stray binaries in src/ or tests/");
}

// ── Probe 02: quorum! macro resolved (Surface #2) ──────────────────────

#[test]
fn probe_02_no_permanent_quorum_macro() {
    let src = read_source("src/combinator/quorum.rs");
    let has_macro = src.contains("macro_rules! quorum");
    if has_macro {
        // If macro exists, it must be cfg-guarded
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("macro_rules! quorum") {
                let start = i.saturating_sub(5);
                let has_guard = lines[start..=i]
                    .iter()
                    .any(|l| l.contains("cfg(not(feature"));
                assert!(
                    has_guard,
                    "quorum! macro at line {} exists without cfg guard",
                    i + 1
                );
            }
        }
    }
    eprintln!("[PASS] quorum! macro resolved (removed or guarded)");
}

// ── Probe 03: try_join! macro resolved (Surface #3) ────────────────────

#[test]
fn probe_03_no_permanent_try_join_macro() {
    let src = read_source("src/combinator/timeout.rs");
    let has_macro = src.contains("macro_rules! try_join");
    if has_macro {
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("macro_rules! try_join") {
                let start = i.saturating_sub(5);
                let has_guard = lines[start..=i]
                    .iter()
                    .any(|l| l.contains("cfg(not(feature"));
                assert!(
                    has_guard,
                    "try_join! macro at line {} exists without cfg guard",
                    i + 1
                );
            }
        }
    }
    eprintln!("[PASS] try_join! macro resolved (removed or guarded)");
}

// ── Probe 04: No compile_error! without cfg guard (Surface #2,#3) ──────

#[test]
fn probe_04_no_permanent_compile_error_stubs() {
    let mut violations = Vec::new();
    for entry in fs::read_dir("src/combinator")
        .into_iter()
        .flatten()
        .flatten()
    {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let src = fs::read_to_string(&path).unwrap();
            let has_stub_compile_error = src
                .lines()
                .any(|line| line.trim_start().starts_with("compile_error!"));
            if !has_stub_compile_error {
                continue;
            }

            if !src.contains("#[cfg(not(feature = \"proc-macros\"))]") {
                violations.push(path.display().to_string());
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Combinator compile_error! stub files must keep proc-macro cfg guards: {violations:?}"
    );
    eprintln!("[PASS] All compile_error! macros have cfg guards");
}

// ── Probe 05: Kafka StubBroker documented as harness (Surface #5) ──────

#[test]
fn probe_05_kafka_stub_broker_is_harness_documented() {
    let src = read_source("src/messaging/kafka.rs");
    let has_harness_doc = src.contains("harness lane") || src.contains("harness-only");
    assert!(
        has_harness_doc,
        "kafka.rs missing harness-only documentation for StubBroker"
    );
    eprintln!("[PASS] Kafka StubBroker documented as harness-only");
}

// ── Probe 06: Legacy UringReactor resolved (Surface #8) ────────────────

#[test]
fn probe_06_legacy_uring_reactor_resolved() {
    let path = Path::new("src/runtime/reactor/uring.rs");
    if path.exists() {
        let src = fs::read_to_string(path).unwrap();
        let has_standalone_struct = src.contains("pub struct UringReactor");
        assert!(
            !has_standalone_struct,
            "uring.rs has standalone UringReactor struct — should be deprecated type alias"
        );
        eprintln!("[PASS] UringReactor is deprecated/aliased (no standalone struct)");
    } else {
        eprintln!("[PASS] uring.rs fully removed");
    }
}

// ── Probe 07: IoUringReactor cfg-off returns Unsupported (Surface #9) ──

#[test]
fn probe_07_io_uring_cfg_off_is_honest() {
    let src = read_source("src/runtime/reactor/io_uring.rs");
    assert!(
        src.contains("Unsupported") && src.contains("cfg(not(all(target_os"),
        "IoUringReactor cfg-off surface missing Unsupported error handling"
    );
    eprintln!("[PASS] IoUringReactor cfg-off returns Unsupported");
}

// ── Probe 08: kqueue reactor is platform-gated (Surface #10) ────────────

#[test]
fn probe_08_kqueue_reactor_is_platform_gated() {
    // kqueue.rs is only compiled on BSD platforms via cfg gate in mod.rs.
    // There is no cfg-off stub — the module simply doesn't exist on non-BSD.
    // Verify the module-level cfg gate exists.
    let mod_rs = read_source("src/runtime/reactor/mod.rs");
    let lines: Vec<&str> = mod_rs.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("pub mod kqueue") {
            // Look back for cfg gate
            let start = i.saturating_sub(5);
            let has_bsd_gate = lines[start..=i].iter().any(|l| {
                l.contains("target_os = \"macos\"") || l.contains("target_os = \"freebsd\"")
            });
            assert!(
                has_bsd_gate,
                "pub mod kqueue at line {} missing BSD platform cfg gate",
                i + 1
            );
            eprintln!("[PASS] kqueue module is platform-gated to BSD");
            return;
        }
    }
    eprintln!("[PASS] kqueue module not found (removed or renamed)");
}

// ── Probe 09: AuthenticationTag not phase-0 (Surface #12) ──────────────

#[test]
fn probe_09_authentication_tag_not_phase_0() {
    let src = read_source("src/security/tag.rs");
    // Should not contain "phase-0" or "Phase 0" language claiming it's temporary
    let has_phase_0 = src.contains("Phase 0") && src.contains("stand-in");
    assert!(
        !has_phase_0,
        "security/tag.rs still has Phase 0 stand-in language"
    );
    eprintln!("[PASS] AuthenticationTag no longer described as phase-0 stand-in");
}

// ── Probe 10: No unimplemented!() in harnesses (Surface #17) ───────────

#[test]
fn probe_10_no_unimplemented_in_harnesses() {
    for path in ["examples/test_manual.rs", "tests/split_utf8_read_line.rs"] {
        if Path::new(path).exists() {
            let src = read_source(path);
            assert!(
                !src.contains("unimplemented!()"),
                "{path} still contains unimplemented!()"
            );
        }
    }
    eprintln!("[PASS] No unimplemented!() in harnesses");
}

// ── Probe 11: API skeleton not in project root (Surface #18) ────────────

#[test]
fn probe_11_api_skeleton_relocated() {
    assert!(
        !Path::new("asupersync_v4_api_skeleton.rs").exists(),
        "API skeleton still in project root"
    );

    let readme = read_source("README.md");
    assert!(
        !readme.contains("./asupersync_v4_api_skeleton.rs"),
        "README.md still links to the removed root API skeleton path"
    );
    assert!(
        readme.contains("./docs/design/api_skeleton_v4.rs"),
        "README.md must link to the relocated API skeleton under docs/design/"
    );

    eprintln!("[PASS] API skeleton relocated from project root and README points at docs/design/");
}

// ── Probe 12: No skeleton_placeholder! in src/ ─────────────────────────

#[test]
fn probe_12_no_skeleton_placeholder_in_src() {
    for file in walk_rs_files(Path::new("src")) {
        if let Ok(src) = fs::read_to_string(&file) {
            assert!(
                !src.contains("skeleton_placeholder!"),
                "skeleton_placeholder! found in {}",
                file.display()
            );
        }
    }
    eprintln!("[PASS] No skeleton_placeholder! in src/");
}

// ── Probe 13: No crate-level dead_code allow (Surface #15) ─────────────

#[test]
fn probe_13_no_crate_level_dead_code_allow() {
    let lib = read_source("src/lib.rs");
    for (i, line) in lib.lines().enumerate() {
        assert!(
            !line.trim().starts_with("#![allow(dead_code)]"),
            "src/lib.rs:{} has crate-level #![allow(dead_code)]",
            i + 1
        );
    }
    eprintln!("[PASS] No crate-level dead_code allow");
}

// ── Probe 14: transport/mock is feature-gated (Surface #16) ────────────

#[test]
fn probe_14_transport_mock_is_gated() {
    let src = read_source("src/transport/mod.rs");
    let lines: Vec<&str> = src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("pub mod mock") {
            let prev = if i > 0 { lines[i - 1] } else { "" };
            assert!(
                prev.contains("cfg(") || line.contains("cfg("),
                "transport/mock at line {} not feature-gated",
                i + 1
            );
            eprintln!("[PASS] transport/mock is feature-gated");
            return;
        }
    }
    eprintln!("[PASS] transport/mock module not found (removed or gated out)");
}

// ── Probe 15: BrowserEntropy not described as stub (Surface #11) ────────

#[test]
fn probe_15_browser_entropy_not_stub() {
    let src = read_source("src/util/entropy.rs");
    // Should not describe itself as a "stub"
    let has_stub_language = src
        .lines()
        .any(|l| l.contains("Stub implementation") && !l.contains("honest"));
    assert!(
        !has_stub_language,
        "entropy.rs still describes BrowserEntropy as a stub"
    );
    eprintln!("[PASS] BrowserEntropy not described as stub");
}

// ── Probe 16: Harness poll_read uses Ready(Ok(())) ─────────────────────

#[test]
fn probe_16_harness_poll_read_returns_ready_ok() {
    for path in ["examples/test_manual.rs", "tests/split_utf8_read_line.rs"] {
        if Path::new(path).exists() {
            let src = read_source(path);
            assert!(
                src.contains("Poll::Ready(Ok(()))"),
                "{path} must use non-panicking poll_read"
            );
        }
    }
    eprintln!("[PASS] Harness poll_read uses Poll::Ready(Ok(()))");
}

// ── Probe 17: Canonical stub-ratchet assets are audited ────────────────

#[test]
fn probe_17_stub_ratchet_assets_are_audited() {
    let audit_index = read_source("audit_index.jsonl");
    let required_paths = [
        "scripts/scan_stubs.sh",
        "scripts/verify_stub_resolution.sh",
        "tests/stub_resolution_audit.rs",
        "docs/stub_closure_policy.md",
        "docs/stub_disposition_matrix.md",
        "TESTING.md",
        ".stub-allowlist.txt",
    ];

    for path in required_paths {
        assert!(
            audit_index.contains(&format!("\"file\":\"{path}\"")),
            "audit_index.jsonl missing canonical Track Z ratchet asset entry for {path}"
        );
    }

    eprintln!("[PASS] Canonical stub-ratchet assets are recorded in audit_index.jsonl");
}

// ── Probe 18: Stub-resolution runner publishes stable latest manifests ──

#[test]
fn probe_18_stub_resolution_runner_publishes_stable_latest_manifests() {
    let script = read_source("scripts/verify_stub_resolution.sh");
    assert!(
        script.contains("latest.json"),
        "verify_stub_resolution.sh must publish a stable latest.json pointer"
    );
    assert!(
        script.contains("latest_success.json"),
        "verify_stub_resolution.sh must publish a stable latest_success.json pointer"
    );
    assert!(
        script.contains("stub-resolution-suite-pointer-v1"),
        "verify_stub_resolution.sh must version the stable suite pointer manifest"
    );

    let testing = read_source("TESTING.md");
    assert!(
        testing.contains("latest.json") && testing.contains("latest_success.json"),
        "TESTING.md must document the stable stub-resolution manifest contract"
    );

    eprintln!("[PASS] Stub-resolution runner publishes stable latest manifests");
}
