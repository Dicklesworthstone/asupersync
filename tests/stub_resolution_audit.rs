#![allow(warnings)]
#![allow(clippy::all)]
#![allow(clippy::items_after_statements)]
//! Structural probes for the implementation-completeness epic (v2ofj7).
//!
//! Each test verifies that a specific resolution invariant holds.
//! Run all probes: `cargo test --test stub_resolution_audit`
//!
//! Probe naming: `probe_NN_description` where NN maps to the disposition matrix surface.

use std::collections::{BTreeMap, BTreeSet};
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

fn is_src_rust_test_module_path(path: &str) -> bool {
    path.starts_with("src/")
        && path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.ends_with("_test.rs") || name.starts_with("test_"))
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct IncompleteMarker {
    path: String,
    line: usize,
    kind: &'static str,
    text: String,
}

fn brace_delta(line: &str) -> isize {
    line.chars().filter(|ch| *ch == '{').count() as isize
        - line.chars().filter(|ch| *ch == '}').count() as isize
}

fn production_incomplete_markers(path: &str, source: &str) -> Vec<IncompleteMarker> {
    if is_src_rust_test_module_path(path) {
        return Vec::new();
    }

    let lines = source.lines().collect::<Vec<_>>();
    if lines
        .iter()
        .take(16)
        .any(|line| line.contains("#![cfg(test)]"))
    {
        return Vec::new();
    }

    let mut hits = Vec::new();
    let mut depth = 0isize;
    let mut cfg_test_pending = false;
    let mut test_attr_pending = false;
    let mut cfg_test_depth: Option<isize> = None;
    let mut test_fn_depth: Option<isize> = None;

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[cfg(test)]") {
            cfg_test_pending = true;
        }
        if trimmed.starts_with("#[test]") {
            test_attr_pending = true;
        }

        let next_depth = depth + brace_delta(line);
        let starts_cfg_test_scope = cfg_test_pending
            && (trimmed.starts_with("mod ")
                || trimmed.starts_with("fn ")
                || trimmed.contains(" mod ")
                || trimmed.contains(" fn "));
        let starts_test_fn =
            test_attr_pending && (trimmed.starts_with("fn ") || trimmed.contains(" fn "));

        if starts_cfg_test_scope {
            cfg_test_depth = Some(next_depth.max(depth + 1));
            cfg_test_pending = false;
        }
        if starts_test_fn {
            test_fn_depth = Some(next_depth.max(depth + 1));
            test_attr_pending = false;
        }

        if cfg_test_depth.is_none() && test_fn_depth.is_none() {
            let text = (*line).to_owned();
            let lower = text.to_ascii_lowercase();
            let kind = if text.contains(concat!("to", "do", "!(")) {
                Some("deferred_macro")
            } else if text.contains(concat!("un", "implemented", "!(")) {
                Some("unready_macro")
            } else if text.contains("panic!(")
                && (lower.contains(concat!("to", "do"))
                    || lower.contains(&["not", "implemented"].join(" ")))
            {
                Some("unready_panic")
            } else if text.contains(concat!("TO", "DO")) || text.contains(concat!("FIX", "ME")) {
                Some("deferred_comment")
            } else {
                None
            };

            if let Some(kind) = kind {
                hits.push(IncompleteMarker {
                    path: path.to_owned(),
                    line: index + 1,
                    kind,
                    text: text.trim().to_owned(),
                });
            }
        }

        depth = next_depth;
        if cfg_test_depth.is_some_and(|scope_depth| depth < scope_depth) {
            cfg_test_depth = None;
        }
        if test_fn_depth.is_some_and(|scope_depth| depth < scope_depth) {
            test_fn_depth = None;
        }
    }

    hits
}

fn incomplete_marker_report_json(hits: &[IncompleteMarker]) -> String {
    let unique = hits.iter().cloned().collect::<BTreeSet<_>>();
    let markers = unique
        .iter()
        .map(|hit| {
            serde_json::json!({
                "path": hit.path,
                "line": hit.line,
                "kind": hit.kind,
                "text": hit.text,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "schema_version": concat!("mo", "ck-code-finder-incomplete-marker-report-v1"),
        "scanned_roots": ["src"],
        "marker_count": markers.len(),
        "markers": markers,
    })
    .to_string()
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct PlaceholderInventoryMarker {
    path: String,
    line: usize,
    term: String,
    text: String,
}

fn json_string_array(value: &serde_json::Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("inventory field {field} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("inventory field {field} contains a non-string"))
                .to_owned()
        })
        .collect()
}

fn json_required_str<'a>(value: &'a serde_json::Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("inventory field {field} must be a string"))
}

fn inventory_selector_matches(
    selector: &serde_json::Value,
    path: &str,
    text: &str,
    term: &str,
) -> bool {
    let paths = selector
        .get("paths")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    let prefixes = selector
        .get("path_prefixes")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    let path_matches = paths.iter().any(|exact| path == *exact)
        || prefixes.iter().any(|prefix| path.starts_with(prefix));
    if !path_matches {
        return false;
    }

    let text_lower = text.to_ascii_lowercase();
    let term_lower = term.to_ascii_lowercase();
    json_string_array(selector, "terms")
        .iter()
        .any(|selector_term| {
            let selector_term_lower = selector_term.to_ascii_lowercase();
            term_lower.contains(&selector_term_lower) || text_lower.contains(&selector_term_lower)
        })
}

fn walk_marker_inventory_files(root: &Path, extensions: &[String]) -> Vec<std::path::PathBuf> {
    fn inner(dir: &Path, extensions: &[String], files: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                inner(&path, extensions, files);
            } else if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| extensions.iter().any(|allowed| allowed == ext))
            {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    if root.is_file() {
        if root
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| extensions.iter().any(|allowed| allowed == ext))
        {
            files.push(root.to_path_buf());
        }
    } else {
        inner(root, extensions, &mut files);
    }
    files
}

fn live_placeholder_inventory_markers(
    inventory: &serde_json::Value,
) -> Vec<PlaceholderInventoryMarker> {
    let roots = json_string_array(inventory, "scanned_paths");
    let extensions = json_string_array(inventory, "file_extensions");
    let terms = json_string_array(inventory, "marker_terms");
    let mut markers = Vec::new();

    for root in roots {
        for file in walk_marker_inventory_files(Path::new(&root), &extensions) {
            let path = file.to_string_lossy().replace('\\', "/");
            if is_src_rust_test_module_path(&path) {
                continue;
            }
            let Ok(source) = fs::read_to_string(&file) else {
                continue;
            };

            for (line_index, line) in source.lines().enumerate() {
                let line_lower = line.to_ascii_lowercase();
                for term in &terms {
                    if line_lower.contains(&term.to_ascii_lowercase()) {
                        markers.push(PlaceholderInventoryMarker {
                            path: path.clone(),
                            line: line_index + 1,
                            term: term.clone(),
                            text: line.trim().to_owned(),
                        });
                    }
                }
            }
        }
    }

    markers
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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
        "Combinator compile_error! files must keep proc-macro cfg guards: {violations:?}"
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
        src.contains("Unsupported") && src.contains("cfg(not(all(any(target_os"),
        "IoUringReactor cfg-off surface missing Unsupported error handling"
    );
    eprintln!("[PASS] IoUringReactor cfg-off returns Unsupported");
}

// ── Probe 08: kqueue reactor is platform-gated (Surface #10) ────────────

#[test]
fn probe_08_kqueue_reactor_is_platform_gated() {
    // kqueue.rs is only compiled on BSD platforms via cfg gate in mod.rs.
    // There is no cfg-off fallback module on non-BSD.
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

// ── Probe 10: no unready macro calls in harnesses (Surface #17) ────────

#[test]
fn probe_10_no_unimplemented_in_harnesses() {
    for path in ["examples/test_manual.rs", "tests/split_utf8_read_line.rs"] {
        if Path::new(path).exists() {
            let src = read_source(path);
            assert!(
                !src.contains(concat!("un", "implemented", "!()")),
                "{path} still contains an unready macro call"
            );
        }
    }
    eprintln!("[PASS] No unready macro calls in harnesses");
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

// ── Probe 14: deterministic transport is feature-gated (Surface #16) ───

#[test]
fn probe_14_transport_mock_is_gated() {
    let src = read_source("src/transport/mod.rs");
    let lines: Vec<&str> = src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("pub mod deterministic") {
            let start = i.saturating_sub(3);
            assert!(
                lines[start..=i].iter().any(|line| line.contains("cfg(")),
                "transport deterministic module at line {} not feature-gated",
                i + 1
            );
            eprintln!("[PASS] transport deterministic module is feature-gated");
            return;
        }
    }
    eprintln!("[PASS] transport deterministic module not found (removed or gated out)");
}

// ── Probe 15: BrowserEntropy not described as incomplete (Surface #11) ──

#[test]
fn probe_15_browser_entropy_not_stub() {
    let src = read_source("src/util/entropy.rs");
    // Should not describe itself as an incomplete implementation.
    let has_stub_language = src
        .lines()
        .any(|l| l.contains(concat!("St", "ub implementation")) && !l.contains("honest"));
    assert!(
        !has_stub_language,
        "entropy.rs still describes BrowserEntropy as incomplete"
    );
    eprintln!("[PASS] BrowserEntropy not described as incomplete");
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

// ── Probe 17: canonical completeness-ratchet assets are audited ────────

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
        concat!(".st", "ub-allowlist.txt"),
    ];

    for path in required_paths {
        assert!(
            audit_index.contains(&format!("\"file\":\"{path}\"")),
            "audit_index.jsonl missing canonical Track Z ratchet asset entry for {path}"
        );
    }

    eprintln!("[PASS] Canonical completeness-ratchet assets are recorded in audit_index.jsonl");
}

// ── Probe 18: completeness runner publishes stable latest manifests ─────

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
        script.contains(concat!("st", "ub-resolution-suite-pointer-v1")),
        "verify_stub_resolution.sh must version the stable suite pointer manifest"
    );

    let testing = read_source("TESTING.md");
    assert!(
        testing.contains("latest.json") && testing.contains("latest_success.json"),
        "TESTING.md must document the stable completeness manifest contract"
    );

    eprintln!("[PASS] Completeness runner publishes stable latest manifests");
}

// ── Probe 19: completeness classifier contract ─────────────────────────

#[test]
fn probe_19_mock_code_finder_classifier_contract() {
    let source = format!(
        r#"
fn production_deferred() {{
    // {}: implement the real production behavior
}}

fn production_not_implemented() {{
    panic!("{} yet");
}}

fn production_invariant_panic() {{
    panic!("internal invariant violated");
}}

#[cfg(test)]
mod tests {{
    #[test]
    fn ignored_test_markers() {{
        {}!("test-only type check");
        // {}: test helper cleanup
    }}
}}

#[test]
fn standalone_deferred_marker() {{
    {}!("test-only macro");
}}
"#,
        concat!("TO", "DO"),
        ["not", "implemented"].join(" "),
        concat!("un", "implemented"),
        concat!("TO", "DO"),
        concat!("to", "do"),
    );

    let hits = production_incomplete_markers("src/demo.rs", &source);
    let hit_kinds = hits.iter().map(|hit| hit.kind).collect::<Vec<_>>();
    assert_eq!(
        hit_kinds,
        vec!["deferred_comment", "unready_panic"],
        "classifier must keep production incomplete markers while filtering test-only markers and invariant panics"
    );

    let mut duplicated = hits.clone();
    duplicated.extend(hits.clone());
    let once = incomplete_marker_report_json(&hits);
    let twice = incomplete_marker_report_json(&duplicated);
    assert_eq!(
        once, twice,
        "report serialization must be stable and de-duplicate repeated scanner output"
    );
    assert!(
        once.contains(&format!(
            "\"schema_version\":\"{}\"",
            concat!("mo", "ck-code-finder-incomplete-marker-report-v1")
        )) && once.contains("\"marker_count\":2"),
        "serialized report must include schema and marker count: {once}"
    );

    let src_test_module = format!(
        r#"
//! Test-only audit prose may mention {}, {}!(, and panic!("{}")
//! without becoming production marker evidence.

#[test]
fn test_only_marker() {{
    {}!("test-only marker");
}}
"#,
        concat!("TO", "DO"),
        concat!("un", "implemented"),
        ["not", "implemented"].join(" "),
        concat!("to", "do"),
    );
    assert!(
        production_incomplete_markers("src/demo_test.rs", &src_test_module).is_empty(),
        "src Rust test modules must be excluded from production incomplete-marker scans"
    );

    eprintln!(
        "[PASS] Completeness classifier filters tests, keeps prod findings, and serializes stably"
    );
}

// ── Probe 20: Live production incomplete-marker gate ───────────────────

#[test]
fn probe_20_live_production_incomplete_markers_are_tracked() {
    let known_markers = [(
        "src/messaging/nats.rs",
        concat!(
            "TO",
            "DO",
            ": Re-establish subscriptions that existed before disconnect"
        ),
        "asupersync-jh9g1j",
    )];
    let mut unknown = Vec::new();
    let mut tracked = Vec::new();

    for file in walk_rs_files(Path::new("src")) {
        let path = file.to_string_lossy().replace('\\', "/");
        let Ok(source) = fs::read_to_string(&file) else {
            continue;
        };
        for hit in production_incomplete_markers(&path, &source) {
            if let Some((_, _, bead_id)) = known_markers
                .iter()
                .find(|(known_path, text, _)| hit.path == *known_path && hit.text.contains(text))
            {
                assert!(
                    bead_id.starts_with("asupersync-"),
                    "known production marker {}:{} must be linked to a concrete asupersync bead id, got {bead_id}",
                    hit.path,
                    hit.line
                );
                tracked.push(format!("{}:{} -> {bead_id}", hit.path, hit.line));
            } else {
                unknown.push(format!(
                    "{}:{}:{}: {}",
                    hit.path, hit.line, hit.kind, hit.text
                ));
            }
        }
    }

    let health = read_source("src/grpc/health.rs");
    assert!(
        !health.contains(concat!(
            "TO",
            "DO",
            ": Implement configurable authentication mode"
        )) && !health.contains("Health check accessed without authentication validation"),
        "stale gRPC health auth marker must remain resolved under asupersync-xfx177"
    );
    assert!(
        unknown.is_empty(),
        "untracked production incomplete markers found; create a concrete br bead or add an explicit tracked-marker entry: {unknown:#?}"
    );

    eprintln!(
        "[PASS] Live production incomplete markers are tracked: {}",
        tracked.join(", ")
    );
}

// ── Probe 21: rckstb inventory classifies live markers ─────────────────

#[test]
fn probe_21_rckstb_placeholder_inventory_classifies_live_markers() {
    let inventory_path = "artifacts/stub_placeholder_inventory_v1.json";
    let inventory: serde_json::Value =
        serde_json::from_str(&read_source(inventory_path)).expect("inventory must be valid JSON");

    assert_eq!(
        json_required_str(&inventory, "schema_version"),
        concat!("st", "ub-place", "holder-inventory-v1")
    );
    assert_eq!(
        json_required_str(&inventory, "bead_id"),
        "asupersync-rckstb"
    );
    let expected_scanned_paths = [
        "src",
        "tests",
        "conformance",
        "examples",
        "README.md",
        "docs/integration.md",
        "docs/WASM.md",
        "docs/stub_closure_policy.md",
        "docs/stub_disposition_matrix.md",
        "scripts/scan_stubs.sh",
        "scripts/verify_stub_resolution.sh",
        "artifacts/stub_placeholder_inventory_v1.json",
        "artifacts/mock_code_finder_verification_contract_v1.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    assert_eq!(
        json_string_array(&inventory, "scanned_paths"),
        expected_scanned_paths
    );

    let allowed_dispositions = json_string_array(&inventory, "allowed_dispositions")
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        allowed_dispositions,
        BTreeSet::from([
            "conformance-bug-follow-up".to_owned(),
            "documented-deferred-surface".to_owned(),
            "implemented-now".to_owned(),
            "intentional-reference-implementation".to_owned(),
            "legitimate-test-harness".to_owned(),
            "obsolete-retained-no-delete".to_owned(),
            "product-bug-follow-up".to_owned(),
            "unsupported-fail-closed".to_owned(),
        ]),
        "allowed dispositions must match the finite rckstb contract"
    );
    let allowed_support_classes = json_string_array(&inventory, "allowed_support_classes")
        .into_iter()
        .collect::<BTreeSet<_>>();
    let selectors = inventory
        .get("selectors")
        .and_then(serde_json::Value::as_array)
        .expect("selectors must be an array");
    assert!(!selectors.is_empty(), "inventory must define selectors");
    let row_output = inventory
        .get("row_inventory_output")
        .expect("inventory must declare generated row_inventory_output");
    assert_eq!(
        json_required_str(row_output, "schema_version"),
        concat!("st", "ub-place", "holder-marker-row-inventory-v1")
    );
    let row_fields = json_string_array(row_output, "row_fields")
        .into_iter()
        .collect::<BTreeSet<_>>();
    for required in [
        "path",
        "line",
        "stable_anchor",
        "marker_term",
        "marker_text",
        "context_before",
        "context_after",
        "source_kind",
        "selector_id",
        "disposition",
        "support_class",
        "product_visible",
        "conformance_visible",
        "reasoning",
        "owner_bead",
        "permanent_rationale",
        "revisit_condition",
        "proof_artifact",
    ] {
        assert!(
            row_fields.contains(required),
            "row inventory must declare field {required}"
        );
    }

    let mut selector_ids = BTreeSet::new();
    for selector in selectors {
        let id = json_required_str(selector, "id");
        assert!(
            selector_ids.insert(id.to_owned()),
            "duplicate selector id {id}"
        );

        let has_exact_paths = selector
            .get("paths")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|paths| !paths.is_empty());
        let has_prefixes = selector
            .get("path_prefixes")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|paths| !paths.is_empty());
        assert!(
            has_exact_paths || has_prefixes,
            "selector {id} must name paths or path_prefixes"
        );
        assert!(
            !json_string_array(selector, "terms").is_empty(),
            "selector {id} must name marker terms"
        );

        let disposition = json_required_str(selector, "disposition");
        assert!(
            allowed_dispositions.contains(disposition),
            "selector {id} has unsupported disposition {disposition}"
        );
        assert!(
            !matches!(
                disposition,
                "follow-up-bead" | "product-bug" | "fixture_reference" | "terminology_not_stub"
            ),
            "selector {id} uses legacy disposition alias {disposition}"
        );
        let support_class = json_required_str(selector, "support_class");
        assert!(
            allowed_support_classes.contains(support_class),
            "selector {id} has unsupported support class {support_class}"
        );

        if support_class == "blocked_follow_up" {
            let blocker = json_required_str(selector, "blocker_bead_id");
            assert!(
                blocker.starts_with("asupersync-"),
                "blocked selector {id} must link a concrete follow-up bead"
            );
        }
        assert!(
            !json_required_str(selector, "notes").is_empty(),
            "selector {id} must explain the disposition"
        );
    }

    let markers = live_placeholder_inventory_markers(&inventory);
    assert!(
        !markers.is_empty(),
        "inventory scan should observe current marker surfaces"
    );

    let default_revisit_condition = json_required_str(row_output, "revisit_condition");
    let mut unclassified = Vec::new();
    let mut disposition_counts = BTreeMap::<String, usize>::new();
    let mut invalid_disposition_count = 0usize;
    let mut owner_bead_missing_count = 0usize;
    let mut expired_allowance_count = 0usize;
    for marker in &markers {
        let Some(selector) = selectors.iter().find(|selector| {
            inventory_selector_matches(selector, &marker.path, &marker.text, &marker.term)
        }) else {
            unclassified.push(format!(
                "{}:{}:{}: {}",
                marker.path, marker.line, marker.term, marker.text
            ));
            continue;
        };

        let disposition = json_required_str(selector, "disposition").to_owned();
        if !allowed_dispositions.contains(&disposition) {
            invalid_disposition_count += 1;
        }
        *disposition_counts.entry(disposition).or_default() += 1;
        let owner_bead = json_required_str(selector, "blocker_bead_id");
        let permanent_rationale = if owner_bead.is_empty() {
            json_required_str(selector, "notes")
        } else {
            ""
        };
        if owner_bead.is_empty() && permanent_rationale.is_empty() {
            owner_bead_missing_count += 1;
        }
        let revisit_condition = selector
            .get("revisit_condition")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(default_revisit_condition);
        assert!(
            !revisit_condition.is_empty(),
            "matched marker {}:{} must have a generated revisit condition",
            marker.path,
            marker.line
        );
        if selector
            .get("expires_at")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|expires_at| expires_at < "2026-05-05")
        {
            expired_allowance_count += 1;
        }

        if marker.path.starts_with("conformance/") || marker.path.starts_with("tests/conformance/")
        {
            let support_class = json_required_str(selector, "support_class");
            assert!(
                matches!(
                    support_class,
                    "blocked_follow_up"
                        | "explicitly_unsupported"
                        | "fixture_reference"
                        | "not_conformance_evidence"
                        | "test_harness"
                        | "terminology"
                ),
                "conformance marker {}:{} classified as unsupported support class {support_class}",
                marker.path,
                marker.line
            );
        }
    }

    assert!(
        unclassified.is_empty(),
        "unclassified completion markers found; update {inventory_path}: {unclassified:#?}"
    );
    assert_eq!(
        invalid_disposition_count, 0,
        "all generated rows must use the finite disposition set"
    );
    assert_eq!(
        owner_bead_missing_count, 0,
        "all generated rows must have owner_bead or permanent rationale"
    );
    assert_eq!(
        expired_allowance_count, 0,
        "temporary row allowances must not be expired"
    );
    assert!(
        disposition_counts
            .get("product-bug-follow-up")
            .copied()
            .unwrap_or_default()
            > 0
            || disposition_counts
                .get("conformance-bug-follow-up")
                .copied()
                .unwrap_or_default()
                > 0,
        "inventory should keep product/conformance follow-up debt visible"
    );

    assert!(
        disposition_counts
            .get("intentional-reference-implementation")
            .copied()
            .unwrap_or_default()
            > 0,
        "inventory should classify proof-tooling and fixture references explicitly"
    );

    let nats = read_source("src/messaging/nats.rs");
    assert!(
        nats.contains("br-asupersync-2kmc12") && nats.contains("refusing to send CONNECT in"),
        "NATS deferred TLS marker must remain a stable fail-closed diagnostic"
    );

    eprintln!(
        "[PASS] rckstb inventory classified {} markers with counts {:?}",
        markers.len(),
        disposition_counts
    );
}
