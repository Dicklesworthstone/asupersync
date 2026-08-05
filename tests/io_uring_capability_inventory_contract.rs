//! Static io_uring architecture, capability, probe, and no-win contract.
//!
//! Bead: asupersync-sched-hot-path-perf-bt4y5f.7.1
//! Fixture: artifacts/io_uring_capability_inventory_v1.json
//!
//! This contract checks the frozen source inventory and future decision policy.
//! It does not prove compilation, live-kernel support, activation, correctness,
//! performance, broad workspace health, or production adoption.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/io_uring_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/io_uring_capability_inventory.md";
const UNSAFE_LEDGER_PATH: &str = "artifacts/unsafe_boundary_ledger_v1.json";
const ARTIFACT_ID: &str = "io-uring-capability-inventory-v1";
const BEAD_ID: &str = "asupersync-sched-hot-path-perf-bt4y5f.7.1";
const DOC_BEGIN: &str = "<!-- BEGIN IO URING CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END IO URING CAPABILITY INVENTORY -->";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_file(path: &str) -> String {
    String::from_utf8(read_repo_bytes(path))
        .unwrap_or_else(|error| panic!("{path} must be UTF-8: {error}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("{ARTIFACT_PATH} must be valid JSON: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn unsigned(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn string_list<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
        })
        .collect()
}

fn boolean_list(value: &Value, key: &str) -> Vec<bool> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_bool()
                .unwrap_or_else(|| panic!("{key} entries must be booleans"))
        })
        .collect()
}

fn expected_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn locator_signature(locator: &Value, line_key: &str) -> String {
    format!(
        "{}|{}|{}",
        text(locator, "kind"),
        unsigned(locator, line_key),
        text(locator, "pattern")
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[test]
fn source_pins_and_live_surface_anchors_match_the_tree() {
    let inventory = artifact();
    assert_eq!(inventory["schema_version"], 1);
    assert_eq!(text(&inventory, "artifact_id"), ARTIFACT_ID);
    assert_eq!(text(&inventory, "bead_id"), BEAD_ID);
    assert_eq!(
        text(&inventory, "disposition"),
        "STATIC_INVENTORY_COMPLETE_PRODUCTION_UNCHANGED"
    );

    let scope = object(&inventory, "inventory_scope");
    let scope_value = Value::Object(scope.clone());
    assert!(text(&scope_value, "reactor_target_family").contains("Linux and Android"));
    assert_eq!(text(&scope_value, "filesystem_target"), "Linux only");
    assert_eq!(
        string_set(&scope_value, "included_live_backends"),
        expected_set(&[
            "EpollReactor",
            "IoUringReactor",
            "no reactor with socket re-poll fallback",
        ])
    );
    assert_eq!(array(&scope_value, "included_live_backends").len(), 3);
    assert_eq!(
        string_set(&scope_value, "excluded_platform_backends"),
        expected_set(&[
            "BrowserReactor",
            "IocpReactor",
            "KqueueReactor",
            "LabReactor",
        ])
    );
    assert_eq!(array(&scope_value, "excluded_platform_backends").len(), 4);
    assert!(text(&scope_value, "exclusion_reason").contains("not reachable"));

    let expected_paths = expected_set(&[
        "Cargo.toml",
        "artifacts/unsafe_boundary_ledger_v1.json",
        "benches/reactor_benchmark.rs",
        "docs/io_uring_capability_inventory.md",
        "docs/unsafe_boundary_ledger.md",
        "src/bytes/bytes.rs",
        "src/bytes/bytes_mut.rs",
        "src/fs/dir.rs",
        "src/fs/file.rs",
        "src/fs/mod.rs",
        "src/fs/open_options.rs",
        "src/fs/path_ops.rs",
        "src/fs/uring.rs",
        "src/net/tcp/listener.rs",
        "src/net/tcp/split.rs",
        "src/net/tcp/stream.rs",
        "src/runtime/builder.rs",
        "src/runtime/io_driver.rs",
        "src/runtime/reactor/epoll.rs",
        "src/runtime/reactor/io_uring.rs",
        "src/runtime/reactor/mod.rs",
        "src/runtime/reactor/uring.rs",
        "tests/conformance_io_uring_buffer_pool.rs",
        "tests/e2e_fs.rs",
        "tests/io_uring_reactor.rs",
        "tests/io_uring_stress.rs",
        "tests/io_uring_capability_inventory_contract.rs",
    ]);
    let pins = array(&inventory, "source_pins");
    assert_eq!(pins.len(), expected_paths.len());
    assert_eq!(row_ids(pins, "path"), expected_paths);

    for pin in pins {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        let source = String::from_utf8(bytes.clone())
            .unwrap_or_else(|error| panic!("{path} must be UTF-8: {error}"));
        assert_eq!(sha256_hex(&bytes), text(pin, "sha256"), "{path}");
        assert_eq!(
            u64::try_from(source.lines().count()).expect("line count fits u64"),
            pin.get("line_count")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| panic!("{path} line_count must be u64")),
            "{path}"
        );
        assert!(!text(pin, "role").is_empty(), "{path} role must be set");
    }

    let expected_surfaces = expected_set(&[
        "URING-SURFACE-BENCH",
        "URING-SURFACE-BOUNDARY-LEDGER",
        "URING-SURFACE-BUFFER-SCAFFOLD",
        "URING-SURFACE-BUILDER",
        "URING-SURFACE-BYTES",
        "URING-SURFACE-EVIDENCE",
        "URING-SURFACE-EPOLL-FALLBACK",
        "URING-SURFACE-FACTORY",
        "URING-SURFACE-FEATURE",
        "URING-SURFACE-FS-DEFAULT",
        "URING-SURFACE-FS-FILE",
        "URING-SURFACE-FS-PATH-DIR",
        "URING-SURFACE-HISTORICAL",
        "URING-SURFACE-INSPECTOR",
        "URING-SURFACE-NO-REACTOR-FALLBACK",
        "URING-SURFACE-REACTOR",
        "URING-SURFACE-TCP-ACCEPT",
        "URING-SURFACE-TCP-BORROWED-SPLIT",
        "URING-SURFACE-TCP-STREAM",
    ]);
    let surfaces = array(&inventory, "surface_matrix");
    assert_eq!(surfaces.len(), expected_surfaces.len());
    assert_eq!(row_ids(surfaces, "surface_id"), expected_surfaces);

    for surface in surfaces {
        let paths = string_set(surface, "paths");
        assert!(!paths.is_empty());
        assert!(paths.is_subset(&expected_paths));
        let sources: Vec<String> = paths.iter().map(|path| read_repo_file(path)).collect();
        for anchor in array(surface, "anchors") {
            let anchor = anchor.as_str().expect("surface anchor must be text");
            assert!(
                sources.iter().any(|source| source.contains(anchor)),
                "{} anchor not found: {anchor}",
                text(surface, "surface_id")
            );
        }
        assert!(!text(surface, "current_state").is_empty());
        assert!(!text(surface, "gap").is_empty());
        assert!(text(surface, "owner_bead").starts_with("asupersync-"));
    }
}

#[test]
fn source_accuracy_ledger_and_existing_evidence_gaps_are_explicit() {
    let inventory = artifact();
    assert!(text(&inventory, "source_accuracy_scope").contains("material"));
    let accuracy = array(&inventory, "source_accuracy_gaps");
    assert_eq!(accuracy.len(), 5);
    assert_eq!(
        row_ids(accuracy, "gap_id"),
        expected_set(&[
            "URING-ACCURACY-BUFFER-SUPPORT",
            "URING-ACCURACY-E2E-DEFAULT-FS-LABEL",
            "URING-ACCURACY-FS-DIR-HEADER",
            "URING-ACCURACY-FS-OPCODE-DOC",
            "URING-ACCURACY-FS-URING-EXECUTION",
        ])
    );
    let pinned_paths = row_ids(array(&inventory, "source_pins"), "path");
    for gap in accuracy {
        assert!(pinned_paths.contains(text(gap, "path")));
        assert!(!text(gap, "recorded_claim").is_empty());
        assert!(!text(gap, "pinned_reality").is_empty());
        let source = read_repo_file(text(gap, "path"));
        for anchor in array(gap, "source_anchors") {
            let anchor = anchor.as_str().expect("source accuracy anchor must be text");
            assert!(source.contains(anchor), "{} missing {anchor}", text(gap, "gap_id"));
        }
        assert!(text(gap, "owner_bead").starts_with("asupersync-"));
    }

    let expected_sites = expected_set(&[
        "unsafe-src-fs-dir-rs",
        "unsafe-src-fs-path-ops-rs",
        "unsafe-src-fs-uring-rs",
        "unsafe-src-runtime-reactor-io-uring-rs",
    ]);
    let reconciliation = array(&inventory, "boundary_ledger_reconciliation");
    assert_eq!(reconciliation.len(), expected_sites.len());
    assert_eq!(row_ids(reconciliation, "site_id"), expected_sites);

    let ledger: Value = serde_json::from_str(&read_repo_file(UNSAFE_LEDGER_PATH))
        .unwrap_or_else(|error| panic!("{UNSAFE_LEDGER_PATH} must be valid JSON: {error}"));
    let ledger_sites = array(&ledger, "sites");
    let mut total_locators = 0usize;
    let mut total_exact = 0usize;
    let mut total_stale = 0usize;

    for site in reconciliation {
        let site_id = text(site, "site_id");
        let ledger_site = find_row(ledger_sites, "site_id", site_id);
        assert_eq!(text(site, "path"), text(ledger_site, "path"), "{site_id}");

        let recorded_locators = array(ledger_site, "operation_locators");
        let current_locators = array(site, "locators");
        assert_eq!(
            current_locators.len(),
            usize::try_from(unsigned(site, "recorded_locator_count"))
                .expect("recorded locator count fits usize"),
            "{site_id}"
        );
        assert_eq!(current_locators.len(), recorded_locators.len(), "{site_id}");

        let recorded_signatures: BTreeSet<String> = recorded_locators
            .iter()
            .map(|locator| locator_signature(locator, "line"))
            .collect();
        let reconciled_signatures: BTreeSet<String> = current_locators
            .iter()
            .map(|locator| locator_signature(locator, "recorded_line"))
            .collect();
        assert_eq!(recorded_signatures.len(), recorded_locators.len(), "{site_id}");
        assert_eq!(
            reconciled_signatures.len(),
            current_locators.len(),
            "{site_id}"
        );
        assert_eq!(reconciled_signatures, recorded_signatures, "{site_id}");

        let source = read_repo_file(text(site, "path"));
        let exact = current_locators
            .iter()
            .filter(|locator| text(locator, "status") == "EXACT_LIVE_PATTERN")
            .count();
        let stale = current_locators
            .iter()
            .filter(|locator| text(locator, "status") == "STALE_LINE_LIVE_PATTERN")
            .count();
        assert_eq!(
            exact,
            usize::try_from(unsigned(site, "exact_locator_count"))
                .expect("exact locator count fits usize"),
            "{site_id}"
        );
        assert_eq!(
            stale,
            usize::try_from(unsigned(site, "stale_locator_count"))
                .expect("stale locator count fits usize"),
            "{site_id}"
        );
        assert_eq!(exact + stale, current_locators.len(), "{site_id}");

        for locator in current_locators {
            let current_line = unsigned(locator, "current_line");
            assert!(current_line > 0, "{site_id} current line must be positive");
            let line = source
                .lines()
                .nth(usize::try_from(current_line - 1).expect("line fits usize"))
                .unwrap_or_else(|| panic!("{site_id} current line must exist"));
            assert!(
                line.contains(text(locator, "pattern")),
                "{site_id} current pattern drifted: {}",
                text(locator, "pattern")
            );
            match text(locator, "status") {
                "EXACT_LIVE_PATTERN" => {
                    assert_eq!(locator["recorded_line"], locator["current_line"]);
                }
                "STALE_LINE_LIVE_PATTERN" => {
                    assert_ne!(locator["recorded_line"], locator["current_line"]);
                }
                status => panic!("{site_id} has unknown locator status {status}"),
            }
        }

        assert_eq!(
            text(site, "owner_bead"),
            "asupersync-sched-hot-path-perf-bt4y5f.7.3"
        );
        total_locators += current_locators.len();
        total_exact += exact;
        total_stale += stale;
    }
    assert_eq!(total_locators, 39);
    assert_eq!(total_exact, 6);
    assert_eq!(total_stale, 33);

    let expected_evidence = expected_set(&[
        "URING-EVIDENCE-FILESYSTEM-E2E",
        "URING-EVIDENCE-INLINE-REACTOR",
        "URING-EVIDENCE-MOCK-BUFFER-POOL",
        "URING-EVIDENCE-READINESS-INTEGRATION",
        "URING-EVIDENCE-SYNTHETIC-CQE-BENCH",
    ]);
    let evidence = array(&inventory, "evidence_matrix");
    assert_eq!(evidence.len(), 5);
    assert_eq!(row_ids(evidence, "evidence_id"), expected_evidence);
    for row in evidence {
        assert!(!array(row, "covers").is_empty());
        assert!(!array(row, "does_not_cover").is_empty());
        assert!(
            text(row, "state").contains("SOURCE_PRESENT")
                || text(row, "state").contains("SIMULATION")
        );
        assert!(text(row, "owner_bead").starts_with("asupersync-"));
    }
}

#[test]
fn capability_levels_and_runtime_probes_are_independent() {
    let inventory = artifact();
    let expected_capabilities = expected_set(&[
        "URING-CAP-FIXED-BUFFERS",
        "URING-CAP-MAPPED-BUFFER-RING",
        "URING-CAP-MULTISHOT-ACCEPT",
        "URING-CAP-MULTISHOT-RECV",
        "URING-CAP-PROVIDED-GROUPS",
        "URING-CAP-SQPOLL",
    ]);
    let capabilities = array(&inventory, "capability_matrix");
    assert_eq!(capabilities.len(), 6);
    assert_eq!(row_ids(capabilities, "capability_id"), expected_capabilities);

    let fixed = find_row(capabilities, "capability_id", "URING-CAP-FIXED-BUFFERS");
    assert_eq!(
        text(fixed, "current_state"),
        "SCAFFOLD_ONLY_NOT_USED_BY_DATA_PLANE"
    );
    for capability in capabilities {
        assert!(!text(capability, "name").is_empty());
        assert!(!text(capability, "current_state").is_empty());
        assert!(!array(capability, "missing").is_empty());
        assert!(text(capability, "implementation_owner").starts_with("asupersync-"));
        assert_eq!(
            text(capability, "terminal_evidence_owner"),
            "asupersync-sched-hot-path-perf-bt4y5f.7.7"
        );
    }

    let probe_contract = object(&inventory, "runtime_probe_contract");
    let probe_contract_value = Value::Object(probe_contract.clone());
    assert_eq!(
        string_set(&probe_contract_value, "decision_fields"),
        expected_set(&["active", "fallback_reason", "requested", "supported"])
    );
    assert_eq!(array(&probe_contract_value, "decision_fields").len(), 4);
    assert_eq!(
        string_set(&probe_contract_value, "supported_states"),
        expected_set(&["NOT_PROBED", "SUPPORTED", "UNSUPPORTED"])
    );
    assert_eq!(array(&probe_contract_value, "supported_states").len(), 3);
    assert_eq!(
        text(&probe_contract_value, "success_fallback_reason_id"),
        "URING-FB-NONE"
    );
    assert!(!boolean(
        &probe_contract_value,
        "kernel_version_is_sufficient"
    ));
    assert_eq!(
        array(&probe_contract_value, "authority_order"),
        &vec![
            Value::String("explicit_force_off".to_owned()),
            Value::String("bounded_operation_probe".to_owned()),
            Value::String("opcode_probe".to_owned()),
            Value::String("kernel_metadata".to_owned()),
        ]
    );

    let probes = array(&probe_contract_value, "probe_rows");
    assert_eq!(probes.len(), 6);
    assert_eq!(row_ids(probes, "capability_id"), expected_capabilities);
    let registered_reasons = row_ids(array(&inventory, "fallback_reason_registry"), "id");
    for probe in probes {
        assert!(array(probe, "probe_sequence").len() >= 5);
        assert!(!text(probe, "success_condition").is_empty());
        assert!(!text(probe, "fallback_on_failure").is_empty());
        let expected_probe_reasons = match text(probe, "capability_id") {
            "URING-CAP-FIXED-BUFFERS"
            | "URING-CAP-PROVIDED-GROUPS"
            | "URING-CAP-MULTISHOT-ACCEPT" => expected_set(&[
                "URING-FB-OP-UNSUPPORTED",
                "URING-FB-PROBE-ERROR",
                "URING-FB-RESOURCE",
                "URING-FB-RING-CREATE",
            ]),
            "URING-CAP-MAPPED-BUFFER-RING" | "URING-CAP-MULTISHOT-RECV" => {
                expected_set(&[
                    "URING-FB-DEPENDENCY",
                    "URING-FB-OP-UNSUPPORTED",
                    "URING-FB-PROBE-ERROR",
                    "URING-FB-RESOURCE",
                    "URING-FB-RING-CREATE",
                ])
            }
            "URING-CAP-SQPOLL" => expected_set(&[
                "URING-FB-PERMISSION",
                "URING-FB-PROBE-ERROR",
                "URING-FB-RESOURCE",
                "URING-FB-RING-CREATE",
            ]),
            capability => panic!("unexpected capability probe {capability}"),
        };
        let actual_probe_reasons = string_set(probe, "fallback_reason_ids");
        assert_eq!(actual_probe_reasons, expected_probe_reasons);
        assert_eq!(
            array(probe, "fallback_reason_ids").len(),
            actual_probe_reasons.len()
        );
        assert!(actual_probe_reasons.is_subset(&registered_reasons));
    }
}

#[test]
fn force_off_fallback_and_observability_contracts_fail_closed() {
    let inventory = artifact();
    let force_off = object(&inventory, "force_off_contract");
    let force_off_value = Value::Object(force_off.clone());
    assert!(!boolean(&force_off_value, "ambient_environment_read_allowed"));
    assert!(boolean(&force_off_value, "global_disable_precedes_probe"));
    assert!(boolean(&force_off_value, "per_capability_mask_precedes_probe"));
    assert!(text(&force_off_value, "production_source").contains("RuntimeBuilder"));
    let forced = object(&force_off_value, "forced_off_result");
    assert_eq!(forced.get("requested").and_then(Value::as_bool), Some(true));
    assert_eq!(text(&Value::Object(forced.clone()), "supported"), "NOT_PROBED");
    assert_eq!(forced.get("active").and_then(Value::as_bool), Some(false));
    assert_eq!(
        text(&Value::Object(forced.clone()), "fallback_reason"),
        "URING-FB-FORCED-OFF"
    );

    let expected_reasons = expected_set(&[
        "URING-FB-DEPENDENCY",
        "URING-FB-FEATURE-DISABLED",
        "URING-FB-FORCED-OFF",
        "URING-FB-NONE",
        "URING-FB-NOT-REQUESTED",
        "URING-FB-NO-WIN",
        "URING-FB-OP-UNSUPPORTED",
        "URING-FB-PERMISSION",
        "URING-FB-PROBE-ERROR",
        "URING-FB-REACTOR-UNAVAILABLE",
        "URING-FB-RESOURCE",
        "URING-FB-RING-CREATE",
        "URING-FB-TARGET-UNSUPPORTED",
        "URING-FB-UNKNOWN",
    ]);
    let reasons = array(&inventory, "fallback_reason_registry");
    assert_eq!(reasons.len(), expected_reasons.len());
    assert_eq!(row_ids(reasons, "id"), expected_reasons);
    for reason in reasons {
        assert!(!text(reason, "meaning").is_empty());
    }
    let no_win_reason = find_row(reasons, "id", "URING-FB-NO-WIN");
    assert_eq!(
        text(no_win_reason, "meaning"),
        "candidate remains inactive because a correctness, comparability, measurement, or \
         resource gate failed"
    );

    let decision = object(&inventory, "decision_tuple_contract");
    let decision_value = Value::Object(decision.clone());
    assert!(boolean(&decision_value, "fallback_reason_required"));
    assert!(boolean(&decision_value, "none_is_active_success_only"));
    assert_eq!(text(&decision_value, "none_reason_id"), "URING-FB-NONE");
    assert_eq!(
        text(&decision_value, "invalid_tuple_reason_id"),
        "URING-FB-UNKNOWN"
    );
    let invalid_tuple_action = text(&decision_value, "invalid_tuple_action");
    assert!(invalid_tuple_action.contains("preserve received requested and supported"));
    assert!(invalid_tuple_action.contains("active false"));
    let reason_precedence = string_list(&decision_value, "reason_precedence");
    assert_eq!(
        reason_precedence,
        vec![
            "URING-FB-NOT-REQUESTED",
            "URING-FB-FORCED-OFF",
            "URING-FB-FEATURE-DISABLED",
            "URING-FB-TARGET-UNSUPPORTED",
            "URING-FB-DEPENDENCY",
            "URING-FB-RING-CREATE",
            "URING-FB-REACTOR-UNAVAILABLE",
            "URING-FB-OP-UNSUPPORTED",
            "URING-FB-PERMISSION",
            "URING-FB-RESOURCE",
            "URING-FB-PROBE-ERROR",
            "URING-FB-NO-WIN",
            "URING-FB-NONE",
            "URING-FB-UNKNOWN",
        ]
    );
    assert_eq!(
        reason_precedence
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect::<BTreeSet<_>>(),
        expected_reasons
    );

    let valid_states = array(&decision_value, "valid_reason_state_map");
    assert_eq!(valid_states.len(), expected_reasons.len());
    assert_eq!(row_ids(valid_states, "fallback_reason"), expected_reasons);
    let expected_state_rows: [(&str, &[bool], &[&str], bool); 14] = [
        ("URING-FB-NONE", &[true], &["SUPPORTED"], true),
        (
            "URING-FB-NOT-REQUESTED",
            &[false],
            &["NOT_PROBED"],
            false,
        ),
        (
            "URING-FB-FEATURE-DISABLED",
            &[true],
            &["NOT_PROBED"],
            false,
        ),
        (
            "URING-FB-TARGET-UNSUPPORTED",
            &[true],
            &["UNSUPPORTED"],
            false,
        ),
        (
            "URING-FB-FORCED-OFF",
            &[true],
            &["NOT_PROBED"],
            false,
        ),
        (
            "URING-FB-RING-CREATE",
            &[true],
            &["NOT_PROBED"],
            false,
        ),
        (
            "URING-FB-REACTOR-UNAVAILABLE",
            &[true],
            &["NOT_PROBED"],
            false,
        ),
        (
            "URING-FB-OP-UNSUPPORTED",
            &[true],
            &["UNSUPPORTED"],
            false,
        ),
        (
            "URING-FB-PERMISSION",
            &[true],
            &["NOT_PROBED"],
            false,
        ),
        (
            "URING-FB-RESOURCE",
            &[true],
            &["NOT_PROBED"],
            false,
        ),
        (
            "URING-FB-PROBE-ERROR",
            &[true],
            &["NOT_PROBED"],
            false,
        ),
        (
            "URING-FB-DEPENDENCY",
            &[true],
            &["NOT_PROBED"],
            false,
        ),
        ("URING-FB-NO-WIN", &[true], &["SUPPORTED"], false),
        (
            "URING-FB-UNKNOWN",
            &[false, true],
            &["NOT_PROBED", "SUPPORTED", "UNSUPPORTED"],
            false,
        ),
    ];
    for (reason, requested_states, supported_states, active) in expected_state_rows {
        let row = find_row(valid_states, "fallback_reason", reason);
        assert_eq!(
            boolean_list(row, "requested_states").as_slice(),
            requested_states
        );
        assert_eq!(
            string_list(row, "supported_states").as_slice(),
            supported_states
        );
        assert_eq!(boolean(row, "active"), active);
    }

    let invariants = array(&decision_value, "invariants");
    assert_eq!(invariants.len(), 7);
    let invariant_text = invariants
        .iter()
        .map(|invariant| invariant.as_str().expect("decision invariant must be text"))
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "active implies requested is true",
        "unless fallback_reason is URING-FB-UNKNOWN, requested false implies",
        "forced off implies supported is NOT_PROBED",
        "unless fallback_reason is URING-FB-UNKNOWN, supported UNSUPPORTED implies",
        "dependency-inactive capability is not probed",
        "fails closed as inactive with URING-FB-UNKNOWN",
        "URING-FB-UNKNOWN is the sole invariant exception",
    ] {
        assert!(invariant_text.contains(required));
    }

    let factory = object(&inventory, "factory_fallback_contract");
    let factory_value = Value::Object(factory.clone());
    assert_eq!(
        array(&factory_value, "selection_order"),
        &vec![
            Value::String("injected io driver".to_owned()),
            Value::String("injected reactor".to_owned()),
            Value::String("requested ordinary io_uring reactor".to_owned()),
            Value::String("epoll reactor".to_owned()),
            Value::String("no reactor with socket re-poll fallback".to_owned()),
        ]
    );
    assert_eq!(
        text(&factory_value, "whole_reactor_force_off_reason_id"),
        "URING-FB-FORCED-OFF"
    );
    assert_eq!(
        text(&factory_value, "ordinary_ring_failure_reason_id"),
        "URING-FB-RING-CREATE"
    );
    assert_eq!(
        text(&factory_value, "terminal_reactor_failure_reason_id"),
        "URING-FB-REACTOR-UNAVAILABLE"
    );
    assert!(text(&factory_value, "terminal_runtime_state").contains("timer backoff"));
    assert!(text(&factory_value, "terminal_runtime_state").contains("immediate rewake"));
    assert!(
        text(&factory_value, "current_observability")
            .contains("runtime_builder_platform_reactor_unavailable")
    );

    let observability = object(&inventory, "observability_contract");
    let observability_value = Value::Object(observability.clone());
    assert_eq!(
        string_set(&observability_value, "required_snapshot_fields"),
        expected_set(&[
            "active",
            "backend",
            "capability_id",
            "fallback_reason",
            "requested",
            "supported",
        ])
    );
    assert_eq!(array(&observability_value, "required_snapshot_fields").len(), 6);
    assert!(boolean(&observability_value, "bounded_cardinality"));
    assert!(!boolean(
        &observability_value,
        "free_form_host_error_in_metric_label"
    ));
    assert!(text(&observability_value, "current_inspector").contains("IoDriverHandle::stats"));
    assert_eq!(
        string_set(&observability_value, "current_fields"),
        expected_set(&[
            "deregistrations",
            "events_received",
            "polls",
            "registrations",
            "unknown_tokens",
            "wakers_dispatched",
        ])
    );
    assert_eq!(array(&observability_value, "current_fields").len(), 6);
    assert_eq!(
        string_set(&observability_value, "missing_fields"),
        expected_set(&[
            "active",
            "backend",
            "capability_id",
            "fallback_reason",
            "requested",
            "supported",
        ])
    );
    assert_eq!(array(&observability_value, "missing_fields").len(), 6);
}

#[test]
fn evidence_ownership_and_no_win_policy_are_exact() {
    let inventory = artifact();
    let expected_owners = expected_set(&[
        "asupersync-sched-hot-path-perf-bt4y5f.7.1",
        "asupersync-sched-hot-path-perf-bt4y5f.7.2",
        "asupersync-sched-hot-path-perf-bt4y5f.7.3",
        "asupersync-sched-hot-path-perf-bt4y5f.7.4",
        "asupersync-sched-hot-path-perf-bt4y5f.7.5",
        "asupersync-sched-hot-path-perf-bt4y5f.7.6",
        "asupersync-sched-hot-path-perf-bt4y5f.7.7",
    ]);
    let owners = array(&inventory, "evidence_ownership");
    assert_eq!(owners.len(), 7);
    assert_eq!(row_ids(owners, "bead_id"), expected_owners);
    for owner in owners {
        assert!(!array(owner, "owns").is_empty());
    }
    let uring_1 = find_row(owners, "bead_id", BEAD_ID);
    assert!(string_set(uring_1, "owns").contains("capability taxonomy"));

    let no_win = object(&inventory, "no_win_policy");
    let no_win_value = Value::Object(no_win.clone());
    assert_eq!(
        string_set(&no_win_value, "terminal_states"),
        expected_set(&["ADOPT", "KEEP", "NO_WIN", "UNSUPPORTED"])
    );
    assert_eq!(array(&no_win_value, "terminal_states").len(), 4);
    assert_eq!(
        string_list(&no_win_value, "disposition_precedence"),
        vec!["UNSUPPORTED", "NO_WIN", "ADOPT", "KEEP"]
    );
    assert_eq!(
        no_win.get("required_host_families").and_then(Value::as_u64),
        Some(2)
    );
    assert!(boolean(&no_win_value, "host_family_keys_must_be_distinct"));
    assert_eq!(
        string_set(&no_win_value, "host_family_key_fields"),
        expected_set(&[
            "cpu_family",
            "cpu_model",
            "cpu_vendor",
            "kernel_major_minor",
            "machine_class",
        ])
    );
    assert_eq!(array(&no_win_value, "host_family_key_fields").len(), 5);
    assert_eq!(
        no_win
            .get("minimum_repetitions_per_cell")
            .and_then(Value::as_u64),
        Some(5)
    );

    let primary = object(&no_win_value, "primary_metric");
    let primary_value = Value::Object(primary.clone());
    assert_eq!(
        primary
            .get("adopt_improvement_min_pct")
            .and_then(Value::as_f64),
        Some(5.0)
    );
    assert_eq!(text(&primary_value, "id"), "echo_requests_per_second");
    assert_eq!(text(&primary_value, "direction"), "higher_is_better");
    assert_eq!(
        text(&primary_value, "aggregation"),
        "median of per-repetition point estimates"
    );
    assert_eq!(
        primary
            .get("keep_improvement_floor_pct")
            .and_then(Value::as_f64),
        Some(0.0)
    );
    assert_eq!(
        no_win
            .get("latency_guardrail_regression_max_pct")
            .and_then(Value::as_f64),
        Some(5.0)
    );
    assert_eq!(
        string_set(&no_win_value, "required_percentiles"),
        expected_set(&["p50", "p95"])
    );
    assert_eq!(array(&no_win_value, "required_percentiles").len(), 2);
    assert_eq!(
        string_set(&no_win_value, "required_secondary_metrics"),
        expected_set(&[
            "additional_threads",
            "cpu_seconds_per_request",
            "peak_rss_bytes",
            "syscalls_per_request",
        ])
    );
    assert_eq!(array(&no_win_value, "required_secondary_metrics").len(), 4);

    let noise = object(&no_win_value, "noise_rule");
    assert!(text(&Value::Object(noise.clone()), "statistic").contains("median absolute"));
    assert_eq!(noise.get("maximum_pct").and_then(Value::as_f64), Some(5.0));
    assert_eq!(text(&Value::Object(noise.clone()), "exceeded_action"), "NO_WIN");

    let resources = object(&no_win_value, "resource_envelope");
    for key in [
        "peak_rss_increase_max_pct",
        "cpu_seconds_per_request_increase_max_pct",
    ] {
        assert_eq!(resources.get(key).and_then(Value::as_f64), Some(5.0));
    }
    assert_eq!(resources.get("additional_threads_max_default").and_then(Value::as_u64), Some(0));
    assert_eq!(
        resources
            .get("additional_threads_max_sqpoll_opt_in")
            .and_then(Value::as_u64),
        Some(1)
    );
    for key in [
        "quiescent_descriptor_delta",
        "quiescent_completion_delta",
        "quiescent_buffer_lease_delta",
        "quiescent_obligation_delta",
    ] {
        assert_eq!(resources.get(key).and_then(Value::as_u64), Some(0));
    }

    assert_eq!(
        string_set(&no_win_value, "required_context"),
        expected_set(&[
            "configuration",
            "environment",
            "features",
            "host",
            "kernel",
            "sample count",
            "source revision",
            "toolchain",
            "workload",
        ])
    );
    assert_eq!(array(&no_win_value, "required_context").len(), 9);
    assert_eq!(
        string_set(&no_win_value, "required_correctness_before_measurement"),
        expected_set(&[
            "active path parity",
            "cancellation drain",
            "forced-fallback parity",
            "zero outstanding buffer leases",
            "zero outstanding completions",
            "zero outstanding descriptors",
            "zero outstanding obligations",
        ])
    );
    assert_eq!(
        array(&no_win_value, "required_correctness_before_measurement").len(),
        7
    );
    assert_eq!(
        text(&no_win_value, "adopt_when"),
        "all correctness, comparability, noise, latency, and resource gates pass and primary \
         improvement is at least 5 percent on both host families"
    );
    assert_eq!(
        text(&no_win_value, "adopt_action"),
        "retain the candidate only under its declared policy; this receipt alone cannot change \
         the production default"
    );
    assert_eq!(
        text(&no_win_value, "keep_when"),
        "complete admissible evidence is nonnegative on both host families but misses the 5 \
         percent adoption threshold on at least one host"
    );
    assert_eq!(
        text(&no_win_value, "keep_action"),
        "retain the incumbent default; the candidate may remain explicitly opt-in and carries \
         no improvement claim"
    );
    assert_eq!(
        text(&no_win_value, "unsupported_when"),
        "complete bounded probes report unsupported on every declared target host family"
    );
    assert_eq!(
        text(&no_win_value, "unsupported_action"),
        "leave the capability inactive and retain its ordinary fallback"
    );
    assert_eq!(
        string_set(&no_win_value, "no_win_when"),
        expected_set(&[
            "correctness or lifecycle evidence is incomplete",
            "p50 or p95 regresses by more than 5 percent",
            "primary improvement is negative on either host family",
            "resource use exceeds the numeric resource envelope",
            "results are missing or incomparable",
            "the relative median absolute deviation exceeds 5 percent",
        ])
    );
    assert_eq!(array(&no_win_value, "no_win_when").len(), 6);
    assert_eq!(
        text(&no_win_value, "no_win_action"),
        "retain the incumbent path, mark the lever NO_WIN, preserve rollback and make no \
         improvement claim"
    );
}

#[test]
fn docs_and_no_claim_boundary_remain_honest() {
    let inventory = artifact();
    let docs = read_repo_file(DOC_PATH);
    for required in [
        DOC_BEGIN,
        DOC_END,
        ARTIFACT_PATH,
        "The current implementation is a useful, feature-gated readiness backend",
        "Kernel versions are metadata",
        "URING-CAP-FIXED-BUFFERS",
        "URING-CAP-PROVIDED-GROUPS",
        "URING-CAP-MAPPED-BUFFER-RING",
        "URING-CAP-MULTISHOT-ACCEPT",
        "URING-CAP-MULTISHOT-RECV",
        "URING-CAP-SQPOLL",
        "requested",
        "supported",
        "active",
        "fallback_reason",
        "URING-FB-NONE",
        "URING-FB-REACTOR-UNAVAILABLE",
        "sole invariant",
        "39 locators",
        "borrowed split",
        "two distinct host-family keys",
        "relative median absolute deviation",
        "five percent",
        "without creating a metric claim",
        "Their precedence is `UNSUPPORTED`, then",
        "not executed in this static lane",
    ] {
        assert!(docs.contains(required), "missing docs marker: {required}");
    }

    let validation = object(&inventory, "validation_state");
    assert!(boolean(&Value::Object(validation.clone()), "source_hashes_checked"));
    assert!(boolean(&Value::Object(validation.clone()), "json_shape_checked"));
    assert!(boolean(&Value::Object(validation.clone()), "rust_contract_authored"));
    assert!(!boolean(&Value::Object(validation.clone()), "rust_contract_executed"));
    assert!(!boolean(
        &Value::Object(validation.clone()),
        "live_kernel_probes_executed"
    ));
    assert!(!boolean(
        &Value::Object(validation.clone()),
        "benchmarks_executed"
    ));

    let claims = array(&inventory, "no_claims");
    assert_eq!(claims.len(), 6);
    let joined = claims
        .iter()
        .map(|claim| claim.as_str().expect("no_claims entries must be text"))
        .collect::<Vec<_>>()
        .join(" ");
    for boundary in [
        "changes no reactor",
        "does not prove compilation",
        "does not prove buffer ownership",
        "records no benchmark result",
        "does not prove broad workspace health",
        "does not authorize dependency",
    ] {
        assert!(joined.contains(boundary), "missing no-claim boundary: {boundary}");
    }
}
