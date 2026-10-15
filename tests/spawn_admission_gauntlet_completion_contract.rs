#![allow(clippy::too_many_lines, missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const PACKET_PATH: &str = "artifacts/spawn_admission_gauntlet_completion_v1.json";
const PACKET_SHA256: &str = "b0a66612b72c0dba9e2897033c5836830c363ab9eecf6a53067395fadfda9e2b";
const SCHEMA_VERSION: &str = "spawn-admission-gauntlet-completion-v1";
const LEDGER_PATH: &str = ".skill-loop-progress.md";
const LEDGER_SHA256: &str = "b9ffbd7db22ee6385af976e9eb7667f35a285d56263336a02362c884997fbcc6";
const LEDGER_STATUS_MARKER: &str = "## Status: COMPLETE — Pass 10 of 10 complete; campaign closed";
const CLOSE_COMMIT: &str = "3e278859f36d279c95ec8d8cb623163ba98215fe";
const CLOSE_PARENT: &str = "81279d2e654c7716148330635bc38065fc1f30a2";
const CLOSE_TREE: &str = "155f81d3f9564fd5dbc8bcf6efc5d51b718a79f8";

struct ExpectedPassBinding {
    commit: &'static str,
    ledger_sha256: &'static str,
}

const EXPECTED_PASS_BINDINGS: [ExpectedPassBinding; 10] = [
    ExpectedPassBinding {
        commit: "726c7449c67d6d88d1b7be7c454372035aff7a76",
        ledger_sha256: "0ca05f84002bc780538e582fe0475f622e3169f7621c05b143d7cbb208dd8adf",
    },
    ExpectedPassBinding {
        commit: "90949d62ffd6221873a047ea14c7b6bb0060849f",
        ledger_sha256: "6490e1b4cb00075c2acbd0877854af6c280bad0ff38e9b0e05224571d1c08960",
    },
    ExpectedPassBinding {
        commit: "8bda2ae33d2a50ab1e6c4d1c45126a5183c670da",
        ledger_sha256: "042bd3a2c310240d162687a56f6d7ca070625679885066aa4ee631b2d2c5552e",
    },
    ExpectedPassBinding {
        commit: "c3b4dcd289b153aeb0d826b43c1649f69a27a816",
        ledger_sha256: "b222cd89c222f39c1fb7a335ce6ba790d10170216f694281042d70b22ed7ff35",
    },
    ExpectedPassBinding {
        commit: "5dc09dc8ad364d213130dcab4f3a09a98f144314",
        ledger_sha256: "ab740f0c99db22f3ab991c4f4eeca348e30b318e1f14df10e632413796ff7bbe",
    },
    ExpectedPassBinding {
        commit: "8c4df2afd6df64182aeab6bb8c729acece37321b",
        ledger_sha256: "f084c11363d9e807022df88af779380404df102f36d1bdfcd9c5872064e81fed",
    },
    ExpectedPassBinding {
        commit: "8c4df2afd6df64182aeab6bb8c729acece37321b",
        ledger_sha256: "f084c11363d9e807022df88af779380404df102f36d1bdfcd9c5872064e81fed",
    },
    ExpectedPassBinding {
        commit: "2e5bd9c6da02358491075e812c13557b8d69cebd",
        ledger_sha256: "23700dd36586c10b32858f9fb0f281ea1afc8ea05b607b6fc8c2dca6e5a586b4",
    },
    ExpectedPassBinding {
        commit: "81279d2e654c7716148330635bc38065fc1f30a2",
        ledger_sha256: "f1d4acb081ff9253eba9cce8a897fe944d1f53f1acd36cadcdee214fc3f9f2f3",
    },
    ExpectedPassBinding {
        commit: CLOSE_COMMIT,
        ledger_sha256: LEDGER_SHA256,
    },
];

const EXPECTED_ADMITTED_CLAIMS: [&[&str]; 10] = [
    &["corrected_same_worker_baseline_decision_recorded"],
    &["bounded_cpu_attribution_decision_recorded"],
    &[
        "bounded_performance_gate_result_recorded",
        "correctness_gate_failure_recorded",
    ],
    &[
        "synchronous_typed_admission_error_blocker_recorded",
        "governor_and_quota_semantic_blockers_recorded",
    ],
    &[
        "batch_one_runtime_change_retained",
        "mailbox_pending_nonblocking_io_guard_retained",
        "bounded_admitted_workload_gain_recorded",
    ],
    &["callback_panic_safety_blocker_recorded"],
    &["direct_p99_gate_failure_recorded"],
    &[
        "bounded_ready_publication_profile_recorded",
        "non_isomorphic_candidates_rejected",
    ],
    &[
        "adversarial_measurement_harness_retained",
        "production_candidate_rejection_recorded",
    ],
    &[
        "ten_pass_sequence_completion_recorded",
        "profile_gate_rejection_recorded",
        "proof_admission_blocker_recorded",
    ],
];

const EXPECTED_NO_CLAIMS: [&[&str]; 10] = [
    &[
        "no_durable_default_flip_evidence",
        "no_cross_host_performance_claim",
    ],
    &[
        "no_total_cycle_comparison",
        "no_allocation_or_lock_wait_claim",
    ],
    &[
        "no_default_mailbox_promotion",
        "no_check_clippy_or_behavioral_equivalence_claim",
    ],
    &[
        "no_default_mailbox_promotion",
        "no_broad_health_or_clippy_claim",
    ],
    &[
        "no_individual_request_latency_claim",
        "no_scheduler_wide_or_drive_io_equivalence_claim",
    ],
    &[
        "no_compile_test_benchmark_or_performance_claim",
        "no_callback_free_commit_boundary_claim",
    ],
    &[
        "no_retained_epoch_fold",
        "no_mean_win_override_of_tail_gate",
    ],
    &[
        "no_ready_publication_speedup",
        "no_cross_host_or_production_workload_claim",
    ],
    &[
        "no_retained_runtime_optimization",
        "no_individual_request_p99_or_production_speedup_claim",
    ],
    &[
        "no_fresh_reprofile_or_candidate_ab",
        "no_fresh_check_clippy_format_or_broad_proof",
        "no_performance_workspace_health_or_release_readiness_claim",
    ],
];

struct ExpectedRetainedBinding {
    binding_id: &'static str,
    pass_ordinal: u64,
    change_class: &'static str,
    commit: &'static str,
    path: &'static str,
    sha256: &'static str,
    markers: &'static [&'static str],
}

const EXPECTED_RETAINED_BINDINGS: [ExpectedRetainedBinding; 2] = [
    ExpectedRetainedBinding {
        binding_id: "pass_5_runtime_change",
        pass_ordinal: 5,
        change_class: "production_runtime",
        commit: "5dc09dc8ad364d213130dcab4f3a09a98f144314",
        path: "src/runtime/scheduler/three_lane.rs",
        sha256: "ccd30349b8b6ea554baff1610167650c5c6faedb00e0c5eb76e9249fc14bd579",
        markers: &[
            "const SPAWN_ADMISSION_BATCH: usize = 1;",
            "fn select_io_poll_timeout(",
            "pending_spawn_mailbox_forces_nonblocking_io_poll",
        ],
    },
    ExpectedRetainedBinding {
        binding_id: "pass_9_measurement_harness",
        pass_ordinal: 9,
        change_class: "benchmark_only",
        commit: "718b5378b9f78ed8ffe1ec363c94ba80161d113d",
        path: "benches/spawn_throughput.rs",
        sha256: "d9439fbc82c5c567497130a26cc1952d6e2e26d4fb25ddc91749610b004d7fd6",
        markers: &[
            "fn direct_quota_denial(",
            "fn deferred_gateway_quota_denial(",
            "fn cancel_storm(",
            "fn bench_adversarial_tails(",
        ],
    },
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(repo_path(relative)).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn read_repo_text(relative: &str) -> String {
    String::from_utf8(read_repo_bytes(relative))
        .unwrap_or_else(|error| panic!("decode {relative} as UTF-8: {error}"))
}

fn packet() -> Value {
    serde_json::from_slice(&read_repo_bytes(PACKET_PATH))
        .unwrap_or_else(|error| panic!("parse {PACKET_PATH}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn git_output(args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .map_err(|error| format!("run git {args:?}: {error}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn git_file(commit: &str, path: &str) -> Result<Vec<u8>, String> {
    git_output(&["show", &format!("{commit}:{path}")])
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| panic!("{key} entries must be nonempty strings"))
                .to_owned()
        })
        .collect()
}

fn string_values<'a>(value: &'a Value, key: &str) -> Option<Vec<&'a str>> {
    value
        .get(key)?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect()
}

fn assert_full_git_history_available() {
    let shallow = String::from_utf8(git_output(&["rev-parse", "--is-shallow-repository"]).unwrap())
        .expect("git shallow-repository result is UTF-8");
    assert_eq!(
        shallow.trim(),
        "false",
        "spawn-admission history contract requires a non-shallow checkout"
    );
}

fn validate_structure(root: &Value) -> Vec<String> {
    let mut errors = Vec::new();

    if root.get("schema_version").and_then(Value::as_str) != Some(SCHEMA_VERSION) {
        errors.push("schema_version mismatch".to_owned());
    }
    if root.get("campaign_bead_id").and_then(Value::as_str)
        != Some("asupersync-spawn-admission-opt-gauntlet-p8zm1v")
    {
        errors.push("campaign bead mismatch".to_owned());
    }

    let Some(status) = root.get("campaign_status") else {
        errors.push("campaign_status missing".to_owned());
        return errors;
    };
    if status.get("sequence_status").and_then(Value::as_str) != Some("complete") {
        errors.push("sequence status must stay complete".to_owned());
    }
    if status.get("proof_status").and_then(Value::as_str) != Some("blocked") {
        errors.push("proof status must stay blocked".to_owned());
    }
    if status.get("combined_status").and_then(Value::as_str)
        != Some("sequence_complete_proof_blocked")
    {
        errors.push("combined status must stay sequence_complete_proof_blocked".to_owned());
    }
    if status.get("expected_pass_count").and_then(Value::as_u64) != Some(10) {
        errors.push("expected pass count must be ten".to_owned());
    }
    if status
        .get("serial_execution_required")
        .and_then(Value::as_bool)
        != Some(true)
    {
        errors.push("serial execution must be required".to_owned());
    }
    if status.get("pass_11_authorized").and_then(Value::as_bool) != Some(false) {
        errors.push("Pass 11 must remain unauthorized".to_owned());
    }
    if status.get("completion_claim").and_then(Value::as_str)
        != Some("ten_serial_decisions_recorded")
    {
        errors.push("completion claim exceeded ten recorded decisions".to_owned());
    }
    if status
        .get("tracker_status_at_packet_creation")
        .and_then(Value::as_str)
        != Some("in_progress")
    {
        errors.push("tracker status at packet creation drifted".to_owned());
    }
    if status
        .get("tracker_assignee_at_packet_creation")
        .and_then(Value::as_str)
        != Some("MistyOsprey")
    {
        errors.push("tracker authority owner drifted".to_owned());
    }
    if status.get("tracker_status_drift").and_then(Value::as_bool) != Some(true) {
        errors.push("tracker status drift must stay visible".to_owned());
    }
    if status
        .get("tracker_close_authorized")
        .and_then(Value::as_bool)
        != Some(false)
    {
        errors.push("packet must not authorize parent tracker close".to_owned());
    }

    let Some(ledger) = root.get("ledger_binding") else {
        errors.push("ledger_binding missing".to_owned());
        return errors;
    };
    for (key, expected) in [
        ("path", LEDGER_PATH),
        ("close_commit_full", CLOSE_COMMIT),
        ("close_parent_full", CLOSE_PARENT),
        ("close_tree_full", CLOSE_TREE),
        ("sha256", LEDGER_SHA256),
        ("required_status_marker", LEDGER_STATUS_MARKER),
    ] {
        if ledger.get(key).and_then(Value::as_str) != Some(expected) {
            errors.push(format!("ledger binding {key} mismatch"));
        }
    }

    let expected_verdicts = [
        "measurement_only",
        "measurement_only",
        "rejected_fail_closed",
        "rejected_fail_closed",
        "retained_production_change",
        "rejected_fail_closed",
        "rejected_performance_gate",
        "measurement_only",
        "retained_measurement_harness",
        "measurement_only",
    ];
    let expected_dispositions = [
        "no_candidate",
        "no_candidate",
        "candidate_reverted",
        "candidate_reverted",
        "candidate_retained",
        "candidate_reverted",
        "candidate_reverted",
        "candidates_rejected_before_edit",
        "runtime_candidate_reverted_harness_retained",
        "candidate_rejected_before_edit",
    ];

    let Some(passes) = root.get("passes").and_then(Value::as_array) else {
        errors.push("passes missing".to_owned());
        return errors;
    };
    if passes.len() != 10 {
        errors.push(format!("expected 10 passes, found {}", passes.len()));
    }

    for (index, pass) in passes.iter().enumerate() {
        let expected_ordinal = u64::try_from(index + 1).expect("pass ordinal fits u64");
        if pass.get("ordinal").and_then(Value::as_u64) != Some(expected_ordinal) {
            errors.push(format!(
                "pass {} is missing, duplicated, or reordered",
                index + 1
            ));
        }
        if pass.get("verdict").and_then(Value::as_str) != expected_verdicts.get(index).copied() {
            errors.push(format!("pass {} verdict mismatch", index + 1));
        }
        if pass.get("candidate_disposition").and_then(Value::as_str)
            != expected_dispositions.get(index).copied()
        {
            errors.push(format!("pass {} candidate disposition mismatch", index + 1));
        }
        if let Some(expected) = EXPECTED_PASS_BINDINGS.get(index) {
            if pass.get("record_commit_full").and_then(Value::as_str) != Some(expected.commit) {
                errors.push(format!("pass {} record commit was rebound", index + 1));
            }
            if pass.get("ledger_snapshot_sha256").and_then(Value::as_str)
                != Some(expected.ledger_sha256)
            {
                errors.push(format!("pass {} ledger hash was rebound", index + 1));
            }
        }
        if string_values(pass, "admitted_claims").as_deref()
            != EXPECTED_ADMITTED_CLAIMS.get(index).copied()
        {
            errors.push(format!("pass {} admitted claims drifted", index + 1));
        }
        if string_values(pass, "no_claims").as_deref() != EXPECTED_NO_CLAIMS.get(index).copied() {
            errors.push(format!("pass {} no-claims drifted", index + 1));
        }

        let runtime_retained = pass
            .get("retained_runtime_change")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let harness_retained = pass
            .get("retained_measurement_harness")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if runtime_retained != (index == 4) {
            errors.push(format!("pass {} runtime-retained flag mismatch", index + 1));
        }
        if harness_retained != (index == 8) {
            errors.push(format!("pass {} harness-retained flag mismatch", index + 1));
        }

        if let Some(receipts) = pass.get("external_receipts").and_then(Value::as_array) {
            for receipt in receipts {
                let path = receipt.get("path").and_then(Value::as_str).unwrap_or("");
                if !path.starts_with('/') {
                    errors.push(format!(
                        "pass {} external receipt must be absolute",
                        index + 1
                    ));
                }
                if receipt.get("location_class").and_then(Value::as_str)
                    != Some("external_ephemeral")
                {
                    errors.push(format!("pass {} external receipt was promoted", index + 1));
                }
                if receipt.get("decision_role").and_then(Value::as_str)
                    != Some("historical_context_only")
                {
                    errors.push(format!(
                        "pass {} external receipt became authoritative",
                        index + 1
                    ));
                }
                if let Some(digest) = receipt.get("sha256").and_then(Value::as_str)
                    && !is_lower_hex(digest, 64)
                {
                    errors.push(format!("pass {} external checksum is malformed", index + 1));
                }
            }
        }
    }

    let runtime_passes = passes
        .iter()
        .filter(|pass| pass.get("retained_runtime_change").and_then(Value::as_bool) == Some(true))
        .filter_map(|pass| pass.get("ordinal").and_then(Value::as_u64))
        .collect::<Vec<_>>();
    if runtime_passes != [5] {
        errors.push(format!("runtime retained passes were {runtime_passes:?}"));
    }
    let harness_passes = passes
        .iter()
        .filter(|pass| {
            pass.get("retained_measurement_harness")
                .and_then(Value::as_bool)
                == Some(true)
        })
        .filter_map(|pass| pass.get("ordinal").and_then(Value::as_u64))
        .collect::<Vec<_>>();
    if harness_passes != [9] {
        errors.push(format!(
            "measurement-harness retained passes were {harness_passes:?}"
        ));
    }

    let Some(bindings) = root
        .get("retained_change_bindings")
        .and_then(Value::as_array)
    else {
        errors.push("retained_change_bindings missing".to_owned());
        return errors;
    };
    if bindings.len() != EXPECTED_RETAINED_BINDINGS.len() {
        errors.push(format!(
            "expected {} retained bindings, found {}",
            EXPECTED_RETAINED_BINDINGS.len(),
            bindings.len()
        ));
    }
    let bound_passes = bindings
        .iter()
        .filter_map(|binding| binding.get("pass_ordinal").and_then(Value::as_u64))
        .collect::<Vec<_>>();
    if bound_passes != [5, 9] {
        errors.push(format!("retained bindings were {bound_passes:?}"));
    }
    for (binding, expected) in bindings.iter().zip(&EXPECTED_RETAINED_BINDINGS) {
        for (key, expected_value) in [
            ("binding_id", expected.binding_id),
            ("change_class", expected.change_class),
            ("commit_full", expected.commit),
            ("path", expected.path),
            ("sha256_at_commit", expected.sha256),
        ] {
            if binding.get(key).and_then(Value::as_str) != Some(expected_value) {
                errors.push(format!("{} {key} was rebound", expected.binding_id));
            }
        }
        if binding.get("pass_ordinal").and_then(Value::as_u64) != Some(expected.pass_ordinal) {
            errors.push(format!("{} pass ordinal was rebound", expected.binding_id));
        }
        if string_values(binding, "required_source_markers").as_deref() != Some(expected.markers) {
            errors.push(format!("{} source markers drifted", expected.binding_id));
        }
    }

    let required_boundaries = BTreeSet::from([
        "does_not_promote_mailbox_to_default".to_owned(),
        "does_not_prove_individual_request_p99".to_owned(),
        "does_not_prove_cross_host_performance".to_owned(),
        "does_not_prove_production_workload_speedup".to_owned(),
        "does_not_prove_scheduler_wide_performance".to_owned(),
        "does_not_prove_runtime_correctness".to_owned(),
        "does_not_prove_workspace_health".to_owned(),
        "does_not_prove_release_readiness".to_owned(),
        "does_not_prove_fresh_pass_10_rch_validation".to_owned(),
        "does_not_prove_external_receipt_durability".to_owned(),
        "does_not_authorize_local_cargo_fallback".to_owned(),
        "does_not_authorize_parent_tracker_close".to_owned(),
        "does_not_authorize_peer_process_cancellation".to_owned(),
        "does_not_authorize_file_deletion".to_owned(),
    ]);
    let actual_boundaries = root
        .get("no_claim_boundaries")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if actual_boundaries != required_boundaries {
        errors.push("global no-claim boundary set drifted".to_owned());
    }
    if actual_boundaries
        .iter()
        .any(|boundary| !boundary.starts_with("does_not_"))
    {
        errors.push("no-claim boundary must use does_not token".to_owned());
    }

    errors
}

fn verify_ledger_bindings(root: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let ledger = &root["ledger_binding"];
    let path = ledger.get("path").and_then(Value::as_str).unwrap_or("");
    let close = ledger
        .get("close_commit_full")
        .and_then(Value::as_str)
        .unwrap_or("");
    let expected_hash = ledger.get("sha256").and_then(Value::as_str).unwrap_or("");

    let current = read_repo_bytes(path);
    if sha256(&current) != expected_hash {
        errors.push("current completion ledger hash mismatch".to_owned());
    }
    match git_file(close, path) {
        Ok(bytes) if sha256(&bytes) == expected_hash => {}
        Ok(_) => errors.push("close-commit completion ledger hash mismatch".to_owned()),
        Err(error) => errors.push(error),
    }

    let progress = String::from_utf8_lossy(&current);
    let marker = ledger
        .get("required_status_marker")
        .and_then(Value::as_str)
        .unwrap_or("");
    if progress.matches(marker).count() != 1 {
        errors.push("completion status marker missing or duplicated".to_owned());
    }
    if progress.contains("### Pass 11") {
        errors.push("unauthorized Pass 11 found".to_owned());
    }

    let mut previous_offset = None;
    if let Some(passes) = root.get("passes").and_then(Value::as_array) {
        for pass in passes {
            let ordinal = pass.get("ordinal").and_then(Value::as_u64).unwrap_or(0);
            let title = pass.get("title").and_then(Value::as_str).unwrap_or("");
            let heading = format!("### Pass {ordinal} — {title}");
            if progress.matches(&heading).count() != 1 {
                errors.push(format!("heading missing or duplicated: {heading}"));
            }
            if let Some(offset) = progress.find(&heading) {
                if previous_offset.is_some_and(|previous| offset <= previous) {
                    errors.push(format!("pass heading out of order: {heading}"));
                }
                previous_offset = Some(offset);
            }

            let commit = pass
                .get("record_commit_full")
                .and_then(Value::as_str)
                .unwrap_or("");
            let snapshot_hash = pass
                .get("ledger_snapshot_sha256")
                .and_then(Value::as_str)
                .unwrap_or("");
            match git_file(commit, path) {
                Ok(bytes) => {
                    if sha256(&bytes) != snapshot_hash {
                        errors.push(format!("pass {ordinal} ledger snapshot hash mismatch"));
                    }
                    if !String::from_utf8_lossy(&bytes).contains(&heading) {
                        errors.push(format!("pass {ordinal} heading absent at record commit"));
                    }
                }
                Err(error) => errors.push(error),
            }
        }
    }

    errors
}

fn verify_retained_bindings(root: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(bindings) = root
        .get("retained_change_bindings")
        .and_then(Value::as_array)
    else {
        return vec!["retained_change_bindings missing".to_owned()];
    };

    for binding in bindings {
        let id = binding
            .get("binding_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let commit = binding
            .get("commit_full")
            .and_then(Value::as_str)
            .unwrap_or("");
        let path = binding.get("path").and_then(Value::as_str).unwrap_or("");
        let expected_hash = binding
            .get("sha256_at_commit")
            .and_then(Value::as_str)
            .unwrap_or("");
        let historical = match git_file(commit, path) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        if sha256(&historical) != expected_hash {
            errors.push(format!("{id} historical Git-object hash mismatch"));
        }
        let historical_text = String::from_utf8_lossy(&historical);
        let current_text = read_repo_text(path);
        for marker in array(binding, "required_source_markers") {
            let marker = marker.as_str().unwrap_or("");
            if !historical_text.contains(marker) {
                errors.push(format!("{id} historical source marker missing: {marker}"));
            }
            if !current_text.contains(marker) {
                errors.push(format!("{id} current source marker missing: {marker}"));
            }
        }
    }

    errors
}

#[test]
fn packet_structure_is_fail_closed_and_scoped() {
    assert_eq!(sha256(&read_repo_bytes(PACKET_PATH)), PACKET_SHA256);
    let root = packet();
    assert_eq!(validate_structure(&root), Vec::<String>::new());

    let scope = &root["scope"];
    assert_eq!(
        string(scope, "certificate_class"),
        "process_completion_only"
    );
    assert_eq!(string(scope, "formal_assurance_tier"), "A");
    assert!(!bool_field(scope, "atp_paths_in_scope"));
    assert!(!bool_field(scope, "runtime_default_promotion_claimed"));
    assert!(!bool_field(scope, "fresh_pass_10_proof_claimed"));
    assert!(!bool_field(
        scope,
        "canonical_proof_lane_registration_claimed"
    ));

    let focused = &root["focused_validation"];
    assert!(bool_field(focused, "remote_required"));
    assert!(bool_field(focused, "no_local_fallback"));
    let command = string(focused, "command");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(command.contains("CARGO_TARGET_DIR="));
    assert!(command.contains("spawn_admission_gauntlet_completion_contract"));
    assert!(command.contains("--include-ignored"));
    assert!(string(focused, "git_history_prerequisite").contains("non-shallow Git checkout"));
    assert_eq!(string(focused, "manifest_registration"), "not_registered");
}

#[test]
#[ignore = "requires full Git history; run the packet's focused command"]
fn ledger_snapshots_are_git_bound_and_strictly_serial() {
    assert_full_git_history_available();
    let root = packet();
    assert_eq!(verify_ledger_bindings(&root), Vec::<String>::new());

    let parent =
        String::from_utf8(git_output(&["rev-parse", &format!("{CLOSE_COMMIT}^")]).unwrap())
            .expect("git parent output is UTF-8");
    assert_eq!(parent.trim(), CLOSE_PARENT);
    let tree = String::from_utf8(
        git_output(&["show", "--no-patch", "--format=%T", CLOSE_COMMIT]).unwrap(),
    )
    .expect("git tree output is UTF-8");
    assert_eq!(tree.trim(), CLOSE_TREE);
}

#[test]
#[ignore = "requires full Git history; run the packet's focused command"]
fn retained_changes_match_historical_git_objects_and_current_markers() {
    assert_full_git_history_available();
    let root = packet();
    assert_eq!(verify_retained_bindings(&root), Vec::<String>::new());

    let bindings = array(&root, "retained_change_bindings");
    assert_eq!(string(&bindings[0], "change_class"), "production_runtime");
    assert_eq!(string(&bindings[1], "change_class"), "benchmark_only");
    assert!(string(&bindings[0], "behavior_boundary").contains("does not promote Mailbox"));
    assert!(string(&bindings[1], "behavior_boundary").contains("candidate was reverted"));
}

#[test]
fn proof_obligations_and_no_claim_boundaries_are_complete() {
    let root = packet();
    let obligations = array(&root, "proof_obligations");
    let ids = obligations
        .iter()
        .map(|obligation| string(obligation, "obligation_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids,
        BTreeSet::from([
            "PO-SEQUENCE".to_owned(),
            "PO-EVIDENCE-ADMISSIBILITY".to_owned(),
            "PO-RETAINED-BINDINGS".to_owned(),
            "PO-TRACKER-AUTHORITY".to_owned(),
            "PO-NO-CLAIM-MONOTONICITY".to_owned(),
        ])
    );
    for obligation in obligations {
        for field in [
            "assumptions",
            "statement",
            "verification_method",
            "failure_conditions",
            "rollback_or_mitigation",
        ] {
            assert!(!string(obligation, field).trim().is_empty());
        }
    }

    let interlocks = array(&root, "correctness_interlocks_at_sequence_close");
    let interlock_ids = interlocks
        .iter()
        .map(|interlock| string(interlock, "bead_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        interlock_ids,
        BTreeSet::from([
            "asupersync-909482".to_owned(),
            "asupersync-20t5x2".to_owned(),
            "asupersync-ob2lqk".to_owned(),
            "asupersync-5mty2b".to_owned(),
        ])
    );

    let external = &root["external_receipt_policy"];
    assert!(!bool_field(
        external,
        "durable_completion_depends_on_external_receipt_availability"
    ));
    assert!(!bool_field(
        external,
        "external_receipts_reverified_by_this_packet"
    ));
    assert!(!bool_field(
        external,
        "external_receipts_may_authorize_new_performance_claims"
    ));

    assert!(
        string_set(&root, "no_claim_boundaries")
            .contains("does_not_authorize_parent_tracker_close")
    );
}

#[test]
fn tampering_is_detected_before_any_completion_claim() {
    let canonical = packet();

    let mut missing_pass = canonical.clone();
    missing_pass["passes"].as_array_mut().unwrap().remove(4);
    assert!(!validate_structure(&missing_pass).is_empty());

    let mut reordered = canonical.clone();
    reordered["passes"].as_array_mut().unwrap().swap(2, 3);
    assert!(!validate_structure(&reordered).is_empty());

    let mut rejected_promoted = canonical.clone();
    rejected_promoted["passes"][2]["retained_runtime_change"] = Value::Bool(true);
    assert!(!validate_structure(&rejected_promoted).is_empty());

    let mut external_promoted = canonical.clone();
    external_promoted["passes"][0]["external_receipts"][0]["location_class"] =
        Value::String("git_object".to_owned());
    assert!(!validate_structure(&external_promoted).is_empty());

    let mut tracker_self_closed = canonical.clone();
    tracker_self_closed["campaign_status"]["tracker_close_authorized"] = Value::Bool(true);
    assert!(!validate_structure(&tracker_self_closed).is_empty());

    let mut boundary_removed = canonical.clone();
    boundary_removed["no_claim_boundaries"]
        .as_array_mut()
        .unwrap()
        .retain(|boundary| boundary.as_str() != Some("does_not_prove_release_readiness"));
    assert!(!validate_structure(&boundary_removed).is_empty());

    let mut proof_promoted = canonical.clone();
    proof_promoted["campaign_status"]["proof_status"] = Value::String("complete".to_owned());
    assert!(!validate_structure(&proof_promoted).is_empty());

    let mut admitted_claim_promoted = canonical.clone();
    admitted_claim_promoted["passes"][0]["admitted_claims"] =
        serde_json::json!(["release_readiness_proved"]);
    assert!(!validate_structure(&admitted_claim_promoted).is_empty());

    let mut pass_coherently_rebound = canonical.clone();
    pass_coherently_rebound["passes"][0]["record_commit_full"] =
        Value::String(CLOSE_COMMIT.to_owned());
    pass_coherently_rebound["passes"][0]["ledger_snapshot_sha256"] =
        Value::String(LEDGER_SHA256.to_owned());
    assert!(!validate_structure(&pass_coherently_rebound).is_empty());

    let mut ledger_coherently_rebound = canonical.clone();
    ledger_coherently_rebound["ledger_binding"]["close_commit_full"] =
        Value::String(CLOSE_PARENT.to_owned());
    ledger_coherently_rebound["ledger_binding"]["sha256"] =
        Value::String(EXPECTED_PASS_BINDINGS[8].ledger_sha256.to_owned());
    assert!(!validate_structure(&ledger_coherently_rebound).is_empty());

    let mut retained_coherently_rebound = canonical;
    retained_coherently_rebound["retained_change_bindings"][0]["commit_full"] =
        Value::String(CLOSE_COMMIT.to_owned());
    retained_coherently_rebound["retained_change_bindings"][0]["path"] =
        Value::String(LEDGER_PATH.to_owned());
    retained_coherently_rebound["retained_change_bindings"][0]["sha256_at_commit"] =
        Value::String(LEDGER_SHA256.to_owned());
    retained_coherently_rebound["retained_change_bindings"][0]["required_source_markers"] =
        serde_json::json!([]);
    assert!(!validate_structure(&retained_coherently_rebound).is_empty());
}

#[test]
#[ignore = "requires full Git history; run the packet's focused command"]
fn historical_binding_tampering_is_detected() {
    assert_full_git_history_available();
    let canonical = packet();

    let mut ledger_rebound = canonical.clone();
    ledger_rebound["ledger_binding"]["sha256"] = Value::String("0".repeat(64));
    assert!(!verify_ledger_bindings(&ledger_rebound).is_empty());

    let mut retained_rebound = canonical;
    retained_rebound["retained_change_bindings"][0]["sha256_at_commit"] =
        Value::String("f".repeat(64));
    assert!(!verify_retained_bindings(&retained_rebound).is_empty());
}
