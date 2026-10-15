//! Deterministic VER A1 evidence-plan generator.
//!
//! This binary reads the checked dependency-plan tracker and capability registry,
//! then renders the fail-closed unit/property/fuzz evidence plan consumed by
//! `tests/dependency_verification_matrix_contract.rs`.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.6.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const ARTIFACT_PATH: &str = "artifacts/dependency_verification_matrix_v1.json";
const DOC_PATH: &str = "docs/dependency_verification_matrix.md";
const CONTRACT_PATH: &str = "tests/dependency_verification_matrix_contract.rs";
const AUTHORITY_MARKER: &str = "CAPABILITY AUTHORITY";

const BASE_CASES: &[&str] = &[
    "happy_path",
    "empty_boundary",
    "maximum_overflow",
    "malformed_error",
    "resource_bound",
    "regression",
];
const PARSER_CASES: &[&str] = &[
    "truncation",
    "invalid_state",
    "round_trip",
    "independent_vector",
];
const CONCURRENCY_CASES: &[&str] = &[
    "cancellation",
    "race_shutdown",
    "task_leak",
    "obligation_leak",
    "loser_drain",
    "quiescence",
];
const SECURITY_CASES: &[&str] = &[
    "security_misuse",
    "authentication_failure",
    "secret_redaction",
];
const PUBLIC_CASES: &[&str] = &["downstream_compile", "downstream_runtime"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(repo_root().join(path))
        .map_err(|error| format!("failed to read {path}: {error}"))
}

fn parse_json(path: &str) -> Result<Value, String> {
    serde_json::from_str(&read_repo_file(path)?)
        .map_err(|error| format!("{path} must be valid JSON: {error}"))
}

fn parse_tracker() -> Result<Vec<Value>, String> {
    read_repo_file(TRACKER_PATH)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|error| {
                format!("{TRACKER_PATH}:{} must be valid JSON: {error}", index + 1)
            })
        })
        .collect()
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn has_label(issue: &Value, label: &str) -> bool {
    issue
        .get("labels")
        .and_then(Value::as_array)
        .is_some_and(|labels| labels.iter().any(|entry| entry.as_str() == Some(label)))
}

fn is_matrix_bead(issue: &Value) -> bool {
    has_label(issue, "dep-plan")
        && issue.get("issue_type").and_then(Value::as_str) != Some("epic")
        && !is_superseded_duplicate(issue)
}

/// Disposition tokens that mark a closed tracker issue as superseded by a
/// canonical successor, matching the documented `coverage_scope`.
///
/// These are matched as whole ASCII words, never as substrings. A naked
/// `contains` match fails open: it silently drops a bead from required
/// verification coverage whenever an unrelated longer word happens to embed
/// one of these tokens. `asupersync-ym2wtv.1` is the live example -- it closed
/// as a DEFER decision whose reason reads "GB-03 duplicated-runtime finding is
/// decisive", and `contains("duplicate")` matched inside "duplicated".
const SUPERSEDED_DUPLICATE_TOKENS: [&str; 2] = ["superseded", "duplicate"];

fn is_superseded_duplicate(issue: &Value) -> bool {
    issue.get("status").and_then(Value::as_str) == Some("closed")
        && issue
            .get("close_reason")
            .and_then(Value::as_str)
            .is_some_and(contains_superseded_duplicate_token)
}

/// Returns true when `reason` contains a disposition token as a whole word.
///
/// Word boundaries are any non-alphanumeric ASCII character, so
/// "plan superseded", "closed: duplicate of x" and "(duplicate)" all match,
/// while "duplicated", "deduplicate" and "superseded_by_nothing" do not.
fn contains_superseded_duplicate_token(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    SUPERSEDED_DUPLICATE_TOKENS.iter().any(|token| {
        reason.match_indices(token).any(|(start, matched)| {
            let before_ok = reason[..start]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_alphanumeric());
            let after_ok = reason[start + matched.len()..]
                .chars()
                .next()
                .is_none_or(|character| !character.is_ascii_alphanumeric());
            before_ok && after_ok
        })
    })
}

fn slug(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut last_was_separator = false;
    for character in text.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            output.push('_');
            last_was_separator = true;
        }
    }
    output.trim_matches('_').to_owned()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn issue_text(issue: &Value) -> String {
    let labels = strings(issue, "labels").join(" ");
    [
        issue.get("title").and_then(Value::as_str).unwrap_or(""),
        issue
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or(""),
        issue
            .get("acceptance_criteria")
            .and_then(Value::as_str)
            .unwrap_or(""),
        &labels,
    ]
    .join(" ")
    .to_ascii_lowercase()
}

fn authority_capabilities(issue: &Value) -> BTreeSet<String> {
    let mut capabilities = BTreeSet::new();
    let Some(comments) = issue.get("comments").and_then(Value::as_array) else {
        return capabilities;
    };

    for comment in comments {
        let Some(text) = comment.get("text").and_then(Value::as_str) else {
            continue;
        };
        if !text.contains(AUTHORITY_MARKER) {
            continue;
        }
        let authority_segment = text.split("Role =").next().unwrap_or(text);
        for token in authority_segment.split(|character: char| {
            character.is_ascii_whitespace() || matches!(character, ',' | ';' | '.' | '`')
        }) {
            let candidate = token.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '-'
            });
            if candidate.starts_with("CAP-")
                && candidate
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            {
                capabilities.insert(candidate.to_owned());
            }
        }
    }
    capabilities
}

fn mapped_capabilities(issue: &Value, registry: &Value) -> Result<BTreeSet<String>, String> {
    let authority = authority_capabilities(issue);
    if !authority.is_empty() {
        return Ok(authority);
    }

    let issue_id = string(issue, "id")?;
    let mut capabilities = BTreeSet::new();
    let rules = registry
        .get("bead_mapping_rules")
        .and_then(Value::as_array)
        .ok_or_else(|| "registry bead_mapping_rules must be an array".to_owned())?;
    for rule in rules {
        let scope = rule.get("scope").and_then(Value::as_str).unwrap_or("");
        let mapped_id = rule.get("bead_id").and_then(Value::as_str).unwrap_or("");
        let matches = match scope {
            "exact" => issue_id == mapped_id,
            "prefix" => issue_id.starts_with(mapped_id),
            _ => false,
        };
        if matches {
            capabilities.extend(strings(rule, "capability_ids"));
        }
    }
    Ok(capabilities)
}

fn role(issue: &Value, text: &str) -> &'static str {
    let issue_type = issue
        .get("issue_type")
        .and_then(Value::as_str)
        .unwrap_or("task");
    if issue_type == "question"
        || contains_any(text, &["terminal keep", "owner decision", "go/no-go"])
    {
        "decision"
    } else if has_label(issue, "adr")
        || has_label(issue, "architecture")
        || text.starts_with("adr:")
    {
        "architecture"
    } else if contains_any(
        text,
        &[
            " audit",
            " signoff",
            " verification",
            " benchmark",
            " corpus",
            " evidence",
            " inventory",
            " review",
            " contract",
        ],
    ) {
        "verification"
    } else {
        "implementation"
    }
}

fn risks(issue: &Value, text: &str, capability_ids: &BTreeSet<String>) -> BTreeSet<String> {
    let mut risks = BTreeSet::from(["boundary".to_owned()]);
    let capability_text = capability_ids
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let combined = format!("{text} {capability_text}");

    if contains_any(
        &combined,
        &[
            "parser", "codec", "decode", "encode", "wire", "format", "grammar", "protobuf",
            "base64", "hex", "regex", "x.509", "x509", "lz4", "deflate", "zlib", "gzip", "toml",
            "yaml", "rfc3339", "nkey", "kafka", "sqlite",
        ],
    ) {
        risks.insert("parser_codec".to_owned());
    }
    if contains_any(
        &combined,
        &[
            "concurrency",
            "concurrent",
            "cancel",
            "runtime",
            "scheduler",
            "mutex",
            "rwlock",
            "condvar",
            "queue",
            "channel",
            "future",
            "stream",
            "backpressure",
            "shutdown",
            "lifecycle",
            "quiescence",
            "leak",
            "race",
        ],
    ) {
        risks.insert("concurrency".to_owned());
    }
    if contains_any(
        &combined,
        &[
            "security",
            "auth",
            "credential",
            "tls",
            "x509",
            "certificate",
            "nkey",
            "jwt",
            "privacy",
            "secret",
            "crypto",
            "signer",
            "unsafe",
        ],
    ) {
        risks.insert("security".to_owned());
    }
    if contains_any(
        &combined,
        &[
            "public",
            "downstream",
            "generic",
            "api",
            "consumer",
            "cli",
            "serde",
        ],
    ) {
        risks.insert("public_generic".to_owned());
    }
    if contains_any(
        &combined,
        &[
            "e2e",
            "real service",
            "real-service",
            "interop",
            "user journey",
            "user-journey",
            "protocol",
            "daemon",
            "broker",
            "installed",
        ],
    ) {
        risks.insert("user_journey".to_owned());
    }
    if contains_any(
        &combined,
        &[
            "property",
            "model",
            "compiler",
            "algorithm",
            "state machine",
            "state-machine",
            "determin",
            "differential",
        ],
    ) || risks.contains("parser_codec")
    {
        risks.insert("property".to_owned());
    }
    if has_label(issue, "fuzz")
        || contains_any(&combined, &["fuzz", "adversarial"])
        || risks.contains("parser_codec")
        || risks.contains("security")
    {
        risks.insert("fuzz".to_owned());
    }
    risks
}

fn required_cases(risks: &BTreeSet<String>) -> Vec<String> {
    let mut cases = BTreeSet::new();
    cases.extend(BASE_CASES.iter().map(|case| (*case).to_owned()));
    if risks.contains("parser_codec") {
        cases.extend(PARSER_CASES.iter().map(|case| (*case).to_owned()));
    }
    if risks.contains("concurrency") {
        cases.extend(CONCURRENCY_CASES.iter().map(|case| (*case).to_owned()));
    }
    if risks.contains("security") {
        cases.extend(SECURITY_CASES.iter().map(|case| (*case).to_owned()));
    }
    if risks.contains("public_generic") {
        cases.extend(PUBLIC_CASES.iter().map(|case| (*case).to_owned()));
    }
    cases.into_iter().collect()
}

fn capability_rows(registry: &Value) -> Result<BTreeMap<String, Value>, String> {
    let rows = registry
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| "registry capabilities must be an array".to_owned())?;
    let mut by_id = BTreeMap::new();
    for row in rows {
        let id = string(row, "capability_id")?.to_owned();
        if by_id.insert(id.clone(), row.clone()).is_some() {
            return Err(format!("duplicate capability_id {id}"));
        }
    }
    Ok(by_id)
}

fn capability_invariants(capabilities: &BTreeMap<String, Value>) -> Vec<Value> {
    capabilities
        .iter()
        .map(|(capability_id, row)| {
            let mut invariants = vec![
                json!({
                    "invariant_id": format!("{capability_id}::input"),
                    "kind": "input",
                    "statement": row.get("input_semantics").cloned().unwrap_or(Value::Null),
                }),
                json!({
                    "invariant_id": format!("{capability_id}::output"),
                    "kind": "output",
                    "statement": row.get("output_semantics").cloned().unwrap_or(Value::Null),
                }),
                json!({
                    "invariant_id": format!("{capability_id}::error"),
                    "kind": "error",
                    "statement": row.get("error_semantics").cloned().unwrap_or(Value::Null),
                }),
                json!({
                    "invariant_id": format!("{capability_id}::resource"),
                    "kind": "resource",
                    "statement": row.get("resource_semantics").cloned().unwrap_or(Value::Null),
                }),
            ];
            for (index, statement) in strings(row, "security_invariants").into_iter().enumerate() {
                invariants.push(json!({
                    "invariant_id": format!("{capability_id}::security::{:02}", index + 1),
                    "kind": "security",
                    "statement": statement,
                }));
            }
            for (index, statement) in strings(row, "cancellation_invariants")
                .into_iter()
                .enumerate()
            {
                invariants.push(json!({
                    "invariant_id": format!("{capability_id}::cancellation::{:02}", index + 1),
                    "kind": "cancellation",
                    "statement": statement,
                }));
            }
            json!({
                "capability_id": capability_id,
                "invariants": invariants,
            })
        })
        .collect()
}

fn invariant_ids(
    capability_ids: &BTreeSet<String>,
    capabilities: &BTreeMap<String, Value>,
) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    for capability_id in capability_ids {
        let row = capabilities
            .get(capability_id)
            .ok_or_else(|| format!("unknown mapped capability {capability_id}"))?;
        ids.extend([
            format!("{capability_id}::input"),
            format!("{capability_id}::output"),
            format!("{capability_id}::error"),
            format!("{capability_id}::resource"),
        ]);
        ids.extend(
            strings(row, "security_invariants")
                .into_iter()
                .enumerate()
                .map(|(index, _)| format!("{capability_id}::security::{:02}", index + 1)),
        );
        ids.extend(
            strings(row, "cancellation_invariants")
                .into_iter()
                .enumerate()
                .map(|(index, _)| format!("{capability_id}::cancellation::{:02}", index + 1)),
        );
    }
    Ok(ids)
}

fn feature_requirements(
    capability_ids: &BTreeSet<String>,
    capabilities: &BTreeMap<String, Value>,
) -> Vec<String> {
    let mut features = BTreeSet::new();
    for capability_id in capability_ids {
        if let Some(row) = capabilities.get(capability_id) {
            features.extend(strings(row, "features"));
        }
    }
    features.into_iter().collect()
}

fn target_requirements(
    capability_ids: &BTreeSet<String>,
    capabilities: &BTreeMap<String, Value>,
) -> Vec<String> {
    let mut targets = BTreeSet::new();
    for capability_id in capability_ids {
        if let Some(row) = capabilities.get(capability_id) {
            targets.extend(strings(row, "platforms"));
        }
    }
    targets.into_iter().collect()
}

fn local_test_file(
    bead_role: &str,
    capability_ids: &BTreeSet<String>,
    capabilities: &BTreeMap<String, Value>,
) -> String {
    if bead_role != "implementation" {
        return CONTRACT_PATH.to_owned();
    }
    for capability_id in capability_ids {
        if let Some(row) = capabilities.get(capability_id) {
            for owner in strings(row, "source_owners") {
                if std::path::Path::new(&owner)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
                    && (owner.starts_with("src/")
                        || owner.starts_with("asupersync-")
                        || owner.starts_with("franken"))
                {
                    return owner;
                }
            }
        }
    }
    CONTRACT_PATH.to_owned()
}

fn target_slug(bead_id: &str) -> String {
    let digest = Sha256::digest(bead_id.as_bytes());
    let suffix = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}_{}",
        slug(bead_id).chars().take(42).collect::<String>(),
        suffix
    )
}

fn focused_command(bead_slug: &str, test_name: &str) -> String {
    format!(
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 \
         CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
         CARGO_TARGET_DIR=\"${{RCH_TARGET_BASE:-${{TMPDIR:-/tmp}}}}/\
         rch_target_ver_a1_{bead_slug}\" cargo test -p asupersync \
         --all-targets --features test-internals {test_name} -- --nocapture"
    )
}

struct EvidenceContext<'a> {
    bead_id: &'a str,
    bead_slug: &'a str,
    role: &'a str,
    test_file: &'a str,
    risks: &'a BTreeSet<String>,
    required_cases: &'a [String],
    feature_requirements: &'a [String],
}

fn plan(
    context: &EvidenceContext<'_>,
    class: &str,
    test_file: String,
    stable_test_names: Vec<String>,
    covers: Vec<String>,
    seed_or_fixture_id: String,
    command: String,
    extra: Option<Value>,
) -> Value {
    let evidence_id = format!("{}::{class}", context.bead_id);
    let artifact_leaf = slug(&evidence_id);
    let mut value = json!({
        "evidence_id": evidence_id,
        "class": class,
        "test_file": test_file,
        "stable_test_names": stable_test_names,
        "feature_requirements": context.feature_requirements,
        "seed_or_fixture_id": seed_or_fixture_id,
        "command": command,
        "artifact_root": format!(
            "target/test-artifacts/dependency-sovereignty/{}/{}",
            context.bead_slug, artifact_leaf
        ),
        "expected_outcome": "pass",
        "evidence_owner": context.bead_id,
        "plan_state": "PLANNED_BLOCKING",
        "covers_case_classes": covers,
    });
    if let Some(extra) = extra {
        value
            .as_object_mut()
            .expect("plan must be an object")
            .insert("class_contract".to_owned(), extra);
    }
    value
}

fn evidence_plans(context: &EvidenceContext<'_>) -> Vec<Value> {
    let local_kind = if context.role == "implementation" {
        "unit"
    } else {
        "contract"
    };
    let local_name = format!("ver_a1_{}__local_invariants", context.bead_slug);
    let mut plans = vec![plan(
        context,
        local_kind,
        context.test_file.to_owned(),
        vec![local_name.clone()],
        context.required_cases.to_vec(),
        format!("fixture:{}:local", context.bead_id),
        focused_command(context.bead_slug, &local_name),
        None,
    )];

    if context.risks.contains("property") {
        let name = format!("ver_a1_{}__property_matrix", context.bead_slug);
        plans.push(plan(
            context,
            "property",
            context.test_file.to_owned(),
            vec![name.clone()],
            context.required_cases.to_vec(),
            format!("fixed-seeds:{}:0..64", context.bead_id),
            focused_command(context.bead_slug, &name),
            Some(json!({
                "seed_start_inclusive": 0,
                "seed_end_exclusive": 64,
                "deterministic_entropy": true,
                "minimized_failure_retention": "required",
            })),
        ));
    }

    if context.risks.contains("concurrency") {
        let name = format!("ver_a1_{}__lab_lifecycle", context.bead_slug);
        plans.push(plan(
            context,
            "lab",
            context.test_file.to_owned(),
            vec![name.clone()],
            CONCURRENCY_CASES
                .iter()
                .map(|case| (*case).to_owned())
                .collect(),
            format!("lab-seeds:{}:0..16", context.bead_id),
            focused_command(context.bead_slug, &name),
            Some(json!({
                "seed_start_inclusive": 0,
                "seed_end_exclusive": 16,
                "required_oracles": [
                    "task_leak",
                    "obligation_leak",
                    "loser_drain",
                    "cancellation_protocol",
                    "quiescence"
                ],
                "virtual_time": true,
            })),
        ));
    }

    if context.risks.contains("fuzz") {
        let target = format!("dependency_{}", context.bead_slug);
        let command = format!(
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 \
             CARGO_TARGET_DIR=\"${{RCH_TARGET_BASE:-${{TMPDIR:-/tmp}}}}/\
             rch_target_ver_a1_fuzz_{}\" cargo fuzz run {target} -- \
             -max_total_time=60 -max_len=1048576",
            context.bead_slug
        );
        let mut fuzz_cases = vec![
            "malformed_error".to_owned(),
            "resource_bound".to_owned(),
            "regression".to_owned(),
        ];
        if context.risks.contains("security") {
            fuzz_cases.push("security_misuse".to_owned());
            fuzz_cases.push("authentication_failure".to_owned());
        }
        plans.push(plan(
            context,
            "fuzz",
            format!("fuzz/fuzz_targets/{target}.rs"),
            vec![target.clone()],
            fuzz_cases,
            format!("fuzz/corpus/{target}"),
            command,
            Some(json!({
                "max_total_time_seconds": 60,
                "max_input_bytes": 1_048_576,
                "corpus_owner": context.bead_id,
                "corpus_path": format!("fuzz/corpus/{target}"),
                "crash_artifact_path": format!("fuzz/artifacts/{target}"),
                "crash_minimization_command": format!(
                    "cargo fuzz tmin {target} <crash-artifact>"
                ),
                "oracle_retirement_independent": true,
                "oracle_evidence_may_authorize_cutover": false,
            })),
        ));
    }

    if context.risks.contains("public_generic") {
        let name = format!("ver_a1_{}__downstream_consumer", context.bead_slug);
        let command = format!(
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 \
             CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
             CARGO_TARGET_DIR=\"${{RCH_TARGET_BASE:-${{TMPDIR:-/tmp}}}}/\
             rch_target_ver_a1_downstream_{}\" cargo test \
             --manifest-path tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml \
             --locked -- --nocapture",
            context.bead_slug
        );
        plans.push(plan(
            context,
            "downstream",
            "tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs".to_owned(),
            vec![name],
            PUBLIC_CASES.iter().map(|case| (*case).to_owned()).collect(),
            "tests/fixtures/dependency-capability-baseline-consumer".to_owned(),
            command,
            Some(json!({
                "compile_fixture_required": true,
                "runtime_fixture_required": true,
                "public_only": true,
                "test_internals_forbidden": true,
            })),
        ));
    }

    if context.risks.contains("user_journey") {
        let scenario = format!("dep-sovereignty-{}", context.bead_slug);
        plans.push(plan(
            context,
            "e2e",
            "scripts/run_all_e2e.sh".to_owned(),
            vec![scenario.clone()],
            vec!["happy_path".to_owned(), "regression".to_owned()],
            format!("scenario:{scenario}"),
            "scripts/run_all_e2e.sh --suite dependency-sovereignty".to_owned(),
            Some(json!({
                "no_mock": true,
                "aggregate_owner": "asupersync-dep-p1-foundations-upksjk.6.2",
                "scenario_id": scenario,
                "required_artifacts": [
                    "target/e2e-results/dependency-sovereignty/<run_id>/summary.json",
                    "target/e2e-results/dependency-sovereignty/<run_id>/events.ndjson",
                    "target/e2e-results/dependency-sovereignty/<run_id>/<scenario_id>/<step_id>.stdout.log",
                    "target/e2e-results/dependency-sovereignty/<run_id>/<scenario_id>/<step_id>.stderr.log"
                ],
            })),
        ));
    }
    plans
}

fn tracker_projection(issues: &[Value]) -> Value {
    Value::Array(
        issues
            .iter()
            .filter(|issue| has_label(issue, "dep-plan"))
            .map(|issue| {
                let mut dependencies = issue
                    .get("dependencies")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|dependency| {
                        json!({
                            "depends_on_id": dependency.get("depends_on_id"),
                            "type": dependency.get("type"),
                        })
                    })
                    .collect::<Vec<_>>();
                dependencies.sort_by_key(|entry| entry.to_string());
                json!({
                    "id": issue.get("id"),
                    "title": issue.get("title"),
                    "description": issue.get("description"),
                    "acceptance_criteria": issue.get("acceptance_criteria"),
                    "issue_type": issue.get("issue_type"),
                    "labels": strings(issue, "labels"),
                    "dependencies": dependencies,
                    "authority_capabilities": authority_capabilities(issue),
                    "superseded_duplicate": is_superseded_duplicate(issue),
                })
            })
            .collect(),
    )
}

fn fingerprint(value: &Value) -> Result<String, String> {
    let encoded =
        serde_json::to_vec(value).map_err(|error| format!("fingerprint encode failed: {error}"))?;
    Ok(Sha256::digest(encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn build_artifact() -> Result<Value, String> {
    let registry = parse_json(REGISTRY_PATH)?;
    let capabilities = capability_rows(&registry)?;
    let issues = parse_tracker()?;
    let projection = tracker_projection(&issues);
    let registry_fingerprint = fingerprint(&registry)?;
    let tracker_fingerprint = fingerprint(&projection)?;

    let mut matrix = Vec::new();
    let mut role_counts = BTreeMap::<String, usize>::new();
    let mut risk_counts = BTreeMap::<String, usize>::new();
    let mut evidence_counts = BTreeMap::<String, usize>::new();
    let mut capability_counts = BTreeMap::<String, usize>::new();

    for issue in issues.iter().filter(|issue| is_matrix_bead(issue)) {
        let bead_id = string(issue, "id")?;
        let title = string(issue, "title")?;
        let text = issue_text(issue);
        let bead_role = role(issue, &text);
        let capability_ids = mapped_capabilities(issue, &registry)?;
        if capability_ids.is_empty() {
            return Err(format!("{bead_id} has no capability mapping"));
        }
        for capability_id in &capability_ids {
            if !capabilities.contains_key(capability_id) {
                return Err(format!("{bead_id} maps unknown capability {capability_id}"));
            }
            *capability_counts.entry(capability_id.clone()).or_default() += 1;
        }
        let bead_risks = risks(issue, &text, &capability_ids);
        let cases = required_cases(&bead_risks);
        let feature_requirements = feature_requirements(&capability_ids, &capabilities);
        let targets = target_requirements(&capability_ids, &capabilities);
        let test_file = local_test_file(bead_role, &capability_ids, &capabilities);
        let bead_slug = target_slug(bead_id);
        let context = EvidenceContext {
            bead_id,
            bead_slug: &bead_slug,
            role: bead_role,
            test_file: &test_file,
            risks: &bead_risks,
            required_cases: &cases,
            feature_requirements: &feature_requirements,
        };
        let plans = evidence_plans(&context);

        *role_counts.entry(bead_role.to_owned()).or_default() += 1;
        for risk in &bead_risks {
            *risk_counts.entry(risk.clone()).or_default() += 1;
        }
        for evidence in &plans {
            if let Some(class) = evidence.get("class").and_then(Value::as_str) {
                *evidence_counts.entry(class.to_owned()).or_default() += 1;
            }
        }

        matrix.push(json!({
            "bead_id": bead_id,
            "title": title,
            "issue_type": issue.get("issue_type").cloned().unwrap_or(Value::Null),
            "role": bead_role,
            "capability_ids": capability_ids,
            "invariant_ids": invariant_ids(&capability_ids, &capabilities)?,
            "risk_tags": bead_risks,
            "feature_requirements": feature_requirements,
            "target_requirements": targets,
            "required_case_classes": cases,
            "evidence_plans": plans,
            "cutover_state": "BLOCKED_PENDING_EVIDENCE",
            "no_claim_boundary": "This is a checked future evidence plan. PLANNED_BLOCKING rows are not behavioral proof, do not satisfy a cutover gate, and do not authorize dependency, feature, API, format, protocol, platform, diagnostic, or user-journey removal.",
        }));
    }
    matrix.sort_by_key(|row| {
        row.get("bead_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    });

    let matrix_bead_count = matrix.len();
    let invariant_count = capability_invariants(&capabilities)
        .iter()
        .map(|row| {
            row.get("invariants")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum::<usize>();
    let evidence_plan_count = evidence_counts.values().sum::<usize>();

    Ok(json!({
        "schema_version": 1,
        "artifact_id": "dependency-verification-matrix-v1",
        "program_id": PROGRAM_ID,
        "bead_id": BEAD_ID,
        "purpose": "Fail-closed invariant-to-unit/property/lab/fuzz/downstream/E2E evidence plan for every executable non-epic dependency-sovereignty bead.",
        "inputs": {
            "tracker_path": TRACKER_PATH,
            "tracker_plan_sha256": tracker_fingerprint,
            "capability_registry_path": REGISTRY_PATH,
            "capability_registry_sha256": registry_fingerprint,
        },
        "policy": {
            "coverage_scope": "Every dep-plan issue whose issue_type is not epic, excluding only closed tracker duplicates explicitly superseded by a canonical successor. This intentionally includes implementation, architecture, verification, and decision leaves so no executable bead can bypass evidence planning.",
            "plan_state": "Every generated evidence row is PLANNED_BLOCKING until its owning implementation bead replaces it with retained terminal evidence.",
            "local_test_rule": "Implementation leaves name an exact current source owner and stable focused test filter. Architecture, verification, and decision leaves name this matrix contract as their local structural gate.",
            "case_rule": "All leaves require happy, empty/boundary, maximum/overflow, malformed/error, resource and regression cases. Risk tags add parser, concurrency, security and public/downstream cases.",
            "fuzz_rule": "Parser/codec and security risks require bounded fuzz plans with explicit corpus ownership, input/time bounds, crash artifacts, minimization, and oracle-retirement independence.",
            "generic_rule": "Public or generic surfaces require both a public-only downstream compile fixture and a runtime fixture without test-internals.",
            "e2e_rule": "User-visible, service, wire, persisted-format and operational surfaces name a stable no-mock dependency-sovereignty scenario owned by VER A2.",
            "cutover_rule": "PLANNED_BLOCKING is never SAME/BETTER evidence. Any missing, stale, blocked, unsupported or failing row preserves the incumbent and blocks cutover.",
        },
        "case_class_catalog": {
            "base": BASE_CASES,
            "parser_codec": PARSER_CASES,
            "concurrency": CONCURRENCY_CASES,
            "security": SECURITY_CASES,
            "public_generic": PUBLIC_CASES,
        },
        "capability_invariants": capability_invariants(&capabilities),
        "matrix": matrix,
        "counts": {
            "capabilities": capabilities.len(),
            "capability_invariants": invariant_count,
            "matrix_beads": matrix_bead_count,
            "evidence_plans": evidence_plan_count,
            "roles": role_counts,
            "risks": risk_counts,
            "evidence_classes": evidence_counts,
            "capability_bead_mappings": capability_counts,
        },
        "validation": {
            "generator": "src/bin/dependency_verification_matrix.rs",
            "contract_test": CONTRACT_PATH,
            "human_summary": DOC_PATH,
            "focused_proof_command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=\"${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_verification_matrix\" cargo test -p asupersync --test dependency_verification_matrix_contract -- --nocapture",
            "generator_check_command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=\"${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_verification_matrix\" cargo run -p asupersync --bin dependency_verification_matrix -- --check",
            "negative_fixtures": [
                "missing happy-path coverage",
                "missing edge/maximum coverage",
                "missing malformed/error coverage",
                "missing resource-bound coverage",
                "missing cancellation/leak/quiescence coverage for concurrent rows",
                "missing security/misuse/redaction coverage for security rows",
                "missing regression coverage",
                "public/generic row missing downstream compile or runtime fixture",
                "fuzz row missing bounds, corpus owner, crash minimization or oracle-retirement independence",
                "unknown capability or invariant reference",
                "duplicate or missing executable bead",
                "planned evidence falsely promoted to proof or cutover authority"
            ],
            "no_claim_boundary": "This contract proves deterministic plan coverage and fail-closed schema behavior only. It does not execute the planned behavior tests, prove runtime correctness, service interoperability, performance, broad workspace health, release readiness, RCH fleet availability, or authorize any cutover or deletion."
        }
    }))
}

fn render_artifact() -> Result<String, String> {
    let artifact = build_artifact()?;
    let mut rendered = serde_json::to_string_pretty(&artifact)
        .map_err(|error| format!("artifact encode failed: {error}"))?;
    rendered.push('\n');
    Ok(rendered)
}

fn first_difference(expected: &str, actual: &str) -> String {
    for (index, (left, right)) in expected.lines().zip(actual.lines()).enumerate() {
        if left != right {
            return format!(
                "first difference at line {}:\nexpected: {left}\nactual:   {right}",
                index + 1
            );
        }
    }
    let mut message = String::new();
    let _ = write!(
        message,
        "line counts differ: expected {}, actual {}",
        expected.lines().count(),
        actual.lines().count()
    );
    message
}

fn check_artifact(rendered: &str) -> Result<(), String> {
    let actual = read_repo_file(ARTIFACT_PATH)?;
    if actual == rendered {
        Ok(())
    } else {
        Err(format!(
            "{ARTIFACT_PATH} is stale; regenerate from checked inputs\n{}",
            first_difference(rendered, &actual)
        ))
    }
}

fn write_artifact(rendered: &str, path: &Path) -> Result<(), String> {
    std::fs::write(path, rendered)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let rendered = render_artifact()?;
    match arguments.as_slice() {
        [] => {
            print!("{rendered}");
            Ok(())
        }
        [mode] if mode == "--render" => {
            print!("{rendered}");
            Ok(())
        }
        [mode] if mode == "--check" => check_artifact(&rendered),
        [mode, path] if mode == "--write" => write_artifact(&rendered, Path::new(path)),
        _ => Err(
            "usage: dependency_verification_matrix [--render|--check|--write <path>]".to_owned(),
        ),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("dependency_verification_matrix: {error}");
        std::process::exit(1);
    }
}
