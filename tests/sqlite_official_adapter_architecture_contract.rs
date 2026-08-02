//! Fail-closed contract for the provisional SQLite official-adapter architecture.
//!
//! Bead: asupersync-ym2wtv.3.1
//! Governing ADR: DEP-ADR-010
//! Artifact: artifacts/sqlite_official_adapter_architecture_v1.json
//!
//! This contract deliberately proves only the packet's internal consistency,
//! the preferred package direction, the explicitly incomplete graph matrix, and the
//! absence of a reverse edge in Asupersync's checked manifest and lockfile. It
//! is not adapter compilation, runtime, parity, publication, or owner evidence.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/sqlite_official_adapter_architecture_v1.json";
const DOC_PATH: &str = "docs/adr/sqlite_official_adapter_architecture.md";
const BEAD_ID: &str = "asupersync-ym2wtv.3.1";
const DECISION: &str = "KEEP_PENDING_CURRENT_GRAPH_AND_OWNER_CONTRACT";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("{ARTIFACT_PATH} must be valid JSON: {error}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .filter(|entry| entry.is_object())
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn strings<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    array(value, key)
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key}[{index}] must be a string"))
        })
        .collect()
}

fn string_set<'a>(value: &'a Value, key: &str) -> BTreeSet<&'a str> {
    let values = strings(value, key);
    let set: BTreeSet<&str> = values.iter().copied().collect();
    assert_eq!(
        values.len(),
        set.len(),
        "{key} must not contain duplicate entries"
    );
    set
}

fn is_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn coordinate<'a>(contract: &'a Value, coordinate_id: &str) -> &'a Value {
    array(contract, "coordinates")
        .iter()
        .find(|row| text(row, "coordinate_id") == coordinate_id)
        .unwrap_or_else(|| panic!("missing coordinate {coordinate_id}"))
}

struct ExpectedCoordinate<'a> {
    id: &'a str,
    root: &'a str,
    profile: &'a str,
    features: &'a str,
    host: &'a str,
    target: &'a str,
    dependency_kinds: &'a [&'a str],
    receipt_state: &'a str,
}

#[test]
fn packet_identity_and_decision_fail_closed() {
    let artifact = artifact();
    assert_eq!(
        text(&artifact, "artifact_id"),
        "sqlite-official-adapter-architecture-v1"
    );
    assert_eq!(artifact["schema_version"], 1);
    assert_eq!(text(&artifact, "bead_id"), BEAD_ID);
    assert_eq!(text(&artifact, "governing_adr"), "DEP-ADR-010");
    assert_eq!(text(&artifact, "doc_path"), DOC_PATH);

    let decision = object(&artifact, "architecture_decision");
    assert_eq!(text(decision, "state"), DECISION);
    assert_eq!(text(decision, "incumbent_state"), "ACCEPTED_AND_SUPPORTED");
    assert_eq!(
        text(decision, "candidate_state"),
        "PROVISIONAL_PREFERENCE_NOT_IMPLEMENTATION_AUTHORIZED"
    );
    assert_eq!(
        decision
            .get("implementation_allowed")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        decision.get("close_bead_allowed").and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        text(decision, "reason").contains("asupersync[sqlite]"),
        "the pending decision must name the incumbent it keeps"
    );
}

#[test]
fn preferred_candidate_reuses_the_existing_downstream_facade_without_hiding_blockers() {
    let artifact = artifact();
    let candidate = object(&artifact, "preferred_candidate");

    assert_eq!(text(candidate, "repository_id"), "frankensqlite");
    assert_eq!(text(candidate, "package"), "fsqlite");
    assert_eq!(text(candidate, "package_kind"), "EXISTING_PUBLIC_FACADE");
    assert_eq!(
        text(candidate, "new_package_disposition"),
        "UNKNOWN_PENDING_COMPANION_GRAPH_AND_OWNER_COMPARISON"
    );
    assert_eq!(text(candidate, "public_namespace"), "fsqlite::async_api");
    assert_eq!(text(candidate, "root_reexport"), "fsqlite::AsyncConnection");
    assert_eq!(text(candidate, "feature"), "async-api");
    assert_eq!(
        text(candidate, "feature_forwarding_state"),
        "BLOCKED_BY_CURRENT_NATIVE_URING_COUPLING"
    );

    let current = string_set(candidate, "current_feature_forwarding");
    assert_eq!(
        current,
        BTreeSet::from(["dep:asupersync", "dep:futures-lite", "fsqlite-types/native"])
    );
    let required = string_set(candidate, "required_feature_forwarding");
    assert_eq!(
        required,
        BTreeSet::from(["dep:asupersync", "dep:futures-lite", "native"])
    );
    assert!(
        text(candidate, "required_native_feature_contract").contains("optional"),
        "the preferred native feature contract must separate the Linux io-uring edge"
    );
    assert!(
        text(candidate, "current_linux_native_observation").contains("unconditional"),
        "the current implicit io-uring edge must not be hidden"
    );
    assert!(
        text(candidate, "public_context_requirement").contains("&asupersync::Cx"),
        "the official API must select the native capability context"
    );
    assert!(
        text(candidate, "worker_requirement").contains("I2"),
        "worker lifecycle proof must be assigned rather than implied"
    );

    let companion = array(&artifact, "alternatives")
        .iter()
        .find(|row| text(row, "alternative") == "create a new fsqlite-asupersync package")
        .expect("companion-package alternative");
    assert_eq!(
        text(companion, "disposition"),
        "DEFER_PENDING_OWNER_AND_GRAPH_COMPARISON"
    );
}

#[test]
fn proposed_dag_includes_the_structural_core_edge_and_never_points_back() {
    let artifact = artifact();
    let dag = object(&artifact, "proposed_dependency_dag");

    let production_edges = array(dag, "production_edges");
    let exact_edges: BTreeSet<(&str, &str)> = production_edges
        .iter()
        .map(|edge| (text(edge, "from"), text(edge, "to")))
        .collect();
    assert_eq!(
        exact_edges.len(),
        production_edges.len(),
        "production dependency edges must be unique"
    );
    assert_eq!(
        exact_edges,
        BTreeSet::from([
            ("supported-user", "asupersync@0.3.10"),
            ("supported-user", "fsqlite@0.1.19"),
            ("fsqlite@0.1.19[async-api]", "asupersync@^0.3.10"),
            ("fsqlite@0.1.19", "fsqlite-core@0.1.19"),
            ("fsqlite-core@0.1.19", "asupersync@^0.3.10"),
            (
                "asupersync@0.3.10[sqlite]",
                "rusqlite@0.40 and sqlparser@0.62",
            ),
        ]),
        "the provisional production DAG must stay exact"
    );
    assert!(
        production_edges.iter().any(|edge| {
            text(edge, "from").starts_with("fsqlite@")
                && text(edge, "to").starts_with("asupersync@")
        }),
        "the selected downstream adapter edge must point to Asupersync"
    );
    assert!(
        production_edges.iter().any(|edge| {
            text(edge, "from") == "fsqlite@0.1.19"
                && text(edge, "to") == "fsqlite-core@0.1.19"
                && text(edge, "configuration").contains("unconditional")
        }),
        "the facade-to-core structural edge must be explicit"
    );
    assert!(
        production_edges.iter().any(|edge| {
            text(edge, "from") == "fsqlite-core@0.1.19"
                && text(edge, "to") == "asupersync@^0.3.10"
                && text(edge, "configuration").contains("disabling async-api is not")
        }),
        "the core-to-Asupersync edge must prove that async-api is not a cycle escape"
    );
    assert!(
        production_edges.iter().all(|edge| {
            let from_asupersync = text(edge, "from").starts_with("asupersync@");
            let destination = text(edge, "to").to_ascii_lowercase();
            !(from_asupersync
                && (destination.contains("fsqlite") || destination.contains("frankensqlite")))
        }),
        "a production Asupersync-to-FrankenSQLite edge would close the cycle"
    );

    let forbidden = array(dag, "forbidden_edges");
    let reverse = forbidden
        .iter()
        .find(|edge| text(edge, "from") == "asupersync")
        .expect("the reverse edge must be explicitly forbidden");
    assert_eq!(text(reverse, "to"), "fsqlite-or-any-frankensqlite-package");
    let edge_kinds = string_set(reverse, "edge_kinds");
    assert_eq!(edge_kinds, BTreeSet::from(["build", "dev", "normal"]));

    let invariants = strings(dag, "package_identity_invariants");
    assert!(
        invariants
            .iter()
            .any(|entry| entry.contains("exactly one asupersync package ID"))
    );
    assert!(
        invariants
            .iter()
            .any(|entry| entry.contains("zero fsqlite or FrankenSQLite package IDs"))
    );
    assert!(
        invariants
            .iter()
            .any(|entry| entry.contains("disabling async-api does not remove"))
    );
}

#[test]
fn asupersync_manifest_and_lockfile_have_no_reverse_edge() {
    for path in ["Cargo.toml", "Cargo.lock"] {
        let contents = read_repo_file(path).to_lowercase();
        for forbidden in ["frankensqlite", "fsqlite"] {
            assert!(
                !contents.contains(forbidden),
                "{path} contains {forbidden}, violating the accepted dependency direction"
            );
        }
    }
}

#[test]
fn observed_pins_are_explicit_and_asupersync_pins_match_the_tree() {
    let artifact = artifact();
    let repositories = array(&artifact, "observed_repositories");
    assert_eq!(repositories.len(), 2);

    let asupersync = repositories
        .iter()
        .find(|row| text(row, "repository_id") == "asupersync")
        .expect("Asupersync observation");
    assert_eq!(text(asupersync, "package_version"), "0.3.10");
    assert_eq!(text(asupersync, "toolchain"), "nightly-2026-07-05");
    assert_eq!(
        text(asupersync, "observed_revision"),
        "77f5a4221886fffc32ce6049bb853e3af617fa9b"
    );
    assert!(is_lower_hex_sha(text(asupersync, "observed_revision")));

    let manifest = read_repo_file("Cargo.toml");
    assert!(manifest.contains("name = \"asupersync\""));
    assert!(manifest.contains("version = \"0.3.10\""));
    let toolchain = read_repo_file("rust-toolchain.toml");
    assert!(toolchain.contains("channel = \"nightly-2026-07-05\""));

    let fsqlite = repositories
        .iter()
        .find(|row| text(row, "repository_id") == "frankensqlite")
        .expect("FrankenSQLite observation");
    assert_eq!(text(fsqlite, "package_version"), "0.1.19");
    assert_eq!(
        text(fsqlite, "observed_revision"),
        "43463019323f77dbf178b9557daa0085a4ac54a3"
    );
    assert!(is_lower_hex_sha(text(fsqlite, "observed_revision")));
    assert_eq!(
        text(fsqlite, "reproducibility_state"),
        "OBSERVED_DIRTY_WORKTREE_NOT_ACCEPTANCE_EVIDENCE"
    );
}

#[test]
fn graph_matrix_is_explicitly_incomplete_and_every_proposed_coordinate_is_exact() {
    let artifact = artifact();
    let contract = object(&artifact, "graph_evidence_contract");
    assert_eq!(
        text(contract, "matrix_state"),
        "INCOMPLETE_PENDING_OWNER_TARGET_AND_VERSION_ALLOWSETS"
    );
    let required = string_set(contract, "required_dependency_kinds");
    assert_eq!(required, BTreeSet::from(["build", "dev", "normal"]));
    let classifications = string_set(contract, "required_package_classifications");
    assert_eq!(
        classifications,
        BTreeSet::from(["build-script", "native-code", "proc-macro", "tokio"])
    );
    assert!(
        text(contract, "proc_macro_method").contains("cargo metadata"),
        "proc-macro classification must use metadata target kinds"
    );
    assert_eq!(
        text(contract, "target_allowset_state"),
        "PROPOSED_NOT_OWNER_ACCEPTED"
    );
    assert_eq!(
        string_set(contract, "proposed_target_allowset"),
        BTreeSet::from([
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
        ])
    );
    assert_eq!(
        strings(contract, "explicitly_unsupported_targets"),
        vec!["wasm32-unknown-unknown for the dedicated-thread adapter"]
    );

    let coordinates = array(contract, "coordinates");
    let expected = [
        ExpectedCoordinate {
            id: "ASUP-DEFAULT-LINUX",
            root: "asupersync",
            profile: "default production",
            features: "default",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "build"],
            receipt_state: "MISSING_CURRENT_RECEIPT",
        },
        ExpectedCoordinate {
            id: "ASUP-SQLITE-LINUX",
            root: "asupersync",
            profile: "incumbent sqlite production",
            features: "no-default-features + sqlite",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "build"],
            receipt_state: "MISSING_CURRENT_RECEIPT",
        },
        ExpectedCoordinate {
            id: "ASUP-SQLITE-DEV-LINUX",
            root: "asupersync",
            profile: "incumbent sqlite package tests",
            features: "no-default-features + sqlite",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "dev", "build"],
            receipt_state: "MISSING_CURRENT_RECEIPT",
        },
        ExpectedCoordinate {
            id: "FSQLITE-DEFAULT-LINUX",
            root: "fsqlite",
            profile: "FrankenSQLite public facade baseline",
            features: "default",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "build"],
            receipt_state: "MISSING_CURRENT_RECEIPT",
        },
        ExpectedCoordinate {
            id: "FSQLITE-WORKSPACE-DEV-LINUX",
            root: "frankensqlite-workspace",
            profile: "FrankenSQLite workspace dev baseline",
            features: "workspace default package profiles",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "dev", "build"],
            receipt_state: "MISSING_CURRENT_RECEIPT",
        },
        ExpectedCoordinate {
            id: "FSQLITE-ASYNC-LINUX",
            root: "fsqlite",
            profile: "preferred adapter production",
            features: "no-default-features + async-api after native/io-uring feature split",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "build"],
            receipt_state: "BLOCKED_BY_CURRENT_NATIVE_URING_COUPLING",
        },
        ExpectedCoordinate {
            id: "FSQLITE-ASYNC-DEV-LINUX",
            root: "fsqlite",
            profile: "preferred adapter package tests",
            features: "no-default-features + async-api after native/io-uring feature split",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "dev", "build"],
            receipt_state: "BLOCKED_BY_CURRENT_NATIVE_URING_COUPLING",
        },
        ExpectedCoordinate {
            id: "FSQLITE-ASYNC-STABLE-X86_64",
            root: "fsqlite",
            profile: "preferred adapter stable/MSRV negative coordinate",
            features: "no-default-features + async-api",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "build"],
            receipt_state: "KNOWN_UNSUPPORTED_AT_CURRENT_REVISION_CORE_INTRINSICS",
        },
        ExpectedCoordinate {
            id: "USER-COEXIST-LINUX",
            root: "neutral-parity-consumer",
            profile: "incumbent and candidate coexistence",
            features: "asupersync no-default-features + sqlite; fsqlite no-default-features + async-api",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "dev", "build"],
            receipt_state: "BLOCKED_BY_CURRENT_NATIVE_URING_COUPLING",
        },
        ExpectedCoordinate {
            id: "USER-LOWEST-SUPPORTED-LINUX",
            root: "neutral-parity-consumer",
            profile: "lowest proposed compatible release pair",
            features: "asupersync no-default-features + sqlite; fsqlite no-default-features + async-api",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "dev", "build"],
            receipt_state: "BLOCKED_BY_UNPUBLISHED_VERSION_INTERVAL",
        },
        ExpectedCoordinate {
            id: "USER-HIGHEST-SUPPORTED-LINUX",
            root: "neutral-parity-consumer",
            profile: "highest proposed compatible release pair",
            features: "asupersync no-default-features + sqlite; fsqlite no-default-features + async-api",
            host: "x86_64-unknown-linux-gnu",
            target: "x86_64-unknown-linux-gnu",
            dependency_kinds: &["normal", "dev", "build"],
            receipt_state: "BLOCKED_BY_UNPUBLISHED_VERSION_INTERVAL",
        },
        ExpectedCoordinate {
            id: "USER-ADAPTER-MACOS",
            root: "neutral-parity-consumer",
            profile: "preferred adapter native-host resolution",
            features: "fsqlite no-default-features + async-api",
            host: "aarch64-apple-darwin",
            target: "aarch64-apple-darwin",
            dependency_kinds: &["normal", "build"],
            receipt_state: "MISSING_CURRENT_RECEIPT",
        },
        ExpectedCoordinate {
            id: "USER-ADAPTER-WINDOWS",
            root: "neutral-parity-consumer",
            profile: "preferred adapter native-host resolution",
            features: "fsqlite no-default-features + async-api",
            host: "x86_64-pc-windows-msvc",
            target: "x86_64-pc-windows-msvc",
            dependency_kinds: &["normal", "build"],
            receipt_state: "MISSING_CURRENT_RECEIPT",
        },
        ExpectedCoordinate {
            id: "USER-ADAPTER-WASM",
            root: "neutral-parity-consumer",
            profile: "preferred adapter unsupported-target disposition",
            features: "fsqlite no-default-features + async-api",
            host: "x86_64-unknown-linux-gnu",
            target: "wasm32-unknown-unknown",
            dependency_kinds: &["normal", "build"],
            receipt_state: "UNSUPPORTED_DEDICATED_THREAD_ADAPTER",
        },
    ];
    assert_eq!(coordinates.len(), expected.len());
    let ids: BTreeSet<&str> = coordinates
        .iter()
        .map(|row| text(row, "coordinate_id"))
        .collect();
    assert_eq!(
        ids.len(),
        coordinates.len(),
        "coordinate ids must be unique"
    );

    let expected_classifications =
        BTreeSet::from(["build-script", "native-code", "proc-macro", "tokio"]);
    for expected_row in &expected {
        let row = coordinate(contract, expected_row.id);
        assert_eq!(text(row, "root"), expected_row.root);
        assert_eq!(text(row, "profile"), expected_row.profile);
        assert_eq!(text(row, "features"), expected_row.features);
        assert_eq!(text(row, "host"), expected_row.host);
        assert_eq!(text(row, "target"), expected_row.target);
        assert_eq!(text(row, "receipt_state"), expected_row.receipt_state);
        assert_eq!(
            string_set(row, "dependency_kinds"),
            expected_row.dependency_kinds.iter().copied().collect()
        );
        assert_eq!(
            string_set(row, "package_classifications"),
            expected_classifications
        );
    }
    assert_eq!(
        text(
            coordinate(contract, "FSQLITE-ASYNC-STABLE-X86_64"),
            "toolchain"
        ),
        "stable 1.85"
    );

    let invariants = strings(contract, "production_invariants");
    for phrase in [
        "zero fsqlite",
        "exactly one asupersync",
        "zero Tokio",
        "dedicated OS-thread",
        "dev-only",
    ] {
        assert!(
            invariants.iter().any(|entry| entry.contains(phrase)),
            "production invariants must cover {phrase:?}"
        );
    }
}

#[test]
fn ownership_toolchain_and_blockers_are_explicit() {
    let artifact = artifact();

    let ownership = object(&artifact, "ownership_contract");
    assert_eq!(
        text(ownership, "acceptance_state"),
        "MISSING_NAMED_OWNER_APPROVAL"
    );
    let responsibility_owners: BTreeSet<&str> = array(ownership, "responsibilities")
        .iter()
        .map(|row| text(row, "owner"))
        .collect();
    assert_eq!(
        responsibility_owners,
        BTreeSet::from([
            "Asupersync repository maintainers",
            "FrankenSQLite repository maintainers",
            "joint release gate",
        ])
    );
    for row in array(ownership, "responsibilities") {
        assert!(
            text(row, "owns").len() > 80,
            "each responsibility must be substantive"
        );
    }
    let release_order = strings(ownership, "release_order");
    assert_eq!(release_order.len(), 6);
    for (index, phrase) in [
        "freeze immutable packaged",
        "before either publication",
        "publish the validated Asupersync",
        "crates.io resolution",
        "publish the matching validated fsqlite",
        "both releases",
    ]
    .iter()
    .enumerate()
    {
        assert!(
            release_order[index].contains(phrase),
            "release step {index} must contain {phrase:?}"
        );
    }
    assert_eq!(
        text(object(ownership, "support_lifecycle"), "current_state"),
        "NOT_YET_ACCEPTED"
    );

    let versions = object(&artifact, "version_and_toolchain_contract");
    assert_eq!(
        text(versions, "supported_interval"),
        "NOT_YET_PROVED_OR_PUBLISHED"
    );
    assert_eq!(
        text(versions, "stable_floor"),
        "KNOWN_UNSUPPORTED_AT_CURRENT_REVISION_ON_X86_64_AND_WINDOWS"
    );
    assert!(
        text(versions, "candidate_nightly_requirement").contains("core_intrinsics"),
        "known nightly-only source must be recorded"
    );
    assert_eq!(
        text(versions, "toolchain_disposition"),
        "OWNER_DECISION_PENDING_PINNED_NIGHTLY_OR_STABLE_SOURCE_REFACTOR"
    );
    assert!(
        text(versions, "nightly_policy").contains("floating nightly")
            && text(versions, "nightly_policy").contains("nightly-outcome-try"),
        "the policy must reject floating nightly without enabling Asupersync's default nightly feature"
    );

    let blockers = array(&artifact, "blocking_gaps");
    assert_eq!(blockers.len(), 4);
    let blocker_ids: BTreeSet<&str> = blockers.iter().map(|row| text(row, "gap_id")).collect();
    for required in [
        "I1-GRAPH-01",
        "I1-OWNER-01",
        "I1-FEATURE-01",
        "I1-TOOLCHAIN-01",
    ] {
        assert!(blocker_ids.contains(required));
    }
    for blocker in blockers {
        assert_eq!(text(blocker, "state"), "BLOCKED");
        assert!(!text(blocker, "owner").is_empty());
        assert!(!text(blocker, "detail").is_empty());
        assert!(!text(blocker, "unblock").is_empty());
        assert!(
            !text(blocker, "owner").contains(".3.2") && !text(blocker, "owner").contains(".3.4"),
            "I1 must not wait on a bead that it blocks"
        );
    }

    let downstream = array(&artifact, "downstream_implementation_gates");
    assert_eq!(downstream.len(), 3);
    let downstream_ids: BTreeSet<&str> =
        downstream.iter().map(|row| text(row, "gate_id")).collect();
    assert_eq!(
        downstream_ids,
        BTreeSet::from([
            "I2-API-CX",
            "I2-LIFECYCLE-CANCELLATION",
            "I4-PACKAGED-RELEASE",
        ])
    );
    for gate in downstream {
        assert_eq!(
            text(gate, "state"),
            "NOT_AN_I1_CLOSURE_BLOCKER",
            "downstream work must not deadlock I1"
        );
        assert!(!text(gate, "requirement").is_empty());
    }
}

#[test]
fn documentation_and_no_claim_boundary_match_the_packet() {
    let artifact = artifact();
    let doc = read_repo_file(DOC_PATH);
    for marker in [
        BEAD_ID,
        DECISION,
        "fsqlite::async_api",
        "fsqlite-core",
        "BLOCKED_BY_CURRENT_NATIVE_URING_COUPLING",
        "KNOWN_UNSUPPORTED_AT_CURRENT_REVISION_ON_X86_64_AND_WINDOWS",
        "&asupersync::Cx",
        "MISSING_NAMED_OWNER_APPROVAL",
        "USER-ADAPTER-WASM",
        "No-claim boundary",
    ] {
        assert!(doc.contains(marker), "{DOC_PATH} is missing {marker:?}");
    }

    let validation = object(&artifact, "validation");
    assert_eq!(
        text(validation, "contract_test"),
        "tests/sqlite_official_adapter_architecture_contract.rs"
    );
    let boundary = text(validation, "no_claim_boundary");
    for phrase in [
        "does not prove any current FrankenSQLite graph",
        "owner acceptance",
        "authorizes no source implementation",
        "bead closure",
    ] {
        assert!(
            boundary.contains(phrase),
            "no-claim boundary must cover {phrase:?}"
        );
    }
    let closure = strings(&artifact, "closure_conditions");
    assert_eq!(closure.len(), 6);
    for phrase in [
        "structural fsqlite-core edge",
        "owner-accepted I1 graph coordinates",
        "target allowset",
        "pre-publication validation order",
        "publication and operational proof remain I4 work",
        "terminal KEEP before implementation",
    ] {
        assert!(
            closure.iter().any(|entry| entry.contains(phrase)),
            "closure conditions must cover {phrase:?}"
        );
    }
    assert!(
        closure
            .iter()
            .all(|entry| !entry.contains("I2-API") && !entry.contains("I2-LIFECYCLE")),
        "I1 closure must not depend on I2 implementation"
    );
}
