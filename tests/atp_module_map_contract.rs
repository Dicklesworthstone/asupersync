//! Contract tests for the ATP module map and implementation ownership plan.
//!
//! These tests keep `docs/atp_architecture.md` and
//! `docs/atp_contributor_guide.md` aligned with the current ATP source layout.
//! The goal is not to test prose style; the goal is to prevent future ATP work
//! from inventing incompatible module boundaries, skipping owner beads, or
//! landing unproven surfaces.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};

const ARCHITECTURE_DOC: &str = include_str!("../docs/atp_architecture.md");
const CONTRIBUTOR_GUIDE: &str = include_str!("../docs/atp_contributor_guide.md");

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn assert_contains_all(haystack: &str, label: &str, needles: &[&str]) {
    let missing = needles
        .iter()
        .copied()
        .filter(|needle| !haystack.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{label} is missing required ATP module-map markers: {missing:?}"
    );
}

#[test]
fn architecture_doc_declares_the_atp_m4_owner_contract() {
    assert_contains_all(
        ARCHITECTURE_DOC,
        "docs/atp_architecture.md",
        &[
            "ATP-M4 Implementation Ownership Contract",
            "asupersync-w9xymh",
            "Status vocabulary",
            "`committed`",
            "`active`",
            "`planned`",
            "Primary owner rule",
            "Current committed module inventory",
            "Planned module families and write boundaries",
            "Boundary rules for new ATP modules",
            "one exact file reservation set",
            "one focused proof lane",
        ],
    );
}

#[test]
fn committed_inventory_paths_exist_and_are_cross_linked() {
    let committed_paths = [
        "src/atp/mod.rs",
        "src/atp/object.rs",
        "src/atp/manifest.rs",
        "src/atp/path.rs",
        "src/atp/platform/mod.rs",
        "src/atp/doctor/mod.rs",
        "src/atp/verifier.rs",
        "src/net/atp/mod.rs",
        "src/net/atp/path/mod.rs",
        "src/net/atp/protocol/frames.rs",
        "src/net/atp/protocol/codec.rs",
        "src/net/atp/protocol/varint.rs",
        "src/net/atp/protocol/transcript.rs",
        "src/net/atp/protocol/outcome.rs",
        "src/net/atp/protocol/session.rs",
        "src/net/atp/protocol/quic_frames.rs",
        "src/net/atp/protocol/packet_assembly.rs",
        "src/net/atp/protocol/transport_params.rs",
        "src/net/atp/rendezvous/mod.rs",
        "src/net/atp/stun/mod.rs",
        "src/net/quic_native/endpoint.rs",
        "src/net/quic_native/tls.rs",
        "src/net/quic_native/connection.rs",
        "src/net/quic_native/transport.rs",
        "src/net/quic_native/streams.rs",
        "src/net/quic_native/forensic_log.rs",
        "src/bin/asupersync.rs",
    ];

    for path in committed_paths {
        assert!(
            repo_path(path).is_file(),
            "committed ATP path must exist: {path}"
        );
        assert!(
            ARCHITECTURE_DOC.contains(path),
            "architecture doc must reference committed path: {path}"
        );
        assert!(
            CONTRIBUTOR_GUIDE.contains(path),
            "contributor guide must reference committed path: {path}"
        );
    }
}

#[test]
fn planned_boundaries_preserve_the_full_data_movement_layer_scope() {
    assert_contains_all(
        ARCHITECTURE_DOC,
        "planned ATP module families",
        &[
            "Transfer actor and per-transfer ownership",
            "ATP Transfer Brain and scheduler feedback",
            "ACK, loss, PTO, congestion, and anti-amplification",
            "Chunking profiles",
            "Crash-safe disk writer and journal",
            "RaptorQ repair coordinator",
            "Path graph engine and relay adapters",
            "SDK facade",
            "Daemon and identity",
            "CLI and first-run UX",
            "Offline mailbox",
            "Swarm and cache-assisted transfer",
            "Lab, replay, benchmark cartel, and crashpacks",
            "Governance and dependency gates",
        ],
    );

    assert_contains_all(
        CONTRIBUTOR_GUIDE,
        "ATP contributor tracker-to-code map",
        &[
            "Transfer actor and ownership topology",
            "Chunking profiles",
            "ACK/loss/PTO/congestion feedback",
            "RaptorQ repair coordinator",
            "Crash-safe disk and journal",
            "SDK facade",
            "Daemon, identity, peer directory, receive preflight",
            "Mailbox, relay, Tailscale candidate, path doctor",
            "Lab, replay, crashpacks, benchmark cartel",
            "Governance, dependency gates, Definition of Done",
        ],
    );
}

#[test]
fn owner_workstreams_and_proof_lanes_are_testable() {
    assert_contains_all(
        ARCHITECTURE_DOC,
        "ATP owner workstreams",
        &[
            "asupersync-l21xmv",
            "asupersync-e8hst6",
            "asupersync-uh6u63",
            "asupersync-51uf70",
            "asupersync-9yjgrz",
            "asupersync-3ui2zb",
            "asupersync-sbk7th",
            "asupersync-jaghjr",
            "asupersync-xvaftm",
        ],
    );

    assert_contains_all(
        CONTRIBUTOR_GUIDE,
        "ATP focused proof lanes",
        &[
            "tests/atp_module_map_contract.rs",
            "tests/atp_native_quic_endpoint_contract.rs",
            "tests/atp_quic_packet_protection.rs",
            "tests/atp_session_negotiation.rs",
            "scripts/run_atp_manifest_e2e.sh",
            "scripts/run_atp_quic_packet_protection_e2e.sh",
            "scripts/run_atp_session_negotiation_e2e.sh",
            "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_atp_module_map cargo test -p asupersync --test atp_module_map_contract -- --nocapture",
        ],
    );
}

#[test]
fn boundary_rules_keep_atp_native_and_asupersync_shaped() {
    assert_contains_all(
        ARCHITECTURE_DOC,
        "ATP boundary rules",
        &[
            "Public effectful APIs must take `&Cx` first",
            "Long-lived workers belong under supervised daemon/AppSpec topology",
            "Protocol parsing, manifest validation, verification, repair, disk commit",
            "Native QUIC modules may use TLS primitives through the provider boundary",
            "may not import an external QUIC endpoint stack",
            "Planned module names are reservations for architecture coherence",
        ],
    );

    assert_contains_all(
        CONTRIBUTOR_GUIDE,
        "ATP design rules",
        &[
            "Do not create branches or worktrees",
            "Do not add external",
            "QUIC crates or Tokio-runtime dependencies",
            "Public effectful APIs must take `&Cx` first",
            "Preserve cancellation semantics",
            "Verification remains the exposure",
        ],
    );
}
