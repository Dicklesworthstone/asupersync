//! Progressive-disclosure contract checks for the FABRIC messaging surface.
//!
//! These tests intentionally read the checked-in source files instead of
//! constructing the full public API. The FABRIC implementation is still in a
//! scaffold phase, so the contract we can reliably enforce today is that the
//! module docs and delivery-class taxonomy keep the cheap path explicit and
//! keep stronger semantics opt-in.

#![allow(clippy::duplicate_mod)]

use std::path::PathBuf;

/// Test utilities
pub mod util {
    pub use asupersync::util::DetHasher;
}

#[path = "../src/messaging/class.rs"]
mod class;
#[path = "../src/messaging/ir.rs"]
mod ir;
#[path = "../src/messaging/subject.rs"]
mod subject;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    let full_path = repo_root().join(path);
    std::fs::read_to_string(&full_path)
        .unwrap_or_else(|_| panic!("missing {}", full_path.display()))
}

#[test]
fn delivery_class_progression_stays_explicit_and_ordered() {
    let content = read_repo_file("src/messaging/class.rs");
    let classes = [
        "EphemeralInteractive",
        "DurableOrdered",
        "ObligationBacked",
        "MobilitySafe",
        "ForensicReplayable",
    ];

    let mut positions = Vec::new();
    let default_position = content
        .find("#[default]")
        .expect("expected DeliveryClass to mark the default variant explicitly");
    for class_name in classes {
        let position = content.find(class_name).unwrap_or_else(|| {
            panic!("expected DeliveryClass variant `{class_name}` in src/messaging/class.rs")
        });
        positions.push((class_name, position));
    }

    let (_, first_position) = positions[0];
    assert!(
        default_position < first_position,
        "expected #[default] to be attached to the first DeliveryClass variant"
    );

    for pair in positions.windows(2) {
        let (left_name, left_pos) = pair[0];
        let (right_name, right_pos) = pair[1];
        assert!(
            left_pos < right_pos,
            "expected `{left_name}` to appear before `{right_name}` in DeliveryClass, \
             got positions {left_pos} and {right_pos}"
        );
    }
}

#[test]
fn messaging_root_docs_keep_common_case_cheap_and_opt_in() {
    let content = read_repo_file("src/messaging/mod.rs");

    for expected in [
        "The public mental model stays NATS-small",
        "The experimental native brokerless fabric surface is gated behind the",
        "Stronger guarantees are named service classes, not hidden taxes on the",
        "Packet-plane ergonomics stay cheap by default; authority, evidence,",
        "# Progressive Disclosure",
        "Layer 0: connect, publish, and subscribe stay NATS-small",
        "Layer 4: replay-heavy, evidence-rich, and counterfactual tooling stays in",
        "Lower layers must remain correct on their own terms.",
        "The full numbered checklist lives in `docs/FABRIC_GUARDRAILS.md`.",
    ] {
        assert!(
            content.contains(expected),
            "expected src/messaging/mod.rs to contain progressive-disclosure guidance `{expected}`"
        );
    }
}

#[test]
fn messaging_root_keeps_legacy_integrations_visible_alongside_fabric() {
    let content = read_repo_file("src/messaging/mod.rs");
    let cargo_toml = read_repo_file("Cargo.toml");
    let lib_rs = read_repo_file("src/lib.rs");

    assert!(
        cargo_toml.contains("messaging-fabric = []"),
        "expected Cargo.toml to declare the native fabric feature gate"
    );
    assert!(
        cargo_toml.contains("\"messaging-fabric\""),
        "expected Cargo.toml unexpected_cfgs allowlist to recognize messaging-fabric"
    );

    let cfg_position = content
        .find("#[cfg(feature = \"messaging-fabric\")]")
        .expect("expected src/messaging/mod.rs to feature-gate the native fabric export");
    let fabric_position = content
        .find("pub mod fabric;")
        .expect("expected src/messaging/mod.rs to export the native fabric module");
    assert!(
        cfg_position < fabric_position,
        "expected the messaging-fabric cfg gate to appear directly before the fabric export"
    );
    assert!(
        lib_rs.contains("pub mod messaging;"),
        "expected src/lib.rs to keep the messaging root exported for legacy integrations"
    );

    for expected in [
        "pub mod jetstream;",
        "pub mod kafka;",
        "pub mod kafka_consumer;",
        "pub mod nats;",
        "pub mod redis;",
    ] {
        assert!(
            content.contains(expected),
            "expected src/messaging/mod.rs to keep `{expected}` visible in the public module tree"
        );
    }
}

#[test]
fn brokerless_fabric_foundation_stays_narrow_until_higher_layers_land() {
    let content = read_repo_file("src/messaging/fabric.rs");

    for expected in [
        "The goal of this module is deliberately narrow",
        "does not attempt to implement the",
        "full distributed data plane, federation, or consumer semantics yet.",
    ] {
        assert!(
            content.contains(expected),
            "expected src/messaging/fabric.rs to keep the narrow brokerless foundation contract: `{expected}`"
        );
    }
}

#[test]
fn fabric_ir_scaffold_compiles_as_a_real_schema_surface() {
    let ir = ir::FabricIr::default();
    assert_eq!(ir.schema_version, ir::FABRIC_IR_SCHEMA_VERSION);
    assert!(ir.validate().is_empty());

    let consumer = ir::ConsumerPolicy::default();
    assert_eq!(consumer.delivery_class.minimum_ack(), consumer.ack_kind);
}
