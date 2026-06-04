//! Fuzz target for `src/plan/certificate.rs` — PlanHash determinism.
//!
//! Exercises:
//!   - `PlanHash::of(dag)` — deterministic content hash of a replay-stable
//!     plan DAG.
//!   - Property: `of(x) == of(y) iff x == y` for byte-derived one-leaf DAGs
//!     (collision-free for SHA-256-class digests; not provable but no false
//!     matches in practice).
//!   - Property: `of(x).as_bytes()` is exactly 32 bytes.
//!   - Property: hashing the same DAG twice produces the same hash
//!     (determinism — the project relies on PlanHash for
//!     replay-stable plan certificates).
//!   - Property: hashing DAGs derived from different prefixes of the same input
//!     produces different hashes (no truncation bug).

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::fmt::Write;

use asupersync::plan::PlanDag;
use asupersync::plan::certificate::PlanHash;

const MAX_PLAN_BYTES: usize = 4096;

fn dag_from_bytes(data: &[u8]) -> PlanDag {
    let mut dag = PlanDag::new();
    let root = dag.leaf(hex_label(data));
    dag.set_root(root);
    dag
}

fn hex_label(data: &[u8]) -> String {
    let mut label = String::with_capacity(data.len() * 2);
    for byte in data {
        let _ = write!(label, "{byte:02x}");
    }
    label
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PLAN_BYTES {
        return;
    }

    let dag = dag_from_bytes(data);

    // Determinism: of(x) twice gives the same hash.
    let h1 = PlanHash::of(&dag);
    let h2 = PlanHash::of(&dag);
    assert_eq!(
        h1, h2,
        "PlanHash::of is not deterministic for identical input"
    );

    // Length: 32 bytes.
    assert_eq!(
        h1.as_bytes().len(),
        32,
        "PlanHash::as_bytes() must be 32 bytes (SHA-256-class digest)"
    );

    // Prefix sensitivity: hashing prefixes of different lengths must
    // produce different hashes (otherwise we have a length-extension
    // or truncation bug).
    if data.len() >= 2 {
        let prefix_dag = dag_from_bytes(&data[..1]);
        let h_prefix = PlanHash::of(&prefix_dag);
        let h_full = PlanHash::of(&dag);
        if data.len() != 1 {
            assert_ne!(
                h_prefix, h_full,
                "PlanHash::of of a 1-byte prefix matched the full input — truncation bug"
            );
        }
    }

    // Distinctness: appending a byte should change the hash.
    if data.len() < 1024 {
        let mut extended = data.to_vec();
        extended.push(0xAB);
        let extended_dag = dag_from_bytes(&extended);
        let h_ext = PlanHash::of(&extended_dag);
        assert_ne!(
            h1, h_ext,
            "PlanHash::of did not change after appending a byte"
        );
    }

    // Symmetry of equality: the Eq impl is reflexive.
    assert_eq!(h1, h1);

    // Hash is Copy/Clone — exercise.
    let h3 = h1;
    assert_eq!(h1, h3);
});
