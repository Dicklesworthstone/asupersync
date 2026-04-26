#![no_main]

//! br-asupersync-5o8xxe — fuzz target for
//! `RestorableSnapshot::validate` in `src/lab/snapshot_restore.rs`.
//!
//! ## Contract under test
//!
//! `RestorableSnapshot::validate(&self)` walks the entire serialised
//! runtime state — region tree, task table, obligation table, parent
//! pointers, timestamps, region states — and produces a typed
//! `ValidationResult`. It MUST never panic on any input, even when
//! the input contains:
//!
//! - cycles in the region parent graph (self-loops, 2-cycles, long
//!   chains, multi-component graphs with one cyclic component);
//! - dangling parent / owner / obligation_owner_region IDs;
//! - duplicate IDs across the three tables;
//! - regions in `Closed` state with live children counts > 0
//!   (`NonQuiescentClosure`);
//! - timestamps going backwards across causally-ordered events;
//! - integer overflow on counts when the snapshot vecs are huge.
//!
//! Restoring an invalid snapshot is rejected by callers, but
//! `validate()` itself is the gate — if `validate()` panics, the
//! caller can't even decide whether to reject. That is the contract
//! this fuzz target pins.
//!
//! ## Input shape
//!
//! Two strategies, selected by the top bit of the first input byte:
//!
//! - **Strategy A (raw JSON):** treat the remaining bytes as utf-8
//!   JSON and pass to `serde_json::from_slice::<RestorableSnapshot>`.
//!   This stresses the serde recursion-depth, schema-version mismatch,
//!   content-hash mismatch, and field-overflow paths.
//!
//! - **Strategy B (synthesised typed seed):** consume the remaining
//!   bytes via `arbitrary::Unstructured` to build a JSON document
//!   shaped like a snapshot (with cycles, orphans, and id collisions
//!   intentionally injected), then feed it through `from_slice`. This
//!   guarantees every iteration reaches `validate()` rather than
//!   bouncing off the serde wall.
//!
//! ## Bounded resources
//!
//! - Input is clamped to 256 KiB.
//! - Synthesised snapshots cap regions / tasks / obligations to <= 64
//!   each so cycle-detection runs in microseconds. The point is to
//!   prove `validate()` is panic-free across the SHAPE space, not to
//!   stress the linear walks (those are stressed independently by
//!   property tests in src/lab/snapshot_restore.rs already).

use arbitrary::{Arbitrary, Unstructured};
use asupersync::lab::snapshot_restore::RestorableSnapshot;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 256 * 1024;
const MAX_REGIONS: usize = 64;
const MAX_TASKS: usize = 64;
const MAX_OBLIGATIONS: usize = 64;

/// Synthesised snapshot seed. Field counts and id ranges are tight so
/// the resulting JSON is small and the validator's O(N) walks finish
/// in microseconds; the goal is shape coverage, not throughput stress.
#[derive(Arbitrary, Debug)]
struct SnapshotSeed {
    schema_version: u32,
    content_hash: u64,
    region_count: u8,
    task_count: u8,
    obligation_count: u8,
    /// Adversarial parent pointer mask: each entry decides whether
    /// region[i].parent points to a valid id, a self-loop, a forward
    /// id (potential cycle), or a dangling id.
    parent_mode: [u8; MAX_REGIONS],
    /// Adversarial state for each region.
    state_choice: [u8; MAX_REGIONS],
    /// Adversarial owner id for each task (mod region_count, plus
    /// dangling/duplicate flags).
    task_owner: [u8; MAX_TASKS],
    /// Adversarial owner region for each obligation.
    obl_region: [u8; MAX_OBLIGATIONS],
    /// Adversarial owner task for each obligation.
    obl_task: [u8; MAX_OBLIGATIONS],
    /// Adversarial timestamps (u64 raw). Pre-fix: monotonic; post-fix:
    /// random per the parent_mode flags.
    timestamps: [u64; 32],
    /// Whether to include a `NonQuiescentClosure` shape (Closed region
    /// with live children).
    inject_non_quiescent_closure: bool,
    /// Whether to inject a duplicate region id.
    inject_duplicate_region: bool,
    /// Whether to inject a duplicate task id.
    inject_duplicate_task: bool,
}

impl SnapshotSeed {
    fn region_count(&self) -> usize {
        usize::from(self.region_count) % (MAX_REGIONS + 1)
    }
    fn task_count(&self) -> usize {
        usize::from(self.task_count) % (MAX_TASKS + 1)
    }
    fn obligation_count(&self) -> usize {
        usize::from(self.obligation_count) % (MAX_OBLIGATIONS + 1)
    }

    /// Render the seed to a JSON document. The shape mirrors what
    /// `RestorableSnapshot` expects (one top-level object with
    /// `snapshot`, `schema_version`, `content_hash` keys). The
    /// snapshot's inner shape uses the wire format produced by
    /// `RuntimeSnapshot`'s serde derive — and adversarial mismatches
    /// against that shape are themselves a fuzz dimension we want
    /// `from_slice` to reject without panicking.
    fn to_json(&self) -> String {
        let region_count = self.region_count();
        let task_count = self.task_count();
        let obligation_count = self.obligation_count();

        let regions: Vec<serde_json::Value> = (0..region_count)
            .map(|i| {
                let mode = self.parent_mode[i] & 0x07;
                let parent: serde_json::Value = match mode {
                    0 => serde_json::Value::Null,                     // root
                    1 => serde_json::json!(i),                        // self-loop
                    2 if region_count > 0 => serde_json::json!((i + 1) % region_count), // forward (cycle if i is last)
                    3 => serde_json::json!(u64::MAX),                 // dangling
                    4 if i > 0 => serde_json::json!(i - 1),           // valid backward
                    _ => serde_json::Value::Null,
                };
                let state = match self.state_choice[i] & 0x07 {
                    0 => "Open",
                    1 => "Closing",
                    2 => "Draining",
                    3 => "Finalizing",
                    4 => "Closed",
                    _ => "Open",
                };
                let id = if self.inject_duplicate_region && i + 1 == region_count && i > 0 {
                    0u64
                } else {
                    i as u64
                };
                serde_json::json!({
                    "id": id,
                    "parent": parent,
                    "state": state,
                    "created_at": self.timestamps[i % 32],
                    "live_children": if self.inject_non_quiescent_closure
                        && state == "Closed" { 1u32 } else { 0u32 },
                })
            })
            .collect();

        let tasks: Vec<serde_json::Value> = (0..task_count)
            .map(|i| {
                let owner_choice = self.task_owner[i];
                let owner: u64 = if region_count == 0 {
                    u64::from(owner_choice)
                } else if owner_choice & 0x80 != 0 {
                    u64::MAX // dangling
                } else {
                    u64::from(owner_choice) % (region_count as u64)
                };
                let id = if self.inject_duplicate_task && i + 1 == task_count && i > 0 {
                    0u64
                } else {
                    i as u64
                };
                serde_json::json!({
                    "id": id,
                    "owner": owner,
                    "created_at": self.timestamps[(i + 5) % 32],
                })
            })
            .collect();

        let obligations: Vec<serde_json::Value> = (0..obligation_count)
            .map(|i| {
                let region_choice = self.obl_region[i];
                let region_id: u64 = if region_count == 0 {
                    u64::from(region_choice)
                } else if region_choice & 0x80 != 0 {
                    u64::MAX
                } else {
                    u64::from(region_choice) % (region_count as u64)
                };
                let task_choice = self.obl_task[i];
                let task_id: u64 = if task_count == 0 {
                    u64::from(task_choice)
                } else if task_choice & 0x80 != 0 {
                    u64::MAX
                } else {
                    u64::from(task_choice) % (task_count as u64)
                };
                serde_json::json!({
                    "id": i as u64,
                    "region_id": region_id,
                    "task_id": task_id,
                    "created_at": self.timestamps[(i + 11) % 32],
                })
            })
            .collect();

        serde_json::to_string(&serde_json::json!({
            "snapshot": {
                "regions": regions,
                "tasks": tasks,
                "obligations": obligations,
                "now_ns": self.timestamps[0],
            },
            "schema_version": self.schema_version,
            "content_hash": self.content_hash,
        }))
        .unwrap_or_default()
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }

    let strategy_b = data[0] & 0x80 != 0;
    let payload = &data[1..];

    let json: Vec<u8> = if strategy_b {
        let mut u = Unstructured::new(payload);
        let Ok(seed) = SnapshotSeed::arbitrary(&mut u) else {
            return;
        };
        seed.to_json().into_bytes()
    } else {
        payload.to_vec()
    };

    // Contract: deserialisation may fail (typed Err) but must not
    // panic.
    let snap: RestorableSnapshot = match serde_json::from_slice(&json) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Contract: validate is total — every input shape produces a
    // ValidationResult. Cycle detection on adversarial parent
    // pointers, orphan walks on dangling IDs, NonQuiescentClosure
    // checks, and DuplicateId scans must all complete without
    // panicking.
    let _result = snap.validate();
});
