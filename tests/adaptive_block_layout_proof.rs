//! Behavioral proof for adaptive RaptorQ block sizing (bead
//! `asupersync-raptorq-leverage-3bb2pl.3`).
//!
//! The adaptive block-layout policy lives in `src/distributed/encoding.rs`
//! (`derive_layout_decision` over the `ADAPTIVE_BLOCK_LAYOUT_POLICY` table, with
//! a static fallback when path quality is unknown). This focused integration
//! test exercises it through the public `StateEncoder` API and the replayable
//! `EncodingLayoutDecision` telemetry, proving:
//!
//! - AC4: unknown path quality falls back to the static policy.
//! - AC3: a known snapshot emits adaptive telemetry carrying the snapshot.
//! - AC2: repair overhead is monotone non-decreasing in loss (worse loss never
//!   reduces the repair budget) — the policy table's required property.
//! - Determinism: same config + seed + snapshot => identical layout decision.
//!
//! Run with: `cargo test --test adaptive_block_layout_proof --features test-internals`
//! (a focused integration-test binary: it links the library compiled without
//! `#[cfg(test)]`, so it is not affected by unrelated in-tree test-module WIP).

#![cfg(feature = "test-internals")]

use asupersync::distributed::{
    ADAPTIVE_BLOCK_LAYOUT_POLICY_ID, BudgetSnapshot, EncodingConfig, EncodingLayoutDecision,
    PathQualitySnapshot, RegionSnapshot, STATIC_BLOCK_LAYOUT_POLICY_ID, StateEncoder, TaskSnapshot,
    TaskState,
};
use asupersync::record::region::RegionState;
use asupersync::security::AuthenticationTag;
use asupersync::trace::distributed::vclock::VectorClock;
use asupersync::types::{RegionId, TaskId, Time};
use asupersync::util::DetRng;

fn snapshot(pad: usize) -> RegionSnapshot {
    RegionSnapshot {
        region_id: RegionId::new_for_test(1, 0),
        state: RegionState::Open,
        timestamp: Time::from_secs(100),
        sequence: 1,
        vector_clock: VectorClock::new(),
        origin_id: 1,
        epoch: 1,
        tasks: vec![TaskSnapshot {
            task_id: TaskId::new_for_test(1, 0),
            state: TaskState::Running,
            priority: 5,
        }],
        children: vec![],
        finalizer_count: 2,
        budget: BudgetSnapshot {
            deadline_nanos: Some(1_000_000_000),
            polls_remaining: Some(100),
            cost_remaining: None,
        },
        cancel_reason: None,
        parent: None,
        metadata: vec![0xAB; pad],
        auth_tag: AuthenticationTag::zero(),
    }
}

fn layout_for_loss(loss_permille: u16, pad: usize) -> EncodingLayoutDecision {
    let config = EncodingConfig {
        path_quality: Some(PathQualitySnapshot::new(50, loss_permille, 0)),
        ..EncodingConfig::default()
    };
    let mut encoder = StateEncoder::new(config, DetRng::new(42));
    let encoded = encoder
        .encode(&snapshot(pad), Time::from_secs(1))
        .expect("encode succeeds");
    encoded.layout_decision
}

#[test]
fn unknown_quality_uses_static_fallback() {
    // AC4: no path quality -> static policy, never worse than today.
    let mut encoder = StateEncoder::new(EncodingConfig::default(), DetRng::new(1));
    let encoded = encoder
        .encode(&snapshot(0), Time::from_secs(1))
        .expect("encode succeeds");
    assert_eq!(
        encoded.layout_decision.policy_id,
        STATIC_BLOCK_LAYOUT_POLICY_ID
    );
    assert!(encoded.layout_decision.path_quality.is_none());
}

#[test]
fn known_quality_emits_adaptive_telemetry() {
    // AC3: a known snapshot selects the adaptive policy and the decision row
    // carries the snapshot (replayable telemetry).
    let decision = layout_for_loss(200, 0);
    assert_eq!(decision.policy_id, ADAPTIVE_BLOCK_LAYOUT_POLICY_ID);
    assert_eq!(
        decision.path_quality,
        Some(PathQualitySnapshot::new(50, 200, 0))
    );
}

#[test]
fn repair_is_monotone_in_loss() {
    // AC2: worse loss never reduces the repair budget (the policy table's
    // required monotonicity property), holding RTT and reorder fixed.
    let mut prev = layout_for_loss(0, 0).effective_min_repair_symbols;
    let mut prev_mult = layout_for_loss(0, 0).repair_multiplier_permille;
    let mut loss: u16 = 0;
    while loss <= 1000 {
        let decision = layout_for_loss(loss, 0);
        assert!(
            decision.effective_min_repair_symbols >= prev,
            "repair symbols regressed at loss {loss}: {} < {prev}",
            decision.effective_min_repair_symbols
        );
        assert!(
            decision.repair_multiplier_permille >= prev_mult,
            "repair multiplier regressed at loss {loss}"
        );
        prev = decision.effective_min_repair_symbols;
        prev_mult = decision.repair_multiplier_permille;
        loss += 50;
    }
}

#[test]
fn lossy_path_gets_at_least_as_much_repair_as_clean() {
    let clean = layout_for_loss(0, 0);
    let lossy = layout_for_loss(1000, 0);
    assert!(lossy.effective_min_repair_symbols >= clean.effective_min_repair_symbols);
    assert!(lossy.repair_multiplier_permille >= clean.repair_multiplier_permille);
}

#[test]
fn layout_decision_is_deterministic() {
    assert_eq!(layout_for_loss(150, 64), layout_for_loss(150, 64));
}
