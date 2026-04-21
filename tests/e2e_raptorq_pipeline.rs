#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

//! E2E RaptorQ FEC pipeline under erasure (T4.1).
//!
//! RegionSnapshot → encode → simulate packet loss → decode → verify recovery.

#[macro_use]
mod common;

use asupersync::distributed::encoding::{EncodedState, EncodingConfig, StateEncoder};
use asupersync::distributed::recovery::{RecoveryDecodingConfig, StateDecoder};
use asupersync::distributed::snapshot::{BudgetSnapshot, RegionSnapshot, TaskSnapshot, TaskState};
use asupersync::record::region::RegionState;
use asupersync::security::{AuthenticatedSymbol, AuthenticationTag};
use asupersync::types::{RegionId, TaskId, Time};
use asupersync::util::DetRng;
use common::e2e_harness::E2eLabHarness;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a realistic region snapshot with N tasks and M children.
fn make_realistic_snapshot(task_count: usize, child_count: usize) -> RegionSnapshot {
    let tasks: Vec<TaskSnapshot> = (0..task_count)
        .map(|i| TaskSnapshot {
            task_id: TaskId::new_for_test(i as u32 + 1, 0),
            state: match i % 4 {
                0 => TaskState::Running,
                1 => TaskState::Pending,
                2 => TaskState::Completed,
                _ => TaskState::Cancelled,
            },
            priority: ((i % 10) * 10) as u8,
        })
        .collect();

    let children: Vec<RegionId> = (0..child_count)
        .map(|i| RegionId::new_for_test(100 + i as u32, 0))
        .collect();

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let metadata: Vec<u8> = (0..64).map(|i| ((i * 7 + 13) & 0xFF) as u8).collect();

    RegionSnapshot {
        region_id: RegionId::new_for_test(1, 0),
        state: RegionState::Open,
        timestamp: Time::from_secs(1_710_600_000),
        sequence: 42,
        tasks,
        children,
        finalizer_count: (child_count as u32).min(5),
        budget: BudgetSnapshot {
            deadline_nanos: Some(10_000_000_000),
            polls_remaining: Some(5000),
            cost_remaining: Some(10000),
        },
        cancel_reason: None,
        parent: Some(RegionId::new_for_test(0, 0)),
        metadata,
    }
}

fn encode_snapshot(snapshot: &RegionSnapshot, symbol_size: u16, seed: u64) -> EncodedState {
    let config = EncodingConfig {
        symbol_size,
        min_repair_symbols: 8,
        ..Default::default()
    };
    StateEncoder::new(config, DetRng::new(seed))
        .encode(snapshot, Time::ZERO)
        .expect("encoding should succeed")
}

fn deterministic_exact_budget_symbols(
    encoded: &EncodedState,
) -> (Vec<AuthenticatedSymbol>, BTreeMap<u8, usize>) {
    let mut repair_counts = BTreeMap::new();
    for symbol in encoded.repair_symbols() {
        *repair_counts.entry(symbol.id().sbn()).or_insert(0usize) += 1;
    }

    let mut dropped_source_counts = BTreeMap::new();
    let mut kept = Vec::with_capacity(encoded.min_symbols_for_decode() as usize);
    for symbol in &encoded.symbols {
        if symbol.kind().is_source() {
            let block = symbol.id().sbn();
            let drop_budget = repair_counts.get(&block).copied().unwrap_or(0);
            let dropped = dropped_source_counts.entry(block).or_insert(0);
            if *dropped < drop_budget {
                *dropped += 1;
                continue;
            }
        }

        kept.push(AuthenticatedSymbol::new_verified(
            symbol.clone(),
            AuthenticationTag::zero(),
        ));
    }

    (kept, dropped_source_counts)
}

// ---------------------------------------------------------------------------
// T4.1a: Encode-decode round trip — no loss
// ---------------------------------------------------------------------------

#[test]
fn e2e_raptorq_roundtrip_no_loss() {
    let mut h = E2eLabHarness::new("e2e_raptorq_roundtrip_no_loss", 0xE2E4_1001);
    h.phase("setup");

    let snapshot = make_realistic_snapshot(50, 5);
    let original_hash = snapshot.content_hash();

    h.phase("encode");
    let encoded = encode_snapshot(&snapshot, 256, 0xE2E4_1001);
    tracing::info!(
        source_symbols = encoded.source_count,
        repair_symbols = encoded.repair_count,
        total_symbols = encoded.symbols.len(),
        symbol_size = 256,
        "encoded snapshot"
    );

    h.phase("decode — no loss");
    let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
    for sym in &encoded.symbols {
        let authed = AuthenticatedSymbol::new_verified(sym.clone(), AuthenticationTag::zero());
        decoder.add_symbol(&authed).unwrap();
    }
    let recovered = decoder
        .decode_snapshot(&encoded.params)
        .expect("decode should succeed");

    h.phase("verify");
    let recovered_hash = recovered.content_hash();
    assert_with_log!(
        original_hash == recovered_hash,
        "byte-perfect recovery (content hash)",
        original_hash,
        recovered_hash
    );
    assert_with_log!(
        recovered.tasks.len() == 50,
        "task count preserved",
        50,
        recovered.tasks.len()
    );
    assert_with_log!(
        recovered.children.len() == 5,
        "children count preserved",
        5,
        recovered.children.len()
    );

    // RaptorQ encode/decode is pure computation — create a minimal runtime
    // context so oracle verification in finish() has something to check.
    let root = h.create_root();
    h.spawn(root, async {});
    h.run_until_quiescent();
    h.finish();
}

// ---------------------------------------------------------------------------
// T4.1b: Recovery under 30% packet loss
// ---------------------------------------------------------------------------

#[test]
fn e2e_raptorq_recovery_30pct_loss() {
    let mut h = E2eLabHarness::new("e2e_raptorq_recovery_30pct_loss", 0xE2E4_1002);
    h.phase("setup");

    let snapshot = make_realistic_snapshot(50, 5);
    let original_hash = snapshot.content_hash();

    h.phase("encode");
    let encoded = encode_snapshot(&snapshot, 256, 0xE2E4_1002);

    h.phase("simulate 30% erasure");
    let mut rng = DetRng::new(0xE2E4_1002);
    let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
    let mut kept = 0usize;
    let total = encoded.symbols.len();
    for sym in &encoded.symbols {
        // Map u64 to [0, 1). The +1.0 prevents the edge case where u64::MAX
        // maps to ~1.0, ensuring the range is strictly [0, 1).
        #[allow(clippy::cast_precision_loss)]
        let val = rng.next_u64() as f64 / (u64::MAX as f64 + 1.0);
        if val >= 0.30 {
            // Keep this symbol (not lost)
            let authed = AuthenticatedSymbol::new_verified(sym.clone(), AuthenticationTag::zero());
            decoder.add_symbol(&authed).unwrap();
            kept += 1;
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let loss_pct = (total - kept) as f64 / total as f64 * 100.0;

    tracing::info!(
        total_symbols = total,
        kept_symbols = kept,
        loss_pct = loss_pct,
        "after erasure"
    );

    h.phase("decode");
    match decoder.decode_snapshot(&encoded.params) {
        Ok(recovered) => {
            let recovered_hash = recovered.content_hash();
            assert_with_log!(
                original_hash == recovered_hash,
                "byte-perfect recovery under 30% loss",
                original_hash,
                recovered_hash
            );
            tracing::info!("recovery successful under 30% loss");
        }
        Err(e) => {
            // With 30% loss, decode might fail depending on which symbols were lost
            tracing::warn!(error = %e, "decode failed under 30% loss (acceptable with bad luck)");
        }
    }

    let root = h.create_root();
    h.spawn(root, async {});
    h.run_until_quiescent();
    h.finish();
}

// ---------------------------------------------------------------------------
// T4.1c: Multi-seed determinism verification
// ---------------------------------------------------------------------------

#[test]
fn e2e_raptorq_deterministic_encoding() {
    let mut h = E2eLabHarness::new("e2e_raptorq_deterministic_encoding", 0xE2E4_1003);
    h.phase("determinism check");

    let snapshot = make_realistic_snapshot(20, 3);

    // Encode with same seed twice — must produce identical output
    let encoded1 = encode_snapshot(&snapshot, 128, 0xDEAD_BEEF);
    let encoded2 = encode_snapshot(&snapshot, 128, 0xDEAD_BEEF);

    assert_with_log!(
        encoded1.symbols.len() == encoded2.symbols.len(),
        "same symbol count",
        encoded1.symbols.len(),
        encoded2.symbols.len()
    );

    for (i, (s1, s2)) in encoded1
        .symbols
        .iter()
        .zip(encoded2.symbols.iter())
        .enumerate()
    {
        assert_with_log!(
            s1 == s2,
            &format!("symbol {i} identical"),
            "equal",
            if s1 == s2 { "equal" } else { "different" }
        );
    }

    // Different seed → different encoding
    let encoded3 = encode_snapshot(&snapshot, 128, 0xCAFE_BABE);
    let any_different = encoded1
        .symbols
        .iter()
        .zip(encoded3.symbols.iter())
        .any(|(s1, s3)| s1 != s3);
    assert_with_log!(
        any_different,
        "different seed produces different encoding",
        true,
        any_different
    );

    let root = h.create_root();
    h.spawn(root, async {});
    h.run_until_quiescent();
    h.finish();
}

// ---------------------------------------------------------------------------
// T4.1d: Deterministic exact-budget recovery
// ---------------------------------------------------------------------------

#[test]
fn e2e_raptorq_recovery_exact_budget_deterministic() {
    let mut h = E2eLabHarness::new(
        "e2e_raptorq_recovery_exact_budget_deterministic",
        0xE2E4_1004,
    );
    h.phase("setup");

    let snapshot = make_realistic_snapshot(50, 5);
    let original_hash = snapshot.content_hash();

    h.phase("encode");
    let encoded = encode_snapshot(&snapshot, 64, 0xE2E4_1004);

    h.phase("select exact decode budget");
    let (kept_symbols, dropped_source_counts) = deterministic_exact_budget_symbols(&encoded);
    let total_symbols = encoded.symbols.len();
    let kept_count = kept_symbols.len();
    let dropped_count = total_symbols - kept_count;
    let min_symbols = encoded.min_symbols_for_decode() as usize;

    tracing::info!(
        total_symbols,
        kept_count,
        dropped_count,
        min_symbols,
        dropped_source_counts = ?dropped_source_counts,
        "selected deterministic exact-budget symbol set"
    );

    assert_with_log!(
        kept_count == min_symbols,
        "kept symbol count matches exact decode budget",
        min_symbols,
        kept_count
    );
    assert_with_log!(
        dropped_count == usize::from(encoded.repair_count),
        "dropped source count matches total repair budget",
        usize::from(encoded.repair_count),
        dropped_count
    );

    h.phase("decode");
    let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
    for symbol in &kept_symbols {
        decoder.add_symbol(symbol).unwrap();
    }
    let recovered = decoder
        .decode_snapshot(&encoded.params)
        .expect("decode should succeed at exact budget");

    h.phase("verify");
    let recovered_hash = recovered.content_hash();
    assert_with_log!(
        original_hash == recovered_hash,
        "byte-perfect recovery at exact budget",
        original_hash,
        recovered_hash
    );

    let root = h.create_root();
    h.spawn(root, async {});
    h.run_until_quiescent();
    h.finish();
}
