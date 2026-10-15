//! br-asupersync-7tcipb (item 4): `ChunkReuseManager` bounds its per-transfer
//! tracking maps so a peer that floods the manager with unique transfer ids
//! cannot grow `transfer_chunks` / `transfer_stats` without bound (memory DoS).
//!
//! The chunk *cache* is already LRU-capped; before this fix the per-transfer
//! key space was not, so `register_transfer_chunk` / `register_chunk_reuse`
//! with attacker-influenced transfer ids grew unboundedly. These tests assert
//! the tracked-transfer count stays at the configured cap and that eviction is
//! deterministic FIFO (oldest transfers dropped first).

use asupersync::atp::manifest::ProofStrength;
use asupersync::net::atp::chunk::dedupe::{ChunkIdentity, ChunkReuseManager};

fn identity() -> ChunkIdentity {
    ChunkIdentity::from_data(b"chunk-bytes", "scope", ProofStrength::Basic)
}

#[test]
fn transfer_stats_tracking_is_bounded_fifo() {
    let cap = 4;
    let mut manager = ChunkReuseManager::with_max_tracked_transfers(cap);
    let id = identity();

    // Register chunk reuse for 10 DISTINCT transfer ids — far past the cap.
    for i in 0..10u32 {
        manager
            .register_chunk_reuse(&format!("transfer-{i}"), &id, "source")
            .expect("register reuse");
    }

    // The tracked-transfer count never exceeds the configured bound.
    assert_eq!(
        manager.tracked_transfer_count(),
        cap,
        "tracked transfer count must be clamped to the configured maximum"
    );

    // FIFO: the oldest 6 transfers were evicted; their stats are gone.
    for i in 0..6u32 {
        assert!(
            manager
                .get_reuse_statistics(&format!("transfer-{i}"))
                .is_none(),
            "evicted transfer-{i} must retain no stats"
        );
    }
    // The most recent `cap` transfers are retained.
    for i in 6..10u32 {
        assert!(
            manager
                .get_reuse_statistics(&format!("transfer-{i}"))
                .is_some(),
            "recent transfer-{i} must retain stats"
        );
    }
}

#[test]
fn transfer_chunk_registration_is_bounded() {
    let cap = 3;
    let mut manager = ChunkReuseManager::with_max_tracked_transfers(cap);
    let id = identity();

    for i in 0..50u32 {
        manager
            .register_transfer_chunk(&format!("transfer-{i}"), &id)
            .expect("register chunk");
    }

    assert_eq!(
        manager.tracked_transfer_count(),
        cap,
        "register_transfer_chunk must also respect the tracked-transfer bound"
    );
}

#[test]
fn same_transfer_id_counts_once_across_both_maps() {
    let mut manager = ChunkReuseManager::with_max_tracked_transfers(8);
    let id = identity();

    // The same transfer id touched via both maps and repeated must count once.
    manager.register_transfer_chunk("t1", &id).expect("chunk");
    manager
        .register_chunk_reuse("t1", &id, "source")
        .expect("reuse");
    manager
        .register_transfer_chunk("t1", &id)
        .expect("chunk again");

    assert_eq!(
        manager.tracked_transfer_count(),
        1,
        "one distinct transfer id must be tracked once, not per registration"
    );
}

#[test]
fn below_cap_retains_all_transfers() {
    let mut manager = ChunkReuseManager::with_max_tracked_transfers(16);
    let id = identity();

    for i in 0..5u32 {
        manager
            .register_chunk_reuse(&format!("transfer-{i}"), &id, "source")
            .expect("register reuse");
    }

    assert_eq!(manager.tracked_transfer_count(), 5);
    for i in 0..5u32 {
        assert!(
            manager
                .get_reuse_statistics(&format!("transfer-{i}"))
                .is_some(),
            "below the cap, no transfer should be evicted"
        );
    }
}
