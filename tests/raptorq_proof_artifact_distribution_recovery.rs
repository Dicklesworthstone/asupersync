//! RaptorQ proof-artifact distribution & recovery conformance.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330). Pins the production proof-artifact
//! distribution surface in `raptorq::proof` that had ZERO integration coverage:
//! `package_proof_artifact_for_distribution`, `recover_proof_artifact_from_shards`,
//! and the self-authenticating `ProofArtifactManifest` (`recompute_hash` /
//! `hash_is_valid`).
//!
//! This surface packages a proof artifact into deterministic, authenticated
//! RaptorQ shards (a self-describing manifest + source/repair symbols), then
//! recovers the original bytes from any sufficiently complete *authenticated*
//! shard subset. It is exactly the "no hidden ambient behavior / fail-closed"
//! surface the program cares about: every field is hashed, every shard carries a
//! deterministic auth tag, and recovery refuses to emit bytes that do not match
//! the manifest's source-payload hash.
//!
//! The relations checked are oracle-free structural/round-trip invariants:
//!   * package → recover with ALL shards reproduces the original bytes exactly,
//!     reports `authenticated == true`, and the fresh manifest self-authenticates;
//!   * recovery survives source-symbol erasure by consuming repair shards
//!     (the whole point of erasure-coded distribution), and is independent of the
//!     order shards are supplied in;
//!   * every authentication / validation guard fails closed with the *specific*
//!     error variant — tampered manifest hash (`ManifestHashMismatch`), corrupted
//!     RFC parameter (`ManifestParameterMismatch`), wrong-manifest shard
//!     (`ManifestMismatch`), flipped shard payload (`ShardPayloadHashMismatch`),
//!     forged shard kind (`ShardAuthenticationFailed`), wrong shard size
//!     (`ShardSizeMismatch`);
//!   * malformed packaging input fails closed (`EmptyArtifact`,
//!     `InvalidSymbolSize`).
//!
//! Repro: `cargo test -p asupersync --test raptorq_proof_artifact_distribution_recovery`

use asupersync::raptorq::proof::{
    ProofArtifactDistribution, ProofArtifactDistributionError,
    package_proof_artifact_for_distribution, recover_proof_artifact_from_shards,
};
use asupersync::types::ObjectId;

const SYMBOL_SIZE: usize = 16;
const SEED: u64 = 0x5AFE_C0DE_1234_5678;

/// Deterministic, non-trivial artifact bytes (no all-zero symbols, so payload
/// hashing and shard authentication are exercised on real data).
fn sample_artifact(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) & 0xFF) as u8).collect()
}

/// Package a representative artifact with generous repair redundancy.
fn package_sample(artifact: &[u8], repair_symbols: usize) -> ProofArtifactDistribution {
    package_proof_artifact_for_distribution(
        artifact,
        SYMBOL_SIZE,
        repair_symbols,
        SEED,
        ObjectId::new(0xA11C_E000_0000_0001, 0x0000_0000_0000_BEEF),
        7,
    )
    .expect("packaging a well-formed artifact must succeed")
}

#[test]
fn package_then_recover_all_shards_round_trips() {
    let artifact = sample_artifact(200);
    let dist = package_sample(&artifact, 24);

    // The manifest is self-authenticating immediately after packaging.
    assert!(dist.manifest.hash_is_valid());
    assert_eq!(dist.manifest.recompute_hash(), dist.manifest.manifest_hash);
    assert_eq!(dist.manifest.artifact_len, artifact.len());
    assert_eq!(dist.manifest.symbol_size, SYMBOL_SIZE);
    assert_eq!(dist.manifest.repair_symbols, 24);
    // Shards are emitted as `source_symbols` systematic shards + repair shards.
    assert_eq!(dist.shards.len(), dist.manifest.source_symbols + 24);

    let recovery = recover_proof_artifact_from_shards(&dist.manifest, &dist.shards)
        .expect("all authenticated shards must decode");

    // Byte-identical recovery, fully authenticated, with the expected accounting.
    assert_eq!(recovery.payload, artifact);
    assert!(recovery.authenticated);
    assert_eq!(recovery.manifest_hash, dist.manifest.manifest_hash);
    assert_eq!(recovery.symbols_received, dist.shards.len());
    assert_eq!(
        recovery.overhead_symbols,
        dist.shards.len() - dist.manifest.source_symbols
    );
}

#[test]
fn recovery_survives_source_erasure_via_repair_shards() {
    let artifact = sample_artifact(176);
    let dist = package_sample(&artifact, 24);

    // Drop several systematic *source* shards; recovery must lean on repair
    // shards. Keep every repair shard so the system stays over-determined.
    let dropped = 4usize;
    assert!(dist.manifest.source_symbols > dropped);
    let surviving: Vec<_> = dist
        .shards
        .iter()
        .filter(|s| !s.is_source)
        .cloned()
        .chain(
            dist.shards
                .iter()
                .filter(|s| s.is_source)
                .skip(dropped)
                .cloned(),
        )
        .collect();
    // We genuinely lost source symbols but kept enough total symbols to decode.
    assert_eq!(surviving.len(), dist.shards.len() - dropped);
    assert!(surviving.iter().filter(|s| s.is_source).count() < dist.manifest.source_symbols);

    let recovery = recover_proof_artifact_from_shards(&dist.manifest, &surviving)
        .expect("erasure within repair budget must still decode");
    assert_eq!(recovery.payload, artifact);
    assert!(recovery.authenticated);
}

#[test]
fn recovery_is_independent_of_shard_order() {
    let artifact = sample_artifact(150);
    let dist = package_sample(&artifact, 20);

    let forward = recover_proof_artifact_from_shards(&dist.manifest, &dist.shards)
        .expect("forward order decodes");

    let mut reversed = dist.shards.clone();
    reversed.reverse();
    let backward = recover_proof_artifact_from_shards(&dist.manifest, &reversed)
        .expect("reversed order decodes");

    assert_eq!(forward.payload, artifact);
    assert_eq!(backward.payload, artifact);
    assert_eq!(forward.payload, backward.payload);
}

#[test]
fn tampered_manifest_hash_fails_closed() {
    let artifact = sample_artifact(128);
    let dist = package_sample(&artifact, 16);

    // Mutate a hashed field without recomputing the manifest hash: the manifest
    // no longer self-authenticates, and recovery refuses it.
    let mut manifest = dist.manifest.clone();
    manifest.seed ^= 0x1;
    assert!(!manifest.hash_is_valid());

    let err = recover_proof_artifact_from_shards(&manifest, &dist.shards)
        .expect_err("a manifest whose hash no longer matches must be rejected");
    assert!(
        matches!(
            err,
            ProofArtifactDistributionError::ManifestHashMismatch { .. }
        ),
        "expected ManifestHashMismatch, got {err:?}"
    );
}

#[test]
fn corrupted_rfc_parameter_fails_closed_before_hash() {
    let artifact = sample_artifact(128);
    let dist = package_sample(&artifact, 16);

    // Corrupt the RFC 6330 `k_prime` parameter. Parameter validation runs ahead
    // of the manifest-hash check, so the recovery must surface the precise
    // parameter mismatch (a manifest that lies about its own RFC parameters).
    let mut manifest = dist.manifest.clone();
    manifest.k_prime += 1;

    let err = recover_proof_artifact_from_shards(&manifest, &dist.shards)
        .expect_err("a manifest with a wrong RFC parameter must be rejected");
    assert!(
        matches!(
            err,
            ProofArtifactDistributionError::ManifestParameterMismatch { field, .. } if field == "k_prime"
        ),
        "expected ManifestParameterMismatch{{k_prime}}, got {err:?}"
    );
}

#[test]
fn shard_from_a_different_manifest_is_rejected() {
    let dist_a = package_sample(&sample_artifact(120), 12);
    // A distinct artifact yields a distinct manifest hash.
    let dist_b = package_sample(&sample_artifact(96), 12);
    assert_ne!(dist_a.manifest.manifest_hash, dist_b.manifest.manifest_hash);

    let mut shards = dist_a.shards.clone();
    shards.push(dist_b.shards[0].clone());

    let err = recover_proof_artifact_from_shards(&dist_a.manifest, &shards)
        .expect_err("a shard bound to another manifest must be rejected");
    assert!(
        matches!(err, ProofArtifactDistributionError::ManifestMismatch { .. }),
        "expected ManifestMismatch, got {err:?}"
    );
}

#[test]
fn flipped_shard_payload_fails_data_hash() {
    let artifact = sample_artifact(112);
    let dist = package_sample(&artifact, 12);

    // Flip a byte in a shard payload without touching its stored data hash.
    let mut shards = dist.shards.clone();
    shards[0].data[0] ^= 0xFF;

    let err = recover_proof_artifact_from_shards(&dist.manifest, &shards)
        .expect_err("a payload that no longer matches its data hash must be rejected");
    assert!(
        matches!(
            err,
            ProofArtifactDistributionError::ShardPayloadHashMismatch { .. }
        ),
        "expected ShardPayloadHashMismatch, got {err:?}"
    );
}

#[test]
fn forged_shard_kind_fails_authentication() {
    let artifact = sample_artifact(112);
    let dist = package_sample(&artifact, 12);

    // Find a repair shard and forge its `is_source` flag. The payload and its
    // data hash still agree, so the data-hash guard passes, but the auth tag was
    // computed over the original kind — authentication must fail closed.
    let mut shards = dist.shards.clone();
    let repair_idx = shards
        .iter()
        .position(|s| !s.is_source)
        .expect("distribution includes repair shards");
    shards[repair_idx].is_source = true;

    let err = recover_proof_artifact_from_shards(&dist.manifest, &shards)
        .expect_err("a shard with a forged kind must fail authentication");
    assert!(
        matches!(
            err,
            ProofArtifactDistributionError::ShardAuthenticationFailed { .. }
        ),
        "expected ShardAuthenticationFailed, got {err:?}"
    );
}

#[test]
fn wrong_size_shard_is_rejected() {
    let artifact = sample_artifact(112);
    let dist = package_sample(&artifact, 12);

    let mut shards = dist.shards.clone();
    shards[0].data.push(0); // now one byte longer than `symbol_size`

    let err = recover_proof_artifact_from_shards(&dist.manifest, &shards)
        .expect_err("a shard whose payload is the wrong symbol size must be rejected");
    assert!(
        matches!(
            err,
            ProofArtifactDistributionError::ShardSizeMismatch { expected, actual, .. }
                if expected == SYMBOL_SIZE && actual == SYMBOL_SIZE + 1
        ),
        "expected ShardSizeMismatch, got {err:?}"
    );
}

#[test]
fn malformed_packaging_input_fails_closed() {
    let object_id = ObjectId::new(1, 2);

    let empty = package_proof_artifact_for_distribution(&[], SYMBOL_SIZE, 4, SEED, object_id, 0);
    assert!(
        matches!(empty, Err(ProofArtifactDistributionError::EmptyArtifact)),
        "empty artifact must be rejected, got {empty:?}"
    );

    let zero_symbol =
        package_proof_artifact_for_distribution(&sample_artifact(32), 0, 4, SEED, object_id, 0);
    assert!(
        matches!(
            zero_symbol,
            Err(ProofArtifactDistributionError::InvalidSymbolSize)
        ),
        "zero symbol size must be rejected, got {zero_symbol:?}"
    );
}
