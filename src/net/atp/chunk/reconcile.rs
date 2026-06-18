//! Rateless chunk set reconciliation for ATP delta transfers.
//!
//! This module reconciles sender and receiver chunk-fingerprint sets before
//! any chunk bytes are sent. The sketch is an IBLT: communication scales with
//! the symmetric difference instead of the full fingerprint set, and the caller
//! can grow the sketch ratelessly when a decode attempt does not peel cleanly.

use super::ChunkingProfileError;
use super::dedupe::CdcChunkData;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};

/// Canonical chunk identifier used by set reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkFingerprint(pub [u8; 32]);

impl ChunkFingerprint {
    /// Build a fingerprint from a raw SHA-256 chunk hash.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the raw fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for ChunkFingerprint {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&CdcChunkData> for ChunkFingerprint {
    fn from(chunk: &CdcChunkData) -> Self {
        Self(chunk.content_hash)
    }
}

/// Rateless IBLT sizing knobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatelessIbltConfig {
    /// Initial number of IBLT cells to encode.
    pub initial_cell_count: usize,
    /// Maximum decode/grow attempts.
    pub max_rounds: usize,
    /// Number of deterministic hash locations per key.
    pub hash_function_count: usize,
}

impl Default for RatelessIbltConfig {
    fn default() -> Self {
        Self {
            initial_cell_count: 64,
            max_rounds: 8,
            hash_function_count: 3,
        }
    }
}

impl RatelessIbltConfig {
    fn validate(&self) -> Result<(), ChunkingProfileError> {
        if self.initial_cell_count == 0 {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "IBLT initial cell count must be greater than zero".to_string(),
            ));
        }
        if self.max_rounds == 0 {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "IBLT max rounds must be greater than zero".to_string(),
            ));
        }
        if self.hash_function_count == 0 {
            return Err(ChunkingProfileError::InvalidChunkParameters(
                "IBLT hash function count must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

/// Exact set-difference estimate for deciding whether reconciliation is worth it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkSetDeltaEstimate {
    /// Unique sender chunk fingerprints.
    pub sender_unique_chunks: usize,
    /// Unique receiver chunk fingerprints.
    pub receiver_unique_chunks: usize,
    /// Fingerprints present on both sides.
    pub shared_chunks: usize,
    /// Fingerprints present only on the sender.
    pub receiver_missing_chunks: usize,
    /// Fingerprints present only on the receiver.
    pub receiver_stale_chunks: usize,
    /// Full symmetric difference.
    pub symmetric_difference_chunks: usize,
    /// Sender-side naive "upload all fingerprints" baseline.
    pub naive_sender_fingerprint_bytes: usize,
    /// Suggested first IBLT size for delta-proportional exchange.
    pub recommended_initial_cells: usize,
}

/// Successful reconciliation output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkSetReconciliation {
    /// Chunk IDs present on the sender and missing from the receiver.
    pub receiver_missing: BTreeSet<ChunkFingerprint>,
    /// Chunk IDs present on the receiver but absent from the sender target.
    pub receiver_stale: BTreeSet<ChunkFingerprint>,
    /// Number of rateless rounds required to decode.
    pub rounds: usize,
    /// Cell count of the sketch that decoded.
    pub cell_count: usize,
    /// Estimated serialized IBLT bytes for the successful sketch.
    pub estimated_wire_bytes: usize,
    /// Sender-side naive "upload all fingerprints" baseline bytes.
    pub naive_sender_fingerprint_bytes: usize,
}

/// Reconcile CDC chunk outputs directly.
pub fn reconcile_cdc_chunks(
    sender_chunks: &[CdcChunkData],
    receiver_chunks: &[CdcChunkData],
    config: &RatelessIbltConfig,
) -> Result<ChunkSetReconciliation, ChunkingProfileError> {
    reconcile_chunk_sets(
        sender_chunks.iter().map(ChunkFingerprint::from),
        receiver_chunks.iter().map(ChunkFingerprint::from),
        config,
    )
}

/// Estimate set delta from arbitrary chunk fingerprints.
#[must_use]
pub fn estimate_chunk_set_delta<I, J>(sender_chunks: I, receiver_chunks: J) -> ChunkSetDeltaEstimate
where
    I: IntoIterator<Item = ChunkFingerprint>,
    J: IntoIterator<Item = ChunkFingerprint>,
{
    let sender_set: BTreeSet<ChunkFingerprint> = sender_chunks.into_iter().collect();
    let receiver_set: BTreeSet<ChunkFingerprint> = receiver_chunks.into_iter().collect();
    let shared_chunks = sender_set.intersection(&receiver_set).count();
    let receiver_missing_chunks = sender_set.difference(&receiver_set).count();
    let receiver_stale_chunks = receiver_set.difference(&sender_set).count();
    let symmetric_difference_chunks = receiver_missing_chunks + receiver_stale_chunks;
    let recommended_initial_cells = recommended_cell_count(symmetric_difference_chunks);

    ChunkSetDeltaEstimate {
        sender_unique_chunks: sender_set.len(),
        receiver_unique_chunks: receiver_set.len(),
        shared_chunks,
        receiver_missing_chunks,
        receiver_stale_chunks,
        symmetric_difference_chunks,
        naive_sender_fingerprint_bytes: sender_set.len() * CHUNK_FINGERPRINT_BYTES,
        recommended_initial_cells,
    }
}

/// Reconcile sender and receiver chunk sets using rateless IBLT growth.
pub fn reconcile_chunk_sets<I, J>(
    sender_chunks: I,
    receiver_chunks: J,
    config: &RatelessIbltConfig,
) -> Result<ChunkSetReconciliation, ChunkingProfileError>
where
    I: IntoIterator<Item = ChunkFingerprint>,
    J: IntoIterator<Item = ChunkFingerprint>,
{
    config.validate()?;

    let sender_set: BTreeSet<ChunkFingerprint> = sender_chunks.into_iter().collect();
    let receiver_set: BTreeSet<ChunkFingerprint> = receiver_chunks.into_iter().collect();
    let naive_sender_fingerprint_bytes = sender_set.len() * CHUNK_FINGERPRINT_BYTES;
    let mut cell_count = config.initial_cell_count;

    for round in 1..=config.max_rounds {
        let mut sketch = IbltSketch::new(cell_count, config.hash_function_count);
        for fingerprint in &sender_set {
            sketch.apply(*fingerprint, 1);
        }
        for fingerprint in &receiver_set {
            sketch.apply(*fingerprint, -1);
        }

        if let Some(decoded) = sketch.decode() {
            return Ok(ChunkSetReconciliation {
                receiver_missing: decoded.positive,
                receiver_stale: decoded.negative,
                rounds: round,
                cell_count,
                estimated_wire_bytes: cell_count * IBLT_CELL_WIRE_BYTES,
                naive_sender_fingerprint_bytes,
            });
        }

        cell_count = cell_count.checked_mul(2).ok_or_else(|| {
            ChunkingProfileError::InvalidChunkParameters(
                "IBLT cell count overflow during rateless growth".to_string(),
            )
        })?;
    }

    Err(ChunkingProfileError::InvalidChunkParameters(format!(
        "IBLT decode failed after {} rateless rounds from {} initial cells",
        config.max_rounds, config.initial_cell_count
    )))
}

fn recommended_cell_count(symmetric_difference_chunks: usize) -> usize {
    let scaled = symmetric_difference_chunks.max(1).saturating_mul(3);
    scaled
        .checked_next_power_of_two()
        .unwrap_or(usize::MAX)
        .max(8)
}

#[derive(Debug, Clone)]
struct IbltSketch {
    cells: Vec<IbltCell>,
    hash_function_count: usize,
}

impl IbltSketch {
    fn new(cell_count: usize, hash_function_count: usize) -> Self {
        Self {
            cells: vec![IbltCell::default(); cell_count],
            hash_function_count,
        }
    }

    fn apply(&mut self, fingerprint: ChunkFingerprint, sign: i64) {
        for position in iblt_positions(fingerprint, self.cells.len(), self.hash_function_count) {
            self.cells[position].apply(fingerprint, sign);
        }
    }

    fn decode(mut self) -> Option<DecodedIblt> {
        let mut queue = VecDeque::new();
        for index in 0..self.cells.len() {
            if self.cells[index].is_pure() {
                queue.push_back(index);
            }
        }

        let mut positive = BTreeSet::new();
        let mut negative = BTreeSet::new();

        while let Some(index) = queue.pop_front() {
            if !self.cells[index].is_pure() {
                continue;
            }

            let cell = self.cells[index];
            let fingerprint = ChunkFingerprint(cell.key_xor);
            let sign = cell.count.signum();

            if sign > 0 {
                positive.insert(fingerprint);
            } else {
                negative.insert(fingerprint);
            }

            for position in iblt_positions(fingerprint, self.cells.len(), self.hash_function_count)
            {
                self.cells[position].apply(fingerprint, -sign);
                if self.cells[position].is_pure() {
                    queue.push_back(position);
                }
            }
        }

        if self.cells.iter().all(IbltCell::is_empty) {
            Some(DecodedIblt { positive, negative })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct IbltCell {
    count: i64,
    key_xor: [u8; 32],
    checksum_xor: u64,
}

impl IbltCell {
    fn apply(&mut self, fingerprint: ChunkFingerprint, sign: i64) {
        self.count += sign;
        for (target, source) in self.key_xor.iter_mut().zip(fingerprint.0) {
            *target ^= source;
        }
        self.checksum_xor ^= fingerprint_checksum(fingerprint);
    }

    fn is_empty(&self) -> bool {
        self.count == 0 && self.key_xor == [0u8; 32] && self.checksum_xor == 0
    }

    fn is_pure(&self) -> bool {
        self.count.abs() == 1
            && self.checksum_xor == fingerprint_checksum(ChunkFingerprint(self.key_xor))
    }
}

#[derive(Debug, Clone)]
struct DecodedIblt {
    positive: BTreeSet<ChunkFingerprint>,
    negative: BTreeSet<ChunkFingerprint>,
}

fn iblt_positions(
    fingerprint: ChunkFingerprint,
    cell_count: usize,
    hash_function_count: usize,
) -> Vec<usize> {
    let target_positions = hash_function_count.min(cell_count);
    let mut positions = BTreeSet::new();
    let mut nonce = 0u64;

    while positions.len() < target_positions {
        positions.insert(fingerprint_index(fingerprint, nonce, cell_count));
        nonce += 1;
    }

    positions.into_iter().collect()
}

fn fingerprint_index(fingerprint: ChunkFingerprint, nonce: u64, cell_count: usize) -> usize {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync::atp::chunk-reconcile::iblt-index::v1");
    hasher.update(fingerprint.0);
    hasher.update(nonce.to_be_bytes());
    let digest = hasher.finalize();
    let raw = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    (raw % cell_count as u64) as usize
}

fn fingerprint_checksum(fingerprint: ChunkFingerprint) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync::atp::chunk-reconcile::iblt-checksum::v1");
    hasher.update(fingerprint.0);
    let digest = hasher.finalize();
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

const CHUNK_FINGERPRINT_BYTES: usize = 32;
const IBLT_CELL_WIRE_BYTES: usize = 8 + CHUNK_FINGERPRINT_BYTES + 8;

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(seed: u64) -> ChunkFingerprint {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync::atp::chunk-reconcile::test-fingerprint::v1");
        hasher.update(seed.to_be_bytes());
        ChunkFingerprint(hasher.finalize().into())
    }

    #[test]
    fn reconciles_k_diffs_with_delta_scaled_wire_bytes() {
        let mut sender = Vec::new();
        let mut receiver = Vec::new();
        for seed in 0..1_000 {
            let id = fingerprint(seed);
            sender.push(id);
            receiver.push(id);
        }
        for seed in 1_000..1_007 {
            sender.push(fingerprint(seed));
        }
        for seed in 2_000..2_003 {
            receiver.push(fingerprint(seed));
        }

        let result = reconcile_chunk_sets(
            sender,
            receiver,
            &RatelessIbltConfig {
                initial_cell_count: 32,
                max_rounds: 8,
                hash_function_count: 3,
            },
        )
        .expect("IBLT should peel small deltas");

        assert_eq!(result.receiver_missing.len(), 7);
        assert_eq!(result.receiver_stale.len(), 3);
        assert!(result.estimated_wire_bytes < result.naive_sender_fingerprint_bytes);
    }

    #[test]
    fn undersized_decode_grows_until_success() {
        let sender: Vec<_> = (0..48).map(fingerprint).collect();
        let receiver: Vec<_> = (0..24).map(fingerprint).collect();

        let result = reconcile_chunk_sets(
            sender,
            receiver,
            &RatelessIbltConfig {
                initial_cell_count: 1,
                max_rounds: 10,
                hash_function_count: 3,
            },
        )
        .expect("rateless growth should eventually decode");

        assert!(result.rounds > 1);
        assert_eq!(result.receiver_missing.len(), 24);
        assert!(result.receiver_stale.is_empty());
    }

    #[test]
    fn delta_estimate_reports_exact_symmetric_difference() {
        let sender = [fingerprint(1), fingerprint(2), fingerprint(3)];
        let receiver = [fingerprint(2), fingerprint(4)];
        let estimate = estimate_chunk_set_delta(sender, receiver);

        assert_eq!(estimate.sender_unique_chunks, 3);
        assert_eq!(estimate.receiver_unique_chunks, 2);
        assert_eq!(estimate.shared_chunks, 1);
        assert_eq!(estimate.receiver_missing_chunks, 2);
        assert_eq!(estimate.receiver_stale_chunks, 1);
        assert_eq!(estimate.symmetric_difference_chunks, 3);
        assert_eq!(estimate.naive_sender_fingerprint_bytes, 96);
        assert!(estimate.recommended_initial_cells >= 8);
    }

    #[test]
    fn reconcile_cdc_chunks_uses_content_hash_identity() {
        let shared = CdcChunkData {
            byte_offset: 0,
            size_bytes: 4,
            content_hash: fingerprint(10).0,
        };
        let sender_only = CdcChunkData {
            byte_offset: 4,
            size_bytes: 4,
            content_hash: fingerprint(11).0,
        };

        let result = reconcile_cdc_chunks(
            &[shared.clone(), sender_only.clone()],
            &[shared],
            &RatelessIbltConfig::default(),
        )
        .expect("CDC chunk reconciliation should decode");

        assert_eq!(
            result.receiver_missing,
            BTreeSet::from([ChunkFingerprint(sender_only.content_hash)])
        );
        assert!(result.receiver_stale.is_empty());
    }
}
