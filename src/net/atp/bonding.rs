//! ATP channel-bonding transfer descriptors.
//!
//! Phase A is intentionally source-first: before a donor is allowed to serve
//! symbols for a bonded transfer, its local byte view must match the descriptor
//! exactly. Any index, path, size, SHA-256, or Merkle-root mismatch is a hard
//! validation error.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::net::atp::transport_common::{flat_merkle_root_from_slices, hex_encode};
use crate::types::symbol::ObjectId as RqObjectId;

/// Logical transfer descriptor shared by the primary sender and bonded donors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondTransferDescriptor {
    /// Stable transfer identifier used by the RQ object-id derivation.
    pub transfer_id: String,
    /// Name of the transfer root.
    pub root_name: String,
    /// Whether the root is a directory.
    pub is_directory: bool,
    /// Total bytes across all entries.
    pub total_bytes: u64,
    /// Lowercase hex Merkle root over the same flat object graph as RQ/TCP/QUIC manifests.
    pub merkle_root_hex: String,
    /// Transfer entries in stable manifest order.
    pub entries: Vec<BondTransferEntry>,
    /// RaptorQ symbol size advertised for the bonded transfer.
    pub symbol_size: u16,
    /// Maximum source-block size for the bonded transfer.
    pub max_block_size: u64,
}

impl BondTransferDescriptor {
    /// Build a descriptor from already-known entry digests.
    pub fn new(
        transfer_id: impl Into<String>,
        root_name: impl Into<String>,
        is_directory: bool,
        merkle_root_hex: impl Into<String>,
        entries: Vec<BondTransferEntry>,
        symbol_size: u16,
        max_block_size: u64,
    ) -> Result<Self, BondingError> {
        let total_bytes = entries.iter().map(|entry| entry.size).sum();
        let descriptor = Self {
            transfer_id: transfer_id.into(),
            root_name: root_name.into(),
            is_directory,
            total_bytes,
            merkle_root_hex: merkle_root_hex.into(),
            entries,
            symbol_size,
            max_block_size,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Build a deterministic descriptor from in-memory byte slices.
    ///
    /// Streaming callers should compute the same entry digests and Merkle root
    /// while walking files, then call [`Self::new`]. This helper exists for
    /// tests, fixtures, and callers that already hold the content.
    pub fn from_byte_slices(
        transfer_id: impl Into<String>,
        root_name: impl Into<String>,
        is_directory: bool,
        symbol_size: u16,
        max_block_size: u64,
        entries: &[(&str, &[u8])],
    ) -> Result<Self, BondingError> {
        let merkle_root_hex = flat_merkle_root_from_slices(entries.iter().copied());
        let entries = entries
            .iter()
            .enumerate()
            .map(|(index, (rel_path, bytes))| BondTransferEntry {
                index: index as u32,
                rel_path: (*rel_path).to_string(),
                size: bytes.len() as u64,
                sha256_hex: sha256_hex(bytes),
            })
            .collect();
        Self::new(
            transfer_id,
            root_name,
            is_directory,
            merkle_root_hex,
            entries,
            symbol_size,
            max_block_size,
        )
    }

    /// Validate structural invariants before a descriptor is accepted.
    pub fn validate(&self) -> Result<(), BondingError> {
        if self.transfer_id.is_empty() {
            return Err(BondingError::EmptyTransferId);
        }
        if self.root_name.is_empty() {
            return Err(BondingError::EmptyRootName);
        }
        if self.symbol_size == 0 {
            return Err(BondingError::InvalidSymbolSize);
        }
        if self.max_block_size == 0 {
            return Err(BondingError::InvalidMaxBlockSize);
        }
        if !is_lower_hex_64(&self.merkle_root_hex) {
            return Err(BondingError::InvalidMerkleRoot {
                merkle_root_hex: self.merkle_root_hex.clone(),
            });
        }

        let mut computed_total = 0_u64;
        for (position, entry) in self.entries.iter().enumerate() {
            let expected_index = position as u32;
            if entry.index != expected_index {
                return Err(BondingError::EntryIndexMismatch {
                    expected: expected_index,
                    actual: entry.index,
                });
            }
            if entry.rel_path.is_empty() {
                return Err(BondingError::EmptyRelPath { index: entry.index });
            }
            if !is_lower_hex_64(&entry.sha256_hex) {
                return Err(BondingError::InvalidEntrySha {
                    index: entry.index,
                    sha256_hex: entry.sha256_hex.clone(),
                });
            }
            computed_total = computed_total.saturating_add(entry.size);
        }

        if self.total_bytes != computed_total {
            return Err(BondingError::TotalBytesMismatch {
                declared: self.total_bytes,
                computed: computed_total,
            });
        }
        Ok(())
    }

    /// Verify a donor's local byte view against this descriptor.
    ///
    /// This is the fail-closed gate for bonded serving: donors that cannot
    /// prove the exact same entry list, sizes, per-entry SHA-256 values, and
    /// flat Merkle root are rejected before they can contribute symbols.
    pub fn verify_donor_byte_match(
        &self,
        proof: &BondDonorByteMatchProof,
    ) -> Result<(), BondingError> {
        self.validate()?;
        proof.validate()?;

        if proof.merkle_root_hex != self.merkle_root_hex {
            return Err(BondingError::ProofMerkleRootMismatch {
                expected: self.merkle_root_hex.clone(),
                actual: proof.merkle_root_hex.clone(),
            });
        }
        if proof.entries.len() != self.entries.len() {
            return Err(BondingError::ProofEntryCountMismatch {
                expected: self.entries.len(),
                actual: proof.entries.len(),
            });
        }

        for (position, (expected, actual)) in self.entries.iter().zip(&proof.entries).enumerate() {
            if actual.index != expected.index {
                return Err(BondingError::ProofEntryIndexMismatch {
                    position,
                    expected: expected.index,
                    actual: actual.index,
                });
            }
            if actual.rel_path != expected.rel_path {
                return Err(BondingError::ProofEntryPathMismatch {
                    index: expected.index,
                    expected: expected.rel_path.clone(),
                    actual: actual.rel_path.clone(),
                });
            }
            if actual.size != expected.size {
                return Err(BondingError::ProofEntrySizeMismatch {
                    index: expected.index,
                    expected: expected.size,
                    actual: actual.size,
                });
            }
            if actual.sha256_hex != expected.sha256_hex {
                return Err(BondingError::ProofEntryShaMismatch {
                    index: expected.index,
                    expected: expected.sha256_hex.clone(),
                    actual: actual.sha256_hex.clone(),
                });
            }
        }

        Ok(())
    }

    /// Derive the RaptorQ object id for a descriptor entry.
    #[must_use]
    pub fn entry_object_id(&self, index: u32) -> RqObjectId {
        rq_entry_object_id(&self.transfer_id, index)
    }
}

/// One file-like object in a bonded transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondTransferEntry {
    /// Stable descriptor index.
    pub index: u32,
    /// Path relative to the transfer root.
    pub rel_path: String,
    /// Entry length in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256 of the entry content.
    pub sha256_hex: String,
}

/// Donor-side proof that its local bytes match the descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondDonorByteMatchProof {
    /// Lowercase hex Merkle root computed from the donor's local entries.
    pub merkle_root_hex: String,
    /// Donor entries in descriptor order.
    pub entries: Vec<BondDonorEntryProof>,
}

impl BondDonorByteMatchProof {
    /// Build a donor proof from in-memory byte slices.
    pub fn from_byte_slices(entries: &[(&str, &[u8])]) -> Result<Self, BondingError> {
        let proof = Self {
            merkle_root_hex: flat_merkle_root_from_slices(entries.iter().copied()),
            entries: entries
                .iter()
                .enumerate()
                .map(|(index, (rel_path, bytes))| BondDonorEntryProof {
                    index: index as u32,
                    rel_path: (*rel_path).to_string(),
                    size: bytes.len() as u64,
                    sha256_hex: sha256_hex(bytes),
                })
                .collect(),
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Validate proof shape before comparing it to a descriptor.
    pub fn validate(&self) -> Result<(), BondingError> {
        if !is_lower_hex_64(&self.merkle_root_hex) {
            return Err(BondingError::InvalidProofMerkleRoot {
                merkle_root_hex: self.merkle_root_hex.clone(),
            });
        }

        for (position, entry) in self.entries.iter().enumerate() {
            let expected_index = position as u32;
            if entry.index != expected_index {
                return Err(BondingError::ProofEntryIndexMismatch {
                    position,
                    expected: expected_index,
                    actual: entry.index,
                });
            }
            if entry.rel_path.is_empty() {
                return Err(BondingError::EmptyProofRelPath { index: entry.index });
            }
            if !is_lower_hex_64(&entry.sha256_hex) {
                return Err(BondingError::InvalidProofEntrySha {
                    index: entry.index,
                    sha256_hex: entry.sha256_hex.clone(),
                });
            }
        }
        Ok(())
    }
}

/// One donor-side entry digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondDonorEntryProof {
    /// Stable descriptor index.
    pub index: u32,
    /// Path relative to the transfer root.
    pub rel_path: String,
    /// Entry length in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256 of the donor's local entry content.
    pub sha256_hex: String,
}

/// Derive the per-entry RaptorQ object id from the transfer id and entry index.
///
/// This mirrors the existing RQ transport derivation exactly so channel-bonded
/// donors and the primary sender address the same fountain object without extra
/// signaling.
#[must_use]
pub fn rq_entry_object_id(transfer_id: &str, index: u32) -> RqObjectId {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.entry-object-id.v1\0");
    hasher.update(transfer_id.as_bytes());
    hasher.update(index.to_be_bytes());
    let digest = hasher.finalize();
    let high = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    let low = u64::from_be_bytes([
        digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
        digest[15],
    ]);
    RqObjectId::new(high, low)
}

/// Bonding descriptor validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BondingError {
    /// Descriptor has no transfer id.
    #[error("bond transfer descriptor has empty transfer_id")]
    EmptyTransferId,
    /// Descriptor has no root name.
    #[error("bond transfer descriptor has empty root_name")]
    EmptyRootName,
    /// Descriptor cannot advertise zero-sized symbols.
    #[error("bond transfer descriptor has zero symbol_size")]
    InvalidSymbolSize,
    /// Descriptor cannot advertise zero-sized source blocks.
    #[error("bond transfer descriptor has zero max_block_size")]
    InvalidMaxBlockSize,
    /// Descriptor Merkle root is not lowercase 64-character hex.
    #[error("bond transfer descriptor has invalid merkle_root_hex {merkle_root_hex:?}")]
    InvalidMerkleRoot {
        /// Invalid Merkle root.
        merkle_root_hex: String,
    },
    /// Descriptor entry index does not match manifest order.
    #[error("bond transfer descriptor entry index mismatch: expected {expected}, actual {actual}")]
    EntryIndexMismatch {
        /// Expected index.
        expected: u32,
        /// Actual index.
        actual: u32,
    },
    /// Descriptor entry has no transfer-relative path.
    #[error("bond transfer descriptor entry {index} has empty rel_path")]
    EmptyRelPath {
        /// Entry index.
        index: u32,
    },
    /// Descriptor entry SHA-256 is not lowercase 64-character hex.
    #[error("bond transfer descriptor entry {index} has invalid sha256_hex {sha256_hex:?}")]
    InvalidEntrySha {
        /// Entry index.
        index: u32,
        /// Invalid SHA-256 value.
        sha256_hex: String,
    },
    /// Descriptor total byte count does not match entries.
    #[error(
        "bond transfer descriptor total bytes mismatch: declared {declared}, computed {computed}"
    )]
    TotalBytesMismatch {
        /// Declared total bytes.
        declared: u64,
        /// Computed total bytes.
        computed: u64,
    },
    /// Donor proof Merkle root is not lowercase 64-character hex.
    #[error("bond donor proof has invalid merkle_root_hex {merkle_root_hex:?}")]
    InvalidProofMerkleRoot {
        /// Invalid Merkle root.
        merkle_root_hex: String,
    },
    /// Donor proof entry index does not match proof order.
    #[error(
        "bond donor proof entry index mismatch at position {position}: expected {expected}, actual {actual}"
    )]
    ProofEntryIndexMismatch {
        /// Proof vector position.
        position: usize,
        /// Expected index.
        expected: u32,
        /// Actual index.
        actual: u32,
    },
    /// Donor proof entry has no transfer-relative path.
    #[error("bond donor proof entry {index} has empty rel_path")]
    EmptyProofRelPath {
        /// Entry index.
        index: u32,
    },
    /// Donor proof entry SHA-256 is not lowercase 64-character hex.
    #[error("bond donor proof entry {index} has invalid sha256_hex {sha256_hex:?}")]
    InvalidProofEntrySha {
        /// Entry index.
        index: u32,
        /// Invalid SHA-256 value.
        sha256_hex: String,
    },
    /// Donor proof Merkle root does not match the descriptor.
    #[error("bond donor proof merkle root mismatch: expected {expected}, actual {actual}")]
    ProofMerkleRootMismatch {
        /// Descriptor Merkle root.
        expected: String,
        /// Donor proof Merkle root.
        actual: String,
    },
    /// Donor proof entry count does not match the descriptor.
    #[error("bond donor proof entry count mismatch: expected {expected}, actual {actual}")]
    ProofEntryCountMismatch {
        /// Descriptor entry count.
        expected: usize,
        /// Donor proof entry count.
        actual: usize,
    },
    /// Donor proof path does not match the descriptor.
    #[error(
        "bond donor proof path mismatch at entry {index}: expected {expected:?}, actual {actual:?}"
    )]
    ProofEntryPathMismatch {
        /// Entry index.
        index: u32,
        /// Descriptor path.
        expected: String,
        /// Donor proof path.
        actual: String,
    },
    /// Donor proof size does not match the descriptor.
    #[error(
        "bond donor proof size mismatch at entry {index}: expected {expected}, actual {actual}"
    )]
    ProofEntrySizeMismatch {
        /// Entry index.
        index: u32,
        /// Descriptor size.
        expected: u64,
        /// Donor proof size.
        actual: u64,
    },
    /// Donor proof SHA-256 does not match the descriptor.
    #[error(
        "bond donor proof sha256 mismatch at entry {index}: expected {expected}, actual {actual}"
    )]
    ProofEntryShaMismatch {
        /// Entry index.
        index: u32,
        /// Descriptor SHA-256.
        expected: String,
        /// Donor proof SHA-256.
        actual: String,
    },
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<(&'static str, &'static [u8])> {
        vec![("a.txt", b"alpha"), ("dir/b.txt", b"bravo")]
    }

    #[test]
    fn identical_bytes_build_identical_descriptors() {
        let entries = sample_entries();
        let first = BondTransferDescriptor::from_byte_slices(
            "transfer-1",
            "root",
            true,
            1280,
            1 << 20,
            &entries,
        )
        .expect("descriptor");
        let second = BondTransferDescriptor::from_byte_slices(
            "transfer-1",
            "root",
            true,
            1280,
            1 << 20,
            &entries,
        )
        .expect("descriptor");

        assert_eq!(first, second);
    }

    #[test]
    fn donor_byte_match_accepts_identical_entries() {
        let entries = sample_entries();
        let descriptor = BondTransferDescriptor::from_byte_slices(
            "transfer-1",
            "root",
            true,
            1280,
            1 << 20,
            &entries,
        )
        .expect("descriptor");
        let proof = BondDonorByteMatchProof::from_byte_slices(&entries).expect("proof");

        descriptor
            .verify_donor_byte_match(&proof)
            .expect("matching proof");
    }

    #[test]
    fn donor_byte_match_rejects_mismatched_content() {
        let descriptor_entries = sample_entries();
        let donor_entries = vec![("a.txt", b"alpha" as &[u8]), ("dir/b.txt", b"tampered")];
        let descriptor = BondTransferDescriptor::from_byte_slices(
            "transfer-1",
            "root",
            true,
            1280,
            1 << 20,
            &descriptor_entries,
        )
        .expect("descriptor");
        let proof = BondDonorByteMatchProof::from_byte_slices(&donor_entries).expect("proof");

        let err = descriptor
            .verify_donor_byte_match(&proof)
            .expect_err("tampered donor must fail closed");

        assert!(matches!(err, BondingError::ProofMerkleRootMismatch { .. }));
    }

    #[test]
    fn donor_byte_match_rejects_same_root_but_mismatched_entry_sha() {
        let entries = sample_entries();
        let descriptor = BondTransferDescriptor::from_byte_slices(
            "transfer-1",
            "root",
            true,
            1280,
            1 << 20,
            &entries,
        )
        .expect("descriptor");
        let mut proof = BondDonorByteMatchProof::from_byte_slices(&entries).expect("proof");
        proof.entries[1].sha256_hex = sha256_hex(b"tampered");

        let err = descriptor
            .verify_donor_byte_match(&proof)
            .expect_err("entry sha mismatch must fail closed");

        assert!(matches!(err, BondingError::ProofEntryShaMismatch { .. }));
    }

    #[test]
    fn descriptor_rejects_uppercase_sha() {
        let err = BondTransferDescriptor::new(
            "transfer-1",
            "root",
            true,
            "ab".repeat(32),
            vec![BondTransferEntry {
                index: 0,
                rel_path: "a.txt".to_string(),
                size: 1,
                sha256_hex: "AA".repeat(32),
            }],
            1280,
            1 << 20,
        )
        .expect_err("uppercase digest must be rejected");

        assert!(matches!(err, BondingError::InvalidEntrySha { .. }));
    }

    #[test]
    fn entry_object_id_uses_rq_derivation() {
        let descriptor = BondTransferDescriptor::from_byte_slices(
            "transfer-1",
            "root",
            true,
            1280,
            1 << 20,
            &sample_entries(),
        )
        .expect("descriptor");

        assert_eq!(
            descriptor.entry_object_id(1),
            rq_entry_object_id("transfer-1", 1)
        );
        assert_ne!(
            descriptor.entry_object_id(0),
            rq_entry_object_id("transfer-1", 1)
        );
    }
}
