//! An explicit, versioned commitment to a manifest's chunk descriptors.
//!
//! The legacy [`MerkleRoot`](super::manifest::MerkleRoot) calculation does not
//! include chunk boundaries. Keep its wire format and existing roots unchanged;
//! callers that authorize bytes using chunk hashes must pin this additional
//! commitment through an authenticated application channel instead.
//!
//! Computing a commitment from an untrusted manifest is NOT authentication. The
//! receiver must compare against a value previously obtained from its trusted
//! producer. This format binds the legacy root, manifest version, ordered roots,
//! object identities/kinds/sizes/content hashes, and every canonical chunk field.
//! Profile-only `ChunkMetadata` and other fields omitted by the legacy root are
//! not independently authenticated here. This is not a signature or permission.

use super::manifest::{Manifest, ManifestError};
use super::object::ObjectId;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"asupersync.atp.manifest-chunk-commitment.v1\0";

/// A trusted supplement to a legacy manifest root for chunk-based verification.
///
/// The 32 bytes are SHA-256 over the versioned format documented by this module.
/// They are separate from `Manifest::merkle_root`; no legacy root is rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestChunkCommitment([u8; 32]);

/// Failure to construct or verify a chunk commitment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestChunkCommitmentError {
    /// Structural validation or the legacy root check failed.
    #[error("invalid manifest: {0}")]
    InvalidManifest(ManifestError),
    /// A manifest record is stored under another object's key.
    #[error("manifest object identity differs from its map key")]
    ObjectIdentityMismatch,
    /// A collection cannot be represented in this format.
    #[error("manifest collection length exceeds the commitment format")]
    CountOverflow,
    /// The manifest is not the one authorized by the expected commitment.
    #[error("manifest chunk commitment mismatch")]
    Mismatch,
}

impl ManifestChunkCommitment {
    /// Import commitment bytes obtained through a trusted application channel.
    /// This does not itself establish that the bytes or their source are trusted.
    #[must_use]
    pub const fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    /// Export the commitment for authenticated transport or trusted persistence.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.0
    }

    /// Commit a structurally valid manifest without changing its legacy root.
    ///
    /// Hashing streams the descriptors with constant auxiliary space after
    /// existing manifest validation; it never concatenates the chunk payloads.
    /// No input-size or complexity bound is added to `Manifest::validate`.
    pub fn from_manifest(manifest: &Manifest) -> Result<Self, ManifestChunkCommitmentError> {
        manifest
            .validate()
            .map_err(ManifestChunkCommitmentError::InvalidManifest)?;
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(manifest.version.0.to_be_bytes());
        hasher.update(manifest.merkle_root.hash());
        hash_count(&mut hasher, manifest.roots.len())?;
        for root in &manifest.roots {
            hash_object_id(&mut hasher, root);
        }
        hash_count(&mut hasher, manifest.objects.len())?;
        for (id, object) in &manifest.objects {
            if &object.id != id {
                return Err(ManifestChunkCommitmentError::ObjectIdentityMismatch);
            }
            hash_object_id(&mut hasher, id);
            hasher.update([object.kind as u8]);
            match object.size_bytes {
                Some(size) => {
                    hasher.update([1]);
                    hasher.update(size.to_be_bytes());
                }
                None => hasher.update([0]),
            }
            match object.content_hash {
                Some(hash) => {
                    hasher.update([1]);
                    hasher.update(hash);
                }
                None => hasher.update([0]),
            }
            hash_count(&mut hasher, object.chunk_boundaries.len())?;
            for chunk in &object.chunk_boundaries {
                hasher.update(chunk.index.to_be_bytes());
                hasher.update(chunk.byte_offset.to_be_bytes());
                hasher.update(chunk.size_bytes.to_be_bytes());
                hasher.update(chunk.content_hash);
                hasher.update([chunk.strategy as u8]);
            }
        }
        Ok(Self(hasher.finalize().into()))
    }

    /// Validate and compare against this independently trusted commitment.
    /// A mismatched digest never falls back to accepting only the legacy root.
    pub fn verify(&self, manifest: &Manifest) -> Result<(), ManifestChunkCommitmentError> {
        let actual = Self::from_manifest(manifest)?;
        if actual == *self {
            Ok(())
        } else {
            Err(ManifestChunkCommitmentError::Mismatch)
        }
    }
}

fn hash_count(hasher: &mut Sha256, count: usize) -> Result<(), ManifestChunkCommitmentError> {
    let count = u64::try_from(count).map_err(|_| ManifestChunkCommitmentError::CountOverflow)?;
    hasher.update(count.to_be_bytes());
    Ok(())
}

fn hash_object_id(hasher: &mut Sha256, id: &ObjectId) {
    // Equal hash bytes in the content and manifest namespaces are not the same ID.
    hasher.update([u8::from(id.is_content_addressed())]);
    hasher.update(id.hash_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::manifest::{ChunkBoundary, ChunkStrategy, MerkleRoot};
    use crate::atp::object::{ContentId, MetadataPolicy, Object, ObjectGraph};

    fn chunk(index: u32, offset: u64, bytes: &[u8]) -> ChunkBoundary {
        ChunkBoundary {
            index,
            byte_offset: offset,
            size_bytes: bytes.len() as u64,
            content_hash: Sha256::digest(bytes).into(),
            strategy: ChunkStrategy::FixedSize,
            metadata: None,
        }
    }

    fn legacy_root(manifest: &Manifest) -> MerkleRoot {
        MerkleRoot::from_manifest_components(
            &manifest.objects,
            &manifest.chunk_plan,
            &manifest.raptorq_layout,
            &manifest.compression_policy,
            &manifest.encryption_policy,
            &manifest.capability_policy,
            &manifest.transform_order,
            &manifest.transform_proof_policy,
            &manifest.repair_groups,
        )
    }

    fn sample() -> Manifest {
        let mut graph = ObjectGraph::new();
        graph.add_root(Object::file(b"abcdefgh".to_vec())).unwrap();
        let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
        manifest.objects.values_mut().next().unwrap().chunk_boundaries = vec![
            chunk(0, 0, b"abcd"),
            chunk(1, 4, b"efgh"),
        ];
        manifest.merkle_root = legacy_root(&manifest);
        manifest.validate().unwrap();
        manifest
    }

    #[test]
    fn roundtrip_preserves_the_legacy_manifest_and_root() {
        let manifest = sample();
        let original = manifest.clone();
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        assert_eq!(ManifestChunkCommitment::new(*expected.hash()), expected);
        expected.verify(&manifest).unwrap();
        assert_eq!(manifest, original);
        assert_eq!(legacy_root(&manifest), original.merkle_root);
    }

    #[test]
    fn every_canonical_chunk_field_is_bound_even_when_the_legacy_root_is_unchanged() {
        let original = sample();
        let expected = ManifestChunkCommitment::from_manifest(&original).unwrap();
        for mutation in 0..5 {
            let mut tampered = original.clone();
            let chunk = &mut tampered.objects.values_mut().next().unwrap().chunk_boundaries[1];
            match mutation {
                0 => chunk.index += 1,
                1 => chunk.byte_offset += 1,
                2 => chunk.size_bytes -= 1,
                3 => chunk.content_hash[0] ^= 1,
                4 => chunk.strategy = ChunkStrategy::ObjectSpecific,
                _ => unreachable!(),
            }
            tampered.validate().unwrap();
            assert_eq!(legacy_root(&tampered), original.merkle_root);
            assert_eq!(expected.verify(&tampered), Err(ManifestChunkCommitmentError::Mismatch));
        }
    }

    #[test]
    fn chunk_insertion_deletion_and_empty_ledger_cannot_reuse_a_commitment() {
        let original = sample();
        let expected = ManifestChunkCommitment::from_manifest(&original).unwrap();
        for mutation in 0..3 {
            let mut tampered = original.clone();
            let chunks = &mut tampered.objects.values_mut().next().unwrap().chunk_boundaries;
            match mutation {
                0 => { chunks.pop(); }
                1 => chunks.clear(),
                2 => chunks.push(chunk(2, 8, b"tail")),
                _ => unreachable!(),
            }
            tampered.validate().unwrap();
            assert_eq!(expected.verify(&tampered), Err(ManifestChunkCommitmentError::Mismatch));
        }
    }

    #[test]
    fn structural_rejection_precedes_commitment_acceptance() {
        let mut manifest = sample();
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        manifest.objects.values_mut().next().unwrap().chunk_boundaries.reverse();
        assert!(matches!(expected.verify(&manifest),
            Err(ManifestChunkCommitmentError::InvalidManifest(_))));
    }

    #[test]
    fn chunk_ledgers_are_bound_to_their_own_objects() {
        let mut graph = ObjectGraph::new();
        let first = Object::file(b"abcdefgh".to_vec());
        let second = Object::file(b"ijklmnop".to_vec());
        let first_id = first.id.clone();
        let second_id = second.id.clone();
        graph.add_root(first).unwrap();
        graph.add_root(second).unwrap();
        let mut manifest = Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap();
        let a = vec![chunk(0, 0, b"abcdefgh")];
        let b = vec![chunk(0, 0, b"ijklmnop")];
        manifest.objects.get_mut(&first_id).unwrap().chunk_boundaries = a.clone();
        manifest.objects.get_mut(&second_id).unwrap().chunk_boundaries = b.clone();
        manifest.merkle_root = legacy_root(&manifest);
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        manifest.objects.get_mut(&first_id).unwrap().chunk_boundaries = b;
        manifest.objects.get_mut(&second_id).unwrap().chunk_boundaries = a;
        manifest.validate().unwrap();
        assert_eq!(expected.verify(&manifest), Err(ManifestChunkCommitmentError::Mismatch));
    }

    #[test]
    fn inconsistent_object_identity_cannot_be_committed() {
        let mut manifest = sample();
        manifest.objects.values_mut().next().unwrap().id =
            ObjectId::content(ContentId::from_bytes(b"another object"));
        manifest.validate().unwrap();
        assert_eq!(ManifestChunkCommitment::from_manifest(&manifest),
            Err(ManifestChunkCommitmentError::ObjectIdentityMismatch));
    }

    #[test]
    fn changed_whole_object_hash_cannot_reuse_a_chunk_commitment() {
        let mut manifest = sample();
        let expected = ManifestChunkCommitment::from_manifest(&manifest).unwrap();
        manifest.objects.values_mut().next().unwrap().content_hash = None;
        manifest.merkle_root = legacy_root(&manifest);
        manifest.validate().unwrap();
        assert_eq!(expected.verify(&manifest), Err(ManifestChunkCommitmentError::Mismatch));
    }
}
