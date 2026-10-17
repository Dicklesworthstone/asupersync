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
#[path = "manifest_chunk_commitment_inline_tests.rs"]
mod tests;
