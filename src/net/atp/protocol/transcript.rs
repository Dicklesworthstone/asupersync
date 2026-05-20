//! ATP Transcript Generation
//!
//! Provides canonical transcript hashing for ATP frames to enable deterministic
//! replay, verification, and protocol debugging. Transcripts are stable across
//! platforms and include all protocol-relevant fields.

use crate::net::atp::protocol::frames::Frame;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Canonical transcript hasher for ATP sessions
#[derive(Debug, Clone)]
pub struct TranscriptHasher {
    hasher: Sha256,
    frame_count: u64,
}

impl TranscriptHasher {
    /// Create a new transcript hasher
    pub fn new() -> Self {
        let mut hasher = Sha256::new();

        // Initialize with protocol identifier
        hasher.update(b"ATP-TRANSCRIPT-V1\x00");

        Self {
            hasher,
            frame_count: 0,
        }
    }

    /// Add a frame to the transcript
    ///
    /// Only includes protocol-relevant fields in canonical order:
    /// - Frame sequence number
    /// - Protocol version
    /// - Frame type
    /// - Payload length
    /// - Extensions (sorted by ID)
    /// - Payload hash (not full payload for efficiency)
    pub fn update_frame(&mut self, frame: &Frame) {
        // Frame sequence number (ensures ordering)
        self.hasher.update(self.frame_count.to_le_bytes());
        self.frame_count += 1;

        // Protocol version
        self.hasher.update(frame.header.version.0.to_le_bytes());

        // Frame type (as u16)
        self.hasher
            .update((frame.header.frame_type as u16).to_le_bytes());

        // Payload length
        self.hasher
            .update(frame.header.payload_length.value().to_le_bytes());

        // Extensions (sorted by ID for canonical ordering)
        let mut sorted_extensions: BTreeMap<u16, &Vec<u8>> = BTreeMap::new();
        for (id, data) in &frame.header.extensions {
            sorted_extensions.insert(*id, data);
        }

        // Extension count
        self.hasher
            .update((sorted_extensions.len() as u32).to_le_bytes());

        // Extension data (in sorted order)
        for (ext_id, ext_data) in sorted_extensions {
            self.hasher.update(ext_id.to_le_bytes());
            self.hasher.update((ext_data.len() as u32).to_le_bytes());
            self.hasher.update(ext_data);
        }

        // Payload hash (not full payload to avoid large memory usage)
        let payload_hash = Sha256::digest(&frame.payload);
        self.hasher.update(payload_hash);
    }

    /// Get the current transcript hash
    pub fn current_hash(&self) -> TranscriptHash {
        TranscriptHash(self.hasher.clone().finalize().into())
    }

    /// Finalize and get the transcript hash
    pub fn finalize(self) -> TranscriptHash {
        TranscriptHash(self.hasher.finalize().into())
    }

    /// Get the number of frames processed
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    /// Create a checkpoint that can be used to verify partial transcripts
    pub fn checkpoint(&self) -> TranscriptCheckpoint {
        TranscriptCheckpoint {
            hash: self.current_hash(),
            frame_count: self.frame_count,
        }
    }
}

impl Default for TranscriptHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// A 256-bit transcript hash
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TranscriptHash(pub [u8; 32]);

impl TranscriptHash {
    /// Get hash as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> Result<Self, TranscriptError> {
        let bytes = hex::decode(hex)
            .map_err(|_| TranscriptError::InvalidHash("invalid hex encoding".to_string()))?;

        if bytes.len() != 32 {
            return Err(TranscriptError::InvalidHash(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(TranscriptHash(hash))
    }

    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for TranscriptHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Transcript checkpoint for partial verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptCheckpoint {
    /// Hash at this checkpoint
    pub hash: TranscriptHash,
    /// Number of frames processed at checkpoint
    pub frame_count: u64,
}

/// Session transcript that accumulates frames and provides verification
#[derive(Debug, Clone)]
pub struct SessionTranscript {
    hasher: TranscriptHasher,
    checkpoints: Vec<TranscriptCheckpoint>,
}

impl SessionTranscript {
    /// Create a new session transcript
    pub fn new() -> Self {
        Self {
            hasher: TranscriptHasher::new(),
            checkpoints: Vec::new(),
        }
    }

    /// Add a frame to the transcript
    pub fn add_frame(&mut self, frame: &Frame) {
        self.hasher.update_frame(frame);
    }

    /// Create a checkpoint at the current state
    pub fn checkpoint(&mut self) -> TranscriptCheckpoint {
        let checkpoint = self.hasher.checkpoint();
        self.checkpoints.push(checkpoint.clone());
        checkpoint
    }

    /// Verify that current state matches expected hash
    pub fn verify_hash(&self, expected: &TranscriptHash) -> bool {
        &self.hasher.current_hash() == expected
    }

    /// Get all checkpoints
    pub fn checkpoints(&self) -> &[TranscriptCheckpoint] {
        &self.checkpoints
    }

    /// Get current hash
    pub fn current_hash(&self) -> TranscriptHash {
        self.hasher.current_hash()
    }

    /// Get frame count
    pub fn frame_count(&self) -> u64 {
        self.hasher.frame_count()
    }

    /// Finalize transcript and get final hash
    pub fn finalize(self) -> TranscriptHash {
        self.hasher.finalize()
    }
}

impl Default for SessionTranscript {
    fn default() -> Self {
        Self::new()
    }
}

/// Transcript-related errors
#[derive(Debug, thiserror::Error)]
pub enum TranscriptError {
    /// Transcript hash encoding or length is invalid.
    #[error("invalid transcript hash: {0}")]
    InvalidHash(String),

    /// Transcript hash did not match the expected checkpoint.
    #[error("transcript verification failed: expected {expected}, got {actual}")]
    VerificationFailed {
        /// Expected transcript hash.
        expected: TranscriptHash,
        /// Actual transcript hash.
        actual: TranscriptHash,
    },

    /// Transcript checkpoint sequence did not match expectations.
    #[error("frame sequence error: expected frame {expected}, got {actual}")]
    SequenceError {
        /// Expected frame count.
        expected: u64,
        /// Actual frame count.
        actual: u64,
    },
}

/// Utility for verifying transcript integrity between sessions
pub struct TranscriptVerifier {
    expected_checkpoints: Vec<TranscriptCheckpoint>,
    current_index: usize,
}

impl TranscriptVerifier {
    /// Create a verifier with expected checkpoints
    pub fn new(expected_checkpoints: Vec<TranscriptCheckpoint>) -> Self {
        Self {
            expected_checkpoints,
            current_index: 0,
        }
    }

    /// Verify a checkpoint against expected sequence
    pub fn verify_checkpoint(
        &mut self,
        checkpoint: &TranscriptCheckpoint,
    ) -> Result<(), TranscriptError> {
        if self.current_index >= self.expected_checkpoints.len() {
            return Err(TranscriptError::SequenceError {
                expected: self.expected_checkpoints.len() as u64,
                actual: self.current_index as u64,
            });
        }

        let expected = &self.expected_checkpoints[self.current_index];

        if checkpoint.frame_count != expected.frame_count {
            return Err(TranscriptError::SequenceError {
                expected: expected.frame_count,
                actual: checkpoint.frame_count,
            });
        }

        if checkpoint.hash != expected.hash {
            return Err(TranscriptError::VerificationFailed {
                expected: expected.hash,
                actual: checkpoint.hash,
            });
        }

        self.current_index += 1;
        Ok(())
    }

    /// Check if all expected checkpoints have been verified
    pub fn is_complete(&self) -> bool {
        self.current_index == self.expected_checkpoints.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::protocol::frames::{FrameType, ProtocolVersion};

    #[test]
    fn test_transcript_deterministic() {
        // Create identical frames
        let frame1 =
            Frame::new(ProtocolVersion::V0, FrameType::Handshake, b"hello".to_vec()).unwrap();

        let frame2 = Frame::new(
            ProtocolVersion::V0,
            FrameType::HandshakeAck,
            b"world".to_vec(),
        )
        .unwrap();

        // Hash with two different hashers
        let mut hasher1 = TranscriptHasher::new();
        hasher1.update_frame(&frame1);
        hasher1.update_frame(&frame2);

        let mut hasher2 = TranscriptHasher::new();
        hasher2.update_frame(&frame1);
        hasher2.update_frame(&frame2);

        // Should produce identical hashes
        assert_eq!(hasher1.finalize(), hasher2.finalize());
    }

    #[test]
    fn test_transcript_order_sensitive() {
        let frame1 =
            Frame::new(ProtocolVersion::V0, FrameType::Handshake, b"hello".to_vec()).unwrap();

        let frame2 = Frame::new(
            ProtocolVersion::V0,
            FrameType::HandshakeAck,
            b"world".to_vec(),
        )
        .unwrap();

        // Hash in different orders
        let mut hasher1 = TranscriptHasher::new();
        hasher1.update_frame(&frame1);
        hasher1.update_frame(&frame2);

        let mut hasher2 = TranscriptHasher::new();
        hasher2.update_frame(&frame2);
        hasher2.update_frame(&frame1);

        // Should produce different hashes
        assert_ne!(hasher1.finalize(), hasher2.finalize());
    }

    #[test]
    fn test_transcript_with_extensions() {
        let mut frame = Frame::new(
            ProtocolVersion::V0,
            FrameType::Capabilities,
            b"test".to_vec(),
        )
        .unwrap();

        // Add extensions in non-sorted order
        frame.header.extensions.insert(3, b"ext3".to_vec());
        frame.header.extensions.insert(1, b"ext1".to_vec());
        frame.header.extensions.insert(2, b"ext2".to_vec());

        let mut hasher1 = TranscriptHasher::new();
        hasher1.update_frame(&frame);

        // Create identical frame with different insertion order
        let mut frame2 = Frame::new(
            ProtocolVersion::V0,
            FrameType::Capabilities,
            b"test".to_vec(),
        )
        .unwrap();

        frame2.header.extensions.insert(2, b"ext2".to_vec());
        frame2.header.extensions.insert(3, b"ext3".to_vec());
        frame2.header.extensions.insert(1, b"ext1".to_vec());

        let mut hasher2 = TranscriptHasher::new();
        hasher2.update_frame(&frame2);

        // Should produce identical hashes despite different insertion order
        assert_eq!(hasher1.finalize(), hasher2.finalize());
    }

    #[test]
    fn test_session_transcript() {
        let mut transcript = SessionTranscript::new();

        let frame1 =
            Frame::new(ProtocolVersion::V0, FrameType::Handshake, b"hello".to_vec()).unwrap();

        transcript.add_frame(&frame1);
        let checkpoint1 = transcript.checkpoint();

        let frame2 = Frame::new(
            ProtocolVersion::V0,
            FrameType::HandshakeAck,
            b"world".to_vec(),
        )
        .unwrap();

        transcript.add_frame(&frame2);
        let checkpoint2 = transcript.checkpoint();

        assert_eq!(checkpoint1.frame_count, 1);
        assert_eq!(checkpoint2.frame_count, 2);
        assert_ne!(checkpoint1.hash, checkpoint2.hash);
    }

    #[test]
    fn test_transcript_hash_hex() {
        let hash = TranscriptHash([0xab; 32]);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| "0123456789abcdef".contains(c)));

        let parsed = TranscriptHash::from_hex(&hex).unwrap();
        assert_eq!(parsed, hash);
    }

    #[test]
    fn test_transcript_verifier() {
        let checkpoints = vec![
            TranscriptCheckpoint {
                hash: TranscriptHash([1; 32]),
                frame_count: 1,
            },
            TranscriptCheckpoint {
                hash: TranscriptHash([2; 32]),
                frame_count: 2,
            },
        ];

        let mut verifier = TranscriptVerifier::new(checkpoints.clone());

        // Verify correct sequence
        verifier.verify_checkpoint(&checkpoints[0]).unwrap();
        verifier.verify_checkpoint(&checkpoints[1]).unwrap();
        assert!(verifier.is_complete());

        // Test incorrect hash
        let mut bad_verifier = TranscriptVerifier::new(checkpoints.clone());
        let bad_checkpoint = TranscriptCheckpoint {
            hash: TranscriptHash([99; 32]),
            frame_count: 1,
        };

        assert!(bad_verifier.verify_checkpoint(&bad_checkpoint).is_err());
    }
}
