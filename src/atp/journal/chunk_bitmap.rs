//! Chunk State Bitmap for Transfer Progress Tracking

use crate::atp::journal::range_tracker::SparseRange;
use std::collections::HashMap;

/// Different states a chunk can be in during transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChunkState {
    /// Chunk is wanted/needed for the transfer
    Wanted = 0,
    /// Chunk has been received from the network
    Received = 1,
    /// Chunk hash has been verified
    Verified = 2,
    /// Chunk has been written to disk
    Written = 3,
    /// Chunk was derived from repair decode operation
    RepairDerived = 4,
    /// Chunk is committed to final file
    Committed = 5,
    /// Chunk is quarantined due to corruption or failure
    Quarantined = 6,
    /// Chunk has been invalidated and should be re-fetched
    Invalidated = 7,
}

impl ChunkState {
    /// Get all possible chunk states
    pub const fn all() -> &'static [ChunkState] {
        &[
            ChunkState::Wanted,
            ChunkState::Received,
            ChunkState::Verified,
            ChunkState::Written,
            ChunkState::RepairDerived,
            ChunkState::Committed,
            ChunkState::Quarantined,
            ChunkState::Invalidated,
        ]
    }

    /// Check if this state implies the chunk data is available
    pub fn has_data(&self) -> bool {
        matches!(
            self,
            ChunkState::Received
                | ChunkState::Verified
                | ChunkState::Written
                | ChunkState::RepairDerived
                | ChunkState::Committed
        )
    }

    /// Check if this state implies the chunk is verified
    pub fn is_verified(&self) -> bool {
        matches!(
            self,
            ChunkState::Verified | ChunkState::Written | ChunkState::Committed
        )
    }

    /// Check if this state is a final state (no further transitions expected)
    pub fn is_final(&self) -> bool {
        matches!(self, ChunkState::Committed | ChunkState::Quarantined)
    }

    /// Get the priority of this state (higher = more advanced)
    pub fn priority(&self) -> u8 {
        match self {
            ChunkState::Wanted => 0,
            ChunkState::Received => 1,
            ChunkState::RepairDerived => 2,
            ChunkState::Verified => 3,
            ChunkState::Written => 4,
            ChunkState::Committed => 5,
            ChunkState::Quarantined => 10, // Different scale - error state
            ChunkState::Invalidated => 11, // Needs to go back to wanted
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ChunkState::Wanted => "Wanted - chunk needed for transfer",
            ChunkState::Received => "Received - chunk data received from network",
            ChunkState::Verified => "Verified - chunk hash verified against manifest",
            ChunkState::Written => "Written - chunk written to disk file",
            ChunkState::RepairDerived => "RepairDerived - chunk recovered via repair decode",
            ChunkState::Committed => "Committed - chunk committed to final file",
            ChunkState::Quarantined => "Quarantined - chunk quarantined due to error",
            ChunkState::Invalidated => "Invalidated - chunk marked invalid, needs re-fetch",
        }
    }

    /// Decode a `ChunkState` from its wire-format `u8`. Fail closed on unknown discriminants.
    pub fn from_u8(byte: u8) -> Result<Self, ChunkBitmapDecodeError> {
        match byte {
            0 => Ok(ChunkState::Wanted),
            1 => Ok(ChunkState::Received),
            2 => Ok(ChunkState::Verified),
            3 => Ok(ChunkState::Written),
            4 => Ok(ChunkState::RepairDerived),
            5 => Ok(ChunkState::Committed),
            6 => Ok(ChunkState::Quarantined),
            7 => Ok(ChunkState::Invalidated),
            other => Err(ChunkBitmapDecodeError::UnknownChunkState(other)),
        }
    }
}

/// Errors returned when decoding a serialized `ChunkBitmap`.
///
/// Every variant represents a fail-closed condition: malformed input must never
/// silently degrade to an empty or partially-populated bitmap.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChunkBitmapDecodeError {
    #[error("truncated chunk bitmap (need {needed} more bytes at offset {offset})")]
    Truncated { offset: usize, needed: usize },
    #[error("bad chunk bitmap magic: expected {expected:?}, got {actual:?}")]
    BadMagic { expected: [u8; 4], actual: [u8; 4] },
    #[error("unsupported chunk bitmap version {0}")]
    UnsupportedVersion(u8),
    #[error("checksum mismatch: expected {expected:#x}, computed {actual:#x}")]
    ChecksumMismatch { expected: u32, actual: u32 },
    #[error("invalid utf-8 in chunk bitmap field: {0}")]
    InvalidUtf8(String),
    #[error("unknown chunk state discriminant {0}")]
    UnknownChunkState(u8),
    #[error("invalid bool discriminant {0}")]
    InvalidBool(u8),
    #[error("trailing bytes after chunk bitmap payload ({0} unread)")]
    TrailingBytes(usize),
    #[error("field length {0} exceeds remaining input")]
    OversizedField(u64),
}

/// A chunk entry in the bitmap
#[derive(Debug, Clone)]
pub struct ChunkEntry {
    /// Current state of the chunk
    pub state: ChunkState,
    /// Timestamp when the chunk entered this state
    pub state_timestamp: u64,
    /// Hash of the chunk data (if available)
    pub chunk_hash: Option<[u8; 32]>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl ChunkEntry {
    /// Create a new chunk entry in the given state
    pub fn new(state: ChunkState, timestamp: u64) -> Self {
        Self {
            state,
            state_timestamp: timestamp,
            chunk_hash: None,
            metadata: HashMap::new(),
        }
    }

    /// Create a new chunk entry with hash
    pub fn with_hash(state: ChunkState, timestamp: u64, hash: [u8; 32]) -> Self {
        Self {
            state,
            state_timestamp: timestamp,
            chunk_hash: Some(hash),
            metadata: HashMap::new(),
        }
    }

    /// Update the state if the new state has higher priority
    pub fn update_state(&mut self, new_state: ChunkState, timestamp: u64) -> bool {
        // Don't allow backwards transitions except for invalidation
        if new_state == ChunkState::Invalidated {
            self.state = new_state;
            self.state_timestamp = timestamp;
            return true;
        }

        // Allow transition if new state has higher priority
        if new_state.priority() > self.state.priority() {
            self.state = new_state;
            self.state_timestamp = timestamp;
            true
        } else {
            false
        }
    }

    /// Set or update metadata
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// Transfer state bitmap tracking chunk states
#[derive(Debug)]
pub struct ChunkBitmap {
    /// Map from chunk offset to chunk entry
    chunks: HashMap<u64, ChunkEntry>,
    /// Total size of the transfer
    total_size: u64,
    /// Chunk size used for this transfer
    chunk_size: u64,
    /// Transfer ID this bitmap belongs to
    transfer_id: String,
    /// Creation timestamp
    created_at: u64,
    /// Last update timestamp
    updated_at: u64,
}

impl ChunkBitmap {
    /// Create a new chunk bitmap
    pub fn new(transfer_id: String, total_size: u64, chunk_size: u64, timestamp: u64) -> Self {
        Self {
            chunks: HashMap::new(),
            total_size,
            chunk_size,
            transfer_id,
            created_at: timestamp,
            updated_at: timestamp,
        }
    }

    /// Initialize all chunks as wanted
    pub fn initialize_wanted_chunks(&mut self, timestamp: u64) {
        let num_chunks = (self.total_size + self.chunk_size - 1) / self.chunk_size;

        for i in 0..num_chunks {
            let offset = i * self.chunk_size;
            self.chunks
                .insert(offset, ChunkEntry::new(ChunkState::Wanted, timestamp));
        }

        self.updated_at = timestamp;
    }

    /// Update the state of a chunk
    pub fn update_chunk_state(
        &mut self,
        chunk_offset: u64,
        new_state: ChunkState,
        timestamp: u64,
        chunk_hash: Option<[u8; 32]>,
    ) -> bool {
        let updated = if let Some(entry) = self.chunks.get_mut(&chunk_offset) {
            let state_updated = entry.update_state(new_state, timestamp);
            if let Some(hash) = chunk_hash {
                entry.chunk_hash = Some(hash);
            }
            state_updated
        } else {
            // Create new entry
            let mut entry = ChunkEntry::new(new_state, timestamp);
            if let Some(hash) = chunk_hash {
                entry.chunk_hash = Some(hash);
            }
            self.chunks.insert(chunk_offset, entry);
            true
        };

        if updated {
            self.updated_at = timestamp;
        }

        updated
    }

    /// Set metadata for a chunk
    pub fn set_chunk_metadata(
        &mut self,
        chunk_offset: u64,
        key: String,
        value: String,
        timestamp: u64,
    ) {
        if let Some(entry) = self.chunks.get_mut(&chunk_offset) {
            entry.set_metadata(key, value);
            self.updated_at = timestamp;
        }
    }

    /// Get the state of a chunk
    pub fn get_chunk_state(&self, chunk_offset: u64) -> Option<ChunkState> {
        self.chunks.get(&chunk_offset).map(|entry| entry.state)
    }

    /// Get chunk entry
    pub fn get_chunk_entry(&self, chunk_offset: u64) -> Option<&ChunkEntry> {
        self.chunks.get(&chunk_offset)
    }

    /// Get all chunks in a specific state
    pub fn get_chunks_in_state(&self, state: ChunkState) -> Vec<u64> {
        self.chunks
            .iter()
            .filter_map(|(&offset, entry)| {
                if entry.state == state {
                    Some(offset)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get chunks in any of the given states
    pub fn get_chunks_in_states(&self, states: &[ChunkState]) -> Vec<u64> {
        self.chunks
            .iter()
            .filter_map(|(&offset, entry)| {
                if states.contains(&entry.state) {
                    Some(offset)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get ranges of chunks in specific states
    pub fn get_ranges_in_state(&self, state: ChunkState) -> Vec<SparseRange> {
        let mut offsets = self.get_chunks_in_state(state);
        offsets.sort_unstable();

        self.offsets_to_ranges(&offsets)
    }

    /// Get ranges of chunks in any of the given states
    pub fn get_ranges_in_states(&self, states: &[ChunkState]) -> Vec<SparseRange> {
        let mut offsets = self.get_chunks_in_states(states);
        offsets.sort_unstable();

        self.offsets_to_ranges(&offsets)
    }

    /// Convert sorted chunk offsets to sparse ranges
    fn offsets_to_ranges(&self, offsets: &[u64]) -> Vec<SparseRange> {
        if offsets.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut start = offsets[0];
        let mut end = start + self.chunk_size;

        for &offset in offsets.iter().skip(1) {
            if offset == end {
                // Contiguous chunk
                end += self.chunk_size;
            } else {
                // Gap found, finalize current range
                ranges.push(SparseRange::new(start, end));
                start = offset;
                end = offset + self.chunk_size;
            }
        }

        // Add the final range
        ranges.push(SparseRange::new(start, end.min(self.total_size)));

        ranges
    }

    /// Get bitmap statistics
    pub fn get_stats(&self) -> ChunkBitmapStats {
        let mut state_counts = HashMap::new();
        for state in ChunkState::all() {
            state_counts.insert(*state, 0);
        }

        for entry in self.chunks.values() {
            *state_counts.get_mut(&entry.state).unwrap() += 1; // ubs:ignore - map pre-initialized with all variants
        }

        let total_chunks = self.chunks.len();
        let verified_chunks = state_counts[&ChunkState::Verified]
            + state_counts[&ChunkState::Written]
            + state_counts[&ChunkState::Committed];
        let completed_chunks = state_counts[&ChunkState::Committed];

        ChunkBitmapStats {
            transfer_id: self.transfer_id.clone(),
            total_size: self.total_size,
            chunk_size: self.chunk_size,
            total_chunks,
            state_counts,
            verified_chunks,
            completed_chunks,
            completion_ratio: if total_chunks > 0 {
                completed_chunks as f64 / total_chunks as f64
            } else {
                0.0
            },
            verification_ratio: if total_chunks > 0 {
                verified_chunks as f64 / total_chunks as f64
            } else {
                0.0
            },
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Check if transfer is complete (all chunks committed)
    pub fn is_complete(&self) -> bool {
        !self.chunks.is_empty()
            && self
                .chunks
                .values()
                .all(|entry| entry.state == ChunkState::Committed)
    }

    /// Check if transfer has any errors (quarantined or invalidated chunks)
    pub fn has_errors(&self) -> bool {
        self.chunks.values().any(|entry| {
            matches!(
                entry.state,
                ChunkState::Quarantined | ChunkState::Invalidated
            )
        })
    }

    /// Get missing chunks (wanted but not received)
    pub fn get_missing_chunks(&self) -> Vec<u64> {
        self.get_chunks_in_state(ChunkState::Wanted)
    }

    /// Get chunks that need verification
    pub fn get_unverified_chunks(&self) -> Vec<u64> {
        self.get_chunks_in_states(&[ChunkState::Received, ChunkState::RepairDerived])
    }

    /// Get chunks ready for writing
    pub fn get_verified_unwritten_chunks(&self) -> Vec<u64> {
        self.get_chunks_in_state(ChunkState::Verified)
    }

    /// Mark all chunks with a specific state as invalidated
    pub fn invalidate_chunks_in_state(
        &mut self,
        target_state: ChunkState,
        timestamp: u64,
    ) -> usize {
        let mut invalidated_count = 0;

        for entry in self.chunks.values_mut() {
            if entry.state == target_state {
                entry.state = ChunkState::Invalidated;
                entry.state_timestamp = timestamp;
                invalidated_count += 1;
            }
        }

        if invalidated_count > 0 {
            self.updated_at = timestamp;
        }

        invalidated_count
    }

    /// Read-only accessor for the transfer this bitmap belongs to.
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    /// Total payload size tracked by this bitmap.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Chunk size used to partition the payload.
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Creation timestamp captured when the bitmap was constructed.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Most-recent update timestamp.
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Number of chunk entries currently tracked.
    pub fn entry_count(&self) -> usize {
        self.chunks.len()
    }

    /// Serialize this bitmap to a deterministic, length-prefixed byte sequence
    /// suitable for atomic on-disk persistence and crash recovery.
    ///
    /// Wire format (little-endian, matches the rest of the ATP journal):
    /// ```text
    ///   magic: b"ABMP" (4 bytes)
    ///   version: u8 = 1
    ///   transfer_id: u32 len + utf-8 bytes
    ///   total_size: u64
    ///   chunk_size: u64
    ///   created_at: u64
    ///   updated_at: u64
    ///   chunk_count: u32 (sorted by offset for determinism)
    ///   for each chunk:
    ///     offset: u64
    ///     state: u8
    ///     state_timestamp: u64
    ///     has_hash: u8 (0|1)
    ///     hash: 32 bytes if has_hash
    ///     metadata_count: u32 (sorted by key for determinism)
    ///     for each metadata pair:
    ///       key: u32 len + utf-8 bytes
    ///       value: u32 len + utf-8 bytes
    ///   crc32: u32 (over all preceding bytes including magic+version)
    /// ```
    pub fn serialize_to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.chunks.len() * 64);
        out.extend_from_slice(&Self::SERIALIZATION_MAGIC);
        out.push(Self::SERIALIZATION_VERSION);

        put_string(&mut out, &self.transfer_id);
        put_u64(&mut out, self.total_size);
        put_u64(&mut out, self.chunk_size);
        put_u64(&mut out, self.created_at);
        put_u64(&mut out, self.updated_at);

        let mut offsets: Vec<u64> = self.chunks.keys().copied().collect();
        offsets.sort_unstable();
        put_u32(&mut out, u32::try_from(offsets.len()).unwrap_or(u32::MAX));

        for offset in offsets {
            let entry = match self.chunks.get(&offset) {
                Some(entry) => entry,
                None => continue,
            };
            put_u64(&mut out, offset);
            out.push(entry.state as u8);
            put_u64(&mut out, entry.state_timestamp);
            match entry.chunk_hash {
                Some(hash) => {
                    out.push(1);
                    out.extend_from_slice(&hash);
                }
                None => out.push(0),
            }

            let mut keys: Vec<&String> = entry.metadata.keys().collect();
            keys.sort();
            put_u32(&mut out, u32::try_from(keys.len()).unwrap_or(u32::MAX));
            for key in keys {
                let value = match entry.metadata.get(key) {
                    Some(value) => value.as_str(),
                    None => continue,
                };
                put_string(&mut out, key);
                put_string(&mut out, value);
            }
        }

        let checksum = crc32fast::hash(&out);
        out.extend_from_slice(&checksum.to_le_bytes());
        out
    }

    /// Deserialize a `ChunkBitmap` previously produced by `serialize_to_bytes`.
    ///
    /// Fails closed on truncation, magic/version mismatch, CRC mismatch, or any
    /// invalid discriminant (chunk state, bool, utf-8). No partial bitmap is
    /// returned on error.
    pub fn deserialize_from_bytes(bytes: &[u8]) -> Result<Self, ChunkBitmapDecodeError> {
        if bytes.len() < Self::SERIALIZATION_MAGIC.len() + 1 + 4 {
            return Err(ChunkBitmapDecodeError::Truncated {
                offset: 0,
                needed: Self::SERIALIZATION_MAGIC.len() + 1 + 4,
            });
        }
        let payload_len = bytes.len() - 4;
        let payload = &bytes[..payload_len];
        let stored_checksum = {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[payload_len..]);
            u32::from_le_bytes(buf)
        };
        let computed_checksum = crc32fast::hash(payload);
        if computed_checksum != stored_checksum {
            return Err(ChunkBitmapDecodeError::ChecksumMismatch {
                expected: stored_checksum,
                actual: computed_checksum,
            });
        }

        let mut cursor = BitmapCursor::new(payload);
        let magic = cursor.read_array::<4>()?;
        if magic != Self::SERIALIZATION_MAGIC {
            return Err(ChunkBitmapDecodeError::BadMagic {
                expected: Self::SERIALIZATION_MAGIC,
                actual: magic,
            });
        }
        let version = cursor.read_u8()?;
        if version != Self::SERIALIZATION_VERSION {
            return Err(ChunkBitmapDecodeError::UnsupportedVersion(version));
        }

        let transfer_id = cursor.read_string()?;
        let total_size = cursor.read_u64()?;
        let chunk_size = cursor.read_u64()?;
        let created_at = cursor.read_u64()?;
        let updated_at = cursor.read_u64()?;
        let chunk_count = cursor.read_u32()? as usize;

        let mut chunks = HashMap::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            let offset = cursor.read_u64()?;
            let state = ChunkState::from_u8(cursor.read_u8()?)?;
            let state_timestamp = cursor.read_u64()?;
            let chunk_hash = match cursor.read_u8()? {
                0 => None,
                1 => Some(cursor.read_array::<32>()?),
                other => return Err(ChunkBitmapDecodeError::InvalidBool(other)),
            };
            let metadata_count = cursor.read_u32()? as usize;
            let mut metadata = HashMap::with_capacity(metadata_count);
            for _ in 0..metadata_count {
                let key = cursor.read_string()?;
                let value = cursor.read_string()?;
                metadata.insert(key, value);
            }
            chunks.insert(
                offset,
                ChunkEntry {
                    state,
                    state_timestamp,
                    chunk_hash,
                    metadata,
                },
            );
        }

        cursor.finish()?;

        Ok(Self {
            chunks,
            total_size,
            chunk_size,
            transfer_id,
            created_at,
            updated_at,
        })
    }

    /// Magic header identifying the ATP chunk bitmap on-disk format.
    pub const SERIALIZATION_MAGIC: [u8; 4] = *b"ABMP";

    /// Current serialization format version. Bumped only on incompatible changes.
    pub const SERIALIZATION_VERSION: u8 = 1;

    /// Export bitmap state for recovery
    pub fn export_state(&self) -> HashMap<u64, (ChunkState, u64, Option<[u8; 32]>)> {
        self.chunks
            .iter()
            .map(|(&offset, entry)| {
                (
                    offset,
                    (entry.state, entry.state_timestamp, entry.chunk_hash),
                )
            })
            .collect()
    }

    /// Import bitmap state from recovery data
    pub fn import_state(&mut self, state: HashMap<u64, (ChunkState, u64, Option<[u8; 32]>)>) {
        for (offset, (state, timestamp, hash)) in state {
            let mut entry = ChunkEntry::new(state, timestamp);
            entry.chunk_hash = hash;
            self.chunks.insert(offset, entry);
        }

        // Update timestamp to latest
        self.updated_at = self
            .chunks
            .values()
            .map(|entry| entry.state_timestamp)
            .max()
            .unwrap_or(self.updated_at);
    }
}

/// Statistics about chunk bitmap state
#[derive(Debug, Clone)]
pub struct ChunkBitmapStats {
    pub transfer_id: String,
    pub total_size: u64,
    pub chunk_size: u64,
    pub total_chunks: usize,
    pub state_counts: HashMap<ChunkState, usize>,
    pub verified_chunks: usize,
    pub completed_chunks: usize,
    pub completion_ratio: f64,
    pub verification_ratio: f64,
    pub created_at: u64,
    pub updated_at: u64,
}

impl std::fmt::Display for ChunkBitmapStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ChunkBitmap({}) - {} chunks, {:.1}% verified, {:.1}% complete",
            self.transfer_id,
            self.total_chunks,
            self.verification_ratio * 100.0,
            self.completion_ratio * 100.0
        )
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    put_u32(out, len);
    out.extend_from_slice(bytes);
}

struct BitmapCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> BitmapCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], ChunkBitmapDecodeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ChunkBitmapDecodeError::Truncated {
                offset: self.offset,
                needed: len,
            })?;
        if end > self.data.len() {
            return Err(ChunkBitmapDecodeError::Truncated {
                offset: self.offset,
                needed: len,
            });
        }
        let slice = &self.data[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ChunkBitmapDecodeError> {
        let slice = self.read_slice(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, ChunkBitmapDecodeError> {
        Ok(self.read_slice(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, ChunkBitmapDecodeError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, ChunkBitmapDecodeError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    fn read_string(&mut self) -> Result<String, ChunkBitmapDecodeError> {
        let len = self.read_u32()? as usize;
        let remaining = self.data.len().saturating_sub(self.offset);
        if len > remaining {
            return Err(ChunkBitmapDecodeError::OversizedField(len as u64));
        }
        let bytes = self.read_slice(len)?.to_vec();
        String::from_utf8(bytes).map_err(|e| ChunkBitmapDecodeError::InvalidUtf8(e.to_string()))
    }

    fn finish(self) -> Result<(), ChunkBitmapDecodeError> {
        let remaining = self.data.len().saturating_sub(self.offset);
        if remaining > 0 {
            Err(ChunkBitmapDecodeError::TrailingBytes(remaining))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_state_properties() {
        assert!(ChunkState::Verified.has_data());
        assert!(ChunkState::Verified.is_verified());
        assert!(!ChunkState::Wanted.has_data());
        assert!(!ChunkState::Received.is_verified());
        assert!(ChunkState::Committed.is_final());
        assert!(!ChunkState::Verified.is_final());
    }

    #[test]
    fn test_chunk_entry_state_updates() {
        let mut entry = ChunkEntry::new(ChunkState::Wanted, 1000);

        // Forward transitions should work
        assert!(entry.update_state(ChunkState::Received, 1001));
        assert_eq!(entry.state, ChunkState::Received);

        assert!(entry.update_state(ChunkState::Verified, 1002));
        assert_eq!(entry.state, ChunkState::Verified);

        // Backward transitions should be rejected
        assert!(!entry.update_state(ChunkState::Received, 1003));
        assert_eq!(entry.state, ChunkState::Verified);

        // Invalidation should always work
        assert!(entry.update_state(ChunkState::Invalidated, 1004));
        assert_eq!(entry.state, ChunkState::Invalidated);
    }

    #[test]
    fn test_chunk_bitmap_basic() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 1024, 256, 1000);

        // Initialize wanted chunks
        bitmap.initialize_wanted_chunks(1001);
        assert_eq!(bitmap.chunks.len(), 4); // 1024 / 256 = 4 chunks

        // Check all chunks are wanted
        let wanted_chunks = bitmap.get_chunks_in_state(ChunkState::Wanted);
        assert_eq!(wanted_chunks.len(), 4);

        // Update first chunk to received
        assert!(bitmap.update_chunk_state(0, ChunkState::Received, 1002, None));
        assert_eq!(bitmap.get_chunk_state(0), Some(ChunkState::Received));

        // Update with hash
        let hash = [1u8; 32];
        assert!(bitmap.update_chunk_state(256, ChunkState::Verified, 1003, Some(hash)));

        let entry = bitmap.get_chunk_entry(256).unwrap();
        assert_eq!(entry.state, ChunkState::Verified);
        assert_eq!(entry.chunk_hash, Some(hash));
    }

    #[test]
    fn test_chunk_bitmap_ranges() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 1000, 100, 1000);
        bitmap.initialize_wanted_chunks(1001);

        // Mark some chunks as verified
        bitmap.update_chunk_state(0, ChunkState::Verified, 1002, None);
        bitmap.update_chunk_state(100, ChunkState::Verified, 1003, None);
        bitmap.update_chunk_state(200, ChunkState::Verified, 1004, None);
        bitmap.update_chunk_state(400, ChunkState::Verified, 1005, None);

        let verified_ranges = bitmap.get_ranges_in_state(ChunkState::Verified);
        assert_eq!(verified_ranges.len(), 2);

        // First range: 0-300 (chunks 0, 100, 200)
        assert_eq!(verified_ranges[0], SparseRange::new(0, 300));

        // Second range: 400-500 (chunk 400)
        assert_eq!(verified_ranges[1], SparseRange::new(400, 500));
    }

    #[test]
    fn test_chunk_bitmap_stats() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 400, 100, 1000);
        bitmap.initialize_wanted_chunks(1001);

        // Update chunk states
        bitmap.update_chunk_state(0, ChunkState::Received, 1002, None);
        bitmap.update_chunk_state(100, ChunkState::Verified, 1003, None);
        bitmap.update_chunk_state(200, ChunkState::Written, 1004, None);
        bitmap.update_chunk_state(300, ChunkState::Committed, 1005, None);

        let stats = bitmap.get_stats();
        assert_eq!(stats.total_chunks, 4);
        assert_eq!(stats.state_counts[&ChunkState::Received], 1);
        assert_eq!(stats.state_counts[&ChunkState::Verified], 1);
        assert_eq!(stats.state_counts[&ChunkState::Written], 1);
        assert_eq!(stats.state_counts[&ChunkState::Committed], 1);
        assert_eq!(stats.completed_chunks, 1);
        assert_eq!(stats.verified_chunks, 3); // verified + written + committed
        assert_eq!(stats.completion_ratio, 0.25);
        assert_eq!(stats.verification_ratio, 0.75);
    }

    #[test]
    fn test_chunk_bitmap_completion() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 200, 100, 1000);
        bitmap.initialize_wanted_chunks(1001);

        assert!(!bitmap.is_complete());

        // Commit all chunks
        bitmap.update_chunk_state(0, ChunkState::Committed, 1002, None);
        bitmap.update_chunk_state(100, ChunkState::Committed, 1003, None);

        assert!(bitmap.is_complete());
    }

    #[test]
    fn test_chunk_bitmap_error_detection() {
        let mut bitmap = ChunkBitmap::new("test_transfer".to_string(), 200, 100, 1000);
        bitmap.initialize_wanted_chunks(1001);

        assert!(!bitmap.has_errors());

        // Quarantine one chunk
        bitmap.update_chunk_state(0, ChunkState::Quarantined, 1002, None);
        assert!(bitmap.has_errors());

        // Invalidate another chunk
        bitmap.update_chunk_state(100, ChunkState::Invalidated, 1003, None);
        assert!(bitmap.has_errors());
    }

    #[test]
    fn test_chunk_bitmap_export_import() {
        let mut bitmap1 = ChunkBitmap::new("test_transfer".to_string(), 300, 100, 1000);
        bitmap1.initialize_wanted_chunks(1001);

        // Update some states
        bitmap1.update_chunk_state(0, ChunkState::Verified, 1002, Some([1u8; 32]));
        bitmap1.update_chunk_state(100, ChunkState::Written, 1003, Some([2u8; 32]));

        // Export and import
        let exported = bitmap1.export_state();
        let mut bitmap2 = ChunkBitmap::new("test_transfer".to_string(), 300, 100, 1000);
        bitmap2.import_state(exported);

        // Verify states match
        assert_eq!(bitmap2.get_chunk_state(0), Some(ChunkState::Verified));
        assert_eq!(bitmap2.get_chunk_state(100), Some(ChunkState::Written));
        assert_eq!(bitmap2.get_chunk_state(200), Some(ChunkState::Wanted)); // From export

        let entry1 = bitmap2.get_chunk_entry(0).unwrap(); // ubs:ignore - test oracle
        assert_eq!(entry1.chunk_hash, Some([1u8; 32]));
    }

    fn populated_bitmap() -> ChunkBitmap {
        let mut bitmap = ChunkBitmap::new("xfer-9".to_string(), 1024, 256, 5_000);
        bitmap.initialize_wanted_chunks(5_001);
        bitmap.update_chunk_state(0, ChunkState::Received, 5_010, None);
        bitmap.update_chunk_state(256, ChunkState::Verified, 5_020, Some([7u8; 32]));
        bitmap.update_chunk_state(512, ChunkState::Written, 5_030, Some([9u8; 32]));
        bitmap.update_chunk_state(768, ChunkState::Quarantined, 5_040, None);
        bitmap.set_chunk_metadata(256, "source".into(), "peer-a".into(), 5_050);
        bitmap.set_chunk_metadata(256, "verifier".into(), "sha256".into(), 5_060);
        bitmap
    }

    #[test]
    fn serialization_round_trip_preserves_state() {
        let original = populated_bitmap();
        let bytes = original.serialize_to_bytes();
        let decoded = ChunkBitmap::deserialize_from_bytes(&bytes).expect("decode succeeds");

        assert_eq!(decoded.transfer_id(), original.transfer_id());
        assert_eq!(decoded.total_size(), original.total_size());
        assert_eq!(decoded.chunk_size(), original.chunk_size());
        assert_eq!(decoded.created_at(), original.created_at());
        assert_eq!(decoded.updated_at(), original.updated_at());
        assert_eq!(decoded.entry_count(), original.entry_count());

        for offset in [0, 256, 512, 768] {
            let original_entry = original.get_chunk_entry(offset).expect("entry exists");
            let decoded_entry = decoded.get_chunk_entry(offset).expect("entry exists");
            assert_eq!(original_entry.state, decoded_entry.state);
            assert_eq!(
                original_entry.state_timestamp,
                decoded_entry.state_timestamp
            );
            assert_eq!(original_entry.chunk_hash, decoded_entry.chunk_hash);
            assert_eq!(original_entry.metadata, decoded_entry.metadata);
        }
    }

    #[test]
    fn serialization_is_deterministic() {
        let bitmap = populated_bitmap();
        let a = bitmap.serialize_to_bytes();
        let b = bitmap.serialize_to_bytes();
        assert_eq!(a, b, "two serializations of the same bitmap must be equal");

        // Reconstruct from decoded form and re-serialize -- canonical form survives a round trip.
        let decoded = ChunkBitmap::deserialize_from_bytes(&a).expect("decode succeeds");
        let re_serialized = decoded.serialize_to_bytes();
        assert_eq!(a, re_serialized);
    }

    #[test]
    fn deserialize_rejects_truncated_input() {
        let bytes = populated_bitmap().serialize_to_bytes();
        for cut in 0..bytes.len().min(80) {
            let result = ChunkBitmap::deserialize_from_bytes(&bytes[..cut]);
            assert!(
                matches!(
                    result,
                    Err(ChunkBitmapDecodeError::Truncated { .. }
                        | ChunkBitmapDecodeError::ChecksumMismatch { .. }
                        | ChunkBitmapDecodeError::BadMagic { .. })
                ),
                "cut={cut} must fail closed, got {result:?}"
            );
        }
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        let mut bytes = populated_bitmap().serialize_to_bytes();
        bytes[0] = b'X';
        // Recompute checksum so the magic check is exercised, not the crc.
        let payload_len = bytes.len() - 4;
        let crc = crc32fast::hash(&bytes[..payload_len]);
        bytes[payload_len..].copy_from_slice(&crc.to_le_bytes());
        match ChunkBitmap::deserialize_from_bytes(&bytes) {
            Err(ChunkBitmapDecodeError::BadMagic { .. }) => (),
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_unsupported_version() {
        let mut bytes = populated_bitmap().serialize_to_bytes();
        bytes[4] = 0xFE;
        let payload_len = bytes.len() - 4;
        let crc = crc32fast::hash(&bytes[..payload_len]);
        bytes[payload_len..].copy_from_slice(&crc.to_le_bytes());
        match ChunkBitmap::deserialize_from_bytes(&bytes) {
            Err(ChunkBitmapDecodeError::UnsupportedVersion(0xFE)) => (),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_checksum_mismatch() {
        let mut bytes = populated_bitmap().serialize_to_bytes();
        // Flip a byte deep in the payload without recomputing the trailing CRC.
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x80;
        match ChunkBitmap::deserialize_from_bytes(&bytes) {
            Err(ChunkBitmapDecodeError::ChecksumMismatch { .. }) => (),
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_empty_bitmap_round_trips() {
        let original = ChunkBitmap::new("empty".to_string(), 0, 4096, 7);
        let bytes = original.serialize_to_bytes();
        let decoded = ChunkBitmap::deserialize_from_bytes(&bytes).expect("decode succeeds");
        assert_eq!(decoded.transfer_id(), "empty");
        assert_eq!(decoded.entry_count(), 0);
        assert_eq!(decoded.chunk_size(), 4096);
    }
}
