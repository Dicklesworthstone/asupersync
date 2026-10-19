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
    #[error("invalid chunk bitmap geometry: total_size={total_size}, chunk_size={chunk_size}")]
    InvalidGeometry { total_size: u64, chunk_size: u64 },
    #[error("chunk count {actual} exceeds expected geometry count {expected}")]
    InvalidChunkCount { expected: u64, actual: u64 },
    #[error("invalid chunk offset {offset} for total_size={total_size}, chunk_size={chunk_size}")]
    InvalidChunkOffset {
        offset: u64,
        total_size: u64,
        chunk_size: u64,
    },
    #[error("duplicate chunk offset {0}")]
    DuplicateChunkOffset(u64),
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

    fn expected_chunk_count_for(total_size: u64, chunk_size: u64) -> Option<u64> {
        if chunk_size == 0 {
            return None;
        }
        Some(total_size.div_ceil(chunk_size))
    }

    fn expected_chunk_count(&self) -> Option<usize> {
        let expected = Self::expected_chunk_count_for(self.total_size, self.chunk_size)?;
        usize::try_from(expected).ok()
    }

    fn is_valid_chunk_offset_for(total_size: u64, chunk_size: u64, offset: u64) -> bool {
        chunk_size != 0 && offset < total_size && offset % chunk_size == 0
    }

    fn is_valid_chunk_offset(&self, offset: u64) -> bool {
        Self::is_valid_chunk_offset_for(self.total_size, self.chunk_size, offset)
    }

    /// Initialize all chunks as wanted
    pub fn initialize_wanted_chunks(&mut self, timestamp: u64) {
        // A zero `chunk_size` is invalid geometry that can arrive from a crafted
        // or corrupt deserialized bitmap. The old
        // `(total_size + chunk_size - 1) / chunk_size` divided by zero (and
        // underflowed when total_size == 0) — a remote crash/DoS on the recovery
        // path. Treat it as "nothing to enumerate" and leave the bitmap empty.
        if self.chunk_size == 0 {
            self.updated_at = timestamp;
            return;
        }
        let num_chunks = match Self::expected_chunk_count_for(self.total_size, self.chunk_size) {
            Some(num_chunks) => num_chunks,
            None => {
                self.updated_at = timestamp;
                return;
            }
        };

        for i in 0..num_chunks {
            // `i * self.chunk_size` could overflow u64 for a crafted
            // total_size/chunk_size pair; stop instead of panicking.
            let Some(offset) = i.checked_mul(self.chunk_size) else {
                break;
            };
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
        // Public mutation/import APIs retain invalid entries for diagnostics.
        // As with get_stats, they must not contribute valid byte coverage.
        let mut offsets = offsets
            .iter()
            .copied()
            .filter(|offset| self.is_valid_chunk_offset(*offset));
        let Some(mut start) = offsets.next() else {
            return Vec::new();
        };

        let mut ranges = Vec::new();
        let mut end = start.saturating_add(self.chunk_size).min(self.total_size);

        for offset in offsets {
            if offset == end {
                // Contiguous chunk
                end = offset.saturating_add(self.chunk_size).min(self.total_size);
            } else {
                // Gap found, finalize current range
                ranges.push(SparseRange::new(start, end));
                start = offset;
                end = offset.saturating_add(self.chunk_size).min(self.total_size);
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

        let expected_chunks = self.expected_chunk_count().unwrap_or(0);
        let mut valid_tracked_chunks = 0usize;
        for (&offset, entry) in &self.chunks {
            if self.is_valid_chunk_offset(offset) {
                valid_tracked_chunks += 1;
                *state_counts.get_mut(&entry.state).unwrap() += 1; // ubs:ignore - map pre-initialized with all variants
            }
        }

        let missing_chunks = expected_chunks.saturating_sub(valid_tracked_chunks);
        *state_counts.get_mut(&ChunkState::Wanted).unwrap() += missing_chunks; // ubs:ignore - map pre-initialized with all variants

        let total_chunks = expected_chunks;
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
        let Some(expected_chunks) = self.expected_chunk_count() else {
            return false;
        };
        expected_chunks > 0
            && self.chunks.len() == expected_chunks
            && self.chunks.iter().all(|(&offset, entry)| {
                self.is_valid_chunk_offset(offset) && entry.state == ChunkState::Committed
            })
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
        let chunk_count_raw = cursor.read_u32()?;
        let expected_chunks = Self::expected_chunk_count_for(total_size, chunk_size).ok_or(
            ChunkBitmapDecodeError::InvalidGeometry {
                total_size,
                chunk_size,
            },
        )?;
        if u64::from(chunk_count_raw) > expected_chunks {
            return Err(ChunkBitmapDecodeError::InvalidChunkCount {
                expected: expected_chunks,
                actual: u64::from(chunk_count_raw),
            });
        }
        let chunk_count = chunk_count_raw as usize;

        let mut chunks = HashMap::new();
        for _ in 0..chunk_count {
            let offset = cursor.read_u64()?;
            if !Self::is_valid_chunk_offset_for(total_size, chunk_size, offset) {
                return Err(ChunkBitmapDecodeError::InvalidChunkOffset {
                    offset,
                    total_size,
                    chunk_size,
                });
            }
            let state = ChunkState::from_u8(cursor.read_u8()?)?;
            let state_timestamp = cursor.read_u64()?;
            let chunk_hash = match cursor.read_u8()? {
                0 => None,
                1 => Some(cursor.read_array::<32>()?),
                other => return Err(ChunkBitmapDecodeError::InvalidBool(other)),
            };
            let metadata_count = cursor.read_u32()? as usize;
            let mut metadata = HashMap::new();
            for _ in 0..metadata_count {
                let key = cursor.read_string()?;
                let value = cursor.read_string()?;
                metadata.insert(key, value);
            }
            let old = chunks.insert(
                offset,
                ChunkEntry {
                    state,
                    state_timestamp,
                    chunk_hash,
                    metadata,
                },
            );
            if old.is_some() {
                return Err(ChunkBitmapDecodeError::DuplicateChunkOffset(offset));
            }
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

impl ChunkBitmap {
    /// Return coalesced byte ranges that are wanted, including absent entries.
    ///
    /// Unlike `get_missing_chunks` (which preserves its explicit-entry semantics),
    /// this supports sparse recovered bitmaps without initializing every logical
    /// chunk. An untracked cell has the same Wanted meaning used by `get_stats`.
    /// Valid non-Wanted cells are excluded, including Invalidated and Quarantined:
    /// retry requires the explicit `requeue_invalidated_chunk` transition below.
    /// Invalid imported offsets are diagnostic only and cannot hide missing bytes.
    ///
    /// Ranges are sorted, disjoint, coalesced and clipped to the declared size.
    /// Zero chunk size is an error, including for an empty object. The calculation
    /// uses u64 offsets and never enumerates the logical chunk count or sparse
    /// gaps. Work is O(n + k log k), and auxiliary/output space is O(k + 1), where
    /// n is tracked entries and k is valid non-Wanted entries. Caller-held bitmap
    /// metadata and later expansion of returned ranges are separate memory costs.
    ///
    /// This is scheduling state, not authentication or durable resume permission.
    /// Received/Verified/RepairDerived cells must still complete their existing
    /// verification and durability stages. No file or journal is changed here.
    pub fn get_missing_chunk_ranges(&self) -> Result<Vec<SparseRange>, ChunkBitmapDecodeError> {
        if self.chunk_size == 0 {
            return Err(ChunkBitmapDecodeError::InvalidGeometry {
                total_size: self.total_size,
                chunk_size: self.chunk_size,
            });
        }
        let mut occupied: Vec<u64> = self.chunks.iter().filter_map(|(&offset, entry)| {
            (entry.state != ChunkState::Wanted && self.is_valid_chunk_offset(offset))
                .then_some(offset)
        }).collect();
        occupied.sort_unstable();
        let mut ranges = Vec::new();
        let mut cursor = 0_u64;
        for offset in occupied {
            if cursor < offset {
                ranges.push(SparseRange::new(cursor, offset));
            }
            // A final short cell can extend past u64::MAX arithmetically; clamp
            // the endpoint to the declared extent without offset+size overflow.
            cursor = offset.saturating_add(self.chunk_size).min(self.total_size);
        }
        if cursor < self.total_size {
            ranges.push(SparseRange::new(cursor, self.total_size));
        }
        Ok(ranges)
    }

    /// Explicitly schedule one valid Invalidated chunk for a new receive attempt.
    ///
    /// The ordinary priority-based update API intentionally cannot move from
    /// Invalidated back to Wanted. This separate transition resets ONLY the
    /// selected invalidated cell, discarding its stale hash and all per-attempt
    /// metadata before setting Wanted and both update timestamps. Preserve any
    /// forensic metadata elsewhere before requesting this reset.
    ///
    /// Unknown, misaligned, out-of-extent and non-Invalidated cells refuse without
    /// any mutation. Quarantined/Committed cells are not automatically reopened;
    /// another explicit invalidation decision is required first. New bytes must
    /// pass the ordinary receive/verify/write/commit stages: the reset grants no
    /// verification credit and does not erase payload files or journal records.
    pub fn requeue_invalidated_chunk(&mut self, offset: u64, timestamp: u64) -> bool {
        if !self.is_valid_chunk_offset(offset) {
            return false;
        }
        let Some(entry) = self.chunks.get_mut(&offset) else {
            return false;
        };
        if entry.state != ChunkState::Invalidated {
            return false;
        }
        *entry = ChunkEntry::new(ChunkState::Wanted, timestamp);
        self.updated_at = timestamp;
        true
    }
}

#[cfg(test)]
#[path = "chunk_bitmap_inline_tests.rs"]
mod tests;

#[cfg(test)]
mod sparse_retry_tests {
    use super::*;

    #[test]
    fn sparse_missing_ranges_include_implicit_wanted_and_preserve_short_tail() {
        let mut bitmap = ChunkBitmap::new("sparse".to_owned(), 10, 4, 1);
        assert!(bitmap.get_missing_chunks().is_empty()); // Legacy query is unchanged.
        assert_eq!(bitmap.get_missing_chunk_ranges().unwrap(), vec![SparseRange::new(0, 10)]);
        assert_eq!(bitmap.entry_count(), 0);
        bitmap.update_chunk_state(0, ChunkState::Written, 2, Some([1; 32]));
        bitmap.update_chunk_state(8, ChunkState::Verified, 3, Some([2; 32]));
        assert_eq!(bitmap.get_missing_chunk_ranges().unwrap(), vec![SparseRange::new(4, 8)]);
        bitmap.update_chunk_state(4, ChunkState::Wanted, 4, None);
        let before = bitmap.serialize_to_bytes();
        assert_eq!(bitmap.get_missing_chunk_ranges().unwrap(), vec![SparseRange::new(4, 8)]);
        assert_eq!(bitmap.serialize_to_bytes(), before);
        let decoded = ChunkBitmap::deserialize_from_bytes(&before).unwrap();
        assert_eq!(decoded.get_missing_chunk_ranges().unwrap(), vec![SparseRange::new(4, 8)]);
    }

    #[test]
    fn invalidated_retry_discards_old_attempt_evidence_and_uses_normal_progression() {
        let mut bitmap = ChunkBitmap::new("retry".to_owned(), 4, 4, 1);
        bitmap.update_chunk_state(0, ChunkState::Verified, 2, Some([1; 32]));
        bitmap.set_chunk_metadata(0, "old-proof".to_owned(), "old-attempt".to_owned(), 3);
        assert_eq!(bitmap.invalidate_chunks_in_state(ChunkState::Verified, 4), 1);
        assert!(!bitmap.update_chunk_state(0, ChunkState::Wanted, 5, None));
        assert!(bitmap.get_missing_chunk_ranges().unwrap().is_empty());
        assert!(bitmap.requeue_invalidated_chunk(0, 6));
        let entry = bitmap.get_chunk_entry(0).unwrap();
        assert_eq!(entry.state, ChunkState::Wanted);
        assert_eq!(entry.state_timestamp, 6);
        assert_eq!(entry.chunk_hash, None);
        assert!(entry.metadata.is_empty());
        assert_eq!(bitmap.created_at(), 1);
        assert_eq!(bitmap.updated_at(), 6);
        assert_eq!(bitmap.entry_count(), 1);
        assert_eq!(bitmap.get_stats().verified_chunks, 0);
        assert_eq!(bitmap.get_missing_chunks(), vec![0]);
        assert_eq!(bitmap.get_missing_chunk_ranges().unwrap(), vec![SparseRange::new(0, 4)]);
        assert!(!bitmap.requeue_invalidated_chunk(0, 7));
        assert_eq!(bitmap.updated_at(), 6);
        for (state, timestamp, hash) in [
            (ChunkState::Received, 8, None),
            (ChunkState::Verified, 9, Some([2; 32])),
            (ChunkState::Written, 10, None),
            (ChunkState::Committed, 11, None),
        ] {
            assert!(bitmap.update_chunk_state(0, state, timestamp, hash));
        }
        assert_eq!(bitmap.get_chunk_entry(0).unwrap().chunk_hash, Some([2; 32]));
        assert!(bitmap.is_complete());
        assert!(bitmap.get_missing_chunk_ranges().unwrap().is_empty());
    }

    #[test]
    fn every_other_state_and_invalid_offset_refuse_retry_without_changing_evidence() {
        for state in ChunkState::all().iter().copied() {
            if state == ChunkState::Invalidated { continue; }
            let mut bitmap = ChunkBitmap::new("state".to_owned(), 8, 4, 1);
            bitmap.update_chunk_state(0, state, 2, Some([9; 32]));
            bitmap.set_chunk_metadata(0, "diagnostic".to_owned(), "keep".to_owned(), 3);
            let before = bitmap.serialize_to_bytes();
            assert!(!bitmap.requeue_invalidated_chunk(0, 99));
            assert_eq!(bitmap.serialize_to_bytes(), before, "state={state:?}");
            assert_eq!(bitmap.get_missing_chunk_ranges().unwrap(), if state == ChunkState::Wanted {
                vec![SparseRange::new(0, 8)]
            } else { vec![SparseRange::new(4, 8)] });
        }
        let mut bitmap = ChunkBitmap::new("diagnostic".to_owned(), 8, 4, 1);
        for offset in [1, 8, u64::MAX] {
            bitmap.update_chunk_state(offset, ChunkState::Invalidated, 2, Some([7; 32]));
            let before = bitmap.serialize_to_bytes();
            assert!(!bitmap.requeue_invalidated_chunk(offset, 3));
            assert_eq!(bitmap.serialize_to_bytes(), before);
        }
        assert!(!bitmap.requeue_invalidated_chunk(0, 4)); // Valid but untracked.
        assert_eq!(bitmap.get_missing_chunk_ranges().unwrap(), vec![SparseRange::new(0, 8)]);
    }

    #[test]
    fn huge_sparse_geometry_does_not_expand_missing_cells_and_zero_size_is_explicit() {
        let mut bitmap = ChunkBitmap::new("huge".to_owned(), u64::MAX, 1, 1);
        bitmap.update_chunk_state(0, ChunkState::Written, 2, None);
        bitmap.update_chunk_state(u64::MAX - 1, ChunkState::Written, 2, None);
        assert_eq!(bitmap.get_missing_chunk_ranges().unwrap(),
            vec![SparseRange::new(1, u64::MAX - 1)]);
        assert_eq!(bitmap.entry_count(), 2);
        let mut tail = ChunkBitmap::new("tail".to_owned(), u64::MAX, u64::MAX - 1, 1);
        tail.update_chunk_state(u64::MAX - 1, ChunkState::Written, 2, None);
        assert_eq!(tail.get_missing_chunk_ranges().unwrap(), vec![SparseRange::new(0, u64::MAX - 1)]);
        tail.update_chunk_state(0, ChunkState::Written, 3, None);
        assert!(tail.get_missing_chunk_ranges().unwrap().is_empty());
        let empty = ChunkBitmap::new("empty".to_owned(), 0, 4, 1);
        assert!(empty.get_missing_chunk_ranges().unwrap().is_empty());
        for size in [0, 1, u64::MAX] {
            let mut invalid = ChunkBitmap::new("invalid".to_owned(), size, 0, 1);
            invalid.update_chunk_state(0, ChunkState::Invalidated, 2, Some([1; 32]));
            let before = invalid.serialize_to_bytes();
            assert_eq!(invalid.get_missing_chunk_ranges().unwrap_err(),
                ChunkBitmapDecodeError::InvalidGeometry { total_size: size, chunk_size: 0 });
            assert!(!invalid.requeue_invalidated_chunk(0, 3));
            assert_eq!(invalid.serialize_to_bytes(), before);
        }
    }

    #[test]
    fn sparse_missing_and_retry_ranges_match_a_byte_set_oracle() {
        for (length, chunk_size) in [(5_u64, 1_u64), (11, 3), (17, 4)] {
            let count = length.div_ceil(chunk_size);
            for pattern in 0_u64..4_u64.pow(count as u32) {
                let mut bitmap = ChunkBitmap::new("oracle".to_owned(), length, chunk_size, 1);
                let mut digits = pattern;
                for i in 0..count {
                    let state = match digits % 4 {
                        0 => None,
                        1 => Some(ChunkState::Wanted),
                        2 => Some(ChunkState::Written),
                        _ => Some(ChunkState::Invalidated),
                    };
                    digits /= 4;
                    if let Some(state) = state { bitmap.update_chunk_state(i * chunk_size, state, 2, None); }
                }
                for retry in [false, true] {
                    if retry {
                        for i in 0..count { bitmap.requeue_invalidated_chunk(i * chunk_size, 3); }
                    }
                    let expected: Vec<u64> = (0..length).filter(|byte| {
                        matches!(bitmap.get_chunk_state((byte / chunk_size) * chunk_size),
                            None | Some(ChunkState::Wanted))
                    }).collect();
                    let ranges = bitmap.get_missing_chunk_ranges().unwrap();
                    assert!(ranges.iter().all(|r| r.start < r.end && r.end <= length));
                    assert!(ranges.windows(2).all(|pair| pair[0].end < pair[1].start));
                    let actual: Vec<u64> = ranges.iter().flat_map(|r| r.start..r.end).collect();
                    assert_eq!(actual, expected, "length={length} chunk={chunk_size} pattern={pattern} retry={retry}");
                }
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn persisted_sparse_retry_reopens_without_old_hash_or_quarantine_credit() {
        use crate::cx::Cx;
        use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
        use std::time::Duration;

        for workers in [1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::new().worker_threads(workers).with_sharded_state(true) };
            let runtime = builder.blocking_threads(1, 2).build().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let mut bitmap = ChunkBitmap::new("reopened".to_owned(), 16, 4, 1);
                bitmap.update_chunk_state(0, ChunkState::Written, 2, Some([1; 32]));
                bitmap.update_chunk_state(4, ChunkState::Invalidated, 3, Some([2; 32]));
                bitmap.set_chunk_metadata(4, "receipt".to_owned(), "old".to_owned(), 4);
                bitmap.update_chunk_state(8, ChunkState::Quarantined, 5, Some([3; 32]));
                let old_path = directory.path().join("before.bitmap");
                let old_bytes = bitmap.serialize_to_bytes();
                cx.scoped_fs().write(old_path.clone(), old_bytes.clone()).await.unwrap();
                let bytes = cx.scoped_fs().read(old_path.clone()).await.unwrap();
                let mut reopened = ChunkBitmap::deserialize_from_bytes(&bytes).unwrap();
                assert_eq!(reopened.get_missing_chunk_ranges().unwrap(), vec![SparseRange::new(12, 16)]);
                assert!(reopened.requeue_invalidated_chunk(4, 6));
                assert!(!reopened.requeue_invalidated_chunk(8, 6));
                let new_path = directory.path().join("after.bitmap");
                cx.scoped_fs().write(new_path.clone(), reopened.serialize_to_bytes()).await.unwrap();
                let bytes = cx.scoped_fs().read(new_path).await.unwrap();
                let reopened = ChunkBitmap::deserialize_from_bytes(&bytes).unwrap();
                assert_eq!(reopened.get_missing_chunk_ranges().unwrap(),
                    vec![SparseRange::new(4, 8), SparseRange::new(12, 16)]);
                assert_eq!(reopened.get_chunk_entry(4).unwrap().chunk_hash, None);
                assert!(reopened.get_chunk_entry(4).unwrap().metadata.is_empty());
                assert_eq!(reopened.get_chunk_entry(0).unwrap().chunk_hash, Some([1; 32]));
                assert_eq!(reopened.get_chunk_state(8), Some(ChunkState::Quarantined));
                assert!(reopened.has_errors());
                assert_eq!(cx.scoped_fs().read(old_path).await.unwrap(), old_bytes);
            });
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.pending_obligations, 0);
        }
    }
}
