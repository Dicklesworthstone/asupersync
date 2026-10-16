//! Symbol types for the RaptorQ-based distributed layer.
//!
//! This module provides the core symbol primitives used for erasure coding
//! in Asupersync's distributed structured concurrency layer. RaptorQ (RFC 6330)
//! is a fountain code that enables reliable data transmission with loss tolerance.
//!
//! # Core Types
//!
//! - [`ObjectId`]: Unique identifier for an object being encoded/decoded
//! - [`SymbolId`]: Identifies a specific symbol within an object (SBN + ESI)
//! - [`Symbol`]: The actual encoded data with its identity and metadata
//!
//! # RaptorQ Concepts
//!
//! - **Source symbols**: Original data split into fixed-size chunks
//! - **Repair symbols**: Generated symbols for redundancy (fountain property)
//! - **Source Block Number (SBN)**: For objects split into multiple blocks
//! - **Encoding Symbol ID (ESI)**: Index of symbol within a source block
//!
//! # Example
//!
//! ```ignore
//! // Create an object ID for data to encode
//! let object_id = ObjectId::new_random(&mut rng);
//!
//! // Symbol IDs identify specific symbols within the object
//! let symbol_id = SymbolId::new(object_id, 0, 0); // SBN=0, ESI=0
//!
//! // Symbols contain the actual encoded data
//! let symbol = Symbol::new(symbol_id, data, SymbolKind::Source);
//! ```

use core::fmt;

/// Maximum symbol payload size in bytes (default: 1280 bytes per RFC 6330 common usage).
pub const DEFAULT_SYMBOL_SIZE: usize = 1280;

/// A unique identifier for an object being encoded/decoded.
///
/// Objects are the high-level data units that get split into symbols
/// for erasure-coded transmission. Each object has a unique 128-bit ID.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct ObjectId {
    /// High 64 bits of the object ID.
    high: u64,
    /// Low 64 bits of the object ID.
    low: u64,
}

impl ObjectId {
    /// Creates a new object ID from two 64-bit values.
    #[inline]
    #[must_use]
    pub const fn new(high: u64, low: u64) -> Self {
        Self { high, low }
    }

    /// Creates an object ID from a 128-bit value.
    #[inline]
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self {
            high: (value >> 64) as u64,
            low: value as u64,
        }
    }

    /// Converts the object ID to a 128-bit value.
    #[inline]
    #[must_use]
    pub const fn as_u128(self) -> u128 {
        ((self.high as u128) << 64) | (self.low as u128)
    }

    /// Returns the high 64 bits.
    #[inline]
    #[must_use]
    pub const fn high(self) -> u64 {
        self.high
    }

    /// Returns the low 64 bits.
    #[inline]
    #[must_use]
    pub const fn low(self) -> u64 {
        self.low
    }

    /// Creates a random object ID using a deterministic RNG.
    ///
    /// This is the primary way to create object IDs in production code.
    #[must_use]
    pub fn new_random(rng: &mut crate::util::DetRng) -> Self {
        Self {
            high: rng.next_u64(),
            low: rng.next_u64(),
        }
    }

    /// Creates an object ID for testing purposes.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub const fn new_for_test(value: u64) -> Self {
        Self {
            high: 0,
            low: value,
        }
    }

    /// The nil (zero) object ID.
    pub const NIL: Self = Self { high: 0, low: 0 };
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({:016x}{:016x})", self.high, self.low)
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display abbreviated form (first 8 hex chars)
        write!(f, "Obj-{:08x}", (self.high >> 32) as u32)
    }
}

/// Identifies a specific symbol within an object.
///
/// A symbol ID consists of:
/// - The parent object ID
/// - Source Block Number (SBN): For objects split into multiple blocks
/// - Encoding Symbol ID (ESI): Index of symbol within the source block
///
/// For RaptorQ:
/// - ESI < K: source symbols (original data)
/// - ESI >= K: repair symbols (generated for redundancy)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId {
    /// The object this symbol belongs to.
    object_id: ObjectId,
    /// Source Block Number (which block within a large object).
    sbn: u8,
    /// Encoding Symbol ID (which symbol within the block).
    esi: u32,
}

impl SymbolId {
    /// Creates a new symbol ID.
    #[inline]
    #[must_use]
    pub const fn new(object_id: ObjectId, sbn: u8, esi: u32) -> Self {
        Self {
            object_id,
            sbn,
            esi,
        }
    }

    /// Returns the parent object ID.
    #[inline]
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        self.object_id
    }

    /// Returns the Source Block Number.
    #[inline]
    #[must_use]
    pub const fn sbn(self) -> u8 {
        self.sbn
    }

    /// Returns the Encoding Symbol ID.
    #[inline]
    #[must_use]
    pub const fn esi(self) -> u32 {
        self.esi
    }

    /// Returns true if this is a source symbol (ESI < source_count).
    #[inline]
    #[must_use]
    pub const fn is_source(self, source_count: u32) -> bool {
        self.esi < source_count
    }

    /// Returns true if this is a repair symbol (ESI >= source_count).
    #[inline]
    #[must_use]
    pub const fn is_repair(self, source_count: u32) -> bool {
        self.esi >= source_count
    }

    /// Creates a symbol ID for testing purposes.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub const fn new_for_test(object_value: u64, sbn: u8, esi: u32) -> Self {
        Self {
            object_id: ObjectId::new_for_test(object_value),
            sbn,
            esi,
        }
    }
}

impl fmt::Debug for SymbolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SymbolId({}, sbn={}, esi={})",
            self.object_id, self.sbn, self.esi
        )
    }
}

impl fmt::Display for SymbolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.object_id, self.sbn, self.esi)
    }
}

/// The kind of symbol (source or repair).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// A source symbol containing original data.
    Source,
    /// A repair symbol generated for redundancy.
    Repair,
}

impl SymbolKind {
    /// Returns true if this is a source symbol.
    #[inline]
    #[must_use]
    pub const fn is_source(self) -> bool {
        matches!(self, Self::Source)
    }

    /// Returns true if this is a repair symbol.
    #[inline]
    #[must_use]
    pub const fn is_repair(self) -> bool {
        matches!(self, Self::Repair)
    }
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => write!(f, "source"),
            Self::Repair => write!(f, "repair"),
        }
    }
}

/// An encoded symbol with its data payload.
///
/// Symbols are the fundamental unit of erasure-coded data. Each symbol
/// contains a fixed-size payload and metadata identifying it within its
/// parent object.
///
/// # Memory Layout
///
/// The symbol stores its data inline for cache efficiency. For larger
/// payloads or streaming scenarios, consider using `SymbolRef` (future).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Symbol {
    /// Unique identifier for this symbol.
    id: SymbolId,
    /// The kind of symbol (source or repair).
    kind: SymbolKind,
    /// The symbol payload data.
    data: Vec<u8>,
}

impl Symbol {
    /// Creates a new symbol with the given data.
    ///
    /// # Arguments
    ///
    /// * `id` - The unique identifier for this symbol
    /// * `data` - The payload data (will be cloned)
    /// * `kind` - Whether this is a source or repair symbol
    #[inline]
    #[must_use]
    pub fn new(id: SymbolId, data: Vec<u8>, kind: SymbolKind) -> Self {
        Self { id, kind, data }
    }

    /// Creates a symbol from a byte slice (copies the data).
    #[inline]
    #[must_use]
    pub fn from_slice(id: SymbolId, data: &[u8], kind: SymbolKind) -> Self {
        Self {
            id,
            kind,
            data: data.to_vec(),
        }
    }

    /// Creates an empty symbol with the specified size.
    #[inline]
    #[must_use]
    pub fn empty(id: SymbolId, size: usize, kind: SymbolKind) -> Self {
        Self {
            id,
            kind,
            data: vec![0u8; size],
        }
    }

    /// Returns the symbol's unique identifier.
    #[inline]
    #[must_use]
    pub const fn id(&self) -> SymbolId {
        self.id
    }

    /// Returns the symbol's kind.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> SymbolKind {
        self.kind
    }

    /// Returns the symbol's data payload.
    #[must_use]
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable reference to the symbol's data payload.
    #[inline]
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Consumes the symbol and returns its data.
    #[inline]
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Returns the size of the data payload in bytes.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the data payload is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the object ID this symbol belongs to.
    #[must_use]
    #[inline]
    pub const fn object_id(&self) -> ObjectId {
        self.id.object_id()
    }

    /// Returns the Source Block Number.
    #[inline]
    #[must_use]
    pub const fn sbn(&self) -> u8 {
        self.id.sbn()
    }

    /// Returns the Encoding Symbol ID.
    #[inline]
    #[must_use]
    pub const fn esi(&self) -> u32 {
        self.id.esi()
    }

    /// Creates a source symbol for testing purposes.
    ///
    /// This default matches the common test case of constructing ordered source
    /// sequences. When repair-kind semantics matter, tests must opt into
    /// [`Self::new_repair_for_test`] explicitly because source-vs-repair depends
    /// on block `K`, not on `esi == 0`.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub fn new_for_test(object_value: u64, sbn: u8, esi: u32, data: &[u8]) -> Self {
        Self::new_source_for_test(object_value, sbn, esi, data)
    }

    /// Creates an explicit source symbol for testing purposes.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub fn new_source_for_test(object_value: u64, sbn: u8, esi: u32, data: &[u8]) -> Self {
        Self {
            id: SymbolId::new_for_test(object_value, sbn, esi),
            kind: SymbolKind::Source,
            data: data.to_vec(),
        }
    }

    /// Creates an explicit repair symbol for testing purposes.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn new_repair_for_test(object_value: u64, sbn: u8, esi: u32, data: &[u8]) -> Self {
        Self {
            id: SymbolId::new_for_test(object_value, sbn, esi),
            kind: SymbolKind::Repair,
            data: data.to_vec(),
        }
    }
}

impl fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Symbol")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Symbol({}, {}, {} bytes)",
            self.id,
            self.kind,
            self.data.len()
        )
    }
}

/// Metadata about an object for encoding/decoding.
///
/// This contains the parameters needed to encode or decode an object
/// using RaptorQ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectParams {
    /// The object ID.
    pub object_id: ObjectId,
    /// Total size of the original object in bytes.
    pub object_size: u64,
    /// Size of each symbol in bytes.
    pub symbol_size: u16,
    /// Number of source blocks the object is divided into.
    pub source_blocks: u16,
    /// Number of source symbols per block (K).
    pub symbols_per_block: u16,
}

impl ObjectParams {
    /// Creates new object parameters.
    #[must_use]
    #[inline]
    pub const fn new(
        object_id: ObjectId,
        object_size: u64,
        symbol_size: u16,
        source_blocks: u16,
        symbols_per_block: u16,
    ) -> Self {
        Self {
            object_id,
            object_size,
            symbol_size,
            source_blocks,
            symbols_per_block,
        }
    }

    /// Calculates the minimum number of symbols needed for decoding.
    ///
    /// `ObjectParams` describes the entire encoded object, so the minimum
    /// decode threshold is the total source-symbol count across all source
    /// blocks, not the per-block `K`.
    #[must_use]
    #[inline]
    pub const fn min_symbols_for_decode(&self) -> u32 {
        self.total_source_symbols()
    }

    /// Calculates the total number of source symbols across all blocks.
    #[must_use]
    pub const fn total_source_symbols(&self) -> u32 {
        if self.symbol_size == 0 || self.object_size == 0 {
            return 0;
        }

        let sym_size = self.symbol_size as u64;
        let total = self.object_size.div_ceil(sym_size);
        if total > u32::MAX as u64 {
            u32::MAX
        } else {
            total as u32
        }
    }

    /// Creates object parameters for testing.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub const fn new_for_test(object_value: u64, size: u64) -> Self {
        let symbol_size = DEFAULT_SYMBOL_SIZE as u64;
        let symbols_per_block = if size == 0 {
            0
        } else {
            (size - 1) / symbol_size + 1
        };
        Self {
            object_id: ObjectId::new_for_test(object_value),
            object_size: size,
            symbol_size: DEFAULT_SYMBOL_SIZE as u16,
            source_blocks: 1,
            symbols_per_block: symbols_per_block as u16,
        }
    }
}

impl fmt::Display for ObjectParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjectParams({}, {} bytes, {} symbols/block)",
            self.object_id, self.object_size, self.symbols_per_block
        )
    }
}

#[cfg(test)]
#[path = "symbol_inline_tests.rs"]
mod tests;
