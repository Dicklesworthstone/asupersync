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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId {
    /// High 64 bits of the object ID.
    high: u64,
    /// Low 64 bits of the object ID.
    low: u64,
}

impl ObjectId {
    /// Creates a new object ID from two 64-bit values.
    #[must_use]
    pub const fn new(high: u64, low: u64) -> Self {
        Self { high, low }
    }

    /// Creates an object ID from a 128-bit value.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self {
            high: (value >> 64) as u64,
            low: value as u64,
        }
    }

    /// Converts the object ID to a 128-bit value.
    #[must_use]
    pub const fn as_u128(self) -> u128 {
        ((self.high as u128) << 64) | (self.low as u128)
    }

    /// Returns the high 64 bits.
    #[must_use]
    pub const fn high(self) -> u64 {
        self.high
    }

    /// Returns the low 64 bits.
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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
    #[must_use]
    pub const fn new(object_id: ObjectId, sbn: u8, esi: u32) -> Self {
        Self {
            object_id,
            sbn,
            esi,
        }
    }

    /// Returns the parent object ID.
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        self.object_id
    }

    /// Returns the Source Block Number.
    #[must_use]
    pub const fn sbn(self) -> u8 {
        self.sbn
    }

    /// Returns the Encoding Symbol ID.
    #[must_use]
    pub const fn esi(self) -> u32 {
        self.esi
    }

    /// Returns true if this is a source symbol (ESI < source_count).
    #[must_use]
    pub const fn is_source(self, source_count: u32) -> bool {
        self.esi < source_count
    }

    /// Returns true if this is a repair symbol (ESI >= source_count).
    #[must_use]
    pub const fn is_repair(self, source_count: u32) -> bool {
        self.esi >= source_count
    }

    /// Creates a symbol ID for testing purposes.
    #[doc(hidden)]
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
    #[must_use]
    pub const fn is_source(self) -> bool {
        matches!(self, Self::Source)
    }

    /// Returns true if this is a repair symbol.
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
    #[must_use]
    pub fn new(id: SymbolId, data: Vec<u8>, kind: SymbolKind) -> Self {
        Self { id, kind, data }
    }

    /// Creates a symbol from a byte slice (copies the data).
    #[must_use]
    pub fn from_slice(id: SymbolId, data: &[u8], kind: SymbolKind) -> Self {
        Self {
            id,
            kind,
            data: data.to_vec(),
        }
    }

    /// Creates an empty symbol with the specified size.
    #[must_use]
    pub fn empty(id: SymbolId, size: usize, kind: SymbolKind) -> Self {
        Self {
            id,
            kind,
            data: vec![0u8; size],
        }
    }

    /// Returns the symbol's unique identifier.
    #[must_use]
    pub const fn id(&self) -> SymbolId {
        self.id
    }

    /// Returns the symbol's kind.
    #[must_use]
    pub const fn kind(&self) -> SymbolKind {
        self.kind
    }

    /// Returns the symbol's data payload.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable reference to the symbol's data payload.
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Consumes the symbol and returns its data.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Returns the size of the data payload in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the data payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the object ID this symbol belongs to.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.id.object_id()
    }

    /// Returns the Source Block Number.
    #[must_use]
    pub const fn sbn(&self) -> u8 {
        self.id.sbn()
    }

    /// Returns the Encoding Symbol ID.
    #[must_use]
    pub const fn esi(&self) -> u32 {
        self.id.esi()
    }

    /// Creates a symbol for testing purposes with minimal data.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(object_value: u64, sbn: u8, esi: u32, data: &[u8]) -> Self {
        Self {
            id: SymbolId::new_for_test(object_value, sbn, esi),
            kind: if esi == 0 {
                SymbolKind::Source
            } else {
                SymbolKind::Repair
            },
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
    pub source_blocks: u8,
    /// Number of source symbols per block (K).
    pub symbols_per_block: u16,
}

impl ObjectParams {
    /// Creates new object parameters.
    #[must_use]
    pub const fn new(
        object_id: ObjectId,
        object_size: u64,
        symbol_size: u16,
        source_blocks: u8,
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
    /// For RaptorQ, you need at least K symbols to decode (where K is
    /// the number of source symbols), though having slightly more
    /// improves decoding probability.
    #[must_use]
    pub const fn min_symbols_for_decode(&self) -> u32 {
        self.symbols_per_block as u32
    }

    /// Calculates the total number of source symbols across all blocks.
    #[must_use]
    pub const fn total_source_symbols(&self) -> u32 {
        (self.source_blocks as u32) * (self.symbols_per_block as u32)
    }

    /// Creates object parameters for testing.
    #[doc(hidden)]
    #[must_use]
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
mod tests {
    use super::*;

    #[test]
    fn object_id_conversions() {
        let id = ObjectId::new(0x1234_5678_9abc_def0, 0xfed_cba9_8765_4321);
        assert_eq!(id.high(), 0x1234_5678_9abc_def0);
        assert_eq!(id.low(), 0xfed_cba9_8765_4321);

        let from_u128 = ObjectId::from_u128(id.as_u128());
        assert_eq!(id, from_u128);
    }

    #[test]
    fn object_id_nil() {
        let nil = ObjectId::NIL;
        assert_eq!(nil.high(), 0);
        assert_eq!(nil.low(), 0);
        assert_eq!(nil.as_u128(), 0);
    }

    #[test]
    fn object_id_test_constructor() {
        let id = ObjectId::new_for_test(42);
        assert_eq!(id.high(), 0);
        assert_eq!(id.low(), 42);
    }

    #[test]
    fn symbol_id_creation() {
        let object_id = ObjectId::new_for_test(1);
        let symbol_id = SymbolId::new(object_id, 0, 5);

        assert_eq!(symbol_id.object_id(), object_id);
        assert_eq!(symbol_id.sbn(), 0);
        assert_eq!(symbol_id.esi(), 5);
    }

    #[test]
    fn symbol_id_source_vs_repair() {
        let symbol_id = SymbolId::new_for_test(1, 0, 5);

        // With 10 source symbols, ESI 5 is a source symbol
        assert!(symbol_id.is_source(10));
        assert!(!symbol_id.is_repair(10));

        // With 5 source symbols, ESI 5 is a repair symbol
        assert!(!symbol_id.is_source(5));
        assert!(symbol_id.is_repair(5));
    }

    #[test]
    fn symbol_creation_and_data() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let data = vec![1, 2, 3, 4, 5];
        let symbol = Symbol::new(id, data.clone(), SymbolKind::Source);

        assert_eq!(symbol.id(), id);
        assert_eq!(symbol.kind(), SymbolKind::Source);
        assert_eq!(symbol.data(), &data[..]);
        assert_eq!(symbol.len(), 5);
        assert!(!symbol.is_empty());
    }

    #[test]
    fn symbol_from_slice() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let data = [10, 20, 30];
        let symbol = Symbol::from_slice(id, &data, SymbolKind::Repair);

        assert_eq!(symbol.data(), &data[..]);
        assert_eq!(symbol.kind(), SymbolKind::Repair);
    }

    #[test]
    fn symbol_empty() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::empty(id, 100, SymbolKind::Source);

        assert_eq!(symbol.len(), 100);
        assert!(symbol.data().iter().all(|&b| b == 0));
    }

    #[test]
    fn symbol_into_data() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let original_data = vec![1, 2, 3];
        let symbol = Symbol::new(id, original_data.clone(), SymbolKind::Source);

        let recovered = symbol.into_data();
        assert_eq!(recovered, original_data);
    }

    #[test]
    fn symbol_kind_checks() {
        assert!(SymbolKind::Source.is_source());
        assert!(!SymbolKind::Source.is_repair());
        assert!(!SymbolKind::Repair.is_source());
        assert!(SymbolKind::Repair.is_repair());
    }

    #[test]
    fn object_params_calculations() {
        let params = ObjectParams::new(
            ObjectId::new_for_test(1),
            10000, // 10KB object
            1280,  // symbol size
            1,     // 1 source block
            8,     // 8 symbols per block
        );

        assert_eq!(params.min_symbols_for_decode(), 8);
        assert_eq!(params.total_source_symbols(), 8);
    }

    #[test]
    fn object_params_multi_block() {
        let params = ObjectParams::new(
            ObjectId::new_for_test(1),
            1_000_000, // 1MB object
            1280,
            4,  // 4 source blocks
            64, // 64 symbols per block
        );

        assert_eq!(params.total_source_symbols(), 256);
    }

    #[test]
    fn display_formatting() {
        let object_id = ObjectId::new(0x1234_5678_0000_0000, 0);
        assert!(format!("{object_id}").contains("Obj-"));

        let symbol_id = SymbolId::new(object_id, 1, 42);
        let display = format!("{symbol_id}");
        assert!(display.contains(":1:42"));

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let display = format!("{symbol}");
        assert!(display.contains("3 bytes"));
    }

    #[test]
    fn debug_formatting() {
        let object_id = ObjectId::new_for_test(42);
        let debug = format!("{object_id:?}");
        assert!(debug.contains("ObjectId"));

        let symbol_id = SymbolId::new_for_test(1, 2, 3);
        let debug = format!("{symbol_id:?}");
        assert!(debug.contains("SymbolId"));
        assert!(debug.contains("sbn=2"));
        assert!(debug.contains("esi=3"));
    }
}
