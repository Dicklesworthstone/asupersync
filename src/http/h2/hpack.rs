//! HPACK header compression for HTTP/2.
//!
//! Implements RFC 7541: HPACK - Header Compression for HTTP/2.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use crate::bytes::{Bytes, BytesMut};

use super::error::H2Error;

/// br-asupersync-1tvdlr: 4-bit-stride Huffman decoder state table.
///
/// Pre-builds the canonical HPACK decoder table used by nghttp2 / h2:
/// 256 trie-states × 16 input nibbles × 4 bytes = 16 KiB, fits in L1.
///
/// Each input byte is processed as two 4-bit nibbles; per nibble we do a
/// single array lookup that returns `(next_state, flags, sym)`. This
/// replaces the prior `HashMap<(u32,u8), Option<u8>>` whose hot-path
/// decode loop performed a HashMap lookup per code length per symbol —
/// with up to 22 such probes for the longest codes. Branchless table
/// lookup is uniformly faster than the prior cascade of 5/6/7/8-bit
/// `match` fast-paths plus HashMap slow path.
///
/// Flags semantics (per nghttp2):
///   * HUFF_ACCEPTED: ending the decode here is a valid termination
///     (the resulting state is root, or a 1-7 bit prefix of EOS — the
///     only valid HPACK paddings per RFC 7541 §5.2).
///   * HUFF_SYM: the entry decoded a symbol (`sym` field is valid).
///   * HUFF_FAIL: the input byte sequence is not decodable from this
///     state (the trie has no such transition, or the EOS symbol was
///     reached, which RFC 7541 §5.2 forbids).
const HUFF_ACCEPTED: u8 = 0x01;
const HUFF_SYM: u8 = 0x02;
const HUFF_FAIL: u8 = 0x04;

#[derive(Copy, Clone, Default)]
struct HuffmanDecodeEntry {
    /// Resulting decoder state (0 = root) after consuming this nibble
    /// from the starting state. Meaningless when HUFF_FAIL is set.
    next_state: u8,
    /// Bitwise OR of HUFF_ACCEPTED, HUFF_SYM, HUFF_FAIL.
    flags: u8,
    /// Symbol byte if HUFF_SYM is set; 0 otherwise.
    sym: u8,
    /// Padding for natural u32 alignment.
    _pad: u8,
}

static HUFFMAN_DECODE_TABLE: LazyLock<Box<[[HuffmanDecodeEntry; 16]; 256]>> =
    LazyLock::new(build_huffman_decode_table);

#[allow(clippy::too_many_lines)] // Trie + table builder splits would obscure the bit-level semantics.
fn build_huffman_decode_table() -> Box<[[HuffmanDecodeEntry; 16]; 256]> {
    // Step 1: build a binary trie from HUFFMAN_TABLE. Bit positions are
    // walked MSB-first, matching how the encoder packs codes.
    #[derive(Default, Clone)]
    struct TrieNode {
        children: [Option<usize>; 2],
        sym: Option<u16>,
    }
    let mut nodes: Vec<TrieNode> = vec![TrieNode::default()]; // node 0 = root
    for (sym_idx, &(code, code_bits)) in HUFFMAN_TABLE.iter().enumerate() {
        let mut cur = 0usize;
        for bit_pos in (0..code_bits).rev() {
            let bit = ((code >> bit_pos) & 1) as usize;
            cur = match nodes[cur].children[bit] {
                Some(idx) => idx,
                None => {
                    let new_idx = nodes.len();
                    nodes.push(TrieNode::default());
                    nodes[cur].children[bit] = Some(new_idx);
                    new_idx
                }
            };
        }
        nodes[cur].sym = Some(sym_idx as u16);
    }

    // Step 2: assign u8 state IDs to internal nodes only (HPACK has 257
    // leaves so the trie has exactly 256 internal nodes — fits in u8).
    let mut state_of_node: Vec<Option<u8>> = vec![None; nodes.len()];
    let mut next_state_id: u32 = 0;
    for (idx, n) in nodes.iter().enumerate() {
        if n.sym.is_none() {
            assert!(
                next_state_id < 256,
                "HPACK trie exceeded 256 internal nodes"
            );
            state_of_node[idx] = Some(next_state_id as u8);
            next_state_id += 1;
        }
    }
    let num_states = next_state_id as usize;

    let mut node_of_state: Vec<usize> = vec![0; num_states];
    for (idx, &maybe_id) in state_of_node.iter().enumerate() {
        if let Some(id) = maybe_id {
            node_of_state[id as usize] = idx;
        }
    }

    // Step 3: identify ACCEPTED states. Per RFC 7541 §5.2, valid padding
    // is 0-7 trailing bits forming a prefix of the EOS code (all 1s).
    // So accepted states are: root, plus the right-only-edge path of
    // depth 1..=7. Padding ≥ 8 bits is a decoding error.
    let mut accepted_state = [false; 256];
    accepted_state[0] = true;
    let mut walk = 0usize;
    for _depth in 1..=7 {
        match nodes[walk].children[1] {
            Some(idx) if nodes[idx].sym.is_none() => {
                let st = state_of_node[idx].expect("EOS prefix node missing state ID");
                accepted_state[st as usize] = true;
                walk = idx;
            }
            _ => break,
        }
    }

    // Step 4: simulate consuming each 4-bit nibble from each starting
    // state. Per HPACK constraints (5-bit minimum code length) at most
    // ONE symbol can be emitted within a 4-bit window from any starting
    // state, so the entry stores at most one `sym`.
    let mut table: Box<[[HuffmanDecodeEntry; 16]; 256]> =
        Box::new([[HuffmanDecodeEntry::default(); 16]; 256]);
    for state in 0..num_states {
        let start_node = node_of_state[state];
        for nibble in 0u8..16 {
            let mut cur_node = start_node;
            let mut emitted: Option<u8> = None;
            let mut fail = false;
            for bit_idx in 0..4u8 {
                let bit = ((nibble >> (3 - bit_idx)) & 1) as usize;
                cur_node = match nodes[cur_node].children[bit] {
                    Some(idx) => idx,
                    None => {
                        fail = true;
                        break;
                    }
                };
                if let Some(sym) = nodes[cur_node].sym {
                    if sym == 256 {
                        fail = true; // EOS symbol literal-encoded — RFC 7541 §5.2 forbids.
                        break;
                    }
                    if emitted.is_some() {
                        // Defensive: HPACK 5-bit minimum precludes two symbols per nibble.
                        fail = true;
                        break;
                    }
                    emitted = Some(sym as u8);
                    cur_node = 0; // reset to root after emitting
                }
            }

            let entry = if fail {
                HuffmanDecodeEntry {
                    next_state: 0,
                    flags: HUFF_FAIL,
                    sym: 0,
                    _pad: 0,
                }
            } else {
                let next_state = state_of_node[cur_node].expect("trie walk landed on a leaf");
                let mut flags = 0u8;
                if emitted.is_some() {
                    flags |= HUFF_SYM;
                }
                if accepted_state[next_state as usize] {
                    flags |= HUFF_ACCEPTED;
                }
                HuffmanDecodeEntry {
                    next_state,
                    flags,
                    sym: emitted.unwrap_or(0),
                    _pad: 0,
                }
            };
            table[state][nibble as usize] = entry;
        }
    }
    table
}

/// Pre-built index for exact (name, value) → 1-based static table index lookups.
static STATIC_EXACT_INDEX: LazyLock<HashMap<(&'static str, &'static str), usize>> =
    LazyLock::new(|| {
        STATIC_TABLE
            .iter()
            .enumerate()
            .map(|(i, &(n, v))| ((n, v), i.saturating_add(1)))
            .collect()
    });

/// Pre-built index for name-only → first 1-based static table index lookups.
static STATIC_NAME_INDEX: LazyLock<HashMap<&'static str, usize>> = LazyLock::new(|| {
    let mut map = HashMap::with_capacity(STATIC_TABLE.len());
    for (i, &(name, _)) in STATIC_TABLE.iter().enumerate() {
        map.entry(name).or_insert(i.saturating_add(1));
    }
    map
});

/// Maximum allowed HPACK table size to prevent DoS (1MB).
const MAX_ALLOWED_TABLE_SIZE: usize = 1024 * 1024;

/// Maximum size of the dynamic table (default: 4096 bytes).
pub const DEFAULT_MAX_TABLE_SIZE: usize = 4096;

/// Static table entries as defined in RFC 7541 Appendix A.
static STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),                   // 1
    (":method", "GET"),                   // 2
    (":method", "POST"),                  // 3
    (":path", "/"),                       // 4
    (":path", "/index.html"),             // 5
    (":scheme", "http"),                  // 6
    (":scheme", "https"),                 // 7
    (":status", "200"),                   // 8
    (":status", "204"),                   // 9
    (":status", "206"),                   // 10
    (":status", "304"),                   // 11
    (":status", "400"),                   // 12
    (":status", "404"),                   // 13
    (":status", "500"),                   // 14
    ("accept-charset", ""),               // 15
    ("accept-encoding", "gzip, deflate"), // 16
    ("accept-language", ""),              // 17
    ("accept-ranges", ""),                // 18
    ("accept", ""),                       // 19
    ("access-control-allow-origin", ""),  // 20
    ("age", ""),                          // 21
    ("allow", ""),                        // 22
    ("authorization", ""),                // 23
    ("cache-control", ""),                // 24
    ("content-disposition", ""),          // 25
    ("content-encoding", ""),             // 26
    ("content-language", ""),             // 27
    ("content-length", ""),               // 28
    ("content-location", ""),             // 29
    ("content-range", ""),                // 30
    ("content-type", ""),                 // 31
    ("cookie", ""),                       // 32
    ("date", ""),                         // 33
    ("etag", ""),                         // 34
    ("expect", ""),                       // 35
    ("expires", ""),                      // 36
    ("from", ""),                         // 37
    ("host", ""),                         // 38
    ("if-match", ""),                     // 39
    ("if-modified-since", ""),            // 40
    ("if-none-match", ""),                // 41
    ("if-range", ""),                     // 42
    ("if-unmodified-since", ""),          // 43
    ("last-modified", ""),                // 44
    ("link", ""),                         // 45
    ("location", ""),                     // 46
    ("max-forwards", ""),                 // 47
    ("proxy-authenticate", ""),           // 48
    ("proxy-authorization", ""),          // 49
    ("range", ""),                        // 50
    ("referer", ""),                      // 51
    ("refresh", ""),                      // 52
    ("retry-after", ""),                  // 53
    ("server", ""),                       // 54
    ("set-cookie", ""),                   // 55
    ("strict-transport-security", ""),    // 56
    ("transfer-encoding", ""),            // 57
    ("user-agent", ""),                   // 58
    ("vary", ""),                         // 59
    ("via", ""),                          // 60
    ("www-authenticate", ""),             // 61
];

/// A header name-value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Header name (lowercase).
    pub name: String,
    /// Header value.
    pub value: String,
}

impl Header {
    /// Create a new header.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Calculate the size of this header for HPACK table purposes.
    /// Size = name bytes + value bytes + 32 overhead.
    #[must_use]
    pub fn size(&self) -> usize {
        self.name
            .len()
            .saturating_add(self.value.len())
            .saturating_add(32)
    }
}

/// Internal storage entry for the dynamic table (br-asupersync-d04pmz).
///
/// Uses `Arc<str>` instead of `String` so cloning an entry — required on
/// every "indexed header" decode and "literal with incremental indexing"
/// — is two atomic refcount bumps (~10 ns total) rather than two heap
/// allocations + memcpy of the name + value bytes (hundreds of ns each
/// for typical header sizes).
///
/// The user-facing `Header` type still uses `String` (preserving the
/// public API). Conversion happens at the dynamic-table boundary:
///   * insert: pays the alloc-once cost (Arc::from(String) is one alloc
///     + one move)
///   * lookup: returns &DynamicTableEntry, callers Arc::clone to keep
///     a reference, then convert to Header at their boundary
///
/// Pre-fix: `dynamic_table.insert(header.clone())` at decoder.rs:579
/// allocated TWO Strings per dynamic-table insert (the clone() before
/// insert) plus another two when the caller built the returned Header.
/// Post-fix: Arc construction once, refcount bumps thereafter.
#[derive(Debug, Clone)]
struct DynamicTableEntry {
    name: std::sync::Arc<str>,
    value: std::sync::Arc<str>,
    /// RFC 7541 §4.1 size: the name's and value's octets plus 32. It is
    /// kept rather than recomputed because a value decoded from obs-text
    /// holds more UTF-8 bytes than the octets the peer sent and counted.
    size: usize,
    /// Monotonic generation assigned at insert time. Used by the side
    /// indices (see `DynamicTable`) to recover an entry's current
    /// position in O(1) without walking `entries`. See
    /// `DynamicTable::index_from_generation` for the position formula.
    generation: u64,
}

impl DynamicTableEntry {
    /// Construct from owned Strings, paying the allocation once into Arc.
    /// `value_octets` is the value's length on the wire.
    fn from_strings(name: String, value: String, value_octets: usize, generation: u64) -> Self {
        let size = name.len().saturating_add(value_octets).saturating_add(32);
        Self {
            name: std::sync::Arc::from(name.into_boxed_str()),
            value: std::sync::Arc::from(value.into_boxed_str()),
            size,
            generation,
        }
    }

    /// Convert back to a public `Header` by allocating fresh Strings.
    /// (The Arc<str> doesn't satisfy the public API; callers needing a
    /// Header must allocate. This still saves the dynamic-table-side
    /// clone — see file header doc.)
    fn to_header(&self) -> Header {
        Header {
            name: self.name.as_ref().to_string(),
            value: self.value.as_ref().to_string(),
        }
    }

    fn size(&self) -> usize {
        self.size
    }
}

/// Side indices for O(1) dynamic-table lookups.
///
/// br-asupersync-4pshog: previously `find`/`find_name` walked `entries`
/// linearly on every encoded header, costing
/// `O(headers × table_size)` per request. The two HashMaps below let
/// `find` and `find_name` resolve the matching entry in expected O(1),
/// trading a few KiB of extra memory for the win.
///
/// Both maps store **generations**, not positions, because positions
/// shift on `push_front`. A generation is the monotonic
/// `insert_count` value at the moment the entry was inserted; it never
/// changes. We recover the entry's current 0-indexed position via
/// `i = (insert_count - 1) - generation` (see
/// `DynamicTable::index_from_generation`). When the table is mutated:
///
/// - **insert** (push_front): assign a new generation = old
///   `insert_count`, increment `insert_count`, then push the
///   generation onto the **front** of each side-index `VecDeque`.
///   Newest entry has the largest generation, so it sits at front.
/// - **evict** (pop_back): the entry being removed always has the
///   smallest generation among entries with the same (name, value)
///   and the smallest among those with the same name (FIFO order),
///   so we pop from the **back** of the relevant `VecDeque`s. The
///   `debug_assert_eq!` in `pop_back_with_index_cleanup` enforces
///   this invariant.
#[derive(Debug, Default)]
struct DynamicTableIndex {
    /// `name → value → deque<generation>` (front = newest).
    /// Two-level keying lets `find` resolve an exact match in
    /// `O(1)` expected without scanning entries that share a name.
    by_name_value: HashMap<std::sync::Arc<str>, HashMap<std::sync::Arc<str>, VecDeque<u64>>>,
    /// `name → deque<generation>` (front = newest).
    /// Used by `find_name` to return the most-recent generation for a
    /// name without a value comparison.
    by_name: HashMap<std::sync::Arc<str>, VecDeque<u64>>,
}

impl DynamicTableIndex {
    fn add(&mut self, name: &std::sync::Arc<str>, value: &std::sync::Arc<str>, generation: u64) {
        self.by_name_value
            .entry(std::sync::Arc::clone(name))
            .or_default()
            .entry(std::sync::Arc::clone(value))
            .or_default()
            .push_front(generation);
        self.by_name
            .entry(std::sync::Arc::clone(name))
            .or_default()
            .push_front(generation);
    }

    fn remove_oldest(
        &mut self,
        name: &std::sync::Arc<str>,
        value: &std::sync::Arc<str>,
        generation: u64,
    ) {
        if let Some(inner) = self.by_name_value.get_mut(name.as_ref()) {
            if let Some(deque) = inner.get_mut(value.as_ref()) {
                debug_assert_eq!(
                    deque.back().copied(),
                    Some(generation),
                    "evicted generation must be the oldest in by_name_value bucket"
                );
                deque.pop_back();
                if deque.is_empty() {
                    inner.remove(value.as_ref());
                }
            }
            if inner.is_empty() {
                self.by_name_value.remove(name.as_ref());
            }
        }
        if let Some(deque) = self.by_name.get_mut(name.as_ref()) {
            debug_assert_eq!(
                deque.back().copied(),
                Some(generation),
                "evicted generation must be the oldest in by_name bucket"
            );
            deque.pop_back();
            if deque.is_empty() {
                self.by_name.remove(name.as_ref());
            }
        }
    }

    fn newest_for_pair(&self, name: &str, value: &str) -> Option<u64> {
        self.by_name_value.get(name)?.get(value)?.front().copied()
    }

    fn newest_for_name(&self, name: &str) -> Option<u64> {
        self.by_name.get(name)?.front().copied()
    }

    fn clear(&mut self) {
        self.by_name_value.clear();
        self.by_name.clear();
    }
}

/// Dynamic table for HPACK encoding/decoding.
///
/// Uses `VecDeque` so that front insertion (`push_front`) is O(1) amortized
/// rather than the O(n) of `Vec::insert(0, ...)`.
///
/// br-asupersync-d04pmz: stores `DynamicTableEntry` (`Arc<str>`) internally
/// rather than `Header` (String) so post-insert clones cost atomic
/// refcount bumps instead of full String allocs.
///
/// br-asupersync-4pshog: also keeps `DynamicTableIndex` side maps so
/// that `find` and `find_name` resolve in expected O(1) instead of
/// scanning every entry on every encoded header.
#[derive(Debug)]
pub struct DynamicTable {
    entries: VecDeque<DynamicTableEntry>,
    size: usize,
    max_size: usize,
    /// Monotonic counter assigned to entries on insert (never decreases,
    /// even on eviction or `set_max_size`). Combined with an entry's
    /// `generation` it yields the entry's current 0-indexed position
    /// without scanning `entries`.
    insert_count: u64,
    /// Side indices for O(1) `find` / `find_name`. See
    /// [`DynamicTableIndex`] for the invariants.
    index: DynamicTableIndex,
}

impl DynamicTable {
    /// Create a new dynamic table with default max size.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_size(DEFAULT_MAX_TABLE_SIZE)
    }

    /// Create a dynamic table with specified max size.
    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size: max_size.min(MAX_ALLOWED_TABLE_SIZE),
            insert_count: 0,
            index: DynamicTableIndex::default(),
        }
    }

    /// Get the current size of the table.
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get the maximum size of the table.
    #[must_use]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Set the maximum size of the table, evicting entries if necessary.
    pub fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size.min(MAX_ALLOWED_TABLE_SIZE);
        self.evict();
    }

    /// Insert a new entry at the beginning of the table.
    pub fn insert(&mut self, header: Header) {
        let value_octets = header.value.len();
        self.insert_counted(header, value_octets);
    }

    /// Insert an entry whose value the peer sent as `value_octets` octets.
    /// RFC 7541 §4.1 sizes the entry by those octets, which a value decoded
    /// from obs-text exceeds in UTF-8.
    fn insert_counted(&mut self, header: Header, value_octets: usize) {
        // br-asupersync-d04pmz: convert at the boundary — pays the
        // Arc::from(String) alloc ONCE; subsequent table accesses are
        // refcount bumps.
        // br-asupersync-4pshog: stamp the entry with a monotonic
        // generation so the side index can recover its position later
        // in O(1).
        let generation = self.insert_count;
        let entry =
            DynamicTableEntry::from_strings(header.name, header.value, value_octets, generation);
        let entry_size = entry.size();

        // Evict oldest entries (at back) to make room. Use the
        // index-aware pop so the side indices stay in sync.
        while self.size.saturating_add(entry_size) > self.max_size && !self.entries.is_empty() {
            self.pop_back_with_index_cleanup();
        }

        // Only insert if it fits.
        if entry_size <= self.max_size {
            self.index.add(&entry.name, &entry.value, generation);
            // Increment generation counter only when the entry is
            // actually retained, so unfit-and-skipped inserts don't
            // poison future position math.
            self.insert_count = self.insert_count.saturating_add(1);
            self.size = self.size.saturating_add(entry_size);
            self.entries.push_front(entry);
        } else {
            // Entry too large to ever fit; the spec requires the table
            // to be emptied (RFC 7541 §4.4). The eviction loop above
            // already drained it, but be explicit so the indices match
            // and any future regression of the eviction loop can't
            // leak entries into the indices.
            debug_assert!(self.entries.is_empty());
            self.index.clear();
        }
    }

    /// Get an entry by index (1-indexed, after static table).
    ///
    /// br-asupersync-d04pmz: returns an owned Header (allocating fresh
    /// Strings from the internal `Arc<str>`). Callers that want to avoid
    /// this allocation should be migrated to use the index-only path
    /// or a future `Arc<str>`-aware accessor.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<Header> {
        if index == 0 || index > self.entries.len() {
            None
        } else {
            Some(self.entries[index.saturating_sub(1)].to_header())
        }
    }

    /// The RFC 7541 size of the entry at `index` (1-based), without copying it.
    fn entry_size(&self, index: usize) -> Option<usize> {
        index
            .checked_sub(1)
            .and_then(|position| self.entries.get(position))
            .map(DynamicTableEntry::size)
    }

    /// Find an entry by name and value, returning the index if found.
    ///
    /// br-asupersync-4pshog: O(1) expected via the side index.
    #[must_use]
    pub fn find(&self, name: &str, value: &str) -> Option<usize> {
        let generation = self.index.newest_for_pair(name, value)?;
        Some(self.index_from_generation(generation))
    }

    /// Find an entry by name only, returning the index if found.
    ///
    /// br-asupersync-4pshog: O(1) expected via the side index.
    #[must_use]
    pub fn find_name(&self, name: &str) -> Option<usize> {
        let generation = self.index.newest_for_name(name)?;
        Some(self.index_from_generation(generation))
    }

    /// Convert a stored entry generation into its current 1-indexed
    /// HPACK index (which is `STATIC_TABLE.len() + position + 1`).
    ///
    /// Position formula: with `insert_count` monotonically incremented
    /// on each retained insert and `generation` set to the value of
    /// `insert_count` at that insert, the entry's 0-indexed position
    /// in `entries` (front=0) is `(insert_count - 1) - generation`,
    /// hence the HPACK index is
    /// `STATIC_TABLE.len() + insert_count - generation`.
    fn index_from_generation(&self, generation: u64) -> usize {
        debug_assert!(self.insert_count > generation);
        STATIC_TABLE.len()
            + usize::try_from(self.insert_count.saturating_sub(generation))
                .unwrap_or(self.entries.len())
    }

    /// Pop the oldest entry and remove it from the side indices.
    fn pop_back_with_index_cleanup(&mut self) {
        if let Some(evicted) = self.entries.pop_back() {
            self.size = self.size.saturating_sub(evicted.size());
            self.index
                .remove_oldest(&evicted.name, &evicted.value, evicted.generation);
        }
    }

    /// Evict oldest entries (at back) to fit within max size.
    fn evict(&mut self) {
        while self.size > self.max_size && !self.entries.is_empty() {
            self.pop_back_with_index_cleanup();
        }
    }
}

impl Default for DynamicTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Find entry in static table by name and value (O(1) via pre-built index).
fn find_static(name: &str, value: &str) -> Option<usize> {
    STATIC_EXACT_INDEX.get(&(name, value)).copied()
}

/// Find entry in static table by name only (O(1) via pre-built index).
fn find_static_name(name: &str) -> Option<usize> {
    STATIC_NAME_INDEX.get(name).copied()
}

/// Get entry from static table by index.
fn get_static(index: usize) -> Option<(&'static str, &'static str)> {
    if index == 0 || index > STATIC_TABLE.len() {
        None
    } else {
        Some(STATIC_TABLE[index.saturating_sub(1)])
    }
}

/// HPACK encoder for encoding headers.
#[derive(Debug)]
pub struct Encoder {
    dynamic_table: DynamicTable,
    use_huffman: bool,
    /// Minimum dynamic table size observed since the last header block.
    /// RFC 7541 Section 4.2 requires emitting a size reduction if the size
    /// dropped and then increased between blocks.
    min_size_update: Option<usize>,
    /// Pending final dynamic table size update to emit at the start of the next header block.
    /// RFC 7541 Section 6.3 requires this when the table size changes.
    pending_size_update: Option<usize>,
}

impl Encoder {
    /// Create a new encoder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_size(DEFAULT_MAX_TABLE_SIZE)
    }

    /// Create an encoder with specified max table size.
    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::with_max_size(max_size),
            use_huffman: true,
            min_size_update: None,
            pending_size_update: None,
        }
    }

    /// Set whether to use Huffman encoding for strings.
    pub fn set_use_huffman(&mut self, use_huffman: bool) {
        self.use_huffman = use_huffman;
    }

    /// Set the maximum dynamic table size.
    ///
    /// Per RFC 7541 Section 6.3, the encoder will emit a dynamic table size
    /// update at the start of the next encoded header block.
    pub fn set_max_table_size(&mut self, size: usize) {
        let capped = size.min(MAX_ALLOWED_TABLE_SIZE);
        self.dynamic_table.set_max_size(capped);

        if let Some(min_so_far) = self.min_size_update {
            self.min_size_update = Some(min_so_far.min(capped));
        } else {
            self.min_size_update = Some(capped);
        }
        self.pending_size_update = Some(capped);
    }

    /// Returns the current dynamic table size in bytes.
    #[must_use]
    pub fn dynamic_table_size(&self) -> usize {
        self.dynamic_table.size()
    }

    /// Returns the current dynamic table size limit in bytes.
    #[must_use]
    pub fn dynamic_table_max_size(&self) -> usize {
        self.dynamic_table.max_size()
    }

    /// Encode a list of headers.
    ///
    /// If a dynamic table size update is pending (from `set_max_table_size`),
    /// it is emitted at the start of the block per RFC 7541 Section 6.3.
    pub fn encode(&mut self, headers: &[Header], dst: &mut BytesMut) {
        self.emit_pending_size_update(dst);
        for header in headers {
            self.encode_header(header, dst, true);
        }
    }

    /// Encode headers as "never indexed" (for sensitive headers like auth tokens).
    ///
    /// Uses RFC 7541 §6.2.3 "Literal Header Field Never Indexed" representation,
    /// which signals to intermediaries that these headers must not be compressed
    /// or added to any index, even on re-encoding.
    ///
    /// If a dynamic table size update is pending, it is emitted first.
    pub fn encode_sensitive(&mut self, headers: &[Header], dst: &mut BytesMut) {
        self.emit_pending_size_update(dst);
        for header in headers {
            self.encode_header(header, dst, false);
        }
    }

    /// Emit a pending dynamic table size update instruction on the wire.
    fn emit_pending_size_update(&mut self, dst: &mut BytesMut) {
        if let Some(min_size) = self.min_size_update.take() {
            if let Some(final_size) = self.pending_size_update.take() {
                if min_size < final_size {
                    encode_integer(dst, min_size, 5, 0x20);
                }
                encode_integer(dst, final_size, 5, 0x20);
            }
        }
    }

    /// Encode a single header.
    fn encode_header(&mut self, header: &Header, dst: &mut BytesMut, index: bool) {
        let normalized_name = if header.name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(header.name.to_ascii_lowercase())
        } else {
            Cow::Borrowed(header.name.as_str())
        };
        let name = normalized_name.as_ref();
        let value = header.value.as_str();

        if index {
            // Exact-match indexing is only legal for regular indexed fields.
            // Sensitive headers must stay on the RFC 7541 §6.2.3 "never
            // indexed" representation even if the same name/value is already
            // present in the static or dynamic table.
            if let Some(idx) =
                find_static(name, value).or_else(|| self.dynamic_table.find(name, value))
            {
                encode_integer(dst, idx, 7, 0x80);
                return;
            }
        }

        // Try to find name match
        let name_idx = find_static_name(name).or_else(|| self.dynamic_table.find_name(name));

        if index {
            // Literal with incremental indexing
            if let Some(idx) = name_idx {
                encode_integer(dst, idx, 6, 0x40);
            } else {
                dst.put_u8(0x40);
                encode_string(dst, name, self.use_huffman);
            }
            encode_string(dst, value, self.use_huffman);

            // br-asupersync-nzs9lx — construct the indexed header directly.
            // The previous shape was `let mut h = header.clone(); h.name =
            // normalized_name.into_owned();` which cloned `header.name` only
            // to immediately drop it and overwrite with the normalized form
            // — wasted String clone + drop per insert. Now the name is
            // moved out of the Cow once (Borrowed → owned, or Owned →
            // moved) and only the value is cloned.
            let indexed_header = Header {
                name: normalized_name.into_owned(),
                value: header.value.clone(),
            };
            self.dynamic_table.insert(indexed_header);
        } else {
            // Literal without indexing (never indexed for sensitive)
            if let Some(idx) = name_idx {
                encode_integer(dst, idx, 4, 0x10);
            } else {
                dst.put_u8(0x10);
                encode_string(dst, name, self.use_huffman);
            }
            encode_string(dst, value, self.use_huffman);
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum allowed decoded string length to prevent DoS (256 KB).
/// This bounds the allocation size before the header-list-size check runs.
const MAX_STRING_LENGTH: usize = 256 * 1024;
/// Maximum consecutive dynamic table size updates allowed at block start.
const MAX_SIZE_UPDATES: usize = 16;
/// Hard ceiling on one decoded header list (RFC 7541 section 4.1 sizes),
/// applied even when the configured `max_header_list_size` is "unlimited"
/// (`u32::MAX`, which gRPC's `max_metadata_size(0)` maps to). An indexed field
/// costs one octet on the wire but decodes to a full copy of a dynamic-table
/// entry, so a single 256 KiB block of them could otherwise allocate about a
/// gigabyte (br-asupersync-dycth8 H1). 16 MiB is the `h2` crate's default
/// header list limit, far above any real request's headers.
const MAX_DECODED_HEADER_LIST_SIZE: usize = 16 * 1024 * 1024;

/// HPACK decoder for decoding headers.
#[derive(Debug)]
pub struct Decoder {
    dynamic_table: DynamicTable,
    max_header_list_size: usize,
    /// Maximum table size allowed by SETTINGS (from peer).
    /// Dynamic table size updates must not exceed this.
    allowed_table_size: usize,
}

impl Decoder {
    /// Create a new decoder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_size(DEFAULT_MAX_TABLE_SIZE)
    }

    /// Create a decoder with specified max table size.
    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        let capped_size = max_size.min(MAX_ALLOWED_TABLE_SIZE);
        Self {
            dynamic_table: DynamicTable::with_max_size(capped_size),
            max_header_list_size: 16384,
            allowed_table_size: capped_size,
        }
    }

    /// Set the maximum header list size.
    ///
    /// Decoding never retains more than 16 MiB of headers per block, whatever
    /// this is set to: a larger value, including "unlimited", acts as 16 MiB.
    pub fn set_max_header_list_size(&mut self, size: usize) {
        self.max_header_list_size = size;
    }

    /// Set the allowed table size (from SETTINGS frame).
    /// This limits what the peer can request via dynamic table size updates.
    pub fn set_allowed_table_size(&mut self, size: usize) {
        self.allowed_table_size = size.min(MAX_ALLOWED_TABLE_SIZE);
    }

    /// Returns the current dynamic table size in bytes.
    #[must_use]
    pub fn dynamic_table_size(&self) -> usize {
        self.dynamic_table.size()
    }

    /// Returns the current dynamic table size limit in bytes.
    #[must_use]
    pub fn dynamic_table_max_size(&self) -> usize {
        self.dynamic_table.max_size()
    }

    /// Returns the maximum table size currently allowed by peer SETTINGS.
    #[must_use]
    pub fn allowed_table_size(&self) -> usize {
        self.allowed_table_size
    }

    /// Decode headers from a buffer.
    ///
    /// Per RFC 7541 §4.2, dynamic table size updates are only permitted at the
    /// beginning of the header block (before the first header field
    /// representation). Any size update after a header field representation is
    /// a COMPRESSION_ERROR.
    pub fn decode(&mut self, src: &mut Bytes) -> Result<Vec<Header>, H2Error> {
        let mut headers = Vec::with_capacity(8);
        let mut total_size = 0;

        // RFC 7541 §4.2: dynamic table size updates are valid at the beginning
        // of a header block and MAY appear multiple times there.
        // Accept update-only blocks as valid.
        let mut size_update_count: usize = 0;
        while !src.is_empty() && (src[0] & 0xe0 == 0x20) {
            size_update_count = size_update_count.saturating_add(1);
            if size_update_count > MAX_SIZE_UPDATES {
                return Err(H2Error::compression(
                    "too many consecutive dynamic table size updates",
                ));
            }

            let new_size = decode_integer(src, 5)?;
            if new_size > self.allowed_table_size {
                return Err(H2Error::compression(
                    "dynamic table size update exceeds allowed maximum",
                ));
            }
            self.dynamic_table.set_max_size(new_size);
        }

        let limit = self.max_header_list_size.min(MAX_DECODED_HEADER_LIST_SIZE);
        while !src.is_empty() {
            let remaining_budget = limit.saturating_sub(total_size);
            let header = self.decode_header(src, remaining_budget)?;
            total_size = total_size.saturating_add(header.size());
            if total_size > limit {
                return Err(H2Error::compression("header list too large"));
            }
            headers.push(header);
        }

        Ok(headers)
    }

    /// Decode a single header.
    ///
    /// `remaining_budget` is the remaining `max_header_list_size` allowance; it
    /// bounds how much memory a literal in this header can allocate before the
    /// running `total_size` check would reject it anyway. This prevents a
    /// single oversized literal from being fully decoded (and allocated) prior
    /// to the post-decode size check.
    fn decode_header(
        &mut self,
        src: &mut Bytes,
        remaining_budget: usize,
    ) -> Result<Header, H2Error> {
        if src.is_empty() {
            return Err(H2Error::compression("unexpected end of header block"));
        }

        let first = src[0];

        if first & 0x80 != 0 {
            // Indexed header field. A dynamic entry is refused before it is
            // copied when it alone would overrun the list budget.
            let index = decode_integer(src, 7)?;
            if let Some(size) = index
                .checked_sub(STATIC_TABLE.len())
                .and_then(|dynamic| self.dynamic_table.entry_size(dynamic))
                && size > remaining_budget
            {
                return Err(H2Error::compression("header list too large"));
            }
            return self.get_indexed(index);
        }

        if first & 0x40 != 0 {
            // Literal with incremental indexing
            let (name, value, value_octets) = self.decode_literal(src, 6, remaining_budget)?;
            let header = Header::new(name, value);
            self.dynamic_table
                .insert_counted(header.clone(), value_octets);
            return Ok(header);
        }

        if first & 0x20 != 0 {
            return Err(H2Error::compression(
                "dynamic table size update after first header in block",
            ));
        }

        if first & 0x10 != 0 {
            // Literal never indexed
            let (name, value, _) = self.decode_literal(src, 4, remaining_budget)?;
            return Ok(Header::new(name, value));
        }

        // Literal without indexing
        let (name, value, _) = self.decode_literal(src, 4, remaining_budget)?;
        Ok(Header::new(name, value))
    }

    /// Decode a literal header field.
    ///
    /// Validates header name and value characters per RFC 9113 Section 8.2.1:
    /// - Names must be lowercase ASCII (a-z, 0-9, and `!#$%&'*+-.^_`|~`).
    /// - Values must not contain NUL (`\0`), CR (`\r`), or LF (`\n`).
    ///
    /// Rejecting these characters prevents HTTP/1 header injection when H2
    /// frames are forwarded to HTTP/1.1 backends.
    ///
    /// Also returns the value's length in octets as sent, which the dynamic
    /// table counts.
    fn decode_literal(
        &self,
        src: &mut Bytes,
        prefix_bits: u8,
        remaining_budget: usize,
    ) -> Result<(String, String, usize), H2Error> {
        let index = decode_integer(src, prefix_bits)?;

        let name = if index == 0 {
            let n = decode_string_bounded(src, remaining_budget)?;
            validate_header_name(&n)?;
            n
        } else {
            self.get_indexed_name(index)?
        };

        let value_budget = remaining_budget.saturating_sub(name.len());
        // Pseudo-header values (a method, scheme, authority, path or
        // status) have no obs-text form; they stay UTF-8 only.
        let (value, value_octets) = if name.starts_with(':') {
            let value = decode_string_bounded(src, value_budget)?;
            let value_octets = value.len();
            (value, value_octets)
        } else {
            decode_field_value_bounded(src, value_budget)?
        };
        validate_header_value(&value)?;
        Ok((name, value, value_octets))
    }

    /// Get a header by index from static or dynamic table.
    fn get_indexed(&self, index: usize) -> Result<Header, H2Error> {
        if index == 0 {
            return Err(H2Error::compression("invalid index 0"));
        }

        if index <= STATIC_TABLE.len() {
            let (name, value) =
                get_static(index).ok_or_else(|| H2Error::compression("invalid static index"))?;
            Ok(Header::new(name, value))
        } else {
            let dyn_index = index - STATIC_TABLE.len();
            self.dynamic_table
                .get(dyn_index)
                .ok_or_else(|| H2Error::compression("invalid dynamic index"))
        }
    }

    /// Get only the header name by index from static or dynamic table.
    ///
    /// This avoids cloning full header values on indexed-name literal fields.
    fn get_indexed_name(&self, index: usize) -> Result<String, H2Error> {
        if index == 0 {
            return Err(H2Error::compression("invalid index 0"));
        }

        if index <= STATIC_TABLE.len() {
            let (name, _) =
                get_static(index).ok_or_else(|| H2Error::compression("invalid static index"))?;
            Ok(name.to_string())
        } else {
            let dyn_index = index - STATIC_TABLE.len();
            self.dynamic_table
                .get(dyn_index)
                .map(|h| h.name)
                .ok_or_else(|| H2Error::compression("invalid dynamic index"))
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode an integer using HPACK integer encoding.
#[inline]
fn encode_integer(dst: &mut BytesMut, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1_usize << prefix_bits).saturating_sub(1);

    if value < max_first {
        dst.put_u8(prefix | value as u8);
    } else {
        dst.put_u8(prefix | max_first as u8);
        let mut remaining = value - max_first;
        while remaining >= 128 {
            dst.put_u8((remaining & 0x7f) as u8 | 0x80);
            remaining >>= 7;
        }
        dst.put_u8(remaining as u8);
    }
}

/// Decode an integer using HPACK integer encoding.
fn decode_integer(src: &mut Bytes, prefix_bits: u8) -> Result<usize, H2Error> {
    if src.is_empty() {
        return Err(H2Error::compression("unexpected end of integer"));
    }

    let max_first = (1_usize << prefix_bits).saturating_sub(1);
    let first = src[0] & max_first as u8;
    let _ = src.split_to(1);

    if (first as usize) < max_first {
        return Ok(first as usize);
    }

    let mut value = max_first;
    let mut shift = 0;

    loop {
        if src.is_empty() {
            return Err(H2Error::compression("unexpected end of integer"));
        }
        let byte = src[0];
        let _ = src.split_to(1);

        // Guard against unbounded continuation sequences. The shift limit
        // ensures the loop terminates even on malicious input.
        if shift > 28 {
            return Err(H2Error::compression("integer too large"));
        }

        // Compute increment = (byte & 0x7f) * 2^shift using checked
        // arithmetic. Note: checked_shl only validates shift < bit_width,
        // it does NOT detect when the result silently truncates (e.g. on
        // 32-bit where 127 << 28 overflows u32). Using checked_mul on the
        // multiplier catches the actual value overflow on all platforms.
        let multiplier = 1usize
            .checked_shl(shift)
            .ok_or_else(|| H2Error::compression("integer overflow in shift"))?;
        let increment = ((byte & 0x7f) as usize)
            .checked_mul(multiplier)
            .ok_or_else(|| H2Error::compression("integer overflow in multiply"))?;
        value = value
            .checked_add(increment)
            .ok_or_else(|| H2Error::compression("integer overflow in addition"))?;
        shift += 7;

        if byte & 0x80 == 0 {
            break;
        }
    }

    Ok(value)
}

const fn build_bit_masks() -> [u64; 65] {
    let mut masks = [0u64; 65];
    let mut i = 0usize;
    while i <= 64 {
        masks[i] = if i == 64 {
            u64::MAX
        } else {
            (1u64 << i).saturating_sub(1)
        };
        i += 1;
    }
    masks
}

const BIT_MASKS: [u64; 65] = build_bit_masks();

/// Calculate the size of Huffman-encoded data without actually encoding it.
pub(crate) fn huffman_encoded_size(src: &[u8]) -> usize {
    let mut total_bits: u32 = 0;

    for &byte in src {
        let (_, code_bits) = HUFFMAN_TABLE[byte as usize];
        total_bits += u32::from(code_bits);
    }

    // Convert bits to bytes (round up)
    ((total_bits + 7) / 8) as usize
}

/// Huffman-encode a byte slice directly into a BytesMut buffer per RFC 7541 Appendix B.
///
/// Packs variable-length Huffman codes into whole bytes with EOS-padding
/// (all-1s) in the final partial byte, as required by Section 5.2.
///
/// This version writes directly to the destination buffer, avoiding intermediate allocation.
pub(crate) fn encode_huffman_to_buffer(dst: &mut BytesMut, src: &[u8]) {
    // Reserve estimated space to reduce reallocations
    dst.reserve(src.len());
    let mut accumulator: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in src {
        let (code, code_bits) = HUFFMAN_TABLE[byte as usize];
        let code_bits_u32 = u32::from(code_bits);
        accumulator = (accumulator << code_bits_u32) | u64::from(code);
        bits += code_bits_u32;

        while bits >= 8 {
            bits -= 8;
            dst.put_u8((accumulator >> bits) as u8);
            accumulator &= BIT_MASKS[bits as usize];
        }
    }

    // Pad remaining bits with EOS prefix (all 1s) per RFC 7541 Section 5.2.
    if bits > 0 {
        let padding = 8 - bits;
        accumulator = (accumulator << padding) | BIT_MASKS[padding as usize];
        dst.put_u8(accumulator as u8);
    }
}

/// Legacy Huffman encoder for tests - returns allocated Vec.
#[cfg(test)]
fn encode_huffman(src: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode_huffman_to_buffer(&mut buf, src);
    buf.to_vec()
}

/// Encode a string (with optional Huffman encoding per RFC 7541 Section 5.2).
#[inline]
fn encode_string(dst: &mut BytesMut, value: &str, use_huffman: bool) {
    if use_huffman {
        let src_bytes = value.as_bytes();

        // Calculate encoded size without actually encoding
        let encoded_size = huffman_encoded_size(src_bytes);

        // High bit (0x80) signals Huffman-encoded string.
        encode_integer(dst, encoded_size, 7, 0x80);

        // Now encode directly to the destination buffer
        encode_huffman_to_buffer(dst, src_bytes);
    } else {
        let bytes = value.as_bytes();
        encode_integer(dst, bytes.len(), 7, 0x00);
        dst.extend_from_slice(bytes);
    }
}

/// Decode a string (handling Huffman encoding).
/// Validate an HTTP/2 header name per RFC 9113 Section 8.2.1.
///
/// Header names must consist of lowercase ASCII letters (`a-z`), digits (`0-9`),
/// and the token characters `!#$%&'*+-.^_`|~`. Uppercase letters, spaces,
/// tabs, and control characters (including NUL, CR, LF) are forbidden.
///
/// Pseudo-header names (starting with `:`) are also permitted.
fn validate_header_name(name: &str) -> Result<(), H2Error> {
    if name.is_empty() {
        return Err(H2Error::compression("empty header name"));
    }
    for (i, b) in name.bytes().enumerate() {
        let valid = matches!(b,
            b'a'..=b'z' | b'0'..=b'9'
            | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*'
            | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        ) || (b == b':' && i == 0);
        if !valid {
            return Err(H2Error::compression(
                "invalid character in header name (RFC 9113 Section 8.2.1)",
            ));
        }
    }
    Ok(())
}

/// Validate an HTTP/2 header value per RFC 9113 Section 8.2.1.
///
/// Header values must not contain NUL (`\0`), CR (`\r`), or LF (`\n`).
/// These characters enable HTTP/1 header injection when H2 frames are
/// forwarded to HTTP/1.1 backends.
fn validate_header_value(value: &str) -> Result<(), H2Error> {
    for b in value.bytes() {
        if matches!(b, b'\0' | b'\r' | b'\n') {
            return Err(H2Error::compression(
                "invalid character in header value (RFC 9113 Section 8.2.1)",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn decode_string(src: &mut Bytes) -> Result<String, H2Error> {
    decode_string_bounded(src, MAX_STRING_LENGTH)
}

/// Decode an HPACK string primitive, bounding the allocation to at most
/// `max_len` bytes (further capped by the hard `MAX_STRING_LENGTH` ceiling).
///
/// The length prefix is checked against `max_len` BEFORE any bytes are split
/// off or copied, so an attacker cannot force a large allocation by claiming
/// a length that would later be rejected by `max_header_list_size`.
fn decode_string_bounded(src: &mut Bytes, max_len: usize) -> Result<String, H2Error> {
    let (huffman, data) = split_string_literal(src, max_len)?;

    if huffman {
        decode_huffman(&data)
    } else {
        // br-asupersync-73dak3 — validate UTF-8 on the borrowed slice and
        // allocate exactly once. The previous shape was
        // `String::from_utf8(data.to_vec())`, which copied the bytes into a
        // fresh Vec *first* and only then validated; on bad UTF-8 we paid
        // the alloc + copy before failing. Validating first is also a
        // single contiguous pass over the bytes (good for the cache).
        std::str::from_utf8(&data)
            .map(str::to_owned)
            .map_err(|_| H2Error::compression("invalid UTF-8 in header"))
    }
}

/// Decode an HPACK string literal that holds a field value.
///
/// RFC 9110 §5.5 allows obs-text (octets 0x80-0xFF) in field values, so a
/// value that is not UTF-8 is read one character per octet (Latin-1), as
/// the HTTP/1 codec reads it, instead of failing the whole connection.
/// Also returns the value's length in octets before Huffman coding, the
/// length the dynamic table counts (RFC 7541 §4.1).
fn decode_field_value_bounded(src: &mut Bytes, max_len: usize) -> Result<(String, usize), H2Error> {
    let (huffman, data) = split_string_literal(src, max_len)?;
    let octets = if huffman {
        decode_huffman_octets(&data)?
    } else {
        data.to_vec()
    };
    let value_octets = octets.len();
    let value = String::from_utf8(octets).unwrap_or_else(|not_utf8| {
        not_utf8
            .as_bytes()
            .iter()
            .map(|&octet| char::from(octet))
            .collect()
    });
    Ok((value, value_octets))
}

/// Split one HPACK string literal off `src`: its Huffman flag and its
/// octets as sent.
///
/// The length prefix is checked against `max_len` BEFORE any bytes are split
/// off or copied, so an attacker cannot force a large allocation by claiming
/// a length that would later be rejected by `max_header_list_size`.
fn split_string_literal(src: &mut Bytes, max_len: usize) -> Result<(bool, Bytes), H2Error> {
    if src.is_empty() {
        return Err(H2Error::compression("unexpected end of string"));
    }

    let huffman = src[0] & 0x80 != 0;
    let length = decode_integer(src, 7)?;

    let effective_max = max_len.min(MAX_STRING_LENGTH);
    if length > effective_max {
        return Err(H2Error::compression("string length exceeds budget"));
    }

    if src.len() < length {
        return Err(H2Error::compression("string length exceeds buffer"));
    }

    Ok((huffman, src.split_to(length)))
}

/// Huffman code table from RFC 7541 Appendix B.
///
/// Each entry is (code, bit_length) where code is the Huffman code for that symbol
/// and bit_length is the number of bits in the code. Symbol 256 is the EOS marker.
#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
static HUFFMAN_TABLE: [(u32, u8); 257] = [
    (0x1ff8, 13),      // 0
    (0x7fffd8, 23),    // 1
    (0xfffffe2, 28),   // 2
    (0xfffffe3, 28),   // 3
    (0xfffffe4, 28),   // 4
    (0xfffffe5, 28),   // 5
    (0xfffffe6, 28),   // 6
    (0xfffffe7, 28),   // 7
    (0xfffffe8, 28),   // 8
    (0xffffea, 24),    // 9
    (0x3ffffffc, 30),  // 10
    (0xfffffe9, 28),   // 11
    (0xfffffea, 28),   // 12
    (0x3ffffffd, 30),  // 13
    (0xfffffeb, 28),   // 14
    (0xfffffec, 28),   // 15
    (0xfffffed, 28),   // 16
    (0xfffffee, 28),   // 17
    (0xfffffef, 28),   // 18
    (0xffffff0, 28),   // 19
    (0xffffff1, 28),   // 20
    (0xffffff2, 28),   // 21
    (0x3ffffffe, 30),  // 22
    (0xffffff3, 28),   // 23
    (0xffffff4, 28),   // 24
    (0xffffff5, 28),   // 25
    (0xffffff6, 28),   // 26
    (0xffffff7, 28),   // 27
    (0xffffff8, 28),   // 28
    (0xffffff9, 28),   // 29
    (0xffffffa, 28),   // 30
    (0xffffffb, 28),   // 31
    (0x14, 6),         // 32 ' '
    (0x3f8, 10),       // 33 '!'
    (0x3f9, 10),       // 34 '"'
    (0xffa, 12),       // 35 '#'
    (0x1ff9, 13),      // 36 '$'
    (0x15, 6),         // 37 '%'
    (0xf8, 8),         // 38 '&'
    (0x7fa, 11),       // 39 '\''
    (0x3fa, 10),       // 40 '('
    (0x3fb, 10),       // 41 ')'
    (0xf9, 8),         // 42 '*'
    (0x7fb, 11),       // 43 '+'
    (0xfa, 8),         // 44 ','
    (0x16, 6),         // 45 '-'
    (0x17, 6),         // 46 '.'
    (0x18, 6),         // 47 '/'
    (0x0, 5),          // 48 '0'
    (0x1, 5),          // 49 '1'
    (0x2, 5),          // 50 '2'
    (0x19, 6),         // 51 '3'
    (0x1a, 6),         // 52 '4'
    (0x1b, 6),         // 53 '5'
    (0x1c, 6),         // 54 '6'
    (0x1d, 6),         // 55 '7'
    (0x1e, 6),         // 56 '8'
    (0x1f, 6),         // 57 '9'
    (0x5c, 7),         // 58 ':'
    (0xfb, 8),         // 59 ';'
    (0x7ffc, 15),      // 60 '<'
    (0x20, 6),         // 61 '='
    (0xffb, 12),       // 62 '>'
    (0x3fc, 10),       // 63 '?'
    (0x1ffa, 13),      // 64 '@'
    (0x21, 6),         // 65 'A'
    (0x5d, 7),         // 66 'B'
    (0x5e, 7),         // 67 'C'
    (0x5f, 7),         // 68 'D'
    (0x60, 7),         // 69 'E'
    (0x61, 7),         // 70 'F'
    (0x62, 7),         // 71 'G'
    (0x63, 7),         // 72 'H'
    (0x64, 7),         // 73 'I'
    (0x65, 7),         // 74 'J'
    (0x66, 7),         // 75 'K'
    (0x67, 7),         // 76 'L'
    (0x68, 7),         // 77 'M'
    (0x69, 7),         // 78 'N'
    (0x6a, 7),         // 79 'O'
    (0x6b, 7),         // 80 'P'
    (0x6c, 7),         // 81 'Q'
    (0x6d, 7),         // 82 'R'
    (0x6e, 7),         // 83 'S'
    (0x6f, 7),         // 84 'T'
    (0x70, 7),         // 85 'U'
    (0x71, 7),         // 86 'V'
    (0x72, 7),         // 87 'W'
    (0xfc, 8),         // 88 'X'
    (0x73, 7),         // 89 'Y'
    (0xfd, 8),         // 90 'Z'
    (0x1ffb, 13),      // 91 '['
    (0x7fff0, 19),     // 92 '\\'
    (0x1ffc, 13),      // 93 ']'
    (0x3ffc, 14),      // 94 '^'
    (0x22, 6),         // 95 '_'
    (0x7ffd, 15),      // 96 '`'
    (0x3, 5),          // 97 'a'
    (0x23, 6),         // 98 'b'
    (0x4, 5),          // 99 'c'
    (0x24, 6),         // 100 'd'
    (0x5, 5),          // 101 'e'
    (0x25, 6),         // 102 'f'
    (0x26, 6),         // 103 'g'
    (0x27, 6),         // 104 'h'
    (0x6, 5),          // 105 'i'
    (0x74, 7),         // 106 'j'
    (0x75, 7),         // 107 'k'
    (0x28, 6),         // 108 'l'
    (0x29, 6),         // 109 'm'
    (0x2a, 6),         // 110 'n'
    (0x7, 5),          // 111 'o'
    (0x2b, 6),         // 112 'p'
    (0x76, 7),         // 113 'q'
    (0x2c, 6),         // 114 'r'
    (0x8, 5),          // 115 's'
    (0x9, 5),          // 116 't'
    (0x2d, 6),         // 117 'u'
    (0x77, 7),         // 118 'v'
    (0x78, 7),         // 119 'w'
    (0x79, 7),         // 120 'x'
    (0x7a, 7),         // 121 'y'
    (0x7b, 7),         // 122 'z'
    (0x7ffe, 15),      // 123 '{'
    (0x7fc, 11),       // 124 '|'
    (0x3ffd, 14),      // 125 '}'
    (0x1ffd, 13),      // 126 '~'
    (0xffffffc, 28),   // 127
    (0xfffe6, 20),     // 128
    (0x3fffd2, 22),    // 129
    (0xfffe7, 20),     // 130
    (0xfffe8, 20),     // 131
    (0x3fffd3, 22),    // 132
    (0x3fffd4, 22),    // 133
    (0x3fffd5, 22),    // 134
    (0x7fffd9, 23),    // 135
    (0x3fffd6, 22),    // 136
    (0x7fffda, 23),    // 137
    (0x7fffdb, 23),    // 138
    (0x7fffdc, 23),    // 139
    (0x7fffdd, 23),    // 140
    (0x7fffde, 23),    // 141
    (0xffffeb, 24),    // 142
    (0x7fffdf, 23),    // 143
    (0xffffec, 24),    // 144
    (0xffffed, 24),    // 145
    (0x3fffd7, 22),    // 146
    (0x7fffe0, 23),    // 147
    (0xffffee, 24),    // 148
    (0x7fffe1, 23),    // 149
    (0x7fffe2, 23),    // 150
    (0x7fffe3, 23),    // 151
    (0x7fffe4, 23),    // 152
    (0x1fffdc, 21),    // 153
    (0x3fffd8, 22),    // 154
    (0x7fffe5, 23),    // 155
    (0x3fffd9, 22),    // 156
    (0x7fffe6, 23),    // 157
    (0x7fffe7, 23),    // 158
    (0xffffef, 24),    // 159
    (0x3fffda, 22),    // 160
    (0x1fffdd, 21),    // 161
    (0xfffe9, 20),     // 162
    (0x3fffdb, 22),    // 163
    (0x3fffdc, 22),    // 164
    (0x7fffe8, 23),    // 165
    (0x7fffe9, 23),    // 166
    (0x1fffde, 21),    // 167
    (0x7fffea, 23),    // 168
    (0x3fffdd, 22),    // 169
    (0x3fffde, 22),    // 170
    (0xfffff0, 24),    // 171
    (0x1fffdf, 21),    // 172
    (0x3fffdf, 22),    // 173
    (0x7fffeb, 23),    // 174
    (0x7fffec, 23),    // 175
    (0x1fffe0, 21),    // 176
    (0x1fffe1, 21),    // 177
    (0x3fffe0, 22),    // 178
    (0x1fffe2, 21),    // 179
    (0x7fffed, 23),    // 180
    (0x3fffe1, 22),    // 181
    (0x7fffee, 23),    // 182
    (0x7fffef, 23),    // 183
    (0xfffea, 20),     // 184
    (0x3fffe2, 22),    // 185
    (0x3fffe3, 22),    // 186
    (0x3fffe4, 22),    // 187
    (0x7ffff0, 23),    // 188
    (0x3fffe5, 22),    // 189
    (0x3fffe6, 22),    // 190
    (0x7ffff1, 23),    // 191
    (0x3ffffe0, 26),   // 192
    (0x3ffffe1, 26),   // 193
    (0xfffeb, 20),     // 194
    (0x7fff1, 19),     // 195
    (0x3fffe7, 22),    // 196
    (0x7ffff2, 23),    // 197
    (0x3fffe8, 22),    // 198
    (0x1ffffec, 25),   // 199
    (0x3ffffe2, 26),   // 200
    (0x3ffffe3, 26),   // 201
    (0x3ffffe4, 26),   // 202
    (0x7ffffde, 27),   // 203
    (0x7ffffdf, 27),   // 204
    (0x3ffffe5, 26),   // 205
    (0xfffff1, 24),    // 206
    (0x1ffffed, 25),   // 207
    (0x7fff2, 19),     // 208
    (0x1fffe3, 21),    // 209
    (0x3ffffe6, 26),   // 210
    (0x7ffffe0, 27),   // 211
    (0x7ffffe1, 27),   // 212
    (0x3ffffe7, 26),   // 213
    (0x7ffffe2, 27),   // 214
    (0xfffff2, 24),    // 215
    (0x1fffe4, 21),    // 216
    (0x1fffe5, 21),    // 217
    (0x3ffffe8, 26),   // 218
    (0x3ffffe9, 26),   // 219
    (0xffffffd, 28),   // 220
    (0x7ffffe3, 27),   // 221
    (0x7ffffe4, 27),   // 222
    (0x7ffffe5, 27),   // 223
    (0xfffec, 20),     // 224
    (0xfffff3, 24),    // 225
    (0xfffed, 20),     // 226
    (0x1fffe6, 21),    // 227
    (0x3fffe9, 22),    // 228
    (0x1fffe7, 21),    // 229
    (0x1fffe8, 21),    // 230
    (0x7ffff3, 23),    // 231
    (0x3fffea, 22),    // 232
    (0x3fffeb, 22),    // 233
    (0x1ffffee, 25),   // 234
    (0x1ffffef, 25),   // 235
    (0xfffff4, 24),    // 236
    (0xfffff5, 24),    // 237
    (0x3ffffea, 26),   // 238
    (0x7ffff4, 23),    // 239
    (0x3ffffeb, 26),   // 240
    (0x7ffffe6, 27),   // 241
    (0x3ffffec, 26),   // 242
    (0x3ffffed, 26),   // 243
    (0x7ffffe7, 27),   // 244
    (0x7ffffe8, 27),   // 245
    (0x7ffffe9, 27),   // 246
    (0x7ffffea, 27),   // 247
    (0x7ffffeb, 27),   // 248
    (0xffffffe, 28),   // 249
    (0x7ffffec, 27),   // 250
    (0x7ffffed, 27),   // 251
    (0x7ffffee, 27),   // 252
    (0x7ffffef, 27),   // 253
    (0x7fffff0, 27),   // 254
    (0x3ffffee, 26),   // 255
    (0x3fffffff, 30),  // 256 EOS
];

/// Decode a Huffman-encoded string using grouped code-length matching.
///
/// Security: This decoder avoids the O(n*257) worst case of the naive linear
/// scan approach. By grouping codes by bit length and checking shortest first,
/// the decoder consumes at least 5 bits per iteration, bounding the work per
/// input byte to a constant factor.
/// Decode a Huffman-encoded HPACK string literal per RFC 7541 Appendix B.
///
/// br-asupersync-1tvdlr: implements the canonical 4-bit-stride state
/// machine used by nghttp2 and h2-rs. Each input byte is processed as
/// two 4-bit nibbles; per nibble we do a single array lookup into
/// `HUFFMAN_DECODE_TABLE` (16 KiB, fits in L1) that returns the next
/// state, optional decoded symbol, and a flag indicating whether the
/// resulting state is a valid termination point.
///
/// Replaces the prior decoder which:
///   * tested for 5/6/7/8-bit codes via cascaded `match` statements
///     (compile-checked but adds branch misprediction cost);
///   * fell back to a HashMap probe per-code-length on the long-code
///     path (up to 22 probes for the longest 30-bit codes).
///
/// The table-driven decoder has uniform cost per byte regardless of
/// code length: 2 array accesses + 2 conditionals.
pub(crate) fn decode_huffman(src: &Bytes) -> Result<String, H2Error> {
    String::from_utf8(decode_huffman_octets(src)?)
        .map_err(|_| H2Error::compression("invalid UTF-8 in huffman"))
}

/// Decode a Huffman-coded string to its octets, which need not be UTF-8.
pub(crate) fn decode_huffman_octets(src: &Bytes) -> Result<Vec<u8>, H2Error> {
    // Shortest HPACK code is 5 bits; preallocate to upper bound to avoid
    // growth reallocs on the common case where decoded > encoded length.
    let estimated_symbols = src.len().saturating_mul(8).saturating_add(4) / 5;
    let mut result = Vec::with_capacity(estimated_symbols);
    let table: &[[HuffmanDecodeEntry; 16]; 256] = &HUFFMAN_DECODE_TABLE;
    let mut state: u8 = 0;
    let mut accepted = true;

    for &byte in src.iter() {
        // High nibble first (MSB-first packing). Intermediate accepted
        // flag from the high nibble is irrelevant — only the byte's low
        // nibble determines the post-byte termination state.
        let entry = table[state as usize][((byte >> 4) & 0x0F) as usize];
        if entry.flags & HUFF_FAIL != 0 {
            return Err(H2Error::compression("invalid huffman code"));
        }
        if entry.flags & HUFF_SYM != 0 {
            result.push(entry.sym);
        }
        state = entry.next_state;

        let entry = table[state as usize][(byte & 0x0F) as usize];
        if entry.flags & HUFF_FAIL != 0 {
            return Err(H2Error::compression("invalid huffman code"));
        }
        if entry.flags & HUFF_SYM != 0 {
            result.push(entry.sym);
        }
        state = entry.next_state;
        accepted = entry.flags & HUFF_ACCEPTED != 0;
    }

    if !accepted {
        // Final state is neither root nor a valid 1-7-bit EOS prefix. This
        // catches both incomplete trailing codes and overlong (≥ 8-bit)
        // padding per RFC 7541 §5.2.
        return Err(H2Error::compression("invalid huffman padding"));
    }

    Ok(result)
}

#[cfg(test)]
#[path = "hpack_inline_tests.rs"]
mod tests;
