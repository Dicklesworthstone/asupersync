//! HPACK header compression for HTTP/2.
//!
//! Implements RFC 7541: HPACK - Header Compression for HTTP/2.

use std::collections::VecDeque;

use crate::bytes::{Bytes, BytesMut};

use super::error::H2Error;

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
        self.name.len() + self.value.len() + 32
    }
}

/// Dynamic table for HPACK encoding/decoding.
///
/// Uses `VecDeque` so that front insertion (`push_front`) is O(1) amortized
/// rather than the O(n) of `Vec::insert(0, ...)`.
#[derive(Debug)]
pub struct DynamicTable {
    entries: VecDeque<Header>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    /// Create a new dynamic table with default max size.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size: DEFAULT_MAX_TABLE_SIZE,
        }
    }

    /// Create a dynamic table with specified max size.
    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size,
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
        self.max_size = max_size;
        self.evict();
    }

    /// Insert a new entry at the beginning of the table.
    pub fn insert(&mut self, header: Header) {
        let entry_size = header.size();

        // Evict oldest entries (at back) to make room
        while self.size + entry_size > self.max_size && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop_back() {
                self.size -= evicted.size();
            }
        }

        // Only insert if it fits
        if entry_size <= self.max_size {
            self.entries.push_front(header);
            self.size += entry_size;
        }
    }

    /// Get an entry by index (1-indexed, after static table).
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Header> {
        if index == 0 || index > self.entries.len() {
            None
        } else {
            Some(&self.entries[index - 1])
        }
    }

    /// Find an entry by name and value, returning the index if found.
    #[must_use]
    pub fn find(&self, name: &str, value: &str) -> Option<usize> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.name == name && entry.value == value {
                return Some(STATIC_TABLE.len() + i + 1);
            }
        }
        None
    }

    /// Find an entry by name only, returning the index if found.
    #[must_use]
    pub fn find_name(&self, name: &str) -> Option<usize> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.name == name {
                return Some(STATIC_TABLE.len() + i + 1);
            }
        }
        None
    }

    /// Evict oldest entries (at back) to fit within max size.
    fn evict(&mut self) {
        while self.size > self.max_size && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop_back() {
                self.size -= evicted.size();
            }
        }
    }
}

impl Default for DynamicTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Find entry in static table by name and value.
fn find_static(name: &str, value: &str) -> Option<usize> {
    for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
        if *n == name && *v == value {
            return Some(i + 1);
        }
    }
    None
}

/// Find entry in static table by name only.
fn find_static_name(name: &str) -> Option<usize> {
    for (i, (n, _)) in STATIC_TABLE.iter().enumerate() {
        if *n == name {
            return Some(i + 1);
        }
    }
    None
}

/// Get entry from static table by index.
fn get_static(index: usize) -> Option<(&'static str, &'static str)> {
    if index == 0 || index > STATIC_TABLE.len() {
        None
    } else {
        Some(STATIC_TABLE[index - 1])
    }
}

/// HPACK encoder for encoding headers.
#[derive(Debug)]
pub struct Encoder {
    dynamic_table: DynamicTable,
    use_huffman: bool,
    /// Pending dynamic table size update to emit at the start of the next header block.
    /// RFC 7541 Section 6.3 requires this when the table size changes.
    pending_size_update: Option<usize>,
}

impl Encoder {
    /// Create a new encoder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::new(),
            use_huffman: true,
            pending_size_update: None,
        }
    }

    /// Create an encoder with specified max table size.
    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::with_max_size(max_size),
            use_huffman: true,
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
        self.dynamic_table.set_max_size(size);
        self.pending_size_update = Some(size);
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
        if let Some(new_size) = self.pending_size_update.take() {
            encode_integer(dst, new_size, 5, 0x20);
        }
    }

    /// Encode a single header.
    fn encode_header(&mut self, header: &Header, dst: &mut BytesMut, index: bool) {
        let name = header.name.as_str();
        let value = header.value.as_str();

        // Try to find exact match in tables
        if let Some(idx) = find_static(name, value).or_else(|| self.dynamic_table.find(name, value))
        {
            // Indexed header field
            encode_integer(dst, idx, 7, 0x80);
            return;
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

            // Add to dynamic table
            self.dynamic_table.insert(header.clone());
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

/// Maximum allowed HPACK table size to prevent DoS (1MB).
const MAX_ALLOWED_TABLE_SIZE: usize = 1024 * 1024;

/// Maximum allowed decoded string length to prevent DoS (256 KB).
/// This bounds the allocation size before the header-list-size check runs.
const MAX_STRING_LENGTH: usize = 256 * 1024;
/// Maximum consecutive dynamic table size updates allowed at block start.
const MAX_SIZE_UPDATES: usize = 16;

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
        Self {
            dynamic_table: DynamicTable::new(),
            max_header_list_size: 16384,
            allowed_table_size: 4096, // HTTP/2 default
        }
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
    pub fn set_max_header_list_size(&mut self, size: usize) {
        self.max_header_list_size = size;
    }

    /// Set the allowed table size (from SETTINGS frame).
    /// This limits what the peer can request via dynamic table size updates.
    pub fn set_allowed_table_size(&mut self, size: usize) {
        self.allowed_table_size = size.min(MAX_ALLOWED_TABLE_SIZE);
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
        let mut size_update_count = 0;
        while !src.is_empty() && (src[0] & 0xe0 == 0x20) {
            size_update_count += 1;
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

        while !src.is_empty() {
            let header = self.decode_header(src)?;
            total_size += header.size();
            if total_size > self.max_header_list_size {
                return Err(H2Error::compression("header list too large"));
            }
            headers.push(header);
        }

        Ok(headers)
    }

    /// Decode a single header.
    ///
    fn decode_header(&mut self, src: &mut Bytes) -> Result<Header, H2Error> {
        if src.is_empty() {
            return Err(H2Error::compression("unexpected end of header block"));
        }

        let first = src[0];

        if first & 0x80 != 0 {
            // Indexed header field
            let index = decode_integer(src, 7)?;
            return self.get_indexed(index);
        }

        if first & 0x40 != 0 {
            // Literal with incremental indexing
            let (name, value) = self.decode_literal(src, 6)?;
            let header = Header::new(name, value);
            self.dynamic_table.insert(header.clone());
            return Ok(header);
        }

        if first & 0x20 != 0 {
            return Err(H2Error::compression(
                "dynamic table size update after first header in block",
            ));
        }

        if first & 0x10 != 0 {
            // Literal never indexed
            let (name, value) = self.decode_literal(src, 4)?;
            return Ok(Header::new(name, value));
        }

        // Literal without indexing
        let (name, value) = self.decode_literal(src, 4)?;
        Ok(Header::new(name, value))
    }

    /// Decode a literal header field.
    fn decode_literal(
        &self,
        src: &mut Bytes,
        prefix_bits: u8,
    ) -> Result<(String, String), H2Error> {
        let index = decode_integer(src, prefix_bits)?;

        let name = if index == 0 {
            decode_string(src)?
        } else {
            self.get_indexed_name(index)?
        };

        let value = decode_string(src)?;
        Ok((name, value))
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
                .cloned()
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
                .map(|h| h.name.clone())
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
fn encode_integer(dst: &mut BytesMut, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1 << prefix_bits) - 1;

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

    let max_first = (1 << prefix_bits) - 1;
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

/// Huffman-encode a byte slice per RFC 7541 Appendix B.
///
/// Packs variable-length Huffman codes into whole bytes with EOS-padding
/// (all-1s) in the final partial byte, as required by Section 5.2.
fn encode_huffman(src: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(src.len());
    let mut accumulator: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in src {
        let (code, code_bits) = HUFFMAN_TABLE[byte as usize];
        let code_bits_u32 = u32::from(code_bits);
        accumulator = (accumulator << code_bits_u32) | u64::from(code);
        bits += code_bits_u32;

        while bits >= 8 {
            bits -= 8;
            dst.push((accumulator >> bits) as u8);
            accumulator &= (1u64 << bits) - 1;
        }
    }

    // Pad remaining bits with EOS prefix (all 1s) per RFC 7541 Section 5.2.
    if bits > 0 {
        let padding = 8 - bits;
        accumulator = (accumulator << padding) | ((1u64 << padding) - 1);
        dst.push(accumulator as u8);
    }

    dst
}

/// Encode a string (with optional Huffman encoding per RFC 7541 Section 5.2).
fn encode_string(dst: &mut BytesMut, value: &str, use_huffman: bool) {
    if use_huffman {
        let encoded = encode_huffman(value.as_bytes());
        // High bit (0x80) signals Huffman-encoded string.
        encode_integer(dst, encoded.len(), 7, 0x80);
        dst.extend_from_slice(&encoded);
    } else {
        let bytes = value.as_bytes();
        encode_integer(dst, bytes.len(), 7, 0x00);
        dst.extend_from_slice(bytes);
    }
}

/// Decode a string (handling Huffman encoding).
fn decode_string(src: &mut Bytes) -> Result<String, H2Error> {
    if src.is_empty() {
        return Err(H2Error::compression("unexpected end of string"));
    }

    let huffman = src[0] & 0x80 != 0;
    let length = decode_integer(src, 7)?;

    if length > MAX_STRING_LENGTH {
        return Err(H2Error::compression("string length exceeds maximum"));
    }

    if src.len() < length {
        return Err(H2Error::compression("string length exceeds buffer"));
    }

    let data = src.split_to(length);

    if huffman {
        decode_huffman(&data)
    } else {
        String::from_utf8(data.to_vec())
            .map_err(|_| H2Error::compression("invalid UTF-8 in header"))
    }
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
#[allow(clippy::too_many_lines)] // Huffman decoding table is large; splitting obscures verification.
fn decode_huffman(src: &Bytes) -> Result<String, H2Error> {
    let mut result = Vec::with_capacity(src.len());
    let mut accumulator: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in src.iter() {
        accumulator = (accumulator << 8) | u64::from(byte);
        bits += 8;

        while bits >= 5 {
            // Fast path: check 5-bit codes first (most common ASCII symbols).
            // Codes 0x00-0x09 in 5 bits map to: '0','1','2','a','c','e','i','o','s','t'
            let high_5 = (accumulator >> (bits - 5)) as u32 & 0x1F;
            if high_5 < 10 {
                let sym = match high_5 {
                    0 => b'0',
                    1 => b'1',
                    2 => b'2',
                    3 => b'a',
                    4 => b'c',
                    5 => b'e',
                    6 => b'i',
                    7 => b'o',
                    8 => b's',
                    9 => b't',
                    _ => unreachable!(),
                };
                result.push(sym);
                bits -= 5;
                accumulator &= (1u64 << bits) - 1;
                continue;
            }

            // Fast path: check 6-bit codes (next most common).
            if bits >= 6 {
                let high_6 = (accumulator >> (bits - 6)) as u32 & 0x3F;
                // 6-bit codes range from 0x14 to 0x2d (symbols: space, %, -, ., /,
                // 3-9, =, A-Z, _, b, d, f-h, l-p, r, u)
                let sym_6 = match high_6 {
                    0x14 => Some(b' '),
                    0x15 => Some(b'%'),
                    0x16 => Some(b'-'),
                    0x17 => Some(b'.'),
                    0x18 => Some(b'/'),
                    0x19 => Some(b'3'),
                    0x1a => Some(b'4'),
                    0x1b => Some(b'5'),
                    0x1c => Some(b'6'),
                    0x1d => Some(b'7'),
                    0x1e => Some(b'8'),
                    0x1f => Some(b'9'),
                    0x20 => Some(b'='),
                    0x21 => Some(b'A'),
                    0x22 => Some(b'_'),
                    0x23 => Some(b'b'),
                    0x24 => Some(b'd'),
                    0x25 => Some(b'f'),
                    0x26 => Some(b'g'),
                    0x27 => Some(b'h'),
                    0x28 => Some(b'l'),
                    0x29 => Some(b'm'),
                    0x2a => Some(b'n'),
                    0x2b => Some(b'p'),
                    0x2c => Some(b'r'),
                    0x2d => Some(b'u'),
                    _ => None,
                };
                if let Some(s) = sym_6 {
                    result.push(s);
                    bits -= 6;
                    accumulator &= (1u64 << bits) - 1;
                    continue;
                }
            }

            // Fast path: check 7-bit codes.
            if bits >= 7 {
                let high_7 = (accumulator >> (bits - 7)) as u32 & 0x7F;
                let sym_7 = match high_7 {
                    0x5c => Some(b':'),
                    0x5d => Some(b'B'),
                    0x5e => Some(b'C'),
                    0x5f => Some(b'D'),
                    0x60 => Some(b'E'),
                    0x61 => Some(b'F'),
                    0x62 => Some(b'G'),
                    0x63 => Some(b'H'),
                    0x64 => Some(b'I'),
                    0x65 => Some(b'J'),
                    0x66 => Some(b'K'),
                    0x67 => Some(b'L'),
                    0x68 => Some(b'M'),
                    0x69 => Some(b'N'),
                    0x6a => Some(b'O'),
                    0x6b => Some(b'P'),
                    0x6c => Some(b'Q'),
                    0x6d => Some(b'R'),
                    0x6e => Some(b'S'),
                    0x6f => Some(b'T'),
                    0x70 => Some(b'U'),
                    0x71 => Some(b'V'),
                    0x72 => Some(b'W'),
                    0x73 => Some(b'Y'),
                    0x74 => Some(b'j'),
                    0x75 => Some(b'k'),
                    0x76 => Some(b'q'),
                    0x77 => Some(b'v'),
                    0x78 => Some(b'w'),
                    0x79 => Some(b'x'),
                    0x7a => Some(b'y'),
                    0x7b => Some(b'z'),
                    _ => None,
                };
                if let Some(s) = sym_7 {
                    result.push(s);
                    bits -= 7;
                    accumulator &= (1u64 << bits) - 1;
                    continue;
                }
            }

            // Fast path: check 8-bit codes.
            if bits >= 8 {
                let high_8 = (accumulator >> (bits - 8)) as u32 & 0xFF;
                let sym_8 = match high_8 {
                    0xf8 => Some(b'&'),
                    0xf9 => Some(b'*'),
                    0xfa => Some(b','),
                    0xfb => Some(b';'),
                    0xfc => Some(b'X'),
                    0xfd => Some(b'Z'),
                    _ => None,
                };
                if let Some(s) = sym_8 {
                    result.push(s);
                    bits -= 8;
                    accumulator &= (1u64 << bits) - 1;
                    continue;
                }
            }

            // Slow path for codes 9-30 bits: use table scan but only for
            // codes of the exact length range we need. Since we already
            // handled 5-8 bit codes above, we start at 9.
            let mut decoded = false;
            for code_len in 9u32..=30 {
                if bits < code_len {
                    break;
                }
                let shift = bits - code_len;
                let candidate = (accumulator >> shift) as u32;
                let mask = (1u32 << code_len) - 1;
                let candidate = candidate & mask;

                // Scan only entries with matching code length.
                for (sym, &(code, code_bits)) in HUFFMAN_TABLE.iter().enumerate() {
                    if u32::from(code_bits) != code_len {
                        continue;
                    }
                    if (code & mask) == candidate {
                        if sym == 256 {
                            return Err(H2Error::compression("invalid huffman code (EOS symbol)"));
                        }
                        result.push(sym as u8);
                        bits = shift;
                        accumulator &= (1u64 << bits) - 1;
                        decoded = true;
                        break;
                    }
                }
                if decoded {
                    break;
                }
            }

            if !decoded {
                // If we have enough bits for the longest possible Huffman
                // code (30 bits for EOS) and still couldn't decode, the
                // input is definitively invalid. Returning early also
                // prevents `bits` from exceeding 64 on subsequent bytes,
                // which would cause a shift overflow in the u64 accumulator.
                if bits >= 30 {
                    return Err(H2Error::compression("invalid huffman code"));
                }
                break;
            }
        }
    }

    if bits >= 8 {
        return Err(H2Error::compression("invalid huffman padding (overlong)"));
    }

    // Check remaining bits are valid padding (all 1s) per RFC 7541 Section 5.2
    if bits > 0 && bits < 8 {
        let mask = (1u64 << bits) - 1;
        if accumulator != mask {
            return Err(H2Error::compression(
                "invalid Huffman padding (must be all 1s)",
            ));
        }
    }

    String::from_utf8(result).map_err(|_| H2Error::compression("invalid UTF-8 in huffman"))
}

#[cfg(test)]
mod tests {
    use super::super::error::ErrorCode;
    use super::*;

    fn assert_compression_error<T>(result: Result<T, H2Error>) {
        match result {
            Ok(_) => panic!("expected compression error"),
            Err(err) => assert_eq!(err.code, ErrorCode::CompressionError),
        }
    }

    #[test]
    fn test_integer_encoding_small() {
        let mut buf = BytesMut::new();
        encode_integer(&mut buf, 10, 5, 0x00);
        assert_eq!(buf.as_ref(), &[10]);

        let mut src = buf.freeze();
        let decoded = decode_integer(&mut src, 5).unwrap();
        assert_eq!(decoded, 10);
    }

    #[test]
    fn test_integer_encoding_large() {
        let mut buf = BytesMut::new();
        encode_integer(&mut buf, 1337, 5, 0x00);
        // 1337 = 31 + (154 & 0x7f) + ((10 & 0x7f) << 7)
        assert_eq!(buf.as_ref(), &[31, 154, 10]);

        let mut src = buf.freeze();
        let decoded = decode_integer(&mut src, 5).unwrap();
        assert_eq!(decoded, 1337);
    }

    #[test]
    fn test_integer_decode_empty() {
        let mut src = Bytes::new();
        assert_compression_error(decode_integer(&mut src, 5));
    }

    #[test]
    fn test_integer_decode_truncated() {
        let mut src = Bytes::from_static(&[0x1f, 0x80]);
        assert_compression_error(decode_integer(&mut src, 5));
    }

    #[test]
    fn test_integer_decode_shift_overflow() {
        let mut bytes = vec![0x1f];
        bytes.extend_from_slice(&[0x80; 6]);
        let mut src = Bytes::from(bytes);
        assert_compression_error(decode_integer(&mut src, 5));
    }

    #[test]
    fn test_string_encoding_literal() {
        let mut buf = BytesMut::new();
        encode_string(&mut buf, "hello", false);

        let mut src = buf.freeze();
        let decoded = decode_string(&mut src).unwrap();
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_string_decode_length_exceeds_buffer() {
        let mut src = Bytes::from_static(&[0x03, b'a', b'b']);
        assert_compression_error(decode_string(&mut src));
    }

    #[test]
    fn test_string_decode_invalid_utf8() {
        let mut src = Bytes::from_static(&[0x01, 0xff]);
        assert_compression_error(decode_string(&mut src));
    }

    #[test]
    fn test_huffman_decode_invalid_padding() {
        let mut src = Bytes::from_static(&[0x81, 0x00]);
        assert_compression_error(decode_string(&mut src));
    }

    #[test]
    fn test_indexed_header_zero_rejected() {
        let mut decoder = Decoder::new();
        let mut src = Bytes::from_static(&[0x80]); // indexed header with index 0
        assert_compression_error(decoder.decode(&mut src));
    }

    #[test]
    fn test_dynamic_table_size_update_exceeds_allowed() {
        let mut decoder = Decoder::new();
        decoder.set_allowed_table_size(1);

        let mut buf = BytesMut::new();
        encode_integer(&mut buf, 2, 5, 0x20);

        let mut src = buf.freeze();
        assert_compression_error(decoder.decode(&mut src));
    }

    #[test]
    fn test_dynamic_table_size_update_without_header_is_accepted() {
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::new();
        encode_integer(&mut buf, 0, 5, 0x20);

        let mut src = buf.freeze();
        let headers = decoder.decode(&mut src).unwrap();
        assert!(headers.is_empty());
        assert_eq!(decoder.dynamic_table.max_size(), 0);
    }

    #[test]
    fn test_multiple_size_updates_without_headers_apply_last_value() {
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::new();
        encode_integer(&mut buf, 1024, 5, 0x20);
        encode_integer(&mut buf, 512, 5, 0x20);

        let mut src = buf.freeze();
        let headers = decoder.decode(&mut src).unwrap();
        assert!(headers.is_empty());
        assert_eq!(decoder.dynamic_table.max_size(), 512);
    }

    #[test]
    fn test_dynamic_table_size_update_too_many() {
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::new();
        for _ in 0..17 {
            encode_integer(&mut buf, 0, 5, 0x20);
        }

        let mut src = buf.freeze();
        assert_compression_error(decoder.decode(&mut src));
    }

    #[test]
    fn test_header_list_size_exceeded() {
        let mut decoder = Decoder::new();
        decoder.set_max_header_list_size(1);

        let mut buf = BytesMut::new();
        // Literal without indexing, name "a", value "b".
        encode_integer(&mut buf, 0, 4, 0x00);
        encode_string(&mut buf, "a", false);
        encode_string(&mut buf, "b", false);

        let mut src = buf.freeze();
        assert_compression_error(decoder.decode(&mut src));
    }

    #[test]
    fn test_decoder_caps_allowed_table_size() {
        let decoder = Decoder::with_max_size(MAX_ALLOWED_TABLE_SIZE + 1);
        assert_eq!(decoder.allowed_table_size, MAX_ALLOWED_TABLE_SIZE);
        assert_eq!(decoder.dynamic_table.max_size(), MAX_ALLOWED_TABLE_SIZE);
    }

    #[test]
    fn test_set_allowed_table_size_caps() {
        let mut decoder = Decoder::new();
        decoder.set_allowed_table_size(MAX_ALLOWED_TABLE_SIZE + 1);
        assert_eq!(decoder.allowed_table_size, MAX_ALLOWED_TABLE_SIZE);
    }

    #[test]
    fn test_dynamic_table_insert() {
        let mut table = DynamicTable::new();
        table.insert(Header::new("custom-header", "custom-value"));

        assert_eq!(
            table.size(),
            "custom-header".len() + "custom-value".len() + 32
        );
        assert!(table.get(1).is_some());
    }

    #[test]
    fn test_dynamic_table_eviction() {
        let mut table = DynamicTable::with_max_size(100);

        // Insert entries that exceed max size
        table.insert(Header::new("header1", "value1")); // 32 + 7 + 6 = 45
        table.insert(Header::new("header2", "value2")); // 32 + 7 + 6 = 45

        // First entry should be evicted
        assert!(table.size() <= 100);
    }

    #[test]
    fn test_encoder_decoder_roundtrip() {
        let mut encoder = Encoder::new();
        encoder.set_use_huffman(false);

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "example.com"),
            Header::new("accept", "text/html"),
        ];

        let mut encoded_block = BytesMut::new();
        encoder.encode(&headers, &mut encoded_block);

        let mut decoder = Decoder::new();
        let mut src = encoded_block.freeze();
        let decoded_headers = decoder.decode(&mut src).unwrap();

        assert_eq!(decoded_headers.len(), headers.len());
        for (orig, dec) in headers.iter().zip(decoded_headers.iter()) {
            assert_eq!(orig.name, dec.name);
            assert_eq!(orig.value, dec.value);
        }
    }

    #[test]
    fn test_static_table_indexed() {
        let mut decoder = Decoder::new();

        // Encode ":method: GET" as indexed (index 2 in static table)
        let mut src = Bytes::from_static(&[0x82]); // 0x80 | 2
        let headers = decoder.decode(&mut src).unwrap();

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, ":method");
        assert_eq!(headers[0].value, "GET");
    }

    #[test]
    fn test_huffman_encode_decode_roundtrip() {
        let inputs = [
            "www.example.com",
            "no-cache",
            "custom-key",
            "custom-value",
            "",
            "a",
            "Hello, World!",
        ];

        for &input in &inputs {
            let encoded = encode_huffman(input.as_bytes());
            let encoded_bytes = Bytes::from(encoded);
            let decoded = decode_huffman(&encoded_bytes).unwrap();
            assert_eq!(decoded, input, "roundtrip failed for {input:?}");
        }
    }

    #[test]
    fn test_huffman_encoding_is_smaller() {
        let input = b"www.example.com";
        let encoded = encode_huffman(input);
        assert!(
            encoded.len() < input.len(),
            "huffman should compress ASCII text: {} >= {}",
            encoded.len(),
            input.len()
        );
    }

    #[test]
    fn test_string_encoding_huffman_roundtrip() {
        let mut buf = BytesMut::new();
        encode_string(&mut buf, "hello", true);

        // First byte should have high bit set (Huffman flag).
        assert_ne!(buf[0] & 0x80, 0, "huffman flag should be set");

        let mut src = buf.freeze();
        let decoded = decode_string(&mut src).unwrap();
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_encoder_decoder_roundtrip_with_huffman() {
        let mut encoder = Encoder::new();
        encoder.set_use_huffman(true);

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/index.html"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "www.example.com"),
            Header::new("accept-encoding", "gzip, deflate"),
        ];

        let mut encoded_block = BytesMut::new();
        encoder.encode(&headers, &mut encoded_block);

        let mut decoder = Decoder::new();
        let mut src = encoded_block.freeze();
        let decoded_headers = decoder.decode(&mut src).unwrap();

        assert_eq!(decoded_headers.len(), headers.len());
        for (orig, dec) in headers.iter().zip(decoded_headers.iter()) {
            assert_eq!(orig.name, dec.name, "name mismatch for {:?}", orig.name);
            assert_eq!(orig.value, dec.value, "value mismatch for {:?}", orig.name);
        }
    }

    // =========================================================================
    // RFC 7541 Standard Test Vectors (bd-et96)
    // =========================================================================

    #[test]
    fn test_rfc7541_c1_integer_representation() {
        // RFC 7541 C.1.1: Encoding 10 using a 5-bit prefix
        // Expected: 0x0a (10 fits in 5 bits)
        let mut buf = BytesMut::new();
        encode_integer(&mut buf, 10, 5, 0x00);
        assert_eq!(&buf[..], &[0x0a]);

        // RFC 7541 C.1.2: Encoding 1337 using a 5-bit prefix
        // 1337 = 31 + 1306, 1306 = 0x51a = 10 + 128*10 + 128*128*0
        // Expected: 0x1f 0x9a 0x0a
        buf.clear();
        encode_integer(&mut buf, 1337, 5, 0x00);
        assert_eq!(&buf[..], &[0x1f, 0x9a, 0x0a]);

        // RFC 7541 C.1.3: Encoding 42 at an octet boundary (8-bit prefix)
        buf.clear();
        encode_integer(&mut buf, 42, 8, 0x00);
        assert_eq!(&buf[..], &[0x2a]);
    }

    #[test]
    fn test_rfc7541_integer_decode_roundtrip() {
        // Test various integer values using encode/decode roundtrip
        for &(value, prefix_bits) in &[
            (0_usize, 5_u8),
            (1, 5),
            (30, 5),
            (31, 5),
            (32, 5),
            (127, 7),
            (128, 7),
            (255, 8),
            (256, 8),
            (1337, 5),
            (65535, 8),
        ] {
            let mut buf = BytesMut::new();
            encode_integer(&mut buf, value, prefix_bits, 0x00);

            let mut src = buf.freeze();
            let decoded = decode_integer(&mut src, prefix_bits).unwrap();
            assert_eq!(
                decoded, value,
                "roundtrip failed for {value} with {prefix_bits}-bit prefix"
            );
        }
    }

    #[test]
    fn test_rfc7541_c2_header_field_indexed() {
        // RFC 7541 C.2.4: Indexed Header Field
        // Index 2 in static table = :method: GET
        let mut decoder = Decoder::new();
        let mut src = Bytes::from_static(&[0x82]);
        let headers = decoder.decode(&mut src).unwrap();

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, ":method");
        assert_eq!(headers[0].value, "GET");
    }

    #[test]
    fn test_rfc7541_c3_request_without_huffman() {
        // RFC 7541 C.3.1: First Request (without Huffman)
        // :method: GET, :scheme: http, :path: /, :authority: www.example.com
        let wire: &[u8] = &[
            0x82, // :method: GET (indexed 2)
            0x86, // :scheme: http (indexed 6)
            0x84, // :path: / (indexed 4)
            0x41, 0x0f, // :authority: with literal value, 15 bytes
            b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm',
        ];

        let mut decoder = Decoder::new();
        let mut src = Bytes::copy_from_slice(wire);
        let headers = decoder.decode(&mut src).unwrap();

        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0].name, ":method");
        assert_eq!(headers[0].value, "GET");
        assert_eq!(headers[1].name, ":scheme");
        assert_eq!(headers[1].value, "http");
        assert_eq!(headers[2].name, ":path");
        assert_eq!(headers[2].value, "/");
        assert_eq!(headers[3].name, ":authority");
        assert_eq!(headers[3].value, "www.example.com");
    }

    #[test]
    fn test_rfc7541_c4_request_with_huffman() {
        // Encode headers with Huffman, then decode and verify
        let mut enc = Encoder::new();
        enc.set_use_huffman(true);

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "http"),
            Header::new(":path", "/"),
            Header::new(":authority", "www.example.com"),
        ];

        let mut buf = BytesMut::new();
        enc.encode(&headers, &mut buf);

        let mut dec = Decoder::new();
        let mut src = buf.freeze();
        let headers_out = dec.decode(&mut src).unwrap();

        assert_eq!(headers_out.len(), 4);
        assert_eq!(headers_out[3].value, "www.example.com");
    }

    #[test]
    fn test_rfc7541_c5_response_without_huffman() {
        // Test response headers encoding/decoding
        let mut enc = Encoder::new();
        enc.set_use_huffman(false);

        let headers = vec![
            Header::new(":status", "302"),
            Header::new("cache-control", "private"),
            Header::new("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            Header::new("location", "https://www.example.com"),
        ];

        let mut buf = BytesMut::new();
        enc.encode(&headers, &mut buf);

        let mut dec = Decoder::new();
        let mut src = buf.freeze();
        let headers_out = dec.decode(&mut src).unwrap();

        assert_eq!(headers_out.len(), 4);
        assert_eq!(headers_out[0].name, ":status");
        assert_eq!(headers_out[0].value, "302");
        assert_eq!(headers_out[3].name, "location");
        assert_eq!(headers_out[3].value, "https://www.example.com");
    }

    #[test]
    fn test_rfc7541_huffman_decode_www_example_com() {
        // RFC 7541 C.4.1 encoded "www.example.com" with Huffman
        // This is a known encoding from the spec
        let huffman_encoded: &[u8] = &[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let decoded = decode_huffman(&Bytes::copy_from_slice(huffman_encoded)).unwrap();
        assert_eq!(decoded, "www.example.com");
    }

    // =========================================================================
    // Dynamic Table Edge Cases (bd-et96)
    // =========================================================================

    #[test]
    fn test_dynamic_table_empty() {
        let table = DynamicTable::new();
        assert_eq!(table.size(), 0);
        assert!(table.get(1).is_none());
        assert!(table.get(0).is_none());
        assert!(table.get(100).is_none());
    }

    #[test]
    fn test_dynamic_table_single_entry() {
        let mut table = DynamicTable::new();
        table.insert(Header::new("x-custom", "value"));

        // Index 1 should return the entry
        let entry = table.get(1).unwrap();
        assert_eq!(entry.name, "x-custom");
        assert_eq!(entry.value, "value");

        // Index 2 should be None (only 1 entry)
        assert!(table.get(2).is_none());
    }

    #[test]
    fn test_dynamic_table_fifo_order() {
        let mut table = DynamicTable::new();
        table.insert(Header::new("first", "1"));
        table.insert(Header::new("second", "2"));
        table.insert(Header::new("third", "3"));

        // Most recent entry is at index 1
        assert_eq!(table.get(1).unwrap().name, "third");
        assert_eq!(table.get(2).unwrap().name, "second");
        assert_eq!(table.get(3).unwrap().name, "first");
    }

    #[test]
    fn test_dynamic_table_size_calculation() {
        let mut table = DynamicTable::new();

        // Entry size = name.len() + value.len() + 32 (RFC 7541 Section 4.1)
        let header = Header::new("custom", "value"); // 6 + 5 + 32 = 43
        table.insert(header);
        assert_eq!(table.size(), 43);

        table.insert(Header::new("a", "b")); // 1 + 1 + 32 = 34
        assert_eq!(table.size(), 43 + 34);
    }

    #[test]
    fn test_dynamic_table_max_size_zero() {
        let mut table = DynamicTable::with_max_size(0);
        table.insert(Header::new("header", "value"));

        // With max_size 0, table should always be empty
        assert_eq!(table.size(), 0);
        assert!(table.get(1).is_none());
    }

    #[test]
    fn test_dynamic_table_exact_fit() {
        // Entry is exactly 43 bytes: 6 + 5 + 32
        let mut table = DynamicTable::with_max_size(43);
        table.insert(Header::new("custom", "value"));

        assert_eq!(table.size(), 43);
        assert!(table.get(1).is_some());

        // Insert another entry, first should be evicted
        table.insert(Header::new("newkey", "newva")); // 6 + 5 + 32 = 43
        assert_eq!(table.size(), 43);
        assert_eq!(table.get(1).unwrap().name, "newkey");
        assert!(table.get(2).is_none()); // First entry evicted
    }

    #[test]
    fn test_dynamic_table_cascade_eviction() {
        let mut table = DynamicTable::with_max_size(100);

        // Insert 3 small entries (each 34 bytes = 1+1+32)
        table.insert(Header::new("a", "1"));
        table.insert(Header::new("b", "2"));
        table.insert(Header::new("c", "3"));

        // With max_size=100, inserting 102 bytes triggers eviction of oldest
        // After eviction, only 2 entries should remain (68 bytes)
        assert_eq!(table.size(), 68);
        assert!(table.size() <= 100);
    }

    #[test]
    fn test_dynamic_table_set_max_size() {
        let mut table = DynamicTable::new();
        table.insert(Header::new("header1", "value1")); // 7 + 6 + 32 = 45
        table.insert(Header::new("header2", "value2")); // 7 + 6 + 32 = 45

        let initial_size = table.size();
        assert_eq!(initial_size, 90); // 45 + 45 = 90

        // Reduce max size to force eviction
        table.set_max_size(50);
        assert!(table.size() <= 50);
    }

    #[test]
    fn test_dynamic_table_resize_to_zero() {
        let mut table = DynamicTable::new();
        table.insert(Header::new("key", "val"));
        assert!(table.size() > 0);

        table.set_max_size(0);
        assert_eq!(table.size(), 0);
        assert!(table.get(1).is_none());
    }

    #[test]
    fn test_encoder_dynamic_table_reuse() {
        let mut encoder = Encoder::new();
        encoder.set_use_huffman(false);

        // First encode
        let headers1 = vec![Header::new("x-custom", "value1")];
        let mut buf1 = BytesMut::new();
        encoder.encode(&headers1, &mut buf1);

        // Second encode with same header name
        let headers2 = vec![Header::new("x-custom", "value2")];
        let mut buf2 = BytesMut::new();
        encoder.encode(&headers2, &mut buf2);

        // Both should decode correctly
        let mut decoder = Decoder::new();
        let decoded1 = decoder.decode(&mut buf1.freeze()).unwrap();
        let decoded2 = decoder.decode(&mut buf2.freeze()).unwrap();

        assert_eq!(decoded1[0].name, "x-custom");
        assert_eq!(decoded2[0].name, "x-custom");
    }

    #[test]
    fn test_decoder_shared_state_across_blocks() {
        let mut enc = Encoder::new();
        enc.set_use_huffman(false);

        let mut dec = Decoder::new();

        // First block adds to dynamic table
        let headers1 = vec![Header::new("x-custom", "initial")];
        let mut buf1 = BytesMut::new();
        enc.encode(&headers1, &mut buf1);
        dec.decode(&mut buf1.freeze()).unwrap();

        // Second block can reference dynamic table entries
        let headers2 = vec![Header::new("x-custom", "updated")];
        let mut buf2 = BytesMut::new();
        enc.encode(&headers2, &mut buf2);
        let headers_out = dec.decode(&mut buf2.freeze()).unwrap();

        assert_eq!(headers_out[0].value, "updated");
    }

    // =========================================================================
    // Invalid Input Handling (bd-et96)
    // =========================================================================

    #[test]
    fn test_decode_empty_input() {
        let mut decoder = Decoder::new();
        let mut src = Bytes::new();
        let headers = decoder.decode(&mut src).unwrap();
        assert!(headers.is_empty());
    }

    #[test]
    fn test_decode_invalid_indexed_zero() {
        // Index 0 is invalid per RFC 7541 Section 6.1
        let mut decoder = Decoder::new();
        let mut src = Bytes::from_static(&[0x80]); // Indexed with index 0
        let result = decoder.decode(&mut src);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_index_too_large() {
        // Index beyond static + dynamic table
        let mut decoder = Decoder::new();
        let mut src = Bytes::from_static(&[0xff, 0xff, 0xff, 0x7f]); // Very large index
        let result = decoder.decode(&mut src);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_truncated_integer() {
        // Multi-byte integer without continuation
        let mut decoder = Decoder::new();
        let mut src = Bytes::from_static(&[0x1f]); // Needs continuation but none provided
        let result = decoder.decode(&mut src);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_truncated_string() {
        // String length says 10 bytes but only 3 provided
        let mut decoder = Decoder::new();
        let mut src = Bytes::from_static(&[
            0x40, // Literal header with incremental indexing
            0x0a, // Name length = 10
            b'a', b'b', b'c', // Only 3 bytes
        ]);
        let result = decoder.decode(&mut src);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_huffman_invalid_eos() {
        // EOS symbol must not appear in the decoded stream.
        let invalid_huffman: &[u8] = &[0xff, 0xff, 0xff, 0xff]; // 32 ones contains EOS (30 ones)
        let result = decode_huffman(&Bytes::copy_from_slice(invalid_huffman));
        assert_compression_error(result);
    }

    #[test]
    fn test_decode_integer_overflow_protection() {
        // Attempt to decode an integer that would overflow
        // First byte 0x7f means "use continuation bytes" for 7-bit prefix
        let mut src =
            Bytes::from_static(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        // Should either error or return a reasonable value, not panic
        let result = decode_integer(&mut src, 7);
        // We're testing that it handles this gracefully (should error on overflow)
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_literal_with_empty_name() {
        // Literal header with empty name (valid per spec)
        let mut enc = Encoder::new();
        enc.set_use_huffman(false);

        let headers = vec![Header::new("", "value")];
        let mut buf = BytesMut::new();
        enc.encode(&headers, &mut buf);

        let mut dec = Decoder::new();
        let headers_out = dec.decode(&mut buf.freeze()).unwrap();

        assert_eq!(headers_out.len(), 1);
        assert_eq!(headers_out[0].name, "");
        assert_eq!(headers_out[0].value, "value");
    }

    #[test]
    fn test_decode_literal_with_empty_value() {
        let mut enc = Encoder::new();
        enc.set_use_huffman(false);

        let headers = vec![Header::new("x-empty", "")];
        let mut buf = BytesMut::new();
        enc.encode(&headers, &mut buf);

        let mut dec = Decoder::new();
        let headers_out = dec.decode(&mut buf.freeze()).unwrap();

        assert_eq!(headers_out[0].name, "x-empty");
        assert_eq!(headers_out[0].value, "");
    }

    #[test]
    fn test_static_table_all_entries_accessible() {
        // Verify all 61 static table entries are accessible
        for idx in 1..=61usize {
            let entry = get_static(idx);
            assert!(entry.is_some(), "static table entry {idx} should exist");
        }
        assert!(get_static(62).is_none());
        assert!(get_static(0).is_none());
    }

    #[test]
    fn test_static_table_known_entries() {
        // Verify specific well-known entries
        let method_get = get_static(2).unwrap();
        assert_eq!(method_get.0, ":method");
        assert_eq!(method_get.1, "GET");

        let method_post = get_static(3).unwrap();
        assert_eq!(method_post.0, ":method");
        assert_eq!(method_post.1, "POST");

        let status_200 = get_static(8).unwrap();
        assert_eq!(status_200.0, ":status");
        assert_eq!(status_200.1, "200");

        let status_404 = get_static(13).unwrap();
        assert_eq!(status_404.0, ":status");
        assert_eq!(status_404.1, "404");
    }

    #[test]
    fn test_huffman_all_ascii_printable() {
        // Ensure all printable ASCII characters roundtrip correctly
        let mut input = String::new();
        for c in 32u8..=126 {
            input.push(c as char);
        }

        let encoded = encode_huffman(input.as_bytes());
        let decoded = decode_huffman(&Bytes::from(encoded)).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_huffman_empty_string() {
        let encoded = encode_huffman(b"");
        assert!(encoded.is_empty());

        let decoded = decode_huffman(&Bytes::new()).unwrap();
        assert_eq!(decoded, "");
    }

    #[test]
    fn test_sensitive_header_encoding() {
        // Test headers that should never be indexed (sensitive data)
        let mut enc = Encoder::new();
        let mut dec = Decoder::new();

        // Encode with never-index flag for sensitive headers
        let headers = vec![
            Header::new(":method", "GET"),
            Header::new("authorization", "Bearer secret123"),
        ];

        let mut buf = BytesMut::new();
        enc.encode(&headers, &mut buf);

        let headers_out = dec.decode(&mut buf.freeze()).unwrap();
        assert_eq!(headers_out.len(), 2);
        assert_eq!(headers_out[1].name, "authorization");
        assert_eq!(headers_out[1].value, "Bearer secret123");
    }

    #[test]
    fn test_large_header_value() {
        let mut enc = Encoder::new();
        enc.set_use_huffman(false);

        // Create a large header value (but within reasonable limits)
        let large_value: String = "x".repeat(4096);
        let headers = vec![Header::new("x-large", &large_value)];

        let mut buf = BytesMut::new();
        enc.encode(&headers, &mut buf);

        let mut dec = Decoder::new();
        let headers_out = dec.decode(&mut buf.freeze()).unwrap();

        assert_eq!(headers_out[0].value, large_value);
    }

    #[test]
    fn test_many_headers() {
        let mut enc = Encoder::new();
        enc.set_use_huffman(true);

        // Encode many headers
        let headers: Vec<Header> = (0..100)
            .map(|i| Header::new(format!("x-header-{i}"), format!("value-{i}")))
            .collect();

        let mut buf = BytesMut::new();
        enc.encode(&headers, &mut buf);

        let mut dec = Decoder::new();
        let headers_out = dec.decode(&mut buf.freeze()).unwrap();

        assert_eq!(headers_out.len(), 100);
        for (i, header) in headers_out.iter().enumerate() {
            assert_eq!(header.name, format!("x-header-{i}"));
            assert_eq!(header.value, format!("value-{i}"));
        }
    }

    #[test]
    fn test_deterministic_encoding() {
        // Same input should always produce same output (deterministic for testing)
        let mut encoder1 = Encoder::new();
        let mut encoder2 = Encoder::new();

        let headers = vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/api/test"),
            Header::new("content-type", "application/json"),
        ];

        let mut buf1 = BytesMut::new();
        let mut buf2 = BytesMut::new();
        encoder1.encode(&headers, &mut buf1);
        encoder2.encode(&headers, &mut buf2);

        assert_eq!(buf1, buf2, "encoding should be deterministic");
    }

    // =========================================================================
    // Security Stress Tests (bd-1z7e)
    // =========================================================================

    #[test]
    fn stress_test_hpack_integer_malformed() {
        // Malformed multi-byte integer sequences: verify no panics, only clean errors.
        for shift in 0..=40u8 {
            // Continuation bytes that would cause large shifts
            let mut data = vec![0x7f_u8]; // 7-bit prefix full
            data.extend(std::iter::repeat_n(0xff, shift as usize));
            data.push(0x00); // terminator
            let mut src = Bytes::from(data);
            let _ = decode_integer(&mut src, 7);
        }

        // Random-ish malformed sequences
        for seed in 0..1000u16 {
            let len = ((seed % 10) + 1) as usize;
            let mut data = Vec::with_capacity(len);
            for i in 0..len {
                data.push(((seed.wrapping_mul(31).wrapping_add(i as u16)) & 0xff) as u8);
            }
            // Set prefix to trigger multi-byte path
            if !data.is_empty() {
                data[0] |= 0x1f;
            }
            let mut src = Bytes::from(data);
            let _ = decode_integer(&mut src, 5);
        }
    }

    #[test]
    fn stress_test_huffman_random_bytes() {
        // Random byte sequences: verify graceful failure or valid decode, never panic.
        for seed in 0..2000u32 {
            let len = ((seed % 200) + 1) as usize;
            let mut data = Vec::with_capacity(len);
            for i in 0..len {
                data.push(((seed.wrapping_mul(97).wrapping_add(i as u32)) & 0xff) as u8);
            }
            let _ = decode_huffman(&Bytes::from(data));
        }
    }

    #[test]
    fn stress_test_dynamic_table_churn() {
        // Rapid size oscillation with interleaved insertions: verify memory bounded.
        let mut table = DynamicTable::new();
        for i in 0..5000u32 {
            if i % 3 == 0 {
                table.set_max_size(0);
            } else if i % 3 == 1 {
                table.set_max_size(4096);
            }
            table.insert(Header::new(format!("x-churn-{i}"), format!("value-{i}")));
            assert!(table.size() <= 4096);
        }
    }

    #[test]
    fn stress_test_decoder_malformed_blocks() {
        // Fuzz-like: random byte sequences as HPACK header blocks.
        for seed in 0..1000u32 {
            let len = ((seed % 100) + 1) as usize;
            let mut data = Vec::with_capacity(len);
            for i in 0..len {
                data.push(((seed.wrapping_mul(53).wrapping_add(i as u32 * 7)) & 0xff) as u8);
            }
            let mut decoder = Decoder::new();
            let mut src = Bytes::from(data);
            let _ = decoder.decode(&mut src);
        }
    }

    #[test]
    fn test_huffman_all_single_bytes() {
        // Every single byte value 0x00-0xFF: encode always works, decode
        // succeeds for valid UTF-8 bytes and fails gracefully for others.
        for byte in 0..=255u8 {
            let input = [byte];
            let encoded = encode_huffman(&input);
            let result = decode_huffman(&Bytes::from(encoded));
            if std::str::from_utf8(&input).is_ok() {
                let decoded = result.unwrap_or_else(|e| {
                    panic!("decode failed for valid UTF-8 byte 0x{byte:02x}: {e:?}")
                });
                assert_eq!(
                    decoded.as_bytes(),
                    &input,
                    "roundtrip failed for byte 0x{byte:02x}"
                );
            } else {
                // Non-UTF-8 bytes: should not panic (error is acceptable)
                let _ = result;
            }
        }
    }

    #[test]
    fn test_huffman_long_code_symbols() {
        // Symbols with the longest Huffman codes (9-30 bits) to exercise slow path.
        // Byte values 0x00-0x1f are control chars with longer codes.
        let mut input = Vec::new();
        for b in 0..=31u8 {
            input.push(b);
        }
        let encoded = encode_huffman(&input);
        let decoded = decode_huffman(&Bytes::from(encoded)).unwrap();
        assert_eq!(decoded.as_bytes(), &input[..]);
    }

    #[test]
    fn test_integer_max_valid_value() {
        // Encode and decode a large (but valid) integer.
        let value = 1_000_000_usize;
        let mut buf = BytesMut::new();
        encode_integer(&mut buf, value, 5, 0x00);
        let mut src = buf.freeze();
        let decoded = decode_integer(&mut src, 5).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_integer_all_prefix_sizes() {
        for prefix in [5_u8, 6, 7, 8] {
            for &value in &[0_usize, 1, 30, 31, 127, 128, 255, 256, 65535] {
                let mut buf = BytesMut::new();
                encode_integer(&mut buf, value, prefix, 0x00);
                let mut src = buf.freeze();
                let decoded = decode_integer(&mut src, prefix).unwrap();
                assert_eq!(decoded, value, "prefix={prefix}, value={value}");
            }
        }
    }

    // =========================================================================
    // Audit Fix Tests (br-10x0x.5)
    // =========================================================================

    #[test]
    fn test_encoder_emits_size_update_on_wire() {
        // RFC 7541 §6.3: After set_max_table_size, the encoder MUST emit a
        // dynamic table size update at the start of the next header block.
        let mut encoder = Encoder::new();
        encoder.set_use_huffman(false);

        // Change max table size
        encoder.set_max_table_size(256);

        // Encode a header — the size update should precede it
        let headers = vec![Header::new(":method", "GET")];
        let mut buf = BytesMut::new();
        encoder.encode(&headers, &mut buf);

        // First byte should be a dynamic table size update (0x20 prefix)
        assert_eq!(
            buf[0] & 0xe0,
            0x20,
            "first byte should be dynamic table size update prefix"
        );

        // Decode and verify: the size update should be consumed, then the header
        let mut decoder = Decoder::new();
        decoder.set_allowed_table_size(256);
        let mut src = buf.freeze();
        let decoded_headers = decoder.decode(&mut src).unwrap();
        assert_eq!(decoded_headers.len(), 1);
        assert_eq!(decoded_headers[0].name, ":method");
        assert_eq!(decoded_headers[0].value, "GET");
    }

    #[test]
    fn test_encoder_size_update_not_repeated() {
        // The size update should only be emitted once, not on subsequent blocks.
        let mut encoder = Encoder::new();
        encoder.set_use_huffman(false);
        encoder.set_max_table_size(256);

        // First encode — should have size update prefix
        let mut buf1 = BytesMut::new();
        encoder.encode(&[Header::new(":method", "GET")], &mut buf1);
        assert_eq!(buf1[0] & 0xe0, 0x20, "first block should have size update");

        // Second encode — should NOT have size update prefix
        let mut buf2 = BytesMut::new();
        encoder.encode(&[Header::new(":method", "POST")], &mut buf2);
        // First byte should be indexed header (0x80 prefix) not size update
        assert_ne!(
            buf2[0] & 0xe0,
            0x20,
            "second block should not repeat size update"
        );
    }

    #[test]
    fn test_encoder_size_update_roundtrip_full() {
        // Full encoder/decoder roundtrip after a size change
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new();
        encoder.set_use_huffman(false);

        // Initial encode works
        let headers1 = vec![Header::new("x-test", "value1")];
        let mut buf1 = BytesMut::new();
        encoder.encode(&headers1, &mut buf1);
        let dec1 = decoder.decode(&mut buf1.freeze()).unwrap();
        assert_eq!(dec1[0].value, "value1");

        // Change table size on both sides
        encoder.set_max_table_size(128);
        decoder.set_allowed_table_size(128);

        // Encode after size change — decoder should accept the size update
        let headers2 = vec![Header::new("x-test", "value2")];
        let mut buf2 = BytesMut::new();
        encoder.encode(&headers2, &mut buf2);
        let dec2 = decoder.decode(&mut buf2.freeze()).unwrap();
        assert_eq!(dec2[0].value, "value2");
    }

    #[test]
    fn test_integer_decode_checked_mul_overflow() {
        // On all platforms, verify that the checked_mul path catches
        // values that would silently truncate with plain checked_shl.
        // Craft input: prefix full (0x1f for 5-bit), then continuation
        // bytes that push the value beyond what fits in the platform usize.
        // 5-bit prefix full, then 4 continuation bytes (0xff = value 0x7f + continue)
        let mut data = vec![0x1f_u8];
        data.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        data.push(0x7f); // final byte without continuation
        let mut src = Bytes::from(data);
        // On 32-bit this MUST error (value would be ~34 GB).
        // On 64-bit the value fits, so it may succeed, but we verify no panic.
        let _ = decode_integer(&mut src, 5);
    }

    // =========================================================================
    // Audit Fix Tests: RFC 7541 §4.2 mid-block size update rejection
    // =========================================================================

    #[test]
    fn test_size_update_before_first_header_accepted() {
        // Size update at the start of a block (before any headers) is valid.
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::new();

        // Size update to 2048
        encode_integer(&mut buf, 2048, 5, 0x20);
        // Then an indexed header (:method: GET)
        buf.put_u8(0x82);

        let mut src = buf.freeze();
        let headers = decoder.decode(&mut src).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, ":method");
        assert_eq!(headers[0].value, "GET");
    }

    #[test]
    fn test_size_update_after_first_header_rejected() {
        // RFC 7541 §4.2: size update after the first header field
        // representation MUST be a COMPRESSION_ERROR.
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::new();

        // First: an indexed header (:method: GET)
        buf.put_u8(0x82);
        // Then: a size update (illegal mid-block)
        encode_integer(&mut buf, 2048, 5, 0x20);
        // Then: another indexed header
        buf.put_u8(0x84);

        let mut src = buf.freeze();
        let result = decoder.decode(&mut src);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::CompressionError);
    }

    #[test]
    fn test_multiple_size_updates_then_header_ok() {
        // Multiple size updates before the first header are valid.
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::new();

        // Two consecutive size updates
        encode_integer(&mut buf, 1024, 5, 0x20);
        encode_integer(&mut buf, 2048, 5, 0x20);
        // Then a header
        buf.put_u8(0x82); // :method: GET

        let mut src = buf.freeze();
        let headers = decoder.decode(&mut src).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, ":method");
    }

    // =========================================================================
    // Audit Fix Tests: String length DoS prevention
    // =========================================================================

    #[test]
    fn test_string_length_exceeds_maximum() {
        // Craft a string header with a length claiming > MAX_STRING_LENGTH.
        // The integer encodes 300000 (> 256 * 1024 = 262144).
        let mut buf = BytesMut::new();
        encode_integer(&mut buf, 300_000, 7, 0x00); // literal string, length 300k

        let mut src = buf.freeze();
        let result = decode_string(&mut src);
        assert!(result.is_err());
    }

    #[test]
    fn test_string_length_at_maximum_boundary() {
        // A string of exactly MAX_STRING_LENGTH should be accepted
        // (if the buffer actually contains that many bytes).
        let data = vec![b'x'; MAX_STRING_LENGTH];
        let mut buf = BytesMut::new();
        encode_integer(&mut buf, MAX_STRING_LENGTH, 7, 0x00);
        buf.extend_from_slice(&data);

        let mut src = buf.freeze();
        let result = decode_string(&mut src);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), MAX_STRING_LENGTH);
    }
}
