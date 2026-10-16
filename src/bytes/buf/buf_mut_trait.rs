//! The BufMut trait for writing bytes to a buffer.

use super::Limit;

/// Write bytes to a buffer.
///
/// This is the main abstraction for writing bytes. It provides methods for
/// putting various data types into a buffer.
///
/// # Required Methods
///
/// Implementors must provide:
/// - [`remaining_mut()`](BufMut::remaining_mut): Returns logical append capacity
/// - [`chunk_mut()`](BufMut::chunk_mut): Returns a directly writable slice
/// - [`advance_mut()`](BufMut::advance_mut): Advances after a direct write
///
/// Growable buffers that append through an overridden
/// [`put_slice()`](BufMut::put_slice) may have logical capacity without exposing
/// a direct writable window. Such implementations must override
/// [`direct_remaining_mut()`](BufMut::direct_remaining_mut) to return `0`.
///
/// # Default Implementations
///
/// All other methods have default implementations built on the required methods.
///
/// # Examples
///
/// ```
/// use asupersync::bytes::BufMut;
///
/// let mut buf = Vec::new();
/// buf.put_u16(0x1234);
/// buf.put_u16_le(0x5678);
/// assert_eq!(buf, vec![0x12, 0x34, 0x78, 0x56]);
/// ```
pub trait BufMut {
    /// Returns the number of bytes that can be appended.
    ///
    /// This is the logical capacity used by [`put_slice()`](BufMut::put_slice)
    /// and the scalar `put_*` helpers. It can be greater than
    /// [`direct_remaining_mut()`](BufMut::direct_remaining_mut) for growable
    /// buffers that append without exposing initialized spare storage.
    ///
    /// For growable buffers like `Vec<u8>`, this returns `usize::MAX - len()`.
    fn remaining_mut(&self) -> usize;

    /// Returns the number of bytes writable through `chunk_mut`/`advance_mut`.
    ///
    /// The default matches [`remaining_mut()`](BufMut::remaining_mut), which is
    /// appropriate for fixed or cursor-backed buffers. Append-only growable
    /// buffers must override this to return `0` while still reporting their
    /// logical append capacity from `remaining_mut`.
    #[inline]
    fn direct_remaining_mut(&self) -> usize {
        self.remaining_mut()
    }

    /// Returns an initialized mutable slice for direct writing.
    ///
    /// The slice may be empty even when [`remaining_mut()`](BufMut::remaining_mut)
    /// is positive if the implementation supports logical appends but has no
    /// direct window. Callers that require direct access must check
    /// [`direct_remaining_mut()`](BufMut::direct_remaining_mut). When that value
    /// is positive, this method must return a non-empty slice whose length does
    /// not exceed it.
    fn chunk_mut(&mut self) -> &mut [u8];

    /// Advance the write cursor by `cnt` bytes.
    ///
    /// `cnt` must not exceed the direct capacity reported before the most recent
    /// call to [`chunk_mut()`](BufMut::chunk_mut). Calling this with `0` is always
    /// permitted, including for append-only buffers with no direct window.
    fn advance_mut(&mut self, cnt: usize);

    // === Default implementations ===

    /// Returns true if there is space remaining.
    #[inline]
    fn has_remaining_mut(&self) -> bool {
        self.remaining_mut() > 0
    }

    /// Put a slice into the buffer.
    ///
    /// # Panics
    ///
    /// Panics if `src.len() > self.remaining_mut()`.
    #[inline]
    fn put_slice(&mut self, src: &[u8]) {
        assert!(
            self.remaining_mut() >= src.len(),
            "buffer overflow: need {} bytes, have {}",
            src.len(),
            self.remaining_mut()
        );

        let mut off = 0;
        while off < src.len() {
            let direct_remaining = self.direct_remaining_mut();
            assert!(
                direct_remaining > 0,
                "put_slice requires direct writable space; append-only implementors must override put_slice"
            );
            let dst = self.chunk_mut();
            assert!(
                !dst.is_empty(),
                "chunk_mut returned empty with direct_remaining_mut() > 0"
            );
            assert!(
                dst.len() <= direct_remaining,
                "chunk_mut exceeded direct capacity: chunk_len={}, direct_remaining={direct_remaining}",
                dst.len()
            );
            let cnt = std::cmp::min(dst.len(), src.len() - off);
            dst[..cnt].copy_from_slice(&src[off..off + cnt]);
            self.advance_mut(cnt);
            off += cnt;
        }
    }

    /// Put a single byte.
    #[inline]
    fn put_u8(&mut self, n: u8) {
        self.put_slice(&[n]);
    }

    /// Put an i8.
    #[inline]
    fn put_i8(&mut self, n: i8) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian u16.
    #[inline]
    fn put_u16(&mut self, n: u16) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian u16.
    #[inline]
    fn put_u16_le(&mut self, n: u16) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian u16.
    #[inline]
    fn put_u16_ne(&mut self, n: u16) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian i16.
    #[inline]
    fn put_i16(&mut self, n: i16) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian i16.
    #[inline]
    fn put_i16_le(&mut self, n: i16) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian i16.
    #[inline]
    fn put_i16_ne(&mut self, n: i16) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian u32.
    #[inline]
    fn put_u32(&mut self, n: u32) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian u32.
    #[inline]
    fn put_u32_le(&mut self, n: u32) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian u32.
    #[inline]
    fn put_u32_ne(&mut self, n: u32) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian i32.
    #[inline]
    fn put_i32(&mut self, n: i32) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian i32.
    #[inline]
    fn put_i32_le(&mut self, n: i32) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian i32.
    #[inline]
    fn put_i32_ne(&mut self, n: i32) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian u64.
    #[inline]
    fn put_u64(&mut self, n: u64) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian u64.
    #[inline]
    fn put_u64_le(&mut self, n: u64) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian u64.
    #[inline]
    fn put_u64_ne(&mut self, n: u64) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian i64.
    #[inline]
    fn put_i64(&mut self, n: i64) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian i64.
    #[inline]
    fn put_i64_le(&mut self, n: i64) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian i64.
    #[inline]
    fn put_i64_ne(&mut self, n: i64) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian u128.
    #[inline]
    fn put_u128(&mut self, n: u128) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian u128.
    #[inline]
    fn put_u128_le(&mut self, n: u128) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian u128.
    #[inline]
    fn put_u128_ne(&mut self, n: u128) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian i128.
    #[inline]
    fn put_i128(&mut self, n: i128) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian i128.
    #[inline]
    fn put_i128_le(&mut self, n: i128) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian i128.
    #[inline]
    fn put_i128_ne(&mut self, n: i128) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian f32.
    #[inline]
    fn put_f32(&mut self, n: f32) {
        self.put_u32(n.to_bits());
    }

    /// Put a little-endian f32.
    #[inline]
    fn put_f32_le(&mut self, n: f32) {
        self.put_u32_le(n.to_bits());
    }

    /// Put a native-endian f32.
    #[inline]
    fn put_f32_ne(&mut self, n: f32) {
        self.put_u32_ne(n.to_bits());
    }

    /// Put a big-endian f64.
    #[inline]
    fn put_f64(&mut self, n: f64) {
        self.put_u64(n.to_bits());
    }

    /// Put a little-endian f64.
    #[inline]
    fn put_f64_le(&mut self, n: f64) {
        self.put_u64_le(n.to_bits());
    }

    /// Put a native-endian f64.
    #[inline]
    fn put_f64_ne(&mut self, n: f64) {
        self.put_u64_ne(n.to_bits());
    }

    /// Limit writing to `limit` bytes.
    #[inline]
    fn limit(self, limit: usize) -> Limit<Self>
    where
        Self: Sized,
    {
        Limit::new(self, limit)
    }
}

// === Implementations for standard types ===

impl BufMut for Vec<u8> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        usize::MAX - self.len()
    }

    #[inline]
    fn direct_remaining_mut(&self) -> usize {
        0
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        // For Vec, we grow dynamically via put_slice override.
        // chunk_mut returns empty because Vec doesn't have pre-allocated
        // writable space without using unsafe.
        &mut []
    }

    #[inline]
    fn advance_mut(&mut self, cnt: usize) {
        // For Vec, advance is handled in put_slice.
        // Any non-zero advance would silently drop data, so fail fast.
        assert!(
            cnt == 0,
            "advance_mut is unsupported for Vec<u8>; use put_slice"
        );
    }

    // Override put_slice for efficient Vec implementation
    #[inline]
    fn put_slice(&mut self, src: &[u8]) {
        self.extend_from_slice(src);
    }
}

impl BufMut for &mut [u8] {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.len()
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        self
    }

    #[inline]
    fn advance_mut(&mut self, cnt: usize) {
        assert!(
            cnt <= self.len(),
            "advance_mut out of bounds: cnt={cnt}, len={}",
            self.len()
        );
        // Take the remaining portion
        let tmp = std::mem::take(self);
        *self = &mut tmp[cnt..];
    }
}

#[cfg(test)]
#[path = "buf_mut_trait_inline_tests.rs"]
mod tests;
