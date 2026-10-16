//! The Buf trait for reading bytes from a buffer.

use super::{Chain, Take};

/// Read bytes from a buffer.
///
/// This is the main abstraction for reading bytes. It provides a cursor-like
/// interface that advances through the buffer as bytes are consumed.
///
/// # Required Methods
///
/// Implementors must provide:
/// - [`remaining()`](Buf::remaining): Returns bytes available to read
/// - [`chunk()`](Buf::chunk): Returns the next contiguous chunk
/// - [`advance()`](Buf::advance): Advances the cursor
///
/// # Default Implementations
///
/// All other methods have default implementations built on the required methods.
///
/// # Examples
///
/// ```
/// use asupersync::bytes::Buf;
///
/// let mut buf: &[u8] = &[0x12, 0x34, 0x56, 0x78];
/// assert_eq!(buf.get_u16(), 0x1234);
/// assert_eq!(buf.get_u16(), 0x5678);
/// assert_eq!(buf.remaining(), 0);
/// ```
pub trait Buf {
    /// Returns the number of bytes remaining.
    fn remaining(&self) -> usize;

    /// Returns a slice of the next contiguous chunk.
    ///
    /// May return less than [`remaining()`](Buf::remaining) if the buffer
    /// is fragmented (e.g., for chained buffers).
    fn chunk(&self) -> &[u8];

    /// Advance the internal cursor by `cnt` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `cnt > self.remaining()`.
    fn advance(&mut self, cnt: usize);

    // === Default implementations ===

    /// Returns true if there are bytes remaining.
    #[inline]
    fn has_remaining(&self) -> bool {
        self.remaining() > 0
    }

    /// Copy bytes to `dst`, advancing the cursor.
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() > self.remaining()`.
    #[inline]
    fn copy_to_slice(&mut self, dst: &mut [u8]) {
        assert!(
            self.remaining() >= dst.len(),
            "buffer underflow: need {} bytes, have {}",
            dst.len(),
            self.remaining()
        );

        let mut off = 0;
        while off < dst.len() {
            let chunk = self.chunk();
            assert!(
                !chunk.is_empty(),
                "chunk returned empty with remaining() > 0"
            );
            let cnt = std::cmp::min(chunk.len(), dst.len() - off);
            dst[off..off + cnt].copy_from_slice(&chunk[..cnt]);
            self.advance(cnt);
            off += cnt;
        }
    }

    /// Copy the next `len` bytes into a freshly returned [`crate::bytes::Bytes`], advancing
    /// the cursor.
    ///
    /// The default implementation copies. Implementations backed by shared
    /// storage (for example [`BytesCursor`](crate::bytes::BytesCursor))
    /// override this to return a zero-copy slice of the underlying buffer.
    ///
    /// # Panics
    ///
    /// Panics if `len > self.remaining()`.
    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> crate::bytes::Bytes {
        assert!(
            self.remaining() >= len,
            "buffer underflow: need {} bytes, have {}",
            len,
            self.remaining()
        );
        let mut dst = Vec::with_capacity(len);
        let mut off = 0;
        while off < len {
            let chunk = self.chunk();
            assert!(
                !chunk.is_empty(),
                "chunk returned empty with remaining() > 0"
            );
            let cnt = std::cmp::min(chunk.len(), len - off);
            dst.extend_from_slice(&chunk[..cnt]);
            self.advance(cnt);
            off += cnt;
        }
        crate::bytes::Bytes::from(dst)
    }

    /// Get a u8, advancing the cursor.
    ///
    /// # Panics
    ///
    /// Panics if fewer than 1 byte remains.
    #[inline]
    fn get_u8(&mut self) -> u8 {
        assert!(self.remaining() >= 1, "buffer underflow: need 1 byte");
        let val = self.chunk()[0];
        self.advance(1);
        val
    }

    /// Get an i8, advancing the cursor.
    #[inline]
    fn get_i8(&mut self) -> i8 {
        i8::from_ne_bytes([self.get_u8()])
    }

    /// Get a big-endian u16.
    #[inline]
    fn get_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        u16::from_be_bytes(buf)
    }

    /// Get a little-endian u16.
    #[inline]
    fn get_u16_le(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        u16::from_le_bytes(buf)
    }

    /// Get a native-endian u16.
    #[inline]
    fn get_u16_ne(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        u16::from_ne_bytes(buf)
    }

    /// Get a big-endian i16.
    #[inline]
    fn get_i16(&mut self) -> i16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        i16::from_be_bytes(buf)
    }

    /// Get a little-endian i16.
    #[inline]
    fn get_i16_le(&mut self) -> i16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        i16::from_le_bytes(buf)
    }

    /// Get a native-endian i16.
    #[inline]
    fn get_i16_ne(&mut self) -> i16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        i16::from_ne_bytes(buf)
    }

    /// Get a big-endian u32.
    #[inline]
    fn get_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        u32::from_be_bytes(buf)
    }

    /// Get a little-endian u32.
    #[inline]
    fn get_u32_le(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        u32::from_le_bytes(buf)
    }

    /// Get a native-endian u32.
    #[inline]
    fn get_u32_ne(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        u32::from_ne_bytes(buf)
    }

    /// Get a big-endian i32.
    #[inline]
    fn get_i32(&mut self) -> i32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        i32::from_be_bytes(buf)
    }

    /// Get a little-endian i32.
    #[inline]
    fn get_i32_le(&mut self) -> i32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        i32::from_le_bytes(buf)
    }

    /// Get a native-endian i32.
    #[inline]
    fn get_i32_ne(&mut self) -> i32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        i32::from_ne_bytes(buf)
    }

    /// Get a big-endian u64.
    #[inline]
    fn get_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        u64::from_be_bytes(buf)
    }

    /// Get a little-endian u64.
    #[inline]
    fn get_u64_le(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// Get a native-endian u64.
    #[inline]
    fn get_u64_ne(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        u64::from_ne_bytes(buf)
    }

    /// Get a big-endian i64.
    #[inline]
    fn get_i64(&mut self) -> i64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        i64::from_be_bytes(buf)
    }

    /// Get a little-endian i64.
    #[inline]
    fn get_i64_le(&mut self) -> i64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        i64::from_le_bytes(buf)
    }

    /// Get a native-endian i64.
    #[inline]
    fn get_i64_ne(&mut self) -> i64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        i64::from_ne_bytes(buf)
    }

    /// Get a big-endian u128.
    #[inline]
    fn get_u128(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        u128::from_be_bytes(buf)
    }

    /// Get a little-endian u128.
    #[inline]
    fn get_u128_le(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        u128::from_le_bytes(buf)
    }

    /// Get a native-endian u128.
    #[inline]
    fn get_u128_ne(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        u128::from_ne_bytes(buf)
    }

    /// Get a big-endian i128.
    #[inline]
    fn get_i128(&mut self) -> i128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        i128::from_be_bytes(buf)
    }

    /// Get a little-endian i128.
    #[inline]
    fn get_i128_le(&mut self) -> i128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        i128::from_le_bytes(buf)
    }

    /// Get a native-endian i128.
    #[inline]
    fn get_i128_ne(&mut self) -> i128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        i128::from_ne_bytes(buf)
    }

    /// Get a big-endian f32.
    #[inline]
    fn get_f32(&mut self) -> f32 {
        f32::from_bits(self.get_u32())
    }

    /// Get a little-endian f32.
    #[inline]
    fn get_f32_le(&mut self) -> f32 {
        f32::from_bits(self.get_u32_le())
    }

    /// Get a native-endian f32.
    #[inline]
    fn get_f32_ne(&mut self) -> f32 {
        f32::from_bits(self.get_u32_ne())
    }

    /// Get a big-endian f64.
    #[inline]
    fn get_f64(&mut self) -> f64 {
        f64::from_bits(self.get_u64())
    }

    /// Get a little-endian f64.
    #[inline]
    fn get_f64_le(&mut self) -> f64 {
        f64::from_bits(self.get_u64_le())
    }

    /// Get a native-endian f64.
    #[inline]
    fn get_f64_ne(&mut self) -> f64 {
        f64::from_bits(self.get_u64_ne())
    }

    /// Chain this buffer with another.
    ///
    /// Returns a buffer that reads from `self` first, then `next`.
    #[inline]
    fn chain<U: Buf>(self, next: U) -> Chain<Self, U>
    where
        Self: Sized,
    {
        Chain::new(self, next)
    }

    /// Limit reading to the first `limit` bytes.
    #[inline]
    fn take(self, limit: usize) -> Take<Self>
    where
        Self: Sized,
    {
        Take::new(self, limit)
    }
}

// === Implementations for standard types ===

impl Buf for &[u8] {
    #[inline]
    fn remaining(&self) -> usize {
        self.len()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(
            cnt <= self.len(),
            "advance out of bounds: cnt={cnt}, len={}",
            self.len()
        );
        *self = &self[cnt..];
    }
}

#[inline]
fn cursor_logical_start(position: u64, len: usize) -> usize {
    usize::try_from(position).unwrap_or(usize::MAX).min(len)
}

impl Buf for std::io::Cursor<&[u8]> {
    #[inline]
    fn remaining(&self) -> usize {
        let len = self.get_ref().len();
        let pos = cursor_logical_start(self.position(), len);
        len.saturating_sub(pos)
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        let inner = self.get_ref();
        let pos = cursor_logical_start(self.position(), inner.len());
        &inner[pos..]
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(
            cnt <= self.remaining(),
            "advance out of bounds: cnt={cnt}, remaining={}",
            self.remaining()
        );
        let pos = self.position();
        self.set_position(pos + cnt as u64);
    }
}

impl Buf for std::io::Cursor<Vec<u8>> {
    #[inline]
    fn remaining(&self) -> usize {
        let len = self.get_ref().len();
        let pos = cursor_logical_start(self.position(), len);
        len.saturating_sub(pos)
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        let inner = self.get_ref();
        let pos = cursor_logical_start(self.position(), inner.len());
        &inner[pos..]
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(
            cnt <= self.remaining(),
            "advance out of bounds: cnt={cnt}, remaining={}",
            self.remaining()
        );
        let pos = self.position();
        self.set_position(pos + cnt as u64);
    }
}

#[cfg(test)]
#[path = "buf_trait_inline_tests.rs"]
mod tests;
