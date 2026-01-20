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
/// - [`remaining_mut()`](BufMut::remaining_mut): Returns bytes that can be written
/// - [`chunk_mut()`](BufMut::chunk_mut): Returns a mutable slice for writing
/// - [`advance_mut()`](BufMut::advance_mut): Advances after writing
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
    /// Returns number of bytes that can be written.
    ///
    /// For growable buffers like `Vec<u8>`, this returns `usize::MAX - len()`.
    fn remaining_mut(&self) -> usize;

    /// Returns a mutable slice for writing.
    ///
    /// The returned slice may be uninitialized. Callers must initialize bytes
    /// before calling [`advance_mut()`](BufMut::advance_mut).
    fn chunk_mut(&mut self) -> &mut [u8];

    /// Advance the write cursor by `cnt` bytes.
    ///
    /// # Safety Note
    ///
    /// While this method is safe, callers must ensure that `cnt` bytes have
    /// been written to the buffer returned by [`chunk_mut()`](BufMut::chunk_mut).
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
    fn put_slice(&mut self, src: &[u8]) {
        assert!(
            self.remaining_mut() >= src.len(),
            "buffer overflow: need {} bytes, have {}",
            src.len(),
            self.remaining_mut()
        );

        let mut off = 0;
        while off < src.len() {
            let dst = self.chunk_mut();
            assert!(
                !dst.is_empty(),
                "chunk_mut returned empty with remaining_mut() > 0; implementor must provide writable space"
            );
            let cnt = std::cmp::min(dst.len(), src.len() - off);
            dst[..cnt].copy_from_slice(&src[off..off + cnt]);
            self.advance_mut(cnt);
            off += cnt;
        }
    }

    /// Put a single byte.
    fn put_u8(&mut self, n: u8) {
        self.put_slice(&[n]);
    }

    /// Put an i8.
    fn put_i8(&mut self, n: i8) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian u16.
    fn put_u16(&mut self, n: u16) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian u16.
    fn put_u16_le(&mut self, n: u16) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian u16.
    fn put_u16_ne(&mut self, n: u16) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian i16.
    fn put_i16(&mut self, n: i16) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian i16.
    fn put_i16_le(&mut self, n: i16) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian i16.
    fn put_i16_ne(&mut self, n: i16) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian u32.
    fn put_u32(&mut self, n: u32) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian u32.
    fn put_u32_le(&mut self, n: u32) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian u32.
    fn put_u32_ne(&mut self, n: u32) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian i32.
    fn put_i32(&mut self, n: i32) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian i32.
    fn put_i32_le(&mut self, n: i32) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian i32.
    fn put_i32_ne(&mut self, n: i32) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian u64.
    fn put_u64(&mut self, n: u64) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian u64.
    fn put_u64_le(&mut self, n: u64) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian u64.
    fn put_u64_ne(&mut self, n: u64) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian i64.
    fn put_i64(&mut self, n: i64) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian i64.
    fn put_i64_le(&mut self, n: i64) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian i64.
    fn put_i64_ne(&mut self, n: i64) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian u128.
    fn put_u128(&mut self, n: u128) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian u128.
    fn put_u128_le(&mut self, n: u128) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian u128.
    fn put_u128_ne(&mut self, n: u128) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian i128.
    fn put_i128(&mut self, n: i128) {
        self.put_slice(&n.to_be_bytes());
    }

    /// Put a little-endian i128.
    fn put_i128_le(&mut self, n: i128) {
        self.put_slice(&n.to_le_bytes());
    }

    /// Put a native-endian i128.
    fn put_i128_ne(&mut self, n: i128) {
        self.put_slice(&n.to_ne_bytes());
    }

    /// Put a big-endian f32.
    fn put_f32(&mut self, n: f32) {
        self.put_u32(n.to_bits());
    }

    /// Put a little-endian f32.
    fn put_f32_le(&mut self, n: f32) {
        self.put_u32_le(n.to_bits());
    }

    /// Put a native-endian f32.
    fn put_f32_ne(&mut self, n: f32) {
        self.put_u32_ne(n.to_bits());
    }

    /// Put a big-endian f64.
    fn put_f64(&mut self, n: f64) {
        self.put_u64(n.to_bits());
    }

    /// Put a little-endian f64.
    fn put_f64_le(&mut self, n: f64) {
        self.put_u64_le(n.to_bits());
    }

    /// Put a native-endian f64.
    fn put_f64_ne(&mut self, n: f64) {
        self.put_u64_ne(n.to_bits());
    }

    /// Limit writing to `limit` bytes.
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

    fn chunk_mut(&mut self) -> &mut [u8] {
        // For Vec, we grow dynamically via put_slice override.
        // chunk_mut returns empty because Vec doesn't have pre-allocated
        // writable space without using unsafe.
        &mut []
    }

    fn advance_mut(&mut self, cnt: usize) {
        // For Vec, advance is handled in put_slice.
        // Any non-zero advance would silently drop data, so fail fast.
        assert!(
            cnt == 0,
            "advance_mut is unsupported for Vec<u8>; use put_slice"
        );
    }

    // Override put_slice for efficient Vec implementation
    fn put_slice(&mut self, src: &[u8]) {
        self.extend_from_slice(src);
    }
}

impl BufMut for &mut [u8] {
    fn remaining_mut(&self) -> usize {
        self.len()
    }

    fn chunk_mut(&mut self) -> &mut [u8] {
        self
    }

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
mod tests {
    use super::super::Buf;
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_buf_mut_vec_put_u8() {
        init_test("test_buf_mut_vec_put_u8");
        let mut buf = Vec::new();
        buf.put_u8(42);
        buf.put_u8(43);
        let ok = buf == vec![42, 43];
        crate::assert_with_log!(ok, "buf", vec![42, 43], buf);
        crate::test_complete!("test_buf_mut_vec_put_u8");
    }

    #[test]
    fn test_buf_mut_vec_put_u16() {
        init_test("test_buf_mut_vec_put_u16");
        let mut buf = Vec::new();
        buf.put_u16(0x1234);
        let ok = buf == vec![0x12, 0x34];
        crate::assert_with_log!(ok, "buf", vec![0x12, 0x34], buf);
        crate::test_complete!("test_buf_mut_vec_put_u16");
    }

    #[test]
    fn test_buf_mut_vec_put_u16_le() {
        init_test("test_buf_mut_vec_put_u16_le");
        let mut buf = Vec::new();
        buf.put_u16_le(0x1234);
        let ok = buf == vec![0x34, 0x12];
        crate::assert_with_log!(ok, "buf", vec![0x34, 0x12], buf);
        crate::test_complete!("test_buf_mut_vec_put_u16_le");
    }

    #[test]
    fn test_buf_mut_vec_put_u32() {
        init_test("test_buf_mut_vec_put_u32");
        let mut buf = Vec::new();
        buf.put_u32(0x1234_5678);
        let ok = buf == vec![0x12, 0x34, 0x56, 0x78];
        crate::assert_with_log!(ok, "buf", vec![0x12, 0x34, 0x56, 0x78], buf);
        crate::test_complete!("test_buf_mut_vec_put_u32");
    }

    #[test]
    fn test_buf_mut_vec_put_slice() {
        init_test("test_buf_mut_vec_put_slice");
        let mut buf = Vec::new();
        buf.put_slice(b"hello");
        buf.put_slice(b" world");
        let ok = buf == b"hello world";
        crate::assert_with_log!(ok, "buf", b"hello world", buf);
        crate::test_complete!("test_buf_mut_vec_put_slice");
    }

    #[test]
    fn test_buf_mut_vec_put_f32() {
        init_test("test_buf_mut_vec_put_f32");
        let mut buf = Vec::new();
        let expected = std::f32::consts::PI;
        buf.put_f32(expected);

        // Verify by reading back
        let mut read: &[u8] = &buf;
        let val = read.get_f32();
        let ok = (val - expected).abs() < 0.0001;
        crate::assert_with_log!(ok, "f32", true, ok);
        crate::test_complete!("test_buf_mut_vec_put_f32");
    }

    #[test]
    fn test_buf_mut_vec_put_f64() {
        init_test("test_buf_mut_vec_put_f64");
        let mut buf = Vec::new();
        buf.put_f64(std::f64::consts::PI);

        // Verify by reading back
        let mut read: &[u8] = &buf;
        let val = read.get_f64();
        let ok = (val - std::f64::consts::PI).abs() < 1e-10;
        crate::assert_with_log!(ok, "f64", true, ok);
        crate::test_complete!("test_buf_mut_vec_put_f64");
    }

    #[test]
    fn test_buf_mut_slice() {
        init_test("test_buf_mut_slice");
        let mut data = [0u8; 10];
        let mut buf: &mut [u8] = &mut data;

        buf.put_u16(0x1234);
        buf.put_u16(0x5678);

        let ok = data[0..4] == [0x12, 0x34, 0x56, 0x78];
        crate::assert_with_log!(ok, "data", [0x12, 0x34, 0x56, 0x78], data[0..4].to_vec());
        crate::test_complete!("test_buf_mut_slice");
    }

    #[test]
    fn test_roundtrip_all_types() {
        init_test("test_roundtrip_all_types");
        let mut buf = Vec::new();
        let expected_f32 = std::f32::consts::PI;

        buf.put_u8(0x12);
        buf.put_i8(-5);
        buf.put_u16(0x1234);
        buf.put_u16_le(0x5678);
        buf.put_i16(-1000);
        buf.put_u32(0x1234_5678);
        buf.put_u32_le(0x9ABC_DEF0);
        buf.put_i32(-100_000);
        buf.put_u64(0x1234_5678_9ABC_DEF0);
        buf.put_u64_le(0xFEDC_BA98_7654_3210);
        buf.put_f32(expected_f32);
        let expected = std::f64::consts::E;
        buf.put_f64(expected);

        let mut read: &[u8] = &buf;

        let v = read.get_u8();
        crate::assert_with_log!(v == 0x12, "u8", 0x12, v);
        let v = read.get_i8();
        crate::assert_with_log!(v == -5, "i8", -5, v);
        let v = read.get_u16();
        crate::assert_with_log!(v == 0x1234, "u16", 0x1234, v);
        let v = read.get_u16_le();
        crate::assert_with_log!(v == 0x5678, "u16_le", 0x5678, v);
        let v = read.get_i16();
        crate::assert_with_log!(v == -1000, "i16", -1000, v);
        let v = read.get_u32();
        crate::assert_with_log!(v == 0x1234_5678, "u32", 0x1234_5678, v);
        let v = read.get_u32_le();
        crate::assert_with_log!(v == 0x9ABC_DEF0, "u32_le", 0x9ABC_DEF0u32, v);
        let v = read.get_i32();
        crate::assert_with_log!(v == -100_000, "i32", -100_000, v);
        let v = read.get_u64();
        crate::assert_with_log!(
            v == 0x1234_5678_9ABC_DEF0,
            "u64",
            0x1234_5678_9ABC_DEF0u64,
            v
        );
        let v = read.get_u64_le();
        crate::assert_with_log!(
            v == 0xFEDC_BA98_7654_3210,
            "u64_le",
            0xFEDC_BA98_7654_3210u64,
            v
        );
        let ok = (read.get_f32() - expected_f32).abs() < 0.0001;
        crate::assert_with_log!(ok, "f32", true, ok);
        let ok = (read.get_f64() - expected).abs() < 1e-9;
        crate::assert_with_log!(ok, "f64", true, ok);
        crate::test_complete!("test_roundtrip_all_types");
    }
}
