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
            let cnt = std::cmp::min(chunk.len(), dst.len() - off);
            dst[off..off + cnt].copy_from_slice(&chunk[..cnt]);
            self.advance(cnt);
            off += cnt;
        }
    }

    /// Get a u8, advancing the cursor.
    ///
    /// # Panics
    ///
    /// Panics if fewer than 1 byte remains.
    fn get_u8(&mut self) -> u8 {
        assert!(self.remaining() >= 1, "buffer underflow: need 1 byte");
        let val = self.chunk()[0];
        self.advance(1);
        val
    }

    /// Get an i8, advancing the cursor.
    fn get_i8(&mut self) -> i8 {
        i8::from_ne_bytes([self.get_u8()])
    }

    /// Get a big-endian u16.
    fn get_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        u16::from_be_bytes(buf)
    }

    /// Get a little-endian u16.
    fn get_u16_le(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        u16::from_le_bytes(buf)
    }

    /// Get a native-endian u16.
    fn get_u16_ne(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        u16::from_ne_bytes(buf)
    }

    /// Get a big-endian i16.
    fn get_i16(&mut self) -> i16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        i16::from_be_bytes(buf)
    }

    /// Get a little-endian i16.
    fn get_i16_le(&mut self) -> i16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        i16::from_le_bytes(buf)
    }

    /// Get a native-endian i16.
    fn get_i16_ne(&mut self) -> i16 {
        let mut buf = [0u8; 2];
        self.copy_to_slice(&mut buf);
        i16::from_ne_bytes(buf)
    }

    /// Get a big-endian u32.
    fn get_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        u32::from_be_bytes(buf)
    }

    /// Get a little-endian u32.
    fn get_u32_le(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        u32::from_le_bytes(buf)
    }

    /// Get a native-endian u32.
    fn get_u32_ne(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        u32::from_ne_bytes(buf)
    }

    /// Get a big-endian i32.
    fn get_i32(&mut self) -> i32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        i32::from_be_bytes(buf)
    }

    /// Get a little-endian i32.
    fn get_i32_le(&mut self) -> i32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        i32::from_le_bytes(buf)
    }

    /// Get a native-endian i32.
    fn get_i32_ne(&mut self) -> i32 {
        let mut buf = [0u8; 4];
        self.copy_to_slice(&mut buf);
        i32::from_ne_bytes(buf)
    }

    /// Get a big-endian u64.
    fn get_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        u64::from_be_bytes(buf)
    }

    /// Get a little-endian u64.
    fn get_u64_le(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// Get a native-endian u64.
    fn get_u64_ne(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        u64::from_ne_bytes(buf)
    }

    /// Get a big-endian i64.
    fn get_i64(&mut self) -> i64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        i64::from_be_bytes(buf)
    }

    /// Get a little-endian i64.
    fn get_i64_le(&mut self) -> i64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        i64::from_le_bytes(buf)
    }

    /// Get a native-endian i64.
    fn get_i64_ne(&mut self) -> i64 {
        let mut buf = [0u8; 8];
        self.copy_to_slice(&mut buf);
        i64::from_ne_bytes(buf)
    }

    /// Get a big-endian u128.
    fn get_u128(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        u128::from_be_bytes(buf)
    }

    /// Get a little-endian u128.
    fn get_u128_le(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        u128::from_le_bytes(buf)
    }

    /// Get a native-endian u128.
    fn get_u128_ne(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        u128::from_ne_bytes(buf)
    }

    /// Get a big-endian i128.
    fn get_i128(&mut self) -> i128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        i128::from_be_bytes(buf)
    }

    /// Get a little-endian i128.
    fn get_i128_le(&mut self) -> i128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        i128::from_le_bytes(buf)
    }

    /// Get a native-endian i128.
    fn get_i128_ne(&mut self) -> i128 {
        let mut buf = [0u8; 16];
        self.copy_to_slice(&mut buf);
        i128::from_ne_bytes(buf)
    }

    /// Get a big-endian f32.
    fn get_f32(&mut self) -> f32 {
        f32::from_bits(self.get_u32())
    }

    /// Get a little-endian f32.
    fn get_f32_le(&mut self) -> f32 {
        f32::from_bits(self.get_u32_le())
    }

    /// Get a native-endian f32.
    fn get_f32_ne(&mut self) -> f32 {
        f32::from_bits(self.get_u32_ne())
    }

    /// Get a big-endian f64.
    fn get_f64(&mut self) -> f64 {
        f64::from_bits(self.get_u64())
    }

    /// Get a little-endian f64.
    fn get_f64_le(&mut self) -> f64 {
        f64::from_bits(self.get_u64_le())
    }

    /// Get a native-endian f64.
    fn get_f64_ne(&mut self) -> f64 {
        f64::from_bits(self.get_u64_ne())
    }

    /// Chain this buffer with another.
    ///
    /// Returns a buffer that reads from `self` first, then `next`.
    fn chain<U: Buf>(self, next: U) -> Chain<Self, U>
    where
        Self: Sized,
    {
        Chain::new(self, next)
    }

    /// Limit reading to the first `limit` bytes.
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

impl Buf for std::io::Cursor<&[u8]> {
    fn remaining(&self) -> usize {
        let pos = self.position() as usize;
        let len = self.get_ref().len();
        len.saturating_sub(pos)
    }

    fn chunk(&self) -> &[u8] {
        let pos = self.position() as usize;
        let inner = self.get_ref();
        if pos >= inner.len() {
            &[]
        } else {
            &inner[pos..]
        }
    }

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
    fn remaining(&self) -> usize {
        let pos = self.position() as usize;
        let len = self.get_ref().len();
        len.saturating_sub(pos)
    }

    fn chunk(&self) -> &[u8] {
        let pos = self.position() as usize;
        let inner = self.get_ref();
        if pos >= inner.len() {
            &[]
        } else {
            &inner[pos..]
        }
    }

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
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_buf_slice_remaining() {
        init_test("test_buf_slice_remaining");
        let buf: &[u8] = &[1, 2, 3, 4, 5];
        let remaining = buf.remaining();
        crate::assert_with_log!(remaining == 5, "remaining", 5, remaining);
        crate::test_complete!("test_buf_slice_remaining");
    }

    #[test]
    fn test_buf_slice_get_u8() {
        init_test("test_buf_slice_get_u8");
        let mut buf: &[u8] = &[1, 2, 3, 4, 5];
        let v = buf.get_u8();
        crate::assert_with_log!(v == 1, "get_u8", 1, v);
        let v = buf.get_u8();
        crate::assert_with_log!(v == 2, "get_u8", 2, v);
        let remaining = buf.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        crate::test_complete!("test_buf_slice_get_u8");
    }

    #[test]
    fn test_buf_get_u16() {
        init_test("test_buf_get_u16");
        let mut buf: &[u8] = &[0x12, 0x34];
        let v = buf.get_u16();
        crate::assert_with_log!(v == 0x1234, "get_u16", 0x1234, v);
        crate::test_complete!("test_buf_get_u16");
    }

    #[test]
    fn test_buf_get_u16_le() {
        init_test("test_buf_get_u16_le");
        let mut buf: &[u8] = &[0x34, 0x12];
        let v = buf.get_u16_le();
        crate::assert_with_log!(v == 0x1234, "get_u16_le", 0x1234, v);
        crate::test_complete!("test_buf_get_u16_le");
    }

    #[test]
    fn test_buf_get_u32() {
        init_test("test_buf_get_u32");
        let mut buf: &[u8] = &[0x12, 0x34, 0x56, 0x78];
        let v = buf.get_u32();
        crate::assert_with_log!(v == 0x1234_5678, "get_u32", 0x1234_5678, v);
        crate::test_complete!("test_buf_get_u32");
    }

    #[test]
    fn test_buf_get_u64() {
        init_test("test_buf_get_u64");
        let mut buf: &[u8] = &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let v = buf.get_u64();
        crate::assert_with_log!(
            v == 0x1234_5678_9ABC_DEF0,
            "get_u64",
            0x1234_5678_9ABC_DEF0u64,
            v
        );
        crate::test_complete!("test_buf_get_u64");
    }

    #[test]
    fn test_buf_copy_to_slice() {
        init_test("test_buf_copy_to_slice");
        let mut buf: &[u8] = &[1, 2, 3, 4, 5];
        let mut dst = [0u8; 3];
        buf.copy_to_slice(&mut dst);
        let ok = dst == [1, 2, 3];
        crate::assert_with_log!(ok, "dst", [1, 2, 3], dst);
        let remaining = buf.remaining();
        crate::assert_with_log!(remaining == 2, "remaining", 2, remaining);
        crate::test_complete!("test_buf_copy_to_slice");
    }

    #[test]
    fn test_buf_get_f32() {
        init_test("test_buf_get_f32");
        let mut buf = Vec::new();
        let expected = std::f32::consts::PI;
        buf.extend_from_slice(&expected.to_be_bytes());
        let mut slice: &[u8] = &buf;
        let val = slice.get_f32();
        let ok = (val - expected).abs() < 0.0001;
        crate::assert_with_log!(ok, "f32", true, ok);
        crate::test_complete!("test_buf_get_f32");
    }

    #[test]
    fn test_buf_get_f64() {
        init_test("test_buf_get_f64");
        let mut buf = Vec::new();
        buf.extend_from_slice(&std::f64::consts::PI.to_be_bytes());
        let mut slice: &[u8] = &buf;
        let val = slice.get_f64();
        let ok = (val - std::f64::consts::PI).abs() < 1e-10;
        crate::assert_with_log!(ok, "f64", true, ok);
        crate::test_complete!("test_buf_get_f64");
    }

    #[test]
    #[should_panic(expected = "buffer underflow")]
    fn test_buf_underflow() {
        let mut buf: &[u8] = &[1];
        buf.get_u16();
    }

    #[test]
    fn test_buf_cursor() {
        init_test("test_buf_cursor");
        let data = vec![1u8, 2, 3, 4, 5];
        let mut cursor = std::io::Cursor::new(data);
        let remaining = cursor.remaining();
        crate::assert_with_log!(remaining == 5, "remaining", 5, remaining);
        let v = cursor.get_u8();
        crate::assert_with_log!(v == 1, "get_u8", 1, v);
        let remaining = cursor.remaining();
        crate::assert_with_log!(remaining == 4, "remaining", 4, remaining);
        crate::test_complete!("test_buf_cursor");
    }

    #[test]
    fn test_roundtrip_all_integers() {
        init_test("test_roundtrip_all_integers");
        // Write all types
        let mut write_buf = Vec::new();
        write_buf.extend_from_slice(&0x12u8.to_be_bytes());
        write_buf.extend_from_slice(&(-5i8).to_be_bytes());
        write_buf.extend_from_slice(&0x1234u16.to_be_bytes());
        write_buf.extend_from_slice(&0x5678u16.to_le_bytes());
        write_buf.extend_from_slice(&(-1000i16).to_be_bytes());
        write_buf.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        write_buf.extend_from_slice(&0x9ABC_DEF0u32.to_le_bytes());
        write_buf.extend_from_slice(&(-100_000i32).to_be_bytes());
        write_buf.extend_from_slice(&0x1234_5678_9ABC_DEF0u64.to_be_bytes());
        write_buf.extend_from_slice(&0xFEDC_BA98_7654_3210u64.to_le_bytes());

        // Read all types
        let mut read: &[u8] = &write_buf;
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
        crate::test_complete!("test_roundtrip_all_integers");
    }
}
