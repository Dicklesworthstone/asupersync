//! Mutable buffer with efficient growth and splitting.

use super::Bytes;
use super::buf::BufMut;
use std::ops::{Deref, DerefMut, RangeBounds};

/// Mutable buffer that can be frozen into `Bytes`.
///
/// `BytesMut` provides a mutable buffer with efficient growth, splitting,
/// and the ability to freeze into an immutable `Bytes`.
///
/// # Implementation
///
/// This implementation uses `Vec<u8>` as the backing storage, ensuring
/// safety without unsafe code. For small buffers, inline storage could
/// be added as an optimization in the future.
///
/// # Examples
///
/// ```
/// use asupersync::bytes::BytesMut;
///
/// let mut buf = BytesMut::with_capacity(100);
/// buf.put_slice(b"hello");
/// buf.put_slice(b" world");
///
/// let frozen = buf.freeze();
/// assert_eq!(&frozen[..], b"hello world");
/// ```
pub struct BytesMut {
    /// The backing storage.
    data: Vec<u8>,
}

impl BytesMut {
    /// Create an empty `BytesMut`.
    #[must_use]
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a `BytesMut` with the given capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::BytesMut;
    ///
    /// let buf = BytesMut::with_capacity(100);
    /// assert!(buf.is_empty());
    /// assert!(buf.capacity() >= 100);
    /// ```
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Returns the number of bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the capacity.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Freeze into an immutable `Bytes`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::new();
    /// buf.put_slice(b"hello world");
    ///
    /// let frozen = buf.freeze();
    /// assert_eq!(&frozen[..], b"hello world");
    /// ```
    #[must_use]
    pub fn freeze(self) -> Bytes {
        Bytes::from(self.data)
    }

    /// Reserve at least `additional` more bytes of capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::new();
    /// buf.reserve(100);
    /// assert!(buf.capacity() >= 100);
    /// ```
    pub fn reserve(&mut self, additional: usize) {
        self.data.reserve(additional);
    }

    /// Append bytes to the buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::new();
    /// buf.put_slice(b"hello");
    /// buf.put_slice(b" world");
    /// assert_eq!(&buf[..], b"hello world");
    /// ```
    pub fn put_slice(&mut self, src: &[u8]) {
        self.data.extend_from_slice(src);
    }

    /// Extend from slice (alias for `put_slice`).
    pub fn extend_from_slice(&mut self, src: &[u8]) {
        self.put_slice(src);
    }

    /// Put a single byte.
    pub fn put_u8(&mut self, n: u8) {
        self.data.push(n);
    }

    /// Split off bytes from `at` to end.
    ///
    /// Self becomes `[0, at)`, returns `[at, len)`.
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::new();
    /// buf.put_slice(b"hello world");
    ///
    /// let world = buf.split_off(6);
    /// assert_eq!(&buf[..], b"hello ");
    /// assert_eq!(&world[..], b"world");
    /// ```
    #[must_use]
    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(
            at <= self.len(),
            "split_off out of bounds: at={at}, len={}",
            self.len()
        );

        let tail = self.data.split_off(at);
        Self { data: tail }
    }

    /// Split off bytes from beginning to `at`.
    ///
    /// Self becomes `[at, len)`, returns `[0, at)`.
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::new();
    /// buf.put_slice(b"hello world");
    ///
    /// let hello = buf.split_to(6);
    /// assert_eq!(&hello[..], b"hello ");
    /// assert_eq!(&buf[..], b"world");
    /// ```
    #[must_use]
    pub fn split_to(&mut self, at: usize) -> Self {
        assert!(
            at <= self.len(),
            "split_to out of bounds: at={at}, len={}",
            self.len()
        );

        let mut head = Vec::with_capacity(at);
        head.extend_from_slice(&self.data[..at]);

        // Remove the head from our data
        self.data.drain(..at);

        Self { data: head }
    }

    /// Truncate to `len` bytes.
    ///
    /// If `len` is greater than the current length, this has no effect.
    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Resize to `new_len`, filling with `value` if growing.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::new();
    /// buf.put_slice(b"hello");
    ///
    /// // Grow
    /// buf.resize(10, b'!');
    /// assert_eq!(&buf[..], b"hello!!!!!");
    ///
    /// // Shrink
    /// buf.resize(5, 0);
    /// assert_eq!(&buf[..], b"hello");
    /// ```
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data.resize(new_len, value);
    }

    /// Returns a slice of self for the given range.
    ///
    /// # Panics
    ///
    /// Panics if the range is out of bounds.
    #[must_use]
    pub fn slice(&self, range: impl RangeBounds<usize>) -> &[u8] {
        use std::ops::Bound;

        let start = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.checked_add(1).expect("range start overflow"),
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(&n) => n.checked_add(1).expect("range end overflow"),
            Bound::Excluded(&n) => n,
            Bound::Unbounded => self.len(),
        };

        &self.data[start..end]
    }

    /// Returns the remaining spare capacity as a mutable slice.
    #[must_use]
    pub fn spare_capacity_mut(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        self.data.spare_capacity_mut()
    }

    /// Resize the buffer to `len`, zero-filling any new bytes.
    ///
    /// When growing, new bytes are filled with `0`. When shrinking, excess
    /// bytes are dropped. This is equivalent to [`resize(len, 0)`](Self::resize).
    ///
    /// **Note:** Because new bytes are zeroed, data previously written via
    /// [`spare_capacity_mut()`](Self::spare_capacity_mut) will be overwritten.
    /// If you need the `write-then-set-len` pattern, use [`resize`](Self::resize)
    /// or write through [`put_slice`](Self::put_slice) instead.
    ///
    /// # Panics
    ///
    /// Panics if `len > capacity`.
    pub fn set_len(&mut self, len: usize) {
        assert!(
            len <= self.capacity(),
            "set_len out of bounds: len={len}, capacity={}",
            self.capacity()
        );
        self.data.resize(len, 0);
    }
}

impl Default for BytesMut {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for BytesMut {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl DerefMut for BytesMut {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl AsRef<[u8]> for BytesMut {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for BytesMut {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl From<Vec<u8>> for BytesMut {
    fn from(vec: Vec<u8>) -> Self {
        Self { data: vec }
    }
}

impl From<&[u8]> for BytesMut {
    fn from(slice: &[u8]) -> Self {
        Self {
            data: slice.to_vec(),
        }
    }
}

impl From<&str> for BytesMut {
    fn from(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }
}

impl From<String> for BytesMut {
    fn from(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }
}

impl std::fmt::Debug for BytesMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytesMut")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("data", &self.data.as_slice())
            .finish()
    }
}

impl PartialEq for BytesMut {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for BytesMut {}

impl PartialEq<[u8]> for BytesMut {
    fn eq(&self, other: &[u8]) -> bool {
        self.data.as_slice() == other
    }
}

impl PartialEq<BytesMut> for [u8] {
    fn eq(&self, other: &BytesMut) -> bool {
        self == other.data.as_slice()
    }
}

impl PartialEq<Vec<u8>> for BytesMut {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.data == other
    }
}

impl std::hash::Hash for BytesMut {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

// === BufMut trait implementation ===

impl BufMut for BytesMut {
    fn remaining_mut(&self) -> usize {
        usize::MAX - self.len()
    }

    fn chunk_mut(&mut self) -> &mut [u8] {
        // For BytesMut, we grow dynamically via put_slice
        // Return an empty slice since we handle growth in put_slice
        &mut []
    }

    fn advance_mut(&mut self, cnt: usize) {
        // For BytesMut, advance is handled implicitly in put_slice
        assert!(
            cnt == 0,
            "advance_mut is unsupported for BytesMut; use put_slice"
        );
    }

    // Override put_slice for efficient BytesMut implementation
    fn put_slice(&mut self, src: &[u8]) {
        self.data.extend_from_slice(src);
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
    fn test_bytes_mut_new() {
        init_test("test_bytes_mut_new");
        let b = BytesMut::new();
        let empty = b.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        let len = b.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("test_bytes_mut_new");
    }

    #[test]
    fn test_bytes_mut_with_capacity() {
        init_test("test_bytes_mut_with_capacity");
        let b = BytesMut::with_capacity(100);
        let empty = b.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        let cap_ok = b.capacity() >= 100;
        crate::assert_with_log!(cap_ok, "capacity >= 100", true, cap_ok);
        crate::test_complete!("test_bytes_mut_with_capacity");
    }

    #[test]
    fn test_bytes_mut_put_slice() {
        init_test("test_bytes_mut_put_slice");
        let mut b = BytesMut::new();
        b.put_slice(b"hello");
        b.put_slice(b" ");
        b.put_slice(b"world");

        let ok = &b[..] == b"hello world";
        crate::assert_with_log!(ok, "contents", b"hello world", &b[..]);
        crate::test_complete!("test_bytes_mut_put_slice");
    }

    #[test]
    fn test_bytes_mut_reserve_and_grow() {
        init_test("test_bytes_mut_reserve_and_grow");
        let mut b = BytesMut::new();

        // Small write
        b.put_slice(b"hello");
        let len = b.len();
        crate::assert_with_log!(len == 5, "len", 5, len);

        // Reserve more
        b.reserve(1000);
        let cap_ok = b.capacity() >= 1005;
        crate::assert_with_log!(cap_ok, "capacity >= 1005", true, cap_ok);

        // Data should be preserved
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "contents", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_reserve_and_grow");
    }

    #[test]
    fn test_bytes_mut_freeze() {
        init_test("test_bytes_mut_freeze");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");

        let frozen = b.freeze();
        let ok = &frozen[..] == b"hello world";
        crate::assert_with_log!(ok, "frozen", b"hello world", &frozen[..]);

        // Should be able to clone cheaply
        let clone = frozen.clone();
        drop(frozen);
        let ok = &clone[..] == b"hello world";
        crate::assert_with_log!(ok, "clone", b"hello world", &clone[..]);
        crate::test_complete!("test_bytes_mut_freeze");
    }

    #[test]
    fn test_bytes_mut_split_off() {
        init_test("test_bytes_mut_split_off");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");

        let world = b.split_off(6);

        let ok = &b[..] == b"hello ";
        crate::assert_with_log!(ok, "left", b"hello ", &b[..]);
        let ok = &world[..] == b"world";
        crate::assert_with_log!(ok, "right", b"world", &world[..]);
        crate::test_complete!("test_bytes_mut_split_off");
    }

    #[test]
    fn test_bytes_mut_split_to() {
        init_test("test_bytes_mut_split_to");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");

        let hello = b.split_to(6);

        let ok = &hello[..] == b"hello ";
        crate::assert_with_log!(ok, "left", b"hello ", &hello[..]);
        let ok = &b[..] == b"world";
        crate::assert_with_log!(ok, "right", b"world", &b[..]);
        crate::test_complete!("test_bytes_mut_split_to");
    }

    #[test]
    fn test_bytes_mut_resize() {
        init_test("test_bytes_mut_resize");
        let mut b = BytesMut::new();
        b.put_slice(b"hello");

        // Grow
        b.resize(10, b'!');
        let ok = &b[..] == b"hello!!!!!";
        crate::assert_with_log!(ok, "grown", b"hello!!!!!", &b[..]);

        // Shrink
        b.resize(5, 0);
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "shrunk", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_resize");
    }

    #[test]
    fn test_bytes_mut_truncate() {
        init_test("test_bytes_mut_truncate");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");
        b.truncate(5);
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "truncate", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_truncate");
    }

    #[test]
    fn test_bytes_mut_clear() {
        init_test("test_bytes_mut_clear");
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");
        b.clear();
        let empty = b.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        crate::test_complete!("test_bytes_mut_clear");
    }

    #[test]
    fn test_bytes_mut_from_vec() {
        init_test("test_bytes_mut_from_vec");
        let v = vec![1u8, 2, 3];
        let b: BytesMut = v.into();
        let ok = b[..] == [1, 2, 3];
        crate::assert_with_log!(ok, "from vec", &[1, 2, 3], &b[..]);
        crate::test_complete!("test_bytes_mut_from_vec");
    }

    #[test]
    fn test_bytes_mut_from_slice() {
        init_test("test_bytes_mut_from_slice");
        let b: BytesMut = b"hello".as_slice().into();
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "from slice", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_from_slice");
    }

    #[test]
    fn test_bytes_mut_from_string() {
        init_test("test_bytes_mut_from_string");
        let s = String::from("hello");
        let b: BytesMut = s.into();
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "from string", b"hello", &b[..]);
        crate::test_complete!("test_bytes_mut_from_string");
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_bytes_mut_split_off_panic() {
        init_test("test_bytes_mut_split_off_panic");
        let mut b = BytesMut::new();
        b.put_slice(b"hello");
        let _bad = b.split_off(100);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_bytes_mut_split_to_panic() {
        init_test("test_bytes_mut_split_to_panic");
        let mut b = BytesMut::new();
        b.put_slice(b"hello");
        let _bad = b.split_to(100);
    }

    // --- Audit tests (SapphireHill, 2026-02-15) ---

    #[test]
    fn set_len_zeros_new_bytes() {
        init_test("set_len_zeros_new_bytes");
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"abc");
        b.set_len(8);
        // Bytes beyond the original "abc" must be zero-filled.
        let ok = &b[..] == b"abc\0\0\0\0\0";
        crate::assert_with_log!(ok, "zero-filled", b"abc\0\0\0\0\0", &b[..]);
        crate::test_complete!("set_len_zeros_new_bytes");
    }

    #[test]
    fn set_len_overwrites_spare_capacity_writes() {
        init_test("set_len_overwrites_spare_capacity_writes");
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"abc");
        // Write 0xFF into spare capacity via the raw spare slice.
        let spare = b.spare_capacity_mut();
        spare[0].write(0xFF);
        spare[1].write(0xFF);
        // set_len uses resize(len, 0) which zeroes new positions.
        b.set_len(5);
        let ok = b[3] == 0 && b[4] == 0;
        crate::assert_with_log!(ok, "zeroed, not 0xFF", true, ok);
        crate::test_complete!("set_len_overwrites_spare_capacity_writes");
    }

    #[test]
    fn set_len_shrink_preserves_data() {
        init_test("set_len_shrink_preserves_data");
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"hello world");
        b.set_len(5);
        let ok = &b[..] == b"hello";
        crate::assert_with_log!(ok, "shrunk", b"hello", &b[..]);
        crate::test_complete!("set_len_shrink_preserves_data");
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn set_len_panics_beyond_capacity() {
        init_test("set_len_panics_beyond_capacity");
        let mut b = BytesMut::with_capacity(4);
        b.set_len(5);
    }

    #[test]
    fn chunk_mut_returns_empty_and_advance_mut_zero_is_ok() {
        init_test("chunk_mut_returns_empty_and_advance_mut_zero_is_ok");
        let mut b = BytesMut::with_capacity(16);
        let chunk = b.chunk_mut();
        let ok = chunk.is_empty();
        crate::assert_with_log!(ok, "chunk_mut empty", true, ok);
        // advance_mut(0) must not panic.
        b.advance_mut(0);
        crate::test_complete!("chunk_mut_returns_empty_and_advance_mut_zero_is_ok");
    }

    #[test]
    #[should_panic(expected = "unsupported")]
    fn advance_mut_nonzero_panics() {
        init_test("advance_mut_nonzero_panics");
        let mut b = BytesMut::with_capacity(16);
        b.advance_mut(1);
    }
}
