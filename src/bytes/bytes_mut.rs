//! Mutable buffer with efficient growth and owned splitting.

use super::Bytes;
use super::buf::BufMut;
use std::ops::{Deref, DerefMut, RangeBounds};

/// Mutable buffer that can be frozen into `Bytes`.
///
/// `BytesMut` provides a mutable buffer with efficient growth, owned splitting,
/// and the ability to freeze into an immutable `Bytes`.
///
/// # Implementation
///
/// This implementation uses `Vec<u8>` as the backing storage, ensuring
/// safety without unsafe code. The active bytes may start at an offset inside
/// the allocation, so repeated front splits can advance the active view without
/// repeatedly moving the remaining suffix. Returned split parts still own
/// distinct `Vec<u8>` storage, preserving mutable independence without shared
/// mutable backing.
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
#[derive(Clone, Default)]
pub struct BytesMut {
    /// The backing storage.
    data: Vec<u8>,
    /// Start offset of the active byte range in `data`.
    start: usize,
}

impl BytesMut {
    /// Create an empty `BytesMut`.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            start: 0,
        }
    }

    #[inline]
    fn active(&self) -> &[u8] {
        &self.data[self.start..]
    }

    #[inline]
    fn active_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.start..]
    }

    #[inline]
    fn active_capacity(&self) -> usize {
        self.data.capacity() - self.start
    }

    #[inline]
    fn compact_front(&mut self) {
        if self.start == 0 {
            return;
        }
        self.data.drain(..self.start);
        self.start = 0;
    }

    #[inline]
    fn compact_front_if_empty(&mut self) {
        if self.start == self.data.len() {
            self.data.clear();
            self.start = 0;
        }
    }

    #[inline]
    fn compact_front_for_additional(&mut self, additional: usize) {
        if self.start == 0 {
            return;
        }

        let len = self.len();
        if len == 0 {
            self.data.clear();
            self.start = 0;
            return;
        }

        let required = len
            .checked_add(additional)
            .expect("BytesMut required capacity overflow");
        if required > self.active_capacity() {
            self.compact_front();
        }
    }

    /// Returns the number of bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len() - self.start
    }

    /// Returns true if empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the capacity.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.active_capacity()
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
    #[inline]
    #[must_use]
    pub fn freeze(mut self) -> Bytes {
        self.compact_front();
        Bytes::from(self.data)
    }

    /// Consume `self` and return the underlying `Vec<u8>` WITHOUT copying.
    ///
    /// br-asupersync-i5w8lh: this is the zero-copy escape hatch for
    /// callers that have a `BytesMut` and need a `Vec<u8>` (e.g. the
    /// HTTP/1 codec building a `Request { body: Vec<u8> }`). The
    /// previous canonical idiom `body_bytes.to_vec()` allocates a fresh
    /// `Vec<u8>` and memcpy's the contents — pointless when we already
    /// own a uniquely-referenced `Vec<u8>` inside this `BytesMut`.
    /// `into_vec` simply moves the inner `data` field out of `self`,
    /// which is one move + zero allocations + zero memcpy.
    ///
    /// Note: in the current `Vec<u8>`-backed `BytesMut` representation,
    /// every `BytesMut` exclusively owns its underlying `Vec<u8>` (no
    /// shared backing — see `split_to` doc), so this conversion is
    /// always safe and zero-cost. If a future refactor introduces
    /// shared backing storage for `BytesMut` (mirroring `Bytes`), this
    /// method may need to clone in the shared case to preserve the
    /// `Vec<u8>` exclusive-ownership contract — but the API contract
    /// remains "consume self, return owned Vec<u8>".
    #[inline]
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        self.compact_front();
        self.data
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
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.compact_front_for_additional(additional);
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
    #[inline]
    pub fn put_slice(&mut self, src: &[u8]) {
        self.compact_front_for_additional(src.len());
        self.data.extend_from_slice(src);
    }

    /// Extend from slice (alias for `put_slice`).
    #[inline]
    pub fn extend_from_slice(&mut self, src: &[u8]) {
        self.put_slice(src);
    }

    /// Put a single byte.
    #[inline]
    pub fn put_u8(&mut self, n: u8) {
        self.compact_front_for_additional(1);
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
    #[inline]
    #[must_use]
    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(
            at <= self.len(),
            "split_off out of bounds: at={at}, len={}",
            self.len()
        );

        let split_at = self
            .start
            .checked_add(at)
            .expect("BytesMut::split_off offset overflow");
        let tail = self.data.split_off(split_at);
        self.compact_front_if_empty();
        Self {
            data: tail,
            start: 0,
        }
    }

    /// Split off bytes from beginning to `at`.
    ///
    /// Self becomes `[at, len)`, returns `[0, at)`.
    ///
    /// This is O(n) in the returned prefix length: the prefix is copied so the
    /// returned `BytesMut` remains mutably independent, while `self` advances
    /// its active start offset instead of moving the remaining suffix.
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
    #[inline]
    #[must_use]
    pub fn split_to(&mut self, at: usize) -> Self {
        assert!(
            at <= self.len(),
            "split_to out of bounds: at={at}, len={}",
            self.len()
        );

        let mut head = Vec::with_capacity(at);
        head.extend_from_slice(&self.active()[..at]);

        self.start = self
            .start
            .checked_add(at)
            .expect("BytesMut::split_to offset overflow");
        self.compact_front_if_empty();

        Self {
            data: head,
            start: 0,
        }
    }

    /// Truncate to `len` bytes.
    ///
    /// If `len` is greater than the current length, this has no effect.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        if len == 0 {
            self.clear();
        } else if len < self.len() {
            let new_len = self
                .start
                .checked_add(len)
                .expect("BytesMut::truncate offset overflow");
            self.data.truncate(new_len);
        }
    }

    /// Clear the buffer.
    #[inline]
    pub fn clear(&mut self) {
        self.data.clear();
        self.start = 0;
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
    #[inline]
    pub fn resize(&mut self, new_len: usize, value: u8) {
        if new_len <= self.len() {
            self.truncate(new_len);
            return;
        }

        let additional = new_len - self.len();
        self.compact_front_for_additional(additional);
        let new_data_len = self
            .start
            .checked_add(new_len)
            .expect("BytesMut::resize offset overflow");
        self.data.resize(new_data_len, value);
    }

    /// Returns a slice of self for the given range.
    ///
    /// # Panics
    ///
    /// Panics if the range is out of bounds.
    #[must_use]
    #[inline]
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

        let start = self
            .start
            .checked_add(start)
            .expect("BytesMut::slice start offset overflow");
        let end = self
            .start
            .checked_add(end)
            .expect("BytesMut::slice end offset overflow");

        &self.data[start..end]
    }

    /// Returns the remaining spare capacity as a mutable slice.
    #[must_use]
    #[inline]
    pub fn spare_capacity_mut(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        self.compact_front_if_empty();
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
    #[inline]
    pub fn set_len(&mut self, len: usize) {
        assert!(
            len <= self.capacity(),
            "set_len out of bounds: len={len}, capacity={}",
            self.capacity()
        );
        self.resize(len, 0);
    }
}

impl Deref for BytesMut {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.active()
    }
}

impl DerefMut for BytesMut {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.active_mut()
    }
}

impl AsRef<[u8]> for BytesMut {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.active()
    }
}

impl AsMut<[u8]> for BytesMut {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.active_mut()
    }
}

impl From<Vec<u8>> for BytesMut {
    #[inline]
    fn from(vec: Vec<u8>) -> Self {
        Self {
            data: vec,
            start: 0,
        }
    }
}

impl From<&[u8]> for BytesMut {
    #[inline]
    fn from(slice: &[u8]) -> Self {
        Self {
            data: slice.to_vec(),
            start: 0,
        }
    }
}

impl From<&str> for BytesMut {
    #[inline]
    fn from(s: &str) -> Self {
        Self::from(s.as_bytes())
    }
}

impl From<String> for BytesMut {
    #[inline]
    fn from(s: String) -> Self {
        Self::from(s.into_bytes())
    }
}

impl std::fmt::Debug for BytesMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytesMut")
            .field("len", &self.len())
            .field("start", &self.start)
            .field("capacity", &self.capacity())
            .field("data", &self.active())
            .finish()
    }
}

impl PartialEq for BytesMut {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.active() == other.active()
    }
}

impl Eq for BytesMut {}

impl PartialEq<[u8]> for BytesMut {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.active() == other
    }
}

impl PartialEq<BytesMut> for [u8] {
    #[inline]
    fn eq(&self, other: &BytesMut) -> bool {
        self == other.active()
    }
}

impl PartialEq<Vec<u8>> for BytesMut {
    #[inline]
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.active() == other.as_slice()
    }
}

impl std::hash::Hash for BytesMut {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.active().hash(state);
    }
}

// === BufMut trait implementation ===

impl BufMut for BytesMut {
    #[inline]
    fn remaining_mut(&self) -> usize {
        usize::MAX - self.len()
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        // For BytesMut, we grow dynamically via put_slice
        // Return an empty slice since we handle growth in put_slice
        &mut []
    }

    #[inline]
    fn advance_mut(&mut self, cnt: usize) {
        // For BytesMut, advance is handled implicitly in put_slice
        assert!(
            cnt == 0,
            "advance_mut is unsupported for BytesMut; use put_slice"
        );
    }

    // Override put_slice for efficient BytesMut implementation
    #[inline]
    fn put_slice(&mut self, src: &[u8]) {
        self.compact_front_for_additional(src.len());
        self.data.extend_from_slice(src);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use proptest::prelude::*;

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

    /// br-asupersync-i5w8lh: into_vec moves out the underlying Vec<u8>
    /// without copying. Verify the returned Vec contains exactly the
    /// bytes that were in the BytesMut, including for non-trivial
    /// payloads (binary, embedded nulls, large) that would catch any
    /// wrong-slice or truncation regression.
    #[test]
    fn into_vec_returns_underlying_bytes_unchanged() {
        let mut b = BytesMut::new();
        b.put_slice(b"hello world");
        let v = b.into_vec();
        assert_eq!(v.as_slice(), b"hello world");
        assert_eq!(v.len(), 11);

        // Non-trivial payload: binary data with embedded nulls.
        let mut b = BytesMut::new();
        b.put_slice(&[0x00, 0xFF, 0x42, 0x00, 0x99, 0x00]);
        let v = b.into_vec();
        assert_eq!(v.as_slice(), &[0x00, 0xFF, 0x42, 0x00, 0x99, 0x00]);

        // Empty BytesMut -> empty Vec, no allocation surprises.
        let b = BytesMut::new();
        let v = b.into_vec();
        assert!(v.is_empty());

        // Large payload: 1 MiB of patterned bytes — verify the move
        // preserves every byte (catches off-by-one slice bugs).
        let mut b = BytesMut::with_capacity(1024 * 1024);
        for i in 0..(1024 * 1024) {
            b.put_u8((i & 0xFF) as u8);
        }
        let v = b.into_vec();
        assert_eq!(v.len(), 1024 * 1024);
        for (i, byte) in v.iter().enumerate().take(1024 * 1024) {
            assert_eq!(*byte, (i & 0xFF) as u8, "mismatch at byte {i}");
        }
    }

    /// br-asupersync-i5w8lh: into_vec preserves bytes even after
    /// split_to. The HTTP/1 codec hot path exercises split_to followed
    /// by into_vec on the resulting BytesMut; this test mirrors that
    /// flow directly to lock in the contract.
    #[test]
    fn into_vec_after_split_to_preserves_payload_slice() {
        let mut buf = BytesMut::new();
        buf.put_slice(b"head\x00\x01\x02tail");
        // Split off the first 7 bytes (b"head\x00\x01\x02").
        let head = buf.split_to(7);
        let v = head.into_vec();
        assert_eq!(v.as_slice(), b"head\x00\x01\x02");
        // The remaining buf should hold the suffix unchanged.
        assert_eq!(&buf[..], b"tail");
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
    fn bytes_mut_split_to_advances_suffix_without_memmove() {
        init_test("bytes_mut_split_to_advances_suffix_without_memmove");
        let mut b = BytesMut::with_capacity(64);
        b.put_slice(b"abcdefghijklmnop");

        let expected_suffix_ptr = b[4..].as_ptr();
        let head = b.split_to(4);

        crate::assert_with_log!(&head[..] == b"abcd", "head", b"abcd", &head[..]);
        crate::assert_with_log!(&b[..] == b"efghijklmnop", "suffix", b"efghijklmnop", &b[..]);
        let suffix_ptr_preserved = std::ptr::eq(b.as_ptr(), expected_suffix_ptr);
        crate::assert_with_log!(
            suffix_ptr_preserved,
            "suffix pointer preserved",
            true,
            suffix_ptr_preserved
        );
        crate::test_complete!("bytes_mut_split_to_advances_suffix_without_memmove");
    }

    #[test]
    fn bytes_mut_split_to_all_reclaims_front_capacity_for_reuse() {
        init_test("bytes_mut_split_to_all_reclaims_front_capacity_for_reuse");
        let mut b = BytesMut::with_capacity(16);
        b.put_slice(b"abcd");
        let original_capacity = b.capacity();

        let head = b.split_to(4);

        crate::assert_with_log!(&head[..] == b"abcd", "head", b"abcd", &head[..]);
        crate::assert_with_log!(b.is_empty(), "buffer empty", true, b.is_empty());
        let capacity_reused = b.capacity() >= original_capacity;
        crate::assert_with_log!(capacity_reused, "capacity reused", true, capacity_reused);

        b.put_slice(b"xy");
        crate::assert_with_log!(&b[..] == b"xy", "rewritten", b"xy", &b[..]);
        let capacity_still_reused = b.capacity() >= original_capacity;
        crate::assert_with_log!(
            capacity_still_reused,
            "capacity still reused",
            true,
            capacity_still_reused
        );
        crate::test_complete!("bytes_mut_split_to_all_reclaims_front_capacity_for_reuse");
    }

    #[test]
    fn bytes_mut_freeze_and_into_vec_discard_consumed_prefix() {
        init_test("bytes_mut_freeze_and_into_vec_discard_consumed_prefix");
        let mut frozen_tail = BytesMut::from(&b"headerbody"[..]);
        let header = frozen_tail.split_to(6);
        crate::assert_with_log!(&header[..] == b"header", "header", b"header", &header[..]);
        let frozen = frozen_tail.freeze();
        crate::assert_with_log!(&frozen[..] == b"body", "frozen tail", b"body", &frozen[..]);

        let mut vec_tail = BytesMut::from(&b"prefixpayload"[..]);
        let prefix = vec_tail.split_to(6);
        crate::assert_with_log!(&prefix[..] == b"prefix", "prefix", b"prefix", &prefix[..]);
        let vec = vec_tail.into_vec();
        crate::assert_with_log!(
            vec.as_slice() == b"payload",
            "vec tail",
            b"payload",
            vec.as_slice()
        );
        crate::test_complete!("bytes_mut_freeze_and_into_vec_discard_consumed_prefix");
    }

    #[test]
    fn bytes_mut_split_parts_are_mutably_independent() {
        init_test("bytes_mut_split_parts_are_mutably_independent");

        let mut middle = BytesMut::from(&b"alpha|beta|gamma"[..]);
        let mut prefix = middle.split_to(6);
        let mut suffix = middle.split_off(5);

        prefix[0] = b'A';
        middle[0] = b'B';
        suffix[0] = b'G';

        crate::assert_with_log!(
            &prefix[..] == b"Alpha|",
            "prefix isolated",
            b"Alpha|",
            &prefix[..]
        );
        crate::assert_with_log!(
            &middle[..] == b"Beta|",
            "middle isolated",
            b"Beta|",
            &middle[..]
        );
        crate::assert_with_log!(
            &suffix[..] == b"Gamma",
            "suffix isolated",
            b"Gamma",
            &suffix[..]
        );
        crate::test_complete!("bytes_mut_split_parts_are_mutably_independent");
    }

    proptest! {
        #[test]
        fn bytes_mut_metamorphic_slice_matches_split_extraction(
            data in prop::collection::vec(any::<u8>(), 0..128),
            start in 0usize..128,
            end in 0usize..128,
        ) {
            let bytes = BytesMut::from(data.as_slice());
            let len = bytes.len();
            let start = start.min(len);
            let end = end.min(len);
            let (start, end) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };

            let direct = bytes.slice(start..end).to_vec();

            let mut split_view = bytes.clone();
            let _prefix = split_view.split_to(start);
            let middle = split_view.split_to(end - start);

            prop_assert_eq!(
                &middle[..],
                direct.as_slice(),
                "direct slicing and split-based extraction must expose identical contiguous bytes",
            );
            prop_assert_eq!(
                &middle[..],
                &data[start..end],
                "both extraction paths must match the original contiguous source slice",
            );
        }

        #[test]
        fn bytes_mut_metamorphic_split_recombine_preserves_payload(
            data in prop::collection::vec(any::<u8>(), 0..192),
            first_split in 0usize..192,
            middle_len in 0usize..192,
        ) {
            let original = BytesMut::from(data.as_slice());
            let len = original.len();
            let first_split = first_split.min(len);
            let middle_len = middle_len.min(len - first_split);

            let mut middle = original.clone();
            let prefix = middle.split_to(first_split);
            let suffix = middle.split_off(middle_len);

            prop_assert_eq!(prefix.len(), first_split);
            prop_assert_eq!(middle.len(), middle_len);
            prop_assert_eq!(suffix.len(), len - first_split - middle_len);

            prop_assert_eq!(&prefix[..], &data[..first_split]);
            prop_assert_eq!(
                &middle[..],
                &data[first_split..first_split + middle_len],
            );
            prop_assert_eq!(&suffix[..], &data[first_split + middle_len..]);

            let prefix_frozen = prefix.clone().freeze();
            let middle_frozen = middle.clone().freeze();
            let suffix_frozen = suffix.clone().freeze();

            let mut recombined = BytesMut::with_capacity(len);
            recombined.put_slice(&prefix_frozen);
            recombined.put_slice(&middle_frozen);
            recombined.put_slice(&suffix_frozen);

            prop_assert_eq!(
                &recombined[..],
                data.as_slice(),
                "split_to/split_off parts must recombine into the original byte order",
            );
            prop_assert_eq!(
                &recombined.freeze()[..],
                data.as_slice(),
                "freezing recombined split parts must preserve the original payload",
            );
        }
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
