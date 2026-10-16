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
#[derive(Default)]
pub struct BytesMut {
    /// The backing storage.
    data: Vec<u8>,
    /// Start offset of the active byte range in `data`.
    start: usize,
}

impl Clone for BytesMut {
    /// Clone the logical active bytes into an independent, normalized buffer.
    ///
    /// Consumed prefix bytes and spare capacity are representation history, not
    /// part of the value, so the clone always starts at offset zero.
    #[inline]
    fn clone(&self) -> Self {
        Self {
            data: self.active().to_vec(),
            start: 0,
        }
    }
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
            if self.start >= len {
                // The consumed prefix is at least as large as the live bytes,
                // so moving them is paid for by the room it frees.
                self.compact_front();
            } else {
                // Moving the live bytes would free only `start` bytes: a loop
                // of small advances and appends on a full buffer then moved the
                // whole buffer for every append. Reallocate with headroom
                // instead, one copy per doubling, as the `bytes` crate does.
                let mut grown =
                    Vec::with_capacity(required.max(self.data.capacity().saturating_mul(2)));
                grown.extend_from_slice(self.active());
                self.data = grown;
                self.start = 0;
            }
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
    /// As with [`into_vec`](Self::into_vec), if bytes were consumed from the
    /// front, the remaining bytes are first shifted to the start of the
    /// buffer (an in-place copy of the remaining length).
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

    /// Consume `self` and return the underlying `Vec<u8>` without allocating.
    ///
    /// br-asupersync-i5w8lh: this is the escape hatch for callers that
    /// have a `BytesMut` and need a `Vec<u8>` (e.g. the HTTP/1 codec
    /// building a `Request { body: Vec<u8> }`). The previous canonical
    /// idiom `body_bytes.to_vec()` allocates a fresh `Vec<u8>` and copies
    /// the contents. `into_vec` moves the inner buffer out instead. If
    /// bytes were consumed from the front (`advance`, `split_to`), the
    /// remaining bytes are first shifted to the start of that buffer: an
    /// in-place copy of the remaining length, still with no allocation
    /// (br-asupersync-htq0xp). Otherwise it is a plain move.
    ///
    /// Note: in the current `Vec<u8>`-backed `BytesMut` representation,
    /// every `BytesMut` exclusively owns its underlying `Vec<u8>` (no
    /// shared backing — see `split_to` doc), so this conversion never
    /// allocates. If a future refactor introduces
    /// shared backing storage for `BytesMut` (mirroring `Bytes`), this
    /// method may need to clone in the shared case to preserve the
    /// `Vec<u8>` exclusive-ownership contract — but the API contract
    /// remains "consume self, return owned `Vec<u8>`".
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
    /// This is O(n) in the tail length: the tail is split off from the
    /// underlying `Vec<u8>` to produce an independent `BytesMut` (unlike
    /// the `bytes` crate's O(1) shared-backing slice).
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

    /// Discards the first `cnt` bytes, advancing past them without copying.
    ///
    /// This is the discard-only counterpart to [`split_to`](Self::split_to):
    /// it applies the *identical* mutation to `self` (bump the front offset,
    /// reclaim the backing `Vec` once fully drained) but does **not** allocate
    /// a head buffer or memcpy the consumed prefix. Use it when a caller only
    /// needs to drop already-consumed bytes — e.g. a codec flush loop that has
    /// written `cnt` bytes to the transport and would otherwise pay an
    /// allocation + memcpy per write pass just to throw the copy away.
    ///
    /// # Panics
    ///
    /// Panics if `cnt > self.len()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::BytesMut;
    ///
    /// let mut buf = BytesMut::from(&b"hello world"[..]);
    /// buf.advance(6);
    /// assert_eq!(&buf[..], b"world");
    /// ```
    #[inline]
    pub fn advance(&mut self, cnt: usize) {
        assert!(
            cnt <= self.len(),
            "advance out of bounds: cnt={cnt}, len={}",
            self.len()
        );

        self.start = self
            .start
            .checked_add(cnt)
            .expect("BytesMut::advance offset overflow");
        self.compact_front_if_empty();
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
    fn direct_remaining_mut(&self) -> usize {
        // `chunk_mut` cannot expose uninitialized spare capacity through a safe
        // `&mut [u8]`. Logical appends remain available through `put_slice`.
        0
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        // For BytesMut, we grow dynamically via the put_slice override; there is
        // no initialized direct writable window to expose.
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
#[path = "bytes_mut_inline_tests.rs"]
mod tests;
