//! Immutable, reference-counted byte slice.

use super::buf::Buf;
use std::ops::{Deref, RangeBounds};
use std::sync::Arc;

/// Immutable byte slice with cheap cloning.
///
/// Cloning a `Bytes` is O(1) - it just increments a reference count.
/// Slicing is also O(1) - no data is copied, just the view is adjusted.
///
/// # Implementation
///
/// This implementation uses `Arc<Vec<u8>>` for shared ownership rather than
/// raw pointers, ensuring memory safety without unsafe code.
///
/// # Examples
///
/// ```
/// use asupersync::bytes::Bytes;
///
/// // Create from static data (no allocation)
/// let b = Bytes::from_static(b"hello world");
/// assert_eq!(&b[..], b"hello world");
///
/// // Clone is cheap (reference counting)
/// let b2 = b.clone();
/// assert_eq!(&b2[..], b"hello world");
///
/// // Slicing is O(1)
/// let hello = b.slice(0..5);
/// assert_eq!(&hello[..], b"hello");
/// ```
#[derive(Clone, Default)]
pub struct Bytes {
    /// The backing storage.
    data: BytesInner,
    /// Start offset within the backing storage.
    start: usize,
    /// Length of this view.
    len: usize,
}

#[derive(Clone, Default)]
enum BytesInner {
    /// Static data (no allocation, 'static lifetime).
    Static(&'static [u8]),
    /// Heap-allocated, reference-counted data.
    Shared(Arc<Vec<u8>>),
    /// Empty bytes (no allocation).
    #[default]
    Empty,
}

impl Bytes {
    /// Create an empty `Bytes`.
    ///
    /// No allocation occurs.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: BytesInner::Empty,
            start: 0,
            len: 0,
        }
    }

    /// Create `Bytes` from a static byte slice.
    ///
    /// No allocation occurs - the bytes point directly to static memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::Bytes;
    ///
    /// let b = Bytes::from_static(b"hello");
    /// assert_eq!(&b[..], b"hello");
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_static(bytes: &'static [u8]) -> Self {
        Self {
            data: BytesInner::Static(bytes),
            start: 0,
            len: bytes.len(),
        }
    }

    /// Copy data from a slice into a new `Bytes`.
    ///
    /// This allocates and copies the data.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::Bytes;
    ///
    /// let data = vec![1, 2, 3, 4, 5];
    /// let b = Bytes::copy_from_slice(&data);
    /// assert_eq!(&b[..], &[1, 2, 3, 4, 5]);
    /// ```
    #[inline]
    #[must_use]
    pub fn copy_from_slice(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::new();
        }
        let vec = data.to_vec();
        let len = vec.len();
        Self {
            data: BytesInner::Shared(Arc::new(vec)),
            start: 0,
            len,
        }
    }

    /// Returns the number of bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Capacity retained by this view, including an otherwise hidden backing
    /// allocation when the view is a slice. Static bytes are charged by view
    /// length so retention budgets also bound their logical payload volume.
    #[cfg(all(feature = "http3", feature = "tls", not(target_arch = "wasm32")))]
    pub(crate) fn retained_capacity(&self) -> usize {
        match &self.data {
            BytesInner::Shared(data) => data.capacity(),
            BytesInner::Static(_) => self.len,
            BytesInner::Empty => 0,
        }
    }

    /// Returns true if empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a slice of self for the given range.
    ///
    /// # Panics
    ///
    /// Panics if the range is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::Bytes;
    ///
    /// let b = Bytes::from_static(b"hello world");
    /// let hello = b.slice(0..5);
    /// assert_eq!(&hello[..], b"hello");
    /// ```
    #[inline]
    #[must_use]
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Self {
        use std::ops::Bound;

        let start = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.checked_add(1).expect("range start overflow"),
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(&n) => n.checked_add(1).expect("range end overflow"),
            Bound::Excluded(&n) => n,
            Bound::Unbounded => self.len,
        };

        assert!(
            start <= end && end <= self.len,
            "slice bounds out of range: start={start}, end={end}, len={}",
            self.len
        );

        // br-asupersync-zfhz06: under a high-volume zero-copy pipeline,
        // repeated `slice()`/`split_to()` calls can advance `self.start`
        // close to `usize::MAX`. The bounds check above only validates
        // `end <= self.len`, not `self.start + start`. Use `checked_add`
        // and panic on overflow rather than silently wrap and read from
        // the wrong offset of the shared underlying buffer.
        Self {
            data: self.data.clone(),
            start: self
                .start
                .checked_add(start)
                .expect("Bytes::slice offset overflow"),
            len: end - start,
        }
    }

    /// Split off the bytes from `at` to the end.
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
    /// use asupersync::bytes::Bytes;
    ///
    /// let mut b = Bytes::from_static(b"hello world");
    /// let world = b.split_off(6);
    /// assert_eq!(&b[..], b"hello ");
    /// assert_eq!(&world[..], b"world");
    /// ```
    #[inline]
    #[must_use]
    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(
            at <= self.len,
            "split_off out of bounds: at={at}, len={}",
            self.len
        );

        // br-asupersync-zfhz06: see slice() for the overflow rationale.
        let other = Self {
            data: self.data.clone(),
            start: self
                .start
                .checked_add(at)
                .expect("Bytes::split_off offset overflow"),
            len: self.len - at,
        };

        self.len = at;
        other
    }

    /// Split off bytes from the beginning.
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
    /// use asupersync::bytes::Bytes;
    ///
    /// let mut b = Bytes::from_static(b"hello world");
    /// let hello = b.split_to(6);
    /// assert_eq!(&hello[..], b"hello ");
    /// assert_eq!(&b[..], b"world");
    /// ```
    #[inline]
    #[must_use]
    pub fn split_to(&mut self, at: usize) -> Self {
        assert!(
            at <= self.len,
            "split_to out of bounds: at={at}, len={}",
            self.len
        );

        let other = Self {
            data: self.data.clone(),
            start: self.start,
            len: at,
        };

        // br-asupersync-zfhz06: see slice() for the overflow rationale.
        // Repeated split_to() advances `self.start`; after enough small
        // advances on a 32-bit target the unchecked `+=` would wrap.
        self.start = self
            .start
            .checked_add(at)
            .expect("Bytes::split_to offset overflow");
        self.len -= at;
        other
    }

    /// Truncate the buffer to `len` bytes.
    ///
    /// If `len` is greater than the current length, this has no effect.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    /// Clear the buffer, making it empty.
    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Get the underlying byte slice.
    ///
    /// br-asupersync-zfhz06: `self.start + self.len` is computed via
    /// `checked_add` to fail loudly rather than read from the wrong
    /// offset of the shared underlying buffer if internal accounting
    /// somehow drifted past `usize::MAX`. The constructor and every
    /// mutator (`slice`, `split_to`, `split_off`) now also use
    /// `checked_add`, so this is belt-and-braces — the invariant
    /// is enforced at every point where it can be broken.
    #[inline]
    fn as_slice(&self) -> &[u8] {
        let end = self
            .start
            .checked_add(self.len)
            .expect("Bytes::as_slice start + len overflow");
        match &self.data {
            BytesInner::Empty => &[],
            BytesInner::Static(s) => &s[self.start..end],
            BytesInner::Shared(arc) => &arc[self.start..end],
        }
    }
}

impl Deref for Bytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Bytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for Bytes {
    #[inline]
    fn from(vec: Vec<u8>) -> Self {
        if vec.is_empty() {
            return Self::new();
        }
        let len = vec.len();
        Self {
            data: BytesInner::Shared(Arc::new(vec)),
            start: 0,
            len,
        }
    }
}

impl From<&'static [u8]> for Bytes {
    #[inline]
    fn from(slice: &'static [u8]) -> Self {
        Self::from_static(slice)
    }
}

impl From<&'static str> for Bytes {
    #[inline]
    fn from(s: &'static str) -> Self {
        Self::from_static(s.as_bytes())
    }
}

impl From<String> for Bytes {
    #[inline]
    fn from(s: String) -> Self {
        Self::from(s.into_bytes())
    }
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bytes")
            .field("len", &self.len)
            .field("start", &self.start)
            .field("data", &self.as_slice())
            .finish()
    }
}

impl PartialEq for Bytes {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Bytes {}

impl PartialEq<[u8]> for Bytes {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<Bytes> for [u8] {
    #[inline]
    fn eq(&self, other: &Bytes) -> bool {
        self == other.as_slice()
    }
}

impl PartialEq<Vec<u8>> for Bytes {
    #[inline]
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl std::hash::Hash for Bytes {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

// === Buf trait implementation ===

/// A cursor for reading from Bytes.
///
/// This wrapper tracks the read position, allowing Bytes to implement Buf.
#[derive(Clone, Debug)]
pub struct BytesCursor {
    inner: Bytes,
    pos: usize,
}

impl BytesCursor {
    /// Create a new cursor at position 0.
    #[inline]
    #[must_use]
    pub fn new(bytes: Bytes) -> Self {
        Self {
            inner: bytes,
            pos: 0,
        }
    }

    /// Get a reference to the underlying Bytes.
    #[inline]
    #[must_use]
    pub fn get_ref(&self) -> &Bytes {
        &self.inner
    }

    /// Consume the cursor, returning the underlying Bytes.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> Bytes {
        self.inner
    }

    /// Get the current position.
    #[inline]
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Set the position.
    #[inline]
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }
}

impl Buf for BytesCursor {
    #[inline]
    fn remaining(&self) -> usize {
        self.inner.len().saturating_sub(self.pos)
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        let slice = self.inner.as_slice();
        if self.pos >= slice.len() {
            &[]
        } else {
            &slice[self.pos..]
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(
            cnt <= self.remaining(),
            "advance out of bounds: cnt={cnt}, remaining={}",
            self.remaining()
        );
        self.pos += cnt;
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(
            len <= self.remaining(),
            "buffer underflow: need {len} bytes, have {}",
            self.remaining()
        );
        if len == 0 {
            return Bytes::new();
        }
        let out = self.inner.slice(self.pos..self.pos + len);
        self.pos += len;
        out
    }
}

impl Bytes {
    /// Create a cursor for reading from this Bytes.
    ///
    /// The cursor implements `Buf` and tracks the read position.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::bytes::{Bytes, Buf};
    ///
    /// let b = Bytes::from_static(b"\x00\x01\x02\x03");
    /// let mut cursor = b.reader();
    /// assert_eq!(cursor.get_u8(), 0);
    /// assert_eq!(cursor.get_u8(), 1);
    /// assert_eq!(cursor.remaining(), 2);
    /// ```
    #[inline]
    #[must_use]
    pub fn reader(self) -> BytesCursor {
        BytesCursor::new(self)
    }
}

#[cfg(test)]
#[path = "bytes_inline_tests.rs"]
mod tests;
