//! Chain adapter for chaining two Buf implementations.

use super::Buf;

/// A `Buf` that chains two buffers together.
///
/// Created by [`Buf::chain()`].
///
/// # Examples
///
/// ```
/// use asupersync::bytes::Buf;
///
/// let a: &[u8] = &[1, 2, 3];
/// let b: &[u8] = &[4, 5, 6];
///
/// let mut chain = a.chain(b);
/// assert_eq!(chain.remaining(), 6);
///
/// let mut dst = [0u8; 6];
/// chain.copy_to_slice(&mut dst);
/// assert_eq!(dst, [1, 2, 3, 4, 5, 6]);
/// ```
#[derive(Debug)]
pub struct Chain<T, U> {
    a: T,
    b: U,
}

impl<T, U> Chain<T, U> {
    /// Create a new `Chain` from two buffers.
    #[inline]
    pub(crate) fn new(a: T, b: U) -> Self {
        Self { a, b }
    }

    /// Gets a reference to the first buffer.
    #[inline]
    #[must_use]
    pub fn first_ref(&self) -> &T {
        &self.a
    }

    /// Gets a mutable reference to the first buffer.
    #[inline]
    pub fn first_mut(&mut self) -> &mut T {
        &mut self.a
    }

    /// Gets a reference to the second buffer.
    #[inline]
    #[must_use]
    pub fn last_ref(&self) -> &U {
        &self.b
    }

    /// Gets a mutable reference to the second buffer.
    #[inline]
    pub fn last_mut(&mut self) -> &mut U {
        &mut self.b
    }

    /// Consumes this `Chain`, returning the underlying buffers.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> (T, U) {
        (self.a, self.b)
    }
}

impl<T: Buf, U: Buf> Buf for Chain<T, U> {
    #[inline]
    fn remaining(&self) -> usize {
        self.a.remaining().saturating_add(self.b.remaining())
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        if self.a.has_remaining() {
            self.a.chunk()
        } else {
            self.b.chunk()
        }
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        let a_rem = self.a.remaining();

        if cnt <= a_rem {
            self.a.advance(cnt);
        } else {
            // Drain all of a
            if a_rem > 0 {
                self.a.advance(a_rem);
            }
            cnt -= a_rem;

            // Advance b
            self.b.advance(cnt);
        }
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> crate::bytes::Bytes {
        let a_rem = self.a.remaining();
        if a_rem >= len {
            self.a.copy_to_bytes(len)
        } else if a_rem == 0 {
            self.b.copy_to_bytes(len)
        } else {
            assert!(
                len <= self.remaining(),
                "cannot copy {} bytes with {} remaining",
                len,
                self.remaining()
            );
            // Copy straight from each half's chunks: copy_to_bytes on a half
            // that is not shared storage would allocate a temporary first.
            let mut ret = Vec::with_capacity(len);
            while ret.len() < len {
                let chunk = self.chunk();
                let n = chunk.len().min(len - ret.len());
                assert!(n > 0, "a Buf with bytes remaining returned an empty chunk");
                ret.extend_from_slice(&chunk[..n]);
                self.advance(n);
            }
            crate::bytes::Bytes::from(ret)
        }
    }
}

#[cfg(test)]
#[path = "chain_inline_tests.rs"]
mod tests;
