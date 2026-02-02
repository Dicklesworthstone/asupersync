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
    pub(crate) fn new(a: T, b: U) -> Self {
        Self { a, b }
    }

    /// Gets a reference to the first buffer.
    #[must_use]
    pub fn first_ref(&self) -> &T {
        &self.a
    }

    /// Gets a mutable reference to the first buffer.
    pub fn first_mut(&mut self) -> &mut T {
        &mut self.a
    }

    /// Gets a reference to the second buffer.
    #[must_use]
    pub fn last_ref(&self) -> &U {
        &self.b
    }

    /// Gets a mutable reference to the second buffer.
    pub fn last_mut(&mut self) -> &mut U {
        &mut self.b
    }

    /// Consumes this `Chain`, returning the underlying buffers.
    #[must_use]
    pub fn into_inner(self) -> (T, U) {
        (self.a, self.b)
    }
}

impl<T: Buf, U: Buf> Buf for Chain<T, U> {
    fn remaining(&self) -> usize {
        self.a.remaining().saturating_add(self.b.remaining())
    }

    fn chunk(&self) -> &[u8] {
        if self.a.has_remaining() {
            self.a.chunk()
        } else {
            self.b.chunk()
        }
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_chain_remaining() {
        init_test("test_chain_remaining");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let chain = Chain::new(a, b);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 6, "remaining", 6, remaining);
        crate::test_complete!("test_chain_remaining");
    }

    #[test]
    fn test_chain_chunk() {
        init_test("test_chain_chunk");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let chain = Chain::new(a, b);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [1, 2, 3], "chunk", &[1, 2, 3], chunk);
        crate::test_complete!("test_chain_chunk");
    }

    #[test]
    fn test_chain_advance() {
        init_test("test_chain_advance");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let mut chain = Chain::new(a, b);

        chain.advance(2);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 4, "remaining", 4, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [3], "chunk", &[3], chunk);

        chain.advance(1);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 3, "remaining", 3, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [4, 5, 6], "chunk", &[4, 5, 6], chunk);

        chain.advance(2);
        let remaining = chain.remaining();
        crate::assert_with_log!(remaining == 1, "remaining", 1, remaining);
        let chunk = chain.chunk();
        crate::assert_with_log!(chunk == [6], "chunk", &[6], chunk);
        crate::test_complete!("test_chain_advance");
    }

    #[test]
    fn test_chain_copy_to_slice() {
        init_test("test_chain_copy_to_slice");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let mut chain = Chain::new(a, b);

        let mut dst = [0u8; 6];
        chain.copy_to_slice(&mut dst);
        let ok = dst == [1, 2, 3, 4, 5, 6];
        crate::assert_with_log!(ok, "dst", [1, 2, 3, 4, 5, 6], dst);
        crate::test_complete!("test_chain_copy_to_slice");
    }

    #[test]
    fn test_chain_getters() {
        init_test("test_chain_getters");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let mut chain = Chain::new(a, b);

        let first = *chain.first_ref();
        crate::assert_with_log!(first == &[1, 2, 3][..], "first", &[1, 2, 3][..], first);
        let last = *chain.last_ref();
        crate::assert_with_log!(last == &[4, 5, 6][..], "last", &[4, 5, 6][..], last);

        // Advance and check
        chain.advance(4);
        let first = *chain.first_ref();
        crate::assert_with_log!(first == b"", "first", b"", first);
        let last = *chain.last_ref();
        crate::assert_with_log!(last == &[5, 6][..], "last", &[5, 6][..], last);
        crate::test_complete!("test_chain_getters");
    }

    #[test]
    fn test_chain_into_inner() {
        init_test("test_chain_into_inner");
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[4, 5, 6];
        let chain = Chain::new(a, b);

        let (a_out, b_out) = chain.into_inner();
        let ok = a_out == [1, 2, 3];
        crate::assert_with_log!(ok, "a_out", &[1, 2, 3], a_out);
        let ok = b_out == [4, 5, 6];
        crate::assert_with_log!(ok, "b_out", &[4, 5, 6], b_out);
        crate::test_complete!("test_chain_into_inner");
    }
}
