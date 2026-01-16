//! Deterministic pseudo-random number generator.
//!
//! This module provides a simple, deterministic PRNG that requires no external
//! dependencies. It uses the xorshift64 algorithm for simplicity and speed.
//!
//! # Determinism
//!
//! Given the same seed, the sequence of generated numbers is always identical.
//! This is critical for deterministic schedule exploration in the lab runtime.

/// A deterministic pseudo-random number generator using xorshift64.
///
/// This PRNG is intentionally simple and fast, with no external dependencies.
/// It is NOT cryptographically secure.
#[derive(Debug, Clone)]
pub struct DetRng {
    state: u64,
}

impl DetRng {
    /// Creates a new PRNG with the given seed.
    ///
    /// The seed must be non-zero. If zero is provided, it will be replaced with 1.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    /// Generates the next pseudo-random u64 value.
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: mutates self
    pub fn next_u64(&mut self) -> u64 {
        // xorshift64 algorithm
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Generates a pseudo-random u32 value.
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Generates a pseudo-random usize value in the range [0, bound).
    ///
    /// # Panics
    ///
    /// Panics if `bound` is zero.
    #[allow(clippy::cast_possible_truncation)]
    pub fn next_usize(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "bound must be non-zero");
        (self.next_u64() as usize) % bound
    }

    /// Generates a pseudo-random boolean.
    pub fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// Shuffles a slice in place using the Fisher-Yates algorithm.
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.next_usize(i + 1);
            slice.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_sequence() {
        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(42);

        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn different_seeds_different_sequences() {
        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(43);

        // Very unlikely to match
        assert_ne!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn zero_seed_handled() {
        let mut rng = DetRng::new(0);
        // Should not hang or produce all zeros
        assert_ne!(rng.next_u64(), 0);
    }
}
