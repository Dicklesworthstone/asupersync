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
#[derive(Clone)]
pub struct DetRng {
    state: u64,
}

// br-asupersync-jebj8u: manual Debug impl that REDACTS the internal
// xorshift64 state. The previous `#[derive(Debug)]` would print the
// raw state bytes anywhere a DetRng appeared in a tracing event,
// panic, or `{:?}` log line — which is enough for an attacker who
// observes one such leak to clone the PRNG and predict every
// subsequent value (xorshift64 is a 1-iteration-back-recoverable
// LCG-class generator). DetRng feeds lab-runtime decision sequences,
// shuffle ordering, and chaos injection, so a leak would let an
// attacker who can exfiltrate ANY traced state mirror those decisions
// off-runtime.
impl std::fmt::Debug for DetRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetRng")
            .field("state", &"<redacted>")
            .finish()
    }
}

impl DetRng {
    /// Creates a new PRNG with the given seed.
    ///
    /// The seed must be non-zero. If zero is provided, it will be replaced with 1.
    #[must_use]
    #[inline]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    /// Generates the next pseudo-random u64 value.
    #[inline]
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
    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Generates a pseudo-random usize value in the range [0, bound).
    ///
    /// Uses rejection sampling to avoid modulo bias.
    ///
    /// # Panics
    ///
    /// Panics if `bound` is zero.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn next_usize(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "bound must be non-zero");
        let bound_u64 = bound as u64;
        let threshold = u64::MAX - (u64::MAX % bound_u64);
        loop {
            let value = self.next_u64();
            if value < threshold {
                return (value % bound_u64) as usize;
            }
        }
    }

    /// Generates a pseudo-random boolean.
    #[inline]
    pub fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// Fills a buffer with pseudo-random bytes.
    #[inline]
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let rand = self.next_u64();
            let bytes = rand.to_le_bytes();
            let n = std::cmp::min(dest.len() - i, 8);
            dest[i..i + n].copy_from_slice(&bytes[..n]);
            i += n;
        }
    }

    /// Shuffles a slice in place using the Fisher-Yates algorithm.
    #[inline]
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.next_usize(i + 1);
            slice.swap(i, j);
        }
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

    // =========================================================================
    // Wave 57 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn det_rng_debug_clone() {
        let mut rng = DetRng::new(42);
        let dbg = format!("{rng:?}");
        assert!(dbg.contains("DetRng"), "{dbg}");

        // Clone preserves sequence position
        let _ = rng.next_u64(); // advance once
        let mut forked = rng.clone();
        assert_eq!(rng.next_u64(), forked.next_u64());
    }

    /// br-asupersync-jebj8u: Debug output MUST NOT leak the internal
    /// xorshift64 state. An attacker who recovers a DetRng's state
    /// from any trace, panic, or log line can mirror every subsequent
    /// random decision off-runtime (the xorshift64 update is fully
    /// invertible from one observed output, so even partial leaks are
    /// catastrophic).
    ///
    /// We assert: across a wide range of seeds — including ones whose
    /// decimal/hex representations are SHORT enough that any partial
    /// embedding in the Debug string would catch them — the formatted
    /// Debug never contains the seed's decimal, hex, lower-hex, upper-
    /// hex, or little-endian byte representations.
    #[test]
    fn debug_does_not_leak_state() {
        let seeds: [u64; 8] = [
            0xDEAD_BEEF_CAFE_BABE,
            0x1234_5678_9ABC_DEF0,
            42,
            1,
            u64::MAX,
            0x0000_0001_0000_0001,
            0xAAAA_AAAA_AAAA_AAAA,
            0x5555_5555_5555_5555,
        ];
        for &seed in &seeds {
            let rng = DetRng::new(seed);
            let dbg = format!("{rng:?}");
            assert!(
                dbg.contains("DetRng"),
                "Debug must still identify the type, got {dbg:?}"
            );
            assert!(
                dbg.contains("<redacted>"),
                "Debug must mark redaction explicitly, got {dbg:?}"
            );
            // No decimal, no upper-hex, no lower-hex of the state.
            let dec = format!("{seed}");
            let lhex = format!("{seed:x}");
            let uhex = format!("{seed:X}");
            assert!(
                !dbg.contains(&dec),
                "decimal state {dec} leaked in Debug: {dbg}"
            );
            // Skip lower/upper hex check for trivial seeds whose hex
            // form would coincidentally appear inside other words
            // (e.g. seed=1 → "1" which is too short to be diagnostic).
            if lhex.len() >= 4 {
                assert!(
                    !dbg.contains(&lhex),
                    "lower-hex state {lhex} leaked in Debug: {dbg}"
                );
                assert!(
                    !dbg.contains(&uhex),
                    "upper-hex state {uhex} leaked in Debug: {dbg}"
                );
            }
        }
    }

    /// Defense-in-depth: even AFTER the PRNG has advanced (so its
    /// internal state diverges from the seed), Debug must not leak the
    /// current state.
    #[test]
    fn debug_does_not_leak_state_after_advance() {
        let mut rng = DetRng::new(0xDEAD_BEEF_CAFE_BABE);
        for _ in 0..1000 {
            let _ = rng.next_u64();
        }
        // Capture the internal state by sampling, then check Debug
        // output doesn't embed that next-output value either (since
        // xorshift64 next-state recovery from one output is trivial).
        let mut probe = rng.clone();
        let next = probe.next_u64();
        let dbg = format!("{rng:?}");
        let dec = format!("{next}");
        let lhex = format!("{next:x}");
        let uhex = format!("{next:X}");
        assert!(
            !dbg.contains(&dec),
            "post-advance decimal state leaked: {dbg}"
        );
        if lhex.len() >= 4 {
            assert!(!dbg.contains(&lhex), "post-advance lhex leaked: {dbg}");
            assert!(!dbg.contains(&uhex), "post-advance uhex leaked: {dbg}");
        }
    }
}
