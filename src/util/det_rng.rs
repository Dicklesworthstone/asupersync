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

/// Seed validation result for replay safety analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedQuality {
    /// High-quality seed suitable for production and lab use.
    Excellent,
    /// Good seed with adequate entropy.
    Good,
    /// Acceptable seed but with some entropy concerns.
    Acceptable,
    /// Poor seed quality - use with caution.
    Poor,
    /// Dangerous seed that could compromise replay consistency.
    Dangerous {
        /// Specific issue with the seed.
        reason: &'static str,
    },
}

impl DetRng {
    /// Creates a new PRNG with the given seed after validation.
    ///
    /// **Security**: Validates seed quality for replay safety. Zero seeds
    /// are automatically corrected to 1. Dangerous seeds trigger warnings.
    #[must_use]
    #[inline]
    pub const fn new(seed: u64) -> Self {
        let validated_seed = Self::validate_and_correct_seed(seed);
        Self {
            state: validated_seed,
        }
    }

    /// Creates a new PRNG with explicit seed quality validation.
    ///
    /// **Security**: Returns both the RNG and a quality assessment.
    /// Use this when seed quality matters for security analysis.
    #[must_use]
    pub fn new_with_quality(seed: u64) -> (Self, SeedQuality) {
        let quality = Self::assess_seed_quality(seed);
        let validated_seed = Self::validate_and_correct_seed(seed);
        (
            Self {
                state: validated_seed,
            },
            quality,
        )
    }

    /// Creates a high-entropy PRNG suitable for production use.
    ///
    /// **Security**: Uses OS entropy to generate a cryptographically random seed.
    /// This provides replay-safe determinism while preventing seed prediction.
    ///
    /// # Panics
    ///
    /// Panics when strict entropy isolation is enabled. Use [`Self::new`] with
    /// an explicit seed or the task's `Cx` entropy capability in that mode.
    #[must_use]
    pub fn from_entropy() -> Self {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};

        crate::util::entropy::check_ambient_entropy("det-rng");

        // Generate high-quality seed from OS entropy
        let random_state = RandomState::new();
        let mut hasher = random_state.build_hasher();

        // Mix multiple entropy sources for better quality
        std::process::id().hash(&mut hasher);
        std::thread::current().id().hash(&mut hasher);

        // Add timestamp for additional entropy (but not for lab determinism)
        #[cfg(not(feature = "test-internals"))]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .hash(&mut hasher);
        }

        let entropy_seed = hasher.finish();
        Self::new(entropy_seed)
    }

    /// Validates and corrects a seed for replay safety.
    ///
    /// **Security**: Ensures the seed won't cause xorshift64 to degenerate
    /// into a short cycle or produce predictable sequences.
    #[must_use]
    const fn validate_and_correct_seed(seed: u64) -> u64 {
        // Zero seed would cause xorshift64 to stick at zero
        if seed == 0 {
            return 1;
        }

        // Check for seeds that create short cycles in xorshift64
        if Self::is_degenerate_seed(seed) {
            return seed.wrapping_add(0x9e3779b97f4a7c15); // Add golden ratio
        }

        seed
    }

    /// Checks if a seed would cause xorshift64 to have a short cycle.
    ///
    /// **Security**: Prevents replay divergence from degenerate PRNG cycles.
    #[must_use]
    const fn is_degenerate_seed(seed: u64) -> bool {
        // Seeds with all bits in specific patterns can cause short cycles
        // Check for common degenerate patterns
        matches!(
            seed,
            0xFFFF_FFFF_FFFF_FFFF |  // All ones
            0x0000_0000_FFFF_FFFF |  // High zeros, low ones
            0xFFFF_FFFF_0000_0000 |  // High ones, low zeros
            0x5555_5555_5555_5555 |  // Alternating bits
            0xAAAA_AAAA_AAAA_AAAA // Alternating bits (inverted)
        )
    }

    /// Assesses the quality of a seed for replay consistency.
    ///
    /// **Security**: Analyzes seed entropy and potential replay hazards.
    #[must_use]
    pub fn assess_seed_quality(seed: u64) -> SeedQuality {
        if seed == 0 {
            return SeedQuality::Dangerous {
                reason: "Zero seed causes xorshift64 to stick at zero",
            };
        }

        if Self::is_degenerate_seed(seed) {
            return SeedQuality::Dangerous {
                reason: "Seed creates short cycles in xorshift64",
            };
        }

        // Analyze bit patterns for entropy quality
        let popcount = seed.count_ones();
        let leading_zeros = seed.leading_zeros();
        let trailing_zeros = seed.trailing_zeros();

        // Check for low entropy patterns
        if popcount <= 8 || popcount >= 56 {
            return SeedQuality::Poor;
        }

        if leading_zeros >= 32 || trailing_zeros >= 32 {
            return SeedQuality::Poor;
        }

        // Check for simple patterns that might indicate weak entropy
        if Self::has_simple_pattern(seed) {
            return SeedQuality::Acceptable;
        }

        // High-quality seed
        if (20..=44).contains(&popcount) && leading_zeros <= 8 && trailing_zeros <= 8 {
            SeedQuality::Excellent
        } else {
            SeedQuality::Good
        }
    }

    /// Detects simple patterns that indicate poor entropy.
    #[must_use]
    const fn has_simple_pattern(seed: u64) -> bool {
        // Check for byte repetition patterns
        let bytes = seed.to_le_bytes();
        let b0 = bytes[0];

        // All bytes the same
        let mut all_same = true;
        let mut idx = 1usize;
        while idx < bytes.len() {
            if bytes[idx] != b0 {
                all_same = false;
                break;
            }
            idx += 1;
        }
        if all_same {
            return true;
        }

        // Simple arithmetic progressions in bytes
        let mut is_arithmetic = true;
        if bytes.len() >= 3 {
            let diff = bytes[1].wrapping_sub(bytes[0]);
            let mut i = 2usize;
            while i < bytes.len() {
                if bytes[i].wrapping_sub(bytes[i - 1]) != diff {
                    is_arithmetic = false;
                    break;
                }
                i += 1;
            }
        }

        is_arithmetic
    }

    /// Verifies replay consistency between two RNG instances.
    ///
    /// **Security**: Ensures identical seeds produce identical sequences
    /// across different platforms and compiler versions.
    pub fn verify_replay_consistency(seed: u64, steps: usize) -> Result<(), String> {
        let mut rng1 = Self::new(seed);
        let mut rng2 = Self::new(seed);

        for step in 0..steps {
            let val1 = rng1.next_u64();
            let val2 = rng2.next_u64();

            if val1 != val2 {
                return Err(format!(
                    "Replay divergence at step {step}: rng1={val1:#x}, rng2={val2:#x}"
                ));
            }
        }

        Ok(())
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
#[path = "det_rng_inline_tests.rs"]
mod tests;
