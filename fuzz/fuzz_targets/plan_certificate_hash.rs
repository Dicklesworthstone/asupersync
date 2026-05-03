//! Fuzz target for `src/plan/certificate.rs` — PlanHash determinism.
//!
//! Exercises:
//!   - `PlanHash::of(bytes)` — deterministic content hash of arbitrary
//!     byte input.
//!   - Property: `of(x) == of(y) iff x == y` (collision-free for
//!     SHA-256-class digests; not provable but no false matches in
//!     practice).
//!   - Property: `of(x).as_bytes()` is exactly 32 bytes.
//!   - Property: hashing the same bytes twice produces the same hash
//!     (determinism — the project relies on PlanHash for
//!     replay-stable plan certificates).
//!   - Property: hashing two different prefixes of the same input
//!     produces different hashes (no truncation bug).

#![no_main]

use libfuzzer_sys::fuzz_target;

use asupersync::plan::certificate::PlanHash;

fuzz_target!(|data: &[u8]| {
    // Determinism: of(x) twice gives the same hash.
    let h1 = PlanHash::of(data);
    let h2 = PlanHash::of(data);
    assert_eq!(
        h1, h2,
        "PlanHash::of is not deterministic for identical input"
    );

    // Length: 32 bytes.
    assert_eq!(
        h1.as_bytes().len(),
        32,
        "PlanHash::as_bytes() must be 32 bytes (SHA-256-class digest)"
    );

    // Prefix sensitivity: hashing prefixes of different lengths must
    // produce different hashes (otherwise we have a length-extension
    // or truncation bug).
    if data.len() >= 2 {
        let h_prefix = PlanHash::of(&data[..1]);
        let h_full = PlanHash::of(data);
        if data.len() != 1 {
            assert_ne!(
                h_prefix, h_full,
                "PlanHash::of of a 1-byte prefix matched the full input — truncation bug"
            );
        }
    }

    // Distinctness: appending a byte should change the hash.
    if data.len() < 1024 {
        let mut extended = data.to_vec();
        extended.push(0xAB);
        let h_ext = PlanHash::of(&extended);
        assert_ne!(
            h1, h_ext,
            "PlanHash::of did not change after appending a byte"
        );
    }

    // Symmetry of equality: the Eq impl is reflexive.
    assert_eq!(h1, h1);

    // Hash is Copy/Clone — exercise.
    let h3 = h1;
    assert_eq!(h1, h3);
});
