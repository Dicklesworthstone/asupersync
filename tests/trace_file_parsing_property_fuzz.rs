//! Property-based fuzz over trace file parser edge cases.
//!
//! Bead: br-asupersync-belaif
//!
//! `fuzz/fuzz_targets/trace_file_parsing.rs` is a random-bytes fuzz that
//! mostly hits early-rejection paths (wrong magic, too-short input). It
//! does NOT systematically cover:
//!   1. Valid header followed by truncation at every byte offset
//!   2. Header with `version > TRACE_FILE_VERSION` (currently 2) — every
//!      future-version code must error with `UnsupportedVersion`
//!   3. Valid magic + valid version + truncated metadata length / body
//!
//! Property: parsing must NEVER panic, NEVER hang, NEVER return Ok with
//! a corrupted reader. It always returns either `Ok(reader)` (whose
//! `read_event()` may then yield a sequence of valid events ending in
//! Ok(None)) or `Err(TraceFileError)`.
//!
//! This is a property test, not a libfuzzer target — it complements the
//! random-bytes target by feeding valid prefixes + targeted mutations,
//! which the libfuzzer corpus would reach only after extensive coverage
//! exploration.

#![cfg(test)]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::trace::file::{
    FLAG_COMPRESSED, HEADER_SIZE, TRACE_FILE_VERSION, TRACE_MAGIC, TraceReader,
};
use proptest::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

/// Build a header-only valid prefix:
/// magic + version + flags + compression byte + metadata length.
/// `HEADER_SIZE` is `11 + 2 + 2 + 1 + 4 = 20` (per src/trace/file.rs:83).
fn valid_header_prefix(version: u16, flags: u16, compression: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE);
    buf.extend_from_slice(TRACE_MAGIC);
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.push(compression);
    buf.extend_from_slice(&0u32.to_le_bytes());
    debug_assert_eq!(buf.len(), HEADER_SIZE);
    buf
}

/// Write `bytes` to a tempfile and try to open it as a TraceReader.
/// Returns `true` if `open()` returned Ok. The tempfile is dropped on
/// scope exit (auto-cleaned).
fn try_open(bytes: &[u8]) -> bool {
    let mut tmp = NamedTempFile::new().expect("tempfile");
    tmp.write_all(bytes).expect("write");
    tmp.flush().expect("flush");
    let result = TraceReader::open(tmp.path());
    result.is_ok()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Truncation at any offset strictly less than HEADER_SIZE (20
    /// bytes) MUST return Err. The parser cannot read a complete header
    /// without all 20 bytes, so an Ok return would imply the parser
    /// silently accepted a truncated file.
    #[test]
    fn truncation_below_header_size_always_errors(truncate_at in 0usize..HEADER_SIZE) {
        let full = valid_header_prefix(TRACE_FILE_VERSION, 0, 0);
        let truncated = &full[..truncate_at];
        prop_assert!(
            !try_open(truncated),
            "truncation at offset {truncate_at} (header_size = {HEADER_SIZE}) returned Ok; \
             expected Err because no complete header is present"
        );
    }

    /// Version code STRICTLY GREATER than TRACE_FILE_VERSION must
    /// always error with UnsupportedVersion (per src/trace/file.rs:896).
    /// Smaller versions (0..TRACE_FILE_VERSION) are accepted as
    /// backward-compat paths and may still fail downstream parsing,
    /// but the version gate alone must not reject them.
    #[test]
    fn future_version_always_errors(future_version in (TRACE_FILE_VERSION + 1)..u16::MAX) {
        let bytes = valid_header_prefix(future_version, 0, 0);
        prop_assert!(
            !try_open(&bytes),
            "future version {future_version} (current = {TRACE_FILE_VERSION}) returned Ok; \
             expected Err::UnsupportedVersion"
        );
    }

    /// Magic-prefix mutations always error — flipping any bit in any
    /// magic byte must trip InvalidMagic before the parser proceeds.
    #[test]
    fn corrupted_magic_always_errors(
        byte_index in 0usize..TRACE_MAGIC.len(),
        bit in 0u8..8,
    ) {
        let mut bytes = valid_header_prefix(TRACE_FILE_VERSION, 0, 0);
        bytes[byte_index] ^= 1u8 << bit;
        prop_assert_ne!(
            &bytes[..TRACE_MAGIC.len()],
            TRACE_MAGIC.as_slice(),
            "magic must actually change after flip"
        );
        prop_assert!(
            !try_open(&bytes),
            "corrupted magic (flipped byte {byte_index} bit {bit}) returned Ok; \
             expected Err::InvalidMagic"
        );
    }

    /// Trailing-flag-bit mutations are NOT a guaranteed reject — the
    /// flag byte has only one defined bit (FLAG_COMPRESSED = 0x0001),
    /// and unknown flag bits may be accepted as forward-compat. The
    /// property here is weaker but still useful: setting random flag
    /// bits never PANICS the parser; it either Ok(reader)s or Err()s.
    /// The test passes if no panic surfaces.
    #[test]
    fn random_flag_bits_never_panic(flags in any::<u16>()) {
        let bytes = valid_header_prefix(TRACE_FILE_VERSION, flags, 0);
        // Whatever the result, the call must return without panic.
        // proptest catches panics and reports them as failures, so
        // the assertion is implicit: we only need to call the function.
        let _ = try_open(&bytes);
        // Sanity-check FLAG_COMPRESSED is observable in the constants
        // we imported (compile-time check, not runtime-meaningful).
        prop_assert!(FLAG_COMPRESSED == 0x0001);
    }
}
