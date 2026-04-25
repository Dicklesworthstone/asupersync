//! Tombstone guard for the renamed `metamorphic_io_copy` integration target.
//!
//! The actual `io::copy` metamorphic suite now lives in
//! `tests/metamorphic_io_copy.rs`. This target stays cheap so the same
//! expensive proptest suite does not run twice under two target names, but it
//! should fail if the canonical suite is disconnected.

const CANONICAL_TARGET: &str = include_str!("metamorphic_io_copy.rs");
const IO_COPY_SUITE: &str = include_str!("metamorphic/io_copy.rs");

#[test]
fn renamed_io_copy_metamorphic_suite_still_exists() {
    assert!(
        CANONICAL_TARGET.contains(r#"include!("metamorphic/io_copy.rs");"#),
        "canonical metamorphic_io_copy target no longer includes the io::copy suite"
    );
    assert!(
        IO_COPY_SUITE.contains("fn mr_copy_transfers_all_bytes")
            && IO_COPY_SUITE.contains("fn mr_copy_respects_writer_limit"),
        "io::copy metamorphic suite no longer contains the core transfer and limit relations"
    );
}
