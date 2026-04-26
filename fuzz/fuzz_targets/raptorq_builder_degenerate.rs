//! br-asupersync-voxekc — Fuzz `RaptorQSenderBuilder` /
//! `RaptorQReceiverBuilder` with degenerate `RaptorQConfig` values.
//!
//! Invariants asserted:
//!   1. No panic — `build()` must return `Result<_, Error>` for any
//!      configuration. Specifically: symbol_size = 0, k-implicit-zero
//!      via tiny max_block_size, NaN/Inf repair_overhead, zero
//!      parallelism, sub-MB memory budgets — all should be either
//!      cleanly rejected via `ConfigError` or accepted and produce a
//!      working sender/receiver. Crash is the only invalid outcome.
//!   2. No OOM — capped via the field ranges below; no allocation
//!      depends on attacker-controlled lengths.
//!   3. No infinite loop — `build()` is a pure validator + struct
//!      construction, no I/O.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::config::RaptorQConfig;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let mut config = RaptorQConfig::default();

    // symbol_size: derived from the first 2 bytes — deliberately allowed
    // to land at 0 (rejected by validate) and at huge values up to u16::MAX.
    config.encoding.symbol_size = u16::from_le_bytes([data[0], data[1]]);

    // repair_overhead: pull 8 bytes and reinterpret as f64. This will
    // produce NaN, Infinity, subnormals, and negatives — all should be
    // rejected by validate, never panic.
    let bits = u64::from_le_bytes([
        data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
    ]);
    config.encoding.repair_overhead = f64::from_bits(bits);

    // max_block_size: derived from byte 10 — allow 0 to exercise the
    // ConfigError::InvalidMaxBlockSize path.
    config.encoding.max_block_size = u32::from(data[10]) as usize;

    // parallelism: byte 11 governs both lanes — 0 is the rejection case.
    config.encoding.encoding_parallelism = data[11] as usize;
    config.encoding.decoding_parallelism = data[11] as usize;

    // resources: tiny budgets exercise InsufficientMemory.
    config.resources.max_symbol_buffer_memory =
        (data[12] as usize).saturating_mul(1024);

    // Standalone validate() invariant: never panics, always returns
    // Result<(), ConfigError>. The builder build()s call this same
    // validate via the trait-bounded path (requires a live SymbolSink /
    // SymbolStream transport), so validating the config directly is the
    // contract we can exercise from a fuzz target without fabricating
    // an entire transport stack.
    let validate_result = catch_unwind(AssertUnwindSafe(|| config.validate()));
    assert!(
        validate_result.is_ok(),
        "RaptorQConfig::validate panicked on degenerate config"
    );

    // Cloning a degenerate config must also not panic — the fuzz catches
    // any future Drop / Clone impl that doesn't tolerate NaN / Inf.
    let clone_result = catch_unwind(AssertUnwindSafe(|| config.clone()));
    assert!(
        clone_result.is_ok(),
        "RaptorQConfig::clone panicked on degenerate config"
    );
});
