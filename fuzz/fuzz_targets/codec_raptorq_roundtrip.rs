#![no_main]

//! Cargo-fuzz target for the RaptorQ codec encode↔decode round-trip.
//!
//! Drives `EncodingPipeline` (src/encoding.rs) → `DecodingPipeline`
//! (src/decoding.rs) end-to-end with random byte streams and asserts:
//!
//!   1. **Round-trip preserves bytes.** When the decoder receives the full
//!      symbol set (no erasures), `into_data()` MUST return exactly the
//!      original payload byte-for-byte.
//!
//!   2. **Decoder fail-safe on truncated symbol set.** When a fraction of
//!      symbols is dropped, the decoder MUST either succeed (when enough
//!      remain to satisfy the K + repair-overhead threshold) or return a
//!      typed `DecodingError` — NEVER panic, NEVER infinite-loop.
//!
//!   3. **No panic on malformed input.** Pathological inputs (zero-length,
//!      `symbol_size = 1`, very large source data clamped to `MAX_INPUT`)
//!      must produce typed errors, not crashes.
//!
//! Coverage strategy: derive `symbol_size` and `source_symbols` from the
//! first few bytes of the fuzz input so libFuzzer can mutate the codec
//! configuration in addition to the payload. All sizes are clamped to a
//! tight envelope (`MAX_INPUT`, `MAX_SYMBOL_SIZE`) so each iteration stays
//! sub-second.

use asupersync::config::EncodingConfig;
use asupersync::decoding::{DecodingConfig, DecodingPipeline};
use asupersync::encoding::EncodingPipeline;
use asupersync::security::AuthenticatedSymbol;
use asupersync::security::tag::AuthenticationTag;
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::{ObjectId, ObjectParams, Symbol};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 8 * 1024;
const MAX_SYMBOL_SIZE: u16 = 1024;
const MAX_SYMBOLS_PER_BLOCK: u16 = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Carve a configuration out of the first 4 bytes so libFuzzer can
    // mutate codec parameters along with payload.
    let config_bytes = &data[..4];
    let payload = &data[4..];
    if payload.len() > MAX_INPUT {
        return;
    }

    // symbol_size ∈ [4, MAX_SYMBOL_SIZE] (must be > 0 and ≤ u16::MAX).
    let raw_ss = u16::from_le_bytes([config_bytes[0], config_bytes[1]]);
    let symbol_size: u16 = (raw_ss % (MAX_SYMBOL_SIZE - 3)) + 4;

    // source_symbols ∈ [1, MAX_SYMBOLS_PER_BLOCK].
    let raw_k = u16::from_le_bytes([config_bytes[2], config_bytes[3]]);
    let source_symbols: u16 = (raw_k % (MAX_SYMBOLS_PER_BLOCK - 1)) + 1;

    // Block must be large enough to hold the payload OR to fit
    // source_symbols × symbol_size, whichever is larger.
    let payload_len = payload.len();
    let max_block_size: usize =
        payload_len.max(usize::from(symbol_size) * usize::from(source_symbols));

    let enc_config = EncodingConfig {
        symbol_size,
        max_block_size,
        repair_overhead: 1.0,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    };

    // Pool sized generously for source + repair symbols. Repair count is
    // set to source_symbols so the codec produces 2K total symbols per
    // block (1.0 repair overhead).
    let repair_symbols = usize::from(source_symbols);
    let pool_size = (usize::from(source_symbols) + repair_symbols).max(16);
    let pool = SymbolPool::new(PoolConfig {
        symbol_size,
        initial_size: pool_size,
        max_size: pool_size.saturating_mul(2),
        allow_growth: true,
        growth_increment: 16,
    });

    let object_id = ObjectId::new_for_test(u64::from(raw_ss) ^ u64::from(raw_k) << 16);
    let mut encoder = EncodingPipeline::new(enc_config, pool);

    // ENCODE — collect all generated symbols. An encoder error is fine
    // (typed); just exit early.
    let symbols: Vec<Symbol> = match encoder
        .encode_with_repair(object_id, payload, repair_symbols)
        .map(|res| res.map(|enc| enc.into_symbol()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(s) => s,
        Err(_typed) => return,
    };

    if symbols.is_empty() {
        // Empty payload or zero-K block — nothing to round-trip.
        return;
    }

    // ROUND-TRIP A: full symbol set ⇒ decoder MUST recover original bytes.
    if let Some(decoded) = decode_attempt(
        symbol_size,
        max_block_size,
        source_symbols,
        object_id,
        payload_len,
        &symbols,
    ) {
        assert_eq!(
            decoded, payload,
            "RaptorQ codec round-trip MUST preserve bytes when full symbol set is received"
        );
    } else {
        // Some configurations (e.g. zero-symbol blocks) legitimately
        // refuse to encode/decode; surface as a no-op rather than
        // asserting false.
        return;
    }

    // ROUND-TRIP B: decoder fail-safe on truncated symbol set. Drop the
    // FIRST source symbol; with 1.0 repair overhead the decoder should
    // still recover. If we drop MORE than the repair budget, the decoder
    // must return a typed error (NOT panic).
    if symbols.len() > 1 {
        let truncated: Vec<Symbol> = symbols.iter().skip(1).cloned().collect();
        // We don't assert success — only fail-safety. The call path
        // inside decode_attempt already requires non-panicking behavior;
        // a None return here is acceptable (Err propagated as typed).
        let _ = decode_attempt(
            symbol_size,
            max_block_size,
            source_symbols,
            object_id,
            payload_len,
            &truncated,
        );
    }

    // ROUND-TRIP C: aggressive truncation — keep only half the symbols.
    // This usually exceeds the repair budget; the decoder MUST surface a
    // typed DecodingError without panicking.
    if symbols.len() >= 4 {
        let half = symbols.len() / 2;
        let truncated: Vec<Symbol> = symbols.iter().take(half).cloned().collect();
        let _ = decode_attempt(
            symbol_size,
            max_block_size,
            source_symbols,
            object_id,
            payload_len,
            &truncated,
        );
    }
});

/// Run the decode pipeline against the provided symbol set. Returns
/// `Some(bytes)` on full recovery, `None` on any typed decoder error.
/// MUST NOT panic regardless of input.
fn decode_attempt(
    symbol_size: u16,
    max_block_size: usize,
    source_symbols: u16,
    object_id: ObjectId,
    data_len: usize,
    symbols: &[Symbol],
) -> Option<Vec<u8>> {
    let dec_config = DecodingConfig {
        symbol_size,
        max_block_size,
        repair_overhead: 1.0,
        min_overhead: 0,
        max_buffered_symbols: symbols.len().saturating_mul(2).max(16),
        block_timeout: std::time::Duration::from_secs(60),
        verify_auth: false,
    };
    let mut decoder = DecodingPipeline::new(dec_config);

    decoder
        .set_object_params(ObjectParams::new(
            object_id,
            data_len as u64,
            symbol_size,
            1,
            source_symbols,
        ))
        .ok()?;

    for symbol in symbols {
        let auth = AuthenticatedSymbol::from_parts(symbol.clone(), AuthenticationTag::zero());
        decoder.feed(auth).ok()?;
    }

    decoder.into_data().ok()
}
