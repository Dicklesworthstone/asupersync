#![no_main]

use libfuzzer_sys::fuzz_target;
use asupersync::types::{Symbol, SymbolId, SymbolKind, ObjectId};
use asupersync::types::typed_symbol::{TypedSymbol, TypeMismatchError};

// Simple test type for fuzzing
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TestData {
    value: u32,
    message: String,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs that would just waste time
    if data.len() > 100_000 {
        return;
    }

    // Try to parse the input as a typed symbol
    // Create a dummy symbol with the input data
    let object_id = ObjectId::new_for_test(0x1234567890abcdef);
    let symbol_id = SymbolId::new(object_id, 0, 0);
    let symbol = Symbol::from_slice(symbol_id, data, SymbolKind::Source);

    // Attempt to parse as a typed symbol - this exercises the parser
    let result: Result<TypedSymbol<TestData>, TypeMismatchError> = TypedSymbol::try_from_symbol(symbol);

    // We don't care if it succeeds or fails, just that it doesn't crash
    let _ = result;

    // Also test direct header parsing if we have enough bytes
    if data.len() >= asupersync::types::typed_symbol::TYPED_SYMBOL_HEADER_LEN {
        // This exercises the TypedHeader::decode function directly
        // We can't call it directly since it's private, but try_from_symbol calls it
    }

    // Test some invariants - even malformed input should never cause undefined behavior
    // The parser should gracefully handle:
    // - Truncated headers
    // - Invalid magic bytes
    // - Out-of-range format values
    // - Mismatched payload lengths
    // - Invalid type IDs
});