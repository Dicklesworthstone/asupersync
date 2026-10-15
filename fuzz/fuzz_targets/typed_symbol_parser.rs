#![no_main]

use asupersync::types::typed_symbol::{
    DeserializationError, SerializationFormat, TYPED_SYMBOL_HEADER_LEN, TYPED_SYMBOL_MAGIC,
    TypeMismatchError, TypedSymbol,
};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static FIXED_ORACLES: OnceLock<()> = OnceLock::new();
static EXPECTED_TYPE_ID_BYTES: OnceLock<[u8; 8]> = OnceLock::new();

// Simple test type for fuzzing
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TestData {
    value: u32,
    message: String,
}

fn test_symbol_id() -> SymbolId {
    let object_id = ObjectId::new_for_test(0x1234567890abcdef);
    SymbolId::new(object_id, 0, 0)
}

fn assert_fixed_oracles() {
    let value = TestData {
        value: 42,
        message: "typed-symbol-canary".to_string(),
    };

    for format in [
        SerializationFormat::MessagePack,
        SerializationFormat::Bincode,
        SerializationFormat::Json,
    ] {
        let typed = TypedSymbol::from_value(&value, format).expect("fixture value must serialize");
        assert_eq!(typed.format(), format);
        assert_eq!(typed.version(), 1);
        assert!(typed.payload_len() > 0);
        assert_eq!(typed.value().expect("fixture value must decode"), value);

        let raw = typed.clone().into_symbol();
        assert!(raw.data().starts_with(&TYPED_SYMBOL_MAGIC));
        let reparsed =
            TypedSymbol::<TestData>::try_from_symbol(raw).expect("typed fixture must reparse");
        assert_eq!(reparsed.format(), format);
        assert_eq!(reparsed.value().expect("reparsed value must decode"), value);
    }

    let typed =
        TypedSymbol::from_value(&value, SerializationFormat::Bincode).expect("fixture serialize");
    let raw = typed.clone().into_symbol();
    match TypedSymbol::<String>::try_from_symbol(raw.clone()) {
        Err(TypeMismatchError::UnknownType { .. }) => {}
        other => panic!("expected UnknownType for mismatched Rust type, got {other:?}"),
    }

    let mut invalid_magic = raw.clone();
    invalid_magic.data_mut()[..4].copy_from_slice(b"XXXX");
    assert!(matches!(
        TypedSymbol::<TestData>::try_from_symbol(invalid_magic),
        Err(TypeMismatchError::InvalidMagic)
    ));

    let mut invalid_format = raw.clone();
    invalid_format.data_mut()[14] = 4;
    assert!(matches!(
        TypedSymbol::<TestData>::try_from_symbol(invalid_format),
        Err(TypeMismatchError::UnsupportedFormatByte { value: 4 })
    ));

    let mut bad_schema = raw.clone();
    bad_schema.data_mut()[15] ^= 0x80;
    assert!(matches!(
        TypedSymbol::<TestData>::try_from_symbol(bad_schema),
        Err(TypeMismatchError::SchemaMismatch { .. })
    ));

    let truncated_payload = Symbol::from_slice(
        test_symbol_id(),
        &raw.data()[..TYPED_SYMBOL_HEADER_LEN],
        SymbolKind::Source,
    );
    let reparsed = TypedSymbol::<TestData>::try_from_symbol(truncated_payload)
        .expect("header remains valid after payload truncation");
    let err = reparsed
        .value()
        .expect_err("header-only typed symbol must reject missing payload");
    assert!(matches!(err, DeserializationError::CorruptData));
    assert_eq!(err.to_string(), "corrupt symbol data");
}

fn build_expected_type_id_bytes() -> [u8; 8] {
    let value = TestData {
        value: 0,
        message: String::new(),
    };
    let typed =
        TypedSymbol::from_value(&value, SerializationFormat::Bincode).expect("fixture serialize");
    let raw = typed.into_symbol();
    let mut out = [0u8; 8];
    out.copy_from_slice(&raw.data()[6..14]);
    out
}

fn expected_type_id_bytes() -> [u8; 8] {
    *EXPECTED_TYPE_ID_BYTES.get_or_init(build_expected_type_id_bytes)
}

fn assert_header_prefix_model(
    data: &[u8],
    result: &Result<TypedSymbol<TestData>, TypeMismatchError>,
) {
    if data.len() < TYPED_SYMBOL_HEADER_LEN || data[..4] != TYPED_SYMBOL_MAGIC {
        assert!(
            matches!(result, Err(TypeMismatchError::InvalidMagic)),
            "short or wrong-magic input must reject as InvalidMagic, got {result:?}"
        );
        return;
    }

    if !matches!(data[14], 1 | 2 | 3 | 255) {
        assert!(
            matches!(
                result,
                Err(TypeMismatchError::UnsupportedFormatByte { value }) if *value == data[14]
            ),
            "unsupported format byte must be preserved in error, got {result:?}"
        );
        return;
    }

    if data[6..14] != expected_type_id_bytes() {
        assert!(
            matches!(result, Err(TypeMismatchError::UnknownType { .. })),
            "wrong type-id bytes must reject as UnknownType, got {result:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    FIXED_ORACLES.get_or_init(assert_fixed_oracles);

    // Guard against excessively large inputs that would just waste time
    if data.len() > 100_000 {
        return;
    }

    let symbol = Symbol::from_slice(test_symbol_id(), data, SymbolKind::Source);

    let result: Result<TypedSymbol<TestData>, TypeMismatchError> =
        TypedSymbol::try_from_symbol(symbol);
    assert_header_prefix_model(data, &result);

    if let Ok(typed) = result {
        assert!(matches!(
            typed.format(),
            SerializationFormat::MessagePack
                | SerializationFormat::Bincode
                | SerializationFormat::Json
                | SerializationFormat::Custom
        ));
        assert_eq!(typed.symbol().data()[..4], TYPED_SYMBOL_MAGIC);
        let _ = typed.value();
    }
});
