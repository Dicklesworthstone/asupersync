#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 96;
const MAX_NAME_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 1024;

#[derive(Arbitrary, Debug)]
struct HeaderMapInput {
    initial_capacity: u8,
    operations: Vec<HeaderOperation>,
}

#[derive(Arbitrary, Debug)]
enum HeaderOperation {
    Append { name: Vec<u8>, value: Vec<u8> },
    Insert { name: Vec<u8>, value: Vec<u8> },
    Get { name: Vec<u8> },
    CloneRoundTrip,
    Iterate,
}

fuzz_target!(|input: HeaderMapInput| {
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }
    if input.operations.iter().any(operation_too_large) {
        return;
    }

    let mut headers = HeaderMap::with_capacity(usize::from(input.initial_capacity));
    let mut model = Vec::<(String, Vec<u8>)>::new();

    for operation in input.operations {
        match operation {
            HeaderOperation::Append { name, value } => {
                let name = header_name_from_bytes(&name);
                let normalized = normalize_header_name(&name);
                let value = value_from_bytes(&value);
                headers.append(
                    HeaderName::from_string(&name),
                    HeaderValue::from_bytes(&value),
                );
                model.push((normalized, value));
            }
            HeaderOperation::Insert { name, value } => {
                let name = header_name_from_bytes(&name);
                let normalized = normalize_header_name(&name);
                let value = value_from_bytes(&value);
                headers.insert(
                    HeaderName::from_string(&name),
                    HeaderValue::from_bytes(&value),
                );
                model.retain(|(existing, _)| existing != &normalized);
                model.push((normalized, value));
            }
            HeaderOperation::Get { name } => {
                let name = header_name_from_bytes(&name);
                assert_get_matches_model(&headers, &model, &name);
            }
            HeaderOperation::CloneRoundTrip => {
                assert_iter_matches_model(&headers, &model);
                let clone = headers.clone();
                assert_iter_matches_model(&clone, &model);
            }
            HeaderOperation::Iterate => {
                assert_iter_matches_model(&headers, &model);
            }
        }

        assert_eq!(headers.len(), model.len());
        assert_eq!(headers.is_empty(), model.is_empty());
        assert_iter_matches_model(&headers, &model);
    }
});

fn operation_too_large(operation: &HeaderOperation) -> bool {
    match operation {
        HeaderOperation::Append { name, value } | HeaderOperation::Insert { name, value } => {
            name.len() > MAX_NAME_BYTES || value.len() > MAX_VALUE_BYTES
        }
        HeaderOperation::Get { name } => name.len() > MAX_NAME_BYTES,
        HeaderOperation::CloneRoundTrip | HeaderOperation::Iterate => false,
    }
}

fn header_name_from_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn normalize_header_name(name: &str) -> String {
    let header_name = HeaderName::from_string(name);
    let normalized = header_name.as_str().to_owned();

    if name.is_ascii() {
        assert_eq!(normalized, name.to_ascii_lowercase());
    }

    normalized
}

fn value_from_bytes(bytes: &[u8]) -> Vec<u8> {
    let header_value = HeaderValue::from_bytes(bytes);
    assert_eq!(header_value.as_bytes(), bytes);
    assert_eq!(
        header_value.to_str().ok(),
        std::str::from_utf8(bytes).ok(),
        "HeaderValue::to_str must match std UTF-8 validation"
    );
    bytes.to_vec()
}

fn assert_get_matches_model(headers: &HeaderMap, model: &[(String, Vec<u8>)], name: &str) {
    let normalized = normalize_header_name(name);
    let expected = model
        .iter()
        .find(|(existing, _)| existing == &normalized)
        .map(|(_, value)| value.as_slice());
    let runtime_name = HeaderName::from_string(name);
    let actual = headers.get(&runtime_name).map(HeaderValue::as_bytes);
    assert_eq!(actual, expected);
}

fn assert_iter_matches_model(headers: &HeaderMap, model: &[(String, Vec<u8>)]) {
    let observed = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_bytes()))
        .collect::<Vec<_>>();
    let expected = model
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect::<Vec<_>>();
    assert_eq!(observed, expected);
}
