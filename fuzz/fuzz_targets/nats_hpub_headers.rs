#![no_main]

use asupersync::messaging::nats::fuzz_encode_nats_headers;
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_HEADERS: usize = 16;
const MAX_FIELD_BYTES: usize = 96;
const MAX_HEADER_BYTES: usize = 1024;
const HPUB_PREFIX: &[u8] = b"NATS/1.0\r\n";
const HPUB_TERMINATOR: &[u8] = b"\r\n\r\n";

#[derive(Clone, Debug)]
struct HeaderField {
    key: String,
    value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelError {
    InvalidKey,
    InvalidValue,
    TooLarge,
}

fn take_byte(data: &[u8], cursor: &mut usize) -> u8 {
    let byte = data.get(*cursor).copied().unwrap_or(0);
    *cursor = cursor.saturating_add(1);
    byte
}

fn take_slice(data: &[u8], cursor: &mut usize, len: usize) -> Vec<u8> {
    let available = data.len().saturating_sub(*cursor);
    let take = available.min(len);
    let slice = data
        .get(*cursor..cursor.saturating_add(take))
        .unwrap_or(&[])
        .to_vec();
    *cursor = cursor.saturating_add(take);
    slice
}

fn insert_str_at_char(text: &mut String, insertion: usize, fragment: &str) {
    let byte_index = text
        .char_indices()
        .nth(insertion)
        .map(|(index, _)| index)
        .unwrap_or(text.len());
    text.insert_str(byte_index, fragment);
}

fn insert_bytes_at(value: &mut Vec<u8>, insertion: usize, fragment: &[u8]) {
    let byte_index = insertion.min(value.len());
    value.splice(byte_index..byte_index, fragment.iter().copied());
}

fn materialize_key(raw: &[u8], key_mode: u8, previous: Option<&str>) -> String {
    let mut key = String::from_utf8_lossy(&raw[..raw.len().min(MAX_FIELD_BYTES)]).into_owned();
    let insertion = raw.first().copied().map_or(0, usize::from) % (key.chars().count() + 1);
    match key_mode % 7 {
        0 => {}
        1 => key.clear(),
        2 => insert_str_at_char(&mut key, insertion, ":"),
        3 => insert_str_at_char(&mut key, insertion, "\r"),
        4 => insert_str_at_char(&mut key, insertion, "\n"),
        5 => insert_str_at_char(&mut key, insertion, "\u{0080}"),
        _ => {
            if let Some(previous) = previous {
                key = previous.to_owned();
            }
        }
    }
    key
}

fn materialize_value(raw: &[u8], value_mode: u8) -> Vec<u8> {
    let mut value = raw[..raw.len().min(MAX_FIELD_BYTES)].to_vec();
    let insertion = raw.first().copied().map_or(0, usize::from) % (value.len() + 1);
    match value_mode % 5 {
        0 => {}
        1 => insert_bytes_at(&mut value, insertion, b"\r"),
        2 => insert_bytes_at(&mut value, insertion, b"\n"),
        3 => insert_bytes_at(&mut value, insertion, b"\r\n"),
        _ => insert_bytes_at(&mut value, insertion, b"\n\r"),
    }
    value
}

fn parse_input(data: &[u8]) -> (usize, Vec<HeaderField>) {
    let mut cursor = 0usize;
    let max_header_bytes = (usize::from(take_byte(data, &mut cursor)) * 4).min(MAX_HEADER_BYTES);
    let header_count = usize::from(take_byte(data, &mut cursor)) % (MAX_HEADERS + 1);
    let mut headers = Vec::with_capacity(header_count);

    for _ in 0..header_count {
        let key_len = usize::from(take_byte(data, &mut cursor)) % (MAX_FIELD_BYTES + 1);
        let value_len = usize::from(take_byte(data, &mut cursor)) % (MAX_FIELD_BYTES + 1);
        let key_mode = take_byte(data, &mut cursor);
        let value_mode = take_byte(data, &mut cursor);
        let key_raw = take_slice(data, &mut cursor, key_len);
        let value_raw = take_slice(data, &mut cursor, value_len);
        let previous = headers.last().map(|field: &HeaderField| field.key.as_str());
        let key = materialize_key(&key_raw, key_mode, previous);
        let value = materialize_value(&value_raw, value_mode);
        headers.push(HeaderField { key, value });
    }

    (max_header_bytes, headers)
}

fn model_encode_headers(
    headers: &[HeaderField],
    max_header_bytes: usize,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ModelError> {
    let mut estimated = HPUB_PREFIX.len() + HPUB_TERMINATOR.len();
    let mut expected = Vec::with_capacity(headers.len());

    for field in headers {
        estimated = estimated
            .checked_add(field.key.len() + field.value.len() + 4)
            .ok_or(ModelError::TooLarge)?;
        if estimated > max_header_bytes {
            return Err(ModelError::TooLarge);
        }
        if field.key.is_empty()
            || !field.key.is_ascii()
            || field
                .key
                .bytes()
                .any(|byte| byte == b':' || byte == b'\r' || byte == b'\n')
        {
            return Err(ModelError::InvalidKey);
        }
        if field
            .value
            .iter()
            .any(|&byte| byte == b'\r' || byte == b'\n')
        {
            return Err(ModelError::InvalidValue);
        }
        expected.push((field.key.as_bytes().to_vec(), field.value.clone()));
    }

    Ok(expected)
}

fn decode_header_block(block: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    if !block.starts_with(HPUB_PREFIX) || !block.ends_with(HPUB_TERMINATOR) {
        return None;
    }

    let mut cursor = &block[HPUB_PREFIX.len()..];
    let mut decoded = Vec::new();

    loop {
        if cursor == b"\r\n" {
            return Some(decoded);
        }

        let line_end = cursor.windows(2).position(|window| window == b"\r\n")?;
        let line = &cursor[..line_end];
        cursor = &cursor[line_end + 2..];

        if line.is_empty() {
            return Some(decoded);
        }

        let separator = line.windows(2).position(|window| window == b": ")?;
        let key = line[..separator].to_vec();
        let value = line[separator + 2..].to_vec();
        decoded.push((key, value));
    }
}

fn assert_error_matches_model(err: &str, model_error: ModelError) {
    match model_error {
        ModelError::InvalidKey => assert!(
            err.contains("invalid NATS header key"),
            "expected invalid key error, got {err:?}"
        ),
        ModelError::InvalidValue => assert!(
            err.contains("invalid NATS header value"),
            "expected invalid value error, got {err:?}"
        ),
        ModelError::TooLarge => assert!(
            err.contains("too large") || err.contains("overflow"),
            "expected oversize/overflow error, got {err:?}"
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let (max_header_bytes, headers) = parse_input(data);
    let materialized = headers
        .iter()
        .map(|field| (field.key.clone(), field.value.clone()))
        .collect::<Vec<_>>();

    let result = catch_unwind(AssertUnwindSafe(|| {
        fuzz_encode_nats_headers(&materialized, max_header_bytes)
    }));
    assert!(
        result.is_ok(),
        "encode_nats_headers panicked for headers {:?} and max_header_bytes {}",
        materialized,
        max_header_bytes
    );

    let result = result.expect("panic checked above");
    let model = model_encode_headers(&headers, max_header_bytes);

    assert_eq!(
        result.is_ok(),
        model.is_ok(),
        "encoder/model validity mismatch for headers {:?} and max_header_bytes {}",
        materialized,
        max_header_bytes
    );

    match (result, model) {
        (Ok(encoded), Ok(expected)) => {
            assert!(
                encoded.len() <= max_header_bytes,
                "encoded block exceeded cap: {} > {}",
                encoded.len(),
                max_header_bytes
            );
            assert!(encoded.starts_with(HPUB_PREFIX));
            assert!(encoded.ends_with(HPUB_TERMINATOR));

            let decoded =
                decode_header_block(&encoded).expect("valid encoded header block must decode");
            assert_eq!(
                decoded, expected,
                "decoded HPUB header block must preserve order, duplicates, and raw values"
            );
        }
        (Err(err), Err(model_error)) => assert_error_matches_model(&err, model_error),
        (other_result, other_model) => panic!(
            "unexpected result/model combination: result={other_result:?} model={other_model:?}"
        ),
    }
});
