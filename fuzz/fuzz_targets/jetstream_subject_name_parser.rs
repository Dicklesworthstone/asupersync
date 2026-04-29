#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{fuzz_stream_name_max_bytes, fuzz_validate_stream_name};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_FUZZ_NAME_BYTES: usize = 256 + 64;

#[derive(Arbitrary, Debug, Clone)]
struct SubjectNameInput {
    raw: Vec<u8>,
    mutation: SubjectMutation,
    extra: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum SubjectMutation {
    RawLossy,
    InsertNull,
    InsertCr,
    InsertLf,
    InsertDot,
    OversizedAscii,
}

impl SubjectNameInput {
    fn materialize(&self, max_name_bytes: usize) -> String {
        match self.mutation {
            SubjectMutation::OversizedAscii => {
                let oversize = max_name_bytes + usize::from(self.extra) + 1;
                "a".repeat(oversize)
            }
            _ => {
                let mut name =
                    String::from_utf8_lossy(&self.raw[..self.raw.len().min(MAX_FUZZ_NAME_BYTES)])
                        .into_owned();
                let insertion = usize::from(self.extra) % (name.chars().count() + 1);
                insert_char(&mut name, insertion, self.mutation);
                name
            }
        }
    }
}

fn insert_char(name: &mut String, insertion: usize, mutation: SubjectMutation) {
    match mutation {
        SubjectMutation::RawLossy | SubjectMutation::OversizedAscii => {}
        SubjectMutation::InsertNull => insert_str_at_char(name, insertion, "\0"),
        SubjectMutation::InsertCr => insert_str_at_char(name, insertion, "\r"),
        SubjectMutation::InsertLf => insert_str_at_char(name, insertion, "\n"),
        SubjectMutation::InsertDot => insert_str_at_char(name, insertion, "."),
    }
}

fn insert_str_at_char(name: &mut String, insertion: usize, value: &str) {
    let byte_index = name
        .char_indices()
        .nth(insertion)
        .map(|(index, _)| index)
        .unwrap_or(name.len());
    name.insert_str(byte_index, value);
}

fn has_prohibited_chars(name: &str) -> bool {
    name.chars().any(|ch| {
        ch.is_whitespace()
            || ch == '.'
            || ch == '*'
            || ch == '>'
            || ch == '/'
            || ch == '\\'
            || ch.is_control()
    })
}

fuzz_target!(|input: SubjectNameInput| {
    let max_name_bytes = fuzz_stream_name_max_bytes();
    let name = input.materialize(max_name_bytes);
    let parse_result = catch_unwind(AssertUnwindSafe(|| fuzz_validate_stream_name(&name)));

    assert!(
        parse_result.is_ok(),
        "validate_stream_name panicked on input {:?}",
        name
    );

    let validation = parse_result.expect("panic checked above");

    if name.is_empty() {
        assert!(validation.is_err(), "empty stream name should be rejected");
    }

    if name.len() > max_name_bytes {
        assert!(
            validation.is_err(),
            "oversized stream name should be rejected: {} > {}",
            name.len(),
            max_name_bytes
        );
    }

    if name
        .chars()
        .any(|ch| matches!(ch, '\0' | '\r' | '\n' | '.'))
    {
        assert!(
            validation.is_err(),
            "stream name with NUL/CR/LF/dot should be rejected: {:?}",
            name
        );
    }

    if has_prohibited_chars(&name) {
        assert!(
            validation.is_err(),
            "stream name with prohibited characters should be rejected: {:?}",
            name
        );
    }

    if let Ok(()) = validation {
        assert!(!name.is_empty());
        assert!(name.len() <= max_name_bytes);
        assert!(!has_prohibited_chars(&name));
    }
});
