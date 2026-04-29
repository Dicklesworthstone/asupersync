#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::nats::{fuzz_nats_subject_max_bytes, fuzz_parse_nats_publish_subject};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_FUZZ_SUBJECT_BYTES: usize = 4 * 1024 + 64;

#[derive(Arbitrary, Debug, Clone)]
struct SubjectParserInput {
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
    InsertTab,
    EmptyToken,
    TrailingDot,
    SingleWildcard,
    TailWildcard,
    OversizedAscii,
}

impl SubjectParserInput {
    fn materialize(&self, max_subject_bytes: usize) -> String {
        match self.mutation {
            SubjectMutation::OversizedAscii => {
                let oversize = max_subject_bytes + usize::from(self.extra) + 1;
                "a".repeat(oversize)
            }
            _ => {
                let mut subject = String::from_utf8_lossy(
                    &self.raw[..self.raw.len().min(MAX_FUZZ_SUBJECT_BYTES)],
                )
                .into_owned();
                let insertion = usize::from(self.extra) % (subject.chars().count() + 1);
                insert_fragment(&mut subject, insertion, self.mutation);
                subject
            }
        }
    }
}

fn insert_fragment(subject: &mut String, insertion: usize, mutation: SubjectMutation) {
    match mutation {
        SubjectMutation::RawLossy | SubjectMutation::OversizedAscii => {}
        SubjectMutation::InsertNull => insert_str_at_char(subject, insertion, "\0"),
        SubjectMutation::InsertCr => insert_str_at_char(subject, insertion, "\r"),
        SubjectMutation::InsertLf => insert_str_at_char(subject, insertion, "\n"),
        SubjectMutation::InsertTab => insert_str_at_char(subject, insertion, "\t"),
        SubjectMutation::EmptyToken => insert_str_at_char(subject, insertion, ".."),
        SubjectMutation::TrailingDot => insert_str_at_char(subject, insertion, "."),
        SubjectMutation::SingleWildcard => insert_str_at_char(subject, insertion, ".*"),
        SubjectMutation::TailWildcard => insert_str_at_char(subject, insertion, ".>"),
    }
}

fn insert_str_at_char(subject: &mut String, insertion: usize, value: &str) {
    let byte_index = subject
        .char_indices()
        .nth(insertion)
        .map(|(index, _)| index)
        .unwrap_or(subject.len());
    subject.insert_str(byte_index, value);
}

fn model_parse_publish_subject(subject: &str, max_subject_bytes: usize) -> Option<Vec<&str>> {
    if subject.is_empty() || subject.len() > max_subject_bytes {
        return None;
    }

    let tokens: Vec<_> = subject.split('.').collect();
    if tokens.iter().any(|token| {
        token.is_empty()
            || token.contains('*')
            || token.contains('>')
            || token
                .chars()
                .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    }) {
        return None;
    }

    Some(tokens)
}

fuzz_target!(|input: SubjectParserInput| {
    let max_subject_bytes = fuzz_nats_subject_max_bytes();
    let subject = input.materialize(max_subject_bytes);
    let parse_result = catch_unwind(AssertUnwindSafe(|| {
        fuzz_parse_nats_publish_subject(&subject)
    }));

    assert!(
        parse_result.is_ok(),
        "parse_publish_subject panicked on input {:?}",
        subject
    );

    let parsed = parse_result.expect("panic checked above");
    let modeled = model_parse_publish_subject(&subject, max_subject_bytes).map(|tokens| {
        tokens
            .into_iter()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>()
    });

    assert_eq!(
        parsed, modeled,
        "parser/model mismatch for subject {:?}",
        subject
    );

    if let Some(tokens) = parsed {
        assert!(!subject.is_empty());
        assert!(subject.len() <= max_subject_bytes);
        assert_eq!(tokens.join("."), subject);
        assert!(tokens.iter().all(|token| {
            !token.is_empty()
                && !token.contains('*')
                && !token.contains('>')
                && !token
                    .chars()
                    .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
        }));
    }
});
