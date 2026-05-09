#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::nats::{
    fuzz_nats_subject_max_bytes, fuzz_validate_nats_publish_subject,
};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_FUZZ_SUBJECT_BYTES: usize = 4 * 1024 + 64;

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
    InsertCrLf,
    OversizedAscii,
    EmptyToken,
    Wildcard,
}

impl SubjectNameInput {
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
                insert_char(&mut subject, insertion, self.mutation);
                subject
            }
        }
    }
}

fn insert_char(subject: &mut String, insertion: usize, mutation: SubjectMutation) {
    match mutation {
        SubjectMutation::RawLossy | SubjectMutation::OversizedAscii => {}
        SubjectMutation::InsertNull => insert_str_at_char(subject, insertion, "\0"),
        SubjectMutation::InsertCr => insert_str_at_char(subject, insertion, "\r"),
        SubjectMutation::InsertLf => insert_str_at_char(subject, insertion, "\n"),
        SubjectMutation::InsertCrLf => insert_str_at_char(subject, insertion, "\r\n"),
        SubjectMutation::EmptyToken => insert_str_at_char(subject, insertion, ".."),
        SubjectMutation::Wildcard => insert_str_at_char(subject, insertion, ".*"),
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

fn has_forbidden_control_or_whitespace(subject: &str) -> bool {
    subject
        .chars()
        .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
}

fn is_valid_publish_token(token: &str) -> bool {
    !token.is_empty()
        && !token.contains('*')
        && !token.contains('>')
        && !has_forbidden_control_or_whitespace(token)
}

fn model_accepts_publish_subject(subject: &str, max_subject_bytes: usize) -> bool {
    if subject.is_empty() || subject.len() > max_subject_bytes {
        return false;
    }

    subject.split('.').all(is_valid_publish_token)
}

fuzz_target!(|input: SubjectNameInput| {
    let max_subject_bytes = fuzz_nats_subject_max_bytes();
    let subject = input.materialize(max_subject_bytes);
    let parse_result = catch_unwind(AssertUnwindSafe(|| {
        fuzz_validate_nats_publish_subject(&subject)
    }));

    assert!(
        parse_result.is_ok(),
        "validate_nats_publish_subject panicked on input {:?}",
        subject
    );

    let validation = parse_result.expect("panic checked above");
    let modeled_valid = model_accepts_publish_subject(&subject, max_subject_bytes);
    assert_eq!(
        validation.is_ok(),
        modeled_valid,
        "validator/model mismatch for subject {:?}",
        subject
    );

    if subject.len() > max_subject_bytes {
        assert!(
            validation.is_err(),
            "oversized subject should be rejected: {} > {}",
            subject.len(),
            max_subject_bytes
        );
    }

    if has_forbidden_control_or_whitespace(&subject) {
        assert!(
            validation.is_err(),
            "subject with whitespace/control characters should be rejected: {:?}",
            subject
        );
    }

    if let Ok(()) = validation {
        assert!(subject.len() <= max_subject_bytes);
        assert!(!has_forbidden_control_or_whitespace(&subject));
        assert!(!subject.is_empty());
        assert!(subject.split('.').all(is_valid_publish_token));
    }
});
