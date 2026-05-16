#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::nats::{
    fuzz_nats_subject_max_bytes, fuzz_parse_nats_publish_subject,
    fuzz_validate_nats_publish_subject,
};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

const MAX_FUZZ_SUBJECT_BYTES: usize = 4 * 1024 + 64;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

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

fn assert_publish_subject_rejection(subject: &str, expected: &str) {
    let error = fuzz_validate_nats_publish_subject(subject)
        .expect_err("fixed NATS publish subject canary should be rejected");

    assert_eq!(
        error, expected,
        "NATS publish subject diagnostic drift for {subject:?}",
    );
    assert!(
        !error.trim().is_empty(),
        "NATS publish subject rejection should expose a diagnostic"
    );
    assert!(
        error.len() <= 512,
        "NATS publish subject rejection diagnostic should stay bounded: {} bytes",
        error.len()
    );
}

fn assert_fixed_publish_subject_error_canaries() {
    assert_publish_subject_rejection("", "NATS protocol error: subject must not be empty");
    assert_publish_subject_rejection(
        "orders created",
        "NATS protocol error: subject contains illegal whitespace/control characters",
    );
    assert_publish_subject_rejection(
        "orders.\n.created",
        "NATS protocol error: subject contains illegal whitespace/control characters",
    );
    assert_publish_subject_rejection(
        "orders.*.created",
        "NATS protocol error: subject must be a fully specified NATS subject without wildcards or empty tokens",
    );
    assert_publish_subject_rejection(
        "orders..created",
        "NATS protocol error: subject must be a fully specified NATS subject without wildcards or empty tokens",
    );
    assert_publish_subject_rejection(
        "orders.>",
        "NATS protocol error: subject must be a fully specified NATS subject without wildcards or empty tokens",
    );

    let max_subject_bytes = fuzz_nats_subject_max_bytes();
    let oversized = "a".repeat(max_subject_bytes + 1);
    assert_publish_subject_rejection(
        &oversized,
        &format!(
            "NATS protocol error: subject exceeds the {max_subject_bytes}-byte NATS subject bound"
        ),
    );
}

fuzz_target!(|input: SubjectParserInput| {
    FIXED_CANARIES.get_or_init(assert_fixed_publish_subject_error_canaries);

    let max_subject_bytes = fuzz_nats_subject_max_bytes();
    let subject = input.materialize(max_subject_bytes);
    let parse_result = catch_unwind(AssertUnwindSafe(|| {
        fuzz_parse_nats_publish_subject(&subject)
    }));
    let validation_result = catch_unwind(AssertUnwindSafe(|| {
        fuzz_validate_nats_publish_subject(&subject)
    }));

    let parsed = match parse_result {
        Ok(parsed) => parsed,
        Err(_) => {
            panic!("parse_publish_subject panicked on input {:?}", subject);
        }
    };

    let validation = match validation_result {
        Ok(validation) => validation,
        Err(_) => {
            panic!(
                "validate_nats_publish_subject panicked on input {:?}",
                subject
            );
        }
    };

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

    match (&parsed, &validation) {
        (Some(_), Ok(())) => {}
        (Some(_), Err(error)) => {
            panic!("parser accepted subject but validator rejected it: {error}");
        }
        (None, Ok(())) => {
            panic!("parser rejected subject but validator accepted it: {subject:?}");
        }
        (None, Err(error)) => {
            assert!(
                !error.trim().is_empty(),
                "publish-subject rejection should expose a diagnostic"
            );
            assert!(
                error.len() <= 512,
                "publish-subject rejection diagnostic should stay bounded: {} bytes",
                error.len()
            );
        }
    }

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
