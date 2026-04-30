#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{
    DiscardPolicy, RetentionPolicy, StorageType, StreamConfig, fuzz_stream_name_max_bytes,
    fuzz_stream_subject_max_bytes, fuzz_validate_stream_config,
};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

const MAX_RAW_NAME_BYTES: usize = 320;
const MAX_RAW_SUBJECT_BYTES: usize = 512;
const MAX_SUBJECTS: usize = 4;

#[derive(Arbitrary, Debug, Clone)]
struct StreamConfigInput {
    name_raw: Vec<u8>,
    name_mode: NameMode,
    subjects_raw: Vec<Vec<u8>>,
    subject_mode: SubjectMode,
    retention: RetentionMode,
    storage: StorageMode,
    discard: DiscardMode,
    max_msgs: Option<i64>,
    max_bytes: Option<i64>,
    max_age_millis: Option<u32>,
    max_msg_size: Option<i32>,
    replicas: u8,
    duplicate_window_millis: Option<u32>,
    extra: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum NameMode {
    ValidAscii,
    RawLossy,
    Empty,
    OversizedAscii,
    InsertDot,
    InsertSpace,
    InsertNull,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum SubjectMode {
    ValidLiteral,
    ValidSingleWildcard,
    ValidTailWildcard,
    RawLossy,
    EmptyToken,
    InvalidWildcardPlacement,
    OversizedAscii,
    CrLfInjection,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum RetentionMode {
    Limits,
    Interest,
    WorkQueue,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum StorageMode {
    File,
    Memory,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum DiscardMode {
    Old,
    New,
}

impl StreamConfigInput {
    fn materialize(&self) -> StreamConfig {
        let mut config = StreamConfig::new(self.materialize_name());
        config.subjects = self.materialize_subjects();
        config.retention = self.retention.into();
        config.storage = self.storage.into();
        config.discard = self.discard.into();
        config.max_msgs = self.max_msgs;
        config.max_bytes = self.max_bytes;
        config.max_age = self
            .max_age_millis
            .map(|millis| Duration::from_millis(u64::from(millis)));
        config.max_msg_size = self.max_msg_size;
        config.replicas = u32::from(self.replicas);
        config.duplicate_window = self
            .duplicate_window_millis
            .map(|millis| Duration::from_millis(u64::from(millis)));
        config
    }

    fn materialize_name(&self) -> String {
        let max_name_bytes = fuzz_stream_name_max_bytes();
        match self.name_mode {
            NameMode::ValidAscii => valid_name_from_bytes(&self.name_raw, 16),
            NameMode::RawLossy => String::from_utf8_lossy(
                &self.name_raw[..self.name_raw.len().min(MAX_RAW_NAME_BYTES)],
            )
            .into_owned(),
            NameMode::Empty => String::new(),
            NameMode::OversizedAscii => "A".repeat(max_name_bytes + usize::from(self.extra) + 1),
            NameMode::InsertDot => format!("{}.", valid_name_from_bytes(&self.name_raw, 15)),
            NameMode::InsertSpace => format!("{} ", valid_name_from_bytes(&self.name_raw, 15)),
            NameMode::InsertNull => format!("{}\0", valid_name_from_bytes(&self.name_raw, 15)),
        }
    }

    fn materialize_subjects(&self) -> Vec<String> {
        self.subjects_raw
            .iter()
            .take(MAX_SUBJECTS)
            .map(|raw| materialize_subject(raw, self.subject_mode, self.extra))
            .collect()
    }
}

impl From<RetentionMode> for RetentionPolicy {
    fn from(value: RetentionMode) -> Self {
        match value {
            RetentionMode::Limits => Self::Limits,
            RetentionMode::Interest => Self::Interest,
            RetentionMode::WorkQueue => Self::WorkQueue,
        }
    }
}

impl From<StorageMode> for StorageType {
    fn from(value: StorageMode) -> Self {
        match value {
            StorageMode::File => Self::File,
            StorageMode::Memory => Self::Memory,
        }
    }
}

impl From<DiscardMode> for DiscardPolicy {
    fn from(value: DiscardMode) -> Self {
        match value {
            DiscardMode::Old => Self::Old,
            DiscardMode::New => Self::New,
        }
    }
}

fn valid_name_from_bytes(raw: &[u8], max_len: usize) -> String {
    let len = raw.len().clamp(1, max_len);
    raw.iter()
        .copied()
        .chain(std::iter::repeat(b'A'))
        .take(len)
        .map(name_char)
        .collect()
}

fn name_char(byte: u8) -> char {
    match byte % 64 {
        0..=25 => char::from(b'A' + (byte % 26)),
        26..=51 => char::from(b'a' + (byte % 26)),
        52..=61 => char::from(b'0' + (byte % 10)),
        62 => '-',
        _ => '_',
    }
}

fn materialize_subject(raw: &[u8], mode: SubjectMode, extra: u8) -> String {
    let max_subject_bytes = fuzz_stream_subject_max_bytes();
    let literal = valid_subject_token(raw, 12);
    let alternate = valid_subject_token(&raw[raw.len() / 2..], 8);

    match mode {
        SubjectMode::ValidLiteral => format!("{literal}.{alternate}"),
        SubjectMode::ValidSingleWildcard => format!("{literal}.*"),
        SubjectMode::ValidTailWildcard => format!("{literal}.>"),
        SubjectMode::RawLossy => {
            String::from_utf8_lossy(&raw[..raw.len().min(MAX_RAW_SUBJECT_BYTES)]).into_owned()
        }
        SubjectMode::EmptyToken => format!("{literal}..{alternate}"),
        SubjectMode::InvalidWildcardPlacement => format!("{literal}.>.{alternate}"),
        SubjectMode::OversizedAscii => {
            format!(
                "{}.{literal}",
                "a".repeat(max_subject_bytes + usize::from(extra) + 1)
            )
        }
        SubjectMode::CrLfInjection => format!("{literal}\r\nPUB evil 0\r\n"),
    }
}

fn valid_subject_token(raw: &[u8], max_len: usize) -> String {
    let len = raw.len().clamp(1, max_len);
    raw.iter()
        .copied()
        .chain(std::iter::repeat(b'a'))
        .take(len)
        .map(|byte| match byte % 63 {
            0..=25 => char::from(b'a' + (byte % 26)),
            26..=51 => char::from(b'A' + (byte % 26)),
            52..=61 => char::from(b'0' + (byte % 10)),
            _ => '_',
        })
        .collect()
}

fn invalid_name(name: &str) -> bool {
    name.is_empty()
        || name.len() > fuzz_stream_name_max_bytes()
        || name
            .chars()
            .any(|ch| !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_'))
}

fn invalid_subject(subject: &str) -> bool {
    if subject.is_empty() || subject.len() > fuzz_stream_subject_max_bytes() {
        return true;
    }

    let tokens: Vec<_> = subject.split('.').collect();
    let token_count = tokens.len();
    if tokens.iter().any(|token| {
        token.is_empty()
            || token
                .chars()
                .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    }) {
        return true;
    }

    for (index, token) in tokens.into_iter().enumerate() {
        match token {
            "*" => {}
            ">" if index + 1 == token_count => {}
            ">" => return true,
            _ if token.contains('*') || token.contains('>') => return true,
            _ => {}
        }
    }

    false
}

fuzz_target!(|input: StreamConfigInput| {
    let config = input.materialize();
    let validation_result = catch_unwind(AssertUnwindSafe(|| fuzz_validate_stream_config(&config)));

    assert!(
        validation_result.is_ok(),
        "fuzz_validate_stream_config panicked on {:?}",
        config
    );

    let mut expected_error_markers = Vec::new();
    if invalid_name(&config.name) {
        expected_error_markers.push(String::from("stream name"));
    }
    for (index, subject) in config.subjects.iter().enumerate() {
        if invalid_subject(subject) {
            expected_error_markers.push(format!("subjects[{index}]"));
        }
    }
    if config.max_msgs.is_some_and(|value| value < 0) {
        expected_error_markers.push(String::from("max_msgs"));
    }
    if config.max_bytes.is_some_and(|value| value < 0) {
        expected_error_markers.push(String::from("max_bytes"));
    }
    if config.max_msg_size.is_some_and(|value| value < 0) {
        expected_error_markers.push(String::from("max_msg_size"));
    }
    if config.replicas == 0 {
        expected_error_markers.push(String::from("replicas"));
    }

    match validation_result.expect("panic checked above") {
        Ok(json) => {
            assert!(
                expected_error_markers.is_empty(),
                "validator accepted config that should fail: {:?}",
                config
            );
            assert!(json.starts_with('{'));
            assert!(json.contains("\"name\""));
            assert!(!json.contains("{,"));
        }
        Err(err) => {
            assert!(
                !err.trim().is_empty(),
                "validator returned an empty error message for {:?}",
                config
            );
            assert!(
                !expected_error_markers.is_empty(),
                "validator rejected apparently valid config {:?}: {}",
                config,
                err
            );
            assert!(
                expected_error_markers
                    .iter()
                    .any(|marker| err.contains(marker)),
                "expected one of {:?} in validator error {:?} for {:?}",
                expected_error_markers,
                err,
                config
            );
        }
    }
});
