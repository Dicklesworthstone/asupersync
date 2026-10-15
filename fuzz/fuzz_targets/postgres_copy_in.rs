#![no_main]

use arbitrary::Arbitrary;
use asupersync::database::postgres::{
    FuzzCopyInEnd, FuzzCopyInSequence, PgError, fuzz_parse_copy_in_segments,
    fuzz_parse_copy_in_sequence,
};
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

const MAX_COPY_DATA_MESSAGES: usize = 16;
const MAX_COPY_DATA_BYTES: usize = 256;
const MAX_ERROR_BYTES: usize = 128;
const MAX_SPLIT_PATTERN_BYTES: usize = 64;
const MAX_POSTGRES_MESSAGE_LEN: i32 = 64 * 1024 * 1024;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    scenario: Scenario,
    chunks: Vec<Vec<u8>>,
    fail_message: Vec<u8>,
    malformed_length: MalformedLength,
    terminal: Terminal,
    trailing: Vec<u8>,
    split_pattern: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Scenario {
    MalformedCopyDataLength,
    EmptyCopyFail,
    CopyDoneBeforeData,
    ValidSequence,
    SegmentedValidSequence,
    SplitEveryByte,
    FrameHeaderBoundary,
    SegmentedMalformedLength,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MalformedLength {
    LessThanHeader,
    Negative,
    TooLarge,
    TooLong(u16),
    OneByteShort,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Terminal {
    Done,
    Fail,
}

#[derive(Debug)]
struct CopyInCase {
    scenario: Scenario,
    chunks: Vec<Vec<u8>>,
    fail_message: String,
    malformed_length: MalformedLength,
    terminal: Terminal,
    trailing: Vec<u8>,
    split_pattern: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum SplitPatternLabel {
    Unsplit,
    Arbitrary,
    EveryByte,
    FrameHeaderBoundary,
}

#[derive(Debug, Clone, Copy)]
enum ParserStateLabel {
    Complete,
    ProtocolError,
    IoError,
    OtherError,
}

#[derive(Debug)]
struct CopyInLabels {
    scenario: Scenario,
    split_pattern: SplitPatternLabel,
    frame_count: usize,
    payload_len: usize,
    parser_state: ParserStateLabel,
    error_kind: &'static str,
    panic_free: bool,
}

fn parser_state_label(result: &Result<FuzzCopyInSequence, PgError>) -> ParserStateLabel {
    match result {
        Ok(_) => ParserStateLabel::Complete,
        Err(PgError::Protocol(_)) => ParserStateLabel::ProtocolError,
        Err(PgError::Io(_)) => ParserStateLabel::IoError,
        Err(_) => ParserStateLabel::OtherError,
    }
}

fn error_kind_label(result: &Result<FuzzCopyInSequence, PgError>) -> &'static str {
    match result {
        Ok(_) => "none",
        Err(PgError::Protocol(_)) => "protocol",
        Err(PgError::Io(_)) => "io",
        Err(PgError::AuthenticationFailed(_)) => "authentication",
        Err(PgError::Server { .. }) => "server",
        Err(PgError::Cancelled(_)) => "cancelled",
        Err(PgError::ConnectionClosed) => "connection_closed",
        Err(PgError::ColumnNotFound(_)) => "column_not_found",
        Err(PgError::TypeConversion { .. }) => "type_conversion",
        Err(PgError::InvalidUrl(_)) => "invalid_url",
        Err(PgError::TlsRequired) => "tls_required",
        Err(PgError::Tls(_)) => "tls",
        Err(PgError::TransactionFinished) => "transaction_finished",
        Err(PgError::UnsupportedAuth(_)) => "unsupported_auth",
        Err(PgError::IsolationLevelMismatch { .. }) => "isolation_level_mismatch",
    }
}

fn expose_labels(labels: CopyInLabels) {
    black_box((
        labels.scenario,
        labels.split_pattern,
        labels.frame_count,
        labels.payload_len,
        labels.parser_state,
        labels.error_kind,
        labels.panic_free,
    ));
}

fn expose_result_labels(
    scenario: Scenario,
    split_pattern: SplitPatternLabel,
    frame_count: usize,
    payload_len: usize,
    result: &Result<FuzzCopyInSequence, PgError>,
) {
    expose_labels(CopyInLabels {
        scenario,
        split_pattern,
        frame_count,
        payload_len,
        parser_state: parser_state_label(result),
        error_kind: error_kind_label(result),
        panic_free: true,
    });
}

impl FuzzInput {
    fn into_case(self) -> CopyInCase {
        let chunks = self
            .chunks
            .into_iter()
            .take(MAX_COPY_DATA_MESSAGES)
            .map(|chunk| chunk.into_iter().take(MAX_COPY_DATA_BYTES).collect())
            .collect();
        let fail_message = sanitize_error_message(self.fail_message);
        let trailing = self
            .trailing
            .into_iter()
            .take(MAX_COPY_DATA_BYTES)
            .collect();
        let split_pattern = self
            .split_pattern
            .into_iter()
            .take(MAX_SPLIT_PATTERN_BYTES)
            .collect();

        CopyInCase {
            scenario: self.scenario,
            chunks,
            fail_message,
            malformed_length: self.malformed_length,
            terminal: self.terminal,
            trailing,
            split_pattern,
        }
    }
}

fn sanitize_error_message(bytes: Vec<u8>) -> String {
    bytes
        .into_iter()
        .filter(|&byte| byte != 0)
        .take(MAX_ERROR_BYTES)
        .map(|byte| char::from(1 + (byte % 0x7f)))
        .collect()
}

fn frame(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = i32::try_from(body.len() + 4).expect("bounded fuzz frame length fits i32");
    let mut out = Vec::with_capacity(1 + 4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn copy_data_frame(data: &[u8]) -> Vec<u8> {
    frame(b'd', data)
}

fn malformed_copy_data_frame(data: &[u8], mode: MalformedLength) -> Vec<u8> {
    let actual_len = i32::try_from(data.len() + 4).expect("bounded fuzz frame length fits i32");
    let declared_len = match mode {
        MalformedLength::LessThanHeader => 3,
        MalformedLength::Negative => -1,
        MalformedLength::TooLarge => MAX_POSTGRES_MESSAGE_LEN + 1,
        MalformedLength::TooLong(extra) => actual_len.saturating_add(i32::from(extra) + 1),
        MalformedLength::OneByteShort if actual_len > 4 => actual_len - 1,
        MalformedLength::OneByteShort => 3,
    };

    let mut out = Vec::with_capacity(1 + 4 + data.len());
    out.push(b'd');
    out.extend_from_slice(&declared_len.to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn copy_done_frame() -> Vec<u8> {
    frame(b'c', &[])
}

fn copy_fail_frame(message: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(message.len() + 1);
    body.extend_from_slice(message.as_bytes());
    body.push(0);
    frame(b'f', &body)
}

fn terminal_frame(terminal: Terminal, fail_message: &str) -> Vec<u8> {
    match terminal {
        Terminal::Done => copy_done_frame(),
        Terminal::Fail => copy_fail_frame(fail_message),
    }
}

fn valid_stream(chunks: &[Vec<u8>], terminal: Terminal, fail_message: &str) -> Vec<u8> {
    let mut stream = Vec::new();
    for chunk in chunks {
        stream.extend_from_slice(&copy_data_frame(chunk));
    }
    stream.extend_from_slice(&terminal_frame(terminal, fail_message));
    stream
}

fn valid_stream_with_frame_lengths(
    chunks: &[Vec<u8>],
    terminal: Terminal,
    fail_message: &str,
) -> (Vec<u8>, Vec<usize>) {
    let mut stream = Vec::new();
    let mut frame_lengths = Vec::with_capacity(chunks.len() + 1);

    for chunk in chunks {
        let frame = copy_data_frame(chunk);
        frame_lengths.push(frame.len());
        stream.extend_from_slice(&frame);
    }

    let terminal = terminal_frame(terminal, fail_message);
    frame_lengths.push(terminal.len());
    stream.extend_from_slice(&terminal);

    (stream, frame_lengths)
}

fn split_stream_at<'a>(stream: &'a [u8], offsets: &[usize]) -> Vec<&'a [u8]> {
    let mut segments = Vec::new();
    let mut start = 0usize;

    for &offset in offsets {
        let end = offset.min(stream.len());
        if end >= start {
            segments.push(&stream[start..end]);
            start = end;
        }
    }

    segments.push(&stream[start..]);
    segments
}

fn arbitrary_segments<'a>(stream: &'a [u8], split_pattern: &[u8]) -> Vec<&'a [u8]> {
    if split_pattern.is_empty() {
        return vec![stream];
    }

    let mut segments = Vec::new();
    let mut cursor = 0usize;

    for &byte in split_pattern {
        if cursor == stream.len() {
            segments.push(&stream[cursor..cursor]);
            continue;
        }

        let remaining = stream.len() - cursor;
        let step = usize::from(byte) % (remaining + 1);
        let next = cursor + step;
        segments.push(&stream[cursor..next]);
        cursor = next;
    }

    segments.push(&stream[cursor..]);
    segments
}

fn every_byte_segments(stream: &[u8]) -> Vec<&[u8]> {
    stream.chunks(1).collect()
}

fn frame_header_boundary_segments<'a>(stream: &'a [u8], frame_lengths: &[usize]) -> Vec<&'a [u8]> {
    let mut offsets = Vec::with_capacity(frame_lengths.len() * 3);
    let mut frame_start = 0usize;

    for &frame_len in frame_lengths {
        let frame_end = frame_start + frame_len;
        offsets.push(frame_start + 1);
        offsets.push(frame_start + 5);
        offsets.push(frame_end);
        frame_start = frame_end;
    }

    split_stream_at(stream, &offsets)
}

fn total_payload_len(chunks: &[Vec<u8>]) -> usize {
    chunks.iter().map(Vec::len).sum()
}

fn expected_sequence(
    chunks: Vec<Vec<u8>>,
    terminal: Terminal,
    fail_message: String,
) -> FuzzCopyInSequence {
    let end = match terminal {
        Terminal::Done => FuzzCopyInEnd::Done,
        Terminal::Fail => FuzzCopyInEnd::Fail(fail_message),
    };
    FuzzCopyInSequence {
        copy_data_chunks: chunks,
        end,
    }
}

fn assert_protocol_error(result: Result<FuzzCopyInSequence, PgError>) {
    match result {
        Err(PgError::Protocol(_)) => {}
        other => panic!("expected COPY IN protocol error, got {other:?}"),
    }
}

fn assert_segmented_equivalence(
    scenario: Scenario,
    stream: &[u8],
    segments: &[&[u8]],
    split_pattern: SplitPatternLabel,
    frame_count: usize,
    payload_len: usize,
) {
    let unsplit = fuzz_parse_copy_in_sequence(stream);
    let segmented = fuzz_parse_copy_in_segments(segments);
    expose_result_labels(
        scenario,
        split_pattern,
        frame_count,
        payload_len,
        &segmented,
    );

    match (unsplit, segmented) {
        (Ok(unsplit), Ok(segmented)) => assert_eq!(segmented, unsplit),
        (Err(PgError::Protocol(_)), Err(PgError::Protocol(_))) => {}
        (left, right) => panic!("segmented COPY IN parser diverged: {left:?} vs {right:?}"),
    }
}

fn exercise_malformed_copy_data_length(case: &CopyInCase) {
    let data = case.chunks.first().map_or(&[][..], Vec::as_slice);
    let mut stream = malformed_copy_data_frame(data, case.malformed_length);
    stream.extend_from_slice(&terminal_frame(case.terminal, &case.fail_message));
    let result = fuzz_parse_copy_in_sequence(&stream);
    expose_result_labels(
        case.scenario,
        SplitPatternLabel::Unsplit,
        2,
        data.len(),
        &result,
    );
    assert_protocol_error(result);
}

fn exercise_empty_copy_fail() {
    let stream = copy_fail_frame("");
    let result = fuzz_parse_copy_in_sequence(&stream);
    expose_result_labels(
        Scenario::EmptyCopyFail,
        SplitPatternLabel::Unsplit,
        1,
        0,
        &result,
    );
    let parsed = result.expect("empty CopyFail should decode");
    assert_eq!(
        parsed,
        FuzzCopyInSequence {
            copy_data_chunks: Vec::new(),
            end: FuzzCopyInEnd::Fail(String::new()),
        }
    );
}

fn exercise_copy_done_before_data() {
    let stream = copy_done_frame();
    let result = fuzz_parse_copy_in_sequence(&stream);
    expose_result_labels(
        Scenario::CopyDoneBeforeData,
        SplitPatternLabel::Unsplit,
        1,
        0,
        &result,
    );
    let parsed = result.expect("early CopyDone should decode");
    assert_eq!(
        parsed,
        FuzzCopyInSequence {
            copy_data_chunks: Vec::new(),
            end: FuzzCopyInEnd::Done,
        }
    );
}

fn exercise_valid_sequence(case: CopyInCase) {
    let stream = valid_stream(&case.chunks, case.terminal, &case.fail_message);
    let result = fuzz_parse_copy_in_sequence(&stream);
    expose_result_labels(
        case.scenario,
        SplitPatternLabel::Unsplit,
        case.chunks.len() + 1,
        total_payload_len(&case.chunks),
        &result,
    );
    let parsed = result.expect("valid COPY IN stream should decode");
    assert_eq!(
        parsed,
        expected_sequence(case.chunks, case.terminal, case.fail_message)
    );

    if !case.trailing.is_empty() {
        let mut with_trailing = stream;
        with_trailing.extend_from_slice(&case.trailing);
        assert_protocol_error(fuzz_parse_copy_in_sequence(&with_trailing));
    }
}

fn exercise_segmented_valid_sequence(case: CopyInCase) {
    let (stream, frame_lengths) =
        valid_stream_with_frame_lengths(&case.chunks, case.terminal, &case.fail_message);
    let segments = arbitrary_segments(&stream, &case.split_pattern);
    assert_segmented_equivalence(
        case.scenario,
        &stream,
        &segments,
        SplitPatternLabel::Arbitrary,
        frame_lengths.len(),
        total_payload_len(&case.chunks),
    );
}

fn exercise_split_every_byte(case: CopyInCase) {
    let (stream, frame_lengths) =
        valid_stream_with_frame_lengths(&case.chunks, case.terminal, &case.fail_message);
    let segments = every_byte_segments(&stream);
    assert_segmented_equivalence(
        case.scenario,
        &stream,
        &segments,
        SplitPatternLabel::EveryByte,
        frame_lengths.len(),
        total_payload_len(&case.chunks),
    );
}

fn exercise_frame_header_boundary(case: CopyInCase) {
    let (stream, frame_lengths) =
        valid_stream_with_frame_lengths(&case.chunks, case.terminal, &case.fail_message);
    let segments = frame_header_boundary_segments(&stream, &frame_lengths);
    assert_segmented_equivalence(
        case.scenario,
        &stream,
        &segments,
        SplitPatternLabel::FrameHeaderBoundary,
        frame_lengths.len(),
        total_payload_len(&case.chunks),
    );
}

fn exercise_segmented_malformed_length(case: &CopyInCase) {
    let data = case.chunks.first().map_or(&[][..], Vec::as_slice);
    let mut stream = malformed_copy_data_frame(data, case.malformed_length);
    stream.extend_from_slice(&terminal_frame(case.terminal, &case.fail_message));
    let segments = arbitrary_segments(&stream, &case.split_pattern);
    assert_segmented_equivalence(
        case.scenario,
        &stream,
        &segments,
        SplitPatternLabel::Arbitrary,
        2,
        data.len(),
    );
}

fn exercise_case(input: FuzzInput) {
    let case = input.into_case();
    match case.scenario {
        Scenario::MalformedCopyDataLength => exercise_malformed_copy_data_length(&case),
        Scenario::EmptyCopyFail => exercise_empty_copy_fail(),
        Scenario::CopyDoneBeforeData => exercise_copy_done_before_data(),
        Scenario::ValidSequence => exercise_valid_sequence(case),
        Scenario::SegmentedValidSequence => exercise_segmented_valid_sequence(case),
        Scenario::SplitEveryByte => exercise_split_every_byte(case),
        Scenario::FrameHeaderBoundary => exercise_frame_header_boundary(case),
        Scenario::SegmentedMalformedLength => exercise_segmented_malformed_length(&case),
    }
}

fuzz_target!(|input: FuzzInput| {
    exercise_case(input);
});
