#![no_main]

use arbitrary::Arbitrary;
use asupersync::database::postgres::{
    FuzzCopyInEnd, FuzzCopyInSequence, PgError, fuzz_parse_copy_in_sequence,
};
use libfuzzer_sys::fuzz_target;

const MAX_COPY_DATA_MESSAGES: usize = 16;
const MAX_COPY_DATA_BYTES: usize = 256;
const MAX_ERROR_BYTES: usize = 128;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    scenario: Scenario,
    chunks: Vec<Vec<u8>>,
    fail_message: Vec<u8>,
    malformed_length: MalformedLength,
    terminal: Terminal,
    trailing: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Scenario {
    MalformedCopyDataLength,
    EmptyCopyFail,
    CopyDoneBeforeData,
    ValidSequence,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MalformedLength {
    LessThanHeader,
    Negative,
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

        CopyInCase {
            scenario: self.scenario,
            chunks,
            fail_message,
            malformed_length: self.malformed_length,
            terminal: self.terminal,
            trailing,
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

fn exercise_malformed_copy_data_length(case: &CopyInCase) {
    let data = case.chunks.first().map_or(&[][..], Vec::as_slice);
    let mut stream = malformed_copy_data_frame(data, case.malformed_length);
    stream.extend_from_slice(&terminal_frame(case.terminal, &case.fail_message));
    assert_protocol_error(fuzz_parse_copy_in_sequence(&stream));
}

fn exercise_empty_copy_fail() {
    let stream = copy_fail_frame("");
    let parsed = fuzz_parse_copy_in_sequence(&stream).expect("empty CopyFail should decode");
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
    let parsed = fuzz_parse_copy_in_sequence(&stream).expect("early CopyDone should decode");
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
    let parsed = fuzz_parse_copy_in_sequence(&stream).expect("valid COPY IN stream should decode");
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

fn exercise_case(input: FuzzInput) {
    let case = input.into_case();
    match case.scenario {
        Scenario::MalformedCopyDataLength => exercise_malformed_copy_data_length(&case),
        Scenario::EmptyCopyFail => exercise_empty_copy_fail(),
        Scenario::CopyDoneBeforeData => exercise_copy_done_before_data(),
        Scenario::ValidSequence => exercise_valid_sequence(case),
    }
}

fuzz_target!(|input: FuzzInput| {
    exercise_case(input);
});
