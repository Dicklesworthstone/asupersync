//! PostgreSQL COPY FROM error handling audit tests.
//!
//! These tests keep the former COPY FROM audit panic covered by the production
//! wire path. PostgreSQL validates CSV/text row shape server-side; the client
//! must stream rows, send `CopyDone`, preserve the backend's structured
//! `ErrorResponse` diagnostics, and resynchronize to `ReadyForQuery`.

#![cfg(test)]

use super::{
    DEFAULT_MAX_PREPARED_STATEMENTS, DEFAULT_MAX_RESULT_ROWS, Format, FrontendMessage,
    FuzzCopyInEnd, PgConnection, PgConnectionInner, PgError, PgErrorDiagnostic, PgStream,
    PreparedStatementCache, fuzz_parse_copy_in_sequence, test_cancel_target,
    test_pg_connect_options,
};
use crate::Cx;
use crate::types::Outcome;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};

struct CopyErrorProbe {
    code: String,
    message: String,
    detail: Option<String>,
    hint: Option<String>,
    diagnostic: PgErrorDiagnostic,
    written_chunks: Vec<Vec<u8>>,
}

fn run<F: std::future::Future>(future: F) -> F::Output {
    futures_lite::future::block_on(future)
}

fn make_test_connection_with_peer() -> (PgConnection, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("read test listener addr");
    let std_stream = std::net::TcpStream::connect(addr).expect("connect test stream");
    let (peer_stream, _) = listener.accept().expect("accept test stream");
    let stream = crate::net::TcpStream::from_std(std_stream).expect("convert test stream");

    (
        PgConnection {
            inner: PgConnectionInner {
                stream: PgStream::Plain(stream),
                options: test_pg_connect_options(),
                process_id: 0,
                secret_key: 0,
                cancel_target: test_cancel_target(),
                parameters: BTreeMap::new(),
                transaction_status: b'I',
                closed: false,
                explicitly_closed: false,
                needs_rollback: false,
                needs_discard: false,
                subscribed_channels: BTreeSet::new(),
                next_stmt_id: 0,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
                prepared_cache: PreparedStatementCache::new(DEFAULT_MAX_PREPARED_STATEMENTS),
                deallocate_retry_queue: VecDeque::new(),
                consecutive_deallocate_failures: 0,
                unhealthy: false,
            },
        },
        peer_stream,
    )
}

fn backend_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = i32::try_from(body.len() + 4).expect("test backend message length fits");
    let mut msg = Vec::with_capacity(1 + 4 + body.len());
    msg.push(msg_type);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(body);
    msg
}

fn copy_in_response_message(overall_format: Format, column_formats: &[Format]) -> Vec<u8> {
    let mut body = Vec::with_capacity(3 + column_formats.len() * 2);
    body.push(overall_format as u8);
    body.extend_from_slice(
        &i16::try_from(column_formats.len())
            .expect("test column count fits")
            .to_be_bytes(),
    );
    for format in column_formats {
        body.extend_from_slice(&(*format as i16).to_be_bytes());
    }
    backend_message(b'G', &body)
}

fn ready_for_query(status: u8) -> Vec<u8> {
    backend_message(b'Z', &[status])
}

fn error_response_message(code: &str, message: &str, fields: &[(u8, &str)]) -> Vec<u8> {
    let extra_len: usize = fields.iter().map(|(_, value)| value.len() + 2).sum();
    let mut body = Vec::with_capacity(code.len() + message.len() + extra_len + 5);
    body.push(b'C');
    body.extend_from_slice(code.as_bytes());
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message.as_bytes());
    body.push(0);
    for (field, value) in fields {
        body.push(*field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    backend_message(b'E', &body)
}

fn frontend_frame_len(data: &[u8], offset: usize) -> usize {
    let len = i32::from_be_bytes([
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
    ]);
    1 + usize::try_from(len).expect("frontend length is non-negative")
}

fn read_until_contains(peer: &mut std::net::TcpStream, needle: &[u8]) -> Vec<u8> {
    peer.set_read_timeout(Some(std::time::Duration::from_millis(200)))
        .expect("set read timeout");

    let mut seen = Vec::new();
    loop {
        let mut chunk = [0u8; 256];
        match peer.read(&mut chunk) {
            Ok(0) => panic!(
                "peer closed before client wrote {:?}; saw {:?}",
                String::from_utf8_lossy(needle),
                seen
            ),
            Ok(n) => {
                seen.extend_from_slice(&chunk[..n]);
                if seen.windows(needle.len()).any(|window| window == needle) {
                    return seen;
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                panic!(
                    "timed out waiting for client bytes {:?}; saw {:?}",
                    String::from_utf8_lossy(needle),
                    seen
                );
            }
            Err(err) => panic!("read client bytes: {err}"),
        }
    }
}

fn copy_from_chunks_with_backend_error(
    sql: &str,
    chunks: Vec<&'static [u8]>,
    code: &str,
    message: &str,
    fields: &[(u8, &str)],
) -> CopyErrorProbe {
    let (mut conn, mut peer) = make_test_connection_with_peer();
    peer.write_all(&copy_in_response_message(
        Format::Text,
        &[Format::Text, Format::Text, Format::Text],
    ))
    .expect("write CopyInResponse");
    peer.write_all(&error_response_message(code, message, fields))
        .expect("write ErrorResponse");
    peer.write_all(&ready_for_query(b'I'))
        .expect("write ReadyForQuery");

    let cx = Cx::for_testing();
    let chunks: Vec<Result<&[u8], PgError>> = chunks.into_iter().map(Ok).collect();
    let err = match run(conn.copy_from_chunks(&cx, sql, chunks)) {
        Outcome::Err(PgError::Server {
            code,
            message,
            detail,
            hint,
            diagnostic,
        }) => CopyErrorProbe {
            code,
            message,
            detail,
            hint,
            diagnostic,
            written_chunks: Vec::new(),
        },
        other => panic!("expected structured backend COPY error, got {other:?}"),
    };

    assert!(!conn.inner.closed, "COPY error drain should resynchronize");
    assert_eq!(conn.inner.transaction_status, b'I');

    let written = read_until_contains(&mut peer, &[FrontendMessage::CopyDone as u8, 0, 0, 0, 4]);
    assert_eq!(written[0], FrontendMessage::Query as u8);
    let copy_offset = frontend_frame_len(&written, 0);
    let parsed = fuzz_parse_copy_in_sequence(&written[copy_offset..]).expect("COPY IN sequence");
    assert_eq!(parsed.end, FuzzCopyInEnd::Done);

    CopyErrorProbe {
        written_chunks: parsed.copy_data_chunks,
        ..err
    }
}

/// AUDIT: malformed COPY rows preserve backend row diagnostics.
#[test]
fn audit_copy_from_malformed_row_error_handling() {
    super::init_test("audit_copy_from_malformed_row_error_handling");

    let probe = copy_from_chunks_with_backend_error(
        "COPY users FROM STDIN WITH (FORMAT text)",
        vec![
            b"1\tJohn\tjohn@example.com\n",
            b"2\tJane\n",
            b"3\tBob\tbob@example.com\n",
        ],
        "22P04",
        "missing data for column \"email\"",
        &[
            (b'S', "ERROR"),
            (b'D', "Row contains too few columns."),
            (b'W', "COPY users, line 2: \"2\tJane\""),
        ],
    );

    assert_eq!(probe.code, "22P04");
    assert_eq!(probe.message, "missing data for column \"email\"");
    assert_eq!(
        probe.detail.as_deref(),
        Some("Row contains too few columns.")
    );
    assert_eq!(
        probe.diagnostic.where_context.as_deref(),
        Some("COPY users, line 2: \"2\tJane\"")
    );
    assert_eq!(
        probe.written_chunks,
        vec![
            b"1\tJohn\tjohn@example.com\n".to_vec(),
            b"2\tJane\n".to_vec(),
            b"3\tBob\tbob@example.com\n".to_vec()
        ]
    );

    crate::test_complete!("audit_copy_from_malformed_row_error_handling");
}

/// AUDIT: row position diagnostics remain exact and actionable.
#[test]
fn audit_copy_from_row_position_accuracy() {
    super::init_test("audit_copy_from_row_position_accuracy");

    let probe = copy_from_chunks_with_backend_error(
        "COPY users FROM STDIN WITH (FORMAT csv)",
        vec![
            b"id,name,email\n",
            b"1,John,john@example.com\n",
            b"2,Jane,not-an-email\n",
        ],
        "22P02",
        "invalid input syntax for type email",
        &[
            (b'S', "ERROR"),
            (b'D', "Input value violates the email parser."),
            (b'W', "COPY users, line 3, column email: \"not-an-email\""),
        ],
    );

    assert_eq!(probe.code, "22P02");
    let where_context = probe.diagnostic.where_context.as_deref().unwrap_or("");
    assert!(where_context.contains("line 3"), "got: {where_context}");
    assert!(
        where_context.contains("column email"),
        "got: {where_context}"
    );
    assert!(
        where_context.contains("not-an-email"),
        "got: {where_context}"
    );

    crate::test_complete!("audit_copy_from_row_position_accuracy");
}

/// AUDIT: backend column-count validation is exposed as a structured error.
#[test]
fn audit_copy_from_column_count_validation() {
    super::init_test("audit_copy_from_column_count_validation");

    let probe = copy_from_chunks_with_backend_error(
        "COPY users(id, name, email) FROM STDIN WITH (FORMAT csv)",
        vec![b"1,John,john@example.com\n", b"2,Jane\n"],
        "22P04",
        "missing data for column \"email\"",
        &[
            (b'S', "ERROR"),
            (b'D', "Row contains 2 columns but COPY expected 3."),
            (b'n', "email"),
            (b'W', "COPY users, line 2, column email: \"Jane\""),
        ],
    );

    assert_eq!(probe.code, "22P04");
    assert_eq!(
        probe.detail.as_deref(),
        Some("Row contains 2 columns but COPY expected 3.")
    );
    assert_eq!(probe.diagnostic.column_name.as_deref(), Some("email"));
    assert_eq!(
        probe.diagnostic.where_context.as_deref(),
        Some("COPY users, line 2, column email: \"Jane\"")
    );

    crate::test_complete!("audit_copy_from_column_count_validation");
}

/// AUDIT: PostgreSQL diagnostic fields are preserved for debugging.
#[test]
fn audit_copy_from_error_message_structure() {
    super::init_test("audit_copy_from_error_message_structure");

    let probe = copy_from_chunks_with_backend_error(
        "COPY users FROM STDIN WITH (FORMAT csv)",
        vec![b"1,John,\xff\n"],
        "22021",
        "invalid byte sequence for encoding \"UTF8\"",
        &[
            (b'S', "ERROR"),
            (b'D', "The byte sequence is not valid UTF-8."),
            (b'H', "Use valid UTF-8 input for text COPY streams."),
            (b'n', "email"),
            (b'W', "COPY users, line 1, column email"),
            (b'R', "CopyReadLineText"),
        ],
    );

    assert_eq!(probe.code, "22021");
    assert_eq!(probe.message, "invalid byte sequence for encoding \"UTF8\"");
    assert_eq!(
        probe.detail.as_deref(),
        Some("The byte sequence is not valid UTF-8.")
    );
    assert_eq!(
        probe.hint.as_deref(),
        Some("Use valid UTF-8 input for text COPY streams.")
    );
    assert_eq!(probe.diagnostic.severity.as_deref(), Some("ERROR"));
    assert_eq!(probe.diagnostic.column_name.as_deref(), Some("email"));
    assert_eq!(
        probe.diagnostic.where_context.as_deref(),
        Some("COPY users, line 1, column email")
    );
    assert_eq!(
        probe.diagnostic.routine_name.as_deref(),
        Some("CopyReadLineText")
    );

    crate::test_complete!("audit_copy_from_error_message_structure");
}

/// AUDIT: successful COPY FROM streams data in bounded `CopyData` frames.
#[test]
fn audit_reference_datarow_column_validation_pattern() {
    super::init_test("audit_reference_datarow_column_validation_pattern");

    let (mut conn, mut peer) = make_test_connection_with_peer();
    peer.write_all(&copy_in_response_message(
        Format::Text,
        &[Format::Text, Format::Text],
    ))
    .expect("write CopyInResponse");
    peer.write_all(&backend_message(b'C', b"COPY 2\0"))
        .expect("write CommandComplete");
    peer.write_all(&ready_for_query(b'I'))
        .expect("write ReadyForQuery");

    let cx = Cx::for_testing();
    let chunks: Vec<Result<&[u8], PgError>> = vec![Ok(b"1\tJohn\n"), Ok(b"2\tJane\n")];
    let complete = match run(conn.copy_from_chunks(&cx, "COPY users FROM STDIN", chunks)) {
        Outcome::Ok(complete) => complete,
        other => panic!("expected successful COPY FROM, got {other:?}"),
    };

    assert_eq!(complete.affected_rows(), 2);
    assert_eq!(complete.chunks_sent(), 2);
    assert_eq!(complete.bytes_sent(), b"1\tJohn\n2\tJane\n".len() as u64);
    assert!(!conn.inner.closed);

    let written = read_until_contains(&mut peer, &[FrontendMessage::CopyDone as u8, 0, 0, 0, 4]);
    let copy_offset = frontend_frame_len(&written, 0);
    let parsed = fuzz_parse_copy_in_sequence(&written[copy_offset..]).expect("COPY IN sequence");
    assert_eq!(
        parsed.copy_data_chunks,
        vec![b"1\tJohn\n".to_vec(), b"2\tJane\n".to_vec()]
    );
    assert_eq!(parsed.end, FuzzCopyInEnd::Done);

    crate::test_complete!("audit_reference_datarow_column_validation_pattern");
}
