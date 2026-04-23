#![no_main]

//! Focused fuzz target for incremental HTTP/1.1 head parsing across CRLF
//! boundary splits.
//!
//! Existing broad H1 fuzzing mostly feeds complete messages. This harness
//! instead forces `Http1Codec` to make framing decisions while `\r`, `\n`, and
//! malformed continuation bytes arrive in separate chunks, which is the exact
//! seam where request-smuggling regressions tend to appear.

use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use libfuzzer_sys::fuzz_target;
use std::io;

const MAX_HINTS: usize = 16;
const MAX_TEXT: usize = 32;

#[derive(Debug, Clone, Copy)]
enum AttackKind {
    Clean,
    BareCrInRequestLine,
    BareCrInHeaderName,
    BareCrInHeaderValue,
    ObsFoldSpace,
    ObsFoldTab,
}

impl<'a> Arbitrary<'a> for AttackKind {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(match u.int_in_range(0..=5u8)? {
            0 => Self::Clean,
            1 => Self::BareCrInRequestLine,
            2 => Self::BareCrInHeaderName,
            3 => Self::BareCrInHeaderValue,
            4 => Self::ObsFoldSpace,
            _ => Self::ObsFoldTab,
        })
    }
}

#[derive(Debug)]
struct H1SplitCrlfInput {
    uri_bytes: Vec<u8>,
    host_bytes: Vec<u8>,
    header_name_bytes: Vec<u8>,
    header_value_bytes: Vec<u8>,
    split_hints: Vec<u8>,
    max_headers_size: u16,
    force_boundary_split: bool,
    attack: AttackKind,
}

impl<'a> Arbitrary<'a> for H1SplitCrlfInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self {
            uri_bytes: arbitrary_bytes(u, MAX_TEXT)?,
            host_bytes: arbitrary_bytes(u, MAX_TEXT)?,
            header_name_bytes: arbitrary_bytes(u, MAX_TEXT)?,
            header_value_bytes: arbitrary_bytes(u, MAX_TEXT)?,
            split_hints: arbitrary_bytes(u, MAX_HINTS)?,
            max_headers_size: u.int_in_range(32..=4096u16)?,
            force_boundary_split: u.arbitrary()?,
            attack: u.arbitrary()?,
        })
    }
}

fn arbitrary_bytes(u: &mut Unstructured<'_>, max_len: usize) -> ArbitraryResult<Vec<u8>> {
    let len = usize::from(u.int_in_range(0..=max_len as u8)?);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(u.arbitrary()?);
    }
    Ok(out)
}

fn sanitize_uri(bytes: &[u8]) -> String {
    let mut uri = String::from("/");
    for &b in bytes.iter().take(MAX_TEXT) {
        let ch = match b % 9 {
            0 => 'a',
            1 => 'b',
            2 => 'c',
            3 => '/',
            4 => '-',
            5 => '_',
            6 => '?',
            7 => '=',
            _ => '1',
        };
        uri.push(ch);
    }
    uri
}

fn sanitize_header_name(bytes: &[u8]) -> String {
    const TCHAR: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";
    let mut out = String::new();
    for &b in bytes.iter().take(MAX_TEXT) {
        out.push(char::from(TCHAR[usize::from(b) % TCHAR.len()]));
    }
    if out.is_empty() {
        out.push_str("X-Fuzz");
    }
    out
}

fn sanitize_header_value(bytes: &[u8], fallback: &str) -> String {
    let mut out = String::new();
    for &b in bytes.iter().take(MAX_TEXT) {
        let ch = match b % 8 {
            0 => 'a',
            1 => 'b',
            2 => 'c',
            3 => '1',
            4 => '2',
            5 => '-',
            6 => '_',
            _ => ' ',
        };
        out.push(ch);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        fallback.to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn build_wire(input: &H1SplitCrlfInput) -> (Vec<u8>, bool, Option<usize>) {
    let uri = sanitize_uri(&input.uri_bytes);
    let host = sanitize_header_value(&input.host_bytes, "example.test");
    let header_name = sanitize_header_name(&input.header_name_bytes);
    let header_value = sanitize_header_value(&input.header_value_bytes, "ok");

    let mut wire = Vec::new();
    let mut split_after = None;

    match input.attack {
        AttackKind::Clean => {
            wire.extend_from_slice(format!("GET {uri} HTTP/1.1\r\n").as_bytes());
            wire.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
            wire.extend_from_slice(format!("{header_name}: {header_value}\r\n\r\n").as_bytes());
            if input.force_boundary_split {
                split_after = wire.iter().rposition(|&b| b == b'\r');
            }
            (wire, true, split_after)
        }
        AttackKind::BareCrInRequestLine => {
            let line = format!("GET {uri}\rX HTTP/1.1\r\n");
            split_after = line.as_bytes().iter().position(|&b| b == b'\r');
            wire.extend_from_slice(line.as_bytes());
            wire.extend_from_slice(format!("Host: {host}\r\n\r\n").as_bytes());
            (wire, false, split_after)
        }
        AttackKind::BareCrInHeaderName => {
            wire.extend_from_slice(format!("GET {uri} HTTP/1.1\r\n").as_bytes());
            let attack_start = wire.len();
            let attack_line = format!("{header_name}\rX: {header_value}\r\n");
            split_after = attack_line
                .as_bytes()
                .iter()
                .position(|&b| b == b'\r')
                .map(|idx| attack_start + idx);
            wire.extend_from_slice(attack_line.as_bytes());
            wire.extend_from_slice(format!("Host: {host}\r\n\r\n").as_bytes());
            (wire, false, split_after)
        }
        AttackKind::BareCrInHeaderValue => {
            wire.extend_from_slice(format!("GET {uri} HTTP/1.1\r\n").as_bytes());
            wire.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
            let attack_start = wire.len();
            let attack_line = format!("{header_name}: {header_value}\rX\r\n\r\n");
            split_after = attack_line
                .as_bytes()
                .iter()
                .position(|&b| b == b'\r')
                .map(|idx| attack_start + idx);
            wire.extend_from_slice(attack_line.as_bytes());
            (wire, false, split_after)
        }
        AttackKind::ObsFoldSpace => {
            wire.extend_from_slice(format!("GET {uri} HTTP/1.1\r\n").as_bytes());
            wire.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
            let attack_start = wire.len();
            let attack_line = format!("{header_name}: {header_value}\r\n injected: yes\r\n\r\n");
            split_after = attack_line
                .as_bytes()
                .windows(2)
                .position(|window| window == b"\r\n")
                .map(|idx| attack_start + idx);
            wire.extend_from_slice(attack_line.as_bytes());
            (wire, false, split_after)
        }
        AttackKind::ObsFoldTab => {
            wire.extend_from_slice(format!("GET {uri} HTTP/1.1\r\n").as_bytes());
            wire.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
            let attack_start = wire.len();
            let attack_line = format!("{header_name}: {header_value}\r\n\tinjected: yes\r\n\r\n");
            split_after = attack_line
                .as_bytes()
                .windows(2)
                .position(|window| window == b"\r\n")
                .map(|idx| attack_start + idx);
            wire.extend_from_slice(attack_line.as_bytes());
            (wire, false, split_after)
        }
    }
}

fn chunk_ranges(
    data_len: usize,
    hints: &[u8],
    force_split_after: Option<usize>,
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut cursor = 0usize;
    let forced = force_split_after
        .map(|idx| idx.saturating_add(1))
        .filter(|&end| end > 0 && end < data_len);

    if let Some(end) = forced {
        ranges.push((0, end));
        cursor = end;
    }

    for &hint in hints {
        if cursor >= data_len {
            break;
        }
        let remaining = data_len - cursor;
        let take = 1 + (usize::from(hint) % remaining);
        ranges.push((cursor, cursor + take));
        cursor += take;
    }

    if cursor < data_len {
        ranges.push((cursor, data_len));
    }

    if ranges.is_empty() && data_len > 0 {
        ranges.push((0, data_len));
    }

    ranges
}

fn assert_clean_headers(req: &asupersync::http::h1::types::Request) {
    for (name, value) in &req.headers {
        assert!(
            !name.bytes().any(|b| b == b'\r' || b == b'\n'),
            "parsed header name leaked control chars: {name:?}"
        );
        assert!(
            !value.bytes().any(|b| b == b'\r' || b == b'\n'),
            "parsed header value leaked control chars: {value:?}"
        );
    }
}

fn is_expected_invalid(err: &HttpError) -> bool {
    match err {
        HttpError::BadRequestLine
        | HttpError::BadHeader
        | HttpError::InvalidHeaderName
        | HttpError::InvalidHeaderValue
        | HttpError::RequestLineTooLong
        | HttpError::HeadersTooLarge => true,
        HttpError::Io(e) => e.kind() == io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

fuzz_target!(|input: H1SplitCrlfInput| {
    let (wire, should_accept, split_after) = build_wire(&input);
    let mut codec = Http1Codec::new().max_headers_size(usize::from(input.max_headers_size));
    let mut buf = BytesMut::new();
    let mut decoded = None;

    for (start, end) in chunk_ranges(wire.len(), &input.split_hints, split_after) {
        buf.extend_from_slice(&wire[start..end]);
        loop {
            match codec.decode(&mut buf) {
                Ok(Some(req)) => {
                    assert!(
                        should_accept,
                        "malformed split-CRLF input decoded successfully: {:?}",
                        input.attack
                    );
                    assert_clean_headers(&req);
                    decoded = Some(req);
                    break;
                }
                Ok(None) => break,
                Err(err) => {
                    assert!(
                        !should_accept,
                        "valid segmented request was rejected early: {err:?}"
                    );
                    assert!(
                        is_expected_invalid(&err),
                        "unexpected invalid-path error: {err:?}"
                    );
                    return;
                }
            }
        }
    }

    if let Some(req) = decoded {
        assert_eq!(req.version.as_str(), "HTTP/1.1");
        assert_eq!(req.method.as_str(), "GET");
        assert!(req.uri.starts_with('/'));
        return;
    }

    match codec.decode_eof(&mut buf) {
        Ok(Some(req)) => {
            assert!(should_accept, "malformed request survived decode_eof");
            assert_clean_headers(&req);
            assert_eq!(req.method.as_str(), "GET");
            assert!(req.uri.starts_with('/'));
        }
        Ok(None) => {
            assert!(
                !should_accept && buf.is_empty(),
                "valid segmented request failed to decode at EOF"
            );
        }
        Err(err) => {
            assert!(
                !should_accept,
                "valid segmented request hit EOF error: {err:?}"
            );
            assert!(
                is_expected_invalid(&err),
                "unexpected invalid-path EOF error: {err:?}"
            );
        }
    }
});
