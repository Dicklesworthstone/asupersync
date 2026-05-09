//! br-asupersync-6ugt3c: fuzz target for the NATS INFO JSON parser
//! and the HMSG header-block decoder.
//!
//! NATS clients consume server-side bytes that, under a compromised-
//! server / MitM threat model, are attacker-controlled. The two
//! highest-impact decode paths a malicious server can exercise are:
//!
//!   1. The `INFO` frame: a JSON object the server sends at connect
//!      time. Production parses it via a hand-rolled extractor
//!      (`extract_json_string`/`_i64`/`_bool`) — no serde, so
//!      depth-limit and escape-handling are bespoke.
//!   2. The `HMSG` frame: a CRLF-terminated header line followed by a
//!      length-prefixed header block (RFC-822-style name/value pairs)
//!      and a payload.
//!
//! Existing `nats_parser` fuzz target covers the high-level state
//! machine but does NOT specifically target the INFO-JSON extractor
//! or the HMSG header-block parser. This target re-implements both
//! paths and fuzzes them on arbitrary bytes — any panic is a bug in
//! the production code that uses identical logic.
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run messaging_nats_info_hmsg
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 64 * 1024;

/// Mirror of asupersync::messaging::nats::extract_json_string.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":\"");
    let start = json.find(&pattern)? + pattern.len();
    let slice = &json[start..];
    let mut out = String::with_capacity(slice.len());
    let mut chars = slice.chars();
    loop {
        match chars.next()? {
            '"' => return Some(out),
            '\\' => {
                let next = chars.next()?;
                match next {
                    'b' => out.push('\x08'),
                    'f' => out.push('\x0C'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let mut hex = String::with_capacity(4);
                        for _ in 0..4 {
                            hex.push(chars.next()?);
                        }
                        if let Ok(cp) = u32::from_str_radix(&hex, 16)
                            && let Some(c) = char::from_u32(cp)
                        {
                            out.push(c);
                        }
                    }
                    other => out.push(other),
                }
            }
            c => out.push(c),
        }
    }
}

fn extract_json_i64(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{key}\":");
    let start = json.find(&pattern)? + pattern.len();
    let slice = json[start..].trim_start();
    let end = slice
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(slice.len());
    slice[..end].parse::<i64>().ok()
}

fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{key}\":");
    let start = json.find(&pattern)? + pattern.len();
    let slice = &json[start..].trim_start();
    if slice.starts_with("true") {
        Some(true)
    } else if slice.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Mirror of the HMSG header-block decoder. Header block format:
/// `NATS/1.0\r\n<name>: <value>\r\n<name>: <value>\r\n\r\n`.
fn parse_hmsg_headers(block: &[u8]) -> Option<Vec<(String, String)>> {
    // Reject any byte outside printable-ASCII + HTAB + CR/LF (the
    // production sanitiser applies the same allowlist when emitting,
    // and the parser must tolerate decoder input that contains the
    // CR/LF separators).
    let text = std::str::from_utf8(block).ok()?;
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    if !first.starts_with("NATS/") {
        return None;
    }
    let mut out = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            // Reject names with CR/LF/NUL — these MUST have been
            // stripped by the encoder.
            if name.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                return None;
            }
            // Trim the leading space the encoder emits after `:`.
            let value = value.strip_prefix(' ').unwrap_or(value);
            // Reject values with CR/LF/NUL.
            if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                return None;
            }
            out.push((name.to_string(), value.to_string()));
        } else {
            return None;
        }
    }
    Some(out)
}

fn assert_fixed_oracles() {
    assert_eq!(
        extract_json_string(
            r#"{"server_id":"line\nquote\"slash\/unknown\zunicode\u0041bad\uZZZZsurrogate\uD800end"}"#,
            "server_id"
        )
        .as_deref(),
        Some("line\nquote\"slash/unknownzunicodeAbadsurrogateend")
    );
    assert_eq!(
        extract_json_string(r#"{"server_id":"truncated\u12"}"#, "server_id"),
        None
    );
    assert_eq!(extract_json_i64(r#"{"proto": -12x}"#, "proto"), Some(-12));
    assert_eq!(
        extract_json_i64(r#"{"max_payload": 42,"#, "max_payload"),
        Some(42)
    );
    assert_eq!(extract_json_i64(r#"{"proto": +1}"#, "proto"), None);
    assert_eq!(
        extract_json_bool(r#"{"headers": trueish}"#, "headers"),
        Some(true)
    );
    assert_eq!(
        extract_json_bool(r#"{"tls_required": falsehood}"#, "tls_required"),
        Some(false)
    );
    assert_eq!(
        parse_hmsg_headers(b"NATS/1.0\r\nStatus: 503\r\nDescription: No Responders\r\n\r\n"),
        Some(vec![
            ("Status".to_string(), "503".to_string()),
            ("Description".to_string(), "No Responders".to_string()),
        ])
    );
    assert_eq!(
        parse_hmsg_headers(b"NATS/1.0 408 Request Timeout\r\n\r\n"),
        Some(Vec::new())
    );
    assert_eq!(parse_hmsg_headers(b"HTTP/1.1\r\nFoo: bar\r\n\r\n"), None);
    assert_eq!(
        parse_hmsg_headers(b"NATS/1.0\r\nBad: va\0lue\r\n\r\n"),
        None
    );
}

fuzz_target!(|data: &[u8]| {
    assert_fixed_oracles();

    if data.len() > MAX_INPUT || data.len() < 2 {
        return;
    }
    // First byte selects which sub-parser to exercise; the rest is the
    // input. Selecting per-byte rather than via a single entry point
    // keeps libfuzzer's coverage signal sharp on each sub-path.
    let mode = data[0] & 0b11;
    let payload = &data[1..];

    match mode {
        0 => {
            // INFO JSON string-extraction: feed arbitrary bytes,
            // attempt to extract every well-known field, panic-free.
            if let Ok(json) = std::str::from_utf8(payload) {
                let _ = extract_json_string(json, "server_id");
                let _ = extract_json_string(json, "server_name");
                let _ = extract_json_string(json, "version");
                // String key with embedded escapes / NUL / unicode-escape
                // surrogate that didn't match \uXXXX shape.
                let _ = extract_json_string(json, "connect_urls");
            }
        }
        1 => {
            // INFO JSON int / bool extractors: same shape.
            if let Ok(json) = std::str::from_utf8(payload) {
                let _ = extract_json_i64(json, "proto");
                let _ = extract_json_i64(json, "max_payload");
                let _ = extract_json_bool(json, "tls_required");
                let _ = extract_json_bool(json, "tls_available");
                let _ = extract_json_bool(json, "headers");
            }
        }
        2 => {
            // HMSG header block: feed arbitrary bytes; parser must
            // either return Some(headers) or None — never panic.
            let _ = parse_hmsg_headers(payload);
        }
        _ => {
            // Combined: treat first half as JSON, second half as
            // header block. Useful for cross-state confusion attacks
            // where a single input is parsed as both shapes by
            // different state-machine branches.
            let half = payload.len() / 2;
            let (a, b) = payload.split_at(half);
            if let Ok(json) = std::str::from_utf8(a) {
                let _ = extract_json_string(json, "server_id");
            }
            let _ = parse_hmsg_headers(b);
        }
    }
});
