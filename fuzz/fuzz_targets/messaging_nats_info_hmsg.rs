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

use asupersync::messaging::nats::{fuzz_parse_nats_hmsg_frame, fuzz_parse_nats_server_info};

const MAX_INPUT: usize = 64 * 1024;

fn assert_fixed_oracles() {
    let info = fuzz_parse_nats_server_info(
        r#"{"server_id":"srv-A","server_name":"node-1","version":"2.10.0","proto":1,"max_payload":42,"tls_required":false,"tls_available":true,"headers":true,"nonce":"abc"}"#,
    )
    .expect("valid INFO JSON should parse through production ServerInfo");
    assert_eq!(info.server_id, "srv-A");
    assert_eq!(info.server_name, "node-1");
    assert_eq!(info.version, "2.10.0");
    assert_eq!(info.proto, 1);
    assert_eq!(info.max_payload, 42);
    assert!(!info.tls_required);
    assert!(info.tls_available);
    assert!(info.headers);
    assert_eq!(info.nonce.as_deref(), Some("abc"));

    assert!(fuzz_parse_nats_server_info("[]").is_err());
    assert!(fuzz_parse_nats_server_info(r#"{"server_id":"truncated\u12"}"#).is_err());

    let headers = b"NATS/1.0\r\nStatus: 503\r\nDescription: No Responders\r\n\r\n";
    let payload = b"hello";
    let frame = build_hmsg_frame("updates", 7, None, headers, payload);
    let parsed = fuzz_parse_nats_hmsg_frame(&frame, MAX_INPUT)
        .expect("valid HMSG frame should not error")
        .expect("valid HMSG frame should be complete");
    assert_eq!(parsed.subject, "updates");
    assert_eq!(parsed.sid, 7);
    assert!(parsed.reply_to.is_none());
    assert_eq!(parsed.headers.as_deref(), Some(headers.as_slice()));
    assert_eq!(parsed.payload, payload);

    let status_headers = b"NATS/1.0 408 Request Timeout\r\n\r\n";
    let parsed = fuzz_parse_nats_hmsg_frame(
        &build_hmsg_frame("status", 8, Some("_INBOX.reply"), status_headers, b""),
        MAX_INPUT,
    )
    .expect("status-line HMSG should not error")
    .expect("status-line HMSG should be complete");
    assert_eq!(parsed.reply_to.as_deref(), Some("_INBOX.reply"));
    assert_eq!(parsed.headers.as_deref(), Some(status_headers.as_slice()));
    assert!(parsed.payload.is_empty());

    let incomplete = b"HMSG s 1 12 16\r\nNATS/1.0\r\n";
    assert!(
        fuzz_parse_nats_hmsg_frame(incomplete, MAX_INPUT)
            .expect("incomplete HMSG should wait for more bytes")
            .is_none()
    );
    assert!(
        fuzz_parse_nats_hmsg_frame(b"HMSG s 1 8 4\r\nNATS/1.0\r\n\r\n\r\n", MAX_INPUT).is_err()
    );
    assert!(fuzz_parse_nats_hmsg_frame(&frame, 1).is_err());
}

fn build_hmsg_frame(
    subject: &str,
    sid: u64,
    reply_to: Option<&str>,
    headers: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let total_len = headers.len() + payload.len();
    let head = if let Some(reply_to) = reply_to {
        format!(
            "HMSG {subject} {sid} {reply_to} {} {total_len}\r\n",
            headers.len()
        )
    } else {
        format!("HMSG {subject} {sid} {} {total_len}\r\n", headers.len())
    };
    let mut frame = Vec::with_capacity(head.len() + total_len + 2);
    frame.extend_from_slice(head.as_bytes());
    frame.extend_from_slice(headers);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(b"\r\n");
    frame
}

fn assert_visible_parse_error(error: &impl std::fmt::Display, context: &str) {
    assert!(
        !error.to_string().is_empty(),
        "{context} parser errors should remain observable"
    );
}

fn observe_info_json(json: &str) {
    match fuzz_parse_nats_server_info(json) {
        Ok(info) => {
            assert!(
                info.connect_urls.is_empty(),
                "INFO parser does not currently materialize connect_urls"
            );
        }
        Err(error) => assert_visible_parse_error(&error, "NATS INFO"),
    }
}

fn observe_hmsg_frame(frame: &[u8]) {
    match fuzz_parse_nats_hmsg_frame(frame, MAX_INPUT) {
        Ok(Some(message)) => {
            assert!(!message.subject.is_empty());
            let headers = message
                .headers
                .as_deref()
                .expect("HMSG parser must attach the accepted header block");
            assert!(
                headers.ends_with(b"\r\n\r\n"),
                "accepted HMSG headers must retain their CRLF terminator"
            );
            assert!(
                headers == b"NATS/1.0\r\n\r\n" || headers.starts_with(b"NATS/1.0"),
                "accepted HMSG headers must carry the NATS/1.0 status line"
            );
            assert!(
                headers.len() + message.payload.len() <= MAX_INPUT,
                "accepted HMSG body must respect the configured read bound"
            );
        }
        Ok(None) => {}
        Err(error) => assert_visible_parse_error(&error, "NATS HMSG"),
    }
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
            if let Ok(json) = std::str::from_utf8(payload) {
                observe_info_json(json);
            }
        }
        1 => {
            observe_hmsg_frame(payload);
        }
        2 => {
            let frame = build_hmsg_frame("fuzz.subject", 1, None, payload, b"");
            observe_hmsg_frame(&frame);
        }
        _ => {
            let half = payload.len() / 2;
            let (a, b) = payload.split_at(half);
            if let Ok(json) = std::str::from_utf8(a) {
                observe_info_json(json);
            }
            let frame = build_hmsg_frame("fuzz.reply", 2, Some("_INBOX.fuzz"), b, a);
            observe_hmsg_frame(&frame);
        }
    }
});
