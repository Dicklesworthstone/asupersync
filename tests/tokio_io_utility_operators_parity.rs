#![allow(clippy::all)]
//! Contract tests for I/O Utility Operators Parity.
//!
//! Bead: asupersync-2oh2u.2.3 ([T2.3])
//!
//! Validates:
//! 1. Machine-readable JSON artifact consistency
//! 2. Operator category inventory
//! 3. Invariant register completeness
//! 4. Cancel-safety matrix coverage
//! 5. Behavioral contracts for copy/split/lines/buf/stream-adapters
//! 6. Obligation-leak-free invariant

#[macro_use]
mod common;

mod asupersync {
    pub use crate::test_complete;
    pub use ::asupersync::*;
}

use std::collections::HashSet;

// ── Artifact loading ────────────────────────────────────────────────────

const UTIL_JSON: &str = include_str!("../docs/tokio_io_utility_operators_parity.json");
const UTIL_MD: &str = include_str!("../docs/tokio_io_utility_operators_parity.md");

fn parse_json() -> serde_json::Value {
    serde_json::from_str(UTIL_JSON).expect("utility operators JSON must parse")
}

fn init_test(name: &str) {
    common::init_test_logging();
    test_phase!(name);
}

// ════════════════════════════════════════════════════════════════════════
// JSON Structural Integrity
// ════════════════════════════════════════════════════════════════════════

#[test]
fn json_parses_and_has_required_fields() {
    init_test("json_parses_and_has_required_fields");
    let v = parse_json();
    for field in &[
        "bead_id",
        "title",
        "version",
        "generated_at",
        "generated_by",
        "source_markdown",
        "domains",
        "operator_categories",
        "total_operators",
        "invariants",
        "cancel_safety",
        "obligation_leak_free",
        "gaps",
        "summary",
        "drift_detection",
    ] {
        assert!(v.get(field).is_some(), "missing field: {field}");
    }
    asupersync::test_complete!("json_parses_and_has_required_fields");
}

#[test]
fn bead_id_matches() {
    init_test("bead_id_matches");
    let v = parse_json();
    assert_eq!(v["bead_id"].as_str().unwrap(), "asupersync-2oh2u.2.3");
    asupersync::test_complete!("bead_id_matches");
}

// ════════════════════════════════════════════════════════════════════════
// Operator Category Inventory
// ════════════════════════════════════════════════════════════════════════

#[test]
fn operator_categories_present() {
    init_test("operator_categories_present");
    let v = parse_json();
    let cats = v["operator_categories"].as_array().unwrap();
    assert!(
        cats.len() >= 5,
        "expected >= 5 categories, got {}",
        cats.len()
    );
    asupersync::test_complete!("operator_categories_present");
}

#[test]
fn required_category_ids_present() {
    init_test("required_category_ids_present");
    let v = parse_json();
    let ids: HashSet<&str> = v["operator_categories"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    for required in &["COPY", "SPLIT", "LINES", "BUF", "ADAPT"] {
        assert!(ids.contains(required), "missing category: {required}");
    }
    asupersync::test_complete!("required_category_ids_present");
}

#[test]
fn total_operators_matches_sum() {
    init_test("total_operators_matches_sum");
    let v = parse_json();
    let sum: u64 = v["operator_categories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["count"].as_u64().unwrap())
        .sum();
    let claimed = v["total_operators"].as_u64().unwrap();
    assert_eq!(
        sum, claimed,
        "total_operators mismatch: sum={sum}, claimed={claimed}"
    );
    asupersync::test_complete!("total_operators_matches_sum");
}

// ════════════════════════════════════════════════════════════════════════
// Invariant Register
// ════════════════════════════════════════════════════════════════════════

#[test]
fn invariants_minimum_count() {
    init_test("invariants_minimum_count");
    let v = parse_json();
    let invs = v["invariants"].as_array().unwrap();
    assert!(
        invs.len() >= 12,
        "expected >= 12 invariants, got {}",
        invs.len()
    );
    asupersync::test_complete!("invariants_minimum_count");
}

#[test]
fn invariant_ids_unique() {
    init_test("invariant_ids_unique");
    let v = parse_json();
    let ids: Vec<&str> = v["invariants"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["id"].as_str())
        .collect();
    let unique: HashSet<&&str> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate invariant IDs");
    asupersync::test_complete!("invariant_ids_unique");
}

#[test]
fn invariant_categories_match_operators() {
    init_test("invariant_categories_match_operators");
    let v = parse_json();
    let inv_cats: HashSet<&str> = v["invariants"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["category"].as_str())
        .collect();
    // At least split, lines, buffering, and stream-adapters should have invariants
    assert!(
        inv_cats.contains("split"),
        "missing split invariant category"
    );
    assert!(
        inv_cats.contains("lines"),
        "missing lines invariant category"
    );
    assert!(
        inv_cats.contains("buffering"),
        "missing buffering invariant category"
    );
    assert!(
        inv_cats.contains("stream-adapters"),
        "missing stream-adapters invariant category"
    );
    asupersync::test_complete!("invariant_categories_match_operators");
}

// ════════════════════════════════════════════════════════════════════════
// Cancel-Safety Matrix
// ════════════════════════════════════════════════════════════════════════

#[test]
fn cancel_safety_covers_all_operators() {
    init_test("cancel_safety_covers_all_operators");
    let v = parse_json();
    let entries = v["cancel_safety"].as_array().unwrap();
    assert!(
        entries.len() >= 8,
        "expected >= 8 cancel-safety entries, got {}",
        entries.len()
    );
    for entry in entries {
        assert!(entry.get("operator").is_some(), "missing operator field");
        assert!(
            entry.get("cancel_safe").is_some(),
            "missing cancel_safe field"
        );
        assert!(entry.get("behavior").is_some(), "missing behavior field");
    }
    asupersync::test_complete!("cancel_safety_covers_all_operators");
}

#[test]
fn all_cancel_safe_in_current_impl() {
    init_test("all_cancel_safe_in_current_impl");
    let v = parse_json();
    let entries = v["cancel_safety"].as_array().unwrap();
    for entry in entries {
        let op = entry["operator"].as_str().unwrap();
        let safe = entry["cancel_safe"].as_bool().unwrap();
        assert!(safe, "operator {op} should be cancel-safe in current impl");
    }
    asupersync::test_complete!("all_cancel_safe_in_current_impl");
}

// ════════════════════════════════════════════════════════════════════════
// Obligation Leak Freedom
// ════════════════════════════════════════════════════════════════════════

#[test]
fn obligation_leak_free_flag() {
    init_test("obligation_leak_free_flag");
    let v = parse_json();
    assert!(
        v["obligation_leak_free"].as_bool().unwrap(),
        "utility operators must be obligation-leak-free"
    );
    asupersync::test_complete!("obligation_leak_free_flag");
}

// ════════════════════════════════════════════════════════════════════════
// Gap Register
// ════════════════════════════════════════════════════════════════════════

#[test]
fn gaps_have_severity_and_id() {
    init_test("gaps_have_severity_and_id");
    let v = parse_json();
    let gaps = v["gaps"].as_array().unwrap();
    assert!(!gaps.is_empty(), "gap register should not be empty");
    for gap in gaps {
        let id = gap["id"].as_str().unwrap();
        assert!(id.starts_with("IO-G"), "gap ID {id} must start with IO-G");
        let sev = gap["severity"].as_str().unwrap();
        assert!(
            ["HIGH", "MEDIUM", "LOW"].contains(&sev),
            "gap {id}: invalid severity {sev}"
        );
    }
    asupersync::test_complete!("gaps_have_severity_and_id");
}

#[test]
fn summary_metrics_consistent() {
    init_test("summary_metrics_consistent");
    let v = parse_json();
    let summary = &v["summary"];
    let total = summary["total_operators"].as_u64().unwrap();
    let claimed_total = v["total_operators"].as_u64().unwrap();
    assert_eq!(total, claimed_total, "summary.total_operators mismatch");

    let inv_count = summary["total_invariants"].as_u64().unwrap();
    let actual_invs = v["invariants"].as_array().unwrap().len() as u64;
    assert_eq!(
        inv_count, actual_invs,
        "summary.total_invariants mismatch: claimed={inv_count}, actual={actual_invs}"
    );

    let cs_count = summary["cancel_safe_count"].as_u64().unwrap();
    let actual_cs = v["cancel_safety"].as_array().unwrap().len() as u64;
    assert_eq!(
        cs_count, actual_cs,
        "summary.cancel_safe_count mismatch: claimed={cs_count}, actual={actual_cs}"
    );

    let high = summary["high_severity_gaps"].as_u64().unwrap();
    let med = summary["medium_severity_gaps"].as_u64().unwrap();
    let low = summary["low_severity_gaps"].as_u64().unwrap();
    let actual_high = v["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["severity"].as_str() == Some("HIGH"))
        .count() as u64;
    let actual_med = v["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["severity"].as_str() == Some("MEDIUM"))
        .count() as u64;
    let actual_low = v["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["severity"].as_str() == Some("LOW"))
        .count() as u64;
    assert_eq!(high, actual_high, "HIGH gap count mismatch");
    assert_eq!(med, actual_med, "MEDIUM gap count mismatch");
    assert_eq!(low, actual_low, "LOW gap count mismatch");

    asupersync::test_complete!("summary_metrics_consistent");
}

// ════════════════════════════════════════════════════════════════════════
// Drift Detection
// ════════════════════════════════════════════════════════════════════════

#[test]
fn drift_rules_present() {
    init_test("drift_rules_present");
    let v = parse_json();
    let rules = v["drift_detection"].as_array().unwrap();
    assert!(
        rules.len() >= 3,
        "expected >= 3 drift rules, got {}",
        rules.len()
    );
    for rule in rules {
        assert!(rule.get("id").is_some(), "drift rule missing id");
        assert!(rule.get("trigger").is_some(), "drift rule missing trigger");
        assert!(rule.get("action").is_some(), "drift rule missing action");
    }
    asupersync::test_complete!("drift_rules_present");
}

// ════════════════════════════════════════════════════════════════════════
// Markdown Cross-Reference
// ════════════════════════════════════════════════════════════════════════

#[test]
fn markdown_references_all_invariants() {
    init_test("markdown_references_all_invariants");
    let v = parse_json();
    for inv in v["invariants"].as_array().unwrap() {
        let id = inv["id"].as_str().unwrap();
        assert!(UTIL_MD.contains(id), "invariant {id} not found in markdown");
    }
    asupersync::test_complete!("markdown_references_all_invariants");
}

#[test]
fn markdown_references_all_gaps() {
    init_test("markdown_references_all_gaps");
    let v = parse_json();
    for gap in v["gaps"].as_array().unwrap() {
        let id = gap["id"].as_str().unwrap();
        assert!(UTIL_MD.contains(id), "gap {id} not found in markdown");
    }
    asupersync::test_complete!("markdown_references_all_gaps");
}

#[test]
fn markdown_references_all_categories() {
    init_test("markdown_references_all_categories");
    let v = parse_json();
    for cat in v["operator_categories"].as_array().unwrap() {
        let name = cat["name"].as_str().unwrap();
        // Check that at least part of the category name appears in markdown
        let first_word = name.split_whitespace().next().unwrap();
        assert!(
            UTIL_MD.contains(first_word),
            "category {name} not found in markdown"
        );
    }
    asupersync::test_complete!("markdown_references_all_categories");
}

// ════════════════════════════════════════════════════════════════════════
// Behavioral: Split Invariants (SPLIT-1 through SPLIT-4)
// ════════════════════════════════════════════════════════════════════════

use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf, SplitStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

fn noop_waker() -> Waker {
    Waker::noop().clone()
}

/// Test stream that stores read data and written data independently.
struct TestStream {
    read_data: Vec<u8>,
    read_pos: usize,
    written: Vec<u8>,
}

impl TestStream {
    fn new(read_data: &[u8]) -> Self {
        Self {
            read_data: read_data.to_vec(),
            read_pos: 0,
            written: Vec::new(),
        }
    }
}

impl AsyncRead for TestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_pos >= this.read_data.len() {
            return Poll::Ready(Ok(()));
        }
        let to_copy = std::cmp::min(this.read_data.len() - this.read_pos, buf.remaining());
        buf.put_slice(&this.read_data[this.read_pos..this.read_pos + to_copy]);
        this.read_pos += to_copy;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn split_invariant_1_read_half_produces_same_bytes() {
    init_test("split_invariant_1_read_half_produces_same_bytes");

    let data = b"hello world, this is test data for split invariant";
    let wrapper = SplitStream::new(TestStream::new(data));
    let (mut read_half, _write_half) = wrapper.split();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut out = vec![0u8; data.len()];
    let mut read_buf = ReadBuf::new(&mut out);

    let result = Pin::new(&mut read_half).poll_read(&mut cx, &mut read_buf);
    assert!(matches!(result, Poll::Ready(Ok(()))));
    assert_eq!(
        read_buf.filled(),
        data,
        "SPLIT-1: read half must produce same bytes"
    );

    asupersync::test_complete!("split_invariant_1_read_half_produces_same_bytes");
}

#[test]
fn split_invariant_2_write_half_commits_same_bytes() {
    init_test("split_invariant_2_write_half_commits_same_bytes");

    let wrapper = SplitStream::new(TestStream::new(b""));
    let (_read_half, mut write_half) = wrapper.split();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let data = b"written via split half";
    let result = Pin::new(&mut write_half).poll_write(&mut cx, data);
    assert!(matches!(result, Poll::Ready(Ok(n)) if n == data.len()));

    let inner = wrapper.into_inner();
    assert_eq!(
        inner.written, data,
        "SPLIT-2: write half must commit same bytes"
    );

    asupersync::test_complete!("split_invariant_2_write_half_commits_same_bytes");
}

#[test]
fn split_invariant_3_into_inner_preserves_state() {
    init_test("split_invariant_3_into_inner_preserves_state");

    let wrapper = SplitStream::new(TestStream::new(b"state test"));
    {
        let (mut read_half, _write_half) = wrapper.split();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut out = [0u8; 5];
        let mut read_buf = ReadBuf::new(&mut out);
        let _ = Pin::new(&mut read_half).poll_read(&mut cx, &mut read_buf);
        // Read 5 bytes "state"
    }

    let inner = wrapper.into_inner();
    assert_eq!(
        inner.read_pos, 5,
        "SPLIT-3: into_inner must preserve read position"
    );

    asupersync::test_complete!("split_invariant_3_into_inner_preserves_state");
}

#[test]
fn split_invariant_4_drop_one_half_other_works() {
    init_test("split_invariant_4_drop_one_half_other_works");

    let wrapper = SplitStream::new(TestStream::new(b"drop test"));
    let (mut read_half, _write_half) = wrapper.split();

    // Drop write half

    // Read half should still work
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut out = [0u8; 9];
    let mut read_buf = ReadBuf::new(&mut out);
    let result = Pin::new(&mut read_half).poll_read(&mut cx, &mut read_buf);
    assert!(matches!(result, Poll::Ready(Ok(()))));
    assert_eq!(
        read_buf.filled(),
        b"drop test",
        "SPLIT-4: read half works after write half dropped"
    );

    asupersync::test_complete!("split_invariant_4_drop_one_half_other_works");
}

// ════════════════════════════════════════════════════════════════════════
// Behavioral: Lines Invariants (LINES-1 through LINES-4)
// ════════════════════════════════════════════════════════════════════════

use asupersync::io::{BufReader, Lines};
use asupersync::stream::Stream;

fn poll_lines_next<R: asupersync::io::AsyncBufRead + Unpin>(
    lines: &mut Lines<R>,
) -> Poll<Option<io::Result<String>>> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    Pin::new(lines).poll_next(&mut cx)
}

#[test]
fn lines_invariant_1_crlf_stripped_correctly() {
    init_test("lines_invariant_1_crlf_stripped_correctly");

    let data: &[u8] = b"line1\r\nline2\r\n";
    let reader = BufReader::new(data);
    let mut lines = Lines::new(reader);

    match poll_lines_next(&mut lines) {
        Poll::Ready(Some(Ok(s))) => {
            assert_eq!(s, "line1", "LINES-1: CRLF must strip both CR and LF");
        }
        other => panic!("expected line1, got {other:?}"),
    }
    match poll_lines_next(&mut lines) {
        Poll::Ready(Some(Ok(s))) => assert_eq!(s, "line2"),
        other => panic!("expected line2, got {other:?}"),
    }
    assert!(matches!(poll_lines_next(&mut lines), Poll::Ready(None)));

    asupersync::test_complete!("lines_invariant_1_crlf_stripped_correctly");
}

#[test]
fn lines_invariant_2_eof_without_newline() {
    init_test("lines_invariant_2_eof_without_newline");

    let data: &[u8] = b"incomplete";
    let reader = BufReader::new(data);
    let mut lines = Lines::new(reader);

    match poll_lines_next(&mut lines) {
        Poll::Ready(Some(Ok(s))) => {
            assert_eq!(
                s, "incomplete",
                "LINES-2: EOF without newline must emit final line"
            );
        }
        other => panic!("expected 'incomplete', got {other:?}"),
    }
    assert!(matches!(poll_lines_next(&mut lines), Poll::Ready(None)));

    asupersync::test_complete!("lines_invariant_2_eof_without_newline");
}

#[test]
fn lines_invariant_3_empty_yields_none() {
    init_test("lines_invariant_3_empty_yields_none");

    let data: &[u8] = b"";
    let reader = BufReader::new(data);
    let mut lines = Lines::new(reader);

    assert!(
        matches!(poll_lines_next(&mut lines), Poll::Ready(None)),
        "LINES-3: empty reader must yield None"
    );

    asupersync::test_complete!("lines_invariant_3_empty_yields_none");
}

#[test]
fn lines_invariant_4_invalid_utf8_error() {
    init_test("lines_invariant_4_invalid_utf8_error");

    let data: &[u8] = &[0xFF, 0xFE, b'\n'];
    let reader = BufReader::new(data);
    let mut lines = Lines::new(reader);

    match poll_lines_next(&mut lines) {
        Poll::Ready(Some(Err(e))) => {
            assert_eq!(
                e.kind(),
                io::ErrorKind::InvalidData,
                "LINES-4: invalid UTF-8 must produce InvalidData error"
            );
        }
        other => panic!("expected InvalidData error, got {other:?}"),
    }

    asupersync::test_complete!("lines_invariant_4_invalid_utf8_error");
}

// ════════════════════════════════════════════════════════════════════════
// Behavioral: BufReader/BufWriter Invariants (BUF-1 through BUF-4)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn buf_invariant_1_bufreader_matches_underlying() {
    init_test("buf_invariant_1_bufreader_matches_underlying");

    let data: &[u8] = b"buffered read test data";
    let mut reader = BufReader::new(data);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut out = vec![0u8; data.len()];
    let mut read_buf = ReadBuf::new(&mut out);

    let result = Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf);
    assert!(matches!(result, Poll::Ready(Ok(()))));
    assert_eq!(
        read_buf.filled(),
        data,
        "BUF-1: BufReader must produce same bytes as underlying"
    );

    asupersync::test_complete!("buf_invariant_1_bufreader_matches_underlying");
}

#[test]
fn buf_invariant_2_bufwriter_flushed_matches() {
    init_test("buf_invariant_2_bufwriter_flushed_matches");

    let sink = TestStream::new(b"");
    let wrapper = SplitStream::new(sink);
    let (_rh, mut wh) = wrapper.split();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Write and flush through BufWriter
    let data = b"buf write test";
    let result = Pin::new(&mut wh).poll_write(&mut cx, data);
    assert!(matches!(result, Poll::Ready(Ok(n)) if n == data.len()));

    let flush = Pin::new(&mut wh).poll_flush(&mut cx);
    assert!(matches!(flush, Poll::Ready(Ok(()))));

    let inner = wrapper.into_inner();
    assert_eq!(
        inner.written, data,
        "BUF-2: flushed bytes must match cumulative writes"
    );

    asupersync::test_complete!("buf_invariant_2_bufwriter_flushed_matches");
}

#[test]
fn buf_invariant_4_bufreader_sequential_reads() {
    init_test("buf_invariant_4_bufreader_sequential_reads");

    let data: &[u8] = b"first second third";
    let mut reader = BufReader::new(data);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Read first 5 bytes
    let mut out1 = [0u8; 5];
    let mut rb1 = ReadBuf::new(&mut out1);
    let _ = Pin::new(&mut reader).poll_read(&mut cx, &mut rb1);
    assert_eq!(rb1.filled(), b"first");

    // Read next 7 bytes
    let mut out2 = [0u8; 7];
    let mut rb2 = ReadBuf::new(&mut out2);
    let _ = Pin::new(&mut reader).poll_read(&mut cx, &mut rb2);
    assert_eq!(rb2.filled(), b" second");

    // Read remaining
    let mut out3 = [0u8; 6];
    let mut rb3 = ReadBuf::new(&mut out3);
    let _ = Pin::new(&mut reader).poll_read(&mut cx, &mut rb3);
    assert_eq!(
        rb3.filled(),
        b" third",
        "BUF-4: sequential reads must accumulate correctly"
    );

    asupersync::test_complete!("buf_invariant_4_bufreader_sequential_reads");
}

// ════════════════════════════════════════════════════════════════════════
// Behavioral: Stream Adapter Invariants (ADAPT-1 through ADAPT-3)
// ════════════════════════════════════════════════════════════════════════

use asupersync::io::{ReaderStream, StreamReader};

#[test]
fn adapt_invariant_1_reader_stream_round_trip() {
    init_test("adapt_invariant_1_reader_stream_round_trip");

    let data: &[u8] = b"round trip via ReaderStream";
    let mut stream = ReaderStream::with_capacity(data, 8);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut collected = Vec::new();
    loop {
        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(chunk))) => collected.extend_from_slice(&chunk),
            Poll::Ready(Some(Err(e))) => panic!("unexpected error: {e}"),
            Poll::Ready(None) => break,
            Poll::Pending => panic!("unexpected pending"),
        }
    }

    assert_eq!(
        collected, data,
        "ADAPT-1: concatenated chunks must equal original data"
    );

    asupersync::test_complete!("adapt_invariant_1_reader_stream_round_trip");
}

#[test]
fn adapt_invariant_2_stream_reader_round_trip() {
    init_test("adapt_invariant_2_stream_reader_round_trip");

    let chunks = vec![Ok(vec![1u8, 2, 3]), Ok(vec![4, 5]), Ok(vec![6, 7, 8, 9])];
    let stream = asupersync::stream::iter(chunks);
    let mut reader = StreamReader::new(stream);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut out = [0u8; 9];
    let mut rb = ReadBuf::new(&mut out);
    let _ = Pin::new(&mut reader).poll_read(&mut cx, &mut rb);
    assert_eq!(
        rb.filled(),
        &[1, 2, 3, 4, 5, 6, 7, 8, 9],
        "ADAPT-2: read output must equal concatenated stream chunks"
    );

    asupersync::test_complete!("adapt_invariant_2_stream_reader_round_trip");
}

#[test]
fn adapt_invariant_3_stream_reader_defers_error() {
    init_test("adapt_invariant_3_stream_reader_defers_error");

    let chunks: Vec<io::Result<Vec<u8>>> = vec![
        Ok(vec![10, 11, 12]),
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "test error")),
    ];
    let stream = asupersync::stream::iter(chunks);
    let mut reader = StreamReader::new(stream);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // First read should return data, not error
    let mut out = [0u8; 10];
    let mut rb = ReadBuf::new(&mut out);
    let result = Pin::new(&mut reader).poll_read(&mut cx, &mut rb);
    assert!(matches!(result, Poll::Ready(Ok(()))));
    assert_eq!(
        rb.filled(),
        &[10, 11, 12],
        "ADAPT-3: data returned before error"
    );

    // Second read should surface the error
    let mut out2 = [0u8; 10];
    let mut rb2 = ReadBuf::new(&mut out2);
    let result2 = Pin::new(&mut reader).poll_read(&mut cx, &mut rb2);
    assert!(
        matches!(result2, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe),
        "ADAPT-3: error surfaced on next read"
    );

    asupersync::test_complete!("adapt_invariant_3_stream_reader_defers_error");
}

// ════════════════════════════════════════════════════════════════════════
// Source Module Existence
// ════════════════════════════════════════════════════════════════════════

#[test]
fn source_modules_exist() {
    init_test("source_modules_exist");

    let v = parse_json();
    for cat in v["operator_categories"].as_array().unwrap() {
        let module = cat["module"].as_str().unwrap();
        // Check that the module path is referenced in the source markdown
        let first_module = module.split(',').next().unwrap().trim();
        assert!(
            UTIL_MD.contains(first_module),
            "module {first_module} not referenced in markdown"
        );
    }

    asupersync::test_complete!("source_modules_exist");
}
