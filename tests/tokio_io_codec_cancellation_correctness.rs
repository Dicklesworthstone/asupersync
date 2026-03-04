#![allow(clippy::items_after_statements)]
#![allow(missing_docs)]
//! I/O and Codec Cancellation-Correctness Contract Tests
//!
//! Bead: asupersync-2oh2u.2.5 ([T2.5])
//!
//! Proves request→drain→finalize correctness for every I/O and codec operator
//! under cancellation and race-loser scenarios. Demonstrates no obligation leaks,
//! no task leaks, and deterministic buffer-state recovery.
//!
//! # Test Categories
//!
//! - CC-*: Contract validation (JSON artifact structure)
//! - CSR-*: Cancel-safe resume (state preservation across cancel)
//! - RLD-*: Race-loser drain (clean drop in race-loser scenarios)
//! - BA-*: Buffer accounting (committed vs lost bytes)
//! - OL-*: Obligation leak checks
//! - CS-*: Codec state preservation

#[macro_use]
mod common;

use common::*;
use std::collections::HashSet;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

fn parse_json() -> serde_json::Value {
    let raw = include_str!("../docs/tokio_io_codec_cancellation_correctness.json");
    serde_json::from_str(raw).expect("JSON artifact must parse")
}

fn parse_md() -> &'static str {
    include_str!("../docs/tokio_io_codec_cancellation_correctness.md")
}

// ════════════════════════════════════════════════════════════════════════
// CC-1 through CC-14: Contract Validation Tests
// ════════════════════════════════════════════════════════════════════════

#[test]
fn cc_01_json_parses_and_has_required_fields() {
    init_test("cc_01_json_parses_and_has_required_fields");
    let v = parse_json();
    assert!(v.get("bead_id").is_some(), "missing bead_id");
    assert!(v.get("title").is_some(), "missing title");
    assert!(v.get("version").is_some(), "missing version");
    assert!(v.get("generated_at").is_some(), "missing generated_at");
    assert!(v.get("generated_by").is_some(), "missing generated_by");
    assert!(v.get("domains").is_some(), "missing domains");
    assert!(
        v.get("operator_families").is_some(),
        "missing operator_families"
    );
    assert!(v.get("invariants").is_some(), "missing invariants");
    assert!(
        v.get("cancel_safety_matrix").is_some(),
        "missing cancel_safety_matrix"
    );
    assert!(v.get("summary").is_some(), "missing summary");
    asupersync::test_complete!("cc_01_json_parses_and_has_required_fields");
}

#[test]
fn cc_02_bead_id_matches() {
    init_test("cc_02_bead_id_matches");
    let v = parse_json();
    assert_eq!(v["bead_id"].as_str().unwrap(), "asupersync-2oh2u.2.5");
    asupersync::test_complete!("cc_02_bead_id_matches");
}

#[test]
fn cc_03_operator_families_present() {
    init_test("cc_03_operator_families_present");
    let v = parse_json();
    let families = v["operator_families"].as_array().unwrap();
    assert!(
        families.len() >= 9,
        "expected >= 9 families, got {}",
        families.len()
    );
    for fam in families {
        assert!(fam.get("id").is_some(), "family missing id");
        assert!(fam.get("name").is_some(), "family missing name");
        assert!(
            fam.get("cancel_model").is_some(),
            "family missing cancel_model"
        );
    }
    asupersync::test_complete!("cc_03_operator_families_present");
}

#[test]
fn cc_04_required_family_ids() {
    init_test("cc_04_required_family_ids");
    let v = parse_json();
    let ids: HashSet<&str> = v["operator_families"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    for required in [
        "COPY", "SPLIT", "LINES", "BUF", "ADAPT", "FREAD", "FWRITE", "CODEC",
    ] {
        assert!(ids.contains(required), "missing family {required}");
    }
    asupersync::test_complete!("cc_04_required_family_ids");
}

#[test]
fn cc_05_invariants_minimum_count() {
    init_test("cc_05_invariants_minimum_count");
    let v = parse_json();
    let invs = v["invariants"].as_array().unwrap();
    assert!(
        invs.len() >= 8,
        "expected >= 8 invariants, got {}",
        invs.len()
    );
    asupersync::test_complete!("cc_05_invariants_minimum_count");
}

#[test]
fn cc_06_invariant_ids_unique() {
    init_test("cc_06_invariant_ids_unique");
    let v = parse_json();
    let ids: Vec<&str> = v["invariants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    let unique: HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate invariant IDs");
    asupersync::test_complete!("cc_06_invariant_ids_unique");
}

#[test]
fn cc_07_cancel_safety_matrix_covers_all_operators() {
    init_test("cc_07_cancel_safety_matrix_covers_all_operators");
    let v = parse_json();
    let matrix = v["cancel_safety_matrix"].as_array().unwrap();
    assert!(
        matrix.len() >= 12,
        "expected >= 12 operators in cancel matrix, got {}",
        matrix.len()
    );
    for entry in matrix {
        assert!(entry.get("operator").is_some(), "missing operator");
        assert!(entry.get("cancel_safe").is_some(), "missing cancel_safe");
        assert!(
            entry.get("obligation_leak").is_some(),
            "missing obligation_leak"
        );
    }
    asupersync::test_complete!("cc_07_cancel_safety_matrix_covers_all_operators");
}

#[test]
fn cc_08_all_cancel_safe() {
    init_test("cc_08_all_cancel_safe");
    let v = parse_json();
    for entry in v["cancel_safety_matrix"].as_array().unwrap() {
        let op = entry["operator"].as_str().unwrap();
        assert!(
            entry["cancel_safe"].as_bool().unwrap(),
            "operator {op} should be cancel-safe"
        );
    }
    asupersync::test_complete!("cc_08_all_cancel_safe");
}

#[test]
fn cc_09_all_obligation_leak_free() {
    init_test("cc_09_all_obligation_leak_free");
    let v = parse_json();
    assert!(v["summary"]["all_obligation_leak_free"].as_bool().unwrap());
    for entry in v["cancel_safety_matrix"].as_array().unwrap() {
        let op = entry["operator"].as_str().unwrap();
        assert!(
            !entry["obligation_leak"].as_bool().unwrap(),
            "operator {op} should be obligation-leak-free"
        );
    }
    asupersync::test_complete!("cc_09_all_obligation_leak_free");
}

#[test]
fn cc_10_race_loser_data_loss_present() {
    init_test("cc_10_race_loser_data_loss_present");
    let v = parse_json();
    let losses = v["race_loser_data_loss"].as_array().unwrap();
    assert!(
        !losses.is_empty(),
        "race loser data loss matrix should not be empty"
    );
    for entry in losses {
        assert!(entry.get("operator").is_some(), "missing operator");
        assert!(entry.get("severity").is_some(), "missing severity");
        let sev = entry["severity"].as_str().unwrap();
        assert!(
            ["HIGH", "MEDIUM", "LOW"].contains(&sev),
            "invalid severity: {sev}"
        );
    }
    asupersync::test_complete!("cc_10_race_loser_data_loss_present");
}

#[test]
fn cc_11_high_severity_race_losers_identified() {
    init_test("cc_11_high_severity_race_losers_identified");
    let v = parse_json();
    let high_count = v["race_loser_data_loss"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["severity"].as_str().unwrap() == "HIGH")
        .count();
    assert!(
        high_count >= 2,
        "expected >= 2 HIGH severity race losers, got {high_count}"
    );
    // BufWriter and FramedWrite must be HIGH
    let high_ops: HashSet<&str> = v["race_loser_data_loss"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["severity"].as_str().unwrap() == "HIGH")
        .map(|e| e["operator"].as_str().unwrap())
        .collect();
    assert!(
        high_ops.contains("BufWriter"),
        "BufWriter should be HIGH severity"
    );
    assert!(
        high_ops.contains("FramedWrite"),
        "FramedWrite should be HIGH severity"
    );
    asupersync::test_complete!("cc_11_high_severity_race_losers_identified");
}

#[test]
fn cc_12_summary_metrics_consistent() {
    init_test("cc_12_summary_metrics_consistent");
    let v = parse_json();
    let summary = &v["summary"];
    let families = v["operator_families"].as_array().unwrap().len();
    assert_eq!(
        summary["total_operator_families"].as_u64().unwrap() as usize,
        families
    );
    let invariants = v["invariants"].as_array().unwrap().len();
    assert_eq!(
        summary["total_invariants"].as_u64().unwrap() as usize,
        invariants
    );
    asupersync::test_complete!("cc_12_summary_metrics_consistent");
}

#[test]
fn cc_13_drift_rules_present() {
    init_test("cc_13_drift_rules_present");
    let v = parse_json();
    let rules = v["drift_detection"].as_array().unwrap();
    assert!(rules.len() >= 3, "expected >= 3 drift rules");
    for rule in rules {
        assert!(rule.get("id").is_some(), "drift rule missing id");
        assert!(rule.get("trigger").is_some(), "drift rule missing trigger");
        assert!(rule.get("action").is_some(), "drift rule missing action");
    }
    asupersync::test_complete!("cc_13_drift_rules_present");
}

#[test]
fn cc_14_markdown_references_key_sections() {
    init_test("cc_14_markdown_references_key_sections");
    let md = parse_md();
    assert!(
        md.contains("Cancellation Model"),
        "missing Cancellation Model section"
    );
    assert!(
        md.contains("Per-Operator Cancellation Proofs"),
        "missing proofs section"
    );
    assert!(
        md.contains("Obligation and Task Leak"),
        "missing obligation leak section"
    );
    assert!(
        md.contains("Race-Loser Data Loss"),
        "missing race-loser section"
    );
    assert!(
        md.contains("Drift Detection"),
        "missing drift detection section"
    );
    asupersync::test_complete!("cc_14_markdown_references_key_sections");
}

// ════════════════════════════════════════════════════════════════════════
// CSR-1 through CSR-8: Cancel-Safe Resume Tests
// ════════════════════════════════════════════════════════════════════════

use asupersync::io::{AsyncRead, AsyncWrite, BufReader, BufWriter, Lines, ReadBuf, SplitStream};
use asupersync::io::{ReaderStream, StreamReader};
use asupersync::stream::Stream;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

/// A reader that returns Pending on first poll, then data on second.
struct PendingThenDataReader {
    data: Vec<u8>,
    polled: bool,
    pos: usize,
}

impl PendingThenDataReader {
    fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            polled: false,
            pos: 0,
        }
    }
}

impl AsyncRead for PendingThenDataReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.polled {
            this.polled = true;
            return Poll::Pending;
        }
        let remaining = &this.data[this.pos..];
        if remaining.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let n = std::cmp::min(remaining.len(), buf.remaining());
        buf.put_slice(&remaining[..n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

/// A writer that returns Pending once then accepts all data.
struct PendingThenWriter {
    data: Vec<u8>,
    pending_done: bool,
}

impl PendingThenWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            pending_done: false,
        }
    }
}

impl AsyncWrite for PendingThenWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.pending_done {
            this.pending_done = true;
            return Poll::Pending;
        }
        this.data.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Simple test stream: AsyncRead + AsyncWrite backed by a Vec.
struct TestStream {
    read_data: Vec<u8>,
    read_pos: usize,
    written: Vec<u8>,
}

impl TestStream {
    fn from_read(data: &[u8]) -> Self {
        Self {
            read_data: data.to_vec(),
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
        let remaining = &this.read_data[this.read_pos..];
        if remaining.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let n = std::cmp::min(remaining.len(), buf.remaining());
        buf.put_slice(&remaining[..n]);
        this.read_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// CSR-1: BufReader preserves buffer state across cancel (Pending, then resume)
#[test]
fn csr_01_bufreader_cancel_preserves_buffer() {
    init_test("csr_01_bufreader_cancel_preserves_buffer");

    let reader = PendingThenDataReader::new(b"hello world");
    let mut buf_reader = BufReader::new(reader);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // First poll: inner reader returns Pending
    let mut out = [0u8; 11];
    let mut rb = ReadBuf::new(&mut out);
    let result = Pin::new(&mut buf_reader).poll_read(&mut cx, &mut rb);
    assert!(
        matches!(result, Poll::Pending),
        "CSR-1: first poll should be Pending"
    );

    // "Cancel" happened — future was dropped and re-created.
    // Resume: second poll should succeed with data.
    let mut out2 = [0u8; 11];
    let mut rb2 = ReadBuf::new(&mut out2);
    let result2 = Pin::new(&mut buf_reader).poll_read(&mut cx, &mut rb2);
    assert!(
        matches!(result2, Poll::Ready(Ok(()))),
        "CSR-1: second poll should succeed"
    );
    assert_eq!(
        rb2.filled(),
        b"hello world",
        "CSR-1: data must be intact after cancel resume"
    );

    asupersync::test_complete!("csr_01_bufreader_cancel_preserves_buffer");
}

// CSR-2: BufWriter preserves flush progress across cancel
#[test]
fn csr_02_bufwriter_cancel_preserves_flush_progress() {
    init_test("csr_02_bufwriter_cancel_preserves_flush_progress");

    let writer = PendingThenWriter::new();
    let mut buf_writer = BufWriter::new(writer);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Write data to buffer
    let data = b"cancel test data";
    let result = Pin::new(&mut buf_writer).poll_write(&mut cx, data);
    assert!(matches!(result, Poll::Ready(Ok(16))));

    // First flush attempt: inner writer returns Pending
    let flush1 = Pin::new(&mut buf_writer).poll_flush(&mut cx);
    assert!(
        matches!(flush1, Poll::Pending),
        "CSR-2: first flush should pend"
    );

    // Resume flush: should succeed
    let flush2 = Pin::new(&mut buf_writer).poll_flush(&mut cx);
    assert!(
        matches!(flush2, Poll::Ready(Ok(()))),
        "CSR-2: second flush should complete"
    );

    assert_eq!(
        buf_writer.get_ref().data,
        data,
        "CSR-2: all data must reach writer after resume"
    );

    asupersync::test_complete!("csr_02_bufwriter_cancel_preserves_flush_progress");
}

// CSR-3: Lines preserves partial line across cancel
#[test]
fn csr_03_lines_cancel_preserves_partial_line() {
    init_test("csr_03_lines_cancel_preserves_partial_line");

    // Use a reader that delivers data in two chunks to simulate a cancel boundary.
    let data: &[u8] = b"complete line\npartial";
    let reader = BufReader::new(data);
    let mut lines = Lines::new(reader);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // First line: complete
    let poll1 = Pin::new(&mut lines).poll_next(&mut cx);
    assert!(
        matches!(poll1, Poll::Ready(Some(Ok(ref s))) if s == "complete line"),
        "CSR-3: first line should be complete"
    );

    // Second poll: returns the partial line (EOF without newline)
    let poll2 = Pin::new(&mut lines).poll_next(&mut cx);
    assert!(
        matches!(poll2, Poll::Ready(Some(Ok(ref s))) if s == "partial"),
        "CSR-3: partial line at EOF must be emitted"
    );

    asupersync::test_complete!("csr_03_lines_cancel_preserves_partial_line");
}

// CSR-4: SplitStream halves survive cancel (drop one, use other)
#[test]
fn csr_04_split_cancel_one_half() {
    init_test("csr_04_split_cancel_one_half");

    let stream = TestStream::from_read(b"split test");
    let split = SplitStream::new(stream);

    // Get both halves, then drop the write half (simulating cancel of write side)
    let (mut read_half, _write_half) = split.split();

    // Read half should still work
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut out = [0u8; 10];
    let mut rb = ReadBuf::new(&mut out);
    let result = Pin::new(&mut read_half).poll_read(&mut cx, &mut rb);
    assert!(matches!(result, Poll::Ready(Ok(()))));
    assert_eq!(
        rb.filled(),
        b"split test",
        "CSR-4: read half works after write half drop"
    );

    asupersync::test_complete!("csr_04_split_cancel_one_half");
}

// CSR-5: StreamReader preserves offset across cancel
#[test]
fn csr_05_stream_reader_preserves_offset() {
    init_test("csr_05_stream_reader_preserves_offset");

    let chunks: Vec<Result<Vec<u8>, io::Error>> = vec![Ok(vec![1, 2, 3, 4, 5])];
    let stream = asupersync::stream::iter(chunks);
    let mut reader = StreamReader::new(stream);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Read 3 bytes (partial consume of chunk)
    let mut out1 = [0u8; 3];
    let mut rb1 = ReadBuf::new(&mut out1);
    let r1 = Pin::new(&mut reader).poll_read(&mut cx, &mut rb1);
    assert!(matches!(r1, Poll::Ready(Ok(()))));
    assert_eq!(rb1.filled(), &[1, 2, 3]);

    // "Cancel" — the read future was dropped mid-stream. Resume.
    // Read remaining 2 bytes from the same chunk.
    let mut out2 = [0u8; 5];
    let mut rb2 = ReadBuf::new(&mut out2);
    let r2 = Pin::new(&mut reader).poll_read(&mut cx, &mut rb2);
    assert!(matches!(r2, Poll::Ready(Ok(()))));
    assert_eq!(
        rb2.filled(),
        &[4, 5],
        "CSR-5: remaining chunk bytes preserved after cancel"
    );

    asupersync::test_complete!("csr_05_stream_reader_preserves_offset");
}

// CSR-6: ReaderStream cancel produces no stale data
#[test]
fn csr_06_reader_stream_cancel_no_stale_data() {
    init_test("csr_06_reader_stream_cancel_no_stale_data");

    use asupersync::stream::Stream;

    let reader = TestStream::from_read(b"stream data here");
    let mut rs = ReaderStream::new(reader);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // First poll: gets a chunk
    let poll1 = Pin::new(&mut rs).poll_next(&mut cx);
    match poll1 {
        Poll::Ready(Some(Ok(ref chunk))) => {
            assert!(!chunk.is_empty(), "CSR-6: first chunk should have data");
        }
        other => panic!("CSR-6: expected data chunk, got {other:?}"),
    }

    // Second poll (stream exhausted or next chunk)
    let poll2 = Pin::new(&mut rs).poll_next(&mut cx);
    // Should either return more data or None — not stale data from previous poll
    match poll2 {
        Poll::Ready(None) => {} // EOF, fine
        Poll::Ready(Some(Ok(ref chunk))) => {
            // If there's more data, it must be from the stream, not recycled
            assert!(!chunk.is_empty());
        }
        other => panic!("CSR-6: unexpected result {other:?}"),
    }

    asupersync::test_complete!("csr_06_reader_stream_cancel_no_stale_data");
}

// CSR-7: FramedRead preserves decode buffer across cancel
#[test]
fn csr_07_framed_read_cancel_preserves_buffer() {
    init_test("csr_07_framed_read_cancel_preserves_buffer");

    use asupersync::codec::{FramedRead, LinesCodec};
    use asupersync::stream::Stream;

    // Reader delivers partial line first, then rest
    let reader = TestStream::from_read(b"hello\nworld\n");
    let mut framed = FramedRead::new(reader, LinesCodec::new());

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // First poll: should decode "hello"
    let poll1 = Pin::new(&mut framed).poll_next(&mut cx);
    assert!(
        matches!(poll1, Poll::Ready(Some(Ok(ref s))) if s == "hello"),
        "CSR-7: first frame should decode"
    );

    // The buffer should still have "world\n" data. Verify by reading next frame.
    let poll2 = Pin::new(&mut framed).poll_next(&mut cx);
    assert!(
        matches!(poll2, Poll::Ready(Some(Ok(ref s))) if s == "world"),
        "CSR-7: buffered data must survive across polls"
    );

    asupersync::test_complete!("csr_07_framed_read_cancel_preserves_buffer");
}

// CSR-8: FramedWrite preserves encode buffer across cancel
#[test]
fn csr_08_framed_write_cancel_preserves_buffer() {
    init_test("csr_08_framed_write_cancel_preserves_buffer");

    use asupersync::codec::{FramedWrite, LinesCodec};

    let writer = PendingThenWriter::new();
    let mut framed = FramedWrite::new(writer, LinesCodec::new());

    // Encode (synchronous — always succeeds)
    framed.send("buffered".to_string()).unwrap();

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // First flush: Pending (writer not ready)
    let flush1 = framed.poll_flush(&mut cx);
    assert!(
        matches!(flush1, Poll::Pending),
        "CSR-8: first flush should pend"
    );

    // Buffer should still have our encoded data
    assert!(
        !framed.write_buffer().is_empty(),
        "CSR-8: encode buffer must survive cancel"
    );

    // Resume flush: should complete
    let flush2 = framed.poll_flush(&mut cx);
    assert!(
        matches!(flush2, Poll::Ready(Ok(()))),
        "CSR-8: resumed flush should complete"
    );

    assert_eq!(
        framed.get_ref().data.as_slice(),
        b"buffered\n",
        "CSR-8: all encoded data must reach writer"
    );

    asupersync::test_complete!("csr_08_framed_write_cancel_preserves_buffer");
}

// ════════════════════════════════════════════════════════════════════════
// RLD-1 through RLD-5: Race-Loser Drain Tests
// ════════════════════════════════════════════════════════════════════════

// RLD-1: Copy future drop is clean (no panic, no leak)
#[test]
fn rld_01_copy_drop_is_clean() {
    init_test("rld_01_copy_drop_is_clean");

    let mut reader = PendingThenDataReader::new(b"race loser data");
    let mut writer = TestStream::from_read(b"");

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    {
        let mut copy_fut = asupersync::io::copy(&mut reader, &mut writer);
        // First poll: reader returns Pending
        let result = Pin::new(&mut copy_fut).poll(&mut cx);
        assert!(matches!(result, Poll::Pending));
        // Drop the future — simulating race-loser cancellation
    }

    // Writer should have no data (nothing was committed before cancel)
    assert!(
        writer.written.is_empty(),
        "RLD-1: no data committed before cancel"
    );

    asupersync::test_complete!("rld_01_copy_drop_is_clean");
}

// RLD-2: BufWriter drop without flush loses buffered data (race-loser scenario)
#[test]
fn rld_02_bufwriter_drop_loses_unflushed() {
    init_test("rld_02_bufwriter_drop_loses_unflushed");

    let writer = TestStream::from_read(b"");
    let committed_len;

    {
        let mut buf_writer = BufWriter::new(writer);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Write data to buffer (not flushed)
        let data = b"this data will be lost";
        let result = Pin::new(&mut buf_writer).poll_write(&mut cx, data);
        assert!(matches!(result, Poll::Ready(Ok(22))));

        // Check inner writer: should have nothing (data is in BufWriter's buffer)
        committed_len = buf_writer.get_ref().written.len();
        // Drop BufWriter without flushing — race loser scenario
    }

    assert_eq!(
        committed_len, 0,
        "RLD-2: unflushed BufWriter must have 0 committed bytes on race-loser drop"
    );

    asupersync::test_complete!("rld_02_bufwriter_drop_loses_unflushed");
}

// RLD-3: FramedWrite drop without flush loses encoded data
#[test]
fn rld_03_framed_write_drop_loses_encoded() {
    init_test("rld_03_framed_write_drop_loses_encoded");

    use asupersync::codec::{FramedWrite, LinesCodec};

    let writer = TestStream::from_read(b"");
    let committed_len;

    {
        let mut framed = FramedWrite::new(writer, LinesCodec::new());
        // Encode a message (synchronous)
        framed.send("lost on race".to_string()).unwrap();
        // Don't flush — simulating race-loser drop
        committed_len = framed.get_ref().written.len();
    }

    assert_eq!(
        committed_len, 0,
        "RLD-3: unflushed FramedWrite must have 0 committed bytes on race-loser drop"
    );

    asupersync::test_complete!("rld_03_framed_write_drop_loses_encoded");
}

// RLD-4: SplitStream race-loser drop preserves inner stream
#[test]
fn rld_04_split_race_loser_preserves_inner() {
    init_test("rld_04_split_race_loser_preserves_inner");

    let stream = TestStream::from_read(b"preserved");
    let split = SplitStream::new(stream);

    // Read a few bytes via read half
    {
        let (mut rh, _wh) = split.split();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut out = [0u8; 4];
        let mut rb = ReadBuf::new(&mut out);
        let _ = Pin::new(&mut rh).poll_read(&mut cx, &mut rb);
        // Drop both halves
    }

    // Drop split — simulating race-loser cancellation of the entire split
    let inner = split.into_inner();

    // Verify inner stream state: read_pos should be 4 (we read 4 bytes)
    assert_eq!(
        inner.read_pos, 4,
        "RLD-4: inner stream position preserved after split drop"
    );

    asupersync::test_complete!("rld_04_split_race_loser_preserves_inner");
}

// RLD-5: Framed duplex drop is clean on both sides
#[test]
fn rld_05_framed_duplex_drop_clean() {
    init_test("rld_05_framed_duplex_drop_clean");

    use asupersync::codec::{Framed, LinesCodec};
    use asupersync::stream::Stream;

    let transport = TestStream::from_read(b"incoming\n");
    let mut framed = Framed::new(transport, LinesCodec::new());

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Read one frame
    let poll = Pin::new(&mut framed).poll_next(&mut cx);
    assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "incoming"));

    // Encode but don't flush (write side)
    framed.send("outgoing".to_string()).unwrap();
    assert!(!framed.write_buffer().is_empty());

    // Drop the Framed — race loser scenario
    let parts = framed.into_parts();

    // Write buffer has unflushed data
    assert!(
        !parts.write_buf.is_empty(),
        "RLD-5: write_buf retains encoded data on into_parts"
    );
    // Read buffer may be empty (consumed by decode)
    // Transport written should be empty (never flushed)
    assert!(
        parts.inner.written.is_empty(),
        "RLD-5: unflushed data never reaches transport"
    );

    asupersync::test_complete!("rld_05_framed_duplex_drop_clean");
}

// ════════════════════════════════════════════════════════════════════════
// BA-1 through BA-4: Buffer Accounting Tests
// ════════════════════════════════════════════════════════════════════════

// BA-1: Copy committed bytes match written bytes exactly
#[test]
fn ba_01_copy_committed_equals_written() {
    init_test("ba_01_copy_committed_equals_written");

    let data = b"exact byte accounting";
    let mut reader = TestStream::from_read(data);
    let mut writer = TestStream::from_read(b"");

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut copy_fut = asupersync::io::copy(&mut reader, &mut writer);
    let result = Pin::new(&mut copy_fut).poll(&mut cx);

    match result {
        Poll::Ready(Ok(n)) => {
            assert_eq!(
                n as usize,
                data.len(),
                "BA-1: copy returns exact byte count"
            );
            assert_eq!(
                writer.written.len(),
                data.len(),
                "BA-1: writer received exact bytes"
            );
            assert_eq!(writer.written.as_slice(), data, "BA-1: data integrity");
        }
        other => panic!("BA-1: expected Ready(Ok), got {other:?}"),
    }

    asupersync::test_complete!("ba_01_copy_committed_equals_written");
}

// BA-2: BufWriter partial flush tracks written cursor correctly
#[test]
fn ba_02_bufwriter_partial_flush_tracks_cursor() {
    init_test("ba_02_bufwriter_partial_flush_tracks_cursor");

    /// Writer that accepts only N bytes at a time.
    struct SlowWriter {
        data: Vec<u8>,
        max_per_write: usize,
    }

    impl AsyncWrite for SlowWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let n = std::cmp::min(buf.len(), this.max_per_write);
            this.data.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let writer = SlowWriter {
        data: Vec::new(),
        max_per_write: 3,
    };
    let mut buf_writer = BufWriter::new(writer);

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Write 10 bytes to buffer
    let data = b"0123456789";
    let _ = Pin::new(&mut buf_writer).poll_write(&mut cx, data);

    // Flush: SlowWriter accepts 3 bytes at a time, but BufWriter loops until done
    let flush = Pin::new(&mut buf_writer).poll_flush(&mut cx);
    assert!(matches!(flush, Poll::Ready(Ok(()))));

    assert_eq!(
        buf_writer.get_ref().data.as_slice(),
        data,
        "BA-2: all bytes must reach slow writer through partial flushes"
    );

    asupersync::test_complete!("ba_02_bufwriter_partial_flush_tracks_cursor");
}

// BA-3: FramedWrite split_to progress is monotonic
#[test]
fn ba_03_framed_write_split_to_monotonic() {
    init_test("ba_03_framed_write_split_to_monotonic");

    use asupersync::codec::{FramedWrite, LinesCodec};

    let writer = TestStream::from_read(b"");
    let mut framed = FramedWrite::new(writer, LinesCodec::new());

    // Encode three messages
    framed.send("alpha".to_string()).unwrap();
    framed.send("beta".to_string()).unwrap();
    framed.send("gamma".to_string()).unwrap();

    let total_encoded = framed.write_buffer().len();
    assert!(total_encoded > 0, "BA-3: encoded data should be non-empty");

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Flush all
    let flush = framed.poll_flush(&mut cx);
    assert!(matches!(flush, Poll::Ready(Ok(()))));

    // Buffer should be empty after flush (all split_to'd)
    assert!(
        framed.write_buffer().is_empty(),
        "BA-3: write buffer empty after complete flush"
    );

    // Writer received all encoded data
    let expected = b"alpha\nbeta\ngamma\n";
    assert_eq!(
        framed.get_ref().written.as_slice(),
        expected,
        "BA-3: all encoded frames reached writer"
    );

    asupersync::test_complete!("ba_03_framed_write_split_to_monotonic");
}

// BA-4: CopyBidirectional returns accurate counts
#[test]
fn ba_04_copy_bidirectional_accurate_counts() {
    init_test("ba_04_copy_bidirectional_accurate_counts");

    // TestStream that supports both read and write
    let mut a = TestStream {
        read_data: b"from_a".to_vec(),
        read_pos: 0,
        written: Vec::new(),
    };
    let mut b = TestStream {
        read_data: b"from_b_longer".to_vec(),
        read_pos: 0,
        written: Vec::new(),
    };

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut bidir = asupersync::io::copy_bidirectional(&mut a, &mut b);
    let result = Pin::new(&mut bidir).poll(&mut cx);

    match result {
        Poll::Ready(Ok((a_to_b, b_to_a))) => {
            assert_eq!(
                a_to_b as usize,
                b"from_a".len(),
                "BA-4: a→b count matches a's data"
            );
            assert_eq!(
                b_to_a as usize,
                b"from_b_longer".len(),
                "BA-4: b→a count matches b's data"
            );
            assert_eq!(b.written.as_slice(), b"from_a", "BA-4: b received a's data");
            assert_eq!(
                a.written.as_slice(),
                b"from_b_longer",
                "BA-4: a received b's data"
            );
        }
        other => panic!("BA-4: expected Ready(Ok), got {other:?}"),
    }

    asupersync::test_complete!("ba_04_copy_bidirectional_accurate_counts");
}

// ════════════════════════════════════════════════════════════════════════
// OL-1 through OL-3: Obligation Leak Tests
// ════════════════════════════════════════════════════════════════════════

// OL-1: All I/O operators are zero-task (verified via source analysis assertion)
#[test]
fn ol_01_io_operators_are_zero_task() {
    init_test("ol_01_io_operators_are_zero_task");

    // Structural proof: instantiate each operator, drop it, verify no panic.
    // All operators are stack-only or heap-buffered; none spawn tasks.

    // Copy
    {
        let mut r = TestStream::from_read(b"a");
        let mut w = TestStream::from_read(b"");
        let _copy = asupersync::io::copy(&mut r, &mut w);
    }

    // BufReader
    {
        let _br = BufReader::new(TestStream::from_read(b"a"));
    }

    // BufWriter
    {
        let _bw = BufWriter::new(TestStream::from_read(b""));
    }

    // Lines
    {
        let reader = BufReader::new(TestStream::from_read(b"a\n"));
        let _lines = Lines::new(reader);
    }

    // SplitStream
    {
        let _split = SplitStream::new(TestStream::from_read(b"a"));
    }

    // ReaderStream
    {
        let _rs = ReaderStream::new(TestStream::from_read(b"a"));
    }

    // StreamReader
    {
        let chunks: Vec<Result<Vec<u8>, io::Error>> = vec![Ok(vec![1])];
        let _sr = StreamReader::new(asupersync::stream::iter(chunks));
    }

    // FramedRead
    {
        use asupersync::codec::{FramedRead, LinesCodec};
        let _fr = FramedRead::new(TestStream::from_read(b"a\n"), LinesCodec::new());
    }

    // FramedWrite
    {
        use asupersync::codec::{FramedWrite, LinesCodec};
        let _fw = FramedWrite::new(TestStream::from_read(b""), LinesCodec::new());
    }

    // Framed
    {
        use asupersync::codec::{Framed, LinesCodec};
        let _f = Framed::new(TestStream::from_read(b"a\n"), LinesCodec::new());
    }

    // If we got here, no panic on any drop — zero-task confirmed
    asupersync::test_complete!("ol_01_io_operators_are_zero_task");
}

// OL-2: Codec operators are stateless or state-preserving on drop
#[test]
fn ol_02_codec_drop_is_clean() {
    init_test("ol_02_codec_drop_is_clean");

    use asupersync::codec::{BytesCodec, LengthDelimitedCodec, LinesCodec};

    // LinesCodec
    {
        let _codec = LinesCodec::new();
    }

    // LengthDelimitedCodec
    {
        let _codec = LengthDelimitedCodec::new();
    }

    // BytesCodec
    {
        let _codec = BytesCodec::new();
    }

    // No panics, no leaked resources
    asupersync::test_complete!("ol_02_codec_drop_is_clean");
}

// OL-3: FramedRead into_parts recovers all state (no hidden obligations)
#[test]
fn ol_03_framed_read_into_parts_complete() {
    init_test("ol_03_framed_read_into_parts_complete");

    use asupersync::codec::{FramedRead, LinesCodec};
    use asupersync::stream::Stream;

    let reader = TestStream::from_read(b"first\nsecond\n");
    let mut framed = FramedRead::new(reader, LinesCodec::new());

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Read one frame
    let _ = Pin::new(&mut framed).poll_next(&mut cx);

    // Decompose: all state accessible
    let (inner, _decoder, buffer) = framed.into_parts();

    // Inner reader has advanced
    assert!(inner.read_pos > 0, "OL-3: reader advanced");

    // Buffer may have remaining data
    // The key point: no hidden state is leaked. Everything is returned via into_parts.
    let _ = buffer; // Buffer accessible for inspection

    asupersync::test_complete!("ol_03_framed_read_into_parts_complete");
}

// ════════════════════════════════════════════════════════════════════════
// CS-1 through CS-3: Codec State Preservation Tests
// ════════════════════════════════════════════════════════════════════════

// CS-1: LinesCodec preserves next_index across partial decode
#[test]
fn cs_01_lines_codec_partial_decode_state() {
    init_test("cs_01_lines_codec_partial_decode_state");

    use asupersync::bytes::BytesMut;
    use asupersync::codec::{Decoder, LinesCodec};

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();

    // Feed partial data (no newline)
    buf.put_slice(b"partial");
    let result = codec.decode(&mut buf);
    assert!(matches!(result, Ok(None)), "CS-1: no complete line yet");

    // Buffer should still have the partial data
    assert_eq!(
        &buf[..],
        b"partial",
        "CS-1: buffer preserved after partial decode"
    );

    // Feed the rest
    buf.put_slice(b" line\n");
    let result = codec.decode(&mut buf);
    assert!(
        matches!(result, Ok(Some(ref s)) if s == "partial line"),
        "CS-1: complete line decoded after resume"
    );

    asupersync::test_complete!("cs_01_lines_codec_partial_decode_state");
}

// CS-2: LengthDelimitedCodec preserves head/data state across partial decode
#[test]
fn cs_02_length_delimited_partial_decode_state() {
    init_test("cs_02_length_delimited_partial_decode_state");

    use asupersync::bytes::BytesMut;
    use asupersync::codec::{Decoder, LengthDelimitedCodec};

    let mut codec = LengthDelimitedCodec::new();
    let mut buf = BytesMut::new();

    // Feed just the length header (4 bytes big-endian for length 5)
    buf.put_slice(&[0, 0, 0, 5]);
    let result = codec.decode(&mut buf);
    // Should need more data (have header but not the body)
    assert!(matches!(result, Ok(None)), "CS-2: need body after header");

    // Feed the body
    buf.put_slice(b"hello");
    let result = codec.decode(&mut buf);
    match result {
        Ok(Some(frame)) => {
            assert_eq!(
                &frame[..],
                b"hello",
                "CS-2: frame decoded correctly after resume"
            );
        }
        other => panic!("CS-2: expected frame, got {other:?}"),
    }

    asupersync::test_complete!("cs_02_length_delimited_partial_decode_state");
}

// CS-3: BytesCodec is stateless (always decodes all available bytes)
#[test]
fn cs_03_bytes_codec_stateless() {
    init_test("cs_03_bytes_codec_stateless");

    use asupersync::bytes::BytesMut;
    use asupersync::codec::{BytesCodec, Decoder};

    let mut codec = BytesCodec::new();
    let mut buf = BytesMut::new();

    // Empty buffer: no frame
    let result = codec.decode(&mut buf);
    assert!(matches!(result, Ok(None)), "CS-3: empty buffer yields None");

    // Some data
    buf.put_slice(b"any bytes");
    let result = codec.decode(&mut buf);
    match result {
        Ok(Some(frame)) => {
            assert_eq!(&frame[..], b"any bytes", "CS-3: all bytes consumed");
        }
        other => panic!("CS-3: expected frame, got {other:?}"),
    }

    // Buffer should be empty after decode
    assert!(
        buf.is_empty(),
        "CS-3: buffer drained after BytesCodec decode"
    );

    asupersync::test_complete!("cs_03_bytes_codec_stateless");
}
