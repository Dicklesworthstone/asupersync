//! Contract tests for the Async I/O parity audit (2oh2u.2.1).
//!
//! Validates document structure, gap coverage, and semantic analysis completeness.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_audit_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_io_parity_audit.md");
    std::fs::read_to_string(path).expect("audit document must exist")
}

fn normalize_table_cell(cell: &str) -> String {
    cell.trim()
        .trim_matches('~')
        .trim_matches('`')
        .trim_matches('*')
        .trim()
        .to_string()
}

fn extract_gap_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = normalize_table_cell(id);
            if id.starts_with("IO-G") && id.len() >= 4 {
                ids.insert(id);
            }
        }
    }
    ids
}

#[test]
fn audit_document_exists_and_is_nonempty() {
    let doc = load_audit_doc();
    assert!(
        doc.len() > 2000,
        "audit document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn audit_references_correct_bead() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("asupersync-2oh2u.2.1"),
        "document must reference bead 2oh2u.2.1"
    );
    assert!(doc.contains("[T2.1]"), "document must reference T2.1");
}

#[test]
fn audit_covers_tokio_io_surface() {
    let doc = load_audit_doc();
    assert!(doc.contains("tokio::io"), "must reference tokio::io");
    assert!(
        doc.contains("AsyncRead") && doc.contains("AsyncWrite"),
        "must cover core AsyncRead/AsyncWrite traits"
    );
    assert!(
        doc.contains("AsyncBufRead"),
        "must cover AsyncBufRead trait"
    );
    assert!(doc.contains("AsyncSeek"), "must cover AsyncSeek trait");
}

#[test]
fn audit_covers_tokio_util_codec_surface() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("tokio-util") || doc.contains("tokio_util"),
        "must reference tokio-util"
    );
    assert!(
        doc.contains("Decoder") && doc.contains("Encoder"),
        "must cover Decoder/Encoder traits"
    );
    assert!(doc.contains("Framed"), "must cover Framed transport");
    assert!(
        doc.contains("LengthDelimited"),
        "must cover LengthDelimitedCodec"
    );
}

#[test]
fn audit_covers_read_ext_methods() {
    let doc = load_audit_doc();
    let methods = [
        "read_exact",
        "read_to_end",
        "read_to_string",
        "chain",
        "take",
    ];
    for method in &methods {
        assert!(
            doc.contains(method),
            "audit must cover AsyncReadExt::{method}"
        );
    }
}

#[test]
fn audit_covers_write_ext_methods() {
    let doc = load_audit_doc();
    let methods = ["write_all", "flush", "shutdown"];
    for method in &methods {
        assert!(
            doc.contains(method),
            "audit must cover AsyncWriteExt::{method}"
        );
    }
}

#[test]
fn audit_covers_buffered_io() {
    let doc = load_audit_doc();
    assert!(doc.contains("BufReader"), "must cover BufReader");
    assert!(doc.contains("BufWriter"), "must cover BufWriter");
}

#[test]
fn audit_covers_split_ownership() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("split") && doc.contains("into_split"),
        "must cover both split modes (borrowed and owned)"
    );
    assert!(
        doc.contains("ReadHalf") || doc.contains("WriteHalf"),
        "must reference split half types"
    );
}

#[test]
fn audit_covers_vectored_io() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("vectored") || doc.contains("Vectored"),
        "must cover vectored I/O"
    );
    assert!(
        doc.contains("is_write_vectored"),
        "must cover vectored capability check"
    );
}

#[test]
fn audit_covers_eof_behavior() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("EOF") && doc.contains("UnexpectedEof"),
        "must cover EOF behavior semantics"
    );
}

#[test]
fn audit_covers_shutdown_semantics() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("Shutdown Semantics") || doc.contains("poll_shutdown"),
        "must cover shutdown semantics"
    );
}

#[test]
fn audit_covers_cancel_safety() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("Cancel-Safe") || doc.contains("cancel-safe"),
        "must cover cancel-safety analysis"
    );
}

#[test]
fn audit_has_gap_entries() {
    let doc = load_audit_doc();
    let ids = extract_gap_ids(&doc);
    assert!(
        ids.len() >= 10,
        "audit must identify >= 10 I/O gaps, found {}",
        ids.len()
    );
}

#[test]
fn audit_classifies_gap_severity() {
    let doc = load_audit_doc();
    for level in &["High", "Medium", "Low"] {
        assert!(
            doc.contains(level),
            "audit must use severity level: {level}"
        );
    }
}

#[test]
fn audit_has_gap_summary_with_phases() {
    let doc = load_audit_doc();
    assert!(doc.contains("Gap Summary"), "must have gap summary section");
    let phase_count = ["Phase A", "Phase B", "Phase C", "Phase D"]
        .iter()
        .filter(|p| doc.contains(**p))
        .count();
    assert!(
        phase_count >= 3,
        "gap summary must have >= 3 execution phases, found {phase_count}"
    );
}

#[test]
fn audit_covers_codec_types() {
    let doc = load_audit_doc();
    let codecs = ["BytesCodec", "LinesCodec", "LengthDelimitedCodec"];
    for codec in &codecs {
        assert!(doc.contains(codec), "audit must cover codec: {codec}");
    }
}

#[test]
fn audit_covers_stream_adapter_gaps() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("ReaderStream") || doc.contains("StreamReader"),
        "must identify Stream/AsyncRead bridge adapter gaps"
    );
}

#[test]
fn audit_covers_duplex_stream_gap() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("Duplex") || doc.contains("SimplexStream"),
        "must identify in-memory duplex/simplex stream gap"
    );
}

#[test]
fn audit_notes_asupersync_extensions() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("WritePermit"),
        "must note Asupersync-specific WritePermit"
    );
    assert!(
        doc.contains("IoCap") || doc.contains("Capability"),
        "must note capability-based I/O extensions"
    );
}

#[test]
fn audit_covers_integer_read_write_gap() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("read_u16") || doc.contains("read_u32"),
        "must identify missing integer read/write methods"
    );
}

// =============================================================================
// EXTENDED COVERAGE: gap enumeration, severity distribution, module paths,
// trait parity tables, semantic sections, asupersync extensions
// =============================================================================

fn extract_gap_summary_rows(doc: &str) -> Vec<(String, String, String)> {
    // Parse rows from the "Gap Summary" section.
    // Format: | ID | Description | Severity | Effort | Phase |
    let Some(summary) = doc.split("Gap Summary").nth(1) else {
        return Vec::new();
    };
    let mut gaps = Vec::new();
    for line in summary.lines() {
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if cols.len() >= 6 {
            let id = normalize_table_cell(cols[1]);
            let severity = normalize_table_cell(cols[3]);
            let phase = cols.get(5).unwrap_or(&"");
            if id.starts_with("IO-G") {
                gaps.push((id, severity, phase.to_string()));
            }
        }
    }
    gaps
}

#[test]
fn gap_summary_covers_all_14_gaps() {
    let doc = load_audit_doc();
    let gaps = extract_gap_summary_rows(&doc);
    assert!(
        gaps.len() >= 14,
        "gap summary must list >= 14 gaps, found {}",
        gaps.len()
    );
}

#[test]
fn all_gap_ids_from_g1_to_g14_present() {
    let doc = load_audit_doc();
    let ids = extract_gap_ids(&doc);
    for i in 1..=14 {
        let id = format!("IO-G{i}");
        assert!(ids.contains(&id), "missing gap ID: {id}");
    }
}

#[test]
fn severity_distribution_matches_documented_totals() {
    let doc = load_audit_doc();
    let gaps = extract_gap_summary_rows(&doc);

    let high = gaps.iter().filter(|(_, s, _)| s == "High").count();
    let medium = gaps.iter().filter(|(_, s, _)| s == "Medium").count();
    let low = gaps.iter().filter(|(_, s, _)| s == "Low").count();

    assert!(high >= 3, "expected >= 3 High gaps, found {high}");
    assert!(medium >= 5, "expected >= 5 Medium gaps, found {medium}");
    assert!(low >= 5, "expected >= 5 Low gaps, found {low}");
}

#[test]
fn high_severity_gaps_are_phase_a() {
    let doc = load_audit_doc();
    let gaps = extract_gap_summary_rows(&doc);

    for (id, severity, phase) in &gaps {
        if severity == "High" {
            assert!(
                phase.contains('A'),
                "high-severity gap {id} should be Phase A, found '{phase}'"
            );
        }
    }
}

#[test]
fn all_phases_are_valid() {
    let doc = load_audit_doc();
    let gaps = extract_gap_summary_rows(&doc);
    let valid_phases = ["A", "B", "C", "D"];

    for (id, _, phase) in &gaps {
        let closed_in_track = phase.starts_with('T');
        assert!(
            closed_in_track || valid_phases.iter().any(|p| phase.contains(p)),
            "gap {id} has invalid phase '{phase}', expected one of {valid_phases:?} or a closure-track marker"
        );
    }
}

#[test]
fn every_gap_id_in_summary_appears_in_body() {
    let doc = load_audit_doc();
    let summary_gaps = extract_gap_summary_rows(&doc);
    let body_ids = extract_gap_ids(&doc);

    for (gap_id, _, _) in &summary_gaps {
        assert!(
            body_ids.contains(gap_id),
            "summary gap {gap_id} must also appear in body sections"
        );
    }
}

#[test]
fn core_trait_parity_table_has_all_four_traits() {
    let doc = load_audit_doc();
    let traits = ["AsyncRead", "AsyncWrite", "AsyncBufRead", "AsyncSeek"];
    let trait_section = doc
        .split("Core Trait Parity")
        .nth(1)
        .expect("must have core trait parity section");

    for t in &traits {
        assert!(
            trait_section.contains(t),
            "core trait parity must list: {t}"
        );
    }
}

#[test]
fn codec_trait_parity_lists_decoder_encoder() {
    let doc = load_audit_doc();
    let section = doc
        .split("tokio-util Traits")
        .nth(1)
        .expect("must have tokio-util traits section");

    assert!(section.contains("Decoder"), "must list Decoder");
    assert!(section.contains("Encoder"), "must list Encoder");
}

#[test]
fn framed_transport_types_complete() {
    let doc = load_audit_doc();
    let framed_types = [
        "Framed<T, U>",
        "FramedRead<R, D>",
        "FramedWrite<W, E>",
        "FramedParts",
    ];
    for ft in &framed_types {
        assert!(doc.contains(ft), "framed transport section must list: {ft}");
    }
}

#[test]
fn semantic_differences_has_all_five_subsections() {
    let doc = load_audit_doc();
    let sections = [
        "EOF Behavior",
        "Shutdown Semantics",
        "Buffering Invariants",
        "Vectored I/O",
        "Cancel-Safety",
    ];
    for section in &sections {
        assert!(
            doc.contains(section),
            "semantic differences must have subsection: {section}"
        );
    }
}

#[test]
fn buffering_invariants_document_defaults() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("8192"),
        "must document 8192-byte buffer defaults"
    );
}

#[test]
fn cancel_safety_table_covers_key_operations() {
    let doc = load_audit_doc();
    let ops = ["read_exact", "write_all", "copy", "flush", "fill_buf"];
    let cancel_section = doc
        .split("Cancel-Safety")
        .nth(1)
        .expect("must have cancel-safety section");

    for op in &ops {
        assert!(
            cancel_section.contains(op),
            "cancel-safety table must cover: {op}"
        );
    }
}

#[test]
fn asupersync_extensions_table_is_complete() {
    let doc = load_audit_doc();
    let extensions = [
        "WritePermit",
        "IoCap",
        "BrowserStream",
        "BrowserStorage",
        "CopyWithProgress",
        "CopyBidirectional",
    ];
    for ext in &extensions {
        assert!(doc.contains(ext), "asupersync extensions must list: {ext}");
    }
}

#[test]
fn module_paths_reference_real_source_locations() {
    let doc = load_audit_doc();
    let paths = [
        "io/read.rs",
        "io/write.rs",
        "io/copy.rs",
        "io/seek.rs",
        "codec/decoder.rs",
        "codec/encoder.rs",
    ];
    for path in &paths {
        assert!(
            doc.contains(path),
            "audit must reference module path: {path}"
        );
    }
}

#[test]
fn io_source_files_exist() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected_files = [
        "src/io/read.rs",
        "src/io/write.rs",
        "src/io/copy.rs",
        "src/io/seek.rs",
        "src/io/buf_reader.rs",
        "src/io/buf_writer.rs",
        "src/io/split.rs",
        "src/codec/decoder.rs",
        "src/codec/encoder.rs",
        "src/codec/framed.rs",
    ];
    for file in &expected_files {
        let path = manifest_dir.join(file);
        assert!(path.exists(), "referenced source file must exist: {file}");
    }
}

#[test]
fn document_has_revision_history() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("Revision History"),
        "audit must include revision history section"
    );
    assert!(
        doc.contains("SapphireHill"),
        "revision history must credit authoring agent"
    );
}

#[test]
fn split_gap_documents_migration_blocker() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("Migration blocker") || doc.contains("migration blocker"),
        "IO-G9 must document that into_split is a migration blocker"
    );
    assert!(
        doc.contains("RefCell"),
        "IO-G9 must note current RefCell-based split limitation"
    );
}

#[test]
fn priority_ranking_has_four_phases() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("Phase A") && doc.contains("Critical for Migration"),
        "must have Phase A (critical for migration)"
    );
    assert!(
        doc.contains("Phase B") && doc.contains("Wire Protocols"),
        "must have Phase B (wire protocols)"
    );
    assert!(
        doc.contains("Phase C") && doc.contains("Convenience"),
        "must have Phase C (convenience)"
    );
    assert!(
        doc.contains("Phase D") && doc.contains("Polish"),
        "must have Phase D (polish)"
    );
}

#[test]
fn total_gap_count_matches_documented_14() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("14 gaps"),
        "document must state total of 14 gaps"
    );
    assert!(
        doc.contains("3 High") && doc.contains("5 Medium") && doc.contains("6 Low"),
        "document must state severity breakdown: 3 High, 5 Medium, 6 Low"
    );
}

#[test]
fn audit_includes_t2_6_reactor_contract_section() {
    let doc = load_audit_doc();
    assert!(
        doc.contains("Reactor Backend Parity and Readiness Consistency (T2.6)"),
        "document must include explicit T2.6 reactor parity section"
    );
    for contract in ["R09.1", "R09.2", "R09.3", "R09.4", "R09.5", "R09.6"] {
        assert!(
            doc.contains(contract),
            "T2.6 section must include contract id: {contract}"
        );
    }
}

#[test]
fn reactor_contract_matrix_covers_all_backends() {
    let doc = load_audit_doc();
    for backend in ["epoll", "kqueue", "IOCP (windows)", "io_uring"] {
        assert!(
            doc.contains(backend),
            "reactor contract matrix must include backend: {backend}"
        );
    }
}

#[test]
fn reactor_contract_links_source_and_test_evidence() {
    let doc = load_audit_doc();
    for source in [
        "src/runtime/reactor/epoll.rs",
        "src/runtime/reactor/kqueue.rs",
        "src/runtime/reactor/windows.rs",
        "src/runtime/reactor/io_uring.rs",
        "src/runtime/io_driver.rs",
    ] {
        assert!(
            doc.contains(source),
            "reactor contract must cite source anchor: {source}"
        );
    }

    for test in [
        "tests/io_uring_reactor.rs",
        "tests/io_driver_concurrency.rs",
        "tests/io_cancellation.rs",
        "tests/tokio_io_parity_audit.rs",
    ] {
        assert!(
            doc.contains(test),
            "reactor contract must cite test anchor: {test}"
        );
    }
}

#[test]
fn reactor_contract_includes_drift_rules() {
    let doc = load_audit_doc();
    for rule_token in [
        "Drift-Detection Rules (T2.6)",
        "stale-token behavior non-panicking",
        "duplicate user-level wake dispatch",
        "NotFound",
    ] {
        assert!(
            doc.contains(rule_token),
            "reactor drift rules must include token: {rule_token}"
        );
    }
}
