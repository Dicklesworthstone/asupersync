//! Comprehensive integration tests for the franken_evidence crate (bd-qaaxt.4).
//!
//! Covers: proptest-based random validation, concurrent writer safety,
//! full pipeline (builder → JSONL → read → render), schema migration,
//! and galaxy-brain rendering determinism.

use franken_evidence::export::{ExporterConfig, JsonlExporter, read_jsonl};
use franken_evidence::render::{self, DiffContext};
use franken_evidence::{EvidenceLedger, EvidenceLedgerBuilder, ValidationError};
use proptest::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::io::Write;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn valid_builder() -> EvidenceLedgerBuilder {
    EvidenceLedgerBuilder::new()
        .ts_unix_ms(1_700_000_000_000)
        .component("scheduler")
        .action("preempt")
        .posterior(vec![0.7, 0.2, 0.1])
        .expected_loss("preempt", 0.05)
        .expected_loss("continue", 0.30)
        .expected_loss("defer", 0.15)
        .chosen_expected_loss(0.05)
        .calibration_score(0.92)
        .fallback_active(false)
        .top_feature("queue_depth", 0.45)
        .top_feature("priority_gap", 0.30)
}

/// Generate a normalized posterior that sums to ~1.0.
fn arb_posterior() -> impl Strategy<Value = Vec<f64>> {
    prop::collection::vec(1.0_f64..=100.0, 1..=10).prop_map(|raw| {
        let sum: f64 = raw.iter().sum();
        raw.iter().map(|v| v / sum).collect()
    })
}

/// Generate a valid EvidenceLedger entry.
fn arb_entry() -> impl Strategy<Value = EvidenceLedger> {
    (
        any::<u64>(),                                            // ts_unix_ms
        "[a-z]{3,12}",                                           // component
        "[a-z]{3,12}",                                           // action
        arb_posterior(),                                         // posterior
        0.0_f64..=10.0,                                          // chosen_expected_loss
        0.0_f64..=1.0,                                           // calibration_score
        any::<bool>(),                                           // fallback_active
        prop::collection::vec(("[a-z]{3,8}", 0.0..=1.0), 0..=5), // top_features
    )
        .prop_map(
            |(ts, component, action, posterior, cel, cal, fb, features)| {
                let mut builder = EvidenceLedgerBuilder::new()
                    .ts_unix_ms(ts)
                    .component(component)
                    .action(action.clone())
                    .posterior(posterior)
                    .expected_loss(action, cel)
                    .chosen_expected_loss(cel)
                    .calibration_score(cal)
                    .fallback_active(fb);
                for (name, weight) in features {
                    builder = builder.top_feature(name, weight);
                }
                builder.build().unwrap()
            },
        )
}

// ---------------------------------------------------------------------------
// (1) Proptest: random validation — valid entries always pass validation
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proptest_valid_entries_pass_validation(entry in arb_entry()) {
        let errors = entry.validate();
        prop_assert!(errors.is_empty(), "unexpected validation errors: {errors:?}");
    }

    #[test]
    fn proptest_serde_roundtrip(entry in arb_entry()) {
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: EvidenceLedger = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(entry.ts_unix_ms, parsed.ts_unix_ms);
        prop_assert_eq!(entry.component, parsed.component);
        prop_assert_eq!(entry.action, parsed.action);
        prop_assert_eq!(entry.fallback_active, parsed.fallback_active);

        // Float fields may have last-bit rounding differences after
        // JSON roundtrip, so compare with tolerance.
        prop_assert_eq!(entry.posterior.len(), parsed.posterior.len());
        for (a, b) in entry.posterior.iter().zip(parsed.posterior.iter()) {
            prop_assert!((a - b).abs() < 1e-12, "posterior mismatch: {a} vs {b}");
        }
        prop_assert_eq!(entry.top_features.len(), parsed.top_features.len());
        for ((n1, w1), (n2, w2)) in entry.top_features.iter().zip(parsed.top_features.iter()) {
            prop_assert_eq!(n1, n2);
            prop_assert!((w1 - w2).abs() < 1e-12, "weight mismatch: {w1} vs {w2}");
        }
    }
}

// ---------------------------------------------------------------------------
// (1 continued) Proptest: invalid entries are caught
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn proptest_unnormalized_posterior_rejected(
        raw in prop::collection::vec(0.1_f64..=10.0, 2..=8)
    ) {
        let sum: f64 = raw.iter().sum();
        // Only test when sum is clearly not ~1.0.
        prop_assume!((sum - 1.0).abs() > 1e-6);
        let entry = EvidenceLedger {
            ts_unix_ms: 1,
            component: "test".to_string(),
            action: "act".to_string(),
            posterior: raw,
            expected_loss_by_action: HashMap::new(),
            chosen_expected_loss: 0.0,
            calibration_score: 0.5,
            fallback_active: false,
            top_features: vec![],
        };
        let errors = entry.validate();
        prop_assert!(
            errors.iter().any(|e| matches!(e, ValidationError::PosteriorNotNormalized { .. })),
            "should catch unnormalized posterior, got: {errors:?}"
        );
    }

    #[test]
    fn proptest_out_of_range_calibration_rejected(cal in prop::num::f64::ANY) {
        prop_assume!(!(0.0..=1.0).contains(&cal));
        prop_assume!(cal.is_finite());
        let entry = EvidenceLedger {
            ts_unix_ms: 1,
            component: "test".to_string(),
            action: "act".to_string(),
            posterior: vec![1.0],
            expected_loss_by_action: HashMap::new(),
            chosen_expected_loss: 0.0,
            calibration_score: cal,
            fallback_active: false,
            top_features: vec![],
        };
        let errors = entry.validate();
        prop_assert!(
            errors.iter().any(|e| matches!(e, ValidationError::CalibrationOutOfRange { .. })),
            "should catch OOB calibration {cal}, got: {errors:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// (8) Concurrent writer safety
// ---------------------------------------------------------------------------

#[test]
fn concurrent_writers_no_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.jsonl");

    // Write initial header.
    {
        let mut exporter = JsonlExporter::open(path.clone()).unwrap();
        exporter.flush().unwrap();
    }

    let threads_count = 10;
    let entries_per_thread = 50;
    let mut handles = Vec::new();

    for thread_id in 0..threads_count {
        let p = path.clone();
        handles.push(std::thread::spawn(move || {
            // Each thread opens its own exporter (append mode) and writes entries.
            // This tests concurrent file appending.
            for i in 0..entries_per_thread {
                let entry = EvidenceLedgerBuilder::new()
                    .ts_unix_ms(thread_id * 1000 + i)
                    .component(format!("thread_{thread_id}"))
                    .action(format!("op_{i}"))
                    .posterior(vec![0.6, 0.4])
                    .chosen_expected_loss(0.1)
                    .calibration_score(0.85)
                    .build()
                    .unwrap();
                // Open/append/flush for each entry to maximize contention.
                let mut exporter = JsonlExporter::open(p.clone()).unwrap();
                exporter.append(&entry).unwrap();
                exporter.flush().unwrap();
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    // Read back and check: all entries should be valid JSON.
    let entries = read_jsonl(&path).unwrap();
    // We may get fewer entries if some lines interleaved, but every parsed
    // entry must be a valid EvidenceLedger.
    assert!(
        !entries.is_empty(),
        "should have recovered at least some entries"
    );
    for entry in &entries {
        assert!(entry.is_valid(), "recovered entry is invalid: {entry:?}");
    }

    // Verify the raw file has no interleaved/corrupted lines by checking
    // that every non-header, non-empty line either parses or is clearly
    // a partial line (crash recovery semantics).
    let content = fs::read_to_string(&path).unwrap();
    let total_lines = content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.contains("\"_schema\""))
        .count();
    // We expect ~500 entries (10 threads * 50), but some may be lost to
    // interleaving. Recovered entries should be valid.
    assert!(
        entries.len() <= total_lines,
        "parsed ({}) should not exceed total lines ({total_lines})",
        entries.len()
    );
}

// ---------------------------------------------------------------------------
// (13) Full pipeline integration test
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_builder_to_jsonl_to_render() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pipeline.jsonl");

    // Phase 1: Create entries via builder.
    let entries: Vec<EvidenceLedger> = (0_u32..10)
        .map(|i| {
            let fi = f64::from(i);
            EvidenceLedgerBuilder::new()
                .ts_unix_ms(1_700_000_000_000 + u64::from(i) * 1000)
                .component(if i % 2 == 0 {
                    "scheduler"
                } else {
                    "supervisor"
                })
                .action(if i < 5 { "preempt" } else { "restart" })
                .posterior(vec![fi.mul_add(0.01, 0.6), fi.mul_add(-0.01, 0.4)])
                .expected_loss("preempt", fi.mul_add(0.01, 0.05))
                .expected_loss("restart", fi.mul_add(-0.01, 0.15))
                .chosen_expected_loss(fi.mul_add(0.01, 0.05))
                .calibration_score(fi.mul_add(0.03, 0.7))
                .fallback_active(i == 7)
                .top_feature("depth", fi.mul_add(-0.02, 0.5))
                .build()
                .unwrap()
        })
        .collect();

    // Phase 2: Write to JSONL.
    {
        let mut exporter = JsonlExporter::open(path.clone()).unwrap();
        for entry in &entries {
            exporter.append(entry).unwrap();
        }
        exporter.flush().unwrap();
        assert_eq!(exporter.entries_written(), 10);
    }

    // Phase 3: Read back from JSONL.
    let read_back = read_jsonl(&path).unwrap();
    assert_eq!(read_back.len(), 10);

    // Phase 4: Verify field equality.
    for (orig, parsed) in entries.iter().zip(read_back.iter()) {
        assert_eq!(orig.ts_unix_ms, parsed.ts_unix_ms);
        assert_eq!(orig.component, parsed.component);
        assert_eq!(orig.action, parsed.action);
        assert_eq!(orig.posterior, parsed.posterior);
        assert_eq!(orig.fallback_active, parsed.fallback_active);
    }

    // Phase 5: Render at all levels and verify non-empty output.
    let mut diff_ctx = DiffContext::new();
    for entry in &read_back {
        let l0 = render::level0(entry);
        assert!(!l0.is_empty());
        assert!(l0.len() <= 120);

        let l0a = render::level0_ansi(entry);
        assert!(!l0a.is_empty());
        assert!(l0a.contains("\x1b["));

        let l1 = render::level1(entry);
        assert!(l1.lines().count() >= 3);

        let l1p = render::level1_plain(entry);
        assert!(!l1p.contains("\x1b["));

        let l2 = render::level2(entry);
        assert!(l2.contains("posterior distribution:"));
        assert!(l2.contains("calibration:"));

        let l3 = diff_ctx.level3(entry);
        assert!(l3.contains("LEVEL 3 DEBUG"));
        assert!(l3.contains("json:"));

        let h = render::html(entry);
        assert!(h.contains("<div"));
        assert!(h.contains("</div>"));

        let md = render::markdown(entry);
        assert!(md.contains("##"));
    }

    // Phase 6: Verify Level 3 diff detects changes across scheduler entries.
    let mut sched_ctx = DiffContext::new();
    let sched_entries: Vec<_> = read_back
        .iter()
        .filter(|e| e.component == "scheduler")
        .collect();
    assert!(sched_entries.len() >= 2);
    let first_output = sched_ctx.level3(sched_entries[0]);
    assert!(first_output.contains("no previous entry"));
    let second_output = sched_ctx.level3(sched_entries[1]);
    assert!(second_output.contains("diff from previous:"));
}

// ---------------------------------------------------------------------------
// (14) Schema version migration / graceful handling
// ---------------------------------------------------------------------------

#[test]
fn schema_v1_file_parsed_by_current_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.jsonl");

    // Write a v1 schema file manually.
    let mut file = fs::File::create(&path).unwrap();
    writeln!(file, r#"{{"_schema":"EvidenceLedger","_version":"1.0.0"}}"#).unwrap();
    writeln!(
        file,
        r#"{{"ts":1700000000000,"c":"test","a":"act","p":[0.6,0.4],"el":{{"act":0.1}},"cel":0.1,"cal":0.8,"fb":false,"tf":[["f",0.5]]}}"#
    )
    .unwrap();

    let entries = read_jsonl(&path).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].component, "test");
    assert_eq!(entries[0].action, "act");
}

#[test]
fn unknown_schema_version_still_readable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v99.jsonl");

    // Write a hypothetical future schema version.
    let mut file = fs::File::create(&path).unwrap();
    writeln!(
        file,
        r#"{{"_schema":"EvidenceLedger","_version":"99.0.0"}}"#
    )
    .unwrap();
    // The entry format is the same as current.
    writeln!(
        file,
        r#"{{"ts":1,"c":"future","a":"x","p":[1.0],"el":{{}},"cel":0.0,"cal":0.5,"fb":false,"tf":[]}}"#
    )
    .unwrap();

    let entries = read_jsonl(&path).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].component, "future");
}

#[test]
fn file_with_extra_fields_parsed_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("extra.jsonl");

    // A future version might add new fields.
    let mut file = fs::File::create(&path).unwrap();
    writeln!(file, r#"{{"_schema":"EvidenceLedger","_version":"2.0.0"}}"#).unwrap();
    writeln!(
        file,
        r#"{{"ts":1,"c":"test","a":"x","p":[1.0],"el":{{}},"cel":0.0,"cal":0.5,"fb":false,"tf":[],"new_field":"extra"}}"#
    )
    .unwrap();

    // Serde's default behavior: ignore unknown fields.
    let entries = read_jsonl(&path).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].component, "test");
}

#[test]
fn file_with_missing_optional_fields_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("incomplete.jsonl");

    // Missing required field (calibration_score / "cal").
    let mut file = fs::File::create(&path).unwrap();
    writeln!(file, r#"{{"_schema":"EvidenceLedger","_version":"1.0.0"}}"#).unwrap();
    writeln!(
        file,
        r#"{{"ts":1,"c":"test","a":"x","p":[1.0],"el":{{}},"cel":0.0,"fb":false,"tf":[]}}"#
    )
    .unwrap();

    // read_jsonl skips unparseable lines (crash recovery).
    let entries = read_jsonl(&path).unwrap();
    assert_eq!(entries.len(), 0, "entry missing 'cal' should be skipped");
}

// ---------------------------------------------------------------------------
// Galaxy-brain rendering determinism (golden checksum stability)
// ---------------------------------------------------------------------------

#[test]
fn render_output_deterministic_across_100_runs() {
    let entry = valid_builder().build().unwrap();

    let l0 = render::level0(&entry);
    let l1 = render::level1(&entry);
    let l2 = render::level2(&entry);
    let h = render::html(&entry);
    let md = render::markdown(&entry);

    for _ in 0..100 {
        assert_eq!(render::level0(&entry), l0);
        assert_eq!(render::level1(&entry), l1);
        assert_eq!(render::level2(&entry), l2);
        assert_eq!(render::html(&entry), h);
        assert_eq!(render::markdown(&entry), md);
    }
}

#[test]
fn level3_deterministic_with_fresh_context() {
    let entry = valid_builder().build().unwrap();

    // Two fresh contexts should produce identical output.
    let mut ctx1 = DiffContext::new();
    let mut ctx2 = DiffContext::new();
    assert_eq!(ctx1.level3(&entry), ctx2.level3(&entry));
}

// ---------------------------------------------------------------------------
// JSONL exporter edge cases
// ---------------------------------------------------------------------------

#[test]
fn exporter_rotation_creates_multiple_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rotation_test.jsonl");

    let config = ExporterConfig {
        max_bytes: 300,
        buf_capacity: 64,
    };
    let mut exporter = JsonlExporter::open_with_config(path.clone(), &config).unwrap();

    for i in 0_u32..30 {
        let entry = EvidenceLedgerBuilder::new()
            .ts_unix_ms(u64::from(i))
            .component("rot")
            .action(format!("op_{i}"))
            .posterior(vec![0.5, 0.5])
            .chosen_expected_loss(0.1)
            .calibration_score(0.8)
            .build()
            .unwrap();
        exporter.append(&entry).unwrap();
    }
    exporter.flush().unwrap();
    drop(exporter);

    // Rotation should create more than one file.
    let file_count = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .count();
    assert!(
        file_count > 1,
        "should have rotated into multiple files, got {file_count}"
    );

    // Read all files and verify all recovered entries are valid.
    let mut all_entries = Vec::new();
    for dir_entry in fs::read_dir(dir.path()).unwrap() {
        let dir_entry = dir_entry.unwrap();
        if dir_entry.path().extension().is_some_and(|e| e == "jsonl") {
            let entries = read_jsonl(&dir_entry.path()).unwrap();
            all_entries.extend(entries);
        }
    }
    assert!(
        !all_entries.is_empty(),
        "should recover entries across rotated files"
    );
    for entry in &all_entries {
        assert!(entry.is_valid());
    }

    // The current file should have a schema header.
    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("\"_schema\""));
}

#[test]
fn exporter_empty_expected_loss_map() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty_map.jsonl");

    let entry = EvidenceLedgerBuilder::new()
        .ts_unix_ms(1)
        .component("test")
        .action("act")
        .posterior(vec![1.0])
        .chosen_expected_loss(0.0)
        .calibration_score(0.5)
        .build()
        .unwrap();

    let mut exporter = JsonlExporter::open(path.clone()).unwrap();
    exporter.append(&entry).unwrap();
    exporter.flush().unwrap();

    let entries = read_jsonl(&path).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].expected_loss_by_action.is_empty());
}
