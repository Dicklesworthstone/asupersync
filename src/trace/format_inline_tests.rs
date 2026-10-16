    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use crate::types::Time;

    #[test]
    fn format_empty_trace() {
        let buffer = TraceBuffer::new(10);
        let output = trace_to_string(&buffer);
        assert!(output.contains("0 events"));
    }

    #[test]
    fn format_with_events() {
        let mut buffer = TraceBuffer::new(10);
        buffer.push(TraceEvent::new(
            1,
            Time::from_millis(100),
            TraceEventKind::UserTrace,
            TraceData::Message("test".to_string()),
        ));
        let output = trace_to_string(&buffer);
        assert!(output.contains("1 events"));
        assert!(output.contains("test"));
    }

    // Pure data-type tests (wave 14 – CyanBarn)

    #[test]
    fn golden_trace_config_debug_clone_eq() {
        let cfg = GoldenTraceConfig {
            seed: 42,
            entropy_seed: 7,
            worker_count: 4,
            trace_capacity: 1000,
            max_steps: Some(500),
            canonical_prefix_layers: 10,
            canonical_prefix_events: 100,
        };
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("GoldenTraceConfig"));

        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
    }

    #[test]
    fn golden_trace_config_ne() {
        let a = GoldenTraceConfig {
            seed: 1,
            entropy_seed: 0,
            worker_count: 1,
            trace_capacity: 10,
            max_steps: None,
            canonical_prefix_layers: 1,
            canonical_prefix_events: 1,
        };
        let mut b = a.clone();
        b.seed = 2;
        assert_ne!(a, b);
    }

    #[test]
    fn golden_trace_oracle_summary_debug_clone_eq() {
        let summary = GoldenTraceOracleSummary {
            violations: vec!["leak".to_string()],
        };
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("GoldenTraceOracleSummary"));

        let cloned = summary.clone();
        assert_eq!(summary, cloned);
    }

    #[test]
    fn golden_trace_oracle_summary_empty() {
        let summary = GoldenTraceOracleSummary { violations: vec![] };
        assert!(summary.violations.is_empty());
    }

    #[test]
    fn golden_trace_diff_default_is_empty() {
        let diff = GoldenTraceDiff::default();
        assert!(diff.is_empty());
    }

    #[test]
    fn golden_trace_diff_debug() {
        let diff = GoldenTraceDiff::default();
        let dbg = format!("{diff:?}");
        assert!(dbg.contains("GoldenTraceDiff"));
    }

    #[test]
    fn golden_trace_diff_display_empty() {
        let diff = GoldenTraceDiff::default();
        let display = diff.to_string();
        assert!(display.is_empty());
    }

    #[test]
    fn golden_trace_diff_error_trait() {
        let diff = GoldenTraceDiff::default();
        let err: &dyn std::error::Error = &diff;
        assert!(err.source().is_none());
    }

    #[test]
    fn golden_trace_mismatch_display_all_variants() {
        let m = GoldenTraceMismatch::SchemaVersion {
            expected: 1,
            actual: 2,
        };
        assert!(m.to_string().contains("schema_version"));

        let m = GoldenTraceMismatch::Fingerprint {
            expected: 0xAB,
            actual: 0xCD,
        };
        assert!(m.to_string().contains("fingerprint"));

        let m = GoldenTraceMismatch::EventCount {
            expected: 10,
            actual: 20,
        };
        assert!(m.to_string().contains("event_count"));

        let m = GoldenTraceMismatch::CanonicalPrefix {
            expected_layers: 3,
            actual_layers: 5,
            first_mismatch: Some((1, 2)),
        };
        let s = m.to_string();
        assert!(s.contains("canonical_prefix"));
        assert!(s.contains("layer 1"));

        let m = GoldenTraceMismatch::CanonicalPrefix {
            expected_layers: 3,
            actual_layers: 5,
            first_mismatch: None,
        };
        assert!(m.to_string().contains("expected_layers=3"));

        let m = GoldenTraceMismatch::OracleViolations {
            expected: vec!["a".into()],
            actual: vec!["b".into()],
        };
        assert!(m.to_string().contains("oracle violations"));
    }

    #[test]
    fn golden_trace_mismatch_config_variant() {
        let cfg1 = GoldenTraceConfig {
            seed: 1,
            entropy_seed: 0,
            worker_count: 1,
            trace_capacity: 10,
            max_steps: None,
            canonical_prefix_layers: 1,
            canonical_prefix_events: 1,
        };
        let cfg2 = GoldenTraceConfig { seed: 2, ..cfg1 };
        let m = GoldenTraceMismatch::Config {
            expected: cfg1,
            actual: cfg2,
        };
        assert!(m.to_string().contains("config changed"));
    }

    #[test]
    fn golden_trace_mismatch_debug() {
        let m = GoldenTraceMismatch::SchemaVersion {
            expected: 1,
            actual: 2,
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("SchemaVersion"));
    }

    #[test]
    fn schema_version_constant() {
        assert_eq!(GOLDEN_TRACE_SCHEMA_VERSION, 1);
    }

    #[test]
    fn first_prefix_mismatch_identical() {
        let a: Vec<Vec<TraceEventKey>> = vec![];
        assert!(first_prefix_mismatch(&a, &a).is_none());
    }

    #[test]
    fn first_prefix_mismatch_different_lengths() {
        let a: Vec<Vec<TraceEventKey>> = vec![vec![]];
        let b: Vec<Vec<TraceEventKey>> = vec![];
        let m = first_prefix_mismatch(&a, &b);
        assert!(m.is_some());
    }

    #[test]
    fn golden_trace_delta_report_clean_when_equal() {
        let config = GoldenTraceConfig {
            seed: 1,
            entropy_seed: 1,
            worker_count: 1,
            trace_capacity: 32,
            max_steps: Some(128),
            canonical_prefix_layers: 2,
            canonical_prefix_events: 8,
        };
        let expected = GoldenTraceFixture::from_events(config, &[], std::iter::empty::<String>());
        let report = expected.delta_report(&expected);
        assert!(report.is_clean());
        assert!(!report.config_drift);
        assert!(!report.semantic_drift);
        assert!(!report.timing_drift);
        assert!(!report.observability_drift);
        assert!(report.to_json().expect("json").contains("\"deltas\""));
    }

    #[test]
    fn golden_trace_delta_report_detects_drift_classes() {
        let config = GoldenTraceConfig {
            seed: 1,
            entropy_seed: 1,
            worker_count: 1,
            trace_capacity: 32,
            max_steps: Some(128),
            canonical_prefix_layers: 2,
            canonical_prefix_events: 8,
        };
        let expected = GoldenTraceFixture::from_events(config, &[], std::iter::empty::<String>());
        let mut actual = expected.clone();
        actual.config.seed = 2;
        actual.fingerprint ^= 0xA5A5;
        actual.event_count = actual.event_count.saturating_add(1);
        actual.oracle_summary.violations = vec!["TaskLeak".to_string()];

        let report = expected.delta_report(&actual);
        assert!(!report.is_clean());
        assert!(report.config_drift);
        assert!(report.semantic_drift);
        assert!(report.timing_drift);
        assert!(report.observability_drift);
        assert!(report.deltas.iter().any(|d| d.field == "config"));
        assert!(report.deltas.iter().any(|d| d.field == "fingerprint"));
        assert!(report.deltas.iter().any(|d| d.field == "event_count"));
        assert!(report.deltas.iter().any(|d| d.field == "oracle_violations"));
    }
