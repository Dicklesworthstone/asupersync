//! OTLP tail-based sampling audit test.
//!
//! **AUDIT SCOPE**: Verifies OTLP-Trace exporter tail-based sampling behavior
//! when spans complete out-of-order (children finish after parents).
//!
//! **TAIL-BASED SAMPLING SPECIFICATION**:
//! - Sampling decisions made AFTER spans complete (not at creation time)
//! - Parent sampling decisions applied to ALL children in trace tree
//! - Out-of-order completion handled correctly (children after parents)
//! - Span buffering until sampling decision can be made for entire trace
//! - Root span completion triggers sampling decision for entire trace tree
//! - NOT: head-based sampling where decisions are made at span creation
//! - NOT: immediate export without considering trace completion
//!
//! **AUDIT FINDING**: Tail-based sampling is NOT IMPLEMENTED
//! - Current implementation uses head-based sampling only
//! - Sampling decisions made at span creation via traceparent headers
//! - No span buffering for deferred decision making
//! - No out-of-order span completion handling for sampling

#![cfg(test)]
use super::{
    OTLP_TAIL_SAMPLING_E2E_BEAD_ID, OTLP_TAIL_SAMPLING_SCOPE_BEAD_ID,
    OTLP_TAIL_SAMPLING_SCOPE_CONTRACT_VERSION, OtlpSpan, OtlpTailSamplingSupportClass,
    otlp_tail_based_sampling_scope,
};

/// The current tail-sampling boundary is a production contract, not an
/// idealized audit-local sampler pretending to be implementation evidence.
#[test]
fn tail_based_sampling_scope_is_explicitly_unsupported() {
    let scope = otlp_tail_based_sampling_scope();

    assert_eq!(
        scope.contract_version,
        OTLP_TAIL_SAMPLING_SCOPE_CONTRACT_VERSION
    );
    assert_eq!(scope.bead_id, OTLP_TAIL_SAMPLING_SCOPE_BEAD_ID);
    assert_eq!(scope.feeds_bead_id, OTLP_TAIL_SAMPLING_E2E_BEAD_ID);
    assert_eq!(
        scope.support_class,
        OtlpTailSamplingSupportClass::ExplicitlyUnsupported
    );
    assert_eq!(scope.support_class_str(), "explicitly_unsupported");
    assert_eq!(scope.evidence_quality, "unsupported");
    assert_eq!(scope.verdict, "unsupported");
    assert!(!scope.production_supported);
}

#[test]
fn tail_based_sampling_scope_names_missing_production_surfaces() {
    let scope = otlp_tail_based_sampling_scope();

    for required_surface in [
        "trace-completion detector",
        "bounded span buffer for deferred decisions",
        "late sampling policy API",
        "flush/shutdown behavior for undecided traces",
    ] {
        assert!(
            scope.missing_surfaces.contains(&required_surface),
            "missing tail-sampling surface not recorded: {required_surface}"
        );
    }

    for required_semantic in [
        "policy match after trace completion",
        "consistent decision across every span in a trace",
        "bounded memory and trace-expiry behavior",
        "no trace leaks on cancellation, flush, or shutdown",
    ] {
        assert!(
            scope.desired_semantics.contains(&required_semantic),
            "future tail-sampling semantic not recorded: {required_semantic}"
        );
    }
}

#[test]
fn head_based_sampling_remains_the_live_export_boundary() {
    let sampled = OtlpSpan {
        span_id: "span-sampled".to_string(),
        name: "sampled-operation".to_string(),
        start_time_unix_nano: 1,
        end_time_unix_nano: 2,
        attributes: Vec::new(),
        trace_flags: Some(0x01),
    };
    let unsampled = OtlpSpan {
        span_id: "span-unsampled".to_string(),
        name: "unsampled-operation".to_string(),
        start_time_unix_nano: 1,
        end_time_unix_nano: 2,
        attributes: Vec::new(),
        trace_flags: Some(0x00),
    };
    let legacy_unspecified = OtlpSpan {
        span_id: "span-legacy".to_string(),
        name: "legacy-operation".to_string(),
        start_time_unix_nano: 1,
        end_time_unix_nano: 2,
        attributes: Vec::new(),
        trace_flags: None,
    };

    assert!(sampled.is_sampled());
    assert!(!unsampled.is_sampled());
    assert!(
        legacy_unspecified.is_sampled(),
        "spans without W3C flags remain sampled for backward-compatible head-based export"
    );
}

#[test]
fn tail_sampling_scope_matches_mock_code_finder_evidence_fields() {
    let scope = otlp_tail_based_sampling_scope();

    assert_eq!(scope.support_class_str(), "explicitly_unsupported");
    assert_eq!(scope.verdict, "unsupported");
    assert_eq!(scope.evidence_quality, "unsupported");
    assert_eq!(scope.feeds_bead_id, "asupersync-uw9zg9");
    assert!(
        !scope.missing_surfaces.is_empty(),
        "unsupported evidence must carry blocker context"
    );
    assert!(
        !scope.desired_semantics.is_empty(),
        "unsupported evidence must state what production support would require"
    );
}
