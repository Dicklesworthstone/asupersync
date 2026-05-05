//! Public contract for the OTLP tail-based sampling support boundary.

use asupersync::observability::{
    OTLP_TAIL_SAMPLING_E2E_BEAD_ID, OTLP_TAIL_SAMPLING_SCOPE_BEAD_ID,
    OTLP_TAIL_SAMPLING_SCOPE_CONTRACT_VERSION, OtlpSpan, OtlpTailSamplingSupportClass,
    otlp_tail_based_sampling_scope,
};

#[test]
fn tail_sampling_scope_is_explicitly_unsupported_and_e2e_ready() {
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
    assert_eq!(scope.verdict, "unsupported");
    assert_eq!(scope.evidence_quality, "unsupported");
    assert!(!scope.production_supported);

    assert!(
        scope
            .missing_surfaces
            .contains(&"bounded span buffer for deferred decisions")
    );
    assert!(
        scope
            .desired_semantics
            .contains(&"no trace leaks on cancellation, flush, or shutdown")
    );
}

#[test]
fn head_based_sampling_is_the_live_trace_export_boundary() {
    let sampled = span_with_trace_flags(Some(0x01));
    let unsampled = span_with_trace_flags(Some(0x00));
    let legacy_unspecified = span_with_trace_flags(None);

    assert!(sampled.is_sampled());
    assert!(!unsampled.is_sampled());
    assert!(legacy_unspecified.is_sampled());
}

fn span_with_trace_flags(trace_flags: Option<u8>) -> OtlpSpan {
    OtlpSpan {
        span_id: "span-id".to_string(),
        name: "operation".to_string(),
        start_time_unix_nano: 1,
        end_time_unix_nano: 2,
        attributes: Vec::new(),
        trace_flags,
    }
}
