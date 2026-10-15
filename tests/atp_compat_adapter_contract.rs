//! ATP compatibility adapter contract tests.
//!
//! Related bead: asupersync-lgssby.

use asupersync::net::atp::h3::{
    AdapterConfig, AtpH3Adapter, AtpH3Error, H3_WEBTRANSPORT_ADAPTER_KIND,
    NATIVE_ATP_FOUNDATION_KIND,
};

#[test]
fn h3_webtransport_negotiation_report_is_stable_and_not_foundational() {
    let adapter = AtpH3Adapter::new(AdapterConfig::default());
    let report = adapter.negotiation_report();

    assert_eq!(report, adapter.negotiation_report());
    assert_eq!(report.adapter_kind, H3_WEBTRANSPORT_ADAPTER_KIND);
    assert_eq!(report.foundation_kind, NATIVE_ATP_FOUNDATION_KIND);
    assert!(report.adapter_after_native);
    assert!(!report.replacement_for_native_quic);
    assert!(
        report
            .supported_features
            .windows(2)
            .all(|pair| pair[0] <= pair[1])
    );
    assert!(report.constraints.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(
        report
            .downgrades
            .windows(2)
            .all(|pair| pair[0].feature <= pair[1].feature)
    );
    assert!(
        report
            .downgrades
            .iter()
            .any(|downgrade| downgrade.reason_code == "native_quic_migration_unavailable")
    );
}

#[test]
fn h3_webtransport_unsupported_feature_error_reports_downgrade() {
    let adapter = AtpH3Adapter::new(AdapterConfig::default());
    let error = adapter.unsupported_feature_error("Raw UDP socket access");

    let AtpH3Error::UnsupportedFeature(message) = error else {
        panic!("expected unsupported-feature error");
    };

    assert!(message.contains(H3_WEBTRANSPORT_ADAPTER_KIND));
    assert!(message.contains(NATIVE_ATP_FOUNDATION_KIND));
    assert!(message.contains("replacement_for_native_quic=false"));
    assert!(message.contains("downgrade_reason=raw_udp_unavailable"));
    assert!(!message.contains("127.0.0.1"));
    assert!(!message.contains("secret"));
}
