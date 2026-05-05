//! Schema + determinism contract test for the Spork harness report (bd-11dm5).

use asupersync::lab::{HarnessAttachmentRef, LabConfig, LabRuntime, SporkHarnessReport};

#[test]
fn spork_harness_report_schema_is_deterministic() {
    let config = LabConfig::new(42).worker_count(2).trace_capacity(1024);

    let attachments_a = vec![
        HarnessAttachmentRef::trace("trace.json"),
        HarnessAttachmentRef::crashpack("crashpack.tar"),
        HarnessAttachmentRef::replay_trace("replay.ndjson"),
    ];

    let attachments_b = vec![
        HarnessAttachmentRef::replay_trace("replay.ndjson"),
        HarnessAttachmentRef::trace("trace.json"),
        HarnessAttachmentRef::crashpack("crashpack.tar"),
    ];

    let mut r1 = LabRuntime::new(config.clone());
    let report1 = r1.run_until_quiescent_spork_report("demo-app", attachments_a);
    assert_eq!(report1.schema_version, SporkHarnessReport::SCHEMA_VERSION);

    let mut r2 = LabRuntime::new(config);
    let report2 = r2.run_until_quiescent_spork_report("demo-app", attachments_b);

    let j1 = report1.to_json();
    let j2 = report2.to_json();

    // Stable JSON schema and stable rendering regardless of attachment insertion order.
    assert_eq!(j1, j2);

    // Schema shape checks (stable field locations).
    assert_eq!(
        j1["schema_version"].as_u64(),
        Some(u64::from(SporkHarnessReport::SCHEMA_VERSION))
    );
    assert_eq!(j1["app"]["name"].as_str(), Some("demo-app"));
    assert_eq!(j1["lab"]["config"]["seed"].as_u64(), Some(42));
    assert!(j1["fingerprints"]["trace"].as_u64().is_some());
    assert!(j1["run"]["trace"]["fingerprint"].as_u64().is_some());
    assert_eq!(j1["crashpack"]["path"].as_str(), Some("crashpack.tar"));
    assert!(j1["crashpack"]["id"].as_str().is_some());
    assert!(j1["crashpack"]["fingerprint"].as_u64().is_some());
    assert!(j1["crashpack"]["replay"]["command_line"].as_str().is_some());

    // Attachment ordering is deterministic: kind first (crashpack, replay_trace, trace), then path.
    let kinds = j1["attachments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["kind"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(kinds, vec!["crashpack", "replay_trace", "trace"]);
}
