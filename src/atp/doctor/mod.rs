//! ATP doctor reports.

use crate::atp::platform::{
    CapabilityProbe, FilesystemCapabilityProfile, NetworkCapabilityProfile,
    PlatformCapabilityProvider, PlatformCapabilityReport, PlatformProbeFamily, ProbeSource,
    ServiceCapabilityProfile, build_atp_platform_capability_report,
    detect_atp_platform_capabilities,
};

/// Stable schema for ATP platform doctor output.
pub const ATP_PLATFORM_DOCTOR_SCHEMA: &str = "asupersync.atp.doctor.platform.v1";

/// Stable schema for one ATP platform probe log entry.
pub const ATP_PLATFORM_PROBE_LOG_SCHEMA: &str = "asupersync.atp.doctor.platform.probe_log.v1";

/// ATP doctor report for platform capability diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AtpPlatformDoctorDocument {
    /// Stable document schema.
    pub schema_version: String,
    /// Compile-time platform family bucket.
    pub platform_family: PlatformProbeFamily,
    /// Capability report used by transfer, disk, scheduler, and packaging policy.
    pub report: PlatformCapabilityReport,
    /// Structured operator logs for every probe.
    pub logs: Vec<AtpPlatformProbeLogEntry>,
}

/// Structured log entry for one platform probe.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AtpPlatformProbeLogEntry {
    /// Stable log-entry schema.
    pub schema_version: String,
    /// Compact platform profile for log correlation.
    pub platform_profile: String,
    /// Capability key.
    pub capability: String,
    /// Capability status.
    pub status: String,
    /// Probe source.
    pub probe_source: String,
    /// Whether this probe was measured, assumed, configured, or skipped.
    pub measurement_kind: String,
    /// Operator-facing probe detail.
    pub detail: String,
    /// Conservative degradation reason, when any.
    pub degradation_reason: Option<String>,
    /// Explicit skip reason for skipped probes.
    pub skip_reason: Option<String>,
    /// Suggested recovery command, when any.
    pub suggested_recovery_command: Option<String>,
}

/// Detects the host platform and builds an ATP doctor document.
#[must_use]
pub fn detect_platform_doctor_document() -> AtpPlatformDoctorDocument {
    document_from_report(detect_atp_platform_capabilities())
}

/// Builds an ATP doctor document from an injected platform provider.
#[must_use]
pub fn build_platform_doctor_document(
    provider: &impl PlatformCapabilityProvider,
) -> AtpPlatformDoctorDocument {
    document_from_report(build_atp_platform_capability_report(provider))
}

fn document_from_report(report: PlatformCapabilityReport) -> AtpPlatformDoctorDocument {
    let logs = collect_probes(&report.filesystem, &report.network, &report.service)
        .into_iter()
        .map(|probe| log_entry(&report, probe))
        .collect();
    AtpPlatformDoctorDocument {
        schema_version: ATP_PLATFORM_DOCTOR_SCHEMA.to_string(),
        platform_family: PlatformProbeFamily::current(),
        report,
        logs,
    }
}

fn log_entry(
    report: &PlatformCapabilityReport,
    probe: &CapabilityProbe,
) -> AtpPlatformProbeLogEntry {
    let platform_profile = format!(
        "{}/{}/{}:{}",
        report.target.family, report.target.os, report.target.arch, report.target.pointer_width
    );
    AtpPlatformProbeLogEntry {
        schema_version: ATP_PLATFORM_PROBE_LOG_SCHEMA.to_string(),
        platform_profile,
        capability: probe.name.clone(),
        status: probe.status.as_str().to_string(),
        probe_source: probe.source.as_str().to_string(),
        measurement_kind: probe.source.as_str().to_string(),
        detail: probe.detail.clone(),
        degradation_reason: probe.degradation_reason.clone(),
        skip_reason: (probe.source == ProbeSource::Skipped).then(|| probe.detail.clone()), // ubs:ignore - enum comparison, not a secret
        suggested_recovery_command: probe.suggested_recovery_command.clone(),
    }
}

fn collect_probes<'a>(
    filesystem: &'a FilesystemCapabilityProfile,
    network: &'a NetworkCapabilityProfile,
    service: &'a ServiceCapabilityProfile,
) -> Vec<&'a CapabilityProbe> {
    vec![
        &filesystem.sparse_files,
        &filesystem.preallocation,
        &filesystem.atomic_rename,
        &filesystem.fsync_durability,
        &filesystem.max_path_length,
        &filesystem.case_sensitive_paths,
        &filesystem.symlink_behavior,
        &network.socket_buffers,
        &network.ipv6,
        &network.router_assist,
        &service.service_manager,
    ]
}

/// Renders the ATP platform doctor document for human CLI output.
#[must_use]
pub fn render_platform_doctor_human(document: &AtpPlatformDoctorDocument) -> String {
    let report = &document.report;
    let mut lines = vec![
        format!("Schema: {}", document.schema_version),
        format!("Platform family: {}", document.platform_family.as_str()),
        format!(
            "Target: {}/{}/{} pointer_width={}",
            report.target.family, report.target.os, report.target.arch, report.target.pointer_width
        ),
        "Filesystem:".to_string(),
    ];
    append_filesystem_capabilities(&mut lines, &report.filesystem);
    lines.push("Network:".to_string());
    append_network_capabilities(&mut lines, &report.network);
    lines.push("Service:".to_string());
    append_service_capabilities(&mut lines, &report.service);
    lines.push("Degradation policy:".to_string());
    lines.push(format!(
        "  disk_writer_mode: {}",
        report.degradation_policy.disk_writer_mode
    ));
    lines.push(format!(
        "  atomic_commit_mode: {}",
        report.degradation_policy.atomic_commit_mode
    ));
    lines.push(format!(
        "  endpoint_mode: {}",
        report.degradation_policy.endpoint_mode
    ));
    lines.push(format!(
        "  packaging_mode: {}",
        report.degradation_policy.packaging_mode
    ));
    lines.push(format!("Caveats: {}", report.caveats.len()));
    for caveat in &report.caveats {
        lines.push(format!("  - {caveat}"));
    }
    lines.push(format!(
        "Suggested recovery commands: {}",
        report.suggested_recovery_commands.len()
    ));
    for command in &report.suggested_recovery_commands {
        lines.push(format!("  - {command}"));
    }
    lines.push(format!("Structured probe logs: {}", document.logs.len()));
    lines.join("\n")
}

fn append_filesystem_capabilities(lines: &mut Vec<String>, profile: &FilesystemCapabilityProfile) {
    append_capability(lines, &profile.sparse_files);
    append_capability(lines, &profile.preallocation);
    append_capability(lines, &profile.atomic_rename);
    append_capability(lines, &profile.fsync_durability);
    append_capability(lines, &profile.max_path_length);
    append_capability(lines, &profile.case_sensitive_paths);
    append_capability(lines, &profile.symlink_behavior);
}

fn append_network_capabilities(lines: &mut Vec<String>, profile: &NetworkCapabilityProfile) {
    append_capability(lines, &profile.socket_buffers);
    append_capability(lines, &profile.ipv6);
    append_capability(lines, &profile.router_assist);
}

fn append_service_capabilities(lines: &mut Vec<String>, profile: &ServiceCapabilityProfile) {
    append_capability(lines, &profile.service_manager);
}

fn append_capability(lines: &mut Vec<String>, capability: &CapabilityProbe) {
    lines.push(format!(
        "  {}: {} source={} detail={}",
        capability.name,
        capability.status.as_str(),
        capability.source.as_str(),
        capability.detail
    ));
    if let Some(reason) = &capability.degradation_reason {
        lines.push(format!("    degradation: {reason}"));
    }
    if let Some(command) = &capability.suggested_recovery_command {
        lines.push(format!("    recovery: {command}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::platform::DeterministicFakePlatformProvider;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn platform_doctor_document_has_stable_shape() {
        init_test("platform_doctor_document_has_stable_shape");
        let provider = DeterministicFakePlatformProvider::fully_supported();
        let document = build_platform_doctor_document(&provider);

        assert_eq!(document.schema_version, ATP_PLATFORM_DOCTOR_SCHEMA);
        assert_eq!(document.report.filesystem.sparse_files.name, "sparse_files");
        assert_eq!(document.logs.len(), 11);
        assert!(
            document
                .logs
                .iter()
                .any(|entry| entry.capability == "service_manager"
                    && entry.measurement_kind == "measured")
        );
        crate::test_complete!("platform_doctor_document_has_stable_shape");
    }

    #[test]
    fn platform_doctor_logs_failed_and_skipped_probe_details() {
        init_test("platform_doctor_logs_failed_and_skipped_probe_details");
        let provider = DeterministicFakePlatformProvider::conservative_degradation();
        let document = build_platform_doctor_document(&provider);

        let sparse = document
            .logs
            .iter()
            .find(|entry| entry.capability == "sparse_files")
            .expect("sparse log");
        assert_eq!(
            sparse.degradation_reason.as_deref(),
            Some("write into quarantine before verified exposure")
        );

        let service = document
            .logs
            .iter()
            .find(|entry| entry.capability == "service_manager")
            .expect("service-manager log");
        assert_eq!(service.probe_source, "skipped");
        assert!(service.skip_reason.is_some());
        assert_eq!(
            service.suggested_recovery_command.as_deref(),
            Some("run atpd under a supported service manager")
        );
        crate::test_complete!("platform_doctor_logs_failed_and_skipped_probe_details");
    }

    #[test]
    fn platform_doctor_human_output_has_stable_sections() {
        init_test("platform_doctor_human_output_has_stable_sections");
        let provider = DeterministicFakePlatformProvider::fully_supported();
        let document = build_platform_doctor_document(&provider);
        let rendered = render_platform_doctor_human(&document);

        assert!(rendered.contains("Schema: asupersync.atp.doctor.platform.v1"));
        assert!(rendered.contains("Filesystem:"));
        assert!(rendered.contains("Network:"));
        assert!(rendered.contains("Service:"));
        assert!(rendered.contains("Degradation policy:"));
        assert!(rendered.contains("Structured probe logs: 11"));
        crate::test_complete!("platform_doctor_human_output_has_stable_sections");
    }

    #[test]
    fn platform_doctor_json_output_has_stable_fields() {
        init_test("platform_doctor_json_output_has_stable_fields");
        let provider = DeterministicFakePlatformProvider::conservative_degradation();
        let document = build_platform_doctor_document(&provider);
        let json = serde_json::to_value(&document).expect("serialize doctor document");

        assert_eq!(json["schema_version"], ATP_PLATFORM_DOCTOR_SCHEMA);
        assert_eq!(
            json["report"]["degradation_policy"]["disk_writer_mode"],
            "contiguous-verified-quarantine"
        );
        assert!(json["logs"].as_array().expect("logs array").iter().any(
            |entry| entry["capability"] == "ipv6"
                && entry["suggested_recovery_command"]
                    == "enable IPv6 loopback/networking on this host"
        ));
        crate::test_complete!("platform_doctor_json_output_has_stable_fields");
    }
}
