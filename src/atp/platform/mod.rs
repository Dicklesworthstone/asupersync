//! ATP platform capability provider facade.
//!
//! The filesystem module owns the low-level probes. ATP depends on this facade
//! so transfer, disk, scheduler, packaging, and doctor code all consume the same
//! capability report shape without reaching into filesystem internals.

pub use crate::fs::{
    CapabilityProbe, CapabilityStatus, FilesystemCapabilityProfile,
    NativePlatformCapabilityProvider, NetworkCapabilityProfile, PLATFORM_CAPABILITY_REPORT_SCHEMA,
    PlatformCapabilityProvider, PlatformCapabilityReport, PlatformDegradationPolicy,
    PlatformTarget, ProbeSource, ServiceCapabilityProfile,
};

/// Stable platform family bucket used by ATP diagnostics and tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformProbeFamily {
    /// Linux native probes.
    Linux,
    /// macOS native probes.
    Macos,
    /// Windows native probes.
    Windows,
    /// Browser storage/networking probes.
    WasmBrowser,
    /// Other Unix-family targets.
    UnixOther,
    /// Unknown or unsupported target family.
    Other,
}

impl PlatformProbeFamily {
    /// Returns the current compile-time platform family bucket.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_family = "windows") {
            Self::Windows
        } else if cfg!(target_arch = "wasm32") {
            Self::WasmBrowser
        } else if cfg!(target_family = "unix") {
            Self::UnixOther
        } else {
            Self::Other
        }
    }

    /// Returns the stable snake-case family label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::WasmBrowser => "wasm_browser",
            Self::UnixOther => "unix_other",
            Self::Other => "other",
        }
    }
}

/// Detect ATP platform capabilities with native host probes.
#[must_use]
pub fn detect_atp_platform_capabilities() -> PlatformCapabilityReport {
    crate::fs::detect_platform_capabilities()
}

/// Build an ATP platform capability report from an injected provider.
#[must_use]
pub fn build_atp_platform_capability_report(
    provider: &impl PlatformCapabilityProvider,
) -> PlatformCapabilityReport {
    crate::fs::build_platform_capability_report(provider)
}

/// Deterministic lab provider for ATP platform policy and doctor tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicLabPlatformProvider {
    target: PlatformTarget,
    sparse_files: CapabilityProbe,
    preallocation: CapabilityProbe,
    atomic_rename: CapabilityProbe,
    fsync_durability: CapabilityProbe,
    max_path_length: CapabilityProbe,
    case_sensitive_paths: CapabilityProbe,
    symlink_behavior: CapabilityProbe,
    socket_buffers: CapabilityProbe,
    ipv6: CapabilityProbe,
    router_assist: CapabilityProbe,
    service_manager: CapabilityProbe,
}

impl DeterministicLabPlatformProvider {
    /// Returns a lab platform where every ATP capability is measured and supported.
    #[must_use]
    pub fn fully_supported() -> Self {
        Self {
            target: PlatformTarget {
                os: "labos".to_string(),
                family: "lab".to_string(),
                arch: "labarch".to_string(),
                pointer_width: 64,
            },
            sparse_files: supported_probe("sparse_files"),
            preallocation: supported_probe("preallocation"),
            atomic_rename: supported_probe("atomic_rename"),
            fsync_durability: supported_probe("fsync_durability"),
            max_path_length: supported_probe("max_path_length"),
            case_sensitive_paths: supported_probe("case_sensitive_paths"),
            symlink_behavior: supported_probe("symlink_behavior"),
            socket_buffers: supported_probe("socket_buffers"),
            ipv6: supported_probe("ipv6"),
            router_assist: supported_probe("router_assist"),
            service_manager: supported_probe("service_manager"),
        }
    }

    /// Returns a lab platform that forces conservative ATP degradation policy.
    #[must_use]
    pub fn conservative_degradation() -> Self {
        Self::fully_supported()
            .with_sparse_files(probe(
                "sparse_files",
                CapabilityStatus::Unsupported,
                ProbeSource::Measured,
                "sparse write probe failed",
                Some("write into quarantine before verified exposure"),
                None,
            ))
            .with_fsync_durability(probe(
                "fsync_durability",
                CapabilityStatus::Degraded,
                ProbeSource::Measured,
                "directory fsync failed",
                Some("replay journal after every restart"),
                None,
            ))
            .with_ipv6(probe(
                "ipv6",
                CapabilityStatus::Degraded,
                ProbeSource::Measured,
                "IPv6 loopback unavailable",
                Some("prefer IPv4 or relay candidates"),
                Some("enable IPv6 loopback/networking on this host"),
            ))
            .with_service_manager(probe(
                "service_manager",
                CapabilityStatus::Unknown,
                ProbeSource::Skipped,
                "service manager probe skipped by deterministic test",
                Some("ship atpd as a foreground process"),
                Some("run atpd under a supported service manager"),
            ))
    }

    /// Overrides sparse-file support.
    #[must_use]
    pub fn with_sparse_files(mut self, probe: CapabilityProbe) -> Self {
        self.sparse_files = probe;
        self
    }

    /// Overrides preallocation support.
    #[must_use]
    pub fn with_preallocation(mut self, probe: CapabilityProbe) -> Self {
        self.preallocation = probe;
        self
    }

    /// Overrides atomic rename support.
    #[must_use]
    pub fn with_atomic_rename(mut self, probe: CapabilityProbe) -> Self {
        self.atomic_rename = probe;
        self
    }

    /// Overrides fsync durability support.
    #[must_use]
    pub fn with_fsync_durability(mut self, probe: CapabilityProbe) -> Self {
        self.fsync_durability = probe;
        self
    }

    /// Overrides IPv6 support.
    #[must_use]
    pub fn with_ipv6(mut self, probe: CapabilityProbe) -> Self {
        self.ipv6 = probe;
        self
    }

    /// Overrides service-manager support.
    #[must_use]
    pub fn with_service_manager(mut self, probe: CapabilityProbe) -> Self {
        self.service_manager = probe;
        self
    }
}

impl PlatformCapabilityProvider for DeterministicLabPlatformProvider {
    fn target(&self) -> PlatformTarget {
        self.target.clone()
    }

    fn sparse_files(&self) -> CapabilityProbe {
        self.sparse_files.clone()
    }

    fn preallocation(&self) -> CapabilityProbe {
        self.preallocation.clone()
    }

    fn atomic_rename(&self) -> CapabilityProbe {
        self.atomic_rename.clone()
    }

    fn fsync_durability(&self) -> CapabilityProbe {
        self.fsync_durability.clone()
    }

    fn max_path_length(&self) -> CapabilityProbe {
        self.max_path_length.clone()
    }

    fn case_sensitive_paths(&self) -> CapabilityProbe {
        self.case_sensitive_paths.clone()
    }

    fn symlink_behavior(&self) -> CapabilityProbe {
        self.symlink_behavior.clone()
    }

    fn socket_buffers(&self) -> CapabilityProbe {
        self.socket_buffers.clone()
    }

    fn ipv6(&self) -> CapabilityProbe {
        self.ipv6.clone()
    }

    fn router_assist(&self) -> CapabilityProbe {
        self.router_assist.clone()
    }

    fn service_manager(&self) -> CapabilityProbe {
        self.service_manager.clone()
    }
}

fn supported_probe(name: &'static str) -> CapabilityProbe {
    probe(
        name,
        CapabilityStatus::Supported,
        ProbeSource::Measured,
        format!("{name} supported"),
        None,
        None,
    )
}

fn probe(
    name: &'static str,
    status: CapabilityStatus,
    source: ProbeSource,
    detail: impl Into<String>,
    degradation_reason: Option<&'static str>,
    suggested_recovery_command: Option<&'static str>,
) -> CapabilityProbe {
    CapabilityProbe {
        name: name.to_string(),
        status,
        source,
        detail: detail.into(),
        degradation_reason: degradation_reason.map(str::to_string),
        suggested_recovery_command: suggested_recovery_command.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn lab_provider_selects_fast_policy() {
        init_test("lab_provider_selects_fast_policy");
        let provider = DeterministicLabPlatformProvider::fully_supported();
        let report = build_atp_platform_capability_report(&provider);

        assert_eq!(
            report.degradation_policy.disk_writer_mode,
            "sparse-preallocated"
        );
        assert_eq!(
            report.degradation_policy.atomic_commit_mode,
            "sync-temp-rename-sync-parent"
        );
        assert_eq!(
            report.degradation_policy.endpoint_mode,
            "ipv6-ipv4-direct-first"
        );
        assert_eq!(report.degradation_policy.packaging_mode, "managed-service");
        assert!(report.caveats.is_empty());
        crate::test_complete!("lab_provider_selects_fast_policy");
    }

    #[test]
    fn lab_provider_selects_conservative_policy() {
        init_test("lab_provider_selects_conservative_policy");
        let provider = DeterministicLabPlatformProvider::conservative_degradation();
        let report = build_atp_platform_capability_report(&provider);

        assert_eq!(
            report.degradation_policy.disk_writer_mode,
            "contiguous-verified-quarantine"
        );
        assert_eq!(
            report.degradation_policy.atomic_commit_mode,
            "rename-with-journal-replay-guard"
        );
        assert_eq!(
            report.degradation_policy.endpoint_mode,
            "ipv4-or-relay-first"
        );
        assert_eq!(
            report.degradation_policy.packaging_mode,
            "foreground-or-user-service"
        );
        assert!(
            report
                .suggested_recovery_commands
                .contains(&"enable IPv6 loopback/networking on this host".to_string())
        );
        crate::test_complete!("lab_provider_selects_conservative_policy");
    }

    #[test]
    fn current_family_has_stable_label() {
        init_test("current_family_has_stable_label");
        let label = PlatformProbeFamily::current().as_str();
        assert!(!label.is_empty());
        assert!(!label.contains('-'));
        crate::test_complete!("current_family_has_stable_label");
    }
}
