//! Platform capability detection for ATP disk and packaging policy.
//!
//! ATP transfer code needs to know which host guarantees are available before
//! it chooses sparse writes, final-file exposure, endpoint policy, or service
//! integration. This module keeps that knowledge explicit and serializable so
//! CLI diagnostics, scheduler policy, and disk writers can consume the same
//! report.

use serde::Serialize;
use std::net::UdpSocket;
use std::path::Path;

/// Stable schema for [`PlatformCapabilityReport`].
pub const PLATFORM_CAPABILITY_REPORT_SCHEMA: &str = "asupersync.fs.platform_capability_report.v1";

/// Capability result for a single probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// The capability is available for the current policy surface.
    Supported,
    /// The capability is available, but ATP must use a conservative path.
    Degraded,
    /// The capability is unavailable.
    Unsupported,
    /// The capability could not be determined without a more invasive probe.
    Unknown,
}

impl CapabilityStatus {
    /// Returns the stable snake-case status label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Degraded => "degraded",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }

    const fn is_full_support(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// Origin of a capability decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeSource {
    /// The current host was observed directly.
    Measured,
    /// The value comes from target-family defaults.
    Assumed,
    /// The capability is intentionally unavailable or disabled.
    Configured,
    /// The probe was skipped to avoid an invasive or non-deterministic action.
    Skipped,
}

impl ProbeSource {
    /// Returns the stable snake-case source label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Assumed => "assumed",
            Self::Configured => "configured",
            Self::Skipped => "skipped",
        }
    }
}

/// Result for one named platform capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityProbe {
    /// Stable capability key.
    pub name: String,
    /// Capability status.
    pub status: CapabilityStatus,
    /// Probe source.
    pub source: ProbeSource,
    /// Human-readable detail for diagnostics.
    pub detail: String,
    /// Conservative policy reason when status is not full support.
    pub degradation_reason: Option<String>,
    /// Operator command or action that may improve this capability.
    pub suggested_recovery_command: Option<String>,
}

impl CapabilityProbe {
    fn new(
        name: &'static str,
        status: CapabilityStatus,
        source: ProbeSource,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            name: name.to_string(),
            status,
            source,
            detail: detail.into(),
            degradation_reason: None,
            suggested_recovery_command: None,
        }
    }

    fn with_degradation_reason(mut self, reason: impl Into<String>) -> Self {
        self.degradation_reason = Some(reason.into());
        self
    }

    fn with_recovery_command(mut self, command: impl Into<String>) -> Self {
        self.suggested_recovery_command = Some(command.into());
        self
    }
}

/// Compile-time target tuple for the report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlatformTarget {
    /// `std::env::consts::OS`.
    pub os: String,
    /// `std::env::consts::FAMILY`.
    pub family: String,
    /// `std::env::consts::ARCH`.
    pub arch: String,
    /// Pointer width in bits.
    pub pointer_width: u8,
}

impl PlatformTarget {
    fn current() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            family: std::env::consts::FAMILY.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            pointer_width: usize::BITS as u8,
        }
    }
}

/// Filesystem capabilities that affect ATP disk safety.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FilesystemCapabilityProfile {
    /// Sparse-file behavior for partially received transfers.
    pub sparse_files: CapabilityProbe,
    /// Preallocation support for reducing fragmentation and ENOSPC surprises.
    pub preallocation: CapabilityProbe,
    /// Same-directory atomic rename support for final commit.
    pub atomic_rename: CapabilityProbe,
    /// File and directory fsync durability support.
    pub fsync_durability: CapabilityProbe,
    /// Maximum path length policy.
    pub max_path_length: CapabilityProbe,
    /// Case-sensitivity behavior for destination path policy.
    pub case_sensitive_paths: CapabilityProbe,
    /// Symlink creation and inspection behavior.
    pub symlink_behavior: CapabilityProbe,
}

/// Network capabilities surfaced by the same platform report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkCapabilityProfile {
    /// Socket buffer tuning and batching support.
    pub socket_buffers: CapabilityProbe,
    /// Public/local IPv6 readiness.
    pub ipv6: CapabilityProbe,
    /// Router-assist and port-mapping hooks.
    pub router_assist: CapabilityProbe,
}

/// Packaging/service integration capabilities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceCapabilityProfile {
    /// Host service manager integration.
    pub service_manager: CapabilityProbe,
}

/// Conservative policy choices derived from platform probes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlatformDegradationPolicy {
    /// Disk writer mode selected from sparse/preallocation support.
    pub disk_writer_mode: String,
    /// Final-file exposure mode selected from rename/fsync support.
    pub atomic_commit_mode: String,
    /// Endpoint family selected from IPv6 support.
    pub endpoint_mode: String,
    /// Packaging mode selected from service-manager support.
    pub packaging_mode: String,
}

/// Full ATP platform capability report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlatformCapabilityReport {
    /// Stable report schema version.
    pub schema_version: String,
    /// Compile-time target tuple.
    pub target: PlatformTarget,
    /// Filesystem capabilities.
    pub filesystem: FilesystemCapabilityProfile,
    /// Network capabilities.
    pub network: NetworkCapabilityProfile,
    /// Service integration capabilities.
    pub service: ServiceCapabilityProfile,
    /// Derived conservative policy choices.
    pub degradation_policy: PlatformDegradationPolicy,
    /// Human-readable caveats for skipped, degraded, or assumed probes.
    pub caveats: Vec<String>,
    /// Suggested recovery commands extracted from degraded probes.
    pub suggested_recovery_commands: Vec<String>,
}

/// Provider interface used by native and deterministic test probes.
pub trait PlatformCapabilityProvider {
    /// Returns the target tuple for this provider.
    fn target(&self) -> PlatformTarget;

    /// Probes sparse-file behavior.
    fn sparse_files(&self) -> CapabilityProbe;

    /// Probes preallocation behavior.
    fn preallocation(&self) -> CapabilityProbe;

    /// Probes same-directory atomic rename behavior.
    fn atomic_rename(&self) -> CapabilityProbe;

    /// Probes fsync durability behavior.
    fn fsync_durability(&self) -> CapabilityProbe;

    /// Probes path length behavior.
    fn max_path_length(&self) -> CapabilityProbe;

    /// Probes case-sensitivity behavior.
    fn case_sensitive_paths(&self) -> CapabilityProbe;

    /// Probes symlink behavior.
    fn symlink_behavior(&self) -> CapabilityProbe;

    /// Probes socket buffer tuning behavior.
    fn socket_buffers(&self) -> CapabilityProbe;

    /// Probes IPv6 readiness.
    fn ipv6(&self) -> CapabilityProbe;

    /// Probes router assist behavior.
    fn router_assist(&self) -> CapabilityProbe;

    /// Probes service manager behavior.
    fn service_manager(&self) -> CapabilityProbe;
}

/// Native platform provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativePlatformCapabilityProvider;

impl PlatformCapabilityProvider for NativePlatformCapabilityProvider {
    fn target(&self) -> PlatformTarget {
        PlatformTarget::current()
    }

    fn sparse_files(&self) -> CapabilityProbe {
        if cfg!(target_arch = "wasm32") {
            CapabilityProbe::new(
                "sparse_files",
                CapabilityStatus::Unsupported,
                ProbeSource::Configured,
                "browser storage does not expose sparse file allocation",
            )
            .with_degradation_reason("use contiguous verified-object storage")
        } else if cfg!(any(target_family = "unix", target_family = "windows")) {
            CapabilityProbe::new(
                "sparse_files",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "host family normally supports sparse files; ATP still verifies chunks before exposure",
            )
        } else {
            CapabilityProbe::new(
                "sparse_files",
                CapabilityStatus::Unknown,
                ProbeSource::Skipped,
                "no non-destructive sparse-file probe is available for this target",
            )
            .with_degradation_reason("treat partial transfers as contiguous until measured")
        }
    }

    fn preallocation(&self) -> CapabilityProbe {
        if cfg!(target_arch = "wasm32") {
            CapabilityProbe::new(
                "preallocation",
                CapabilityStatus::Unsupported,
                ProbeSource::Configured,
                "browser storage does not expose filesystem preallocation",
            )
            .with_degradation_reason("reserve quota through storage policy before large transfers")
        } else if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
            CapabilityProbe::new(
                "preallocation",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "native filesystem can preallocate via platform-specific calls",
            )
        } else if cfg!(target_family = "windows") {
            CapabilityProbe::new(
                "preallocation",
                CapabilityStatus::Degraded,
                ProbeSource::Assumed,
                "Windows allocation behavior depends on the destination filesystem",
            )
            .with_degradation_reason("fall back to set_len plus early free-space checks")
        } else {
            CapabilityProbe::new(
                "preallocation",
                CapabilityStatus::Unknown,
                ProbeSource::Skipped,
                "preallocation support is target-specific",
            )
            .with_degradation_reason("fall back to incremental writes with ENOSPC recovery")
        }
    }

    fn atomic_rename(&self) -> CapabilityProbe {
        if cfg!(target_arch = "wasm32") {
            CapabilityProbe::new(
                "atomic_rename",
                CapabilityStatus::Unsupported,
                ProbeSource::Configured,
                "browser storage has no same-directory atomic rename primitive",
            )
            .with_degradation_reason("commit via manifest-visible version switch")
        } else if cfg!(any(target_family = "unix", target_family = "windows")) {
            CapabilityProbe::new(
                "atomic_rename",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "same-directory std::fs::rename is the ATP final-commit primitive",
            )
        } else {
            CapabilityProbe::new(
                "atomic_rename",
                CapabilityStatus::Unknown,
                ProbeSource::Skipped,
                "rename semantics are unknown for this target",
            )
            .with_degradation_reason("keep verified bytes quarantined until commit can be proven")
        }
    }

    fn fsync_durability(&self) -> CapabilityProbe {
        if cfg!(target_arch = "wasm32") {
            CapabilityProbe::new(
                "fsync_durability",
                CapabilityStatus::Unsupported,
                ProbeSource::Configured,
                "browser storage does not expose fsync",
            )
            .with_degradation_reason("treat local cache as recoverable, not durable")
        } else if cfg!(target_family = "unix") {
            CapabilityProbe::new(
                "fsync_durability",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "file sync_all and parent-directory sync are available",
            )
        } else if cfg!(target_family = "windows") {
            CapabilityProbe::new(
                "fsync_durability",
                CapabilityStatus::Degraded,
                ProbeSource::Assumed,
                "file sync_all is available; directory-entry durability is filesystem-dependent",
            )
            .with_degradation_reason("keep journal replay conservative after process crash")
        } else {
            CapabilityProbe::new(
                "fsync_durability",
                CapabilityStatus::Unknown,
                ProbeSource::Skipped,
                "fsync durability could not be established",
            )
            .with_degradation_reason("assume last append may be torn or missing")
        }
    }

    fn max_path_length(&self) -> CapabilityProbe {
        if cfg!(target_family = "windows") {
            CapabilityProbe::new(
                "max_path_length",
                CapabilityStatus::Degraded,
                ProbeSource::Assumed,
                "legacy Windows paths may be limited to 260 chars without extended-path policy",
            )
            .with_degradation_reason("enable long-path policy or shorten ATP cache roots")
            .with_recovery_command("enable Windows long paths policy")
        } else if cfg!(target_family = "unix") {
            CapabilityProbe::new(
                "max_path_length",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "Unix-like targets usually expose PATH_MAX near 4096 bytes per full path",
            )
        } else {
            CapabilityProbe::new(
                "max_path_length",
                CapabilityStatus::Unknown,
                ProbeSource::Skipped,
                "path length limit is target-specific",
            )
            .with_degradation_reason("reject long destination names before transfer starts")
        }
    }

    fn case_sensitive_paths(&self) -> CapabilityProbe {
        if cfg!(target_os = "linux") {
            CapabilityProbe::new(
                "case_sensitive_paths",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "Linux filesystems are commonly case-sensitive",
            )
        } else if cfg!(target_os = "macos") || cfg!(target_family = "windows") {
            CapabilityProbe::new(
                "case_sensitive_paths",
                CapabilityStatus::Degraded,
                ProbeSource::Assumed,
                "case sensitivity varies by volume and must be treated as path-policy input",
            )
            .with_degradation_reason("detect path collisions case-insensitively before receive")
        } else {
            CapabilityProbe::new(
                "case_sensitive_paths",
                CapabilityStatus::Unknown,
                ProbeSource::Skipped,
                "case-sensitivity behavior is unknown",
            )
            .with_degradation_reason("use collision-safe manifest names")
        }
    }

    fn symlink_behavior(&self) -> CapabilityProbe {
        if cfg!(target_family = "unix") {
            CapabilityProbe::new(
                "symlink_behavior",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "Unix targets expose symlink metadata and symlink creation",
            )
        } else if cfg!(target_family = "windows") {
            CapabilityProbe::new(
                "symlink_behavior",
                CapabilityStatus::Degraded,
                ProbeSource::Assumed,
                "Windows symlink creation may require privileges or developer mode",
            )
            .with_degradation_reason(
                "preserve symlink metadata in manifest and materialize only when allowed",
            )
            .with_recovery_command("enable Windows developer mode for symlink creation")
        } else {
            CapabilityProbe::new(
                "symlink_behavior",
                CapabilityStatus::Unsupported,
                ProbeSource::Configured,
                "symlink operations are unavailable for this target",
            )
            .with_degradation_reason("materialize symlinks as manifest entries, not host links")
        }
    }

    fn socket_buffers(&self) -> CapabilityProbe {
        if cfg!(target_arch = "wasm32") {
            CapabilityProbe::new(
                "socket_buffers",
                CapabilityStatus::Unsupported,
                ProbeSource::Configured,
                "browser networking does not expose UDP socket buffer tuning",
            )
            .with_degradation_reason("use browser transport backpressure")
        } else if cfg!(any(target_family = "unix", target_family = "windows")) {
            CapabilityProbe::new(
                "socket_buffers",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "native sockets can be tuned through socket2-backed ATP transport policy",
            )
        } else {
            CapabilityProbe::new(
                "socket_buffers",
                CapabilityStatus::Unknown,
                ProbeSource::Skipped,
                "socket buffer controls are unknown",
            )
            .with_degradation_reason("start with conservative packet pacing")
        }
    }

    fn ipv6(&self) -> CapabilityProbe {
        if cfg!(target_arch = "wasm32") {
            return CapabilityProbe::new(
                "ipv6",
                CapabilityStatus::Unknown,
                ProbeSource::Configured,
                "browser networking hides address-family socket creation",
            )
            .with_degradation_reason("let browser transport policy select address family");
        }

        match UdpSocket::bind("[::1]:0") {
            Ok(socket) => {
                let local_addr = socket
                    .local_addr()
                    .map_or_else(|_| "[::1]:0".to_string(), |addr| addr.to_string());
                CapabilityProbe::new(
                    "ipv6",
                    CapabilityStatus::Supported,
                    ProbeSource::Measured,
                    format!("bound IPv6 loopback UDP socket at {local_addr}"),
                )
            }
            Err(err) => CapabilityProbe::new(
                "ipv6",
                CapabilityStatus::Degraded,
                ProbeSource::Measured,
                format!("IPv6 loopback UDP bind failed: {err}"),
            )
            .with_degradation_reason("prefer IPv4 candidates or relay until IPv6 is available")
            .with_recovery_command("enable IPv6 loopback/networking on this host"),
        }
    }

    fn router_assist(&self) -> CapabilityProbe {
        CapabilityProbe::new(
            "router_assist",
            CapabilityStatus::Unsupported,
            ProbeSource::Configured,
            "no UPnP/NAT-PMP/PCP router-assist provider is configured yet",
        )
        .with_degradation_reason("use explicit endpoints, hole punching, or relay fallback")
    }

    fn service_manager(&self) -> CapabilityProbe {
        if cfg!(target_os = "linux") {
            if Path::new("/run/systemd/system").exists() {
                CapabilityProbe::new(
                    "service_manager",
                    CapabilityStatus::Supported,
                    ProbeSource::Measured,
                    "systemd runtime directory is present",
                )
            } else {
                CapabilityProbe::new(
                    "service_manager",
                    CapabilityStatus::Degraded,
                    ProbeSource::Measured,
                    "systemd runtime directory is absent",
                )
                .with_degradation_reason("package atpd as a foreground or user-managed service")
                .with_recovery_command("run atpd under a supported service manager")
            }
        } else if cfg!(target_os = "macos") {
            CapabilityProbe::new(
                "service_manager",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "launchd is the expected service manager",
            )
        } else if cfg!(target_family = "windows") {
            CapabilityProbe::new(
                "service_manager",
                CapabilityStatus::Supported,
                ProbeSource::Assumed,
                "Windows Service Control Manager is available",
            )
        } else {
            CapabilityProbe::new(
                "service_manager",
                CapabilityStatus::Unknown,
                ProbeSource::Skipped,
                "service manager integration is unknown for this target",
            )
            .with_degradation_reason("ship atpd as a foreground process")
        }
    }
}

/// Detects ATP platform capabilities using native probes.
pub fn detect_platform_capabilities() -> PlatformCapabilityReport {
    build_platform_capability_report(&NativePlatformCapabilityProvider)
}

/// Builds a capability report from a provider.
pub fn build_platform_capability_report(
    provider: &impl PlatformCapabilityProvider,
) -> PlatformCapabilityReport {
    let filesystem = FilesystemCapabilityProfile {
        sparse_files: provider.sparse_files(),
        preallocation: provider.preallocation(),
        atomic_rename: provider.atomic_rename(),
        fsync_durability: provider.fsync_durability(),
        max_path_length: provider.max_path_length(),
        case_sensitive_paths: provider.case_sensitive_paths(),
        symlink_behavior: provider.symlink_behavior(),
    };
    let network = NetworkCapabilityProfile {
        socket_buffers: provider.socket_buffers(),
        ipv6: provider.ipv6(),
        router_assist: provider.router_assist(),
    };
    let service = ServiceCapabilityProfile {
        service_manager: provider.service_manager(),
    };
    let all_probes = collect_probes(&filesystem, &network, &service);

    PlatformCapabilityReport {
        schema_version: PLATFORM_CAPABILITY_REPORT_SCHEMA.to_string(),
        target: provider.target(),
        degradation_policy: derive_degradation_policy(&filesystem, &network, &service),
        caveats: derive_caveats(&all_probes),
        suggested_recovery_commands: derive_recovery_commands(&all_probes),
        filesystem,
        network,
        service,
    }
}

fn derive_degradation_policy(
    filesystem: &FilesystemCapabilityProfile,
    network: &NetworkCapabilityProfile,
    service: &ServiceCapabilityProfile,
) -> PlatformDegradationPolicy {
    let disk_writer_mode = if filesystem.sparse_files.status.is_full_support()
        && filesystem.preallocation.status.is_full_support()
    {
        "sparse-preallocated".to_string()
    } else if filesystem.sparse_files.status.is_full_support() {
        "sparse-grow-with-enospc-recovery".to_string()
    } else {
        "contiguous-verified-quarantine".to_string()
    };

    let atomic_commit_mode = if filesystem.atomic_rename.status.is_full_support()
        && filesystem.fsync_durability.status.is_full_support()
    {
        "sync-temp-rename-sync-parent".to_string()
    } else if filesystem.atomic_rename.status.is_full_support() {
        "rename-with-journal-replay-guard".to_string()
    } else {
        "manifest-version-switch-quarantine".to_string()
    };

    let endpoint_mode = if network.ipv6.status.is_full_support() {
        "ipv6-ipv4-direct-first".to_string()
    } else {
        "ipv4-or-relay-first".to_string()
    };

    let packaging_mode = if service.service_manager.status.is_full_support() {
        "managed-service".to_string()
    } else {
        "foreground-or-user-service".to_string()
    };

    PlatformDegradationPolicy {
        disk_writer_mode,
        atomic_commit_mode,
        endpoint_mode,
        packaging_mode,
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

fn derive_caveats(probes: &[&CapabilityProbe]) -> Vec<String> {
    probes
        .iter()
        .filter(|probe| {
            probe.status != CapabilityStatus::Supported || probe.source != ProbeSource::Measured
        })
        .map(|probe| {
            let reason = probe
                .degradation_reason
                .as_deref()
                .unwrap_or("confirm before relying on this capability");
            format!(
                "{}: status={} source={} reason={}",
                probe.name,
                probe.status.as_str(),
                probe.source.as_str(),
                reason
            )
        })
        .collect()
}

fn derive_recovery_commands(probes: &[&CapabilityProbe]) -> Vec<String> {
    let mut commands = Vec::new();
    for probe in probes {
        if probe.status.is_full_support() {
            continue;
        }
        if let Some(command) = &probe.suggested_recovery_command {
            if !commands.contains(command) {
                commands.push(command.clone());
            }
        }
    }
    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct DeterministicPlatformCapabilityProvider {
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

    impl DeterministicPlatformCapabilityProvider {
        fn fully_supported() -> Self {
            Self {
                target: PlatformTarget {
                    os: "testos".to_string(),
                    family: "test".to_string(),
                    arch: "testarch".to_string(),
                    pointer_width: 64,
                },
                sparse_files: supported("sparse_files"),
                preallocation: supported("preallocation"),
                atomic_rename: supported("atomic_rename"),
                fsync_durability: supported("fsync_durability"),
                max_path_length: supported("max_path_length"),
                case_sensitive_paths: supported("case_sensitive_paths"),
                symlink_behavior: supported("symlink_behavior"),
                socket_buffers: supported("socket_buffers"),
                ipv6: supported("ipv6"),
                router_assist: supported("router_assist"),
                service_manager: supported("service_manager"),
            }
        }
    }

    impl PlatformCapabilityProvider for DeterministicPlatformCapabilityProvider {
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

    fn supported(name: &'static str) -> CapabilityProbe {
        CapabilityProbe::new(
            name,
            CapabilityStatus::Supported,
            ProbeSource::Measured,
            format!("{name} supported"),
        )
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn fully_supported_provider_selects_fast_policy() {
        init_test("fully_supported_provider_selects_fast_policy");
        let provider = DeterministicPlatformCapabilityProvider::fully_supported();
        let report = build_platform_capability_report(&provider);

        assert_eq!(
            report.schema_version,
            PLATFORM_CAPABILITY_REPORT_SCHEMA.to_string()
        );
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
        assert!(report.suggested_recovery_commands.is_empty());
        crate::test_complete!("fully_supported_provider_selects_fast_policy");
    }

    #[test]
    fn failed_probes_select_conservative_degradation() {
        init_test("failed_probes_select_conservative_degradation");
        let mut provider = DeterministicPlatformCapabilityProvider::fully_supported();
        provider.sparse_files = CapabilityProbe::new(
            "sparse_files",
            CapabilityStatus::Unsupported,
            ProbeSource::Measured,
            "sparse write probe failed",
        )
        .with_degradation_reason("write into quarantine before verified exposure");
        provider.fsync_durability = CapabilityProbe::new(
            "fsync_durability",
            CapabilityStatus::Degraded,
            ProbeSource::Measured,
            "directory fsync failed",
        )
        .with_degradation_reason("replay journal after every restart");
        provider.ipv6 = CapabilityProbe::new(
            "ipv6",
            CapabilityStatus::Degraded,
            ProbeSource::Measured,
            "IPv6 unavailable",
        )
        .with_degradation_reason("prefer IPv4")
        .with_recovery_command("enable IPv6 loopback/networking on this host");

        let report = build_platform_capability_report(&provider);

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
        assert!(report.caveats.iter().any(|caveat| {
            caveat.contains("sparse_files")
                && caveat.contains("write into quarantine before verified exposure")
        }));
        assert_eq!(
            report.suggested_recovery_commands,
            vec!["enable IPv6 loopback/networking on this host".to_string()]
        );
        crate::test_complete!("failed_probes_select_conservative_degradation");
    }

    #[test]
    fn supported_probe_recovery_commands_are_ignored() {
        init_test("supported_probe_recovery_commands_are_ignored");
        let mut provider = DeterministicPlatformCapabilityProvider::fully_supported();
        provider.preallocation = CapabilityProbe::new(
            "preallocation",
            CapabilityStatus::Supported,
            ProbeSource::Measured,
            "preallocation supported",
        )
        .with_recovery_command("do not suggest this for supported probes");

        let report = build_platform_capability_report(&provider);

        assert!(report.suggested_recovery_commands.is_empty());
        crate::test_complete!("supported_probe_recovery_commands_are_ignored");
    }

    #[test]
    fn native_report_has_stable_sections() {
        init_test("native_report_has_stable_sections");
        let report = detect_platform_capabilities();

        assert_eq!(report.schema_version, PLATFORM_CAPABILITY_REPORT_SCHEMA);
        assert_eq!(report.filesystem.sparse_files.name, "sparse_files");
        assert_eq!(report.filesystem.atomic_rename.name, "atomic_rename");
        assert_eq!(report.network.ipv6.name, "ipv6");
        assert_eq!(report.service.service_manager.name, "service_manager");
        assert!(!report.degradation_policy.disk_writer_mode.is_empty());
        assert!(!report.degradation_policy.atomic_commit_mode.is_empty());
        crate::test_complete!("native_report_has_stable_sections");
    }
}
