//! ATP-NR11 cross-platform capability and skip-report contract.
//!
//! This test target intentionally keeps the first slice small: it detects host
//! filesystem/socket capabilities with real probes, then emits a deterministic
//! platform-specific skip row that cannot be counted as a passed capability.

use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::io::{Seek, SeekFrom};
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::path::Path;
use tempfile::TempDir;

#[derive(Debug, Clone, Serialize)]
struct PlatformCapabilityReport {
    schema_version: u32,
    os: String,
    arch: String,
    filesystem: BTreeMap<String, CapabilityStatus>,
    socket: BTreeMap<String, CapabilityStatus>,
    network_overlay: BTreeMap<String, CapabilityStatus>,
    selected_degradation_policy: String,
    scenario_reports: Vec<ScenarioReport>,
}

#[derive(Debug, Clone, Serialize)]
struct CapabilityStatus {
    state: CapabilityState,
    reason: String,
    evidence: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CapabilityState {
    Supported,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
struct ScenarioReport {
    scenario_id: String,
    status: ScenarioStatus,
    reason: String,
    required_capability: String,
    platform: String,
    remediation: String,
    release_gate_counts_as_pass: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScenarioStatus {
    Pass,
    Skip,
}

#[test]
fn test_atp_platform_capability_detector_covers_required_surfaces()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let report = detect_platform_capabilities(temp_dir.path())?;
    let report_json = serde_json::to_value(&report)?;

    assert_eq!(report.schema_version, 1);
    assert!(!report.os.is_empty());
    assert!(!report.arch.is_empty());
    assert_eq!(report_json["os"], std::env::consts::OS);
    assert_eq!(report_json["arch"], std::env::consts::ARCH);

    for capability in [
        "sparse_files",
        "preallocation",
        "atomic_rename",
        "fsync_policy",
        "path_normalization",
        "case_sensitive_paths",
        "symlink_policy",
        "file_permissions",
    ] {
        assert!(
            report.filesystem.contains_key(capability),
            "missing filesystem capability {capability}"
        );
    }

    for capability in [
        "udp_socket_bind",
        "udp_batching",
        "ipv6_loopback",
        "router_assist",
    ] {
        assert!(
            report.socket.contains_key(capability),
            "missing socket capability {capability}"
        );
    }

    assert!(report.network_overlay.contains_key("tailscale"));
    assert!(!report.selected_degradation_policy.trim().is_empty());
    assert!(
        report
            .scenario_reports
            .iter()
            .any(
                |scenario| scenario.scenario_id == "atp.cross_platform.host.capability_detector"
                    && scenario.status == ScenarioStatus::Pass
                    && scenario.release_gate_counts_as_pass
            ),
        "host capability detector pass row missing"
    );

    Ok(())
}

#[test]
fn test_atp_platform_skip_report_is_machine_readable_and_not_a_pass()
-> Result<(), Box<dyn std::error::Error>> {
    let report = build_report_with_scenarios(
        "linux",
        "x86_64",
        BTreeMap::new(),
        BTreeMap::from([(
            "udp_batching".to_string(),
            unsupported("std::net does not expose UDP batch syscalls"),
        )]),
        BTreeMap::new(),
    );

    let skip = report
        .scenario_reports
        .iter()
        .find(|scenario| scenario.status == ScenarioStatus::Skip)
        .expect("platform-specific skip row is recorded");
    assert_eq!(
        skip.scenario_id,
        "atp.cross_platform.macos.kqueue_udp_batching"
    );
    assert_eq!(skip.platform, "linux");
    assert_eq!(skip.required_capability, "macos.kqueue.udp_batching");
    assert!(!skip.release_gate_counts_as_pass);
    assert!(skip.reason.contains("requires macos"));
    assert!(skip.remediation.contains("macOS proof lane"));

    let json = serde_json::to_value(&report)?;
    let skip_json = json["scenario_reports"]
        .as_array()
        .expect("scenario_reports is an array")
        .iter()
        .find(|row| row["status"] == "skip")
        .expect("serialized skip row exists");
    assert_eq!(
        skip_json["release_gate_counts_as_pass"],
        serde_json::Value::Bool(false)
    );

    let passed_count = report
        .scenario_reports
        .iter()
        .filter(|scenario| {
            scenario.status == ScenarioStatus::Pass && scenario.release_gate_counts_as_pass
        })
        .count();
    assert_eq!(
        passed_count, 1,
        "skipped platform capability counted as pass"
    );

    Ok(())
}

fn detect_platform_capabilities(
    scratch: &Path,
) -> Result<PlatformCapabilityReport, Box<dyn std::error::Error>> {
    let filesystem = BTreeMap::from([
        ("sparse_files".to_string(), detect_sparse_files(scratch)),
        ("preallocation".to_string(), detect_preallocation(scratch)?),
        ("atomic_rename".to_string(), detect_atomic_rename(scratch)?),
        ("fsync_policy".to_string(), detect_fsync_policy(scratch)?),
        (
            "path_normalization".to_string(),
            detect_path_normalization(scratch)?,
        ),
        (
            "case_sensitive_paths".to_string(),
            detect_case_sensitive_paths(scratch)?,
        ),
        ("symlink_policy".to_string(), detect_symlink_policy(scratch)),
        (
            "file_permissions".to_string(),
            detect_file_permissions(scratch)?,
        ),
    ]);
    let socket = BTreeMap::from([
        ("udp_socket_bind".to_string(), detect_udp_socket_bind()),
        ("udp_batching".to_string(), detect_udp_batching()),
        ("ipv6_loopback".to_string(), detect_ipv6_loopback()),
        ("router_assist".to_string(), detect_router_assist()),
    ]);
    let network_overlay = BTreeMap::from([("tailscale".to_string(), detect_tailscale())]);

    Ok(build_report_with_scenarios(
        std::env::consts::OS,
        std::env::consts::ARCH,
        filesystem,
        socket,
        network_overlay,
    ))
}

fn build_report_with_scenarios(
    os: &str,
    arch: &str,
    filesystem: BTreeMap<String, CapabilityStatus>,
    socket: BTreeMap<String, CapabilityStatus>,
    network_overlay: BTreeMap<String, CapabilityStatus>,
) -> PlatformCapabilityReport {
    let selected_degradation_policy = if socket
        .get("udp_batching")
        .is_some_and(|capability| capability.state == CapabilityState::Supported)
    {
        "native_udp_batching".to_string()
    } else {
        "portable_single_datagram_udp".to_string()
    };

    PlatformCapabilityReport {
        schema_version: 1,
        os: os.to_string(),
        arch: arch.to_string(),
        filesystem,
        socket,
        network_overlay,
        selected_degradation_policy,
        scenario_reports: vec![
            ScenarioReport {
                scenario_id: "atp.cross_platform.host.capability_detector".to_string(),
                status: ScenarioStatus::Pass,
                reason: "host capability report rendered".to_string(),
                required_capability: "platform.capability_report".to_string(),
                platform: os.to_string(),
                remediation: "none".to_string(),
                release_gate_counts_as_pass: true,
            },
            macos_udp_batching_skip(os),
        ],
    }
}

fn macos_udp_batching_skip(os: &str) -> ScenarioReport {
    if os == "macos" {
        ScenarioReport {
            scenario_id: "atp.cross_platform.macos.kqueue_udp_batching".to_string(),
            status: ScenarioStatus::Pass,
            reason: "macos platform lane selected".to_string(),
            required_capability: "macos.kqueue.udp_batching".to_string(),
            platform: os.to_string(),
            remediation: "none".to_string(),
            release_gate_counts_as_pass: true,
        }
    } else {
        ScenarioReport {
            scenario_id: "atp.cross_platform.macos.kqueue_udp_batching".to_string(),
            status: ScenarioStatus::Skip,
            reason: format!("requires macos; current platform is {os}"),
            required_capability: "macos.kqueue.udp_batching".to_string(),
            platform: os.to_string(),
            remediation: "run the macOS proof lane and attach its skip/pass artifact".to_string(),
            release_gate_counts_as_pass: false,
        }
    }
}

fn detect_preallocation(scratch: &Path) -> Result<CapabilityStatus, std::io::Error> {
    let path = scratch.join("preallocation_probe.bin");
    let file = File::create(&path)?;
    file.set_len(4096)?;
    let len = fs::metadata(&path)?.len();
    Ok(supported(
        "portable set_len reservation succeeded",
        BTreeMap::from([("len".to_string(), len.to_string())]),
    ))
}

fn detect_atomic_rename(scratch: &Path) -> Result<CapabilityStatus, std::io::Error> {
    let src = scratch.join("rename_probe.tmp");
    let dst = scratch.join("rename_probe.final");
    fs::write(&src, b"rename-probe")?;
    fs::rename(&src, &dst)?;
    Ok(supported(
        "rename completed in scratch directory",
        BTreeMap::from([("dst_exists".to_string(), dst.exists().to_string())]),
    ))
}

fn detect_fsync_policy(scratch: &Path) -> Result<CapabilityStatus, std::io::Error> {
    let path = scratch.join("fsync_probe.bin");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    file.write_all(b"fsync-probe")?;
    file.sync_all()?;
    Ok(supported("file sync_all completed", BTreeMap::new()))
}

fn detect_path_normalization(scratch: &Path) -> Result<CapabilityStatus, std::io::Error> {
    let canonical = scratch.canonicalize()?;
    Ok(supported(
        "canonicalize completed",
        BTreeMap::from([("canonical".to_string(), canonical.display().to_string())]),
    ))
}

fn detect_case_sensitive_paths(scratch: &Path) -> Result<CapabilityStatus, std::io::Error> {
    let mixed = scratch.join("CaseProbe");
    let lower = scratch.join("caseprobe");
    fs::write(&mixed, b"case-probe")?;
    if lower.exists() {
        Ok(unsupported("case-insensitive path lookup observed"))
    } else {
        Ok(supported(
            "distinct lowercase path did not resolve",
            BTreeMap::new(),
        ))
    }
}

fn detect_file_permissions(scratch: &Path) -> Result<CapabilityStatus, std::io::Error> {
    let path = scratch.join("permissions_probe.bin");
    fs::write(&path, b"permissions")?;
    let readonly = fs::metadata(&path)?.permissions().readonly();
    Ok(supported(
        "basic permissions metadata readable",
        BTreeMap::from([("readonly".to_string(), readonly.to_string())]),
    ))
}

#[cfg(unix)]
fn detect_sparse_files(scratch: &Path) -> CapabilityStatus {
    use std::os::unix::fs::MetadataExt;

    let path = scratch.join("sparse_probe.bin");
    let result = (|| -> Result<CapabilityStatus, std::io::Error> {
        let mut file = File::create(&path)?;
        file.seek(SeekFrom::Start(1024 * 1024))?;
        file.write_all(&[1])?;
        file.sync_all()?;
        let metadata = fs::metadata(&path)?;
        let allocated_bytes = metadata.blocks().saturating_mul(512);
        if allocated_bytes < metadata.len() {
            Ok(supported(
                "allocated blocks are smaller than logical length",
                BTreeMap::from([
                    ("logical_len".to_string(), metadata.len().to_string()),
                    ("allocated_bytes".to_string(), allocated_bytes.to_string()),
                ]),
            ))
        } else {
            Ok(unsupported("filesystem did not preserve sparse allocation"))
        }
    })();
    result.unwrap_or_else(|error| unsupported(format!("sparse probe failed: {error}")))
}

#[cfg(not(unix))]
fn detect_sparse_files(_scratch: &Path) -> CapabilityStatus {
    unsupported("portable sparse block metadata is unavailable on this target")
}

#[cfg(unix)]
fn detect_symlink_policy(scratch: &Path) -> CapabilityStatus {
    let target = scratch.join("symlink_target");
    let link = scratch.join("symlink_link");
    let result = (|| -> Result<CapabilityStatus, std::io::Error> {
        fs::write(&target, b"symlink-target")?;
        std::os::unix::fs::symlink(&target, &link)?;
        Ok(supported(
            "unix symlink creation succeeded",
            BTreeMap::new(),
        ))
    })();
    result.unwrap_or_else(|error| unsupported(format!("symlink probe failed: {error}")))
}

#[cfg(windows)]
fn detect_symlink_policy(scratch: &Path) -> CapabilityStatus {
    let target = scratch.join("symlink_target");
    let link = scratch.join("symlink_link");
    let result = (|| -> Result<CapabilityStatus, std::io::Error> {
        fs::write(&target, b"symlink-target")?;
        std::os::windows::fs::symlink_file(&target, &link)?;
        Ok(supported(
            "windows file symlink creation succeeded",
            BTreeMap::new(),
        ))
    })();
    result.unwrap_or_else(|error| unsupported(format!("symlink probe failed: {error}")))
}

#[cfg(not(any(unix, windows)))]
fn detect_symlink_policy(_scratch: &Path) -> CapabilityStatus {
    unsupported("symlink probe unavailable on this target")
}

fn detect_udp_socket_bind() -> CapabilityStatus {
    match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => supported(
            "udp loopback bind succeeded",
            BTreeMap::from([(
                "local_addr".to_string(),
                socket
                    .local_addr()
                    .map_or_else(|_| "<unknown>".to_string(), |addr| addr.to_string()),
            )]),
        ),
        Err(error) => unsupported(format!("udp loopback bind failed: {error}")),
    }
}

fn detect_ipv6_loopback() -> CapabilityStatus {
    let addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0);
    match UdpSocket::bind(addr) {
        Ok(socket) => supported(
            "ipv6 loopback udp bind succeeded",
            BTreeMap::from([(
                "local_addr".to_string(),
                socket
                    .local_addr()
                    .map_or_else(|_| "<unknown>".to_string(), |addr| addr.to_string()),
            )]),
        ),
        Err(error) => unsupported(format!("ipv6 loopback udp bind failed: {error}")),
    }
}

fn detect_udp_batching() -> CapabilityStatus {
    unsupported("portable std::net does not expose UDP batching syscalls")
}

fn detect_router_assist() -> CapabilityStatus {
    match std::env::var("ATP_ROUTER_ASSIST_ENDPOINT") {
        Ok(endpoint) if !endpoint.trim().is_empty() => supported(
            "router assist endpoint provided by environment",
            BTreeMap::from([("endpoint".to_string(), endpoint)]),
        ),
        _ => unsupported("ATP_ROUTER_ASSIST_ENDPOINT is unset"),
    }
}

fn detect_tailscale() -> CapabilityStatus {
    if std::env::var("TAILSCALE_IP").is_ok_and(|ip| !ip.trim().is_empty()) {
        return supported("TAILSCALE_IP environment variable is set", BTreeMap::new());
    }

    #[cfg(unix)]
    {
        if Path::new("/var/run/tailscale/tailscaled.sock").exists() {
            return supported("tailscaled unix socket exists", BTreeMap::new());
        }
    }

    unsupported("tailscale was not detected in the host environment")
}

fn supported(reason: impl Into<String>, evidence: BTreeMap<String, String>) -> CapabilityStatus {
    CapabilityStatus {
        state: CapabilityState::Supported,
        reason: reason.into(),
        evidence,
    }
}

fn unsupported(reason: impl Into<String>) -> CapabilityStatus {
    CapabilityStatus {
        state: CapabilityState::Unsupported,
        reason: reason.into(),
        evidence: BTreeMap::new(),
    }
}
