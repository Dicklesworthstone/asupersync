//! Track-I (`asupersync-t1nde`) Windows platform completeness contract tests.
//!
//! These tests are host-agnostic: they validate gated source contracts without
//! requiring a Windows host or Windows target stdlib installation.

#![allow(missing_docs)]

use std::path::Path;

fn project_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn load_source(relative: &str) -> String {
    let path = project_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {}", path.display()))
}

#[test]
fn track_i_named_pipe_surface_is_gated_and_exported() {
    let net_mod = load_source("src/net/mod.rs");
    let net_sys_mod = load_source("src/net/sys/mod.rs");
    let windows_net = load_source("src/net/sys/windows.rs");

    assert!(
        net_mod.contains("#[cfg(target_os = \"windows\")]"),
        "net mod must gate Windows exports with cfg(target_os = \"windows\")"
    );
    assert!(
        net_mod.contains("pub use sys::windows::{NamedPipeClient, NamedPipeClientOptions};"),
        "net mod must export NamedPipeClient and NamedPipeClientOptions on Windows"
    );
    assert!(
        net_sys_mod.contains("#[cfg(target_os = \"windows\")]")
            && net_sys_mod.contains("pub mod windows;"),
        "net/sys mod must gate and expose the windows networking module"
    );

    for token in [
        "#![cfg(target_os = \"windows\")]",
        "const PIPE_PREFIX",
        "fn validate_named_pipe_path",
        "pub struct NamedPipeClientOptions",
        "pub fn new() -> Self",
        "pub fn read(mut self, enabled: bool) -> Self",
        "pub fn write(mut self, enabled: bool) -> Self",
        "pub fn open(self, path: impl AsRef<Path>) -> io::Result<NamedPipeClient>",
        "pub struct NamedPipeClient",
        "pub fn connect(path: impl AsRef<Path>) -> io::Result<Self>",
        "pub fn try_clone(&self) -> io::Result<Self>",
        "pub fn into_inner(self) -> File",
        "impl Read for NamedPipeClient",
        "impl Write for NamedPipeClient",
    ] {
        assert!(
            windows_net.contains(token),
            "windows named-pipe module missing required contract token: {token}"
        );
    }
}

#[test]
fn track_i_process_surface_contains_windows_output_path() {
    let process_src = load_source("src/process.rs");

    for token in [
        "#[cfg(windows)]",
        "fn wait_with_output_windows(mut self) -> Result<Output, ProcessError>",
        "async fn wait_with_output_windows_async(mut self, cx: &Cx) -> Result<Output, ProcessError>",
        "fn spawn_process_output_reader(",
        "fn join_process_output_reader(",
        "async fn collect_process_output_readers(",
    ] {
        assert!(
            process_src.contains(token),
            "process module missing windows-specific token: {token}"
        );
    }

    assert!(
        process_src.contains("use std::os::windows::io::{AsRawHandle, RawHandle};")
            || (process_src.contains("use std::os::windows::{")
                && process_src.contains("io::{AsRawHandle, RawHandle},")),
        "process module must import Windows raw-handle traits for process I/O"
    );
    assert!(
        process_src.contains("return self.wait_with_output_windows();"),
        "wait_with_output must route to windows-specific implementation on Windows"
    );
    assert!(
        process_src.contains("return self.wait_with_output_windows_async(cx).await;"),
        "wait_with_output_async must route through the Cx-aware Windows implementation"
    );
    assert!(
        process_src.contains("let status = match self.wait_async(cx).await"),
        "Windows wait_with_output_async must preserve process cancellation through wait_async"
    );
    assert!(
        process_src
            .contains("collect_process_output_readers(cx, stdout_thread, stderr_thread).await"),
        "Windows wait_with_output_async must collect pipe readers through the Cx-aware async drain"
    );
    assert!(
        process_src.contains("if cx.checkpoint().is_err()")
            && process_src.contains("drop(stdout_reader);")
            && process_src.contains("drop(stderr_reader);"),
        "Windows async output draining must keep cancellation bounded while waiting for reader threads"
    );
    assert!(
        !process_src.contains("let _ = cx;\n            return crate::runtime::spawn_blocking_io"),
        "Windows wait_with_output_async must not discard Cx and block the entire output path"
    );
}

#[test]
fn track_i_signal_surface_contains_windows_subset_mapping() {
    let signal_mod = load_source("src/signal/mod.rs");
    let signal_src = load_source("src/signal/signal.rs");
    let kind_src = load_source("src/signal/kind.rs");

    for token in [
        "#[cfg(windows)]\nfn all_signal_kinds() -> [SignalKind; 3]",
        "SignalKind::Interrupt",
        "SignalKind::Terminate",
        "SignalKind::Quit",
        "#[cfg(windows)]\nfn raw_signal_for_kind(kind: SignalKind) -> i32",
        "kind.as_raw_value().expect(\"windows supported signal kind\")",
        "#[cfg(windows)]\nfn signal_kind_from_raw(raw: i32) -> Option<SignalKind>",
        "raw == signal_hook::consts::SIGBREAK",
        "fn windows_raw_signal_mapping_subset()",
    ] {
        assert!(
            signal_src.contains(token),
            "signal module missing windows-specific token: {token}"
        );
    }

    for token in [
        "#[cfg(any(unix, windows))]\npub use signal::{sigint, sigquit, sigterm};",
        "#[cfg(unix)]\npub use signal::{sigalrm, sigchld, sighup, sigpipe, sigusr1, sigusr2, sigwinch};",
    ] {
        assert!(
            signal_mod.contains(token),
            "signal module must expose only the Windows-supported helper subset cross-platform: {token}"
        );
    }

    for token in [
        "#[cfg(any(unix, windows))]\npub fn sigint()",
        "#[cfg(any(unix, windows))]\npub fn sigterm()",
        "#[cfg(any(unix, windows))]\npub fn sigquit()",
        "Creates a stream for SIGQUIT on Unix or SIGBREAK on Windows.",
    ] {
        assert!(
            signal_src.contains(token),
            "signal helpers must be Windows-visible for the supported subset: {token}"
        );
    }

    assert!(
        kind_src.contains("Windows targets map\n//! the supported subset")
            && kind_src.contains("/// SIGQUIT on Unix; SIGBREAK / Ctrl+Break on Windows."),
        "SignalKind docs must describe the Windows SIGINT/SIGTERM/SIGBREAK subset"
    );
}

#[test]
fn track_i_process_parity_artifacts_mark_windows_as_track_i_scope() {
    let process_md = load_source("docs/tokio_process_lifecycle_parity.md");
    let process_json = load_source("docs/tokio_process_lifecycle_parity.json");

    assert!(
        process_md.contains("Windows direct child-pipe `AsyncRead` / `AsyncWrite` trait parity")
            && process_md.contains("PR-G3 — Track-I"),
        "process lifecycle markdown must explicitly narrow and defer PR-G3 to Track-I"
    );
    assert!(
        process_json.contains("\"id\": \"PR-G3\"")
            && process_json.contains("\"title\": \"Windows direct async child-pipe trait parity\"")
            && process_json
                .contains("\"deferred_to\": \"Track-I (Windows platform completeness)\""),
        "process lifecycle json must preserve narrowed PR-G3 deferred-to Track-I linkage"
    );
}

#[test]
fn track_i_resource_monitor_uses_real_windows_platform_probes() {
    let monitor_src = load_source("src/runtime/resource_monitor.rs");
    let cargo_toml = load_source("Cargo.toml");
    let obsolete_windows_probe_marker = concat!("not ", "implemented on Windows yet");

    assert!(
        !monitor_src.contains(obsolete_windows_probe_marker),
        "resource monitor must not keep obsolete Windows probe gaps"
    );

    for token in [
        "GetProcessHandleCount",
        "GetSystemTimes",
        "GetExtendedTcpTable",
        "GetExtendedUdpTable",
        "TCP_TABLE_OWNER_PID_ALL",
        "UDP_TABLE_OWNER_PID",
        "MIB_TCPROW_OWNER_PID",
        "MIB_TCP6ROW_OWNER_PID",
        "MIB_UDPROW_OWNER_PID",
        "MIB_UDP6ROW_OWNER_PID",
        "WINDOWS_PROCESS_HANDLE_PRESSURE_CEILING",
    ] {
        assert!(
            monitor_src.contains(token),
            "resource monitor missing real Windows probe token: {token}"
        );
    }

    for feature in [
        "\"Win32_NetworkManagement_IpHelper\"",
        "\"Win32_Networking_WinSock\"",
    ] {
        assert!(
            cargo_toml.contains(feature),
            "Cargo.toml must enable windows-sys feature {feature}"
        );
    }
}
