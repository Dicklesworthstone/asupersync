#![allow(warnings)]
#![allow(clippy::all)]
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
        "use std::os::windows::io::{AsRawHandle, RawHandle};",
        "fn wait_with_output_windows(mut self) -> Result<Output, ProcessError>",
    ] {
        assert!(
            process_src.contains(token),
            "process module missing windows-specific token: {token}"
        );
    }

    assert!(
        process_src.contains("return self.wait_with_output_windows();"),
        "wait_with_output must route to windows-specific implementation on Windows"
    );
    assert!(
        process_src.contains("self.wait_with_output_windows().map_err(io::Error::from)"),
        "wait_with_output_async must route through windows-specific implementation on Windows"
    );
}

#[test]
fn track_i_signal_surface_contains_windows_subset_mapping() {
    let signal_src = load_source("src/signal/signal.rs");

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
}

#[test]
fn track_i_process_parity_artifacts_mark_windows_as_track_i_scope() {
    let process_md = load_source("docs/tokio_process_lifecycle_parity.md");
    let process_json = load_source("docs/tokio_process_lifecycle_parity.json");

    assert!(
        process_md.contains("Windows-specific process semantics (PR-G3 — Track-I)"),
        "process lifecycle markdown must explicitly defer PR-G3 to Track-I"
    );
    assert!(
        process_json.contains("\"id\": \"PR-G3\"")
            && process_json
                .contains("\"deferred_to\": \"Track-I (Windows platform completeness)\""),
        "process lifecycle json must preserve PR-G3 deferred-to Track-I linkage"
    );
}
