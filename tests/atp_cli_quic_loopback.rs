//! Binary-level loopback contract for `atp send/recv --transport quic`.
//!
//! This is the F1 gate for `asupersync-arq-quic-epic-b0k8qo.6.1`: the actual
//! standalone `atp` binary must drive the real ATP-over-QUIC transport rather
//! than only exposing the lower-level `transport_quic` API.

#![cfg(all(feature = "atp-cli", feature = "tls"))]
#![allow(missing_docs)]

#[cfg(feature = "atpd-daemon")]
use std::io::Write;
use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
#[cfg(feature = "atpd-daemon")]
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
#[cfg(feature = "atpd-daemon")]
use std::process::{ChildStderr, ChildStdout};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(any(windows, target_os = "linux"))]
use sha2::{Digest, Sha256};

const VALID_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

// Canonical CA + leaf chain shared with the real UDP QUIC transport e2e. The
// leaf has SAN DNS:localhost / IP:127.0.0.1, so the binary path exercises real
// WebPKI verification with no insecure skip-verify branch.
const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwTCCAWigAwIBAgIUTQyiZ96ufyKHVqRYRZBXpRQABGMwCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAUMRIwEAYDVQQDDAlhdHBxLXRlc3QwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBbxlDvlrJDWhuXLXcrwcK4\n\
eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hdo4GSMIGPMBoGA1UdEQQTMBGCCWxv\n\
Y2FsaG9zdIcEfwAAATATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA\n\
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUTWWIxYJyvXlJNVcDd8An36rhuMQw\n\
HwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNzvtYwCgYIKoZIzj0EAwIDRwAw\n\
RAIgOkNWPyvljX7zxCWN9sJ/rpX7XV5ubXvNrPdV70sF8oECIGtMuJr6XEmcump1\n\
YuX2YYZ2gAU6aNU/up/PediXcN5u\n\
-----END CERTIFICATE-----\n";

const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpE59cRbMDhBIZaha\n\
UPAvB8O86PWbkhxy/8cx/FrSa1ShRANCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBb\n\
xlDvlrJDWhuXLXcrwcK4eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hd\n\
-----END PRIVATE KEY-----\n";

const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBlDCCATugAwIBAgIUYOTxo/FMMZjqCnJT+IDmJ2BNux0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAXMRUwEwYDVQQDDAxhdHBxLXRlc3QtY2EwWTATBgcqhkjOPQIB\n\
BggqhkjOPQMBBwNCAASAsNg5paEJFgZwYGu7aCzsZYPyDyjzzcT7fi3O5JHGW0xA\n\
pTqjgqykWTDkyfwdITXWXIfrx2D2+QwoGXOV4OFSo2MwYTAdBgNVHQ4EFgQUG872\n\
eUJJNl9C6SZHmR9sCRNzvtYwHwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNz\n\
vtYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID\n\
RwAwRAIgFLcs0Qdsy190QfKzpvLj28srfpw6wZ2PURF20N+twm8CIFZMWnG65VsE\n\
WkX8ykcdUfalGtZ1XFOTo+aaWs+3gyI1\n\
-----END CERTIFICATE-----\n";

// P-256 self-signed certificate with IP SAN 127.0.0.1, serverAuth EKU, and
// CA:TRUE. This mirrors the benchmark CLI path where the same PEM is passed as
// both --server-cert and --ca; WebPKI rejects it as an end-entity, so the CLI
// must treat the explicit --ca as a direct leaf pin rather than falling back to
// an insecure verifier.
const SELF_SIGNED_CA_TRUE_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwzCCAWigAwIBAgIUUipbHRMHoXz+egbfzEh5Q4NuOZ4wCgYIKoZIzj0EAwIw\n\
FDESMBAGA1UEAwwJMTI3LjAuMC4xMCAXDTI2MDYyMTE4Mjg1MloYDzIxMjYwNTI4\n\
MTgyODUyWjAUMRIwEAYDVQQDDAkxMjcuMC4wLjEwWTATBgcqhkjOPQIBBggqhkjO\n\
PQMBBwNCAAQSPQ5U0Ubuk7y1Ov22oGgWg1jRDQFdLaXeVDisROTsFq6TRJPQBUbC\n\
iF/mpdfpOoU7rznm+EKLwi7QvhHJ8hHZo4GVMIGSMB0GA1UdDgQWBBQMm+XYIbOs\n\
3uarxHpVbY+tEJPDqjAfBgNVHSMEGDAWgBQMm+XYIbOs3uarxHpVbY+tEJPDqjAa\n\
BgNVHREEEzARhwR/AAABgglsb2NhbGhvc3QwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n\
HQ8BAf8EBAMCAoQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSQAw\n\
RgIhANPjfmIIhuKQcQ63E0X0f+O/SW3pR3HHsslbOSj7CdVpAiEA1uk8WzcQOkJ1\n\
/5t6MH+uipuxBmQliyJymsXyLxfFtS8=\n\
-----END CERTIFICATE-----\n";

const SELF_SIGNED_CA_TRUE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4i+BN3DhwfMiy4pT\n\
834gbW6xj5Lewo5bjmdOQTuGm8qhRANCAAQSPQ5U0Ubuk7y1Ov22oGgWg1jRDQFd\n\
LaXeVDisROTsFq6TRJPQBUbCiF/mpdfpOoU7rznm+EKLwi7QvhHJ8hHZ\n\
-----END PRIVATE KEY-----\n";

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_cli_quic_{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, contents).expect("write file");
}

fn spawn_stderr_reader(child: &mut Child) -> mpsc::Receiver<String> {
    let stderr = child.stderr.take().expect("receiver stderr is piped");
    let (tx, rx) = mpsc::channel();
    spawn_line_reader(stderr, tx);
    rx
}

fn spawn_line_reader<R>(stream: R, tx: mpsc::Sender<String>)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
}

#[cfg(feature = "atpd-daemon")]
fn spawn_atpd_output_reader(child: &mut Child) -> mpsc::Receiver<String> {
    let stdout: ChildStdout = child.stdout.take().expect("daemon stdout is piped");
    let stderr: ChildStderr = child.stderr.take().expect("daemon stderr is piped");
    let (tx, rx) = mpsc::channel();
    spawn_line_reader(stdout, tx.clone());
    spawn_line_reader(stderr, tx);
    rx
}

fn parse_quic_listen_line(line: &str) -> Option<SocketAddr> {
    let rest = line.strip_prefix("atp: quic listening on ")?;
    let (addr, _) = rest.split_once(", dest ")?;
    addr.parse().ok()
}

fn parse_tcp_listen_line(line: &str) -> Option<SocketAddr> {
    let rest = line.strip_prefix("atp: tcp listening on ")?;
    let (addr, _) = rest.split_once(", dest ")?;
    addr.parse().ok()
}

fn parse_rq_listen_line(line: &str) -> Option<SocketAddr> {
    let rest = line.strip_prefix("atp: rq control listening on ")?;
    let (addr, _) = rest.split_once(" (udp on ")?;
    addr.parse().ok()
}

#[cfg(target_os = "linux")]
fn parse_bonded_listen_line(line: &str) -> Option<SocketAddr> {
    let rest = line.strip_prefix("atp: bonded control listening on ")?;
    let (addr, _) = rest.split_once(" (udp on ")?;
    addr.parse().ok()
}

#[cfg(feature = "atpd-daemon")]
fn parse_tracing_bind_addr(line: &str, marker: &str) -> Option<SocketAddr> {
    if !line.contains(marker) {
        return None;
    }
    line.split_whitespace().find_map(|part| {
        let value = part.strip_prefix("bind_addr=")?;
        value.trim_end_matches(',').parse().ok()
    })
}

fn wait_for_quic_listen_addr(rx: &mpsc::Receiver<String>) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    loop {
        let now = Instant::now();
        assert!(
            now < deadline,
            "receiver did not print QUIC readiness; stderr lines: {seen:?}"
        );
        let wait = (deadline - now).min(Duration::from_millis(250));
        match rx.recv_timeout(wait) {
            Ok(line) => {
                if let Some(addr) = parse_quic_listen_line(&line) {
                    return addr;
                }
                seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("receiver exited before QUIC readiness; stderr lines: {seen:?}");
            }
        }
    }
}

fn wait_for_tcp_listen_addr(rx: &mpsc::Receiver<String>) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    loop {
        let now = Instant::now();
        assert!(
            now < deadline,
            "receiver did not print TCP readiness; stderr lines: {seen:?}"
        );
        let wait = (deadline - now).min(Duration::from_millis(250));
        match rx.recv_timeout(wait) {
            Ok(line) => {
                if let Some(addr) = parse_tcp_listen_line(&line) {
                    return addr;
                }
                seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("receiver exited before TCP readiness; stderr lines: {seen:?}");
            }
        }
    }
}

fn wait_for_rq_listen_addr(rx: &mpsc::Receiver<String>) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    loop {
        let now = Instant::now();
        assert!(
            now < deadline,
            "receiver did not print RQ readiness; stderr lines: {seen:?}"
        );
        let wait = (deadline - now).min(Duration::from_millis(250));
        match rx.recv_timeout(wait) {
            Ok(line) => {
                if let Some(addr) = parse_rq_listen_line(&line) {
                    return addr;
                }
                seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("receiver exited before RQ readiness; stderr lines: {seen:?}");
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_for_bonded_listen_addr(rx: &mpsc::Receiver<String>) -> (SocketAddr, Vec<String>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    loop {
        let now = Instant::now();
        assert!(
            now < deadline,
            "receiver did not print bonded readiness; stderr lines: {seen:?}"
        );
        let wait = (deadline - now).min(Duration::from_millis(250));
        match rx.recv_timeout(wait) {
            Ok(line) => {
                if let Some(addr) = parse_bonded_listen_line(&line) {
                    seen.push(line);
                    return (addr, seen);
                }
                seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("receiver exited before bonded readiness; stderr lines: {seen:?}");
            }
        }
    }
}

#[cfg(feature = "atpd-daemon")]
fn wait_for_atpd_quic_and_diagnostics_addrs(
    rx: &mpsc::Receiver<String>,
) -> (SocketAddr, SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    let mut quic_addr = None;
    let mut diagnostics_addr = None;
    loop {
        if let (Some(quic), Some(diagnostics)) = (quic_addr, diagnostics_addr) {
            return (quic, diagnostics);
        }
        let now = Instant::now();
        assert!(
            now < deadline,
            "atpd did not report QUIC and diagnostics readiness; output lines: {seen:?}"
        );
        let wait = (deadline - now).min(Duration::from_millis(250));
        match rx.recv_timeout(wait) {
            Ok(line) => {
                if quic_addr.is_none() {
                    quic_addr = parse_tracing_bind_addr(
                        &line,
                        "ATP QUIC transfer listener bound and accepting",
                    );
                }
                if diagnostics_addr.is_none() {
                    diagnostics_addr =
                        parse_tracing_bind_addr(&line, "ATP daemon diagnostics endpoint started");
                }
                seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("atpd exited before readiness; output lines: {seen:?}");
            }
        }
    }
}

fn wait_with_deadline(mut child: Child, label: &str, deadline: Instant) -> Output {
    loop {
        match child.try_wait().expect("poll child status") {
            Some(_) => return child.wait_with_output().expect("collect child output"),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            None => {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .expect("collect killed child output");
                panic!(
                    "{label} did not exit within timeout; stdout: {}; stderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

fn wait_with_timeout(child: Child, label: &str) -> Output {
    wait_with_deadline(child, label, Instant::now() + Duration::from_secs(20))
}

fn wait_for_file(path: &Path, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("{label} did not appear at {}", path.display());
}

struct ChildKillGuard {
    child: Option<Child>,
}

impl ChildKillGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child guard has child")
    }

    fn into_inner(mut self) -> Child {
        self.child.take().expect("child guard has child")
    }

    fn kill_and_wait(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
    }
}

impl Drop for ChildKillGuard {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

#[cfg(windows)]
fn windows_payload(len: usize, multiplier: u32) -> Vec<u8> {
    (0..len)
        .map(|index| {
            (u32::try_from(index)
                .unwrap_or(u32::MAX)
                .wrapping_mul(multiplier)
                % 251) as u8
        })
        .collect()
}

fn parse_cli_json(output: &Output, label: &str) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{label} stdout was not one JSON report: {error}; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn staging_dirs(dest: &Path) -> Vec<PathBuf> {
    if !dest.is_dir() {
        return Vec::new();
    }
    std::fs::read_dir(dest)
        .unwrap_or_else(|error| panic!("read destination {}: {error}", dest.display()))
        .map(|entry| entry.expect("read destination entry"))
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with(".atp-staging-")
                || name.starts_with(".atp-rq-staging-")
                || name.starts_with(".atp-quic-staging-")
        })
        .map(|entry| entry.path())
        .collect()
}

#[cfg(target_os = "linux")]
fn run_linux_command(program: &str, args: &[&str], label: &str) -> Output {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run {label}: {error}"));
    assert!(
        output.status.success(),
        "{label} failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[cfg(target_os = "linux")]
struct LinuxNetnsGuard {
    namespace: String,
    host_veth: String,
}

#[cfg(target_os = "linux")]
impl Drop for LinuxNetnsGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "delete", &self.host_veth])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.namespace])
            .output();
    }
}

#[cfg(target_os = "linux")]
fn linux_interface_counter(interface: &str, counter: &str) -> u64 {
    let path = format!("/sys/class/net/{interface}/statistics/{counter}");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

#[cfg(target_os = "linux")]
fn linux_tc_dropped_packets(namespace: &str, interface: &str) -> u64 {
    let output = run_linux_command(
        "ip",
        &[
            "netns", "exec", namespace, "tc", "-s", "qdisc", "show", "dev", interface,
        ],
        "read netem counters",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split("dropped ")
        .skip(1)
        .filter_map(|suffix| {
            suffix
                .split(|character: char| !character.is_ascii_digit())
                .next()
                .and_then(|count| count.parse::<u64>().ok())
        })
        .sum()
}

#[cfg(windows)]
fn wait_for_staging_dir(dest: &Path, label: &str) -> PathBuf {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(path) = staging_dirs(dest).into_iter().next() {
            return path;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!(
        "{label} did not create a staging directory under {}",
        dest.display()
    );
}

#[cfg(windows)]
fn create_windows_junction(target: &Path, junction: &Path) {
    use std::os::windows::fs::MetadataExt;

    let output = Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(junction)
        .arg(target)
        .output()
        .expect("run cmd.exe mklink /J");
    assert!(
        output.status.success(),
        "mklink /J failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let metadata = std::fs::symlink_metadata(junction).unwrap_or_else(|error| {
        panic!(
            "junction was not created at {}: {error}",
            junction.display()
        )
    });
    assert_ne!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
        0,
        "mklink reported success but {} is not a reparse point",
        junction.display()
    );
}

#[cfg(windows)]
struct WindowsTestRoot {
    path: PathBuf,
}

#[cfg(windows)]
impl WindowsTestRoot {
    fn new(label: &str) -> Self {
        Self {
            path: unique_tmp(label),
        }
    }
}

#[cfg(windows)]
impl std::ops::Deref for WindowsTestRoot {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

#[cfg(windows)]
impl Drop for WindowsTestRoot {
    fn drop(&mut self) {
        if let Err(error) = remove_windows_test_tree(&self.path) {
            if std::thread::panicking() {
                eprintln!(
                    "could not remove Windows test root {} while unwinding: {error}",
                    self.path.display()
                );
            } else {
                panic!(
                    "could not remove Windows test root {}: {error}",
                    self.path.display()
                );
            }
        }
    }
}

#[cfg(windows)]
fn remove_windows_test_tree(path: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let attributes = metadata.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            std::fs::remove_dir(path)
        } else {
            std::fs::remove_file(path)
        };
    }

    let mut permissions = metadata.permissions();
    if permissions.readonly() {
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions)?;
    }
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            remove_windows_test_tree(&entry?.path())?;
        }
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    }
}

#[cfg(windows)]
const WINDOWS_TEST_MTIME_SECS: u64 = 1_700_000_123;

#[cfg(windows)]
struct WindowsMetadataFixture {
    metadata_payload: Vec<u8>,
    packed_readonly_payload: Vec<u8>,
    packed_peer_payload: Vec<u8>,
    hardlink_payload: Vec<u8>,
    file_target_payload: Vec<u8>,
    directory_target_payload: Vec<u8>,
    file_link_target: PathBuf,
    directory_link_target: PathBuf,
}

#[cfg(windows)]
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(windows)]
fn assert_file_bytes_and_hash(path: &Path, expected: &[u8], label: &str) {
    let actual = std::fs::read(path)
        .unwrap_or_else(|error| panic!("read {label} {}: {error}", path.display()));
    let actual_sha256 = sha256_hex(&actual);
    let expected_sha256 = sha256_hex(expected);
    assert_eq!(
        actual.len(),
        expected.len(),
        "{label} length at {}; actual SHA-256 {actual_sha256}, expected {expected_sha256}",
        path.display()
    );
    let first_mismatch = actual
        .iter()
        .zip(expected)
        .position(|(actual, expected)| actual != expected);
    assert!(
        first_mismatch.is_none(),
        "{label} bytes differ at offset {first_mismatch:?} for {}; actual SHA-256 {actual_sha256}, expected {expected_sha256}",
        path.display()
    );
    assert_eq!(
        actual_sha256,
        expected_sha256,
        "{label} SHA-256 at {}",
        path.display()
    );
}

#[cfg(windows)]
fn set_windows_readonly_hidden_and_mtime(path: &Path) {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
    };

    let modified = std::time::UNIX_EPOCH + Duration::from_secs(WINDOWS_TEST_MTIME_SECS);
    let mut options = std::fs::OpenOptions::new();
    let file = options
        .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap_or_else(|error| panic!("open metadata fixture {}: {error}", path.display()));
    file.set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap_or_else(|error| panic!("set metadata fixture mtime {}: {error}", path.display()));
    drop(file);

    let output = Command::new("attrib.exe")
        .args(["+R", "+H"])
        .arg(path)
        .output()
        .expect("run attrib.exe for Windows metadata fixture");
    assert!(
        output.status.success(),
        "attrib +R +H failed for {}; stdout: {}; stderr: {}",
        path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_windows_readonly_hidden_and_mtime(path);
}

#[cfg(windows)]
fn clear_windows_readonly(path: &Path) {
    let output = Command::new("attrib.exe")
        .arg("-R")
        .arg(path)
        .output()
        .expect("run attrib.exe to clear Windows readonly attribute");
    assert!(
        output.status.success(),
        "attrib -R failed for {}; stdout: {}; stderr: {}",
        path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(windows)]
fn assert_windows_readonly_hidden_and_mtime(path: &Path) {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;

    let metadata = std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("stat Windows metadata {}: {error}", path.display()));
    let attributes = metadata.file_attributes();
    assert_ne!(
        attributes & FILE_ATTRIBUTE_READONLY,
        0,
        "readonly attribute missing from {} (attributes {attributes:#010x})",
        path.display()
    );
    assert_ne!(
        attributes & FILE_ATTRIBUTE_HIDDEN,
        0,
        "hidden attribute missing from {} (attributes {attributes:#010x})",
        path.display()
    );
    let modified = metadata
        .modified()
        .expect("read Windows modified time")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Windows modified time after Unix epoch");
    assert_eq!(
        modified,
        Duration::from_secs(WINDOWS_TEST_MTIME_SECS),
        "mtime was not preserved for {}",
        path.display()
    );
}

#[cfg(windows)]
fn create_windows_metadata_fixture(source: &Path) -> WindowsMetadataFixture {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let mut fixture = WindowsMetadataFixture {
        metadata_payload: windows_payload(96 * 1024 + 13, 65_521),
        packed_readonly_payload: windows_payload(1021, 257),
        packed_peer_payload: windows_payload(2039, 509),
        hardlink_payload: windows_payload(64 * 1024 + 29, 32_771),
        file_target_payload: b"typed Windows file symlink target".to_vec(),
        directory_target_payload: b"typed Windows directory symlink target".to_vec(),
        file_link_target: PathBuf::new(),
        directory_link_target: PathBuf::new(),
    };

    let metadata_path = source.join("metadata/readonly-hidden.bin");
    write_file(&metadata_path, &fixture.metadata_payload);
    set_windows_readonly_hidden_and_mtime(&metadata_path);

    let packed_readonly = source.join("packed/readonly-small.bin");
    write_file(&packed_readonly, &fixture.packed_readonly_payload);
    set_windows_readonly_hidden_and_mtime(&packed_readonly);
    write_file(
        &source.join("packed/peer-small.bin"),
        &fixture.packed_peer_payload,
    );

    let hardlink_primary = source.join("links/hard-primary.bin");
    let hardlink_secondary = source.join("links/hard-secondary.bin");
    write_file(&hardlink_primary, &fixture.hardlink_payload);
    std::fs::hard_link(&hardlink_primary, &hardlink_secondary)
        .expect("create Windows source hardlink");
    set_windows_readonly_hidden_and_mtime(&hardlink_primary);

    write_file(
        &source.join("targets/file-target.txt"),
        &fixture.file_target_payload,
    );
    write_file(
        &source.join("targets/dir-target/inside.txt"),
        &fixture.directory_target_payload,
    );
    symlink_file(
        Path::new("targets/file-target.txt"),
        source.join("file-link"),
    )
    .expect("create typed Windows file symlink");
    symlink_dir(Path::new("targets/dir-target"), source.join("dir-link"))
        .expect("create typed Windows directory symlink");
    fixture.file_link_target =
        std::fs::read_link(source.join("file-link")).expect("read source file symlink target");
    fixture.directory_link_target =
        std::fs::read_link(source.join("dir-link")).expect("read source directory symlink target");
    // Apply directory metadata only after populating descendants. Receivers
    // must likewise replay it root-last so readonly/mtime fidelity cannot
    // interfere with child creation.
    set_windows_readonly_hidden_and_mtime(&source.join("metadata"));
    set_windows_readonly_hidden_and_mtime(source);
    fixture
}

#[cfg(windows)]
fn assert_windows_metadata_fixture(dest_root: &Path, fixture: &WindowsMetadataFixture) {
    use std::os::windows::fs::FileTypeExt;

    assert_windows_readonly_hidden_and_mtime(dest_root);
    assert_windows_readonly_hidden_and_mtime(&dest_root.join("metadata"));

    let metadata_path = dest_root.join("metadata/readonly-hidden.bin");
    assert_file_bytes_and_hash(
        &metadata_path,
        &fixture.metadata_payload,
        "Windows metadata payload",
    );
    assert_windows_readonly_hidden_and_mtime(&metadata_path);

    let packed_readonly = dest_root.join("packed/readonly-small.bin");
    assert_file_bytes_and_hash(
        &packed_readonly,
        &fixture.packed_readonly_payload,
        "received packed readonly member",
    );
    assert_windows_readonly_hidden_and_mtime(&packed_readonly);
    assert_file_bytes_and_hash(
        &dest_root.join("packed/peer-small.bin"),
        &fixture.packed_peer_payload,
        "received packed peer member",
    );

    let file_link = dest_root.join("file-link");
    let file_link_type = std::fs::symlink_metadata(&file_link)
        .expect("stat received file symlink")
        .file_type();
    assert!(
        file_link_type.is_symlink_file(),
        "{} was not recreated as a typed file symlink",
        file_link.display()
    );
    assert_eq!(
        std::fs::read_link(&file_link).expect("read received file symlink"),
        fixture.file_link_target.as_path()
    );
    assert_file_bytes_and_hash(
        &file_link,
        &fixture.file_target_payload,
        "received file symlink target",
    );

    let dir_link = dest_root.join("dir-link");
    let dir_link_type = std::fs::symlink_metadata(&dir_link)
        .expect("stat received directory symlink")
        .file_type();
    assert!(
        dir_link_type.is_symlink_dir(),
        "{} was not recreated as a typed directory symlink",
        dir_link.display()
    );
    assert_eq!(
        std::fs::read_link(&dir_link).expect("read received directory symlink"),
        fixture.directory_link_target.as_path()
    );
    assert_file_bytes_and_hash(
        &dir_link.join("inside.txt"),
        &fixture.directory_target_payload,
        "received directory symlink target",
    );

    let hardlink_primary = dest_root.join("links/hard-primary.bin");
    let hardlink_secondary = dest_root.join("links/hard-secondary.bin");
    assert_file_bytes_and_hash(
        &hardlink_primary,
        &fixture.hardlink_payload,
        "received hardlink primary",
    );
    assert_file_bytes_and_hash(
        &hardlink_secondary,
        &fixture.hardlink_payload,
        "received hardlink secondary",
    );
    assert_windows_readonly_hidden_and_mtime(&hardlink_primary);
    assert_windows_readonly_hidden_and_mtime(&hardlink_secondary);
    let replacement = b"mutation through received Windows hardlink";
    clear_windows_readonly(&hardlink_primary);
    std::fs::write(&hardlink_primary, replacement).expect("mutate received hardlink primary");
    assert_file_bytes_and_hash(
        &hardlink_secondary,
        replacement,
        "received hardlink identity",
    );
    set_windows_readonly_hidden_and_mtime(&hardlink_primary);
    assert_windows_readonly_hidden_and_mtime(&hardlink_secondary);
}

#[cfg(windows)]
fn run_windows_tcp_transfer(source: &Path, dest: &Path, no_delta: bool) -> (Output, Output) {
    std::fs::create_dir_all(dest).expect("create Windows TCP destination");
    let mut receiver_command = Command::new(env!("CARGO_BIN_EXE_atp"));
    receiver_command.arg("recv").arg(dest).args([
        "--listen",
        "127.0.0.1:0",
        "--transport",
        "tcp",
        "--once",
    ]);
    if no_delta {
        receiver_command.arg("--no-delta");
    }
    let receiver = receiver_command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows TCP receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_tcp_listen_addr(&receiver_stderr);

    let mut sender_command = Command::new(env!("CARGO_BIN_EXE_atp"));
    sender_command
        .arg("send")
        .arg(source)
        .arg(listen_addr.to_string())
        .args(["--transport", "tcp"]);
    if no_delta {
        sender_command.arg("--no-delta");
    }
    let sender = sender_command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows TCP sender");
    let sender = wait_with_timeout(sender, "Windows TCP sender");
    if !sender.status.success() {
        receiver.kill_and_wait();
        panic!(
            "Windows TCP sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }
    let receiver = wait_with_timeout(receiver.into_inner(), "Windows TCP receiver");
    assert!(
        receiver.status.success(),
        "Windows TCP receiver failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    (sender, receiver)
}

#[cfg(windows)]
fn run_windows_quic_transfer(
    source: &Path,
    dest: &Path,
    cert: &Path,
    key: &Path,
    ca: &Path,
) -> (Output, Output) {
    std::fs::create_dir_all(dest).expect("create Windows QUIC destination");
    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("recv")
        .arg(dest)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "quic",
            "--once",
            "--no-delta",
            "--server-cert",
        ])
        .arg(cert)
        .arg("--server-key")
        .arg(key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows QUIC receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_quic_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("send")
        .arg(source)
        .arg(listen_addr.to_string())
        .args(["--transport", "quic", "--no-delta", "--ca"])
        .arg(ca)
        .args(["--server-name", "localhost"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows QUIC sender");
    let sender = wait_with_timeout(sender, "Windows QUIC sender");
    if !sender.status.success() {
        receiver.kill_and_wait();
        panic!(
            "Windows QUIC sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }
    let receiver = wait_with_timeout(receiver.into_inner(), "Windows QUIC receiver");
    assert!(
        receiver.status.success(),
        "Windows QUIC receiver failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    (sender, receiver)
}

#[cfg(windows)]
fn run_windows_rq_metadata_transfer(source: &Path, dest: &Path) -> (Output, Output) {
    std::fs::create_dir_all(dest).expect("create Windows RQ metadata destination");
    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("recv")
        .arg(dest)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "rq",
            "--once",
            "--no-delta",
            "--repair-overhead",
            "1.05",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows RQ metadata receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_rq_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("send")
        .arg(source)
        .arg(listen_addr.to_string())
        .args([
            "--transport",
            "rq",
            "--no-delta",
            "--streams",
            "1",
            "--repair-overhead",
            "1.05",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows RQ metadata sender");
    let sender = wait_with_timeout(sender, "Windows RQ metadata sender");
    if !sender.status.success() {
        receiver.kill_and_wait();
        panic!(
            "Windows RQ metadata sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }

    let receiver = wait_with_timeout(receiver.into_inner(), "Windows RQ metadata receiver");
    assert!(
        receiver.status.success(),
        "Windows RQ metadata receiver failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    (sender, receiver)
}

#[cfg(feature = "atpd-daemon")]
fn fetch_diagnostics_json(addr: SocketAddr) -> serde_json::Value {
    let mut stream = TcpStream::connect(addr).expect("connect diagnostics endpoint");
    stream
        .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .expect("write diagnostics request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read diagnostics response");
    let (_, body) = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| response.split_at(idx + 4))
        .expect("diagnostics response has headers");
    serde_json::from_slice(body).expect("diagnostics body is json")
}

#[test]
fn atp_tcp_and_rq_send_resolve_localhost_against_ipv4_listener() {
    for transport in ["tcp", "rq"] {
        let root = unique_tmp(&format!("localhost-{transport}"));
        let source = root.join("source/payload.bin");
        let dest = root.join("dest");
        let payload = (0..128 * 1024u32)
            .map(|index| (index.wrapping_mul(31) % 251) as u8)
            .collect::<Vec<_>>();
        write_file(&source, &payload);
        std::fs::create_dir_all(&dest).expect("create localhost destination");

        let mut receiver_command = Command::new(env!("CARGO_BIN_EXE_atp"));
        receiver_command.arg("recv").arg(&dest).args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            transport,
            "--once",
            "--no-delta",
        ]);
        if transport == "rq" {
            receiver_command.args(["--rq-auth-key-hex", VALID_KEY_HEX]);
        }
        let receiver = receiver_command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {transport} receiver: {error}"));
        let mut receiver = ChildKillGuard::new(receiver);
        let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
        let listen_addr = if transport == "tcp" {
            wait_for_tcp_listen_addr(&receiver_stderr)
        } else {
            wait_for_rq_listen_addr(&receiver_stderr)
        };

        let mut sender_command = Command::new(env!("CARGO_BIN_EXE_atp"));
        sender_command
            .arg("send")
            .arg(&source)
            .arg(format!("localhost:{}", listen_addr.port()))
            .args(["--transport", transport, "--no-delta"]);
        if transport == "rq" {
            sender_command.args(["--streams", "1", "--rq-auth-key-hex", VALID_KEY_HEX]);
        }
        let sender = wait_with_timeout(
            sender_command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("spawn {transport} sender: {error}")),
            &format!("{transport} localhost sender"),
        );
        if !sender.status.success() {
            receiver.kill_and_wait();
            panic!(
                "{transport} localhost sender failed; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&sender.stdout),
                String::from_utf8_lossy(&sender.stderr)
            );
        }
        let receiver = wait_with_timeout(
            receiver.into_inner(),
            &format!("{transport} localhost receiver"),
        );
        assert!(
            receiver.status.success(),
            "{transport} localhost receiver failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&receiver.stdout),
            String::from_utf8_lossy(&receiver.stderr)
        );
        let sender_report = parse_cli_json(&sender, &format!("{transport} localhost sender"));
        assert_eq!(sender_report["transport"], serde_json::json!(transport));
        assert_eq!(sender_report["committed"], serde_json::json!(true));
        assert_eq!(
            std::fs::read(dest.join("payload.bin")).expect("read localhost payload"),
            payload
        );
        assert!(staging_dirs(&dest).is_empty());
    }
}

#[test]
fn atp_quic_persistent_serve_rejects_port_zero_before_side_effects() {
    let root = unique_tmp("persistent-port-zero");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    let dest = root.join("dest-must-not-exist");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());

    let output = wait_with_timeout(
        Command::new(env!("CARGO_BIN_EXE_atp"))
            .arg("serve")
            .arg(&dest)
            .args([
                "--listen",
                "127.0.0.1:0",
                "--transport",
                "quic",
                "--no-delta",
                "--server-cert",
            ])
            .arg(&cert)
            .arg("--server-key")
            .arg(&key)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn persistent QUIC port-zero receiver"),
        "persistent QUIC port-zero receiver",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires a fixed non-zero --listen port"));
    assert!(!stderr.contains("listening on"));
    assert!(!dest.exists(), "port-zero rejection created destination");
}

#[test]
fn atp_quic_persistent_serve_does_not_report_readiness_when_bind_fails() {
    let root = unique_tmp("persistent-bind-failure");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    let dest = root.join("dest-must-not-exist");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve UDP port");
    let occupied_addr = occupied.local_addr().expect("reserved UDP address");

    let output = wait_with_timeout(
        Command::new(env!("CARGO_BIN_EXE_atp"))
            .arg("serve")
            .arg(&dest)
            .arg("--listen")
            .arg(occupied_addr.to_string())
            .args(["--transport", "quic", "--no-delta", "--server-cert"])
            .arg(&cert)
            .arg("--server-key")
            .arg(&key)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn persistent QUIC receiver on occupied port"),
        "persistent QUIC occupied-port receiver",
    );
    drop(occupied);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("listening on"),
        "false readiness: {stderr}"
    );
    assert!(!dest.exists(), "bind failure created destination");
}

#[test]
fn atp_quic_persistent_serve_reuses_one_fixed_port_for_two_localhost_transfers() {
    let root = unique_tmp("persistent-two-transfers");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    let ca = root.join("tls/ca.pem");
    let dest = root.join("dest");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());
    write_file(&ca, CA_CERT_PEM.as_bytes());

    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve QUIC port");
    let listen = reservation.local_addr().expect("reserved QUIC address");
    drop(reservation);
    let server = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("serve")
        .arg(&dest)
        .arg("--listen")
        .arg(listen.to_string())
        .args(["--transport", "quic", "--no-delta", "--server-cert"])
        .arg(&cert)
        .arg("--server-key")
        .arg(&key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn persistent QUIC server");
    let mut server = ChildKillGuard::new(server);
    let server_stderr = spawn_stderr_reader(server.child_mut());
    let reported = wait_for_quic_listen_addr(&server_stderr);
    assert_eq!(reported, listen);

    for (name, multiplier) in [("first.bin", 17u32), ("second.bin", 43u32)] {
        let source = root.join("source").join(name);
        let payload = (0..96 * 1024u32)
            .map(|index| (index.wrapping_mul(multiplier) % 251) as u8)
            .collect::<Vec<_>>();
        write_file(&source, &payload);
        let sender = wait_with_timeout(
            Command::new(env!("CARGO_BIN_EXE_atp"))
                .arg("send")
                .arg(&source)
                .arg(format!("localhost:{}", listen.port()))
                .args([
                    "--transport",
                    "quic",
                    "--no-delta",
                    "--quic-handshake-timeout-ms",
                    "1000",
                    "--ca",
                ])
                .arg(&ca)
                .args(["--server-name", "localhost"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("spawn persistent sender for {name}: {error}")),
            &format!("persistent QUIC sender for {name}"),
        );
        assert!(
            sender.status.success(),
            "persistent QUIC sender for {name} failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
        let report = parse_cli_json(&sender, &format!("persistent QUIC sender for {name}"));
        assert_eq!(report["committed"], serde_json::json!(true));
        assert_eq!(
            std::fs::read(dest.join(name)).expect("read persistent QUIC payload"),
            payload
        );
        assert!(
            server
                .child_mut()
                .try_wait()
                .expect("poll persistent QUIC server")
                .is_none(),
            "persistent QUIC server exited after {name}"
        );
    }
    assert!(staging_dirs(&dest).is_empty());
    server.kill_and_wait();
}

#[test]
fn atp_send_auto_does_not_downgrade_after_quic_certificate_failure() {
    let root = unique_tmp("auto-cert-no-downgrade");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    let source = root.join("source/payload.bin");
    let dest = root.join("dest");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());
    write_file(&source, b"certificate failures must not downgrade");
    std::fs::create_dir_all(&dest).expect("create auto certificate destination");

    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("recv")
        .arg(&dest)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "quic",
            "--once",
            "--no-delta",
            "--server-cert",
        ])
        .arg(&cert)
        .arg("--server-key")
        .arg(&key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn private-CA QUIC receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_quic_listen_addr(&receiver_stderr);

    let sender = wait_with_timeout(
        Command::new(env!("CARGO_BIN_EXE_atp"))
            .arg("send")
            .arg(&source)
            .arg(format!("localhost:{}", listen_addr.port()))
            .args([
                "--transport",
                "auto",
                "--no-delta",
                "--allow-plaintext-fallback",
                "--quic-handshake-timeout-ms",
                "1000",
                "--server-name",
                "localhost",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn auto sender with untrusted QUIC receiver"),
        "auto sender certificate failure",
    );
    receiver.kill_and_wait();
    assert!(!sender.status.success());
    let diagnostics = format!(
        "{}\n{}",
        String::from_utf8_lossy(&sender.stdout),
        String::from_utf8_lossy(&sender.stderr)
    )
    .to_ascii_lowercase();
    assert!(
        diagnostics.contains("certificate")
            || diagnostics.contains("issuer")
            || diagnostics.contains("read_hs_fatal_alert")
            || diagnostics.contains("quic handshake: crypto provider failure"),
        "TLS certificate failure was not explicit: {diagnostics}"
    );
    assert!(
        !diagnostics.contains("transport selection: trying tcp"),
        "certificate failure triggered plaintext downgrade: {diagnostics}"
    );
    assert!(!dest.join("payload.bin").exists());
    assert!(staging_dirs(&dest).is_empty());
}

#[test]
fn atp_send_recv_quic_loopback_moves_file_bytes() {
    let root = unique_tmp("loopback");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    let ca = root.join("tls/ca.pem");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());
    write_file(&ca, CA_CERT_PEM.as_bytes());

    let source_dir = root.join("source");
    let dest_dir = root.join("dest");
    let payload_path = source_dir.join("payload.bin");
    let payload = (0..8192u32)
        .map(|i| (i.wrapping_mul(17) % 251) as u8)
        .collect::<Vec<_>>();
    write_file(&payload_path, &payload);
    std::fs::create_dir_all(&dest_dir).expect("create dest dir");
    write_file(&dest_dir.join("payload.bin"), b"stale destination bytes");

    let mut receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .args([
            "recv",
            dest_dir.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "quic",
            "--once",
            "--server-cert",
            cert.to_str().unwrap(),
            "--server-key",
            key.to_str().unwrap(),
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn atp quic receiver");
    let receiver_stderr = spawn_stderr_reader(&mut receiver);
    let listen_addr = wait_for_quic_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .args([
            "send",
            payload_path.to_str().unwrap(),
            &listen_addr.to_string(),
            "--transport",
            "quic",
            "--ca",
            ca.to_str().unwrap(),
            "--server-name",
            "localhost",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .output()
        .expect("run atp quic sender");
    if !sender.status.success() {
        let _ = receiver.kill();
        let _ = receiver.wait();
        panic!(
            "atp quic sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }

    let receiver = wait_with_timeout(receiver, "atp quic receiver");
    assert!(
        receiver.status.success(),
        "atp quic receiver failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );

    let sender_stdout = String::from_utf8_lossy(&sender.stdout);
    let receiver_stdout = String::from_utf8_lossy(&receiver.stdout);
    assert!(
        sender_stdout.contains("\"event\":\"atp_send\"")
            && sender_stdout.contains("\"transport\":\"quic\"")
            && sender_stdout.contains("\"committed\":true")
            && sender_stdout.contains("\"bytes_sent\":8192"),
        "sender stdout: {sender_stdout}"
    );
    assert!(
        receiver_stdout.contains("\"event\":\"atp_receive\"")
            && receiver_stdout.contains("\"transport\":\"quic\"")
            && receiver_stdout.contains("\"committed\":true")
            && receiver_stdout.contains("\"bytes_received\":8192"),
        "receiver stdout: {receiver_stdout}"
    );
    assert_eq!(
        std::fs::read(dest_dir.join("payload.bin")).expect("read received payload"),
        payload
    );
}

#[test]
fn atp_send_recv_quic_loopback_accepts_explicit_self_signed_leaf_pin() {
    let root = unique_tmp("self-signed-leaf-pin");
    let cert = root.join("tls/self-signed.pem");
    let key = root.join("tls/self-signed.key");
    write_file(&cert, SELF_SIGNED_CA_TRUE_CERT_PEM.as_bytes());
    write_file(&key, SELF_SIGNED_CA_TRUE_KEY_PEM.as_bytes());

    let source_dir = root.join("source");
    let dest_dir = root.join("dest");
    let payload_path = source_dir.join("payload.bin");
    let payload = (0..4096u32)
        .map(|i| (i.wrapping_mul(29) % 251) as u8)
        .collect::<Vec<_>>();
    write_file(&payload_path, &payload);
    std::fs::create_dir_all(&dest_dir).expect("create dest dir");

    let mut receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .args([
            "recv",
            dest_dir.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "quic",
            "--once",
            "--symbol-size",
            "1144",
            "--rq-allow-unauthenticated-lab",
            "--server-cert",
            cert.to_str().unwrap(),
            "--server-key",
            key.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn atp quic receiver");
    let receiver_stderr = spawn_stderr_reader(&mut receiver);
    let listen_addr = wait_for_quic_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .args([
            "send",
            payload_path.to_str().unwrap(),
            &listen_addr.to_string(),
            "--transport",
            "quic",
            "--symbol-size",
            "1144",
            "--rq-allow-unauthenticated-lab",
            "--ca",
            cert.to_str().unwrap(),
            "--server-name",
            "127.0.0.1",
        ])
        .output()
        .expect("run atp quic sender");
    if !sender.status.success() {
        let _ = receiver.kill();
        let _ = receiver.wait();
        panic!(
            "atp quic sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }

    let receiver = wait_with_timeout(receiver, "atp quic receiver");
    assert!(
        receiver.status.success(),
        "atp quic receiver failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert_eq!(
        std::fs::read(dest_dir.join("payload.bin")).expect("read received payload"),
        payload
    );
}

#[test]
fn atp_send_auto_falls_back_to_tcp_after_quic_and_rq_fail() {
    let root = unique_tmp("auto-fallback-tcp");
    let source_dir = root.join("source");
    let dest_dir = root.join("dest");
    let payload_path = source_dir.join("payload.bin");
    let payload = (0..4096u32)
        .map(|i| (i.wrapping_mul(31) % 251) as u8)
        .collect::<Vec<_>>();
    write_file(&payload_path, &payload);
    std::fs::create_dir_all(&dest_dir).expect("create dest dir");
    write_file(&dest_dir.join("payload.bin"), b"stale destination bytes");

    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .args([
            "recv",
            dest_dir.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "tcp",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn persistent atp tcp receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_tcp_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .args([
            "send",
            payload_path.to_str().unwrap(),
            &listen_addr.to_string(),
            "--transport",
            "auto",
            "--no-delta",
            "--allow-plaintext-fallback",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
            "--quic-handshake-timeout-ms",
            "100",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn atp auto sender");
    let sender = wait_with_timeout(sender, "atp auto sender");
    if !sender.status.success() {
        receiver.kill_and_wait();
        panic!(
            "atp auto sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }

    wait_for_file(&dest_dir.join("payload.bin"), "auto fallback TCP payload");
    assert_eq!(
        std::fs::read(dest_dir.join("payload.bin")).expect("read received payload"),
        payload
    );

    let sender_report: serde_json::Value =
        serde_json::from_slice(&sender.stdout).expect("sender stdout json");
    assert_eq!(sender_report["event"], serde_json::json!("atp_send"));
    assert_eq!(sender_report["transport"], serde_json::json!("tcp"));
    assert_eq!(
        sender_report["requested_transport"],
        serde_json::json!("auto")
    );
    assert_eq!(
        sender_report["selected_transport"],
        serde_json::json!("tcp")
    );
    assert_eq!(sender_report["committed"], serde_json::json!(true));
    assert_eq!(sender_report["bytes_sent"], serde_json::json!(4096));

    let attempts = sender_report["transport_attempts"]
        .as_array()
        .expect("transport attempts array");
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0]["transport"], serde_json::json!("quic"));
    assert_eq!(attempts[0]["status"], serde_json::json!("failed"));
    assert_eq!(attempts[1]["transport"], serde_json::json!("rq"));
    assert_eq!(attempts[1]["status"], serde_json::json!("failed"));
    assert_eq!(attempts[2]["transport"], serde_json::json!("tcp"));
    assert_eq!(attempts[2]["status"], serde_json::json!("selected"));

    let sender_stderr = String::from_utf8_lossy(&sender.stderr);
    assert!(sender_stderr.contains("transport selection: trying quic"));
    assert!(sender_stderr.contains("transport selection: quic unavailable"));
    assert!(sender_stderr.contains("transport selection: trying rq"));
    assert!(sender_stderr.contains("transport selection: rq unavailable"));
    assert!(sender_stderr.contains("transport selection: selected tcp"));

    receiver.kill_and_wait();
}

#[test]
fn atp_send_auto_falls_back_to_rq_after_quic_fails() {
    let root = unique_tmp("auto-fallback-rq");
    let source_dir = root.join("source");
    let dest_dir = root.join("dest");
    let payload_path = source_dir.join("payload.bin");
    let payload = (0..4096u32)
        .map(|i| (i.wrapping_mul(43) % 251) as u8)
        .collect::<Vec<_>>();
    write_file(&payload_path, &payload);
    std::fs::create_dir_all(&dest_dir).expect("create dest dir");

    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .args([
            "recv",
            dest_dir.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "rq",
            "--once",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn one-shot atp rq receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_rq_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .args([
            "send",
            payload_path.to_str().unwrap(),
            &listen_addr.to_string(),
            "--transport",
            "auto",
            "--no-delta",
            "--allow-plaintext-fallback",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
            "--quic-handshake-timeout-ms",
            "100",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn atp auto sender");
    let sender = wait_with_timeout(sender, "atp auto sender");
    if !sender.status.success() {
        receiver.kill_and_wait();
        panic!(
            "atp auto sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }

    let receiver = wait_with_timeout(receiver.into_inner(), "atp rq receiver");
    assert!(
        receiver.status.success(),
        "atp rq receiver failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert_eq!(
        std::fs::read(dest_dir.join("payload.bin")).expect("read received payload"),
        payload
    );

    let sender_report: serde_json::Value =
        serde_json::from_slice(&sender.stdout).expect("sender stdout json");
    assert_eq!(sender_report["event"], serde_json::json!("atp_send"));
    assert_eq!(sender_report["transport"], serde_json::json!("rq"));
    assert_eq!(
        sender_report["requested_transport"],
        serde_json::json!("auto")
    );
    assert_eq!(sender_report["selected_transport"], serde_json::json!("rq"));
    assert_eq!(sender_report["committed"], serde_json::json!(true));
    assert_eq!(sender_report["bytes_sent"], serde_json::json!(4096));

    let attempts = sender_report["transport_attempts"]
        .as_array()
        .expect("transport attempts array");
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0]["transport"], serde_json::json!("quic"));
    assert_eq!(attempts[0]["status"], serde_json::json!("failed"));
    assert_eq!(attempts[1]["transport"], serde_json::json!("rq"));
    assert_eq!(attempts[1]["status"], serde_json::json!("selected"));

    let sender_stderr = String::from_utf8_lossy(&sender.stderr);
    assert!(sender_stderr.contains("transport selection: trying quic"));
    assert!(sender_stderr.contains("transport selection: quic unavailable"));
    assert!(sender_stderr.contains("transport selection: trying rq"));
    assert!(sender_stderr.contains("transport selection: selected rq"));
}

/// D1 direct-IP acceptance: exercise the real `atp` binary across a Linux
/// veth boundary, not loopback. The receiver deliberately advertises both its
/// reachable veth IP and a planted unreachable decoy. The donor must retain
/// only the control-affine IP (with all of that IP's UDP fanout ports), move
/// real packets across the namespace boundary, and commit exact bytes.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root plus iproute2 network-namespace and veth support"]
fn bond_direct_ip_netns_selects_reachable_advertised_endpoint() {
    let uid = run_linux_command("id", &["-u"], "query effective uid");
    assert_eq!(
        String::from_utf8_lossy(&uid.stdout).trim(),
        "0",
        "explicit D1 netns acceptance requires root/CAP_NET_ADMIN"
    );
    let _ = run_linux_command("ip", &["-Version"], "query iproute2 version");

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos() as u64;
    let pid = std::process::id();
    let slot = (nanos ^ u64::from(pid)) % (2 * 256 * 64);
    let second_octet = 18 + slot / (256 * 64);
    let remainder = slot % (256 * 64);
    let third_octet = remainder / 64;
    let fourth_octet = (remainder % 64) * 4;
    let host_ip = format!("198.{second_octet}.{third_octet}.{}", fourth_octet + 1);
    let donor_ip = format!("198.{second_octet}.{third_octet}.{}", fourth_octet + 2);
    let decoy_ip = "192.0.2.99";
    let suffix = format!("{:04x}{:02x}", pid % 65_536, nanos % 256);
    let namespace = format!("atpd1-{suffix}");
    let host_veth = format!("ad1h{suffix}");
    let donor_veth = format!("ad1d{suffix}");
    let _netns_guard = LinuxNetnsGuard {
        namespace: namespace.clone(),
        host_veth: host_veth.clone(),
    };

    run_linux_command("ip", &["netns", "add", &namespace], "create D1 namespace");
    run_linux_command(
        "ip",
        &[
            "link",
            "add",
            &host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &donor_veth,
        ],
        "create D1 veth pair",
    );
    run_linux_command(
        "ip",
        &["link", "set", &donor_veth, "netns", &namespace],
        "move donor veth into namespace",
    );
    let host_cidr = format!("{host_ip}/30");
    let donor_cidr = format!("{donor_ip}/30");
    run_linux_command(
        "ip",
        &["addr", "add", &host_cidr, "dev", &host_veth],
        "address receiver veth",
    );
    run_linux_command(
        "ip",
        &["link", "set", "dev", &host_veth, "up"],
        "bring receiver veth up",
    );
    run_linux_command(
        "ip",
        &[
            "-n",
            &namespace,
            "addr",
            "add",
            &donor_cidr,
            "dev",
            &donor_veth,
        ],
        "address donor veth",
    );
    run_linux_command(
        "ip",
        &["-n", &namespace, "link", "set", "lo", "up"],
        "bring donor loopback up",
    );
    run_linux_command(
        "ip",
        &["-n", &namespace, "link", "set", "dev", &donor_veth, "up"],
        "bring donor veth up",
    );
    let decoy_cidr = format!("{decoy_ip}/32");
    run_linux_command(
        "ip",
        &["-n", &namespace, "route", "add", "unreachable", &decoy_cidr],
        "plant unreachable advertised route",
    );

    let root = unique_tmp("bond-direct-ip-netns");
    let receiver_source = root.join("receiver-source/payload.bin");
    let donor_source = root.join("donor-source/payload.bin");
    let dest = root.join("dest");
    let payload = (0..(64 * 1024 + 173u32))
        .map(|index| (index.wrapping_mul(67) % 251) as u8)
        .collect::<Vec<_>>();
    write_file(&receiver_source, &payload);
    write_file(&donor_source, &payload);
    std::fs::create_dir_all(&dest).expect("create bonded destination");

    let listen = format!("{host_ip}:0");
    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .env("ATP_BOND_TRACE", "1")
        .arg("bond-recv")
        .arg(&dest)
        .arg(&receiver_source)
        .args([
            "--listen",
            &listen,
            "--expect-donors",
            "1",
            "--udp-bind",
            "0.0.0.0",
            "--udp-advertise",
            decoy_ip,
            "--udp-advertise",
            &host_ip,
            "--workers",
            "2",
            "--max-block-size",
            "65536",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn direct-IP bonded receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let (listen_addr, mut receiver_lines) = wait_for_bonded_listen_addr(&receiver_stderr);
    assert_eq!(
        listen_addr.ip().to_string(),
        host_ip,
        "receiver must report the concrete veth control address"
    );

    let packets_before = linux_interface_counter(&host_veth, "rx_packets");
    let donor = Command::new("ip")
        .args(["netns", "exec", &namespace, "env", "ATP_BOND_TRACE=1"])
        .arg(env!("CARGO_BIN_EXE_atp"))
        .arg("bond-donate")
        .arg(&donor_source)
        .args([
            "--to",
            &listen_addr.to_string(),
            "--workers",
            "2",
            "--max-block-size",
            "65536",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn namespaced direct-IP bonded donor");
    let donor = wait_with_timeout(donor, "namespaced direct-IP bonded donor");
    if !donor.status.success() {
        receiver.kill_and_wait();
        panic!(
            "namespaced direct-IP bonded donor failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&donor.stdout),
            String::from_utf8_lossy(&donor.stderr)
        );
    }

    let receiver = wait_with_timeout(receiver.into_inner(), "direct-IP bonded receiver");
    receiver_lines.extend(receiver_stderr.into_iter());
    assert!(
        receiver.status.success(),
        "direct-IP bonded receiver failed; stdout: {}; trace lines: {:?}",
        String::from_utf8_lossy(&receiver.stdout),
        receiver_lines
    );

    let donor_report = parse_cli_json(&donor, "namespaced direct-IP bonded donor");
    let receiver_report = parse_cli_json(&receiver, "direct-IP bonded receiver");
    assert_eq!(donor_report["committed"], serde_json::json!(true));
    assert_eq!(receiver_report["committed"], serde_json::json!(true));
    assert_eq!(receiver_report["enrolled_donors"], serde_json::json!(1));
    assert!(
        receiver_report["donor_ingress"][0]["symbols_accepted"]
            .as_u64()
            .is_some_and(|accepted| accepted > 0),
        "receiver must report positive ingress from the namespaced donor: {receiver_report}"
    );

    let selected_endpoints = donor_report["receiver_endpoints"]
        .as_array()
        .expect("donor receiver_endpoints array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("receiver endpoint string")
                .parse::<SocketAddr>()
                .expect("receiver endpoint socket address")
        })
        .collect::<Vec<_>>();
    let expected_ip: std::net::IpAddr = host_ip.parse().expect("receiver veth IP");
    assert!(
        !selected_endpoints.is_empty(),
        "donor must report its selected UDP fanout endpoints"
    );
    assert!(
        selected_endpoints
            .iter()
            .all(|endpoint| endpoint.ip() == expected_ip),
        "donor selected endpoints must stay on the control-affine veth IP: {selected_endpoints:?}"
    );
    assert!(
        selected_endpoints
            .iter()
            .all(|endpoint| endpoint.ip().to_string() != decoy_ip),
        "planted unreachable decoy must never become a spray endpoint: {selected_endpoints:?}"
    );

    let donor_trace = String::from_utf8_lossy(&donor.stderr);
    assert!(
        donor_trace.contains("endpoint_path_selected")
            && donor_trace.contains("reason=control-path-affinity")
            && donor_trace.contains(&host_ip)
            && donor_trace.contains(decoy_ip),
        "donor trace must record advertised and selected path sets: {donor_trace}"
    );
    let admission_line = receiver_lines
        .iter()
        .find(|line| line.contains("receiver: donor_admitted "))
        .unwrap_or_else(|| panic!("receiver admission trace missing: {receiver_lines:?}"));
    let admission_json = admission_line
        .split_once("receiver: donor_admitted ")
        .expect("receiver admission trace marker")
        .1;
    let admission: serde_json::Value =
        serde_json::from_str(admission_json).expect("receiver admission trace JSON");
    let advertised_endpoints = admission["receiver_udp_endpoints"]
        .as_array()
        .expect("admission receiver_udp_endpoints array");
    assert!(
        advertised_endpoints.iter().any(|endpoint| endpoint
            .as_str()
            .is_some_and(|value| value.starts_with(&host_ip))),
        "receiver admission must advertise its reachable veth IP: {admission}"
    );
    assert!(
        advertised_endpoints.iter().any(|endpoint| {
            endpoint
                .as_str()
                .is_some_and(|value| value.starts_with(decoy_ip))
        }),
        "receiver admission must carry the planted decoy so donor filtering is causal: {admission}"
    );

    let packets_after = linux_interface_counter(&host_veth, "rx_packets");
    assert!(
        packets_after > packets_before,
        "real control/UDP traffic must cross the receiver veth: before={packets_before}, after={packets_after}"
    );
    assert_eq!(
        std::fs::read(dest.join("payload.bin")).expect("read committed direct-IP payload"),
        payload
    );
    assert!(
        staging_dirs(&dest).is_empty(),
        "successful direct-IP bonded transfer left staging directories: {:?}",
        staging_dirs(&dest)
    );
}

/// H2 acceptance: three independent donor namespaces feed one receiver across
/// three veth pairs. Every donor leg has real kernel `netem` loss and delay,
/// while the receiver advertises all three routed addresses. A successful run
/// therefore proves that endpoint affinity, N-donor enrollment, loss recovery,
/// and the atomic commit path compose across real sockets rather than only in
/// the in-process loopback model.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root plus iproute2 network-namespace, veth, and netem support"]
fn bond_three_donor_netns_commits_under_per_donor_loss() {
    let uid = run_linux_command("id", &["-u"], "query effective uid");
    assert_eq!(
        String::from_utf8_lossy(&uid.stdout).trim(),
        "0",
        "explicit H2 netns acceptance requires root/CAP_NET_ADMIN"
    );
    let _ = run_linux_command("ip", &["-Version"], "query iproute2 version");
    let _ = run_linux_command("tc", &["-Version"], "query tc version");

    struct Leg {
        namespace: String,
        host_veth: String,
        donor_veth: String,
        host_ip: String,
        donor_ip: String,
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos() as u64;
    let pid = std::process::id();
    let slot = (nanos ^ u64::from(pid)) % (2 * 256 * 16);
    let second_octet = 18 + slot / (256 * 16);
    let remainder = slot % (256 * 16);
    let third_octet = remainder / 16;
    let fourth_octet = (remainder % 16) * 16;
    let suffix = format!("{:04x}{:02x}", pid % 65_536, nanos % 256);

    let mut legs = Vec::new();
    let mut netns_guards = Vec::new();
    let loss_rates = ["5%", "7%", "9%"];
    let delays = ["2ms", "3ms", "4ms"];
    for index in 0..3u64 {
        let namespace = format!("atph2{index}-{suffix}");
        let host_veth = format!("ah2h{index}{suffix}");
        let donor_veth = format!("ah2d{index}{suffix}");
        let subnet_base = fourth_octet + index * 4;
        let host_ip = format!("198.{second_octet}.{third_octet}.{}", subnet_base + 1);
        let donor_ip = format!("198.{second_octet}.{third_octet}.{}", subnet_base + 2);

        run_linux_command(
            "ip",
            &["netns", "add", &namespace],
            "create H2 donor namespace",
        );
        netns_guards.push(LinuxNetnsGuard {
            namespace: namespace.clone(),
            host_veth: host_veth.clone(),
        });
        run_linux_command(
            "ip",
            &[
                "link",
                "add",
                &host_veth,
                "type",
                "veth",
                "peer",
                "name",
                &donor_veth,
            ],
            "create H2 veth pair",
        );
        run_linux_command(
            "ip",
            &["link", "set", &donor_veth, "netns", &namespace],
            "move H2 donor veth into namespace",
        );
        let host_cidr = format!("{host_ip}/30");
        let donor_cidr = format!("{donor_ip}/30");
        run_linux_command(
            "ip",
            &["addr", "add", &host_cidr, "dev", &host_veth],
            "address H2 receiver veth",
        );
        run_linux_command(
            "ip",
            &["link", "set", "dev", &host_veth, "up"],
            "bring H2 receiver veth up",
        );
        run_linux_command(
            "ip",
            &[
                "-n",
                &namespace,
                "addr",
                "add",
                &donor_cidr,
                "dev",
                &donor_veth,
            ],
            "address H2 donor veth",
        );
        run_linux_command(
            "ip",
            &["-n", &namespace, "link", "set", "lo", "up"],
            "bring H2 donor loopback up",
        );
        run_linux_command(
            "ip",
            &["-n", &namespace, "link", "set", "dev", &donor_veth, "up"],
            "bring H2 donor veth up",
        );
        run_linux_command(
            "ip",
            &[
                "netns",
                "exec",
                &namespace,
                "tc",
                "qdisc",
                "add",
                "dev",
                &donor_veth,
                "root",
                "netem",
                "loss",
                loss_rates[index as usize],
                "delay",
                delays[index as usize],
            ],
            "attach H2 donor-side netem",
        );
        run_linux_command(
            "tc",
            &[
                "qdisc",
                "add",
                "dev",
                &host_veth,
                "root",
                "netem",
                "loss",
                loss_rates[index as usize],
                "delay",
                delays[index as usize],
            ],
            "attach H2 receiver-side netem",
        );

        legs.push(Leg {
            namespace,
            host_veth,
            donor_veth,
            host_ip,
            donor_ip,
        });
    }

    let root = unique_tmp("bond-three-donor-netns");
    let receiver_source = root.join("receiver-source/payload.bin");
    let dest = root.join("dest");
    let payload = (0..(1024 * 1024 + 173u32))
        .map(|index| (index.wrapping_mul(71) % 251) as u8)
        .collect::<Vec<_>>();
    write_file(&receiver_source, &payload);
    std::fs::create_dir_all(&dest).expect("create H2 bonded destination");
    let donor_sources = (0..3)
        .map(|index| {
            let source = root.join(format!("donor-{index}-source/payload.bin"));
            write_file(&source, &payload);
            source
        })
        .collect::<Vec<_>>();

    let mut receiver_command = Command::new(env!("CARGO_BIN_EXE_atp"));
    receiver_command
        .env("ATP_BOND_TRACE", "1")
        .arg("bond-recv")
        .arg(&dest)
        .arg(&receiver_source)
        .args([
            "--listen",
            "0.0.0.0:0",
            "--expect-donors",
            "3",
            "--udp-bind",
            "0.0.0.0",
        ]);
    for leg in &legs {
        receiver_command.arg("--udp-advertise").arg(&leg.host_ip);
    }
    let receiver = receiver_command
        .args([
            "--workers",
            "3",
            "--max-block-size",
            "65536",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn H2 bonded receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let (listen_addr, mut receiver_lines) = wait_for_bonded_listen_addr(&receiver_stderr);
    assert!(
        listen_addr.ip().is_unspecified(),
        "multi-interface H2 receiver must bind wildcard control address: {listen_addr}"
    );

    let packets_before = legs
        .iter()
        .map(|leg| linux_interface_counter(&leg.host_veth, "rx_packets"))
        .collect::<Vec<_>>();
    let mut donor_guards = Vec::new();
    for (index, leg) in legs.iter().enumerate() {
        let control = SocketAddr::new(
            leg.host_ip.parse().expect("H2 receiver-side veth IP"),
            listen_addr.port(),
        );
        let donor = Command::new("ip")
            .args(["netns", "exec", &leg.namespace, "env", "ATP_BOND_TRACE=1"])
            .arg(env!("CARGO_BIN_EXE_atp"))
            .arg("bond-donate")
            .arg(&donor_sources[index])
            .args([
                "--to",
                &control.to_string(),
                "--workers",
                "3",
                "--max-block-size",
                "65536",
                "--rq-auth-key-hex",
                VALID_KEY_HEX,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn H2 donor {index}: {error}"));
        let mut donor = ChildKillGuard::new(donor);
        let donor_stderr = spawn_stderr_reader(donor.child_mut());
        donor_guards.push((donor, donor_stderr));
    }

    let deadline = Instant::now() + Duration::from_secs(120);
    let donor_outputs = donor_guards
        .into_iter()
        .enumerate()
        .map(|(index, (donor, donor_stderr))| {
            let output = wait_with_deadline(
                donor.into_inner(),
                &format!("H2 namespaced donor {index}"),
                deadline,
            );
            let trace_lines = donor_stderr.into_iter().collect::<Vec<_>>();
            (output, trace_lines)
        })
        .collect::<Vec<_>>();
    for (index, (donor, trace_lines)) in donor_outputs.iter().enumerate() {
        if !donor.status.success() {
            receiver.kill_and_wait();
            panic!(
                "H2 namespaced donor {index} failed; stdout: {}; trace lines: {:?}",
                String::from_utf8_lossy(&donor.stdout),
                trace_lines
            );
        }
    }

    let receiver = wait_with_deadline(
        receiver.into_inner(),
        "H2 three-donor bonded receiver",
        deadline,
    );
    receiver_lines.extend(receiver_stderr.into_iter());
    assert!(
        receiver.status.success(),
        "H2 bonded receiver failed; stdout: {}; trace lines: {:?}",
        String::from_utf8_lossy(&receiver.stdout),
        receiver_lines
    );

    let mut assigned_indices = Vec::new();
    for (index, (donor, trace_lines)) in donor_outputs.iter().enumerate() {
        let report = parse_cli_json(donor, &format!("H2 namespaced donor {index}"));
        assert_eq!(report["committed"], serde_json::json!(true));
        assert_eq!(report["sha_ok"], serde_json::json!(true));
        assert_eq!(report["merkle_ok"], serde_json::json!(true));
        assert_eq!(report["donor_count"], serde_json::json!(3));
        assert!(
            report["symbols_sent"]
                .as_u64()
                .is_some_and(|symbols| symbols > 0),
            "H2 donor {index} must send real symbols: {report}"
        );
        assigned_indices.push(
            report["donor_index"]
                .as_u64()
                .expect("H2 donor_index report"),
        );

        let selected_endpoints = report["receiver_endpoints"]
            .as_array()
            .expect("H2 donor receiver_endpoints array")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("H2 receiver endpoint string")
                    .parse::<SocketAddr>()
                    .expect("H2 receiver endpoint socket address")
            })
            .collect::<Vec<_>>();
        let expected_ip = legs[index]
            .host_ip
            .parse::<std::net::IpAddr>()
            .expect("H2 expected receiver IP");
        assert!(
            !selected_endpoints.is_empty()
                && selected_endpoints
                    .iter()
                    .all(|endpoint| endpoint.ip() == expected_ip),
            "H2 donor {index} must retain only its control-affine path: {selected_endpoints:?}"
        );

        let donor_trace = trace_lines.join("\n");
        assert!(
            donor_trace.contains("endpoint_path_selected")
                && donor_trace.contains("reason=control-path-affinity")
                && legs.iter().all(|leg| donor_trace.contains(&leg.host_ip)),
            "H2 donor {index} trace must show all advertised paths and its selected path: {donor_trace}"
        );
    }
    assigned_indices.sort_unstable();
    assert_eq!(assigned_indices, vec![0, 1, 2]);

    let receiver_report = parse_cli_json(&receiver, "H2 three-donor bonded receiver");
    assert_eq!(receiver_report["committed"], serde_json::json!(true));
    assert_eq!(receiver_report["enrolled_donors"], serde_json::json!(3));
    assert!(
        receiver_report["symbols_accepted"]
            .as_u64()
            .is_some_and(|symbols| symbols > 0),
        "H2 receiver must accept real symbols: {receiver_report}"
    );
    let ingress = receiver_report["donor_ingress"]
        .as_array()
        .expect("H2 donor_ingress array");
    assert_eq!(ingress.len(), 3, "every H2 donor must appear in ingress");
    let mut ingress_indices = Vec::new();
    for row in ingress {
        ingress_indices.push(row["donor_index"].as_u64().expect("H2 ingress donor index"));
        assert!(
            row["symbols_accepted"]
                .as_u64()
                .is_some_and(|symbols| symbols > 0),
            "every H2 donor must contribute novel accepted symbols: {row}"
        );
    }
    ingress_indices.sort_unstable();
    assert_eq!(ingress_indices, vec![0, 1, 2]);

    for (index, leg) in legs.iter().enumerate() {
        let packets_after = linux_interface_counter(&leg.host_veth, "rx_packets");
        assert!(
            packets_after > packets_before[index],
            "H2 donor {index} traffic must cross {}: before={}, after={packets_after}",
            leg.host_veth,
            packets_before[index]
        );
        let dropped = linux_tc_dropped_packets(&leg.namespace, &leg.donor_veth);
        assert!(
            dropped > 0,
            "H2 donor {index} netem leg ({} -> {}, loss {}) must drop real packets",
            leg.donor_ip,
            leg.host_ip,
            loss_rates[index]
        );
    }

    let committed = std::fs::read(dest.join("payload.bin")).expect("read H2 committed payload");
    assert_eq!(committed, payload, "H2 commit must be byte-identical");
    assert_eq!(
        Sha256::digest(&committed),
        Sha256::digest(&payload),
        "H2 committed payload SHA-256 must match the source"
    );
    assert!(
        staging_dirs(&dest).is_empty(),
        "successful H2 transfer left staging directories: {:?}",
        staging_dirs(&dest)
    );

    // Keep the guards visibly live until every counter and qdisc assertion has
    // completed; their Drop impl performs the only namespace cleanup.
    assert_eq!(netns_guards.len(), 3);
}

#[cfg(windows)]
#[test]
fn atp_dry_run_rejects_non_unicode_windows_source_names() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let root = WindowsTestRoot::new("windows-non-unicode");
    let source = root.join("source");
    std::fs::create_dir_all(&source).expect("create source dir");
    let invalid_name = OsString::from_wide(&[0xd800, b'.' as u16, b'b' as u16]);
    std::fs::write(source.join(invalid_name), b"must not be aliased")
        .expect("create non-Unicode source path");

    let output = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("send")
        .arg(&source)
        .arg("127.0.0.1:9")
        .arg("--dry-run")
        .output()
        .expect("run atp dry-run");
    assert!(
        !output.status.success(),
        "non-Unicode source must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not valid Unicode"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(windows)]
#[test]
fn windows_tcp_round_trips_nested_zero_large_and_replacement_files() {
    let root = WindowsTestRoot::new("windows-tcp-tree");
    let source = root.join("source");
    let dest = root.join("dest");
    let nested = source.join("nested/deeper");
    std::fs::create_dir_all(&nested).expect("create nested source tree");
    std::fs::create_dir_all(dest.join("source/nested")).expect("create destination tree");

    let tiny = b"windows tcp nested payload";
    let replacement = b"authoritative replacement bytes";
    let large = windows_payload(16 * 1024 * 1024 + 37, 65_537);
    write_file(&source.join("tiny.txt"), tiny);
    write_file(&nested.join("large.bin"), &large);
    write_file(&source.join("nested/replace.txt"), replacement);
    write_file(&source.join("nested/empty.bin"), b"");
    write_file(
        &dest.join("source/nested/replace.txt"),
        b"stale destination bytes that must be replaced",
    );

    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("recv")
        .arg(&dest)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "tcp",
            "--once",
            "--no-delta",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows TCP receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_tcp_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("send")
        .arg(&source)
        .arg(listen_addr.to_string())
        .args(["--transport", "tcp", "--no-delta"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows TCP sender");
    let sender = wait_with_timeout(sender, "Windows TCP sender");
    if !sender.status.success() {
        receiver.kill_and_wait();
        panic!(
            "Windows TCP sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }
    let receiver = wait_with_timeout(receiver.into_inner(), "Windows TCP receiver");
    assert!(
        receiver.status.success(),
        "Windows TCP receiver failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );

    let expected_bytes =
        u64::try_from(tiny.len() + replacement.len() + large.len()).expect("fixture size fits u64");
    let sender_report = parse_cli_json(&sender, "Windows TCP sender");
    let receiver_report = parse_cli_json(&receiver, "Windows TCP receiver");
    assert_eq!(sender_report["transport"], serde_json::json!("tcp"));
    assert_eq!(sender_report["committed"], serde_json::json!(true));
    assert_eq!(
        sender_report["bytes_sent"],
        serde_json::json!(expected_bytes)
    );
    assert_eq!(receiver_report["transport"], serde_json::json!("tcp"));
    assert_eq!(receiver_report["committed"], serde_json::json!(true));
    assert_eq!(
        receiver_report["bytes_received"],
        serde_json::json!(expected_bytes)
    );

    assert_eq!(
        std::fs::read(dest.join("source/tiny.txt")).expect("read nested tiny file"),
        tiny
    );
    assert_eq!(
        std::fs::read(dest.join("source/nested/deeper/large.bin")).expect("read nested large file"),
        large
    );
    assert_eq!(
        std::fs::read(dest.join("source/nested/replace.txt")).expect("read replacement file"),
        replacement
    );
    assert_eq!(
        std::fs::metadata(dest.join("source/nested/empty.bin"))
            .expect("stat zero-byte file")
            .len(),
        0
    );
    assert!(
        staging_dirs(&dest).is_empty(),
        "successful TCP transfer left staging directories: {:?}",
        staging_dirs(&dest)
    );
}

#[cfg(windows)]
#[test]
fn windows_tcp_default_delta_repairs_stale_destination_without_legacy_state() {
    let root = WindowsTestRoot::new("windows-tcp-default-delta");
    let source = root.join("source/delta-default.bin");
    let dest = root.join("dest");
    let mut expected = windows_payload(3 * 1024 * 1024 + 73, 131_071);
    write_file(&source, &expected);

    let (first_sender, first_receiver) = run_windows_tcp_transfer(&source, &dest, false);
    let first_sender_report = parse_cli_json(&first_sender, "initial Windows TCP delta sender");
    let first_receiver_report =
        parse_cli_json(&first_receiver, "initial Windows TCP delta receiver");
    let logical_bytes = u64::try_from(expected.len()).expect("delta fixture length fits u64");
    assert_eq!(first_sender_report["transport"], serde_json::json!("tcp"));
    assert_eq!(first_sender_report["committed"], serde_json::json!(true));
    assert_eq!(first_sender_report["sha_ok"], serde_json::json!(true));
    assert_eq!(first_sender_report["merkle_ok"], serde_json::json!(true));
    assert_eq!(
        first_sender_report["bytes_sent"],
        serde_json::json!(logical_bytes),
        "an empty destination must receive the complete initial object"
    );
    assert_eq!(first_receiver_report["committed"], serde_json::json!(true));

    let received = dest.join("delta-default.bin");
    assert_file_bytes_and_hash(&received, &expected, "initial default-delta payload");
    let legacy_state_dir = dest.join(".asupersync-atp-delta-v1");
    assert!(
        !legacy_state_dir.exists(),
        "metadata-preserving default unexpectedly created legacy plaintext delta state at {}",
        legacy_state_dir.display()
    );

    for byte in &mut expected[1024 * 1024 + 19..1024 * 1024 + 4096 + 19] {
        *byte ^= 0xa5;
    }
    std::fs::write(&source, &expected).expect("write edited default-delta source");
    let (edited_sender, edited_receiver) = run_windows_tcp_transfer(&source, &dest, false);
    let edited_sender_report = parse_cli_json(&edited_sender, "edited Windows TCP delta sender");
    let edited_receiver_report =
        parse_cli_json(&edited_receiver, "edited Windows TCP delta receiver");
    let edited_bytes = edited_sender_report["bytes_sent"]
        .as_u64()
        .expect("edited delta sender bytes_sent");
    assert!(
        edited_bytes > 0 && edited_bytes < logical_bytes,
        "default TCP delta did not reuse the stale destination; report: {edited_sender_report}"
    );
    assert_eq!(edited_sender_report["committed"], serde_json::json!(true));
    assert_eq!(edited_sender_report["sha_ok"], serde_json::json!(true));
    assert_eq!(edited_sender_report["merkle_ok"], serde_json::json!(true));
    assert_eq!(
        edited_receiver_report["bytes_received"],
        serde_json::json!(edited_bytes)
    );
    assert_file_bytes_and_hash(&received, &expected, "edited default-delta payload");
    assert!(
        !legacy_state_dir.exists(),
        "live TCP delta unexpectedly materialized legacy plaintext state at {}",
        legacy_state_dir.display()
    );

    let mut stale_destination = expected.clone();
    for byte in &mut stale_destination[2 * 1024 * 1024 + 7..2 * 1024 * 1024 + 2048 + 7] {
        *byte ^= 0x3c;
    }
    std::fs::write(&received, &stale_destination).expect("make committed destination stale");
    assert_ne!(
        sha256_hex(&std::fs::read(&received).expect("read stale destination")),
        sha256_hex(&expected)
    );

    let (repair_sender, repair_receiver) = run_windows_tcp_transfer(&source, &dest, false);
    let repair_sender_report = parse_cli_json(&repair_sender, "repair Windows TCP delta sender");
    let repair_receiver_report =
        parse_cli_json(&repair_receiver, "repair Windows TCP delta receiver");
    let repair_bytes = repair_sender_report["bytes_sent"]
        .as_u64()
        .expect("repair delta sender bytes_sent");
    assert!(
        repair_bytes > 0 && repair_bytes < logical_bytes,
        "default TCP delta did not repair the stale destination incrementally; report: {repair_sender_report}"
    );
    assert_eq!(repair_sender_report["committed"], serde_json::json!(true));
    assert_eq!(repair_sender_report["sha_ok"], serde_json::json!(true));
    assert_eq!(repair_sender_report["merkle_ok"], serde_json::json!(true));
    assert_eq!(
        repair_receiver_report["bytes_received"],
        serde_json::json!(repair_bytes)
    );
    assert_file_bytes_and_hash(&received, &expected, "repaired default-delta payload");
    assert!(
        !legacy_state_dir.exists(),
        "stale-destination repair unexpectedly created legacy plaintext state at {}",
        legacy_state_dir.display()
    );
    assert!(
        staging_dirs(&dest).is_empty(),
        "default delta transfers left staging directories: {:?}",
        staging_dirs(&dest)
    );
}

#[cfg(windows)]
#[test]
fn windows_tcp_preserves_attributes_mtime_typed_symlinks_and_hardlinks() {
    let root = WindowsTestRoot::new("windows-tcp-metadata-links");
    let source = root.join("source");
    let dest = root.join("dest");
    let fixture = create_windows_metadata_fixture(&source);

    let (sender, receiver) = run_windows_tcp_transfer(&source, &dest, true);
    let sender_report = parse_cli_json(&sender, "Windows TCP metadata sender");
    let receiver_report = parse_cli_json(&receiver, "Windows TCP metadata receiver");
    assert_eq!(sender_report["transport"], serde_json::json!("tcp"));
    assert_eq!(sender_report["committed"], serde_json::json!(true));
    assert_eq!(sender_report["sha_ok"], serde_json::json!(true));
    assert_eq!(sender_report["merkle_ok"], serde_json::json!(true));
    assert_eq!(receiver_report["transport"], serde_json::json!("tcp"));
    assert_eq!(receiver_report["committed"], serde_json::json!(true));

    assert_windows_metadata_fixture(&dest.join("source"), &fixture);

    let (update_sender, update_receiver) = run_windows_tcp_transfer(&source, &dest, true);
    let update_sender_report = parse_cli_json(&update_sender, "Windows TCP metadata update sender");
    let update_receiver_report =
        parse_cli_json(&update_receiver, "Windows TCP metadata update receiver");
    assert_eq!(update_sender_report["transport"], serde_json::json!("tcp"));
    assert_eq!(update_sender_report["committed"], serde_json::json!(true));
    assert_eq!(update_sender_report["sha_ok"], serde_json::json!(true));
    assert_eq!(update_sender_report["merkle_ok"], serde_json::json!(true));
    assert_eq!(
        update_receiver_report["transport"],
        serde_json::json!("tcp")
    );
    assert_eq!(update_receiver_report["committed"], serde_json::json!(true));
    assert_windows_metadata_fixture(&dest.join("source"), &fixture);
    assert!(
        staging_dirs(&dest).is_empty(),
        "TCP metadata create/update left staging directories: {:?}",
        staging_dirs(&dest)
    );
}

#[cfg(windows)]
#[test]
fn windows_quic_round_trip_requires_and_accepts_explicit_ca() {
    let root = WindowsTestRoot::new("windows-quic-explicit-ca");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    let ca = root.join("tls/ca.pem");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());
    write_file(&ca, CA_CERT_PEM.as_bytes());

    let source = root.join("source/quic-explicit-ca.bin");
    let dest = root.join("dest");
    let payload = windows_payload(256 * 1024 + 19, 8_191);
    write_file(&source, &payload);
    std::fs::create_dir_all(&dest).expect("create QUIC destination");

    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("recv")
        .arg(&dest)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "quic",
            "--once",
            "--no-delta",
            "--server-cert",
        ])
        .arg(&cert)
        .arg("--server-key")
        .arg(&key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows QUIC receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_quic_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("send")
        .arg(&source)
        .arg(listen_addr.to_string())
        .args(["--transport", "quic", "--no-delta", "--ca"])
        .arg(&ca)
        .args(["--server-name", "localhost"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows QUIC sender");
    let sender = wait_with_timeout(sender, "Windows QUIC sender");
    if !sender.status.success() {
        receiver.kill_and_wait();
        panic!(
            "Windows QUIC sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }
    let receiver = wait_with_timeout(receiver.into_inner(), "Windows QUIC receiver");
    assert!(
        receiver.status.success(),
        "Windows QUIC receiver failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );

    let sender_report = parse_cli_json(&sender, "Windows QUIC sender");
    let receiver_report = parse_cli_json(&receiver, "Windows QUIC receiver");
    assert_eq!(sender_report["transport"], serde_json::json!("quic"));
    assert_eq!(sender_report["committed"], serde_json::json!(true));
    assert_eq!(sender_report["sha_ok"], serde_json::json!(true));
    assert_eq!(sender_report["merkle_ok"], serde_json::json!(true));
    assert_eq!(receiver_report["transport"], serde_json::json!("quic"));
    assert_eq!(receiver_report["committed"], serde_json::json!(true));
    assert_eq!(
        std::fs::read(dest.join("quic-explicit-ca.bin")).expect("read QUIC payload"),
        payload
    );
    assert!(
        staging_dirs(&dest).is_empty(),
        "successful QUIC transfer left staging directories: {:?}",
        staging_dirs(&dest)
    );
}

#[cfg(windows)]
#[test]
fn windows_quic_preserves_attributes_mtime_typed_symlinks_and_hardlinks() {
    let root = WindowsTestRoot::new("windows-quic-metadata-links");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    let ca = root.join("tls/ca.pem");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());
    write_file(&ca, CA_CERT_PEM.as_bytes());

    let source = root.join("source");
    let dest = root.join("dest");
    let fixture = create_windows_metadata_fixture(&source);
    let (sender, receiver) = run_windows_quic_transfer(&source, &dest, &cert, &key, &ca);
    let sender_report = parse_cli_json(&sender, "Windows QUIC metadata sender");
    let receiver_report = parse_cli_json(&receiver, "Windows QUIC metadata receiver");
    assert_eq!(sender_report["transport"], serde_json::json!("quic"));
    assert_eq!(sender_report["committed"], serde_json::json!(true));
    assert_eq!(sender_report["sha_ok"], serde_json::json!(true));
    assert_eq!(sender_report["merkle_ok"], serde_json::json!(true));
    assert_eq!(receiver_report["transport"], serde_json::json!("quic"));
    assert_eq!(receiver_report["committed"], serde_json::json!(true));

    assert_windows_metadata_fixture(&dest.join("source"), &fixture);

    let (update_sender, update_receiver) =
        run_windows_quic_transfer(&source, &dest, &cert, &key, &ca);
    let update_sender_report =
        parse_cli_json(&update_sender, "Windows QUIC metadata update sender");
    let update_receiver_report =
        parse_cli_json(&update_receiver, "Windows QUIC metadata update receiver");
    assert_eq!(update_sender_report["transport"], serde_json::json!("quic"));
    assert_eq!(update_sender_report["committed"], serde_json::json!(true));
    assert_eq!(update_sender_report["sha_ok"], serde_json::json!(true));
    assert_eq!(update_sender_report["merkle_ok"], serde_json::json!(true));
    assert_eq!(
        update_receiver_report["transport"],
        serde_json::json!("quic")
    );
    assert_eq!(update_receiver_report["committed"], serde_json::json!(true));
    assert_windows_metadata_fixture(&dest.join("source"), &fixture);
    assert!(
        staging_dirs(&dest).is_empty(),
        "QUIC metadata create/update left staging directories: {:?}",
        staging_dirs(&dest)
    );
}

#[cfg(windows)]
#[test]
fn windows_quic_rejects_private_ca_when_sender_omits_ca() {
    let root = WindowsTestRoot::new("windows-quic-missing-ca");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());

    let source = root.join("source/missing-ca.bin");
    let dest = root.join("dest");
    let payload = windows_payload(64 * 1024 + 17, 8_191);
    write_file(&source, &payload);
    std::fs::create_dir_all(&dest).expect("create missing-CA destination");

    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("recv")
        .arg(&dest)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "quic",
            "--once",
            "--no-delta",
            "--listen-timeout-ms",
            "4000",
            "--quic-handshake-timeout-ms",
            "1500",
            "--server-cert",
        ])
        .arg(&cert)
        .arg("--server-key")
        .arg(&key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows QUIC receiver for missing-CA rejection");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_quic_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("send")
        .arg(&source)
        .arg(listen_addr.to_string())
        .args([
            "--transport",
            "quic",
            "--no-delta",
            "--quic-handshake-timeout-ms",
            "1500",
            "--server-name",
            "localhost",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows QUIC sender without private CA");
    let sender = wait_with_timeout(sender, "Windows QUIC sender without CA");
    receiver.kill_and_wait();
    assert!(
        !sender.status.success(),
        "QUIC sender trusted a private CA without --ca; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&sender.stdout),
        String::from_utf8_lossy(&sender.stderr)
    );
    let diagnostics = format!(
        "{}\n{}",
        String::from_utf8_lossy(&sender.stdout),
        String::from_utf8_lossy(&sender.stderr)
    )
    .to_ascii_lowercase();
    assert!(
        diagnostics.contains("certificate")
            || diagnostics.contains("issuer")
            || diagnostics.contains("unknown ca")
            || diagnostics.contains("trust"),
        "missing-CA failure was not attributed to certificate trust: {diagnostics}"
    );
    assert!(
        !dest.join("missing-ca.bin").exists(),
        "missing-CA transfer wrote destination bytes"
    );
    assert!(
        staging_dirs(&dest).is_empty(),
        "missing-CA rejection left staging directories: {:?}",
        staging_dirs(&dest)
    );
}

#[cfg(windows)]
#[test]
fn windows_rq_round_trip_uses_real_udp_datagrams() {
    let root = WindowsTestRoot::new("windows-rq-real-udp");
    let source = root.join("source/rq-real-udp.bin");
    let dest = root.join("dest");
    let payload = windows_payload(2 * 1024 * 1024 + 101, 131_071);
    write_file(&source, &payload);
    std::fs::create_dir_all(&dest).expect("create RQ destination");

    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("recv")
        .arg(&dest)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "rq",
            "--once",
            "--no-delta",
            "--repair-overhead",
            "1.10",
            "--rq-round0-loss-pct",
            "2",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows RQ receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_rq_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("send")
        .arg(&source)
        .arg(listen_addr.to_string())
        .args([
            "--transport",
            "rq",
            "--no-delta",
            "--streams",
            "1",
            "--repair-overhead",
            "1.10",
            "--rq-round0-loss-pct",
            "2",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows RQ sender");
    let sender = wait_with_timeout(sender, "Windows RQ sender");
    if !sender.status.success() {
        receiver.kill_and_wait();
        panic!(
            "Windows RQ sender failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }
    let receiver = wait_with_timeout(receiver.into_inner(), "Windows RQ receiver");
    assert!(
        receiver.status.success(),
        "Windows RQ receiver failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );

    let sender_report = parse_cli_json(&sender, "Windows RQ sender");
    let receiver_report = parse_cli_json(&receiver, "Windows RQ receiver");
    let symbols_sent = sender_report["symbols_sent"]
        .as_u64()
        .expect("RQ sender symbols_sent counter");
    let udp_datagrams = sender_report["udp_send_acceleration"]["datagrams"]
        .as_u64()
        .expect("RQ sender UDP datagram counter");
    let udp_payload_bytes = sender_report["udp_send_acceleration"]["payload_bytes"]
        .as_u64()
        .expect("RQ sender UDP payload counter");
    let symbols_accepted = receiver_report["symbols_accepted"]
        .as_u64()
        .expect("RQ receiver symbols_accepted counter");
    assert!(symbols_sent > 0, "RQ sender report: {sender_report}");
    assert!(udp_datagrams > 0, "RQ sender report: {sender_report}");
    assert!(udp_payload_bytes > 0, "RQ sender report: {sender_report}");
    assert!(
        symbols_accepted > 0,
        "RQ receiver report: {receiver_report}"
    );
    assert_eq!(sender_report["transport"], serde_json::json!("rq"));
    assert_eq!(sender_report["committed"], serde_json::json!(true));
    assert_eq!(receiver_report["transport"], serde_json::json!("rq"));
    assert_eq!(receiver_report["committed"], serde_json::json!(true));
    assert_eq!(
        std::fs::read(dest.join("rq-real-udp.bin")).expect("read RQ payload"),
        payload
    );
    assert!(
        staging_dirs(&dest).is_empty(),
        "successful RQ transfer left staging directories: {:?}",
        staging_dirs(&dest)
    );
}

#[cfg(windows)]
#[test]
fn windows_rq_preserves_attributes_mtime_and_updates_readonly_destination() {
    let root = WindowsTestRoot::new("windows-rq-metadata-contract");
    let source = root.join("source");
    let dest = root.join("dest");
    let readonly_payload = windows_payload(1021, 257);
    let peer_payload = windows_payload(2039, 509);
    let readonly_source = source.join("packed/readonly-small.bin");
    write_file(&readonly_source, &readonly_payload);
    set_windows_readonly_hidden_and_mtime(&readonly_source);
    write_file(&source.join("packed/peer-small.bin"), &peer_payload);
    // Root and non-empty-directory metadata are separate wire records; apply
    // them only after populating descendants so the receiver must replay them
    // deepest-first/root-last on both initial and update passes.
    set_windows_readonly_hidden_and_mtime(&source.join("packed"));
    set_windows_readonly_hidden_and_mtime(&source);

    let dry_run = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("send")
        .arg(&source)
        .arg("127.0.0.1:9")
        .args(["--transport", "rq", "--dry-run"])
        .output()
        .expect("run Windows RQ metadata dry-run");
    assert!(
        dry_run.status.success(),
        "Windows RQ metadata dry-run failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&dry_run.stdout),
        String::from_utf8_lossy(&dry_run.stderr)
    );
    assert!(
        !dest.exists(),
        "RQ metadata dry-run mutated the destination"
    );

    let received_root = dest.join("source");
    let received_readonly = received_root.join("packed/readonly-small.bin");
    let received_peer = received_root.join("packed/peer-small.bin");
    for pass in ["initial", "readonly destination update"] {
        let (sender, receiver) = run_windows_rq_metadata_transfer(&source, &dest);
        let sender_report = parse_cli_json(&sender, &format!("{pass} Windows RQ metadata sender"));
        let receiver_report =
            parse_cli_json(&receiver, &format!("{pass} Windows RQ metadata receiver"));
        assert_eq!(sender_report["transport"], serde_json::json!("rq"));
        assert_eq!(sender_report["committed"], serde_json::json!(true));
        assert_eq!(sender_report["sha_ok"], serde_json::json!(true));
        assert_eq!(sender_report["merkle_ok"], serde_json::json!(true));
        assert_eq!(receiver_report["transport"], serde_json::json!("rq"));
        assert_eq!(receiver_report["committed"], serde_json::json!(true));
        assert!(
            sender_report["udp_send_acceleration"]["datagrams"]
                .as_u64()
                .is_some_and(|datagrams| datagrams > 0),
            "{pass} RQ metadata transfer did not exercise UDP: {sender_report}"
        );
        assert_file_bytes_and_hash(
            &received_readonly,
            &readonly_payload,
            &format!("{pass} RQ packed readonly member"),
        );
        assert_windows_readonly_hidden_and_mtime(&received_readonly);
        assert_file_bytes_and_hash(
            &received_peer,
            &peer_payload,
            &format!("{pass} RQ packed peer member"),
        );
        assert_windows_readonly_hidden_and_mtime(&received_root);
        assert_windows_readonly_hidden_and_mtime(&received_root.join("packed"));
        assert!(
            staging_dirs(&dest).is_empty(),
            "{pass} RQ metadata transfer left staging directories: {:?}",
            staging_dirs(&dest)
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_quic_peer_cancellation_rolls_back_and_reclaims_staging() {
    let root = WindowsTestRoot::new("windows-quic-cancel-cleanup");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    let ca = root.join("tls/ca.pem");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());
    write_file(&ca, CA_CERT_PEM.as_bytes());

    let source = root.join("source/cancel.bin");
    let dest = root.join("dest");
    let payload = windows_payload(4 * 1024 * 1024 + 23, 524_287);
    write_file(&source, &payload);
    std::fs::create_dir_all(&dest).expect("create cancellation destination");
    let sentinel = b"preexisting destination must survive cancellation";
    write_file(&dest.join("cancel.bin"), sentinel);

    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("recv")
        .arg(&dest)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "quic",
            "--once",
            "--no-delta",
            "--server-cert",
        ])
        .arg(&cert)
        .arg("--server-key")
        .arg(&key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cancellable Windows QUIC receiver");
    let mut receiver = ChildKillGuard::new(receiver);
    let receiver_stderr = spawn_stderr_reader(receiver.child_mut());
    let listen_addr = wait_for_quic_listen_addr(&receiver_stderr);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("send")
        .arg(&source)
        .arg(listen_addr.to_string())
        .args([
            "--transport",
            "quic",
            "--no-delta",
            "--bwlimit",
            "65536",
            "--ca",
        ])
        .arg(&ca)
        .args(["--server-name", "localhost"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cancellable Windows QUIC sender");
    let mut sender = ChildKillGuard::new(sender);

    let staging = wait_for_staging_dir(&dest, "Windows QUIC receiver");
    assert!(
        sender
            .child_mut()
            .try_wait()
            .expect("poll Windows QUIC sender before cancellation")
            .is_none(),
        "sender completed before cancellation after staging appeared at {}",
        staging.display()
    );
    sender
        .child_mut()
        .kill()
        .expect("terminate in-flight Windows QUIC sender");
    let sender = wait_with_timeout(sender.into_inner(), "cancelled Windows QUIC sender");
    assert!(
        !sender.status.success(),
        "cancelled sender unexpectedly succeeded; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&sender.stdout),
        String::from_utf8_lossy(&sender.stderr)
    );

    let receiver = wait_with_timeout(
        receiver.into_inner(),
        "Windows QUIC receiver after peer cancellation",
    );
    assert!(
        !receiver.status.success(),
        "receiver unexpectedly committed a cancelled transfer; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    assert_eq!(
        std::fs::read(dest.join("cancel.bin")).expect("read preserved cancellation sentinel"),
        sentinel
    );
    assert!(
        staging_dirs(&dest).is_empty(),
        "cancelled QUIC transfer leaked staging directories: {:?}",
        staging_dirs(&dest)
    );
}

#[cfg(windows)]
#[test]
fn windows_tcp_rejects_junction_destination_ancestor_without_writes() {
    let root = WindowsTestRoot::new("windows-junction-destination");
    let junction_target = root.join("junction-target");
    let junction = root.join("junction");
    std::fs::create_dir_all(&junction_target).expect("create junction target");
    create_windows_junction(&junction_target, &junction);
    let dest = junction.join("receive");

    let receiver = Command::new(env!("CARGO_BIN_EXE_atp"))
        .arg("recv")
        .arg(&dest)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--transport",
            "tcp",
            "--once",
            "--no-delta",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Windows TCP receiver with junction destination");
    let receiver = wait_with_timeout(receiver, "Windows TCP junction preflight");
    assert!(
        !receiver.status.success(),
        "receiver unexpectedly accepted a destination junction; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    );
    let diagnostics = format!(
        "{}\n{}",
        String::from_utf8_lossy(&receiver.stdout),
        String::from_utf8_lossy(&receiver.stderr)
    )
    .to_ascii_lowercase();
    assert!(
        diagnostics.contains("reparse") || diagnostics.contains("symlink"),
        "junction rejection was not attributed to the link/reparse guard: {diagnostics}"
    );
    assert!(
        !junction_target.join("receive").exists(),
        "receiver wrote through the junction into {}",
        junction_target.display()
    );
    assert!(
        staging_dirs(&junction_target).is_empty(),
        "junction rejection left staging directories in the target: {:?}",
        staging_dirs(&junction_target)
    );
}

#[cfg(feature = "atpd-daemon")]
#[test]
fn atpd_quic_listener_accepts_atp_send_and_reports_diagnostics() {
    let root = unique_tmp("atpd-loopback");
    let cert = root.join("tls/leaf.pem");
    let key = root.join("tls/leaf.key");
    let ca = root.join("tls/ca.pem");
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());
    write_file(&ca, CA_CERT_PEM.as_bytes());

    let daemon_dir = root.join("daemon");
    let init = Command::new(env!("CARGO_BIN_EXE_atpd"))
        .args([
            "init",
            "--data-dir",
            daemon_dir.to_str().unwrap(),
            "--new-identity",
        ])
        .output()
        .expect("run atpd init");
    assert!(
        init.status.success(),
        "atpd init failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let source_dir = root.join("source");
    let payload_path = source_dir.join("payload.bin");
    let payload = (0..8192u32)
        .map(|i| (i.wrapping_mul(17) % 251) as u8)
        .collect::<Vec<_>>();
    write_file(&payload_path, &payload);

    let mut daemon = Command::new(env!("CARGO_BIN_EXE_atpd"))
        .args([
            "--config",
            root.join("missing-config.toml").to_str().unwrap(),
            "--pid-file",
            root.join("atpd.pid").to_str().unwrap(),
            "--log-level",
            "info",
            "--foreground",
            "start",
            "--bind",
            "127.0.0.1:0",
            "--data-dir",
            daemon_dir.to_str().unwrap(),
            "--enable-quic",
            "--quic-server-cert",
            cert.to_str().unwrap(),
            "--quic-server-key",
            key.to_str().unwrap(),
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
            "--diagnostics-bind",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn atpd");
    let daemon_output = spawn_atpd_output_reader(&mut daemon);
    let (quic_addr, diagnostics_addr) = wait_for_atpd_quic_and_diagnostics_addrs(&daemon_output);

    let sender = Command::new(env!("CARGO_BIN_EXE_atp"))
        .args([
            "send",
            payload_path.to_str().unwrap(),
            &quic_addr.to_string(),
            "--transport",
            "quic",
            "--ca",
            ca.to_str().unwrap(),
            "--server-name",
            "localhost",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .output()
        .expect("run atp quic sender to atpd");
    if !sender.status.success() {
        let _ = daemon.kill();
        let _ = daemon.wait();
        panic!(
            "atp quic sender to atpd failed; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&sender.stdout),
            String::from_utf8_lossy(&sender.stderr)
        );
    }

    let received = daemon_dir.join("inbox/payload.bin");
    wait_for_file(&received, "atpd received payload");
    assert_eq!(
        std::fs::read(&received).expect("read atpd payload"),
        payload
    );

    let diagnostics = fetch_diagnostics_json(diagnostics_addr);
    assert_eq!(diagnostics["quic_enabled"], serde_json::json!(true));
    assert_eq!(
        diagnostics["quic_transfer_listener_addr"],
        serde_json::json!(quic_addr.to_string())
    );
    assert_eq!(
        diagnostics["transfers"]["transfers_committed"],
        serde_json::json!(1)
    );
    assert_eq!(
        diagnostics["transfers"]["bytes_received_total"],
        serde_json::json!(8192)
    );

    let _ = daemon.kill();
    let daemon = wait_with_timeout(daemon, "atpd quic daemon");
    assert!(
        !daemon.status.success(),
        "test terminates atpd after diagnostics; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&daemon.stdout),
        String::from_utf8_lossy(&daemon.stderr)
    );
}
