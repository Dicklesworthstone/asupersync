//! Binary-level loopback contract for `atp send/recv --transport quic`.
//!
//! This is the F1 gate for `asupersync-arq-quic-epic-b0k8qo.6.1`: the actual
//! standalone `atp` binary must drive the real ATP-over-QUIC transport rather
//! than only exposing the lower-level `transport_quic` API.

#![cfg(all(feature = "atp-cli", feature = "tls"))]
#![allow(missing_docs)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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
        if now >= deadline {
            panic!("receiver did not print QUIC readiness; stderr lines: {seen:?}");
        }
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
        if now >= deadline {
            panic!("receiver did not print TCP readiness; stderr lines: {seen:?}");
        }
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
        if now >= deadline {
            panic!("receiver did not print RQ readiness; stderr lines: {seen:?}");
        }
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
        if now >= deadline {
            panic!("atpd did not report QUIC and diagnostics readiness; output lines: {seen:?}");
        }
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

fn wait_with_timeout(mut child: Child, label: &str) -> Output {
    let deadline = Instant::now() + Duration::from_secs(20);
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
        .args([
            "send",
            payload_path.to_str().unwrap(),
            &listen_addr.to_string(),
            "--transport",
            "auto",
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
        .args([
            "send",
            payload_path.to_str().unwrap(),
            &listen_addr.to_string(),
            "--transport",
            "auto",
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
