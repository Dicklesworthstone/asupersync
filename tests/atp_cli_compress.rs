//! `atp send --compress` drives negotiated compression from the real binary,
//! over TCP and QUIC (br-asupersync-t1fblr.18).
//!
//! A real `atp recv` and a real `atp send` run as separate processes. A
//! byte-counting relay between them (TCP or UDP) sees exactly what the sender
//! puts on the wire. With `--compress zstd` or `auto`, a compressible file
//! crosses in a fraction of its size; with the default it crosses in full.
//! Every run commits byte-identical files, since the receiver verifies the raw
//! SHA-256 and merkle root before committing.
//!
//! Needs the `zstd` feature as well as `atp-cli` (which bundles TLS). Without
//! the codec, `atp recv` never accepts an offer and `atp send` refuses
//! `--compress`.
#![cfg(all(feature = "atp-cli", feature = "zstd"))]
#![allow(missing_docs)]

use std::io::{BufRead, BufReader, Read};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// How long one `atp` process may run.
const DEADLINE: Duration = Duration::from_secs(120);

/// The transport's default chunk size: the payload spans several chunks.
const CHUNK: usize = 256 * 1024;

// The test CA, leaf and key shared with tests/atp_cli_quic_loopback.rs and the
// real UDP QUIC transport e2e: public fixtures, not production credentials.
// The leaf has SAN DNS:localhost / IP:127.0.0.1.
const VALID_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

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

/// The transport a transfer runs on.
#[derive(Clone, Copy, Debug)]
enum Wire {
    Tcp,
    Quic,
}

impl Wire {
    const fn cli_arg(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
        }
    }
}

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "atp_cli_tcp_compress_{label}_{}_{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create the test root");
    // The receiver refuses destinations below a symlinked ancestor (macOS
    // /var -> /private/var), so use the canonical path.
    root.canonicalize().expect("canonicalize the test root")
}

/// Text-like bytes: words from a small vocabulary.
fn compressible_payload(len: usize) -> Vec<u8> {
    const WORDS: [&str; 8] = [
        "region ",
        "obligation ",
        "cancel ",
        "scope ",
        "budget ",
        "trace ",
        "join ",
        "spawn\n",
    ];
    let mut state = 1_u64;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.extend_from_slice(WORDS[usize::try_from(state >> 61).expect("3 bits")].as_bytes());
    }
    out.truncate(len);
    out
}

/// Kills the child if the test fails before it exits, so no receiver is
/// left listening.
struct KillOnDrop(Option<Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn drain(pipe: Option<impl Read + Send + 'static>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        bytes
    })
}

/// Waits up to [`DEADLINE`] for `child` to exit, draining its pipes meanwhile,
/// and kills it on timeout.
fn finish(mut child: Child, label: &str) -> Output {
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = stderr.join().unwrap_or_default();
            panic!(
                "{label} did not exit within {DEADLINE:?}; stderr: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: stdout.join().expect("drain stdout"),
        stderr: stderr.join().expect("drain stderr"),
    }
}

/// A one-connection relay to `upstream`. It returns the address to dial, and a
/// handle that yields the number of bytes the client (the sender) wrote, once
/// both directions have closed.
fn spawn_counting_relay(upstream: SocketAddr) -> (SocketAddr, thread::JoinHandle<u64>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the relay");
    let addr = listener.local_addr().expect("relay address");
    let handle = thread::spawn(move || {
        let (client, _) = listener.accept().expect("accept the sender");
        let server = TcpStream::connect(upstream).expect("connect to the receiver");
        let mut back_from = server.try_clone().expect("clone the receiver socket");
        let mut back_to = client.try_clone().expect("clone the sender socket");
        let back = thread::spawn(move || {
            let _ = std::io::copy(&mut back_from, &mut back_to);
            let _ = back_to.shutdown(Shutdown::Write);
        });
        let (mut from, mut to) = (client, server);
        let sent = std::io::copy(&mut from, &mut to).expect("relay the sender's bytes");
        let _ = to.shutdown(Shutdown::Write);
        back.join().expect("relay the receiver's bytes");
        sent
    });
    (addr, handle)
}

/// A UDP relay to `upstream` that forwards both ways and counts the bytes the
/// sender puts on the wire. Dropping it stops the relay.
struct UdpRelay {
    addr: SocketAddr,
    sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl UdpRelay {
    fn spawn(upstream: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind the relay");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("relay read timeout");
        let addr = socket.local_addr().expect("relay address");
        let sent = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (counted, stopping) = (Arc::clone(&sent), Arc::clone(&stop));
        let handle = thread::spawn(move || {
            let mut sender = None;
            let mut buf = vec![0_u8; 65_536];
            while !stopping.load(Ordering::Relaxed) {
                let Ok((len, from)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if from == upstream {
                    if let Some(sender) = sender {
                        let _ = socket.send_to(&buf[..len], sender);
                    }
                } else {
                    sender = Some(from);
                    counted.fetch_add(len as u64, Ordering::Relaxed);
                    let _ = socket.send_to(&buf[..len], upstream);
                }
            }
        });
        Self {
            addr,
            sent,
            stop,
            handle: Some(handle),
        }
    }

    /// Stops the relay and returns the sender's byte count.
    fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.sent.load(Ordering::Relaxed)
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create the parent directory");
    }
    std::fs::write(path, contents).expect("write the file");
}

/// The address `atp recv` prints in its `atp: <wire> listening on <addr>,
/// dest ...` line.
fn wait_for_listen_addr(wire: Wire, lines: &mpsc::Receiver<String>) -> SocketAddr {
    let prefix = format!("atp: {} listening on ", wire.cli_arg());
    let deadline = Instant::now() + DEADLINE;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "atp recv printed no listen address; stderr: {seen:?}"
        );
        match lines.recv_timeout(left) {
            Ok(line) => {
                let addr = line
                    .strip_prefix(prefix.as_str())
                    .and_then(|rest| rest.split_once(", dest "))
                    .and_then(|(addr, _)| addr.parse().ok());
                if let Some(addr) = addr {
                    return addr;
                }
                seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("atp recv exited before listening; stderr: {seen:?}")
            }
        }
    }
}

struct Run {
    /// Bytes the sender wrote to the receiver.
    wire_bytes: u64,
    sender_stderr: String,
    committed: Vec<u8>,
}

/// Sends `payload` as `name` from `atp send` (with `--compress compress`, or
/// the default) to `atp recv --once` over `wire`, through a counting relay.
fn transfer(wire: Wire, label: &str, name: &str, payload: &[u8], compress: Option<&str>) -> Run {
    let root = unique_tmp(label);
    let source = root.join(name);
    write_file(&source, payload);
    let dest = root.join("inbox");
    std::fs::create_dir_all(&dest).expect("create the inbox");
    let (cert, key, ca) = (
        root.join("tls/leaf.pem"),
        root.join("tls/leaf.key"),
        root.join("tls/ca.pem"),
    );
    write_file(&cert, LEAF_CERT_PEM.as_bytes());
    write_file(&key, LEAF_KEY_PEM.as_bytes());
    write_file(&ca, CA_CERT_PEM.as_bytes());

    let mut recv = Command::new(env!("CARGO_BIN_EXE_atp"));
    recv.arg("recv").arg(&dest).args([
        "--listen",
        "127.0.0.1:0",
        "--transport",
        wire.cli_arg(),
        "--once",
        "--no-delta",
    ]);
    if matches!(wire, Wire::Quic) {
        recv.arg("--server-cert")
            .arg(&cert)
            .arg("--server-key")
            .arg(&key)
            .args(["--rq-auth-key-hex", VALID_KEY_HEX]);
    }
    let mut receiver = KillOnDrop(Some(
        recv.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn atp recv"),
    ));
    let receiver_stderr = receiver
        .0
        .as_mut()
        .and_then(|child| child.stderr.take())
        .expect("piped receiver stderr");
    let (line_tx, lines) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(receiver_stderr)
            .lines()
            .map_while(Result::ok)
        {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    let upstream = wait_for_listen_addr(wire, &lines);
    let (relay, relay_done) = match wire {
        Wire::Tcp => {
            let (addr, done) = spawn_counting_relay(upstream);
            (addr, Relay::Tcp(done))
        }
        Wire::Quic => {
            let relay = UdpRelay::spawn(upstream);
            (relay.addr, Relay::Udp(relay))
        }
    };

    let mut send = Command::new(env!("CARGO_BIN_EXE_atp"));
    send.arg("send").arg(&source).arg(relay.to_string()).args([
        "--transport",
        wire.cli_arg(),
        "--no-delta",
    ]);
    if matches!(wire, Wire::Quic) {
        send.arg("--ca")
            .arg(&ca)
            .args(["--server-name", "localhost"])
            .args(["--rq-auth-key-hex", VALID_KEY_HEX]);
    }
    if let Some(compress) = compress {
        send.args(["--compress", compress]);
    }
    let sender = finish(
        send.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn atp send"),
        "atp send",
    );
    let sent = sender.status.success();
    let received = if sent {
        Some(finish(
            receiver.0.take().expect("receiver child"),
            "atp recv",
        ))
    } else {
        // A receiver the sender never reached would wait forever.
        drop(receiver);
        None
    };
    let receiver_log: Vec<String> = lines.iter().collect();
    let sender_stderr = String::from_utf8_lossy(&sender.stderr).into_owned();
    assert!(
        sent,
        "{label}: atp send failed: {sender_stderr}\nreceiver: {receiver_log:?}"
    );
    assert!(
        received.is_some_and(|received| received.status.success()),
        "{label}: atp recv failed: {receiver_log:?}"
    );
    Run {
        wire_bytes: match relay_done {
            Relay::Tcp(done) => done.join().expect("relay thread"),
            Relay::Udp(relay) => relay.finish(),
        },
        sender_stderr,
        committed: std::fs::read(dest.join(name)).expect("read the committed file"),
    }
}

/// The relay a transfer crossed, to read its byte count from.
enum Relay {
    Tcp(thread::JoinHandle<u64>),
    Udp(UdpRelay),
}

/// Over `wire`, a compressible file crosses in under a third of its size with
/// `--compress zstd` and with `auto`; `auto` sends a file named as an
/// already-compressed format raw, and the default sends everything raw. Every
/// run commits the exact bytes. All wrong runs are reported at once.
fn compression_follows_the_flag(wire: Wire) {
    let payload = compressible_payload(4 * CHUNK + 17);
    let len = payload.len() as u64;
    let mut wrong = Vec::new();
    for (label, name, compress, compressed) in [
        ("zstd", "payload.txt", Some("zstd"), true),
        ("auto", "payload.txt", Some("auto"), true),
        ("auto, a .png name", "payload.png", Some("auto"), false),
        ("default", "payload.txt", None, false),
    ] {
        let run = transfer(
            wire,
            &format!("{}_{}", wire.cli_arg(), label.replace([' ', ',', '.'], "_")),
            name,
            &payload,
            compress,
        );
        assert!(
            run.committed == payload,
            "{wire:?} {label}: the committed file differs from the source"
        );
        assert_eq!(
            run.sender_stderr
                .contains("[atp] compression: zstd offered"),
            compress.is_some(),
            "{wire:?} {label}: {}",
            run.sender_stderr
        );
        let as_expected = if compressed {
            run.wire_bytes < len / 3
        } else {
            run.wire_bytes > len
        };
        if !as_expected {
            wrong.push((label, compressed, run.wire_bytes));
        }
    }
    assert!(
        wrong.is_empty(),
        "{wire:?}: wire bytes not as expected (label, expected compressed, wire bytes) \
         for {len}: {wrong:?}"
    );
}

#[test]
fn tcp_compression_follows_the_flag() {
    compression_follows_the_flag(Wire::Tcp);
}

#[test]
fn quic_compression_follows_the_flag() {
    compression_follows_the_flag(Wire::Quic);
}

/// `--compress zstd` on rq, which has no codec path, fails before any
/// connection instead of silently sending raw.
#[test]
fn compress_is_refused_on_rq() {
    let root = unique_tmp("rq");
    let source = root.join("payload.txt");
    std::fs::write(&source, compressible_payload(1024)).expect("write the source");
    let out = finish(
        Command::new(env!("CARGO_BIN_EXE_atp"))
            .arg("send")
            .arg(&source)
            .arg("127.0.0.1:9")
            .args(["--transport", "rq", "--compress", "zstd"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn atp send"),
        "atp send --transport rq",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "rq with --compress zstd succeeded");
    assert!(
        stderr.contains("--transport rq would send every chunk raw"),
        "{stderr}"
    );
}
