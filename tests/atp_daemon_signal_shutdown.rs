//! `atp serve` and `atpd start` drain and exit 0 on SIGINT/SIGTERM (vlf155).
//!
//! br-asupersync-vlf155. Each test runs a real daemon binary and signals it. The first signal must
//! cancel the receive loop: an in-flight receive is aborted and drained, so no
//! staging directory survives and the aborted transfer is reported; a final
//! stopped status follows; the process exits 0.
//!
//! Before the fix `atp serve` installed no handler, so the signal's default
//! action killed it (no exit code, terminating signal 15 or 2) and left an
//! in-flight receive's staging directory behind. `atpd` caught the signal but
//! never cancelled its transfer listeners: the runtime teardown dropped an
//! in-flight receive without reporting it, and the listeners never returned.
//!
//! Gated on `atp-cli` and `atpd-daemon`: both binaries, and so
//! `CARGO_BIN_EXE_atp` and `CARGO_BIN_EXE_atpd`, exist only with those
//! features. Run with
//! `cargo test --features atp-cli,atpd-daemon --test atp_daemon_signal_shutdown`.
#![cfg(all(unix, feature = "atp-cli", feature = "atpd-daemon"))]

use asupersync::cx::Cx;
use asupersync::net::atp::transport_common::FilterSet;
use asupersync::net::atp::transport_tcp::{TransferConfig, send_path_filtered};
use asupersync::runtime::RuntimeBuilder;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const ATP_BIN: &str = env!("CARGO_BIN_EXE_atp");
const ATPD_BIN: &str = env!("CARGO_BIN_EXE_atpd");
/// Upper bound for a daemon to report readiness, or a probe connection.
const READY_LIMIT: Duration = Duration::from_secs(30);
/// Upper bound for a daemon to exit after the first signal.
///
/// It is well below the receive loops' 60 s idle accept wait, so an idle
/// daemon that exits in time was woken by the signal, not by a timeout.
const EXIT_LIMIT: Duration = Duration::from_secs(20);
/// Upper bound for a daemon's pipes to close once the process has exited.
const PIPE_LIMIT: Duration = Duration::from_secs(10);
/// Upper bound for a transfer to put its staging directory on disk.
const IN_FLIGHT_LIMIT: Duration = Duration::from_secs(30);
/// Longest the parked TCP sender stays parked if the test never releases it.
const SENDER_PARK_LIMIT: Duration = Duration::from_secs(120);
/// Upper bound for the released TCP sender to finish.
///
/// It fails, because its peer is gone. The bound exceeds the 60 s transport
/// idle timeout, the sender's worst case.
const SENDER_FINISH_LIMIT: Duration = Duration::from_secs(90);
/// Size of each of the two payload files: four 256 KiB ATP-over-TCP chunks.
const ENTRY_BYTES: usize = 1024 * 1024;
/// RQ receiver quiet window after a round marker, in milliseconds.
///
/// The receiver commits only after this window, so the transfer stays in
/// flight, with its staging directory on disk, for the whole test.
const RQ_HOLD_TAIL_DRAIN_MS: &str = "600000";
/// QUIC sender cap in bytes per second.
///
/// The 4 MiB payload then takes about a minute, far longer than the test needs
/// to signal the receiver.
const QUIC_HOLD_BWLIMIT: &str = "65536";
const TCP_STAGING_PREFIX: &str = ".atp-staging-";
const RQ_STAGING_PREFIX: &str = ".atp-rq-staging-";
const QUIC_STAGING_PREFIX: &str = ".atp-quic-staging-";
const ATP_FAILED_PREFIX: &str = "atp: transfer failed: ";
/// The RQ symbol-auth key the other RQ loopback tests use.
const VALID_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ATPD_FAILED: &str = "ATP transfer failed: ";
const ATPD_QUIC_FAILED: &str = "ATP QUIC transfer failed";
const ATPD_COMMITTED: &str = "committed to inbox";
const ATPD_LISTENER_DRAINED: &str = "ATP transfer listener drained and stopped";
const ATPD_LISTENERS_DRAINED: &str = "ATP transfer listeners drained";
const ATPD_STOPPED: &str = "ATP daemon stopped";

// Canonical CA + leaf chain shared with the other ATP QUIC loopback tests. The
// leaf has SAN DNS:localhost / IP:127.0.0.1 and is valid until 2126.
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

/// A fresh scratch root with no symlinked ancestor.
///
/// macOS `$TMPDIR` lives under `/var -> /private/var`, and the ATP receivers
/// reject a destination with a symlinked ancestor. Roots are kept for
/// forensics, like the other ATP loopback tests.
fn scratch_root(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "asupersync-daemon-signal-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create scratch root");
    root.canonicalize().expect("canonicalize scratch root")
}

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent directory");
    }
    std::fs::write(path, contents).expect("write file");
}

/// Writes a payload directory of two files, `entry_bytes` each.
fn write_payload(root: &Path, entry_bytes: usize) -> PathBuf {
    let source = root.join("payload");
    let bytes: Vec<u8> = (0..entry_bytes).map(|index| (index % 251) as u8).collect();
    write_file(&source.join("a.bin"), &bytes);
    write_file(&source.join("b.bin"), &bytes);
    source
}

/// The QUIC receiver's certificate and key, and the CA its senders trust.
struct TlsFiles {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

fn write_tls_files(root: &Path) -> TlsFiles {
    let tls = TlsFiles {
        cert: root.join("tls/leaf.pem"),
        key: root.join("tls/leaf.key"),
        ca: root.join("tls/ca.pem"),
    };
    write_file(&tls.cert, LEAF_CERT_PEM.as_bytes());
    write_file(&tls.key, LEAF_KEY_PEM.as_bytes());
    write_file(&tls.ca, CA_CERT_PEM.as_bytes());
    tls
}

/// A loopback address whose UDP port was free a moment ago.
///
/// Persistent QUIC serve needs a fixed port; the other QUIC loopback tests
/// reserve one the same way.
fn reserve_udp_port() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("reserve a UDP port");
    socket.local_addr().expect("reserved UDP address")
}

/// Every entry of `dir` as a file name, sorted; empty if `dir` does not exist.
fn dir_entries(dir: &Path) -> Vec<String> {
    let read = match std::fs::read_dir(dir) {
        Ok(read) => read,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("read {}: {error}", dir.display()),
    };
    let mut names: Vec<String> = read
        .map(|entry| {
            entry
                .expect("read directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn with_prefix(entries: &[String], prefix: &str) -> Vec<String> {
    entries
        .iter()
        .filter(|name| name.starts_with(prefix))
        .cloned()
        .collect()
}

/// Polls `dir` until an entry starting with `prefix` appears; empty if none did.
fn wait_for_entry(dir: &Path, prefix: &str, limit: Duration) -> Vec<String> {
    let deadline = Instant::now() + limit;
    loop {
        let found = with_prefix(&dir_entries(dir), prefix);
        if !found.is_empty() || Instant::now() >= deadline {
            return found;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn count_prefixed(lines: &[String], prefix: &str) -> usize {
    lines.iter().filter(|line| line.starts_with(prefix)).count()
}

fn count_containing(lines: &[String], needle: &str) -> usize {
    lines.iter().filter(|line| line.contains(needle)).count()
}

fn signal_name(signal: Option<i32>) -> String {
    signal.map_or_else(
        || "none".to_string(),
        |raw| Signal::try_from(raw).map_or_else(|_| format!("signal {raw}"), |sig| sig.to_string()),
    )
}

fn describe_status(status: Option<ExitStatus>) -> String {
    status.map_or_else(
        || format!("still running after {EXIT_LIMIT:?} (then killed)"),
        |status| {
            format!(
                "exit code {:?}, terminating signal {}",
                status.code(),
                signal_name(status.signal())
            )
        },
    )
}

/// Removes ANSI CSI sequences, so a colored log line still matches its text.
fn strip_ansi(line: &str) -> String {
    let mut plain = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            plain.push(c);
            continue;
        }
        // CSI: ESC '[' parameters, then one final byte in '@'..='~'.
        if chars.next() == Some('[') {
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        }
    }
    plain
}

/// Forwards each line read from `pipe`, without ANSI escapes, to the receiver.
fn line_channel(pipe: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else { break };
            if sender.send(strip_ansi(&line)).is_err() {
                break;
            }
        }
    });
    receiver
}

/// Appends lines from `lines` to `into` until its sender hangs up.
///
/// Gives up after `PIPE_LIMIT` and records that the pipe was still open.
fn drain_lines(lines: &mpsc::Receiver<String>, into: &mut Vec<String>, pipe: &str) {
    let deadline = Instant::now() + PIPE_LIMIT;
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => into.push(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                into.push(format!("<{pipe} still open after {PIPE_LIMIT:?}>"));
                return;
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Pipe {
    Stdout,
    Stderr,
}

/// A child process and its output.
///
/// Dropping it kills and reaps a child that is still running, so no test path
/// leaves a process behind.
struct Process {
    label: &'static str,
    child: Option<Child>,
    stdout: mpsc::Receiver<String>,
    stderr: mpsc::Receiver<String>,
    stdout_seen: Vec<String>,
    stderr_seen: Vec<String>,
}

impl Process {
    fn spawn(label: &'static str, command: &mut Command) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("start {label}: {error}"));
        let out = child.stdout.take();
        let err = child.stderr.take();
        let (Some(out), Some(err)) = (out, err) else {
            let _ = child.kill();
            let _ = child.wait();
            unreachable!("both {label} pipes were requested");
        };
        Self {
            label,
            child: Some(child),
            stdout: line_channel(out),
            stderr: line_channel(err),
            stdout_seen: Vec::new(),
            stderr_seen: Vec::new(),
        }
    }

    /// Reads `pipe` until `find` returns `Some` for a line; `None` if none did.
    fn wait_for<T>(
        &mut self,
        pipe: Pipe,
        limit: Duration,
        mut find: impl FnMut(&str) -> Option<T>,
    ) -> Option<T> {
        let deadline = Instant::now() + limit;
        let (lines, seen) = match pipe {
            Pipe::Stdout => (&self.stdout, &mut self.stdout_seen),
            Pipe::Stderr => (&self.stderr, &mut self.stderr_seen),
        };
        while let Ok(line) = lines.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            let found = find(&line);
            seen.push(line);
            if found.is_some() {
                return found;
            }
        }
        None
    }

    fn signal(&self, signal: Signal) {
        let id = self.child.as_ref().expect("child is owned").id();
        let pid = Pid::from_raw(i32::try_from(id).expect("PID fits pid_t"));
        kill(pid, signal)
            .unwrap_or_else(|error| panic!("send {signal} to {}: {error}", self.label));
    }

    fn is_running(&mut self) -> bool {
        self.child.as_mut().is_some_and(|child| {
            child
                .try_wait()
                .unwrap_or_else(|error| panic!("poll {}: {error}", self.label))
                .is_none()
        })
    }

    /// Waits up to `limit` for the process to exit.
    ///
    /// Returns `None` if it was still running; it is then killed and reaped, so
    /// its output can still be collected.
    fn wait_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            let child = self.child.as_mut().expect("child is owned");
            let polled = child
                .try_wait()
                .unwrap_or_else(|error| panic!("poll {}: {error}", self.label));
            if let Some(status) = polled {
                self.child = None;
                return Some(status);
            }
            if Instant::now() >= deadline {
                self.kill();
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Kills and reaps the process if it has not been reaped yet.
    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Every line of `pipe`, read until it closes.
    fn all_lines(&mut self, pipe: Pipe) -> Vec<String> {
        let (lines, seen, name) = match pipe {
            Pipe::Stdout => (&self.stdout, &mut self.stdout_seen, "stdout"),
            Pipe::Stderr => (&self.stderr, &mut self.stderr_seen, "stderr"),
        };
        let mut all = std::mem::take(seen);
        drain_lines(lines, &mut all, name);
        all
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.kill();
    }
}

/// An in-process ATP-over-TCP sender that parks after its first file.
///
/// It parks inside the progress callback, after the first entry's bytes were
/// written and before the second entry starts, so the receiver holds an open
/// staging directory and cannot commit until the sender is released.
struct ParkedSender {
    parked: mpsc::Receiver<(u64, u64)>,
    release: mpsc::Sender<()>,
    outcome: mpsc::Receiver<Result<bool, String>>,
}

impl ParkedSender {
    fn start(addr: SocketAddr, source: PathBuf) -> Self {
        let (parked_tx, parked) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let (outcome_tx, outcome) = mpsc::channel();
        thread::spawn(move || {
            let runtime = RuntimeBuilder::multi_thread()
                .build()
                .expect("sender runtime");
            let result = runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("sender cx");
                let filter = FilterSet::new();
                // Taken at the first mid-transfer progress report, so the
                // sender parks exactly once.
                let mut park = Some((parked_tx, release_rx));
                send_path_filtered(
                    &cx,
                    addr,
                    &source,
                    TransferConfig::default(),
                    "vlf155-parked-sender",
                    &filter,
                    move |sent, total| {
                        if sent < total
                            && let Some((parked_tx, release_rx)) = park.take()
                        {
                            let _ = parked_tx.send((sent, total));
                            let _ = release_rx.recv_timeout(SENDER_PARK_LIMIT);
                        }
                    },
                )
                .await
            }));
            let _ = outcome_tx.send(
                result
                    .map(|report| report.receipt.committed)
                    .map_err(|error| error.to_string()),
            );
        });
        Self {
            parked,
            release,
            outcome,
        }
    }

    /// Waits for the park point and returns `(bytes_sent, total_bytes)` there.
    fn wait_parked(&self) -> (u64, u64) {
        self.parked
            .recv_timeout(IN_FLIGHT_LIMIT)
            .unwrap_or_else(|error| {
                panic!(
                    "the sender did not reach its park point within {IN_FLIGHT_LIMIT:?}: {error}"
                )
            })
    }

    /// Releases the sender and returns whether it reported a committed receipt.
    fn finish(self) -> Result<bool, String> {
        let Self {
            release, outcome, ..
        } = self;
        drop(release);
        outcome
            .recv_timeout(SENDER_FINISH_LIMIT)
            .unwrap_or_else(|error| {
                Err(format!(
                    "sender did not finish within {SENDER_FINISH_LIMIT:?}: {error}"
                ))
            })
    }
}

// ─── atp serve ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum AtpTransport {
    Tcp,
    Rq,
    Quic,
}

impl AtpTransport {
    const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Rq => "rq",
            Self::Quic => "quic",
        }
    }

    /// The `listening` line's prefix, and the text that follows the address.
    const fn listening_line(self) -> (&'static str, &'static str) {
        match self {
            Self::Tcp => ("atp: tcp listening on ", ", dest "),
            Self::Rq => ("atp: rq control listening on ", " (udp on "),
            Self::Quic => ("atp: quic listening on ", ", dest "),
        }
    }

    const fn staging_prefix(self) -> &'static str {
        match self {
            Self::Tcp => TCP_STAGING_PREFIX,
            Self::Rq => RQ_STAGING_PREFIX,
            Self::Quic => QUIC_STAGING_PREFIX,
        }
    }
}

/// `atp serve <dest>` on loopback for `transport`, plus `extra` arguments.
///
/// RQ authenticates symbols with the shared test key, as the other RQ loopback
/// tests do. QUIC presents the canonical leaf certificate on a reserved port.
fn atp_serve_command(root: &Path, dest: &Path, transport: AtpTransport, extra: &[&str]) -> Command {
    let mut command = Command::new(ATP_BIN);
    command
        .arg("serve")
        .arg(dest)
        .args(["--transport", transport.name()]);
    match transport {
        AtpTransport::Tcp => {
            command.args(["--listen", "127.0.0.1:0"]);
        }
        AtpTransport::Rq => {
            command.args([
                "--listen",
                "127.0.0.1:0",
                "--no-delta",
                "--rq-auth-key-hex",
                VALID_KEY_HEX,
            ]);
        }
        AtpTransport::Quic => {
            let tls = write_tls_files(root);
            command
                .arg("--listen")
                .arg(reserve_udp_port().to_string())
                .arg("--no-delta")
                .arg("--server-cert")
                .arg(&tls.cert)
                .arg("--server-key")
                .arg(&tls.key);
        }
    }
    command.args(extra);
    command
}

/// Reads the daemon's `listening` line on stderr and returns its address.
fn atp_listening(daemon: &mut Process, transport: AtpTransport) -> SocketAddr {
    let (prefix, after) = transport.listening_line();
    daemon
        .wait_for(Pipe::Stderr, READY_LIMIT, |line| {
            let (address, _) = line.strip_prefix(prefix)?.split_once(after)?;
            address.parse().ok()
        })
        .unwrap_or_else(|| {
            panic!(
                "atp serve printed no `{prefix}` line within {READY_LIMIT:?}; stderr: {:?}",
                daemon.stderr_seen
            )
        })
}

/// What an `atp serve` daemon left behind after a signal.
struct AtpStop {
    status: Option<ExitStatus>,
    stdout: Vec<String>,
    stderr: Vec<String>,
    dest_entries: Vec<String>,
}

fn stop_atp(daemon: &mut Process, signal: Signal, dest: &Path) -> AtpStop {
    daemon.signal(signal);
    let status = daemon.wait_exit(EXIT_LIMIT);
    AtpStop {
        status,
        stdout: daemon.all_lines(Pipe::Stdout),
        stderr: daemon.all_lines(Pipe::Stderr),
        dest_entries: dir_entries(dest),
    }
}

/// The problems with an `atp serve` stop.
///
/// It must exit 0, print the final status on both pipes, report exactly
/// `failed_lines` failed transfers, and leave the destination empty.
fn atp_stop_problems(
    stop: &AtpStop,
    signal: Signal,
    transport: AtpTransport,
    listen: SocketAddr,
    aborted: u64,
    failed_lines: usize,
) -> Vec<String> {
    let name = transport.name();
    let mut problems = Vec::new();
    if stop.status.and_then(|status| status.code()) != Some(0) {
        problems.push(format!(
            "{signal} must stop atp serve ({name}) with exit 0; got {}",
            describe_status(stop.status)
        ));
    }
    let expected = serde_json::json!({
        "event": "atp_serve_stopped",
        "transport": name,
        "listen_address": listen.to_string(),
        "aborted_receives": aborted,
    });
    let events: Vec<Option<Value>> = stop
        .stdout
        .iter()
        .map(|line| serde_json::from_str(line).ok())
        .collect();
    if events != [Some(expected.clone())] {
        problems.push(format!(
            "stdout must be exactly the final event {expected}; got {:?}",
            stop.stdout
        ));
    }
    let stopped =
        format!("atp: {name} serve stopped on {listen}; aborted {aborted} in-flight receive(s)");
    let stopped_lines = stop.stderr.iter().filter(|line| **line == stopped).count();
    if stopped_lines != 1 {
        problems.push(format!(
            "stderr must carry `{stopped}` once; found it {stopped_lines} time(s)"
        ));
    }
    let failed = count_prefixed(&stop.stderr, ATP_FAILED_PREFIX);
    if failed != failed_lines {
        problems.push(format!(
            "expected {failed_lines} failed-transfer line(s) on stderr; got {failed}"
        ));
    }
    let staging = with_prefix(&stop.dest_entries, transport.staging_prefix());
    if !staging.is_empty() {
        problems.push(format!(
            "staging directories survived the stop: {staging:?}"
        ));
    }
    if !stop.dest_entries.is_empty() {
        problems.push(format!(
            "the destination must stay empty: {:?}",
            stop.dest_entries
        ));
    }
    problems
}

/// An idle `atp serve` stops on `signal` with exit 0 and its final status.
///
/// For TCP and RQ a probe connection that closes at once is accepted and
/// reported as a failed transfer before the signal. The report proves the loop
/// runs and is back in its idle accept wait (60 s for TCP, unbounded for RQ),
/// so an exit within `EXIT_LIMIT` means the signal woke that wait. QUIC's idle
/// accept also waits 60 s for a handshake, and its stop must report no
/// transfer at all.
fn assert_idle_atp_serve_stops(label: &str, transport: AtpTransport, signal: Signal) {
    let root = scratch_root(label);
    let dest = root.join("inbox");
    let mut daemon = Process::spawn(
        "atp serve",
        &mut atp_serve_command(&root, &dest, transport, &[]),
    );
    let listen = atp_listening(&mut daemon, transport);

    let probes = if matches!(transport, AtpTransport::Quic) {
        0
    } else {
        drop(TcpStream::connect(listen).expect("probe the daemon's listener"));
        let reported = daemon.wait_for(Pipe::Stderr, READY_LIMIT, |line| {
            line.starts_with(ATP_FAILED_PREFIX).then_some(())
        });
        assert!(
            reported.is_some(),
            "atp serve ({}) never reported the probe connection; stderr so far: {:?}",
            transport.name(),
            daemon.stderr_seen
        );
        1
    };

    let stop = stop_atp(&mut daemon, signal, &dest);
    let problems = atp_stop_problems(&stop, signal, transport, listen, 0, probes);
    assert!(
        problems.is_empty(),
        "{problems:#?}\nscratch root: {}\nstdout: {:#?}\nstderr: {:#?}",
        root.display(),
        stop.stdout,
        stop.stderr
    );
}

#[test]
fn atp_serve_tcp_sigterm_idle_exits_zero_with_a_stopped_event() {
    assert_idle_atp_serve_stops("tcp-idle-term", AtpTransport::Tcp, Signal::SIGTERM);
}

#[test]
fn atp_serve_tcp_sigint_idle_exits_zero_with_a_stopped_event() {
    assert_idle_atp_serve_stops("tcp-idle-int", AtpTransport::Tcp, Signal::SIGINT);
}

#[test]
fn atp_serve_rq_sigterm_idle_exits_zero_with_a_stopped_event() {
    assert_idle_atp_serve_stops("rq-idle-term", AtpTransport::Rq, Signal::SIGTERM);
}

#[test]
fn atp_serve_quic_sigterm_idle_exits_zero_and_reports_no_transfer() {
    assert_idle_atp_serve_stops("quic-idle-term", AtpTransport::Quic, Signal::SIGTERM);
}

/// SIGTERM during a TCP transfer aborts the receive through the drain.
///
/// The formerly failing state is witnessed before the signal: the sender is
/// parked mid-transfer and the receive's staging directory is on disk.
#[test]
fn atp_serve_tcp_sigterm_mid_transfer_drains_the_receive() {
    let root = scratch_root("tcp-in-flight");
    let source = write_payload(&root, ENTRY_BYTES);
    let dest = root.join("inbox");
    let mut daemon = Process::spawn(
        "atp serve",
        &mut atp_serve_command(&root, &dest, AtpTransport::Tcp, &[]),
    );
    let listen = atp_listening(&mut daemon, AtpTransport::Tcp);
    let sender = ParkedSender::start(listen, source);
    let (sent, total) = sender.wait_parked();
    assert!(
        0 < sent && sent < total,
        "the sender must park mid-transfer, at {sent} of {total} bytes"
    );
    let staging_before = wait_for_entry(&dest, TCP_STAGING_PREFIX, IN_FLIGHT_LIMIT);
    assert!(
        !staging_before.is_empty(),
        "the in-flight receive never put a staging directory into {}: {:?}",
        dest.display(),
        dir_entries(&dest)
    );

    let stop = stop_atp(&mut daemon, Signal::SIGTERM, &dest);
    let send_outcome = sender.finish();
    let mut problems = atp_stop_problems(&stop, Signal::SIGTERM, AtpTransport::Tcp, listen, 1, 1);
    if send_outcome == Ok(true) {
        problems.push("the sender reported a committed receipt for an aborted transfer".into());
    }
    assert!(
        problems.is_empty(),
        "{problems:#?}\nstaging before the signal: {staging_before:?}\nsender outcome: \
         {send_outcome:?}\nscratch root: {}\nstdout: {:#?}\nstderr: {:#?}",
        root.display(),
        stop.stdout,
        stop.stderr
    );
}

/// SIGTERM during an RQ transfer aborts the receive in place.
///
/// The receiver's 600 s quiet window after the sender's round marker keeps the
/// transfer uncommitted with its staging directory on disk. A receiver repair
/// overhead above 1.001 rules out the control-stream source lane, so the
/// transfer takes the UDP spray path that has that window. The staging
/// directory is witnessed before the signal.
#[test]
fn atp_serve_rq_sigterm_mid_transfer_drains_the_receive() {
    let root = scratch_root("rq-in-flight");
    let source = write_payload(&root, ENTRY_BYTES);
    let dest = root.join("inbox");
    let hold = [
        "--rq-tail-drain-ms",
        RQ_HOLD_TAIL_DRAIN_MS,
        "--repair-overhead",
        "1.05",
    ];
    let mut daemon = Process::spawn(
        "atp serve",
        &mut atp_serve_command(&root, &dest, AtpTransport::Rq, &hold),
    );
    let listen = atp_listening(&mut daemon, AtpTransport::Rq);
    let mut sender = Process::spawn(
        "atp send",
        Command::new(ATP_BIN)
            .arg("send")
            .arg(&source)
            .arg(listen.to_string())
            .args(["--transport", "rq", "--no-delta", "--streams", "1"])
            .args([
                "--repair-overhead",
                "1.05",
                "--rq-auth-key-hex",
                VALID_KEY_HEX,
            ]),
    );
    let staging_before = wait_for_entry(&dest, RQ_STAGING_PREFIX, IN_FLIGHT_LIMIT);
    if staging_before.is_empty() {
        sender.kill();
        panic!(
            "the RQ receive never put a staging directory into {}: {:?}\nsender stderr: {:?}",
            dest.display(),
            dir_entries(&dest),
            sender.all_lines(Pipe::Stderr)
        );
    }

    let stop = stop_atp(&mut daemon, Signal::SIGTERM, &dest);
    sender.kill();
    let problems = atp_stop_problems(&stop, Signal::SIGTERM, AtpTransport::Rq, listen, 1, 1);
    assert!(
        problems.is_empty(),
        "{problems:#?}\nstaging before the signal: {staging_before:?}\nscratch root: {}\n\
         stdout: {:#?}\nstderr: {:#?}",
        root.display(),
        stop.stdout,
        stop.stderr
    );
}

/// SIGTERM during a QUIC transfer aborts the receive and reports it.
///
/// The sender's `--bwlimit` cap keeps the 4 MiB transfer in flight for about a
/// minute (a capped sender never takes QUIC's unpaced source-stream lane). The
/// staging directory and a still-running sender are witnessed before the
/// signal.
#[test]
fn atp_serve_quic_sigterm_mid_transfer_drains_the_receive() {
    let root = scratch_root("quic-in-flight");
    let source = write_payload(&root, 2 * ENTRY_BYTES);
    let dest = root.join("inbox");
    let mut daemon = Process::spawn(
        "atp serve",
        &mut atp_serve_command(&root, &dest, AtpTransport::Quic, &[]),
    );
    let listen = atp_listening(&mut daemon, AtpTransport::Quic);
    let tls = write_tls_files(&root);
    let mut sender = Process::spawn(
        "atp send",
        Command::new(ATP_BIN)
            .arg("send")
            .arg(&source)
            .arg(listen.to_string())
            .args([
                "--transport",
                "quic",
                "--no-delta",
                "--bwlimit",
                QUIC_HOLD_BWLIMIT,
            ])
            .args(["--server-name", "localhost", "--ca"])
            .arg(&tls.ca),
    );
    let staging_before = wait_for_entry(&dest, QUIC_STAGING_PREFIX, IN_FLIGHT_LIMIT);
    let sending = sender.is_running();
    if staging_before.is_empty() || !sending {
        sender.kill();
        panic!(
            "the QUIC transfer was not in flight (staging {staging_before:?}, sender running \
             {sending}) in {}: {:?}\nsender stderr: {:?}",
            dest.display(),
            dir_entries(&dest),
            sender.all_lines(Pipe::Stderr)
        );
    }

    let stop = stop_atp(&mut daemon, Signal::SIGTERM, &dest);
    sender.kill();
    let problems = atp_stop_problems(&stop, Signal::SIGTERM, AtpTransport::Quic, listen, 1, 1);
    assert!(
        problems.is_empty(),
        "{problems:#?}\nstaging before the signal: {staging_before:?}\nscratch root: {}\n\
         stdout: {:#?}\nstderr: {:#?}",
        root.display(),
        stop.stdout,
        stop.stderr
    );
}

// ─── atpd ────────────────────────────────────────────────────────────────────

/// `atpd` with a scratch config path (absent: defaults), PID file and no color.
fn atpd_command(root: &Path) -> Command {
    let mut command = Command::new(ATPD_BIN);
    command
        .env("NO_COLOR", "1")
        .arg("--config")
        .arg(root.join("absent-config.toml"))
        .arg("--pid-file")
        .arg(root.join("atpd.pid"));
    command
}

/// Runs `atpd init --new-identity` and returns the daemon's data directory.
fn init_atpd(root: &Path) -> PathBuf {
    let data = root.join("atpd-data");
    let output = atpd_command(root)
        .args(["init", "--new-identity", "--data-dir"])
        .arg(&data)
        .output()
        .expect("run atpd init");
    assert!(
        output.status.success(),
        "atpd init failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    data
}

/// Starts `atpd start` on loopback ports with `extra` arguments.
fn start_atpd(root: &Path, data: &Path, extra: &[String]) -> Process {
    Process::spawn(
        "atpd start",
        atpd_command(root)
            .args(["start", "--bind", "127.0.0.1:0"])
            .args(["--diagnostics-bind", "127.0.0.1:0", "--data-dir"])
            .arg(data)
            .args(extra),
    )
}

/// The `bind_addr=` field of a tracing line that contains `marker`.
fn tracing_bind_addr(line: &str, marker: &str) -> Option<SocketAddr> {
    if !line.contains(marker) {
        return None;
    }
    line.split_whitespace().find_map(|part| {
        let value = part.strip_prefix("bind_addr=")?;
        value.trim_end_matches(',').parse().ok()
    })
}

/// Waits until a signal reaches atpd's handler; returns its TCP listener.
///
/// atpd installs its signal listener after its transfer listeners have bound
/// and before it starts the diagnostics endpoint, so the diagnostics line
/// means that a signal now takes the daemon's stop path. A listener logs its
/// own `bound and accepting` line after it reports the bind, so the lines can
/// arrive in any order.
fn atpd_ready(daemon: &mut Process, quic: bool) -> SocketAddr {
    let mut transfer = None;
    let mut quic_bound = !quic;
    let mut diagnostics = false;
    let ready = daemon.wait_for(Pipe::Stdout, READY_LIMIT, |line| {
        if transfer.is_none() {
            transfer = tracing_bind_addr(line, "ATP transfer listener bound and accepting");
        }
        quic_bound |= line.contains("ATP QUIC transfer listener bound and accepting");
        diagnostics |= line.contains("ATP daemon diagnostics endpoint started");
        transfer.filter(|_| quic_bound && diagnostics)
    });
    ready.unwrap_or_else(|| {
        panic!(
            "atpd did not report its listeners (QUIC: {quic}) and diagnostics within \
             {READY_LIMIT:?}; stdout: {:?}; stderr: {:?}",
            daemon.stdout_seen, daemon.stderr_seen
        )
    })
}

/// What an `atpd` daemon left behind after a signal.
struct AtpdStop {
    status: Option<ExitStatus>,
    log: Vec<String>,
    inbox_entries: Vec<String>,
}

fn stop_atpd(daemon: &mut Process, signal: Signal, inbox: &Path) -> AtpdStop {
    daemon.signal(signal);
    let status = daemon.wait_exit(EXIT_LIMIT);
    let mut log = daemon.all_lines(Pipe::Stdout);
    log.extend(daemon.all_lines(Pipe::Stderr));
    AtpdStop {
        status,
        log,
        inbox_entries: dir_entries(inbox),
    }
}

/// The problems with an `atpd` stop.
///
/// It must exit 0, its TCP listener must return through its drain, the drain
/// summary must count `aborted` receives, exactly `failed_lines` failed
/// transfers must be logged, and the inbox must stay empty.
fn atpd_stop_problems(stop: &AtpdStop, aborted: u64, failed_lines: usize) -> Vec<String> {
    let mut problems = Vec::new();
    if stop.status.and_then(|status| status.code()) != Some(0) {
        problems.push(format!(
            "SIGTERM must stop atpd with exit 0; got {}",
            describe_status(stop.status)
        ));
    }
    for (needle, wanted) in [
        (ATPD_LISTENER_DRAINED, 1),
        (ATPD_LISTENERS_DRAINED, 1),
        (ATPD_STOPPED, 1),
        (ATPD_FAILED, failed_lines),
        (ATPD_QUIC_FAILED, 0),
        (ATPD_COMMITTED, 0),
    ] {
        let found = count_containing(&stop.log, needle);
        if found != wanted {
            problems.push(format!(
                "the log must carry `{needle}` {wanted} time(s); found {found}"
            ));
        }
    }
    let summary = format!("aborted_receives={aborted}");
    let summaries = stop
        .log
        .iter()
        .filter(|line| line.contains(ATPD_LISTENERS_DRAINED) && line.contains(&summary))
        .count();
    if summaries != 1 {
        problems.push(format!(
            "the drain summary must report `{summary}`; matching lines: {summaries}"
        ));
    }
    let staging = with_prefix(&stop.inbox_entries, ".atp-");
    if !staging.is_empty() {
        problems.push(format!(
            "staging directories survived the stop: {staging:?}"
        ));
    }
    if !stop.inbox_entries.is_empty() {
        problems.push(format!(
            "the inbox must stay empty: {:?}",
            stop.inbox_entries
        ));
    }
    problems
}

/// An idle atpd stops on SIGTERM: its listener returns, exit 0.
///
/// A probe connection that closes at once is reported as a failed transfer
/// before the signal, which proves the TCP listener runs and is back in its
/// 60 s idle accept wait.
#[test]
fn atpd_sigterm_idle_drains_the_listener_and_exits_zero() {
    let root = scratch_root("atpd-idle");
    let data = init_atpd(&root);
    let inbox = data.join("inbox");
    let mut daemon = start_atpd(&root, &data, &[]);
    let listen = atpd_ready(&mut daemon, false);
    drop(TcpStream::connect(listen).expect("probe atpd's transfer listener"));
    let probed = daemon.wait_for(Pipe::Stdout, READY_LIMIT, |line| {
        line.contains(ATPD_FAILED).then_some(())
    });
    assert!(
        probed.is_some(),
        "atpd never reported the probe connection; stdout so far: {:?}",
        daemon.stdout_seen
    );

    let stop = stop_atpd(&mut daemon, Signal::SIGTERM, &inbox);
    let problems = atpd_stop_problems(&stop, 0, 1);
    assert!(
        problems.is_empty(),
        "{problems:#?}\nscratch root: {}\nlog: {:#?}",
        root.display(),
        stop.log
    );
}

/// SIGTERM during a transfer to atpd drains and reports the receive.
///
/// The parked sender and the receive's staging directory are witnessed before
/// the signal.
#[test]
fn atpd_sigterm_mid_transfer_reports_the_aborted_receive() {
    let root = scratch_root("atpd-in-flight");
    let data = init_atpd(&root);
    let inbox = data.join("inbox");
    let source = write_payload(&root, ENTRY_BYTES);
    let mut daemon = start_atpd(&root, &data, &[]);
    let listen = atpd_ready(&mut daemon, false);
    let sender = ParkedSender::start(listen, source);
    let (sent, total) = sender.wait_parked();
    assert!(
        0 < sent && sent < total,
        "the sender must park mid-transfer, at {sent} of {total} bytes"
    );
    let staging_before = wait_for_entry(&inbox, TCP_STAGING_PREFIX, IN_FLIGHT_LIMIT);
    assert!(
        !staging_before.is_empty(),
        "the in-flight receive never put a staging directory into {}: {:?}",
        inbox.display(),
        dir_entries(&inbox)
    );

    let stop = stop_atpd(&mut daemon, Signal::SIGTERM, &inbox);
    let send_outcome = sender.finish();
    let mut problems = atpd_stop_problems(&stop, 1, 1);
    if send_outcome == Ok(true) {
        problems.push("the sender reported a committed receipt for an aborted transfer".into());
    }
    assert!(
        problems.is_empty(),
        "{problems:#?}\nstaging before the signal: {staging_before:?}\nsender outcome: \
         {send_outcome:?}\nscratch root: {}\nlog: {:#?}",
        root.display(),
        stop.log
    );
}

/// An idle atpd with its QUIC listener stops on SIGTERM.
///
/// Both listeners return, and the QUIC listener's interrupted idle accept is
/// not reported as a failed transfer.
#[test]
fn atpd_with_quic_sigterm_idle_stops_both_listeners() {
    let root = scratch_root("atpd-quic-idle");
    let data = init_atpd(&root);
    let inbox = data.join("inbox");
    let tls = write_tls_files(&root);
    let quic = [
        "--enable-quic".to_string(),
        "--quic-server-cert".to_string(),
        tls.cert.display().to_string(),
        "--quic-server-key".to_string(),
        tls.key.display().to_string(),
    ];
    let mut daemon = start_atpd(&root, &data, &quic);
    let _listen = atpd_ready(&mut daemon, true);

    let stop = stop_atpd(&mut daemon, Signal::SIGTERM, &inbox);
    let mut problems = atpd_stop_problems(&stop, 0, 0);
    let rebinds = count_containing(&stop.log, "failed to rebind");
    if rebinds != 0 {
        problems.push(format!(
            "the QUIC listener must not try to rebind: {rebinds}"
        ));
    }
    assert!(
        problems.is_empty(),
        "{problems:#?}\nscratch root: {}\nlog: {:#?}",
        root.display(),
        stop.log
    );
}
