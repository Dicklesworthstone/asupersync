//! `atp serve` stops through its drain path on SIGINT and SIGTERM
//! (br-asupersync-ylvfod).
//!
//! Each test runs the real `asupersync` binary as the daemon and signals it.
//! The first signal must cancel the serve loop: in-flight receives are aborted
//! and drained, so no `.atp-staging-*` directory survives and the aborted
//! transfer is reported; a final `stopped` status line follows `listening`;
//! the process exits 0. Before the fix the signal's default action killed the
//! daemon (no exit code, terminating signal 15 or 2, staging left behind).

use asupersync::cx::Cx;
use asupersync::net::atp::transport_common::FilterSet;
use asupersync::net::atp::transport_tcp::{TransferConfig, send_path_filtered};
use asupersync::runtime::RuntimeBuilder;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const ASUPERSYNC_BIN: &str = env!("CARGO_BIN_EXE_asupersync");
/// Upper bound for the daemon to bind and print its `listening` line, and for
/// it to report a probe connection.
const READY_LIMIT: Duration = Duration::from_secs(30);
/// Upper bound for the daemon to exit after the first signal.
///
/// It is well below serve()'s 60 s idle accept wait, so an idle daemon that
/// exits in time was woken by the signal rather than by its accept timeout.
const EXIT_LIMIT: Duration = Duration::from_secs(20);
/// Upper bound for the daemon's pipes to close once the process has exited.
const PIPE_LIMIT: Duration = Duration::from_secs(10);
/// Upper bound for the parked sender to reach its park point, and for the
/// receive it feeds to put a staging directory into the inbox.
const IN_FLIGHT_LIMIT: Duration = Duration::from_secs(30);
/// Longest the sender stays parked if the test never releases it.
const SENDER_PARK_LIMIT: Duration = Duration::from_secs(120);
/// Upper bound for the released sender to finish (it fails: its peer is gone).
/// It exceeds the 60 s transport idle timeout, the sender's worst case.
const SENDER_FINISH_LIMIT: Duration = Duration::from_secs(90);
/// Size of each of the two payload files: four 256 KiB ATP-over-TCP chunks.
const ENTRY_BYTES: usize = 1024 * 1024;
const STAGING_PREFIX: &str = ".atp-staging-";
const FAILED_PREFIX: &str = "atp: transfer failed: ";
const COMMITTED_PREFIX: &str = "atp: committed transfer ";

/// A fresh scratch root with no symlinked ancestor.
///
/// macOS `$TMPDIR` lives under `/var -> /private/var`, and the ATP receiver
/// rejects a destination with a symlinked ancestor. Roots are kept for
/// forensics, like the other ATP loopback tests.
fn scratch_root(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "asupersync-atp-serve-signal-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create scratch root");
    root.canonicalize().expect("canonicalize scratch root")
}

/// Every entry of `dir` as a file name, sorted.
fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| {
            entry
                .expect("read inbox entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn staging_entries(inbox: &Path) -> Vec<String> {
    dir_entries(inbox)
        .into_iter()
        .filter(|name| name.starts_with(STAGING_PREFIX))
        .collect()
}

fn count_prefixed(lines: &[String], prefix: &str) -> usize {
    lines.iter().filter(|line| line.starts_with(prefix)).count()
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

/// Forwards each line read from `pipe` to the returned receiver.
fn line_channel(pipe: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    receiver
}

/// The `asupersync atp serve` child process and its output.
///
/// Dropping it kills and reaps a child that is still running, so no test path
/// leaves a daemon behind.
struct Daemon {
    child: Option<Child>,
    stdout: mpsc::Receiver<String>,
    stderr: mpsc::Receiver<String>,
    stderr_seen: Vec<String>,
    inbox: PathBuf,
}

impl Daemon {
    /// Starts `asupersync --format stream-json atp serve` on an OS-chosen
    /// loopback port with `data_dir` as its data directory.
    fn start(data_dir: &Path) -> Self {
        let mut child = Command::new(ASUPERSYNC_BIN)
            .args(["--format", "stream-json", "atp", "serve"])
            .args(["--listen", "127.0.0.1:0", "--data-dir"])
            .arg(data_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start asupersync atp serve");
        let out = child.stdout.take();
        let err = child.stderr.take();
        let (Some(out), Some(err)) = (out, err) else {
            let _ = child.kill();
            let _ = child.wait();
            unreachable!("both daemon pipes were requested");
        };
        Self {
            child: Some(child),
            stdout: line_channel(out),
            stderr: line_channel(err),
            stderr_seen: Vec::new(),
            inbox: data_dir.join("inbox"),
        }
    }

    /// Reads the `listening` line and returns the bound loopback address.
    fn listening(&self) -> SocketAddr {
        let line = self
            .stdout
            .recv_timeout(READY_LIMIT)
            .unwrap_or_else(|error| {
                panic!("atp serve printed no status line within {READY_LIMIT:?}: {error}")
            });
        let status: Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("status line {line:?} is not JSON: {error}"));
        assert_eq!(status["message"], "listening", "{line}");
        let address: SocketAddr = status["listen_address"]
            .as_str()
            .and_then(|text| text.parse().ok())
            .unwrap_or_else(|| panic!("status line {line:?} has no socket address"));
        assert!(address.ip().is_loopback() && address.port() != 0, "{line}");
        // The v0.4.x `listening` line keeps its exact shape.
        assert_eq!(
            line,
            format!(r#"{{"message":"listening","listen_address":"{address}"}}"#)
        );
        address
    }

    /// Reads stderr until a line starts with `prefix`; false if none did in time.
    fn wait_for_stderr(&mut self, prefix: &str, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while let Ok(line) = self
            .stderr
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            let found = line.starts_with(prefix);
            self.stderr_seen.push(line);
            if found {
                return true;
            }
        }
        false
    }

    fn signal(&self, signal: Signal) {
        let id = self.child.as_ref().expect("daemon child is owned").id();
        let pid = Pid::from_raw(i32::try_from(id).expect("daemon PID fits pid_t"));
        kill(pid, signal).unwrap_or_else(|error| panic!("send {signal} to atp serve: {error}"));
    }

    /// Waits up to `limit` for the daemon to exit.
    ///
    /// Returns `None` if it was still running; it is then killed and reaped, so
    /// its output can still be collected.
    fn wait_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            let child = self.child.as_mut().expect("daemon child is owned");
            if let Some(status) = child.try_wait().expect("poll atp serve") {
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

    /// Kills and reaps the daemon if it has not been reaped yet.
    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Stdout lines after `listening`, read until the pipe closes.
    fn remaining_stdout(&self) -> Vec<String> {
        let mut lines = Vec::new();
        drain_lines(&self.stdout, &mut lines, "stdout");
        lines
    }

    /// Every stderr line, read until the pipe closes.
    fn all_stderr(&mut self) -> Vec<String> {
        let mut lines = std::mem::take(&mut self.stderr_seen);
        drain_lines(&self.stderr, &mut lines, "stderr");
        lines
    }
}

impl Drop for Daemon {
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
                    "ylvfod-parked-sender",
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

/// Polls `inbox` until a staging directory appears; empty if none did.
fn wait_for_staging(inbox: &Path, limit: Duration) -> Vec<String> {
    let deadline = Instant::now() + limit;
    loop {
        let staging = if inbox.is_dir() {
            staging_entries(inbox)
        } else {
            Vec::new()
        };
        if !staging.is_empty() || Instant::now() >= deadline {
            return staging;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// An idle daemon stops on `signal`: exit 0, a final `stopped` line, and an
/// empty inbox.
///
/// A probe connection that closes at once is accepted and reported as a failed
/// transfer before the signal. That report proves the serve loop is running and
/// back in its 60 s idle accept wait, so exiting within `EXIT_LIMIT` means the
/// signal woke that wait.
fn assert_idle_daemon_stops_cleanly(label: &str, signal: Signal) {
    let root = scratch_root(label);
    let mut daemon = Daemon::start(&root.join("data"));
    let listen = daemon.listening();

    drop(TcpStream::connect(listen).expect("probe the daemon's listener"));
    let probe_reported = daemon.wait_for_stderr(FAILED_PREFIX, READY_LIMIT);
    assert!(
        probe_reported,
        "atp serve never reported the probe connection; stderr so far: {:?}",
        daemon.all_stderr()
    );

    daemon.signal(signal);
    let status = daemon.wait_exit(EXIT_LIMIT);
    let after_listening = daemon.remaining_stdout();
    let stderr = daemon.all_stderr();

    let stopped = format!(r#"{{"message":"stopped","listen_address":"{listen}"}}"#);
    let mut problems = Vec::new();
    if status.and_then(|status| status.code()) != Some(0) {
        problems.push(format!(
            "{signal} must stop atp serve with exit 0; got {}",
            describe_status(status)
        ));
    }
    if after_listening.as_slice() != std::slice::from_ref(&stopped) {
        problems.push(format!(
            "stdout after `listening` must be exactly [{stopped}]; got {after_listening:?}"
        ));
    }
    let inbox_entries = dir_entries(&daemon.inbox);
    if !inbox_entries.is_empty() {
        problems.push(format!(
            "an idle daemon's inbox must stay empty: {inbox_entries:?}"
        ));
    }
    let failed = count_prefixed(&stderr, FAILED_PREFIX);
    let committed = count_prefixed(&stderr, COMMITTED_PREFIX);
    if failed != 1 || committed != 0 {
        problems.push(format!(
            "only the probe may be reported; got {failed} failed and {committed} committed \
             transfer line(s)"
        ));
    }
    assert!(
        problems.is_empty(),
        "{problems:#?}\nscratch root: {}\nstderr: {stderr:#?}",
        root.display()
    );
}

#[test]
fn sigterm_stops_an_idle_daemon_with_exit_zero_and_a_stopped_line() {
    assert_idle_daemon_stops_cleanly("idle-term", Signal::SIGTERM);
}

#[test]
fn sigint_stops_an_idle_daemon_with_exit_zero_and_a_stopped_line() {
    assert_idle_daemon_stops_cleanly("idle-int", Signal::SIGINT);
}

/// SIGTERM during a transfer aborts the receive through the drain: the daemon
/// exits 0, reports the aborted transfer, and leaves no staging directory.
///
/// The formerly failing state is witnessed before the signal: the sender is
/// parked mid-transfer and the receive's `.atp-staging-*` directory is on disk.
#[test]
fn sigterm_mid_transfer_drains_the_receive_and_leaves_no_staging_directory() {
    let root = scratch_root("in-flight");
    let source = root.join("payload");
    std::fs::create_dir_all(&source).expect("create payload directory");
    let bytes: Vec<u8> = (0..ENTRY_BYTES).map(|index| (index % 251) as u8).collect();
    std::fs::write(source.join("a.bin"), &bytes).expect("write first payload file");
    std::fs::write(source.join("b.bin"), &bytes).expect("write second payload file");

    let mut daemon = Daemon::start(&root.join("data"));
    let listen = daemon.listening();
    let sender = ParkedSender::start(listen, source);
    let (sent, total) = sender.wait_parked();
    assert!(
        0 < sent && sent < total,
        "the sender must park mid-transfer, at {sent} of {total} bytes"
    );
    let staging_before = wait_for_staging(&daemon.inbox, IN_FLIGHT_LIMIT);
    assert!(
        !staging_before.is_empty(),
        "the in-flight receive never put a staging directory into {}: {:?}",
        daemon.inbox.display(),
        dir_entries(&daemon.inbox)
    );

    daemon.signal(Signal::SIGTERM);
    let status = daemon.wait_exit(EXIT_LIMIT);
    let after_listening = daemon.remaining_stdout();
    let stderr = daemon.all_stderr();
    let inbox_entries = dir_entries(&daemon.inbox);
    let send_outcome = sender.finish();

    let stopped = format!(r#"{{"message":"stopped","listen_address":"{listen}"}}"#);
    let mut problems = Vec::new();
    if status.and_then(|status| status.code()) != Some(0) {
        problems.push(format!(
            "SIGTERM mid-transfer must stop atp serve with exit 0; got {}",
            describe_status(status)
        ));
    }
    if after_listening.as_slice() != std::slice::from_ref(&stopped) {
        problems.push(format!(
            "stdout after `listening` must be exactly [{stopped}]; got {after_listening:?}"
        ));
    }
    let staging_after: Vec<&String> = inbox_entries
        .iter()
        .filter(|name| name.starts_with(STAGING_PREFIX))
        .collect();
    if !staging_after.is_empty() {
        problems.push(format!(
            "staging directories survived the stop: {staging_after:?} (before the signal: \
             {staging_before:?})"
        ));
    }
    if !inbox_entries.is_empty() {
        problems.push(format!(
            "the aborted transfer must leave the inbox empty: {inbox_entries:?}"
        ));
    }
    let failed = count_prefixed(&stderr, FAILED_PREFIX);
    let committed = count_prefixed(&stderr, COMMITTED_PREFIX);
    if failed != 1 || committed != 0 {
        problems.push(format!(
            "the drained receive must be reported as exactly one failed transfer; got \
             {failed} failed and {committed} committed line(s)"
        ));
    }
    if send_outcome == Ok(true) {
        problems.push("the sender reported a committed receipt for an aborted transfer".into());
    }
    assert!(
        problems.is_empty(),
        "{problems:#?}\nsender outcome: {send_outcome:?}\nscratch root: {}\nstderr: {stderr:#?}",
        root.display()
    );
}
