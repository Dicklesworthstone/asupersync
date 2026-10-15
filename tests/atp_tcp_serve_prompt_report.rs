//! `transport_tcp::serve` reports a finished transfer without waiting for the
//! next client.
//!
//! `serve` is the persistent accept loop behind `asupersync atp serve`, the
//! `atp` binary's serve mode, and `atpd`. Their "committed transfer" log lines
//! and the daemon's transfer counters come from its `on_result` callback. The
//! loop used to report finished receive tasks only between accepts, so a
//! transfer that completed while no other client connected stayed unreported
//! until the accept timeout (60 s by default) expired, and was never reported
//! if the server stopped first. This gate runs one real transfer over loopback
//! with no second client and requires the report well inside the accept
//! timeout.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_tcp::{
    ReceiveReport, SendReport, TransferConfig, TransportError, send_path, serve,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::CancelReason;

/// Accept timeout given to the server. Without another client, the old loop
/// could not report a finished transfer before this elapsed.
const SERVE_ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long after the sender holds its receipt the report may take. The loop
/// reports within about 100 ms; the old loop needed `SERVE_ACCEPT_TIMEOUT`.
const REPORT_DEADLINE: Duration = Duration::from_secs(10);
/// Bound on the server's startup, so a broken server fails instead of hanging.
const STARTUP_DEADLINE: Duration = Duration::from_secs(30);
/// Bound on the server's exit after its context is cancelled. It is below
/// `SERVE_ACCEPT_TIMEOUT`, so an exit that merely waited out the accept timeout
/// fails too.
const STOP_DEADLINE: Duration = Duration::from_secs(20);

type ServeOutcome = Result<ReceiveReport, TransportError>;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "atp_tcp_serve_report_{label}_{}_{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create test temp root");
    // Canonicalize so no ancestor is an OS-level symlink (macOS
    // /var -> /private/var): the ATP destination traversal defense
    // correctly rejects symlinked ancestors.
    root.canonicalize().expect("canonicalize test temp root")
}

fn preserve_artifact_root(root: &Path) {
    // Keep loopback artifacts for failure forensics and avoid directory deletion
    // from agent-owned test runs.
    let _ = root;
}

fn run_sender(addr: SocketAddr, source: PathBuf) -> Result<SendReport, TransportError> {
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("sender runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("sender cx");
        send_path(&cx, addr, &source, TransferConfig::default(), "sender").await
    }))
}

async fn bind_loopback() -> Result<(TcpListener, SocketAddr), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("bind 127.0.0.1:0: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("listener address: {err}"))?;
    Ok((listener, addr))
}

/// Binds a loopback listener, publishes its address, runs `serve` as a child
/// task until `stop_flag` is set, then cancels that task's context and joins
/// it. Returns the join result, rendered for diagnostics.
async fn serve_until_stopped(
    dest_dir: PathBuf,
    config: TransferConfig,
    addr_tx: mpsc::Sender<Result<SocketAddr, String>>,
    result_tx: mpsc::Sender<ServeOutcome>,
    stop_flag: Arc<AtomicBool>,
) -> Result<String, String> {
    let cx = Cx::current().ok_or_else(|| "no receiver cx".to_string())?;
    let (listener, addr) = match bind_loopback().await {
        Ok(bound) => bound,
        Err(err) => {
            let _ = addr_tx.send(Err(err.clone()));
            return Err(err);
        }
    };
    let _ = addr_tx.send(Ok(addr));
    let mut serving = cx
        .spawn(move |child| async move {
            serve(
                &child,
                listener,
                dest_dir,
                config,
                "receiver".to_string(),
                move |outcome| {
                    let _ = result_tx.send(outcome);
                },
            )
            .await
        })
        .map_err(|err| format!("spawn the serve loop: {err}"))?;
    while !stop_flag.load(Ordering::Acquire) {
        asupersync::time::sleep(cx.now(), Duration::from_millis(10)).await;
    }
    serving.abort_with_reason(CancelReason::user("test stops the serve loop"));
    let joined = serving.join(&cx).await;
    Ok(format!("{joined:?}"))
}

/// A persistent `serve` loop on its own runtime and thread, like a separate
/// `atp serve` process. Every `on_result` call lands on `results`.
struct Server {
    addr: SocketAddr,
    results: mpsc::Receiver<ServeOutcome>,
    stop_requested: Arc<AtomicBool>,
    exited: mpsc::Receiver<Result<String, String>>,
    worker: thread::JoinHandle<()>,
}

impl Server {
    fn start(dest_dir: PathBuf, config: TransferConfig) -> Self {
        let (addr_tx, addr_rx) = mpsc::channel::<Result<SocketAddr, String>>();
        let (result_tx, results) = mpsc::channel::<ServeOutcome>();
        let (exit_tx, exited) = mpsc::channel::<Result<String, String>>();
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop_requested);
        let worker = thread::spawn(move || {
            let runtime = RuntimeBuilder::multi_thread()
                .build()
                .expect("receiver runtime");
            let exit = runtime.block_on(runtime.handle().spawn(serve_until_stopped(
                dest_dir, config, addr_tx, result_tx, stop_flag,
            )));
            drop(runtime);
            let _ = exit_tx.send(exit);
        });
        let addr = addr_rx
            .recv_timeout(STARTUP_DEADLINE)
            .expect("server reports its listener address")
            .expect("server binds a loopback listener");
        Self {
            addr,
            results,
            stop_requested,
            exited,
            worker,
        }
    }

    /// Cancels the serve loop's context and waits, bounded, for it to exit.
    /// Also returns every `on_result` call that had not been received yet.
    fn stop(self) -> (Result<String, String>, Vec<ServeOutcome>) {
        self.stop_requested.store(true, Ordering::Release);
        let exit = match self.exited.recv_timeout(STOP_DEADLINE) {
            Ok(exit) => exit,
            Err(err) => {
                return (
                    Err(format!(
                        "serve loop did not exit within {STOP_DEADLINE:?}: {err}"
                    )),
                    Vec::new(),
                );
            }
        };
        let exit = match self.worker.join() {
            Ok(()) => exit,
            Err(_) => Err("receiver thread panicked".to_string()),
        };
        (exit, self.results.try_iter().collect())
    }
}

#[test]
fn serve_reports_a_finished_transfer_without_another_client_connecting() {
    let root = unique_tmp("single");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).expect("create source dir");
    std::fs::create_dir_all(&dst_dir).expect("create destination dir");
    let payload: Vec<u8> = (0..200_003u32)
        .map(|index| u8::try_from(index % 251).expect("below 251"))
        .collect();
    let src_file = src_dir.join("payload.bin");
    std::fs::write(&src_file, &payload).expect("write source file");

    let config = TransferConfig {
        accept_timeout: SERVE_ACCEPT_TIMEOUT,
        ..TransferConfig::default()
    };
    let server = Server::start(dst_dir.clone(), config);
    let send = run_sender(server.addr, src_file);
    // The sender holds the receiver's receipt, so the receive task has
    // finished or is about to. Nothing else connects: only `serve` itself can
    // deliver the report now.
    let first = server.results.recv_timeout(REPORT_DEADLINE);
    let (stopped, later) = server.stop();

    let send = send.expect("send succeeds");
    assert!(send.receipt.committed, "sender receipt must be committed");
    let report = match first {
        Ok(Ok(report)) => report,
        Ok(Err(err)) => {
            panic!("serve reported a failure instead of the committed transfer: {err}")
        }
        Err(err) => panic!(
            "serve did not report the finished transfer within {REPORT_DEADLINE:?} of the \
             sender's receipt ({err}): the accept loop drains finished receives only between \
             accepts and was still waiting out its {SERVE_ACCEPT_TIMEOUT:?} accept timeout"
        ),
    };
    assert!(report.committed, "the reported transfer must be committed");
    assert_eq!(report.transfer_id, send.transfer_id);
    assert_eq!(report.files, 1);
    assert_eq!(report.bytes_received, payload.len() as u64);
    let got = std::fs::read(dst_dir.join("payload.bin")).expect("received file");
    assert!(got == payload, "received bytes must be identical");
    assert!(
        stopped.is_ok(),
        "cancelling the serve loop must stop it: {stopped:?}"
    );
    // One transfer, one report. Stopping the loop is not a transfer failure,
    // so the cancelled accept must not reach on_result (the CLI would print
    // "atp: transfer failed" and atpd would count a failure on every stop).
    assert!(
        later.is_empty(),
        "serve reported results after the transfer: {later:?}"
    );

    preserve_artifact_root(&root);
}
