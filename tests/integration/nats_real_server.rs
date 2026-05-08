//! Real NATS server integration tests — no protocol simulator.
//!
//! Bead: br-asupersync-shyxh0
//!
//! Run with:
//!     rch exec -- env REAL_NATS_TESTS=true NATS_URL=nats://127.0.0.1:4222 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_nats_real_server cargo test --test nats_real_server -- --nocapture
//!
//! Behavior:
//! - If `NATS_TEST_URL` or `NATS_URL` is set, connect to that broker after
//!   localhost / production safety checks.
//! - Otherwise, if `nats-server` is available on `PATH` (or via
//!   `NATS_SERVER_BIN`), auto-start a local `nats-server` fixture.
//! - If neither is available, the tests skip cleanly.
//!
//! Production safety guards block:
//!  * `NODE_ENV=production`
//!  * URLs containing `prod` or `production`
//!  * non-localhost hosts unless `ALLOW_NON_LOCALHOST_NATS=true`

#![cfg(test)]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::cx::Cx;
use asupersync::messaging::nats::{Message, NatsClient, NatsConfig, NatsError};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::timeout;

use std::future::Future;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct RealNatsConfig {
    external_url: Option<String>,
    nats_server_bin: Option<String>,
    enabled: bool,
    reason: Option<String>,
}

impl RealNatsConfig {
    fn from_env() -> Self {
        let external_url = std::env::var("NATS_TEST_URL")
            .ok()
            .or_else(|| std::env::var("NATS_URL").ok());
        let toggle = std::env::var("REAL_NATS_TESTS").unwrap_or_default() == "true";
        let allow_remote = std::env::var("ALLOW_NON_LOCALHOST_NATS").unwrap_or_default() == "true";
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();
        let nats_server_bin = resolve_nats_server_bin();

        let reason = if !toggle {
            Some("REAL_NATS_TESTS not set to 'true' — running unit-only".to_string())
        } else if node_env == "production" {
            Some("BLOCKED: NODE_ENV=production".to_string())
        } else if let Some(url) = &external_url {
            let url_lc = url.to_ascii_lowercase();
            let host_looks_local = url_lc.contains("://127.0.0.1")
                || url_lc.contains("://localhost")
                || url_lc.contains("://[::1]");
            let looks_prod = url_lc.contains("prod") || url_lc.contains("production");

            if looks_prod {
                Some(format!("BLOCKED: NATS URL looks like production: {url}"))
            } else if !host_looks_local && !allow_remote {
                Some(format!(
                    "BLOCKED: non-localhost NATS URL without ALLOW_NON_LOCALHOST_NATS=true: {url}"
                ))
            } else {
                None
            }
        } else if nats_server_bin.is_none() {
            Some(
                "REAL_NATS_TESTS=true but neither NATS_TEST_URL/NATS_URL nor nats-server binary is available"
                    .to_string(),
            )
        } else {
            None
        };

        Self {
            external_url,
            nats_server_bin,
            enabled: toggle && reason.is_none(),
            reason,
        }
    }
}

struct NatsTestLogger {
    suite: &'static str,
    test: &'static str,
    start: Instant,
    phase_count: AtomicU32,
}

impl NatsTestLogger {
    fn new(suite: &'static str, test: &'static str) -> Self {
        let me = Self {
            suite,
            test,
            start: Instant::now(),
            phase_count: AtomicU32::new(0),
        };
        me.line("test_start", &[]);
        me
    }

    fn line(&self, event: &str, fields: &[(&str, String)]) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut buf = format!(
            r#"{{"ts":{ts},"suite":"{}","test":"{}","event":"{event}""#,
            self.suite, self.test
        );
        for (key, value) in fields {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            buf.push_str(&format!(r#","{key}":"{escaped}""#));
        }
        buf.push('}');
        eprintln!("{buf}");
    }

    fn phase(&self, name: &str) {
        let phase_num = self.phase_count.fetch_add(1, Ordering::Relaxed);
        self.line(
            "phase",
            &[
                ("phase", name.to_string()),
                ("phase_num", phase_num.to_string()),
                ("elapsed_ms", self.start.elapsed().as_millis().to_string()),
            ],
        );
    }

    fn end(&self, result: &str) {
        self.line(
            "test_end",
            &[
                ("result", result.to_string()),
                ("duration_ms", self.start.elapsed().as_millis().to_string()),
            ],
        );
    }
}

struct LocalNatsServer {
    child: Child,
    url: String,
}

impl LocalNatsServer {
    fn start(bin: &str, log: &NatsTestLogger) -> Result<Self, String> {
        let port = reserve_local_port()?;
        let mut child = Command::new(bin)
            .args(["-a", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {bin}: {e}"))?;

        wait_for_local_server(&mut child, port)?;
        let url = format!("nats://127.0.0.1:{port}");
        log.line(
            "server_ready",
            &[("url", url.clone()), ("binary", bin.to_string())],
        );

        Ok(Self { child, url })
    }
}

impl Drop for LocalNatsServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn resolve_nats_server_bin() -> Option<String> {
    if let Ok(bin) = std::env::var("NATS_SERVER_BIN") {
        if command_reports_version(&bin) {
            return Some(bin);
        }
        return None;
    }

    let default = "nats-server";
    if command_reports_version(default) {
        Some(default.to_string())
    } else {
        None
    }
}

fn command_reports_version(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn reserve_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind local port: {e}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| format!("local_addr for reserved port: {e}"))
}

fn wait_for_local_server(child: &mut Child, port: u16) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let addr = format!("127.0.0.1:{port}");

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("poll nats-server status: {e}"))?
        {
            let mut stderr_text = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut stderr_text);
            }
            return Err(format!(
                "nats-server exited early with {status}: {}",
                stderr_text.trim()
            ));
        }

        if TcpStream::connect(&addr).is_ok() {
            thread::sleep(Duration::from_millis(100));
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for nats-server on {addr}"));
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn skip_if_disabled(cfg: &RealNatsConfig, test_name: &str) -> bool {
    if !cfg.enabled {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let reason = cfg.reason.as_deref().unwrap_or("disabled");
        eprintln!(
            r#"{{"ts":{ts},"event":"test_skipped","test":"{test_name}","reason":"{reason}"}}"#
        );
        return true;
    }
    false
}

fn start_local_nats_server(
    cfg: &RealNatsConfig,
    log: &NatsTestLogger,
) -> Result<Option<LocalNatsServer>, String> {
    if cfg.external_url.is_some() {
        return Ok(None);
    }

    let bin = cfg
        .nats_server_bin
        .as_deref()
        .ok_or_else(|| "enabled config without nats-server binary".to_string())?;
    LocalNatsServer::start(bin, log).map(Some)
}

fn active_nats_url(cfg: &RealNatsConfig, local_server: Option<&LocalNatsServer>) -> String {
    local_server.map_or_else(
        || {
            cfg.external_url
                .clone()
                .expect("external URL exists when no local server is started")
        },
        |server| server.url.clone(),
    )
}

fn unique_subject(prefix: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("asupersync.{prefix}.{ts}.{seq}")
}

fn spawn_runtime_task<F, T>(name: &'static str, task: F) -> thread::JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let runtime = RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("build runtime");
            runtime.block_on(runtime.handle().spawn(task))
        })
        .expect("spawn runtime thread")
}

#[test]
fn nats_real_pub_sub_roundtrip() {
    let cfg = RealNatsConfig::from_env();
    if skip_if_disabled(&cfg, "nats_real_pub_sub_roundtrip") {
        return;
    }

    let log = NatsTestLogger::new("nats_real", "nats_real_pub_sub_roundtrip");
    let local_server = start_local_nats_server(&cfg, &log).expect("start local nats-server");
    let active_url = active_nats_url(&cfg, local_server.as_ref());
    let subject = unique_subject("pubsub");
    let payload = b"hello-from-live-nats".to_vec();

    let (ready_tx, ready_rx) = mpsc::channel();
    let url = active_url.clone();
    let subject_for_sub = subject.clone();
    let subscriber = spawn_runtime_task("nats-real-subscriber", async move {
        let cx = Cx::current().expect("runtime task context");
        let mut client = NatsClient::connect(&cx, &url)
            .await
            .expect("connect subscriber");
        let mut sub = client
            .subscribe(&cx, &subject_for_sub)
            .await
            .expect("subscribe");
        ready_tx.send(()).expect("signal ready");
        client.process(&cx).await.expect("process subscription");
        let message = sub
            .next(&cx)
            .await
            .expect("next result")
            .expect("next message");
        client
            .unsubscribe(&cx, sub.sid())
            .await
            .expect("unsubscribe");
        client.close(&cx).await.expect("close subscriber");
        message
    });

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("subscriber ready");

    let url = active_url.clone();
    let subject_for_pub = subject.clone();
    let payload_for_pub = payload.clone();
    let publisher = spawn_runtime_task("nats-real-publisher", async move {
        let cx = Cx::current().expect("runtime task context");
        let mut client = NatsClient::connect(&cx, &url)
            .await
            .expect("connect publisher");
        client
            .publish(&cx, &subject_for_pub, &payload_for_pub)
            .await
            .expect("publish");
        client.close(&cx).await.expect("close publisher");
    });

    log.phase("join");
    publisher.join().expect("publisher thread");
    let message = subscriber.join().expect("subscriber thread");
    assert_eq!(message.subject, subject);
    assert_eq!(message.payload, payload);
    log.end("pass");
}

#[test]
fn nats_real_request_reply_roundtrip() {
    let cfg = RealNatsConfig::from_env();
    if skip_if_disabled(&cfg, "nats_real_request_reply_roundtrip") {
        return;
    }

    let log = NatsTestLogger::new("nats_real", "nats_real_request_reply_roundtrip");
    let local_server = start_local_nats_server(&cfg, &log).expect("start local nats-server");
    let active_url = active_nats_url(&cfg, local_server.as_ref());
    let subject = unique_subject("request");
    let payload = b"ping-live-nats".to_vec();

    let (ready_tx, ready_rx) = mpsc::channel();
    let url = active_url.clone();
    let subject_for_responder = subject.clone();
    let responder = spawn_runtime_task("nats-real-responder", async move {
        let cx = Cx::current().expect("runtime task context");
        let mut client = NatsClient::connect(&cx, &url)
            .await
            .expect("connect responder");
        let mut sub = client
            .subscribe(&cx, &subject_for_responder)
            .await
            .expect("subscribe responder");
        ready_tx.send(()).expect("signal ready");
        client.process(&cx).await.expect("process request");
        let request = sub
            .next(&cx)
            .await
            .expect("request next result")
            .expect("request message");
        let reply_to = request.reply_to.expect("reply subject");
        client
            .publish(&cx, &reply_to, &request.payload)
            .await
            .expect("publish reply");
        client
            .unsubscribe(&cx, sub.sid())
            .await
            .expect("unsubscribe responder");
        client.close(&cx).await.expect("close responder");
    });

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("responder ready");

    let url = active_url.clone();
    let subject_for_request = subject.clone();
    let payload_for_request = payload.clone();
    let response = spawn_runtime_task("nats-real-requester", async move {
        let cx = Cx::current().expect("runtime task context");
        let mut client = NatsClient::connect(&cx, &url)
            .await
            .expect("connect requester");
        let response = client
            .request(&cx, &subject_for_request, &payload_for_request)
            .await
            .expect("request");
        client.close(&cx).await.expect("close requester");
        response
    })
    .join()
    .expect("requester thread");

    responder.join().expect("responder thread");
    assert!(
        response.subject.starts_with("_INBOX."),
        "request replies must arrive on the generated inbox subject, got {}",
        response.subject
    );
    assert_eq!(response.payload, payload);
    log.end("pass");
}

#[test]
fn nats_real_queue_group_single_delivery() {
    let cfg = RealNatsConfig::from_env();
    if skip_if_disabled(&cfg, "nats_real_queue_group_single_delivery") {
        return;
    }

    let log = NatsTestLogger::new("nats_real", "nats_real_queue_group_single_delivery");
    let local_server = start_local_nats_server(&cfg, &log).expect("start local nats-server");
    let active_url = active_nats_url(&cfg, local_server.as_ref());
    let subject = unique_subject("queue");
    let queue = unique_subject("workers");
    let payload = b"queue-work-item".to_vec();

    let (ready_tx, ready_rx) = mpsc::channel();

    let spawn_worker = |name: &'static str| {
        let url = active_url.clone();
        let subject = subject.clone();
        let queue = queue.clone();
        let ready_tx = ready_tx.clone();
        spawn_runtime_task(name, async move {
            let cx = Cx::current().expect("runtime task context");
            let mut client = NatsClient::connect(&cx, &url)
                .await
                .expect("connect worker");
            let mut sub = client
                .queue_subscribe(&cx, &subject, &queue)
                .await
                .expect("queue subscribe");
            ready_tx.send(()).expect("worker ready");

            let received = match timeout(cx.now(), Duration::from_millis(750), async {
                client.process(&cx).await?;
                sub.next(&cx).await
            })
            .await
            {
                Ok(Ok(Some(message))) => Ok(Some(message)),
                Ok(Ok(None)) | Err(_) => Ok(None),
                Ok(Err(err)) => Err(err.to_string()),
            };

            if received.as_ref().ok().and_then(Option::as_ref).is_some() {
                client
                    .unsubscribe(&cx, sub.sid())
                    .await
                    .expect("unsubscribe worker");
            }
            let _ = client.close(&cx).await;
            received
        })
    };

    let worker_a = spawn_worker("nats-real-queue-a");
    let worker_b = spawn_worker("nats-real-queue-b");

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker a ready");
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker b ready");

    let url = active_url.clone();
    let subject_for_pub = subject.clone();
    let payload_for_pub = payload.clone();
    let publisher = spawn_runtime_task("nats-real-queue-publisher", async move {
        let cx = Cx::current().expect("runtime task context");
        let mut client = NatsClient::connect(&cx, &url)
            .await
            .expect("connect publisher");
        client
            .publish(&cx, &subject_for_pub, &payload_for_pub)
            .await
            .expect("publish queue message");
        client.close(&cx).await.expect("close publisher");
    });

    publisher.join().expect("publisher thread");
    let result_a = worker_a.join().expect("worker a thread");
    let result_b = worker_b.join().expect("worker b thread");
    let result_a = result_a.expect("worker a receive result");
    let result_b = result_b.expect("worker b receive result");

    let delivered = [result_a.as_ref(), result_b.as_ref()]
        .into_iter()
        .flatten()
        .collect::<Vec<&Message>>();
    assert_eq!(
        delivered.len(),
        1,
        "queue group must deliver to exactly one worker"
    );
    assert_eq!(delivered[0].payload, payload);
    assert_eq!(delivered[0].subject, subject);
    log.end("pass");
}

/// `request` against a subject with no subscribers must surface the server's
/// `NATS/1.0 503 No Responders` status header as `NatsError::Server` rather
/// than silently timing out.
///
/// asupersync advertises `headers:true` and `no_responders:true` in CONNECT
/// (src/messaging/nats.rs:1389-1393), so a 2.x+ `nats-server` answers any
/// inbox-style request to an unsubscribed subject with an HMSG status frame.
/// The HMSG parser changes from br-asupersync-6xjxd7 made
/// `reply_status_error` accept both the inline-status-line form
/// (`NATS/1.0 503 No Responders\r\n\r\n`) and the separate-`Status:`-header
/// form. Both unit tests for the parser use mock TCP listeners; this is the
/// roundtrip proof that asupersync's `NatsClient::request` correctly drives
/// the no-responders path against an actual `nats-server`.
#[test]
fn nats_real_request_no_responders_surfaces_503_status_error() {
    let cfg = RealNatsConfig::from_env();
    if skip_if_disabled(
        &cfg,
        "nats_real_request_no_responders_surfaces_503_status_error",
    ) {
        return;
    }

    let log = NatsTestLogger::new(
        "nats_real",
        "nats_real_request_no_responders_surfaces_503_status_error",
    );
    let local_server = start_local_nats_server(&cfg, &log).expect("start local nats-server");
    let active_url = active_nats_url(&cfg, local_server.as_ref());
    // No responder is ever registered for this subject — the request must
    // surface the 503 from the server, not time out.
    let subject = unique_subject("no-responders");
    let payload = b"unanswered-request".to_vec();

    log.phase("connect_and_request");
    let url = active_url.clone();
    let subject_for_request = subject.clone();
    let result = spawn_runtime_task("nats-real-no-responders-requester", async move {
        let cx = Cx::current().expect("runtime task context");
        // Tight per-request timeout: the server replies with 503 immediately,
        // so 2s is generous. If we ever fall off the no-responders path the
        // test fails fast with NatsError::Io(TimedOut) rather than hanging.
        let mut client = NatsClient::connect_with_config(
            &cx,
            NatsConfig {
                request_timeout: Duration::from_secs(2),
                ..NatsConfig::from_url(&url).expect("parse NATS URL")
            },
        )
        .await
        .expect("connect requester");
        let outcome = client.request(&cx, &subject_for_request, &payload).await;
        let _ = client.close(&cx).await;
        outcome
    })
    .join()
    .expect("requester thread");

    log.phase("assert_status_error");
    let err = match result {
        Ok(message) => panic!(
            "request to unsubscribed subject {subject} unexpectedly succeeded with reply on {} ({} bytes)",
            message.subject,
            message.payload.len()
        ),
        Err(err) => err,
    };

    let server_message = match err {
        NatsError::Server(message) => message,
        other => panic!("expected NatsError::Server with no-responders status info, got {other:?}"),
    };

    assert!(
        server_message.contains("503"),
        "server error must surface the 503 status code, got {server_message:?}"
    );
    let lc = server_message.to_ascii_lowercase();
    assert!(
        lc.contains("no responders") || lc.contains("noresponders"),
        "server error must surface the 'No Responders' description, got {server_message:?}"
    );

    log.end("pass");
}
