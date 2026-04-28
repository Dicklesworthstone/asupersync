//! Real JetStream server integration tests — no protocol simulator.
//!
//! Bead: br-asupersync-vkoobf
//!
//! Run with:
//!     REAL_NATS_TESTS=true cargo test --test jetstream_real_server -- --nocapture
//!
//! Behavior:
//! - If `NATS_URL` is set, connect to that broker after localhost / production
//!   safety checks.
//! - Otherwise, if `nats-server` is available on `PATH` (or via
//!   `NATS_SERVER_BIN`), auto-start a local `nats-server -js` fixture.
//! - If neither is available, the tests skip cleanly.
//!
//! Production safety guards block:
//!  * `NODE_ENV=production`
//!  * URLs containing `prod` or `production`
//!  * non-localhost hosts unless `ALLOW_NON_LOCALHOST_NATS=true`

#![cfg(test)]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::cx::Cx;
use asupersync::messaging::jetstream::{
    AckPolicy, ConsumerConfig, JetStreamContext, StorageType, StreamConfig,
};
use asupersync::messaging::nats::NatsClient;
use asupersync::runtime::RuntimeBuilder;

use std::fs;
use std::future::Future;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct RealJetStreamConfig {
    external_url: Option<String>,
    nats_server_bin: Option<String>,
    enabled: bool,
    reason: Option<String>,
}

impl RealJetStreamConfig {
    fn from_env() -> Self {
        let external_url = std::env::var("NATS_URL").ok();
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
                Some(format!("BLOCKED: NATS_URL looks like production: {url}"))
            } else if !host_looks_local && !allow_remote {
                Some(format!(
                    "BLOCKED: non-localhost NATS_URL without ALLOW_NON_LOCALHOST_NATS=true: {url}"
                ))
            } else {
                None
            }
        } else if nats_server_bin.is_none() {
            Some(
                "REAL_NATS_TESTS=true but neither NATS_URL nor nats-server binary is available"
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

struct JetStreamTestLogger {
    suite: &'static str,
    test: &'static str,
    start: Instant,
    phase_count: AtomicU32,
}

impl JetStreamTestLogger {
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

struct LocalJetStreamServer {
    child: Child,
    url: String,
    storage_dir: PathBuf,
}

impl LocalJetStreamServer {
    fn start(bin: &str, log: &JetStreamTestLogger) -> Result<Self, String> {
        let port = reserve_local_port()?;
        let storage_dir = std::env::temp_dir().join(unique_name("jetstream_store"));
        fs::create_dir_all(&storage_dir)
            .map_err(|e| format!("create storage dir {}: {e}", storage_dir.display()))?;

        let mut child = Command::new(bin)
            .args(["-js", "-a", "127.0.0.1", "-p", &port.to_string(), "-sd"])
            .arg(&storage_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {bin}: {e}"))?;

        wait_for_local_server(&mut child, port)?;
        let url = format!("nats://127.0.0.1:{port}");
        log.line(
            "server_ready",
            &[
                ("url", url.clone()),
                ("storage_dir", storage_dir.display().to_string()),
                ("binary", bin.to_string()),
            ],
        );

        Ok(Self {
            child,
            url,
            storage_dir,
        })
    }
}

impl Drop for LocalJetStreamServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.storage_dir);
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

fn skip_if_disabled(cfg: &RealJetStreamConfig, test_name: &str) -> bool {
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

fn unique_name(prefix: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{ts}_{seq}")
}

fn unique_stream_name(prefix: &str) -> String {
    unique_name(prefix).to_ascii_uppercase()
}

fn unique_subject(prefix: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("asupersync.jetstream.{prefix}.{ts}.{seq}")
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

fn run_runtime<F, T>(name: &'static str, task: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    spawn_runtime_task(name, task)
        .join()
        .expect("runtime thread join")
}

#[test]
fn jetstream_real_create_consumer_pull_ack_roundtrip() {
    let cfg = RealJetStreamConfig::from_env();
    if skip_if_disabled(&cfg, "jetstream_real_create_consumer_pull_ack_roundtrip") {
        return;
    }

    let log = Arc::new(JetStreamTestLogger::new(
        "jetstream_real",
        "jetstream_real_create_consumer_pull_ack_roundtrip",
    ));

    let local_server = cfg
        .external_url
        .is_none()
        .then(|| {
            let bin = cfg
                .nats_server_bin
                .as_deref()
                .expect("enabled config without nats-server binary");
            LocalJetStreamServer::start(bin, &log)
        })
        .transpose()
        .expect("start local nats-server");
    let url = local_server.as_ref().map_or_else(
        || cfg.external_url.clone().unwrap(),
        |server| server.url.clone(),
    );

    let stream = unique_stream_name("jetstream_stream");
    let subject = unique_subject("orders");
    let consumer_name = unique_name("durable");
    let payload = b"jetstream-live-message".to_vec();

    log.line(
        "fixture",
        &[
            ("url", url.clone()),
            ("stream", stream.clone()),
            ("subject", subject.clone()),
            ("consumer", consumer_name.clone()),
        ],
    );

    let log_for_runtime = Arc::clone(&log);
    run_runtime("jetstream-real-roundtrip", async move {
        let cx = Cx::current().expect("runtime task context");
        let client = NatsClient::connect(&cx, &url)
            .await
            .expect("connect JetStream client");
        let mut js = JetStreamContext::new(client);

        let stream_info = js
            .create_stream(
                &cx,
                StreamConfig::new(&stream)
                    .subjects(&[subject.as_str()])
                    .storage(StorageType::Memory)
                    .max_messages(64),
            )
            .await
            .expect("create stream");
        log_for_runtime.phase("stream_created");
        log_for_runtime.line(
            "stream_created",
            &[
                ("stream", stream_info.config.name.clone()),
                (
                    "consumer_count",
                    stream_info.state.consumer_count.to_string(),
                ),
            ],
        );

        let publish_ack = js
            .publish(&cx, &subject, &payload)
            .await
            .expect("publish to stream");
        log_for_runtime.phase("message_published");
        log_for_runtime.line(
            "message_published",
            &[
                ("stream", publish_ack.stream.clone()),
                ("sequence", publish_ack.seq.to_string()),
            ],
        );

        let consumer = js
            .create_consumer(
                &cx,
                &stream,
                ConsumerConfig::new(&consumer_name)
                    .ack_policy(AckPolicy::Explicit)
                    .ack_wait(Duration::from_secs(2))
                    .filter_subject(&subject)
                    .max_deliver(4),
            )
            .await
            .expect("create durable consumer");
        log_for_runtime.phase("consumer_created");
        log_for_runtime.line(
            "consumer_created",
            &[("consumer", consumer.name().to_string())],
        );

        let mut messages = consumer
            .pull_with_timeout(js.client(), &cx, 1, Duration::from_secs(2))
            .await
            .expect("pull message");
        log_for_runtime.phase("message_pulled");
        assert_eq!(messages.len(), 1, "expected exactly one pulled message");

        let message = messages.pop().expect("pulled message");
        assert_eq!(message.payload, payload);
        assert_eq!(message.subject, subject);
        assert_eq!(message.delivered, 1);
        log_for_runtime.line(
            "message_pulled",
            &[
                ("sequence", message.sequence.to_string()),
                ("delivered", message.delivered.to_string()),
            ],
        );

        message.ack(js.client(), &cx).await.expect("ack message");
        log_for_runtime.phase("message_acked");

        js.delete_consumer(&cx, &stream, &consumer_name)
            .await
            .expect("delete consumer");
        js.delete_stream(&cx, &stream).await.expect("delete stream");
        js.client().close(&cx).await.expect("close client");
    });

    log.end("pass");
}

#[test]
fn jetstream_real_durable_consumer_redelivers_after_reconnect_without_ack() {
    let cfg = RealJetStreamConfig::from_env();
    if skip_if_disabled(
        &cfg,
        "jetstream_real_durable_consumer_redelivers_after_reconnect_without_ack",
    ) {
        return;
    }

    let log = Arc::new(JetStreamTestLogger::new(
        "jetstream_real",
        "jetstream_real_durable_consumer_redelivers_after_reconnect_without_ack",
    ));

    let local_server = cfg
        .external_url
        .is_none()
        .then(|| {
            let bin = cfg
                .nats_server_bin
                .as_deref()
                .expect("enabled config without nats-server binary");
            LocalJetStreamServer::start(bin, &log)
        })
        .transpose()
        .expect("start local nats-server");
    let url = local_server.as_ref().map_or_else(
        || cfg.external_url.clone().unwrap(),
        |server| server.url.clone(),
    );

    let stream = unique_stream_name("jetstream_redelivery");
    let subject = unique_subject("redelivery");
    let consumer_name = unique_name("durable");
    let payload = b"redeliver-me".to_vec();
    let ack_wait = Duration::from_millis(600);

    log.line(
        "fixture",
        &[
            ("url", url.clone()),
            ("stream", stream.clone()),
            ("subject", subject.clone()),
            ("consumer", consumer_name.clone()),
            ("ack_wait_ms", ack_wait.as_millis().to_string()),
        ],
    );

    let first_url = url.clone();
    let first_stream = stream.clone();
    let first_subject = subject.clone();
    let first_consumer = consumer_name.clone();
    let first_payload = payload.clone();

    let log_for_first_runtime = Arc::clone(&log);
    run_runtime("jetstream-real-first-delivery", async move {
        let cx = Cx::current().expect("runtime task context");
        let client = NatsClient::connect(&cx, &first_url)
            .await
            .expect("connect first JetStream client");
        let mut js = JetStreamContext::new(client);

        js.create_stream(
            &cx,
            StreamConfig::new(&first_stream)
                .subjects(&[first_subject.as_str()])
                .storage(StorageType::Memory)
                .max_messages(64),
        )
        .await
        .expect("create stream");

        js.publish(&cx, &first_subject, &first_payload)
            .await
            .expect("publish message");

        let consumer = js
            .create_consumer(
                &cx,
                &first_stream,
                ConsumerConfig::new(&first_consumer)
                    .ack_policy(AckPolicy::Explicit)
                    .ack_wait(ack_wait)
                    .filter_subject(&first_subject)
                    .max_deliver(4),
            )
            .await
            .expect("create durable consumer");

        let messages = consumer
            .pull_with_timeout(js.client(), &cx, 1, Duration::from_secs(2))
            .await
            .expect("initial pull");
        log_for_first_runtime.phase("first_delivery");
        assert_eq!(messages.len(), 1, "expected initial delivery");
        let message = &messages[0];
        assert_eq!(message.payload, first_payload);
        assert_eq!(message.delivered, 1);
        log_for_first_runtime.line(
            "first_delivery",
            &[
                ("sequence", message.sequence.to_string()),
                ("delivered", message.delivered.to_string()),
            ],
        );

        // Intentionally drop without ack to exercise durable redelivery after reconnect.
        drop(messages);
        js.client().close(&cx).await.expect("close first client");
    });

    log.phase("await_redelivery");
    thread::sleep(ack_wait + Duration::from_millis(700));

    let second_url = url.clone();
    let second_stream = stream.clone();
    let second_consumer = consumer_name.clone();
    let second_payload = payload.clone();

    let log_for_second_runtime = Arc::clone(&log);
    run_runtime("jetstream-real-redelivery", async move {
        let cx = Cx::current().expect("runtime task context");
        let client = NatsClient::connect(&cx, &second_url)
            .await
            .expect("connect second JetStream client");
        let mut js = JetStreamContext::new(client);

        let consumer = js
            .get_consumer(&cx, &second_stream, &second_consumer)
            .await
            .expect("recover durable consumer");

        let mut messages = consumer
            .pull_with_timeout(js.client(), &cx, 1, Duration::from_secs(3))
            .await
            .expect("redelivery pull");
        assert_eq!(messages.len(), 1, "expected redelivered message");

        let message = messages.pop().expect("redelivered message");
        assert_eq!(message.payload, second_payload);
        assert!(
            message.delivered >= 2,
            "redelivered message should increment delivery count, got {}",
            message.delivered
        );
        log_for_second_runtime.line(
            "message_redelivered",
            &[
                ("sequence", message.sequence.to_string()),
                ("delivered", message.delivered.to_string()),
            ],
        );

        message
            .ack(js.client(), &cx)
            .await
            .expect("ack redelivered message");
        js.delete_consumer(&cx, &second_stream, &second_consumer)
            .await
            .expect("delete consumer");
        js.delete_stream(&cx, &second_stream)
            .await
            .expect("delete stream");
        js.client().close(&cx).await.expect("close second client");
    });

    log.end("pass");
}
