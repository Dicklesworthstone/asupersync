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
    AckPolicy, ConsumerConfig, DeliverPolicy, JetStreamContext, StorageType, StreamConfig,
};
use asupersync::messaging::nats::NatsClient;
use asupersync::runtime::RuntimeBuilder;

use serde_json::Value;
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

fn raw_stream_create_payload(stream: &str, subject: &str, duplicate_window: Duration) -> String {
    format!(
        "{{\"name\":\"{stream}\",\"subjects\":[\"{subject}\"],\"retention\":\"limits\",\"storage\":\"memory\",\"discard\":\"old\",\"num_replicas\":1,\"max_msgs\":64,\"duplicate_window\":{}}}",
        duplicate_window.as_nanos()
    )
}

fn raw_consumer_create_payload(
    stream: &str,
    consumer: &str,
    subject: &str,
    start_sequence: u64,
    ack_wait: Duration,
) -> String {
    format!(
        "{{\"stream_name\":\"{stream}\",\"config\":{{\"name\":\"{consumer}\",\"deliver_policy\":\"by_start_sequence\",\"opt_start_seq\":{start_sequence},\"ack_policy\":\"explicit\",\"ack_wait\":{},\"max_deliver\":4,\"max_ack_pending\":1000,\"filter_subject\":\"{subject}\"}}}}",
        ack_wait.as_nanos()
    )
}

fn raw_consumer_create_start_time_payload(
    stream: &str,
    consumer: &str,
    subject: &str,
    start_time: SystemTime,
    ack_wait: Duration,
) -> String {
    let start_time = chrono::DateTime::<chrono::Utc>::from(start_time)
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    format!(
        "{{\"stream_name\":\"{stream}\",\"config\":{{\"name\":\"{consumer}\",\"deliver_policy\":\"by_start_time\",\"opt_start_time\":\"{start_time}\",\"ack_policy\":\"explicit\",\"ack_wait\":{},\"max_deliver\":4,\"max_ack_pending\":1000,\"filter_subject\":\"{subject}\"}}}}",
        ack_wait.as_nanos()
    )
}

fn raw_pull_request_payload(batch: usize, expires: Duration) -> String {
    format!("{{\"batch\":{batch},\"expires\":{}}}", expires.as_nanos())
}

fn parse_pub_ack(payload: &[u8]) -> (u64, bool) {
    let json: Value = serde_json::from_slice(payload).expect("parse JetStream PubAck JSON");
    let seq = json.get("seq").and_then(Value::as_u64).expect("PubAck seq");
    let duplicate = json
        .get("duplicate")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    (seq, duplicate)
}

fn parse_ack_reply_sequence(reply_subject: &str) -> u64 {
    let parts: Vec<_> = reply_subject.split('.').collect();
    assert!(
        parts.len() >= 9 && parts[0] == "$JS" && parts[1] == "ACK",
        "expected JetStream ACK reply subject, got {reply_subject:?}"
    );
    parts[parts.len() - 4]
        .parse()
        .expect("parse stream sequence")
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

#[test]
fn jetstream_real_deliver_by_start_sequence_matches_raw_nats_first_delivery_tick135() {
    let cfg = RealJetStreamConfig::from_env();
    if skip_if_disabled(
        &cfg,
        "jetstream_real_deliver_by_start_sequence_matches_raw_nats_first_delivery_tick135",
    ) {
        return;
    }

    let log = Arc::new(JetStreamTestLogger::new(
        "jetstream_real",
        "jetstream_real_deliver_by_start_sequence_matches_raw_nats_first_delivery_tick135",
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

    let js_stream = unique_stream_name("jetstream_start_seq_js");
    let raw_stream = unique_stream_name("jetstream_start_seq_raw");
    let js_subject = unique_subject("start_seq_js");
    let raw_subject = unique_subject("start_seq_raw");
    let js_consumer = unique_name("start_seq_js");
    let raw_consumer = unique_name("start_seq_raw");
    let duplicate_window = Duration::from_secs(60);
    let ack_wait = Duration::from_secs(2);
    let pull_timeout = Duration::from_secs(2);
    let start_sequence = 2_u64;
    let message_ids = [
        ("msg-1", b"first".as_slice()),
        ("msg-2", b"second".as_slice()),
        ("msg-2", b"second-duplicate".as_slice()),
        ("msg-3", b"third".as_slice()),
    ];

    log.line(
        "fixture",
        &[
            ("url", url.clone()),
            ("js_stream", js_stream.clone()),
            ("raw_stream", raw_stream.clone()),
            ("js_subject", js_subject.clone()),
            ("raw_subject", raw_subject.clone()),
            ("start_sequence", start_sequence.to_string()),
        ],
    );

    let log_for_runtime = Arc::clone(&log);
    run_runtime("jetstream-real-start-sequence-parity", async move {
        let cx = Cx::current().expect("runtime task context");
        let client = NatsClient::connect(&cx, &url)
            .await
            .expect("connect JetStream client");
        let mut js = JetStreamContext::new(client);
        let mut raw = NatsClient::connect(&cx, &url)
            .await
            .expect("connect raw NATS client");

        js.create_stream(
            &cx,
            StreamConfig::new(&js_stream)
                .subjects(&[js_subject.as_str()])
                .storage(StorageType::Memory)
                .max_messages(64)
                .duplicate_window(duplicate_window),
        )
        .await
        .expect("create JetStream-managed stream");

        let raw_stream_payload =
            raw_stream_create_payload(&raw_stream, &raw_subject, duplicate_window);
        raw.request(
            &cx,
            &format!("$JS.API.STREAM.CREATE.{raw_stream}"),
            raw_stream_payload.as_bytes(),
        )
        .await
        .expect("create raw-reference stream");

        let mut js_pub_acks = Vec::new();
        let mut raw_pub_acks = Vec::new();
        for (msg_id, payload) in message_ids {
            let js_ack = js
                .publish_with_id(&cx, &js_subject, msg_id, payload)
                .await
                .expect("publish_with_id via JetStreamContext");
            js_pub_acks.push((js_ack.seq, js_ack.duplicate));

            let raw_ack = raw
                .request_with_headers(
                    &cx,
                    &raw_subject,
                    &[("Nats-Msg-Id", msg_id.as_bytes())],
                    payload,
                )
                .await
                .expect("publish_with_id via raw NATS request_with_headers");
            raw_pub_acks.push(parse_pub_ack(&raw_ack.payload));
        }
        assert_eq!(
            js_pub_acks,
            vec![(1, false), (2, false), (2, true), (3, false)],
            "JetStream publish_with_id dedup sequence drifted"
        );
        assert_eq!(
            raw_pub_acks, js_pub_acks,
            "raw NATS publish_with_id reference must observe the same dedup sequence ordering"
        );
        log_for_runtime.phase("messages_published");

        let consumer = js
            .create_consumer(
                &cx,
                &js_stream,
                ConsumerConfig::new(&js_consumer)
                    .deliver_policy(DeliverPolicy::ByStartSequence(start_sequence))
                    .ack_policy(AckPolicy::Explicit)
                    .ack_wait(ack_wait)
                    .filter_subject(&js_subject)
                    .max_deliver(4),
            )
            .await
            .expect("create JetStream consumer");

        let raw_consumer_payload = raw_consumer_create_payload(
            &raw_stream,
            &raw_consumer,
            &raw_subject,
            start_sequence,
            ack_wait,
        );
        raw.request(
            &cx,
            &format!("$JS.API.CONSUMER.CREATE.{raw_stream}.{raw_consumer}"),
            raw_consumer_payload.as_bytes(),
        )
        .await
        .expect("create raw-reference consumer");

        let mut js_messages = consumer
            .pull_with_timeout(js.client(), &cx, 1, pull_timeout)
            .await
            .expect("pull JetStream first message");
        assert_eq!(js_messages.len(), 1, "expected one JetStream message");
        let js_message = js_messages.pop().expect("JetStream first message");

        let raw_reply = raw
            .request(
                &cx,
                &format!("$JS.API.CONSUMER.MSG.NEXT.{raw_stream}.{raw_consumer}"),
                raw_pull_request_payload(1, pull_timeout).as_bytes(),
            )
            .await
            .expect("pull raw-reference first message");
        let raw_reply_subject = raw_reply
            .reply_to
            .clone()
            .expect("raw reference pull reply subject");
        let raw_first_sequence = parse_ack_reply_sequence(&raw_reply_subject);

        assert_eq!(
            js_message.sequence, raw_first_sequence,
            "DeliverByStartSequence must select the same first stream sequence as the raw NATS JetStream API"
        );
        assert_eq!(
            js_message.payload, raw_reply.payload,
            "DeliverByStartSequence must select the same first payload as the raw NATS JetStream API"
        );
        assert_eq!(
            js_message.sequence, start_sequence,
            "DeliverByStartSequence(2) must start with stream sequence 2 after msg-id dedup"
        );
        assert_eq!(
            js_message.payload,
            b"second".to_vec(),
            "duplicate msg-id publish must not shift first delivered ordering"
        );
        log_for_runtime.line(
            "first_delivery",
            &[
                ("sequence", js_message.sequence.to_string()),
                (
                    "payload",
                    String::from_utf8_lossy(&js_message.payload).into_owned(),
                ),
            ],
        );

        js_message
            .ack(js.client(), &cx)
            .await
            .expect("ack JetStream first message");
        raw.publish(&cx, &raw_reply_subject, b"+ACK")
            .await
            .expect("ack raw-reference first message");

        js.delete_consumer(&cx, &js_stream, &js_consumer)
            .await
            .expect("delete JetStream consumer");
        js.delete_stream(&cx, &js_stream)
            .await
            .expect("delete JetStream stream");
        raw.request(
            &cx,
            &format!("$JS.API.CONSUMER.DELETE.{raw_stream}.{raw_consumer}"),
            b"",
        )
        .await
        .expect("delete raw-reference consumer");
        raw.request(&cx, &format!("$JS.API.STREAM.DELETE.{raw_stream}"), b"")
            .await
            .expect("delete raw-reference stream");

        raw.close(&cx).await.expect("close raw client");
        js.client()
            .close(&cx)
            .await
            .expect("close JetStream client");
    });

    log.end("pass");
}

#[test]
fn jetstream_real_deliver_by_start_time_matches_raw_nats_first_delivery_tick137() {
    let cfg = RealJetStreamConfig::from_env();
    if skip_if_disabled(
        &cfg,
        "jetstream_real_deliver_by_start_time_matches_raw_nats_first_delivery_tick137",
    ) {
        return;
    }

    let log = Arc::new(JetStreamTestLogger::new(
        "jetstream_real",
        "jetstream_real_deliver_by_start_time_matches_raw_nats_first_delivery_tick137",
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

    let stream = unique_stream_name("jetstream_start_time");
    let subject = unique_subject("start_time");
    let js_consumer = unique_name("start_time_js");
    let raw_consumer = unique_name("start_time_raw");
    let duplicate_window = Duration::from_secs(60);
    let ack_wait = Duration::from_secs(2);
    let pull_timeout = Duration::from_secs(2);
    let inter_publish_gap = Duration::from_millis(150);

    log.line(
        "fixture",
        &[
            ("url", url.clone()),
            ("stream", stream.clone()),
            ("subject", subject.clone()),
            (
                "inter_publish_gap_ms",
                inter_publish_gap.as_millis().to_string(),
            ),
        ],
    );

    let log_for_runtime = Arc::clone(&log);
    run_runtime("jetstream-real-start-time-parity", async move {
        let cx = Cx::current().expect("runtime task context");
        let client = NatsClient::connect(&cx, &url)
            .await
            .expect("connect JetStream client");
        let mut js = JetStreamContext::new(client);
        let mut raw = NatsClient::connect(&cx, &url)
            .await
            .expect("connect raw NATS client");

        js.create_stream(
            &cx,
            StreamConfig::new(&stream)
                .subjects(&[subject.as_str()])
                .storage(StorageType::Memory)
                .max_messages(64)
                .duplicate_window(duplicate_window),
        )
        .await
        .expect("create stream");

        let first_ack = js
            .publish(&cx, &subject, b"first")
            .await
            .expect("publish first message");
        thread::sleep(inter_publish_gap);
        let start_time = SystemTime::now();
        thread::sleep(inter_publish_gap);
        let second_ack = js
            .publish(&cx, &subject, b"second")
            .await
            .expect("publish second message");
        let third_ack = js
            .publish(&cx, &subject, b"third")
            .await
            .expect("publish third message");
        assert_eq!(first_ack.seq, 1, "first publish sequence drifted");
        assert_eq!(second_ack.seq, 2, "second publish sequence drifted");
        assert_eq!(third_ack.seq, 3, "third publish sequence drifted");
        log_for_runtime.line(
            "publish_window",
            &[
                (
                    "start_time_epoch_ms",
                    start_time
                        .duration_since(UNIX_EPOCH)
                        .expect("post-epoch start_time")
                        .as_millis()
                        .to_string(),
                ),
                ("first_seq", first_ack.seq.to_string()),
                ("second_seq", second_ack.seq.to_string()),
                ("third_seq", third_ack.seq.to_string()),
            ],
        );

        let consumer = js
            .create_consumer(
                &cx,
                &stream,
                ConsumerConfig::new(&js_consumer)
                    .deliver_policy(DeliverPolicy::ByStartTime(start_time))
                    .ack_policy(AckPolicy::Explicit)
                    .ack_wait(ack_wait)
                    .filter_subject(&subject)
                    .max_deliver(4),
            )
            .await
            .expect("create JetStream start-time consumer");

        let raw_consumer_payload = raw_consumer_create_start_time_payload(
            &stream,
            &raw_consumer,
            &subject,
            start_time,
            ack_wait,
        );
        raw.request(
            &cx,
            &format!("$JS.API.CONSUMER.CREATE.{stream}.{raw_consumer}"),
            raw_consumer_payload.as_bytes(),
        )
        .await
        .expect("create raw-reference start-time consumer");

        let mut js_messages = consumer
            .pull_with_timeout(js.client(), &cx, 1, pull_timeout)
            .await
            .expect("pull JetStream start-time first message");
        assert_eq!(js_messages.len(), 1, "expected one JetStream message");
        let js_message = js_messages
            .pop()
            .expect("JetStream first start-time message");

        let raw_reply = raw
            .request(
                &cx,
                &format!("$JS.API.CONSUMER.MSG.NEXT.{stream}.{raw_consumer}"),
                raw_pull_request_payload(1, pull_timeout).as_bytes(),
            )
            .await
            .expect("pull raw-reference start-time first message");
        let raw_reply_subject = raw_reply
            .reply_to
            .clone()
            .expect("raw reference pull reply subject");
        let raw_first_sequence = parse_ack_reply_sequence(&raw_reply_subject);

        assert_eq!(
            js_message.sequence, raw_first_sequence,
            "DeliverByStartTime must select the same first stream sequence as the raw NATS JetStream API"
        );
        assert_eq!(
            js_message.payload, raw_reply.payload,
            "DeliverByStartTime must select the same first payload as the raw NATS JetStream API"
        );
        assert_eq!(
            js_message.sequence, 2,
            "DeliverByStartTime(start_time between first and second publish) must start with stream sequence 2"
        );
        assert_eq!(
            js_message.payload,
            b"second".to_vec(),
            "DeliverByStartTime must skip messages published before the start_time"
        );
        log_for_runtime.line(
            "first_delivery",
            &[
                ("sequence", js_message.sequence.to_string()),
                (
                    "payload",
                    String::from_utf8_lossy(&js_message.payload).into_owned(),
                ),
            ],
        );

        js_message
            .ack(js.client(), &cx)
            .await
            .expect("ack JetStream start-time first message");
        raw.publish(&cx, &raw_reply_subject, b"+ACK")
            .await
            .expect("ack raw-reference start-time first message");

        raw.request(
            &cx,
            &format!("$JS.API.CONSUMER.DELETE.{stream}.{raw_consumer}"),
            b"",
        )
        .await
        .expect("delete raw-reference consumer");
        js.delete_consumer(&cx, &stream, &js_consumer)
            .await
            .expect("delete JetStream consumer");
        js.delete_stream(&cx, &stream)
            .await
            .expect("delete JetStream stream");

        raw.close(&cx).await.expect("close raw client");
        js.client()
            .close(&cx)
            .await
            .expect("close JetStream client");
    });

    log.end("pass");
}
