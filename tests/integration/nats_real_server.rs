//! Real NATS server integration tests — no protocol simulator.
//!
//! Bead: br-asupersync-shyxh0
//!
//! Run with:
//!     REAL_NATS_TESTS=true \
//!         NATS_URL=nats://127.0.0.1:4222 \
//!         cargo test --test nats_real_server -- --nocapture
//!
//! Production safety guards block:
//!  * `NODE_ENV=production`
//!  * URLs containing `prod` or `production`
//!  * non-localhost hosts unless `ALLOW_NON_LOCALHOST_NATS=true`

#![cfg(test)]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::cx::Cx;
use asupersync::messaging::nats::{Message, NatsClient};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::timeout;

use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct RealNatsConfig {
    url: String,
    enabled: bool,
    reason: Option<String>,
}

impl RealNatsConfig {
    fn from_env() -> Self {
        let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
        let toggle = std::env::var("REAL_NATS_TESTS").unwrap_or_default() == "true";
        let allow_remote = std::env::var("ALLOW_NON_LOCALHOST_NATS").unwrap_or_default() == "true";
        let node_env = std::env::var("NODE_ENV").unwrap_or_default();

        let url_lc = url.to_ascii_lowercase();
        let host_looks_local = url_lc.contains("://127.0.0.1")
            || url_lc.contains("://localhost")
            || url_lc.contains("://[::1]");
        let looks_prod = url_lc.contains("prod") || url_lc.contains("production");

        let reason = if !toggle {
            Some("REAL_NATS_TESTS not set to 'true' — running unit-only".to_string())
        } else if node_env == "production" {
            Some("BLOCKED: NODE_ENV=production".to_string())
        } else if looks_prod {
            Some(format!("BLOCKED: NATS_URL looks like production: {url}"))
        } else if !host_looks_local && !allow_remote {
            Some(format!(
                "BLOCKED: non-localhost NATS_URL without ALLOW_NON_LOCALHOST_NATS=true: {url}"
            ))
        } else {
            None
        };

        Self {
            url,
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
    let subject = unique_subject("pubsub");
    let payload = b"hello-from-live-nats".to_vec();

    let (ready_tx, ready_rx) = mpsc::channel();
    let url = cfg.url.clone();
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

    let url = cfg.url.clone();
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
    let subject = unique_subject("request");
    let payload = b"ping-live-nats".to_vec();

    let (ready_tx, ready_rx) = mpsc::channel();
    let url = cfg.url.clone();
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

    let url = cfg.url.clone();
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
    let subject = unique_subject("queue");
    let queue = unique_subject("workers");
    let payload = b"queue-work-item".to_vec();

    let (ready_tx, ready_rx) = mpsc::channel();

    let spawn_worker = |name: &'static str| {
        let url = cfg.url.clone();
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
                Ok(Ok(Some(message))) => Some(message),
                Ok(Ok(None)) | Err(_) => None,
                Ok(Err(err)) => panic!("worker receive failed: {err}"),
            };

            if received.is_some() {
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

    let url = cfg.url.clone();
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
