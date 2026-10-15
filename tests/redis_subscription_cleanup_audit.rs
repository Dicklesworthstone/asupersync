//! Audit test for Redis streaming subscription cancellation.
//!
//! Dropping a Pub/Sub handle must fail closed so server-side subscriptions are
//! released instead of becoming orphaned.

use asupersync::messaging::redis::RedisClient;
use asupersync::test_utils::run_test_with_cx;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug)]
struct ScriptedRedisReport {
    commands: Vec<String>,
    transport_closed: bool,
}

fn write_hello3_ok(stream: &mut std::net::TcpStream) {
    stream
        .write_all(b"%1\r\n+proto\r\n:3\r\n")
        .expect("write HELLO 3 response");
    stream.flush().expect("flush HELLO 3 response");
}

fn write_subscribe_ack(stream: &mut std::net::TcpStream, remaining: i64) {
    let response = format!("*3\r\n$9\r\nsubscribe\r\n$7\r\ntestch1\r\n:{remaining}\r\n");
    stream
        .write_all(response.as_bytes())
        .expect("write SUBSCRIBE acknowledgment");
    stream.flush().expect("flush SUBSCRIBE acknowledgment");
}

fn write_unsubscribe_ack(stream: &mut std::net::TcpStream, remaining: i64) {
    let response = format!("*3\r\n$11\r\nunsubscribe\r\n$7\r\ntestch1\r\n:{remaining}\r\n");
    stream
        .write_all(response.as_bytes())
        .expect("write UNSUBSCRIBE acknowledgment");
    stream.flush().expect("flush UNSUBSCRIBE acknowledgment");
}

fn spawn_scripted_redis_server(
    listener: TcpListener,
    commands_received: Arc<Mutex<Vec<String>>>,
) -> (thread::JoinHandle<()>, mpsc::Receiver<ScriptedRedisReport>) {
    let (report_tx, report_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept test client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        let reader_stream = stream.try_clone().expect("clone test stream");
        let mut reader = BufReader::new(reader_stream);
        let mut transport_closed = false;

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    transport_closed = true;
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('*') || trimmed.starts_with('$') {
                        continue;
                    }

                    commands_received.lock().unwrap().push(trimmed.to_string());

                    match trimmed {
                        "HELLO" => write_hello3_ok(&mut stream),
                        "SUBSCRIBE" => write_subscribe_ack(&mut stream, 1),
                        "UNSUBSCRIBE" => write_unsubscribe_ack(&mut stream, 0),
                        _ => {}
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(_) => break,
            }
        }

        let commands = commands_received.lock().unwrap().clone();
        report_tx
            .send(ScriptedRedisReport {
                commands,
                transport_closed,
            })
            .expect("send scripted redis report");
    });

    (server, report_rx)
}

#[test]
fn test_pubsub_drop_closes_transport_to_release_subscriptions() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");

    let commands_received = Arc::new(Mutex::new(Vec::<String>::new()));
    let (server, report_rx) = spawn_scripted_redis_server(listener, Arc::clone(&commands_received));

    run_test_with_cx(|cx| async move {
        let url = format!("redis://{}:{}", addr.ip(), addr.port());

        {
            // Create PubSub connection and subscribe
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect to scripted redis fixture");
            let mut pubsub = client.pubsub(&cx).await.expect("create pubsub connection");

            // Subscribe to a channel
            pubsub
                .subscribe(&cx, &["testch1"])
                .await
                .expect("subscribe to channel");

            // Drop the pubsub connection without explicit unsubscribe
            // This simulates a future being cancelled mid-stream
        } // pubsub is dropped here

        // Give some time for any potential cleanup commands
        std::thread::sleep(Duration::from_millis(100));
    });

    server.join().expect("server thread join");
    let report = report_rx.recv().expect("scripted redis report");

    // Verify that SUBSCRIBE was sent
    let subscribe_sent = report.commands.iter().any(|cmd| cmd.contains("SUBSCRIBE"));
    assert!(subscribe_sent, "SUBSCRIBE command should have been sent");

    let unsubscribe_sent = report
        .commands
        .iter()
        .any(|cmd| cmd.contains("UNSUBSCRIBE"));
    assert!(
        !unsubscribe_sent,
        "drop-time cleanup must close the dedicated Pub/Sub socket instead of trying to run async UNSUBSCRIBE"
    );
    assert!(
        report.transport_closed,
        "dropping RedisPubSub must close the dedicated transport so Redis releases subscriptions"
    );
}

#[test]
fn test_explicit_unsubscribe_works() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");

    let commands_received = Arc::new(Mutex::new(Vec::<String>::new()));
    let (server, report_rx) = spawn_scripted_redis_server(listener, Arc::clone(&commands_received));

    run_test_with_cx(|cx| async move {
        let url = format!("redis://{}:{}", addr.ip(), addr.port());

        let client = RedisClient::connect(&cx, &url)
            .await
            .expect("connect to scripted redis fixture");
        let mut pubsub = client.pubsub(&cx).await.expect("create pubsub connection");

        // Subscribe then explicitly unsubscribe
        pubsub
            .subscribe(&cx, &["testch1"])
            .await
            .expect("subscribe to channel");
        pubsub
            .unsubscribe(&cx, &["testch1"])
            .await
            .expect("unsubscribe from channel");
    });

    server.join().expect("server thread join");
    let report = report_rx.recv().expect("scripted redis report");

    let subscribe_sent = report.commands.iter().any(|cmd| cmd.contains("SUBSCRIBE"));
    let unsubscribe_sent = report
        .commands
        .iter()
        .any(|cmd| cmd.contains("UNSUBSCRIBE"));

    assert!(subscribe_sent, "SUBSCRIBE should be sent");
    assert!(unsubscribe_sent, "Explicit UNSUBSCRIBE should be sent");
    assert!(
        report.transport_closed,
        "dropping the explicitly-unsubscribed Pub/Sub handle still closes its dedicated transport"
    );
}

#[test]
fn audit_redis_subscription_cleanup_behavior() {
    let source = include_str!("../src/messaging/redis.rs");
    assert!(
        source.contains("impl Drop for RedisPubSub"),
        "RedisPubSub must have a fail-closed Drop implementation"
    );
    assert!(
        source.contains("self.conn.stream.shutdown_transport()"),
        "RedisPubSub Drop must close the dedicated socket"
    );
}

#[test]
fn run_audit() {
    audit_redis_subscription_cleanup_behavior();
}
