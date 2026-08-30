//! Production service fixture for the server-stack e2e suite
//! (br-asupersync-server-stack-hardening-eeexl1.8, AC5).
//!
//! This example doubles as a readable documentation artifact: it shows how the
//! asupersync server stack composes into a realistic HTTP service with no
//! tokio anywhere. It is deliberately hermetic (in-memory SQLite, no external
//! dependencies) so the scripted e2e scenarios (S1–S5) can drive it
//! reproducibly.
//!
//! What this first slice composes (all on the production API):
//!   * `Http1Listener` bound with an `Http1ListenerConfig` (host policy +
//!     request-aware graceful drain budgets).
//!   * The high-level `web::Router`, connected directly to the production
//!     listener through `Router::into_http_handler`, with two endpoints:
//!       - `GET /health` — a cheap liveness probe.
//!       - `GET /users`  — a handler that runs a real SQLite query through the
//!         cancel-correct blocking pool, proving DB access from a handler.
//!   * The default request-trace middleware, which the listener applies
//!     automatically — every request emits a structured start/finish log that
//!     the e2e scenarios assert against (the logging is the test interface).
//!   * Graceful drain: the service boots, serves a self-probe end to end, then
//!     drains to quiescence and exits cleanly.
//!
//! Deferred to follow-up slices of eeexl1.8 (tracked on the bead): an outbound
//! downstream call via `http::Client`, a supervised background worker, explicit
//! middleware stacking (circuit-breaker / timeout layers), and the S1–S5 chaos
//! scenarios in `scripts/run_server_stack_e2e.sh`.
//!
//! Run it:
//! ```text
//! cargo run --example production_service --features sqlite
//! ```

use std::io::{Read, Write};
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::database::SqliteConnection;
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::Outcome;
use asupersync::web::{AsyncCxFnHandler, FnHandler, Response, Router, StatusCode, get};

/// Listener configuration for the fixture: permissive host policy (a local
/// demo binds to an ephemeral `127.0.0.1` port; a real deployment would use
/// `HostPolicy::allow_list`) and generous request-aware drain budgets so the
/// graceful-shutdown scenarios have room to complete in-flight work.
fn service_config() -> Http1ListenerConfig {
    Http1ListenerConfig::default()
        .http_config(Http1Config {
            allowed_hosts: HostPolicy::allow_all(),
            ..Http1Config::default()
        })
        .drain_timeout(Duration::from_secs(10))
        .hard_drain_timeout(Duration::from_secs(20))
}

fn health_handler() -> &'static str {
    "ok\n"
}

fn not_found_handler() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "not found\n")
}

fn service_router() -> Router {
    Router::new()
        .route("/health", get(FnHandler::new(health_handler)))
        .route("/users", get(AsyncCxFnHandler::new(users_handler)))
        .fallback(FnHandler::new(not_found_handler))
}

/// `GET /users`: open a hermetic in-memory SQLite database, seed it, and return
/// the rows — exercising the cancel-correct blocking-pool DB path from inside a
/// request handler.
///
/// A production service would acquire a connection from a shared, boot-seeded
/// pool; per-request `open_in_memory` keeps this example self-contained.
async fn users_handler(cx: Cx) -> Response {
    let conn = match SqliteConnection::open_in_memory(&cx).await {
        Outcome::Ok(conn) => conn,
        _ => return Response::new(StatusCode::INTERNAL_SERVER_ERROR, "db open failed\n"),
    };

    if !matches!(
        conn.execute_batch(
            &cx,
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL); \
             INSERT INTO users (name) VALUES ('Alice'), ('Bob');",
        )
        .await,
        Outcome::Ok(()),
    ) {
        return Response::new(StatusCode::INTERNAL_SERVER_ERROR, "db seed failed\n");
    }

    let rows = match conn
        .query(&cx, "SELECT id, name FROM users ORDER BY id", &[])
        .await
    {
        Outcome::Ok(rows) => rows,
        _ => return Response::new(StatusCode::INTERNAL_SERVER_ERROR, "db query failed\n"),
    };

    let mut body = String::new();
    for row in &rows {
        let id = row.get_i64("id").unwrap_or_default();
        let name = row.get_str("name").unwrap_or_default();
        body.push_str(&format!("{id}\t{name}\n"));
    }
    Response::new(StatusCode::OK, body)
}

/// Send one blocking `GET` from a std thread so the example can prove it serves
/// requests end to end without pulling in an async client. Returns the HTTP
/// status line and body the server sent back.
fn self_probe(addr: std::net::SocketAddr, path: &str) -> std::io::Result<(String, String)> {
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    Ok((
        head.lines().next().unwrap_or("<no response>").to_owned(),
        body.to_owned(),
    ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::new().worker_threads(2).build()?;
    let handle = runtime.handle();

    runtime.block_on(async move {
        let listener = Http1Listener::bind_with_config(
            "127.0.0.1:0",
            service_router().into_http_handler(),
            service_config(),
        )
        .await
        .expect("bind production service");

        let addr = listener.local_addr().expect("local addr");
        let manager = listener.connection_manager().clone();
        println!("production_service listening on http://{addr}");

        // Drive the accept loop on the runtime; it runs until graceful drain.
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn listener run");

        // Prove the composed stack serves real traffic: a self-probe on a std
        // thread hits /health and /users through the full server path.
        for (path, expected_status, expected_body) in [
            ("/health", "HTTP/1.1 200 OK", "ok\n"),
            ("/users", "HTTP/1.1 200 OK", "1\tAlice\n2\tBob\n"),
            ("/missing", "HTTP/1.1 404 Not Found", "not found\n"),
        ] {
            let probe_addr = addr;
            let probe_path = path.to_owned();
            let (status, body) = std::thread::spawn(move || self_probe(probe_addr, &probe_path))
                .join()
                .expect("probe thread")
                .expect("self-probe response");
            assert_eq!(status, expected_status, "status for {path}");
            assert_eq!(body, expected_body, "body for {path}");
            println!("self-probe GET {path} -> {status}");
        }

        // Graceful, request-aware shutdown: in-flight requests get the soft
        // budget to finish before the hard deadline.
        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run_handle.await.expect("listener run result");
        println!("production_service drained cleanly");
    });

    Ok(())
}
