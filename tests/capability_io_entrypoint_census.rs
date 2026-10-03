//! Behavioral census for the "no ambient authority" claim
//! (br-asupersync-issue65-criticisms-kpmoy5.5.1): which public I/O entry
//! points refuse when the calling task's `Cx` lacks the IO capability?
//!
//! The census task is spawned from an ambient `Cx` narrowed with
//! `Cx::push_restriction` to every capability except IO, so its own runtime
//! mask lacks IO. Before calling anything it proves that state:
//! `Cx::current().io()` is `None`. Each entry point then runs against
//! loopback, a temp directory or `true`, so every call would succeed if
//! allowed. The test asserts the recorded table. A change in any entry
//! point's behavior turns it red. `--nocapture` prints the table with each
//! error.
//!
//! This documents current behavior for the owner decision in
//! br-asupersync-issue65-criticisms-kpmoy5.5.2. Not covered: TLS connectors
//! (behind the `tls` feature) and the DNS `Resolver` (it queries real name
//! servers, so it is not hermetic; `net::lookup_all` stands in for DNS).

use asupersync::Cx;
use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Every capability except IO: spawn, time, random, remote.
type NoIo = CapSet<true, true, true, false, true>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allowed,
    Refused,
}

fn verdict<T, E: std::fmt::Display>(result: Result<T, E>) -> (Verdict, String) {
    match result {
        Ok(_) => (Verdict::Allowed, String::new()),
        Err(error) => (Verdict::Refused, error.to_string()),
    }
}

/// Today's behavior. Every entry point listed proceeds without IO.
const EXPECTED: &[(&str, Verdict)] = &[
    ("net::lookup_all", Verdict::Allowed),
    ("net::TcpStream::connect", Verdict::Allowed),
    ("net::TcpStream::connect_timeout", Verdict::Allowed),
    ("net::TcpListener::bind", Verdict::Allowed),
    ("net::UdpSocket::bind", Verdict::Allowed),
    #[cfg(unix)]
    ("net::UnixListener::bind", Verdict::Allowed),
    #[cfg(unix)]
    ("net::UnixStream::connect", Verdict::Allowed),
    ("fs::File::create", Verdict::Allowed),
    ("fs::File::open", Verdict::Allowed),
    ("fs::File::create_new", Verdict::Allowed),
    ("fs::write", Verdict::Allowed),
    ("fs::read", Verdict::Allowed),
    ("fs::metadata", Verdict::Allowed),
    ("fs::read_dir", Verdict::Allowed),
    ("fs::rename", Verdict::Allowed),
    ("fs::remove_file", Verdict::Allowed),
    ("process::Command::spawn", Verdict::Allowed),
    #[cfg(unix)]
    ("signal::signal", Verdict::Allowed),
    ("http::Client::send_get", Verdict::Allowed),
];

/// A loopback HTTP/1.1 server on a std thread that answers one request with
/// an empty 200.
fn one_shot_http_server() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http server");
    let addr = listener.local_addr().expect("http server addr");
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    addr
}

async fn census(
    cx: Cx,
    dir: PathBuf,
    tcp_target: SocketAddr,
    http: SocketAddr,
) -> Vec<(&'static str, Verdict, String)> {
    let mut rows = Vec::new();
    let mut record = |name: &'static str, (verdict, detail): (Verdict, String)| {
        rows.push((name, verdict, detail));
    };

    record(
        "net::lookup_all",
        verdict(asupersync::net::lookup_all("localhost:80").await),
    );
    record(
        "net::TcpStream::connect",
        verdict(asupersync::net::TcpStream::connect(tcp_target).await),
    );
    record(
        "net::TcpStream::connect_timeout",
        verdict(
            asupersync::net::TcpStream::connect_timeout(tcp_target, Duration::from_secs(5)).await,
        ),
    );
    record(
        "net::TcpListener::bind",
        verdict(asupersync::net::TcpListener::bind("127.0.0.1:0").await),
    );
    record(
        "net::UdpSocket::bind",
        verdict(asupersync::net::UdpSocket::bind("127.0.0.1:0").await),
    );
    #[cfg(unix)]
    {
        let socket_path = dir.join("census.sock");
        let listener = asupersync::net::UnixListener::bind(&socket_path).await;
        // Connect while the listener is alive: dropping it removes the path.
        let connected = if listener.is_ok() {
            verdict(asupersync::net::UnixStream::connect(&socket_path).await)
        } else {
            (Verdict::Refused, "listener was refused".to_owned())
        };
        record("net::UnixListener::bind", verdict(listener));
        record("net::UnixStream::connect", connected);
    }

    let a = dir.join("a");
    record(
        "fs::File::create",
        verdict(asupersync::fs::File::create(&a).await),
    );
    record(
        "fs::File::open",
        verdict(asupersync::fs::File::open(&a).await),
    );
    record(
        "fs::File::create_new",
        verdict(asupersync::fs::File::create_new(dir.join("b")).await),
    );
    let c = dir.join("c");
    record(
        "fs::write",
        verdict(asupersync::fs::write(&c, b"census").await),
    );
    record("fs::read", verdict(asupersync::fs::read(&c).await));
    record("fs::metadata", verdict(asupersync::fs::metadata(&c).await));
    record(
        "fs::read_dir",
        verdict(asupersync::fs::read_dir(&dir).await),
    );
    let d = dir.join("d");
    record("fs::rename", verdict(asupersync::fs::rename(&c, &d).await));
    record(
        "fs::remove_file",
        verdict(asupersync::fs::remove_file(&d).await),
    );

    let spawned = asupersync::process::Command::new("true").spawn();
    let spawned = spawned.map(|mut child| {
        // `true` exits at once; reap it.
        let _ = child.wait();
    });
    record("process::Command::spawn", verdict(spawned));

    #[cfg(unix)]
    record(
        "signal::signal",
        verdict(asupersync::signal::signal(
            asupersync::signal::SignalKind::user_defined1(),
        )),
    );

    let url = format!("http://{http}/census");
    record(
        "http::Client::send_get",
        verdict(
            asupersync::http::client::Client::new()
                .send_get(&cx, &url)
                .await,
        ),
    );
    rows
}

fn run_census(runtime: Runtime, label: &str) {
    let dir = tempfile::tempdir().expect("temp dir");
    let dir_path = dir.path().to_path_buf();
    let target = std::net::TcpListener::bind("127.0.0.1:0").expect("bind connect target");
    let tcp_target = target.local_addr().expect("connect target addr");
    let http = one_shot_http_server();

    let rows = runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let mut handle = {
            // The guard must not live across an await.
            let _no_io = Cx::push_restriction(<NoIo as CapSetRuntimeMask>::MASK);
            let narrowed = Cx::current().expect("narrowed ambient cx");
            assert!(narrowed.io().is_none(), "the narrowed ambient cx lacks IO");
            narrowed
                .spawn(move |task_cx| async move {
                    // State witness: the census task itself runs without IO.
                    let ambient = Cx::current().expect("task cx");
                    assert!(
                        ambient.io().is_none(),
                        "the census task must run with IO masked out"
                    );
                    census(task_cx, dir_path, tcp_target, http).await
                })
                .expect("spawn the census task")
        };
        handle.join(&cx).await.expect("the census task completes")
    });
    drop(target);

    println!("capability IO census ({label}), task Cx without IO:");
    for (name, verdict, detail) in &rows {
        println!("  {name:<34} {verdict:?} {detail}");
    }
    let observed: Vec<(&str, Verdict)> = rows.iter().map(|(n, v, _)| (*n, *v)).collect();
    assert_eq!(
        observed, EXPECTED,
        "an I/O entry point changed how it treats a Cx without IO; update the census table \
         and the owner-decision bead (kpmoy5.5.2)"
    );
}

#[test]
fn io_entry_points_with_io_masked_out_current_thread() {
    run_census(
        RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime"),
        "current_thread",
    );
}

#[test]
fn io_entry_points_with_io_masked_out_multi_thread() {
    run_census(
        RuntimeBuilder::multi_thread()
            .build()
            .expect("build runtime"),
        "multi_thread",
    );
}
