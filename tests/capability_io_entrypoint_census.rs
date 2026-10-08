//! Behavioral census for the "no ambient authority" claim
//! (br-asupersync-issue65-criticisms-kpmoy5.5.1, .5.3): every public I/O
//! entry point listed refuses with `[ASUP-E009]` when the calling task's `Cx`
//! lacks the IO capability, and the same calls succeed for a task whose `Cx`
//! carries it.
//!
//! The restricted census task is spawned from an ambient `Cx` narrowed with
//! `Cx::push_restriction` to every capability except IO, so its own runtime
//! mask lacks IO. Before calling anything it proves that state:
//! `Cx::current().io()` is `None`. Every call targets a fixture that exists
//! before the task starts (a loopback listener, files, a Unix socket, `true`),
//! so each call would succeed if allowed; the unrestricted run proves that. A
//! refusal counts only when it carries `[ASUP-E009]`; any other error is
//! recorded as `Failed`. `--nocapture` prints both tables with each error.
//!
//! Not covered: TLS connectors (behind the `tls` feature) and the DNS
//! `Resolver` (it queries real name servers, so it is not hermetic;
//! `net::lookup_all` stands in for DNS).

use asupersync::Cx;
use asupersync::cx::IoCapabilityDenied;
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
    /// Refused with `[ASUP-E009]`.
    Refused,
    /// Failed for any other reason.
    Failed,
}

fn verdict<T, E: std::fmt::Display>(result: Result<T, E>) -> (Verdict, String) {
    match result {
        Ok(_) => (Verdict::Allowed, String::new()),
        Err(error) => {
            let detail = error.to_string();
            if detail.contains("[ASUP-E009]") {
                (Verdict::Refused, detail)
            } else {
                (Verdict::Failed, detail)
            }
        }
    }
}

/// The entry points, in census order.
const ENTRY_POINTS: &[&str] = &[
    "net::lookup_all",
    "net::TcpStream::connect",
    "net::TcpStream::connect_timeout",
    "net::TcpListener::bind",
    "net::UdpSocket::bind",
    #[cfg(unix)]
    "net::UnixListener::bind",
    #[cfg(unix)]
    "net::UnixStream::connect",
    "fs::File::create",
    "fs::File::open",
    "fs::File::create_new",
    "fs::write",
    "fs::read",
    "fs::metadata",
    "fs::read_dir",
    "fs::rename",
    "fs::remove_file",
    "process::Command::spawn",
    #[cfg(unix)]
    "signal::signal",
    "http::Client::send_get",
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

/// What each call targets; all of it exists before the census task starts.
struct Fixtures {
    dir: PathBuf,
    tcp_target: SocketAddr,
    http: SocketAddr,
    #[cfg(unix)]
    unix_peer: PathBuf,
}

async fn census(cx: Cx, fx: Fixtures) -> Vec<(&'static str, Verdict, String)> {
    let dir = fx.dir;
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
        verdict(asupersync::net::TcpStream::connect(fx.tcp_target).await),
    );
    record(
        "net::TcpStream::connect_timeout",
        verdict(
            asupersync::net::TcpStream::connect_timeout(fx.tcp_target, Duration::from_secs(5))
                .await,
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
        record(
            "net::UnixListener::bind",
            verdict(asupersync::net::UnixListener::bind(dir.join("census.sock")).await),
        );
        record(
            "net::UnixStream::connect",
            verdict(asupersync::net::UnixStream::connect(&fx.unix_peer).await),
        );
    }

    record(
        "fs::File::create",
        verdict(asupersync::fs::File::create(dir.join("created")).await),
    );
    record(
        "fs::File::open",
        verdict(asupersync::fs::File::open(dir.join("existing")).await),
    );
    record(
        "fs::File::create_new",
        verdict(asupersync::fs::File::create_new(dir.join("created_new")).await),
    );
    record(
        "fs::write",
        verdict(asupersync::fs::write(dir.join("written"), b"census").await),
    );
    record(
        "fs::read",
        verdict(asupersync::fs::read(dir.join("existing")).await),
    );
    record(
        "fs::metadata",
        verdict(asupersync::fs::metadata(dir.join("existing")).await),
    );
    record(
        "fs::read_dir",
        verdict(asupersync::fs::read_dir(&dir).await),
    );
    record(
        "fs::rename",
        verdict(asupersync::fs::rename(dir.join("to_rename"), dir.join("renamed")).await),
    );
    record(
        "fs::remove_file",
        verdict(asupersync::fs::remove_file(dir.join("to_remove")).await),
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

    let url = format!("http://{}/census", fx.http);
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

/// Runs the census in a task whose `Cx` lacks IO (`restricted`) or carries
/// it, and asserts that every entry point is refused or allowed accordingly.
fn run_census(runtime: Runtime, label: &str, restricted: bool) {
    let dir = tempfile::tempdir().expect("temp dir");
    for file in ["existing", "to_rename", "to_remove"] {
        std::fs::write(dir.path().join(file), b"fixture").expect("create fixture");
    }
    #[cfg(unix)]
    let unix_peer = dir.path().join("peer.sock");
    #[cfg(unix)]
    let _unix_listener = std::os::unix::net::UnixListener::bind(&unix_peer).expect("bind peer");
    let target = std::net::TcpListener::bind("127.0.0.1:0").expect("bind connect target");
    let fx = Fixtures {
        dir: dir.path().to_path_buf(),
        tcp_target: target.local_addr().expect("connect target addr"),
        http: one_shot_http_server(),
        #[cfg(unix)]
        unix_peer,
    };

    let rows = runtime.block_on(async move {
        let cx = Cx::current().expect("root cx");
        let mut handle = if restricted {
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
                    census(task_cx, fx).await
                })
                .expect("spawn the census task")
        } else {
            cx.spawn(move |task_cx| census(task_cx, fx))
                .expect("spawn the census task")
        };
        handle.join(&cx).await.expect("the census task completes")
    });
    drop(target);

    println!(
        "capability IO census ({label}), task Cx {}:",
        if restricted { "without IO" } else { "with IO" }
    );
    for (name, verdict, detail) in &rows {
        println!("  {name:<34} {verdict:?} {detail}");
    }
    let expected = if restricted {
        Verdict::Refused
    } else {
        Verdict::Allowed
    };
    let observed: Vec<(&str, Verdict)> = rows.iter().map(|(n, v, _)| (*n, *v)).collect();
    let wanted: Vec<(&str, Verdict)> = ENTRY_POINTS.iter().map(|n| (*n, expected)).collect();
    assert_eq!(
        observed, wanted,
        "an I/O entry point changed how it treats the task's IO capability; see the \
         owner decision (kpmoy5.5.2) and the gate (kpmoy5.5.3)"
    );
}

#[test]
fn io_entry_points_refuse_without_io_current_thread() {
    run_census(
        RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime"),
        "current_thread",
        true,
    );
}

#[test]
fn io_entry_points_refuse_without_io_multi_thread() {
    run_census(
        RuntimeBuilder::multi_thread()
            .build()
            .expect("build runtime"),
        "multi_thread",
        true,
    );
}

#[test]
fn io_entry_points_proceed_with_io_current_thread() {
    run_census(
        RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime"),
        "current_thread",
        false,
    );
}

#[test]
fn io_entry_points_proceed_with_io_multi_thread() {
    run_census(
        RuntimeBuilder::multi_thread()
            .build()
            .expect("build runtime"),
        "multi_thread",
        false,
    );
}

/// A thread outside the runtime has no current `Cx`, so the gate does not
/// apply to it.
#[test]
fn a_thread_outside_the_runtime_is_not_gated() {
    std::thread::spawn(|| {
        assert!(Cx::current().is_none(), "no ambient cx on a plain thread");
        let mut child = asupersync::process::Command::new("true")
            .spawn()
            .expect("spawn outside the runtime");
        let _ = child.wait();
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().expect("temp dir");
            asupersync::net::unix::UnixDatagram::bind(dir.path().join("plain.sock"))
                .expect("bind outside the runtime");
        }
    })
    .join()
    .expect("the plain thread finishes");
}

/// The refusal is typed: the `io::Error` carries [`IoCapabilityDenied`]
/// naming the entry point.
#[test]
fn the_refusal_carries_the_typed_denial() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    let denied = runtime.block_on(async {
        let cx = Cx::current().expect("root cx");
        let mut handle = {
            let _no_io = Cx::push_restriction(<NoIo as CapSetRuntimeMask>::MASK);
            Cx::current()
                .expect("narrowed ambient cx")
                .spawn(|_| async {
                    let error = asupersync::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .expect_err("refused without IO");
                    let kind = error.kind();
                    let denied = error
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<IoCapabilityDenied>())
                        .copied();
                    (kind, denied)
                })
                .expect("spawn")
        };
        handle.join(&cx).await.expect("join")
    });
    assert_eq!(denied.0, std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        denied.1.map(|d| d.operation()),
        Some("net::TcpListener::bind")
    );
}

/// `signal::ctrl_c` keeps the typed denial of the `signal` call it makes,
/// instead of reporting that Ctrl+C is unsupported on this platform.
#[test]
fn ctrl_c_refuses_with_the_typed_denial() {
    use std::future::Future;
    use std::task::Poll;
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    let denied = runtime.block_on(async {
        let cx = Cx::current().expect("root cx");
        let mut handle = {
            let _no_io = Cx::push_restriction(<NoIo as CapSetRuntimeMask>::MASK);
            Cx::current()
                .expect("narrowed ambient cx")
                .spawn(|_| async {
                    // One poll: a refusal is immediate, and a wait for a real
                    // Ctrl+C would mean the handler was installed without IO.
                    let mut wait = std::pin::pin!(asupersync::signal::ctrl_c());
                    let polled =
                        std::future::poll_fn(|task| Poll::Ready(wait.as_mut().poll(task))).await;
                    let Poll::Ready(result) = polled else {
                        panic!("ctrl_c waited for a signal in a task without IO");
                    };
                    let error = result.expect_err("refused without IO");
                    let kind = error.kind();
                    let denied = error
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<IoCapabilityDenied>())
                        .copied();
                    (kind, denied)
                })
                .expect("spawn")
        };
        handle.join(&cx).await.expect("join")
    });
    assert_eq!(denied.0, std::io::ErrorKind::PermissionDenied);
    assert_eq!(denied.1.map(|d| d.operation()), Some("signal::signal"));
}

/// `Cx::with_ambient` is the explicit form of the entry points: inside it
/// they are checked against the context passed, not the calling task's.
#[test]
fn with_ambient_checks_against_the_supplied_context() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    let (granted, narrowed_by_type) = runtime.block_on(async {
        let cx = Cx::current().expect("root cx");
        let full = cx.clone();
        let mut handle = {
            let _no_io = Cx::push_restriction(<NoIo as CapSetRuntimeMask>::MASK);
            Cx::current()
                .expect("narrowed ambient cx")
                .spawn(move |_| async move {
                    let own = asupersync::net::TcpListener::bind("127.0.0.1:0").await;
                    assert!(own.is_err(), "the task itself has no IO");
                    // The full context it was handed carries IO.
                    full.with_ambient(asupersync::net::TcpListener::bind("127.0.0.1:0"))
                        .await
                        .map(|_| ())
                })
                .expect("spawn")
        };
        let granted = handle.join(&cx).await.expect("join");
        // A context narrowed by its capability type alone has no IO either.
        let narrowed_by_type = cx
            .clone()
            .restrict::<NoIo>()
            .with_ambient(asupersync::net::TcpListener::bind("127.0.0.1:0"))
            .await
            .map(|_| ());
        (granted, narrowed_by_type)
    });
    assert!(granted.is_ok(), "{granted:?}");
    let error = narrowed_by_type.expect_err("a type-narrowed context refuses");
    assert!(error.to_string().contains("[ASUP-E009]"), "{error}");
}
