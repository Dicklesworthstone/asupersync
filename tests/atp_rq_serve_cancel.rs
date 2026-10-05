//! `transport_rq::serve` returns `Ok(())` when its context is cancelled while it
//! waits for a connection (br-asupersync-ks43rc).
//!
//! `serve` documents that it returns when the capability context is cancelled.
//! It returned `Ok(())` only when the cancellation was observed between
//! accepts. A cancellation that interrupted the pending accept, which is the
//! usual case for an idle server, surfaced as an `Io(Interrupted)` error, so
//! callers reported a failure for an ordinary stop.
#![allow(missing_docs)]

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_rq::{RqConfig, serve};
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::CancelReason;

/// Bound on the server's startup and on its exit after cancellation.
const LIMIT: Duration = Duration::from_secs(20);

#[test]
fn serve_cancelled_while_waiting_for_a_connection_returns_ok() {
    let dest = std::env::temp_dir().join(format!(
        "atp_rq_serve_cancel_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    std::fs::create_dir_all(&dest).expect("create destination dir");
    let dest = dest.canonicalize().expect("canonicalize destination dir");

    let (bound_tx, bound_rx) = mpsc::channel();
    let (served_tx, served_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let runtime = RuntimeBuilder::multi_thread()
            .build()
            .expect("server runtime");
        let joined = runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("server cx");
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback control listener");
            let _ = bound_tx.send(listener.local_addr().expect("bound address"));
            let mut serving = cx
                .spawn(move |child| async move {
                    let mut reports = 0_usize;
                    let result = serve(
                        &child,
                        listener,
                        "127.0.0.1".to_string(),
                        dest,
                        RqConfig::default(),
                        "receiver".to_string(),
                        |_| reports += 1,
                    )
                    .await;
                    // Report what serve itself returned, whatever the join
                    // records for the cancelled task.
                    let _ = served_tx.send((result.map_err(|error| error.to_string()), reports));
                })
                .expect("spawn the serve loop");
            // Let the loop park in its accept: nothing connects.
            asupersync::time::sleep(cx.now(), Duration::from_millis(300)).await;
            serving.abort_with_reason(CancelReason::user("test stops the serve loop"));
            format!("{:?}", serving.join(&cx).await)
        }));
        drop(runtime);
        joined
    });

    bound_rx
        .recv_timeout(LIMIT)
        .expect("the server bound its control listener");
    let served = served_rx
        .recv_timeout(LIMIT)
        .expect("the cancelled serve loop returned within the bound");
    let joined = worker.join().expect("server thread");
    assert_eq!(
        served,
        (Ok(()), 0),
        "a cancelled idle serve must return Ok(()) and report nothing (join: {joined})"
    );
}
