#![cfg(feature = "desktop-runtime-profile")]

use asupersync::channel::{self, mpsc};
use asupersync::desktop_profile::{
    DESKTOP_RUNTIME_PROFILE_NAME, DesktopRuntimeProfile, DesktopRuntimeProfileError,
    ForeignCallCompletion, run_foreign_call,
};
use asupersync::lab::run_async_under_lab;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
fn public_desktop_profile_is_inert_until_the_host_builds_it() {
    let config = DesktopRuntimeProfile::default()
        .runtime_config()
        .expect("default desktop profile is valid");

    assert_eq!(DESKTOP_RUNTIME_PROFILE_NAME, "desktop-bounded-v1");
    assert!(config.global_queue_limit > 0);
    assert!(config.root_region_limits.is_some());
    assert_eq!(config.blocking.max_threads, 2);
}

#[test]
fn public_profile_rejects_unbounded_and_inverted_inputs() {
    let unbounded = DesktopRuntimeProfile::with_limits(1, 0, 1, 1, 0, 0, 1, 1, 1, 1);
    assert_eq!(
        unbounded
            .runtime_config()
            .err()
            .expect("unbounded profile must be rejected"),
        DesktopRuntimeProfileError::UnboundedGlobalQueue
    );

    let inverted = DesktopRuntimeProfile::with_limits(1, 1, 1, 1, 3, 2, 1, 1, 1, 1);
    assert_eq!(
        inverted
            .runtime_config()
            .err()
            .expect("inverted profile must be rejected"),
        DesktopRuntimeProfileError::BlockingRangeInverted { min: 3, max: 2 }
    );
}

#[test]
fn lab_bounded_channel_cancellation_preserves_saturation_boundary() {
    let (result, report) = run_async_under_lab(0xFCB_002A, |cx| async move {
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(1_u8)
            .expect("the one-slot channel starts empty");

        let full = tx
            .try_send(2_u8)
            .expect_err("a second immediate send must observe saturation");
        assert!(matches!(full, mpsc::SendError::Full(2)));

        let (started_tx, mut started_rx) = channel::oneshot::channel();
        let tx_for_child = tx.clone();
        let mut child = cx
            .spawn(move |child_cx| async move {
                started_tx
                    .send_blocking(())
                    .expect("child-start receipt receiver remains live");
                tx_for_child.send(&child_cx, 2_u8).await
            })
            .expect("lab runtime must admit the channel sender");

        started_rx
            .recv(&cx)
            .await
            .expect("child reaches the saturated send");
        asupersync::runtime::yield_now().await;
        child.abort();

        let joined = child.join(&cx).await;
        assert!(matches!(&joined, Ok(Err(mpsc::SendError::Cancelled(2)))));
        assert_eq!(rx.try_recv(), Ok(1));
        joined
    });

    assert!(report.quiescent);
    assert!(report.oracle_report.all_passed());
    assert!(report.invariant_violations.is_empty());
    assert!(matches!(result, Ok(Err(mpsc::SendError::Cancelled(2)))));
}

#[test]
fn foreign_call_completion_survives_cancelled_result_delivery() {
    let runtime = DesktopRuntimeProfile::standard()
        .start()
        .expect("standard profile starts a bounded runtime");
    let completion = ForeignCallCompletion::new();
    let completion_for_task = completion.clone();
    let completion_for_observer = completion.clone();
    let release = Arc::new(AtomicBool::new(false));
    let release_for_call = Arc::clone(&release);
    let release_for_join = Arc::clone(&release);
    let (result, before_release) = runtime.block_on(async move {
        let cx = asupersync::Cx::current().expect("runtime entry installs Cx");
        let (started_tx, mut started_rx) = channel::oneshot::channel();
        let mut task = cx
            .spawn(move |_child_cx| async move {
                run_foreign_call(completion_for_task, move || {
                    started_tx
                        .send_blocking(())
                        .expect("foreign-call start receiver remains live");
                    while !release_for_call.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    42_u32
                })
                .await
            })
            .expect("runtime must admit the foreign-call wrapper");
        started_rx
            .recv(&cx)
            .await
            .expect("foreign call reaches the blocking boundary");
        let before_release = completion_for_observer.is_complete();
        task.abort();
        // Cancellation discards result delivery, not an already-running
        // foreign call. Let that call reach its terminal point before joining
        // the wrapper; otherwise the join correctly waits forever for the
        // intentionally-held operation to complete.
        release_for_join.store(true, Ordering::Release);
        (task.join(&cx).await, before_release)
    });

    assert!(!before_release);
    assert!(matches!(
        result,
        Err(asupersync::runtime::JoinError::Cancelled(_))
    ));

    // The wrapper's task has drained, but the foreign closure may still be
    // finishing on the blocking worker. Wait only through the runtime's
    // explicit close boundary; the verifier will execute this path.
    let closed = runtime.close(Duration::from_secs(1));
    assert!(closed);
    assert!(completion.is_complete());
}

#[test]
fn desktop_profile_selects_injected_first_party_no_io_reactor() {
    let runtime = DesktopRuntimeProfile::standard()
        .start()
        .expect("standard profile starts without native I/O authority");

    assert_eq!(
        runtime.io_reactor_capability_snapshot().backend(),
        asupersync::runtime::reactor::IoReactorBackend::Injected
    );
    assert!(runtime.close(Duration::from_secs(1)));
}

#[test]
fn own_runtime_close_does_not_close_host_owned_state() {
    let host_alive = Arc::new(AtomicBool::new(true));
    let runtime = DesktopRuntimeProfile::standard()
        .start()
        .expect("standard profile starts a bounded runtime");
    let host_seen_by_runtime = Arc::clone(&host_alive);
    assert_eq!(
        runtime.block_on(async move {
            assert!(host_seen_by_runtime.load(Ordering::Acquire));
            7_u8
        }),
        7
    );

    assert!(runtime.close(Duration::from_secs(1)));
    assert!(host_alive.load(Ordering::Acquire));
    host_alive.store(false, Ordering::Release);
    assert!(!host_alive.load(Ordering::Acquire));
}

#[test]
fn invalid_profile_cannot_start_a_runtime() {
    let invalid = DesktopRuntimeProfile::with_limits(1, 0, 1, 1, 0, 0, 1, 1, 1, 1);
    assert!(matches!(
        invalid.start(),
        Err(
            asupersync::desktop_profile::DesktopRuntimeStartError::InvalidProfile(
                DesktopRuntimeProfileError::UnboundedGlobalQueue
            )
        )
    ));
}

/// asupersync-bi2462.121: the profile has no host-I/O reactor. A native socket
/// used to register with the browser event reactor, which accepted it and never
/// reported readiness, so an accept parked forever. Registration is refused and
/// the socket re-polls on its own, so the accept completes once a peer connects.
#[test]
fn native_accept_under_the_desktop_profile_completes_instead_of_parking_forever() {
    let runtime = DesktopRuntimeProfile::standard()
        .start()
        .expect("standard profile starts a bounded runtime");
    let (parked_tx, parked_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let accepted = runtime.block_on(async move {
            let listener = asupersync::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let mut witnessed = false;
            std::future::poll_fn(|task| {
                let poll = listener.poll_accept(task);
                if poll.is_pending() && !witnessed {
                    // Parked witness: accept returned Pending before any peer exists.
                    witnessed = true;
                    parked_tx
                        .send(address)
                        .expect("test thread waits for the witness");
                }
                poll
            })
            .await
            .map(|(_, peer)| peer)
        });
        let _ = done_tx.send(accepted.map_err(|error| error.kind()));
        runtime.close(Duration::from_secs(1))
    });
    let address = parked_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("accept parks before any peer connects");
    let started = std::time::Instant::now();
    let client = std::net::TcpStream::connect(address).expect("peer connects");
    let accepted = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("accept completes after the peer connects instead of parking forever");
    eprintln!(
        "scenario=desktop-profile-accept address={address} accepted={accepted:?} after_connect={:?}",
        started.elapsed()
    );
    assert_eq!(accepted, Ok(client.local_addr().expect("client address")));
    drop(client);
    assert!(
        worker.join().expect("runtime thread"),
        "the desktop runtime closes"
    );
}
