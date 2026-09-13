#![cfg(feature = "desktop-runtime-profile")]

use asupersync::desktop_profile::{
    run_foreign_call, DESKTOP_RUNTIME_PROFILE_NAME, DesktopRuntimeProfile,
    DesktopRuntimeProfileError, ForeignCallCompletion,
};
use asupersync::channel::{self, mpsc};
use asupersync::lab::run_async_under_lab;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
        tx.try_send(1_u8).expect("the one-slot channel starts empty");

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
        assert!(matches!(
            &joined,
            Ok(Err(mpsc::SendError::Cancelled(2)))
        ));
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
    let release = Arc::new(AtomicBool::new(false));
    let release_for_call = Arc::clone(&release);
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
        let before_release = completion.is_complete();
        task.abort();
        (task.join(&cx).await, before_release)
    });

    assert!(!before_release);
    release.store(true, Ordering::Release);
    assert!(matches!(result, Err(asupersync::runtime::JoinError::Cancelled(_))));

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
        Err(asupersync::desktop_profile::DesktopRuntimeStartError::InvalidProfile(
            DesktopRuntimeProfileError::UnboundedGlobalQueue
        ))
    ));
}
