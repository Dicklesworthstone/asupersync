#![cfg(test)]

use super::{Reaper, is_reaped};
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn failed_worker_start_is_reported_and_retryable() {
    let reaper = Arc::new(Reaper::default());
    let attempts = AtomicUsize::new(0);
    let error = reaper
        .ensure_started_with(|_| {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::from_raw_os_error(libc::EAGAIN))
        })
        .expect_err("worker creation failure must be returned to the spawner");
    assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
    assert!(!*reaper.started.lock());
    assert!(reaper.incoming.lock().is_empty());

    reaper
        .ensure_started_with(|_| {
            attempts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    reaper
        .ensure_started_with(|_| panic!("a successful startup must be reused"))
        .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[test]
fn concurrent_admission_launches_only_one_worker() {
    let reaper = Arc::new(Reaper::default());
    let attempts = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..32 {
            let reaper = &reaper;
            let attempts = &attempts;
            scope.spawn(move || {
                reaper
                    .ensure_started_with(|_| {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .unwrap();
            });
        }
    });
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[test]
fn pending_and_transient_errors_retain_reaping_ownership() {
    assert!(!is_reaped(Ok(None)));
    for errno in [libc::EINTR, libc::EAGAIN, libc::EIO] {
        assert!(
            !is_reaped(Err(io::Error::from_raw_os_error(errno))),
            "errno {errno} must not discard an owned child"
        );
    }
}

#[test]
fn terminal_status_and_echild_release_reaping_ownership() {
    assert!(is_reaped(Ok(Some(ExitStatus::from_raw(0)))));
    assert!(is_reaped(Err(io::Error::from_raw_os_error(libc::ECHILD))));
}
