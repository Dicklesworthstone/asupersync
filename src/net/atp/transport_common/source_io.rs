//! Cancellation/authority boundary for bounded ATP source filesystem jobs.
//!
//! Register for the initiating context's cancellation while a job is pending,
//! and acknowledge only through checkpoint(), preserving cancellation masking.
//! Check the current caller's I/O authority on every poll. A submitted blocking
//! job is still soft-cancelled: it may finish and discard its owned result.
//! This does not certify syscall preemption or region-drained retirement.

use std::future::{Future, poll_fn};
use std::io;
use std::path::Path;
use std::pin::{Pin, pin};
use std::task::Poll;

use crate::cx::Cx;

use super::streaming::StreamingError;

fn source_error(path: &Path, error: impl std::fmt::Display) -> StreamingError {
    StreamingError::new(format!("{}: {error}", path.display()))
}

fn cancelled(path: &Path) -> StreamingError {
    source_error(path, io::Error::new(io::ErrorKind::Interrupted, "source operation cancelled"))
}

async fn guard<T>(
    path: &Path,
    operation: &'static str,
    future: impl Future<Output = io::Result<T>>,
) -> Result<T, StreamingError> {
    // Captured on first poll, not future construction. The observer borrows an
    // owned context inside this async frame, so it remains registered between
    // polls and unregisters on success, error, panic or abandonment.
    let owner = Cx::with_current(Clone::clone);
    let mut cancellation = owner.as_ref().map(Cx::cancelled);
    let mut future = pin!(future);
    poll_fn(|task| {
        if let Err(error) = crate::cx::io_gate::require_ambient_io(operation) {
            return Poll::Ready(Err(source_error(path, error)));
        }
        if owner.as_ref().is_some_and(|cx| cx.checkpoint().is_err()) {
            return Poll::Ready(Err(cancelled(path)));
        }
        match future.as_mut().poll(task) {
            Poll::Ready(result) => Poll::Ready(result.map_err(|e| source_error(path, e))),
            Poll::Pending => {
                // The observer closes the check/register race. A masked
                // request may be observed, but it neither aborts this job nor
                // causes a self-wake loop while the filesystem is parked.
                if let Some(wait) = cancellation.as_mut() {
                    if Pin::new(wait).poll(task).is_ready()
                        && owner.as_ref().is_some_and(|cx| cx.checkpoint().is_err())
                    {
                        return Poll::Ready(Err(cancelled(path)));
                    }
                }
                Poll::Pending
            }
        }
    })
    .await
}

pub(super) async fn run<T, F>(
    path: &Path,
    operation: &'static str,
    job: F,
) -> Result<T, StreamingError>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    // spawn_blocking_io is lazy: guard checks before its first poll dispatches
    // the closure. Calling run for each batch also checks between ready jobs.
    guard(path, operation, crate::runtime::spawn_blocking_io(job)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    use crate::types::CancelKind;
    use super::super::streaming::{collect_entries, hash_file_streaming};

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PendingProbe {
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl Future for PendingProbe {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    impl Drop for PendingProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn probe() -> (PendingProbe, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        (PendingProbe { polls: polls.clone(), drops: drops.clone() }, polls, drops)
    }

    #[test]
    fn cancelled_before_first_poll_does_not_dispatch() {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let started = Arc::new(AtomicBool::new(false));
        let flag = started.clone();
        let error = futures_lite::future::block_on(cx.with_ambient(run(
            Path::new("source"), "fs", move || {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            },
        ))).unwrap_err();
        assert!(error.message().contains("source operation cancelled"));
        assert!(!started.load(Ordering::SeqCst));
    }

    #[test]
    fn denied_before_first_poll_does_not_dispatch() {
        let cx = Cx::for_testing().restrict::<crate::cx::cap::None>();
        let started = Arc::new(AtomicBool::new(false));
        let flag = started.clone();
        let error = futures_lite::future::block_on(cx.with_ambient(run(
            Path::new("source"), "fs", move || {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            },
        ))).unwrap_err();
        assert!(error.message().contains("[ASUP-E009]"));
        assert!(!started.load(Ordering::SeqCst));
    }

    #[test]
    fn request_wakes_pending_work_and_does_not_poll_it_again() {
        let cx = Cx::for_testing();
        let (inner, polls, drops) = probe();
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(cx.with_ambient(guard(Path::new("source"), "fs", inner)));
        assert!(future.as_mut().poll(&mut task).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        cx.cancel_fast(CancelKind::User);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        let Poll::Ready(Err(error)) = future.as_mut().poll(&mut task) else {
            panic!("cancellation must resolve without another filesystem poll");
        };
        assert!(error.message().contains("cancelled"));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        drop(future);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn restriction_between_polls_refuses_without_repolling_work() {
        let cx = Cx::for_testing();
        let denied = cx.restrict::<crate::cx::cap::None>();
        let (inner, polls, drops) = probe();
        let mut future = Box::pin(guard(Path::new("source"), "fs", inner));
        let mut task = Context::from_waker(Waker::noop());
        {
            let _ambient = cx.clone().set_current_restricted();
            assert!(future.as_mut().poll(&mut task).is_pending());
        }
        {
            let _ambient = denied.set_current_restricted();
            let Poll::Ready(Err(error)) = future.as_mut().poll(&mut task) else {
                panic!("attenuated caller must not consume pending source work");
            };
            assert!(error.message().contains("[ASUP-E009]"));
        }
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        drop(future);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_pending_guard_unregisters_its_waker() {
        let cx = Cx::for_testing();
        let (inner, _, drops) = probe();
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let weak = Arc::downgrade(&count);
        let waker = Waker::from(count);
        let mut future = Box::pin(cx.with_ambient(guard(Path::new("source"), "fs", inner)));
        assert!(future.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(waker);
        assert!(weak.upgrade().is_some(), "pending cancellation owns a registration");
        drop(future);
        assert!(weak.upgrade().is_none(), "abandoned work must release its observer");
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn masked_request_neither_aborts_nor_self_wakes_parked_work() {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let (inner, polls, _) = probe();
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(cx.with_ambient(guard(Path::new("source"), "fs", inner)));
        cx.masked(|| {
            for _ in 0..4 {
                assert!(future.as_mut().poll(&mut task).is_pending());
            }
            assert_eq!(count.0.load(Ordering::SeqCst), 0);
        });
        let Poll::Ready(Err(error)) = future.as_mut().poll(&mut task) else {
            panic!("the first unmasked poll must acknowledge cancellation");
        };
        assert!(error.message().contains("cancelled"));
        assert_eq!(polls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn masked_completed_work_can_return_its_value() {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let value = cx.masked(|| futures_lite::future::block_on(cx.with_ambient(guard(
            Path::new("source"), "fs", std::future::ready(Ok(42)),
        )))).unwrap();
        assert_eq!(value, 42);
        assert!(cx.checkpoint().is_err());
    }

    #[test]
    fn no_ambient_context_preserves_values_and_source_scoped_errors() {
        let value = futures_lite::future::block_on(guard(
            Path::new("source"), "fs", std::future::ready(Ok(42)),
        )).unwrap();
        assert_eq!(value, 42);
        let error = futures_lite::future::block_on(guard::<()>(
            Path::new("source"), "fs",
            std::future::ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "read failed"))),
        )).unwrap_err();
        assert_eq!(error.message(), "source: read failed");
    }

    #[test]
    fn submitted_job_retires_its_result_without_starting_the_next_batch() {
        use std::sync::mpsc;
        use std::time::Duration;

        struct Retired(mpsc::Sender<()>);
        impl Drop for Retired {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let cx = Cx::for_testing();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (retired_tx, retired_rx) = mpsc::channel();
        let next_started = Arc::new(AtomicBool::new(false));
        let next_flag = next_started.clone();
        let work = async move {
            let _value = run(Path::new("source"), "fs", move || {
                started_tx.send(()).map_err(io::Error::other)?;
                release_rx.recv_timeout(Duration::from_secs(10)).map_err(io::Error::other)?;
                Ok(Retired(retired_tx))
            }).await?;
            run(Path::new("source"), "fs", move || {
                next_flag.store(true, Ordering::SeqCst);
                Ok(())
            }).await
        };
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(cx.with_ambient(work));
        assert!(future.as_mut().poll(&mut task).is_pending());
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        cx.cancel_fast(CancelKind::User);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Err(_))));
        drop(future);
        assert!(!next_started.load(Ordering::SeqCst));
        // Soft cancellation does not preempt the submitted job. Release it and
        // witness destruction of the result that no caller can now receive.
        release_tx.send(()).unwrap();
        retired_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(!next_started.load(Ordering::SeqCst));
    }

    #[test]
    fn public_hash_and_directory_pass_observe_requested_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source");
        std::fs::write(&path, b"content").unwrap();
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let mut scratch = [0; 16];
        let error = futures_lite::future::block_on(
            cx.with_ambient(hash_file_streaming(&path, &mut scratch)),
        ).unwrap_err();
        assert!(error.message().contains("source operation cancelled"));
        let error = futures_lite::future::block_on(cx.with_ambient(collect_entries(root.path())))
            .unwrap_err();
        assert!(error.message().contains("source operation cancelled"));
    }
}
