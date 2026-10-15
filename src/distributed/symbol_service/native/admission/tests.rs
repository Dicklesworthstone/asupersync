use super::*;
use std::pin::Pin;
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Waker};

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn zero_denies_before_invoking_an_eager_factory() {
    let limiter = Admission::new(0);
    let mut future = Box::pin(limiter.run(|| {
        panic!("denied factory must not encode or dispatch");
        #[allow(unreachable_code)]
        async { Ok::<_, RemoteSymbolError>(()) }
    }));
    assert!(matches!(poll(future.as_mut()), Poll::Ready(Err(RemoteSymbolError::Admission))));
    assert_eq!(limiter.active(), 0);
}

#[test]
fn admission_is_lazy_and_shared_between_clones_and_operation_kinds() {
    let root = Arc::new(Admission::new(1));
    let clone = Arc::clone(&root);
    let calls = AtomicUsize::new(0);
    let mut send = Box::pin(root.run(|| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<Result<(), RemoteSymbolError>>()
    }));
    assert_eq!(root.active(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(poll(send.as_mut()).is_pending());
    assert_eq!(root.active(), 1);
    let mut fetch = Box::pin(clone.run(|| async { Ok(17) }));
    assert!(matches!(poll(fetch.as_mut()), Poll::Ready(Err(RemoteSymbolError::Admission))));
    drop(send);
    assert_eq!(clone.active(), 0);
    let mut fetch = Box::pin(clone.run(|| async { Ok(17) }));
    assert!(matches!(poll(fetch.as_mut()), Poll::Ready(Ok(17))));
    assert_eq!(root.active(), 0); // Completed wrapper deliberately stays alive.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

struct Owned<'a> {
    limiter: &'a Admission,
    drops: &'a AtomicUsize,
    ready: bool,
    panic_poll: bool,
    panic_drop: bool,
}
impl Future for Owned<'_> {
    type Output = Result<(), RemoteSymbolError>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(self.limiter.active(), 1);
        assert!(!self.panic_poll, "poll sentinel");
        if self.ready { Poll::Ready(Ok(())) } else { Poll::Pending }
    }
}
impl Drop for Owned<'_> {
    fn drop(&mut self) {
        assert_eq!(self.limiter.active(), 1, "credit must cover inner destruction");
        assert!(matches!(self.limiter.acquire(), Err(RemoteSymbolError::Admission)));
        self.drops.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic_drop, "drop sentinel");
    }
}

#[test]
fn ready_future_destruction_precedes_capacity_reuse() {
    let limiter = Admission::new(1);
    let drops = AtomicUsize::new(0);
    let mut future = Box::pin(limiter.run(|| Owned {
        limiter: &limiter, drops: &drops, ready: true, panic_poll: false, panic_drop: false,
    }));
    assert!(matches!(poll(future.as_mut()), Poll::Ready(Ok(()))));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(limiter.active(), 0);
}

#[test]
fn dropping_pending_work_retires_inner_before_credit() {
    let limiter = Admission::new(1);
    let drops = AtomicUsize::new(0);
    let mut future = Box::pin(limiter.run(|| Owned {
        limiter: &limiter, drops: &drops, ready: false, panic_poll: false, panic_drop: false,
    }));
    assert!(poll(future.as_mut()).is_pending());
    drop(future);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(limiter.active(), 0);
}

#[test]
fn constructor_unwind_returns_credit_without_dispatching_again() {
    let limiter = Admission::new(1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut future = Box::pin(limiter.run(|| {
            assert_eq!(limiter.active(), 1);
            panic!("factory sentinel");
            #[allow(unreachable_code)]
            async { Ok::<_, RemoteSymbolError>(()) }
        }));
        let _ = poll(future.as_mut());
    }));
    assert!(result.is_err());
    assert_eq!(limiter.active(), 0);
}

#[test]
fn poll_and_destructor_unwinds_return_credit() {
    for (panic_poll, panic_drop) in [(true, false), (false, true)] {
        let limiter = Admission::new(1);
        let drops = AtomicUsize::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut future = Box::pin(limiter.run(|| Owned {
                limiter: &limiter, drops: &drops, ready: true, panic_poll, panic_drop,
            }));
            let _ = poll(future.as_mut());
        }));
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(limiter.active(), 0);
    }
}

#[test]
fn application_error_returns_credit_and_original_error() {
    let limiter = Admission::new(1);
    let mut future = Box::pin(limiter.run(|| async { Err::<(), _>(RemoteSymbolError::Refused) }));
    assert!(matches!(poll(future.as_mut()), Poll::Ready(Err(RemoteSymbolError::Refused))));
    assert_eq!(limiter.active(), 0);
}

#[test]
fn concurrent_admission_never_exceeds_the_shared_ceiling() {
    let limiter = Arc::new(Admission::new(2));
    let barrier = Arc::new(Barrier::new(9));
    let admitted = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let (limiter, barrier, admitted) = (Arc::clone(&limiter), Arc::clone(&barrier), Arc::clone(&admitted));
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            let credit = limiter.acquire();
            if credit.is_ok() { admitted.fetch_add(1, Ordering::SeqCst); }
            barrier.wait();
            barrier.wait();
            drop(credit);
        }));
    }
    barrier.wait();
    barrier.wait();
    let observed = (limiter.active(), admitted.load(Ordering::SeqCst));
    barrier.wait();
    for thread in threads { thread.join().unwrap(); }
    assert_eq!(observed, (2, 2));
    assert_eq!(limiter.active(), 0);
}

#[test]
fn maximum_limit_cannot_wrap_the_counter() {
    let limiter = Admission::new(usize::MAX);
    limiter.active.store(usize::MAX - 1, Ordering::Release);
    let credit = limiter.acquire().unwrap();
    assert_eq!(limiter.active(), usize::MAX);
    assert!(matches!(limiter.acquire(), Err(RemoteSymbolError::Admission)));
    drop(credit);
    assert_eq!(limiter.active(), usize::MAX - 1);
}
