#![allow(missing_docs)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use asupersync::Cx;
use asupersync::sync::{OwnedSemaphorePermit, Semaphore};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

#[derive(Default)]
struct BenchWake;

impl Wake for BenchWake {
    fn wake(self: Arc<Self>) {}
}

fn poll_pending<F>(future: &mut F, waker: &Waker)
where
    F: Future + Unpin,
{
    let mut cx = Context::from_waker(waker);
    let poll = Pin::new(future).poll(&mut cx);
    assert!(
        matches!(poll, Poll::Pending),
        "queued waiter should stay pending"
    );
}

fn bench_semaphore_waiter_refresh(c: &mut Criterion) {
    let mut group = c.benchmark_group("sync/semaphore/waiter_refresh");

    for &depth in &[8usize, 64, 256, 1024] {
        let semaphore: &'static Arc<Semaphore> = Box::leak(Box::new(Arc::new(Semaphore::new(1))));
        let _held = OwnedSemaphorePermit::try_acquire_arc(semaphore, 1)
            .expect("setup should hold the only permit");
        let cx: &'static Cx = Box::leak(Box::new(Cx::for_testing()));
        let noop = Waker::noop();

        let mut waiters: Vec<_> = (0..depth).map(|_| semaphore.acquire(cx, 1)).collect();
        for waiter in &mut waiters {
            poll_pending(waiter, noop);
        }

        let target = depth / 2;
        let waker_a = Waker::from(Arc::new(BenchWake));
        let waker_b = Waker::from(Arc::new(BenchWake));
        let mut use_a = false;

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, _| {
            b.iter(|| {
                let waker = if use_a { &waker_a } else { &waker_b };
                use_a = !use_a;
                poll_pending(&mut waiters[target], waker);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_semaphore_waiter_refresh);
criterion_main!(benches);
