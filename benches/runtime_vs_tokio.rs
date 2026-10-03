//! Same-process head-to-head: asupersync vs tokio on the operations a server
//! does constantly (br-asupersync-issue65-criticisms-kpmoy5.1.1).
//!
//! Every group runs a tokio row and the matching asupersync rows inside one
//! Criterion group, so both share the host, the build profile, and the
//! moment. Compare rows within a run; absolute values are host-specific.
//!
//! - `spawn_join`: a parent spawns `n` trivial tasks, keeps every handle, and
//!   awaits them all. Tokio's parent is the `block_on` future; the asupersync
//!   rows use `RuntimeHandle::spawn` (Direct admission, the default) and the
//!   structured `Cx::spawn` + `TaskHandle::join` path users are told to use.
//! - `spawn_join_current_thread`: the same on single-threaded runtimes.
//! - `yield`: one task yields `n` times.
//! - `mpsc_ping_pong`: two tasks exchange a value `n` times over capacity-1
//!   channels.
//! - `fan_out`: `n` concurrent children owned by one parent: tokio spawn +
//!   join versus asupersync fibers (same task, not parallel). Tokio's own
//!   in-task equivalent is `futures::stream::FuturesUnordered`, which is not
//!   a dependency here; compare fibers with it before claiming a win.
//! - `mutex_contended`: `tasks` tasks each take the runtime's async mutex
//!   1000 times.
//! - `yield_storm`: `tasks` tasks each yield 1000 times.
//!
//! Timing starts inside the parent future: runtime construction and
//! `block_on` entry are excluded on both sides. Run with:
//!
//! ```text
//! cargo bench -p asupersync --bench runtime_vs_tokio --features criterion-benches -- --noplot
//! ```
//!
//! Feature set: building any bench also builds the `conformance`
//! dev-dependency, which enables asupersync's `metrics`, `test-internals`,
//! `tracing-integration` and `fuzz` features, and Cargo unifies them into the
//! library under test. These rows therefore measure that build, not a
//! default-feature dependency (`tracing-integration` keeps the epoch tracker
//! on, for example). For production-default numbers, build the same code in a
//! separate crate that depends on asupersync with default features.

#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::runtime::{Runtime, RuntimeBuilder};

const WORKERS: usize = 4;

fn asup_multi() -> Runtime {
    RuntimeBuilder::new()
        .worker_threads(WORKERS)
        .build()
        .expect("build asupersync multi-thread runtime")
}

fn asup_current() -> Runtime {
    RuntimeBuilder::current_thread()
        .build()
        .expect("build asupersync current-thread runtime")
}

fn tokio_multi() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .build()
        .expect("build tokio multi-thread runtime")
}

fn tokio_current() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build tokio current-thread runtime")
}

fn asup_handle_spawn_join(rt: &Runtime, n: usize) -> Duration {
    rt.block_on(async move {
        let handle = Runtime::current_handle().expect("block_on installs a runtime handle");
        let start = Instant::now();
        let mut joins = Vec::with_capacity(n);
        for i in 0..n {
            joins.push(handle.spawn(async move { i }));
        }
        let mut sum = 0usize;
        for join in joins {
            sum = sum.wrapping_add(join.await);
        }
        black_box(sum);
        start.elapsed()
    })
}

fn asup_cx_spawn_join(rt: &Runtime, n: usize) -> Duration {
    rt.block_on(rt.handle().spawn(async move {
        let cx = Cx::current().expect("a spawned task has a Cx");
        let start = Instant::now();
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            handles.push(cx.spawn(move |_cx| async move { i }).expect("Cx::spawn"));
        }
        let mut sum = 0usize;
        for mut handle in handles {
            sum = sum.wrapping_add(handle.join(&cx).await.expect("join"));
        }
        black_box(sum);
        start.elapsed()
    }))
}

fn tokio_spawn_join(rt: &tokio::runtime::Runtime, n: usize) -> Duration {
    rt.block_on(async move {
        let start = Instant::now();
        let mut joins = Vec::with_capacity(n);
        for i in 0..n {
            joins.push(tokio::spawn(async move { i }));
        }
        let mut sum = 0usize;
        for join in joins {
            sum = sum.wrapping_add(join.await.expect("tokio join"));
        }
        black_box(sum);
        start.elapsed()
    })
}

fn asup_yield(rt: &Runtime, n: usize) -> Duration {
    rt.block_on(rt.handle().spawn(async move {
        let start = Instant::now();
        for _ in 0..n {
            asupersync::runtime::yield_now().await;
        }
        start.elapsed()
    }))
}

fn tokio_yield(rt: &tokio::runtime::Runtime, n: usize) -> Duration {
    rt.block_on(async move {
        tokio::spawn(async move {
            let start = Instant::now();
            for _ in 0..n {
                tokio::task::yield_now().await;
            }
            start.elapsed()
        })
        .await
        .expect("tokio yield task")
    })
}

fn asup_ping_pong(rt: &Runtime, n: usize) -> Duration {
    rt.block_on(rt.handle().spawn(async move {
        let cx = Cx::current().expect("a spawned task has a Cx");
        let (ping_tx, mut ping_rx) = asupersync::channel::mpsc::channel::<u64>(1);
        let (pong_tx, mut pong_rx) = asupersync::channel::mpsc::channel::<u64>(1);
        let mut echo = cx
            .spawn(move |cx| async move {
                while let Ok(value) = ping_rx.recv(&cx).await {
                    if pong_tx.send(&cx, value + 1).await.is_err() {
                        break;
                    }
                }
            })
            .expect("spawn echo task");
        let start = Instant::now();
        let mut acc = 0u64;
        for i in 0..n as u64 {
            ping_tx.send(&cx, i).await.expect("ping");
            acc = acc.wrapping_add(pong_rx.recv(&cx).await.expect("pong"));
        }
        let elapsed = start.elapsed();
        drop(ping_tx);
        let _ = echo.join(&cx).await;
        black_box(acc);
        elapsed
    }))
}

fn tokio_ping_pong(rt: &tokio::runtime::Runtime, n: usize) -> Duration {
    rt.block_on(async move {
        tokio::spawn(async move {
            let (ping_tx, mut ping_rx) = tokio::sync::mpsc::channel::<u64>(1);
            let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<u64>(1);
            let echo = tokio::spawn(async move {
                while let Some(value) = ping_rx.recv().await {
                    if pong_tx.send(value + 1).await.is_err() {
                        break;
                    }
                }
            });
            let start = Instant::now();
            let mut acc = 0u64;
            for i in 0..n as u64 {
                ping_tx.send(i).await.expect("ping");
                acc = acc.wrapping_add(pong_rx.recv().await.expect("pong"));
            }
            let elapsed = start.elapsed();
            drop(ping_tx);
            let _ = echo.await;
            black_box(acc);
            elapsed
        })
        .await
        .expect("tokio ping-pong task")
    })
}

/// `n` concurrent child computations owned by one parent, as asupersync
/// fibers: same task, borrowing the parent's data, no runtime task each.
fn asup_fiber_fan_out(rt: &Runtime, n: usize) -> Duration {
    rt.block_on(rt.handle().spawn(async move {
        let inputs: Vec<usize> = (0..n).collect();
        let inputs = &inputs;
        let start = Instant::now();
        let sum = asupersync::cx::fiber::scope(|scope| async move {
            let handles: Vec<_> = (0..n)
                .map(|i| scope.spawn(async move { inputs[i] }))
                .collect();
            let mut sum = 0usize;
            for handle in handles {
                sum = sum.wrapping_add(handle.await.expect("fiber"));
            }
            sum
        })
        .await;
        black_box(sum);
        start.elapsed()
    }))
}

const OPS_PER_TASK: usize = 1_000;

/// `tasks` tasks each lock and increment a shared counter `OPS_PER_TASK` times.
fn asup_mutex_contended(rt: &Runtime, tasks: usize) -> Duration {
    rt.block_on(rt.handle().spawn(async move {
        let cx = Cx::current().expect("a spawned task has a Cx");
        let counter = Arc::new(asupersync::sync::Mutex::new(0usize));
        let start = Instant::now();
        let mut handles = Vec::with_capacity(tasks);
        for _ in 0..tasks {
            let counter = Arc::clone(&counter);
            handles.push(
                cx.spawn(move |cx| async move {
                    for _ in 0..OPS_PER_TASK {
                        *counter.lock(&cx).await.expect("lock") += 1;
                    }
                })
                .expect("Cx::spawn"),
            );
        }
        for mut handle in handles {
            handle.join(&cx).await.expect("join");
        }
        let elapsed = start.elapsed();
        assert_eq!(
            *counter.lock(&cx).await.expect("lock"),
            tasks * OPS_PER_TASK
        );
        elapsed
    }))
}

fn tokio_mutex_contended(rt: &tokio::runtime::Runtime, tasks: usize) -> Duration {
    rt.block_on(async move {
        let counter = Arc::new(tokio::sync::Mutex::new(0usize));
        let start = Instant::now();
        let mut joins = Vec::with_capacity(tasks);
        for _ in 0..tasks {
            let counter = Arc::clone(&counter);
            joins.push(tokio::spawn(async move {
                for _ in 0..OPS_PER_TASK {
                    *counter.lock().await += 1;
                }
            }));
        }
        for join in joins {
            join.await.expect("tokio join");
        }
        let elapsed = start.elapsed();
        assert_eq!(*counter.lock().await, tasks * OPS_PER_TASK);
        elapsed
    })
}

/// `tasks` tasks each yield `OPS_PER_TASK` times.
fn asup_yield_storm(rt: &Runtime, tasks: usize) -> Duration {
    rt.block_on(rt.handle().spawn(async move {
        let cx = Cx::current().expect("a spawned task has a Cx");
        let start = Instant::now();
        let mut handles = Vec::with_capacity(tasks);
        for _ in 0..tasks {
            handles.push(
                cx.spawn(move |_cx| async move {
                    for _ in 0..OPS_PER_TASK {
                        asupersync::runtime::yield_now().await;
                    }
                })
                .expect("Cx::spawn"),
            );
        }
        for mut handle in handles {
            handle.join(&cx).await.expect("join");
        }
        start.elapsed()
    }))
}

fn tokio_yield_storm(rt: &tokio::runtime::Runtime, tasks: usize) -> Duration {
    rt.block_on(async move {
        let start = Instant::now();
        let mut joins = Vec::with_capacity(tasks);
        for _ in 0..tasks {
            joins.push(tokio::spawn(async move {
                for _ in 0..OPS_PER_TASK {
                    tokio::task::yield_now().await;
                }
            }));
        }
        for join in joins {
            join.await.expect("tokio join");
        }
        start.elapsed()
    })
}

/// Times `iters` batches of `n` operations with the clock inside the parent.
fn timed(iters: u64, mut batch: impl FnMut() -> Duration) -> Duration {
    (0..iters).map(|_| batch()).sum()
}

fn bench_spawn_join(c: &mut Criterion) {
    let asup = asup_multi();
    let tokio = tokio_multi();
    let mut group = c.benchmark_group("spawn_join");
    for n in [100usize, 1_000, 10_000] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::new("tokio", n), |b| {
            b.iter_custom(|iters| timed(iters, || tokio_spawn_join(&tokio, n)));
        });
        group.bench_function(BenchmarkId::new("asupersync_handle", n), |b| {
            b.iter_custom(|iters| timed(iters, || asup_handle_spawn_join(&asup, n)));
        });
        group.bench_function(BenchmarkId::new("asupersync_cx", n), |b| {
            b.iter_custom(|iters| timed(iters, || asup_cx_spawn_join(&asup, n)));
        });
    }
    group.finish();
}

fn bench_spawn_join_current_thread(c: &mut Criterion) {
    let asup = asup_current();
    let tokio = tokio_current();
    let mut group = c.benchmark_group("spawn_join_current_thread");
    for n in [100usize, 1_000, 10_000] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::new("tokio", n), |b| {
            b.iter_custom(|iters| timed(iters, || tokio_spawn_join(&tokio, n)));
        });
        group.bench_function(BenchmarkId::new("asupersync_handle", n), |b| {
            b.iter_custom(|iters| timed(iters, || asup_handle_spawn_join(&asup, n)));
        });
        group.bench_function(BenchmarkId::new("asupersync_cx", n), |b| {
            b.iter_custom(|iters| timed(iters, || asup_cx_spawn_join(&asup, n)));
        });
    }
    group.finish();
}

fn bench_yield(c: &mut Criterion) {
    let asup_mt = asup_multi();
    let tokio_mt = tokio_multi();
    let asup_ct = asup_current();
    let tokio_ct = tokio_current();
    let n = 10_000usize;
    let mut group = c.benchmark_group("yield");
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function("tokio_multi", |b| {
        b.iter_custom(|iters| timed(iters, || tokio_yield(&tokio_mt, n)));
    });
    group.bench_function("asupersync_multi", |b| {
        b.iter_custom(|iters| timed(iters, || asup_yield(&asup_mt, n)));
    });
    group.bench_function("tokio_current", |b| {
        b.iter_custom(|iters| timed(iters, || tokio_yield(&tokio_ct, n)));
    });
    group.bench_function("asupersync_current", |b| {
        b.iter_custom(|iters| timed(iters, || asup_yield(&asup_ct, n)));
    });
    group.finish();
}

fn bench_ping_pong(c: &mut Criterion) {
    let asup_mt = asup_multi();
    let tokio_mt = tokio_multi();
    let asup_ct = asup_current();
    let tokio_ct = tokio_current();
    let n = 10_000usize;
    let mut group = c.benchmark_group("mpsc_ping_pong");
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function("tokio_multi", |b| {
        b.iter_custom(|iters| timed(iters, || tokio_ping_pong(&tokio_mt, n)));
    });
    group.bench_function("asupersync_multi", |b| {
        b.iter_custom(|iters| timed(iters, || asup_ping_pong(&asup_mt, n)));
    });
    group.bench_function("tokio_current", |b| {
        b.iter_custom(|iters| timed(iters, || tokio_ping_pong(&tokio_ct, n)));
    });
    group.bench_function("asupersync_current", |b| {
        b.iter_custom(|iters| timed(iters, || asup_ping_pong(&asup_ct, n)));
    });
    group.finish();
}

/// Fine-grained fan-out: `n` concurrent child computations owned by one
/// parent. Tokio's structured tool for this is spawn + join (each child is a
/// runtime task); asupersync can use fibers, which stay inside the parent
/// task. Fibers are not parallel; this row measures fan-out overhead.
fn bench_fan_out(c: &mut Criterion) {
    let asup = asup_multi();
    let tokio = tokio_multi();
    let mut group = c.benchmark_group("fan_out");
    for n in [100usize, 1_000, 10_000] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::new("tokio_spawn_join", n), |b| {
            b.iter_custom(|iters| timed(iters, || tokio_spawn_join(&tokio, n)));
        });
        group.bench_function(BenchmarkId::new("asupersync_fibers", n), |b| {
            b.iter_custom(|iters| timed(iters, || asup_fiber_fan_out(&asup, n)));
        });
    }
    group.finish();
}

fn bench_mutex_contended(c: &mut Criterion) {
    let asup = asup_multi();
    let tokio = tokio_multi();
    let mut group = c.benchmark_group("mutex_contended");
    for tasks in [2usize, 8] {
        group.throughput(Throughput::Elements((tasks * OPS_PER_TASK) as u64));
        group.bench_function(BenchmarkId::new("tokio", tasks), |b| {
            b.iter_custom(|iters| timed(iters, || tokio_mutex_contended(&tokio, tasks)));
        });
        group.bench_function(BenchmarkId::new("asupersync", tasks), |b| {
            b.iter_custom(|iters| timed(iters, || asup_mutex_contended(&asup, tasks)));
        });
    }
    group.finish();
}

fn bench_yield_storm(c: &mut Criterion) {
    let asup = asup_multi();
    let tokio = tokio_multi();
    let tasks = 4usize;
    let mut group = c.benchmark_group("yield_storm");
    group.throughput(Throughput::Elements((tasks * OPS_PER_TASK) as u64));
    group.bench_function(BenchmarkId::new("tokio", tasks), |b| {
        b.iter_custom(|iters| timed(iters, || tokio_yield_storm(&tokio, tasks)));
    });
    group.bench_function(BenchmarkId::new("asupersync", tasks), |b| {
        b.iter_custom(|iters| timed(iters, || asup_yield_storm(&asup, tasks)));
    });
    group.finish();
}

criterion_group!(
    runtime_vs_tokio,
    bench_spawn_join,
    bench_spawn_join_current_thread,
    bench_yield,
    bench_ping_pong,
    bench_fan_out,
    bench_mutex_contended,
    bench_yield_storm
);
criterion_main!(runtime_vs_tokio);
