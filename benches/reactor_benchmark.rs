//! Reactor benchmark suite comparing Phase 0 (busy-loop) vs Phase 2 (reactor-based) I/O.
//!
//! These benchmarks measure the performance of the reactor-based I/O infrastructure
//! that enables Phase 2's efficient async I/O.
//!
//! Key metrics:
//! - Reactor registration throughput: Registrations per second
//! - Interest operations: Overhead of interest flag manipulation
//! - Waker operations: Cost of waker creation and invocation
//! - Connection handling: TCP accept/connect patterns
//! - Echo latency: Round-trip time for various message sizes
//!
//! Phase 2 improvements over Phase 0:
//! - Real reactor integration (epoll/kqueue) instead of busy-loop
//! - Efficient wakeup mechanism instead of wake_by_ref spinning
//! - O(1) event dispatch instead of O(n) polling

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(unused_imports)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use asupersync::runtime::reactor::Interest;
use asupersync::runtime::{Events, LabReactor, Reactor, Token};

// =============================================================================
// TEST WAKERS
// =============================================================================

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Arc::new(NoopWaker).into()
}

struct CountingWaker {
    count: Arc<AtomicU64>,
}

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

fn counting_waker() -> (Waker, Arc<AtomicU64>) {
    let count = Arc::new(AtomicU64::new(0));
    let waker = Arc::new(CountingWaker {
        count: count.clone(),
    })
    .into();
    (waker, count)
}

// =============================================================================
// REACTOR REGISTRATION BENCHMARKS
// =============================================================================

fn bench_reactor_registration(c: &mut Criterion) {
    let mut group = c.benchmark_group("reactor/registration");

    // Benchmark Lab reactor registration
    group.bench_function("lab_register", |b| {
        let reactor = LabReactor::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let mut token_id = 0usize;

        b.iter(|| {
            let token = Token::new(token_id);
            token_id += 1;
            reactor
                .register(&listener, token, Interest::READABLE)
                .expect("register");
            std::hint::black_box(token);
        });
    });

    // Benchmark Lab reactor register/deregister cycle
    group.bench_function("lab_register_deregister_cycle", |b| {
        let reactor = LabReactor::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let token = Token::new(0);

        b.iter(|| {
            reactor
                .register(&listener, token, Interest::READABLE)
                .expect("register");
            reactor.deregister(token).expect("deregister");
        });
    });

    // Batch registration throughput
    for &count in &[10_usize, 100] {
        let count_u64 = u64::try_from(count).expect("count fits u64");
        group.throughput(Throughput::Elements(count_u64));

        group.bench_with_input(
            BenchmarkId::new("batch_register", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let reactor = LabReactor::new();
                    let listeners: Vec<_> = (0..count)
                        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind"))
                        .collect();

                    let tokens: Vec<_> = listeners
                        .iter()
                        .enumerate()
                        .map(|(i, l)| {
                            let token = Token::new(i);
                            reactor
                                .register(l, token, Interest::READABLE)
                                .expect("register");
                            token
                        })
                        .collect();

                    std::hint::black_box(tokens)
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// REACTOR WAKE BENCHMARKS
// =============================================================================

fn bench_reactor_wake(c: &mut Criterion) {
    let mut group = c.benchmark_group("reactor/wake");

    // Benchmark Lab reactor poll with wake
    group.bench_function("lab_poll_with_pending_wake", |b| {
        let reactor = LabReactor::new();
        let mut events = Events::with_capacity(64);

        b.iter(|| {
            // Schedule a wake
            reactor.wake().expect("wake");
            // Poll should return quickly
            events.clear();
            let count = reactor
                .poll(&mut events, Some(Duration::from_millis(0)))
                .expect("poll");
            std::hint::black_box(count);
        });
    });

    // Benchmark wake overhead
    group.bench_function("lab_wake_overhead", |b| {
        let reactor = LabReactor::new();

        b.iter(|| {
            reactor.wake().expect("wake");
        });
    });

    // Benchmark poll without events (should return quickly with timeout)
    group.bench_function("lab_poll_empty_instant", |b| {
        let reactor = LabReactor::new();
        let mut events = Events::with_capacity(64);

        b.iter(|| {
            events.clear();
            let count = reactor
                .poll(&mut events, Some(Duration::from_millis(0)))
                .expect("poll");
            std::hint::black_box(count);
        });
    });

    group.finish();
}

// =============================================================================
// WAKER THROUGHPUT BENCHMARKS
// =============================================================================

fn bench_waker_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("reactor/waker");

    // Benchmark waker creation
    group.bench_function("create_noop_waker", |b| {
        b.iter(|| {
            let waker = noop_waker();
            std::hint::black_box(waker);
        });
    });

    // Benchmark waker clone
    group.bench_function("clone_waker", |b| {
        let waker = noop_waker();
        b.iter(|| {
            let cloned = waker.clone();
            std::hint::black_box(cloned);
        });
    });

    // Benchmark wake_by_ref
    group.bench_function("wake_by_ref", |b| {
        let (waker, count) = counting_waker();
        b.iter(|| {
            waker.wake_by_ref();
        });
        std::hint::black_box(count.load(Ordering::Relaxed));
    });

    // Benchmark wake (consumes waker)
    group.bench_function("wake_consuming", |b| {
        b.iter(|| {
            let (waker, _) = counting_waker();
            waker.wake();
        });
    });

    group.finish();
}

// =============================================================================
// INTEREST FLAGS BENCHMARKS
// =============================================================================

fn bench_interest_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("reactor/interest");

    group.bench_function("create_readable", |b| {
        b.iter(|| std::hint::black_box(Interest::READABLE));
    });

    group.bench_function("create_writable", |b| {
        b.iter(|| std::hint::black_box(Interest::WRITABLE));
    });

    group.bench_function("combine_interests", |b| {
        b.iter(|| std::hint::black_box(Interest::READABLE | Interest::WRITABLE));
    });

    group.bench_function("check_contains", |b| {
        let interest = Interest::READABLE | Interest::WRITABLE;
        b.iter(|| std::hint::black_box(interest.contains(Interest::READABLE)));
    });

    group.bench_function("intersect_interests", |b| {
        let a = Interest::READABLE | Interest::WRITABLE;
        let b_int = Interest::READABLE;
        b.iter(|| std::hint::black_box(a & b_int));
    });

    group.finish();
}

// =============================================================================
// TCP CONNECTION BENCHMARKS (Blocking baseline)
// =============================================================================

fn bench_tcp_connection(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp/connection");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(5));

    // Benchmark TCP listener accept (blocking)
    group.bench_function("blocking_accept", |b| {
        b.iter_custom(|iters| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("local_addr");

            let connector_handle = thread::spawn(move || {
                for _ in 0..iters {
                    let _ = TcpStream::connect(addr);
                }
            });

            let start = Instant::now();
            let mut accepted = 0u64;
            while accepted < iters {
                match listener.accept() {
                    Ok(_) => accepted += 1,
                    Err(_) => break,
                }
            }
            let elapsed = start.elapsed();

            connector_handle.join().expect("join");
            elapsed
        });
    });

    // Benchmark connect throughput
    group.bench_function("blocking_connect", |b| {
        b.iter_custom(|iters| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("local_addr");

            let acceptor_handle = thread::spawn(move || {
                for _ in 0..iters {
                    let _ = listener.accept();
                }
            });

            let start = Instant::now();
            for _ in 0..iters {
                let _ = TcpStream::connect(addr);
            }
            let elapsed = start.elapsed();

            acceptor_handle.join().expect("join");
            elapsed
        });
    });

    group.finish();
}

// =============================================================================
// ECHO LATENCY BENCHMARKS
// =============================================================================

fn bench_echo_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp/echo_latency");

    for &size in &[64_usize, 1024, 8192] {
        let size_u64 = u64::try_from(size).expect("size fits u64");
        group.throughput(Throughput::Bytes(size_u64));

        group.bench_with_input(
            BenchmarkId::new("blocking_echo", size),
            &size,
            |b, &size| {
                // Set up echo server
                let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
                let addr = listener.local_addr().expect("local_addr");

                let server_handle = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().expect("accept");
                    let mut buf = vec![0u8; 65536];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });

                // Give server time to start
                thread::sleep(Duration::from_millis(10));

                let mut client = TcpStream::connect(addr).expect("connect");
                client.set_nodelay(true).expect("nodelay");
                let data = vec![0xAB_u8; size];
                let mut buf = vec![0u8; size];

                b.iter(|| {
                    client.write_all(&data).expect("write");
                    client.read_exact(&mut buf).expect("read");
                    std::hint::black_box(&buf);
                });

                drop(client);
                server_handle.join().expect("join");
            },
        );
    }

    group.finish();
}

// =============================================================================
// SCALABILITY BENCHMARKS
// =============================================================================

fn bench_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp/scalability");
    group.sample_size(20);

    for &count in &[10_usize, 50] {
        let count_u64 = u64::try_from(count).expect("count fits u64");
        group.throughput(Throughput::Elements(count_u64));

        group.bench_with_input(
            BenchmarkId::new("concurrent_connections", count),
            &count,
            |b, &count| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;

                    for _ in 0..iters {
                        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
                        let addr = listener.local_addr().expect("local_addr");

                        // Create connections
                        let handles: Vec<_> = (0..count)
                            .map(|_| thread::spawn(move || TcpStream::connect(addr)))
                            .collect();

                        let start = Instant::now();

                        // Accept all connections
                        let mut accepted = Vec::with_capacity(count);
                        while accepted.len() < count {
                            if let Ok((stream, _)) = listener.accept() {
                                accepted.push(stream);
                            }
                        }

                        total += start.elapsed();

                        // Join connector threads
                        for h in handles {
                            let _ = h.join();
                        }
                    }

                    total
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// TOKEN OPERATIONS BENCHMARKS
// =============================================================================

fn bench_token_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("reactor/token");

    group.bench_function("create_token", |b| {
        b.iter(|| {
            let token = Token(std::hint::black_box(42));
            std::hint::black_box(token);
        });
    });

    group.bench_function("compare_tokens", |b| {
        let t1 = Token(1);
        let t2 = Token(2);
        b.iter(|| std::hint::black_box(t1 == t2));
    });

    group.bench_function("hash_token", |b| {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let token = Token(42);
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            token.hash(&mut hasher);
            std::hint::black_box(hasher.finish());
        });
    });

    group.finish();
}

// =============================================================================
// LAB REACTOR SPECIFIC BENCHMARKS
// =============================================================================

fn bench_lab_reactor(c: &mut Criterion) {
    let mut group = c.benchmark_group("lab_reactor");

    // Benchmark Lab reactor creation
    group.bench_function("create", |b| {
        b.iter(|| {
            let reactor = LabReactor::new();
            std::hint::black_box(reactor);
        });
    });

    // Benchmark Lab reactor with multiple registrations
    group.bench_function("multi_registration_poll", |b| {
        let reactor = LabReactor::new();
        let listeners: Vec<_> = (0..10)
            .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind"))
            .collect();

        let tokens: Vec<_> = listeners
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let token = Token::new(i);
                reactor
                    .register(l, token, Interest::READABLE)
                    .expect("register");
                token
            })
            .collect();
        let _ = tokens; // Keep tokens in scope

        let mut events = Events::with_capacity(64);
        b.iter(|| {
            events.clear();
            let count = reactor
                .poll(&mut events, Some(Duration::from_millis(0)))
                .expect("poll");
            std::hint::black_box(count);
        });
    });

    group.finish();
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_reactor_registration,
    bench_reactor_wake,
    bench_waker_throughput,
    bench_interest_operations,
    bench_tcp_connection,
    bench_echo_latency,
    bench_scalability,
    bench_token_operations,
    bench_lab_reactor,
);

criterion_main!(benches);
