//! Same-process head-to-head: asupersync vs tokio on the operations a server
//! does constantly (br-asupersync-issue65-criticisms-kpmoy5.1.1).
//!
//! Every group runs a tokio row and the matching asupersync rows inside one
//! Criterion group, so both share the host, the build profile, and the
//! moment. Compare rows within a run; absolute values are host-specific.
//!
//! - `spawn_join`: a parent spawns `n` trivial tasks, keeps every handle, and
//!   awaits them all. Tokio's parent is the `block_on` future; the asupersync
//!   rows use `RuntimeHandle::spawn` (Direct admission, the default, plus
//!   Mailbox admission as an informational row) and the structured
//!   `Cx::spawn` + `TaskHandle::join` path users are told to use.
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
//! - `join_set`: a parent spawns `n` trivial members into a `JoinSet` and
//!   collects them in completion order with `join_next`.
//! - `tcp_rr`: `conns` loopback TCP connections, one server echo task and one
//!   client task per connection, each client making 200 round trips of a
//!   64-byte request. Throughput comes from Criterion. Round-trip p50/p99
//!   are printed as `tcp_rr latency ...` lines before the group runs (only
//!   when no filter is given or a filter names `tcp_rr`).
//! - `http1_hello`: `conns` keep-alive connections to asupersync's HTTP/1.1
//!   server (`Http1Listener::run_in`, a handler answering a 5-byte body),
//!   each client sending 200 `GET /` requests one after another. asupersync
//!   only: hyper is not a dependency of this crate. Latency lines print as
//!   for `tcp_rr`.
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

/// The same multi-thread runtime with spawns admitted through the spawn
/// mailbox; informational next to the default Direct admission.
fn asup_multi_mailbox() -> Runtime {
    RuntimeBuilder::new()
        .worker_threads(WORKERS)
        .spawn_admission(asupersync::runtime::config::SpawnAdmissionMode::Mailbox)
        .build()
        .expect("build asupersync multi-thread runtime with mailbox admission")
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

/// The multi-thread tokio runtime with its I/O driver, for `tcp_rr`. The
/// other rows keep `tokio_multi`, which has none. asupersync's default
/// runtime always builds its platform reactor.
fn tokio_multi_io() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .enable_io()
        .build()
        .expect("build tokio multi-thread runtime with I/O")
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

fn asup_join_set(rt: &Runtime, n: usize) -> Duration {
    rt.block_on(rt.handle().spawn(async move {
        let cx = Cx::current().expect("a spawned task has a Cx");
        let start = Instant::now();
        let mut set = asupersync::combinator::JoinSet::in_cx(&cx);
        for i in 0..n {
            set.spawn(&cx, move |_| async move { Ok::<usize, ()>(i) })
                .expect("JoinSet::spawn");
        }
        let mut sum = 0usize;
        while let Some(outcome) = set.join_next(&cx).await {
            sum = sum.wrapping_add(outcome.expect("member ok"));
        }
        black_box(sum);
        start.elapsed()
    }))
}

fn tokio_join_set(rt: &tokio::runtime::Runtime, n: usize) -> Duration {
    rt.block_on(async move {
        let start = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for i in 0..n {
            set.spawn(async move { i });
        }
        let mut sum = 0usize;
        while let Some(result) = set.join_next().await {
            sum = sum.wrapping_add(result.expect("tokio member"));
        }
        black_box(sum);
        start.elapsed()
    })
}

/// Bytes in each `tcp_rr` request and in its echoed response.
const TCP_RR_MESSAGE: usize = 64;
/// Round trips each `tcp_rr` connection makes per batch.
const TCP_RR_ROUND_TRIPS: usize = 200;
/// Batches whose per-round-trip latencies are pooled for the p50/p99 report.
const TCP_RR_LATENCY_BATCHES: usize = 10;

/// One `tcp_rr` batch: its wall time, plus each round trip's latency in
/// nanoseconds when the batch records them.
type RrBatch = (Duration, Vec<u64>);

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// `conns` loopback connections, each served by its own echo task. Every
/// client task makes `TCP_RR_ROUND_TRIPS` request/response round trips.
/// Connection setup is outside the timed span.
fn asup_tcp_rr(rt: &Runtime, conns: usize, record: bool) -> RrBatch {
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};
    use asupersync::net::{TcpListener, TcpStream};

    rt.block_on(rt.handle().spawn(async move {
        let cx = Cx::current().expect("a spawned task has a Cx");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("listener address");
        let mut server = cx
            .spawn(move |cx| async move {
                let mut echoes = Vec::with_capacity(conns);
                for _ in 0..conns {
                    let (mut stream, _) = listener.accept().await.expect("accept");
                    stream.set_nodelay(true).expect("server nodelay");
                    let echo = cx.spawn(move |_| async move {
                        let mut buf = [0u8; TCP_RR_MESSAGE];
                        while stream.read_exact(&mut buf).await.is_ok() {
                            if stream.write_all(&buf).await.is_err() {
                                break;
                            }
                        }
                    });
                    echoes.push(echo.expect("spawn echo task"));
                }
                for mut echo in echoes {
                    let _ = echo.join(&cx).await;
                }
            })
            .expect("spawn server task");
        let mut streams = Vec::with_capacity(conns);
        for _ in 0..conns {
            let stream = TcpStream::connect(addr).await.expect("connect");
            stream.set_nodelay(true).expect("client nodelay");
            streams.push(stream);
        }

        let start = Instant::now();
        let mut clients = Vec::with_capacity(conns);
        for mut stream in streams {
            let client = cx.spawn(move |_| async move {
                let mut latencies = Vec::with_capacity(if record { TCP_RR_ROUND_TRIPS } else { 0 });
                let mut buf = [7u8; TCP_RR_MESSAGE];
                for _ in 0..TCP_RR_ROUND_TRIPS {
                    let sent = Instant::now();
                    stream.write_all(&buf).await.expect("request");
                    stream.read_exact(&mut buf).await.expect("response");
                    if record {
                        latencies.push(nanos(sent.elapsed()));
                    }
                }
                latencies
            });
            clients.push(client.expect("spawn client task"));
        }
        let mut latencies = Vec::new();
        for mut client in clients {
            latencies.extend(client.join(&cx).await.expect("client task"));
        }
        let elapsed = start.elapsed();
        let _ = server.join(&cx).await;
        (elapsed, latencies)
    }))
}

fn tokio_tcp_rr(rt: &tokio::runtime::Runtime, conns: usize, record: bool) -> RrBatch {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    rt.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let mut echoes = Vec::with_capacity(conns);
            for _ in 0..conns {
                let (mut stream, _) = listener.accept().await.expect("accept");
                stream.set_nodelay(true).expect("server nodelay");
                echoes.push(tokio::spawn(async move {
                    let mut buf = [0u8; TCP_RR_MESSAGE];
                    while stream.read_exact(&mut buf).await.is_ok() {
                        if stream.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                }));
            }
            for echo in echoes {
                let _ = echo.await;
            }
        });
        let mut streams = Vec::with_capacity(conns);
        for _ in 0..conns {
            let stream = TcpStream::connect(addr).await.expect("connect");
            stream.set_nodelay(true).expect("client nodelay");
            streams.push(stream);
        }

        let start = Instant::now();
        let mut clients = Vec::with_capacity(conns);
        for mut stream in streams {
            clients.push(tokio::spawn(async move {
                let mut latencies = Vec::with_capacity(if record { TCP_RR_ROUND_TRIPS } else { 0 });
                let mut buf = [7u8; TCP_RR_MESSAGE];
                for _ in 0..TCP_RR_ROUND_TRIPS {
                    let sent = Instant::now();
                    stream.write_all(&buf).await.expect("request");
                    stream.read_exact(&mut buf).await.expect("response");
                    if record {
                        latencies.push(nanos(sent.elapsed()));
                    }
                }
                latencies
            }));
        }
        let mut latencies = Vec::new();
        for client in clients {
            latencies.extend(client.await.expect("client task"));
        }
        let elapsed = start.elapsed();
        let _ = server.await;
        (elapsed, latencies)
    })
}

/// Prints the pooled round-trip latency percentiles of
/// `TCP_RR_LATENCY_BATCHES` recorded batches of `group`. Criterion reports
/// throughput; it has no percentile output.
fn report_rr_latency(group: &str, row: &str, conns: usize, mut batch: impl FnMut() -> RrBatch) {
    let mut elapsed = Duration::ZERO;
    let mut latencies = Vec::new();
    for _ in 0..TCP_RR_LATENCY_BATCHES {
        let (batch_elapsed, batch_latencies) = batch();
        elapsed += batch_elapsed;
        latencies.extend(batch_latencies);
    }
    latencies.sort_unstable();
    let at = |percent: usize| {
        let index = (latencies.len() * percent / 100).min(latencies.len() - 1);
        Duration::from_nanos(latencies[index]).as_secs_f64() * 1e6
    };
    println!(
        "{group} latency {row}/{conns}: {} round trips, p50 {:.1} us, p99 {:.1} us, {:.0} round trips/s",
        latencies.len(),
        at(50),
        at(99),
        latencies.len() as f64 / elapsed.as_secs_f64(),
    );
}

/// Keep-alive requests each `http1_hello` connection sends per batch.
const HTTP1_REQUESTS: usize = 200;
const HTTP1_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

/// Reads one HTTP/1.1 response with a `Content-Length` body from `stream`,
/// keeping bytes past it in `buf` for the next response.
async fn read_http1_response(
    stream: &mut asupersync::net::TcpStream,
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    use asupersync::io::AsyncReadExt;

    let mut chunk = [0u8; 1024];
    loop {
        if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&buf[..head_end]).map_err(std::io::Error::other)?;
            let body_len = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .ok_or_else(|| std::io::Error::other("response without Content-Length"))?;
            let total = head_end + 4 + body_len;
            if buf.len() >= total {
                buf.drain(..total);
                return Ok(());
            }
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// `conns` keep-alive connections to asupersync's HTTP/1.1 server
/// (`Http1Listener::run_in`), whose handler answers every request with a
/// fixed 5-byte body. Each client sends `HTTP1_REQUESTS` requests one after
/// another. Connection setup and shutdown are outside the timed span.
fn asup_http1_hello(rt: &Runtime, conns: usize, record: bool) -> RrBatch {
    use asupersync::http::h1::server::HostPolicy;
    use asupersync::http::h1::{Http1Config, Http1Listener, Http1ListenerConfig, Response};
    use asupersync::io::AsyncWriteExt;
    use asupersync::net::TcpStream;

    rt.block_on(rt.handle().spawn(async move {
        let cx = Cx::current().expect("a spawned task has a Cx");
        // The default host policy rejects every request: allow the one name
        // the client sends.
        let config = Http1ListenerConfig::default().http_config(
            Http1Config::default().host_policy(HostPolicy::AllowList(vec!["localhost".to_owned()])),
        );
        let listener = Http1Listener::bind_with_config(
            "127.0.0.1:0",
            |_request| async { Response::new(200, "OK", b"hello".to_vec()) },
            config,
        )
        .await
        .expect("bind the HTTP/1.1 listener");
        let addr = listener.local_addr().expect("listener address");
        let shutdown = listener.shutdown_signal();
        let mut server = cx
            .spawn(move |cx| async move {
                let _ = listener.run_in(&cx).await;
            })
            .expect("spawn the listener");
        let mut streams = Vec::with_capacity(conns);
        for _ in 0..conns {
            let stream = TcpStream::connect(addr).await.expect("connect");
            stream.set_nodelay(true).expect("client nodelay");
            streams.push(stream);
        }

        let start = Instant::now();
        let mut clients = Vec::with_capacity(conns);
        for mut stream in streams {
            let client = cx.spawn(move |_| async move {
                let mut latencies = Vec::with_capacity(if record { HTTP1_REQUESTS } else { 0 });
                let mut buf = Vec::with_capacity(1024);
                for _ in 0..HTTP1_REQUESTS {
                    let sent = Instant::now();
                    stream.write_all(HTTP1_REQUEST).await.expect("request");
                    read_http1_response(&mut stream, &mut buf)
                        .await
                        .expect("response");
                    if record {
                        latencies.push(nanos(sent.elapsed()));
                    }
                }
                latencies
            });
            clients.push(client.expect("spawn client task"));
        }
        let mut latencies = Vec::new();
        for mut client in clients {
            latencies.extend(client.join(&cx).await.expect("client task"));
        }
        let elapsed = start.elapsed();
        shutdown.trigger_immediate();
        let _ = server.join(&cx).await;
        (elapsed, latencies)
    }))
}

/// Whether this run's benchmark filters can select `http1_hello`; its latency
/// report runs only then.
fn http1_hello_selected() -> bool {
    let filters: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with('-'))
        .collect();
    filters.is_empty()
        || filters.iter().any(|filter| {
            filter.contains("http1_hello") || "http1_hello".starts_with(filter.as_str())
        })
}

/// Times `iters` batches of `n` operations with the clock inside the parent.
fn timed(iters: u64, mut batch: impl FnMut() -> Duration) -> Duration {
    (0..iters).map(|_| batch()).sum()
}

fn bench_spawn_join(c: &mut Criterion) {
    let asup = asup_multi();
    let asup_mailbox = asup_multi_mailbox();
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
        group.bench_function(BenchmarkId::new("asupersync_handle_mailbox", n), |b| {
            b.iter_custom(|iters| timed(iters, || asup_handle_spawn_join(&asup_mailbox, n)));
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

fn bench_join_set(c: &mut Criterion) {
    let asup = asup_multi();
    let tokio = tokio_multi();
    let mut group = c.benchmark_group("join_set");
    for n in [1_000usize, 10_000] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::new("tokio", n), |b| {
            b.iter_custom(|iters| timed(iters, || tokio_join_set(&tokio, n)));
        });
        group.bench_function(BenchmarkId::new("asupersync", n), |b| {
            b.iter_custom(|iters| timed(iters, || asup_join_set(&asup, n)));
        });
    }
    group.finish();
}

/// Whether this run's benchmark filters (the positional arguments) can
/// select `tcp_rr`; the latency report runs only then.
fn tcp_rr_selected() -> bool {
    let filters: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with('-'))
        .collect();
    filters.is_empty()
        || filters
            .iter()
            .any(|filter| filter.contains("tcp_rr") || "tcp_rr".starts_with(filter.as_str()))
}

fn bench_tcp_rr(c: &mut Criterion) {
    let asup = asup_multi();
    let tokio = tokio_multi_io();
    if tcp_rr_selected() {
        for conns in [1usize, 64] {
            report_rr_latency("tcp_rr", "tokio", conns, || {
                tokio_tcp_rr(&tokio, conns, true)
            });
            report_rr_latency("tcp_rr", "asupersync", conns, || {
                asup_tcp_rr(&asup, conns, true)
            });
        }
    }
    let mut group = c.benchmark_group("tcp_rr");
    group.sample_size(20);
    for conns in [1usize, 64] {
        group.throughput(Throughput::Elements((conns * TCP_RR_ROUND_TRIPS) as u64));
        group.bench_function(BenchmarkId::new("tokio", conns), |b| {
            b.iter_custom(|iters| timed(iters, || tokio_tcp_rr(&tokio, conns, false).0));
        });
        group.bench_function(BenchmarkId::new("asupersync", conns), |b| {
            b.iter_custom(|iters| timed(iters, || asup_tcp_rr(&asup, conns, false).0));
        });
    }
    group.finish();
}

/// asupersync's HTTP/1.1 server only: hyper is not a dependency of this
/// crate, so there is no tokio row here (the standalone probe compares).
fn bench_http1_hello(c: &mut Criterion) {
    let asup = asup_multi();
    if http1_hello_selected() {
        for conns in [1usize, 64] {
            report_rr_latency("http1_hello", "asupersync", conns, || {
                asup_http1_hello(&asup, conns, true)
            });
        }
    }
    let mut group = c.benchmark_group("http1_hello");
    group.sample_size(20);
    for conns in [1usize, 64] {
        group.throughput(Throughput::Elements((conns * HTTP1_REQUESTS) as u64));
        group.bench_function(BenchmarkId::new("asupersync", conns), |b| {
            b.iter_custom(|iters| timed(iters, || asup_http1_hello(&asup, conns, false).0));
        });
    }
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
    bench_yield_storm,
    bench_join_set,
    bench_tcp_rr,
    bench_http1_hello
);
criterion_main!(runtime_vs_tokio);
