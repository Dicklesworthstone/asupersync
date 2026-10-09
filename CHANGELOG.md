# Changelog

All notable changes to [Asupersync](https://github.com/Dicklesworthstone/asupersync) are documented here.

Asupersync is a spec-first, cancel-correct, capability-secure async runtime for Rust.

**Format notes:**

- Versions with a **Release** badge have published GitHub Releases. Plain git tags are milestone markers without release artifacts.
- Commit links point to representative commits, not exhaustive lists.
- Organized by landed capabilities within each version, not by diff order.

Scope window: current work through 2026-09-12, reconstructed from git history,
beads, benchmark ledgers, and live repo artifacts. `v0.5.0` is published to
crates.io and GitHub; release evidence is recorded in `asupersync-v5fn1e`.

## Version Timeline

- **v0.6.0 (unreleased)**: the workspace version was bumped on `main` in
  `85f7a8e59` (2026-09-18), but v0.6.0 has not been tagged, released on GitHub or
  published to crates.io; the latest published version is v0.5.0. Planned
  content: durable ATP sender/receiver journaling and resume across process
  loss, targeted resume-client revocation without peer restart, QUIC protected
  close and post-close accounting shutdown, bounded clock capture and replay,
  and an HTTP/1 fix that answers a rejected request head with
  `400`/`413`/`431` instead of a silent close.
- **v0.5.0 Release**: the approved capability-preserving context installation
  boundary, browser local-task isolation and shutdown, reentrant worker
  retirement, QUIC connection reclamation, and buffered I/O recovery.
  Published from `78b64636e` with nine crates and signed Linux, macOS, and
  Windows assets through DSR without GitHub Actions.
- **v0.4.11 Release**: runtime cancellation and teardown, root-region drain,
  non-blocking file traits, Kafka lifecycle fixes, and bounded QUIC receive
  reassembly. Published from `9b114c1f2` to crates.io and GitHub, with signed
  Linux, macOS, and Windows assets. Release validation and publication are
  recorded in `asupersync-ghxhvm`.
- **v0.4.10 Release**: lock-free `Cx::published_cancel_requested()` for hot
  cancellation polls and a RaptorQ lib-test build fix, preserving the v0.4.3
  public compatibility floor. Published to crates.io on 2026-09-01 from
  `997e8d116` (the sha recorded in the tarball's `.cargo_vcs_info.json`);
  the `v0.4.10` tag was created at that commit on 2026-09-02.
- **v0.4.9 Release**: additive runtime-context and owned-OTLP APIs, SQLite
  cancellation/security/row-metadata correctness, ATP bootstrap-secret
  hardening, and a terminal dual-engine SQLite parity packet, while preserving
  the v0.4.3 public compatibility floor.
- **v0.4.8 Release**: patch release fixing cross-runtime local-task placement,
  foreign-worker cancellation routing, and out-of-order ambient-context guard
  teardown while preserving the v0.4.3 public compatibility floor.
- **v0.4.7 Release**: patch release adding bounded runtime shutdown, typed
  runtime-handle join outcomes, and strict canonical Lab schedule artifacts,
  while hardening authenticated QUIC/ATP reassembly and preserving the v0.4.3
  public compatibility floor.
- **v0.4.6 Release**: patch release tightening HTTP/1 framing parsing and
  completing `Sleep` timer/waker cleanup without changing the v0.4.3 public
  surface.
- **v0.4.5 Release**: patch release fixing timer-parked cancellation and
  driverless Windows connects while preserving the complete v0.4.3 public
  surface.
- **v0.4.4 Release**: patch release preserving acknowledged native-task
  cancellation and hardening HTTP/1 streaming request-body cancellation and
  connection reuse.
- **v0.4.3 Release**: patch release for panic containment across the owned
  future boundary and web error-handler middleware.
- **v0.4.2 Release**: patch release for the owned safe blocking kernel and its
  executable wake, context-policy, quiescence, and performance evidence.
- **v0.4.1 Release**: patch release for capability-aware ATP Stream progress,
  packaged RFC conformance fixtures, and release-evidence pin reconciliation.
- **v0.4.0 Release**: semantic-versioning re-anchor for the current public API,
  plus the runtime correctness, capability, codec, protocol, and evidence work
  landed after `v0.3.10`.
- **v0.3.10 Release**: 2026-07-27 patch release. It included two coherent but
  breaking tracked-session-channel API changes and is not yanked; consumers
  should use `v0.4.0` as the policy-correct compatibility anchor.
- **v0.3.8 workspace version marker**: source for the standalone ATP v0.3.8
  seven-platform release on 2026-07-10; no upstream asupersync tag is implied.
- **v0.3.5 workspace version marker**: internal package/version update on 2026-06-18; no `v0.3.5` git tag or GitHub Release existed when this changelog was refreshed.
- **v0.3.4 Release**: published GitHub Release/tag dated 2026-06-07 and
  superseded by `v0.3.10`.
- **v0.3.3 Pre-release**: superseded by `v0.3.4`.
- **v0.3.2 Release** and older entries: retained release-history sections below.

---

## [Unreleased]

## [v0.6.0] - Unreleased (version bumped on `main` 2026-09-18; not yet published)

250 commits since v0.5.0. The theme is **durability**: ATP transfers now survive
a process dying mid-send or mid-receive, QUIC closes cleanly and stops accounting
afterwards, and the clock can be captured and replayed within bounded windows.

### Migration note — `Outcome<T, E>` and conditionally derived `Debug`

**Correction (2026-09-22):** the attribution below is wrong. The
`#[derive(Debug, ...)]` on `Outcome<T, E>` is byte-identical at v0.4.3 and at
v0.5.0 (`src/types/outcome.rs` line 217 in both tags), so it cannot be what
changed in 0.5.0. The conditional-`Debug` behaviour described below is
accurate. It has held since before v0.4.3, so it may explain an `E0277` in new
code, but it is not a 0.5.0 change.

**Root cause (2026-09-24, `asupersync-bi2462.139`):** the downstream break was
not an asupersync API change. `Cx::for_request`, `Cx::for_request_with_budget`
and `Cx::for_testing` have been gated behind the `test-internals` feature since
before v0.4.3, and that is unchanged in 0.5.0. `sqlmodel` 0.4.0 enabled
`asupersync/test-internals` in its normal (non-dev) dependencies, so every
build that pulled in `sqlmodel` 0.4 also had the test-only constructors, and
production code came to rely on them. `sqlmodel` 0.5.0 stopped leaking the
feature (sqlmodel_rust `580e66e`). Upgrading to it together with asupersync 0.5
removed the constructors from production builds. `--all-targets` builds still
compiled because dev-dependencies enable the feature. Production code should
not call these constructors: take the ambient context with `Cx::current()`, or
mint one from the runtime with `Runtime::request_cx_with_budget`. Keep
`test-internals` in `[dev-dependencies]` only.

This is not new in 0.6.0; it landed in **0.5.0** and is documented here because
it is a silent, source-breaking change for downstream crates that only surfaces
under `--all-targets`, so it tends to be discovered in test code.

`Outcome<T, E>` derives `Debug`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome<T, E> { Ok(T), Err(E), Cancelled(CancelReason), Panicked(PanicPayload) }
```

A derived `Debug` is **conditional**: `Outcome<T, E>: Debug` holds only when
`T: Debug` and `E: Debug`. Code that debug-formats a whole `Outcome` whose `Ok`
type is not `Debug` therefore stops compiling.

- **Symptom:** `E0277`, "`...` doesn't implement `Debug`", pointing at a
  `{:?}` of an entire `Outcome`, typically inside a test or an `expect`/`panic!`.
- **Cause:** the `Ok` type is not `Debug`. Pooled connection handles, raw socket
  wrappers and similar opaque types commonly are not.
- **Fix:** match the variants instead of formatting the whole enum. This also
  preserves more diagnostic detail than the original:

```rust
match outcome {
    Outcome::Ok(value) => value,
    Outcome::Err(error) => panic!("operation failed: {error:?}"),
    Outcome::Cancelled(reason) => panic!("operation cancelled: {reason:?}"),
    Outcome::Panicked(payload) => panic!("operation panicked: {payload:?}"),
}
```

The derive itself is correct and is not changing. Thanks to the
`mcp_agent_mail_rust` maintainers for reporting the concrete breakage.

### Breaking CLI change — plaintext ATP-over-TCP is refused off loopback

`atp send`, `atp recv`, `atp serve` and `asupersync atp serve` now refuse
`--transport tcp` (the default transport) toward or on any non-loopback
address unless `--allow-plaintext` is given. `asupersync atp send`, which
always sends plaintext TCP, refuses a non-loopback target the same way. The receivers' default listen
address, `0.0.0.0`, counts as non-loopback, so a bare `atp recv DIR` or
`asupersync atp serve` needs the flag or a loopback `--listen`. Loopback
transfers are unchanged.

Why: that transport is plaintext and its manifest is unauthenticated. The
SHA-256 and Merkle checks catch corruption, but an on-path attacker can
substitute the manifest and the bytes together. For transfers between hosts,
use `--transport quic` (or `auto`), which is authenticated and encrypted, or
pass `--allow-plaintext` to accept the risk. An SSH-bootstrapped send forwards
the flag to the remote receiver, so an older remote `atp` rejects the unknown
flag and has to be upgraded (`asupersync-bi2462.126`).

### Breaking change — `QuicFrame` gained three variants and is non-exhaustive

`net::atp::protocol::QuicFrame` gained `NewConnectionId`,
`RetireConnectionId` and `NewToken`, which the native QUIC stack decodes for
connection ID management and key updates. A `match` on `QuicFrame` outside
this crate that listed every variant no longer compiles. The enum is now
`#[non_exhaustive]`, so such a `match` needs a wildcard arm once, and later
frame types will not break it again.

`net::quic_native::client_handshake_over_udp` keeps its v0.5.0 signature,
`Result<(), QuicTlsError>`. During 0.6.0 development it briefly returned the
1-RTT packets that arrive before the handshake completes; the new
`client_handshake_over_udp_with_early_data` returns them, like
`server_handshake_over_udp_with_early_data` on the server side
(`asupersync-nao6pg`, GitHub #77).

### Breaking change — a child region keeps its opener's capability set

`ChildRegionOpening` and `ChildRegion` gained a type parameter, `Caps`, which
defaults to `cap::All`. `Cx::open_child_region` returns
`ChildRegionOpening<Caps>` for the opener's `Caps`, and the child's `cx()` is a
`Cx<Caps>`. Before, a restricted context such as `Cx<cap::None>` could open a
child region and get back a `Cx<cap::All>` with every gated API, such as
`spawn` and `blocking_pool_handle`.

A caller holding `Cx<cap::All>` gets the same types as in v0.5.0. Code that
opened a child region from a restricted context and relied on the wider child
`Cx` no longer compiles; that was the escalation (`05f6ab6c6`,
`asupersync-cwxavr`, GitHub #77).

### Breaking build change — wasm32 builds need `default-features = false`

The default features now include `runtime-core` and `native-runtime`
(`0967799e0`). A wasm32 build that keeps the default features fails with
"feature `native-runtime` is forbidden on wasm32 browser builds". At v0.5.0
the defaults did not include `native-runtime`, so this check did not fire.

Turn the defaults off and pick one browser profile, as the wasm documentation
shows:

```toml
asupersync = { version = "0.6", default-features = false, features = ["wasm-browser-prod"] }
```

Native builds compile as before. Both features are markers for the planned
runtime split and gate none of the v0.5.0 code (GitHub #77).

### Behavior change — the legacy ATP SDK session refuses work it cannot do

`asupersync::atp::sdk::AtpSession` has no transport and no object store.
Several of its methods used to report work that never happened. They now
return typed errors (`asupersync-bi2462.127`):

- `send_object`, `stream_large_buffer`, `verify_object` and `path_diagnose`
  return `AtpError::Policy(PolicyError::FeatureDisabled)`. Before, they
  returned a transfer handle that moved no bytes, a stream handle reporting
  a committed stream with zero bytes sent, a verdict that compared the
  object id's own hash with itself, and a `NoAvailablePaths` diagnosis that
  never probed a path.
- `cancel_transfer` on an id the session does not hold returns
  `ProtocolError::SessionStateMismatch`. Before, it returned `Ok(())`.

Signatures are unchanged. Use `asupersync::net::atp::sdk`, the canonical
SDK: `AtpSdk::native_transfers` (feature `tls`) moves bytes.

The net SDK's `AtpSession::verify_object` now hashes files in bounded reads,
and only the expected hash decides `integrity_check_passed`. Before, a tar
archive (zero padding at a 512-byte multiple) and any empty file whose path
lacked "empty" failed even when the hash matched. Its methods now report a
cancelled `Cx` as `Cancelled` rather than as
`PlatformError::OperatingSystemError`.

### Behavior change — the production runtime enforces explicit poll quotas

`Budget::with_poll_quota` bounds how many times a task is polled. The
`LabRuntime` always enforced it; the production scheduler ignored it, so a
quota that held in lab tests did not hold in production
(`asupersync-r017wv`). The production scheduler now spends one poll before
each poll of a task with a finite quota, and requests cancellation with
`CancelKind::PollQuota` once it is spent.

Budgets without a quota are unaffected: `Budget::new()`, `Budget::default()`
and `Budget::INFINITE` carry `u32::MAX`, as do the root region and the
`block_on` request context. Code that sets a quota explicitly now gets the
documented bound. That covers scope and region budgets, AppSpec
`budgets[].poll_quota`, and a request budget such as `with_poll_quota(10_000)`,
which now cancels a long-running streaming handler after 10,000 polls. Raise
or drop such quotas where work is meant to be unbounded.

A cancelled task's cleanup budget stays advisory in production. Work the task
starts during cleanup (spawned tasks, scopes and regions) does not inherit the
cleanup budget's poll quota. A cancellation already requested on a task's
`Cx` keeps its reason when the quota runs out (`asupersync-0fvvq9`).

### Behavior change — I/O without the IO capability is refused

The I/O entry points that take no `Cx` used to ignore the calling task's
capabilities, so a task narrowed to exclude IO could still connect, bind,
open files, spawn processes and register signal handlers. They now check the
calling task's context. Without the IO capability they return an
`io::Error` of kind `PermissionDenied` whose inner error is
`asupersync::cx::IoCapabilityDenied` (`[ASUP-E009]`). This applies to
`TcpStream::connect`, `TcpListener::bind`, `UdpSocket::bind`, the Unix
socket types, `net::lookup_all`, the `fs` path functions and `File::open`,
`process::Command::spawn`, `signal::signal` and the HTTP client
(`asupersync-issue65-criticisms-kpmoy5.5.3`).

Unaffected: threads outside the runtime, and every context that carries IO
(the default for tasks, `block_on` and request contexts). Affected: code
under `Cx::push_restriction` or `set_current_restricted` without IO, and
AppSpec work units that require neither the io nor the net capability. Grant
the capability, or run the call under an explicit context with
`cx.with_ambient(future)`.

### Behavior change — adaptive cancel preemption is opt-in

`RuntimeConfig::enable_adaptive_cancel_streak` now defaults to `false`. A
default runtime uses the fixed cancel-streak limit of 16
(`cancel_lane_max_streak`), as `LabRuntime` already did. The discounted-UCB1
selector over `{4, 8, 16, 32, 64}` is unchanged and remains available through
`RuntimeBuilder::enable_adaptive_cancel_streak(true)`. The 64-core host
profiles keep enabling it explicitly.

Measured in one process with interleaved rounds (adaptive vs fixed 16, four
workers, default features, two hosts), the selector did not beat the fixed
limit on cancel-heavy workloads:
- the drain time of 2,000 or 10,000 aborted tasks was about the same;
- the latency of ready work during the drain was mixed: better on some
  percentiles, worse on others.

On plain work it was slower on spawn+join, `yield_now` and channel round
trips. That was 23-29% on one host. On the other, spawn+join was 16% slower,
ping-pong 11% and `yield_now` 1%. Spawn from four producers was within noise.
The owner's delegated rule (keep it on only if it wins on cancel-heavy work
and loses nowhere else) therefore makes the fixed limit the default
(`asupersync-issue65-criticisms-kpmoy5.1.12`).

### Behavior change — budget deadlines are enforced when they pass

A task's budget deadline (a region or task deadline in its `Budget`) used to
be checked only at checkpoints, so a task parked in a cancel-aware wait (a
channel receive, a lock, a semaphore) outlived it indefinitely, and so did
anything that closed or joined its region. The runtime now arms one timer per
task that has a deadline. At the deadline the task's context is cancelled with
`CancelKind::Deadline` and its parked wait is woken. Tasks without a deadline
pay nothing. Consequences:

- A task that runs past its deadline without checkpointing is cancelled at
  the deadline. If it then returns a value without acknowledging the
  cancellation (a failed `checkpoint`), the value is reported as task-level
  cancellation, the existing rule for cancellation-blind late values.
- A task spawned under a deadline that has already passed is cancelled at
  the runtime's next timer turn, which can come before its first poll. Before,
  it ran until its first checkpoint, or to completion if it never checked.
  Budget deadlines are instants on the runtime clock, whose zero is the first
  time the process reads it: `Budget::with_deadline_at_secs(30)` means 30 s
  after that, not 30 s from now. For a timeout, use
  `Budget::tightened_by_timeout` with the current time.
- Async finalizers are not armed (their masked infrastructure deadline is
  unchanged).

(asupersync-pev2xi)

### Behavior change — `RuntimeBuilder` starts with an on-demand blocking pool

`RuntimeBuilder::new()` and every preset built on it (`current_thread`,
`multi_thread`, `high_throughput`, `low_latency`) now configure
`blocking_threads(0, 512)` on native targets. No pool thread starts until the
first blocking job, and idle threads retire. Before, a bare builder had no
pool, so `spawn_blocking`, `File`'s poll traits and the other blocking-backed
`fs` facades ran their syscalls inline on an async worker and stalled every
task scheduled behind them. `#[main]`/`#[test]` already configured this pool;
the builder default now matches them. Consequences:

- `blocking_threads(0, 0)` restores the old behaviour: no pool, inline
  fallback. `#[asupersync::main(blocking = 0)]` and `#[asupersync::test(blocking = 0)]`
  now emit it explicitly; before, the macro emitted no blocking step and would
  have inherited the new default.
- APIs that refuse to run without a pool now accept on a default runtime:
  `spawn_blocking_drained`, `Runtime::spawn_blocking` (it returns `Some`),
  `blocking_handle`, `ScopedFs`, scoped Kafka consumers, persistent
  membership, the durable symbol service, `NativeRemoteDiscoveryDriver::run`,
  and managed-app `Blocking` capability binds.
- Setting only `ASUPERSYNC_BLOCKING_MIN_THREADS` (or `[blocking] min_threads`)
  now keeps the default maximum of 512 instead of a pool of exactly that size.
- `RuntimeConfig::default()`, `Runtime::with_config`, `LabRuntime` and wasm32
  builds are unchanged: they still have no pool unless one is configured.
- CPU-bound fan-out onto the pool reads the cap of an explicitly sized pool
  (`blocking_threads`, `ASUPERSYNC_BLOCKING_MAX_THREADS`, `[blocking]
  max_threads`, the entry macros) as its CPU width, as before. The default
  pool's cap is not a CPU estimate, so ATP's RaptorQ decode, symbol
  verification and parallel packet unprotect bound their width on it by the
  host's available parallelism. Without a pool, decode used the same bound
  and the other two ran serially.

(asupersync-issue65-criticisms-kpmoy5.1.15)

### Behavior change — a race drains what its losing branches spawned

`race!`, blocking `select!`, `Cx::race_drained*`, `Cx::race_drained_with*` and
`Cx::hedge_drained_with*` cancelled and drained each losing branch task, but a
task that a branch spawned through its own `Cx` lived in the caller's region
and kept running after the race returned, until that region closed. Each
branch now runs in its own child region of the caller's region:

- When the race resolves, every losing branch's region is cancelled and
  awaited before the race returns, so nothing a loser started is still
  running. The loser task's own cancellation and its `RaceLost` attribution
  are unchanged; its descendants see `RaceLost` (or `ParentCancelled` in
  nested regions). A failed race (owner cancellation, admission failure)
  treats every branch as a loser and drains with the race's reason.
- Tasks the winner spawned keep running after the race returns and can still
  spawn. The winner's region closes by itself once its last task finishes; it
  stays owned by the caller's region.
- Inside a caller region with admission limits (`RegionLimits`), branches stay
  in that region as before, so the limits still count every branch.
- Dropping a race future keeps its documented behavior: the branch regions
  stay owned by the caller's region, which remains the cleanup boundary.

`Scope::race`, `Scope::race_all` and the other `Scope` combinators take
handles the caller already spawned and are unchanged.
(asupersync-issue65-criticisms-kpmoy5.2.2)

### Behavior change — a supervised `NatsClient` sends keepalive PINGs

`NatsClient::connect` and `NatsClient::connect_with_config` now enable a
client-side keepalive: `NatsKeepalive::default()`, with nats.go's defaults.

- The connection supervisor sends a `PING` every 2 minutes.
- When 2 are still unanswered at a tick, it replaces the connection: it
  reconnects within `NatsConfig`'s limits and replays the subscriptions.
- A half-open connection is therefore replaced within about 6 minutes. Before,
  it lasted until the kernel gave up, about 15 minutes on Linux.
- A peer that never answers `PING` is reconnected about every 6 minutes.

`NatsClient::ping` waits for the `PONG` that answers its own `PING`, so a
publish-then-ping flush still covers the publishes. With a keepalive it waits
at most `interval × max_pings_out`.

To keep the v0.5.0 wire behaviour, use
`NatsClient::connect_with_keepalive(cx, config, NatsKeepalive::disabled())`.
A client whose `Cx` has no spawn gateway (and so no supervisor) is unchanged.
(asupersync-messaging-client-audit-k6pxks item 8)

### Behavior change — HTTP `deflate` is the zlib format

`Content-Encoding: deflate` is now the zlib format that RFC 9110 requires
(RFC 1950: a two-byte header, the deflate data and an Adler-32 trailer).
Before, `DeflateCompressor`, and through it the response compression
middleware, produced raw RFC 1951 data labelled `deflate`, which clients that
decode `deflate` as zlib reject. `DeflateDecompressor` decodes zlib and still
accepts raw data when the zlib header check fails. Code that calls
`DeflateCompressor` directly now gets zlib framing; see
`docs/http_deflate_compatibility.md` (`asupersync-zodgeb`).

### Native GenServers and actors

`Cx::spawn_gen_server`, `Cx::spawn_actor` and `Cx::spawn_supervised_actor`
run GenServers and actors as tasks on the native runtime, where only the lab
could spawn them before. Their handles report the admitted task id, abort and
join through the runtime task, and their monitors and links fire in
production (`asupersync-yvs9cx`).

### Fiber cancellation

Every fiber started by `cx::fiber::scope` inside a task has its own
cancellation (its own `Cx::current()` while it runs):

- the task's cancellation reaches every fiber;
- `FiberHandle::cancel` stops one fiber;
- a panicking fiber cancels its siblings with `FailFast`.

The scope still waits for every fiber when its body returns, like
`std::thread::scope` (`asupersync-issue65-criticisms-kpmoy5.3.1`, `.3.2`,
`.3.3`).

### Scheduler decision evidence

`RuntimeBuilder::scheduler_evidence_sink(sink)` records every scheduling
decision of the Lyapunov governor (one `scheduler` evidence entry per
decision, plus the decision contract's audit entries) into an
`EvidenceSink`. Only a runtime built with `enable_governor(true)` makes such
decisions. Before, only a test could attach a sink to a worker. The docs of
`StateTransitionVerifier`, `epoch_gc`, `epoch_tracking` and
`resource_cleanup_verifier` now say the runtime does not use them
(`asupersync-7yq1pv`).

### Durable ATP resume and journaling

- Sender checkpoints are persisted in bounded, append-only journals before EOF,
  so a sender process lost before EOF resumes instead of restarting the transfer.
  Final checkpoints are stored in private, create-only files, and EOF intent is
  recorded before the final publication request.
- Receiver epochs are journaled before writes and acknowledgments, receiver WAL
  is paired with exclusive resumable data files, and journaled receiver sessions
  restore on the shared authenticated port without rebinding.
- A committed `Proof` can be recovered from verified durable receipts and from
  application-validated commit history, including after the source is gone and
  after both peers have exited.
- Shared file publication is gated on durable session history, and retained
  inbox growth is bounded across admission and restart.
- Resume journals, checkpoints and revocation now live in one store, reachable
  through a polled store interface.
- One resume client's authority can be revoked without stopping its peers, and
  protected client revocations reload without restarting healthy peers.
- Concurrent retained resume sessions are served on a single port with delivery
  isolation and bounded retirement, behind strict explicit TLS.

### QUIC connection close

- Endpoint shutdown sends a protected close, commits a local close without
  further congestion work after drain, and caches one encrypted local close for
  bounded UDP retries.
- Trailing frames after a peer `CONNECTION_CLOSE` are ignored, and ATP QUIC
  accounting stops after a native `CONNECTION_CLOSE`.
- Endpoint I/O is retired if shutdown is cancelled or dropped, caller idle pacing
  is preserved after UDP close expiry, and close/clock intervals are subtracted
  with checked `Instant` math.

### Time capture and replay

- Bounded clock observation windows can be captured and replayed, and replay
  tapes persist with bounded canonical decoding.

### Selectable TLS crypto provider

- New feature `tls-core` compiles the TLS code without linking a crypto
  provider, for applications that must not link ring. New feature `tls-ring`
  names the ring selection; `tls` is `tls-ring`, with the same dependencies
  and behavior as before.
- `TlsConnectorBuilder::crypto_provider` and `TlsAcceptorBuilder::crypto_provider`
  take a rustls `CryptoProvider`. Every implicit provider choice (the TLS
  builders, PostgreSQL TLS, native ATP authentication, native QUIC) resolves in
  one order: the explicit provider, then the linked ring provider, then rustls's
  process default; with none, it is a configuration error, not a panic.
- `TlsStream::negotiated_cipher_suite` and
  `TlsStream::negotiated_key_exchange_group` report what the handshake chose.
- Fixed: with CRLs configured, the connector's certificate verifier, the
  acceptor's client-certificate verifier and the native QUIC server-identity
  verifier used rustls's process default (installing ring as that default
  when none was set) instead of the connection's provider. They now use the
  provider the connection uses.

(asupersync-sdua27)

### W3C trace context propagation

Incoming `traceparent`, `tracestate` and `baggage` headers are now continued
by the HTTP and gRPC stacks when you add the new pieces:

- web: `W3CTraceContextMiddleware`, `W3CTraceContextLayer` and
  `MiddlewareStack::with_w3c_trace_context`;
- gRPC: `W3CTraceContextInterceptor`.

A valid incoming trace is continued as a child span: same trace id, new span
id. A missing or invalid one starts a new trace and drops its `tracestate`.
Malformed baggage is dropped without breaking the trace. The web middleware
draws new ids from the request's `Cx` entropy, so lab runs replay them; the
gRPC interceptor gets no `Cx` and uses the operating system's random source.
`observability::continue_or_start_trace` and `continue_or_start_trace_with`
expose the same logic. Before, the extract and inject helpers existed but
nothing called them (`asupersync-cx78tm`).

### Resource-pressure sampling (opt-in)

`RuntimeBuilder::resource_sampling(interval)` runs the resource monitor's OS
probes on a thread every `interval` (at least 100 ms) until the runtime is
dropped. While it runs, every task context the runtime builds carries the
sampled pressure, so `Cx::pressure()` reports headroom instead of `None`.
Child region creation also consults it: under pressure `Low` and `BestEffort`
regions are refused, and at `Emergency` `Normal` ones too. Before, the monitor
was never sampled, so these checks always admitted. The probes are host-wide:
in a container they describe the host, not the container's quota. Sampling is
off by default (`asupersync-1ir2em`).

### HTTP client response decompression (opt-in)

`HttpClientBuilder::response_decompression(true)` (feature `compression`)
sends `Accept-Encoding: gzip, deflate, br` and decodes the response body
through `Response::decode_content`, bounded by the client's maximum body
size. It does not touch a request that sets its own `Accept-Encoding` or a
`Range` header (`asupersync-ecnp0m`).

### Supervisor restart storms are reported

`ManagedSupervisorReport::restart_storm_detected` is set, and a
`restart_storm` trace is recorded, when a managed supervisor configured with
`SupervisionConfig::with_storm_threshold` crosses that threshold. Before, the
storm detector ran but nothing read it (`asupersync-k7muvv`).

### Macaroon replay keys

`MacaroonToken::replay_key()` returns SHA-256 of the token's identifier and
signature, a key for replay caches. Locations are not covered by the
signature, so a token's bytes can change without changing what it authorizes;
the replay key does not (`asupersync-s45073`).

### Retry budgets

`RetryBudget` is a token bucket that many `retry` loops share, so retries
against a failing dependency stay within a rate instead of becoming a retry
storm. `Retry::with_budget(budget)` makes each retry (never a first attempt)
take a token. With none left, the loop fails at once with the error it just
got. `RateLimitedRetryPolicy::budget(now)` builds one from the policy's token
bucket. `RetryBudget`, `RetryTokenBucket` and `RateLimitedRetryPolicy` are
re-exported from `asupersync::combinator` (`asupersync-e9gn8y`).

### Fixed

- HTTP/1 answers a rejected request head with `400`/`413`/`431` instead of
  closing the connection silently, so clients see why a request was refused.
- The scheduler polls the I/O driver every 64 busy dispatches, so I/O readiness
  is not starved by a hot dispatch loop.
- A V3 peer lease is bounded to 24 hours for expiry enforcement.
- A Redis read or write parked on a silent server ends with `Cancelled` at the
  budget deadline of the caller's `Cx` or of the task driving it; before, the
  deadline went unnoticed until the server answered or TCP gave up. A transport
  `Interrupted` error is no longer reported as `Cancelled` unless a context was
  actually cancelled. The Redis module docs now describe the two-context
  cancellation rule (a cancelled task cannot run cleanup commands by passing a
  fresh `Cx`).

### Fixed: `Cx::current()` inside a spawned task lacked the spawner's handles

Inside a task started with `Cx::spawn` or `Cx::spawn_local`, `Cx::current()`
returned the runtime's admission context. That context did not carry the
handles the task inherited from its spawner: the name registry, I/O
capability, remote capability, evidence sink, macaroon, HTTP client slot and
pressure handle. Its entropy stream and blocking pool were also not the
spawner's. The task's own `cx` argument had them. Code that reached for
`Cx::current()` (helpers several calls deep, prebuilt `race!` branches) lost
them, and so did every task it spawned through that context. The task's
contexts now share one set of handles, built at admission from a snapshot
the spawner takes, which also removes a full copy of those handles per spawn
(`asupersync-93zkbz`). In a seeded lab run, randomness drawn through
`Cx::current()` inside a spawned task now comes from the spawner's forked
stream, the one the task's own `cx` already used. Spawning through a `Cx` no
longer forks the runtime's own entropy source, so tasks created by other
paths (for example `RuntimeHandle::spawn`) can draw different seeded streams
than before. A panicking custom `EntropySource::fork` still resolves the
spawned task's join handle as `Panicked`.

### Fixed by the 2026-10-03 audits

Read-only audits of the protocol, messaging, stream and runtime modules found
the defects below; each fix landed with a regression test that fails on the
old code. The commit messages carry the details and receipts.

Security and denial of service:

- `Redirect::to_with_allowed_hosts` refuses a userinfo part, which let
  `https://allowed:443@attacker/` through as an allowed host.
- A static-file mount no longer decodes `%2F` into a path separator, which
  reached files below a more specific mount.
- HTTP/3 consumes received stream bytes in amortized constant time (a peer
  could make it copy quadratically), and a malformed message, a malformed
  trailer or a request stream that ends before its HEADERS resets only that
  stream instead of closing the connection.
- QUIC bounds out-of-order receive fragments across a connection's streams,
  not only per stream (a peer could hold about a million one-byte holes), and
  no longer re-advertises every finished stream's window on each ACK.
- The streaming HTTP/1 decoders bound the chunk-size line, and the server
  bounds chunk extensions by the data received (the class of Node's
  CVE-2024-22019). Bodyless responses never carry chunked framing, and an
  HTTP/1.0 client gets `Content-Length` instead of chunked.
- The buffered `Multipart` extractor no longer rescans the rest of the body
  for each part; the `Router::layer` compressor leaves BREACH-sensitive and
  `206` responses uncompressed; the debug server refuses other web origins.
- An ATP-over-RaptorQ receiver bounds the sender's symbol geometry before it
  sizes receive state: an unauthenticated Hello with one-byte symbols and an
  unbounded block size used to make it allocate per-symbol tables for a whole
  4 GiB entry and abort. Deciding whether to seed a block no longer runs a
  full rank analysis for every repair packet.
- An HTTP/1 handler response whose declared `Content-Length` does not match
  its body gets `500` and a closed connection instead of desynchronizing the
  client.
- A bonded ATP donor serves at most what a receiver can keep for each block:
  one plaintext NeedMore frame naming a window of four billion repair
  symbols used to make it reserve and fill about 17 GiB.
- `DecodingPipeline` refuses a symbol whose ESI cannot belong to its block
  when it arrives; once kept, such a symbol failed every later decode of the
  block, so a block that needed repair never decoded.
- HTTP/2: a field block refused with a stream error is still decoded, so the
  following requests on the connection no longer read the wrong header
  values, and a block past the fragment caps ends the connection.

Lost data and hangs:

- JetStream acks reach the server (they were sent to a subject the server
  does not listen on), the process-wide pull estimate no longer grows until
  every pull is refused, named consumers are durable, and a pull ends on the
  server's status reply.
- NATS: a timed-out supervised call no longer stalls the connection, `ping()`
  after a denied publish waits for its PONG, and a JetStream pull's inbox
  holds its whole batch.
- Kafka: a send whose delivery report arrived reports it even if the caller
  was cancelled, and a poll returns the record its broker poll fetched.
- Redis: a `Pipeline` refuses reply-changing commands instead of mispairing
  replies, and a Pub/Sub subscribe the server refuses keeps the connection.
- Streams: the concurrent `for_each` terminals see a member's failure and the
  caller's cancellation while waiting for the source, and `buffered`,
  `buffer_unordered` and `try_buffered` no longer lose a wakeup with more
  than 1024 futures in flight.
- `Scope::timeout` keeps the caller's cancellation reason instead of
  reporting a timeout; the circuit breaker no longer re-opens on its
  recovering probe.
- PBFT: a repeated or cancelled proposal no longer stops the message pump or
  wedges the primary; SWIM gives a suspicion at a newer incarnation its own
  window; a lease reactor that lags behind membership compaction still revokes
  departed nodes.
- Trace and ATP journals recover from a damaged stripe and from a device
  number that changed across a reboot.
- `read_line` and `LineReader` skip the rest of a line with invalid UTF-8
  instead of returning its tail as the next line, and `LineReader` reports
  EOF after a stream that ended inside a code point.
- QUIC: STREAM_DATA_BLOCKED and MAX_STREAM_DATA open a peer's stream (a lost
  first packet used to fail the connection), and `QuicStreamIo` writes what
  the flow-control windows allow instead of waiting for credit for the whole
  buffer.
- HTTP/2 client: a response whose closing HEADERS frame continues in
  CONTINUATION frames is taken instead of failing as `STREAM_CLOSED`.
- `BytesMut` grows instead of moving its whole live region on every small
  advance-then-append cycle.

### Fixed by the 2026-10-04 audits

A second round of read-only audits (runtime, time, I/O, HTTP, streams,
GenServer, remote and supervision) found the defects below; each fix landed
with a regression test that fails on the old code, and the commit messages
carry the details and receipts.

Hangs and lost wakeups:

- A cancelled task whose loop only awaits `sleep` returns to the scheduler
  every turn; it used to run every remaining turn inside one poll, pinning
  its worker (a current-thread runtime froze). A sleep that was already
  parked still completes at once when its task is cancelled.
- `stream::merge` over more than 64 streams polls every child again after
  one wakes it; an item on a child outside the next scan window was lost.
- `io::split_owned` halves in two tasks both wake over a stream that keeps
  one waker (a plain `TcpStream`, a TLS stream).
- A panicking waker no longer leaves the other tasks woken by the same
  reactor turn unwoken.
- Any number of tasks can accept on one TCP or Unix listener; 33 or more
  used to wake each other forever.
- The blocking pool starts a thread for every queued job its cap allows,
  including after the cap is raised; a job submitted while a worker picked
  up another could wait behind it, deadlocking two jobs that wait on each
  other.
- A GenServer dropped before it runs aborts its queued calls (the obligation
  drop bomb used to panic a scheduler worker), and a `stop()` racing the
  server's start is no longer lost.
- `race` and `race_all` on the multi-thread `block_on` root drain their
  losers when the winner panics; dropping a `Scope::timeout`, `quorum` or
  `first_ok` future asks the branches it started to stop.
- The remote computation service returns a handler result published before
  it saw the lease expire, instead of reporting and caching `Cancelled`.

Protocol and data:

- HTTP/2: trailers and a final empty DATA frame wait behind DATA blocked on
  flow control; a response (any gRPC unary reply larger than the client's
  window) used to send `END_STREAM` before its body.
- `Http1ClientCodec` reports a response cut off mid-body at end of input as
  `UnexpectedEof` instead of a clean end of the stream.
- A managed supervisor stops when its own budget deadline passes instead of
  restarting children into a dead region.

Resource use:

- A chunked symbol upload allocates its declared size once; one-byte chunks
  made every append copy the whole upload under the shared staging lock.
- The remote service frees an idle peer's expired idempotency records.
- The timer wheel drops cancelled timers in bounded batches and finds the
  next deadline without scanning every stored entry under its lock.
- A pending TCP connect waits for its writable event instead of re-polling
  every millisecond; `Debounce` no longer spins while its task is cancelled.
- Child-process pipes leave the reactor before closing their file
  descriptor, so a reused descriptor number no longer collides with a stale
  registration.
- `BlockingTaskHandle::wait_timeout` and `BlockingPool::shutdown_and_wait`
  accept any timeout (`Duration::MAX` used to panic).

### Fixed by the 2026-10-05 audits

Two more rounds of read-only audits found the defects below. The first covered
QUIC, HTTP/3, WebSocket, cancellation, combinators, channels, messaging, web,
the filesystem and the lab. The second covered the runtime tables, scheduler
queues, deadlines, the obligation mailbox, region close, the channel and
blocking paths, and server request regions. Each fix landed with a regression
test that fails on the old code, and the commit messages carry the details and
receipts.

QUIC, HTTP/3 and WebSocket:

- The standalone QUIC server handshake (`NativeQuicUdpConnection::accept`)
  sends an unvalidated client address at most three times what it received,
  drops a first Initial under 1200 bytes and ignores other addresses once its
  peer is known. One forged ClientHello used to trigger up to 64 full flights
  at the forged address.
- A QUIC handshake whose certificate chain is larger than one datagram
  completes: its Handshake-level CRYPTO is split into packet-sized datagrams
  (it failed with a send error).
- An atpd QUIC accept discards a garbage or forged long-header datagram
  instead of failing, and ignores other addresses once its client is known.
- QUIC ACK processing costs time in proportion to the packets an ACK touches;
  many-range ACKs used to cost packets in flight times ranges each.
- `MAX_STREAMS` never advertises more than 2^60 streams, the RFC 9000 limit a
  peer must enforce by closing the connection.
- A produced HTTP/3 response whose DATA frame is larger than the client's
  stream window is sent in pieces instead of stalling after HEADERS.
- A WebSocket closed by cancellation sends the configured
  `CloseConfig::cancellation_code` (it always sent 1001).

Cancellation and obligations:

- A cancel broadcast forwards a message once when two copies arrive at the
  same time, and a broadcast whose retry fails stays at the front of the
  retry queue.
- `Cx::cancel_with` stamps its reason with the current time, so it no longer
  replaces an older reason of the same severity.
- An `ObligationToken` dropped during a panic counts in `panic_leak_count`.
- Release builds no longer take the global cancel-protocol validator lock on
  spawn, completion, obligations and region lifecycle, and no longer record
  every region close as a protocol violation (an unreleased regression).

Combinators and channels:

- A `reset()` racing a queued acquire no longer wraps the rate limiter's or
  bulkhead's pending count, which rejected every later request until the next
  reset; `Bulkhead::reset` no longer loses capacity to a concurrent grant.
- `Retry` starts no new attempt once its backoff sleep has observed
  cancellation; `RetryTokenBucket::time_to_tokens` no longer panics for tiny
  refill rates; `RateLimiter::retry_after` counts the tokens queued waiters
  take first.
- A bounded `mpsc` channel reserves at most 64 queue slots up front and grows
  to its bound (a large bound allocated it all, or panicked).

Messaging and web:

- A Kafka record buffered by a dropped `poll` is delivered by the next poll
  instead of being overwritten.
- Pooled Redis commands refuse the `UNSUBSCRIBE` family before taking a
  connection, and a cancelled pub/sub `PING` counts the messages it buffered
  as dropped events.
- NATS `INFO` fields are read from the top-level JSON object whatever its
  spacing (a field name inside a string value could be read instead).
- A JetStream message refused at `max_ack_pending` no longer frees another
  message's ack slot.
- Compression gives a compressed body a weak `ETag`, adds `Vary` to a
  `304 Not Modified`, and leaves empty bodies unencoded.
- Multipart `Content-Disposition` parameters are found outside quoted values
  only (`filename="a; name=x"` no longer sets the field name).

Filesystem and I/O:

- An `fs::File` write settled by an interleaved read or flush is not written a
  second time when its caller retries.
- `read_line` and `LineReader::read_line` leave the caller's buffer as they
  found it when a line is not valid UTF-8, as std and tokio do.

HTTP/2 and HTTP/3:

- `Http2Listener` reads frames up to the `SETTINGS_MAX_FRAME_SIZE` it
  advertises; past 8 MiB it used to drop the connection.
- `NativeH3Session::send_request` refuses a request larger than a new
  stream's send credit before opening the stream; the failed call used to
  leave the stream open, using up one of the peer's stream slots.
- A pushed HTTP/2 response whose stream the client never grants window
  times out and is reset like any other response; it used to keep the
  connection from idling or closing.

Performance:

- A `Cx::spawn` + join makes six fewer heap allocations (about 30 down to
  24 in the allocation audit): one shared OS entropy source, no throwaway
  logical clock, checkpoint history allocated on first use, and epoch
  telemetry receipts batched inline.

Documentation:

- Settings that are accepted but not applied yet now say so:
  `RateLimitPolicy::algorithm` (always a token bucket),
  `sync::PoolConfig::health_check_interval` / `evict_unhealthy` (and
  `min_size` is warm-up only), `RegionLimits::curve_budget`,
  `ObligationTrackerConfig` periodic checks, the gRPC server keepalive
  settings (the client applies its keepalive to native streaming and
  duplex calls only), and the ATP SDK's transfer timeout, automatic retry
  (never performed, though on by default), progress interval, session
  timeout and stream buffer size.

Lab runtime:

- The task-leak and quiescence oracles check regions the runtime closed and
  removed; they used to see only regions still in the table, so a real close
  never reached them.
- `LabConfig::with_auto_advance()` moves virtual time in
  `run_until_quiescent` (and so `run_async_under_lab` and async
  `#[lab_test]`), and `run_with_auto_advance` under a paused clock ends with
  `StuckBailout` instead of spinning forever.
- `TraceMinimizer` caches a candidate by its events rather than its length,
  so delta debugging no longer stops early, and reports essential events by
  their index in the original trace.

Runtime, deadlines and obligations:

- The runtime no longer keeps a record of every obligation ever resolved. Each
  mpsc send, oneshot, permit and lease left a record behind for the life of the
  runtime. So did an index entry for every task that ever held one, and an
  entry for every region ever closed. Memory grew with the number of messages
  sent, and task completion slowed down as the index grew. The most recent 4096
  resolved obligations and 4096 closed regions stay queryable. Pending and
  leaked obligations are always kept. (asupersync-fu6cr0)
- A task's priority now applies to every wake, not only the first one. Re-wakes
  of a task, and of tasks woken when another completes, used to run at
  priority 0. (asupersync-5khftq)
- A local task stored while its runtime's key was being retired is dropped
  instead of being kept in a revived store until the thread exits.
  (asupersync-kopidb)
- `watch::Receiver::changed` reports a final value sent just before the sender
  dropped, instead of returning `Closed` without it. (asupersync-lh4z78)
- Replacing a `BroadcastStream`'s receiver through `get_mut` no longer evicts
  the waker of a receiver parked on another channel, which then hung.
  (asupersync-lh4z78)
- Without a blocking pool, `spawn_blocking` callers over the 256-thread
  fallback cap park until a thread exits, instead of re-polling at 100 % CPU.
  (asupersync-yr34lg)
- The obligation mailbox applies posts one at a time, so a post that panics
  (a leak under the `Panic` policy) no longer drops the posts queued behind
  it. A dropped reserve used to leave its region unable to close.
  (asupersync-e6igie)
- Lab runtime: a spawn denied because its region began closing re-advances the
  region, as the native scheduler does; the region's close used to hang.
  (asupersync-6edxi7)
- A pipeline sink effect that completes after the pipeline was cancelled is
  acknowledged and counted as consumed. It was counted as not done, so a
  caller resuming from `consumed` repeated the write. (asupersync-zn11mm)
- A spawn denied by a closing region whose captured future panics on drop
  still resolves its handle and re-advances the region, and the worker thread
  survives. (asupersync-01oghn)
- A blocking-pool `on_thread_start` hook that panics no longer kills every
  worker before its first job; it is contained like the stop hook.
  (asupersync-mopkmt)
- `AppSpecV1::bind_managed` refuses routes that the router would merge or
  shadow (`/users` and `/users/`, or `GET /users/:id` with `DELETE
  /users/:uid` registered as different routes). One of the handlers used to
  be unreachable while `bind_managed` returned `Ok`. (asupersync-mopkmt)
- A server's shutdown drain, and the HTTP/2 listener's drain supervision,
  wait for their deadlines instead of spinning a worker at 100 % CPU when the
  listener task is cancelled, and the drain no longer misses a last
  connection closing just before it starts waiting. (asupersync-m8xsjx)
- A server request whose deadline has passed is answered as a deadline
  (503 with ASUP-E501) instead of being reported as cancelled before the
  handler starts, or as a lost connection when the request's own context
  serves as its connection context (the HTTP/2 owned request path).
  (asupersync-m8xsjx)

Runtime performance:

- Opening and closing a child region costs O(1) instead of O(siblings) under
  the runtime lock, so per-request child regions no longer make each request
  pay for every concurrent request, and draining N of them on shutdown is no
  longer O(N^2). (asupersync-exeimj)

Later fixes from the same audits:

- A messaging-fabric `FabricConsumer` no longer keeps a record of every
  delivery it ever made, and no longer panics after `u32::MAX` deliveries. Its
  obligation ledger keeps the most recent 4096 resolved obligations; pending
  and leaked ones are always kept. The new
  `ObligationLedger::with_resolved_retention` offers the same to other
  ledgers; `ObligationLedger::new` is unchanged. (asupersync-rrtgoy)
- A circuit breaker's sliding window ignores the outcomes of half-open probes
  from an episode that has already ended, so a successful recovery no longer
  re-opens the breaker at once. (asupersync-e9gn8y)
- A quorum whose caller is cancelled as a race loser before the quorum is met
  returns `QuorumError::Cancelled`, and reports the strongest of the
  branches' cancellation reasons. (asupersync-1sngsf)
- `UnixStream::recv_with_ancillary` counts received descriptors within the
  control bytes the kernel copied. On macOS and BSD a truncated `SCM_RIGHTS`
  message made it read past its buffer and return garbage descriptors.
  (asupersync-8vrx8q)
- `VirtualTcpListener::accept` no longer misses a connection or close that
  arrives while it registers its waker, and observes cancellation.
  (asupersync-8vrx8q)
- Split TCP and Unix halves deregister from the reactor before their socket
  closes, and reuniting them keeps a registration on the fallback I/O driver
  movable to the runtime's driver. (asupersync-8vrx8q)
- `TcpStream::set_user_timeout` and `TcpSocket::set_user_timeout` round a
  non-zero timeout under 1 ms up to 1 ms. It used to become 0, which the
  kernel reads as its default. (asupersync-8vrx8q)
- `SporkAppHarness::oracles_pass` checks the oracles against the runtime's
  state. It read a suite nothing fed, so it always passed. (asupersync-vcu2oz)
- WebSocket `close()` and `send(Message::Close)` on the client and server
  end when their explicit `Cx` is cancelled, even after the close handshake
  has started. A close writing to a peer that stopped reading hung forever.
  (asupersync-fmw87f)
- A cancelled `Http1Listener` waits between drain checks instead of spinning
  while requests are still in flight. (asupersync-m8xsjx)
- A panicking `Waker` no longer strands the other senders woken when an
  `mpsc` channel closes or frees several slots. Waking a waiter from a drop
  that runs during a panic no longer aborts the process; this also covers
  `Notify`'s `notify_one` baton. (asupersync-9siwk7)
- `RateLimiter` and `SlidingWindowRateLimiter` round a fractional-millisecond
  period up to whole milliseconds. A period under 1 ms never refilled, and the
  sliding window then refused every request for good; 1.9 ms admitted 1.9
  times the rate. (asupersync-e9gn8y)
- A retry policy with a zero initial delay stays at zero for every attempt,
  instead of jumping to `max_delay` after about a thousand attempts.
  (asupersync-e9gn8y)
- `fs::write_atomic` creates the temp file for an existing target with the
  target's permission bits, so a private file's new contents are never
  readable more widely while they are written. (asupersync-pxg07b)
- The ATP QUIC receiver's accept no longer keeps short-header datagrams from
  anyone before the client is known, and keeps at most 4096 packets / 4 MiB
  of early 1-RTT data. An unauthenticated sender could fill its memory for
  the whole accept timeout. (asupersync-8vrx8q)
- The web router joins an HTTP/2 or HTTP/3 request's split `Cookie` fields
  with "; " (RFC 9113 §8.2.3, RFC 9114 §4.2.1). Only the last piece used to
  reach the application, so a session cookie in an earlier piece was lost and
  the user looked logged out. (asupersync-a1q12q)
- `SessionData::clear` keeps a pending `regenerate()` request. After the
  documented logout, `regenerate()` then `clear()`, a handler that panicked or
  was cancelled left the logged-in session valid, and data stored after the
  clear was saved under the old ID. The plain logout still deletes the session
  and expires its cookie. (asupersync-a1q12q)
- The lab's `cancellation_protocol` oracle checks that a cancelled region's
  live child regions are cancelled too in every run. Once a task had been
  polled, it used to see no region tree at all and pass. (asupersync-vcu2oz)
- The lab determinism oracle (`DeterminismOracle::verify`,
  `assert_deterministic*`) compares whole traces. When a run records more
  events than its trace buffer keeps, it runs once more with a buffer that
  holds them all, so a divergence among evicted events is reported; it
  compared only the newest 4096. Message events are compared whole; a
  100-byte prefix missed later differences and could panic inside a
  multi-byte character. (asupersync-vcu2oz)
- The lab loser-drain oracle replays the runtime's race history on every
  report, not only the first: a race in flight at one report was reported as
  never completed in every later one, later races were never checked, and a
  reset suite stayed empty. (asupersync-vcu2oz)
- `Router::route` with the same pattern and method registered twice answers
  with the first registration again, as in v0.4.3; merging repeated patterns
  (so GET and POST registered separately both answer) had let the later
  registration replace it. (asupersync-pblpeg)

Security:

- `MacaroonKeyRing::verify` accepted an all-zero signature whenever no
  retired key was set.
- Verifying a macaroon whose third-party discharges fan out could take
  exponential time; each (discharge, chain signature) pair is now verified
  once per call.
- `ResourceScope` glob matching let `..`, `.` and backslash segments escape
  the scope (`files/public/../secret`); they now fail to match.

Panics and stale names:

- `NameRegistry::abort_permit` panicked (ASUP-E101) on every error path. It
  now resolves the permit and returns the error.
- A registration refused because its holder is the root region left the name
  taken with no lease, or had already evicted the previous holder. Nothing
  changes before the refusal now.
- `NamedGenServerHandle::release_name` and `abort_lease` left the lease
  armed after another task took the name over, so dropping the handle
  panicked. They still return the registry's error, as in v0.4.3.

### Fixed by the 2026-10-07 and 2026-10-08 follow-ups

Each fix landed with a regression test that fails on the old code. The commit
messages carry the details and receipts.

Signals:

- A waker that panicked while being woken for a signal ended the signal
  dispatcher thread. Every later delivery was then swallowed, SIGTERM and
  SIGINT included. The panic is now contained.
- `ctrl_c()` called from a task whose `Cx` lacks the IO capability refuses with
  the typed `IoCapabilityDenied` [ASUP-E009], as `signal()` does. Before, it
  reported that Ctrl+C was unsupported on the platform.

Runtime and synchronization:

- A task that finished before its deferred cancellation was published made the
  cancel Wakers of the rest of its batch be dropped unwoken.
- `BlockingPool::shutdown_and_wait` reported a clean shutdown while an accepted
  job was still waiting for a worker, which then ran unjoined after teardown. A
  retiring blocking worker also fences before it checks for new work, so a job
  queued at that moment cannot be stranded on weak memory models.
- `Mutex::is_locked` reports a lock that has been handed to a woken waiter,
  which `try_lock` already refused.
- `DynamicSupervisor::next_completed` no longer reports a quarantined child a
  second time after `wait_child` or `terminate_child` reported it.
- `SelectAllDrain` returns its losers in their original order, the coordinates
  `winner_index` uses (it used to move the last one into the winner's slot).

Processes and I/O:

- A process error converted to `io::Error` keeps its kind: a missing program
  is `NotFound` and a refused one `PermissionDenied`. It used to be `Other`.
  A missing working directory is reported with the OS error instead of as
  "process not found" for the program.
- `Child::wait_with_output` and `Command::output`, cancelled through the
  task's `Cx`, terminate and reap the child before they return, as
  `wait_async` does. Before, they returned "cancelled" with the child still
  running.
- `Command::output_async` and `status_async` refuse a `Cx` that is already
  cancelled before they start the program.
- `BrowserReadableStream` reads a body exactly `max_total_read_bytes` long to
  its end instead of failing it with `ReadLimitExceeded`.

Networking and web:

- The new bytes of a mostly duplicate QUIC STREAM frame are copied out, so they
  no longer keep the whole datagram alive.
- The live SSE step the HTTP/1 server runs pulls the source through
  `poll_next_event` even without a heartbeat interval. A live source that idles
  stays open without holding a worker thread, instead of ending its stream at
  once or blocking.

Security:

- An identity key rotation or revocation that cannot be persisted leaves the key
  store unchanged, and the serialized key seeds are wiped after each write.
  Before, a failed revocation left the key revoked only in memory, so it was
  valid again after a restart.

### Fixed by the 2026-10-08 and 2026-10-09 audits

- Blocking pool with cohort affinity: every 16 dispatches, a worker looks at
  the other cohorts' queues, in turn. A task routed to a cohort that no live
  worker serves is no longer starved while the live workers stay busy
  (`mopkmt`).
- `ExactImageChild` (Linux):
  - `try_wait` leaves the exited leader unreaped, so its process-group number
    stays reserved;
  - `wait` and drop kill the group before they reap;
  - so a group number freed and reused by an unrelated group is never sent
    SIGKILL (`7tg3di`). macOS keeps reaping in `try_wait`.
- Current-thread runtime: a drive cut short with local spawn requests still
  queued advances their regions after failing the requests, so a Closing
  region waiting only on them can finish (`01oghn`).
- Regions: a closing region drops its heap payloads with its lock released,
  one at a time under `catch_unwind`, and only then publishes the close. A
  panicking destructor no longer leaves it half closed, and whoever sees the
  close still happens after every destructor (`fu6cr0`).
- Metrics: a `RuntimeBuilder::metrics` provider's `record_panic` is called
  with `"task_execution"` for every task that panics, on both runtime shapes.
  Before, only the legacy `scheduler::Worker` called it (`vp02m5`).
- Redis:
  - a cluster `-MOVED`/`-ASK` redirect to a host that is a socket path is
    refused;
  - `unix://` and `redis+unix://` URLs read `user`/`username` and
    `pass`/`password` from the query, and a bare `user@` names the user;
  - other parameters, and a credential given twice, are refused;
  - the socket path is percent-decoded (`x4kh5w`).
- HTTP clients (`mu5yhv`):
  - `Http2Client::tls_connector` gives the client its own connection pool, so
    clones with different TLS identities never reuse each other's
    connections;
  - with `pool_wait_timeout`, a fresh-connection retry waiting at the limit
    takes a connection released during its wait;
  - an `Http2Client` with `reuse_connections` does not reuse a connection
    whose server currently admits no stream (`SETTINGS_MAX_CONCURRENT_STREAMS`
    0), and returning a connection to the pool closes the expired idle
    connections of every origin, not only of the origin used next.
- gRPC:
  - `Channel::server_streaming_on` accepts `unix:` channels, in any case
    (`mu5yhv`);
  - clones of a legacy `GrpcClient` streaming call's `ResponseStream`, read
    from different tasks, are each woken by messages and by the end of the
    call (`mu5yhv`);
  - with `ChannelBuilder::reuse_connections`, a unary call that ends with a
    non-OK `grpc-status` keeps its connection pooled (`mu5yhv`);
  - `Server::bind_registered_duplex_http2_unix` refuses an input
    configuration the TCP bind refuses, before it returns the listener
    (`x4kh5w`);
  - a `unix:` target's query and fragment are not part of its socket path,
    and an absolute path is percent-decoded, as grpc-go reads it
    (`unix:///tmp/my%20app.sock` is `/tmp/my app.sock`); a relative
    `unix:path` is used as written (`mu5yhv`);
  - `Channel::connect` refuses a `unix:` target this platform cannot dial (a
    non-Unix platform, or a socket path too long for `sockaddr_un`) instead
    of failing every call as a retryable UNAVAILABLE (`x4kh5w`).
- Web: with `Router::prefer_specific_mounts`, a request for a mount's prefix
  itself (`/admin`) goes to the mounted router even when it routes no `/`,
  so its fallback and layers answer it instead of a `/:page` route
  (`x4kh5w`).
- W3C trace context: an incoming `tracestate` holding a control character
  other than a tab, or DEL, is dropped, as an over-long one is, instead of
  being forwarded and failing every outgoing request of the trace. Spaces and
  tabs around it are trimmed; other bytes, non-ASCII included, are kept
  (`mu5yhv`).
- `HttpAutoListener::run` (`313vbb`):
  - cancelling the task that runs it stops accepting and drains, instead of
    spinning on `Interrupted` accept errors;
  - the listening socket closes as soon as accepting ends, so new clients
    are refused during the drain, as with the HTTP/1.1 and HTTP/2 listeners.
    As with them, `lb_compat_keep_socket` (in either protocol's config) keeps
    it bound until the drain is over.
- PostgreSQL (`qml5yb`):
  - `SystemTime` maps to `timestamptz` only. Decoding a `timestamp without
    time zone` into it is refused, because that value names no instant.
  - A prepared statement whose parameter the server typed as another built-in
    type refuses a `SystemTime` (cast it, `$n::timestamptz`). Other `ToSql`
    types, and parameters the server typed as a domain, bind as before. (The
    check reads a new `#[doc(hidden)]` provided `ToSql` method; existing
    implementations need no change.)
  - A prepared statement binds a `Vec<String>` or `Vec<&str>` where the
    server typed the parameter `varchar[]` or `bpchar[]`; it was refused with
    42804.
  - For a Unix-socket host, given as `postgres:///db?host=/dir` or
    percent-encoded as the host, `port`, `user` and `password` are read;
    `requirepeer`, `dbname`, repeated values and a second `host` are
    refused. (v0.4.3 parsed `%2F` socket-host URLs without those checks,
    but it had no Unix-socket support, so they never connected.)
  - Crafted timestamp text can no longer overflow the parser.
  - A binary array refuses an element whose `ToSql` encodes as text, unless
    the element type is `text`, `varchar`, `bpchar` or `json`. A downstream
    `PgArrayElement` could otherwise store a wrong value with no error.
  - Over a Unix socket, a configured password the server never asks for (peer
    or trust authentication) is still refused, with a message that says so.
- MySQL: a comment-prefixed `USE` or a version-comment `SET sql_mode` clears
  the prepared-statement cache like a plain one. An executable comment
  (`/*!NNNNN ... */`, MariaDB's `/*M!`) is read both as the statement and as
  skipped, since the server decides which by version, and either reading
  that changes the database clears the cache (`qml5yb`).
- Resource sampling (`1ir2em`):
  - a downgrade waits until usage falls by the hysteresis margin;
  - Emergency is entered inside a cooldown;
  - descriptor and connection pressure use the soft `NOFILE` limit and, on
    Linux, this process's own sockets;
  - on macOS and the BSDs, where only the lifetime peak RSS (`ru_maxrss`) is
    available, memory is not measured, so one burst can no longer hold
    admission at Emergency for the life of the process.

### UDP launch-time sends and the socket error queue (Linux, GH #73)

- `UdpSocket::set_txtime` turns on `SO_TXTIME` (`UdpTxTimeConfig`: clock,
  deadline mode, error reports), and `send_to_with_txtime` /
  `send_with_txtime` attach a per-datagram `SCM_TXTIME` launch time for the
  ETF qdisc or NIC launch-time offload. They wait for writability like
  `send_to`. Once `SO_TXTIME` is on, the plain send paths of that socket
  (`send`, `send_to`, the batch sends, `SendSink`) return `InvalidInput`,
  because ETF silently drops a datagram without a launch time.
- `UdpSocket::recv_error` / `try_recv_error` read the socket error queue
  (`MSG_ERRQUEUE`) as a `UdpErrorReport` (errno, origin, offender, destination,
  and decoded launch-time errors). A pending read waits on `Interest::ERROR`
  without disturbing readable/writable waits. `set_recverr` turns on
  `IP_RECVERR` / `IPV6_RECVERR` so ICMP errors are queued too.

### Native QUIC key updates (RFC 9001 §6.3/§6.5/§6.6)

- The ATP native QUIC 1-RTT data plane now rotates packet-protection keys
  instead of only failing closed at the AEAD confidentiality limit
  (`asupersync-1bheeo`, building on the `asupersync-gsnci5` usage accounting).
  The flush path initiates a local key update before the confidentiality
  threshold and only when no update is already in flight (both key phases
  agree), honoring the RFC 9001 §6.5 one-update-at-a-time rule; the
  `gsnci5` hard-limit fail-closed remains as a backstop.
- The receive path installs the peer's next-generation keys and decrypts
  rotated traffic. It uses the packet number to distinguish a genuine key
  update from a delayed previous-phase packet, and installs next-generation
  keys idempotently so a forged or duplicated key-phase-flip packet cannot
  advance the (single-shot, bidirectional) key ratchet twice and desynchronize
  the connection.
- **Documented-behavior correction (owner-approved 2026-09-13):**
  `QuicTlsMachine::on_peer_key_phase` now accepts repeated alternating peer key
  updates (RFC 9001 §6.3), where it previously rejected the second update. The
  public `QuicTlsError::StalePeerKeyPhase` variant and every method signature
  are preserved; `StalePeerKeyPhase` now fires only for a genuinely stale
  packet whose packet number predates the current generation's floor, via the
  new packet-number-aware `on_peer_key_phase_pn`.

## [v0.5.0] - 2026-09-12

[Published release](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.5.0)
from `78b64636e99fea4ea2d868096576021dd3b8e519`, tracked in
`asupersync-v5fn1e`. All nine crates.io archives and eleven GitHub assets were
downloaded anonymously and matched the reviewed bytes; all four Minisign
signatures verified against the public key at the release tag.

### Runtime capabilities and race history

- Spawn APIs reject a context whose runtime capability mask excludes spawning,
  before allocating a task or invoking its factory. Child-region derivation,
  task admission, and legacy `Scope` spawning preserve the inherited mask,
  including during factory construction, resumed polling, and panic cleanup.
- `Cx::set_current` and `set_current_restricted` preserve restrictions already
  carried by the supplied context. **Compatibility note:** `set_current`
  previously installed a full ambient mask even for an already-restricted
  context. Code that intentionally needs broader authority must retain and
  explicitly install its original privileged `Cx`; a narrowed copy no longer
  recovers that authority. Full-authority contexts keep their existing behavior.
  The owner approved this documented behavior correction on 2026-09-10 for
  the `0.5` release boundary. It is the intentional migration from `0.4.x`.
- Race and quorum histories retain the participant IDs captured when each race
  starts, even when mailbox admission replaces provisional task IDs. This
  prevents false loser-drain violations while retaining cancellation and cleanup.
- Synchronous spawn rejection no longer adds a nonexistent child termination to
  combinator and supervisor counters. Accepted children still count when they
  are cancelled before their first poll.
- Contexts expose inherited blocking-pool handles only when their typed and
  runtime capabilities allow spawning; retrieving a handle never creates a pool.
- The API-v2 integration lane covers 18 native/lab lifecycle cells, 256 seeded
  spawn/cancel/close interleavings, capability denial and inheritance, composed
  macros, loser cleanup, and channel/stream ownership. The journey runner also
  checks that both PureCaps and WebCaps fail to compile when used to spawn.

### Runtime lifetime and browser execution

- Browser runtimes admit only their own local tasks, preserve admission order
  across nested native drives, and cancel queued or parked local tasks on
  shutdown. A retained browser pump no longer keeps stopped tasks alive.
- Native current-thread handoff keeps the local admission owner installed while
  checking for queued work. Local tasks cannot be stranded by lending their
  owning worker to another thread.
- Worker retirement and wake-notifier replacement release their mutexes before
  running user destructors, allowing shutdown callbacks to re-enter safely.
- Browser microtask pumps drain spawn admissions and resume self-waking local
  futures across burst yields. Browser time uses a portable monotonic clock.
- Native reactor-registration exports and UDP fallback test helpers remain
  excluded from WebAssembly builds.

### Buffered I/O and protocol recovery

- `File::into_std` settles pending reads and rewinds unconsumed read-ahead before
  returning the standard file. Failed buffer flushes preserve recoverable
  pending bytes.
- Owned file cursor operations retain read-ahead reconciliation when cancelled
  before starting. Reconciliation and a started operation share one cursor gate,
  preserving ordering with cloned handles and unread bytes after rewind failure.
- HTTP/1, HTTP/2, and remote-service listeners retry descriptor and buffer
  exhaustion with bounded delays while retaining permanent socket errors.
- The opt-in HTTP cookie store preserves `Secure` attributes and suppresses
  those cookies on HTTP requests, including HTTPS-to-HTTP redirects.
- TLS PEM loading uses the maintained parser in `rustls-pki-types`, preserving
  certificate order, private-key selection, and error messages.
- Framed writers reject an underlying writer's impossible byte count with
  `InvalidData`, preserving the unacknowledged suffix for a retry.
- Child-process pipe reads park on the fallback I/O driver when no native
  runtime driver is installed.
- HTTP/1 framing and idle request heads are bounded; HTTP/2 limits pending
  request bodies. SQLite transactions refuse further statements after SQLite
  has ended the transaction.

### Networking and ATP transfers

- Native QUIC reclaims idle and closed connections, so vanished peers cannot
  retain every connection slot indefinitely. Unauthenticated packets and stream
  data received after reset are discarded.
- Driverless TCP listener accepts and owned TCP/Unix split halves park on the
  fallback I/O driver instead of repeatedly waking their executor. Split-half
  registrations move to the ambient driver when one becomes available.
- ATP's QUIC source-stream proof wait measures consecutive peer silence, so
  receiver keep-alives extend a long tree commit within the existing liveness
  cap. Proof-wait retransmissions also respect the path RTT and ramp their
  resend budget within the burst ceiling.
- QUIC receivers accept relative destination paths without attempting to
  inspect an empty ancestor directory.
- ATP delta chunk builders fill each chunk across short reads. This repairs
  delta re-sync failures introduced in `v0.4.11` for files larger than 128 KiB.

### Release verification

- RCH lanes passed formatting, all-target/all-feature checking and Clippy,
  22,808 library tests, 158 integration tests, and 68 compatibility-bridge
  tests. The library run used `test-internals,tls-webpki-roots` and retained
  23 existing ignored tests. All nine package archive verifications and the
  packaged default, TLS, and cancellation consumer checks passed.
- Linux x86-64, macOS ARM64, and Windows x86-64 executables were built through
  RCH and smoke-tested on their native platforms. Linux was built and tested
  on glibc 2.43; older glibc environments have not been validated. Publication
  used DSR with `--no-dispatch`, with GitHub Actions disabled.

## [v0.4.11] - 2026-09-09

### Runtime lifetime

- `Runtime::block_on` accounts for its root future as a live task, so
  `is_quiescent()` stays false while that future runs. A current-thread runtime
  drives spawned tasks on the caller's thread and accepts `spawn_local` from
  the root. Nested calls preserve the outer local-task queue, including after
  an inner panic, while a distinct nested runtime keeps its own task ownership.
  The root also counts toward `max_tasks`: a limit of one leaves no capacity
  for child tasks while `block_on` is running.
  Caveat for `RuntimeBuilder::current_thread()`: the calling thread is the
  runtime's only worker while `block_on` runs, and that worker is parked for
  the duration of every poll of the root future, so no spawned task, timer,
  or reactor turn progresses until the poll returns. A root that blocks its
  thread synchronously on a spawned task (a std channel `recv`, a thread join)
  now deadlocks where a plain `worker_threads(1)` runtime kept that task
  running on its own thread; await the task instead. A `block_on` that cannot
  borrow the worker (from inside a task poll, from the background thread, or
  from another OS thread while the worker is on loan) polls its future on the
  caller as before, without a registered root task. After the root completes,
  `block_on` drains already-runnable work under a bounded stop-predicate check
  budget and never waits on timers or I/O. Remaining `Send` tasks continue on
  the background thread; local tasks wait for their owning thread to drive
  the runtime again.
- Dropping the final runtime owner from one of its async workers transfers
  worker joins to a teardown thread, allowing the current poll to return
  without trying to join itself. The teardown job retains runtime state
  through all joins and cleanup; ordinary caller-thread teardown remains
  synchronous. Native regressions cover successful results, panic unwind,
  worker-stop callbacks and released state ownership.
- A refused teardown-thread spawn preserves the cleanup job for retry.
  Permanent thread-resource exhaustion can still block ordinary drop;
  the explicit bounded-shutdown APIs retain their separate timeout policy.
- Ordinary region cancellation avoids allocating the auxiliary shutdown-budget
  map when no region has an explicit cleanup ceiling. Existing descendant
  ceilings still propagate, including explicit infinite budgets.
- Publishing an earlier timer deadline wakes the native reactor, so a worker
  already waiting on a later deadline observes the new timer promptly. This
  also restores timely HTTP/2 graceful-drain completion. A native regression
  observes the reactor's selected wait before inserting the earlier timer and
  checks the exact task result and future cleanup.
- Updated entry macros remain compatible with the published `0.4.3` runtime:
  an omitted `drain_ms` uses the runtime's drain API when available and retains
  legacy teardown otherwise. Explicit positive bounds require that API.
  The current runtime keeps its existing worker, blocking-pool and drain
  defaults; a cross-version consumer checks the older-runtime pairing.

### QUIC transport and ATP framing

- DATAGRAM admission checks both the peer's frame limit and the protected
  packet budget. Oversized payloads return `DatagramTooLarge` before entering
  the send queue, preserving the connection for subsequent traffic.
- Client Initial packets carry authenticated padding to the required minimum
  datagram size. Received Initial and Handshake packets use the peer's header
  protection key; protected bits are interpreted after unmasking.
- Coalesced handshake packets are bounded by their individual Length fields.
  Processing one packet installs newly available keys before the next packet
  is processed, and authentication failures in an active packet space remain
  errors.
- Adjacent received stream ranges coalesce into contiguous runs, keeping the
  reassembly budget tied to out-of-order holes instead of packet count.
  Packets that exceed receive capacity are dropped before frame side effects
  and acknowledgment, so loss recovery can retry after application reads free
  capacity. The fixed guard remains bounded.
- ATP binary frame decoding preserves incomplete prefixes, rejects truncated
  frames at stream FIN, and binds client completion to its original handshake.
- ATP-over-QUIC receivers send keep-alives while decoded-block writes and
  packed-tree commits are in progress. Sender proof and feedback waits count
  consecutive silent intervals, so a slow receiver that keeps responding can
  finish its local work without exhausting a cumulative idle budget.
- QUIC loss detection excludes packets that never counted as in flight, and
  ACK ranges retain received non-ack-eliciting packet numbers. ACK-only traffic
  no longer causes false losses and congestion-window collapse on clean
  delayed paths.
- RTT sampling uses the ACK frame's largest packet only when it is newly
  acknowledged and the frame also newly acknowledges ack-eliciting traffic.
  Repeated ACK-largest values cannot resample an older packet. The fresh RTT
  estimate is applied before classifying time-threshold losses from that ACK.
- Peer stream-data limits apply separately to each stream direction and type.
  Omitting an unused unidirectional limit no longer removes bidirectional
  stream credit.
- Self-signed certificate coverage distinguishes a valid server leaf from a
  CA certificate used as a leaf. Exact pins preserve WebPKI's role checks.

### Kafka client against a real broker (2026-09-02)

- **Dropping a subscribed `KafkaConsumer` no longer hangs.** A consumer
  dropped without `close()`, and a consumer that had been `close()`d and was
  then dropped, both blocked the dropping thread forever inside librdkafka's
  close path (the rebalance callback's assign/unassign call cannot be
  serviced while `rd_kafka_consumer_close` runs). The consumer now carries
  its own rebalance context and leaves the group in normal polling mode
  before the handle is closed; `close()` and `Drop` both do this, bounded.
- **Transient `UnknownTopicOrPartition` no longer aborts `poll`.** A
  subscription whose topic is still being created is "no message yet"; the
  poll keeps going until its deadline. Transport failures still return an
  error.
- The real-broker suite runs green locally against Redpanda (13/13); CI's
  broker now advertises `127.0.0.1` so a host that resolves `localhost` to
  `::1` cannot strand consumer connections.
- Raw librdkafka properties pass through: `ConsumerConfig::with_property` /
  `set_property` (and the `ProducerConfig` twin) are applied before the typed
  fields, so typed fields win on conflict. `partition.assignment.strategy =
  cooperative-sticky` now reaches the consumer's rebalance context, whose
  incremental path is exercised against a real broker; `KafkaConsumer::
  rebalance_stats()` counts incremental vs eager assign/unassign callbacks and
  `rebalance_protocol()` reads the negotiated protocol outside the callback.
- A swallowed transient error is observable: `KafkaConsumer::last_transient_error()`
  reports the code, first/last occurrence and count, and the consumer traces
  it once per distinct code, so a subscription to a topic that never appears
  is distinguishable from an idle topic.
- `SymbolCancelToken::cancel` publishes `cancelled_at` before the cancelled
  flag, so `child()` no longer waits (a wall-clock bounded spin) for an
  in-flight publication; the lab's determinism no longer depends on host
  timing there.
- The ambient-authority inventory snapshot is keyed without line numbers, so
  an edit above an ambient site no longer moves the snapshot; only a new,
  removed or rewritten site does.

### Lab replay of production schedules, the obligation seam, macOS UDP (2026-09-02)

- `trace::replay::ProductionSchedule::from_runtime_trace` projects a runtime
  trace (Spawn / Poll or Schedule / Yield / Complete / TimeAdvance / Timer
  events) into a replayable schedule with spawn ordinals and a projection
  summary; strict mode refuses a task that acts before its spawn, tolerant
  mode lists it as an orphan. Documented in `docs/replay-debugging.md`.
- `LabRuntime::replay_production_schedule` drives the lab's scheduling
  choices from such a schedule: recorded spawn ordinals bind to lab tasks by
  first entry into the scheduler, a not-yet-runnable task is waited for
  through bounded virtual-time advances, and the first divergence (step,
  index, expected vs actual task, reason) is reported through
  `replay_report()` under a `Stop` or `Continue` policy. The lab derives a
  schedule from its own recording with `recorded_production_schedule()`.
  The production three-lane worker does not emit per-poll trace events yet,
  so a real production trace projects its spawn order but zero steps until
  that emission lands (tracked as the B3 prerequisite).
- Obligation mailbox (`runtime::obligation_mailbox`): a task context built by
  a runtime can mint a runtime-tracked obligation without the state lock
  (`Cx::try_register_obligation`, crate-private), resolve it with
  `commit` / `abort`, and a dropped unresolved token is reported as a leak.
  Posts are Copy values on a lock-free queue, applied by the runtime next to
  spawn admissions through `RuntimeState`'s authoritative obligation methods;
  undrained posts and live tokens count as pending work for `is_quiescent`
  and drain gating. No primitive uses the seam yet.
- A dropped unresolved token goes through the runtime's leak policy
  (`RuntimeState::report_obligation_leak`): it counts toward `leak_count`,
  honours `LeakEscalation`, and under `Recover` is auto-aborted instead of
  marked leaked. The first cut only resolved the record and emitted the trace
  event, so a dropped token could never escalate (found by the macOS full
  suite).
- `UdpSocket::connect` re-targets a connected socket on BSD-derived stacks:
  on `EISCONN` (macOS, iOS, FreeBSD) it dissolves the association by
  connecting to the null address and retries once; Linux and Windows are
  unchanged. Verified on macOS 26.2 (arm64).

### Semaphore permits are runtime obligations (2026-09-04)

- `Semaphore::acquire` and `try_acquire` now register an
  `ObligationKind::SemaphorePermit` through the obligation mailbox, so a permit
  held across a cancelled task is visible to the runtime's obligation table,
  its leak policy and `is_quiescent`. Releasing capacity — dropping the permit
  or calling `commit` — discharges the obligation; `forget`, which
  intentionally keeps the capacity, aborts it; an acquisition that unwinds
  before the permit reaches the caller aborts it too. Acquiring zero permits
  holds no capacity and mints nothing.
- The permit's existing graded token is unchanged and stays type-level; it
  never reached `RuntimeState`, which is why the runtime could not see an
  outstanding permit before. Public signatures are unchanged, and a `Cx`
  without a runtime still registers nothing — including `try_acquire`, whose
  signature carries no `Cx` and so registers only when a task-local one is
  current.
- The lab `obligation_leak` oracle names each leaked record's kind and holder.
  `tests/channel_permit_runtime_obligations_e2e.rs` exercises stock
  MPSC, oneshot, broadcast, and semaphore permits through real lab tasks,
  including leaks and futurelock detection while a permit is held across a
  parked task. `examples/onramp_level3.rs` now leaks a real permit instead of
  constructing an obligation record by hand.

### Kafka consumer close on the cooperative protocol (2026-09-04)

- `KafkaConsumer::close` called `unassign()` unconditionally. That is the eager
  API, and librdkafka rejects it with `RD_KAFKA_RESP_ERR__STATE` ("Local:
  Erroneous state") on a consumer that negotiated the cooperative protocol, so
  a cooperative-sticky consumer failed its own close. The leave-group drain
  that runs first already puts the revoke through the rebalance callback,
  which unassigns incrementally, so that call is now skipped on the
  cooperative path. Found by the new real-broker coverage.

### ATP-over-QUIC source-stream window grows on clean high-RTT paths (2026-09-03)

- The limiter report answered the WAN question (ledger entry 2026-09-03): on a
  clean 90 ms × 300 mbit path the sender waited on the receiver's
  `MAX_STREAM_DATA` credit 90 % of the time because the source-stream receive
  window is a fixed 2 MiB, below that path's bandwidth-delay product. A bigger
  static window is refuted both ways (8 MiB: `good` 42 s → 68 s with 61 % of
  the file re-sent, `bad` fails outright on the reassembly fragment guard).
- The window now grows only when the sender asks, and only on a path that has
  earned it: the native QUIC receiver reacts to STREAM_DATA_BLOCKED on a
  bounded-window stream by doubling the window (up to a cap, only after a full
  window was consumed since the last growth, and never once a quarter of its
  reassembly budget is buffered as out-of-order chunks), and the ATP sender
  sends that frame only while credit is its sole gate, the transfer has never
  retransmitted, and eight windows of credit have passed cleanly. The first
  cut gated on "no repair since the last decision", which is trivially true
  early in a transfer; measured, it grew the window on lossy paths and cost
  the shallow-shaper regime 42 s → 55 s with up to 240 MB re-sent, and failed
  the lossy regime outright on the receiver's reassembly guard. Queue-limited and lossy paths never ask and keep the
  2 MiB path law; the clean WAN cell went from 25.9 s to 15.7 s (1.73× faster
  than rsync-over-ssh). Cap: 4 MiB (`ATP_QUIC_STREAM_RECV_WINDOW_MAX`),
  clamped by the reassembly fragment guard for the receiver's MTU.
  `NativeQuicConnection::allow_stream_recv_window_growth`,
  `report_stream_data_blocked`, `stream_send_limit`,
  `stream_recv_window_bytes` are additive.
- `QuicSendLimiterReport` gains `path_rtprop_micros`,
  `path_bottleneck_bytes_per_s` (the wall-clock path figures; the transport's
  `min_rtt_micros` / `smoothed_rtt_micros` / `pto_count` run on the data
  plane's synthetic event clock and are documented as such),
  `min_unacked_admission_cap_bytes`, `peak_stream_unacked_bytes`,
  `stream_window_requests` and `peak_stream_send_window_bytes`; the CLI
  `limiter` block prints them.

### ATP-over-QUIC sender limiter report (2026-09-02)

- `transport_quic::send_path_with_limiter_report` returns the usual
  `SendReport` plus a `QuicSendLimiterReport`: per-reason stall counts and
  held time (pacing, cwnd, `MAX_STREAM_DATA` credit, ATP's in-flight
  admission cap, send-queue drains, receiver window), peak/final cwnd and
  ssthresh, min/smoothed RTT, loss timeouts, retransmitted bytes, PTO count,
  the admission cap in force, UDP send-batch errors and the applied socket
  buffer sizes. `atp send --transport quic` prints it as the additive
  `limiter` JSON block and one `quic_limiter` progress line naming the
  dominant reason. `send_path` is unchanged; the report is observational.
- Motivation: the netem `wan` / `wanloss` / `wanqueue` regimes showed that a
  shallow queue costs the QUIC sender 61 % while rsync and the RQ fountain
  are unaffected, and that a clean 90 ms pipe leaves it window-limited at
  53 % of the link; the report names which gate is responsible instead of
  leaving it to throughput × RTT arithmetic.

### Encrypted ATP measured honestly (2026-09-02)

- First cross-machine ATP-over-QUIC receipt with SHA-256 on both ends
  (`artifacts/atp_bench_matrix/wan_quic_receipt_2026-09-02.md`): correct,
  but 3–9× slower than the same binary over TCP on ~90 ms paths.
- The bench harness's self-signed certificate carried `CA:TRUE` under
  OpenSSL 3.5, which rustls-webpki refuses for an end entity, so every
  encrypted QUIC cell had been failing in 0.15 s; fixed, and the encrypted
  tier re-measured (48/48 cells, scorecard committed, README table with the
  losses stated).

### Windows CI (2026-09-02)

- The pinned nightly compiles the lib on real Windows hardware (both
  nightly-2026-07-05 and nightly-2026-08-20). The CI-only rustc crash is an
  abort on the small runner; the Windows lib job now runs the rustc frontend
  single-threaded.

### Feature-gated test truth: what `--all-features` was hiding (2026-09-02)

The CI lib job had never completed (runner shutdowns), so nothing had run
the lib suite with every feature on for months. Doing so on Linux and on a
real macOS host found:

- **gRPC: a large but compressible message could bypass the encode size
  limit** (`FramedCodec::encode_message` checked the limit only on the
  compressed bytes). The uncompressed length is now checked first; the
  compressed length is still checked for the frame. `test_compression_bypass_vulnerability`
  (br-asupersync-trmye2) is green.
- **`fs::File` poll traits ran on a fallback thread outside a runtime** after
  the blocking-pool offload (this release), which parked callers with no
  executor. They now offload only when a blocking pool exists and otherwise
  run inline, as before.
- **CI test and coverage jobs run every feature except the legacy audit
  harnesses.** `legacy-internal-test-harnesses` and
  `serialization-golden-harnesses` (both also pulled in by
  `ci-cross-platform`) gate crate-root golden/metamorphic/conformance modules
  whose goldens were never committed; with them on, 93 tests fail on any OS.
  `scripts/ci/release_test_features.sh` derives the list from `cargo metadata`.
- **Lock-name policy under `lock-metrics`** now allows the test-only names
  `external-tasks`, `reader_fanout`, `close_fanout` (7 runtime/sync tests
  failed closed on them).
- Test repairs where the code was right and the test was stale: MySQL/ATP
  CLI content hash is bare hex, config-precedence CLI layer must not carry
  the default profile, `RuntimeState::new()` starts its clock at 1 s
  (obligation ages), `try_wait` polls instead of sleeping 50 ms, multipart
  cancellation message carries the deadline context, TLS acceptor error
  wording, 0-RTT requires an explicit replay-protection policy, and the
  ambient-authority known-finding at `metadata.rs:2546` now names
  `std::fs::metadata`.
- Still red under the CI feature set, deliberately left open rather than
  papered over (tracked on br-asupersync-gap-nonlinux-reactor-ci-gxv3dy):
  the ambient-authority inventory snapshot no longer matches the code (new
  `TcpStream`/`TcpListener` sites in grpc/client.rs and the h1/h2 listeners
  need review, not a snapshot refresh), the pwsh/elvish completion snapshot
  was never committed, `x509-parser` 0.18 accepts a malformed SPKI the
  `der_min` differential expects rejected, and the ALPN-required acceptor
  test.
- Correction: four of those failures were not feature-dependent at all and
  fail with default features too (`ambient_authority_does_not_regress`,
  `known_findings_reference_real_code`, the multipart cancellation message,
  and `streaming_server_refuses_actual_chunked_bytes_over_limit`). The last
  one pinned the pre-2026-09-01 silent close; the h1 streaming server now
  writes the 413 `[ASUP-E505]` refusal with `Connection: close` and counts
  the hop, and the test asserts exactly that (the handler's 200 must not
  reach the wire).
- Genuine macOS differences (51 failures on macOS 26.2 with the same feature
  set, 24 of which are the cross-platform items above) are listed on the
  same bead: TCP option read-back, UDP re-`connect` needing `AF_UNSPEC`,
  `/tmp` and `/var` symlink path validation, unix datagram `peer_cred`,
  bonded-transport loopback binding, APFS sparse allocation.

### Real-server client fixes and CI proof lanes (2026-09-02)

Running the existing real-server suites against real servers for the first
time (docker: postgres:16, mysql:8.0, redis:7, nats:2.10, redpanda) found
four client defects and two test assumptions that only a real server exposes:

- **PostgreSQL: an external cancel now interrupts a parked read.** The
  socket poll loops checked `cx.checkpoint()` but never registered the task's
  waker with the `Cx`, so cancelling a `pg_sleep(30)` query took the full 30 s
  before `Outcome::Cancelled` surfaced. `read_exact`/`write_all`/TLS
  negotiation now hold an owned cancellation-waker registration for the
  duration of the poll; the cancel wakes the read, the checkpoint returns
  `Cancelled`, and the `CancelRequest` path fires. Unit test with a
  never-ready stream plus the real-server suite (8/8, cancel in under 0.4 s).
- **MySQL: `begin_with_isolation` can now succeed for a non-default level.**
  It issued the next-transaction `SET TRANSACTION ISOLATION LEVEL`, which
  never changes `@@SESSION.transaction_isolation` on MySQL 8 or MariaDB, so
  the post-`START TRANSACTION` verification could only pass when the
  requested level equalled the session default. It now sets the SESSION level
  and restores the previous one on commit, rollback, or the implicit rollback
  of an abandoned transaction.
- **MySQL: the static-SQL injection heuristic matches function names at
  identifier boundaries.** `VARCHAR(64)` was rejected because it contains
  `char(`. `MySqlValue::as_i32` accepts an in-range BIGINT (the binary
  protocol types `SELECT 1 AS v` as BIGINT).
- **Redis: a RESP3 null is "no value".** `hget` treated the `_` null Redis 7
  sends after `HELLO 3` as a protocol error.
- **NATS: a bare `NATS/1.0 503` reply is named "No Responders".**
  nats-server sends no Description header for it.
- **Test assumption:** `@@in_transaction` is MariaDB-only; the MySQL
  real-server suite now probes `information_schema.innodb_trx`.

CI:

- New `real-servers` job runs all six real-server suites with the servers in
  docker; `scripts/ci/run_real_server_suite.sh` fails on any skip marker or
  zero-test run, and a wrong-password negative control must fail.
- New `lean-build` job runs `lake build` on the pinned toolchain and uploads
  a hash-bound receipt (`formal/lean/coverage/lake_build_receipt.txt` holds
  the last local build: 189 theorems, 0 sorry).
- New `tla-tlc` job installs Java and a sha-pinned TLC and runs
  `tests/lab_tla_export_tlc_e2e.rs`, the first caller of
  `LabRunReport::export_tla`: a real lab trace is model-checked (with a
  planted invariant that TLC must reject) and the test fails closed under
  `CI=true` when TLC is missing.
- Six workflows carry `concurrency` groups so a push cadence of minutes no
  longer queues dozens of full matrices.

Also:

- `Runtime::trace_snapshot` / `RuntimeHandle::trace_snapshot` export the
  production trace ring buffer for the lab analysis tools.
- The discounted-UCB1 replay golden runs again (it had been ignored since
  2026-04-22 because the scheduler constructor it used never enabled the
  policy); the README now says the selector is a pure function of the
  dispatch sequence and that `LabRuntime` does not run it.
- The K=2048 RaptorQ encoder differential is no longer ignored: it passes
  against `raptorq` 2.0 (the ignore cited 1.8.1).
- `PbftConsensus::submit` is deprecated as an experimental scaffold that
  returns a placeholder response.
- `Runtime::drain_root_region` counts not-yet-admitted spawns on the root
  region and reports task-and-obligation quiescence rather than full
  runtime quiescence (which also requires an empty I/O driver).

### Root-region drain, drain-correct timeout, non-blocking file traits (2026-09-02)

- **The root region is drained when the entry future returns.** New
  `Runtime::drain_root_region(bound) -> RootDrainOutcome` requests
  `CancelKind::Shutdown` on every task the root region still owns, schedules
  them on the cancel lane, and waits up to `bound` for quiescence.
  `#[asupersync::main]` and `#[asupersync::test]` call it after `block_on`
  (new `drain_ms = N` argument, default 2000; `0` restores drop-at-teardown).
  Previously `block_on` returned as soon as its future completed and teardown
  abort-by-dropped any task that outlived `main`, so their cleanup never ran.
  Proven by `tests/entry_macro_root_drain_e2e.rs`: a task that outlives `main`
  runs its post-cancel cleanup before the macro-expanded function returns;
  with `drain_ms = 0` it does not (planted negative); the bound is respected
  against non-cooperative work. A bare `RuntimeBuilder` is unchanged.
- **`Scope::timeout` is the drain-correct timeout.** It spawns the operation
  as a region task and, when the deadline or the caller's cancellation wins,
  protocol-cancels and joins it before returning. Because it uses the ordinary
  `spawn_in` path, an operation that acknowledges the cancellation and still
  returns `Ok`/`Err` has that outcome preserved as `TimedResult::Completed`;
  only a cancellation-blind operation is reported `TimedOut`. `time::timeout`
  is unchanged (it drops the inner future) and its docs now say so. Proven by
  `tests/scope_timeout_e2e.rs` (cleanup counter checked immediately on
  return; late `Ok` preserved; cancellation-blind value discarded).
- **`fs::File`'s `AsyncRead`/`AsyncWrite`/`AsyncSeek` no longer block the
  async worker.** Each poll submits one bounded (128 KiB) syscall to the
  blocking pool and returns `Pending` until it completes; a per-handle state
  machine keeps read-ahead from an abandoned poll, rewinds before writes and
  relative seeks, and the owned cursor methods (`seek`, `read_into_vec`, ...)
  settle any in-flight trait operation first. Without a pool the path degrades
  to the previous inline behaviour. Proven by
  `tests/fs_file_poll_offload_e2e.rs` (a peer task advances once per chunk
  during a 48 MiB `read_exact` on a single-worker runtime; byte-exact
  round-trips through read-ahead, relative seek, and write-after-read-ahead).

### Reality-check follow-through (2026-09-01)

- **`TaskInspector` and `Diagnostics` are reachable from a production
  runtime.** Additive `Runtime::task_inspector(config)`,
  `Runtime::diagnostics()`, and the `RuntimeHandle` equivalents lock the live
  runtime state (and the scheduler's dispatch task table / shard-C obligation
  table where records live) for exactly one query each. New
  `Diagnostics::explain_cancellation(task_id)` renders a task's recorded cancel
  reason and cause chain. Proven by `tests/runtime_inspector_e2e.rs`. Finding:
  the production dispatch path does not advance `TaskRecord::total_polls`, so
  `TaskDetails::poll_count` is 0 for live production tasks.
- **`Scope::quorum` and `Scope::first_ok` execute the combinators the README
  lists.** Quorum spawns every branch, returns once M succeed or success is
  impossible, and protocol-cancels and joins every remaining branch;
  `first_ok` runs lazy factories sequentially and drains an in-flight attempt
  on cancellation. The aggregation types in `src/combinator/{quorum,first_ok}.rs`
  are unchanged. Proven by `tests/combinator_quorum_first_ok_e2e.rs` on the
  production runtime and LabRuntime with leak oracles.
- **MySQL `mysql_native_password` behind the existing opt-in.** With
  `MySqlConnectOptions::insecure_legacy_mysql_native_password = true` the
  client answers the SHA-1 challenge on both the handshake and AuthSwitch
  paths; the default remains fail-closed before any bytes are written. Proven
  with externally derived known-answer vectors and a scripted loopback server
  (`tests/mysql_native_password_optin.rs`).
- **The pooled HTTP client can trust a private root.** New
  `HttpClientBuilder::add_root_certificate` /
  `HttpClientConfig::tls_root_certificates`, consumed by the TLS connect path.
  Previously there was no way to install a root, so plain-`tls` builds failed
  every `https://` request closed and a private CA could never be trusted.
  Proven by `tests/http_client_https_e2e.rs` against a real TLS listener
  (positive with an installed root; fail-closed without one).
- **`cargo test --lib` builds again on main.** A `tls`-only accessor was gated
  on `any(test, feature = "tls")`, failing `deny(dead_code)` in default-feature
  test builds (`b5dd9f8aa`). First full in-source unit-test run afterwards:
  22,197 passed, 4 failed (two ambient-audit drifts, two server-stack
  body-lifecycle tests), 24 ignored.
- **README and docs/WASM.md now describe verified behaviour** for the Browser
  Edition (a lifecycle ledger over browser promises, not a scheduler), RaptorQ
  snapshot distribution (in-process model, test-double transport only), the
  HTTP client, connection pooling, `#[main]` defaults, ProgressCertificate
  reach, the crates.io version, and stale bead/directory references.

### Entry macro runtime defaults

- **`#[asupersync::main]` now builds the multi-thread production runtime by
  default and both entry macros configure an on-demand blocking pool.**
  Previously `#[main]` expanded to `RuntimeBuilder::current_thread()` with the
  builder's default `blocking_threads(0, 0)`, so a hello-world program ran one
  worker and `spawn_blocking` executed inline on that worker. `#[main]` now
  expands to `RuntimeBuilder::multi_thread()` (the host-independent default
  worker count) and both `#[main]` and `#[test]` add `blocking_threads(0, 512)`;
  threads are created only when blocking work arrives. `#[test]` keeps the
  current-thread scheduler so test bodies stay replay-stable. Opt out with
  `#[main(flavor = "current_thread")]` and/or the new `blocking = 0` argument
  (`blocking = N` sets the cap). A bare `RuntimeBuilder` is unchanged: it still
  ships without a pool until `blocking_threads(min, max)` is called. Proven by
  `tests/entry_macro_defaults_e2e.rs` (two spinning tasks only both observe each
  other under the multi-thread default; `spawn_blocking` runs off the worker
  thread with the default pool and on it with `blocking = 0`).

### gRPC server routing

- **Registered unary services can now be called through the native HTTP/2
  listener.** The additive `ServiceHandler::call_unary` hook,
  `ServiceHandlerFuture`, `Server::dispatch_registered_unary`,
  `Server::dispatch_registered_unary_with_trailers`,
  `Server::bind_registered_http2`, and `Server::serve_http2` connect
  descriptor-registered services to the production H2 framing, metadata,
  interceptor, deadline, request-region, cancellation, and status-trailer
  pipeline. Unknown, malformed, streaming-only, and legacy metadata-only
  routes fail closed with gRPC `UNIMPLEMENTED`. The new trait method has a
  default implementation, so an implementation that supplies only the former
  required trait items needs no new item (covered by the in-repo legacy-shaped
  implementation); legacy `Server::serve` remains a bind probe and `bind_http2`
  remains the explicit catch-all transport seam
  ([`3c73a33`](https://github.com/Dicklesworthstone/asupersync/commit/3c73a334c02e9976bda712c19b07221360bc7f3e)).

## [v0.4.10] - 2026-08-30

### Runtime API and correctness

- **Lock-free cancellation polling for hot loops.** New public
  `Cx::published_cancel_requested()` observes the Release-published
  cancellation envelope with one Acquire atomic load instead of the inner
  `RwLock` read `Cx::is_cancel_requested` performs. Runtime cancellation
  producers (`set_cancel_requested`, `cancel`, `cancel_with`, `cancel_fast`,
  task-handle and checkpoint-budget producers) keep the envelope synchronized,
  so both APIs agree everywhere except the legacy v0.4.3 direct
  locked-field-mutation compat path, where the published bit may briefly lag
  (it can only lag; checkpoint delivery is unchanged and the envelope
  re-converges at the next runtime mutation). Added for per-posting
  cancellation polls in hot scoring leaves (br-asupersync bd-tb4c4 / quill
  cancel-poll-leaf-fastpath follow-up).
- **Fix broken lib-test build in the RaptorQ parallel encode property test**
  (stale inline format args under `prop_assert_eq!` since the repair-cursor
  refactor; positional arguments now).

### Notes

- The v0.4.3 public compatibility floor is preserved: the locked
  `is_cancel_requested` contract (including direct `cancel_requested`
  observability and `fast_cancel` handle replacement semantics) is unchanged
  and pinned by the existing compatibility tests plus the new
  `published_cancel_requested_tracks_runtime_mutations_lock_free` test.

## [v0.4.9] - 2026-08-20

### Runtime API and correctness

- **Cloned runtime handles can now mint production request contexts.**
  `RuntimeHandle::request_cx_with_budget` and the fallible counterpart are
  additive to the established `Runtime` method. The resulting `Cx` retains the
  request budget, root region, I/O/timer drivers, spawn gateway, and pending-spawn
  accounting. A weak handle whose runtime has gone away fails closed with
  `SpawnError::RuntimeUnavailable` instead of manufacturing authority
  ([`04a4914`](https://github.com/Dicklesworthstone/asupersync/commit/04a4914afff4b131bba82760e17d1fbd4dcc53c3)).
- **Embedders can attach their own blocking pool to a request context.**
  Public `Cx::with_blocking_pool_handle` lets an embedder route `spawn_blocking`
  through its existing `BlockingPoolHandle`. Without one, an explicit/current
  `Cx` runs the closure inline; only free `runtime::spawn_blocking` with no
  ambient `Cx` uses the bounded dedicated-thread fallback. This additive API
  creates no pool or global state; `None` detaches the pool
  ([`a4b16b4`](https://github.com/Dicklesworthstone/asupersync/commit/a4b16b4e090066cc8b61d2d97ba849a29c114ef1)).
- **Actor and GenServer hot mailboxes now yield after each bounded batch.** Fully ready normal and shutdown-drain loops call `yield_now` after eight messages;
  single-poll regressions stop at eight. This internal repair changes no public
  signature and does not prove whole-runtime fairness or a throughput gain
  ([`05e6d06`](https://github.com/Dicklesworthstone/asupersync/commit/05e6d06c7c96255461081a10dd75d41e499a0f70)).
- **Extreme exponential restart backoff now saturates instead of panicking.** Its fallible duration conversion clamps or falls back to the configured maximum,
  including `Duration::MAX` at `u32::MAX`; the public strategy shape is unchanged
  ([`1127d64`](https://github.com/Dicklesworthstone/asupersync/commit/1127d64d300a2a52524b7bb4870c7a521f7d55aa)).

### OpenTelemetry export

- **OTLP/HTTP configuration is validated before export work begins.** The
  additive immutable `OtlpHttpConfig` builder validates bounded absolute HTTP(S)
  endpoints, TLS/root-provider availability, headers, timeouts, retry/backoff,
  compression, and resource attributes. Core configuration performs no ambient
  environment reads; secrets remain inaccessible/redacted; redirects, cookies,
  and client-internal retries are disabled; exporter retries remain bounded by
  the caller's `Cx`, deadline, and budget
  ([`d0303fd`](https://github.com/Dicklesworthstone/asupersync/commit/d0303fdebac717ee8fb3f09f32ce3dd88e5ae059)).
- **Metrics can be exported through a finite, owned OTLP pipeline.**
  `OwnedOtlpMetrics` maps all 23 fixed `MetricsProvider` instruments into
  deterministic cumulative OTLP requests with exact units and histogram
  boundaries, explicit timestamps and reset semantics, bytewise attribute
  ordering, checked numeric conversion, bounded cardinality and request sizes,
  and request splitting only at metric boundaries. The existing SDK-backed
  `OtelMetrics` bridge remains available and unchanged
  ([`4da1a40`](https://github.com/Dicklesworthstone/asupersync/commit/4da1a40028c533a063ef8e0b113064443c2a2b70)).
- **Traces can be mapped and exported without handing ownership to an external
  SDK.** `OwnedOtlpTraces` performs bounded preflight validation before cloning
  or encoding, applies head sampling before request construction, emits no
  request when every span is unsampled, canonicalizes parent-before-child,
  sibling, event, and link ordering, and sends requests sequentially under the
  caller's `Cx` without orphan tasks. The established SDK bridge and legacy
  queue remain intact. The implemented lineage guarantee is deliberately local
  to parentage within an individual trace; links do not claim arbitrary
  cross-trace structured-concurrency lineage
  ([`b21c025`](https://github.com/Dicklesworthstone/asupersync/commit/b21c025cfcdc7ee0b52f9da71cf8f99db7a0198b),
  [`4610fdc`](https://github.com/Dicklesworthstone/asupersync/commit/4610fdcde56221dcc6953c73b0184ab756f0fd89)).
- **Logs now have a finite owned OTLP mapping surface.** `OwnedOtlpLogs` and its
  additive input and configuration types encode five severities, event and
  observed timestamps, trace/span context, flags, event names, typed OTLP
  bodies, attributes, resource/scope metadata, schema URLs, dropped counts,
  and bounded batching. Recursive values have explicit node, depth, item,
  byte, and wire-envelope limits; ordering is deterministic and privacy
  filtering runs through the established `LogEntry` adapter. Legacy
  `OtlpLogRecord`, `LogsSnapshot`, and exporter APIs remain unchanged. This
  tranche establishes deterministic mapping and collector interoperability,
  not the later partial-success, retry, shutdown, or complete transport-failure
  matrix
  ([`df93ab1`](https://github.com/Dicklesworthstone/asupersync/commit/df93ab1211a906dc0e8072b15a6e99b8562e0839)).

### SQLite correctness and security

- **Cancelling queued SQLite work no longer interrupts another operation that
  owns the connection.** Each operation now moves through explicit queued,
  running, cancellation-requested, and completed phases. Cancellation before
  worker admission performs no database side effect; cancellation targets
  native SQLite interruption only after that operation becomes the connection
  owner; cancelled workers are drained; and an already committed result wins a
  late cancellation race. Row streams follow the same ownership rules, and the
  connection remains reusable afterward. The additive
  `SqliteConnection::interrupt` remains an explicit native interrupt that
  produces the ordinary SQLite interruption error; structured `Cx`
  cancellation is the route to `Outcome::Cancelled` plus worker draining
  ([`4049a7e`](https://github.com/Dicklesworthstone/asupersync/commit/4049a7e67aeab1e1b736751f9ade84ed2c71a893),
  [`05641de`](https://github.com/Dicklesworthstone/asupersync/commit/05641de7c7b616126c5335b285e41d97e8aa0765)).
- **Checked SQLite entry points now enforce one bounded, fail-closed SQL
  admission policy.** Public `validate_checked_sql_statement` and
  `validate_checked_sql_batch` helpers share the exact parser and policy used
  by checked connection and transaction operations. Checked single-statement
  operations reject multiple statements, parser-limit violations, `PRAGMA`,
  transaction and connection control, `ATTACH`/`DETACH`, `VACUUM` including
  `VACUUM INTO`, and `load_extension`; batch execution permits multiple
  statements but applies the same denied-class policy. Token-aware
  classification preserves comments, quoted data, and identifier boundaries.
  Established unchecked APIs remain available for explicitly trusted migration
  workloads, while `ATTACH`/`DETACH` remain denied even there
  ([`41a1ae8`](https://github.com/Dicklesworthstone/asupersync/commit/41a1ae844ec01d5910b1c36cdd0db4dc63e54b92),
  [`355266b`](https://github.com/Dicklesworthstone/asupersync/commit/355266bb61b95211f668a095cd1f8a4b10252f8f)).
- **Callers can opt into structured, redaction-safe SQLite diagnostics without
  changing established error signatures.** The additive, non-exhaustive
  `SqliteOperation`, `SqliteErrorCategory`, `SqliteRetryDisposition`, and
  `SqliteErrorDiagnostic` types plus the private-field `SqliteOperationError`
  wrapper expose stable operation, category, retry, and SQLite
  primary/extended-code data through separately named `*_diagnosed` connection
  and transaction methods. Existing
  methods continue returning the v0.4.3-compatible `SqliteError`; structured
  cancellation remains an outer `Outcome::Cancelled`; and ordinary `Debug`,
  `Display`, and error-chain traversal omit SQL, values, paths, and raw engine
  prose. Callers must explicitly request `legacy_error()` or `engine_source()`
  when they need those compatibility or diagnostic details. Parser-specific
  `SqlInputError` codes and malformed transaction-begin classifications are
  preserved instead of degrading into generic internal errors
  ([`8757273`](https://github.com/Dicklesworthstone/asupersync/commit/875727331),
  [`6387780`](https://github.com/Dicklesworthstone/asupersync/commit/63877809b)).
- **Prepared-statement cleanup and cache boundaries have stronger public
  conformance coverage.** Regression cases now cover positional and named
  binding order, malformed and incorrect arity cleanup, reset and reuse,
  capacity-one eviction and re-prepare, schema invalidation, dropped or
  pre-cancelled row streams, busy-state cleanup, and terminal pool quiescence
  ([`b19079a`](https://github.com/Dicklesworthstone/asupersync/commit/b19079adf8d0fbb7b6ee34db353f52408d86e903),
  [`eacfba3`](https://github.com/Dicklesworthstone/asupersync/commit/eacfba37a226551b07f1acc6d792f5750af6fead)).
  The neutral consumer now executes seven public-surface cases on both pinned engines, bounded to binding, repeated execution, schema refresh,
  malformed/too-few binds, and pre-cancelled no-mutation/reuse. Surplus binds
  and busy-lock behavior are explicit differences; private cache telemetry and
  partial row-stream finalization remain unsupported, and the pinned P3 matrix
  closure authorizes neither dependency cutover nor API removal.
- **Transaction helpers now await helper-owned rollback before returning a
  cancelled or failed body outcome.** `with_sqlite_transaction` and its
  immediate variant poll rollback to a terminal outcome inside a bounded
  cancellation-masked cleanup section, then preserve the callback's original
  `Err`, `Cancelled`, `Panicked`, or rollback-required result. The existing
  generation-guarded `Drop` rollback remains a last-resort fallback rather
  than the normal completion path. A real-disk regression immediately acquires
  a competing zero-time `BEGIN IMMEDIATE` after helper return, proving that the
  database write lock is already released instead of merely becoming reusable
  eventually
  ([`0fd29c8`](https://github.com/Dicklesworthstone/asupersync/commit/0fd29c849)).
- **SQLite rows expose ordered, duplicate-preserving metadata without changing
  legacy lookup behavior.** Additive `column_name`,
  `column_names_in_order`, and `column_index` APIs retain result-set order and
  duplicate names; `column_index` follows SQLite's first
  ASCII-case-insensitive match. Established `get(name)` exact-case,
  last-duplicate behavior and sorted-unique `column_names()` remain intact for
  v0.4.3 compatibility. Additive `SqliteValue::as_real_strict` and
  `SqliteRow::get_f64_strict` reject integer widening when an exact SQLite
  `REAL` is required, while the established widening accessors remain
  unchanged
  ([`f1eb79a`](https://github.com/Dicklesworthstone/asupersync/commit/f1eb79aa3),
  [`bad4b46`](https://github.com/Dicklesworthstone/asupersync/commit/bad4b4666),
  [`7ab8bde`](https://github.com/Dicklesworthstone/asupersync/commit/7ab8bde35)).
- **The SQLite parity campaign now ends in one real dual-engine aggregate.** A
  neutral downstream consumer executes 47 common public-surface cases across
  P2-P8, records eight explicitly native-only cancellation cases, reports zero
  unexplained divergences, and proves terminal runtime-local cleanup on Linux.
  Unsupported target cells and every intentional difference remain explicit;
  the decision is to keep `rusqlite` and `sqlparser`, not authorize a
  FrankenSQLite cutover
  ([`b22544e`](https://github.com/Dicklesworthstone/asupersync/commit/b22544ef8),
  [`a439270`](https://github.com/Dicklesworthstone/asupersync/commit/a4392700f)).

### Compatibility evidence

- **The published v0.4.4 cancellation boundary now has a permanent external
  consumer canary.** A standalone fixture depends on exactly `asupersync
  = "=0.4.4"`, reproduces FrankenGraphDB's stale outer-`Cancelled`
  expectation, and then verifies the shipped acknowledged-cancellation result
  and cleanup behavior. The RCH-only release lane rejects local fallback,
  skipped execution, and zero passed cases. This is exact-release compatibility
  evidence for v0.4.4, not current-HEAD native-runtime proof and not proof that
  the real FrankenGraphDB consumer has completed its migration
  ([`6ab560f`](https://github.com/Dicklesworthstone/asupersync/commit/6ab560f2d77a94638cb1ad566cab0ca30388f343)).
- **The v0.4.3 public compatibility floor remains intact.** All public-surface
  changes in this release are additive: no established public item is removed
  or renamed, no visibility is reduced, and no established signature is
  changed. Existing unchecked SQLite APIs, OTLP SDK and legacy-log surfaces,
  and ordinary runtime-context construction remain functional. The new APIs
  provide opt-in request-context creation, embedder-owned blocking-pool
  attachment, checked-SQL validation, structured SQLite diagnostics, explicit
  SQLite interruption, and finite owned OTLP export.

### ATP security

- **RQ SSH bootstrap keys no longer travel in process arguments.** Generated
  authentication keys are delivered through bounded protected standard input;
  bootstrap subprocesses lose the key-bearing environment, captured output is
  redacted, and configurations that would divert the protected input fail
  closed. OpenSSH token expansion and local-hostname preflight now preserve the
  intended byte semantics without re-exposing the secret
  ([`515d96e`](https://github.com/Dicklesworthstone/asupersync/commit/515d96e7fd7444b33f14e7684c4ba4d988fb58e0)).

### Maintenance

- **Compatibility guidance now matches the behavior that actually ships.**
  MySQL legacy fields do not enable rejected `mysql_native_password`;
  `spawn_local` requires a native owner-worker local lane, unlike `Send`
  spawning; and the compatibility crate installs an Asupersync `Cx`, not a
  Tokio runtime or `Handle`. Libraries requiring `Handle::current()` need an
  independently owned Tokio island; Hyper, Tower, and I/O remain explicit
  component bridges. These are contract corrections, not removals or breaks
  ([`860fa00`](https://github.com/Dicklesworthstone/asupersync/commit/860fa00e5),
  [`506fce0`](https://github.com/Dicklesworthstone/asupersync/commit/506fce04d),
  [`4fb2ba0`](https://github.com/Dicklesworthstone/asupersync/commit/4fb2ba0f9)).
- **Strict all-feature lint and documentation frontiers were repaired.** The
  remaining Clippy and rustdoc-link blockers, including the MySQL context link,
  are gone without intentional runtime behavior changes
  ([`b809ce7`](https://github.com/Dicklesworthstone/asupersync/commit/b809ce7e237d5701ed06e58b16556111efd25c5a),
  [`1aec733`](https://github.com/Dicklesworthstone/asupersync/commit/1aec733e31a7f7cccaa2f204f1555ba426385edd),
  [`0a646d4`](https://github.com/Dicklesworthstone/asupersync/commit/0a646d4f5b03b12026adb86050084c2b89a73438)).

## [v0.4.8] - 2026-08-18

### Runtime correctness

- **Local tasks now remain owned by the runtime that accepted them.** A
  `spawn_local` issued while another runtime's worker TLS was active could
  previously publish the task into that foreign worker's owner-local lane.
  The local-spawn lane is now bound to runtime identity, and a foreign `Cx` is
  rejected with `SpawnError::LocalSchedulerUnavailable` before task allocation,
  reservation, or enqueue. Ordinary `Send` scheduler paths retain their
  established owner-scheduler fallback; non-`Send` tasks are never rerouted
  across runtimes ([`53b6813`](https://github.com/Dicklesworthstone/asupersync/commit/53b681391)).
- **Cancellation no longer targets a foreign worker's local queue.** The
  cancellation fast path now checks scheduler ownership before using the
  current worker-local lane, preventing worker-index collisions across runtime
  instances from stranding cancellation delivery. Native regression coverage
  parks the task before aborting it and verifies the exact acknowledged result
  and cleanup state ([`c2c8965`](https://github.com/Dicklesworthstone/asupersync/commit/c2c896520)).
- **Ambient `Cx` guards remove the exact frame they installed.** Dropping an
  outer `CurrentCxGuard` before a nested guard could previously pop the nested
  capability restriction. Guards now carry frame identity, use an innermost
  fast path, and remove by identity when teardown is out of order, preserving
  capability attenuation and thread-local stack integrity
  ([`c34dcd6`](https://github.com/Dicklesworthstone/asupersync/commit/c34dcd638),
  [`062ad0a`](https://github.com/Dicklesworthstone/asupersync/commit/062ad0ae3)).

### Compatibility

- The fixes are internal and additive: no public item was removed or renamed,
  no public signature or visibility changed, and the v0.4.3 API/behavior
  compatibility contract remains the release floor.

## [v0.4.7] - 2026-08-17

### Runtime correctness

- **Runtime teardown now has a bounded path.** `Runtime::shutdown_timeout`
  synchronously closes task and blocking-pool admission, signals scheduler
  shutdown, runs the normal blocking teardown on a detached reaper thread, and
  returns within the caller's bound even when a
  contract-violating future blocks inside `poll` and its worker never joins;
  `Runtime::shutdown_background` is the non-waiting variant. On a timed-out
  return the reaper retains the runtime state so any still-blocked worker
  keeps operating on live memory. Ordinary `Runtime` drop is unchanged and
  still joins without a bound
  ([#60](https://github.com/Dicklesworthstone/asupersync/issues/60),
  [`6f23db9`](https://github.com/Dicklesworthstone/asupersync/commit/6f23db9bc)).

- **Runtime-handle tasks now have an additive typed join path.**
  `RuntimeHandle::spawn_checked` and `try_spawn_checked` return a
  `CheckedJoinHandle<T>` whose future resolves to `Result<T, JoinError>`, so
  runtime shutdown is distinguishable from a user-task panic without
  unwinding the observer. The established `RuntimeHandle::spawn` and
  `JoinHandle<T>` signatures and panic-propagating behavior remain unchanged
  for v0.4.3 compatibility ([#59](https://github.com/Dicklesworthstone/asupersync/issues/59)).

### Deterministic testing

- **Exact Lab schedules now have a strict canonical artifact codec.**
  `ForcedSchedule::to_canonical_bytes` and bounded decoding through
  `ForcedScheduleDecodeLimits` preserve dispatch identities, reject malformed,
  oversized, checksum-invalid, or semantically inconsistent artifacts, and do
  not fall back to RNG scheduling. This is a Lab evidence-integrity format, not
  a production scheduler-control protocol, workload codec, universal replay
  format, completed minimizer, or persisted downstream reproducer
  ([`de16042`](https://github.com/Dicklesworthstone/asupersync/commit/de160424f),
  [`0f36f1b`](https://github.com/Dicklesworthstone/asupersync/commit/0f36f1b7b)).

### Security and protocols

- **QUIC handshake duplicate detection now runs after authentication.** A
  cleartext long header that reused an accepted packet number could previously
  bypass packet unprotection and be reported as a successful receive. Duplicate
  packets now authenticate before idempotent suppression, and the path RTT used
  by source-stream BDP admission is initialized only by authenticated handshake
  traffic, and packet-history exhaustion is likewise evaluated only after
  authentication. Reordered CRYPTO buffering now caps both payload bytes and
  disjoint range metadata, closing a tiny-frame memory-amplification path;
  rejected conflicting or oversized fragments also leave previously accepted
  reassembly state intact.
- **QUIC and ATP stream reassembly now bound fragment metadata independently
  of buffered bytes.** Authenticated peers can no longer turn a bounded receive
  window into an unbounded number of ordered-map nodes using tiny disjoint
  stream fragments. Limit rejection occurs before flow-control, final-size, or
  buffered-byte state changes, and harmless duplicate fragments remain
  accepted at the cap.
- **ATP validates final size before duplicate trimming.** A duplicate FIN can
  establish the stream's final size, while contradictory final offsets fail
  before mutating reassembly state. Duplicate suppression therefore cannot hide
  a final-size violation
  ([`acfc2a7`](https://github.com/Dicklesworthstone/asupersync/commit/acfc2a7d2)).

### Compatibility and release evidence

- **The v0.4.3 public surface remains the patch-line compatibility floor.**
  The typed join API is additive; established runtime spawning and join
  behavior remain functional. The reassembly limits use existing internal and
  error surfaces without removing, renaming, or narrowing a public API.

## [v0.4.6] - 2026-08-17

### Runtime correctness

- **Lab runs can capture and force an exact bounded dispatch projection.** The
  opt-in lab-only authority binds each task generation to its modeled worker,
  scheduler lane, deterministic step, and virtual time before polling, and
  refuses stale, reordered, partial, or resource-exhausting projections without
  falling back to RNG scheduling. A separate deletion-only candidate API can
  retain an ordered source subsequence and execute those exact task/worker/lane
  choices, reporting quiescence versus exhaustion without treating the source
  terminal certificate as a candidate result. This is the executable replay
  and delta-debugging substrate; it does not yet provide a failure classifier,
  minimizer, workload codec, or persisted replay artifact.
- **Lab command publication is ordered ahead of virtual-time jumps and retained
  candidate dispatches.** Managed spawns and deferred cancellation commands can
  no longer sit outside an empty scheduler while auto-advance skips to a later
  timer/reactor deadline. Exact dispatch also treats lazy cancel promotion as
  authoritative over stale ready/timed heap entries.
- **Cancelled sleeps release timer registrations before the completed future is
  dropped.** A task that retains its completed `Sleep` can no longer retain the
  timer-wheel entry, stored waker, or fallback-thread state after explicit
  cancellation. Resetting a sleep also clears the prior waker and delegates
  through one authoritative registration-cleanup path. Detached custom-clock
  fallback threads preserve their terminal wake without consuming the waker of
  a replacement registration or fallback-to-driver transition.

### Security and protocols

- **HTTP/1 framing and connection tokens now use RFC OWS exactly.**
  `Content-Length`, `Transfer-Encoding`, `Connection`, `Expect`, `Host`, and
  `Retry-After` parsing trims only SP/HTAB, preventing Unicode whitespace or
  `obs-text` from creating parser disagreements across request, response,
  streaming, and pooled-client paths. The client also rejects signed or empty
  URL/proxy ports, non-three-digit CONNECT statuses, and invalid manually
  serialized CONNECT header fields.

### Compatibility and release evidence

- **The v0.4.3 public surface remains the patch-line compatibility floor.** The
  release changes private cleanup and parser validation only; it removes or
  renames no public item and adds no required public field.
- **Native cancellation, timer cleanup, HTTP/1 parsing, and filesystem/process
  conformance regressions are permanent release blockers.** The release gate
  includes the downstream abort/join sequence, exact timer-registration and
  waker cleanup, RFC OWS rejection cases, and deterministic read-only-file
  failure checks that remain valid under privileged remote workers.

---

## [v0.4.5] - 2026-08-16

### Runtime correctness

- **Cancelling a timer-parked native task now wakes it immediately.** `Sleep`
  acknowledges explicit task cancellation on the cancellation-triggered
  repoll, completes the wait so structured cleanup can run, and drops its armed
  timer instead of leaving `abort()` + `join()` blocked until the original
  deadline. Deadline and timeout cancellation remain owned by their
  request-budget combinators, so they cannot be mistaken for successful sleeps
  ([#61](https://github.com/Dicklesworthstone/asupersync/issues/61)).
- **Driverless Windows TCP connects wait for kernel writability.** Embedded
  consumers that drive Asupersync futures from an external executor no longer
  trust an early `getpeername()` success as proof that Winsock finished the
  connection. The fallback observes a concrete writable event, and transient
  post-connect `WSAENOTCONN` retries retain a bounded real-time settling floor,
  preventing the first TLS write from exhausting its retry budget in
  microseconds ([#62](https://github.com/Dicklesworthstone/asupersync/issues/62)).
- **Redis RESP3 streaming is linear and attribute-correct.** Incremental frame
  scanning no longer reprocesses an ever-growing prefix, nested attributes are
  skipped without desynchronizing pipelined replies, and public attribute
  decoding remains intact.
- **Quorum, snapshot, and lock-tracking edge cases are corrected.** Quorum is
  computed over eligible replica attempts, drained panics cannot satisfy a
  nonzero quorum, arena generations are no longer rejected by an artificial
  cap, and lock-order tracking survives task migration.

### Security and protocols

- **Owned NKey primitives now cover the bounded codec substrate.** The release
  adds CRC16, RFC 4648 Base32, seed-prefix packing, typed Ed25519/Curve key
  forms, lifecycle/redaction coverage, and constant-time key comparison while
  keeping deterministic seed constructors explicitly test-only. This does not
  claim a full first-party production identity cutover: the compatibility
  surface still exposes the incumbent `nkeys::KeyPair`, retained-artifact E2E
  evidence remains incomplete, and no generic Asupersync-owned transcript
  signer shipped in this release.
- **HTTP/1 borrowed request heads avoid needless allocation.** Additive public
  borrowed-head APIs feed the server parse path without changing the existing
  owned request surfaces.
- **SQLite lifecycle parity is exercised through the supported adapter.** The
  cycle-safe downstream harness now covers the intended P2 lifecycle scenarios
  without introducing another runtime into the core crate.

### Compatibility and release evidence

- **The v0.4.3 public surface remains the patch-line compatibility floor.** No
  public item was removed or renamed, and the timer cancellation repair is an
  internal behavioral correction covered by permanent native-runtime
  regression tests.
- **Release contracts were reconciled to the published source tree.** The
  focused failure batch, dependency inventories, and source-pinned evidence
  now agree with the 0.4.5 package inputs; these receipts remain scoped and do
  not replace the terminal workspace release gate.

---

## [v0.4.4] - 2026-08-14

### Runtime correctness

- **Native task abort now preserves an acknowledged cancellation result.** A
  task parked on a cancel-aware primitive can observe cancellation, return its
  public `Cancelled` value, and complete cleanup without a concurrent abort
  erasing that value into a generic join cancellation. The terminal publisher
  is non-cancellable, panic attribution remains explicit, and the legacy
  state-threaded API retains its established cancellation-dominant contract.
- **Pending WebSocket close writes honor their explicit caller context.** Once
  a Close frame entered `CloseSent`, the split write path previously suppressed
  cancellation and could strand an aborted task forever on a pending transport
  write. Explicit-`Cx` close operations now return typed interruption while the
  connection owner can fail the partially written close deterministically.
- **The downstream failure is now a permanent native-runtime release gate.**
  The regression matrix uses the public spawn/abort/join sequence that failed
  in FastMCP Rust, proves that the task reached its parked state before abort,
  asserts the exact graceful cancellation result, and verifies terminal task,
  region, and obligation cleanup. Model-only, LabRuntime-only, compile-only,
  and filtered-zero-test results cannot satisfy this gate.

### Compatibility

- **No v0.4.3 public API break is accepted in this patch.** Public
  cancellation fields and `TaskRecord` hooks remain source-compatible, while
  the new internal cancellation publication envelope is kept behind those
  established surfaces. Ordinary `Cx::spawn` continues to preserve a future's
  value after it has acknowledged cancellation; cancellation-dominant
  combinators retain their separately documented semantics.
- **HTTP/1 streaming controls are additive.** `Http1Config` remains usable by
  existing v0.4.3 struct literals. New body-queue and unread-body-drain limits
  live in `Http1StreamingConfig`, and `IncomingBody` compatibility remains
  available while the streaming server uses the richer request type.
- **Breaking changes now have an explicit release policy.** Every 0.4.x
  release must compare against v0.4.3, preserve deprecated entry points, add
  compatible APIs in preference to replacement, and stop unless an exact
  break has extraordinary correctness or security justification, migration
  evidence, downstream compile proof, release-note coverage, and written user
  approval at an intentional semver boundary.

### HTTP/1 request-body safety

- **Streaming bodies execute under the request-region capability context.**
  Backpressure waits, cancellation, budgets, and body-channel limits now
  observe the request lifetime rather than the enclosing connection lifetime.
- **Connection reuse requires bounded framing-aware body synchronization.**
  If a handler leaves a segmented request body unread, the server drains
  decoded frames and chunk trailers within explicit frame, byte, and time
  bounds. The connection is reused only after synchronized body EOF; malformed,
  truncated, over-limit, or cancelled drains close it fail-closed.

### Release evidence

- **The published v0.4.4 downstream compatibility canary is now
  permanent.** An external fixture depends on the exact crates.io release,
  reproduces FrankenGraphDB's stale outer-cancellation expectation as a
  planted negative, and proves the migrated public behavior: acknowledged
  cancellation completes cleanup and joins `Ok(())`, while a
  cancellation-blind child retains outer `JoinError::Cancelled`. RCH job
  `29982692904796167` passed on `ovh-a` with all three required sentinels.
- **Compatibility and proof receipts were reconciled to the shipped bytes.**
  Cancellation, HTTP/1, dependency, protocol, and artifact-governance packets
  retain their scoped no-claim boundaries while pinning the final source and
  contract graph. These receipts and the scoped compatibility canary do not
  replace terminal release gates or broad downstream application testing.

---

## [v0.4.3] - 2026-08-11

### Runtime correctness

- **Owned poll wrappers contain polling and terminal cleanup panics.** The
  internal `catch_unwind` boundary owns its future until one terminal drop,
  never polls after completion, preserves the polling panic when cleanup also
  panics, and surfaces cleanup-only panics. The web boundaries separately
  contain synchronous handler-construction panics. Deterministic LabRuntime
  coverage verifies that the exercised region returns to quiescence.

### Web diagnostics

- **Error-handler panics become `ASUP-E502` failures.** Middleware and
  content-negotiation construction/poll failures return a redacted
  internal-server-error response. With `tracing-integration` enabled, their
  structured events include method, path, trace identifier, and panic details.

### Verification boundary

- **The acceptance proof is focused and executable.** Owned-future unit/Lab
  cases, a direct `ErrorHandlerMiddleware` request/response boundary, and the
  futures-lite capability contract passed before release preparation. This is
  not listener/router/transport end-to-end evidence, and this release does not
  claim the later FUT A6-A9 dependency cutover or removal of the incumbent
  compatibility crate.

---

## [v0.4.2] - 2026-08-09

### Runtime correctness

- **The internal blocking driver now owns its wake and parking semantics.** The
  safe kernel uses an `Arc<Wake>` notification state to avoid lost wakes and
  busy spinning, admits borrowed non-`Send` futures and recursive calls, and
  refuses runtime scheduler contexts before polling while retaining the
  blocking-pool path. It introduces no ambient executor or orphan task.
- **Acceptance behavior is executable and bounded.** Focused unit, notification
  state-model, cross-thread wake/cancellation, context-policy, and LabRuntime
  quiescence cases passed. A Linux comparison receipt observed zero process CPU
  ticks during separate 750 ms idle waits for both the owned and incumbent
  drivers. The owned ready path was slower in the recorded micro-measurement,
  so this release makes no latency-parity or performance-improvement claim.

### Migration boundary

- **The incumbent remains until downstream parity work lands.** This release
  accepts the owned kernel without migrating futures-lite call sites or
  authorizing dependency removal; those cutovers remain assigned to the FUT
  A6-A9 migration groups.

---

## [v0.4.1] - 2026-08-08

### Runtime correctness

- **ATP progress Streams now retain their capability context.** Owned send and
  receive progress Streams poll the underlying channel with the creation `Cx`,
  preserving sender wake registration and cancellation observation without
  introducing a detached executor or compatibility shim.

### Conformance and packaging

- **RFC conformance inputs ship inside the crate package.** The QUIC migration
  RFC 9000 reference registry and the RFC 6330 systematic-index fixture are
  included from package-local paths, so `asupersync-conformance` verifies from
  its crates.io tarball instead of escaping to repository-only files.
- **Release evidence pins are exact again.** Downstream consumer locks and the
  affected typed-format, Base64, and artifact-governance inventories are
  reconciled to the shipped bytes while retaining their existing no-claim
  boundaries.

---

## [v0.4.0] - 2026-08-07

### Breaking changes and version-policy correction

- **Tracked session channels are capability-threaded and proof-returning.**
  `TrackedSender::try_reserve` takes `&Cx`, and `TrackedPermit::try_send`
  returns `CommittedProof<SendPermit>`. These changes first appeared in
  `v0.3.10`, where they were incorrectly shipped under a patch version.
  `v0.4.0` deliberately re-anchors that public API under the project's stated
  pre-1.0 semver policy. `v0.3.10` remains available because yanking it would
  disrupt known downstream consumers.

### Runtime and correctness

- **Scheduler and lifecycle repairs.** Timed tasks are promoted when ready
  work is injected, worker-spawn failure completes affected tasks, deferred
  regions drain before leak diagnostics, spawn effects retain causal ordering,
  and artifact-cache admission has deterministic tie and count behavior.
- **Cancellation-safe synchronization fixes.** The release prevents waiter-ID
  wraparound, rejects completed MPSC reserve repolls, restores interrupted
  semaphore acquisitions, preserves RwLock queue order, linearizes OnceCell
  waiter state, releases mutex rank before wakeup, and removes several stale or
  duplicate waiter ownership states.
- **I/O and database boundaries.** Buffered seeks now account for unread
  buffered data; framed writes have bounded backpressure; SQLite row streams
  remain connection-exclusive and dropped transactions roll back eagerly; and
  Redis PubSub validates control acknowledgements.

### Capabilities, codecs, and protocols

- **Explicit io_uring capability control plane.** Linux backends now retain
  terminal reactor receipts and probe fixed buffers, provided-buffer groups,
  requested SQPOLL, multishot receive/accept, and mapped buffer rings before
  selecting those modes. These are capability probes, not performance claims.
- **First-party bounded codecs and helpers.** Scalar Base64 and hexadecimal
  kernels, deterministic future combinators, allocation-free helper subsets,
  owned polling boundaries, and a parked `block_on` kernel expand the native
  surface without introducing another executor.
- **Protocol hardening.** HTTP/1 bodies fail closed on incomplete termination,
  native H2/gRPC retains status context, fragmented QUIC varints decode
  correctly, bounded OTLP trace/log/metric schemas cover the supported finite
  wire surface, and replay diagnostics use the stable `ASUP-E401` token.

### Configuration and evidence

- **Typed, redacted configuration models.** Runtime, ATP, and ATP daemon
  configuration now have versioned canonical JSON models with secret-bearing
  fields redacted at serialization boundaries.
- **Proof and artifact governance.** The release expands deterministic proof
  lanes, source inventories, claim-to-status mappings, and fail-closed artifact
  graph checks. These records document the surfaces they cover and retain
  explicit no-claim boundaries; they are not broad performance or security
  certifications.

---

## [v0.3.10] - 2026-07-27

### ATP clean-matrix, transport security, and proof-lane consolidation

> Late-June and July work moved ATP from individual architecture wins toward
> matrix-governed benchmark evidence. The bar is now explicit: tuned rsync
> baseline, release `atp`, crypto-symmetric cells, fail-closed SHA/tamper
> checks, rate-capped links, and whole-matrix evidence before claiming a win.
> Stale cells, compile-only checks, or `sha_ok` without timing/bytes evidence do
> not count.

- **ATP-over-QUIC/H3 foundation and native TLS posture.** The transport lane
  now includes ATP QUIC integration, ATP-over-H3/WebTransport adapters, native
  QUIC frame codecs, handshake state, packet protection, real UDP transfer
  paths, and fail-closed X.509/server-name/replay/anti-amplification tests.
  Direct native QUIC/TLS relies on QUIC AEAD authentication; non-direct or
  cross-trust RaptorQ paths still need explicit symbol-auth posture.
  Representative commits include
  [`b45516d70`](https://github.com/Dicklesworthstone/asupersync/commit/b45516d70),
  [`bb20b0fa9`](https://github.com/Dicklesworthstone/asupersync/commit/bb20b0fa9),
  [`651748218`](https://github.com/Dicklesworthstone/asupersync/commit/651748218),
  [`e1a681d80`](https://github.com/Dicklesworthstone/asupersync/commit/e1a681d80),
  [`159113a1f`](https://github.com/Dicklesworthstone/asupersync/commit/159113a1f),
  [`e7e1d8e8`](https://github.com/Dicklesworthstone/asupersync/commit/e7e1d8e8),
  [`4078161f`](https://github.com/Dicklesworthstone/asupersync/commit/4078161f),
  [`1442724ff`](https://github.com/Dicklesworthstone/asupersync/commit/1442724ff),
  and [`ca63bd03e`](https://github.com/Dicklesworthstone/asupersync/commit/ca63bd03e).
- **Reliable clean-source stream and auth/encrypted repair path.** The
  benchmark lane landed authenticated control-source frames, clean encrypted
  source-stream routing, drain/flush fixes, good-link reliable stream admission,
  ack-clocked QUIC datagram pacing, repair-spray pacing, and E802 block-size
  rounding fixes. These are tracked through the matrix harnesses rather than as
  isolated unit claims.
  ([`d7a82fd44`](https://github.com/Dicklesworthstone/asupersync/commit/d7a82fd44),
  [`116e51adf`](https://github.com/Dicklesworthstone/asupersync/commit/116e51adf),
  [`d880f5fb4`](https://github.com/Dicklesworthstone/asupersync/commit/d880f5fb4),
  [`69c9c14be`](https://github.com/Dicklesworthstone/asupersync/commit/69c9c14be),
  [`da53c8e9a`](https://github.com/Dicklesworthstone/asupersync/commit/da53c8e9a),
  [`ace3358d5`](https://github.com/Dicklesworthstone/asupersync/commit/ace3358d5),
  [`0dd7aa708`](https://github.com/Dicklesworthstone/asupersync/commit/0dd7aa708),
  `br-asupersync-8sxwj0`, `br-asupersync-5r1mh8`,
  `br-asupersync-uw1cc2`)
- **Encrypted QUIC receiver/sender overhaul and retransmit coalescing.** The
  July 3 MATRIX-205/206 work replaced the encrypted QUIC receive pump with
  zero-copy frame decode, in-place AEAD unprotect, ACK fast paths,
  inc-hash-on-receive, bounded sender queues, release-on-ACK retention,
  delivery-clocked source-stream pacing, and coalesced retransmit frames.
  Current evidence records the first encrypted mild-loss win (`50M/good`),
  `5G/perfect/encrypted` correctness unblocked, and a large receiver RSS drop,
  while keeping the no-claim boundary explicit: `500M/perfect/encrypted` still
  loses to tuned rsync, `50M/bad/encrypted` still needs a rate-climb/cliff
  recovery mechanism, absolute-schedule pacing was re-refuted, and 5G encrypted
  peak RSS remains follow-up work.
  ([`773a655ef`](https://github.com/Dicklesworthstone/asupersync/commit/773a655ef),
  [`1b480bcab`](https://github.com/Dicklesworthstone/asupersync/commit/1b480bcab),
  `br-asupersync-uw1cc2`, `br-asupersync-oh6gm2`,
  `br-asupersync-xnlyss`)
- **RQ 500M/broken convergence, decode-integrity correction, and scoped win.**
  MATRIX-207/208/209 moved `500M/broken/nocrypto` from timeout, to
  fail-closed convergence, to sha-ok parity, and finally to a banked scoped
  win. The stack includes arrival-evidence pacing loss, rank-stall congestion
  gated by arrival corroboration, lower round-0 FEC overhead, sparse residual
  source requests, shard-absolute FEC seed read-back from shared staging, and
  double-buffered encode-ahead for the paced RQ spray. Current ledger evidence
  supports only this matrix-cell claim: atp median 564.77s, sha-ok 3/3 plus a
  confirming fourth rep, versus tuned rsync median 574.46s. The residual
  `asupersync-c54to7` decode-integrity bead remains open for rare
  redundancy-recovered `InconsistentEquations`; do not read this as an
  encrypted, tree, cross-trust symbol-auth, or whole-matrix win.
  ([`6bfdf6c54`](https://github.com/Dicklesworthstone/asupersync/commit/6bfdf6c54),
  [`a6b797fc9`](https://github.com/Dicklesworthstone/asupersync/commit/a6b797fc9),
  [`814809e5`](https://github.com/Dicklesworthstone/asupersync/commit/814809e5),
  [`acfccb30`](https://github.com/Dicklesworthstone/asupersync/commit/acfccb30),
  `br-asupersync-c54to7`)
- **ATP follow-ups after the banked RQ win remain proof-gated.** MATRIX-210
  raised encrypted QUIC recovery drain caps conservatively (`FAST` 4->8,
  PTO 64->256), and MATRIX-211 landed a one-shot packed-member commit batch on
  the blocking I/O pool for a future `tree_small` A/B. These are implementation
  landings, not standalone benchmark wins: `br-asupersync-oh6gm2` remains open
  for encrypted rate-climb/cliff recovery, `br-asupersync-xnlyss` records the
  5G encrypted receiver RSS profile, and the packed-member path still needs a
  quiet-box matrix proof before any perf claim is banked.
  ([`dc99cad8`](https://github.com/Dicklesworthstone/asupersync/commit/dc99cad8),
  [`3dd3f141`](https://github.com/Dicklesworthstone/asupersync/commit/3dd3f141),
  `br-asupersync-oh6gm2`, `br-asupersync-xnlyss`)
- **Large-object clean wins against tuned rsync.** Incremental hash-on-receive,
  fragment hash overlap, protocol-v3 `ObjectComplete` hash trailers, and
  same-filesystem commit rename cut tail work on large clean transfers. Matrix
  evidence recorded 500M and 5G clean wins in nocrypto+auth cells while keeping
  explicit no-regress and no-claim boundaries for remaining harder lanes.
  ([`faa93d808`](https://github.com/Dicklesworthstone/asupersync/commit/faa93d808),
  [`463a4cfae`](https://github.com/Dicklesworthstone/asupersync/commit/463a4cfae),
  [`81c44d28e`](https://github.com/Dicklesworthstone/asupersync/commit/81c44d28e),
  [`bae50415d`](https://github.com/Dicklesworthstone/asupersync/commit/bae50415d),
  `br-asupersync-2eb4k2`, `br-asupersync-sze9ym`)
- **Delta/resync and bonding groundwork.** Byte-precise subchunk planning,
  mixed-subchunk tests, wire apply reports, compact repeated-chunk framing, and
  manifest-framing reductions landed for delta resync and netns sidecar work.
  The known delta resync hang remains an active blocker rather than a completed
  claim.
  ([`70d8fa001`](https://github.com/Dicklesworthstone/asupersync/commit/70d8fa001),
  [`bec7a27d1`](https://github.com/Dicklesworthstone/asupersync/commit/bec7a27d1),
  [`989331e78`](https://github.com/Dicklesworthstone/asupersync/commit/989331e78),
  [`cbbe37474`](https://github.com/Dicklesworthstone/asupersync/commit/cbbe37474),
  [`8983b7364`](https://github.com/Dicklesworthstone/asupersync/commit/8983b7364),
  `br-asupersync-v0jeoc`, `br-asupersync-cu4zww`,
  `br-asupersync-2qas9c`)
- **RaptorQ hardening and fail-closed decode posture.** The RaptorQ lane now has
  deterministic proof traces, decode verification guards, wrong-width symbol
  rejection, tamper proof witnesses, rank-profile evidence, and data-loss bug
  fixes. Treat it as a proof-carrying subsystem with explicit authentication
  posture, not just an encoder/decoder API.
  ([`ac69a713c`](https://github.com/Dicklesworthstone/asupersync/commit/ac69a713c),
  [`727e21eb7`](https://github.com/Dicklesworthstone/asupersync/commit/727e21eb7),
  [`11a08727b`](https://github.com/Dicklesworthstone/asupersync/commit/11a08727b),
  [`0ac5c3e7c`](https://github.com/Dicklesworthstone/asupersync/commit/0ac5c3e7c),
  [`aa0959143`](https://github.com/Dicklesworthstone/asupersync/commit/aa0959143),
  [`cb44e3cc4`](https://github.com/Dicklesworthstone/asupersync/commit/cb44e3cc4))
- **Proof lanes as first-class source of truth.** Remote `rch` proof commands,
  proof-lane manifests, proof status snapshots, validation-frontier signoff, and
  resource-envelope contracts now govern many documentation/runtime claims.
  Update scripts, artifacts, manifest lanes, and contract tests together.
  ([`1cc389141`](https://github.com/Dicklesworthstone/asupersync/commit/1cc389141),
  [`92e801726`](https://github.com/Dicklesworthstone/asupersync/commit/92e801726),
  [`fd911e707`](https://github.com/Dicklesworthstone/asupersync/commit/fd911e707),
  [`b63bd24cf`](https://github.com/Dicklesworthstone/asupersync/commit/b63bd24cf),
  [`29fb46d10`](https://github.com/Dicklesworthstone/asupersync/commit/29fb46d10))
- **Browser/service/runtime expansion.** Browser Edition added readiness,
  package-integrity, consumer-compatibility, WASM rebuild, native-only cfg, and
  RCH-in-CI gates. Service surfaces also advanced across production H2
  listeners, web middleware layering, fluent HTTP client requests, database
  transaction obligations, and gRPC call-scoped backpressure/cancel coupling.
  Runtime work added spawn/mailbox improvements, platform reactor defaults,
  shared fallback timers, scheduler CPU metrics, and churn gates.
  ([`0f58ff593`](https://github.com/Dicklesworthstone/asupersync/commit/0f58ff593),
  [`186a71303`](https://github.com/Dicklesworthstone/asupersync/commit/186a71303),
  [`057a8d8c0`](https://github.com/Dicklesworthstone/asupersync/commit/057a8d8c0),
  [`2ac589d68`](https://github.com/Dicklesworthstone/asupersync/commit/2ac589d68),
  [`6a79f24b6`](https://github.com/Dicklesworthstone/asupersync/commit/6a79f24b6),
  [`4c772a47c`](https://github.com/Dicklesworthstone/asupersync/commit/4c772a47c),
  [`88ef4e0da`](https://github.com/Dicklesworthstone/asupersync/commit/88ef4e0da),
  [`12c926ef8`](https://github.com/Dicklesworthstone/asupersync/commit/12c926ef8),
  [`326082b0f`](https://github.com/Dicklesworthstone/asupersync/commit/326082b0f),
  [`09868a489`](https://github.com/Dicklesworthstone/asupersync/commit/09868a489))
- **gRPC deadline fallback hardening.** Malformed `grpc-timeout` values now
  use the operator-configured `default_timeout` instead of disabling that
  bound; signed non-grammar values such as `+1S` are rejected, valid peer values
  remain subject to `max_request_deadline` when configured, and unrepresentable
  deadlines expire immediately rather than becoming unbounded. ASCII metadata
  insertion now rejects an invalid value as a whole instead of stripping bytes
  that could transmute a malformed timeout into a valid one, rejects ASCII
  values under the binary-only `-bin` suffix, and unary dispatch enforces the
  inclusive deadline boundary before invoking or polling a handler. gRPC-Web
  trailer decoding also rejects malformed lines and raw non-printable ASCII
  trailer field values.
- **gRPC request-body meter overflow hardening.** Configured aggregate-body
  meters now fail closed when cumulative byte accounting overflows, including
  at a `usize::MAX` cap; uncapped diagnostic accounting remains saturating.

### Runtime scheduler/timer CPU efficiency (`runtime-cpu-overhaul`)

> Live profiling of a heavy consumer (a terminal-multiplexer GUI) localized
> 25–65% CPU to the asupersync runtime even while the application itself was
> wait-bound. This work added the measurement substrate, fixed the one real
> defect it surfaced, and recorded the refuted hypotheses so they are not
> re-attempted. (`br-asupersync-runtime-cpu-overhaul-5vt09v`)

- **Runtime instrumentation counters** behind a new, zero-cost `runtime-metrics`
  feature. `runtime::metrics::snapshot()` exposes timer-thread spawns,
  `sched_yield` calls, worker spins/parks/unparks, and the live timer population
  (registered/fired/cancelled plus a derived `active_timers` gauge). Every
  `record_*` helper inlines to a no-op and `snapshot()` returns all-zero when the
  feature is off, so release builds pay nothing.
  ([`12c926ef8`](https://github.com/Dicklesworthstone/asupersync/commit/12c926ef8),
  `br-asupersync-runtime-cpu-overhaul-5vt09v.1`)
- **Scheduler CPU/churn benchmark and recorded baseline**
  (`benches/scheduler_cpu_churn.rs`,
  `artifacts/scheduler_cpu_churn/baseline.json`): an M-sweep idle+load harness
  that mimics the profiled scheduler shape, reads the counters, and measures
  process CPU, OS-thread high-water, and wakeup-latency p50/p99/p999. A committed
  regression gate (`scripts/run_scheduler_cpu_churn_validation.sh`) fails on
  idle busy-spin, idle-CPU, or thread-per-`sleep` churn regressions.
  ([`12c926ef8`](https://github.com/Dicklesworthstone/asupersync/commit/12c926ef8),
  [`cae8c1540`](https://github.com/Dicklesworthstone/asupersync/commit/cae8c1540),
  `br-asupersync-runtime-cpu-overhaul-5vt09v.2`, `.6.1`)
- **Shared process-global fallback timer** (`time::sleep`): a `Sleep` polled with
  no installed timer driver (`Cx::current().timer_driver()` is `None`) used to
  spawn one OS thread per `Sleep` to drive its deadline — the thread-per-`sleep`
  churn the profile caught (~37/sec) for sleeps driven off the runtime's worker
  threads. It now registers with a single process-lifetime pump thread that
  shares the standard wall-clock timer wheel; a per-`Sleep` thread is kept only
  for custom logical clocks. Behavior-preserving — the default `Cx`-driver path
  is unchanged. As defense-in-depth, taking the fallback now emits a **one-time
  WARN** (via `tracing_compat`) naming the missing timer driver, so a
  mis-configured consumer surfaces in logs instead of churning silently — the
  fallback stays a valid path (no panic), matching the `br-asupersync-9nn568`
  no-driver-warn idiom.
  ([`b67dec457`](https://github.com/Dicklesworthstone/asupersync/commit/b67dec457),
  `br-asupersync-runtime-cpu-overhaul-5vt09v.3`, `.3.5`)
- **`RuntimeBuilder::enable_time()`** convenience: a discoverable, tokio-shaped
  opt-in that installs a wall-clock timer driver unless one was already provided
  via `with_timer_driver` (idempotent, order-independent). `build()` already
  installs a wall-clock driver by default, so this is a clarity/migration aid
  that gives consumers a named method to reach for — and that the off-driver
  fallback warn above points at — rather than a behavior change.
  (`br-asupersync-runtime-cpu-overhaul-5vt09v.3.1`)
- **Empirical findings recorded (no code shipped):** the benchmark proved the
  default multi-threaded runtime is healthy — `timer_threads_spawned == 0`, 0%
  idle CPU, and zero idle `sched_yield` — so the profiled pathologies are
  usage-specific, not default-runtime defects. Replacing the load-path
  `sched_yield` with a userspace spin (Lever 2) was **bench-refuted and
  reverted**: `yield_now` cooperatively deschedules the worker and throttles the
  backoff loop, whereas spinning keeps it hot — a deterministic ~2.7× increase in
  spin-loop iterations, i.e. more CPU, not less, on a multi-worker
  intermittent-work load. The park clock-polling reduction (Lever 3) was found
  already addressed (the multi-lane park reads the clock once per cycle; the
  single-thread worker parks on a constant timeout).
  (`br-asupersync-runtime-cpu-overhaul-5vt09v.4`, `.5`)

## v0.3.8 workspace version marker -- 2026-07-10

> Source marker for the standalone ATP v0.3.8 binary release. The ATP
> distribution repository pins this exact asupersync commit and builds its
> seven archives with DSR; this marker does not create an asupersync release.

### ATP release highlights

- Added native Windows x64/MSVC release support with typed symlink and hardlink
  fidelity, long-path-safe and read-only-safe transactional replacement,
  Windows attributes and 100 ns timestamp handling, full file identities, and
  containment-safe reparse-point and mirror behavior.
- Hardened TCP, RaptorQ, QUIC/TLS, and bonded transfers across platforms with
  canonical manifests, portable bonded descriptors, geometry-bound enrollment,
  fail-closed staging/cleanup, and Windows OpenSSH PowerShell bootstrapping.
- Added real native Windows regression coverage for filesystem metadata,
  transport loopbacks, PowerShell command encoding, and the release installer.

## v0.3.5 workspace version marker -- 2026-06-18

> Dependency-refresh and release-train patch for Rust workspace crates and
> Browser Edition packages.
>
> Internal package-version marker: no `v0.3.5` git tag or GitHub Release was
> present when this changelog was refreshed on 2026-07-04. Until that tag exists,
> compare Unreleased work from `v0.3.4`.

### Release highlights

- Synchronized publishable Rust crates, Browser Edition package manifests, and
  local workspace path dependencies on version 0.3.5.
- Raised remaining non-compatible dependency requirements for the conformance,
  fuzz, SQLite, OpenTelemetry, Redis, SQLx, RaptorQ, and Browser Edition tool
  surfaces so validation resolves against current upstream releases.
- Kept compatible patch/minor dependency resolution in the ignored local
  `Cargo.lock`, preserving the library crate's no-committed-lock policy.
- Updated the public README dependency snippets from 0.3.4 to 0.3.5.

## [v0.3.3] -- 2026-06-01

> 1,991 commits since v0.3.2 (2026-05-20 -> 2026-06-01) | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.3.2...v0.3.3)
>
> Patch release focused on completing the mock-code-finder cleanup push,
> hardening Windows/no-default build surfaces, and repairing the release
> publishing path so crates.io and Browser Edition package releases can run from
> a coherent workspace version.

### Release highlights

- Replaced remaining placeholder/mock-coded test and runtime surfaces with
  deterministic contract-backed behavior across conformance, messaging,
  observability, runtime/lab, and protocol lanes.
- Hardened Windows compilation paths, including no-default CLI binaries and
  capability-safe detached contexts for command-line proof surfaces.
- Synchronized publishable Rust workspace crates and Browser Edition package
  manifests on version 0.3.3 for a coherent release train.
- Repaired the GitHub publish workflow so release cargo jobs use `rch` when it
  is available and fall back to the hosted runner when `rch` is absent, instead
  of failing before crates.io dry-run/package validation.
- Expanded crates.io dry-run coverage so root crates are checked up front and
  every dependent crate is checked immediately before its ordered publish, after
  newly bumped dependencies are visible on crates.io.

## [v0.3.2] -- 2026-05-20 (Release)

> 3,657 commits since v0.3.1 (2026-04-22 → 2026-05-20) | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.3.1...v0.3.2)
>
> Triaged-issue fixes shipped in this release: Windows HTTPS connect path returning `Ok` then failing with `WSAENOTCONN (10057)` (#35, `bc7d3dec`); `Runtime::block_on` not installing an ambient `Cx`, causing `TcpListener::accept` to busy-poll instead of waiting on the reactor (#41, `73dfaaad`); and heuristic `module_desync` epoch-consistency logs demoted from `error!` to `debug!` so normal task-table epoch advances no longer spam errors (#42, `357df7f5`).

### Release theme

A two-week, multi-agent push focused on three things at once: closing
the **Reality-Check Wave 2 / swarm-v2** program (autonomic live control
loop, signed profile bundles, and a 64-core / 256GiB capacity envelope
proof), driving the **mock-code-finder** sweep into every subsystem
(replacing placeholder/mock implementations and broad clippy
suppressions with real semantics and contract artifacts), and a heavy
**runtime/protocol perf and correctness pass** across MPSC, mutex,
HPACK, transport router, scheduler hot paths, HTTP/3 QPACK, and
RaptorQ. Test surface grew with 90+ structure-aware fuzz targets and
a wave of differential / golden / metamorphic suites. Dozens of new
smoke-artifact lanes landed under hidden roots
(`.<name>-smoke-artifacts/`) and dedicated `scripts/run_*_smoke.sh`
runners; the matching `*_contract` integration tests pin them to
deterministic invariants.

### Reality-Check Wave 2 — swarm-v2 autonomic control loop

The headline workstream. Closed as `asupersync-d87ytw` (`[swarm-v2]
Autonomic live control loop and proof certificates`) on 2026-05-05
together with all 15 sub-beads `d87ytw.1`..`d87ytw.15` and the
`reality-check-wave2` siblings (`6qju7t`, `j1dwk6`, `ta56mp`,
`4a3ghz`).

- **Massive-swarm responsiveness program** ([`f660601c8`](https://github.com/Dicklesworthstone/asupersync/commit/f660601c8), [`b832d7fff`](https://github.com/Dicklesworthstone/asupersync/commit/b832d7fff), `br-asupersync-ul9jhr`)
- **64-core / 256GiB massive-swarm capacity envelope proof** with proof-carrying capacity certificates ([`a44863be5`](https://github.com/Dicklesworthstone/asupersync/commit/a44863be5), [`7e56ccdd5`](https://github.com/Dicklesworthstone/asupersync/commit/7e56ccdd5), [`1e0a3abb8`](https://github.com/Dicklesworthstone/asupersync/commit/1e0a3abb8), `br-asupersync-j1dwk6`, `tdgqjy`)
- **Compositional latency-budget certificates** and **mean-field swarm capacity planner** (`asupersync-d87ytw.2`, `d87ytw.3`)
- **Signed profile bundles** with manifests, shadow-run gates, rollback receipts, and true cryptographic signatures ([`66d6d2c1d`](https://github.com/Dicklesworthstone/asupersync/commit/66d6d2c1d), [`f6768f4b2`](https://github.com/Dicklesworthstone/asupersync/commit/f6768f4b2), [`9da861091`](https://github.com/Dicklesworthstone/asupersync/commit/9da861091), `br-asupersync-4buhgd`, `gk0cg3`, `spbsig`, `d87ytw.4`, `d87ytw.7`)
- **Explainable host profile planner** and dry-run runtime config bundles with arena-temperature policy ([`d5fc7b639`](https://github.com/Dicklesworthstone/asupersync/commit/d5fc7b639), [`bc671cd74`](https://github.com/Dicklesworthstone/asupersync/commit/bc671cd74), [`a81c62a8b`](https://github.com/Dicklesworthstone/asupersync/commit/a81c62a8b), `br-asupersync-c1qfr9`)
- **Adaptive batch sizing** for cancel and inject burst handling (`br-asupersync-crtx9h`)
- **Hot-cold arena tiers** and optional large-page cold evidence slabs ([`90d8eda39`](https://github.com/Dicklesworthstone/asupersync/commit/90d8eda39), [`360842bdd`](https://github.com/Dicklesworthstone/asupersync/commit/360842bdd), [`c896ea729`](https://github.com/Dicklesworthstone/asupersync/commit/c896ea729), `br-asupersync-hhlhjv`)
- **NUMA-local arena shard placement** and remote-touch accounting with deterministic locality planner ([`dd7dfdc79`](https://github.com/Dicklesworthstone/asupersync/commit/dd7dfdc79), `br-asupersync-nxd9xm`)
- **NUMA-aware worker cohorts** + local-first stealing (`br-asupersync-3ld2ri`)
- **Cohort-aware admission steering** and remote-spill budget (`br-asupersync-j1980r`)
- **Tail-risk-aware admission control** for overload periods (`br-asupersync-g0aumf`)
- **Overload brownout mode** for optional runtime surfaces, with OTLP trace shedding folded into the brownout-aware observability policy ([`717395913`](https://github.com/Dicklesworthstone/asupersync/commit/717395913), [`75afc4dac`](https://github.com/Dicklesworthstone/asupersync/commit/75afc4dac), [`bc2252817`](https://github.com/Dicklesworthstone/asupersync/commit/bc2252817), `br-asupersync-m1k0pz`, `xnqgmd`, `d87ytw.8`)
- **Read-biased snapshot substrate** for governor and observability hot paths (`br-asupersync-l0q0rs`)
- **Bounded-load distributed routing** for hot-node avoidance (`br-asupersync-lgj5tz`)
- **Contention-adaptive combiner path** for injection hot spots (`br-asupersync-g0kwgh`)
- **Self-tuning trace storage profiles** for 256GiB-class hosts (`br-asupersync-yaj7g6`, `d87ytw.9`)
- **Wake-to-run telemetry** + offline autotuner feedback loop and scheduler evidence artifact schema (`br-asupersync-99if94`, `1l8m9y`)
- **Controller interference matrix** + timescale-separation proof harness; **controller interference digital twin** (`br-asupersync-b4guhs`, `d87ytw.6`)
- **Controller snapshot ledger** for adaptive swarm policies; **controller provenance dashboard** ([`8ac2cc60a`](https://github.com/Dicklesworthstone/asupersync/commit/8ac2cc60a), `br-asupersync-ccgxc3`, `d87ytw.14`)
- **Live tail-causal attribution emitters**, **wait-cause remediation reports**, **session-typed hot-path obligation proofs**, **NUMA-and-capacity certificate merger**, **rch proof-queue workload feedback** (`asupersync-d87ytw.5`/`.10`/`.11`/`.12`/`.13`)
- **Final control-loop signoff audit** ([`a829a677f`](https://github.com/Dicklesworthstone/asupersync/commit/a829a677f), `asupersync-d87ytw.15`)
- **Real agent-swarm workload bridge and replay pack** (parent + sub-beads `qn8i0p` and `qn8i0p.1..8`): coordination workload artifact schema, redacted Agent-Mail/Beads/rch collector, runtime workload corpus expansion, lab replay/minimization hooks, capacity/profile planner ingest, privacy/redaction/trust boundary proofs, one-command smoke runner, final signoff
- **Restart-budget metamorphic oracle** alignment for the supervision storm-monitor regression ([`896e5fcbe`](https://github.com/Dicklesworthstone/asupersync/commit/896e5fcbe), [`95f93ee33`](https://github.com/Dicklesworthstone/asupersync/commit/95f93ee33), `br-asupersync-ta56mp`, `4a3ghz`)
- **Unified capability evidence registry** + proof manifest ([`68b1127cc`](https://github.com/Dicklesworthstone/asupersync/commit/68b1127cc), `br-asupersync-6qju7t`)

The program also added **22+ smoke-artifact lanes** with paired
`scripts/run_*_smoke.sh` runners and `tests/*_contract.rs`
integration tests pinning each lane to deterministic invariants:
adaptive-batch-sizing, blocking-pool-affinity, capacity-envelope-planner,
cohort-admission-steering, compile-frontier-movement,
decision-plane-validation, governor-state-snapshot,
host-profile-planner, hot-cold-arena-tiers,
jetstream-publish-backpressure, massive-swarm-signoff,
numa-arena-locality, otlp-audit-inventory, otlp-brownout-shedding,
overload-brownout, read-biased-region-snapshot,
resource-monitor-platform-gap, runtime-capacity-hints,
signed-profile-bundle, tail-risk-admission, task-record-pool,
trace-storage-profile. Smoke-artifact roots are gitignored by
contract ([`4874ddca9`](https://github.com/Dicklesworthstone/asupersync/commit/4874ddca9), `br-asupersync-9o35bs`).

### Mock-Code-Finder sweep

178 commits prefixed `[mock-code-finder][...]` and 70+ matching closed
beads. The campaign systematically removed broad clippy `#[allow(...)]`
suppressions and replaced placeholder/mock implementations with real
behavior across the repo. Top-touched subsystems: WASM (33 commits),
HTTP/2 (14), HTTP/3 (8), tokio compat, sync, scheduler, combinator,
otel/diagnostics/oracle, pool, lab-live, contract, websocket, trace,
time, recovery, raptorq, quic, notify, lab, kernel, kafka, doctor,
codec, channel, cancel, broadcast, frankenlab, refinement,
leak-checker, gen-server, gf256, golden, type, region, mutex, h1,
hpack, redis, fabric, rate-limit, fs/process/signal,
runtime/control-seam, rwlock, snapshot, semantic-risk.

Real production gaps closed under that banner included:

- **Kafka silent message loss when the `kafka` feature was off** —
  `KafkaProducer::send` was writing to a stub broker on production
  builds without `kafka` (which is not a default feature). Closed as
  CRITICAL.
- **HTTP/2 GOAWAY / PRIORITY / PING / PUSH_PROMISE / DATA END_STREAM
  conformance simulations** replaced with real state-machine and
  SETTINGS-driven assertions; **ENABLE_PUSH** wired to real
  `PUSH_PROMISE` behavior.
- **OTEL placeholders** replaced with real snapshots: histogram /
  metric aggregator extraction, resource / log severity / trace+span
  ID / batching simulations, W3C baggage HTTP extraction and
  injection, tail-based sampling scope, span-semantics success rate.
- **PostgreSQL real `COPY FROM` client API** + protocol state machine
  ([`fabea56fc`](https://github.com/Dicklesworthstone/asupersync/commit/fabea56fc) and related).
- **HTTP/1.1 RFC 9112 request-target validation** suite — six tests
  that previously passed vacuously when codec validation was missing.
- **RaptorQ differential** scaffolding that compared against
  hardcoded `Ok(vec![0x42; 1024])` mocks, plus the Gaussian
  elimination test placeholder, replaced with real round-trip and
  spec-derived assertions.
- **Storm-monitor** default-alignment regression fixed ([`95f93ee33`](https://github.com/Dicklesworthstone/asupersync/commit/95f93ee33)).
- **HTTP/3 conformance harness re-enabled** with 29 sub-suites and
  `static-mut` state replaced with `OnceLock<Mutex>` ([`73d7f63ce`](https://github.com/Dicklesworthstone/asupersync/commit/73d7f63ce)).
- **Hardcoded H3 mock implementations** replaced with real
  functionality ([`1bbfc2168`](https://github.com/Dicklesworthstone/asupersync/commit/1bbfc2168), `br-asupersync-bs9nbz`).

### Concurrency correctness

Real production bugs uncovered while landing the swarm-v2 program:

- **`src/channel/mpsc.rs`** — `try_send` was returning `Full` whenever
  *any* waiter was queued, even with available capacity (`bd
  asupersync-m02s6r`). Reverted to a true capacity check.
- **`src/channel/mpsc.rs`** — `SendPermit::send` was dropping the
  failure mode silently on disconnect; rewrote to surface via
  `Outcome` ([`b75a998f5`](https://github.com/Dicklesworthstone/asupersync/commit/b75a998f5), `br-asupersync-l7t66t`).
- **`src/channel/watch.rs`** — `send_modify` deadlocked because the
  user closure ran under the write lock; closure now executes outside
  the lock window ([`3a6ad1ea8`](https://github.com/Dicklesworthstone/asupersync/commit/3a6ad1ea8), `br-asupersync-0x7fdb`).
- **`src/runtime/io_driver.rs`** — `on_event` callbacks could deadlock
  against the driver's own state lock; ordering fixed ([`99043ae8e`](https://github.com/Dicklesworthstone/asupersync/commit/99043ae8e)).
- **`src/lab/runtime.rs`** — lock-ordering inversion repaired by
  hoisting `cx_inner.read()` out of the `scheduler.lock()` scope
  ([`dc69ed4e8`](https://github.com/Dicklesworthstone/asupersync/commit/dc69ed4e8), `br-asupersync-iwqn3q`).
- **`src/runtime/scheduler/three_lane.rs`** — the steal path was
  evicting tasks whose arena records had been concurrently removed;
  changed to preserve, then steal, then update accounting ([`df763583c`](https://github.com/Dicklesworthstone/asupersync/commit/df763583c), [`dc7123c78`](https://github.com/Dicklesworthstone/asupersync/commit/dc7123c78), `br-asupersync-uguhr2`).
- **`src/runtime/state.rs`** — region close not waking *all* waiters;
  fixed to broadcast ([`f257fd1c4`](https://github.com/Dicklesworthstone/asupersync/commit/f257fd1c4), `asupersync-novvgd`).
- **`src/record/region.rs`** — `IN_REGION_WITH_CALL` panic safety via
  `ReentryGuard` RAII ([`813131f08`](https://github.com/Dicklesworthstone/asupersync/commit/813131f08), `asupersync-b3998e`); `heap_with` /
  `rref_with` reentrant deadlock prevention ([`c5d08813b`](https://github.com/Dicklesworthstone/asupersync/commit/c5d08813b), `asupersync-xtxr28`).
- **`src/runtime/state.rs`** — region epoch advance on obligation
  reservation; obligation pending-counter underflow promoted from
  `debug_assert + saturating_sub` to release-mode panic ([`e3071bc80`](https://github.com/Dicklesworthstone/asupersync/commit/e3071bc80), [`25803feec`](https://github.com/Dicklesworthstone/asupersync/commit/25803feec)).
- **`src/sync/notify.rs`** — `notify_one` waking same waker repeatedly
  via baton drift; corrected baton passing across drop and `notified`
  paths.
- **`src/runtime/scheduler/three_lane.rs`** — `seen_io_tokens` bound
  added so the per-worker scratch set cannot grow without bound across
  long-lived workers ([`3d6bb2104`](https://github.com/Dicklesworthstone/asupersync/commit/3d6bb2104), `br-asupersync-414j0b`).

### HTTP / protocol correctness

- **HTTP/3 QPACK**: enforce max field-section-size ([`2830f0fa4`](https://github.com/Dicklesworthstone/asupersync/commit/2830f0fa4), `asupersync-ifn7kw`); decoded-header count cap for DoS protection ([`fe8dcdc16`](https://github.com/Dicklesworthstone/asupersync/commit/fe8dcdc16), `asupersync-9bvfe5`); dynamic-table base-relative indexing fixed ([`5159c0758`](https://github.com/Dicklesworthstone/asupersync/commit/5159c0758), [`5c77c9340`](https://github.com/Dicklesworthstone/asupersync/commit/5c77c9340), [`e565f9252`](https://github.com/Dicklesworthstone/asupersync/commit/e565f9252)); QPACK documented as static-only and the runtime status reconciled across README tables ([`4ead428b5`](https://github.com/Dicklesworthstone/asupersync/commit/4ead428b5), [`15da98895`](https://github.com/Dicklesworthstone/asupersync/commit/15da98895)).
- **HTTP/3 frame**: varint encoding fixed ([`b61b51396`](https://github.com/Dicklesworthstone/asupersync/commit/b61b51396), [`4a1ebb6aa`](https://github.com/Dicklesworthstone/asupersync/commit/4a1ebb6aa), `br-asupersync-e48gp6`); 29-sub-suite RFC 9114 conformance harness re-enabled ([`73d7f63ce`](https://github.com/Dicklesworthstone/asupersync/commit/73d7f63ce)); `H3UniStreamType::decode` widened to `pub` ([`5fafb3fff`](https://github.com/Dicklesworthstone/asupersync/commit/5fafb3fff)).
- **HTTP/1.1 codec**: forbidden trailers per RFC 9110 §6.5.1 rejected ([`4c3a2cdca`](https://github.com/Dicklesworthstone/asupersync/commit/4c3a2cdca), `br-asupersync-135g0e`); leading-sign in Content-Length and chunk-size rejected ([`52eac7c26`](https://github.com/Dicklesworthstone/asupersync/commit/52eac7c26)); bare-CR scan bound to head region ([`322a1df11`](https://github.com/Dicklesworthstone/asupersync/commit/322a1df11), `br-asupersync-2ovm8z`).
- **HTTP/2 stream**: `StreamStore::ensure_slot` gap capped to prevent memory-DoS ([`db46975e5`](https://github.com/Dicklesworthstone/asupersync/commit/db46975e5), `br-asupersync-jq82r4`); HTTP/2 SETTINGS frame differential test vs `h2` reference ([`4c0048590`](https://github.com/Dicklesworthstone/asupersync/commit/4c0048590)); H2 stream conformance coverage tightened ([`6d13b2151`](https://github.com/Dicklesworthstone/asupersync/commit/6d13b2151), `br-asupersync-h8pga6`).
- **HPACK**: O(1) `DynamicTable` find via side-index ([`46b2d1646`](https://github.com/Dicklesworthstone/asupersync/commit/46b2d1646), `br-asupersync-4pshog`); `Arc<str>` dynamic-table entries plus 4-bit-stride Huffman state table ([`8e3353e44`](https://github.com/Dicklesworthstone/asupersync/commit/8e3353e44)); UTF-8-validate-on-borrow + wasted-clone cleanup ([`e32fd747a`](https://github.com/Dicklesworthstone/asupersync/commit/e32fd747a)); HPACK golden vectors landed ([`c0c07ae6a`](https://github.com/Dicklesworthstone/asupersync/commit/c0c07ae6a)).
- **WebSocket**: receive `Cx` threaded through read-refill polling so cancellation interrupts before transport bytes are consumed ([`192e41654`](https://github.com/Dicklesworthstone/asupersync/commit/192e41654)); frame encoder close-payload validation ([`f553cfcc9`](https://github.com/Dicklesworthstone/asupersync/commit/f553cfcc9), `asupersync-xc1r82`); wire-byte golden snapshot ([`696b2caa3`](https://github.com/Dicklesworthstone/asupersync/commit/696b2caa3)); trailing-bytes mock-code suppressions removed ([`636f94e13`](https://github.com/Dicklesworthstone/asupersync/commit/636f94e13)).
- **gRPC**: trailer timeout harness repaired ([`adc594f26`](https://github.com/Dicklesworthstone/asupersync/commit/adc594f26)); transport timeouts mapped to `DEADLINE_EXCEEDED` ([`b5729089a`](https://github.com/Dicklesworthstone/asupersync/commit/b5729089a), `br-asupersync-p8rju5`); conformance modules revived for grpc_deadline / grpc_health / grpc_status ([`6704791c4`](https://github.com/Dicklesworthstone/asupersync/commit/6704791c4), [`54970da04`](https://github.com/Dicklesworthstone/asupersync/commit/54970da04), `br-asupersync-pfvsch`); initial-window backpressure differential vs grpc-go ([`809e09080`](https://github.com/Dicklesworthstone/asupersync/commit/809e09080)).
- **TLS**: `--features tls -D warnings` cleared ([`a78f535a0`](https://github.com/Dicklesworthstone/asupersync/commit/a78f535a0), `br-asupersync-s0nwli`); ClientHello harness hardened ([`6a8f21a01`](https://github.com/Dicklesworthstone/asupersync/commit/6a8f21a01), `br-asupersync-cuyzmt`); record_conformance post-handshake plaintext-injection cases inverted with `u16::try_from` and tautological asserts replaced ([`9c061e13f`](https://github.com/Dicklesworthstone/asupersync/commit/9c061e13f), [`f222ed94f`](https://github.com/Dicklesworthstone/asupersync/commit/f222ed94f), [`5da6a1632`](https://github.com/Dicklesworthstone/asupersync/commit/5da6a1632)); cryptographic boundary test module ([`aced1f44e`](https://github.com/Dicklesworthstone/asupersync/commit/aced1f44e), `br-asupersync-9fjvs3`); cert-pinning fuzzer ([`2c87c7d1b`](https://github.com/Dicklesworthstone/asupersync/commit/2c87c7d1b), `br-asupersync-t374gm`).
- **DNS**: reject CNAME / MX / SRV RDATA with trailing bytes after the embedded DNS name ([`981b595be`](https://github.com/Dicklesworthstone/asupersync/commit/981b595be)); golden encoder include_bytes paths corrected ([`78eaad0ce`](https://github.com/Dicklesworthstone/asupersync/commit/78eaad0ce), `br-asupersync-knpltd`).
- **Web layer**: compression honors `identity;q=0`; ETags content-derived; error rewrites strip stale headers; health JSON includes top-level detail; nextjs bootstrap invalidates runtime scope on failure ([`676707e1e`](https://github.com/Dicklesworthstone/asupersync/commit/676707e1e)).
- **QUIC**: native QUIC RFC 9000 conformance test suite ([`f1d99ac9d`](https://github.com/Dicklesworthstone/asupersync/commit/f1d99ac9d), `br-asupersync-3mgtqf`); H3 varint frame fuzzer ([`98976fdd1`](https://github.com/Dicklesworthstone/asupersync/commit/98976fdd1), `br-asupersync-0eas0f`); tls_conformance_harness `arb_crypto_sequence` repair ([`3b4c99784`](https://github.com/Dicklesworthstone/asupersync/commit/3b4c99784), `br-asupersync-0pfh9h`).

### Database and messaging

- **MySQL** wire-protocol conformance test suite ([`c2f02422e`](https://github.com/Dicklesworthstone/asupersync/commit/c2f02422e), `asupersync-jysouz`); MariaDB OK_Packet status flags differential ([`c421dfd86`](https://github.com/Dicklesworthstone/asupersync/commit/c421dfd86)); `ResultSet` structure-aware fuzzer ([`b6f10c40a`](https://github.com/Dicklesworthstone/asupersync/commit/b6f10c40a)); MySQL row-stream clippy frontier cleared and explicit `AuthSwitch` coverage timed ([`234fc871a`](https://github.com/Dicklesworthstone/asupersync/commit/234fc871a), [`1cbc303e7`](https://github.com/Dicklesworthstone/asupersync/commit/1cbc303e7), `br-asupersync-m84ex4`, `f9o478`).
- **PostgreSQL** wire parser seam hardening ([`5e9532a44`](https://github.com/Dicklesworthstone/asupersync/commit/5e9532a44)); `CopyData` / `CopyDone` wire format differential conformance ([`eb3d2a164`](https://github.com/Dicklesworthstone/asupersync/commit/eb3d2a164)); real `COPY FROM` client API + extended-query / logical-replication coverage.
- **Database pool** real-server URL safety gates ([`6a7499ff0`](https://github.com/Dicklesworthstone/asupersync/commit/6a7499ff0)); E2E pool-reconnection integration test ([`cc5cdd286`](https://github.com/Dicklesworthstone/asupersync/commit/cc5cdd286), `asupersync-na35bj`).
- **Kafka**: real-broker test harness fix ([`31287df27`](https://github.com/Dicklesworthstone/asupersync/commit/31287df27), `br-asupersync-ygotyp`); committed offsets retained across resubscribe ([`f97d2eaa0`](https://github.com/Dicklesworthstone/asupersync/commit/f97d2eaa0)); compile-blocker rebalance test API repaired ([`c12c415a1`](https://github.com/Dicklesworthstone/asupersync/commit/c12c415a1), `br-asupersync-b0irdm`); `ProduceResponse` parser fuzzer ([`3af44c682`](https://github.com/Dicklesworthstone/asupersync/commit/3af44c682)); record-batch integration repaired ([`fabea56fc`](https://github.com/Dicklesworthstone/asupersync/commit/fabea56fc)).
- **Redis**: RESP3 Push frames accepted in `RedisPubSub::parse_event` ([`8228cf70f`](https://github.com/Dicklesworthstone/asupersync/commit/8228cf70f)); RESP3 SUBSCRIBE pattern routing differential vs `redis-rs` ([`0256200bc`](https://github.com/Dicklesworthstone/asupersync/commit/0256200bc)); RESP3 buffering and `RESP3 pubsub` decoder structure-aware fuzzer ([`25c72e989`](https://github.com/Dicklesworthstone/asupersync/commit/25c72e989), [`e7a705c01`](https://github.com/Dicklesworthstone/asupersync/commit/e7a705c01)).
- **JetStream**: `ConsumerInfo`, `StreamInfo`, `PullSubscribeOpts`, API-response, error-response, and publish-backpressure structure-aware fuzzers ([`db038ab3f`](https://github.com/Dicklesworthstone/asupersync/commit/db038ab3f), [`5ae936ea4`](https://github.com/Dicklesworthstone/asupersync/commit/5ae936ea4), [`cabb82adc`](https://github.com/Dicklesworthstone/asupersync/commit/cabb82adc), [`7cfa88d8b`](https://github.com/Dicklesworthstone/asupersync/commit/7cfa88d8b)).
- **SQLite**: `PRAGMA` serialization structure-aware fuzzer ([`85975767d`](https://github.com/Dicklesworthstone/asupersync/commit/85975767d)).

### RaptorQ erasure coding

- **RFC 6330 LtTuple expansion** inlined into `repair_symbol_into` ([`e4e7e7e0a`](https://github.com/Dicklesworthstone/asupersync/commit/e4e7e7e0a)); FEC-Payload-ID emission benchmark ([`43adfe0b8`](https://github.com/Dicklesworthstone/asupersync/commit/43adfe0b8)).
- **Decode rejects overflowed repair ESIs** instead of panicking in `decode_block` ([`br-asupersync-fm6ys2`](https://github.com/Dicklesworthstone/asupersync/commit/7ba972514), regression test included).
- **GF(256) SIMD vs scalar-reference equivalence fuzzer** ([`4982c3c93`](https://github.com/Dicklesworthstone/asupersync/commit/4982c3c93), `br-asupersync-uc6d7d`).
- **Canonical encode / decode round-trip golden snapshot** ([`894629272`](https://github.com/Dicklesworthstone/asupersync/commit/894629272), `br-asupersync-c12bcb`); RFC 6330 §6 high-loss recovery differential test ([`4aa26704c`](https://github.com/Dicklesworthstone/asupersync/commit/4aa26704c)); RFC 6330 §6 encode-decode round-trip differential ([`7a8c67d35`](https://github.com/Dicklesworthstone/asupersync/commit/7a8c67d35)).
- **Decoder progressive-symbol-arrival cancel-storm fuzzer** ([`1dbb986e4`](https://github.com/Dicklesworthstone/asupersync/commit/1dbb986e4)); decoder symbol-corruption fuzzer ([`324bfe08d`](https://github.com/Dicklesworthstone/asupersync/commit/324bfe08d)); `N_max` boundary fuzzer ([`cff637262`](https://github.com/Dicklesworthstone/asupersync/commit/cff637262)); decoding pipeline `feed()` structure-aware target ([`a6567e0a5`](https://github.com/Dicklesworthstone/asupersync/commit/a6567e0a5)); multi-block coverage ([`8d3d2157a`](https://github.com/Dicklesworthstone/asupersync/commit/8d3d2157a), `br-asupersync-lc0anl`).

### Runtime performance

A continuous-improvement pass; many fixes are bead-traced. Highlights:

- **MPSC O(N) → O(1) slab-based lookups** ([`0ae255739`](https://github.com/Dicklesworthstone/asupersync/commit/0ae255739)); MPSC `try_send` single-lock fast path ([`cdb033b3c`](https://github.com/Dicklesworthstone/asupersync/commit/cdb033b3c), `br-lej99f`); MPSC waiter scans removed.
- **Mutex** O(1) waiter cleanup via slab-backed intrusive linked list ([`f49630a8e`](https://github.com/Dicklesworthstone/asupersync/commit/f49630a8e), `br-asupersync-wlf0xh`, `vgw2yw`).
- **Semaphore** waiter scans removed ([`321132d36`](https://github.com/Dicklesworthstone/asupersync/commit/321132d36), `br-asupersync-8qlc7a`); static description on hot path ([`31b85ecb9`](https://github.com/Dicklesworthstone/asupersync/commit/31b85ecb9)).
- **Three-lane scheduler** `next_task` hot dispatch lock acquisitions optimized; `self.local.lock()` coalesced in next_task hot path ([`f2f2484a5`](https://github.com/Dicklesworthstone/asupersync/commit/f2f2484a5), [`82c0f8a1d`](https://github.com/Dicklesworthstone/asupersync/commit/82c0f8a1d), `br-asupersync-fvixmw`).
- **Local queue** O(1) dedup `HashSet` + lock-free `cached_len` atomic ([`4a14e7844`](https://github.com/Dicklesworthstone/asupersync/commit/4a14e7844), `br-asupersync-5oll2p`, `pvbwxm`).
- **TaskRecord object pool** eliminating ~35% allocation hot-spots ([`579894f8e`](https://github.com/Dicklesworthstone/asupersync/commit/579894f8e)).
- **Transport router** hot-path alloc removal + `DispatchResult` inline capacity ([`c26ee7fb5`](https://github.com/Dicklesworthstone/asupersync/commit/c26ee7fb5), `br-asupersync-klff8q`, `dv32fs`); hash-based `select_n` with consistent hashing ([`71f868f0a`](https://github.com/Dicklesworthstone/asupersync/commit/71f868f0a)).
- **OTLP trace exporter** lock-free `ArrayQueue` ([`3e6a436da`](https://github.com/Dicklesworthstone/asupersync/commit/3e6a436da), [`e2cc810c3`](https://github.com/Dicklesworthstone/asupersync/commit/e2cc810c3)).
- **Distributed assignment** O(K²) `Vec::contains` → O(K log K) `BTreeSet` ([`9a5dfd056`](https://github.com/Dicklesworthstone/asupersync/commit/9a5dfd056), `br-asupersync-45xcbm`).
- **Lyapunov governor** O(1) snapshot via incremental obligation counters ([`adadea72a`](https://github.com/Dicklesworthstone/asupersync/commit/adadea72a), [`f844f5555`](https://github.com/Dicklesworthstone/asupersync/commit/f844f5555), `br-asupersync-xxcss5`).
- **`Cx`** fast-cancel atomic check before write-lock in `checkpoint` ([`2f62175c0`](https://github.com/Dicklesworthstone/asupersync/commit/2f62175c0), `br-is2xg0`); hot-path `Cx::current().is_some*()` migrated to zero-Arc-clone helpers ([`b18f6d3b8`](https://github.com/Dicklesworthstone/asupersync/commit/b18f6d3b8), `br-asupersync-xqt7dj`); `cx/registry` `format!` removed from hot reservation path ([`570d755ec`](https://github.com/Dicklesworthstone/asupersync/commit/570d755ec)).
- **`time::wheel`** redundant `current_time()` call eliminated in `register` path ([`505b91af3`](https://github.com/Dicklesworthstone/asupersync/commit/505b91af3), [`33e34c78c`](https://github.com/Dicklesworthstone/asupersync/commit/33e34c78c), `br-asupersync-ifq7c5`).
- **`runtime/state`** `live_task_count` delegated to `TaskTable`'s O(1) phase-counts sum ([`0ba45c264`](https://github.com/Dicklesworthstone/asupersync/commit/0ba45c264), `br-afv6z4`).
- **`scheduler/worker`** `seen_io_tokens` bounded + cache-waker amortization ([`3d6bb2104`](https://github.com/Dicklesworthstone/asupersync/commit/3d6bb2104), `br-asupersync-414j0b`, `jkb17z`).
- **`observability/cancellation_debt_monitor`** parking_lot + bounded pending map ([`ecbb95c85`](https://github.com/Dicklesworthstone/asupersync/commit/ecbb95c85), `br-asupersync-37sffr`, `i40ap4`).
- **`panic_isolation`** `PANIC_COUNTER` `fetch_add` SeqCst → Relaxed ([`88850ba3e`](https://github.com/Dicklesworthstone/asupersync/commit/88850ba3e), `br-asupersync-h0pfb4`).
- **Hot-path Vec storage** migrated to `SmallVec` inline buffers across runtime ([`8fc1e0d38`](https://github.com/Dicklesworthstone/asupersync/commit/8fc1e0d38)).
- **Arena pre-sizing** optimization ([`9c5183f42`](https://github.com/Dicklesworthstone/asupersync/commit/9c5183f42), `br-asupersync-y4lcl9`).
- **gRPC codec** zero-copy identity frame + sized-Vec gzip ([`d3841aa5c`](https://github.com/Dicklesworthstone/asupersync/commit/d3841aa5c)); H1 zero-copy body via `BytesMut::into_vec` ([`482935ac4`](https://github.com/Dicklesworthstone/asupersync/commit/482935ac4)); H2 stream `StreamStore` flat-Vec replaces `DetHashMap` on hot path ([`eb26cfa67`](https://github.com/Dicklesworthstone/asupersync/commit/eb26cfa67)).

### Test infrastructure expansion

- **165 `feat:` commits, 90+ structure-aware fuzz targets** added across H1, H2, H3, RaptorQ, JetStream, Kafka, Redis, MySQL, SQLite, codecs, intrusive heap, macaroon attenuation, finalizer stack, and task-cancel witness serialization.
- **Differential conformance suites**: HTTP/2 SETTINGS frame vs `h2`; `LengthDelimitedCodec`; gRPC initial-window backpressure vs `grpc-go`; PostgreSQL `CopyData` / `CopyDone`; RESP3 SUBSCRIBE pattern vs `redis-rs`; MySQL vs MariaDB OK_Packet; Bytes shared-slice semantics ([`32b3c56fc`](https://github.com/Dicklesworthstone/asupersync/commit/32b3c56fc), `br-asupersync-6uckg1`); RFC 6330 §6 RaptorQ.
- **Golden snapshot suites**: Plan IR rewrites ([`0a37eb422`](https://github.com/Dicklesworthstone/asupersync/commit/0a37eb422), `br-asupersync-8tajyi`); Plan DAG rewrite-rule ([`0e6066426`](https://github.com/Dicklesworthstone/asupersync/commit/0e6066426)); HPACK ([`c0c07ae6a`](https://github.com/Dicklesworthstone/asupersync/commit/c0c07ae6a), `br-asupersync-l432ti`); WebSocket wire-byte ([`696b2caa3`](https://github.com/Dicklesworthstone/asupersync/commit/696b2caa3), `br-asupersync-z95cah`); trace canonicalizer Foata normal form ([`14fa0df4b`](https://github.com/Dicklesworthstone/asupersync/commit/14fa0df4b)); trace event serialization ([`a5258618c`](https://github.com/Dicklesworthstone/asupersync/commit/a5258618c), `br-asupersync-la3t6w`); h1 request-line + h2 control-frame goldens ([`504ae1fe6`](https://github.com/Dicklesworthstone/asupersync/commit/504ae1fe6)); Plan DAG / analysis / certificate insta baselines ([`e66cf1c97`](https://github.com/Dicklesworthstone/asupersync/commit/e66cf1c97)); obligation ledger goldens ([`e56cdfe69`](https://github.com/Dicklesworthstone/asupersync/commit/e56cdfe69), `asupersync-a2tueg`); symbol_cancel protocol lifecycle golden ([`f00395737`](https://github.com/Dicklesworthstone/asupersync/commit/f00395737)).
- **Metamorphic suites**: `OnceCell` init-then-get equivalence ([`4eb5b01b3`](https://github.com/Dicklesworthstone/asupersync/commit/4eb5b01b3)); three-lane scheduler priority-promotion idempotence ([`e9875ffce`](https://github.com/Dicklesworthstone/asupersync/commit/e9875ffce)); semaphore fairness and cancel-release invariants ([`249093cbe`](https://github.com/Dicklesworthstone/asupersync/commit/249093cbe), `br-asupersync-668nd3`); MPSC FIFO ([`99e3eead4`](https://github.com/Dicklesworthstone/asupersync/commit/99e3eead4)); broadcast MR3 dropped-receiver recovery range pinned to actual sent values ([`9a83b6d44`](https://github.com/Dicklesworthstone/asupersync/commit/9a83b6d44), `br-asupersync-w7g55u`).
- **Cryptographic boundary tests** module ([`aced1f44e`](https://github.com/Dicklesworthstone/asupersync/commit/aced1f44e), `br-asupersync-9fjvs3`).
- **Bytes** shared-slice conformance suite ([`32b3c56fc`](https://github.com/Dicklesworthstone/asupersync/commit/32b3c56fc), `br-asupersync-6uckg1`).
- **HPACK RFC 7541 edge-case + adversarial decoder fuzz targets** ([`5571df6c1`](https://github.com/Dicklesworthstone/asupersync/commit/5571df6c1)).

### Refactoring and code quality

A 2026-04-25 sweep centralized constructor and default behavior across
the runtime, transport, codec, lab, observability, plan, RaptorQ, and
HTTP subsystems via `derive Default` / shared constructor helpers /
test-setup helper reuse. Representative commits: scheduler default
delegations ([`8e5e98783`](https://github.com/Dicklesworthstone/asupersync/commit/8e5e98783), [`ac5dba397`](https://github.com/Dicklesworthstone/asupersync/commit/ac5dba397), [`326685465`](https://github.com/Dicklesworthstone/asupersync/commit/326685465), [`1ecafa20d`](https://github.com/Dicklesworthstone/asupersync/commit/1ecafa20d)), HPACK default
constructors ([`c23a26b5a`](https://github.com/Dicklesworthstone/asupersync/commit/c23a26b5a)), gRPC web frame default ([`6facb4e79`](https://github.com/Dicklesworthstone/asupersync/commit/6facb4e79)), TLS empty
constructors ([`43baf627a`](https://github.com/Dicklesworthstone/asupersync/commit/43baf627a)), CRDT counter constructors ([`0d852e83b`](https://github.com/Dicklesworthstone/asupersync/commit/0d852e83b)),
Lamport clock default ([`b5a0b9e82`](https://github.com/Dicklesworthstone/asupersync/commit/b5a0b9e82)), Conformal calibration defaults
([`366ab1ab1`](https://github.com/Dicklesworthstone/asupersync/commit/366ab1ab1)).

### Observability

- **Cancellation visualizer** namespaced DOT node IDs per trace, escaped labels, overflow-safe duration averages, real throughput accumulator ([`711c97178`](https://github.com/Dicklesworthstone/asupersync/commit/711c97178)).
- **Cancellation analyzer** bottleneck threshold compares fractions instead of percentage points; preserves zero-throughput samples; insufficient-data on empty input ([`edd1f81cc`](https://github.com/Dicklesworthstone/asupersync/commit/edd1f81cc)).
- **`panic_isolation`** runtime lifecycle instrumentation in `CapturingMetrics` ([`bb3afb75f`](https://github.com/Dicklesworthstone/asupersync/commit/bb3afb75f)).
- **OTEL** placeholder histograms / metric aggregator extraction / W3C baggage HTTP extraction / tail-based sampling scope all replaced with real implementations under the mock-code-finder banner.

### Documentation and repository hygiene

A 2026-05-05 cleanup sweep:

- Root `.md` planning / analysis / fuzz-companion / per-subsystem audit files relocated under `docs/{plans,analysis,fuzz,audits}/` ([`56b3de9aa`](https://github.com/Dicklesworthstone/asupersync/commit/56b3de9aa), [`33b6c7ac6`](https://github.com/Dicklesworthstone/asupersync/commit/33b6c7ac6), [`79d5f5139`](https://github.com/Dicklesworthstone/asupersync/commit/79d5f5139), [`800c8a2a9`](https://github.com/Dicklesworthstone/asupersync/commit/800c8a2a9), [`e82f1ee76`](https://github.com/Dicklesworthstone/asupersync/commit/e82f1ee76)).
- Raw modes-of-reasoning per-mode swarm outputs removed ([`a5f3d5692`](https://github.com/Dicklesworthstone/asupersync/commit/a5f3d5692)); tracked ephemeral scan / fix-script / test-binary detritus removed ([`e04a0e708`](https://github.com/Dicklesworthstone/asupersync/commit/e04a0e708)).
- `.gitignore` expanded for root scratch and smoke-artifact accumulation ([`d31e2515a`](https://github.com/Dicklesworthstone/asupersync/commit/d31e2515a), [`4874ddca9`](https://github.com/Dicklesworthstone/asupersync/commit/4874ddca9)).
- Phase 6 reality check added ([`0f192ae63`](https://github.com/Dicklesworthstone/asupersync/commit/0f192ae63), `br-asupersync-ao9m8l`); HTTP/3 implementation status aligned across all README tables ([`15da98895`](https://github.com/Dicklesworthstone/asupersync/commit/15da98895), [`9a577aa7a`](https://github.com/Dicklesworthstone/asupersync/commit/9a577aa7a)).

### Audit campaign

The fresh-eyes / bug-audit campaign continued. Apr-24 / Apr-25 batches
recorded multiple SOUND verdicts, including the cryptographic boundary
test module ([`6d6009c17`](https://github.com/Dicklesworthstone/asupersync/commit/6d6009c17)), lab-network and lab-meta runners
([`3549ad058`](https://github.com/Dicklesworthstone/asupersync/commit/3549ad058)), and the smallvec optimization pass ([`6a28e1a48`](https://github.com/Dicklesworthstone/asupersync/commit/6a28e1a48), `br-asupersync-ms7qud`). The audit index ledger now exceeds 1450 records.

### Beads / workstream evidence

1,726 beads closed since v0.3.1. Beyond the swarm-v2 program above:

- **`asupersync-d87ytw` (parent epic)** + sub-beads `.1`–`.15` — autonomic live control loop and proof certificates (closed 2026-05-05).
- **`asupersync-qn8i0p` (parent)** + sub-beads `.1`–`.8` — real coordination-workload bridge and replay pack.
- **`asupersync-6qju7t`** — unified capability evidence registry and proof manifest.
- **`asupersync-j1dwk6`** — 64-core / 256GiB massive-swarm capacity envelope proof.
- **`asupersync-ul9jhr`** — massive-swarm responsiveness program.
- **`asupersync-wqsael`** — final massive-swarm signoff matrix and operator evidence audit.
- Workstream-specific cleanups: `m84ex4` (mysql clippy), `mmddg3` (runtime config clippy), `pfweja` (three_lane clippy), `vdhei0` (blocking_pool clippy), `xmp8am` (low-risk clippy frontier), `ikol9e` (W3C trace-context generalization), `jm7y3y` (`OnceCell` future_not_send policy), `9o35bs` (smoke-artifact gitignore contract), `5005zl` (E2E conformance helper compile bead).

### Verification

- `cargo check --workspace --all-targets` continues to pass.
- The lib-test frontier work (`br-asupersync-0b0fxk`, `d367a0`,
  `dhrd5p`, `ejzzih`, `hxk1pe`, `i1vce6`, `nuday6`, `oim3yn`, `wfbfg3`,
  `zb9g03`) repaired the residual cross-surface compile drift that
  blocked scheduler / observability / shared-main proof paths under
  `--features test-internals -D warnings`.
- The 22+ `tests/*_smoke_contract.rs` contract tests pin
  reality-check Wave 2 invariants; their generated artifacts live
  under hidden `.<name>-smoke-artifacts/` roots and are gitignored by
  contract.

---

## [v0.3.1](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.3.1) -- 2026-04-21 (Release)

> Hours after v0.3.0 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.3.0...v0.3.1)

### Release theme

Patch release carrying the output of a deep-dive post-v0.3.0 test-suite
hardening pass: **25 real production-code bugs fixed** (most of them
pre-existing, surfaced by the recently-expanded metamorphic test
suite), plus a large batch of test-harness drift fixes that unblock
the library's `cargo test --workspace --lib` path.

### Production bugs fixed

Concurrency correctness (highest severity):

- **`src/runtime/reactor/epoll.rs`** — SIGABRT `IO Safety violation: owned file descriptor already closed`. The test `modify_failure_preserves_bookkeeping_when_poller_fd_closed` was calling `libc::close(poller_fd)` on a descriptor still owned by `Poller::epoll_fd: OwnedFd`. Under parallel `cargo test --workspace --lib` (~200 threads), any concurrent fd allocation could grab that freed number and wrap it in its own `OwnedFd`; the test's subsequent `dup2(saved_poller_fd, poller_fd)` would then silently close the foreign owner's fd, and rust-std would abort the whole process when that foreign `OwnedFd` dropped. Replaced `libc::close(poller_fd)` with `dup2(replacement_fd, poller_fd)` so `poller_fd` is a continuously-valid descriptor throughout the test.
- **`src/runtime/reactor/epoll.rs`** — also added early `EBADF` rejection for `raw_fd < 0` (otherwise the stdlib `fd != -1` debug assertion trips) and a `ReactorState::orphaned` tombstone set so `deregister` is idempotent after `EBADF`/`ENOENT` reaped bookkeeping in `modify`.
- **`src/observability/runtime_integration.rs`** — parking_lot RwLock self-deadlock in `on_task_cancel_completed` and `on_region_closed`. The pattern `if let Some(x) = self.task_traces.write().remove(&id) { ... self.task_traces.read() ... }` extended the `RwLockWriteGuard`'s lifetime into the `if let` body, where the subsequent `.read()` deadlocked on the same non-reentrant lock. Extracted the `write().remove(...)` into a `let` binding so the write guard drops first.
- **`src/service/discover.rs`** — DNS Condvar coalesce observability (from the deep-dive; already in v0.3.0).
- **`src/runtime/epoch_gc.rs`** — `process_safe_epochs` broke on the first unsafe item in the queue, leaving safe items behind it unreclaimed. `try_advance_and_cleanup` / `force_advance_and_cleanup` passed `new_epoch - 1` as the safe boundary instead of `new_epoch`, so items tagged with the just-retired epoch were never reclaimed.
- **`src/runtime/epoch_tracking.rs`** — `GlobalEpochCounter::try_advance` had "simplified: always try to advance" stubbed in place of the rate limiting the docstring promised. Restored CAS-based rate limiting with a shared Instant origin. `DeferredCleanupQueue::execute_safe_cleanups` used `<=` instead of strict `<` on the safe-epoch comparison — violated the pinning invariant.

HTTP protocol correctness / security:

- **`src/http/h1/codec.rs`** — missing bare-CR scan (RFC 9112 §2.2 request-smuggling vector; accepted `\r` without `\n` in the request head) and no printable-ASCII validation on the request target (raw NUL, SOH, DEL, non-ASCII were accepted). Both closed.
- **`src/http/h3_native.rs`** — RFC 9297 DATAGRAM frame decode treated a truncated payload as a streaming short-read (`UnexpectedEof`) instead of peer misbehavior (`InvalidFrame`). Now emits distinct errors for varint vs payload-length truncation.
- **`src/http/h3_native.rs`** — `can_send_early_data` used `saturating_add` and clamped past `u64::MAX`, silently returning `true` for over-budget 0-RTT sends. Fixed to `checked_add` + treat `None` as over-budget.

WebSocket protocol correctness:

- **`src/net/websocket/handshake.rs::selected_protocol`** — violated RFC 6455 §4.2.2 by iterating the server's list rather than the client's offered order (server is required to honor client preference). Also silently returned `None` instead of `ProtocolMismatch` when client offers did not match a non-empty supported set. Both fixed.

Observability correctness:

- **`src/observability/diagnostics.rs::find_leaked_obligations`** — flagged obligations held by Completed tasks as leaks, producing false positives (Completed holders tear their obligations down via the normal scope-exit path). Now skips Completed holders.
- **`src/observability/obligation_tracker.rs`** — `find_potential_leaks` / `summary()` used strict `>` on age, which made the documented "immediate leak detection" config (`leak_age_threshold = Duration::ZERO`) a no-op. Changed to `>=`.
- **`src/lab/oracle/channel_atomicity.rs`** — same `>` → `>=` contract fix for `max_reservation_age_seconds = 0` meaning "immediate leak detection".

Channel correctness:

- **`src/channel/atomicity_test.rs::CancellationInjector::should_cancel`** — bit-shift bug: `(state >> 16) as f64 / u32::MAX as f64` produced values up to 2^48, so `random < probability` was almost never true for any probability in (0, 1). Masked to u32 after shift; added fast-paths for probability ∈ {0, 1}.
- **`src/channel/broadcast.rs`** — ring-buffer overrun when a single sender burst exceeded capacity. Interleaved drain with send so the fast receiver never falls behind the retention window.

Combinator correctness:

- **`src/combinator/bulkhead.rs`** — utilization boundary off-by-one: metric said "at 80% or above" but assertion used strict `>`. Changed to `>=` (8/10 is exactly representable in f64 and should match).

Cancel / progress-certificate correctness:

- **`src/cancel/progress_certificate.rs`** — `EvidenceEntry.bound` field is contractually a probability (docstring: "upper tail probability") but production was writing raw step magnitudes and run-lengths into it. Downstream verifiers that compared `.bound > 0.05` were generating false "bound not tight" alerts. Fixed all seven construction sites to emit probabilities; moved the metric data to the `.description` string.

RaptorQ correctness:

- **`src/raptorq/systematic.rs::rfc_repair_equation`** — `checked_add(padding_delta).expect(...)` panicked at the `u32::MAX` ESI boundary. RFC 6330 tuple derivation requires deterministic wrapping. Fixed to `wrapping_add`.
- **`src/raptorq/linalg.rs`** — Gaussian solvers preferentially reported `Inconsistent` when both `Singular` and `Inconsistent` conditions were present, obscuring the correct failure classification. Restricted the inconsistency scan to the single pivot-aligned row via a new `first_inconsistent_row_at` helper; downstream contradictions now surface only after full forward elimination.
- **`src/raptorq/decoder.rs::inactivate_and_solve_with_proof`** — recorded inactivations into the elimination trace AFTER fallible validation, so fail-closed paths left the proof trace empty even though the decoder had attempted inactivations. Split intent from commit: trace records unconditionally, state mutations are deferred until validation succeeds.

Plus miscellaneous prod fixes to `obligation::saga::compensation`, `lab::oracle::*` counts/threshold contracts, an `fs::uring` unused-import that was tripping `deny(unused_imports)`, and a `three_lane.rs` missing `let mut`.

### Test-harness hygiene

Most of the 110 originally-failing tests were test drift rather than production bugs — stale golden values, snapshot rotations, API signature drift, ratio/threshold constants that grew past old hardcoded expectations:

- **`tests/metamorphic_region_close_ordering.rs`** — fixed `cancel_order` semantic gap (tests didn't actually trigger cancel).
- **`src/sync/mutex_metamorphic.rs::mr2_cancel_non_poisoning`** — `drop(try_result)` before async relock so the guard doesn't hold the mutex across `block_on`.
- **`src/sync/barrier_metamorphic.rs::execute_barrier_scenario`** — `LabConfig::with_auto_advance()` + `run_with_auto_advance()` so virtual time advances through sleeps.
- Multiple `lab::oracle::*` tests — oracle count constants 17 → 24 as new oracles landed; `fail_fast_mode` return-type handling; seed-agnostic scenarios switched to real seeds.
- **`src/raptorq/rfc6330.rs`** — regenerated `GOLDEN_TUPLE_VECTORS` against a Python reference implementing RFC 6330 §5.3.5 byte-for-byte (the previous constants predated an RFC conformance fix in the production implementation).
- **`src/raptorq/metamorphic_tests.rs`** — switched default test fixture to `symbol_size = 16` with `repair_overhead = 4.0` so fixtures stay within the RFC 6330 K' ≥ 10 requirement.
- **`src/http/h2/frame_golden_tests.rs`** — five hex-literal typos in golden values (extra `f`, raw ASCII vs hex, stray `00` bytes, dropped digit).
- **`src/codec/tests/mod.rs`** — aligned test expectations with actual `BytesCodec` (empty decode returns `None`) and `LinesCodec` (strict `\n` delimiter; UTF-8 validated post-terminator) semantics.
- Various **insta snapshot regenerations** across diagnostics v3 schema, cli/doctor reports, decode-proof certificate, etc. — post-refactor cleanup.

### Known remaining failures

~85 tests in `runtime::scheduler`, `plan::fixtures`, `service::retry`, `supervision`, and misc modules continue to fail. These are tracked for a follow-up release; none block library consumers that don't touch those specific surfaces.

### Verification

- `cargo check --workspace --all-targets` on ts2 via rch: clean (exit 0, ~52s).
- `cargo test --workspace --lib`: **14,257 pass, 86 fail, 0 SIGABRT** (was 9,350 pass + 110 fail + abort in v0.3.0).

---

## [v0.3.0](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.3.0) -- 2026-04-21 (Release)

> 2500+ commits since v0.2.9 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.9...v0.3.0)

### Release theme

`v0.3.0` is the first release cut after a six-week high-throughput
multi-agent work sweep that landed hundreds of metamorphic relations,
golden snapshots, fuzz targets, and conformance fixtures across the
runtime, scheduler, obligation ledger, gRPC/HTTP/DNS stacks, RaptorQ,
FABRIC, and the observability surface. This bundles those additions
with a coordinated dependency refresh and a large compile-and-test
hygiene pass.

### Dependency refresh

Coordinated minor-version bumps against latest crates.io and nightly
1.97.0 (`66da6cae1`, 2026-04-20):

- **digest-0.11 wave:** `sha1` 0.10→0.11, `sha2` 0.10→0.11,
  `hmac` 0.12→0.13 — landed together because they all depend on
  `digest` 0.11.
- `hashbrown` 0.15 → 0.17 (skipped 0.16; MSRV 1.85).
- `rusqlite` 0.38 → 0.39 (bundled SQLite now 3.51.3).
- `lz4_flex` 0.12 → 0.13 across normal-deps and dev-deps.
- `signal-hook` 0.3 → 0.4 (non-wasm only).
- `rayon` 1.11 → 1.12 dev-dep.
- Relaxed `io-uring = "0.7.11"` pin to `"0.7"` so future patch
  bumps land automatically via `cargo update`.
- Additionally, `cargo update` refreshed a wide swath of semver-
  compatible patch versions across the dependency graph
  (clap/hyper/rustls/tokio-in-compat-shim/toml/tokio-macros/
  wasm-bindgen/web-sys/webpki-roots/zerocopy and several others).

Deferred:

- `prost` 0.13 → 0.14 — requires coordinated tonic 0.14 migration
  with the new `tonic-prost` + `tonic-prost-build` crate split and
  `Message` trait signature changes. Tracked for a follow-up.
- `time` 0.3.47 — actively blocked by an intentional pin
  (`>=0.3, <0.3.47`) in root `Cargo.toml`; not touching.

### Coordinated callsite updates

Required by the digest-0.11 wave and the sha2-0.11 `Array<u8, _>`
migration:

- Added `use hmac::KeyInit;` at three call sites
  (`src/cx/macaroon.rs`, `src/security/key.rs`, `src/security/tag.rs`)
  because `Hmac::new_from_slice` was moved to the `KeyInit` trait.
- `sha2::Sha256::finalize()` now returns `Array<u8, _>` (from
  hybrid-array) instead of `GenericArray<u8, _>`; the new type no
  longer impls `LowerHex`, so `format!("{digest:x}")` stops
  compiling. Replaced at three callsites
  (`tests/wasm_supply_chain_controls.rs::sha256_hex`,
  `tests/replay_e2e_suite.rs::trace_hash_hex`,
  `tests/conformance/raptorq_differential/src/fixture_loader.rs::calculate_hash`)
  with a manual `write!(&mut out, "{byte:02x}", ..)` loop so hex
  output is byte-identical to the prior `LowerHex` formatting.

### Concurrency bugs fixed as part of the test-gate

Three real production concurrency bugs were uncovered while getting
the test suite to green and are included in this release:

- **`src/observability/runtime_integration.rs`** —
  parking_lot RwLock self-deadlock. `on_task_cancel_completed` and
  `on_region_closed` used
  `if let Some(trace_id) = self.task_traces.write().remove(&id) { ... self.task_traces.read() ... }`;
  the `RwLockWriteGuard`'s lifetime was extended to the end of the
  `if let` block, where the subsequent `.read()` tried to re-acquire
  the same non-reentrant lock and deadlocked forever. Fixed by
  extracting the `write().remove(...)` result into a binding so the
  write guard drops at the end of that statement.
- **`src/service/discover.rs`** — DNS coalesce observability gap.
  The `Condvar`-based coalesce path (where followers park on a
  leader's inflight resolver instead of issuing duplicate requests)
  had no deterministic way for tests to confirm a follower had
  actually parked before the leader was released. Added
  `waiters: AtomicUsize` + `pub fn waiter_count()` to
  `DnsServiceDiscovery`; the five related tests now spin on
  `waiter_count()` until the follower is demonstrably parked, then
  release the leader. No scheduling behavior change on the coalesce
  contract itself.
- **`src/runtime/scheduler/three_lane.rs`** — one-line fix: inner
  `new_with_options` test at line 6526 needed `let mut scheduler`
  for the subsequent `take_workers()` call, which requires
  `&mut self`.

### Test-harness hygiene

- Refactored the three-lane scheduler test harnesses
  (`StarvationTestHarness`, `BudgetTestHarness`,
  `PromotionTestHarness`) to cache
  `workers: Vec<ThreeLaneWorker>` once in `new()` rather than
  calling the one-shot `take_workers()` per simulation pass. This
  also fixes a latent runtime bug in
  `mr_starvation_recovery_consistency` whose phase2 was silently
  dispatching zero tasks against an empty worker vector.
- `metamorphic_region_close_ordering::test_cancel_cascade_ordering`
  actually triggers cancellation now (via
  `state.cancel_request(root_region, &CancelReason::user("cascade"), None)`)
  and spawned tasks record their region_id into `cancel_order` on
  first-observed `Cx::is_cancel_requested()`. The test caller
  asserts membership and uniqueness on the recorded order.
- `mutex_metamorphic::mr2_cancel_non_poisoning` added the missing
  `drop(try_result)` before the subsequent `block_on(mutex.lock(..))`
  so the surviving guard doesn't keep the lock held across the
  async relock.
- `barrier_metamorphic::mr2_spurious_wakeup_preservation_property`
  switched its `execute_barrier_scenario` to
  `LabConfig::new(seed).with_auto_advance()` +
  `run_with_auto_advance()` so virtual time actually moves through
  sleeps.
- Ten-plus tests across the `golden_*` and `metamorphic_*` suites
  re-aligned with current API signatures (`inject_ready` /
  `inject_cancel` / `inject_timed` on `ThreeLaneScheduler`,
  `saturating_add_nanos` on `Time`, `create_task` /
  `cancel_request` / `create_child_region` on `RuntimeState`,
  `for_testing()` on `Cx`, `NavigationTopology` and
  `DoctorScenarioCoveragePackSmokeReport` field-set changes,
  `Output` vs `OutputWriter` rename in `src/cli/output`, etc.).
- `metamorphic_three_lane_fairness::metamorphic_adaptive_streak_convergence`
  is marked `#[ignore]`d with a reason: `LabScheduler` doesn't
  expose the EXP3 adaptive streak policy that only lives on the
  raw `ThreeLaneScheduler`.

### Scope of additions

This window landed (non-exhaustive, mined from commit history):

- Dozens of metamorphic relations across mpsc, mutex, rwlock,
  barrier, notify, Once, intrusive-heap, saga, obligation ledger,
  three-lane scheduler, transport aggregator, pool, region
  close/cascade, semaphore, race-loser drain, and io-driver.
- Dozens of golden snapshots covering CLI output formats,
  diagnostics forensic dump, doctor health report bundle,
  conformance manifest YAML, distributed snapshot, gRPC health
  responses, PostgreSQL query execution log, raptorq decode
  certificates, scheduler state dump, three-lane scheduler state,
  transport aggregator report format, web router dump, etc.
- Fuzz targets including DNS lookup/message decoder, HPACK
  decoder/round-trip, HTTP/1 and HTTP/2 pipelines, QUIC core
  protocol, TLS message parsing, Redis RESP, PostgreSQL wire
  protocol, Kafka wire protocol, RaptorQ codec frame splitter /
  symbol set / matrix ops / decoder state machine, websocket
  frames, and channel state-machine inputs.
- Conformance matrix expansion (manifest schema, doctor scenario
  coverage packs, stress/soak report format).
- Runtime and scheduler hardening (FIFO, reactor, epoch tracking,
  state correctness, cancel attribution, obligation replay
  identity).

### Verification

- `cargo check --workspace --all-targets` on ts2 via rch: green.
- Full `cargo test --workspace` — see release notes on the GitHub
  Release page for the complete pass summary; a handful of
  previously-hanging tests in `blocking_pool`, `observability`,
  `service::discover`, `mutex_metamorphic`, and
  `barrier_metamorphic` all pass now after the root-cause fixes
  listed above.

### Upgrade notes

Consumers on `0.2.x` crossing to `0.3.0` should expect the
coordinated hash/HMAC dependency wave (sha2 0.11 / hmac 0.13) to
require the `KeyInit` import fix at any callsite that used
`Hmac::new_from_slice`, and the `format!("{digest:x}")` → manual
hex-encode fix at any callsite that formatted a raw `finalize()`
output with the lowercase-hex formatter.

---

## [v0.2.9](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.9) -- 2026-03-21 (Release)

> 461 commits since v0.2.8 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.8...v0.2.9)

### Breaking changes

- **`ObjectParams.source_blocks` widened from `u8` to `u16`** ([`f7ae111f`](https://github.com/Dicklesworthstone/asupersync/commit/f7ae111f), [#30](https://github.com/Dicklesworthstone/asupersync/issues/30)). `u8` capped source blocks at 255; the protocol needs up to 256. The change applies to both the public field and the `ObjectParams::new(...)` constructor parameter. A sibling widening of `EncodingConfig::max_source_blocks` from `u8` to `u16` landed the same day in [`37f5b1b2`](https://github.com/Dicklesworthstone/asupersync/commit/37f5b1b2). Downstream consumers using caret constraints on `0.2.x` must update call sites to pass `u16`. Retroactively documented — this was the kind of source-breaking change that should have shipped in `0.3.0`; going forward, public signature width changes get a minor version bump.

### FABRIC Messaging Engine

The largest area of post-v0.2.8 development: a brokerless subject-oriented messaging system with session typing, obligation-backed delivery, and evidence-native decision planes.

- **Session projection engine** with duality verification for two-party protocols ([`3614ffd`](https://github.com/Dicklesworthstone/asupersync/commit/3614ffdb))
- **Semantic execution lane planner** for SubjectCell conversation families ([`85cebd4`](https://github.com/Dicklesworthstone/asupersync/commit/85cebd4f))
- **Deterministic protocol-scaffolding synthesis** for FABRIC sessions ([`0ff5530`](https://github.com/Dicklesworthstone/asupersync/commit/0ff55307))
- **SafetyEnvelope** for adaptive reliability tuning with runtime health evaluator ([`daf9c57`](https://github.com/Dicklesworthstone/asupersync/commit/daf9c572))
- **Fabric discovery sessions**, operator intent compiler, recoverable service capsules, IR monotone normalization ([`8fe3bb2`](https://github.com/Dicklesworthstone/asupersync/commit/8fe3bb25))
- **Full FABRIC IR compilation** with artifact registry, service/morphism/protocol/consumer compilation ([`670d072`](https://github.com/Dicklesworthstone/asupersync/commit/670d0723))
- **Adaptive consumer kernel** with overflow policy, decision audit, and pinned-client delivery ([`9f1d79b`](https://github.com/Dicklesworthstone/asupersync/commit/9f1d79b0))
- **Delta-CRDT metadata layer** for non-authoritative control surfaces ([`2d4561a`](https://github.com/Dicklesworthstone/asupersync/commit/2d4561af))
- **Bounded control-plane artifacts** for brokerless subject fabric ([`31d828e`](https://github.com/Dicklesworthstone/asupersync/commit/31d828e7))
- **Evidence-native data-plane decisions** and operator explain-plan expansion ([`920b531`](https://github.com/Dicklesworthstone/asupersync/commit/920b5315))
- **Delegated cursor partitions**, federation bridge runtime, multi-tenant namespace kernel ([`b69c261`](https://github.com/Dicklesworthstone/asupersync/commit/b69c2613))
- Certificate-carrying request/reply protocol with chunked reply obligations ([`a0cd1ad`](https://github.com/Dicklesworthstone/asupersync/commit/a0cd1ad6))
- Branch-addressable reality framework for cut-certified mobility ([`45859b0`](https://github.com/Dicklesworthstone/asupersync/commit/45859b00))
- Privacy-preserving metadata export with blinding and differential-privacy noise ([`c5878b6`](https://github.com/Dicklesworthstone/asupersync/commit/c5878b63))
- Obligation-backed consumer delivery with redelivery, dead-letter, and stats ([`b93be30`](https://github.com/Dicklesworthstone/asupersync/commit/b93be307))
- Shared fabric state registry with HMAC-SHA256 cell key hierarchy ([`2112b1f`](https://github.com/Dicklesworthstone/asupersync/commit/2112b1f6))
- Saga/Workflow obligation types re-exported from service module ([`017ba9e`](https://github.com/Dicklesworthstone/asupersync/commit/017ba9ef))
- Repair symbol binding, rebalance cut certification, cell epoch rebind ([`566728a`](https://github.com/Dicklesworthstone/asupersync/commit/566728a5))
- Semantic degradation policy for FABRIC lane overload decisions ([`393698e`](https://github.com/Dicklesworthstone/asupersync/commit/393698e1))
- Consistency topology and admission surface for FABRIC explain-plan ([`81f77c6`](https://github.com/Dicklesworthstone/asupersync/commit/81f77c6b))
- FABRIC control plane with system subjects and FrankenSuite advisories ([`848be23`](https://github.com/Dicklesworthstone/asupersync/commit/848be230))
- FABRIC compiler, explain-plan, IR cost model, and ShardedSublist ([`3b2ef97`](https://github.com/Dicklesworthstone/asupersync/commit/3b2ef972))
- Deterministic incident rehearsal framework for cut-certified mobility ([`68df80a`](https://github.com/Dicklesworthstone/asupersync/commit/68df80af))
- SublistLinkCache for per-link subject resolution hot cache ([`c3a3aaa`](https://github.com/Dicklesworthstone/asupersync/commit/c3a3aaa1))
- Quantitative obligation contracts (SLO-style) ([`e9b1c22`](https://github.com/Dicklesworthstone/asupersync/commit/e9b1c22f))
- EvidenceRecord advisory, typed filter, and evidence_id tracing ([`47d7f10`](https://github.com/Dicklesworthstone/asupersync/commit/47d7f10b))

### Transport and Networking

- **Rollback record**, dedup drain, and expiry-driven eviction in symbol aggregator ([`297cc5c`](https://github.com/Dicklesworthstone/asupersync/commit/297cc5c3))
- **Weight-aware select_n** for WeightedRoundRobin load balancing ([`3575ccf`](https://github.com/Dicklesworthstone/asupersync/commit/3575ccf8))
- Weighted round-robin select_n advances by 1 slot per selection, not by weight span ([`f76fcab`](https://github.com/Dicklesworthstone/asupersync/commit/f76fcab1))
- Weighted load balancer tracks active_backend_count, bounds-checks backend operations ([`2634deb`](https://github.com/Dicklesworthstone/asupersync/commit/2634deb5))
- Suppress spurious control traffic from cancel-ack and drain-request after shutdown ([`54bcaba`](https://github.com/Dicklesworthstone/asupersync/commit/54bcaba2))
- Prune_expired now includes default route TTL enforcement ([`a9fe79a`](https://github.com/Dicklesworthstone/asupersync/commit/a9fe79ae))
- Replace single-slot pending_symbol with FIFO staged queue in BufferedSink ([`1eedab5`](https://github.com/Dicklesworthstone/asupersync/commit/1eedab5f))

### Lab and Differential Testing

- **Differential artifact schemas** for retained divergence bundles ([`c372def`](https://github.com/Dicklesworthstone/asupersync/commit/c372deff))
- **Fuzz-to-scenario promotion** for differential regressions ([`5e583c6`](https://github.com/Dicklesworthstone/asupersync/commit/5e583c6e))
- **Evidence normalization** for lab-vs-live comparison ([`d865974`](https://github.com/Dicklesworthstone/asupersync/commit/d8659745))
- CaptureManifest field provenance and LiveWitnessCollector manifest tracking ([`e912340`](https://github.com/Dicklesworthstone/asupersync/commit/e9123408))
- Expand dual-run observable comparison to cover all semantic fields ([`a6c4b90`](https://github.com/Dicklesworthstone/asupersync/commit/a6c4b907))
- Divergence classification pipeline, fuzz-to-dual-run promotion, and divergence corpus registry ([`8e8f4a8`](https://github.com/Dicklesworthstone/asupersync/commit/8e8f4a83))
- Expand differential runner with 3 new scenarios, optional final policy ([`934a034`](https://github.com/Dicklesworthstone/asupersync/commit/934a034a))
- Validate obligation region ownership in snapshot restore ([`0e5de5a`](https://github.com/Dicklesworthstone/asupersync/commit/0e5de5a8))

### WASM and Browser

- **Browser runtime selection**, scope selection, and lane-health demotion/recovery coverage ([`2409c4b`](https://github.com/Dicklesworthstone/asupersync/commit/2409c4bc))
- **Lane-health retry window** coverage proving bounded retry budget before demotion ([`bdc84b7`](https://github.com/Dicklesworthstone/asupersync/commit/bdc84b74))
- Dedicated-worker matrix and execution-ladder diagnostics ([`7fb0c49`](https://github.com/Dicklesworthstone/asupersync/commit/7fb0c490))
- Shared-worker coordinator scaffolding with bounded attach, version handshake ([`f97de80`](https://github.com/Dicklesworthstone/asupersync/commit/f97de80a))
- Prerequisite-loss simulation in dedicated worker consumer test fixture ([`19f1250`](https://github.com/Dicklesworthstone/asupersync/commit/19f12505))
- Bounded service-worker broker API surface ([`45f8ff1`](https://github.com/Dicklesworthstone/asupersync/commit/45f8ff1a))

### Filesystem and I/O

- **BufReader::capacity()** accessor and safety doc comments for get_mut/into_inner ([`44459fe`](https://github.com/Dicklesworthstone/asupersync/commit/44459fe1))
- Correct 0o777 mode for io-uring create_dir, preserve file permissions in write_atomic ([`510fe8e`](https://github.com/Dicklesworthstone/asupersync/commit/510fe8e8))
- copy_buf tracks read_done state to flush correctly after EOF ([`1277755`](https://github.com/Dicklesworthstone/asupersync/commit/12777557))
- Peekable::size_hint returns (0, Some(0)) after cached exhaustion ([`5443ae6`](https://github.com/Dicklesworthstone/asupersync/commit/5443ae63))

### TLS and Security

- Fail closed on missing close_notify per RFC 8446 ([`602571e`](https://github.com/Dicklesworthstone/asupersync/commit/602571e8))
- Malformed grpc-timeout header was treated as no deadline instead of falling back to server default; this historical policy is superseded by the Unreleased fallback hardening above ([`e38a3b1`](https://github.com/Dicklesworthstone/asupersync/commit/e38a3b11))
- Improve certificate directory scanning robustness ([`8780cbc`](https://github.com/Dicklesworthstone/asupersync/commit/8780cbc6))

### Runtime and Concurrency Fixes

- Supervised restart leaves actor in Stopping state (deadlock) -- fixed ([`7812876`](https://github.com/Dicklesworthstone/asupersync/commit/78128769))
- Pending counter leak in Buffer when poll_ready errors ([`192c361`](https://github.com/Dicklesworthstone/asupersync/commit/192c361c))
- Buffer pending slot leak on panic in call() ([`1fad761`](https://github.com/Dicklesworthstone/asupersync/commit/1fad7614))
- Correct notify baton-passing when broadcast follows notify_one ([`fdc7a60`](https://github.com/Dicklesworthstone/asupersync/commit/fdc7a60e))
- Remove spurious baton passing when a notified waiter is dropped before poll ([`c10ca2a`](https://github.com/Dicklesworthstone/asupersync/commit/c10ca2aa))
- Adaptive hedge warmup threshold respects small configured windows ([`f11b4f0`](https://github.com/Dicklesworthstone/asupersync/commit/f11b4f01))
- Clock skew evidence for all skew types, prevent jitter zero-collapse at 1ns boundary ([`78fd305`](https://github.com/Dicklesworthstone/asupersync/commit/78fd3054))
- Enforce max_concurrent_streams for incoming remote-initiated H2 streams ([`0e27de0`](https://github.com/Dicklesworthstone/asupersync/commit/0e27de09))
- Preserve handler Content-Length in HEAD response per RFC 9110 ([`c10f4f9`](https://github.com/Dicklesworthstone/asupersync/commit/c10f4f9d))
- JoinHandle::is_finished detects dropped executor side ([`4ac0e5a`](https://github.com/Dicklesworthstone/asupersync/commit/4ac0e5a7))
- Process: close piped stdin before wait to prevent child deadlock ([`af8541e`](https://github.com/Dicklesworthstone/asupersync/commit/af8541e5))
- Kill_on_drop background reaping prevents zombie processes ([`81be156`](https://github.com/Dicklesworthstone/asupersync/commit/81be156d))
- Saga Drop panicking guard + circuit breaker Acquire ordering ([`79d25ca`](https://github.com/Dicklesworthstone/asupersync/commit/79d25caf))
- Server trigger_immediate runs pre-phase hook before advancing to ForceClosing ([`d0079ee`](https://github.com/Dicklesworthstone/asupersync/commit/d0079eeb))

### RaptorQ Erasure Coding

- Profile-pack v5 schema with decision_evidence_status tracking ([`69916e1`](https://github.com/Dicklesworthstone/asupersync/commit/69916e19))
- Conservative tie-breaker in decision contract, DRY test fixtures in gf256 ([`26beb1b`](https://github.com/Dicklesworthstone/asupersync/commit/26beb1ba))
- E2E script validates decision-metadata and override truthfulness ([`5379f3f`](https://github.com/Dicklesworthstone/asupersync/commit/5379f3f4))
- c==1 addmul fast path and SIMD threshold fix ([`2e4e327`](https://github.com/Dicklesworthstone/asupersync/commit/2e4e3272))
- SparseRow bounds check before zero fast-path ([`62bb40c`](https://github.com/Dicklesworthstone/asupersync/commit/62bb40c2))
- Stricter test log schema validation catches whitespace-only fields ([`ed80616`](https://github.com/Dicklesworthstone/asupersync/commit/ed806169))

### Comprehensive Audit Campaign

- ~130,000 lines audited across batches 391--415, all SOUND
- Representative batch: batch 415 covering service/concurrency_limit + timeout + rate_limit ([`b0c7aa3`](https://github.com/Dicklesworthstone/asupersync/commit/b0c7aa3b))
- Machine-searchable audit history expanded with 576 entries across 472 files ([`04b9d2a`](https://github.com/Dicklesworthstone/asupersync/commit/04b9d2af))

---

## [v0.2.8](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.8) -- 2026-03-15 (Release)

> 958 commits since v0.2.7 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.7...v0.2.8)

The largest release to date: 410+ bug fixes, 222 features, and audit coverage across 500+ files.

### Runtime Correctness and Safety

- **Fail-closed completion guards** added to all Future implementations (streams, I/O, sync, service) -- prevents silent misuse when polling after terminal state ([`a9e737d`](https://github.com/Dicklesworthstone/asupersync/commit/a9e737d8), [`c917822`](https://github.com/Dicklesworthstone/asupersync/commit/c917822d), [`c9069cc`](https://github.com/Dicklesworthstone/asupersync/commit/c9069cc2))
- **ThreeLaneLocalWaker** default_priority prevents priority inversion for cancelled local tasks ([`12d261d`](https://github.com/Dicklesworthstone/asupersync/commit/12d261db))
- **Actual cancel masking** in commit_section ([`85b1ac0`](https://github.com/Dicklesworthstone/asupersync/commit/85b1ac07))
- Deterministic waker drain, early lock drops, keepalive builder, mask optimization ([`0f0fe0a`](https://github.com/Dicklesworthstone/asupersync/commit/0f0fe0a6))
- Stale-entry skipping extended to all scheduler pop methods ([`ac4d2e9`](https://github.com/Dicklesworthstone/asupersync/commit/ac4d2e96))
- Task completion coerced to Cancelled when cancel is in-flight ([`bebe6b9`](https://github.com/Dicklesworthstone/asupersync/commit/bebe6b9b))
- Double-panic guards on all Drop-based leak detectors ([`44708b1`](https://github.com/Dicklesworthstone/asupersync/commit/44708b12))
- yield_now panics on repoll; timeout reset unconditional ([`596f351`](https://github.com/Dicklesworthstone/asupersync/commit/596f3518))
- Soften repoll guards from panic to error return across time, runtime, net ([`4a40627`](https://github.com/Dicklesworthstone/asupersync/commit/4a40627a))
- Join semantics with proper close handling ([`34fbc58`](https://github.com/Dicklesworthstone/asupersync/commit/34fbc581))

### Service Layer

- **Discover-driven topology updates** in LoadBalancer ([`765f9f3`](https://github.com/Dicklesworthstone/asupersync/commit/765f9f34))
- **Weighted strategy** polish with PolledAfterCompletion on LoadShed ([`fdca8d9`](https://github.com/Dicklesworthstone/asupersync/commit/fdca8d97))
- Unified NotReady error variant across all service middlewares ([`fbf95a7`](https://github.com/Dicklesworthstone/asupersync/commit/fbf95a7f))
- Readiness contracts and expanded filter, hedge, and timeout coverage ([`2e97eee`](https://github.com/Dicklesworthstone/asupersync/commit/2e97eeea))
- Buffer NotReady enforcement, OneshotError wrapper, LoadBalancer sync_backend_count ([`1d0505b`](https://github.com/Dicklesworthstone/asupersync/commit/1d0505b3))
- Correct readiness tracking in Filter/Reconnect, add RetryError wrapper ([`32cb86a`](https://github.com/Dicklesworthstone/asupersync/commit/32cb86a5))
- Stale DNS resolution prevented from clobbering newer state ([`1cb7314`](https://github.com/Dicklesworthstone/asupersync/commit/1cb73149))

### HTTP and Protocol Compliance

- **RFC 9110** identity encoding negotiation and HEAD response handling ([`662b127`](https://github.com/Dicklesworthstone/asupersync/commit/662b1271))
- **RFC 7540** reserved streams counted toward max_concurrent_streams ([`02bb14b`](https://github.com/Dicklesworthstone/asupersync/commit/02bb14bb))
- H2-reserved H3 settings rejected ([`518b400`](https://github.com/Dicklesworthstone/asupersync/commit/518b4008))
- Stateful streaming decompression, quality validation, and Expect: 100-continue refactoring ([`65b6677`](https://github.com/Dicklesworthstone/asupersync/commit/65b66771))
- CRLF injection sanitization in response headers, redirect Location, gRPC-web trailers ([`c178930`](https://github.com/Dicklesworthstone/asupersync/commit/c1789300), [`bdfc321`](https://github.com/Dicklesworthstone/asupersync/commit/bdfc3213), [`931150f`](https://github.com/Dicklesworthstone/asupersync/commit/931150f2))
- Tri-state Limited body distinguishes clean EOF from failure ([`2ed0aab`](https://github.com/Dicklesworthstone/asupersync/commit/2ed0aab4))
- Reference-count HealthReporters to prevent premature status clear ([`b96d51c`](https://github.com/Dicklesworthstone/asupersync/commit/b96d51c4))
- SSE: reject null bytes in last_event_id per SSE spec ([`6ae5703`](https://github.com/Dicklesworthstone/asupersync/commit/6ae57034))

### WASM and Browser

- **Real MessagePort and BroadcastChannel** bindings for browser reactor ([`c29a4c9`](https://github.com/Dicklesworthstone/asupersync/commit/c29a4c9b))
- **StreamAccounting** for BrowserReadable/WritableStream ([`119f217`](https://github.com/Dicklesworthstone/asupersync/commit/119f2174))
- Non-clobbering addEventListener-based message and error listeners ([`41ff324`](https://github.com/Dicklesworthstone/asupersync/commit/41ff3240))
- Service-worker broker descriptor and handoff parser validation ([`ddcfad6`](https://github.com/Dicklesworthstone/asupersync/commit/ddcfad65))

### Distributed and CRDT

- **Multi-block encoding** with per-block repair distribution ([`39f38b4`](https://github.com/Dicklesworthstone/asupersync/commit/39f38b45))
- **Quorum-aware recovery** completion and replica mutation guards ([`6985c9c`](https://github.com/Dicklesworthstone/asupersync/commit/6985c9c6))
- Close idempotent, reconcile replica loss across all degraded states ([`ad46fb2`](https://github.com/Dicklesworthstone/asupersync/commit/ad46fb27))
- ORSet tombstone tracking prevents removed values from reappearing on merge ([`7516adf`](https://github.com/Dicklesworthstone/asupersync/commit/7516adf7))
- GCounter saturating add, PNCounter widened to i128, checked ORSet seq ([`0673257`](https://github.com/Dicklesworthstone/asupersync/commit/0673257e))
- Reject trailing bytes in snapshot deserialization ([`99640c5`](https://github.com/Dicklesworthstone/asupersync/commit/99640c56))

### Sync Primitives

- OnceCell::set made non-blocking to prevent async deadlocks ([`a4985e7`](https://github.com/Dicklesworthstone/asupersync/commit/a4985e7f))
- Zero semaphore permits on close and handle pool close-while-create race ([`047c88a`](https://github.com/Dicklesworthstone/asupersync/commit/047c88a7))
- Lost notify_one baton when broadcast supersedes original waiter set ([`95c7de7`](https://github.com/Dicklesworthstone/asupersync/commit/95c7de7e))
- RwLock waiter state cleanup on cancellation and poison ([`3ae13c1`](https://github.com/Dicklesworthstone/asupersync/commit/3ae13c15))
- Atomic record_event replaces split next_seq/push_event to prevent sequence interleaving ([`da4facc`](https://github.com/Dicklesworthstone/asupersync/commit/da4facc8))

### Observability and Lab

- **Sync reactor chaos statistics** into LabRuntime aggregated stats ([`da489aa`](https://github.com/Dicklesworthstone/asupersync/commit/da489aa7))
- **Deadlocked health classification** from explicit trapped wait-cycle evidence ([`bd4b6b1`](https://github.com/Dicklesworthstone/asupersync/commit/bd4b6b1a))
- Task inspector falls back to logical state clock ([`d3c7744`](https://github.com/Dicklesworthstone/asupersync/commit/d3c7744d))
- Timer wheel synchronization to current clock before register/update/query paths ([`16eba13`](https://github.com/Dicklesworthstone/asupersync/commit/16eba13a))
- Trace writer drop flush ([`c6c8114`](https://github.com/Dicklesworthstone/asupersync/commit/c6c81145))
- Evict oldest incomplete traces when complete-trace eviction is insufficient ([`22aa925`](https://github.com/Dicklesworthstone/asupersync/commit/22aa925a))

### Database

- Cancel-aware result set draining and overflow-safe packet reads ([`f5e188d`](https://github.com/Dicklesworthstone/asupersync/commit/f5e188d1))
- DbPool mutex locks survive poisoned state ([`ba43ecc`](https://github.com/Dicklesworthstone/asupersync/commit/ba43ecc4))
- Return_connection reports whether connection was requeued ([`83f31ac`](https://github.com/Dicklesworthstone/asupersync/commit/83f31ac5))
- MySQL IPv6/timeout, QPACK static table and header validation ([`467831d`](https://github.com/Dicklesworthstone/asupersync/commit/467831d6))

### Audit Campaign

- **Over 500 files audited**, all SOUND, across batches 199--379
- 65,307 lines in batches 199--208 alone; 0 bugs remaining after fixes
- Audit coverage includes all major subsystems: runtime, scheduler, channels, net, HTTP, service, distributed, messaging

### Drop_unwrap_finder Utility

- New static analysis utility for finding potential unwrap panics in Drop impls ([`0c45351`](https://github.com/Dicklesworthstone/asupersync/commit/0c453514))

---

## [v0.2.7](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.7) -- 2026-03-03 (Tag)

> 412 commits since v0.2.6 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.6...v0.2.7)

### Web Framework

- **Session middleware** with pluggable backends ([`ff2c55b`](https://github.com/Dicklesworthstone/asupersync/commit/ff2c55be))
- **Static file serving** with ETag and caching ([`d6d012b`](https://github.com/Dicklesworthstone/asupersync/commit/d6d012bb))
- **Multipart form data** parser and RFC 7578 extractor ([`60e6c83`](https://github.com/Dicklesworthstone/asupersync/commit/60e6c83f), [`96292ef`](https://github.com/Dicklesworthstone/asupersync/commit/96292eff))
- **Health check endpoints** for Kubernetes-style probes ([`543587f`](https://github.com/Dicklesworthstone/asupersync/commit/543587f2))
- **Server-Sent Events (SSE)** support ([`5600b25`](https://github.com/Dicklesworthstone/asupersync/commit/5600b25d))
- **Cookie and CookieJar** extractors with header parsing ([`1e54bea`](https://github.com/Dicklesworthstone/asupersync/commit/1e54bea0))
- **CORS middleware** with configurable origin/method/header policies ([`4d9f63f`](https://github.com/Dicklesworthstone/asupersync/commit/4d9f63fa))
- **SecurityHeadersMiddleware** with configurable security policy ([`38bec9c`](https://github.com/Dicklesworthstone/asupersync/commit/38bec9cf))
- **Gzip/deflate compressors** and response compression middleware ([`79f746b`](https://github.com/Dicklesworthstone/asupersync/commit/79f746bf))
- 8 production middleware types for stack parity ([`13912ba`](https://github.com/Dicklesworthstone/asupersync/commit/13912ba8))
- RequestTraceMiddleware for request timing and trace propagation ([`beb1b0b`](https://github.com/Dicklesworthstone/asupersync/commit/beb1b0be))
- Full WebSocket implementation with module doc comment ([`7f0e222`](https://github.com/Dicklesworthstone/asupersync/commit/7f0e222f))
- WebSocket HTTP upgrade extractor ([`aa04fbd`](https://github.com/Dicklesworthstone/asupersync/commit/aa04fbd4))
- Form body size limit and comprehensive extractor tests ([`591d4fd`](https://github.com/Dicklesworthstone/asupersync/commit/591d4fd0))
- Content negotiation module ([`e806de9`](https://github.com/Dicklesworthstone/asupersync/commit/e806de91))
- TypeId-keyed typed state extraction in Extensions ([`d6d202a`](https://github.com/Dicklesworthstone/asupersync/commit/d6d202a4))

### Stream Combinators

- **Scan, peekable, throttle, debounce** combinators ([`2f7be8c`](https://github.com/Dicklesworthstone/asupersync/commit/2f7be8c4))

### Redis

- **Transaction (MULTI/EXEC)** and PubSub APIs ([`fad7cbb`](https://github.com/Dicklesworthstone/asupersync/commit/fad7cbb3))
- Pub/Sub types, PUBLISH, WATCH/UNWATCH, MULTI/EXEC, and PING ([`0d1383b`](https://github.com/Dicklesworthstone/asupersync/commit/0d1383b6))

### gRPC

- **Server reflection service** with descriptor registry ([`23f6f20`](https://github.com/Dicklesworthstone/asupersync/commit/23f6f207))
- **Compression encoding negotiation** on gRPC channel ([`7aedbe2`](https://github.com/Dicklesworthstone/asupersync/commit/7aedbe20))

### Tokio Compatibility Layer

- **Safe blocking bridge** with Cx context propagation ([`72557fa`](https://github.com/Dicklesworthstone/asupersync/commit/72557fae))
- Real I/O trait bridging and functional hyper executor/timer ([`6813e18`](https://github.com/Dicklesworthstone/asupersync/commit/6813e18f))
- Tokio-compat scaffolding, interop ranking, and migration framework ([`e23469a`](https://github.com/Dicklesworthstone/asupersync/commit/e23469a7))
- Replace thread-based sleep with native timer wheel delegation ([`6a58861`](https://github.com/Dicklesworthstone/asupersync/commit/6a58861a))
- Cancel-aware polling in Tower bridge replacing with_tokio_context ([`89e7c3c`](https://github.com/Dicklesworthstone/asupersync/commit/89e7c3c7))

### Database

- **MySQL client hardened** with result limits, URL parsing, abandoned tx drain ([`1a13be2`](https://github.com/Dicklesworthstone/asupersync/commit/1a13be2d))
- **SQLite connection defaults** and runtime configuration ([`6d1e2e1`](https://github.com/Dicklesworthstone/asupersync/commit/6d1e2e19))
- **PostgreSQL** type-safe parameter encoding, extended query protocol, prepared statements ([`3e2ad4f`](https://github.com/Dicklesworthstone/asupersync/commit/3e2ad4f4))

### I/O and Networking

- **RFC 8305 Happy Eyeballs v2** concurrent connection racing ([`60a8023`](https://github.com/Dicklesworthstone/asupersync/commit/60a80230))
- **AsyncSeekExt** trait ([`30993b6`](https://github.com/Dicklesworthstone/asupersync/commit/30993b6e))
- **ReaderStream and StreamReader** bridge adapters ([`e37a9d4`](https://github.com/Dicklesworthstone/asupersync/commit/e37a9d45))
- **Async Command/Child** methods for cooperative polling ([`4376aab`](https://github.com/Dicklesworthstone/asupersync/commit/4376aab5))
- Typed integer read/write methods on AsyncReadExt/AsyncWriteExt ([`40a6866`](https://github.com/Dicklesworthstone/asupersync/commit/40a68661), [`7b4ecdd`](https://github.com/Dicklesworthstone/asupersync/commit/7b4ecdd2))
- **Write_atomic** for durable file replacement via temp+rename ([`dd0573a`](https://github.com/Dicklesworthstone/asupersync/commit/dd0573ab))
- LinesCodec decode_eof, discard-and-recover for oversized lines ([`75b96ff`](https://github.com/Dicklesworthstone/asupersync/commit/75b96ffb))

### QUIC/HTTP3

- Native feature surfaces, deprecate compat wrappers ([`06df9b5`](https://github.com/Dicklesworthstone/asupersync/commit/06df9b52))
- QPACK field-section decode helpers with pseudo-header validation ([`a70436e`](https://github.com/Dicklesworthstone/asupersync/commit/a70436e5))
- 0-RTT/resumption and path migration lifecycle ([`556290c`](https://github.com/Dicklesworthstone/asupersync/commit/556290c9))
- Packet send-state guard and congestion recovery epoch fix ([`be7d9fb`](https://github.com/Dicklesworthstone/asupersync/commit/be7d9fb7))

### Kafka

- Deterministic producer/consumer lifecycle ([`e7a9204`](https://github.com/Dicklesworthstone/asupersync/commit/e7a92040))
- Messaging module gated behind kafka feature ([`c4705b7`](https://github.com/Dicklesworthstone/asupersync/commit/c4705b71))
- NATS graceful flush before shutdown, max_payload enforcement ([`16c4a88`](https://github.com/Dicklesworthstone/asupersync/commit/16c4a88f), [`1527fe9`](https://github.com/Dicklesworthstone/asupersync/commit/1527fe9b))

### WASM Supply Chain

- Supply-chain artifact bundle: SBOM, provenance, integrity manifest ([`37c0037`](https://github.com/Dicklesworthstone/asupersync/commit/37c00370))
- Flake governance framework with policy and checker ([`a48a751`](https://github.com/Dicklesworthstone/asupersync/commit/a48a751a))
- ABI compatibility policy and harness ([`335c905`](https://github.com/Dicklesworthstone/asupersync/commit/335c9051))
- Bundler/runtime compatibility matrix and test suite ([`7d54656`](https://github.com/Dicklesworthstone/asupersync/commit/7d54656d))
- DX error taxonomy, diagnostic enrichment, and IntelliSense quality contract ([`9b3c72b`](https://github.com/Dicklesworthstone/asupersync/commit/9b3c72b0))

### Semantic and Formal Verification

- TLA+ abstraction boundaries and runtime correspondence ([`28f7ca2`](https://github.com/Dicklesworthstone/asupersync/commit/28f7ca22))
- SEM-11 complete: enablement FAQ, maintainer playbook, audit cadence, retrospective ([`b4c57fa`](https://github.com/Dicklesworthstone/asupersync/commit/b4c57fa7))
- SEM-10.5 CI signal-quality gate with flake rate and runtime budget enforcement ([`fef0af4`](https://github.com/Dicklesworthstone/asupersync/commit/fef0af48))
- Residual risk register with bounded exceptions and GO/NO-GO rules ([`0f8d10e`](https://github.com/Dicklesworthstone/asupersync/commit/0f8d10ef))
- Failure-replay cookbook with triage tree and rerun shortcuts ([`c6beffb`](https://github.com/Dicklesworthstone/asupersync/commit/c6beffb6))

### Sync and Channel Fixes

- RwLock pre-grant drop safety extended to OwnedWriteFuture with cascading wakeup ([`94cc4ca`](https://github.com/Dicklesworthstone/asupersync/commit/94cc4cac))
- Watch channel Receiver::changed waker leak ([`5af621b`](https://github.com/Dicklesworthstone/asupersync/commit/5af621b6))
- Waiter ID overflow prevention, RwLock FIFO fairness ([`124a2c3`](https://github.com/Dicklesworthstone/asupersync/commit/124a2c3d))
- Receiver close returns Disconnected when channel empty instead of Empty ([`616d0b6`](https://github.com/Dicklesworthstone/asupersync/commit/616d0b6f))
- Broadcast receiver_count increment inside lock to prevent subscribe race ([`e9314df`](https://github.com/Dicklesworthstone/asupersync/commit/e9314df5))
- RwLock wake blocked readers when last queued writer is dropped ([`605e413`](https://github.com/Dicklesworthstone/asupersync/commit/605e413f))

### Lean Formal Proofs

- No-ambient-authority capability exclusion theorems ([`bd726ce`](https://github.com/Dicklesworthstone/asupersync/commit/bd726ce1))
- Global no-obligation-leak theorems ([`b60f38c`](https://github.com/Dicklesworthstone/asupersync/commit/b60f38c6))
- SingleOwner invariant proof ([`070ef00`](https://github.com/Dicklesworthstone/asupersync/commit/070ef003))
- Cancel-request idempotence theorems ([`447fcd8`](https://github.com/Dicklesworthstone/asupersync/commit/447fcd85))

### Performance

- Fused dual-slice GF(256) SIMD mul/addmul for AVX2 and NEON ([`58b27f4`](https://github.com/Dicklesworthstone/asupersync/commit/58b27f43))
- Always use dual-add fast path for c==1 in gf256_addmul_slices2 ([`b5b37fc`](https://github.com/Dicklesworthstone/asupersync/commit/b5b37fc3))
- AsyncReadVectored for TCP and Unix stream split halves ([`b3e8768`](https://github.com/Dicklesworthstone/asupersync/commit/b3e8768e))

### Doctor CLI

- Performance budget matrix and instrumentation gates ([`f638c35`](https://github.com/Dicklesworthstone/asupersync/commit/f638c35d))
- Visual regression harness and golden fixture suite ([`8367006`](https://github.com/Dicklesworthstone/asupersync/commit/8367006f))
- Guided remediation preview/apply pipeline with staged approval checkpoints ([`184fa87`](https://github.com/Dicklesworthstone/asupersync/commit/184fa87c))
- Post-remediation verification loop with trust scorecards ([`6ae61e4`](https://github.com/Dicklesworthstone/asupersync/commit/6ae61e4d))

---

## [v0.2.6](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.6) -- 2026-02-22 (Tag)

> 260 commits since v0.2.5 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.5...v0.2.6)

### RaptorQ Erasure Coding

- **Wavefront decode pipeline** for bounded assembly+peeling ([`e613664`](https://github.com/Dicklesworthstone/asupersync/commit/e6136648))
- **F8 wavefront pipeline closed** -- all G3 blockers resolved ([`42e2b6f`](https://github.com/Dicklesworthstone/asupersync/commit/42e2b6f2))
- Per-lane floor threshold for dual-addmul auto policy ([`4cfaada`](https://github.com/Dicklesworthstone/asupersync/commit/4cfaadad))
- Arc-wrap dense factor cache artifacts, flatten signature memory layout ([`0c26349`](https://github.com/Dicklesworthstone/asupersync/commit/0c263497))
- Raise addmul floor to 12KiB and add XOR fast path for tiny slices ([`b37eed8`](https://github.com/Dicklesworthstone/asupersync/commit/b37eed89))
- Iterator-based propagation in peel_from_queue ([`8ee3c9c`](https://github.com/Dicklesworthstone/asupersync/commit/8ee3c9c5))
- Dense-column mapping with adaptive DenseColIndexMap ([`b607315`](https://github.com/Dicklesworthstone/asupersync/commit/b607315c))

### HTTP/2 and Security

- **CVE-2023-44487 Rapid Reset** mitigated with RST_STREAM rate limiting ([`b47a7a5`](https://github.com/Dicklesworthstone/asupersync/commit/b47a7a5f))
- Chunked trailer size limit check reordered to avoid premature rejection ([`8754e3d`](https://github.com/Dicklesworthstone/asupersync/commit/8754e3dc))

### Networking

- **TCP accept storm** detection with exponential backoff ([`b187985`](https://github.com/Dicklesworthstone/asupersync/commit/b187985c))
- Exponential backoff for transient accept errors and fallback IO rewakes ([`ab42cfa`](https://github.com/Dicklesworthstone/asupersync/commit/ab42cfad))
- Fallback accept backoff moved to background thread ([`f6e567b`](https://github.com/Dicklesworthstone/asupersync/commit/f6e567b1))
- Region close notification so scope awaits child completion ([`834172e`](https://github.com/Dicklesworthstone/asupersync/commit/834172e1))

### Sync Primitives

- Exception safety improved in barrier/notify primitives ([`de7d4bc`](https://github.com/Dicklesworthstone/asupersync/commit/de7d4bc1))
- RwLockWriteGuard Sync bound tightened to require T: Send + Sync ([`0e74544`](https://github.com/Dicklesworthstone/asupersync/commit/0e745445))
- Require &mut self for oneshot Receiver::recv ([`6a081e2`](https://github.com/Dicklesworthstone/asupersync/commit/6a081e25))
- BlockingOneshotReceiver waker cleared on drop to prevent stale wake ([`118e356`](https://github.com/Dicklesworthstone/asupersync/commit/118e3566))
- Saturating_duration_since in pool eviction to prevent panic ([`925628a`](https://github.com/Dicklesworthstone/asupersync/commit/925628a9))
- Active waiter count incremented when notify waker slot re-filled ([`c2a1ab6`](https://github.com/Dicklesworthstone/asupersync/commit/c2a1ab6d))
- Lost-wakeup chain resolved in mutex and rwlock drop paths ([`698c425`](https://github.com/Dicklesworthstone/asupersync/commit/698c425e))

### Runtime

- Try_lock I/O leader pattern replaced with atomic CAS polling ([`d5ba8a2`](https://github.com/Dicklesworthstone/asupersync/commit/d5ba8a26))
- Panic safety added to blocking pool, shutdown check before wait ([`2ed0ba7`](https://github.com/Dicklesworthstone/asupersync/commit/2ed0ba7a))
- WebSocket close handshake timeout ([`0b473bc`](https://github.com/Dicklesworthstone/asupersync/commit/0b473bc8))
- Finished thread handle reaping + pool timeout cleanup ([`1fba0f9`](https://github.com/Dicklesworthstone/asupersync/commit/1fba0f9c))

### Performance

- Cache max duration as u64 nanoseconds to avoid repeated u128-to-u64 conversions ([`611acf6`](https://github.com/Dicklesworthstone/asupersync/commit/611acf63))
- Compare_exchange in Parker park/unpark ([`e2caecc`](https://github.com/Dicklesworthstone/asupersync/commit/e2caecc3))
- Fast-path empty wheel + purge storage on last cancel ([`70bf97e`](https://github.com/Dicklesworthstone/asupersync/commit/70bf97e6))
- Single-pass reservoir sampling in random load balancer ([`9198d51`](https://github.com/Dicklesworthstone/asupersync/commit/9198d516))
- Fast-path work stealing when queue has no local tasks ([`8b0ee3e`](https://github.com/Dicklesworthstone/asupersync/commit/8b0ee3e7))
- Stack-pin futures in scope race/select patterns ([`9035b20`](https://github.com/Dicklesworthstone/asupersync/commit/9035b204))
- Bounded concurrent sends in distributed distribute() ([`b582ebd`](https://github.com/Dicklesworthstone/asupersync/commit/b582ebd0))
- Bitmap-scan next-deadline via next_occupied_circular() ([`7e2bc5f`](https://github.com/Dicklesworthstone/asupersync/commit/7e2bc5f8))
- Reduce mutex hold time in TcpListener::register_interest ([`c42e9af`](https://github.com/Dicklesworthstone/asupersync/commit/c42e9af9))
- Cap stealer skip-list to inline capacity + full-scan wheel levels ([`465d82f`](https://github.com/Dicklesworthstone/asupersync/commit/465d82f8))

### Oracle and Testing

- **Refinement firewall** and temporal oracle hydration ([`c7c4a21`](https://github.com/Dicklesworthstone/asupersync/commit/c7c4a21c))
- Deterministic fault injection and lab scenario testing ([`766c2fb`](https://github.com/Dicklesworthstone/asupersync/commit/766c2fb0))
- Cumulative event count tracking for ring buffer eviction detection ([`fbf82e6`](https://github.com/Dicklesworthstone/asupersync/commit/fbf82608))
- Edge-case tests for snapshot OOM and timer wraparound ([`025324e`](https://github.com/Dicklesworthstone/asupersync/commit/025324e7))

### QPACK/HTTP3

- QPACK field section encode/decode for static-only mode ([`abfe6ad`](https://github.com/Dicklesworthstone/asupersync/commit/abfe6ad8))
- QPACK wire validation and interop fixture corpus ([`12f3c10`](https://github.com/Dicklesworthstone/asupersync/commit/12f3c108))

### Database

- Synchronous rollback, OOM cap, wrapping IDs fixed ([`c433946`](https://github.com/Dicklesworthstone/asupersync/commit/c4339464))

---

## [v0.2.5](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.5) -- 2026-02-18 (Release)

> 13 commits since v0.2.4 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.4...v0.2.5)

Workspace crate versions aligned to 0.2.5 for crates.io publication with MIT + OpenAI/Anthropic rider license metadata.

- **Deterministic artifact manifests** with replay verification and jq-based contract validation ([`b0c0fd1`](https://github.com/Dicklesworthstone/asupersync/commit/b0c0fd1c))
- **Coverage ratchet**, no-mock waiver expiry, and Track-D CI gates ([`19cfb06`](https://github.com/Dicklesworthstone/asupersync/commit/19cfb068))
- Preserve custom WebSocket close codes, persist load-shed state, tighten HTTP/1 parsing ([`21fb7c8`](https://github.com/Dicklesworthstone/asupersync/commit/21fb7c80))
- Tighten cast failure semantics and cancellation cleanup invariants ([`c5b1d75`](https://github.com/Dicklesworthstone/asupersync/commit/c5b1d758))
- Dense-factor reuse cache and broader decode stress benchmarks ([`c90f59f`](https://github.com/Dicklesworthstone/asupersync/commit/c90f59f6))
- Use BTreeMap for expected_loss_by_action payloads (publish fix) ([`0c8fd60`](https://github.com/Dicklesworthstone/asupersync/commit/0c8fd602))

---

## [v0.2.4](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.4) -- 2026-02-18 (Tag)

> 21 commits since v0.2.3 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.3...v0.2.4)

### Rust 2024 Edition Migration

- **Workspace migrated to Rust edition 2024** ([`db4ec3d`](https://github.com/Dicklesworthstone/asupersync/commit/db4ec3d8))
- Comprehensive rustfmt 2024 formatting applied across entire codebase ([`5cb48b4`](https://github.com/Dicklesworthstone/asupersync/commit/5cb48b40))
- Windows IOCP poller migrated from RawSocket to BorrowedSocket ([`29edc8f`](https://github.com/Dicklesworthstone/asupersync/commit/29edc8fe))

### Bug Fixes

- gRPC CallContext deadline expiry made boundary-inclusive and testable ([`0e36edd`](https://github.com/Dicklesworthstone/asupersync/commit/0e36edd3))
- TraceMonoid PartialEq guarded against fingerprint hash collisions ([`44072cb`](https://github.com/Dicklesworthstone/asupersync/commit/44072cb8))
- EndpointState made atomic; update_endpoint_state no-op fixed ([`fdc9cd1`](https://github.com/Dicklesworthstone/asupersync/commit/fdc9cd1a))
- Bridge sync pending accounting and CRDT obligation acquire idempotency ([`1f678ba`](https://github.com/Dicklesworthstone/asupersync/commit/1f678ba9))
- RFC 6455 close code validation on parse, tighten wire-sendable set ([`591bf57`](https://github.com/Dicklesworthstone/asupersync/commit/591bf574))
- Integer overflow prevention in Duration-to-u64 conversions and HPACK bitmask shifts ([`5b80ba6`](https://github.com/Dicklesworthstone/asupersync/commit/5b80ba69))
- Circuit breaker half_open_max_probes clamped to minimum of 1 ([`70c19da`](https://github.com/Dicklesworthstone/asupersync/commit/70c19dac))
- DummyCx stub in scope compile-fail test ([`b824e69`](https://github.com/Dicklesworthstone/asupersync/commit/b824e692))

### Performance

- Decoder scratch buffer reuse, HPACK prealloc, WatchStream mark_seen ([`9f0522e`](https://github.com/Dicklesworthstone/asupersync/commit/9f0522e0))
- Single-pass HTTP/1 header parsing and raptorq decoder retry snapshot/restore ([`33ce0f0`](https://github.com/Dicklesworthstone/asupersync/commit/33ce0f06))

---

## [v0.2.3](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.3) -- 2026-02-17 (Tag)

> 2 commits since v0.2.2 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.2...v0.2.3)

- Version bump release for tagged milestone
- Fix Windows reactor modify/delete socket source typing ([`63880c2`](https://github.com/Dicklesworthstone/asupersync/commit/63880c24))

---

## [v0.2.2](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.2) -- 2026-02-17 (Tag)

> 380 commits since v0.2.0 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.0...v0.2.2)

### Performance Overhaul: parking_lot Migration

- **Complete migration from std::sync to parking_lot** across the entire codebase -- channels, runtime, scheduler, sync primitives, actor, service, net, transport ([`3c1b335`](https://github.com/Dicklesworthstone/asupersync/commit/3c1b3356), [`067e030`](https://github.com/Dicklesworthstone/asupersync/commit/067e0306))
- Lock-free atomic counters replacing Mutex-guarded stats in channels, bulkhead, DNS, shutdown ([`c9d2ddb`](https://github.com/Dicklesworthstone/asupersync/commit/c9d2ddb3), [`e826391`](https://github.com/Dicklesworthstone/asupersync/commit/e8263919))
- BTreeMap/BTreeSet to HashMap/HashSet migration for hot paths ([`d421836`](https://github.com/Dicklesworthstone/asupersync/commit/d4218361), [`e25acf4`](https://github.com/Dicklesworthstone/asupersync/commit/e25acf4d))
- Then later reversed: HashMap/HashSet back to BTreeMap/BTreeSet for deterministic iteration in tests ([`ae922e6`](https://github.com/Dicklesworthstone/asupersync/commit/ae922e6d), [`e15df42`](https://github.com/Dicklesworthstone/asupersync/commit/e15df427))

### Performance: Hot-Path Optimizations

- Waker cloning eliminated via will_wake() guards across async subsystems ([`da99eb3`](https://github.com/Dicklesworthstone/asupersync/commit/da99eb32))
- CAS loops refined to compare_exchange_weak with match-arm retry ([`2056653`](https://github.com/Dicklesworthstone/asupersync/commit/2056653a))
- Pre-size collections and reduce heap churn across core subsystems ([`b4b053b`](https://github.com/Dicklesworthstone/asupersync/commit/b4b053be))
- Scheduler task dispatch reordering, metrics provider caching, inline waker hot paths ([`8a9330c`](https://github.com/Dicklesworthstone/asupersync/commit/8a9330c6))
- SmallVec in HTTP connection pool cleanup ([`97a1506`](https://github.com/Dicklesworthstone/asupersync/commit/97a1506d))
- Pre-allocate in-flight VecDeque with front-ready fast path in streams ([`aa571c0`](https://github.com/Dicklesworthstone/asupersync/commit/aa571c0f))
- Per-waiter Arc+Mutex eliminated in MPSC channel ([`5df3dad`](https://github.com/Dicklesworthstone/asupersync/commit/5df3dad3))
- Zero-copy response encoding and byte-level header parsing ([`9c4adfe`](https://github.com/Dicklesworthstone/asupersync/commit/9c4adfec))
- Lock-free timed_count, SmallVec steal, and 3-phase next_task ([`58ed379`](https://github.com/Dicklesworthstone/asupersync/commit/58ed3790))
- Stack pinning via std::pin::pin! replacing Box::pin in scopes ([`3967aa7`](https://github.com/Dicklesworthstone/asupersync/commit/3967aa7a))

### RaptorQ Erasure Coding

- **Block-Schur low-rank hard-regime branch** and dense column index acceleration ([`5aaaf82`](https://github.com/Dicklesworthstone/asupersync/commit/5aaaf82c))
- **Runtime decoder policy framework** with sparse elimination refinement ([`178824e`](https://github.com/Dicklesworthstone/asupersync/commit/178824ee))
- Sparse-first column ordering, hybrid elimination, chunked GF256 scalar kernels ([`1104918`](https://github.com/Dicklesworthstone/asupersync/commit/1104918a))
- Precompute GF(256) nibble multiplication tables as compile-time statics ([`8a5fd02`](https://github.com/Dicklesworthstone/asupersync/commit/8a5fd02b))
- Queue-based peeling, hard-regime elimination, input validation, output verification ([`62d79c4`](https://github.com/Dicklesworthstone/asupersync/commit/62d79c40))
- Detect inconsistent overdetermined systems in Gaussian elimination ([`04700e7`](https://github.com/Dicklesworthstone/asupersync/commit/04700e74))
- Binary search peeling removal ([`b015331`](https://github.com/Dicklesworthstone/asupersync/commit/b0153319))
- Cap symbol pool initial allocation to per-object demand ([`040006e`](https://github.com/Dicklesworthstone/asupersync/commit/040006e2))

### Reactor and I/O

- **Edge-triggered, priority, and HUP support** added to epoll reactor ([`65a47d7`](https://github.com/Dicklesworthstone/asupersync/commit/65a47d70))
- io_uring ETIME handling, Windows modify stale socket cleanup ([`c93cc6b`](https://github.com/Dicklesworthstone/asupersync/commit/c93cc6ba))
- io_uring modify() rollback semantics and stale-registration pruning ([`77ae6aa`](https://github.com/Dicklesworthstone/asupersync/commit/77ae6aa9))
- fd registration hardened against reuse and stale deregistration ([`66eff16`](https://github.com/Dicklesworthstone/asupersync/commit/66eff16a))
- Windows: duplicate socket guard, best-effort deregister, stale handle helper ([`2399d00`](https://github.com/Dicklesworthstone/asupersync/commit/2399d007))
- Colocate token and fd maps in EpollReactor, eliminate O(n) fd scan ([`363b898`](https://github.com/Dicklesworthstone/asupersync/commit/363b8982))

### Scheduler

- **Harden intrusive heap** against stale or corrupted heap indices ([`790bc44`](https://github.com/Dicklesworthstone/asupersync/commit/790bc44e))
- Harden local task safety, deadline dispatch, panic recovery, counter underflow protection ([`b07d13f`](https://github.com/Dicklesworthstone/asupersync/commit/b07d13fd))
- CAS for counter saturation, validate queue tags, recover from foreign-pinned waiters ([`aae1b2f`](https://github.com/Dicklesworthstone/asupersync/commit/aae1b2f9))
- Three liveness bugs resolved in work-stealing and shutdown paths ([`9fe7960`](https://github.com/Dicklesworthstone/asupersync/commit/9fe79606))
- Try_local_any_lane for single-lock multi-lane local dispatch ([`9125605`](https://github.com/Dicklesworthstone/asupersync/commit/91256053))
- Pop_any_lane_with_hint for single-call multi-lane dispatch ([`975763d`](https://github.com/Dicklesworthstone/asupersync/commit/975763df))
- Cancel_streak accounting corrected, Parker made poison-tolerant ([`9b2a812`](https://github.com/Dicklesworthstone/asupersync/commit/9b2a812b))
- No-progress detection for tasks that never checkpoint via logical time ([`cfbc3d3`](https://github.com/Dicklesworthstone/asupersync/commit/cfbc3d3c))
- ABBA deadlock prevented in Stealer::steal() lock ordering ([`9f00fae`](https://github.com/Dicklesworthstone/asupersync/commit/9f00faed))

### Formal Verification (Lean)

- **Close/cancel protocol totality proofs** with CI manifest schema validation ([`4b4d7c0`](https://github.com/Dicklesworthstone/asupersync/commit/4b4d7c0d))
- **10 canonical-form decomposition theorems** for state ladder types ([`ad10ca4`](https://github.com/Dicklesworthstone/asupersync/commit/ad10ca4c))
- Cross-entity liveness contract with composition validation tests ([`cd1f7e9`](https://github.com/Dicklesworthstone/asupersync/commit/cd1f7e97))
- Reliability hardening contract and closed-loop impact report ([`017d4ee`](https://github.com/Dicklesworthstone/asupersync/commit/017d4eef))
- Preservation helper prelude with canonical reusable theorems ([`31e7ee4`](https://github.com/Dicklesworthstone/asupersync/commit/31e7ee41))

### Distributed

- **DistributorTransport trait** for replica symbol dispatch ([`781acac`](https://github.com/Dicklesworthstone/asupersync/commit/781acac1))
- Full snapshot application in RegionBridge ([`42365b1`](https://github.com/Dicklesworthstone/asupersync/commit/42365b16))
- Region apply_distributed_snapshot and set_budget for bridge recovery ([`46986e1`](https://github.com/Dicklesworthstone/asupersync/commit/46986e13))
- Verified symbols can replace unverified; tolerate rejected symbols ([`18481eb`](https://github.com/Dicklesworthstone/asupersync/commit/18481ebd))
- ESI acceptance range widened for high-loss recovery scenarios ([`38c4e37`](https://github.com/Dicklesworthstone/asupersync/commit/38c4e37d))
- Recovery collector verified flag not trusted when verify_integrity is enabled ([`1472e42`](https://github.com/Dicklesworthstone/asupersync/commit/1472e425))

### Combinator and Service Layer

- **Async barrier rewrite** from synchronous Condvar to Future-based ([`1079a50`](https://github.com/Dicklesworthstone/asupersync/commit/1079a501))
- ConcurrencyLimit rewritten as async state machine ([`4282f82`](https://github.com/Dicklesworthstone/asupersync/commit/4282f82d))
- Circuit breaker CallGuard prevents probe permit leak on panic ([`21fb6d1`](https://github.com/Dicklesworthstone/asupersync/commit/21fb6d12))
- BulkheadPermit converted to RAII guard with Drop, fixes zombie queue capacity leak ([`81e80be`](https://github.com/Dicklesworthstone/asupersync/commit/81e80bea))
- Bulkhead cancel releases granted-but-unclaimed permits ([`08721816`](https://github.com/Dicklesworthstone/asupersync/commit/08721816))
- Lock ordering fixed in bulkhead, circuit breaker, and rate limiter ([`0dde97d`](https://github.com/Dicklesworthstone/asupersync/commit/0dde97db))
- RwLock metrics replaced with atomic counters on hot paths ([`335a6c8`](https://github.com/Dicklesworthstone/asupersync/commit/335a6c8a))
- RAII guards for connection slots and dispatch counters in transport ([`8feb047`](https://github.com/Dicklesworthstone/asupersync/commit/8feb0477))
- Drain pending queue after cancel returns a permit ([`698c425`](https://github.com/Dicklesworthstone/asupersync/commit/698c425e))

### Channel Correctness

- Broadcast channel recv protected from u64->usize truncation on 32-bit ([`3e6cb7d`](https://github.com/Dicklesworthstone/asupersync/commit/3e6cb7de))
- Cancellation-aware partition sends and fault buffer ownership safety ([`f889405`](https://github.com/Dicklesworthstone/asupersync/commit/f8894057))
- Flush errors propagated and undelivered messages requeued in fault channel ([`e2ce5dc`](https://github.com/Dicklesworthstone/asupersync/commit/e2ce5dca))
- Reorder buffer pre-allocation preserved across flushes ([`7ee583a`](https://github.com/Dicklesworthstone/asupersync/commit/7ee583a2))

### Supervision

- Configurable tolerance added to RestartStormMonitor ([`9225331`](https://github.com/Dicklesworthstone/asupersync/commit/92253312))

### Database

- MySQL auth nonce parsing and PostgreSQL error handling robustness ([`752e164`](https://github.com/Dicklesworthstone/asupersync/commit/752e164e))
- MySQL: disambiguate 0x00 data rows from OK terminators in DEPRECATE_EOF mode ([`cfd1792`](https://github.com/Dicklesworthstone/asupersync/commit/cfd17929))
- MySQL: use negotiated capabilities for result-set parsing ([`4197df9`](https://github.com/Dicklesworthstone/asupersync/commit/4197df9f))
- PostgreSQL: return Ok after successful SCRAM authentication ([`173ed90`](https://github.com/Dicklesworthstone/asupersync/commit/173ed903))
- PostgreSQL: drain to ReadyForQuery on ErrorResponse ([`a0b8a5f`](https://github.com/Dicklesworthstone/asupersync/commit/a0b8a5f2))

### HTTP/2 Protocol

- Skipped queued outbound DATA for reset/closed streams ([`e736975`](https://github.com/Dicklesworthstone/asupersync/commit/e7369754))
- Reject PUSH_PROMISE with promised stream ID 0 per RFC 7540 ([`b8546e4`](https://github.com/Dicklesworthstone/asupersync/commit/b8546e45))
- Wire role-aware settings into connection, reject server ENABLE_PUSH ([`9111259`](https://github.com/Dicklesworthstone/asupersync/commit/91112595))
- Enforce RFC 7540 idle stream connection errors ([`b434c29`](https://github.com/Dicklesworthstone/asupersync/commit/b434c291))
- RFC 7540/7541 conformance hardening and HPACK security fixes ([`995196e`](https://github.com/Dicklesworthstone/asupersync/commit/995196e2))
- CONTINUATION on closed streams and headers_complete corruption prevented ([`fa79c39`](https://github.com/Dicklesworthstone/asupersync/commit/fa79c392))

### Sync Primitives

- Cancellation-safe barrier, lost-wakeup prevention in Notify, wake-under-lock elimination in Semaphore ([`f4ed526`](https://github.com/Dicklesworthstone/asupersync/commit/f4ed5264))
- Broadcast-cancelled Notify waiter prevented from leaking stored token ([`686716c`](https://github.com/Dicklesworthstone/asupersync/commit/686716c6))
- Mutex baton-passing coverage and OnceCell::set() retry on cancelled initializer ([`b2406c6`](https://github.com/Dicklesworthstone/asupersync/commit/b2406c6b))
- OnceCell queued waker refreshed on re-poll in get_or_init ([`c5a2dd0`](https://github.com/Dicklesworthstone/asupersync/commit/c5a2dd0a))
- Pool return-waker notification, contended_mutex poison discrimination ([`ca438a3`](https://github.com/Dicklesworthstone/asupersync/commit/ca438a34))
- BarrierWaitFuture Drop impl and type-erased ConcurrencyLimit acquire future ([`d5b0b95`](https://github.com/Dicklesworthstone/asupersync/commit/d5b0b950))

### Determinism

- HashMap migrated to DetHashMap across determinism-sensitive paths ([`bf17982`](https://github.com/Dicklesworthstone/asupersync/commit/bf179823))
- DetHasher hardened for portable hashing with little-endian encoding ([`556b5d3`](https://github.com/Dicklesworthstone/asupersync/commit/556b5d33))

### Net

- Bind/reuseaddr/reuseport configuration before TcpSocket::connect ([`50fd1f2`](https://github.com/Dicklesworthstone/asupersync/commit/50fd1f27))
- UnixDatagram::bind prevented from deleting non-socket files ([`61bdbdd`](https://github.com/Dicklesworthstone/asupersync/commit/61bddbda))
- UnixListener::bind only removes stale socket files, refuses non-socket paths ([`8fd90c5`](https://github.com/Dicklesworthstone/asupersync/commit/8fd90c55))
- TCP and Unix split locks held across driver.register() to prevent EEXIST race ([`41de223`](https://github.com/Dicklesworthstone/asupersync/commit/41de2239))

### WebSocket

- Cancel-safety and pong encoding fixed in split halves ([`27ee9ce`](https://github.com/Dicklesworthstone/asupersync/commit/27ee9cea))
- Reserved close codes rejected and 1-byte close payloads per RFC 6455 ([`0eb5467`](https://github.com/Dicklesworthstone/asupersync/commit/0eb5467b))
- Frame codec hardened for RFC 6455: minimal encoding, MSB, close reason ([`178ecaf`](https://github.com/Dicklesworthstone/asupersync/commit/178ecafc))
- Server-selected subprotocol validated against client request per RFC 6455 ([`717ed35`](https://github.com/Dicklesworthstone/asupersync/commit/717ed35c))

### Test Coverage Expansion

- **Massive B10 test wave campaign** (waves 1--87): ~2,000+ new tests covering pure data-type invariants across every module
- Comprehensive E2E test suite for QUIC/H3 (72 scenarios) ([`d317506`](https://github.com/Dicklesworthstone/asupersync/commit/d3175068))
- Database: 109 unit tests for postgres, sqlite, and migration modules ([`fa7fab2`](https://github.com/Dicklesworthstone/asupersync/commit/fa7fab29))
- Cancellation protocol and race-drain conformance tests ([`99ee740`](https://github.com/Dicklesworthstone/asupersync/commit/99ee7409))

---

## [v0.2.0](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.0) -- 2026-02-15 (Tag)

> 396 commits since v0.1.1 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.1.1...v0.2.0)

Major version bump covering formal verification, deep audit, and RaptorQ decoder rewrite.

### Formal Verification (Lean 4)

- **Track-2 declaration-order stabilization** closed ([`ecc2921`](https://github.com/Dicklesworthstone/asupersync/commit/ecc29215))
- Obligation stability theorems registered and frontier tests hardened ([`96caeba`](https://github.com/Dicklesworthstone/asupersync/commit/96caeba8))
- Refinement map enriched with ownership, routing metadata, conformance tests ([`3c47575`](https://github.com/Dicklesworthstone/asupersync/commit/3c47575a))
- Lean proof-guided performance opportunity map ([`7cbb175`](https://github.com/Dicklesworthstone/asupersync/commit/7cbb1755), [`4cd59ec`](https://github.com/Dicklesworthstone/asupersync/commit/4cd59ec5))
- Track 2 burndown dashboard and CI verification profiles ([`cacb264`](https://github.com/Dicklesworthstone/asupersync/commit/cacb2648))
- Lean smoke gate job for pull requests ([`8800e82`](https://github.com/Dicklesworthstone/asupersync/commit/8800e82f))
- Proof-aware review workflow, artifact contract tests ([`68d09cc`](https://github.com/Dicklesworthstone/asupersync/commit/68d09cc1))

### RaptorQ Decoder

- **RFC 6330 tuple semantics** and repair equation generation ([`d8c37ad`](https://github.com/Dicklesworthstone/asupersync/commit/d8c37ad4))
- **RFC 6330 Table 2 lookup** replacing ad-hoc parameter derivation ([`5bf62fb`](https://github.com/Dicklesworthstone/asupersync/commit/5bf62fb7))
- **RFC 6330 golden vector conformance suite** ([`666d705`](https://github.com/Dicklesworthstone/asupersync/commit/666d705a))
- **Metamorphic property erasure-recovery** test battery ([`fe0d7de`](https://github.com/Dicklesworthstone/asupersync/commit/fe0d7dee))
- GF256 AVX2 and NEON SIMD intrinsics with feature-gated unsafe ([`4c51ee6`](https://github.com/Dicklesworthstone/asupersync/commit/4c51ee64))
- SIMD kernel dispatch infrastructure with AVX2/NEON scaffolds ([`47ed283`](https://github.com/Dicklesworthstone/asupersync/commit/47ed283a))
- Legacy soliton-based repair path removed, unified on RFC 6330 tuples ([`1c062a5`](https://github.com/Dicklesworthstone/asupersync/commit/1c062a50))
- Full pivoting in systematic constraint solver ([`a720f11`](https://github.com/Dicklesworthstone/asupersync/commit/a720f115))
- Minimum-degree row selection for constraint matrix pivoting ([`957c50b`](https://github.com/Dicklesworthstone/asupersync/commit/957c50b4))
- Deterministic D6 E2E scenario runner with profile support ([`da10a1a`](https://github.com/Dicklesworthstone/asupersync/commit/da10a1a0))
- Deterministic pivot tie-breaking tests and GF256 replay catalog ([`96dc92d`](https://github.com/Dicklesworthstone/asupersync/commit/96dc92d5))
- Canonical test log schema (D7) with failure context migration ([`49965c2`](https://github.com/Dicklesworthstone/asupersync/commit/49965c2e))
- SIMD intrinsics made opt-in for stable Rust compatibility ([`5a6a753`](https://github.com/Dicklesworthstone/asupersync/commit/5a6a753c))

### Runtime Correctness

- Macaroon discharge first-party caveats evaluated during verification ([`79fc52a`](https://github.com/Dicklesworthstone/asupersync/commit/79fc52af))
- Spurious cancel prevented when dropping ready JoinFuture ([`8834c12`](https://github.com/Dicklesworthstone/asupersync/commit/8834c12e))
- Scheduler collision slots collapsed when task generations drain ([`b202312`](https://github.com/Dicklesworthstone/asupersync/commit/b202312b))
- Blocking pool idle-thread retirement uses atomic CAS to prevent undershoot ([`441c7f5`](https://github.com/Dicklesworthstone/asupersync/commit/441c7f5c))
- Atomic saturating_decrement and polls_remaining consumption ([`467fcd3`](https://github.com/Dicklesworthstone/asupersync/commit/467fcd3b))
- Governor_interval=0 normalization and env config coverage expanded ([`38bd7e1`](https://github.com/Dicklesworthstone/asupersync/commit/38bd7e10))
- LeakEscalation threshold=0 clamped to 1 ([`a9442b5`](https://github.com/Dicklesworthstone/asupersync/commit/a9442b53))
- Region heap alloc made transactional w.r.t. stats ([`91f002b`](https://github.com/Dicklesworthstone/asupersync/commit/91f002b7))

### Channel and Sync

- Wake outside lock in broadcast and oneshot channels ([`a821183`](https://github.com/Dicklesworthstone/asupersync/commit/a8211831))
- Wake-under-lock deadlock prevented in mpsc sender cascade ([`c90c4ad`](https://github.com/Dicklesworthstone/asupersync/commit/c90c4ade))
- Integer-precision drift calculation and exhaustive waker cleanup on terminal paths ([`f0a7ce7`](https://github.com/Dicklesworthstone/asupersync/commit/f0a7ce7c))
- Double-panic abort prevented in mpsc and watch channel Drop impls ([`47d2c03`](https://github.com/Dicklesworthstone/asupersync/commit/47d2c03d), [`add13a3`](https://github.com/Dicklesworthstone/asupersync/commit/add13a3d))
- Waker lifecycle, permit semantics, and evidence emission fixes ([`5136714`](https://github.com/Dicklesworthstone/asupersync/commit/51367145))
- Waker-while-locked hazards eliminated in TCP and WebSocket split halves ([`6004fc3`](https://github.com/Dicklesworthstone/asupersync/commit/6004fc3f))

### Reactor

- events.len() corrected for kqueue, macOS kqueue, and Windows IOCP poll ([`775ffdf`](https://github.com/Dicklesworthstone/asupersync/commit/775ffdfb))
- epoll poll returns count of actually stored events ([`5d74e64`](https://github.com/Dicklesworthstone/asupersync/commit/5d74e642))
- Adapted to polling 3.11 Events API ([`b01c40c`](https://github.com/Dicklesworthstone/asupersync/commit/b01c40c4))
- io_uring fcntl pre-flight check for modify() early stale-fd pruning ([`4b87067`](https://github.com/Dicklesworthstone/asupersync/commit/4b870679))
- Poll_events mutex guard dropped before returning from EpollReactor::poll ([`5da8d49`](https://github.com/Dicklesworthstone/asupersync/commit/5da8d49d))

### Networking

- TCP split test guard drops and CombinedWaker for owned split halves ([`7a8d7cf`](https://github.com/Dicklesworthstone/asupersync/commit/7a8d7cf7))
- MX records sorted by RFC-priority order on construction ([`98b4ec2`](https://github.com/Dicklesworthstone/asupersync/commit/98b4ec24))
- Non-UTF8 Unix paths supported in io-uring path_to_cstring helpers ([`bc4cb65`](https://github.com/Dicklesworthstone/asupersync/commit/bc4cb65e))
- TCP/Unix split combined waiter interest on re-registration ([`b035ae6`](https://github.com/Dicklesworthstone/asupersync/commit/b035ae68), [`c841b9d`](https://github.com/Dicklesworthstone/asupersync/commit/c841b9da))

### H2 Protocol

- last_stream_id tracked for GOAWAY, CONTINUATION interleaving prevented ([`b94f07b`](https://github.com/Dicklesworthstone/asupersync/commit/b94f07bd))
- last_stream_id pollution on rejected HEADERS prevented ([`ed85b9b`](https://github.com/Dicklesworthstone/asupersync/commit/ed85b9bd))
- Zero-increment WINDOW_UPDATE on stream is stream error, not connection ([`1f65a18`](https://github.com/Dicklesworthstone/asupersync/commit/1f65a187))
- RFC 7540 error classification corrected for PRIORITY and WINDOW_UPDATE ([`2965fab`](https://github.com/Dicklesworthstone/asupersync/commit/2965fabf))

### Combinator

- Select polls both futures each tick so loser gets initialized ([`63525618`](https://github.com/Dicklesworthstone/asupersync/commit/63525618))
- join2 dual-cancellation strengthening and SelectAllDrain simultaneous-ready safety ([`520c561`](https://github.com/Dicklesworthstone/asupersync/commit/520c561e))
- Bracket catch panics from release future during Drop to prevent abort ([`49d6ac7`](https://github.com/Dicklesworthstone/asupersync/commit/49d6ac7c))
- Bracket drives release future to completion when dropped during Releasing phase ([`41c0e45`](https://github.com/Dicklesworthstone/asupersync/commit/41c0e45b))
- Saturating arithmetic strengthened in circuit breaker, scheduler, transport ([`357bebd`](https://github.com/Dicklesworthstone/asupersync/commit/357bebd3))
- Map_reduce edge cases hardened ([`2cb3dba`](https://github.com/Dicklesworthstone/asupersync/commit/2cb3dba2))

### Choreography

- Loop label scoping and Continue projection bugs fixed ([`3621d7a`](https://github.com/Dicklesworthstone/asupersync/commit/3621d7a6))
- first_active_participant traverses inert Seq/Par prefixes ([`271b6da`](https://github.com/Dicklesworthstone/asupersync/commit/271b6da0))
- Loop codegen break, duplicate participant detection ([`7d6a2d1`](https://github.com/Dicklesworthstone/asupersync/commit/7d6a2d17))
- Parallel knowledge-of-choice validation, compensation stubs, LabRuntime tests ([`a9d7e13`](https://github.com/Dicklesworthstone/asupersync/commit/a9d7e13f))

### Deep Audit Campaign

- Extensive deep audit of major subsystems, all confirmed SOUND
- Scheduler (worker, local_queue, global_injector), gen_server, blocking_pool, io_driver, bulkhead, channel subsystem, transport/aggregator, fs/uring, tcp/split, sharded_state, resource_accounting, time/driver, kafka ([`82a9d3f`](https://github.com/Dicklesworthstone/asupersync/commit/82a9d3f3), [`85cc3a1`](https://github.com/Dicklesworthstone/asupersync/commit/85cc3a15), [`f0133e3`](https://github.com/Dicklesworthstone/asupersync/commit/f0133e32))

### Performance Tuning

- #[inline] on hot-path cancel check, Cx clone, DetRng PRNG methods ([`0451e25`](https://github.com/Dicklesworthstone/asupersync/commit/0451e256), [`9e0f2e8`](https://github.com/Dicklesworthstone/asupersync/commit/9e0f2e8d))
- Atomic orderings relaxed, scheduler allocations eliminated, Cx clone consolidated ([`027821f`](https://github.com/Dicklesworthstone/asupersync/commit/027821f4))
- Scheduler skip cancel-lane rebuild when re-promotion priority is same or lower ([`316e7f7`](https://github.com/Dicklesworthstone/asupersync/commit/316e7f73))
- SmallVec for hot-path waker collections ([`aa3b61a`](https://github.com/Dicklesworthstone/asupersync/commit/aa3b61a4))

### CI

- Tag-triggered builds and owner-routing in Lean failure payloads ([`bf8a3c4`](https://github.com/Dicklesworthstone/asupersync/commit/bf8a3c44))
- Lean smoke gate, full gate, and bundle config in CI profiles ([`cb9cd9a`](https://github.com/Dicklesworthstone/asupersync/commit/cb9cd9aa))
- Nightly toolchain pinned to 2026-02-05 for reproducible builds ([`ef2540c`](https://github.com/Dicklesworthstone/asupersync/commit/ef2540c0))

### Dependencies

- polling 2.8 to 3.11, opentelemetry{,_sdk} 0.28 to 0.31 ([`0cef3b6`](https://github.com/Dicklesworthstone/asupersync/commit/0cef3b6b))
- rusqlite 0.33 to 0.38, rcgen 0.13 to 0.14, lz4_flex 0.11 to 0.12, toml 0.8 to 1.0, webpki-roots 0.26 to 1.0 ([`1f5733f`](https://github.com/Dicklesworthstone/asupersync/commit/1f5733f3), [`f2e5164`](https://github.com/Dicklesworthstone/asupersync/commit/f2e51646), [`d7ea4cf`](https://github.com/Dicklesworthstone/asupersync/commit/d7ea4cfe))

### Observability

- Lock-free resource accounting ([`4c68494`](https://github.com/Dicklesworthstone/asupersync/commit/4c68494b))
- Conformance test runner (cancellation protocol and race-drain) ([`99ee740`](https://github.com/Dicklesworthstone/asupersync/commit/99ee7409))
- 88 new trace event tests, 31 trace integrity tests, 24 trace recorder tests ([`6cdab62`](https://github.com/Dicklesworthstone/asupersync/commit/6cdab62a), [`aa8f0a4`](https://github.com/Dicklesworthstone/asupersync/commit/aa8f0a44), [`d0fe05d`](https://github.com/Dicklesworthstone/asupersync/commit/d0fe05db))

---

## [v0.1.1](https://github.com/Dicklesworthstone/asupersync/tag/v0.1.1) -- 2026-02-07 (Tag)

> 3 commits since v0.1.0 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.1.0...v0.1.1)

- Exclude `.out` files from crate package and fix match arm syntax ([`67f660c`](https://github.com/Dicklesworthstone/asupersync/commit/67f660cc))
- Add `.tmp/` to `.gitignore` ([`e8f03f1`](https://github.com/Dicklesworthstone/asupersync/commit/e8f03f18))

---

## [v0.1.0](https://github.com/Dicklesworthstone/asupersync/tag/v0.1.0) -- 2026-02-06 (Tag)

> ~1,650 commits | Initial public milestone

The initial tagged milestone establishing the core async runtime with structured concurrency, cancel-correctness, and capability security.

### Core Runtime

- **Structured concurrency** with region-based task ownership -- every spawned task belongs to a region that closes to quiescence ([`33335ea`](https://github.com/Dicklesworthstone/asupersync/commit/33335ea3))
- **Cancel-correct protocol**: cancellation is request, drain, finalize -- never silent data loss
- **Capability-secure effects**: all effects flow through explicit `Cx` context; no ambient authority
- **Four-valued Outcome**: `Ok`, `Err`, `Cancelled(reason)`, `Panicked(payload)` with severity lattice
- **Lab runtime**: deterministic testing with virtual time, deterministic scheduling, and trace replay
- **Test oracle module** for runtime invariant verification ([`dc03abd`](https://github.com/Dicklesworthstone/asupersync/commit/dc03abd8))

### Channels (Two-Phase Send)

- **MPSC channel** with reserve/commit pattern ([`73dab81`](https://github.com/Dicklesworthstone/asupersync/commit/73dab815))
- **Oneshot channel** with reserve/commit pattern ([`0f478cd`](https://github.com/Dicklesworthstone/asupersync/commit/0f478cd9))
- **Broadcast channel** with two-phase send and lagging receiver detection
- **Watch channel** with borrow-and-clone semantics

### Sync Primitives

- Two-phase sync primitives with guard obligations ([`cb7b1f1`](https://github.com/Dicklesworthstone/asupersync/commit/cb7b1f1c))
- Mutex, RwLock, Semaphore, Barrier, Notify, OnceCell -- all cancel-aware with `&Cx`

### Combinators

- **join_all**, **race_all** (N-way), **select** (2-way), **first_ok**, **pipeline**, **map_reduce** ([`945414a`](https://github.com/Dicklesworthstone/asupersync/commit/945414a6), [`d04745b`](https://github.com/Dicklesworthstone/asupersync/commit/d04745bc), [`34fe222`](https://github.com/Dicklesworthstone/asupersync/commit/34fe2220), [`d457794`](https://github.com/Dicklesworthstone/asupersync/commit/d457794c))
- **Bulkhead** combinator with queue timeout ([`180dc9e`](https://github.com/Dicklesworthstone/asupersync/commit/180dc9ea))
- **Circuit breaker** with half-open probing
- **Bracket** combinator: cancel-safe resource acquisition with Drop-based release ([`fdb20e7`](https://github.com/Dicklesworthstone/asupersync/commit/fdb20e76))

### Time

- Sleep and Timeout primitives with explicit time sources ([`1a58619`](https://github.com/Dicklesworthstone/asupersync/commit/1a586194))
- Timer wheel for efficient timeout management
- Works with virtual time in lab runtime for deterministic testing

### Scheduler

- EDF (Earliest Deadline First) scheduling with bug fixes ([`3787abb`](https://github.com/Dicklesworthstone/asupersync/commit/3787abbf))
- Three-lane priority scheduler
- Work-stealing with local queues and global injector

### I/O and Networking

- TCP, UDP, Unix stream/datagram support
- I/O conformance test suite (IO-001 through IO-007) ([`6a9a876`](https://github.com/Dicklesworthstone/asupersync/commit/6a9a876f))
- HTTP/1 and HTTP/2 codec and connection management
- TLS with ALPN negotiation

### Supervision (Spork/OTP Model)

- **GenServer** with init/terminate lifecycle and trace schema ([`c6a9068`](https://github.com/Dicklesworthstone/asupersync/commit/c6a90682))
- **Restart storm detection** via anytime-valid e-processes ([`500ac33`](https://github.com/Dicklesworthstone/asupersync/commit/500ac33c))
- **Conformal calibration** for health thresholds ([`b0ed01f`](https://github.com/Dicklesworthstone/asupersync/commit/b0ed01f9))
- **CrashPack**: golden snapshots, replay tests, artifact writer capability, versioned manifest ([`267153c`](https://github.com/Dicklesworthstone/asupersync/commit/267153cd), [`3ba14c7`](https://github.com/Dicklesworthstone/asupersync/commit/3ba14c75))
- **Link/Monitor system** with LinkedExit cancel kind and trap-exit policy ([`756d65d`](https://github.com/Dicklesworthstone/asupersync/commit/756d65db))
- NamePermit reserve/commit with linear obligations ([`13cbc6a`](https://github.com/Dicklesworthstone/asupersync/commit/13cbc6ae))
- Deterministic collision resolution for NameRegistry ([`77cd887`](https://github.com/Dicklesworthstone/asupersync/commit/77cd887e))
- AppSpec compiled to SupervisorSpec + Regions ([`50e566c`](https://github.com/Dicklesworthstone/asupersync/commit/50e566c9))

### RaptorQ (FEC)

- Core symbol types and encoding/decoding pipeline
- Benchmark baselines ([`74784392`](https://github.com/Dicklesworthstone/asupersync/commit/74784392))

### Formal Verification

- Determinism oracle ([`1b33dad`](https://github.com/Dicklesworthstone/asupersync/commit/1b33dad4))
- Divergent prefix minimizer ([`3d38c21`](https://github.com/Dicklesworthstone/asupersync/commit/3d38c21a))

### Documentation

- Comprehensive README with architecture diagrams, tokio mapping table, and quick examples
- Spork OTP mental model section ([`f26f319`](https://github.com/Dicklesworthstone/asupersync/commit/f26f319f))
- Networking, database, channels, and observability architecture sections ([`c367fd5`](https://github.com/Dicklesworthstone/asupersync/commit/c367fd54))

---

[Unreleased]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.10...HEAD
[v0.4.10]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.9...v0.4.10
[v0.4.9]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.8...v0.4.9
[v0.4.8]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.7...v0.4.8
[v0.4.7]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.6...v0.4.7
[v0.4.6]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.5...v0.4.6
[v0.4.5]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.4...v0.4.5
[v0.4.4]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.3...v0.4.4
[v0.4.3]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.2...v0.4.3
[v0.4.2]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.1...v0.4.2
[v0.4.1]: https://github.com/Dicklesworthstone/asupersync/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.10...v0.4.0
[v0.3.10]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.4...v0.3.10
[v0.3.4]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.3...v0.3.4
[v0.3.3]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.2...v0.3.3
[v0.3.2]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/Dicklesworthstone/asupersync/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.9...v0.3.0
[v0.2.9]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.8...v0.2.9
[v0.2.8]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.7...v0.2.8
[v0.2.7]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.6...v0.2.7
[v0.2.6]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.5...v0.2.6
[v0.2.5]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.4...v0.2.5
[v0.2.4]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.3...v0.2.4
[v0.2.3]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.0...v0.2.2
[v0.2.0]: https://github.com/Dicklesworthstone/asupersync/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/Dicklesworthstone/asupersync/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/Dicklesworthstone/asupersync/commits/v0.1.0
