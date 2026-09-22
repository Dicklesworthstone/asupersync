# Native SWIM gossip and failure-detection driver

`distributed::membership::driver::UdpSwimDriver` drives the maintained `Swim`
state machine through `UdpMembershipTransport`, inside an existing native runtime
task. The detector no longer requires an application to manually interleave
`tick`, `handle`, UDP send, and UDP receive calls. It has no implicit task spawn.

## Explicit topology and runtime ownership

Construct the driver with `new_trusted_network(local, protocol, seed, peers,
transport, bounds)`. `peers` is a `BTreeMap<NodeId, SocketAddr>`: names and
addresses are supplied by the owner, never discovered from a received datagram.
The caller supplies an already-bound, unconnected `UdpSocket` through the existing
membership adapter. The local identity cannot also be a peer, peer addresses must
be distinct, and identities are bounded to 255 UTF-8 bytes.

Run the future inside a native runtime context with an I/O driver. The supplied
`Cx` must carry its explicit timer driver. The detector uses that timer for both
logical SWIM time and maintenance deadlines; a missing timer or active I/O context
is a typed refusal rather than a fallback OS thread.

```rust,ignore
use std::sync::Arc;
use asupersync::sync::Notify;

// `driver` is configured with caller-owned topology and a bound transport.
// `cx` is the current native runtime task's context.
let observer = driver.observer();
let stop = Arc::new(Notify::new());
let signal = Arc::clone(&stop);
let mut handle = cx.spawn(move |child| async move {
    driver.run_until(&child, signal.notified()).await
})?;

let initial = observer.snapshot();
let next = observer.changed(initial.revision).await;
// Inspect next.status, next.stats and next.membership. Seeded Alive is not
// evidence that a peer answered a probe: received traffic is counted separately.

stop.notify_one();
let report = handle.join(cx).await?;
// Inspect report.outcome. Ok means local Leave datagram acceptance, not delivery.
```

`run(cx)` runs until cancellation or a typed failure. `run_until(cx, stop)` starts
a graceful departure when the owner's stop future completes. Context cancellation
wins a simultaneous stop. It requests detector shutdown, calls the ordinary
checkpoint for acknowledgement subject to masking, and returns a typed cancelled
outcome. The driver never detaches another task. Dropping an unstarted driver or
running future drops its socket and publishes `Dropped`, not graceful completion.

## Progress and bounded resources

Each poll services a bounded receive batch, due protocol maintenance, and a bounded
send batch. Ready ACKs have a bounded opportunity to arrive before a timeout is
concluded. An incoming flood cannot indefinitely postpone ticks, and a pending
send cannot prevent reads, cancellation, or maintenance. Saturating a ready batch
requests another poll; an idle loop parks on readiness, its timer, and cancellation.
The socket currently has one reactor interest slot; the maintenance timer bounds
retry latency when one direction replaces the other's readiness interest.

Outbound packets are encoded once. `Pending` retains exactly those bytes without
rerunning gossip selection. Ordinary packets have a finite queue age; expiry and
network send errors count as losses, never successful sends. A full outbox returns
`OutboxFull`. No oldest-packet eviction hides overflow. Partial UDP progress is
refused rather than counted as a complete send. The core's member/relay cap is
tightened to the configured peer ceiling. IDs in gossip subjects, accusers, and
indirect targets must belong to the configured topology or local node.

The raw receive buffer is a fixed 64 KiB. Source and MTU checks precede packet
decoding. Ingress rejects trailing/noncanonical bytes in addition to codec errors.
Encoded outbox storage is bounded by MTU times queue capacity; transient core
output, member state, and gossip are bounded by the admitted topology/core limits.
Allocator overhead, consumer-retained snapshots and observer waiters are separate.
These are logical limits, not exact RSS, WAN throughput or poll-duration guarantees.

## Observations, departure, and authority

`SwimObserver` owns only a bounded `MembershipView`, counters and notification
state, not the socket or task. `changed(revision)` coalesces publications. For the
membership event history, compare your absolute cursor with `compact_base()`;
lagged consumers must reconcile the snapshot rather than silently skip transitions.
Terminal driver status means the view is no longer a live failure detector.

Graceful stop discards unsent ordinary probes, stops receiving/generating probes,
and sends one explicit Leave rumor to every configured peer. It retains pending
Leave bytes until socket acceptance or the finite departure deadline. Cancellation
and drop do not invent Leave delivery. The transport is retired before a returned
terminal report is published. Observers can outlive the driver without retaining it.

This constructor preserves **unauthenticated** legacy SWIM UDP. An address allowlist
is not authentication and cannot prevent source spoofing or malicious configured
peers. Use it only within an independently trusted network boundary. It is a
failure-detection data plane, not the authenticated membership decision service.
It never automatically grants/revokes leases, changes remote authority, or claims
Byzantine safety. Dead/Left identities keep the core's terminal semantics; automatic
same-identity restart/re-enrollment, encrypted/authenticated gossip, cross-host proof,
and authoritative discovery orchestration remain separate work.

## Validation commands and status

First run the existing native cancellation baseline, then the focused new tests:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-swim-driver-validation cargo test -p asupersync --test runtime_abort_vs_cancel_semantics_audit
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-swim-driver-validation cargo test -p asupersync --lib distributed::membership::driver:: -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-swim-driver-validation cargo test -p asupersync --test swim_driver_native -- --nocapture
```

The implementation adds 13 focused unit tests and three real native loopback test
sources. They include exact-byte Pending retry, queue overflow, malformed/topology
refusal, traffic floods, indirect probing through three actual state machines,
no-input failure detection, Leave deadlines, observer lag, owner drop, current-thread
and two-worker probe/ACK exchange, and parked cancellation followed by actual
suspicion/death and socket release.

These Rust tests were **not compiled or executed** in the authoring environment.
Rust, Cargo, rustfmt and RCH were unavailable. Patch/file checks are not Rust
validation, independent interoperability, release proof, or closure of the broader
snapshot/SWIM/authority gap. Related bead:
`asupersync-gap-snapshot-transport-swim-pbft-e6drlx` (remains open).
