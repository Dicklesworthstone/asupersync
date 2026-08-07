# io_uring architecture and capability inventory

<!-- BEGIN IO URING CAPABILITY INVENTORY -->

Bead: `asupersync-sched-hot-path-perf-bt4y5f.7.1`

Machine artifact: `artifacts/io_uring_capability_inventory_v1.json`

Static contract: `tests/io_uring_capability_inventory_contract.rs`

## Disposition

The current implementation is a useful, feature-gated readiness backend, not
an advanced io_uring data plane. `IoUringReactor` submits one-shot `PollAdd`
and `PollRemove` operations. A classic registered-buffer pool exists beside
that readiness path, but no live operation consumes one of its buffer IDs.
A bounded provided-buffer-group probe now performs one selected receive and
cleanup, but no runtime data-plane operation uses that group. Separate bounded
probes exercise multishot accept and dependency-gated multishot receive without
wiring either into the TCP data plane. Mapped buffer rings remain absent. A
requested-only SQPOLL probe creates a bounded temporary ring and completes one
NOP, while SQPOLL remains off by default and absent from the runtime data plane.

URING-1 freezes that boundary and the contract for evaluating later work. It
does not change production behavior. Kernel versions are metadata; bounded
operation probes and their terminal results are the support authority.

## Live architecture

This inventory follows the Linux/Android factory path where io_uring can be
selected; its filesystem ring surfaces are Linux-only. `KqueueReactor`,
`IocpReactor`, `BrowserReactor`, and `LabReactor` are live elsewhere, but none
is reachable as an io_uring fallback, so they are outside this campaign matrix.

The machine artifact pins 28 source and evidence files and classifies 19
surfaces. The important ownership flow is:

1. `Cargo.toml` enables the optional dependency edge.
2. `runtime::reactor::create_reactor` tries `IoUringReactor::new()` and falls
   back to the live `EpollReactor` backend if construction fails.
3. If epoll construction also fails, `RuntimeBuilder` continues without an
   `IoDriver`, retains a typed `URING-FB-REACTOR-UNAVAILABLE` runtime snapshot,
   emits one startup warning, and socket paths re-poll.
4. `RuntimeBuilder` otherwise installs the selected platform reactor unless a
   caller injects a reactor or driver, or disables the whole platform path.
5. `IoDriver` consumes only the generic `Reactor` readiness interface.
6. Default `File` owned-buffer helpers and `OpenOptions` offload blocking work,
   while the default poll traits issue direct file syscalls on their caller;
   `IoUringFile` remains a separate opt-in type.
7. TCP listeners, full streams, and owned split halves perform ordinary socket
   I/O after readiness. Borrowed split halves have no reactor registration and
   use one-millisecond timer backoff when a timer exists and immediate re-wake
   otherwise.
8. Immutable `Bytes` can be empty, borrow a static slice, or share heap-backed
   `Arc<Vec<u8>>` storage. `BytesMut` exclusively owns a growable `Vec<u8>`;
   neither type tracks a kernel lease.
9. Linux-only `IoUringFile`, path operations, and directory operations use
   separate rings. `IoUringFile` locks its ring and drives completion
   synchronously inside poll; none consumes the reactor's registered pool.

`src/runtime/reactor/uring.rs` is historical source. The live module mapping in
`src/runtime/reactor/mod.rs` explicitly maps module `uring` to
`src/runtime/reactor/io_uring.rs`. The historical kernel-version helper is not
the runtime inspector and cannot establish operation support.

## Current surface matrix

| Surface | Current state | Material gap | Next owner |
|---|---|---|---|
| Build edge | optional feature and dependency | compilation does not establish host support | URING-2 |
| Backend factory | try io_uring, then epoll, retain immutable selection metadata, and probe five requested advanced operations | mapped buffer-ring probe remains | URING-2 |
| Reactor | live one-shot readiness | no advanced data-plane operations | URING-2 onward |
| Epoll fallback | live Linux/Android readiness backend with feature-disabled or ring-create receipt | mapped buffer-ring probe remains | URING-2 |
| Buffer scaffold | cached fixed-buffer and provided-group selected-receive probes, classic kernel registration, and manual IDs | probe buffers and IDs remain unused by runtime data-plane I/O | URING-3 |
| Default file API | owned helpers offload; poll traits block directly | separate from opt-in io_uring and unsuitable as an async comparator | URING-7 |
| File I/O | Linux-only file-local ring driven synchronously in poll | no fixed/selected buffer and unsuitable as an async comparator | URING-3 |
| Path and directory I/O | Linux-only independent one-operation rings | outside one capability/fallback model | URING-2 |
| TCP listener | ordinary accept plus readiness; bounded multishot accept probe is separate | no runtime multishot lifecycle | URING-4 |
| TCP full and owned split streams | ordinary socket I/O plus readiness | no selected-buffer leases | URING-5 |
| TCP borrowed split streams | timer backoff or immediate re-wake | no reactor registration or advanced receive | URING-5 |
| `Bytes` / `BytesMut` | empty/static/shared heap bytes; exclusive mutable `Vec<u8>` | no kernel-in-flight lease state | URING-3 |
| Builder | whole-reactor enable/disable, injection, and typed per-capability policy | live operation outcomes remain | URING-2 |
| No-reactor fallback | runtime continues with socket re-polls and retains a typed terminal snapshot | data-plane behavior remains the incumbent re-poll path | URING-2 |
| Inspector | generic `IoStats` plus immutable driver/runtime capability snapshots | one capability probe remains | URING-2 |
| Tests | mock pool, live readiness, filesystem lifecycle | no advanced-capability matrix | URING-7 |
| Benchmark | synthetic completion bookkeeping | no real-socket comparison | URING-7 |
| Boundary ledger | four relevant rows and 42 locators | 20 filesystem locators are stale; all 21 reactor locators are exact | URING-3 |
| Historical file | excluded from live module graph | version heuristic is not authority | URING-2 |

The four pinned rows contain 42 locators. All 21 reactor locators and one
filesystem locator match exactly; 20 filesystem locators retain their pattern
at a different line. The artifact reconciles every recorded locator to its
current line. URING-3 owns the remaining filesystem alignment.

Five material source-accuracy records are explicit. The file module header names
`OPENAT` and `CLOSE` as ring operations even though constructors call
`libc::openat` synchronously and no corresponding ring opcode consumer exists;
it also claims nonblocking asynchronous completion although poll drives
`submit_and_wait`. The directory header misclassifies the `MkDirAt` path. The
former hardcoded buffer-support answer is resolved at the capability-probe
boundary by a cached, bounded fixed-opcode, register, fixed write/read,
completion-integrity, and unregister sequence; the runtime data plane still
does not consume the registered pool. Finally, an E2E comment labels default
`fs::write`/`fs::read` as io_uring evidence. Unresolved statements may not be
promoted into capability or execution evidence.

## Existing evidence

| Evidence | What it currently covers | What it does not cover |
|---|---|---|
| Inline reactor tests | intended readiness and pool bookkeeping plus deterministic fixed/provided/SQPOLL completion classification and force-off gating | runtime data-plane advanced I/O |
| Buffer-pool conformance test | simulated API shape | kernel registration, live acquisition, leases |
| Reactor integration and stress | one-shot readiness lifecycle | advanced buffer, multishot, or configured runtime SQPOLL paths |
| Filesystem E2E | opt-in file lifecycle and attribution | its mislabeled default-helper case, advanced buffers, network paths |
| Reactor benchmark | synthetic completion bookkeeping | kernel submission, real sockets, syscall or throughput deltas |

All five evidence rows are source-present but unexecuted by URING-1. The mock
pool's registration method also does not retain the configuration later needed
by acquisition, so it is not even a self-contained live-pool substitute.

## Capability levels

The six levers are independent. Support for one must never imply support for a
later one.

| Capability ID | Current state | Required before activation |
|---|---|---|
| `URING-CAP-FIXED-BUFFERS` | live registration probe plus scaffold; not used by the data plane | real fixed operation, linear lease, terminal drain |
| `URING-CAP-PROVIDED-GROUPS` | live bounded selected-receive probe; not used by the data plane | runtime lease and data-plane integration |
| `URING-CAP-MAPPED-BUFFER-RING` | absent | bounded mapped ring, lifetime proof, selection and return |
| `URING-CAP-MULTISHOT-ACCEPT` | live bounded loopback probe; not used by the data plane | runtime generation tags, bounded descriptor queue and listener lifecycle |
| `URING-CAP-MULTISHOT-RECV` | live dependency-gated multishot receive probe; not used by the data plane | runtime selected-buffer obligations, bounded queues and split-half cancellation |
| `URING-CAP-SQPOLL` | live requested-only temporary-ring and NOP probe; off by default | operator-configurable settings, runtime ring, cost visibility and rollback |

The ordinary readiness backend is already live, but it is deliberately not a
seventh advanced capability. It is the incumbent fallback that later levers
must preserve.

## Runtime probe contract

Every decision snapshot has exactly four semantic fields: `requested`,
`supported`, `active`, and `fallback_reason`. `supported` is a three-state value
(`SUPPORTED`, `UNSUPPORTED`, or `NOT_PROBED`) so forced-off and dependency-
blocked paths do not invent host support claims.

`fallback_reason` is never null. An active capability must be requested and
`SUPPORTED`, with `URING-FB-NONE`. A non-requested or forced-off capability is
inactive and `NOT_PROBED`, with its exact reason. An unsupported capability is
inactive with a classified unsupported reason. Any inconsistent tuple fails
closed to inactive with `URING-FB-UNKNOWN`. That reason is the sole invariant
exception: it preserves the received request/support fields for diagnosis while
forcing `active` to false.

The authority order is:

1. explicit typed force-off policy;
2. bounded operation probe and terminal cleanup;
3. opcode availability probe;
4. kernel metadata for diagnostics only.

The artifact defines one bounded probe sequence per capability:

- Fixed buffers register a bounded table, complete a fixed operation on a
  fixture descriptor, and unregister only after terminal completion.
- Provided groups require a selected receive whose completion reports the
  expected buffer ID, followed by group removal and drain.
- Mapped buffer rings require registration, selection, lease return, and clean
  unregister on one bounded ring.
- Multishot accept uses a loopback listener, two clients, MORE observations,
  cancellation, one terminal completion, and exactly-owned descriptors.
- Multishot receive uses a loopback stream pair, two payloads, unique leases,
  MORE observations, cancellation, and a zero-lease terminal state.
- SQPOLL requires an explicit typed request, constructs a separate two-entry
  ring with a one-millisecond idle, completes one NOP, classifies policy
  failures, and shuts its polling thread down cleanly. This probe does not
  configure the runtime's readiness ring.

Probe failures map only to frozen reason IDs:

| Capability | Allowed probe-failure reasons |
|---|---|
| Fixed buffers | `RING-CREATE`, `OP-UNSUPPORTED`, `RESOURCE`, `PROBE-ERROR` |
| Provided groups | `RING-CREATE`, `OP-UNSUPPORTED`, `RESOURCE`, `PROBE-ERROR` |
| Mapped buffer ring | `RING-CREATE`, `DEPENDENCY`, `OP-UNSUPPORTED`, `RESOURCE`, `PROBE-ERROR` |
| Multishot accept | `RING-CREATE`, `OP-UNSUPPORTED`, `RESOURCE`, `PROBE-ERROR` |
| Multishot receive | `RING-CREATE`, `DEPENDENCY`, `OP-UNSUPPORTED`, `RESOURCE`, `PROBE-ERROR` |
| SQPOLL | `RING-CREATE`, `PERMISSION`, `RESOURCE`, `PROBE-ERROR` |

Every table entry has the `URING-FB-` prefix in the machine registry. The
generic `UNKNOWN` reason is reserved for an invalid decision state, not a
normal operation-probe outcome.

Failure retains the ordinary path for that surface. A failed advanced probe
must not disable an independently working ordinary io_uring readiness backend.
If ordinary ring construction fails, epoll is selected. If epoll construction
also fails, runtime construction continues without a reactor. Socket paths use
timer backoff or immediate re-wake; `URING-FB-REACTOR-UNAVAILABLE` records that
terminal branch.

## Deterministic force-off

`IoUringCapabilityPolicy` is now carried from `RuntimeBuilder` into immutable
reactor construction. Production code does not read an ambient environment
variable to control the hot path. Unrequested capabilities are not probed, and
the per-capability force-off mask takes effect before an injected probe outcome.

The deterministic fixture accepts requested states and bounded probe outcomes
without consulting the host. A requested but forced-off capability has
`supported=NOT_PROBED`, `active=false`, and
`fallback_reason=URING-FB-FORCED-OFF`.

The existing `enable_platform_reactor(false)` remains a whole-platform escape
hatch. `with_reactor` and `with_io_driver` remain explicit injection seams.
They are not substitutes for the per-capability decision model.

## Fallback and observability

The artifact freezes 14 bounded-cardinality reason IDs. They cover active
success (`NONE`), not-requested, feature-disabled, unsupported target,
forced-off, ring-creation, total reactor unavailability, unsupported operation,
permission, resource, probe-error, dependency, no-win, and unknown states.
Unknown or inconsistent state fails closed.

The factory order is explicit injection, requested ordinary io_uring, epoll,
then no reactor with socket re-poll fallback. Whole-reactor force-off uses
`URING-FB-FORCED-OFF`; ordinary ring creation failure uses
`URING-FB-RING-CREATE`; exhaustion of the reactor chain uses
`URING-FB-REACTOR-UNAVAILABLE`. Feature-disabled and ring-creation fallback are
retained in the immutable driver snapshot. The terminal no-reactor branch
stores the same bounded model in `RuntimeState`, exposed through
`Runtime::io_reactor_capability_snapshot` and
`RuntimeHandle::io_reactor_capability_snapshot`, even though no
`IoDriverHandle` exists.

`IoDriverHandle::stats` continues to expose polls, received events, dispatched
wakers, unknown tokens, registrations, and deregistrations. The new
`IoDriverHandle::capability_snapshot` separately exposes immutable bounded
control-plane state:

- backend;
- capability ID;
- requested;
- supported;
- active;
- fallback reason.

This checkpoint supplies five conservative support outcomes. Requested fixed
buffers run a cached temporary-ring probe that checks fixed read/write opcodes,
registers one eight-byte buffer, completes a fixed write and read through a
nonblocking Unix stream pair, verifies both completions and the returned data,
then unregisters. Requested provided groups run a separate cached temporary
ring that provides one buffer, completes a selected receive, verifies the
buffer ID and bytes, re-provides the consumed buffer, and removes the group.
Requested multishot accept binds one bounded loopback listener, connects two
clients, immediately gives each distinct accepted descriptor one RAII owner,
requires `MORE` on both accept completions, explicitly cancels the request, and
observes its terminal completion. Unexpected positive completions are also
owned before the probe fails closed, so no accepted descriptor is leaked.
Requested multishot receive first requires that same provided-group capability
to be requested and independently proven. Its separate cached ring then
receives two exact payloads into two distinct selected buffers, requires `MORE`
on both data completions, submits an explicit cancellation, observes the cancel
and terminal completions, returns both buffers, and removes the group.
Requested SQPOLL creates a separate two-entry ring with a one-millisecond idle,
completes one NOP, and drops the ring and its polling thread. The runtime data
plane uses none of these probe operations and does not enable SQPOLL; mapped
buffer rings still have no authoritative live outcome. Any requested capability
without an outcome fails closed with `URING-FB-PROBE-ERROR`; no advanced
capability is requested or active by default.

Metric labels use only the frozen identifiers. A raw host error may appear in a
bounded startup diagnostic or trace detail, never as an unbounded metric label.

## Evidence ownership

| Bead | Sole evidence responsibility |
|---|---|
| URING-1 | inventory, taxonomy, probe contract, no-win and no-claim policy |
| URING-2 | immutable decision model, live probes, force-off injection, fallback observability |
| URING-3 | buffer leases, one real fixed or selected-buffer operation, ledger alignment |
| URING-4 | multishot accept lifecycle and ordinary-accept fallback |
| URING-5 | multishot receive, buffer obligations and ordinary-receive fallback |
| URING-6 | typed SQPOLL opt-in, cost visibility and one-change rollback |
| URING-7 | real-host correctness, like-for-like measurements and terminal dispositions |

This split prevents a mock buffer test, a readiness test, or synthetic completion
benchmark from being promoted into evidence for a capability it does not
exercise.

## Measured no-win gate

Each lever ends as `ADOPT`, `KEEP`, `UNSUPPORTED`, or `NO_WIN`. Measurement is
admissible only after active and forced-fallback correctness, cancellation
drain, and zero outstanding descriptors, completions, buffer leases, and
obligations. A correctness failure reaches `NO_WIN`
without creating a metric claim.

The terminal comparison requires two distinct host-family keys, at least five
repetitions per cell, p50 and p95 latency, and exact source, toolchain, features,
host, kernel, configuration, environment, workload, and sample-count identity.
The primary metric is median echo requests per second. The per-cell
relative median absolute deviation may not exceed five percent.

The numeric resource envelope permits at most five percent additional peak RSS
and CPU seconds per request, no extra default thread, and exactly one extra
thread for explicit SQPOLL. At quiescence, descriptor, completion, buffer-lease,
and obligation deltas must all be zero.

The dispositions are disjoint. Their precedence is `UNSUPPORTED`, then
`NO_WIN`, then `ADOPT`, then `KEEP`:

- `ADOPT`: all gates pass and throughput improves by at least five percent on
  both host families. The candidate stays within its declared policy; this does
  not authorize a production-default change.
- `KEEP`: admissible evidence is nonnegative on both families, but at least one
  misses five percent. The incumbent remains default and no improvement is
  claimed; the candidate may remain explicitly opt-in.
- `UNSUPPORTED`: complete bounded probes report unsupported on every declared
  target host family, so the ordinary fallback remains active.
- `NO_WIN`: either family is negative, a latency/resource/noise gate fails, or
  correctness, comparability, or evidence completeness fails. The incumbent is
  retained and rollback remains explicit.

## Static validation boundary

The 2026-08-07 claim-time pin audit found two later source changes. The
`RuntimeBuilder` diff adds the versioned TOML/JSON configuration layer while
leaving its platform-reactor policy, dependency injection, and force-off
surface intact. The inventory contract itself received a formatting-only pass.
Both diffs were inspected before refreshing their exact hashes and line counts;
the remaining twenty-five pins already matched.

This lane checked JSON shape, recorded exact hashes and line counts, and authored
the Rust contract. The Rust contract, project tests, live kernel probes, and
benchmarks were not executed in this static lane.

The later URING-2 control-plane checkpoint added the immutable model, typed
policy, factory selection receipt, and driver snapshot. RCH job
`j-29964935379288247` checked the default-feature library at clean-overlay base
`90d28c97324a0c42b8453be836f53f8ef6a1e1ce` and exited zero. The next checkpoint
replaced the fixed-buffer support placeholder with the bounded cached probe and
then extended it through fixed write/read completion and data verification.
The terminal no-driver checkpoint retained the fallback decision in
`RuntimeState` and exposed it through `Runtime` and `RuntimeHandle`. The next
checkpoint added the bounded provided-group selected-receive and cleanup probe.
The SQPOLL checkpoint added an off-by-default, requested-only probe that
creates a two-entry ring, completes one NOP, and drops the ring and polling
thread before returning its cached classified outcome. The current checkpoint
adds the bounded multishot accept operation probe: two distinct RAII-owned
accepted descriptors with `MORE`, explicit cancellation, terminal drain, and
fail-closed ownership of any unexpected positive completion. The preceding
checkpoint added dependency-gated multishot receive with two distinct selected
buffers, `MORE`, cancellation, terminal drain, buffer return, and group removal.
An RCH clean-overlay feature compile on `hz2` used project hash
`30d538e3f406ef90`, base `9a3d6b9c5ed4d3005eb7935a241e07a0224d941e`,
overlay fingerprint
`26f22fd6237fd2fa0194f974ff7c15123a3eba4715c5bef2b5b845323c217361`,
and exited zero for `cargo check -p asupersync --lib --features io-uring`.
A focused `terminal_` test attempt under project hash `6605dee8352b6c69`
stopped emitting output after compiling the edited library and the local wait
was stopped with exit 130. It
produced no terminal test result, so this checkpoint makes no test claim and no
live-kernel outcome claim.

Accordingly, this inventory and checkpoint do not prove focused test success,
live-host support, the remaining mapped-buffer operation probe, advanced data-plane
behavior, lifecycle correctness, performance,
broad workspace health, release readiness, production-on-by-default status, or
fleet availability. The checkpoint changes control-plane metadata only and
authorizes no dependency, capability, or file removal, tracker closure, or
terminal adoption.

<!-- END IO URING CAPABILITY INVENTORY -->
