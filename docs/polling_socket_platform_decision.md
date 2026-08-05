# Polling and socket platform terminal decision

<!-- BEGIN POLLING SOCKET PLATFORM DECISION -->

This is the operator-readable companion to
`artifacts/polling_socket_platform_decision_v1.json` for
`asupersync-3u3tej.4`.

The terminal decision is **KEEP**. The `polling` and `socket2` incumbents stay
in place, the cutover state remains `KEEP_INCUMBENT`, and this decision grants
no implementation or dependency-exit authority.

This packet is deliberately static. It inventories current source and checked
artifacts, but it did not compile or execute the focused contract, run a
platform probe, or produce fresh runtime or benchmark evidence.

## Why KEEP is the terminal result

The replacement plan already classifies both dependencies as KEEP:

- `socket2` has small marginal graph cost but owns socket creation, address
  conversion, abstract Unix addresses, borrowed socket configuration,
  keepalive, and cross-platform TCP and UDP options.
- `polling` has small marginal graph cost but owns interrupted waits,
  registration races, descriptor or handle reuse, wakeups, one-shot and edge
  modes, and epoll, kqueue, and IOCP behavior.

The capability registry agrees: `KEEP_UNTIL_PARITY`, `BASELINE_PLANNED`, and
`KEEP_INCUMBENT`. The baseline remains `BLOCKED_PLATFORM` and is not cutover
eligible. No named incumbent defect, applicable advisory, maintenance failure,
owner-chartered suite-wide platform project, or meaningful marginal-cost
increase was found.

Taking ownership of this boundary would therefore exchange two reviewed
portable dependencies for a first-party concurrency, lifecycle, syscall, and
platform-maintenance program without a measured reason to do so.
KEEP is the decision, not an unfinished replacement campaign.

## Dependency and graph receipt

Both dependencies are direct native-only root edges under
`cfg(not(target_arch = "wasm32"))`:

| Dependency | Requirement | Locked package | Direct feature | Safety taxonomy |
| --- | --- | --- | --- | --- |
| `polling` | `3.11` | `polling@3.11.0` | none | `BOUNDARY-UNSAFE`, `KEEP_UNLESS_GATED` |
| `socket2` | `0.6` | `socket2@0.6.5` | `all` | `BOUNDARY-UNSAFE`, `KEEP_UNLESS_GATED` |

The canonical marginal ledger spans thirteen profiles and four target cells
per profile. Each dependency is active in the 39 Linux, macOS, and Windows
cells and inactive in the thirteen wasm cells.

| Measurement | `polling` | `socket2` |
| --- | ---: | ---: |
| Active rows | 39 | 39 |
| Rows removing zero package versions | 0 | 3 |
| Rows removing one package version | 27 | 36 |
| Rows removing two package versions | 12 | 0 |
| Marginal package-version observations | 51 | 36 |

The twelve two-package `polling` rows are synthesized Windows consumer cells
where `concurrent-queue` also becomes marginal. The three zero-package
`socket2` rows are workspace development-audit cells where another workspace
parent retains the dependency.

All 78 active rows report no marginal native code and empty marginal build
script and proc-macro sets. That is not a claim that the complete root graph is
native-code-free: root-native status is `unknown` in 65 rows and `none` in
thirteen. Removing `polling` would not remove `rustix`; the lock also contains
independent `tempfile` and `xattr` parents.
There is no `rustix`-eviction result.

### Ledger freshness

The ledger source revision is `ddea6250aee80357756fa1f39456823df88f7af1`;
this receipt is pinned at
`e263782a6d5a793b78e53065f70ce7f76605e863`. Current static inspection confirms
that the two declarations and their locked versions did not change, but the
ledger was not regenerated. Its counts are canonical historical graph
evidence corroborated by current source, not a fresh build or runtime result.

## Exact direct-use inventory

Exactly three production files call `polling` directly:

| Backend | Direct owner |
| --- | --- |
| Linux and Android epoll | `src/runtime/reactor/epoll.rs` |
| macOS and supported BSD kqueue | `src/runtime/reactor/kqueue.rs` |
| Windows IOCP facade | `src/runtime/reactor/windows.rs` |

Exactly nine Rust files under `src` and `tests` call `socket2` directly. Six
are production owners:

- `src/net/atp/transport_rq/mod.rs`
- `src/net/tcp/socket.rs`
- `src/net/tcp/stream.rs`
- `src/net/tcp/traits.rs`
- `src/net/udp.rs`
- `src/net/unix/stream.rs`

Three uses are test-only:

- `src/messaging/nats.rs`
- `src/net/unix/listener.rs`
- `tests/conformance/udp_socket.rs`

The capability registry names the three reactor backends plus the TCP socket
and stream files. It omits four current production direct `socket2` owners:
ATP transport tuning, TCP traits, UDP, and Unix stream. This packet records the
expanded inventory and fails closed on direct-use path drift; it does not treat
the registry omission as replacement authority.

## Polling semantics that a replacement would own

### Registration, modification, and deregistration

All three native adapters reject duplicate tokens and duplicate raw resources.
They retain bookkeeping on hard backend errors and discard it when the kernel
resource is confirmed already gone. Epoll also tracks orphan tombstones.

Normal runtime registrations use generation-tagged `TokenSlab` entries. A
slot is retired rather than wrapping at its maximum generation. Raw Reactor
callers can still supply arbitrary tokens, so generation protection is an
IoDriver property rather than an unconditional backend property.

### Interrupted waits and wakeups

The resolved `polling` implementation retries interrupted waits against a
fixed deadline. Repository adapters delegate directly to that wait operation,
although the Reactor trait still permits an interrupted error. All three
native adapters delegate wakeup to the dependency notification mechanism, and
the IoDriver serializes one active poll leader.

Some pre-registration and rearm wake errors are intentionally ignored. This
receipt preserves that as an incumbent-hardening gap and makes no wake-recovery
claim.

### Descriptor and handle reuse

The backends do not have identical protection:

- Epoll compares an `fstat` device, inode, and mode tuple before and after
  registration and again during lifecycle operations. This narrows close and
  reuse races but is not an opaque file-description generation.
- Kqueue checks descriptor validity with `fcntl(F_GETFD)` but cannot identify
  close-and-reuse between checks and operations.
- Windows tracks raw socket values and has no handle-generation identity.

Generational IoDriver tokens reject stale events after a local slot is reused.
That does not prove the persistent kernel registration disappeared after a
hard deregistration error.

### One-shot, edge, and readiness semantics

The public interest flags include read, write, error, HUP, priority, one-shot,
edge, and dispatch. Platform support differs:

- Epoll rejects dispatch but maps the remaining readiness sidebands.
- Kqueue rejects dispatch and priority and has a narrower error/HUP mapping.
- Windows accepts only readable and writable interests.

Epoll and kqueue map default registrations to one-shot, edge registrations to
edge, and edge plus one-shot to edge-one-shot. Windows rejects public mode
flags while the dependency default remains one-shot. No public route selects
the dependency's level mode, so this packet makes no true level-triggering
claim.

### Cancellation, close, and fork

`IoRegistration` and the separate exported `Registration` type provide RAII
cleanup and a bounded retry. The exported type also catches backend panics,
but its constructor is test-only and no production `ReactorHandle` wiring was
found. Its public production narrative is therefore a documentation and API
gap, not evidence of a second production path.

No reactor or driver at-fork hook, process-ownership check, child
reinitialization path, or inherited-poller policy was found. Fork safety after
reactor or thread initialization is unproven.

## Socket semantics that a replacement would own

### Creation and addresses

The boundary creates IPv4 and IPv6 TCP sockets and Unix stream sockets,
applies nonblocking mode, binds or connects through `SockAddr`, and transfers
successful sockets into standard-library ownership. Early errors drop the
owned socket normally.

Linux abstract Unix connect encodes a leading NUL in the path bytes and has a
source-level interoperability path with a standard-library listener. Empty,
maximum-length, and embedded-NUL abstract-name boundaries are not established
by this packet.

### Borrowed configuration

`SockRef` applies TCP keepalive, observes or tunes UDP buffers, and applies
best-effort bounded send and receive buffer hints to the ATP control stream.
The borrowed view does not transfer socket ownership.

TCP keepalive supports idle, interval, and retry parameters where the target
surface permits them. Unsupported interval or retry targets return
`Unsupported` rather than silently accepting a request. No retained macOS,
BSD, or Windows applied-value receipt is included here.

TCP creation additionally owns reuse-address, conditionally available
reuse-port, IPv6-only, nodelay, bind, listen backlog, and nonblocking
conversion. UDP creation remains in the standard library; `socket2` is used to
observe and tune bounded buffer sizes.

### Connect, cancellation, and lifecycle

TCP and Unix nonblocking connect classify in-progress and interrupted states,
wait for readiness, inspect the socket error or peer state, and stop
multi-address fallback when cancellation is observed. Successful conversion
preserves OS ownership and registration coupling. UDP cloning creates a
distinct OS handle and registration.

These are not thin wrappers. They are lifecycle and error-contract boundaries
whose behavior varies by target.

## Platform evidence status

| Platform family | Current source surface | Receipt status |
| --- | --- | --- |
| Linux/Android | epoll or optional io_uring; TCP, UDP, Unix, Linux abstract names | source present; complete live platform receipt absent |
| macOS/supported BSD | kqueue; TCP, UDP, Unix, platform-varying options | source present; BSD ledger target and live option receipts absent |
| Windows | IOCP-backed polling; TCP and UDP; no Unix module | source present; live rearm, reuse, and option-value receipts absent |
| wasm | BrowserReactor; both dependency edges inactive | excluded by manifest; wasm test-target coverage for test-only imports unproven |
| other | explicit unsupported reactor path | no support claim |

The planned baseline names seven parity modes and two scenarios,
`polling_socket_cross_platform` and `socket_cancel_close_race`. The baseline is
still `BLOCKED_PLATFORM`, and the verification rows are plans, not executed
evidence. They describe the size of a future suite-wide platform project; they
are not prerequisites for retaining the incumbents.

## Reconsideration gate

KEEP may change only through a new owner-reviewed gate after at least one of
these evidence-backed triggers:

1. A reproducible supported-platform incumbent defect cannot be repaired
   upstream or while retaining the dependency.
2. An applicable advisory, unsoundness report, or maintenance-abandonment
   record materially changes incumbent risk.
3. A fresh canonical ledger proves an owner-approved graph, native-code,
   trust, or supply-chain budget violation or a materially larger marginal
   removal.
4. An owner charters a suite-wide platform-boundary project with complete
   Linux, macOS, Windows, supported-BSD, and explicit-unsupported contracts
   and receipts.
5. Independent review demonstrates a narrower first-party design with no
   greater unsafe, FFI, concurrency, or maintenance burden and an explicit
   rollback plan.

Every trigger requires owner approval. A proposal, partial implementation,
single-host result, or compile-only signal is insufficient.

## No-claim boundary

This packet proves a source-pinned terminal governance decision only. It does
not prove compilation, test passage, runtime behavior, platform equivalence,
performance, release readiness, broad workspace health, cancellation
correctness, descriptor-reuse safety, fork safety, wake recovery, or applied
socket-option values.

KEEP does not bless the routed incumbent-hardening gaps. It authorizes no
replacement implementation, dependency removal, manifest or lockfile edit,
source migration, cutover, file deletion, destructive cleanup, branch,
worktree, local fallback, peer-job cancellation, or tracker-data rewrite.

<!-- END POLLING SOCKET PLATFORM DECISION -->
