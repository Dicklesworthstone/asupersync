# futures-lite capability inventory

<!-- BEGIN FUTURES LITE CAPABILITY INVENTORY -->

This is the operator-facing view of
`artifacts/futures_lite_capability_inventory_v1.json`, the FUT A1 baseline for
`CAP-FUTURES-STREAMS`. The inventory is source-pinned to
`ed1c0c3ae4ba68947cd2c0212f1aab2242f60724` and follows the accepted
`DEP-ADR-008` decision: **KEEP_UNTIL_PARITY**. It inventories the current
dependency; it does not authorize a cutover.

## Result

The root crate has an unconditional normal `futures-lite = "2.6"` dependency,
resolved to 2.6.1 with its `std` and `race` default features. It remains present
under default features, `--no-default-features`, every optional root feature,
native targets, and the excluded wasm and fuzz workspaces that depend on the
root by path. The Tokio compatibility member separately has a direct
`futures-lite = "2"` dev dependency. Its normal library build does not have that
edge; its unit tests do.

The baseline Rust-source census is exact:

| Scope | Files | `futures_lite` tokens | Cargo-built classification |
|---|---:|---:|---|
| `src` | 150 | 817 | 6 production, 2 public doctest, 809 test |
| `tests` | 151 | 534 | integration test |
| `benches` | 3 | 3 | benchmark |
| `examples` | 1 | 1 | example |
| `asupersync-tokio-compat` | 3 | 5 | 3 dev-dependency API tokens, 2 local helper-name tokens |
| `fuzz` | 2 | 2 | comments only |
| Total | 310 | 1362 | fully classified; zero unknown |

The contract excludes its own post-baseline source file from those numbers and
records its single import separately as temporary dev-oracle evidence. It also
pins a digest of every baseline `path<TAB>count` row, so a new reference, a
removed reference, or a moved reference fails the focused contract.

The ADR's approximate `796 / 148` `src` count has already drifted to `817 / 150`.
Migration owners must use the executable census rather than copying the ADR
headline.

## Production and public surfaces

Six production source tokens in five files preserve seven behaviors:

| ID | Source | Contract |
|---|---|---|
| `FUT-PROD-ATP-STREAM` | `src/net/atp/sdk/stream.rs` | One trait import supports public `Stream<Item = TransferProgress>` impls for both `AtpWriter` and `AtpReader`. Empty progress queues self-wake and return `Pending`; disconnected or cancelled queues terminate. Drop best-effort signals cancellation and aborts an outstanding obligation. |
| `FUT-PROD-MIDDLEWARE-CATCH` | `src/web/middleware.rs` | `CatchPanicMiddleware` separately catches construction panic with `std`, then catches poll panic with `FutureExt`. It emits stable `ASUP-E502` behavior and never intentionally repolls after panic. |
| `FUT-PROD-NEGOTIATE-CATCH` | `src/web/negotiate.rs` | `ErrorHandlerMiddleware` catches poll panic and converts it through content negotiation. Construction happens before the adapter and is not contained by this site. |
| `FUT-PROD-ROUTER-BLOCK` | `src/web/router.rs` | Public synchronous `Router::handle` drives `handle_with_cx` on the caller thread without an ambient runtime. |
| `FUT-PROD-RELOAD-BLOCK` | `src/signal/shutdown.rs` | The SIGHUP receive loop blocks on its dedicated `asupersync-reload-sighup` standard thread. |
| `FUT-PROD-SHUTDOWN-BLOCK` | `src/signal/shutdown.rs` | Each watched shutdown signal blocks on its own named standard thread. |

Two additional references are compiled public doctests on `Notify`. They are
not production runtime calls, but removing the test executor without migrating
them would break the documented public workflow.

The public exposure is a foreign trait implementation, not a root re-export or
a foreign type in a function signature. That is still downstream-observable:
generic code bounded on `futures_lite::Stream` accepts the two ATP SDK types
today. `artifacts/api_surface_map_v1.json` maps root exports and therefore does
not enumerate this nested trait-implementation property.

At the original inventory baseline, the standalone downstream fixture proved
only `asupersync::stream::{Stream, StreamExt}` and did not mention the ATP SDK
types. The follow-on A2 source contract below adds owned-side ATP assertions,
but deliberately adds no futures-lite dependency and therefore cannot catch a
break to the retained foreign impls.

### FUT A2 static owned-Stream progress

At base revision `9f3684b48af00f93a6717af8575bbb4c984d5873`, bead
`asupersync-d24mms.6.2` adds alongside-incumbent owned Stream implementations
for `AtpWriter` and `AtpReader`. This is `STATIC_SOURCE_PROGRESS`; its
executable state is `NOT_RUN_STATIC_ONLY`, and the bead remains open.

The incumbent and owned trait implementations all delegate to one private
`poll_progress` kernel. That kernel preserves the frozen behavior: one queued
`TransferProgress` becomes `Ready(Some(_))`, an empty queue self-wakes and
returns `Pending`, and a disconnected or cancelled queue becomes `Ready(None)`.
The types' existing Drop implementations still best-effort signal cancellation
and abort an outstanding graded obligation. The incumbent public trait remains
implemented; no downstream break or dependency cutover is authorized.

Inline and public-contract compile assertions have been authored for both ATP
types under `asupersync::stream::Stream<Item = TransferProgress>`. They have not
been compiled or executed in this static-only increment.

At follow-on base revision `aa23f536a5c22d3c16ecd592f9c3b743d3e78fc2`,
the standalone downstream fixture also names both ATP types, asserts the owned
Stream item contract, and instantiates their `StreamExt::next` function shape.
This source-authored compile contract does not construct an ATP stream and has
not been run. It therefore does not prove Pending/wake/item/EOF behavior,
cancellation, Drop cleanup, region quiescence, or the separately retained
foreign Stream journey.

At documentation-contract base revision
`862c58a609c1c7b6087e992903b287d08208d7ad`, the owned trait and `Next`
documentation now freeze the semantic boundary that A2 requires:

- `poll_next` receives a pinned mutable reference, and `StreamExt::next`
  requires `Unpin`; a pinned pointer can expose a `!Unpin` target;
- `Pending` must account for the current waker, while `Ready(None)` is not a
  fused-stream promise;
- `size_hint` is an untrusted bound for optimization, never correctness;
- neither `Stream` nor `StreamExt` globally adds `Send`, `Sync`, `Unpin`, or
  `'static`, and fallible streams carry `Result<T, E>` as their item;
- dropping `Next` releases its borrow but cannot roll back poll-side state, and
  dropping a stream may discard buffers or invoke implementation-specific
  cleanup; and
- the `Pin<P>`, `Box<S>`, and `&mut S` adapters forward the underlying polling
  and size-hint semantics under their stated bounds.

This corrects the former blanket claim that every stream poll is losslessly
cancel-safe. It changes documentation only. The source contract has not been
compiled as rustdoc or executed, and it does not prove that every existing
implementation satisfies the documented wake, pinning, size-hint, cancellation,
or drop obligations.

At pinned-downstream base revision
`64a80ef684d277238a5b2e19ccef684ebcf7984b`, the standalone consumer adds
`DownstreamPinnedLocalStream<'_>`. It borrows its item cell, carries `Rc` local
state, and includes `PhantomPinned`, so the same custom stream simultaneously
exercises a non-`'static`, non-`Send`/`Sync`, and `!Unpin` shape. The fixture
holds it behind `Pin<Box<_>>`, names `StreamExt::next` on that forwarding
adapter, drops the unpolled `Next`, and then source-authors size-hint, item, and
EOF observations. The `StreamExt::next` rustdoc also adds the inverse
compile-fail case for calling `next` directly on an address-sensitive value.

Neither case has been compiled or run. They do not claim a stable compiler
diagnostic, runtime cancellation behavior, ATP progress behavior, ecosystem
trait parity, or permission to remove the incumbent dependency.

The same downstream fixture now also maps its custom stream into
`Result<u32, &'static str>` items and names
`StreamExt::try_collect::<u32, &'static str, Vec<u32>>`. This is compile-shape
coverage only; it has not exercised error short-circuiting or completion.

#### A2 acceptance status

| Requirement | Source status | Missing terminal evidence |
|---|---|---|
| Owned API | Authored, not executed | Focused compile |
| Downstream ergonomics | Authored, not executed | Fixture execution |
| Compile-fail rustdoc | Authored, not executed | Rustdoc execution |
| Pin/drop/bounds | Authored, not executed | Behavior execution |
| Error adapter | Authored, not executed | Behavior execution |
| ATP runtime E2E | Runtime scenario missing | ATP runtime E2E |
| User trial | Missing | SAME-or-BETTER receipt |
| Cutover | Blocked | Every receipt above |

This matrix is fail-closed. It is not a terminal receipt, does not authorize
closing A2, and does not convert source-authored assertions into executed
evidence.

The reviewed ATP source-pin row is refreshed in the first increment. At that
base revision, seven unrelated pins had already drifted. The follow-on
increments refresh the reviewed downstream-fixture row, leaving six unrelated
stale pins: `Cargo.toml`, `Cargo.lock`, `src/sync/notify.rs`, the capability
registry, the marginal ledger, and the API surface map. Those six rows are not
blindly repinned here, and no focused-contract or broad-health claim is made.

## `block_on` context

The incumbent pins the future on the calling stack, polls it, and parks the
current thread after `Pending`. Its Waker unparks that Parker. A thread-local
Parker/Waker pair is reused for ordinary calls; a recursive call on the same
thread gets a fresh pair because the cache is already borrowed.

`block_on` adds no `Send`, `Unpin`, or `'static` bound. That matters:

- `Router::handle` can borrow `self` and its local `Cx`.
- unit tests can drive borrowed and non-`Send` futures;
- recursive calls are supported;
- signal listeners satisfy thread ownership because their closures move the
  listener state, not because `block_on` requires it;
- no ambient executor or orphan task is created.

The production call contexts are the public router caller thread and dedicated
signal-listener threads. Test call contexts also include ordinary test threads,
runtime and lab helpers, blocking-pool tests, benchmarks, examples, and the
Tokio compatibility member. A replacement must explicitly test all of those
contexts. “Works in a normal unit test” is not parity.

### FUT A3 static kernel progress

At base revision `02b380ee063e7e643105b1a7997360a7021bf32e`, bead
`asupersync-d24mms.6.3` added an alongside-incumbent owned kernel at the
crate-private `crate::util::future` module. This is `STATIC_SOURCE_PROGRESS`; its
executable state is `NOT_RUN_STATIC_ONLY`, and the bead remains open.

The kernel pins its future on the calling stack and uses one `Arc`-owned
thread-notification state per invocation. The waker records a release-ordered
notification before unparking the caller. The waiter consumes notifications
with acquire-release ordering on both sides of each poll, so a wake between the
pending result and the actual park remains represented by either the atomic bit
or the thread's park token. A boolean notification coalesces repeated wakes.
Spurious park returns do not cause an unnotified repoll: the waiter checks the
notification bit and parks again. Separate state per invocation preserves
ordinary recursion without a thread-local borrow or a shared poisoned mutex.

The kernel policy is deliberately conservative:

- `crate::util::future::block_on` preserves the parity-shaped direct-output
  shape for admitted internal contexts, while
  `crate::util::future::try_block_on` exposes a typed refusal;
- borrowed, non-`Send`, non-`Unpin`, and non-`'static` futures remain admissible;
- ordinary host threads and Asupersync blocking-pool threads are admitted;
- any installed `Runtime::current_handle()` is rejected before the future is
  polled, covering both scheduler workers and a nested call from the thread
  driving `Runtime::block_on`;
- `wasm32` is rejected because host-thread parking is unavailable;
- the kernel creates no executor, task, region, obligation, or ambient `Cx`;
- cancellation remains explicit future behavior: progress requires the
  cancellation source to wake the future after changing its state.

Inline cases have been authored for ready-without-park, borrowed non-`Send`
recursion, wake coalescing, deterministic spurious returns, stable waker
identity, wake-after-pending, explicit cancellation wake, panic propagation,
refusal before polling in an installed runtime context, and execution on the
real blocking-pool implementation. None of those cases has been executed in
this static-only increment.

This is not parity and is not a migration authorization. In particular, the
kernel cannot distinguish an Asupersync scheduler worker from the external
thread driving a runtime, cannot identify arbitrary foreign executors, has no
loom/lab receipt, and carries no idle-CPU or latency measurement. The three
production blocking sites and every test call remain on the incumbent. The
dependency, manifests, capability registry, source-pinned A1 artifact, and
cutover state remain unchanged at `KEEP_UNTIL_PARITY` /
`BLOCKED_PENDING_EVIDENCE`.

### FUT A4 static helper progress

At base revision `050fd0f08e4cf127e348bbf545c1e46cc392f6b5`, bead
`asupersync-d24mms.6.4` adds the allocation-free helper subset beside the
incumbent in `crate::util::future`. This is `STATIC_SOURCE_PROGRESS`; its
executable state is `NOT_RUN_STATIC_ONLY`, and the bead remains open.

The subset deliberately uses the standard library where it already provides
the required semantics:

- `poll_fn` is a direct adoption of `std::future::poll_fn`, preserving the
  caller's Context, one closure call per wrapper poll, closure drop, panic
  propagation, and the absence of extra `Send` or `'static` bounds;
- `pending` is a direct adoption of `std::future::pending`, so it remains
  pending without scheduling a wake;
- the owned `poll_once` pins its input inside the returned future, polls it
  exactly once, maps `Ready(value)` to `Some(value)`, maps `Pending` to `None`
  without waiting, and drops the input when that observation completes;
- the owned `YieldNow` self-wakes and returns `Pending` on its first poll, then
  returns `Ready(())` on every later poll without another wake. This repeated
  ready behavior is intentionally distinct from `runtime::yield_now`, whose
  separate runtime-facing contract rejects a post-completion repoll.

At follow-on base revision `da8d632b5ef51ea4074589aed0664cb8f5e33d41`, a
second static-only increment adds the deterministic two-future combinators:

- the owned `Zip` polls left before right on every wrapper poll, stores each
  completed output, drops that completed child in place, and never polls it
  again while the other child remains pending;
- the owned `Or` polls left first and returns immediately when left is ready,
  otherwise polling right. Completion leaves the other future to be dropped
  with the wrapper; it does not claim to drain a losing structured task.

Both combinators use the root crate's existing pin-projection dependency and
store their state inline; they add no heap allocation or executor.

Inline cases have been authored for Context identity and closure-call count,
ready and pending one-poll observations, pending-input drop, the exact
first/second/later yield sequence, a pending future that never wakes, zip poll
order and completed-child suppression, retained-output and unfinished-child
drop, and left-biased `or` selection, fallthrough, and loser drop. None of those
cases has been executed in these static-only increments.

These increments do not implement randomized `race` and do not invent a
comment-only `join_all` target. They also do not migrate an incumbent call site,
change a manifest, authorize cutover, establish differential parity, or provide
unit, property, lab, DPOR, performance, or loser-drain evidence. The remaining
race surface and its explicit cancellation/quiescence policy keep FUT A4 open.

## Consumed helper semantics

The live API set is:

- `block_on`
- `poll_fn`
- `poll_once`
- `yield_now`
- `zip`
- `race`
- `or`
- `pending`
- `FutureExt::catch_unwind`
- `Stream`

`poll_fn` invokes its `FnMut` once per poll and forwards the caller's Context.
`poll_once` performs exactly one inner poll, turning `Ready(v)` into `Some(v)`
and `Pending` into `None`; completion drops the inner future. `yield_now`
self-wakes and returns `Pending` once, then returns `Ready(())`.

`zip` polls left then right, stores completed outputs, and returns an ordered
pair after both complete. Dropping it drops the remaining child and any stored
output.

`race` randomizes the first child on each wrapper poll. `or` always polls left
first. Both return the first ready output and drop the losing future when the
wrapper is dropped. They do **not** drain the loser or prove region quiescence.
Any owned replacement must either preserve this incumbent behavior for
differential compatibility or explicitly upgrade it to the project's stronger
race contract with obligation-aware drain evidence. Merely dropping the loser
cannot be reported as “losers are drained.”

`pending` never completes and never schedules a wake. `catch_unwind` wraps each
inner poll in `std::panic::catch_unwind`, producing
`Err(Box<dyn Any + Send>)`; the middleware construction-stage catch remains a
separate requirement. The `Stream` trait is the futures-core trait re-export
and adds no `Send`, `Sync`, `Unpin`, or `'static` supertrait.

### ADR correction: no `join_all`

`future::join_all` is not consumed. The only repository occurrence is a stale
comment in `src/sync/notify_metamorphic.rs`, and futures-lite 2.6.1 exports no
such function. Conversely, `future::or` is used by
`tests/channel_conformance.rs` and was absent from the ADR list.

FUT A4 must implement the executable inventory, not the stale prose list:
include `or`; do not invent a futures-lite `join_all` parity target. The
project's own join-all behavior remains a separate asupersync combinator
surface.

## Exact migration ownership

Every baseline occurrence is assigned by a deterministic path selector. Each
group carries the SHA-256 digest of its sorted `path<TAB>count` projection:

| Group | Bead | Files | Tokens | Scope |
|---|---|---:|---:|---|
| `FUT-A6-CORE` | `.6.6` | 42 | 258 | actor, cancellation, channels, combinators, Cx, epoch, gen-server, lab, obligations, runtime, service, session, owned stream, sync, test utilities, tracing |
| `FUT-A7-IO` | `.6.7` | 31 | 145 | filesystem, IO, non-ATP network, process, signal, time, TLS |
| `FUT-A8-SERVICES` | `.6.8` | 33 | 196 | web, HTTP, gRPC, database, messaging, distributed |
| `FUT-A9-ATP-DEV` | `.6.9` | 204 | 763 | ATP, transports, root real/conformance test modules, integration tests, benchmarks, examples, compatibility tests, fuzz comments |

Before editing, an owner must materialize the group's digest projection, reserve
every exact path it intends to change, and fail closed if the projection drifts.
The groups are ownership partitions, not permission for a bulk rewrite.

Design and kernel ownership remains:

- `.6.2`: owned Stream/public extension contract and ATP downstream ergonomics;
- `.6.3`: safe blocking kernel, Parker/Waker state, recursion, runtime and
  blocking-pool policy;
- `.6.4`: `poll_fn`, `poll_once`, `yield_now`, `zip`, `race`, `or`, and
  `pending`;
- `.6.5`: construction- and poll-phase panic containment;
- `.6.10`: aggregate parity, graph proof, downstream E2E, rollback, and only
  then a conditional cutover decision.

## Marginal ledger

The existing marginal ledger has 52 root-edge cells: 13 feature profiles over
four target triples.

| Unique marginal package versions | Cells |
|---:|---:|
| 0 | 4 |
| 3 | 21 |
| 4 | 13 |
| 5 | 14 |

The possible unique set is futures-lite 2.6.1, futures-io 0.3.33, parking
2.2.1, futures-core 0.3.33, and pin-project-lite 0.2.17. No marginal build
script, proc macro, or native-code package is recorded.

All four zero-marginal cells are `workspace-dev-build-audit` targets. Removing
the root normal edge would not remove a package there because workspace
dev/test edges—including the Tokio compatibility member's direct dev
dependency—retain the incumbent. Therefore:

1. production normal-edge exit is one gate;
2. temporary differential/dev-oracle retention is a separate, explicit gate;
3. dev-oracle retirement happens only after standalone owned tests replace the
   oracle;
4. a zero workspace marginal is not evidence that production already stopped
   using futures-lite.

## Required downstream and real E2E evidence

`public_stream_consumer` must compile and run an external crate whose generic
functions are bounded on the ecosystem Stream trait and consume both ATP SDK
types. It must cover Pending, wake, progress item, EOF, channel cancellation,
drop, obligation cleanup, and region-close quiescence.

`stream_cancel_backpressure` must exercise the real bounded progress path and
prove cancellation signaling, obligation resolution, no task leak, no
obligation leak, loser cleanup, and quiescence.

`test_block_on` must cover a borrowed non-`Send` future, recursive invocation,
wake-after-Pending, panic propagation, ordinary test threads, runtime contexts,
and blocking-pool contexts with no spin, deadlock, or orphan task.

Canonical aggregate execution remains:

```bash
scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario futures_streams
```

The scenario must retain the standard provenance, normalized outcomes,
resource state, timings, redaction scan, and deterministic replay command.
`BLOCKED` or `UNSUPPORTED` is explicit; silent skip is not green.

## Fail-closed findings

- The capability registry names the wrong source owners.
- Its feature list implies a gate that does not exist.
- Registry and baseline evidence states disagree.
- The manifest comment describes only the two web adapter sites.
- Public ATP ecosystem Stream behavior and downstream usability are untested.
- ATP's Empty path self-wakes and has no focused wake-churn test.
- The ADR count drifted, listed comment-only `join_all`, omitted live `or`, and
  omitted the compatibility-member direct dev edge.
- Two fuzz comments imply direct use that does not exist.

All are routed in the machine artifact. None is permission to expand A1 into a
source migration.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/futures_lite_capability_inventory_v1.json \
  --overlay-path docs/futures_lite_capability_inventory.md \
  --overlay-path tests/futures_lite_capability_inventory_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_futures_lite_capability_inventory" \
  cargo test -p asupersync --test futures_lite_capability_inventory_contract -- --nocapture
```

## No-claim boundary

This inventory proves a source-pinned, zero-unknown classification and focused
incumbent semantic probes. It does not prove arbitrary downstream Stream
compatibility, replacement parity, broad workspace health, release readiness,
performance, no regression, live RCH fleet availability, local Cargo fallback
approval, or permission to remove futures-lite. Package-count marginals are not
behavioral evidence. Dropping a race loser is not the project's required loser
drain. The owned Stream semantics and ATP additions described above are
source-authored and unexecuted; they do not extend the historical proof state.

<!-- END FUTURES LITE CAPABILITY INVENTORY -->
