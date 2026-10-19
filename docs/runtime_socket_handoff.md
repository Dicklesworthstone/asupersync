# Socket runtime handoff (GH#85)

Tracking: [asupersync #85](https://github.com/Dicklesworthstone/asupersync/issues/85),
[sqlmodel_rust #43](https://github.com/Dicklesworthstone/sqlmodel_rust/issues/43),
and the shared-dispatcher lifecycle work in `asupersync-8ynh18`.

## Execution status

The reporter's published **0.5.0** result is a current-thread failure at ten
seconds and a successful two-worker control at about 203 milliseconds. Those
are the reporter's results, not executions of this repair.

The unchanged-main reproduction was attempted on
`662521ba0e3edfeec1ab7f2e173b3273adc67c1b` before production edits. Its bounded
consumer build was stopped during the crates.io index update because shared
temporary storage was exhausted. Cargo had not reached compilation. There is
therefore **no old-main-red or repaired-main-green native receipt** from this
investigation. During review, main advanced through unrelated Spork and HTTP
work and through `fec7be6d7608b14b5448f24a69124e7bb3b4ee34`, which independently
landed the weak root waker and established-socket dispatcher migration. This
implementation was preserved in
`8ff71ca3e5b3f2d8ab62fee02d9d82f87f97a131`, which added worker waker ownership,
retirement notifications, pending connect adoption and surviving-waiter
departures. Further inspection of main at
`91b6fa92363a2e60a8cec3598edb000bc9946afd` found explicit driverless-context
adoption, shared opposite-direction interests and waiter callback locking still
needed repair; the follow-up changes address those boundaries.

The library changes and native tests remain **uncompiled and unexecuted** in
this session. Pinned `nightly-2026-08-31` rustfmt parsing and source review are
supplemental checks. The standard-library-only registration census was compiled
separately and passed; it does not execute the runtime. GitHub Actions is
disabled under the repository's validation policy, so a commit does not imply
that CI will supply the missing evidence. The land-then-heal rules in
`asupersync-bi2462.162` still require an exact-commit RCH/watchdog receipt and
forward repair of any red result. Neither issue nor a release is qualified by
this source review.

## Ownership and readiness decisions

There are two runtime-created waker cycles to break: the current-thread root
waker's strong I/O driver handle, and the strong handle reachable through the
worker coordinator retained by ordinary, local and cancellation task wakers.
Both now retain a weak reference to their runtime's reactor participant using
`IoDriverHandle::downgrade_reactor()`. An actual wake upgrades that participant;
Parker notification, wake coalescing, local scheduling and worker selection keep
their existing paths.

A weak waker alone cannot handle a live but unserviced source runtime. On a
blocked socket poll, the registration now compares its dispatcher identity with
the current native runtime's dispatcher. A different owner causes retirement of
the old registration before fresh registration on the current driver. The
common path covers ordinary TCP, UDP, Unix sockets, listeners, `AsyncFd` and
child-process pipes. Pending TCP and Unix connect futures also resolve the
current driver inside their poll instead of retaining their first driver
across an await.

A present runtime context without an I/O driver, including one built with
`enable_platform_reactor(false)`, must also retire a registration left on
another runtime. The existing fallback path can then service its readiness.
An existing fallback registration already has the correct owner in this case.
With no ambient context at all, an existing manually driven registration keeps
its owner. This distinction applies to pending connects as well as established
socket registrations.

The comparison uses the shared `IoDriver` allocation, not the participant
reactor allocation. Independently constructed runtimes sharing one supplied
reactor intentionally share its dispatcher and token namespace. Switching
between those participants must retain the existing token. Same-dispatcher
polls borrow the current context's handle for the comparison, avoiding new
context/driver clones on that path. This is a structural performance safeguard;
throughput and wake latency have not been benchmarked here.

`IoRegistration` retains a weak reference to the dispatcher's owner separately
from its weak mutex reference. The mutex can remain allocated while the final
owner's destructor is executing. During that interval, registrations must
already report inactive and reject rearm, interest mutation and waker
replacement. Otherwise a retirement callback can arm an emptied old dispatcher.

Final dispatcher retirement removes backend registrations and publishes the
vacant token namespace before waking detached waiters. Callbacks run outside
the driver and registry locks. Existing token generations and per-callback
panic isolation remain in effect. A retained registration's eventual drop
cannot deregister a replacement dispatcher's token.

A retained runtime-created `Cx` still owns a strong driver handle. Installing
that same context on an unrelated executor after runtime shutdown is a remaining
service-lifetime boundary: the driver can be allocated and report an active
owner while no runtime services it. This needs runtime service revocation that
also preserves active participants of a shared dispatcher and manual drivers.
The native retained-context test keeps the old context alive but polls under
the destination runtime's fresh context; it does not validate installing a
stale context on another executor.

## Concurrent waiters and cancellation

Owned TCP and Unix halves use their existing serialized registration
transition: install waiter generations, take the old registration, release the
split lock for deregistration, then register the current union of interests.
Concurrent polls or cancellations can update generations while deregistration
runs. An old readiness callback can consume only the generations it captured.

When one pending half finishes or is cancelled, its surviving sibling receives
one notification after the locks are released. The sibling then re-polls under
its own runtime and can reclaim the registration. This handles a registration
migrated to B just before B's caller finishes and B becomes idle. Ordinary
polling and migration do not issue these departure notifications, which would
make two blocked halves repeatedly wake one another.

The same departure rule applies to shared Unix ancillary waiters, TCP/Unix
accept waiters and `AsyncFd` readiness waiters. A stale or already-consumed
waiter identity must not notify newer waiters. `AsyncFd` departure wakes do not
manufacture readiness bits. Cancellation/drop maintenance does not select an
unrelated driver from the context performing the drop; adoption happens when
the surviving operation is actually polled.

Shared Unix ancillary entries now retain each parked operation's direction.
Fresh registration after migration uses the union of those entries, so a
writer moving the registration cannot strand an earlier reader, or vice versa.
Completed or cancelled entries are absent from the next fresh registration.
`AsyncFd` similarly updates and snapshots its armed-direction union under the
registration mutex. Concurrent dispatch can consume that snapshot, publish
readiness hints and wake the waiters; a later rearm of the snapshot preserves
the existing spurious-readiness contract. Departure alone never sets ready bits.

Waiter replacement must also allow a retired task waker's destructor to re-enter
cancellation. Ancillary, accept and `AsyncFd` registration perform user waker
clones, disposal and wake callbacks outside their waiter/registration locks.
Anonymous waiter eviction and insertion remain one serialized mutation, so a
reentrant callback cannot refill an eviction slot before the incoming waiter is
installed and exceed the bounded list.

## Regression coverage

`tests/runtime_handoff.rs` retains the reporter's original two public-API tests.
Its additional native cases require a real `Poll::Pending` before releasing
peer traffic, verify exact bytes and socket identity, finish bidirectional
traffic and EOF, and join the new fixture/watchdog threads. The cases cover:

- Dropped and explicitly shut-down source runtimes, with all current-thread and
  two-worker source/destination combinations.
- A nested destination while the live current-thread source worker is still
  on loan to its root, so the source background thread cannot service I/O.
- Repeated transfers back and forth, including a two-worker destination.
- Driverless current-thread and two-worker destinations, both while the source
  is alive but unable to service its reactor and after drop or explicit shutdown
  with a retained source context. `test-internals` additionally checks removal
  of the retained driver's registration; public-API behavior runs without it.
- Socket handoff through actual spawned tasks in both runtime flavors.
- A root panic after a witnessed pending read.
- Cancellation of a parked child read, preserving `Interrupted`, an unchanged
  buffer, the acknowledged cleanup result and ownership of the original stream.
- Simultaneously pending owned reads/writes on separate runtimes, followed by
  reunification and exact payload/EOF checks.

Unit regressions additionally cover runtime-created root/worker/local waker
lifetimes, safe stale wakes, final shared-owner retirement, reentrant and
panicking retirement callbacks, repeated live dispatcher changes, failed
replacement registration, same-dispatcher participant reuse, connect handoff,
and surviving split/shared waiter generations. Further deterministic cases use
real nonblocking descriptors with model-provided readiness to cover both
ancillary and `AsyncFd` read/write migration orders, repeated transfers,
cancellation, directional clearing and an old dispatch extracted before
migration but delivered afterward. Callback probes cover reentrant replacement
destructors and anonymous waiter eviction.

`tests/runtime_handoff_registration_census.rs` inventories production references
to the registration types. A new unclassified carrier fails this census and
requires an explicit handoff/retirement witness. The prior suite missed the
cross-runtime boundary: a readiness test within one driver, and even a passing
two-worker root test, do not exercise an escaped current-thread root waker or
the task-waker coordinator cycle. Model tests and source inventory alone also
cannot show that a real socket wakes a native executor.

## Required native verification

Run the focused lane before broader suites, on the exact repaired main commit,
with the repository's pinned toolchain and required remote RCH admission. Give
every remote command an explicit target directory:

```sh
handoff_target="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_runtime_handoff"
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo test -p asupersync --locked --test runtime_handoff -- --test-threads=1 --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo test -p asupersync --locked --features test-internals --test runtime_handoff -- --test-threads=1 --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo test -p asupersync --locked --test runtime_handoff_registration_census -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo test -p asupersync --locked --lib runtime:: -- --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo test -p asupersync --locked --lib net:: -- --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo test -p asupersync --locked --lib io::async_fd:: -- --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo test -p asupersync --locked --lib cancel:: -- --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo test -p asupersync --locked --test runtime_abort_vs_cancel_semantics_audit -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo test -p asupersync --locked --test runtime_bounded_shutdown_and_reentrant_block_on --test runtime_io_driver_fd_eager_close_audit --test polled_replay_native_tcp --test tcp_socket_options -- --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo check --all-targets --keep-going
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="$handoff_target" cargo clippy --all-targets -- -D warnings
```

Capture the actual command, source commit, feature graph, remote admission,
terminal exit and named test results. Reject a native lane with missing,
ignored, filtered or zero tests. Re-run the preserved original reproduction
against the pre-repair implementation as its negative control; a test newly
written after the repair is not an old-red receipt. Cover supported native
backends and feature combinations, including the no-default-features consumer
graph, before claiming portability or release readiness.

## Downstream and 0.5.x maintenance

SQLModel's manifest selects `asupersync = { version = "0.5.0",
default-features = false }`. Main is 0.6.0, outside that compatible requirement;
a plain Cargo patch pointing at this 0.6.0 checkout will not replace a 0.5
dependency. No SQLModel PostgreSQL canary was executed here, and no PostgreSQL
fixture was available. An unset `SQLMODEL_TEST_POSTGRES_URL` can skip the
PostgreSQL cases, so a generic pool-test success is insufficient evidence.

The downstream production canary must retain its original-connection reuse
assertion, normal and panic holder exits, both runtime flavors, real request
contexts, default checkout validation, bounded process deadline and
`close_and_drain` cleanup. Its existing pool target is:

```sh
cargo +nightly-2026-08-31 test --locked -p sqlmodel-e2e --test pool -- --test-threads=1 --nocapture
```

The downstream acquire budget's unbounded checkout-ping await is a separate
contract issue described in sqlmodel_rust #43. This upstream ownership repair
does not add that deadline.

The weak waker and poll-time adoption changes are internal and add no dependency
or public signature changes, making a 0.5.x port plausible. It is not a verified
backport: v0.5.0 predates the current shared-owner/token-namespace implementation
and several rearm/locking repairs. Port the ownership and liveness invariants to
that implementation and repeat the native negative control and downstream
canary. Building/tagging a 0.5.x lineage also needs an owner decision compatible
with the repository's main-only rule. This change does not authorize a release,
create a maintenance branch, change package versions, or publish a tag.
