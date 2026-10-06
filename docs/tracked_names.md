# Runtime-accounted names and two-phase startup

`cx::TrackedNameRegistry` wraps the canonical `NameRegistry` with checked
runtime `Lease` obligations. Unlike a raw `NameLease`, a tracked guard is
visible to region accounting and holder-completion leak detection. A stateless
`Cx` is refused; this API never silently falls back to untracked ownership.

```rust
use asupersync::cx::{TrackedNameError, TrackedNameRegistry};

async fn serve(cx: &asupersync::Cx, names: &TrackedNameRegistry)
    -> Result<(), TrackedNameError>
{
    let permit = names.reserve(cx, "search-index")?;
    assert_eq!(names.whereis("search-index"), None);

    // Perform asynchronous initialization here. Dropping this future before
    // publication aborts the invisible reservation and returns its quota.
    // A competing registration cannot take the reserved name.

    let lease = permit.commit()?;
    assert_eq!(names.whereis("search-index"), Some(cx.task_id()));
    // Keep the lease while this task serves requests.
    lease.release()?;
    Ok(())
}
```

`register(cx, name)` provides immediate publication. `reserve(cx, name)` keeps
the name invisible until `TrackedNamePermit::commit`. Both obtain one credit
from the same region quota used by checked channel permits and other checked
obligations. Commit transfers the original ticket and credit into the visible
lease; it neither briefly resolves the obligation nor requires spare quota.
A collision returns unused credit before the method returns.

Release removes discovery and commits the runtime obligation. Explicit abort
and guard drop remove the name or pending reservation and abort the obligation.
Physical cleanup and quota return are synchronous; mailbox draining projects
those decisions into the runtime's obligation table. Notification callbacks
run outside the registry lock. Cancellation during admission refuses
publication, and permit commit honors the original context's checkpoint mask.
Late cleanup after the runtime has already chosen a leak cannot rewrite that
outcome; `SettlementRejected` reports that physical cleanup happened but runtime
settlement did not succeed.

## Waiting for an occupied name

`reserve_wait(cx, name).await` waits for an active or invisible reservation to
be released, then returns an invisible, checked permit. `register_wait` also
commits that permit before returning a lease. `reserve_wait_until` adds an
absolute wait deadline:

```rust
# async fn acquire(cx: &asupersync::Cx, names: &asupersync::cx::TrackedNameRegistry)
#     -> Result<(), asupersync::cx::TrackedNameError> {
let deadline = cx.now().saturating_add_nanos(5_000_000_000);
let permit = names.reserve_wait_until(cx, "search-index", deadline).await?;
// Initialization can now run while the name remains invisible.
let lease = permit.commit()?;
lease.release()?;
# Ok(())
# }
```

A sleeping contender holds no runtime quota and no name reservation. In
particular, it can wait while the current owner uses the region's only lease
credit. When the name becomes available, quota refusal is returned as an
error rather than silently waiting for unrelated credits. A provisional raw
reservation owns rollback during the synchronous admission callback; it never
crosses an await or escapes without checked accounting.

Waits park on per-name notifications and an independent cancellation
registration. Release/abort/drop returns credit before waking contenders,
including when a settlement notifier panics. Unrelated names do not trigger
fanout. A persistent change epoch prevents a release between the condition
check and waiter registration from being lost. The last departing waiter
removes its per-name subscription metadata; cancellation does not accumulate
abandoned name entries.

Waiters compete after notification: this API does not promise FIFO order or
starvation freedom and does not change the raw registry's separate FIFO `Wait`
policy. Cancellation respects checkpoint masking. A deadline-bearing parked
wait requires `cx`'s timer driver and returns `TimerRequired` when none exists;
there is no ambient wall-clock or background-thread fallback. Explicit deadline
expiry returns `Registry(WaitBudgetExceeded)`. The context's own deadline may
cancel the wait sooner. Returning a permit ends the acquisition deadline; it is
not an implicit deadline for later initialization or publication.

## Runtime identity and lifetime

A registry permanently binds to the first runtime accepted by an acquisition
attempt. All clones share that binding. `DifferentRuntime` rejects another
runtime even when it generates the same numeric task and region IDs, or after
the old runtime has exited and all names have been removed. The binding is a
weak mailbox identity, not a strong owner of runtime resources. Different
gateway wrappers over the same runtime mailbox remain compatible.

Admission callbacks, clock reads, and checkpoints can run user code. The
implementation revalidates holder identity and liveness after those callbacks
and before publication. A permit whose runtime is gone or whose original
holder is already retired is refused without taking a second quota credit.
These checks do not extend a task's lifetime or transfer its obligation;
keep guards within the admitting task's lifetime. A guard deliberately
forgotten or retained beyond holder completion is detectable by the runtime,
but this does not automatically reclaim its name.

Raw legacy leases and the existing managed-supervisor registry integration
remain unchanged, so this is not closure of every remaining part of
`asupersync-bi2462.100`. The backing registry stays private: there is no
force-remove, raw-mutation, or replacement API that can bypass the guards.
The implementation does not claim network-wide discovery, automatic task
handoff, or descendant cleanup when a caller discards its lease too early.

## Validation status

The original 20 tracked-name tests cover runtime accounting, quota reuse,
collision rollback, cancellation, notification lock boundaries and panics,
retained-guard leak detection, and invisible startup. Six additional authority
regressions cover runtime identity reuse, weak retention, wrapper gateways,
retirement during admission, late publication, and teardown. Thirteen waiting
regressions cover quota-one progress, release and abort wakeups, cancellation,
drop cleanup, name-isolated fanout, independent/migrating wakers, the pre-park
release race, admission rollback, elapsed and virtual deadlines, and notifier
panic recovery.

The implementation environment had neither a Rust toolchain nor RCH access.
These Rust tests were authored but not compiled or executed there. Source SHA
and whitespace checks are not compilation, formatting, Clippy, or test proof.
Run the project's RCH validation lane before claiming executable evidence:

```sh
rch exec -- cargo test -p asupersync --lib cx::tracked_registry -- --nocapture
```
