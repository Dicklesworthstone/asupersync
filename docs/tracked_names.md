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

## Boundaries

Use one registry instance per runtime; clones share discovery. Keep guards
within the admitting task's lifetime. Moving a guard in Rust does not transfer
holder or region liability. A guard deliberately forgotten or retained beyond
holder completion is detectable by the runtime, but this does not automatically
reclaim its name. Raw legacy leases and the existing managed-supervisor registry
integration remain unchanged, so this is not closure of every remaining part
of `asupersync-bi2462.100`.

The backing registry stays private. There is no force-remove, raw-mutation,
replacement, or queued-waiter API that can bypass the guards. Failed startup
cannot leave a pending entry through the ordinary abort/drop paths. This API
uses the existing canonical registry algorithm rather than duplicating it.
It does not claim network-wide name discovery, automatic task handoff, or
cleanup of descendants owned by a caller that discards its lease too early.

## Validation status

The added tests cover runtime accounting, same-turn quota return, collision
rollback, cancellation, notification lock boundaries and panics, retained-guard
leak detection, invisible startup, drop during async setup, same-ticket commit,
and shared quota with MPSC permits. They were authored but not compiled or run
in the implementation environment, which had no Rust toolchain. Source SHA
and whitespace checks are not substitutes for compilation or execution.

Run the project's RCH validation lane before claiming executable proof:

```sh
rch exec -- cargo test -p asupersync --lib cx::tracked_registry -- --nocapture
```
