# Named managed children

`CompiledSupervisor::bind_managed_with_registry` binds a compiled topology's
`NameRegistrationPolicy` values to an explicit
`Arc<parking_lot::Mutex<NameRegistry>>`. The existing `bind_managed` API keeps
rejecting registry-bearing specs when no registry has been supplied.

```rust,ignore
use asupersync::cx::registry::NameRegistry;
use asupersync::supervision::{NameCollisionPolicy, NameRegistrationPolicy};
use parking_lot::Mutex;
use std::sync::Arc;

let registry = Arc::new(Mutex::new(NameRegistry::new()));
// Add this registration policy to the existing ChildSpec before compiling:
let child = child.with_registration(NameRegistrationPolicy::Register {
    name: "search-index".into(),
    collision: NameCollisionPolicy::Fail,
});
// Compile the topology with `child`, then bind its managed factories:
let managed = compiled.bind_managed_with_registry(bindings, config, registry.clone())?;
let mut controller = managed.spawn(&cx)?;
// Lookups return the actual task identity, including its arena generation.
let current_worker = registry.lock().whereis("search-index");
controller.abort();
let report = controller.join().await?;
```

Each admitted child task acquires its name before the managed factory is
invoked or its start is reported. The factory's explicit `Cx` carries the
bound registry capability; tasks spawned through that context inherit it.
Name acquisition establishes discoverability, not asynchronous application
readiness. Keep using an application readiness channel where startup does
asynchronous work.

The controller retains the lease while the generation's task, descendants,
and finalizers drain. It releases the old lease after region closure and
before starting a replacement. A lookup in the replacement factory therefore
finds the new task, and a delayed release using the old lease cannot remove
the successor's entry. Before spawning a named generation, the controller waits
for the runtime to acknowledge a finalizer that retains the lease guard. This
first-registered finalizer runs after descendants and later LIFO finalizers.
Dropping a controller requests structured cancellation; that runtime-owned
finalizer retains the name while descendant cleanup is still pending, then
the last owner removes it. Dropping a future cannot synchronously guarantee
that its descendant cleanup finished.

## Collision policies

| Policy | Executing behavior |
| --- | --- |
| `Fail` | Refuses the generation with `ManagedSupervisorError::Registration`; its factory is not invoked. A required child's refusal stops its supervisor, while an optional child can remain stopped. |
| `Wait` | Joins the existing registry's FIFO queue. The inherited child budget supplies the deadline. The child checks its own grant on a real timer at most once per millisecond and observes cancellation. Cancellation removes its queued request or uncollected grant without taking another consumer's lease. |
| `Replace` | Replaces discovery and requests runtime cancellation of the displaced task before invoking the replacement factory. This policy does not wait for an unrelated displaced task to drain. Use normal managed restart with `Fail` when predecessor cleanup must finish before replacement. |

Use one registry within one runtime. Task and region identifiers belong to a
runtime's arenas, so sharing this registry between independent runtimes does
not provide meaningful global identity or cancellation routing. A raw registry
user that removes an entry while a managed generation is still running can
invalidate discovery; the controller's eventual cleanup will resolve its old
token without removing an independently acquired successor.

## Obligation boundary and validation

The managed integration owns its leases privately and resolves them during
generation cleanup. It does not convert the existing standalone `NameLease`
API into runtime-table obligations. A raw lease obtained directly from
`NameRegistry`, then passed to `mem::forget`, is still outside the runtime
obligation oracle. This remaining part of bead `asupersync-bi2462.100` is
explicitly open.

`tests/named_supervision.rs` adds Lab and native journeys for restart while a
descendant is parked in cleanup, lookup before factory execution, stale
generation release refusal, closed-context admission refusal, collision
failure, FIFO waiter cancellation, replacement cancellation, abandoned
controllers with parked descendant cleanup, and empty names after closure.
The native journey runs on one and two workers. These tests
were authored but not compiled or executed in this environment. The required
RCH follow-up is default `cargo check --all-targets --keep-going` and
`cargo test --test named_supervision -- --nocapture`; a receipt is required
before treating their behavior as proven.

Runtime teardown also retires unapplied finalizer commands, closing their
acknowledgment channels even when retained contexts keep the mailbox alive.
The added library regressions
`runtime_drop_releases_unapplied_region_finalizers_outside_state_lock` and
`lab_teardown_releases_unapplied_region_finalizer_acknowledgment` require RCH
execution as well. The native case retains two queued values, injects a panic
in one destructor, and checks that both receivers wake and both values retire
outside the runtime lock.
