# Initialized supervisor topologies

This is an experimental `test-internals` surface pending native validation.
It does not change the default build or the existing supervision APIs.

`CompiledSupervisor::bind_initialized` connects an existing supervisor DAG to
initialization-aware factories and live readiness dependencies. The incumbent
compiler still validates names, cycles, ordering and forward references; the
incumbent managed controller still owns restart strategies, intensity, budgets,
generation tasks and region drain. This is not another task-group executor.

## Assemble the actual application

Types live in
`asupersync::cx::worker_readiness::dependencies::supervisor`.
Each binding supplies initialization, state-consuming run, managed restart mode,
and an explicit classification of the full attempt result. Resources and work
errors can differ between bindings and require `Send`, not `Clone` or `Sync`.
Only the classified supervisor error type must be common across the topology.

This example preserves every unsuccessful lifecycle report as a typed error:

```rust,ignore
use asupersync::{Cx, Outcome};
use asupersync::cx::DynamicSupervisorConfig;
use asupersync::cx::worker_readiness::dependencies::supervisor::{
    InitializedChildBinding, InitializedRunResult, InitializedTopologyLimits,
};
use asupersync::supervision::{
    BackoffStrategy, ManagedRestartMode, SupervisionConfig, SupervisorBuilder,
};
use std::time::Duration;

type Fault = Box<InitializedRunResult<&'static str>>;

fn service(name: &str) -> InitializedChildBinding<Fault> {
    InitializedChildBinding::new(
        name,
        ManagedRestartMode::Transient,
        |_cx, _generation| async {
            // Open the application's resources here; return owned state.
            Outcome::<_, &'static str>::Ok(String::from("initialized state"))
        },
        |cx, _generation, state: String| async move {
            // Serve using state. Cancellation observation is not acknowledgement.
            cx.cancelled().await;
            let _ = cx.checkpoint();
            drop(state); // Replace with the application's awaited cleanup.
            Outcome::Cancelled(cx.cancel_reason().expect("observed cancellation"))
        },
        |result| {
            if result.as_ref().is_ok_and(|report| report.is_success()) {
                Outcome::Ok(())
            } else {
                Outcome::Err(Box::new(result))
            }
        },
    )
}

async fn application(cx: &Cx) {
    let storage = service("storage");
    let frontend = service("frontend");
    let topology = SupervisorBuilder::new("services")
        .child(frontend.spec().depends_on("storage")) // Forward reference is valid.
        .child(storage.spec())
        .compile().expect("valid DAG");
    let policy = SupervisionConfig::new(3, Duration::from_secs(60))
        .with_backoff(BackoffStrategy::Fixed(Duration::from_millis(100)));
    let (managed, readiness) = topology.bind_initialized(
        vec![storage, frontend], policy,
        InitializedTopologyLimits { max_children: 2, max_edges: 1 },
    ).expect("valid initialized binding");
    let mut owner = cx.open_dynamic_supervisor::<Fault>(DynamicSupervisorConfig::new(1))
        .await.expect("dynamic owner");
    let id = owner.start_child("application", managed).await.expect("submitted");
    let ready = readiness.all().wait_ready(cx).await.expect("startup succeeded");
    assert!(ready.is_current()); // An observation, not a lease.
    let completion = owner.terminate_child(&id).await.expect("reaped");
    assert!(completion.close.is_ok());
    // Also inspect completion.supervisor and every child outcome in real code.
    let shutdown = owner.shutdown().await;
    assert!(shutdown.close.is_ok());
}
```

`binding.spec()` creates ordinary `ChildSpec` metadata so callers need not
invent a legacy start callback. Its legacy `ChildStart` entry intentionally
refuses execution. Use `bind_initialized`, not legacy supervisor spawning, with
these specs. Existing manually constructed compiled topologies also work.

## Edge and ownership semantics

Each declared edge gates **initialization itself**, not just the run loop.
All prerequisites are sampled as one coherent ready-generation vector. Once an
attempt starts, loss of any selected generation cancels its dependent subtree.
A ready replacement cannot stand in for the selected generation; old dependent
work and descendants drain before the enclosing managed attempt can be replaced.
Readiness may change immediately after a successful check, so effects still need
the application's own authorization and resource-lifetime discipline.

Each attempt has the existing managed task/region plus the work task/region
created by `WorkerDependencies::run`. Initialization receives the actual inner
work Cx and its task/region IDs; the generation number comes from the managed
attempt. Managed reports identify the outer task. Do not equate those task IDs.

The classifier receives either a startup/admission refusal or the complete
`DependencyScopeReport`, including the typed work outcome, selected dependencies,
stop cause, independent cancellation and close result. It runs after the close
**attempt**, not a fabricated success barrier. An unsuccessful close is not
quiescence. The existing outer managed region must close before replacement.
The application controls mapping to `Outcome<(), E>`; the adapter does not turn
an error into text or guess whether a dependency loss should restart a worker.

An `Err` mapping is eligible for Transient restart; `Ok`/`Cancelled` are normally
not. The controller may also restart Transient siblings during a collateral
OneForAll/RestForOne batch. Therefore this adapter never permanently closes a
Transient factory merely because its latest attempt returned cancellation or
success. That decision cannot be inferred from a racing worker-side observation.

Only Temporary bindings publish early `Closed` when their sole attempt ends,
including classifier panic or abandoned driving future. An active body is first
marked `Stopping`, not falsely declared retired. This lets dependents detect a
failed Temporary initializer even when unrelated workers keep the supervisor
and its factories alive. Other factories close their views when dropped.

## Bounds and remaining boundaries

Child and supplied-binding counts plus the raw number of edge declarations are
bounded before recompilation/edge allocation. Repeated edges count against the
limit, then are deduplicated exactly as by the original compiler. The limits do
not bound caller-owned closure captures, names, application resources or the
work performed by initializers. The incumbent compiler's complexity is retained;
no startup-performance improvement has been measured.

Deferred children are rejected rather than promising readiness for work that
will not start. Existing unsupported name-registration and conflicting restart
configuration errors remain errors. No initialization/run/classifier is invoked
while validating the topology. Public compiled fields are revalidated before use.

Readiness is not an authoritative permanent-retirement notification from the
managed controller. In particular, a normally stopped Transient child, or a
restart-budget `Stop` decision, can leave its retained view `Retired` while
unrelated siblings continue. A readiness wait can then remain pending. Applications
must own startup deadlines and shutdown decisions; this increment does not claim
that every stopped prerequisite is automatically diagnosed. It does not add
live topology mutation, distributed dependency leases or universal termination.
Arbitrary stalled work/finalizers can still prevent drain. Preserve the managed
join and enclosing-region barriers, including when abandoning observer waits.

## Validation

The source contains nine binding/state regressions and eight native tests.
Native tests cover current-thread and two-worker execution: a TCP-gated diamond
with an independent ready sibling; one-for-one dependency restart held behind old
descendant cleanup while the upstream replacement is already ready; one-for-all
collateral Transient reuse; and failed Temporary initialization whose dependent
must stop waiting while an unrelated sibling keeps the controller alive.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_initialized_topology cargo test -p asupersync --features test-internals --lib cx::worker_readiness::dependencies::supervisor::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_initialized_topology cargo test -p asupersync --features test-internals --test initialized_supervisor_native
```

Both commands require the repository-authorized remote runner. In this authoring
session they stopped before compilation because `rch` was not installed (127).
The Rust source, tests and example have **not been compiled or executed**.
Source review, delimiter/whitespace checks and Git blob comparisons are not
native behavioral evidence or release readiness. No default promotion is made.
