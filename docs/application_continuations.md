# Supported application-state continuations (bridge R13)

## V1 design and execution boundary

`distributed::symbol_service::checkpoint::continuation` supports one explicitly
checkpointed application workload, restored into fresh runtime-owned work. It is
not a serialized Rust stack, a replacement for the lab's `RestorableSnapshot`, or
universal runtime recovery. The existing SNAP and manifest formats are unchanged.
This is an additive implementation slice of bridge R13; multi-task/topology and
unsupported external-effect restoration remain unfinished, not relabelled complete.

A `RestorableWorkload` implementation supplies a local name, nonzero revision and
state-schema fingerprint, deterministic state codec, and native future factory.
These implementations form the finite set of formats the embedding application
supports. There is no dynamic module loader or snapshot-selected executable.
The factory receives a fresh admitted `Cx` and owned decoded state. Provision
connections, destinations and credentials on the local workload object. A file,
peer or state blob cannot supply runtime capability handles or a callback.

The codec is trusted application code, not sandboxed Rust. It must reject states
that require unsupported effects and must bound its own allocations and CPU. The
application must establish a safe checkpoint boundary and coordinate/idempotently
replay external effects. The library cannot infer transaction commit from a
counter, prove a user decoder pure, or make a network side effect exactly once.

V1 uses an otherwise empty, open root `RegionSnapshot` as an APPLICATION-state
carrier. It refuses saved task summaries/stacks, child regions, finalizers,
cancellation, parent topology, and saved deadline/poll/cost budgets. This prevents
silently discarding runtime owners while pretending the whole region was restored.
The source region/origin/epoch/sequence and causal clock remain provenance, never
destination arena identities or effect authority. A runtime budget is supplied
locally and constrained by the destination's parent context.

## Capture and prepare

`checkpoint_workload(snapshot, &workload, &state, &snapshot_key, limits)` refuses
nonempty existing metadata rather than overwriting another application contract.
It encodes and validates a canonical state, then signs the existing snapshot with
an explicit key. Its envelope is stored only in the snapshot metadata. Returning
a signed snapshot does not persist or replicate it. Use the existing StateEncoder
and checkpoint publication workflow for authenticated replica storage.

The metadata wire is little-endian: `ASUPCNT\0`, format u32 (=1), workload revision
u32, name length u16, reserved u16 (=0), schema fingerprint [32], state length u64,
state digest [32], exact workload-name bytes, then canonical state bytes. The state
digest is SHA-256 over a continuation-specific domain, u64 length and state. It is
not an authenticator; the existing snapshot HMAC authenticates the whole envelope.
Unknown formats, flags, names/revisions/schemas, lengths, digest mismatches and
trailing bytes refuse. Unknown effect profiles cannot silently fall back to V1.

`prepare_workload` takes serialized SNAP bytes, independent exact source identity,
snapshot key, byte bounds and `Arc<W>` for the local workload. The whole snapshot
bound precedes authenticated decoding. Source/shape/envelope validation precedes
application decoding. Decode then encode must reproduce exactly the same bytes.
No runtime task, lease, factory invocation or network operation occurs in prepare.
The resulting `PreparedContinuation<W>` has no Clone implementation or public
state mutator. Its state is consumed by one run, but preparing the same saved
bytes again remains a new execution, not a globally deduplicated operation.

Limits cover serialized snapshot and canonical state bytes, not arbitrary
application-code allocations, all RSS, or time spent inside a synchronous poll.
Snapshot parsing can temporarily own metadata alongside the caller's input. Our
temporary serialization/state buffers and decoded metadata copies zeroize on drop;
returned RegionSnapshots, typed states, copies, credentials and files retain their
existing caller-owned protection responsibilities. Debug does not expose state.

## Resume actual work

Call `prepared.run(&owner, &cx, &node, incarnation, duration, child_spec)` for an
`OwnedMembershipController`, or `run_persistent` for a
`PersistentMembershipController`. The source checkpoint cannot choose the current
member incarnation or grant policy. Both paths reuse `run_scoped`: the admitting
task retains a real checked Lease, creates a new child region, and invokes the
factory only after destination admission. Expiry, revocation and cancellation
close/drain the subtree; descendants and finalizers participate in its result.

`Ok(report)` is not workload success. Inspect `report.is_success()` for task,
subtree/cleanup and winning lease commit, then inspect application errors inside
`W::Output`. A useful value returned during cancellation cannot become authorized
success. Continue polling through drain to receive the actual close receipt.
Dropping the runner requests cleanup but cannot synchronously await it. Started
blocking syscalls or noncooperative polls can delay drain. Effects already sent
to external systems are not rolled back and remote quiescence is not inferred.

The initial tests cover canonical and hostile metadata, explicit unsupported
snapshots, independent source/workload identity, trusted-codec refusal and native
execution of the remaining counter steps under a real checked lease. They are
authored until executed, not proof of current compilation or native behavior.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls --lib distributed::symbol_service::native::checkpoint::continuation::
```
