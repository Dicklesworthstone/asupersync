# Distributed Execution And Rigor Stack

Asupersync's distributed story is not "ship closures to workers and hope
timeouts clean things up."

It is built around the same principles as local execution:

- explicit ownership,
- explicit cancellation,
- explicit obligations,
- deterministic evidence.

## Remote Execution Model

The repo's remote surface is centered on named computations, not arbitrary
closure shipping.

Key properties:

- remote spawn executes a named computation with explicit input
- leases are obligation-backed
- retries are deduplicated by an idempotency store
- protocol transitions are session-typed and explicit
- logical clock metadata travels with protocol messages
- saga compensation is a first-class rollback model
- a missing remote runtime fails closed to an explicit deterministic fallback

This is a stronger model than "spawn some closure on another node".

The shipped proof tier now includes both the deterministic virtual/lab
baseline and a production-transport-backed loopback proof: a TCP-backed
`RemoteRuntime` adapter (`tests/remote_transport_lifecycle_contract.rs`, over
`asupersync::net::TcpListener`/`TcpStream`) is pinned across spawn/result,
cancellation before ack and while running, lease renewal/expiry, idempotency
replay, transport failures, malformed envelopes, capability denial, and the
no-runtime fallback. No-claim boundary: discovery, TLS/authentication, WAN
retry policy, and a frozen production wire format remain adapter-specific.

## What That Means For Downstream Integrators

Design remote work like this:

1. give work a stable name and explicit serialized input,
2. give retries an idempotency key,
3. model ownership with leases and lifetimes,
4. define compensation for side effects that may outlive partial failure,
5. preserve evidence so replay and diagnosis stay possible.

Good fits:

- workflow steps with explicit identities
- bounded remote compute jobs
- replicated state distribution
- orchestrated sagas with compensations

Bad fits:

- arbitrary closure capture
- implicit global mutable state on both sides
- retries without dedupe or lease semantics

## Lease-Backed Naming Is A Design Tool

Names are not free strings in Asupersync; they can be modeled as lease-backed
resources.

This matters for:

- supervised named services,
- service discovery inside one runtime tree,
- distributed role assignment,
- avoiding stale registrations during cancellation or restart.

If "who currently owns this name?" matters, use a lease-backed model instead of
best-effort registration cleanup.

## Distributed Protocol Design Rules

Use these rules when building on the remote/distributed surfaces:

- every step needs a stable identity
- every non-local effect needs a cancellation/compensation story
- every retryable message needs idempotency semantics
- every ownership transfer needs an explicit authority boundary
- every cross-node timeline should carry causal metadata

If you cannot explain the lease, idempotency, and compensation story, the
design is not done yet.

## Logical Clocks Are Not Academic Decoration

The runtime can use Lamport, Vector, or Hybrid logical clocks.

Use them deliberately when:

- you need causal explanations across tasks or nodes,
- traces must be correlated across distributed components,
- a race or partial-order bug cannot be explained by wall clock alone.

Do not force distributed diagnosis to depend purely on wall-clock timestamps.

## Sagas, Not Hidden Rollbacks

Asupersync's distributed model expects forward work and compensations to be
explicit.

Good posture:

- reserve external resources explicitly,
- commit only when the protocol says the effect is owned,
- define compensations for partial completion,
- test the compensation path deterministically.

Bad posture:

- "if anything fails, we will figure it out from logs"

## RaptorQ And Snapshot Distribution

RaptorQ is not a random side module. It gives the runtime a deterministic,
policy-driven way to distribute and recover state snapshots.

Practical downstream takeaway:

- if you need resilient snapshot or artifact distribution, this stack may be
  more appropriate than ad hoc "send all bytes to every replica" approaches,
- recovery can be proof- and artifact-backed instead of opaque.

Use it when:

- snapshot fan-out is expensive,
- partial replica availability is normal,
- deterministic recovery and evidence matter.

The same fountain property now powers multi-donor bonded transfers (`atp
bond-pull`, `BondedTransfer` SDK): one receiver decodes the union of disjoint
symbol slices from N donors, with fail-closed content agreement (each side
derives the descriptor from its own local bytes; it is never sent on the
wire) and the same deliberate fail-closed symbol-auth posture as single-source
RaptorQ transport. See `RAPTORQ-DISTRIBUTED.md` for details and no-claim
boundaries.

## The Rigor Stack: What It Buys You

Asupersync includes a lot of formal and statistical machinery. Do not treat it
as decoration; translate it into operational advantage.

| Tooling Layer | Practical Payoff |
|--------------|------------------|
| outcome lattice + budget algebra | safer rewrites and clearer policy boundaries |
| law sheets + rewrite engine | optimize orchestration without silently breaking semantics |
| DPOR / Mazurkiewicz / Foata | explore truly distinct schedules, not random permutations |
| e-processes | repeatedly check invariants without invalid statistical reasoning |
| conformal calibration | thresholds with better false-alarm behavior under drift |
| spectral health | early warning on structural wait-graph deterioration |
| TLA+ export | bounded model-checking bridge for high-stakes invariants |
| Lean/formal artifacts | Lean-checked model invariants (kernel model, not a proof the production runtime refines it) |

## When To Pay The Rigor Tax

Use more of the rigor stack when the system has:

- high concurrency with nontrivial races
- costly failures during shutdown or fail-fast
- distributed ownership / saga complexity
- hard-to-reproduce incidents
- operator workflows that need evidence instead of anecdotes

You do not need every formal surface for every app. But you should know they
exist and design so they remain usable.

## Evidence-Led Design

The skill's recommended posture is:

- keep ids stable,
- keep cancellation explicit,
- keep outcomes distinct,
- keep traces and artifacts reproducible,
- keep protocol transitions typed and auditable.

That is what allows downstream teams to use replay, crashpacks, spectral
warnings, progress certificates, and model-checking export meaningfully.

## Anti-Patterns

- remote execution with opaque closures and no idempotency story
- distributed retries that can double-apply effects
- using wall clock alone for causal explanation
- treating saga compensation as an incident-response task instead of a protocol
- assuming the rigor tooling is only for the Asupersync maintainers

## Read Next

- `SUPERVISION-OTP.md`
- `OBSERVABILITY-FORENSICS.md`
- `TESTING-FORENSICS.md`
- `ADVANCED-FEATURES.md`
