# FABRIC Threat Model

This document defines the V1 threat model, fault model, and economic envelope
for the planned Semantic Subject Fabric in `src/messaging/`. It is the boundary
document that future FABRIC work must satisfy before implementation details,
performance claims, or product language are treated as real.

This document is intentionally narrower than the repository-wide threat model in
[`docs/THREAT_MODEL.md`](./THREAT_MODEL.md). Its job is to keep FABRIC honest
about:

- what failures and adversaries V1 is designed to resist,
- what it only partially addresses,
- what it explicitly does not claim,
- what each service class must pay for, and
- what reviewers must demand before approving new semantics.

The guardrail checklist in [`docs/FABRIC_GUARDRAILS.md`](./FABRIC_GUARDRAILS.md)
remains the canonical review checklist. This document provides the concrete
threat and cost framing behind guardrails 7, 15, 18, 19, 20, 21, 23, 26, 27,
and 33.

## Scope

FABRIC is the future native messaging substrate for Asupersync. It is expected
to coexist with existing client integrations (`NATS`, `JetStream`, `Redis`,
`Kafka`) instead of replacing them with ambient-runtime shortcuts.

The V1 design target is:

- a NATS-small public mental model,
- explicit service classes instead of hidden taxes,
- capability-scoped authority,
- recoverability-based durability,
- replayable control decisions, and
- bounded operational cost on the default path.

## Assets and Truthful Claims

Future FABRIC work must protect the following assets and must never over-claim
what those assets guarantee.

| Asset | Why it matters | Truthful V1 claim |
| --- | --- | --- |
| Namespace capability integrity | Unauthorized actors must not publish, subscribe, or claim reply space outside granted scope. | Capability checks and authenticated membership gate authority-bearing actions. |
| Subject routing correctness | Messages must reach the subjects and consumers the fabric says they reach. | Delivery semantics are class-specific and explicit; no magical exactly-once claim. |
| Recoverability-class integrity | A publish acknowledgment must mean something precise. | An ack certifies the declared recoverability class, not impossible downstream guarantees. |
| Epoch and control-capsule integrity | Stale epochs and stale control state must not silently regain authority. | Epoch, lease, and generation data are part of safety boundaries. |
| Obligation ledger integrity | Acks, leases, redeliveries, and handoffs must remain inspectable. | Pending work is obligation-backed and must be explainable. |
| Operator legibility | Operators need to understand what the system is doing and why. | Advanced behavior lowers into inspectable artifacts and reason codes. |
| Hot-path cost honesty | Layer 0 usage must remain cheap by default. | Authority, evidence, and recoverability costs are opt-in and measurable. |

## Trust Boundaries

FABRIC must keep three planes distinct:

| Plane | Primary concern | Must stay true |
| --- | --- | --- |
| Packet plane | fast publish/subscribe/request paths | No surprise control-plane or evidence tax on default traffic |
| Authority plane | control capsules, leases, capability checks, placement, cursor ownership | Explicit, authenticated, bounded, and replayable |
| Evidence plane | trace, decision records, replay, explainability | Selective, policy-driven, and never confused with authority itself |

Design mistake to avoid: allowing evidence-plane or authority-plane mechanics to
silently leak into Layer 0 publish/subscribe until the simple path is no longer
simple, cheap, or truthful.

## Designed to Resist in V1

The following adversaries and failure modes are in scope for V1 and must be
designed against directly.

### 1. Crash-fault stewards, relays, and witnesses

Participants may stop, restart, or disappear without Byzantine behavior.

Required FABRIC response:

- lease and epoch boundaries make stale ownership invalid,
- handoff and restore logic remain explicit,
- recovery is based on declared recoverability class,
- no region or subject cell requires ambient broker immortality.

### 2. Honest-but-curious protocol participants

Stewards or witnesses may follow protocol while attempting to infer tenant
behavior, subject structure, traffic intensity, or service topology.

Required FABRIC response:

- subject visibility and interest summaries are capability-scoped,
- metadata exposure is narrower than generic membership,
- privacy claims stay bounded and explicit,
- differential privacy applies only to export summaries, never to authoritative
  control state.

### 3. Stale, slow, or partition-healed participants

Nodes may act on old epoch state, delayed cursor information, or replayed
placement hints after a partition or slow recovery.

Required FABRIC response:

- control decisions are epoch-bound,
- repair symbols bind to epoch and retention generation,
- delegated cursor partitions and leases fail closed on staleness,
- stale advisories remain advisory and cannot silently regain authority.

### 4. Unauthorized namespace or reply-space access

Clients or peers may attempt to publish into subjects, consume from streams, or
claim reply space they are not allowed to touch.

Required FABRIC response:

- authority-bearing operations require authenticated membership plus explicit
  capability,
- reply spaces are first-class authority surfaces, not incidental strings,
- service contracts and delivery classes are narrower than bare connectivity.

### 5. Replay attacks on tokens, certificates, and control messages

Old credentials, acks, cursor decisions, or placement records may be replayed
across epochs or after retention changes.

Required FABRIC response:

- tokens and certificates are epoch-scoped,
- retention generation and lease state are part of validity,
- replay acceptance rules are explicit and testable.

### 6. Sybil and data-poisoning pressure on discovery and stewardship

Unauthorized peers may attempt to bias placement, advertise false interest, or
distort discovery with fake identities.

Required FABRIC response:

- discovery requires authenticated membership,
- health and placement hints remain advisory until authorized by current
  control state,
- steward eligibility is capability- and policy-scoped,
- V1 remains crash-fault oriented rather than pretending to be BFT.

## Partially Addressed, Not Eliminated

These risks are real, but V1 should describe them as bounded rather than solved.

| Risk | Why only partial | Required honesty |
| --- | --- | --- |
| Network-level traffic analysis | Even blinded metadata and DP summaries do not erase timing and volume leakage. | Never claim confidentiality beyond the declared metadata boundary. |
| Colluding protocol-compliant stewards | Key narrowing and trust scoping help, but they do not erase all correlated inference. | State what cooperation assumptions remain. |
| Operational misconfiguration | Policy gates and named classes reduce accidental misuse, but humans can still choose bad envelopes. | Fail closed where possible; make unsafe modes explicit. |
| Hot-cell overload | Admission control and class gating help, but extreme hotspots still create economic pressure. | Publish cost vectors instead of pretending the hot path is free. |

## Explicitly Out of Scope for V1

The following are not truthful V1 claims and must not be implied in docs, code
review, or marketing language:

1. Byzantine-fault tolerance from `ControlCapsuleV1` or any Raft-like control
   substrate.
2. Global exactly-once delivery semantics.
3. Elimination of all traffic-analysis leakage.
4. Full physical isolation between tenants on shared hardware.
5. Protection against legal coercion of operators.
6. Hot-path homomorphic or zero-knowledge heavy proof systems by default.
7. Generic speculative execution without narrow class gates, rollback, and
   kill switches.

## Fault Model

V1 FABRIC should assume the following classes of faults and should say exactly
which recovery story applies to each one.

| Fault class | Examples | Expected system behavior |
| --- | --- | --- |
| Crash / omission | steward dies, relay stops, witness disappears | leases expire, authority re-evaluates, recoverability class determines what can be reconstructed |
| Delay / partition | slow links, partitioned cell, delayed cursor update | stale decisions fail closed; app-visible guarantees remain class-scoped |
| Epoch skew | replayed token, old placement record, stale cut | current epoch rejects stale authority |
| Overload | hot fanout, oversized control surface, abusive consumer backlog | explicit admission control, backpressure, or class downgrade; no invisible magic scaling |
| Data loss below class envelope | insufficient witnesses or expired retention generation | report recoverability failure honestly instead of pretending the data still exists |
| Policy or operator error | wrong class, wrong capability, unsafe exposure | fail closed when possible; surface high-signal diagnostics and reason codes |

## Economic Envelope

Every meaningful FABRIC feature must publish a cost vector before it can be
called production-worthy. This prevents "semantic inflation" where stronger
guarantees are added without accounting for the control-plane, storage, or
operator costs they introduce.

The required dimensions are:

| Dimension | Question it answers |
| --- | --- |
| Steady-state latency | What does the common case pay? |
| Tail latency (`p99`/`p999`) | What happens under stress, retries, and repair? |
| Storage amplification | How much larger than raw payload does the retained state become? |
| Control-plane amplification | How many control messages and control writes does the feature induce? |
| CPU / crypto cost | What per-message compute budget does the feature burn? |
| Evidence bytes | How much audit or replay material does the feature emit? |
| Restore / handoff time | How long does authority or recoverability recovery take? |

### Layer-by-Layer Cost Expectations

| Layer | Public shape | Cost expectation |
| --- | --- | --- |
| Layer 0 | `connect`, `publish`, `subscribe` with `EphemeralInteractive` defaults | must stay cheap; no default RaptorQ, no hidden authority-plane tax |
| Layer 1 | request/reply with timeout-derived budgets | bounded extra cost, still no durability tax by default |
| Layer 2 | durable streams, consumers, acknowledgments | explicit storage/control/lease cost, published up front |
| Layer 3 | service contracts, session types, decision contracts | stronger correctness and auditability, but visibly more control/evidence cost |
| Layer 4 | replay, branching, forensic analysis | expensive by design, opt-in only, never leaked into the packet path |

### Cost-Vector Review Rule

If a feature cannot say which dimension it increases, it is not ready. If it
claims "zero cost" on all seven dimensions, it is probably hiding work in the
wrong plane.

Planned schema sketch for the eventual `src/messaging/ir.rs` type:

```text
CostVector {
  steady_state_latency,
  tail_latency,
  storage_amplification,
  control_plane_amplification,
  cpu_crypto_cost,
  evidence_bytes,
  restore_handoff_time,
}
```

This document defines the contract now; the concrete Rust type, helper field
types, and compile-time placement belong with the FABRIC IR work rather than
this doc-only bead.

## Non-Negotiable Review Questions

Before approving a FABRIC change, reviewers should ask:

1. Does this broaden authority beyond explicit capability and authenticated
   membership?
2. Does it impose a hidden control-plane, storage, or evidence tax on Layer 0
   or Layer 1?
3. Does it rely on stale epoch data remaining authoritative?
4. Does it accidentally claim exactly-once, BFT, or stronger privacy than the
   mechanism actually provides?
5. Does it enlarge `ControlCapsuleV1` or consumer state until stewardship and
   handoff become operationally expensive?
6. Does it make the operator story less legible than the NATS-sized mental
   model it is supposed to preserve?

## Relationship to Neighboring FABRIC Work

- [`docs/FABRIC_GUARDRAILS.md`](./FABRIC_GUARDRAILS.md) is the numbered
  enforcement checklist.
- The progressive-disclosure work must keep this document true for every layer;
  lower layers cannot quietly depend on upper-layer machinery to be safe.
- Public API work must avoid vocabulary that implies stronger guarantees than
  this document allows.
- Discovery, stewardship, stream, and consumer work should cite this document
  when they define capability, replay, and cost boundaries.

## Status

This is a V1 boundary document, not a claim that all FABRIC machinery already
exists in code today. Any implementation that cannot satisfy these boundaries
should narrow its claims or change its design before it lands.

The concise module-level FABRIC summary now exists in `src/messaging/mod.rs`.
This standalone document remains the deeper boundary reference behind that
summary.

The remaining implementation-facing follow-on is the concrete `CostVector` type
and associated FABRIC IR wiring, rather than additional threat-model prose in
this document.
