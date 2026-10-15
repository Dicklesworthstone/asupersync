# FABRIC Guardrails

This document is the canonical governance checklist for the planned Semantic
Subject Fabric in `src/messaging/`. It exists to keep future implementation
work legible, bounded, and honest about what the system can and cannot claim.

The current north-star criteria are:

1. Keep the public mental model NATS-small.
2. Make stronger guarantees explicit named service classes, never hidden taxes.
3. Lower radical behavior into small inspectable artifacts.
4. Keep autonomous policy loops inside declared safety envelopes with replay,
   evidence, and rollback.
5. Aim the first product wedge at systems that need sovereignty, durable
   partial progress, and post-incident explanation together.

Anti-goal: do not build a grand unified fabric that makes the common case
slower, the rare case magical, or the operator story less legible than NATS.

## NATS Discipline

Do not copy:

- Goroutine-per-connection mental model.
- Ambient authority over time, storage, or network.
- Protocol-first internals.
- Lock-heavy shared mutability.
- Casual cancellation semantics.

Preserve:

- Disciplined bring-up order.
- Subject-first API design.
- Layered routing caches.
- Explicit topology roles.
- Stream capture through the same substrate as ordinary messaging.
- System advisories as native fabric messages.
- The operational simplicity of NATS's public mental model.

## Guardrail Checklist

1. `[REVIEW-ONLY]` Guarantees hold only inside Asupersync's capability boundary, not for arbitrary unmanaged external side effects.
2. `[REVIEW-ONLY]` Convergence to quiescence assumes the usual cooperative runtime conditions: checkpoints, bounded masking, and fair progress.
3. `[REVIEW-ONLY]` Local region quiescence does not imply a globally consistent distributed cut; cross-node consistency needs explicit cut, lease, or snapshot protocol.
4. `[REVIEW-ONLY]` Replayable snapshots and counterfactual runs must model remote peers, clocks, and external effects explicitly.
5. `[REVIEW-ONLY]` Branch-addressable views must fence unmanaged side effects or model them explicitly.
6. `[TESTABLE]` Branch and cut indexes must have explicit retention, compaction, and access policy instead of pretending reality history is infinite.
7. `[REVIEW-ONLY]` Distributed execution uses idempotency plus leases; never claim magical global exactly-once semantics.
8. `[TESTABLE]` Evidence and decision recording are policy-driven and selective, not sprayed onto the default packet path.
9. `[TESTABLE]` Reasoning-plane evidence, branch, and query surfaces must not leak into the default packet path without explicit elevation.
10. `[REVIEW-ONLY]` Service-class vocabulary must stay small, named, and inspectable; do not let teams invent unbounded one-off classes.
11. `[TESTABLE]` Subject routing and fanout need explicit admission control and backpressure budgets.
12. `[REVIEW-ONLY]` In-band control subjects are not the only recovery path; preserve a break-glass path.
13. `[REVIEW-ONLY]` Causality-native views sit above dependency metadata; they do not replace linear control streams.
14. `[REVIEW-ONLY]` Do not force every peer to decode or store everything; data capsules should let recoverability replace replication.
15. `[TESTABLE]` Keep control capsules small enough for cheap stewardship changes; do not accrete policy or telemetry into a monolith.
16. `[TESTABLE]` Certified cut and branch indexes need explicit retention, compaction, and materialization policy.
17. `[REVIEW-ONLY]` Do not let high-fanout consumer state collapse into one monolithic control capsule; use shard or hierarchy.
18. `[REVIEW-ONLY]` ControlCapsuleV1 does not handle arbitrary hot-cell fanout before delegated cursor partitions exist.
19. `[REVIEW-ONLY]` Publish acknowledgement certifies the chosen recoverability class, not impossible downstream guarantees.
20. `[TESTABLE]` Repair symbols must bind to epoch and retention generation so expired data cannot be resurrected.
21. `[TESTABLE]` Discovery and stewardship require authenticated membership and explicit capability to resist Sybil and data-poisoning pressure.
22. `[REVIEW-ONLY]` Not every participant is steward-eligible; eligibility is a capability and policy question.
23. `[TESTABLE]` Do not synchronously RaptorQ-encode every tiny publish; preserve direct or batched fast paths for the hot path.
24. `[REVIEW-ONLY]` Do not run full concurrent CGKA per hot subject cell; agreement belongs at the steward-pool layer.
25. `[TESTABLE]` CRDTs may live only on non-authoritative surfaces; authoritative state cannot quietly degrade into merge-anything semantics.
26. `[REVIEW-ONLY]` Do not claim BFT from a Raft-based ControlCapsuleV1; Byzantine tolerance is a named future direction.
27. `[REVIEW-ONLY]` Differential privacy does not eliminate traffic analysis; it only bounds leakage per disclosure.
28. `[REVIEW-ONLY]` Session typing covers in-process Rust statically and distributed behavior dynamically; it does not cover arbitrary unmanaged participants.
29. `[REVIEW-ONLY]` Reactive synthesis may generate correct scaffolding, not correct business logic.
30. `[TESTABLE]` Speculative execution is allowed only for low-conflict classes with rollback and kill switches.
31. `[TESTABLE]` Heavy crypto proofs stay off the default path and belong only to named compliance or audit lanes.
32. `[REVIEW-ONLY]` Do not put homomorphic transforms on the hot path; encrypted payloads with blinded metadata are the practical line.
33. `[REVIEW-ONLY]` Progressive disclosure fails if Layer 0 or Layer 1 become footguns that force users to understand Layer 3 or Layer 4.
34. `[TESTABLE]` Randomized or irreversible transforms must stay out of authority-bearing import and export edges.

## Code Review Checklist

Use this list in every FABRIC review:

- State which north-star criteria the change advances.
- Name the fallback or downgrade path that keeps the common case truthful.
- If the change touches authority or durability, address guardrails 7, 19, 20, and 21 explicitly.
- If the change touches topology, cursoring, or retained state, address guardrails 15, 16, 17, and 18 explicitly.
- If the change touches the packet path, show how guardrails 8, 9, 10, 11, and 23 remain true.
- If the change introduces advanced control or autonomy, address guardrails 4, 29, 30, 31, and 32 explicitly.
- If the change touches transforms or interop edges, address guardrail 34 explicitly and explain whether reversibility or fail-closed behavior is required.
