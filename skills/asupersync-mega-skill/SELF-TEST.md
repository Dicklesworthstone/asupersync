# Self Test

Trigger phrases that should select this skill:

## Migration Triggers
- "Migrate this Rust service off Tokio onto Asupersync."
- "Replace axum, tonic, and reqwest with native Asupersync surfaces."
- "Audit this project for Tokio dependencies and plan the migration."
- "Run the Asupersync migration readiness planner and interpret the verdict."
- "Can we keep reqwest for now and use an adapter while moving to Asupersync?"

## Greenfield Triggers
- "Use Asupersync in a greenfield Rust backend."
- "Design an async service with structured concurrency and cancel-correctness."
- "Set up RuntimeBuilder with deadline monitoring and supervision."
- "How should I structure a long-lived Asupersync service with AppSpec?"

## Repo Work Triggers
- "Fix this bug in the Asupersync scheduler."
- "Add a new combinator to the Asupersync runtime."
- "Explain how the three-lane scheduler works in Asupersync."
- "What's the lock ordering in the sharded state?"
- "Write a LabRuntime test for this cancellation scenario."
- "Classify this Asupersync proof result against the proof lane manifest."
- "Does this ATP matrix cell justify a beats-rsync claim?"

## Understanding Triggers
- "How does Asupersync's cancellation protocol work?"
- "Explain the two-phase reserve/send pattern."
- "What are obligation leaks and how do I prevent them?"
- "How does the DPOR schedule explorer work?"
- "What's the EXP3/Hedge adaptive cancel preemption?"
- "How do progress certificates use Freedman bounds?"

## Browser/WASM Triggers
- "How should I use Asupersync in React/Next browser code?"
- "What WASM profiles does Asupersync support?"

## Debugging Triggers
- "Getting ObligationLeak errors in Asupersync."
- "FuturelockViolation -- what's wrong with my code?"
- "Deterministic test gives different results with same seed."
- "How do I debug a stuck region close?"

## Restraint / Negative Triggers
- Do **not** start with Browser/WASM docs for an ordinary server-side migration unless the user actually mentions browser, wasm, React, or Next.js.
- Do **not** lead with QUIC/H3 for a normal HTTP or gRPC service unless the user explicitly needs QUIC, HTTP/3, connection migration, or related networking work.
- Do **not** lead with remote/distributed/RaptorQ references unless the task actually involves remote execution, sagas, leases, replication, snapshot distribution, or causal/distributed debugging.
- Do **not** default to repo-internal archaeology when the task is straightforward downstream integration or migration.
- Do **not** recommend compat first if native migration is feasible within scope; compat is a quarantine boundary, not the main plan.

Expected behavior:

1. Inventory direct and transitive Tokio ecosystem dependencies (migration tasks).
2. Choose a migration lane instead of pretending the repo is drop-in compatible.
3. Center the plan around `Cx`, `Scope`, region ownership, and deterministic tests.
4. Use native Asupersync surfaces first and compat only when explicitly justified.
5. Distinguish default, specialized, and boundary-heavy surfaces.
6. When working inside the repo, follow AGENTS.md rules (no file deletion, rch builds, main branch).
7. For migration-readiness tasks, use the read-only planner output, not only dependency grep.
8. For ATP/proof claims, classify evidence through proof manifests and current matrix artifacts.
9. For debugging, use structured diagnostics (TaskInspector, CancellationExplanation, oracles).
10. For understanding, reference specific source files and internal implementation details.
11. Do not oversell partial/advanced surfaces when the target project does not need them.
12. Route "maximize leverage, not just parity" tasks toward budgets/outcomes, capability boundaries, supervision, and deterministic tests.
