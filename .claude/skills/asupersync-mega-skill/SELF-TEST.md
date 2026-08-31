# Self Test

## Routing Contract

Each positive case names the first task reference a fresh agent should load;
release/current-status prompts may first consult SOURCE-MAP's status card.
Negative controls must not select this skill merely because they mention generic
Rust, Tokio, React, PostgreSQL, or HTTP/3 work. The validator parses the table
and its referenced paths. Independent fresh-agent review should additionally
exercise actual selection and behavior because static validation cannot do so.

<!-- ROUTING_CASES_START -->
| ID | Select | Prompt | First reference | Must do | Must not do |
|---|---|---|---|---|---|
| migration-native | yes | `Migrate this Rust service off Tokio onto Asupersync.` | `references/BROWNFIELD-MIGRATION.md` | Inventory the graph and choose a migration lane. | Promise a drop-in executor swap. |
| migration-compat | yes | `Will asupersync-tokio-compat make Handle::current work for axum?` | `references/COMPAT-BOUNDARY.md` | Require exact bridge compile and runtime evidence. | Claim the compat crate installs Tokio. |
| greenfield | yes | `Design a greenfield backend around Cx, regions, and deterministic tests.` | `references/NATIVE-GREENFIELD.md` | Start from owned runtime and request boundaries. | Lead with niche protocol lanes. |
| cancellation | yes | `A timer-parked Asupersync task does not finish after abort.` | `references/TESTING-FORENSICS.md` | Reproduce the public native-runtime sequence and cleanup. | Substitute a Lab-only or compile-only case. |
| local-task | yes | `Why does Asupersync spawn_local return ASUP-E004 under run_test_with_cx?` | `references/RUNTIME-CONTROLS.md` | Enter the owning runtime's real worker-local lane. | Treat run_test as a local executor. |
| web-handler | yes | `How do I register a Cx-aware async handler with Asupersync's web router?` | `references/GREENFIELD-PATTERNS.md` | Use the matching AsyncCxFnHandler arity. | Pass a raw async function to get or post. |
| grpc-serving | yes | `Serve my registered Asupersync gRPC service over native HTTP/2.` | `references/WEB-GRPC-HTTP.md` | Distinguish callable live-HEAD serving from the legacy bind probe. | Claim the API shipped in v0.4.9. |
| sqlite | yes | `Use Asupersync SQLite diagnosed methods without exposing SQL.` | `references/DB-MESSAGING-FS-PROCESS.md` | Keep diagnosed APIs additive and cancellation outer. | Change established SqliteError signatures. |
| otlp | yes | `Which Asupersync owned OTLP signals are shipped and which remain open?` | `references/OBSERVABILITY-FORENSICS.md` | Separate A2-A5 mapping from A6-A11. | Promote an ignored Collector case to routine proof. |
| browser | yes | `Use Asupersync in a React browser application.` | `references/BROWSER-WASM.md` | Separate JS package GA from Rust preview and broker-only roles. | Infer native host parity. |
| atp | yes | `Does this Asupersync ATP matrix cell justify a beats-rsync claim?` | `references/RAPTORQ-DISTRIBUTED.md` | Use the current matrix and exact cell scope. | Treat sha_ok or compilation as a benchmark win. |
| repository-proof | yes | `Classify this Asupersync RCH result for a release.` | `references/REPO-CONTRIBUTOR-GUIDE.md` | Use manifest, status snapshot, and terminal receipt. | Count admission metadata as executed tests. |
| generic-rust | no | `Optimize this Rust iterator and reduce allocations.` | - | Stay in ordinary Rust work. | Load Asupersync references. |
| generic-tokio | no | `Configure Tokio's multithread scheduler for this existing app.` | - | Answer the requested Tokio task. | Turn it into an unsolicited migration. |
| generic-react | no | `Build a React settings page for my web app.` | - | Use the relevant frontend workflow. | Load Browser Edition guidance. |
| generic-postgres | no | `Tune PostgreSQL autovacuum on this database server.` | - | Treat it as database operations work. | Load Asupersync's client reference. |
| generic-http3 | no | `Explain RFC 9114 HTTP/3 framing.` | - | Answer the protocol question directly. | Assume the user is adopting Asupersync. |
<!-- ROUTING_CASES_END -->

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
13. For `!Send` local-task tests, enter a real scheduler worker before calling
    `spawn_local`; a direct `block_on`, entry-macro body, or `run_test_with_cx`
    does not install the worker-local lane.
14. Treat exact `ForcedSchedule` artifacts as bounded Lab replay evidence, not
    production scheduler control, artifact authentication, or automatic proof
    that a reduced candidate preserves the failure.
15. State that `asupersync-tokio-compat` does not install a Tokio runtime or
    prove `Handle::current()`-dependent frameworks; require downstream compile
    and runtime evidence for each bridge.
16. Identify the high-level pooled client as HTTP/1. H2 has native protocol
    machinery, but no demonstrated shared H1/H2 client pool.
17. Distinguish reserve shapes: MPSC reserve is asynchronous; oneshot and
    broadcast reserve synchronously create permits.
18. Classify native FABRIC as experimental and `messaging-fabric` gated.
19. Treat RCH pre-admission refusal, exit 103, worker assignment, a PID, or
    local fallback as zero remote tests executed, not proof.
20. For repository proof commands, read live `AGENTS.md` and the proof-lane
    manifest; label raw downstream Cargo commands as smoke checks only.
21. Keep wakers, observers, callbacks, and extension hooks outside runtime-state
    locks; identify the open callback-under-lock P0 as unshipped.
22. Treat `/dp`, `/data/projects`, and remote checkout prefixes as locations,
    not repository or evidence identities.
23. Keep the open ATP receive-watchdog bead as an unshipped acceptance
    boundary. State that RQ SSH protected-stdin secret delivery shipped in
    v0.4.9 at commit `515d96e7f`, while the legacy argv spelling remains
    supported and should not be described as removed.
24. Use `RuntimeHandle::try_request_cx_with_budget` when a cloned handle owns
    the request boundary and teardown can race context creation; a stale weak
    handle fails closed with `SpawnError::RuntimeUnavailable`. The method ships
    in v0.4.9.
25. For runtime-less embedders, attach an already-owned `BlockingPoolHandle`
    with `Cx::with_blocking_pool_handle`; do not imply that this installs a
    scheduler or enables `spawn_local`. The method ships in v0.4.9.
26. Describe finite owned OTLP metrics, trace, and log mapping as published
    v0.4.9 native `metrics` capability, while distinguishing loopback wire
    smoke from the explicitly ignored pinned external-Collector lane.
27. Explain that checked SQLite connection/transaction entry points and the
    public validators share one fail-closed policy, while explicitly trusted
    `*_unchecked` methods preserve compatibility and do not imply cross-engine
    SQL safety.
28. For SQLite result metadata, preserve legacy exact-case/last-duplicate
    `get(name)` and sorted-unique `column_names()` semantics. Route ordered,
    duplicate-preserving, ASCII-case-insensitive lookup through the additive
    `column_names_in_order`, `column_name`, and `column_index` APIs; use the
    strict REAL accessors when integer widening is unacceptable.
29. State that cancelled/error/panic transaction helpers poll rollback inside a
    bounded cancellation-masked commit section before returning the original
    outcome. Keep the primary outcome and the separate best-effort transaction
    `Drop` fallback explicit; cite immediate physical rollback only for the
    focused real-disk cancellation case that proves it.
30. Treat MySQL's insecure legacy-auth fields as source-compatibility inputs,
    not escape hatches: production permanently rejects
    `mysql_native_password` on both initial and switched authentication paths.
31. Describe the terminal SQLite aggregate as 47 common P2-P8 cases plus eight
    native-only P5 cancellation cases with zero unexplained divergences. Keep
    the seven-case P3 prepared-statement family, surplus-bind and busy-timeout
    differences, unsupported platform cells, and KEEP-incumbent decision
    explicit. Do not convert bounded parity into engine equivalence or cutover.
32. State that v0.4.9 actor and `GenServer` receive/drain loops perform a
    real scheduler yield after each eight continuously ready messages. Do not
    turn that bounded scheduling point into a stronger priority or latency
    guarantee.
33. State that extreme exponential restart backoff saturates at the configured
    maximum, including `Duration::MAX`, without implying that compiled
    supervisor trees now perform automatic live child restarts.
34. For the escaped parked-mutex abort, require a real native waiter-count
    witness before abort, exact `Ok(Err(LockError::Cancelled))`, and waiter
    count zero before releasing the holder. Do not substitute an owned-guard
    compile fix or a Lab-only model for cancellation-delivery proof.
35. Reject `spawn_local` when the visible owner-worker lane belongs to another
    runtime; an ambient `Cx` from runtime A does not authorize publication to
    runtime B's worker-local scheduler.
36. Report OTLP status as configuration plus three owned-signal tranches
    (A2-A5) shipped in v0.4.9, with A6-A11 still open. Ordinary workspace
    totals do not prove the feature-gated mapper cases or the ignored official
    Collector lane.
37. Keep SQLite's v0.4.9 diagnostics opt-in: established methods return
    `SqliteError`; separately named `*_diagnosed` methods return
    `SqliteOperationError`; outer cancellation stays `Outcome::Cancelled`; and
    legacy/engine prose requires explicit accessors. Match the non-exhaustive
    operation, category, retry-disposition, and diagnostic component types with
    forward-compatible patterns; `SqliteOperationError` itself is the
    private-field wrapper, not another non-exhaustive enum.
38. Distinguish the proof manifest (command, guarantee, envelope, no-claims),
    status snapshot (freshness/blockers), and terminal execution receipt. A
    green structural contract is not broad runtime or release proof.
39. Use Beads and CASS for intent and rationale, but resolve shipped support
    against tagged source, public signatures, focused evidence, and registry
    state when a tracker status or search index is stale.
40. For high-level web routes, give async handlers a by-value `Cx` first and
    wrap them with the matching `AsyncCxFnHandler*` arity before passing them to
    `get`, `post`, or another method router. Distinguish request
    `JsonExtract<T>` from response `Json<T>`.
41. Resolve release and open-boundary questions through SOURCE-MAP's dated
    status card and then verify live source/tracker state. Treat callable
    registered-service gRPC H2 routing as unreleased after v0.4.9 until a later
    tag contains commit `3c73a334c`; preserve `Server::serve` as the legacy bind
    probe and the default `ServiceHandler::call_unary` fail-closed behavior.
