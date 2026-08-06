# Comprehensive Master Plan for the Asupersync-Native RCH Accelerated Build Sidecar (RABS)

**Status:** Authoritative implementation plan, revised after six adversarial consistency passes  
**Version:** 1.6  
**Date:** 2026-08-06  
**Primary repositories:** `remote_compilation_helper` (RCH), `asupersync`  
**Architecture decision:** Accepted

---

## Document purpose

This document consolidates and supersedes the prior architectural reviews, critiques, recommendations, and sequencing discussions concerning the RCH Accelerated Build Sidecar, abbreviated **RABS**. It is intended to be sufficiently specific that implementation agents can derive epics, beads/issues, code boundaries, schemas, tests, rollout gates, and operational runbooks without having to reconstruct the design from earlier conversations.

The plan deliberately distinguishes:

- **Hard invariants**, which are architectural constraints and must not be traded away casually.
- **Adopt-now capabilities**, which should enter the first production path.
- **Hardening work**, which must complete before a subsystem becomes authoritative.
- **Evidence-gated frontier work**, which is valuable only if measurements justify it.
- **Explicit cuts**, which are outside the project even if technically interesting.

The central synthesis is:

> **RABS is an Asupersync-native, ATP-native, content-addressed execution system that makes unmodified Cargo and rustc behave like a persistent, branch-aware, fleet-wide structured-concurrency service. Concurrent requests for one valid action key collapse onto one shared primary execution lineage; additional attempts exist only under explicit retry, recovery, hedge, verification, or determinism-audit policy, and once a result commits it is reused while retained and trusted. Cargo’s observable semantics, diagnostics, pipelining, freshness behavior, and safe fallback boundary remain intact within the explicitly selected build-path semantic policy; strict real-path-preserving work never silently receives canonical-path semantics.**

A more market-facing formulation is:

> **Bazel-grade caching and remote execution under unmodified Cargo, specialized for fleets of coding agents: canonicalized and hermetic actions, cross-agent singleflight, branch-aware incremental state, speculative prebuilds, agent-aware scheduling, and complete miss explainability.**

### Revision 1.1: adversarial-audit corrections

This revision incorporates a fresh, source-level review of Cargo's current execution and pipelining behavior and corrects several assumptions that would otherwise have reduced hit rate or weakened soundness:

- Fine-grained action keys use the **minimal enforced input closure**, not the entire workspace snapshot. The full immutable snapshot remains the materialization and provenance source.
- Workspace-wide cross-worktree convergence requires a **canonical Cargo driver**, because Cargo itself creates path-sensitive unit identities and compiler arguments before a rustc wrapper is invoked.
- All semantically visible output, `OUT_DIR`, incremental, home, secret, and temporary paths are stable; attempt IDs, action keys, and snapshot IDs may exist only in hidden physical backing paths and metadata.
- Dependency projection is conservative by default: the key hashes the exact dependency artifact rustc receives. Reduced metadata-only projections require an invocation-class proof and shadow differential evidence.
- The environment is constructed explicitly and hashed as presented. Filesystem tracers are not treated as a reliable way to discover `getenv` calls, and raw clock/randomness access receives an explicit trust classification.
- The fleet has one active `CoordinatorAuthority`. Per-host edge daemons own local wrappers, source capture, path translation, and fail-open; the coordinator alone owns fleet-wide singleflight, leases, scheduling, and action publication.
- Cargo's early-metadata protocol is described precisely: rustc emits an artifact-notification JSON line for the completed `.rmeta`; Cargo parses that line and marks its internal metadata edge complete.
- Worker result preparation and coordinator publication are one-way in authority: workers may offer prepared results, but only the coordinator commits the action pointer.
- Jobserver control accounts for Cargo's implicit token by acquiring a root permit before each Cargo process, rather than assuming one shared pipe alone bounds many independent Cargo invocations.
- macOS and other non-Linux platforms have explicit authority tiers; unsupported isolation or input-observation properties reduce portability or serving authority rather than being silently assumed.

These corrections are normative. Where older wording conflicts with them, this revision controls.

### Revision 1.2: second consistency and failure-mode corrections

A second hostile review of the revised design found several remaining state-model and operational hazards. This revision fixes them:

- A Cargo command/build operation, a logical action-cache entry, an execution attempt, and a subscriber's delivery/materialization state are separate state machines. A cache hit does not "commit" an action again, and observable commit is tracked per subscriber.
- Publication fencing uses a structured coordinator authority, one action execution generation, and distinct per-attempt execution leases. Concurrent hedge attempts share the generation but never invalidate one another merely because another lease exists.
- Worker restart generation and coordinator incarnation are part of authority-bearing identities. Lease expiry uses monotonic TTL/renewal rules rather than comparing unsynchronized wall clocks.
- Provisional metadata lineage is transitive. A dependent may commit only when every provisional ancestor resolves to the exact logical object in a committed producer result; an equivalent winning producer attempt may adopt the object, while a differing object invalidates descendants.
- Existing action-key publication is compare-and-set. A second result with the same key but different canonical semantic-result digest is a determinism/key-soundness incident, not a harmless "first result wins" case; observation-only and evidence-only differences are handled separately.
- CAS objects are never exposed through writable hardlinks. Output trees reject traversal, duplicate/case-colliding paths, escaping symlinks, and undeclared special files before materialization.
- Cargo owns the semantically visible output and `OUT_DIR` paths. RABS canonicalizes Cargo before planning and maps Cargo's exact paths to hidden backing storage; it does not invent a replacement `OUT_DIR` after Cargo has already established unit identity.
- Build-script runs include the pre-run `OUT_DIR`/Cargo output-cache state when observable, and cached replay atomically installs the complete post-state including deletions rather than merging into stale directories.
- Shared mutable target directories are prohibited. Whole-command hot state is privately leased or cloned per operation; fine-grained reuse flows through immutable CAS objects.
- Root permits and jobserver grants have exact accounting: a grant of `C` execution slots consists of Cargo's one implicit token plus at most `C-1` transferable jobserver tokens, with an acyclic acquisition order and reserved progress capacity.
- Critical control traffic is physically or provably isolated from bulk-object congestion. The initial transport may use separate control and data connections if one QUIC connection cannot meet cancellation/lease tail-latency gates.
- Per-test caching does not assume process isolation implies semantic independence. Shared setup, ordering, external state, and suite fixtures force a batch/suite action or a bypass.
- Self-hosting recursion, wrapper re-entry, client/edge restart resumption, filesystem semantic classes, code-signing/notarization boundaries, and licensing/SBOM metadata are now explicit plan items.

Revision 1.2 controls wherever any earlier action, lease, observable-commit, `OUT_DIR`, materialization, or coordinator-recovery wording conflicts with it.


### Revision 1.3: canonical-result, byte-fidelity, and edge-case corrections

A third consistency pass concentrated on false cache divergence, file/argument fidelity, source-capture safety, and Cargo-facing edge cases. It makes the following normative corrections:

- Canonical action-result identity is separated from attempt evidence and the coordinator publication record. Worker identity, attempt IDs, timings, verification observations, provisional lineage, and incremental snapshots no longer make equivalent outputs appear different by construction.
- Same-key conflict handling compares a canonical semantic-result digest and a canonical observable-result digest. Attempt-evidence differences are normal; semantic divergence quarantines the action, while observation-only divergence receives a narrower presentation/observability quarantine and disables ordinary replay until resolved.
- Subscription context and attempt-dispatch context are separate. Subscriber priority, path translation, and presentation state are not confused with an attempt purpose, selected worker, resource grant, or execution lease.
- `ActionInputManifest` contains positive inputs only. Negative dependencies and the presented environment remain distinct descriptor components, eliminating duplicate fields and inconsistent hashes.
- Paths, argv, response-file names/content, environment keys/values, and symlink targets are byte-preserving on Unix; UTF-8 is a presentation concern, not a wire or key assumption.
- Source capture receives an explicit confidentiality policy. `.gitignore` is not a security boundary; denied or secret-classified inputs force a capability-scoped/local lane rather than silent upload.
- Edge-side digest and snapshot indexes reuse trusted content identities without relying on mtimes alone. Watcher overflow, weak filesystems, or identity ambiguity force rehash/rescan or reduced authority.
- CAS logical objects and stored representations are separate. Compression/packing races cannot make one logical digest ambiguously name several physical encodings, and manifest graphs are cycle/fan-out/range validated.
- Process-group ownership is supplemented by cgroup/PID-namespace or VM containment where the profile claims descendant control. Wrapper signal/parent-death behavior and slow-subscriber isolation are explicit.
- Cargo configuration discovery, command eligibility, subscriber-specific dep-info derivation, rust-analyzer canonical-launch requirements, nextest setup/retry semantics, and benchmark non-cacheability are now explicit.
- Peers persist the highest accepted coordinator authority term/credential generation so a restored database or reused lower term cannot regain authority without an operator reset proof.
- Canonical build paths are an explicit semantic policy, not a free equivalence transform. Path-observable projects either opt into stable canonical paths, prove path opacity/remapping, or use a real-path-preserving lane with reduced reuse.
- Canonical publication, append-only evidence, and serving trust evaluation are separate records; later audits can promote, restrict, or quarantine serving without rewriting canonical result identity.
- Cargo-visible delivery uses a write-ahead, sequence-acknowledged commit protocol. An uncertain output/event delivery after a crash fails coherently and never falls back optimistically.
- Outputs derived from unresolved provisional lineage may pipeline provisionally, but subscriber terminal success and final output readiness wait for lineage closure.
- Fine-grained cache-hit materialization uses a per-operation destination arbiter; disjoint output bundles may install concurrently, while overlapping destinations serialize or bypass.

Revision 1.3 controls wherever earlier wording conflates canonical result bytes with attempt evidence, assumes UTF-8 paths, treats a watcher/mtime as content authority, or leaves source-transfer, command, signal, test-runner, or storage-representation behavior implicit.

### Revision 1.4: final closure, delivery-frontier, and incarnation-fencing corrections

A fourth adversarial pass closed the remaining contradictions between the high-level promises, concrete schemas, and failure behavior:

- Fleet singleflight now promises one shared primary execution lineage for concurrent duplicate demand, not the impossible claim that a generation can never require a sequential retry or recovery attempt.
- Subscriber delivery distinguishes ordinary transcript exposure from state-advancing Cargo output/readiness/terminal commits. Stateful commits use durable write-ahead sequencing; transcript-only output has its own fallback policy and does not require an fsync transaction for every diagnostic line.
- Subscriber delivery is explicitly iterative: a wrapper may receive many diagnostics, metadata notifications, output installations, and a terminal result, with sequence acknowledgement after each item and `DeliveryComplete` only after the terminal item and all owned outputs.
- Worker identity now includes a fresh process-incarnation ID in addition to a durable boot generation. The coordinator admits one active incarnation per worker identity/generation and fences stale or cloned sessions.
- Canonical-result conflict handling now treats two different canonical manifest objects with equal declared semantic/observable digests as a projection-completeness or canonical-serialization incident rather than quietly accepting them.
- The wrapper release profile must preserve panic containment: size optimization may not select abort-on-panic unless a separate guard process can still execute the original chain before any exposure frontier.
- Action-family, subscription, key-breakdown, jobserver-environment, negative-dependency, and protocol schemas are aligned with the normative prose. Tiny commands use an absolute-overhead/local-pass-through SLO rather than an impossible percentage-only target.

Revision 1.4 controls wherever earlier wording overstates execute-once semantics, conflates transcript bytes with stateful observable commit, omits worker process incarnation, or allows wrapper/profile/projection behavior to weaken fail-open or conflict detection.

### Revision 1.5: publication/serving separation, snapshot lineage, and protocol-ordering corrections

A fifth adversarial pass found several remaining cross-cutting inconsistencies and closes them normatively:

- Logical publication history is now separate from mutable serving disposition. Quarantine, evidence expiry, and retention eviction do not rewrite a committed canonical publication or conflate cache policy with action identity.
- `ActionGeneration` is ABA-safe across failed generations, eviction, restart, and metadata repair. Generation identity includes a never-reused opaque generation ID plus a canonical digest binding to the creating coordinator authority; per-key ordinals/tombstones are diagnostic and fencing aids, not the sole identity.
- Cargo commands may have an initial source snapshot and a derived resolved snapshot after legitimate dependency-resolution or lockfile mutation. Fine-grained actions bind to one sealed snapshot generation; they never combine pre- and post-resolution state.
- The protocol uses independent bounded sequence domains for authority/control, action lifecycle, subscriber delivery, and object transfer. Critical cancellation and lease traffic never waits behind a missing bulk-data sequence merely to preserve a fictitious global total order.
- Transcript delivery has an explicit in-flight/uncertain state. Any complete frame handed to the wrapper but not fully acknowledged is conservatively treated as possibly exposed, so seamless fallback cannot duplicate a partial transcript.
- Canonical publication creates its durable reachability root/publication pin in the same metadata transaction as the action pointer. A crash cannot expose a committed pointer whose object closure is immediately collectible.
- Cargo root/jobserver tokens are acquired only after input readiness and disk/output reservations; RABS never holds a scarce compiler token while waiting on bulk transfer. Provisional-lineage waiters are bounded so they cannot consume every Cargo job slot.
- Stable wire/persistence schemas use RABS-owned causal timestamps, deadline budgets, durations, peer IDs, and authority types rather than leaking Asupersync implementation types.
- A random worker incarnation fences overlapping sessions but does not prove which clone is legitimate. Clone ambiguity fails closed or requires hardware-bound enrollment/operator re-enrollment; the plan makes no anti-cloning claim without that evidence.
- Provenance and attempt identity are associated with a publication through evidence records; they are not fields of the canonical action result.
- Edge/coordinator recovery text now consistently applies the transcript-versus-stateful delivery frontiers rather than the older single “observable commit” shorthand.

Revision 1.5 controls wherever earlier wording conflates publication with serving policy, permits generation-ID reuse, assumes one immutable snapshot across a legitimate Cargo resolution mutation, imposes a global cross-stream event sequence, or treats an unacknowledged transcript/result delivery as safely unexposed.

### Revision 1.6: authority-binding, edge-handoff, and persistence-schema closure

A sixth adversarial pass checked the revised schemas against the prose, persistence model, and reconnect behavior and closes the remaining representation-level contradictions:

- A `BuildOperation` owns an explicit requested→resolved snapshot lineage rather than one ambiguously named command snapshot. Each action subscription binds to exactly one sealed generation.
- `CoordinatorAuthority` has one full authority-bearing representation per attempt/publication path. `ActionGeneration` carries a canonical digest binding to the authority that created it, avoiding two independently mutable copies of the same authority inside one attempt identity.
- Peer authority high-water comparison is lexicographic by credential generation and then term; reusing the accepted pair with another incarnation is rejected absent a valid operator-reset proof.
- Edge fencing admits one active incarnation per boot generation. A bounded two-incarnation overlap exists only through an explicit handoff token, names the predecessor, and ends by fencing the predecessor before the successor can own materialization rights alone.
- The logical metadata schema now explicitly includes action generations/tombstones, immutable publications, mutable serving state, evidence/trust records, peer high-water marks, worker/edge incarnation fences, and atomic publication reachability roots. Deterministic failures are ordinary typed publications, not a second competing cache table.
- Transcript sequencing no longer implies an fsync per diagnostic line. The wrapper reports the last fully accepted and possibly in-flight framed item during reconnect; if the edge/wrapper pair cannot resolve uncertainty, the command fails coherently rather than guessing.
- Protocol backlog wording now consistently requires independent per-domain sequence/replay windows rather than one per-operation sequence spanning control and bulk transfer.
- V1 authoritative action/schema/authority digest algorithms and domains are explicit and typed; raw 32-byte values from different algorithms or domains are never interchangeable.
- Build-script path-valued directives and linker implicit search/default inputs are parsed and closed semantically, not treated as harmless stdout or assumed to be captured by argv alone.

Revision 1.6 controls wherever earlier wording duplicates coordinator authority inside generation/attempt identity, treats edge handoff as an arbitrary active-incarnation set, leaves authority-fence/publication-serving tables implicit, or describes a Cargo operation as owning one immutable snapshot despite legitimate resolution phases.

---

## Navigation

1. [Part I. Executive decisions](#part-i-executive-decisions)
2. [Part II. Goals, non-goals, and success criteria](#part-ii-goals-non-goals-and-success-criteria)
3. [Part III. Hard invariants](#part-iii-hard-invariants)
4. [Part IV. System architecture and component boundaries](#part-iv-system-architecture-and-component-boundaries)
5. [Part V. Runtime ownership model](#part-v-runtime-ownership-model)
6. [Part VI. Action model, identity, and lifecycle](#part-vi-action-model-identity-and-lifecycle)
7. [Part VII. Canonical virtual execroot](#part-vii-canonical-virtual-execroot)
8. [Part VIII. Hermetic sandboxing and observed-input closure](#part-viii-hermetic-sandboxing-and-observed-input-closure)
9. [Part IX. Profound Asupersync integration](#part-ix-profound-asupersync-integration)
10. [Part X. RABS application protocol over ATP](#part-x-rabs-application-protocol-over-atp)
11. [Part XI. Durable CAS, action cache, and publication](#part-xi-durable-cas-action-cache-and-publication)
12. [Part XII. Scheduling and global resource control](#part-xii-scheduling-and-global-resource-control)
13. [Part XIII. Cargo and rustc integration](#part-xiii-cargo-and-rustc-integration)
14. [Part XIV. Agent-native acceleration](#part-xiv-agent-native-acceleration)
15. [Part XV. Test-result caching](#part-xv-test-result-caching)
16. [Part XVI. Security, trust, and privacy](#part-xvi-security-trust-and-privacy)
17. [Part XVII. Observability, evidence, and explainability](#part-xvii-observability-evidence-and-explainability)
18. [Part XVIII. Failure semantics and recovery](#part-xviii-failure-semantics-and-recovery)
19. [Part XIX. Compatibility, upstream absorption, and deliberate reuse](#part-xix-compatibility-upstream-absorption-and-deliberate-reuse)
20. [Part XX. Performance and measurement program](#part-xx-performance-and-measurement-program)
21. [Part XXI. Verification and proof program](#part-xxi-verification-and-proof-program)
22. [Part XXII. Implementation roadmap with gates](#part-xxii-implementation-roadmap-with-gates)
23. [Part XXIII. Rollout and operations](#part-xxiii-rollout-and-operations)
24. [Part XXIV. Risk register and mitigations](#part-xxiv-risk-register-and-mitigations)
25. [Part XXV. Concrete schemas and contracts](#part-xxv-concrete-schemas-and-contracts)
26. [Part XXVI. Granular implementation backlog](#part-xxvi-granular-implementation-backlog)
27. [Part XXVII. Recommended first execution tranche](#part-xxvii-recommended-first-execution-tranche)
28. [Part XXVIII. Definition of done](#part-xxviii-definition-of-done)
29. [Part XXIX. Source and evidence basis](#part-xxix-source-and-evidence-basis)

# Part I. Executive decisions

## 1. Final architectural decision

RABS will be **Asupersync-native internally**, with three explicit deployment roles:

```text
rabs-edge   per client/developer host
rabs-coord  one active authoritative fleet coordinator authority
rabs-wkr    one or more authenticated execution workers
```

A combined edge+coordinator process is permitted for the initial single-host deployment, but the domain model, durable schemas, and protocol must preserve the role split from the beginning.

V1 uses one statically configured coordinator authority and does **not** perform automatic active failover. Each restart acquires the exclusive authority lock, advances a durably persisted term, and creates a fresh incarnation ID. Disaster recovery to a different host is an explicit operator-fenced procedure that proves the old authority stopped or revokes/rotates its fleet credential. `CoordinatorAuthority` is a structured fencing identity, not a substitute for consensus under two simultaneously active leaders.

Asupersync will provide the core runtime and lifecycle substrate for the long-running edge, coordinator, and worker daemons:

- regions, task ownership, quiescent close, and explicit `Cx` capability contexts;
- budgets, deadlines, cancellation request/drain/finalize behavior, and four-valued outcomes;
- managed subprocesses, process groups, termination escalation, and child reaping;
- supervision, restart limits, escalation, and lifecycle observability;
- remote named computations, capabilities, leases, idempotency, and transport injection;
- ATP sessions, object transfer, manifests, resumable journals, sparse writes, and atomic staging primitives;
- deterministic lab execution, virtual time, schedule exploration, fault injection, replay, and invariant oracles;
- structured observability, pressure signals, admission receipts, SLO brownout, and advisory pool sizing.

RABS will define and own the build-specific semantic layer above those primitives:

- Cargo/rustc interception and transparent wrapper behavior;
- coherent immutable command snapshots and minimal enforced action-input closures;
- canonical action keys, presentation variants, and action schemas;
- canonical Cargo-driver and compiler execroots;
- hermetic sandbox policy and observed filesystem/process-input discovery;
- Cargo pipelining fidelity and provisional metadata handling;
- compiler, linker, build-script, native compilation, and test semantics;
- durable CAS and action-cache storage through a storage abstraction;
- fleet scheduling, root jobserver permits, critical-path priorities, and cache locality;
- coordinator-authoritative action-result publication, provenance, explainability, and trust policy;
- speculative compilation, branch-aware incremental snapshots, and agent-native optimization.

Role authority is deliberately asymmetric:

- `rabs-edge` owns the sub-10-ms local wrapper path, coherent source capture, virtual-to-real path translation, local materialization, subscriber connection state, and safe local fallback.
- `rabs-coord` alone owns the authoritative action registry, current coordinator authority, fleet-wide singleflight, attempt fencing, worker leases, scheduling decisions, the action index, and committed action-result pointers.
- `rabs-wkr` owns sandboxed execution, local object staging, process groups, early-output production, and prepared-result offers. A worker never commits an action pointer.

## 2. Native protocol decision

RABS will use a **native RABS application profile over ATP**, initially and precisely:

```text
RABS/1 over ATP/0
```

ATP transport versions and RABS application versions evolve independently and are negotiated explicitly. The plan does not use the ambiguous notation `ATP/0+`; any later ATP version receives a concrete negotiated number and compatibility matrix.

ATP will be the authoritative internal control and object-transfer substrate after its RABS blockers are hardened. RABS will not use gRPC/Tonic/REAPI as its internal constitution.

REAPI remains valuable as a conceptual reference and an interoperability boundary. RABS will preserve clean mappings to REAPI concepts and may later expose an isolated, stateless `rabs-reapi-gateway`, but the gateway will translate into the native RABS/ATP model rather than dictate internal cancellation, scheduling, CAS, trust, or action semantics.

State-changing operations do not use QUIC 0-RTT in the initial protocol. Session resumption may reduce handshake cost, but replay-sensitive action submission, lease changes, cancellation, and publication require a fully authenticated live session until explicit replay proofs justify otherwise.

## 3. Compatibility and migration decision

The existing RCH stack is Tokio-heavy and already contains operationally important functionality. Migration will therefore be incremental:

1. Introduce an Asupersync runtime island while retaining existing SSH/rsync transport.
2. Move lifecycle, cancellation, process ownership, supervision, and action actors first.
3. Add ATP as a shadow control plane.
4. Add a durable ATP-backed object data plane.
5. Cut over authoritative execution only after evidence gates pass.
6. Keep compatibility-bound Tokio services isolated behind `asupersync-tokio-compat` until replacement has measurable value.

There will be no flag-day rewrite.

## 4. Product boundary decisions

The following are accepted decisions:

- **Unmodified Cargo remains the graph oracle.** RABS observes and accelerates Cargo/rustc rather than replacing Cargo's package-resolution and unit-planning semantics.
- **Canonical Cargo execution is required for shared workspace authority.** A rustc wrapper alone can authoritatively accelerate immutable dependencies, but workspace cross-worktree convergence requires Cargo itself to plan and launch the build inside the canonical namespace.
- **The wrapper remains tiny.** Full Asupersync, QUIC, ATP, scheduling, and storage machinery live in long-running daemons, not in each wrapper invocation.
- **Canonical execroot is the keystone.** Path stability is addressed before broad workspace-member caching, and no semantically visible canonical path contains an action key, attempt ID, snapshot ID, worker ID, or subscriber ID.
- **Fine-grained keys use minimal closures.** The complete immutable source snapshot is used for coherent materialization and provenance; only the action's enforced declared/observed closure and negative dependencies enter a fine-grained key.
- **Hermetic by construction, observation second.** Sandboxing fixes ambient variability; tracing discovers residual filesystem, directory, symlink, subprocess, and network inputs. The complete presented environment is explicit and hashed rather than inferred from `getenv` tracing.
- **Dependencies first.** Registry and immutable git dependencies are the first authoritative action-cache product because they offer immutable inputs and high compiler-second concentration.
- **Dual execution planes remain.** RABS supports whole-command remote execution and fine-grained rustc/link/build/test actions over one shared object and lifecycle substrate.
- **Whole-command V1 is primarily an execution plane.** Arbitrary Cargo commands are not treated as safely cacheable unless all target/build-directory deltas, declared outputs, and externally visible side effects are captured.
- **Nested remote execution is local to the selected whole-command worker in V1.** Child rustc actions may use that worker's local/shared CAS and coordinator singleflight, but cross-worker child dispatch is deferred until jobserver, locality, cancellation, and failure semantics are proven.
- **Fleet-wide singleflight means one active coordinator authority.** Separate edge daemons do not each own independent authoritative action actors.
- **Global scheduling owns a root permit and the jobserver.** Every Cargo process consumes a brokered root permit backing Cargo's implicit token; worker-local jobservers and cgroups bound descendants.
- **Exact link caching is in scope; a bespoke incremental linker is not.** Wild/lld remain pluggable; Wild is the preferred upstream bet.
- **Test-result caching is first-class, but only for side-effect-closed tests.** Compilation alone does not capture agent intent-to-green latency.
- **Explainability is a product pillar.** `rch why` and fragmentation analysis are required, not optional polish.
- **Agents never write shared cache state directly.** Only trusted daemons publish after sandboxed execution and verification.
- **Workers prepare; coordinators commit.** No worker-originated message carries authority to commit an action-cache pointer.
- **Storage is abstracted.** FrankenSQLite is the preferred dogfood backend, but it becomes authoritative only after transaction, crash-recovery, and differential gates against a reference SQLite-compatible implementation.
- **The initial security model is one trusted administrative fleet, not hostile multi-tenancy.** Cross-user or multi-tenant isolation is a separate future program.
- **GPU compiler work and a bespoke linker are cut.** Custom rustc/LLVM profiling is tightly gated and killed if measured gains are small.
- **Advanced ATP features are evidence-gated.** RaptorQ, swarming, multipath, relay, mailbox, and broad internet discovery do not block the core product.
- **State is layered, not overloaded.** Build operations, logical action publication, concrete attempts, and per-subscriber delivery each have independent durable states and identifiers.
- **Hedges share an action generation but own independent leases.** A second hedge does not revoke the first; publication selects one valid winner atomically.
- **Divergent same-key outputs fail closed.** A different canonical result for an already committed action key quarantines the action entry and triggers a key/determinism incident.
- **CAS materialization never grants writable aliasing.** Writable hardlinks to immutable CAS inodes are prohibited; use read-only binds, reflinks with copy-on-write, or copies.
- **Mutable Cargo state is privately owned.** Per-worktree target state remains isolated, and whole-command worker target state is exclusively leased or cloned rather than shared concurrently.
- **Licensing and package metadata must agree.** The combined project preserves the actual rider-bearing license, corrects misleading `MIT` package metadata, and emits accurate SBOM/release metadata.
- **Canonical results are distinct from attempt evidence.** Action publication points to canonical outputs/observable behavior; worker identity, timings, provenance, verification, provisional lineage, and incremental state remain separately attached evidence.
- **Source capture is policy-scoped.** Build-input soundness does not authorize indiscriminate transfer of `.env`, credentials, private keys, unrelated home files, or denied project paths.

# Part II. Goals, non-goals, and success criteria

## 5. Primary goals

### G1. Preserve Cargo semantics

RABS must preserve, or intentionally improve without semantic drift:

- Cargo’s exit status and signal behavior;
- JSON diagnostic ordering and content;
- streamed artifact notifications;
- pipelining based on early `.rmeta` availability;
- stdout/stderr routing and human-readable output;
- per-worktree target isolation;
- dependency and build-script metadata propagation;
- freshness behavior, including mtime choreography where checksum freshness is unavailable;
- local fallback behavior when RABS is disabled, unavailable, unsupported, or uncertain.

### G2. Make action identity both sound and stable

A valid action key must include every semantically relevant input, but it must also avoid irrelevant instability. The system must not choose between correctness and hit rate; it must engineer both:

- **Soundness:** no wrong result may be served because an input was omitted.
- **Stability:** identical work across agents, worktrees, and compatible machines should produce identical keys.

### G3. Collapse duplicate demand onto one shared execution lineage

For a valid action key, concurrent requests from many agents join one supervised action actor and one primary attempt lineage. Sequential retry/recovery after a nonpublishable failure, or concurrent hedge/verification/determinism-audit attempts, are permitted only under explicit bounded policy and remain visible as separate attempts.

### G4. Reduce intent-to-green latency, not merely compiler time

The north-star measurement is p50/p90/p95 **intent-to-result latency over replayed real agent traces**, including:

- queueing;
- source capture;
- key construction;
- cache lookup;
- transfer;
- compiler/linker execution;
- test execution;
- output materialization;
- Cargo notification;
- cancellation and retries.

### G5. Build trust through evidence

Before authoritative serving, RABS must demonstrate:

- zero served-result divergence across a large shadow corpus;
- deterministic or correctly classified nondeterministic behavior;
- atomic publication and corruption quarantine;
- no orphan processes, leaked slots, unresolved obligations, or exposed partial artifacts;
- reproducible failure bundles and deterministic lab replays.

### G6. Become an agent-native compilation health platform

Beyond caching, RABS should use fleet-wide provenance and timing data to provide:

- `rch why` miss and rebuild attribution;
- critical-path scheduling;
- speculative next-state compilation;
- git-event and CI prewarming;
- key-fragmentation analysis;
- toolchain/feature/flag convergence recommendations;
- crate-architecture advice such as identifying rebuild-tail bottlenecks.

## 6. Quantitative product targets

The initial production target envelope is:

| Metric | Target |
|---|---:|
| Wrapper decision path, p95 | `< 10 ms`, with a lower aspirational target |
| Cache-miss overhead | `< 1–2%` for admitted non-tiny actions above the configured break-even floor; separate absolute p95 cap for tiny/local-pass-through actions |
| Local metadata lookup | sub-millisecond to low single-digit milliseconds |
| Local small-artifact hit | `< 50 ms` plus unavoidable filesystem cost |
| Served-result divergence | `0` |
| Median agent edit/check/test loop | `≥ 3×` faster on representative replay corpus |
| p90 agent loop | `≥ 2×` faster |
| Fifteen-agent storm | `≥ 3×` useful throughput or equivalent tail reduction |
| Branch ping-pong | `≥ 3×` faster after snapshot support |
| Cold wide workspace on suitable fleet | `≥ 1.5×` |
| Fleet rustc invocations served rather than executed | long-run goal `> 90%` in warm, converged workloads |

Targets are gates, not marketing estimates. The percentage miss-overhead target applies only where action duration is large enough for a meaningful ratio; capability probes and other tiny commands use direct local pass-through or a tiny local cache and are judged by absolute added latency. Where a workload cannot improve, the system must report why.

## 7. Explicit non-goals

The core RABS program will not:

- replace Cargo’s resolver, package model, or unit graph with a custom build system;
- maintain a long-lived fork of rustc or Cargo;
- implement a bespoke persistent incremental linker;
- pursue GPU compiler acceleration;
- require source-code changes in user projects;
- require Bazel/Buck migration;
- assume every build script, proc macro, test, or linker invocation is cacheable;
- cache signal-terminated, OOM-killed, cancelled, or infrastructure-failed actions as deterministic failures;
- make speculative work compete equally with foreground work;
- expose experimental Asupersync types in stable wire formats, durable rows, or public CLI JSON;
- use application-level capabilities as a substitute for kernel sandboxing;
- delete SSH from bootstrap, repair, and break-glass operations;
- turn RABS into a general internet P2P transfer product before the known fleet use case is solved;
- promise hostile multi-tenant isolation in the first deployment;
- cache arbitrary whole-Cargo commands whose complete build-directory mutations or external side effects are not captured;
- dispatch child rustc actions from a remotely running Cargo process to arbitrary second-hop workers in V1;
- treat best-effort macOS filesystem watching as authoritative read-closure evidence;
- infer environment-variable reads from filesystem or syscall tracing;
- use a semantic dependency projection more permissive than the exact artifact rustc consumes without a versioned proof and shadow gate.

---

# Part III. Hard invariants

## 8. Invariant catalog

### I1. Canonical execution identity

Every fleet-shared portable action executes in a canonical namespace whose semantically visible paths are independent of the requesting worktree, agent, host alias, shell PID, and transient attempt directory. An action requiring original subscriber-path semantics uses a separately keyed path-preserving lane and does not claim cross-worktree portability.

### I2. Coherent immutable command snapshot

A Cargo command and every action derived from it refer to a coherent immutable snapshot. Snapshot capture detects concurrent mutation and retries rather than combining files from different moments.

### I3. Minimal enforced action-input closure

A fine-grained key contains the action's complete enforced positive and negative input closure, not the complete workspace merely because the workspace supplied the snapshot. Authoritative execution exposes only the closed view or aborts and rediscovers on a new read.

### I4. Full snapshot retained for materialization and provenance

The immutable command snapshot remains available to construct sandboxes, diagnose omitted reads, and reproduce a build, but it is not automatically a fine-grained semantic key component.

### I5. One authoritative owner per action key

Exactly one active coordinator authority owns the authoritative `ActionActor` for an action key. Edge daemons and workers may cache immutable data, but cannot independently create competing committed action pointers.

### I6. Reference-counted cancellation

Cancelling one subscriber does not cancel work still needed by others. The underlying action is cancellable only after policy determines that no retained interest remains.

### I7. Region-owned external effects

Worker leases, Cargo root permits, compiler processes, streams, CAS pins, provisional artifacts, publication rights, and cleanup work are region-owned obligations. A successful region close implies they are resolved.

### I8. Atomic visibility

Action-cache publication is transactional. No consumer can observe a result until the complete output object closure is verified and the valid attempt is committed by the coordinator.

### I9. Attempt and coordinator fencing

Only an attempt carrying the current coordinator authority and valid execution lease may offer an eligible result. Late attempts may contribute verified immutable blobs but may not mutate the action-cache pointer.

### I10. Trusted coordinator-only publication

Agents and build subprocesses cannot publish. Workers may upload immutable objects and offer prepared manifests; only the coordinator validates and commits the action entry.

### I11. Safe fail-open frontier

Before a subscriber exposes any Cargo-visible early output or target-tree mutation, coordinator loss may trigger that subscriber's uncoordinated, nonpublishing local fallback. After that subscriber's observable commit, fallback must be coordinated or its wrapper fails coherently; other subscribers retain their own independent frontier.

### I12. Cargo pipelining fidelity

For pipelined rustc actions, the exact `.rmeta` object is fully materialized and verified before the wrapper replays the rustc artifact-notification JSON line that Cargo uses to complete its internal metadata dependency edge.

### I13. Provisional metadata never becomes stable prematurely

Early `.rmeta` remains pinned to its producer action generation, attempt, logical output, and exact object ID. Every descendant carries the transitive provisional lineage and may commit only after each ancestor resolves to the exact object in a committed producer result or an explicit compatible adoption edge.

### I14. Stable public boundaries

`rabs-protocol`, durable schemas, and CLI contracts are independent of Asupersync implementation types and are explicitly versioned.

### I15. Content integrity

All transferred and stored content is verified by cryptographic digest. Location corruption, logical-object corruption, manifest invalidity, and semantic action divergence are quarantined at different scopes.

### I16. No cache poisoning by abnormal termination

Cancelled, OOM-killed, signal-terminated, lease-expired, and infrastructure-failed actions are never published or served as deterministic failures.

### I17. Reconciliation is idempotent

Coordinator, edge, worker, and transfer restarts may replay messages or repeat reconciliation without double publication, double slot release, duplicate root permits, or lost ownership.

### I18. Foreground work dominates optional work

Speculation, prewarming, audits, and reports brown out before user-requested actions or required cleanup.

### I19. Canonical Cargo planning for workspace authority

Workspace results are shared across worktrees only when Cargo's own planning process, package paths, target/build directories, and child invocations were produced in the canonical namespace. A wrapper cannot retroactively canonicalize path-sensitive values Cargo already generated.

### I20. Stable visible paths; hidden physical uniqueness

In the canonical-portable lane, action keys, attempt IDs, snapshot IDs, and random staging names may appear in hidden backing paths and metadata, but never in `CARGO_MANIFEST_DIR`, `OUT_DIR`, `TMPDIR`, incremental paths, visible toolchain paths, or other program-observable paths. A path-preserving lane exposes the original path deliberately and includes that semantic choice in its identity.

### I21. Explicit environment contract

The exact environment presented to an action, including absent values and canonical `PATH`, is constructed and hashed. Environment soundness does not depend on discovering `getenv` calls after process start.

### I22. Conservative dependency identity

The default key includes the exact dependency artifact bytes supplied to rustc or the linker. Any reduced semantic projection is an optimization with a versioned extractor, invocation-class proof, and zero-divergence shadow gate.

### I23. Output semantics are distinct from execution eligibility

Target ABI, SDK, CPU features, toolchain, and output-affecting policy enter the key. Worker pressure, kernel capability, queue priority, cgroup size, and selected host are scheduler constraints unless they affect output semantics.

### I24. Presentation is distinct from semantic action identity

Color, terminal width, subscriber path mapping, and human rendering do not fragment the semantic artifact key. RABS stores a canonical structured event log and either re-renders safely or uses a presentation-variant key for exact transcript replay.

### I25. Isolation authority is explicit

Every result records an isolation/input-observation profile. Linux strict-hermetic results, macOS VM/chroot results, host-audit results, and volatile results do not silently share the same serving authority.

### I26. Source and secret confidentiality are policy dimensions

The first deployment is a single administrative trust domain. Secret-sensitive outputs are nonshareable or scoped by a trusted opaque secret-version digest and access-control namespace; raw secrets never enter keys, logs, or receipts.

### I27. Measurement precedes frontier complexity

Incremental snapshots, rmeta projections, RaptorQ, multipath, swarming, second-hop action dispatch, and custom compiler builds proceed only after corpus evidence justifies them.

### I28. Unknown behavior loses authority, not visibility

When RABS cannot prove a path, input, environment, side effect, or platform property, it records and explains the uncertainty, executes locally or in shadow where useful, and refuses authoritative shared serving rather than guessing.


### I29. Build, action, attempt, and delivery states are separate

A Cargo/build operation may subscribe to many actions, and one action may serve many operations. Logical action publication, execution-attempt lifecycle, and subscriber materialization/observable-commit state are never represented by one overloaded enum or one global operation ID.

### I30. Observable commit is per subscriber

Every wrapper/subscriber independently records whether a Cargo-visible event, deterministic failure, or complete output has been exposed. One subscriber's observable commit neither commits another subscriber nor removes another subscriber's safe fallback frontier.

### I31. Hedge attempts use independent leases under one action generation

All attempts competing to produce the same not-yet-committed result share an `ActionGeneration`, but each owns a unique execution lease. Lease renewal/revocation affects only that attempt unless the coordinator supersedes the entire generation.

### I32. Provisional lineage closes transitively

A result that consumed provisional artifacts carries the complete transitive ancestor closure. Publication verifies that every ancestor's committed result contains the exact consumed object, or the descendant is refused/quarantined.

### I33. Immutable CAS objects never acquire writable aliases

RABS never materializes a writable hardlink to an immutable CAS inode. Mutable target, `OUT_DIR`, temp, and incremental state use private copies, copy-on-write reflinks, or private writable layers so mtime/content changes cannot corrupt shared objects.

### I34. Same-key output divergence is an incident

If two valid attempts for one action key produce different canonical semantic-result digests, RABS does not silently prefer the first. It quarantines the action entry, preserves both candidates, disables serving, and opens a determinism or key-soundness incident. If semantic outputs match but the canonical observable-result digest differs, RABS opens a narrower observability/presentation incident and disables ordinary event/transcript replay until policy resolves it. Attempt-evidence differences alone are expected and are not result divergence.

### I35. Mutable target state has one owner

No two unrelated Cargo operations concurrently mutate the same target/build/incremental directory. Hot whole-command state requires an exclusive lease or a private clone; fine-grained sharing occurs only through immutable content-addressed objects.

### I36. Wrapper and self-host recursion is bounded explicitly

RABS detects its own build/upgrade/bootstrap operations, wrapper-chain loops, and re-entry depth. A signed/validated bypass marker executes the original chain without re-interception; arbitrary user environment values cannot silently disable policy.

### I37. Canonical result identity excludes attempt evidence

The committed action pointer names a canonical result manifest. Attempt IDs, worker identity, timings, resource samples, trust observations, verification runs, provisional lineage, and incremental snapshots are separate immutable evidence or auxiliary-state objects and cannot create false result divergence.

### I38. Source capture is policy-scoped and byte-preserving

The edge captures only paths permitted by an explicit source policy, preserving raw path/argv/environment bytes on platforms that permit them. `.gitignore` and UTF-8 conversion are never treated as security or correctness boundaries.

### I39. Subscriber-derived artifacts are not canonical outputs

Real-path dep-info, rendered diagnostics, mtimes, and other subscriber-specific materializations are derived from canonical objects under a versioned presentation/materialization contract. Their bytes do not masquerade as the shared semantic object.

### I40. Authority high-water marks survive rollback

Edges and workers durably remember the highest accepted coordinator term and credential generation for a cluster. A restored database, reused lower term, or fresh incarnation under stale credentials cannot regain authority without an explicit operator reset/fencing proof.

### I41. Build-path semantics are explicit

Canonicalization, remapping, and original-path preservation are semantic policies. `file!()`, `CARGO_MANIFEST_DIR`, generated path strings, runtime resource opens, panic locations, and user-visible logs cannot be silently changed merely to improve hit rate.

### I42. Trust evaluation evolves outside publication identity

A committed canonical result is immutable. Evidence bundles and policy evaluations are append-only/versioned records that may promote, restrict, or quarantine serving for particular subscribers without changing the canonical result manifest.

### I43. Subscriber delivery is two-phase and uncertainty fails closed

Before any Cargo-visible rename, terminal return, or compiler event, the edge records a delivery intent and sequence. The wrapper acknowledges only after complete exposure. A crash in the uncertain interval forbids uncoordinated fallback or blind replay.

### I44. Provisional lineage gates terminal delivery

Provisional metadata may unblock dependents, but a subscriber cannot receive terminal success or non-provisional final-output readiness for a descendant until the complete provisional ancestor closure resolves to committed exact objects.

### I45. Destination ownership is explicit

Every materialized output path belongs to one build operation and one declared output bundle at a time. Disjoint bundles may install concurrently; overlapping or ambiguous destinations are serialized, rejected, or executed through the owning Cargo process rather than raced.

### I46. Transcript exposure and stateful observable commit are distinct

Diagnostics, stdout, stderr, and progress bytes may become visible without advancing Cargo's dependency/output state. RABS tracks that transcript frontier separately from stateful output/readiness/terminal commits. Seamless unlabelled local fallback is permitted only before either frontier; any recovery after transcript exposure is explicit policy, while stateful commit intent always forbids uncoordinated fallback.

### I47. Worker process incarnation is fenced

A durable worker identity and boot generation are insufficient when a disk image is cloned or two daemons overlap. Every worker start generates a fresh process-incarnation ID; the coordinator admits one active incarnation per identity/generation, binds every attempt lease to it, and rejects stale, duplicate, or non-increasing incarnations absent an operator reset proof.

### I48. Canonical result projections are complete

If two candidates for one action key claim identical semantic and observable result digests but their canonical manifest bytes/object IDs differ, RABS treats that as a canonical-serialization or projection-completeness incident. It never labels unexplained canonical-manifest differences as ordinary evidence-only variation.

### I49. Wrapper panic containment preserves the fallback boundary

Tiny wrappers avoid panics by construction, install a pre-exposure panic hook that records internally without writing to Cargo, and contain unexpected unwinds at the top level. Before any transcript or stateful exposure, an internal wrapper panic executes the exact original wrapper/compiler chain when possible. After exposure it fails according to the applicable delivery frontier. Abort-on-panic is prohibited for the wrapper unless a separate minimal guard process proves the same behavior; allocator abort/OOM remains outside unwind guarantees and is mitigated through bounded allocation.

### I50. Publication history and serving disposition are separate

A committed canonical publication is immutable history. Eligibility, evidence expiry, quarantine, local-object availability, and retention eviction are versioned serving/index dispositions layered over that history; changing them never rewrites canonical result identity.

### I51. Action-generation identity is never reused

Every active generation carries a never-reused opaque `ActionGenerationId` bound to coordinator authority and action key. Failed generations, eviction, restart, database repair, or ordinal wraparound cannot recreate an authority tuple accepted for an earlier attempt.

### I52. Protocol ordering is scoped, not globally serialized

Authority/control, action lifecycle, subscriber delivery, and object-transfer streams use independent sequence domains with explicit causal references. Critical cancellation, lease, and fencing traffic never waits for unrelated bulk-transfer ordering.

### I53. Resolution-derived snapshots are explicit

A command begins from an immutable requested snapshot. If unmodified Cargo legitimately resolves dependencies or mutates `Cargo.lock` in its private overlay, RABS seals a derived resolved snapshot before compilation actions bind to it. No action observes a mixture of pre- and post-resolution source state.

### I54. Worker incarnation fencing is not anti-cloning proof

A fresh worker incarnation ID prevents simultaneous lease reuse and detects duplicate sessions. It does not identify the legitimate copy of cloned credentials or disk state. Ambiguous clones fail closed or require hardware-bound enrollment/operator re-enrollment.


# Part IV. System architecture and component boundaries

## 9. Top-level architecture

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Agent / shell / IDE / CI on each client host                                │
│                                                                              │
│ tiny rch / rch-rustc / rch-link / rch-cc wrappers                           │
│        │ UDS, bounded request/event stream                                    │
│        ▼                                                                      │
│ rabs-edge                                                                     │
│ - local wrapper endpoint and circuit breaker                                  │
│ - canonical Cargo-driver launcher                                             │
│ - coherent source snapshot capture                                            │
│ - virtual↔real diagnostic/materialization mapping                             │
│ - edge-local CAS and object uploader                                          │
│ - subscriber connection state                                                 │
│ - safe nonpublishing local fallback                                           │
└─────────────────────────────┬────────────────────────────────────────────────┘
                              │ authenticated RABS/ATP session
                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ rabs-coord — one active `CoordinatorAuthority`                     │
│ Asupersync production runtime                                                 │
│                                                                              │
│ - fleet-wide ActionActor and DiscoveryActor registries                        │
│ - action key and policy validation                                            │
│ - action index / provenance DAG / trust evidence                              │
│ - global scheduling, Cargo root permits, and worker leases                    │
│ - singleflight, hedging, speculation, prewarm                                 │
│ - coordinator-authoritative prepare validation and commit                     │
│ - reconciliation, GC policy, explainability                                   │
└───────────────┬─────────────────────────────┬────────────────────────────────┘
                │ control/action events       │ object streams
                ▼                             ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ rabs-wkr                                                                    │
│ Asupersync production runtime                                                 │
│                                                                              │
│ - authenticated worker session and local CAS                                  │
│ - canonical sandbox/execroot materialization                                  │
│ - managed Cargo/rustc/link/build-script/test process groups                   │
│ - filesystem/process/network input observation                                │
│ - early `.rmeta` and diagnostic streaming                                     │
│ - output harvesting, digest verification, and prepared-result offers          │
│ - journals, drain, and crash recovery                                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

Initial deployment may run `rabs-edge` and `rabs-coord` in one binary/process,
but their authority, durable state, and protocol interfaces remain distinct.
The coordinator database is local to the active coordinator and is never placed
on a shared network filesystem.

Optional boundary processes:

```text
SSH                   bootstrap, deployment, repair, break-glass fallback
rabs-reapi-gateway    external REAPI interoperability only
existing HTTP/OTel    compatibility-isolated administrative surfaces
```

## 10. Recommended crate and process boundaries

### 10.1 `rabs-protocol`

Purpose: stable domain and wire schemas shared by wrappers, edge, coordinator, workers, gateways, fixtures, and test harnesses.

Rules:

- no Asupersync dependency;
- no Tokio dependency;
- no filesystem or process effects;
- canonical codecs and schema versions;
- bounded collections, recursion, and payloads;
- forward/unknown-field policy;
- golden wire fixtures;
- compatibility tests for current and previous supported versions.

Primary types:

- `ActionKey`, `ActionKeyEpoch`, `ActionClass`, `ResultKind`;
- `ActionDescriptor`, `ActionSubscriptionContext`, `AttemptDispatchContext`, `CanonicalActionResultManifest`, `AttemptEvidenceBundle`, `ActionPublicationRecord`, `ActionTrustEvaluationRecord`, `ActionFailure`;
- `BuildPathSemanticPolicyId`, `TrustEvidenceTier`, `SubscriberDeliveryState`, `ObservableCommitKind`;
- `ExecutionSnapshotRoot`, `ActionInputManifest`, `NegativeDependencySet`;
- `BuildOperationId`, `SubscriberId`, `ActionGeneration`, `ActionGenerationId`, `AttemptId`, `ExecutionLeaseId`, `LeaseRenewalSeq`, `CoordinatorAuthority`, `WorkerBootGeneration`, `WorkerIncarnationId`, `EdgeBootGeneration`, `EdgeIncarnationId`;
- `OutputPlatformContract`, `ExecutionEligibility`, `ToolchainContract`, `SandboxSemanticPolicyId`;
- `PresentationContract`, `CanonicalCompilerEvent`, `PathTranslationTable`, `DeadlineBudget`, `CausalTimestamp`, `SequenceDomain`;
- `ObservedInputRecipe`, `OutputDeclaration`, `TrustEvidenceRecord`;
- `WorkerCapabilities`, `WorkerPressureSnapshot`;
- `DecisionReceipt`, `ProvenanceReceipt`;
- local wrapper request/response/event envelopes;
- ATP application message payloads.

### 10.2 `rabs-action`

Purpose: pure action semantics and state machines.

Responsibilities:

- action lifecycle transitions;
- subscriber interest accounting;
- attempt fencing;
- deterministic retry classification;
- publication eligibility;
- provisional metadata ownership;
- failure taxonomy;
- action-result validation rules;
- pure reconciliation decisions.

This crate must be runnable in the Asupersync lab and in ordinary deterministic unit/property tests without network or filesystem access.

### 10.3 `rabs-key`

Purpose: canonical semantic key construction, discovery recipes, presentation variants, and explainability.

Responsibilities:

- normalized invocation model, including nested wrapper-chain decoding;
- separation of command snapshot identity from fine-grained action-input closure;
- positive and negative filesystem dependency normalization;
- path-to-content and path-to-logical-unit resolution;
- exact presented-environment normalization;
- conservative dependency-artifact identity and gated projections;
- toolchain and output-platform contract hashing;
- sandbox semantic-policy hashing without scheduler-only implementation details;
- canonical compiler-event and presentation-variant keys;
- key component diffing for `rch why`;
- versioned key and projection epochs;
- compatibility/upgrade invalidation rules.

Key construction returns:

```text
ActionKey
ActionKeyBreakdown
PresentationVariantKey, when exact byte replay requires one
```

The breakdown is a structured, redaction-safe tree of contributing components used for miss attribution and offline audits.

### 10.4 `rabs-cas`

Purpose: durable content-addressed storage, action-cache indexing, object lifecycle, and publication transactions.

Responsibilities:

- immutable blob, pack, and chunk storage;
- ATP object/manifest adaptation;
- streaming digest verification and atomic `put_if_absent`;
- chunk deduplication, deterministic small-object packs, and compression;
- pin, lease, reference, and delayed-tombstone accounting;
- staging and atomic coordinator commit;
- location-, logical-object-, manifest-, and action-entry quarantine;
- periodic scrub, reachability GC, and eviction;
- object-location evidence;
- metadata-store abstraction with a reference SQLite-compatible backend and a gated FrankenSQLite backend;
- optional cold-store and peer-replication adapters.

Large object bytes never enter the metadata database. The active coordinator is the sole writer of authoritative action-index state.

### 10.5 `rabs-sandbox`

Purpose: coherent snapshot capture, canonical execroot construction, kernel isolation, environment policy, input observation, and output harvesting.

Responsibilities:

- mutation-safe source snapshot capture and path-dependency closure;
- Linux mount/user/pid/network namespaces and cgroups;
- canonical Cargo-driver and child-process path layout;
- immutable source mounts and closed authoritative input views;
- toolchain/sysroot/SDK mounts;
- stable `CARGO_HOME`, `HOME`, `OUT_DIR`, incremental, temp, locale, hostname, and secret-slot paths;
- complete explicit environment construction;
- filesystem read, failed-open, directory enumeration, symlink, subprocess, and network observation;
- strict-hermetic versus host-audit isolation profiles;
- path leak detection;
- output-path and side-effect enforcement;
- platform-specific authority classification;
- cleanup and failure bundles.

### 10.6 `rabs-scheduler`

Purpose: build-action admission and placement, distinct from Asupersync’s internal runtime scheduler.

Responsibilities:

- coordinator Cargo root-permit brokerage plus host- and worker-local jobserver policy;
- worker candidate scoring;
- CPU/memory/disk/IO admission classes;
- PSI and cgroup feedback;
- cache locality and transfer break-even;
- critical-path and fan-out priorities;
- speculative/foreground promotion;
- hedging policy;
- fairness and starvation bounds;
- policy receipts and replay.

### 10.7 `rabs-asupersync`

Purpose: the only broad adapter between RABS domain types and Asupersync/ATP implementation types.

Responsibilities:

- `Cx`/region ownership adapters;
- action actor hosting;
- process management adapters;
- remote named-computation registry;
- ATP session/stream adapters;
- ATP object/manifest conversion;
- supervision configuration;
- lab scenario helpers;
- observability conversion;
- pressure/admission bridge;
- API compatibility shims across pinned Asupersync revisions.

No durable or public RABS schema may contain a type from this crate.

### 10.8 `rabs-edge` and `rabs-coord`

The implementation may initially ship both roles in a binary named `rabsd`, but the roles remain explicit.

`rabs-edge` responsibilities:

- local wrapper endpoint;
- daemon-dead circuit breaker and safe local fallback;
- canonical Cargo-driver launch;
- coherent source snapshot and path-dependency capture;
- edge-local object cache and upload;
- virtual-to-requesting-worktree path translation;
- target-tree materialization;
- subscriber connection lifecycle;
- reconnect to the coordinator.

`rabs-coord` responsibilities:

- one active durable coordinator authority;
- fleet-wide `DiscoveryActor` and `ActionActor` registries;
- action-key/policy validation;
- metadata store and action index;
- global scheduling, Cargo root permits, and worker selection;
- source/object availability planning;
- attempt leases and fencing;
- coordinator-only action-result commit;
- operation reconciliation;
- provenance, trust, explainability, GC policy, and speculation.

The first production topology uses one active coordinator. Standby recovery may be added later with explicit authority-term, credential-generation, and external-fencing rules; active-active consensus is out of scope until justified.

### 10.9 `rabs-wkr`

Purpose: trusted worker daemon.

Responsibilities:

- authenticated ATP session;
- worker capability and pressure reporting;
- CAS/object fetch and seeding;
- sandbox materialization;
- compiler/linker/test process execution;
- streaming diagnostics and early artifacts;
- output verification and staging;
- result preparation;
- cancellation/drain and crash recovery.

It should be a specialized worker, not a mode added to the broad `atpd` binary.

### 10.10 Tiny wrapper binaries

Recommended binaries:

- `rch-rustc`: outer `RUSTC_WRAPPER` path for dependency and general interception;
- `rch-workspace-rustc`: optional `RUSTC_WORKSPACE_WRAPPER` path for workspace classification;
- `rch-link`: exact linker-action interception;
- `rch-cc`, `rch-cxx`, `rch-ar`: native compilation interception;
- existing `rch exec`: canonical Cargo-driver and whole-command entry;
- optional nextest target-runner adapter after feasibility proof.

Cargo may nest wrappers as:

```text
$RUSTC_WRAPPER $RUSTC_WORKSPACE_WRAPPER $RUSTC <rustc args...>
```

Therefore the outer wrapper must decode and preserve the entire compiler-wrapper chain rather than assuming its first argument is always the rustc binary. Wrapper configuration changes Cargo fingerprints and the first enablement may rebuild; doctor and documentation must state this explicitly.

Wrapper rules:

- minimal dependencies and startup time;
- no full runtime initialization;
- no remote connection establishment;
- no direct shared-CAS or action-index writes;
- one local edge-daemon round trip;
- immediate fallback to the original wrapper/tool chain only while the subscriber remains before the applicable transcript/stateful exposure frontier;
- byte/line streaming rather than whole-output buffering;
- top-level panic containment with `panic = "unwind"` and a nonprinting pre-exposure panic hook by default; size-oriented abort-on-panic is disallowed unless a separate minimal parent guard can still execute the original chain before exposure.

### 10.11 `rabs-reapi-gateway`

Purpose: optional isolated compatibility process.

Responsibilities:

- translate external REAPI CAS/ActionCache/Execution concepts to native RABS operations;
- expose or consume external cache backends where useful;
- carry no authority to weaken native RABS fencing or trust semantics;
- remain deployable and removable independently.

The gateway may use Tokio/Tonic because it is not the critical internal path.

### 10.12 Binary-specific optimization profiles

RABS must not inherit one workspace-wide size-optimized release profile for every binary. The performance objective differs by role:

- tiny wrappers optimize startup latency and footprint, with `opt-level = "z"`/`"s"`, stripping, and LTO selected only after startup benchmarks; panic containment remains a correctness requirement and is not traded away for size;
- `rabs-edge`, `rabs-coord`, and `rabs-wkr` optimize sustained latency/throughput, hashing, scheduling, protocol, CAS, and materialization performance, normally beginning from `opt-level = 3` with measured LTO/codegen-unit/allocator choices;
- operational builds retain enough symbols/build IDs for crashpacks and profiling according to release policy;
- package-specific profiles or separate release workspaces prevent wrapper goals from slowing daemons or vice versa;
- every profile is benchmarked on startup, local-hit, cache-miss, transfer, hash, and compile-storm traces.

RCH's currently reviewed workspace-wide size-oriented release profile is therefore an input to migrate, not a profile RABS should copy unquestioningly.

## 11. Responsibility matrix

| Concern | Edge | Coordinator | Worker | Asupersync/ATP | External/OS |
|---|---|---|---|---|---|
| Local wrapper/fail-open | authoritative | policy input | — | generic lifecycle | Unix socket/process |
| Coherent command snapshot | authoritative capture | validates identity | materializes | object transfer | filesystem snapshot APIs |
| Cargo/rustc semantics | observes/translates | semantic policy | executes | generic lifecycle only | Cargo/rustc binaries |
| Action key | contributes local facts | authoritative validation | verifies descriptor | opaque identifier | — |
| Action actor/singleflight | subscriber proxy | authoritative | attempt only | region mechanism | — |
| Regions/cancellation | local regions | fleet/action regions | attempt regions | authoritative mechanism | signals/kernel process model |
| Object manifests | capture/materialize | build object semantics | stage/verify | ATP generic object types | filesystem/object store |
| Durable CAS | edge-local cache | lifecycle/index authority | worker-local cache | chunk/delta/journal primitives | disks/object store |
| Publication | none | sole commit authority | prepared-result offer | transport/identity primitives | metadata transaction |
| Worker scheduling | — | authoritative | resource evidence | pure admission helpers | cgroups/PSI/jobserver |
| Runtime scheduling | configuration | configuration | configuration | authoritative | OS threads/reactor |
| Sandboxing | canonical Cargo launch | policy | enforcement | cancellation/capability integration | namespaces/VM/seccomp/cgroups |
| Trust | path/subscriber evidence | authoritative serving policy | authenticated execution evidence | identity/transport primitives | TLS/kernel isolation |
| Lab/fault testing | RABS scenarios | RABS scenarios | RABS scenarios | authoritative harness | test host |
| REAPI | optional gateway mapping | not authoritative | not authoritative | not authoritative | external services |


# Part V. Runtime ownership model

## 12. Region tree

A representative edge region tree is:

```text
RabsEdgeRoot
├── LocalApiRegion
│   ├── WrapperConnectionRegion(...)
│   └── AdminConnectionRegion(...)
├── CoordinatorSessionRegion
├── CargoDriverRegion(command_id)
│   ├── CargoRootPermitRegion
│   ├── CoherentSnapshotRegion
│   ├── PathTranslationRegion
│   ├── SubscriberRegion(subscriber_id)
│   └── LocalMaterializationOrFallbackRegion
├── EdgeObjectCacheRegion
└── EdgeObservabilityRegion
```

A representative coordinator region tree is:

```text
RabsCoordinatorRoot(coordinator_authority)
├── EdgeSessionRegion(edge_peer_id)...
├── WorkerFleetRegion
│   ├── WorkerSessionRegion(worker_a)
│   └── WorkerHealthCollectorRegion(...)
├── BuildOperationRegistryRegion
│   └── BuildOperationRegion(build_operation_id)
├── DiscoveryRegistryRegion
│   └── DiscoveryRegion(action_family)
├── ActionRegistryRegion
│   └── ActionRegion(action_key)
│       ├── SubscriberSetRegion
│       ├── CacheLookupRegion
│       ├── AttemptSetRegion
│       │   └── AttemptProxyRegion(attempt_id)...
│       ├── OutputVerificationRegion
│       └── PublicationRegion
├── SchedulerAndRootPermitRegion
├── SpeculationRegion
├── GarbageCollectionRegion
├── ReconciliationRegion
└── ObservabilityRegion
```

A representative worker action region is:

```text
WorkerActionAttemptRegion(action_key, action_generation, attempt_id, execution_lease_id, worker_boot_generation)
├── ObjectFetchRegion
├── SandboxMaterializationRegion
├── InputEnforcementAndTraceRegion
├── CompilerProcessRegion
│   ├── StdoutDrainRegion
│   ├── StderrDrainRegion
│   └── DescendantProcessGroup
├── EarlyMetadataRegion
├── OutputHarvestRegion
├── OutputUploadRegion
├── PreparedResultOfferRegion
└── CleanupFinalizerRegion
```

The ownership tree must be reflected in tracing and crashpacks so every leaked effect can be attributed to a region, coordinator authority, build operation, action generation, action, and attempt.

## 13. Obligation catalog

RABS-specific obligations should be explicit domain types even when implemented using generic Asupersync machinery:

- `CoordinatorAuthorityObligation`;
- `CargoRootPermitObligation`;
- `WorkerAssignmentObligation`;
- `ActionGenerationObligation`;
- `ExecutionLeaseObligation`;
- `AttemptFenceObligation`;
- `CoherentSnapshotObligation`;
- `ActionInputClosureObligation`;
- `SourceSnapshotPinObligation`;
- `InputObjectPinObligation`;
- `OutputStagingPinObligation`;
- `ProvisionalMetadataObligation`;
- `DirectProducerCommitObligation`;
- `TransitiveProvisionalLineageObligation`;
- `DiagnosticStreamObligation`;
- `ProcessGroupDrainObligation`;
- `PreparedResultOfferObligation`;
- `CoordinatorPublicationObligation`;
- `SubscriberDeliveryObligation`;
- `SubscriberNotificationObligation`;
- `PerSubscriberObservableCommitObligation`;
- `TargetStateLeaseObligation`;
- `WinnerCommitObligation`;
- `SandboxCleanupObligation`;
- `JournalCheckpointObligation`.

A producing attempt may offer a candidate only after its attempt-local success obligations resolve. Coordinator publication additionally requires canonical-result, object-closure, authority, and provisional-lineage obligations. Subscriber delivery and action-actor quiescence may continue after publication. A cancelled or failed path still resolves its cleanup obligations before its owning region closes. Cargo root permits are held for the complete Cargo process lifetime and released exactly once.

## 14. Outcome mapping

Asupersync’s four-valued outcome model should map into RABS without flattening important distinctions:

| Asupersync outcome | RABS interpretation |
|---|---|
| `Ok` | successful result or successful cleanup |
| `Err` | deterministic application failure or typed infrastructure error, depending on phase |
| `Cancelled` | explicit cancellation with attributable reason |
| `Panicked` | internal defect; quarantine attempt and produce crashpack |

RABS additionally distinguishes cacheability and retryability:

```text
DeterministicFailure
VolatileFailure
InfrastructureFailure
WorkerLost
LeaseExpired
Cancelled
OomKilled
SignalTerminated
InternalPanic
PolicyRefused
```

Only explicitly classified deterministic failures are eligible for immutable failure publication plus short-lived serving authority, and only after normal termination and complete provenance capture.


---

# Part VI. Action model, identity, and lifecycle

## 15. Action classes

`ActionClass` describes output semantics, not why or with what priority an action was requested.

Initial semantic classes:

```text
CargoWholeCommandBounded
RustcDependencyCompile
RustcWorkspaceCompile
RustdocCompile
Link
BuildScriptCompile
BuildScriptRun
NativeCompileC
NativeCompileCxx
NativeArchive
BindgenGeneration
CodeGeneratorRun
NextestTestCase
TestBinaryBatch
DoctestCompile
DoctestRun
ClippyCompile
BenchmarkCompile
BenchmarkRun
ToolchainProbe
WorkerProbe
```

The following are **not** action classes because making them classes would fragment otherwise identical work:

```text
Speculative
GitPrewarm
CIRequired
DeterminismAudit
CacheVerification
AdministrativeRepair
```

They are represented outside the semantic key as `SubscriberKind`, `AttemptPurpose`, priority, and verification policy. A speculative compile and a foreground compile with identical semantics must join the same `ActionActor`.

Each action class has a policy record defining:

- local-cache, remote-execution, deterministic-failure publication/serving, speculation, and hedge eligibility;
- required isolation and input-observation profile;
- declared/observed/negative input rules;
- output and side-effect declarations;
- exact presented-environment policy;
- network/secret policy;
- default budget and resource class;
- whether provisional outputs are allowed;
- verification and publication evidence requirements.

`BenchmarkCompile` may reuse ordinary compile artifacts. `BenchmarkRun` is non-result-cacheable by default because timing/resource measurements are observations of a particular machine/load; it may be remotely scheduled only on an explicit hardware/pressure profile. A benchmark harness declared as a functional deterministic test uses `TestBinaryBatch` instead.

## 16. Action descriptor

RABS separates immutable execution materialization from semantic action identity.

Conceptual schema:

```rust
struct ActionDescriptor {
    schema_version: u32,
    key_epoch: u32,
    projection_epoch: u32,
    action_class: ActionClass,
    normalized_invocation: NormalizedInvocation,
    virtual_working_directory: VirtualPath,
    action_inputs: ActionInputManifest,
    negative_dependencies: NegativeDependencySet,
    dependency_inputs: Vec<DependencyArtifactInput>,
    toolchain: ToolchainContract,
    output_platform: OutputPlatformContract,
    environment: PresentedEnvironment,
    sandbox_semantic_policy: SandboxSemanticPolicyId,
    build_path_semantic_policy: BuildPathSemanticPolicyId,
    output_declarations: Vec<LogicalOutputDeclaration>,
    execution_semantics: ExecutionSemanticsContract,
}

struct ActionSubscriptionContext {
    execution_snapshot_root: ObjectId,
    requesting_edge: PeerId,
    build_operation_id: BuildOperationId,
    subscriber_id: SubscriberId,
    subscriber_kind: SubscriberKind,
    presentation: PresentationContract,
    compiler_events: CanonicalCompilerEventContract,
    pipelining: PipeliningContract,
    path_translation: PathTranslationTableId,
    execution_requirements: ExecutionRequirements,
    minimum_evidence_tier: TrustEvidenceTier,
    queue_priority: Priority,
    deadline_budget: Option<DeadlineBudget>,
}

struct ExecutionRequirements {
    minimum_isolation_profile: IsolationProfileId,
    privacy_scope: AccessScopeId,
    required_worker_capabilities: CapabilitySet,
    locality_and_policy_constraints: ExecutionConstraintSet,
}

struct AttemptDispatchContext {
    attempt_authority: AttemptAuthority,
    attempt_purpose: AttemptPurpose,
    selected_execution_snapshot_root: ObjectId,
    selected_worker: PeerId,
    execution_eligibility_receipt: ExecutionEligibilityReceipt,
    resource_grant: ResourceGrant,
    sandbox_implementation: SandboxImplementationId,
    object_source_plan: ObjectSourcePlan,
}
```

`ActionDescriptor` is immutable after final key computation. `ActionSubscriptionContext` may change through promotion, path translation, minimum evidence/isolation/privacy requirements, or subscriber presentation without changing the artifact key. `ExecutionRequirements` contains only serving/placement constraints proven not to alter output bytes or exit behavior. `AttemptDispatchContext` is created only after coordinator scheduling and is unique to one concrete attempt; it never becomes part of semantic result identity. Any requirement capable of changing output bytes or exit behavior belongs in `ActionDescriptor`/`OutputPlatformContract`, not in `ExecutionRequirements`.

Compiler-event and pipelining contracts live in request/presentation context by default because they govern observation, replay, and readiness rather than generated artifact identity. A field moves into the semantic descriptor only when a versioned toolchain-specific proof demonstrates that it can change exit status or artifact bytes. Diagnostic and lint flags are therefore classified conservatively: ambiguous flags remain in the semantic invocation or force a distinct presentation variant.

`execution_snapshot_root` is recorded in provenance and used to materialize discovery or whole-command sandboxes, but it does **not** automatically enter a fine-grained action key. A bounded whole-command action may intentionally key on the full snapshot because the complete snapshot is its declared input.

## 17. Action key composition

Conceptually:

```text
ActionKey = H_domain(
    "rabs.action-key.vN",
    key_epoch,
    projection_epoch,
    action_class,
    normalized_invocation,
    virtual_working_directory,
    action_input_manifest,
    negative_dependency_set,
    dependency_artifact_inputs,
    presented_environment,
    toolchain_contract,
    output_platform_contract,
    sandbox_semantic_policy,
    build_path_semantic_policy,
    execution_semantics,
    logical_output_declarations
)
```

Every component has canonical serialization and explicit schema identity. Queue priority, worker identity, kernel version, subscriber kind, attempt purpose, cgroup size, transfer plan, and presentation rendering are excluded unless they alter program outputs or exit semantics.

### 17.1 Key and projection epochs

`key_epoch` permits cheap global invalidation when key logic changes. `projection_epoch` independently versions dependency and input projections. Epoch changes are required for:

- adding a previously omitted semantic or negative input;
- changing path or environment normalization;
- changing dependency-artifact projection;
- changing sandbox-visible state;
- changing canonical serialization;
- changing logical output interpretation.

An epoch bump creates a cold namespace. It never reinterprets old entries under new semantics.

### 17.2 Normalized invocation

The normalized invocation retains semantic order but removes wrapper, transport, and local-placement details.

It includes:

- the fully decoded compiler-wrapper chain and actual compiler identity;
- compiler/linker arguments after wrapper-only flags are removed;
- argument ordering where meaningful;
- response-file bytes and semantic position rather than unstable local filenames;
- `--extern` mappings resolved to the conservative dependency-artifact identities;
- crate type, edition, target, profile, features, cfgs, lint flags, codegen flags, and emit modes;
- link arguments and native-library identities;
- working-directory-sensitive argument paths after canonical virtualization;
- stdin content digest when stdin is used.

The actual virtual working directory is the separate `ActionDescriptor.virtual_working_directory` component and is not duplicated inside `NormalizedInvocation`.

On Unix, argv elements, response-file path names, environment keys/values, paths, and symlink targets are canonical byte strings, not assumed UTF-8 `String`s. Human/JSON displays use an escaped or loss-marked presentation representation without changing the keyed bytes. Windows support uses a separately versioned native path/environment encoding contract.

It excludes:

- edge/coordinator socket paths;
- request, subscriber, action-attempt, and worker IDs;
- real worktree and physical staging roots;
- local target-directory spelling after virtual mapping;
- local jobserver descriptors;
- presentation-only color and terminal width.

### 17.3 Command snapshots, positive inputs, and negative dependencies

A coherent immutable `ExecutionSnapshotRoot` represents the complete command snapshot and path-dependency closure. It is used for discovery, materialization, provenance, and reproduction.

A fine-grained `ActionInputManifest` contains only inputs the action may observe authoritatively:

- virtual path and object identity;
- file type, executable bit, and semantic metadata;
- symlink target and resolution chain;
- declared directories and enumeration results;
- approved generated/toolchain objects.

Environment-variable presence/absence belongs exclusively to `PresentedEnvironment`; it is not duplicated in the filesystem/namespace set.

`NegativeDependencySet` records filesystem and executable-namespace absence observations that can change behavior:

- failed opens and missing paths;
- directory listings and glob results;
- `PATH` lookup misses and selected executable;
- missing symlink targets or alternative resolution candidates.

A new file that changes a previous failed open or directory listing must invalidate the key. Timestamps are not source identity by default.

Snapshot capture must be coherent. Prefer filesystem snapshots/reflinks. Otherwise read/hash with before-and-after inode/size/mtime/version verification and retry if any input mutates during capture. `.git` is hidden unless represented by an explicit git-state object.

### 17.4 Presented environment

RABS creates a minimal exact environment and hashes every presented key/value and relevant absence. It does not claim to discover arbitrary `getenv` calls through eBPF, fanotify, or syscall tracing because environment reads ordinarily occur from process memory.

Environment categories:

```text
SemanticConstant
SemanticHashed
SemanticNormalized
ScrubbedAbsent
SecretOpaqueDigest
VolatileRefusal
PresentationOnly
```

Rules:

- `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, features, cfgs, deployment targets, and target features are semantic inputs;
- locale, timezone, username, `HOME`, and hostname are fixed when the isolation profile can enforce them;
- `PATH` is a canonical ordered tool manifest; selected tools and lookup failures are key inputs;
- jobserver descriptors are excluded and replaced on the execution host;
- git state is explicit or hidden;
- a secret that can affect output is either noncacheable/nonshareable or contributes a trusted opaque HMAC over secret value/version/scope; capability ID alone is insufficient;
- raw secret values never appear in a key breakdown, receipt, or diagnostic archive.

Environment ordering and raw bytes are constructed deterministically for platforms where a process can observe them. A lossy UTF-8 conversion is never used as the semantic key input.

### 17.5 Toolchain contract

The toolchain contract includes at least:

- compiler binary digest and verbose commit identity;
- LLVM/backend identity;
- sysroot object root;
- Cargo identity for canonical Cargo/whole-command actions;
- rustdoc/clippy component identity when applicable;
- linker and native-tool identities;
- target specification digest;
- unstable-feature profile;
- allocator/runtime libraries where output-sensitive;
- RABS semantic adapter epoch, not merely the RABS binary version.

Toolchains are immutable ATP `DatasetObject`s mounted at stable visible paths such as `/__rabs/toolchain`, not at a digest-bearing program-visible path.

### 17.6 Output platform versus execution eligibility

`OutputPlatformContract`, which enters the key, includes:

- target triple and ABI;
- host ABI for proc macros, build scripts, and host tools;
- explicit CPU feature/baseline contract;
- libc/runtime, linker format, SDK/Xcode identity, deployment target, and unsigned/ad-hoc-signing policy where relevant;
- filesystem semantic class by default for any action that can observe namespace behavior; omission requires an action-class proof;
- target specification and output architecture.

`ExecutionEligibility`, which does not enter the output key unless proven output-semantic, includes:

- kernel version and namespace/VM capabilities;
- available RAM/disk/CPU;
- pressure and queue state;
- worker identity and location;
- sandbox implementation choice satisfying the same semantic policy;
- transfer locality.

`-C target-cpu=native` is never silently normalized. It selects an explicit host cohort and key namespace, or is refused for portable fleet caching.

### 17.7 Dependency artifact inputs

The safe default is the exact content identity of the artifact actually supplied to the consumer invocation:

- if Cargo/rustc passes `.rmeta`, hash that `.rmeta`;
- if it passes an `.rlib`, hash the complete `.rlib` by default;
- proc macros and host tools hash the executable/dylib and runtime dependencies;
- link steps hash ordered implementation artifacts and link semantics;
- LTO modes hash every bitcode/rlib component actually consumed.

A reduced projection, such as extracting an rlib metadata member while ignoring code, is permitted only when all of the following hold:

1. the invocation class proves rustc cannot observe the omitted bytes;
2. the extractor and projection schema are versioned;
3. exact-artifact and projected-key shadow runs produce zero divergence over the required corpus;
4. the projection is disabled automatically for ambiguous flags or future toolchain changes.

Early cutoff then emerges automatically: if every conservative or proven semantic dependency input remains identical, the downstream key hits. RABS does not infer source-level API equality itself.

### 17.8 Logical output declarations

The semantic key includes expected logical output classes and virtual paths, never physical staging locations. Declarations specify whether outputs are files, trees, symlinks, executable artifacts, diagnostics, dep-info, build-script metadata, or provisional metadata.

Physical materialization paths on an edge host are carried in `ActionSubscriptionContext` and a result materialization map. They do not alter the artifact identity.

### 17.9 Presentation and event replay

RABS stores a canonical structured compiler event log. The semantic `ActionKey` includes only diagnostic/lint settings that can alter exit behavior or generated artifacts. Color, terminal width, real-path translation, and human formatting live in a `PresentationContract`.

- Exact byte-transcript replay requires a matching `PresentationVariantKey`.
- Where a canonical structured diagnostic can be safely re-rendered or path-translated, one semantic artifact result may serve multiple presentation contracts.
- If safe rendering fidelity is uncertain, RABS bypasses transcript reuse rather than polluting the artifact key or inventing output.

## 18. Action-key discovery cycle

Rust, proc-macro, build-script, generator, and test actions may have filesystem/process inputs not fully knowable before first execution. RABS therefore uses a versioned discovery cycle.

### 18.1 Stable action-family and discovery singleflight

An `ActionFamilyKey` identifies the stable unit and invocation shape without embedding source content:

- stable logical repository scope plus package/target/unit identity;
- semantic compiler invocation shape;
- toolchain and projection epochs;
- action class;
- sandbox semantic policy and build-path semantic policy;
- dependency roles, output-platform class, and host/target context;
- toolchain behavior/capability profile and semantic-adapter epoch.

It intentionally excludes the current source root and observed input digests. Otherwise every source edit would orphan the recipe.

Concurrent first-seen requests join a coordinator-owned `DiscoveryActor`. Discovery may execute once against a conservative immutable command snapshot, then publishes or joins the final `ActionActor` after closure and final-key construction.

### 18.2 Discovery execution

1. Build a coherent immutable command snapshot and conservative preliminary descriptor.
2. Execute in nonserving discovery mode with the broad snapshot available read-only.
3. Capture dep-info/binary-dep-info, successful and failed filesystem opens, directory enumeration, symlink resolution, subprocess/tool selection, network attempts, and output writes.
4. Use the exact constructed environment as the environment closure; do not rely on `getenv` tracing.
5. Record clock, randomness, hostname, git, and other ambient surfaces according to the isolation profile and its explicit no-claims.
6. Produce positive inputs, negative dependencies, volatility evidence, and a final descriptor.
7. Recompute the final action key.
8. Treat the broad-snapshot discovery output as a candidate, not automatically as an authoritative result.
9. Re-execute once under the enforced closed view and compare outputs/events before the first authoritative publication, except for action classes whose complete immutable closure was known and enforced before their first run.
10. Publish only under the final key and only if the trust/isolation profile permits it.

### 18.3 Authoritative subsequent execution

1. Load the prior recipe by `ActionFamilyKey` and recipe epoch.
2. Resolve and hash the known positive and negative inputs from the new coherent snapshot.
3. Construct the final key directly and perform cache lookup.
4. On a miss requiring execution, expose only the closed input view plus approved capabilities.
5. If enforcement observes a new read, changed directory enumeration, path escape, or undeclared executable, abort the authoritative attempt before publication, update the recipe, and re-enter discovery.
6. Sample stable families for re-audit and stock differential execution.

Recipes are optimization hints, never trust anchors. A recipe cannot authorize serving without the final input-complete key and compatible trust evidence.

## 19. Volatility and isolation-authority classification

Actions receive both an effect classification and an isolation-evidence profile.

Effect classes:

| Class | Meaning | Policy |
|---|---|---|
| `Hermetic` | all positive/negative inputs and effects are closed | full eligibility within trust profile |
| `HermeticWithCapabilities` | approved secret/fetched/service capability affects semantics | scoped key/access namespace |
| `ObservedStable` | undeclared filesystem/process inputs were discovered and then enforced | cacheable after recipe validation |
| `PathSensitive` | output genuinely depends on an unvirtualized path | restricted namespace or local only |
| `HostIdentitySensitive` | observes real hostname/user/home/machine identity | explicit captured input or volatile/local |
| `ClockSensitive` | reads real time | volatile unless strict time virtualization is proven |
| `RandomnessSensitive` | reads nondeterministic entropy | volatile unless a declared deterministic seed is the input |
| `GitStateSensitive` | reads `.git` or VCS commands | explicit git-state object or volatile |
| `NetworkSensitive` | external mutable network input | captured-fetch split or volatile |
| `SecretSensitive` | secret value can affect output | nonshareable or opaque-secret scoped |
| `SideEffecting` | externally visible side effect is not represented as an output | no result-cache serving |
| `Nondeterministic` | identical closed inputs diverge | shared-cache denylist; retain evidence |
| `Unclosable` | effect/input cannot be captured or enforced safely | no authoritative cache |

Isolation profiles:

| Profile | Evidence boundary | Serving authority |
|---|---|---|
| `StrictHermeticLinux` | namespace/cgroup policy, explicit env, closed filesystem/process/network view, validated time/randomness policy | eligible for authoritative fleet sharing |
| `StrictHermeticVm` | VM/chroot-style stable root and validated input/effect boundary | eligible within compatible platform class |
| `HostSandboxAudit` | useful tracing and containment, but raw clock/randomness or read closure may escape | shadow/dev-local by default |
| `DependencyImmutableFastPath` | immutable checksummed dependency source plus conservative exact inputs | authoritative for admitted dependency classes |
| `VolatileLocal` | real ambient effects exposed | local execution only |

`SOURCE_DATE_EPOCH`, a fixed hostname, or best-effort syscall tracing are helpful controls, not proof by themselves. `clock_gettime` may use vDSO, entropy may arrive through several interfaces, and macOS FSEvents reports changes rather than authoritative reads. The profile records what was actually enforced.

## 20. Four interacting state machines

RABS must not compress the entire system into one lifecycle enum. Four state machines interact through typed events and obligations.

### 20.1 Build operation state

A `BuildOperation` represents one user/agent/IDE/CI Cargo command or other top-level validation intent. It owns the requested→resolved immutable snapshot lineage, the currently sealed execution generation, root permit, live wrapper connections, and the set of action subscriptions created while the command runs.

```text
Created
  → Snapshotting
  → CargoStarting
  → CargoRunning
  → CargoDraining
  → Completed
```

Terminal alternatives:

```text
Cancelled
FailedBeforeStart
FailedAfterObservableCommit
LocalFallbackCompleted
AbandonedClient
InternalFailure
```

One build operation may subscribe to many action keys. A single action actor may simultaneously serve subscribers from many build operations and hosts. `BuildOperationId` therefore never belongs to the semantic action key or to the action actor as a singleton field.

### 20.2 Logical action publication and serving state

The authority-bearing publication slot is deliberately small:

```text
Absent
  → Executing(ActionGenerationId)
  → Committed(ActionPublicationRecordId)
```

When all attempts in an executing generation terminate without an eligible candidate, the coordinator durably closes that never-reusable generation and returns the active slot to `Absent` while retaining its generation fence/history. A later request creates a new opaque `ActionGenerationId`. A cache hit observes an existing publication and does not commit again.

Serving/index policy is a separate versioned record:

```text
Eligible
EvidencePending
ExpiredNeedsRevalidation
Quarantined
ObjectsUnavailable
EvictedFromActiveIndex
```

Successful and admitted deterministic-failure publications use the same immutable canonical form; `ResultKind` distinguishes them. Failure TTL, trust promotion/demotion, quarantine, local-object eviction, and retention policy change serving disposition rather than rewriting the publication. Expired deterministic failures are revalidated against the committed result; a mismatch is divergence, not a replacement publication. An eviction that forgets active lookup data retains a bounded generation/result tombstone until every stale lease and publication-conflict window is closed.

### 20.3 Execution attempt state

Each concrete attempt has an independent lifecycle and lease:

```text
Created
  → LeaseOffered
  → LeaseAccepted
  → AwaitingInputs
  → Materializing
  → Running
      ├── MetadataReady(LogicalOutputId)  [event, at most once per attempt/output]
      └── Diagnostic/Progress events
  → ProcessExited(NormalizedProcessOutcome)
      ├── success → HarvestingOutputs → UploadingOutputs → VerifyingOutputs
      ├── eligible deterministic failure → HarvestingCanonicalObservations → VerifyingFailure
      └── nonpublishable abnormal outcome → Draining
  → PreparedResultOffered
  → AcceptedAsWinner | RejectedAsDuplicate | RejectedAsStale | RejectedAsDivergent
  → Draining
  → Finished
```

Cancellation, OOM, signal termination, volatile failure, infrastructure failure, lease expiry, worker restart, quarantine, and internal panic are nonpublishable abnormal outcomes. A deterministic tool failure reaches `PreparedResultOffered` only for an action class whose deterministic-failure publication policy validates complete inputs, canonical observations, normalized exit semantics, and absence of materializable partial outputs. Losing or stale attempts may leave verified immutable blobs in CAS but cannot mutate the action pointer.

### 20.4 Subscriber delivery, transcript, and stateful observable-commit state

Each subscriber/wrapper has one ordered delivery stream and two exposure frontiers:

```text
Subscribed
  ↔ WaitingForResultOrAttempt
  ↔ StagingPrivateOutputs

transcript-only item:
  TranscriptIntentRecorded(sequence)
    → EmittingTranscript(sequence)
    → TranscriptExposed(sequence) after full wrapper acknowledgement
    → return to Waiting/Staging

stateful item:
  CommitIntentRecorded(sequence)
    → EmittingStatefulObservable(sequence)
    → StatefulObservableCommit(sequence)
    → return to Waiting/Staging for the next item

terminal item after all owned outputs:
  → DeliveryComplete
```

`TranscriptDeliveryUncertain(sequence)` is entered when a complete transcript frame may have reached the wrapper but full exposure was not acknowledged. `DeliveryUncertain(sequence)` is entered when the edge/wrapper connection dies after stateful commit intent but before a complete delivery acknowledgement. Stateful observable facts include:

- atomically installing a Cargo-visible declared output at its live destination;
- replaying a rustc metadata/artifact notification after the named output is complete;
- returning a cached deterministic terminal failure;
- returning a completed cached terminal result.

Ordinary diagnostics, stdout, stderr, and progress are transcript-only unless a tool/protocol-specific contract makes a particular event state-advancing. They remain ordered and sequence-acknowledged, but do not require a durability transaction/fsync per diagnostic line. Their first fully acknowledged exposure sets `TranscriptExposed`; an unacknowledged in-flight transcript is conservatively `TranscriptDeliveryUncertain`, never silently pre-exposure.

`TranscriptIntentRecorded` denotes assignment of a framed subscriber sequence and retention in the edge/wrapper reconnect window, not an independent metadata-store fsync for each line. The wrapper accepts only complete length-bounded frames and, on reconnect, reports both its last fully exposed sequence and any frame whose write may have begun. If the wrapper survives an edge crash, that report reconstructs uncertainty; if both processes disappear, the Cargo command has failed and a later invocation starts a new `BuildOperation` rather than replaying an unknowable partial transcript.

The edge durably records stateful commit intent before the first visible rename/write or state-advancing readiness/terminal event. The wrapper acknowledges an event sequence only after it has completely written the item to Cargo and completed any required output exposure. Reconnect compares both sides' last fully delivered sequence. If stateful delivery is uncertain, RABS neither blindly replays nor launches uncoordinated local fallback; it reconnects/resolves or fails the current Cargo command coherently. If the wrapper itself was killed, its Cargo parent observes failure and a later Cargo invocation starts a fresh build operation.

Seamless unlabelled local fallback is safe only before transcript exposure and before any stateful commit intent/visible state. After transcript-only exposure, the default is reconnect or coherent failure; an explicitly configured `LabeledTranscriptRecovery` mode may detach the subscription and run the original chain with an unmistakable boundary marker when exact transcript fidelity is not required. After stateful commit intent, uncoordinated fallback is forbidden. Another subscriber independently tracks both frontiers and may remain in a different state.

### 20.5 Transition and durability rules

- Final positive/negative input closure and conservative dependency identity precede action lookup or generation creation.
- The coordinator creates at most one active `ActionGeneration` for a missing key.
- Every hedge/retry attempt has a unique `AttemptId` and `ExecutionLeaseId`; attempts do not share one mutable execution lease.
- Worker `MetadataReady` is provisional until the edge fully materializes the output and advances that subscriber's delivery state.
- Worker preparation supplies a candidate only; coordinator compare-and-set performs the sole logical action commit.
- A same-key/different-semantic-result candidate is divergent, not merely late; evidence-only differences append evidence, and observable-only differences enter presentation/observability quarantine.
- Subscriber delivery may continue from a committed result after the producing attempt has drained.
- No abnormal attempt terminal becomes a committed deterministic failure or success without the action-class-specific publication checks.
- State transitions that survive acknowledgement are durably recorded before the acknowledgement is sent.
- Subscriber terminal success and non-provisional final output delivery require the complete provisional ancestor closure to be committed; early metadata may be delivered provisionally under the dedicated lineage journal.
- Every state-advancing destination rename/readiness/terminal event uses the subscriber delivery write-ahead protocol; transcript-only events use ordered acknowledgement without pretending to be stateful commits. Delivery loops over many sequence items, and neither `TranscriptDeliveryUncertain` nor `DeliveryUncertain` is ever treated as a pre-exposure state.

## 21. Action actor

The authoritative `ActionActor` lives only in `rabs-coord` and owns:

- immutable action descriptor, descriptor digest, and action key;
- current publication slot, active `ActionGeneration` if any, immutable publication history, and separately versioned serving/trust disposition;
- subscribers across edge hosts, each with `BuildOperationId`, priority/deadline, presentation context, and independent delivery/observable-commit state;
- cache lookup, retention, quarantine, object-closure state, append-only evidence set, and versioned trust evaluations;
- attempt set, with one independent execution lease and worker incarnation per attempt;
- worker-selection receipts and generation-level retry/hedge budget;
- provisional artifacts and the transitive producer-lineage graph;
- prepared canonical-result candidates, attempt-evidence bundles, and compare-and-set winner state;
- final committed result, deterministic-failure entry, or terminal generation outcome;
- provenance and canonical compiler-event stream.

The actor does **not** own one global `BuildOperationId` or one global observable-commit bit. Edge daemons hold subscriber-delivery proxies and private materialization state; workers hold attempt actors. Neither creates a competing authoritative action owner.

### 21.1 Subscriber interest

Subscriber kinds:

```text
ForegroundInteractive
ForegroundAgent
CIRequired
Speculative
GitPrewarm
VerificationAudit
DeterminismAudit
AdministrativeRepair
```

The actor tracks reference-counted interests and the strongest priority/deadline while preserving each subscriber's own fallback and presentation state. Subscriber kind is not a semantic action-key component.

Each subscription also declares minimum evidence, isolation, privacy, and platform requirements. One canonical result may serve subscribers whose requirements are satisfied while another subscriber waits for an additional verification attempt or refuses the result. Verification appends evidence and recomputes a versioned trust evaluation; it does not create a new semantic action key or rewrite the original publication record.

### 21.2 Promotion

When a speculative action receives foreground interest:

- it remains the same action actor, action key, and active generation;
- scheduler priority and deadline are promoted;
- already transferred inputs and partial execution are retained;
- optional-work brownout no longer applies while foreground interest exists;
- provenance records the promotion.

### 21.3 Cancellation

A subscriber cancellation:

1. removes that subscriber's retained interest;
2. closes only that subscriber's delivery obligation;
3. acknowledges subscriber completion promptly;
4. leaves shared work running if any retained interest remains;
5. otherwise asks policy whether a near-complete or cache-populating generation should finish;
6. if cancellation wins, supersedes the generation or cancels its attempts and drains every process, stream, lease, token, and pin.

A subscriber that already crossed observable commit may still cancel its wait, but the edge must preserve or clean the already exposed state according to Cargo/process semantics.

### 21.4 Hedging and verification attempts

Hedging or pre-commit verification is represented by `AttemptPurpose`, not `ActionClass`. Every concrete contender gets a unique `AttemptId` and execution lease while sharing the same action generation. The first candidate that wins coordinator compare-and-set may commit only after full validation. Losing attempts are cancelled and drained. Post-commit audits cannot publish; a byte-identical audit records reproducibility, while a different canonical result quarantines the action and triggers an incident instead of silently replacing or coexisting with the committed result.

## 22. Authority, generation, attempt, and lease identity

Authority-bearing messages use structured identities rather than one overloaded epoch counter:

```rust
struct CoordinatorAuthority {
    cluster_id: ClusterId,
    credential_generation: u64,
    term: u64,
    incarnation_id: CoordinatorIncarnationId,
}

struct ActionGeneration {
    generation_id: ActionGenerationId,
    per_key_ordinal: u64,
    created_under_authority_digest: Digest,
}

struct AttemptAuthority {
    coordinator: CoordinatorAuthority,
    action_key: ActionKey,
    action_generation: ActionGeneration,
    attempt_id: AttemptId,
    execution_lease_id: ExecutionLeaseId,
    lease_renewal_seq: LeaseRenewalSeq,
    worker_peer_id: PeerId,
    worker_boot_generation: WorkerBootGeneration,
    worker_incarnation_id: WorkerIncarnationId,
    execution_policy_digest: Digest,
}
```

`BuildOperationId` and `SubscriberId` travel on request/delivery messages but are not fields of the logical action or attempt authority.

Rules:

- V1 has one statically configured active coordinator. On every successful authority acquisition it holds an exclusive local authority lock, durably advances a cluster-wide monotonically increasing `term` before issuing authority-bearing messages, carries a nondecreasing credential generation, and creates a fresh random `incarnation_id`.
- Automatic cross-host leader election is out of scope. Disaster recovery to another host is operator-fenced and rotates/revokes credentials or otherwise proves the old authority cannot continue.
- One missing action key receives one active generation containing a never-reused opaque `ActionGenerationId`, an optional monotonic per-key ordinal, and the canonical digest of the coordinator authority that created it. Normal attempts, retries, hedges, and any pre-commit verification attempts competing to publish carry that identity. Generation high-water/tombstone state outlives active metadata long enough to prevent ABA reuse. Post-commit audits reference the committed result and have no publication eligibility.
- Each attempt receives a unique execution lease. Renewing, revoking, or expiring one lease does not revoke sibling hedge attempts.
- `AttemptAuthority.coordinator` is the sole full coordinator-authority value in an attempt identity. `created_under_authority_digest` is `H_domain("rabs.coordinator-authority.v1", canonical(CoordinatorAuthority))`; its value must equal the digest of `AttemptAuthority.coordinator` and, for a publication, the accompanying publication authority. Any mismatch is malformed or stale authority and is rejected before lease admission or result preparation.
- Lease messages use coordinator-issued TTLs and monotonic local timers plus renewal sequence numbers. Hosts do not decide authority by comparing unsynchronized wall-clock timestamps.
- A worker restart increments a durable boot generation, creates a fresh random process-incarnation ID, and invalidates every prior execution lease for the old incarnation. The coordinator rejects a non-increasing boot generation and rejects duplicate/conflicting active incarnations for one worker identity/generation. If cloned credentials/state create two plausible peers, first-session fencing detects the conflict but does not prove legitimacy; policy fails closed or requires hardware-bound enrollment/operator re-enrollment.
- An edge restart likewise advances a durable edge boot generation and creates a fresh incarnation. Exactly one incarnation owns subscriber/materialization rights for a boot generation except during a bounded explicit handoff: the successor presents a coordinator-authorized handoff token naming the predecessor/session set, both report delivery frontiers during reconciliation, and the predecessor is fenced before the successor becomes sole owner. Arbitrary multi-incarnation overlap is forbidden.
- Every edge and worker durably persists the highest accepted `(credential_generation, term)` for `cluster_id`. Comparison is lexicographic: a lower credential generation is always stale; within the accepted generation, a lower term is stale; the accepted pair may name only the previously accepted coordinator incarnation unless a cluster-root-signed operator-reset record proves the old authority fenced. A higher credential generation establishes a new term namespace but still requires the configured credential-chain proof.
- The coordinator compare-and-set commits only when the action is still uncommitted, the action generation is current, the candidate attempt authority is valid, and the complete object/provisional-lineage closure passes policy.
- Repeated commit of the same canonical result manifest is idempotent. A different canonical semantic-result digest for the same key is a divergence incident and action quarantine, even if one candidate committed first; an observable-only mismatch receives presentation/observability quarantine. Previously served consumers are enumerated from provenance and the incident is escalated according to their trust/release tier. Different attempt evidence with the same canonical result is appended normally.
- Stale attempts may contribute independently verified immutable objects, but their result offers cannot change publication state.
- The committed row records the winning generation and attempt. Attempt journals remain append-only evidence.
- A database rollback, restored backup, or reused term cannot regain authority because peers also bind the cluster, credential generation, high-water mark, and fresh coordinator incarnation. A brand-new peer still relies on external fencing/credential rotation during disaster recovery.

# Part VII. Canonical virtual execroot

## 23. Why canonical execution is first-order

Key soundness without key stability produces a correct but ineffective cache. Absolute worktree, target, registry, sysroot, `OUT_DIR`, and temporary paths contaminate compiler arguments, dep-info, diagnostics, `.rmeta`, debuginfo, generated code, and incremental state. Separate agent worktrees would therefore produce different keys and outputs for logically identical work.

Canonical execution is consequently **Invariant I1 and an early engineering milestone**, not a later optimization.

## 24. Canonical path layout

Semantically visible paths are stable and deliberately omit content hashes and attempt identities:

```text
/__rabs/workspace/                         primary workspace root
/__rabs/repos/<logical-repo-id>/          additional path-dependency repos
/__rabs/registry/<source-checksum>/       immutable registry sources
/__rabs/git/<source-checksum>/            immutable git sources
/__rabs/toolchain/                        selected toolchain/sysroot
/__rabs/cargo-home/                       canonical Cargo home
/__rabs/out/<logical-unit-id>/            declared compiler outputs
/__rabs/build/<logical-unit-id>/out/      stable build-script OUT_DIR
/__rabs/incremental/<logical-unit-id>/    stable incremental path
/__rabs/tmp/                              isolated stable temp root
/__rabs/home/                             canonical nonsecret home
/run/rabs-secrets/<logical-slot>/         capability-scoped secret mount
```

Physical backing directories may contain operation IDs, action keys, attempt IDs, random staging names, or snapshot IDs because they are hidden behind a mount namespace, chroot, VM root, or equivalent. They must never leak into `CARGO_MANIFEST_DIR`, `OUT_DIR`, `TMPDIR`, compiler arguments, generated source, dep-info, debuginfo, or program-visible paths.

The primary workspace uses a fixed path because every sandbox is isolated. Additional path-dependency repositories receive stable logical IDs derived from an explicit repository-closure manifest, not from host paths.

`VirtualPath` preserves native path-component bytes on Unix. Canonical manifests do not require filenames or symlink targets to be valid UTF-8; display layers escape them explicitly. Cross-platform reuse requires a path-encoding/filesystem-semantic compatibility proof.


Logical repository IDs are assigned from Cargo/package source identity or a project-configured stable UUID plus closure role. They are not derived solely from a mutable Git remote URL, local checkout path, branch name, or current commit. Collision and alias resolution are explicit in the closure manifest.

Every sandbox declares a `FilesystemSemanticClass` including case sensitivity, Unicode normalization behavior, symlink and hardlink semantics, executable-bit/permission behavior, and any exposed xattr/ACL policy. The safe default is to require equality of this class for actions that can observe filesystem namespace behavior; omitting it requires proof that the action cannot distinguish the difference.

### Canonical Cargo-driver requirement

For workspace authority, the **Cargo process itself** runs with this root layout. Cargo computes package roots, build/output paths, unit hashes, `-C metadata`, environment variables, and child arguments before a rustc wrapper sees them. Running only rustc canonically cannot reliably erase path divergence already introduced by Cargo.

Dependency-only wrapper serving may operate without canonicalizing the parent Cargo when immutable source paths and invocation identity already converge, but broad workspace cross-worktree serving cannot.

## 25. Linux implementation

Linux is the first full-authority platform.

Preferred implementation:

- a canonical Cargo-driver namespace per command or compatible command group;
- nested per-action mount views where a finer closed input view is required;
- read-only snapshot/reflink/overlay lower layers;
- stable visible mounts for workspace, path dependencies, toolchain, registry, Cargo home, outputs, incremental state, home, temp, and secrets;
- default-deny network namespace;
- pid/user/mount namespace policy and controlled `/proc`;
- cgroup v2 resource envelope;
- seccomp/Landlock/bubblewrap-style restrictions according to measured host support;
- deterministic hostname, locale, timezone, approved pseudo-files, and device allowlist;
- explicit time/randomness policy rather than assumed syscall visibility;
- openat2-style containment or equivalent path-escape defenses;
- a small audited privileged helper only where unavoidable.

The helper's protocol is bounded, path-safe, fuzzed where applicable, and entered in the unsafe-boundary ledger. `StrictHermeticLinux` authority requires proof that the selected combination actually enforces the documented boundary.

## 26. macOS and non-Linux implementation

APFS clones provide efficient data copies but **do not** by themselves give many concurrent processes the same canonical visible absolute path. FSEvents observes changes, not reads. Therefore macOS has a staged authority model:

1. **Immutable dependency fast path:** cache checksummed registry/git dependencies whose paths and exact inputs are already stable.
2. **Canonical root through an isolated process root:** use a validated privileged chroot/sandbox helper with APFS-clone backing, or a lightweight Virtualization.framework VM, so each action sees the same root concurrently.
3. **Authoritative input observation:** use a privileged Endpoint Security or VM-mediated mechanism that can support the stated read/exec/network boundary; FSEvents remains only an edit/speculation watcher.
4. **Fallback host-audit mode:** fixed environment, paths where possible, process ownership, and best-effort tracing, but no cross-worktree authoritative workspace publication.
5. **Serialized canonical slot:** acceptable as an experimental fallback for small concurrency, but measured because serialization may erase acceleration.

Platform maturity matrix:

| Platform/profile | Dependency serving | Workspace serving | Cross-machine publication |
|---|---:|---:|---:|
| Linux strict hermetic | yes after gates | yes after gates | yes within output-platform class |
| macOS VM/chroot strict | yes | yes after platform proof | yes within matching SDK/ABI class |
| macOS host-audit | selected immutable deps | no authoritative shared workspace | no |
| Windows initial | observation/limited classes | deferred | no implied parity |

Unsupported isolation properties reduce authority explicitly; they do not receive optimistic parity labels.

## 27. Path remapping and diagnostics

The compiler receives path-remap/trim flags where supported, but remapping is a supplement to canonical execution rather than a substitute.

Each edge maintains a subscriber-specific mapping:

```text
canonical virtual path → requesting worktree path
```

RABS applies it to canonical structured compiler events, rendered diagnostics, dep-info materialized for Cargo, panic/file references where safely structured, and `rch why` output.

Important distinctions:

- The rustc artifact-notification path replayed to Cargo is the exact output path Cargo requested and on which Cargo's current process is waiting.
- Cargo's outward `compiler-artifact` message is a different Cargo-generated event and must not be confused with rustc's internal artifact-notification JSON line.
- A semantic artifact result can serve multiple subscribers only if path translation is complete and safe; otherwise RABS uses a presentation variant or bypasses replay.
- Raw stored provenance uses canonical paths and a redacted mapping receipt, never user home paths.

### 27.1 Build-path semantic policy

Canonical absolute paths can change real program behavior even when binaries run at the same speed. Examples include `file!()`, `env!("CARGO_MANIFEST_DIR")`, generated strings derived from `OUT_DIR`, panic/reporting locations, embedded source maps, runtime resource lookup, and tests that assert paths.

Every workspace action therefore selects one versioned policy:

```text
CanonicalPortablePath
    the project/profile intentionally adopts stable canonical build paths;
    cross-worktree serving is permitted after the ordinary gates

PathOpaqueVerified
    differential/path-leak evidence proves the relevant output/use profile
    cannot observably distinguish original versus canonical paths

ProjectRelativeRemapped
    a validated compiler/toolchain profile exposes stable project-relative
    semantics without leaking the host/worktree path

SubscriberPathPreserving
    execute with the subscriber's original visible paths, include the path
    semantic identity, and forgo broad cross-worktree portability
```

The default for a new workspace family is shadow/audit, not an assumption that canonical paths are harmless. A runtime-visible canonical string is semantic even when it is never opened as a file. Unsafe or ambiguous remapping causes a path-preserving/local lane rather than a canonical shared hit.

## 28. Stable `OUT_DIR`, incremental, temp, and home paths

Build scripts and generated source frequently embed `OUT_DIR`, `TMPDIR`, `HOME`, target, or incremental paths. The **Cargo-generated visible path is authoritative**. RABS canonicalizes Cargo before planning and maps Cargo's exact requested paths to private hidden backing storage; it does not overwrite `OUT_DIR` after Cargo has already selected a unit hash or fingerprint path.

The conceptual stable roots are:

- Cargo's exact canonical `OUT_DIR`, normally under a stable canonical target/build root;
- incremental state under a stable canonical logical-unit path selected before rustc invocation;
- `TMPDIR=/__rabs/tmp` inside each isolated action/operation namespace;
- `HOME=/__rabs/home`;
- secret mounts at stable logical slots under `/run/rabs-secrets`.

`/__rabs/build/<logical-unit-id>/out` is valid only when the canonical Cargo driver was configured to produce that path before planning. A wrapper may not silently substitute it for a different Cargo-provided `OUT_DIR`.

The action key, attempt ID, snapshot ID, and random physical staging path exist only in hidden backing storage and metadata. A logical unit ID is stable across equivalent worktrees and excludes current source content unless Cargo's actual semantics require otherwise.

A `BuildScriptRun` action also models the **pre-run** visible `OUT_DIR` and Cargo build-script output-cache/fingerprint state whenever the program can observe them. Replay installs the complete captured post-state, including deletions, into a clean private directory and atomically swaps it into place; it never merges cached files into an unknown stale `OUT_DIR`.

RABS captures generated outputs as object manifests and replays exact Cargo directives. It never rewrites arbitrary generated content merely to hide a path. If content intentionally embeds an unvirtualized path, the action is path-sensitive and loses portable serving authority.

## 29. Path leak and identity audit

Discovery and determinism audit scan artifacts, metadata, compiler events, generated source, and dep-info for:

- actual worktree roots and user homes;
- worker-specific temp/CAS roots;
- hidden physical operation/action/attempt/snapshot paths;
- hostnames and usernames;
- actual target/build directories;
- secret mount backing paths;
- different Cargo-generated metadata hashes for otherwise equivalent canonical commands.

The scanner distinguishes debug-only references from loadable/runtime-visible data. An embedded canonical absolute path is not automatically safe: runtime-visible strings are semantic, and code that later opens `CARGO_MANIFEST_DIR`, `OUT_DIR`, or another build-time path is additionally `RuntimePathSensitive` unless the project packages the resource or explicitly guarantees the canonical runtime mount.

Findings are classified as:

- canonical and explicitly admitted by `BuildPathSemanticPolicy`;
- presentation-only and safely translated;
- remappable debug metadata;
- key-relevant semantic leakage;
- output-semantic path sensitivity;
- privacy/secret incident;
- evidence that Cargo was not actually launched canonically.

Ambiguous loadable-data leakage loses portable serving authority and falls back to the path-preserving lane.

Cross-worktree tests compare not merely normalized descriptors but Cargo child argv, `-C metadata` values, output filenames, `.rmeta`, dep-info, and selected binary sections.

## 30. Mtime and checksum freshness

Cargo’s default freshness behavior remains mtime-sensitive. Materialization must therefore follow a coherent policy:

- outputs become newer than relevant inputs from Cargo’s perspective;
- dep-info references are consistent with the requesting virtual-to-real mapping;
- a result bundle includes the matching incremental snapshot where supported;
- repeated hits do not induce rebuild storms;
- atomic rename prevents partially materialized target trees.

Where nightly Cargo supports checksum freshness, RABS should provide an opt-in profile and validate it thoroughly. The system should be designed to absorb stable checksum freshness later without changing CAS semantics.


### 30.1 Mutable target-state and inode ownership

- Client worktrees keep private target/build directories; they never share one mutable target tree merely to obtain cache reuse.
- Whole-command worker hot state is protected by an exclusive `TargetStateLease` or cloned into a private operation root before mutation.
- Fine-grained cache reuse materializes immutable outputs from CAS into the requesting private target tree.
- RABS never presents a writable hardlink to a CAS blob, pack member, manifest, or retained target snapshot. Use read-only bind mounts, copy-on-write reflinks, or copies.
- Mtime changes are applied only to private materializations. If a reflink implementation can mutate shared metadata/content, it is treated as unsupported and falls back to copy.
- A per-build-operation destination arbiter reserves every declared output path before installation. Disjoint bundles may install concurrently; overlapping paths, parent-directory replacement, or undeclared writes serialize, bypass, or fail coherently. Installation is atomic per owned file/subtree/bundle, not by swapping an unrelated shared target root. A complete owned tree such as one build script's `OUT_DIR` may be atomically swapped after validation.
- If source inputs have future/skewed mtimes that cannot be represented coherently, use validated checksum freshness or bypass serving rather than guessing.
- Object content IDs generally exclude timestamps, but an action that can observe source/output mtime, ctime, ownership, inode/link metadata, or directory order either sees a declared canonicalized value or includes the exact observed metadata/order in its action-input closure and compatibility class.

---

# Part VIII. Hermetic sandboxing and observed-input closure

## 31. Hermetic-by-construction defaults and coherent snapshot capture

Default sandbox values:

| Surface | Default |
|---|---|
| Network | denied |
| Clock | strict virtual/fixed policy only in a profile that can enforce it; otherwise volatile evidence |
| Timezone | UTC |
| Locale | fixed UTF-8 locale |
| Hostname | canonical constant when isolated |
| Username/home | canonical nonsecret values |
| Randomness | denied or deterministic declared seed; otherwise volatile |
| Git metadata | hidden unless mounted as an explicit input object |
| Environment | exact scrubbed allowlist, wholly hashed as presented |
| Filesystem | immutable declared/observed closure plus controlled outputs/temp; fixed umask and filesystem semantic class |
| Process context | closed inherited-FD set, canonical argv0/cwd, bounded rlimits, declared CPU-count/topology view |
| Secrets | capability-mounted at stable logical slots, opaque-keyed or nonshareable |
| External services | denied unless split into captured fetch/input actions |

Before Cargo or an action starts, the edge creates a coherent command snapshot:

1. resolve the workspace, lockfile, `.cargo` configuration, toolchain files, and path-dependency closure;
2. include relevant untracked files and symlink structure according to policy;
3. exclude known ephemeral locks and mutable build output roots;
4. prefer filesystem snapshot/reflink primitives;
5. otherwise use a directory-generation watcher plus at least two stable scans; read each file through an open descriptor, hash its bytes, and verify identity/size/metadata before and after the read;
6. retry the entire capture if any watched mutation, directory-set change, inode replacement, symlink change, or metadata inconsistency occurs during the capture window;
7. refuse authoritative workspace snapshotting on a platform/filesystem where a coherent boundary cannot be established within policy;
8. hide `.git` unless a canonical git-state object is declared;
9. bind the snapshot root and filesystem semantic class into provenance and every child action request.

Speculative snapshots may be abandoned when edits continue. An explicit user command receives a coherent snapshot before authoritative serving or execution.

RABS never silently substitutes fake wall time, deterministic randomness, fabricated git state, or canonical host identity for a project that intentionally consumes the real value. Such normalization is an explicit sandbox semantic policy, enters the key, and is shadow-compared; otherwise the action is classified host/time/randomness/git sensitive and loses shared authority.


### 31.1 Source-capture confidentiality policy

Snapshot completeness and transfer authorization are distinct decisions. Each project/fleet defines a `SourceCapturePolicy` with path classes such as `BuildInputAllowed`, `LocalOnly`, `SecretCapability`, `Denied`, and `ExplicitOperatorApproval`.

Rules:

- `.gitignore`, Cargo package inclusion, and editor ignore files are convenience signals, never security boundaries;
- common credential/key locations, `.env*`, private-key formats, cloud credentials, signing material, and configured sensitive paths default to denied or secret-capability handling;
- symlink escape, bind-mount escape, device files, sockets, and unrelated home/ancestor paths are refused;
- every permitted file read outside the workspace/path-dependency closure must belong to a declared immutable toolchain/SDK/native dataset or an explicit `ExternalInputCapability`; the capability assigns a stable virtual mount, object identity, metadata/filesystem class, privacy scope, and revocation/version identity; raw host absolute paths never become portable inputs by accident;
- an undeclared external read, or an external tree too broad/mutable to snapshot and reproduce, makes the action local-only/volatile or fails discovery rather than being uploaded opportunistically;
- source/object namespaces carry project/access classification and optional at-rest encryption policy;
- discovery that attempts to read a denied path does not upload it silently: the action becomes local-only, requests a narrow capability, or is refused with an explanation;
- secret scanners are advisory defense-in-depth and cannot prove absence of secrets in ordinary source bytes;
- permitted snapshot members preserve raw path bytes and access classifications; denied/local-only path observations remain in an edge-private policy receipt and are not uploaded merely to describe their denial, while logs expose only redacted virtual paths.

### 31.2 Incremental content-identity and snapshot index

A full byte rehash of every workspace and dependency artifact on every command would violate the miss-overhead SLO. `rabs-edge` therefore maintains a durable, per-filesystem content-identity index and local digest singleflight.

Safe reuse sources, strongest first:

1. a RABS materialization receipt binding an immutable private file to an object ID;
2. a real filesystem snapshot plus a stable file identity/version primitive proven on that filesystem;
3. open-descriptor stat/version checks combined with a no-overflow mutation journal;
4. full rehash when identity/version evidence is weak or contradictory.

The index may record device/inode or platform file ID, size, nanosecond metadata, `statx`/generation data where reliable, watcher generation, content ID, and provenance. Mtime/size alone are never content authority. Watcher overflow, rename ambiguity, coarse timestamps, network filesystems, index corruption, or audit mismatch force a bounded rescan/rehash or reduced authority. Periodic sampled/full audits verify reused identities. Snapshot manifests structurally share unchanged subtrees and object IDs without changing action semantics.

## 32. Observation and enforcement layers

RABS combines evidence sources because no single source is complete:

- rustc dep-info;
- binary-dependency dep-info where available;
- successful and failed filesystem-open observation;
- directory enumeration/glob observation;
- symlink resolution and path-escape observation;
- subprocess execution and executable-selection observation;
- network-attempt observation;
- declared Cargo rerun directives and build-script metadata;
- output write-set and external-side-effect observation;
- project-declared git/time/randomness capability use;
- metadata-only queries such as `stat`, `lstat`, `access`, permission/ownership checks, mtime/ctime reads, and filesystem-capability probes;
- dynamic loader and plugin activity, inherited file descriptors, `argv[0]`, cwd/realpath, umask/rlimits, CPU-count/affinity, and process/system identity probes.

The **environment is not learned through these tracers**. RABS supplies the complete environment and hashes it. Similarly, raw clock access may bypass syscall tracing through vDSO, and entropy may come from multiple interfaces. A strict profile must virtualize or deny those surfaces through a validated mechanism; otherwise the action is classified accordingly.

Linux may use eBPF, fanotify, ptrace, seccomp-notify, Landlock, and namespace enforcement in measured combinations. macOS may use Endpoint Security or VM mediation where available. FSEvents/inotify are useful edit watchers but are not authoritative read tracers.

Absence capture is mandatory: missing paths, directory contents, and executable lookup alternatives belong in `NegativeDependencySet`, while absent environment variables belong in `PresentedEnvironment`. All can change future behavior.

If raw directory-enumeration order or metadata fields are observable, the action closure records them and the sandbox must reproduce them. Because native `readdir` ordering can vary even on nominally similar filesystems, order-sensitive actions are restricted to a proven materializer/filesystem class or classified nonportable/volatile.


Unbounded namespace observations are not silently serialized into enormous keys. If an action enumerates an overly broad or mutable tree, probes arbitrary host paths, or observes a namespace RABS cannot reproduce, policy either promotes the relevant tree root into a declared snapshot input, narrows it through project configuration, or classifies the action as volatile.

Host introspection that can alter outputs—`uname`, CPU feature detection/CPUID, CPU count/affinity, `sysctl`, `/proc`, rlimits, umask, loader configuration, dynamic libraries, SDK discovery, `pkg-config`, device queries, file metadata, and similar probes—is supplied from a canonical toolchain/platform view or captured as an explicit semantic input. Merely matching target triples is insufficient. Unapproved inherited file descriptors are closed before spawn; approved descriptors such as the local jobserver are capability-scoped and excluded from semantic identity only when proven output-neutral.

## 33. Proc-macro policy

Untracked proc-macro inputs are a critical correctness risk. RABS should:

1. treat proc-macro executable identity and its host-runtime dependencies as semantic dependencies;
2. run first-seen rustc families under filesystem/process/network discovery;
3. supply and hash the complete exact environment rather than trying to observe `getenv`;
4. capture raw successful/failed file reads, directory enumeration, and executable lookup not represented in dep-info;
5. respect rustc tracked-path/tracked-env signals when available as additional evidence;
6. include explicit git/time/randomness capability policy;
7. execute authoritative repeats against an enforced closed view;
8. abort and rediscover on a new read;
9. sample re-audit previously stable families;
10. deny shared caching when closure or isolation authority cannot be proven.

## 34. Build-script policy

Policy split:

### Registry/git dependency build scripts

- aggressive sandboxing and discovery;
- immutable source expectation validated by checksum;
- native subcompile interception enabled;
- launcher-shim or canonical-Cargo interposition only after Cargo fingerprint/jobserver tests;
- exact stdout/stderr bytes, per-stream order, recorded event sequence, and generated-output capture;
- pre-run `OUT_DIR`, Cargo build-script output-cache, and any other readable prior state captured or proven empty;
- complete post-state replacement including tombstones/deletions rather than merge replay;
- determinism audit before broad sharing.

### Workspace build scripts

- audit-first;
- explicit project policy for git, clock, randomness, network, or secrets;
- volatility preferred over optimistic caching;
- actionable `rch why` refusal explanation.

Replay must preserve exact ordered bytes and semantics for:

- `cargo:rerun-if-changed` / `cargo::rerun-if-changed`;
- `cargo:rerun-if-env-changed`;
- `cargo:rustc-*` / `cargo::rustc-*` directives;
- `cargo:key=value` metadata that becomes `DEP_<LINKS>_*` input;
- warnings/errors and exit status;
- the complete declared generated output tree.

Exact stdout is accompanied by a structured directive manifest used for validation and downstream key construction. In particular:

- path-valued `rustc-link-search` directives must resolve to declared generated outputs, immutable toolchain/native datasets, or explicitly captured host-bound inputs that exist under the same canonical path for every consumer; otherwise the run is nonportable/volatile;
- `rustc-link-lib` and implicit search semantics cause the selected native libraries, startup objects, linker plugins, default scripts, and negative search candidates to enter the downstream link closure;
- `rustc-env`, metadata, cfg, and flag directives preserve exact bytes and feed the corresponding downstream presented environment/invocation; RABS does not guess whether an arbitrary string is a path;
- replay validates that every directive-referenced generated path belongs to the installed post-run output tree before exposing stdout to Cargo.

The launcher shim is an evidence-gated mechanism, not an assumption. It must prove across stable/beta/nightly that executable identity, mtimes, Cargo fingerprints, output-cache behavior, and inherited jobserver descriptors remain correct. If a shim perturbs Cargo, RABS uses canonical Cargo-driver/process interposition or leaves `BuildScriptRun` caching disabled. Failed or cancelled build-script runs never publish partial `OUT_DIR` contents.

## 35. Native build-tool policy

Build scripts invoking `cc`, `c++`, `clang`, `ar`, `cmake`, or related tools are a high-value early target.

RABS should inject wrapper identities through `CC`, `CXX`, `AR`, and tool-specific launcher settings. Native action keys include:

- compiler/archive tool identity;
- normalized flags;
- source/header closure;
- generated include roots;
- target ABI;
- environment and sandbox policy;
- declared output;
- assembler/linker/subprocess identities, dynamic-loader dependencies, built-in include roots, `pkg-config`/SDK resolution, and filesystem semantic class.

This plane should precede the generalized build-script-run cache because it captures a large fraction of expensive dependency build time with comparatively mature semantics.

## 36. Networked generators and fetched inputs

When a generator requires network data, the preferred pattern is:

1. execute an explicit fetch action under a network capability;
2. capture the fetched bytes and response metadata as immutable objects;
3. execute the build/generator action offline against those objects;
4. key the action on captured content, not a URL or wall-clock fetch result.

If this separation is not possible, the action is volatile or capability-specific and must not enter the ordinary shared cache.


---

# Part IX. Profound Asupersync integration

## 37. Adopt-now capability map

| Asupersync capability | RABS use |
|---|---|
| `Cx`, regions, task ownership | daemon, build-intent, action, attempt, worker-session, and transfer ownership |
| `Budget`, deadlines, checkpoints | queue, execution, transfer, cancellation, and cleanup bounds |
| `Outcome` | preserve success/error/cancel/panic distinctions |
| structured spawn/join/race | action fan-out, hedging, cache-vs-execution races, drained losers |
| channels and obligations | event streams, permits, publication and provisional-output protocols |
| process subsystem | rustc/linker/test/build-script process groups and cancel-drain |
| supervision | worker sessions, action services, transfer loops, compatibility islands |
| remote named computations | audited RABS worker operation registry |
| `RemoteCap`, leases, idempotency | explicit remote authority and attempt lifecycle |
| ATP objects/manifests | source snapshots, toolchains, artifacts, incremental images |
| ATP journals/sparse writers | interrupted transfer recovery and atomic staging |
| ATP session negotiation | identity, feature, version, and path-policy negotiation |
| native QUIC | persistent worker data/control transport after hardening |
| deterministic lab | concurrency, cancellation, crash, and network proof scenarios |
| observability | causal traces, decision receipts, pressure, obligation visibility |
| RCH health policy | deterministic worker admission and refusal explanations |
| SLO runtime bridge | optional-work brownout and cleanup preservation |
| pool-sizing substrate | advisory action/CAS/hash/link/test concurrency recommendations |
| path candidate machinery | LAN/Tailscale/relay-fallback candidate policy |

## 38. RABS remote computation registry

Remote execution must use a closed, versioned registry. Initial operations:

```text
rabs.worker.probe.v1
rabs.worker.materialize_snapshot.v1
rabs.worker.execute_action.v1
rabs.worker.query_attempt.v1
rabs.worker.cancel_attempt.v1
rabs.worker.seed_objects.v1
rabs.worker.verify_objects.v1
rabs.worker.collect_failure_bundle.v1
```

Every registry entry defines:

- stable numeric operation code;
- canonical textual name;
- request/response schema versions;
- maximum inline bytes;
- required capabilities;
- idempotency behavior;
- retry safety;
- cancellation responsiveness contract;
- lease behavior;
- expected object references;
- observability and redaction policy;
- lab scenarios and golden fixtures.

No large source or artifact payload is carried inline in generic `RemoteInput`; requests carry object IDs and bounded descriptors.

The named-computation registry contains operations actually executed on a worker. Session capability exchange, missing-object negotiation, attempt events, prepared-result offers, lease renewal, and reconciliation remain typed RABS/ATP protocol messages; they are not mislabeled as worker computations. `NextestTestCase` is normally an `execute_action` class unless a separate operation proves useful.

## 39. Capability model

RABS should refine generic remote authority into narrow application capabilities:

```text
ReadObject(ObjectId or namespace)
WriteStaging(ActionKey, AttemptId)
ExecuteAction(ActionClass, ToolchainDigest, SandboxPolicy)
OfferPreparedActionResult(ActionKey, ActionGeneration, AttemptId, ExecutionLeaseId)
MaterializeSnapshot(RepoId)
OpenNetwork(NetworkPolicyId)
ReadSecret(SecretCapabilityId)
EmitDiagnostics(ActionKey)
SeedPeerObjects(PeerScope)
RunVerification(ActionKey)
AdminRepair(WorkerScope)
```

Capabilities must be:

- explicit in session/operation context;
- least-privilege;
- redaction-safe in receipts;
- revocable or lease-bounded;
- unavailable to arbitrary build subprocesses except through controlled mounts/FDs;
- checked both by coordinator policy and worker operation handlers.

## 40. Process-management integration

Every external action runs in a managed process group or session.

Required behavior:

- spawn under action attempt ownership;
- capture stdout/stderr concurrently with strict byte bounds and spill-to-object behavior;
- replace local jobserver handles with worker-local ones;
- register descendants in the managed process group;
- checkpoint cancellation at pre-spawn, post-spawn, I/O, and wait boundaries;
- on cancellation, send graceful termination to the group;
- continue draining output and child state;
- escalate after a bounded policy interval;
- reap every child;
- classify actual termination cause;
- release slots/tokens only after process ownership is resolved;
- emit a cancellation progress receipt.

A Unix process group is not a complete hostile-descendant boundary because a child can create a new session/process group. `StrictHermeticLinux` therefore uses the action cgroup and PID namespace as ultimate descendant containment, with graceful process-group termination followed by bounded cgroup-wide kill/reap. VM profiles use the VM boundary; weaker host profiles make a narrower no-orphans claim. Jobserver and other inherited descriptors are closed during finalization so escaped/background children cannot retain capacity indefinitely.

RABS should retire ad hoc remote PGID-file and SSH-kill logic from the authoritative path once this implementation proves parity and reliability.

## 41. Supervision tree

Recommended supervision policies:

| Child | Strategy | Notes |
|---|---|---|
| local wrapper connection | stop | request failure must not restart a dead client |
| worker session | restart with bounded exponential backoff | preserve operation reconciliation |
| ATP endpoint | restart/escalate | repeated failures may degrade transport to fallback |
| action actor | stop or controlled retry | retries create new fenced attempts, not actor replacement ambiguity |
| health collector | restart | stale evidence fails closed for remote-required work |
| CAS writer | escalate on invariant violation | publication must not continue after storage corruption |
| compatibility HTTP/OTel island | restart/stop | must not bring down build execution |
| GC | restart with cadence/backoff | admission must handle low-disk state independently |
| speculation service | stop/restart, optional | never threaten foreground path |

Restarts consume budgets and are trace-visible. A restarted worker session must reconcile durable operations before admitting new authoritative work.

## 42. Asupersync runtime configuration profile

Create a minimal, audited `rabs-profile` feature and configuration contract rather than enabling the entire default surface indiscriminately.

Profile concerns:

- production native runtime;
- process support;
- ATP object/journal/protocol support;
- native QUIC and TLS when the transport is enabled;
- tracing/metrics required by RABS;
- lab/test internals only in test builds;
- no browser, Kafka, database, H3, WebTransport, mailbox, relay, or broad compatibility features unless explicitly needed;
- optional `io_uring` only after measured benefit and compatibility validation;
- explicit pinned nightly/stable subset policy.

CI should produce a dependency and feature graph artifact proving what entered the critical binaries.

## 43. Compatibility island policy

Existing Tokio-locked services may run through `asupersync-tokio-compat` or separate supervised processes during migration.

Rules:

- no new Tokio dependency enters `rabs-action`, `rabs-key`, `rabs-cas`, or the native action path without an approved exception;
- compatibility islands have bounded queues and cancellation adapters;
- they cannot own action publication authority;
- they may fail without preventing local execution;
- every island has an exit criterion and performance/reliability comparison.

## 44. Asupersync issues that are RABS blockers

### 44.1 Canonical frame encoding

ATP frame extensions must have deterministic canonical ordering. Replace unordered extension encoding with a `BTreeMap` or explicit numeric sort. Golden fixtures must prove byte identity across runs and implementations.

### 44.2 Protocol version negotiation

ATP’s current V0-only interpretation must evolve into:

- supported transport-version range;
- negotiated RABS application version;
- explicit current and minimum compatible versions;
- typed unsupported-version responses;
- N/N−1 fixtures and rolling-upgrade tests.

### 44.3 Durable remote identities

Process-local numeric remote task IDs are insufficient for reconciliation. RABS messages must use durable build-operation/action-generation/attempt/execution-lease identities and map them into generic Asupersync handles.

### 44.4 Bounded asynchronous send admission

The remote message path needs explicit backpressure:

- per-peer byte and message limits;
- priority lanes;
- reserve/commit semantics for enqueued messages;
- nonblocking policy refusal instead of unbounded buffering;
- cancellation-aware wait for permits;
- separate control-plane reserve so bulk data cannot starve cancellation or leases.

### 44.5 Managed QUIC event loop

Before authoritative use:

- remove fixed one-millisecond polling as the normal wake mechanism;
- use reactor/timer wakeups;
- inject Asupersync time rather than reading wall clock directly in core paths;
- validate timer precision, packet wake latency, and prolonged idle behavior;
- add adaptive packet batching;
- run high-connection and high-throughput soak tests;
- add cancellation tests during receive/send/timer paths;
- compare against established QUIC implementations and current SSH/Tailscale behavior.

### 44.6 Durable CAS backend

ATP’s deterministic in-memory CAS substrate must be adapted to RABS’s durable store. Asupersync should retain generic content/manifest/delta semantics; RABS owns persistence, lifecycle, and action indexing.

### 44.7 Current coverage evidence

Regenerate ATP coverage/readiness ledgers from live test metadata. A production cutover cannot rely on stale manually maintained `PLANNED` rows that disagree with compiled tests.

### 44.8 Nested runtime and timer regression pin

Retain watchdog-guarded tests for nested/re-entrant current-thread runtime timer behavior and avoid introducing nested `block_on` patterns into RABS. Long-running daemons should use one owned runtime rather than sync bridges that recursively drive runtimes.

## 45. Adopt, harden, defer matrix

### Adopt immediately

- regions, `Cx`, budgets, outcomes;
- process groups and cancellation;
- supervision;
- deterministic lab;
- observability and obligation tracking;
- generic ATP object identifiers/manifests;
- journal/sparse writer/atomic commit concepts;
- RCH health admission policy;
- SLO optional-work bridge;
- advisory pool sizing.

### Harden before authoritative production

- native QUIC;
- ATP canonical codec and versioning;
- remote message backpressure;
- durable IDs and reconciliation;
- transport identity binding;
- durable CAS adapter;
- long-running soak and interoperability evidence;
- public adapter stability.

### Defer until evidence

- RaptorQ repair;
- multi-source swarm fetch;
- fan-out across paths/connections;
- mailbox/store-and-forward;
- generic relay infrastructure;
- H3/WebTransport/MASQUE;
- automatic adaptive transfer-brain control;
- distributed live-region migration.

---

# Part X. RABS application protocol over ATP

## 46. Protocol layers

```text
local UDS wrapper protocol
  → rabs-edge
    → authenticated RABS/ATP coordinator session
      → rabs-coord
        → authenticated RABS/ATP worker session
          → rabs-wkr
```

For native remote links:

```text
UDP/TCP/Tailscale path
  → native QUIC/TLS or approved fallback
    → ATP/0 transport/session/frame layer
      → RABS/1 application envelope
        → typed action/CAS/health/reconciliation message
```

Local wrapper, ATP transport, and RABS application versions are distinct. A change in one does not silently change the others. The edge/coordinator split is part of the application protocol even when both roles run in one process.

## 47. Session handshake

By default, edges and workers initiate long-lived outbound sessions to the statically configured coordinator, simplifying NAT/firewall deployment and keeping coordinator identity singular. Inbound/coordinator-initiated dialing is an explicit alternate profile, not an implicit fallback.

An edge or worker session handshake establishes:

1. transport authentication;
2. durable peer identity and key generation;
3. identity-to-certificate/channel binding;
4. peer role: edge, coordinator, worker, gateway, or administrative client;
5. supported ATP transport versions and selected `ATP/0` initially;
6. supported RABS application versions and selected `RABS/1` initially;
7. current active `CoordinatorAuthority` and coordinator identity;
8. worker output-platform classes and execution eligibility, or edge platform/capture capabilities;
9. sandbox and input-observation profiles;
10. object-store capabilities, digest algorithms, packs, compression, and chunking profiles;
11. maximum frame, message, manifest, stream, and resource limits;
12. remote computation registry versions;
13. worker or edge restart generation plus a fresh process-incarnation ID; workers admit one active incarnation per durable identity/generation, while overlapping edge incarnations require an explicit handoff/resumption token and cannot both materialize the same subscriber operation;
14. causal trace mode and independent per-domain sequence rules;
15. path class and measured quality;
16. trust scope and publication permissions.

A mismatch yields an explicit downgrade, compatibility route, local fallback, or refusal. It never silently assumes compatibility.

QUIC 0-RTT is disabled for state-changing RABS messages in V1. Resumed sessions may use 0-RTT only for explicitly idempotent read-only queries after a separate replay-safety review.

## 48. Stream, sequencing, and priority model

### 48.1 Required logical streams

```text
critical-control
    cancellation, lease renewal, coordinator authority, fencing, commit notification

control
    heartbeat, capability, admission, operation query, reconciliation commands

action-events
    ordered lifecycle, progress, canonical compiler events, diagnostics metadata

early-artifacts
    `.rmeta`, dep-info, small generated metadata, tiny outputs

bulk-objects
    source chunks/packs, rlibs, objects, executables, toolchains, snapshots

telemetry
    sampled/loss-tolerant observations and detailed performance data

reconciliation
    durable operation inventories, attempt journals, pin and transfer recovery
```

Implementations may multiplex physical QUIC streams, but logical priorities, independent flow-control windows, and reserved critical-control capacity remain.


Connection-level congestion can still starve a high-priority stream. V1 therefore either uses a small dedicated authenticated control connection plus one or more bulk-data connections, or proves through loss/throughput/soak tests that the selected QUIC scheduler keeps cancellation and lease-renewal p99 within budget while bulk transfer saturates the path. Separate connections are cryptographically bound to the same authenticated peer identities, session generation, coordinator authority, and negotiated capability set. Failure of the latency gate forces physical separation.

### 48.2 Priority mapping

| Priority | Examples |
|---|---|
| Critical control | cancellation, coordinator authority, lease renewal, fencing, committed-result notification |
| Control | heartbeat, capability update, operation query |
| Early usability | `.rmeta`, dep-info, compiler errors, canonical artifact events |
| Standard high | manifests, packs, and small files needed to start |
| Standard | source and ordinary outputs |
| Bulk low | toolchain and incremental snapshot prefetch |
| Optional/speculative | prewarm objects and speculative outputs |
| Repair | retransmission/recovery data if later enabled |

### 48.3 Sequence domains and causal ordering

RABS does not impose one global sequence across control and bulk streams. Each envelope names a bounded `SequenceDomain`, for example:

```text
AuthorityControl
ActionLifecycle(attempt)
SubscriberDelivery(subscriber)
ObjectTransfer(transfer)
TelemetryBestEffort
```

Each reliable domain has its own monotonically increasing sequence and acknowledgement high-water mark. Cross-domain dependencies are explicit object IDs, authority tuples, causal references, and readiness/commit messages; a missing bulk range never blocks cancellation or lease renewal merely because it had a smaller global number. Receivers:

- accept duplicates idempotently within a domain;
- reject or buffer bounded out-of-order events according to that domain/message type;
- persist the last terminal/authority-bearing sequence before acknowledgement;
- resume each domain from its last accepted sequence after reconnect;
- never infer commit from stream closure or from another domain's progress.

Bulk transfers must never consume all memory or congestion budget needed by cancellation, lease-renewal, coordinator-authority, or reconciliation traffic. One slow subscriber has an independent bounded/spillable queue and cannot backpressure the canonical action stream or other subscribers indefinitely.

## 49. Message catalog

### 49.1 Session and capability

```text
RabsClientHello
RabsEdgeHello
RabsWorkerHello
RabsVersionSelected
RabsCapabilities
RabsCapabilitiesAck
RabsSessionRefused
RabsSessionResume
CoordinatorAuthorityAnnounce
PeerAuthorityHighWaterReport
OperatorResetProof
EdgeHandoffOffer
EdgeHandoffAccepted
EdgeHandoffCompleted
EdgeIncarnationFenced
```

### 49.2 Worker health and scheduling evidence

```text
WorkerHeartbeat
WorkerPressureSnapshot
WorkerCacheInventoryHint
WorkerToolchainInventory
WorkerAdmissionCaveat
WorkerDrainState
CargoRootPermitRequest
CargoRootPermitGranted
CargoRootPermitReleased
```

### 49.3 Object/CAS

```text
FindMissingObjectsRequest
FindMissingObjectsResponse
ObjectManifestOffer
ObjectPackOffer
ObjectRangeRequest
ObjectRangeData
ObjectRangeAckBitmap
ObjectCreditUpdate
ObjectTransferComplete
ObjectVerificationFailed
ObjectPinRequest
ObjectPinReleased
```

`FindMissingObjects` is batched and bounded. Inventory hints and Bloom filters may reduce queries but are never correctness authority. Large transfers use cumulative ranges/bitmaps and credit windows, not an acknowledgement message per ordinary chunk. Lots of tiny objects may use deterministic pack objects with independently verifiable member indexes.

### 49.4 Action submission and subscription

```text
SubmitAction
JoinAction
ActionAccepted
ActionCacheHit
ActionCacheMiss
ActionQueued
ActionRejected
SubscriberCancelInterest
SubscriberPromotePriority
```

### 49.5 Attempt lifecycle

```text
AttemptLeaseOffer
AttemptLeaseAccepted
AttemptLeaseRefused
AttemptStarted
AttemptProgress
AttemptLeaseRenewal
AttemptLeaseExpired
AttemptCancel
AttemptDrainProgress
AttemptDrained
```

### 49.6 Diagnostics and provisional outputs

```text
CanonicalCompilerEvent
StdoutChunk
StderrChunk
ProvisionalObjectAvailable
MetadataReady
ProvisionalObjectInvalidated
SubscriberTranscriptIntent
SubscriberTranscriptAcknowledged
SubscriberTranscriptDeliveryUncertain
SubscriberStatefulCommitIntent
SubscriberStatefulCommitAcknowledged
SubscriberStatefulDeliveryUncertain
SubscriberDeliveryComplete
```

### 49.7 Result publication

```text
OfferPreparedActionResult          worker → coordinator
PreparedResultAccepted             coordinator → worker
PreparedResultRejected             coordinator → worker
ActionResultCommitted              coordinator → edges/workers/subscribers
ActionResultQuarantined            coordinator → interested peers
ActionTerminalFailure
```

There is no worker-authoritative `CommitActionResult`. The coordinator commits the action pointer inside its own metadata transaction and then emits `ActionResultCommitted` as a notification of an already durable fact.

### 49.8 Reconciliation

```text
ReconcileOperation
OperationInventory
OperationStateDigest
ResumeAttempt
SupersedeAttempt
RecoverTransferJournal
ReleaseOrphanPins
ReconcileSubscriberDeliveryState
```

### 49.9 Administrative/verification

```text
RunDeterminismAudit
RunShadowVerification
CollectFailureBundle
QuarantineLocation
QuarantineLogicalObject
QuarantineActionEntry
RepairObject
SeedPeerObjects
```

## 50. Envelope requirements

Every RABS message contains or derives:

- ATP and RABS protocol/schema versions;
- session ID and authenticated peer roles;
- `CoordinatorAuthority` for authority-bearing operations;
- causal trace ID;
- sender and destination peer IDs;
- build-operation/subscriber identity for delivery messages and action-generation/attempt/execution-lease/worker-boot/worker-incarnation identity for authority-bearing messages;
- idempotency key;
- sequence domain plus monotonic per-domain event sequence;
- payload length, collection counts, and nesting limits;
- capability scope reference;
- redaction and privacy classification;
- optional response-to and resume-from identifiers.

Decoders enforce byte, count, recursion, manifest-fanout, and decompression limits before allocation. Unknown authority-bearing fields fail closed unless the negotiated schema explicitly defines safe ignorance.

## 51. Canonical serialization

Requirements:

- deterministic field and map ordering;
- canonical integer, enum, optional-field, and byte-string encoding;
- no architecture-dependent layout;
- byte-preserving fields for Unix paths, argv, environment, and symlink targets, with explicit escaped display forms;
- bounded strings, lists, maps, nesting, and decompressed size;
- duplicate-field rejection;
- sorted semantic sets and maps;
- stable unknown-field behavior by message class;
- explicit normalization before transcript hashing or signing;
- golden fixture files for every message family;
- differential encoder/decoder tests;
- an ATP frame extension map encoded in numeric key order;
- independent versioning of object manifests, action schemas, and transport messages.

The native wire format is not Rust `repr`, arbitrary serde/bincode output, or an incidental in-memory enum layout.

## 52. Idempotency and replay

State-changing operations require idempotency keys and structured coordinator/attempt fencing. The receiver records enough durable state to answer safe retries:

- repeated `SubmitAction` joins the coordinator's existing action actor;
- repeated lease acceptance returns the existing attempt state;
- repeated range writes are digest/range idempotent;
- repeated prepared-result offers return the previous acceptance/rejection or conflict;
- repeated coordinator commit notification returns the already committed manifest;
- repeated cancellation or permit release cannot double-release resources;
- stale coordinator or execution leases fail closed;
- read-only inventory queries may be replayed, but state-changing 0-RTT remains disabled.

Idempotency does not mean an old coordinator may resume authority after a newer coordinator term/incarnation exists. Lease TTLs are evaluated with monotonic clocks and renewal sequences; wall-clock timestamps are diagnostic only.

## 53. Reconnect and reconciliation protocol

On an edge/coordinator or worker/coordinator session loss:

1. coordinator retains durable operation, subscriber-observable-state, and lease data;
2. edge retains wrapper connection state, materialization progress, transcript intent/exposure/uncertainty, stateful commit intent/commit/uncertainty, and per-domain delivery high-water marks;
3. worker retains attempt journal, process state where observable, staged pins, and transfer journal;
4. reconnection authenticates peer restart generation and current coordinator authority;
5. peers exchange bounded operation inventories and last accepted sequences per sequence domain;
6. pure reconciliation logic decides resume, supersede, cancel, collect, fail subscriber, or abandon;
7. publication eligibility is reissued only through the current coordinator authority, action generation, and execution lease;
8. orphan pins, processes, root permits, and provisional outputs are cleaned after proof;
9. edges that lost the coordinator before transcript exposure and before stateful commit intent may report or initiate a nonpublishing local fallback; after transcript exposure they reconnect, fail coherently, or use explicit labeled recovery, and after stateful commit intent they never launch uncoordinated fallback.

## 54. Path selection

Initial path policy:

1. direct LAN ATP;
2. direct Tailscale ATP;
3. Tailscale with DERP assistance where necessary;
4. ATP over TCP/TLS 443 fallback if implemented and proven;
5. existing SSH control/transfer fallback during migration and break-glass cases.

Path selection uses measured RTT, loss, throughput, stability, privacy, and policy. Tailscale provider failures are nonfatal caveats; they do not corrupt worker health state.

The coordinator selects object sources independently from execution placement. An action may execute on one worker while missing immutable inputs arrive from another verified peer. Cross-worker **child action dispatch from a remote Cargo process** remains disabled in V1 even though peer object seeding is allowed.

# Part XI. Durable CAS, action cache, and publication

## 55. Object model mapping

RABS should use ATP object concepts with build-specific profiles:

| ATP object concept | RABS profile |
|---|---|
| `FileObject` | source file, rmeta, rlib, object, executable, diagnostic blob |
| `DirectoryObject` | directory subtree |
| `SnapshotObject` | immutable source or execroot snapshot |
| `DatasetObject` | toolchain, sysroot, registry source set, native SDK |
| `ArtifactBundle` | complete action result output set |
| `SparseImage` | incremental-state snapshot or large sparse build state |
| `StreamObject` | diagnostics/action-event archive |
| `ApplicationDefinedObject` | action result, provenance, decision receipt, failure bundle |

Object kinds have explicit metadata policies. Source and output timestamps are excluded from logical object identity only for object/action profiles that declare and prove them nonsemantic. If timestamp or other metadata is observable, it is included in the manifest/key or the action loses portable shared authority. Permissions, symlinks, executable bits, xattrs, and platform attributes likewise follow an explicit profile.

## 56. Digest model

Use a versioned digest record rather than forcing one algorithm into every role:

```rust
struct DigestSet {
    atp_content_id: [u8; 32],
    blake3: Option<[u8; 32]>,
    raw_sha256: Option<[u8; 32]>,
    logical_size_bytes: u64,
}
```

Recommended roles:

- ATP domain-separated SHA-256 content ID: native logical object and manifest identity;
- BLAKE3: optional fast local fingerprints, chunk prechecks, and selected internal indexes;
- raw SHA-256: computed when an external gateway/store requires it, not universally by default;
- **V1 authoritative action keys, canonical schema identities, descriptor digests, and authority-binding digests:** SHA-256 over length-delimited canonical bytes with a distinct fixed domain separator and a typed algorithm/domain identifier.

Concretely, `ActionKey` is `SHA-256("rabs.action-key.sha256.v1\0" || len(canonical_descriptor) || canonical_descriptor)`, with the length encoded canonically. Other authoritative digests use their own domains, such as `rabs.coordinator-authority.v1`. A serialized digest always names its algorithm and semantic domain; two raw 32-byte arrays are never compared across digest types. Changing algorithm, canonical encoding, or domain creates a new key/schema epoch and namespace. BLAKE3 may accelerate local prechecks but is not silently substituted for an authoritative V1 digest.

A streaming writer computes required digests while writing a private temporary object, verifies expected logical bytes, applies storage encoding metadata separately, and atomically publishes only after completion. Digests are tagged by algorithm and domain; compressed bytes never masquerade as the logical uncompressed object identity.

Logical object identity and physical storage representation are separate:

```rust
struct StoredRepresentationId {
    logical_object_id: ObjectId,
    storage_profile_id: StorageProfileId,
    encoded_digest: Digest,
    encoded_size_bytes: u64,
}
```

A local store may retain raw, zstd, packed, or other versioned representations of one logical object. Representation selection never changes action keys. Concurrent writers using different storage profiles publish different representation records rather than racing for one ambiguous `<logical-digest>` pathname.

## 57. Whole-object, chunk, and pack identity

- Small standalone files and metadata may be stored as single blobs.
- Many tiny files may be placed into deterministic pack objects with a canonical member index, per-member digest/length, and bounded random access.
- Large rlibs, binaries, toolchains, source archives, and snapshots use deterministic chunk manifests.
- Incremental-state snapshots use content-defined chunking because adjacent states are highly self-similar.
- Tree manifests provide hierarchical short-circuit and missing-range discovery.
- Whole-object digest remains the correctness identity even when transport/storage uses chunks or packs.

Chunking and packing parameters are versioned. Old manifests are never reinterpreted under new settings. Pack membership is a storage optimization, not a semantic action-key input.

## 58. Compression

Default policy:

- do not compress already-compressed or tiny objects where overhead dominates;
- use zstd profiles selected by object class and CPU pressure;
- store compressed chunks with canonical metadata and content verification over uncompressed logical bytes unless the profile explicitly defines otherwise;
- measure CPU per GiB and transfer savings;
- allow worker-local uncompressed hot cache where it improves repeated materialization.

## 59. Storage tiers and trust namespace

```text
L0  process-local metadata and tiny-object cache
L1  edge-host local filesystem CAS
L2  worker-local filesystem CAS
L3  coordinator-directed fleet/LAN CAS peers
L4  optional encrypted cold object storage
```

The action index records object-location evidence, verification time, storage encoding, and quarantine status. Placement chooses the cheapest verified source.

V1 assumes one administratively trusted fleet namespace. Source and output objects are not exposed across unrelated users or tenants. At-rest encryption, namespace ACLs, and per-project keys may be added for sensitive fleets, but the plan makes no hostile multi-tenant isolation claim.

## 60. Durable CAS interface and write semantics

Required interface:

```text
has(object_id)
stat(object_id)
open_read(object_id)
put_if_absent(stream, expected_logical_digest, storage_profile) -> StoredRepresentationId
find_missing_batched(object_ids)
commit_manifest(manifest)
verify(object_id)
pin(object_id, owner, lease)
unpin(object_id, owner)
renew_pin(owner, lease)
quarantine_location(location, reason)
quarantine_logical_object(object_id, reason)
quarantine_action_entry(action_key, reason)
list_references(manifest_id)
mark_reachable(root)
gc(policy)
locate(object_id)
seed(destination, object_ids)
scrub(policy)
```

`put_if_absent`:

1. streams to a private temp file;
2. enforces logical-size and decompression limits;
3. computes/verifies the logical digest;
4. optionally compresses/encodes into a second private representation or stores canonical encoding metadata;
5. fsyncs file data/metadata according to trust/storage policy;
6. atomically renames into the final directory and fsyncs the containing directory before reporting durable publication where the platform supports it;
7. publishes under `(logical_object_id, storage_profile_id, encoded_digest)` and handles concurrent writers by atomic create/rename, verifying any existing representation before reuse;
8. if an existing typed logical digest/size resolves to different canonical bytes, or an encoded digest resolves to different encoded bytes/profile metadata, it opens a digest-domain collision/corruption incident, quarantines all implicated locations, and refuses publication rather than selecting one value;
9. publishes no partial path;
10. returns the already-existing verified object on a race and cleans the losing private temp object.

Operations are idempotent, bounded, crash-safe, and observable.

## 61. Filesystem layout

A recommended on-disk layout separates immutable content, packs, manifests, staging, journals, quarantine, and metadata:

```text
cas/
  logical/aa/bb/<logical-digest>.meta
  representations/<storage-profile>/aa/bb/<encoded-digest>
  chunks/<storage-profile>/aa/bb/<encoded-digest>
  packs/<storage-profile>/aa/bb/<encoded-digest>
  manifests/aa/bb/<logical-manifest-digest>
  staging/<operation-id>/<attempt-id>/
  journals/<operation-id>/
  quarantine/location/<incident-id>/
  quarantine/logical/<digest>/<incident-id>/
  temp/
  locks/
metadata/
  rabs.sqlite
```

Use atomic create/rename and explicit fsync policy. Staging and final CAS reside on the same filesystem where atomic rename is required. Reflinks are an optimization, never assumed. Periodic scrubbing verifies a sampled or complete set according to storage risk.


Manifest and materialization validation rejects absolute member paths, `..`, NULs, duplicate paths, platform-equivalent case/Unicode collisions, escaping symlinks, undeclared hardlinks, device nodes, sockets, FIFOs, overlapping/out-of-bounds pack member ranges, and other special files unless an action class explicitly defines and safely handles them. Tree/result manifests must be acyclic, depth/fan-out/count bounded, and closed under referenced object identity. CAS files are immutable and never writable-hardlinked into target, temp, `OUT_DIR`, or incremental directories. Platform-critical metadata such as executable bits, code-signature-preserving xattrs, or SDK/toolchain attributes is retained only through an explicit object profile and verified on materialization.

## 62. Metadata-store abstraction and FrankenSQLite gate

Define a narrow transactional `RabsMetadataStore` interface covering:

- coordinator authority acquisition;
- action lookup and coordinator-only commit;
- action-generation/attempt/execution-lease lifecycle;
- object location/edge/pin metadata;
- observed-input recipes and key breakdowns;
- trust, verification, and quarantine state;
- GC snapshots and reconciliation scans.

Provide:

1. a reference SQLite-compatible backend used for differential and crash-recovery truth;
2. a FrankenSQLite backend as the preferred dogfood implementation after it passes the same transaction, WAL/recovery, concurrency, fault-injection, and migration suite.

The database never holds large object bytes and is never hosted on NFS/shared mutable storage. One active coordinator owns authoritative writes. Loss of nonauthority location/index metadata degrades to misses and object reindex/rebuild, not source loss. Loss or rollback of coordinator authority, publication, generation-fence, trust, or subscriber-delivery metadata requires restore/reconciliation or an explicit new credential/operator-reset generation; it is never treated as an ordinary cold cache.

Recommended logical tables:

```text
coordinator_authorities
peer_authority_high_water
worker_incarnation_fences
edge_incarnation_fences
action_entries
action_generations
action_generation_tombstones
action_attempts
action_publications
action_serving_states
action_evidence_index
action_trust_evaluations
operations
edge_subscribers
objects
object_locations
object_edges
manifests
pins
leases
location_quarantine
logical_quarantine
action_quarantine
worker_sessions
worker_capabilities
worker_health_samples
decision_receipts
provenance_edges
observed_input_recipes
key_breakdowns
determinism_audits
verification_samples
materialization_records
gc_runs
schema_epochs
```

Important constraints:

- `ActionKey` is unique in the active slot/index; key/projection epoch columns are retained for inspection and migration even though they already contribute to the key;
- only the active coordinator authority may create a generation, accept a prepared result, or commit a publication;
- `ActionGenerationId` is globally never reused within a cluster authority lineage, and generation tombstones/high-water state survive active-slot eviction and metadata compaction for the full stale-lease/conflict window;
- `ActionGeneration.created_under_authority_digest` must equal the canonical digest of the full coordinator authority carried by each eligible attempt/publication;
- immutable publication history points to one immutable canonical result manifest, while current serving, trust, quarantine, expiry, and retention disposition lives in separate versioned rows;
- deterministic failures are `ResultKind::DeterministicFailure` publications governed by serving policy; there is no second failure-cache identity or overwrite path;
- attempts and evidence associations are append-only lifecycle records;
- current action generation and per-attempt execution leases are explicit;
- the publication row stores the canonical descriptor digest and winner generation/attempt, and its durable publication reachability root/pin is created in the same transaction;
- a same-key candidate with a different descriptor digest or canonical semantic result enters conflict quarantine rather than overwriting; evidence-only differences append normally;
- peer authority high-water and worker/edge incarnation-fence rows are authoritative recovery inputs, not disposable cache metadata;
- edge handoff rows represent at most one active incarnation plus one named predecessor during a bounded handoff;
- object edges permit reachability traversal;
- pins have owner and expiry/renewal semantics;
- quarantined locations/objects/actions are selected according to distinct rules;
- migrations are transactional and versioned;
- startup reconciliation checks rows against filesystem reality and refuses serving when authority/publication/fence state is incomplete.

## 63. Pin and lease model

Pin classes:

```text
ActionPublicationPin
ActiveAttemptInputPin
ActiveAttemptOutputPin
ProvisionalMetadataPin
MaterializationPin
TransferPin
VerificationPin
ToolchainInventoryPin
RetentionPolicyPin
AdministrativePin
```

Pins have:

- owner identity;
- object/manifest root;
- creation evidence;
- optional authority-issued lease/validity record;
- renewal sequence/high-water mark;
- durable versus ephemeral classification;
- reason and provenance.

Pin expiry never depends on a worker comparing its wall clock with a coordinator timestamp. Publication and administrative pins are durable until an explicit authority-bearing retention transition. Ephemeral pins use coordinator-issued lease IDs, monotonic renewal sequences, and a conservative coordinator validity record; after coordinator/worker restart, partition, or clock uncertainty, an unresolved pin remains protected through reconciliation and grace rather than being collected optimistically. Release is idempotent and authority-scoped. Workers may release their candidate/attempt pins but cannot release an action-publication root.

GC may delete only objects unreachable from retained roots and unprotected by valid pins/leases. A missing, stale, or contradictory lease row fails toward retention until reconciliation proves the owner terminal or the authority generation fenced.

## 64. Atomic coordinator-authoritative action-result publication

### Worker preparation and offer

1. compiler process exits normally or produces a separately classified deterministic failure;
2. worker harvests the private output write set;
3. outputs and side effects are validated against declarations;
4. each object is hashed and uploaded with `put_if_absent` under candidate pins;
5. worker builds an immutable `ArtifactBundle` and `CanonicalActionResultManifest` containing only canonical result identity;
6. worker separately builds an `AttemptEvidenceBundle` containing producer authority, command snapshot, observed-input report, provisional lineage, isolation/trust evidence, raw process/event evidence, timings/resources, verification observations, and optional incremental snapshot reference;
7. worker sends `OfferPreparedActionResult` naming both objects with coordinator/action-generation/attempt/execution-lease identity. Candidate pins remain valid through coordinator decision/reconciliation.

### Coordinator validation and commit

8. coordinator verifies its current authority, action generation, and attempt authority fence;
9. coordinator reloads and byte-compares the canonical descriptor object, validates the action key and independent descriptor digest, then checks projection/key schemas, output platform, toolchain, isolation/trust evidence, output declarations, complete object closure, and provisional lineage;
10. coordinator independently recomputes `semantic_result_digest` from a versioned semantic projection that excludes both digest fields and attempt evidence, then recomputes `observable_result_digest` from that semantic projection plus canonical observations, again excluding the digest fields themselves; it records the prepared candidate/evidence transactionally;
11. coordinator performs a compare-and-set requiring the action to be uncommitted and the candidate generation to be current, then atomically writes `action_key → canonical_result_manifest_id`, descriptor digest, winner generation/attempt/evidence, provenance edges, publication receipt, and the durable action-publication reachability root/pin; an independent evidence index and trust-evaluation record govern serving eligibility;
12. if the row already names the same canonical result, the result is idempotently compatible and the new attempt evidence may be appended; a different semantic-result digest quarantines the action, while a semantic match with observable-result divergence enters presentation/observability quarantine; if both declared digests match but canonical manifest bytes/object IDs differ, the coordinator opens a canonical-serialization/projection-completeness incident and quarantines ordinary serving rather than treating the difference as evidence-only;
13. CAS objects/manifests satisfy their configured durability profile before the metadata transaction can commit; only after that transaction, including the publication pin, is durable does the coordinator emit `ActionResultCommitted`;
14. candidate pins then release or convert to subscriber/materialization/verification pins; the publication root already protects the committed closure;
15. stale/lost attempts are cancelled and drained.

A worker never sends a command that asks another component to perform an authority-bearing commit on the worker's behalf. Repeating the same candidate/evidence offer is idempotent; a new evidence bundle for the same canonical result is compatible append-only evidence rather than a duplicate commit. Attempt-specific provenance, timings, verification, and incremental state never alter canonical result identity. No action result is patched in place; correction means quarantine plus recomputation or a new key/projection epoch.

## 65. Provisional metadata storage and transitive lineage

Provisional `.rmeta` and related early outputs:

- are immutable verified objects;
- are pinned by `(CoordinatorAuthority, ActionKey, ActionGeneration, AttemptId, ExecutionLeaseId, LogicalOutputId)`;
- are visible only to authorized dependent attempts and the edge/Cargo instance awaiting them;
- become Cargo-visible for one subscriber only after complete materialization at that subscriber's exact requested path;
- trigger exactly one replayed rustc artifact-notification line per subscriber/logical metadata output;
- are marked provisional in provenance;
- cannot become stable merely because another attempt for the same action succeeds;
- carry a lineage record naming the producer action/generation/attempt, logical output ID, and exact object ID;
- create a direct producer obligation for the consumer and propagate the complete transitive provisional-ancestor set into every prepared descendant result;
- block descendant publication until the coordinator resolves the entire ancestor closure;
- are invalidated if the producer generation fails, is superseded without compatible adoption, or loses authority;
- are garbage-collected only after all consumer and reconciliation obligations drain.
- create edge-local provisional materialization records for every subscriber output installed before lineage closure.
- mark every descendant output derived from unresolved lineage as provisional, even when its own producing process has exited successfully;
- permit early metadata/event delivery only under the subscriber's provisional journal;
- withhold terminal wrapper success and non-provisional final-output readiness until all ancestors resolve to committed exact objects;

If lineage later fails, the edge marks those materializations unusable and performs only ownership-safe cleanup: it removes/replaces a path only when the current bytes/identity still match the RABS-installed object and the path belongs to that operation. Otherwise it marks the target state dirty and requires Cargo revalidation or a private target reset. Cargo fingerprint/output-cache cleanup follows stock differential fixtures; RABS never guesses by deleting unrelated user state.

### 65.1 Adoption by a different winning producer attempt

A hedge/retry attempt may win after a consumer used metadata from another attempt. The coordinator may satisfy that lineage only when the committed producer result contains the **same logical output object ID** under a compatible toolchain/event contract. In that case it records an explicit adoption edge from the provisional attempt to the committed result. If the object differs, every descendant that consumed it is cancelled/refused and cannot publish.

### 65.2 Transitive publication check

A prepared result stores a canonical sorted set of provisional ancestor references. The coordinator's commit transaction checks that every referenced producer action is committed and resolves to the exact consumed object. Direct-only checks are insufficient: if A provisionally feeds B and B provisionally feeds C, C cannot commit until both A and B resolve.

## 66. Deterministic-failure publication and serving policy

An eligible deterministic failure uses the same immutable publication path as success, with `ResultKind::DeterministicFailure`; it is not written into a second action identity or overwriteable side cache. Publication is permitted only when all conditions hold:

- normal process exit with a deterministic nonzero status;
- complete canonical diagnostic/event capture;
- closed positive and negative input set;
- no undeclared external side effect;
- no OOM, signal, cancellation, timeout, worker loss, transport failure, or internal panic;
- action class and trust policy permit deterministic-failure publication;
- key/projection/toolchain identity matches exactly.

The mutable `ActionServingStateRecord` applies a short revalidation TTL by default. TTL expiry suppresses serving and schedules or requires re-execution; it never rewrites the immutable failure publication. A byte-identical revalidation appends evidence and renews serving disposition. A success or observably different failure under the same exact key is a soundness/determinism incident and quarantines the action rather than replacing the publication.

Deterministic-failure manifests may contain canonical diagnostics/stdout/stderr and the normalized process outcome, but never materializable build outputs, provisional metadata, mutable target deltas, or attempt-specific auxiliary state. Exact byte replay requires a matching presentation variant; otherwise RABS safely re-renders canonical diagnostics or bypasses serving.

## 67. Corruption and quarantine scopes

Do not quarantine an entire logical action merely because one storage location has a bad copy.

### Location quarantine

Use when a blob at one disk/peer fails its expected digest or cannot be read:

1. remove that location from selection;
2. preserve incident evidence;
3. refetch from another verified location;
4. scrub adjacent data if device failure is suspected;
5. keep the logical object/action valid when another verified copy exists.

### Logical object or manifest quarantine

Use when all known copies disagree with the object identity, a manifest closure is invalid, or canonical decoding fails. Dependent action entries become unavailable until a valid object is reconstructed or rebuilt.

### Action-entry quarantine

Use for semantic divergence, invalid provenance/trust, an incorrect key projection, or an output set inconsistent with the action descriptor. Immutable blobs may remain usable by other valid manifests.

No object is silently rewritten under the same digest, and quarantine release requires an explicit verified repair receipt.

## 68. GC, retention, and deletion races

GC is reachability-based with policy layers:

- committed action results retained by LRU/value policy;
- toolchains and hot dependencies retained longer;
- active branch/commit snapshots pinned;
- nearest incremental ancestors retained under bounded per-repo budgets;
- provisional/staging data expire aggressively only after reconciliation;
- quarantined data follows incident-retention policy;
- cold storage may retain manifests after local representations are evicted.

GC must:

- operate from a consistent metadata snapshot;
- protect active builds, materializations, transfers, open readers, and valid pins;
- use mark → tombstone → grace period → unlink rather than immediate deletion;
- recheck liveness/pins before final unlink;
- expose planned and actual reclaim receipts;
- handle disk-pressure emergency mode without deleting authoritative evidence blindly;
- stop before causing foreground I/O collapse;
- remain correct under concurrent `put_if_absent`, materialization, and peer seeding.

## 69. Peer seeding, replication, and privacy

Initial policy is coordinator-directed, not free-form swarm behavior:

- workers/edges advertise compact probabilistic inventory hints;
- correctness still uses bounded missing-object queries or verified reads;
- scheduler prefers workers already holding required toolchain/input/dependency objects;
- coordinator may seed hot immutable objects worker-to-worker;
- every received object is independently verified;
- seeding is optional work and browns out under pressure;
- object location is evidence, not identity;
- secret-sensitive or project-restricted namespaces are not seeded outside their access policy;
- cold replication can encrypt objects and manifests at rest according to fleet policy.

Multi-peer union and erasure-repair paths remain evidence-gated frontier work.

# Part XII. Scheduling and global resource control

## 70. Two schedulers, one authoritative fleet coordinator

Do not conflate:

- **Asupersync runtime scheduling**, which runs futures, I/O, timers, cancellation, and control tasks;
- **RABS action scheduling**, which admits expensive Cargo/compiler/linker/test processes across the fleet.

`rabs-coord` is the sole authoritative action scheduler in V1. Edge daemons may make the bounded local decision to fail open before observable commit, but they do not independently lease workers or commit shared actions.

Single authority does not mean one executor thread or one global mutex. The coordinator shards the action/discovery registries by `ActionKey`, gives each actor a bounded mailbox, isolates authority/cancellation/lease queues from telemetry and bulk-object planning, and permits concurrent read/lookup/evidence work. Only the narrow metadata transactions that create generations, mutate serving state, or commit publications require serialized database authority. Slow subscribers, object inventory scans, verification audits, and dashboards run outside action-actor critical sections. Bounded overload causes explicit defer/refuse or pre-frontier local fallback; it never creates a second coordinator.

Coordinator capacity is a release gate: measure lookup/join/admission/publication latency, mailbox depth, metadata commit latency, scheduler loop lag, CPU/memory, and recovery scan time under at least the fifteen-agent replay plus burst and long-lived-session workloads. A future partitioned/sharded authority requires real consensus/fencing and is not smuggled in as “horizontal scaling.”

Fail-open is an availability/safety mode, not a performance guarantee. When the coordinator or edge is unavailable, fleet singleflight and root-permit accounting may be lost. The wrapper/agent harness may use a pre-existing host-local emergency limiter where one is available without violating the latency bound, but it must not wait on stale distributed authority. Telemetry labels this `UncoordinatedLocalFallback`, and storm benchmarks include the degraded case.

Compiler CPU work remains in managed OS processes/cgroups. Asupersync orchestrates it but does not run LLVM codegen on executor threads.

For a whole-command remote Cargo action, V1 keeps child rustc/link/build-script execution on the selected worker. Those children may use worker-local/shared CAS and join coordinator-owned identical results, but the remote Cargo process does not dispatch its children to arbitrary second-hop workers until a later evidence-gated design.

## 71. Cargo root permits and global jobserver ownership

A shared jobserver pipe alone is insufficient because each independent Cargo process assumes an implicit token. RABS therefore uses two coupled controls.

The meaning of a Cargo grant depends on the execution plane:

- **local Cargo with fine-grained remote children:** the root/frontier grant bounds live Cargo graphs and submitted wrapper requests; expensive CPU/memory is admitted separately on the selected worker;
- **whole-command Cargo on a worker:** the root permit and worker-local jobserver are derived from that worker's execution resource grant;
- **coordinated local execution:** the edge's jobserver/resource grant reflects local pressure;
- **uncoordinated fail-open:** no stale fleet grant is reused; an already-running host-local emergency limiter may bound the fallback without delaying the safety path.

A worker execution grant is never invented before worker selection merely because local Cargo holds a graph token.

### Root permit

Before spawning a Cargo process under the managed command palette, `rabs-edge` obtains a `CargoRootPermit` from `rabs-coord` or a coordinator-issued local grant. The permit backs Cargo's implicit token and is held until Cargo exits and descendants/cleanup release it. Starting ten Cargo processes requires ten root permits; no unaccounted implicit concurrency is created.

### Jobserver tokens

For a Cargo grant of capacity `C ≥ 1`, Cargo's implicit token consumes one unit and the local jobserver exposes at most `C - 1` transferable tokens. A grant of one therefore exposes zero extra tokens, not one.

1. the coordinator allocates one Cargo root/frontier grant; a worker/host execution resource grant is allocated separately when placement is known;
2. the edge or worker creates/joins a valid local GNU make jobserver sized to the remaining transferable capacity;
3. Cargo and rustc inherit valid descriptors/auth and use tokens for crate/codegen/native parallelism;
4. local descriptors are stripped from remote requests;
5. worker-local descriptors never refer to a client-host pipe;
6. build scripts and native make/Ninja tools cooperate where supported;
7. standalone fine-grained remote compiler attempts receive an action resource grant, not a fictitious Cargo root permit;
8. token/root-permit ownership is an obligation released exactly once;
9. PSI/cgroup pressure can reduce future grants or admission, but existing token protocols remain valid.

Acquisition order is fixed and tested:

```text
coordinator graph/root or action admission
  → placement plus bounded input-transfer reservation
  → input materialization and temp/output-disk reservation
  → worker/edge execution admission and memory envelope
  → local jobserver token immediately before process spawn
  → process execution against pre-reserved output capacity
```

No code waits on bulk network/CAS input transfer while holding a scarce compiler jobserver token. No code waits for an earlier-tier permit while holding a later-tier resource that another action needs to release it. Each active Cargo root receives reserved producer/control capacity, and provisional-lineage waiters are bounded so they cannot occupy every job slot.

Do not rely on a contradictory "very high `-j` but hidden token limit" configuration without compatibility tests. The exact `-j`, implicit-token, and jobserver behavior is tested across supported stable/beta/nightly Cargo/rustc versions. Raw jobserver descriptors/auth strings are execution capabilities and are replaced per host; any child-visible logical capacity such as `NUM_JOBS`, normalized `CARGO_MAKEFLAGS`/`MAKEFLAGS`, or another queryable parallelism value is supplied canonically and enters the presented environment whenever it can affect behavior.

Jobserver control is necessary but not sufficient: memory-heavy links/LTO, disk pressure, and many independent external tools also require wrapper-level admission and cgroup limits.

## 72. Resource dimensions

Every action has an estimated resource envelope:

```text
cpu_threads
memory_bytes
memory_peak_class
disk_read_bytes
disk_write_bytes
temp_space_bytes
network_input_bytes
network_output_bytes
linker_heaviness
lto_heaviness
process_count
expected_duration
uncertainty
```

Estimates derive from historical action-class/toolchain/crate observations and are updated after completion.

## 73. Admission classes

Recommended classes:

```text
TinyMetadata
OrdinaryRustc
HeavyCodegen
ProcMacroHost
BuildScriptLight
NativeCompile
HeavyNativeBuild
LinkOrdinary
LinkHeavy
ThinLto
FatLto
TestShort
TestLong
ToolchainTransfer
IncrementalSnapshotTransfer
VerificationAudit
Speculative
```

Each class has default concurrency, memory headroom, queue policy, and remote break-even threshold.

## 74. Worker snapshot and admission

Worker execution-eligibility snapshots, which are scheduler evidence rather than action-key inputs, include:

- durable worker identity and generation;
- admin intent and eligibility state;
- queue depth and active slots;
- CPU utilization and load;
- memory PSI and available memory;
- I/O PSI and disk queue/latency;
- root/temp/CAS free space;
- toolchain inventory;
- cache locality hints;
- recent artifact retrieval success/timeouts/failures;
- recent cancellation debt and process cleanup reliability;
- path quality;
- snapshot age and confidence;
- active-project exclusion state;
- canary/quarantine state.

Use Asupersync’s deterministic RCH health/admission model as the pure policy core, extended with RABS action dimensions. The output is a structured candidate receipt and final decision.

## 75. Candidate scoring

A conceptual score:

```text
expected_completion_time =
    predicted_queue_delay
  + missing_input_transfer_time
  + toolchain_materialization_time
  + predicted_execution_time
  + output_return_time
  + reliability_risk_penalty
  + pressure_penalty
```

Hard exclusions occur before scoring:

- incompatible platform/toolchain;
- stale or contradictory health evidence;
- insufficient disk/memory headroom;
- admin disabled/draining state;
- active-project exclusion;
- unreliable artifact retrieval beyond policy;
- sandbox capability mismatch;
- trust or identity mismatch;
- transfer break-even failure for remote-required policy.

## 76. Transfer break-even

Remote execution should occur only when predicted benefit is positive, except when an explicit remote-required policy applies.

Inputs:

- expected local queue delay;
- expected local execution duration;
- remote queue and execution duration;
- already-local object fraction;
- path throughput/RTT/loss;
- output size;
- toolchain availability;
- cancellation risk;
- action uncertainty.

Tiny actions with cold remote inputs should usually execute locally. Long or widely shared actions may justify remote execution even with moderate transfer cost.

## 77. Critical-path scheduling

The provenance DAG and live Cargo observations allow critical-path estimates. Prioritize actions by:

- number and importance of blocked dependents;
- historical downstream fan-out;
- remaining path duration;
- foreground subscriber urgency;
- metadata-ready potential;
- action duration and uncertainty;
- cache/prewarm status.

A slow dependency blocking many crates outranks an independent leaf action even if they arrived in the opposite order.

## 78. Speculation and SLO brownout

Speculative work is modeled as optional SLO work.

Policy:

- no foreground interest: optional;
- foreground subscription arrives: promote to required;
- pressure crosses soft threshold: stop admitting new speculation;
- pressure crosses harder threshold: cancel low-value speculation and drain;
- cleanup and object integrity work remain required;
- provenance records wasted and saved speculative work.

A speculation model should optimize expected saved foreground latency minus execution/transfer/storage cost.

## 79. Hedging policy

Hedge only when:

- action is on the critical path;
- predicted tail risk is high;
- duplicate cost is acceptable;
- workers are independent enough to reduce correlated risk;
- action is safe to duplicate;
- output publication fencing is active.

Examples:

- remote attempt stalls under ambiguous network degradation: hedge locally or to another warm worker;
- short ordinary crate: do not hedge;
- huge expensive LTO action: hedge only under exceptional deadline policy.

## 80. Pool sizing

Use Asupersync’s queueing-theoretic pool-sizing substrate in advisory mode for:

- concurrent compiler actions;
- hashing workers;
- CAS readers/writers;
- compression workers;
- linkers;
- native build actions;
- test processes;
- transfer streams.

Managed automatic resizing requires:

- stable observation windows;
- hysteresis;
- minimum evidence counts;
- replay validation;
- explicit operator opt-in;
- rollback on tail-latency regression.

## 81. Fairness

Fairness dimensions:

- foreground versus optional;
- agent/user identity;
- repository/project;
- CI versus interactive;
- long versus short actions;
- cleanup versus new work.

Use weighted fair scheduling with deadline/critical-path overrides and starvation limits. Cleanup and cancellation control traffic always retain reserved capacity.

---

# Part XIII. Cargo and rustc integration

## 82. Integration surfaces and canonical Cargo driver

Primary surfaces:

- `rch exec -- cargo ...`, hook interception, or an equivalent launcher that starts Cargo inside the canonical driver namespace;
- `RUSTC_WRAPPER` for broad rustc interception;
- `RUSTC_WORKSPACE_WRAPPER` where separate workspace classification is beneficial;
- linker proxy through target/linker configuration or rustc link args;
- `CC`, `CXX`, `AR` wrappers for native build subactions;
- a gated nextest target-runner adapter for per-test actions;
- file watchers and git hooks for speculation/prewarm.

The canonical Cargo driver is a P0 requirement for workspace cross-worktree authority. Before launch it resolves an `EffectiveCargoConfigContract` containing every applicable workspace/ancestor `.cargo/config*`, `CARGO_HOME` config, command-line `--config`, environment override, alias, source replacement, registry, target runner/linker, credential-helper reference, and toolchain-selection input. The contract preserves each config value's origin and resolves origin-relative paths exactly as Cargo would, including `[env]` relative semantics and local directory/source replacements. Secret credentials remain capabilities/fetch-phase inputs. Host-global config never influences an authoritative action invisibly.

It canonicalizes:

- Cargo cwd/workspace/package roots;
- `CARGO_HOME` and registry/git paths;
- target and build directories;
- `OUT_DIR` and generated child environments;
- Cargo-generated unit hashes, metadata flags, and output filenames;
- wrapper and linker paths;
- path-dependency closure.

A noncanonical Cargo parent may still use a dependency fast path if exact immutable dependency inputs and output paths satisfy the admitted profile. It cannot publish shared workspace entries merely because its child rustc process was remounted later.


### 82.1 Dependency resolution, fetching, and workspace mutation

Canonical execution must preserve Cargo behavior when dependencies are missing or Cargo would update workspace files:

- registry/git/index/network acquisition is an explicit fetch/resolution phase with a bounded network capability; its resulting source/index/config objects become immutable inputs to the offline canonical build;
- RABS never silently adds `--locked`, `--offline`, or another semantic flag merely to simplify caching;
- when the user's command would update `Cargo.lock`, manifests, or another workspace file, Cargo runs against a private writable overlay and RABS records a source-mutation receipt;
- such mutations are applied back to the requesting worktree only with content/version preconditions and before unrelated cached build outputs are declared complete;
- a concurrent-edit conflict aborts remote mutation replay and falls back/fails coherently rather than overwriting the user's work;
- commands with unbounded workspace mutation remain local or whole-command side-effecting operations and do not publish fine-grained shared action results from an inconsistent snapshot;
- immutable dependency fast paths require the exact resolved package/source/checksum identity, not merely a package name/version string.

This phase separation keeps ordinary compilation offline and reproducible without changing what unmodified Cargo would have resolved or written.

### 82.2 Requested and resolved snapshot lineage

A `BuildOperation` may own a short immutable snapshot lineage rather than pretending that legitimate Cargo resolution mutations never occur:

```text
RequestedCommandSnapshot
    → private resolution/fetch/lockfile overlay
    → ResolvedExecutionSnapshot
    → zero or more action-closure manifests
```

Rules:

- Cargo resolution/fetch begins from `RequestedCommandSnapshot`; only the operation-owned overlay is writable.
- Before the first compilation action that depends on resolved state, the edge seals `ResolvedExecutionSnapshot`, including any derived lockfile/config/source-selection state.
- Every fine-grained action names exactly one sealed snapshot generation in subscription/provenance and derives its minimal closure from that generation.
- If Cargo or another process mutates a semantically relevant source/config file after sealing, the operation either seals a strictly newer phase before dependent actions start, restarts planning coherently, or becomes a side-effecting whole-command/local operation.
- Applying a lockfile mutation back to the subscriber worktree uses preconditions and never retroactively changes the snapshot identity of actions that already ran.

## 83. Wrapper role split and nested-wrapper semantics

### Outer/global wrapper

Optimized for registry/git dependencies and general interception:

- very fast key/lookup path;
- immutable source assumptions validated by checksum;
- high hit-rate expectation;
- conservative exact dependency artifact inputs;
- minimal agent-specific intelligence.

### Workspace wrapper

Adds classification and canonical Cargo context for:

- coherent command snapshots and action closures;
- branch-aware incremental state;
- speculation and priority promotion;
- richer provenance and workspace volatility policy.

Cargo may invoke:

```text
$RUSTC_WRAPPER $RUSTC_WORKSPACE_WRAPPER $RUSTC <args>
```

The outer wrapper receives the workspace wrapper as its compiler argument for workspace crates. It must preserve/normalize the chain and ultimately execute the exact intended inner wrapper and rustc. Tests cover one wrapper, two nested wrappers, wrapper paths with spaces, response files, environment overrides, and first-enable fingerprint changes.

If dual-wrapper configuration causes unacceptable fingerprint or compatibility churn, one tiny binary may implement both policies, but the semantic distinction remains.

## 84. Wrapper request flow

1. validate a bounded wrapper re-entry depth and signed/internal self-host bypass marker, then capture argv, decoded wrapper chain, canonical/real cwd, exact presented environment digest, stdin mode, and parent Cargo context;
2. identify action class, output paths, and unsupported patterns;
3. connect to local `rabs-edge` UDS with a tiny bounded timeout and a resumable request token;
4. submit the bounded request and subscriber presentation/path context;
5. edge resolves the wrapper request against the existing operation-owned sealed snapshot generation; only standalone dependency/probe paths may construct a new bounded snapshot at this point;
6. receive `ExecuteOriginalChain`, `ServeHit`, `JoinAction`, `RemoteExecute`, or `PolicyRefused`;
7. stream canonical transcript events and stateful materialization/readiness instructions with one monotonically ordered subscriber sequence;
8. materialize each output before replaying the state-advancing event that declares it ready;
9. track transcript exposure separately from every stateful observable commit, loop over all delivered items, and acknowledge only after complete exposure;
10. return the exact tool exit status only as the terminal delivered item;
11. on edge restart, reconnect using the request token and per-subscriber delivery sequence; on unrecoverable edge/coordinator failure before transcript exposure and before any stateful commit intent/observable exposure, detach the subscription, revoke its future materialization rights, discard private staging, and execute the original wrapper/tool chain locally as a nonpublishing fallback when policy allows. After transcript-only exposure, use reconnect/coherent failure by default or the explicit labeled-recovery policy; after stateful commit intent, never launch uncoordinated fallback.
12. forward SIGINT/SIGTERM/SIGHUP and parent-death/client-disconnect into that subscriber's cancellation state while preserving signal-versus-exit classification; when the wrapped tool terminates by signal, the wrapper restores default handling and terminates itself with the same signal where the platform permits rather than silently translating it to `128+N`. The shared attempt is cancelled only through reference-counted action policy when no retained interest remains. A SIGKILLed wrapper is detected from UDS/PID liveness and loses only its own subscription.
13. treat PTY/TTY-dependent or interactive actions as local/whole-command passthrough unless a separately proven terminal proxy profile applies.

## 85. Per-subscriber transcript and stateful fail-open boundaries

```text
Silent / NoStatefulCommit
    no transcript bytes exposed
    no rustc early artifact notification replayed
    no target/build output exposed as complete
    no deterministic failure or terminal result served
    → seamless local nonpublishing fallback may be safe

TranscriptExposed / NoStatefulCommit
    diagnostics/stdout/stderr/progress already shown
    → reconnect or fail coherently by default; optional explicitly labeled transcript recovery only

StatefulCommitIntentOrCommit
    `.rmeta` notification replayed, output declared ready, or cached terminal result exposed/being exposed
    → no uncoordinated fallback; reconnect/continue or fail coherently
```

Before a particular subscriber exposes either frontier, duplicate remote work may continue after a partition, but coordinator fencing prevents stale attempts from publishing. Other subscribers may already have crossed one or both frontiers. Any local fallback is nonpublishing unless a later explicit reconciliation proves it is the valid attempt.

After transcript exposure, silently restarting the original chain would create a mixed or duplicated transcript. After stateful commit intent, an independent local producer could additionally mix incompatible provisional/final state in Cargo's live build. The edge therefore follows the stricter applicable policy: reconnect, receive a coordinator-issued recovery/hedge, run an explicitly labeled transcript-only recovery where permitted, or terminate the wrapper coherently.

## 86. Cargo/rustc event and diagnostic fidelity

RABS distinguishes three streams:

1. rustc's line-delimited JSON diagnostics and artifact notifications consumed by Cargo;
2. Cargo's own outward JSON messages such as `compiler-artifact`;
3. human stdout/stderr presentation.

The wrapper must:

- preserve line-delimited framing and required ordering;
- stream diagnostics promptly;
- store canonical structured compiler events;
- replay artifact notifications only after the named output exists completely at Cargo's expected path;
- let Cargo itself generate its outward messages;
- translate virtual paths through a tested subscriber mapping;
- preserve diagnostic codes, lint/error semantics, rendered children, and process exit status;
- handle non-JSON and mixed output modes through presentation variants or bypass;
- cap memory through streaming/spill;
- maintain golden behavior fixtures across stable/beta/nightly Cargo and rustc.

## 87. Cargo pipelining

Cargo's current pipeline marks an internal metadata dependency edge complete when it parses a rustc artifact-notification JSON line whose artifact path ends in `.rmeta`. This is not Cargo's outward `compiler-artifact` event.

### Cache hit under local Cargo

1. resolve the exact `.rmeta` logical output and Cargo-requested path;
2. fetch, verify, and fully materialize the file atomically;
3. apply required mtime/freshness metadata;
4. replay the exact canonical rustc artifact-notification JSON line with the expected path;
5. Cargo may now start dependents;
6. continue materializing rlib/object/other outputs;
7. replay each remaining required compiler event only after its output is ready;
8. return success after complete result materialization.

### Fine-grained remote execution under local Cargo

1. worker closes and verifies the declared `.rmeta` output;
2. upload it and emit `MetadataReady` for its stable logical output ID;
3. coordinator checks current attempt authority and forwards it to subscribed edge(s);
4. edge materializes the exact requested path completely;
5. wrapper replays the rustc artifact-notification line exactly once;
6. dependent actions may execute against a provisional pin and producer-commit obligation;
7. producer continues codegen and final result offer.

### Whole-command remote Cargo

Cargo and rustc pipeline locally on the selected worker. The client does not need each worker-local `.rmeta`; only diagnostics/progress and requested final artifacts return, unless a future nested action plane is explicitly enabled.

Golden tests pin current Cargo event parsing and queue behavior. RABS treats upstream changes as compatibility-matrix failures, not assumptions.

### 87.1 Provisional-lineage waiters and Cargo progress capacity

A dependent wrapper that consumed provisional metadata may finish execution before its ancestors commit, but it cannot return terminal success until lineage closes. Such wrappers still occupy Cargo job slots. RABS therefore:

- reserves at least one producer/progress slot per active Cargo root;
- bounds the number and transitive depth of lineage-waiting wrappers;
- stops replaying additional provisional metadata when waiters would consume the root's progress reserve;
- prioritizes unresolved producer attempts and their required output transfer/control traffic;
- measures whether pipelining benefit exceeds occupied-slot cost and can fall back to full-result readiness for pathological graphs.

No wrapper holds a separately acquired transferable jobserver token while waiting on bulk input transfer; Cargo-owned child-slot occupancy is accounted explicitly in the frontier scheduler.

## 88. Provisional dependency failure

If a producer later fails or loses authority:

- coordinator invalidates its provisional lineage for stable use;
- dependent attempts that consumed it receive cancellation/supersession;
- their processes, tokens, streams, and pins drain;
- the producer wrapper's nonzero exit naturally reports the original compiler failure to its Cargo process;
- coordinator prevents dependent publication through the unresolved producer-commit obligation;
- a causal trace records which dependents began from the provisional output;
- already emitted Cargo diagnostics/events are not fabricated or silently retracted.

RABS does not claim it can make Cargo forget an already replayed metadata notification. Its safety mechanism is to prevent invalid dependent results from committing and to fail/cancel the live build coherently.

## 89. Dep-info, negative dependencies, and input enforcement

RABS parses and normalizes:

- standard dep-info;
- binary-dependency dep-info where available;
- response files;
- exact extern artifacts;
- build-script generated sources;
- source-map/path-remap data;
- successful and failed file reads;
- directory enumerations and symlink resolutions;
- selected subprocess executable and `PATH` alternatives.

Dep-info is evidence, not a complete security boundary. Authoritative execution uses a closed filesystem view and aborts on a new read. The exact presented environment is independently key-complete.

Dep-info materialized for Cargo is rewritten coherently to the live Cargo path model and mtime/checksum policy; RABS never mutates immutable CAS inodes merely to adjust mtimes.

The shared result stores canonical dep-info. Each edge derives a subscriber-specific dep-info file with exact Makefile escaping/path semantics, records its derivation contract and digest, and installs it privately. Derived real-path dep-info is not the canonical CAS object or a semantic dependency artifact. If lossless rewriting cannot be proven for a format/toolchain case, RABS bypasses that hit.

## 90. Exact link caching

Link action key includes:

- linker identity;
- exact normalized link arguments;
- ordered object/archive/shared-library content identities;
- linker scripts and response files;
- environment;
- target/platform contract;
- relevant sysroot/runtime objects;
- output class and flags.

The invocation family is discovered and then executed under a closed linker filesystem view. RABS records the actual files selected by `-l`/framework/default search, startup objects, default linker scripts, linker plugins, response-file inclusions, and failed/alternative lookup candidates. A bare `-lfoo`, framework name, or default CRT behavior is never keyed only by its spelling. If the selected linker can read an uncontrolled system search path that RABS cannot close and reproduce, the link action remains local/nonshareable.

Link outputs and diagnostics are cached atomically. Wild, lld, and system linkers remain selectable. RABS does not implement its own incremental linker.

## 91. Build-script execution interception

Preferred mechanisms, in order:

1. canonical Cargo-driver integration that can intercept a build-script run without substituting path identity;
2. a launcher shim at Cargo's expected path only after compatibility proof;
3. no run-cache serving when neither mechanism preserves Cargo semantics.

For an eligible run:

1. build-script executable is compiled normally or served from cache;
2. RABS submits a `BuildScriptRun` action with exact inherited environment, jobserver state replacement, Cargo-provided visible paths, and a digest of any readable pre-run `OUT_DIR`/Cargo output-cache state;
3. worker materializes that exact pre-state or a proven-empty state, then executes under the required isolation profile and traces filesystem/process/network inputs;
4. exact stdout/stderr bytes, per-stream ordering, recorded cross-stream event sequence where observed, Cargo directives, complete post-run `OUT_DIR`, deletions/tombstones, Cargo output-cache files, and process status are captured; RABS does not invent an unknowable total order between independently piped streams;
5. RABS parses a structured directive manifest, validates every path-valued directive against the output/toolchain/native input closure, and records the native-link search/result dependencies that downstream rustc/link actions may observe;
6. successful closed results may publish;
7. a hit stages the complete post-state in a clean private directory, atomically replaces the destination, revalidates directive-referenced paths, and only then replays exact ordered stdout bytes/directives.

The compatibility matrix verifies Cargo fingerprints, executable mtimes/identity, output-cache files, jobserver descriptors, `DEP_<LINKS>_*`, and stable/beta/nightly behavior. Failed/cancelled runs never publish a shared cache entry. For fine-grained interception, RABS either executes directly in the operation-owned Cargo destination or reproduces the exact observed failure post-state before returning; if that equivalence is not proven, the run executes locally. Shared staging is cleaned only after live-operation semantics are resolved, rather than universally discarding partial state that stock Cargo/build scripts might observe on retry.

## 92. Native subcompile interception

`CC`, `CXX`, and `AR` wrappers should be enabled early for dependency builds. CMake/meson launcher integration may be added where it preserves correctness. Native outputs become dependencies of the parent build-script action result.

## 93. Incremental-state snapshots

Incremental state is an evidence-gated dev-profile feature. Until this milestone is authoritative, shared action-cache serving runs admitted classes with incremental compilation disabled, or treats the complete incremental input/output state as private nonshareable execution state. An incremental directory is never an implicit unkeyed input.

Snapshot bundle:

- stable logical unit identity and canonical visible incremental path;
- hidden snapshot manifest ID;
- toolchain, target, profile, and projection identity;
- source/input recipe and compatible state point;
- incremental directory manifest;
- matching output artifacts;
- trust/provenance and determinism status.

Selection policy:

- exact state first;
- nearest compatible git/source ancestor;
- historical cost-benefit estimate;
- no transfer when state size exceeds predicted compile saving;
- no reuse across isolation/output-platform classes without proof.

Storage uses content-defined chunks, compression where useful, bounded per-repo lineage retention, and reachability/LRU GC. The visible path remains `/__rabs/incremental/<logical-unit-id>`; snapshot IDs exist only in hidden backing metadata.

Every restored incremental snapshot is materialized as a private writable clone/copy for one attempt; the retained snapshot and CAS chunks remain immutable and are never mounted writable by two rustc processes. Capture occurs only after the producing compiler process and its output writers are quiescent, and the incremental manifest plus matching ordinary outputs publish as one auxiliary snapshot unit. Cancellation or crash before that commit leaves only disposable staging. A sampled cold/exact rebuild verifies compatibility before a snapshot family gains portable authority.

## 94. Dependency projection and `.rmeta` equality experiment

Before enabling any reduced rlib projection or specialized metadata analytics:

- run a corpus experiment across internal repos and representative crates;
- canonicalize Cargo and child paths first;
- record the exact artifact each consuming invocation receives;
- compare conservative exact-artifact keys with candidate metadata projections;
- classify upstream edits as interface-changing or implementation-only;
- measure byte-identical `.rmeta` frequency and downstream hits;
- inspect span/hash/metadata sources of oversensitivity;
- shadow-execute every projected hit against the conservative path;
- define a proceed threshold and projection-epoch rollback.

Exact `.rmeta` inputs already provide free byte-equality cutoff when Cargo supplies `.rmeta`. No source-level semantic API parser is built by RABS.

## 95. Command palette, whole-command boundary, and nested-dispatch policy

The agent harness prescribes canonical commands and profiles:

- standard `cargo check` profile;
- standard `cargo nextest run` invocation;
- fixed features, target, deployment target, and CPU baseline;
- consistent clippy/lint flags;
- fixed debug/linker/toolchain configuration;
- explicit doctest policy;
- canonical Cargo-driver launcher.

This reduces key fragmentation.

Command eligibility is explicit:

| Command family | V1 policy |
|---|---|
| rustc/Cargo capability probes (`-vV`, `--print`, target-info/file-name queries) | direct local pass-through or a separately keyed tiny probe cache; do not pay remote-dispatch overhead by default |
| `build`, `check`, `clippy`, `doc`, compile phase of `test`/`bench` | canonical driver plus admitted action acceleration |
| `test`/nextest execution | admitted test-action or bounded whole-command policy |
| `run` | compile may accelerate; execution stays local/explicit and is not result-cached by default |
| `bench` execution | matching-hardware scheduled observation; timing result is never reused as a cached benchmark measurement |
| `clean`, `fix`, `install`, `publish`, `package`, source-mutating/package-manager commands | local or explicit side-effecting whole-command path; no ordinary result cache |
| watch/background/interactive/PTY-dependent commands | local passthrough unless a separately proven proxy profile exists |
| custom unstable Cargo modes (`build-std`, custom target runners, artifact dependencies, etc.) | compatibility-matrix admission or explained bypass |

Aliases are classified after Cargo/config expansion where feasible; wrapper interception alone never guesses that a mutating command is pure.

### Whole-command result-cache boundary

`CargoWholeCommandBounded` may be result-cached only when RABS captures all semantically relevant:

- immutable command snapshot;
- exact Cargo/toolchain/config/environment;
- requested final outputs;
- target/build-directory delta needed for subsequent Cargo freshness;
- build-script metadata/output-cache state;
- externally visible side effects, or proof that none exist.

Until that closure is proven, the whole-command plane is remote execution with hot worker state and ATP deltas, not a universal action cache. Commands such as install, publish, networked tests, or arbitrary side-effecting scripts are excluded.


Hot worker target state is never concurrently shared. The worker obtains an exclusive target-state lease or clones a retained target snapshot into a private command root. The full target/build delta, including removals and Cargo fingerprint/output-cache files, is captured before any whole-command result can be served elsewhere.

### Nested remote execution

For V1, a Cargo process running on `rabs-wkr` launches its child compiler/linker/build-script processes on the same worker under one worker-local jobserver and process tree. Child actions may query local/shared CAS and coordinator singleflight, but are not second-hop dispatched to other workers. Cross-worker nested dispatch requires a separate design review and benchmark.

# Part XIV. Agent-native acceleration

## 96. Cross-agent and cross-host singleflight

Cross-agent singleflight is the headline capability:

- all edge hosts submit final action keys to one active coordinator authority;
- the coordinator owns one authoritative actor per key;
- local and remote agents subscribe to one cache lookup/execution;
- edge-specific diagnostics and materialization use subscriber path/presentation contexts;
- subscriber cancellation is reference-counted;
- one coordinator commit serves all subscribers;
- verification and hedge attempts are explicit attempt purposes;
- coordinator restart advances the term and creates a new incarnation and reconciles actors before reissuing authority; automatic failover is not a V1 claim;
- per-subscriber latency and saved work are measured.

Without the edge/coordinator split, separate host-local daemons would only provide per-host singleflight and the fleet-wide claim would be false.

## 97. Save-time speculative compilation

A filesystem watcher observes agent edits and predicts likely next commands.

Pipeline:

1. detect stable-enough edit boundary using debounce and editor write semantics;
2. snapshot changed source state immutably;
3. infer likely action set from historical agent commands and provenance DAG;
4. select nearest compatible incremental snapshot;
5. submit low-priority speculative actions;
6. brown out under pressure;
7. promote instantly if the agent invokes the matching command;
8. measure saved foreground latency and wasted work.

The demo target is:

> The daemon compiles the agent’s diff while the agent is composing its next message, so the subsequent Cargo command is already a hit or joins an in-progress action.

## 98. Git-event prewarming

Events:

- branch checkout;
- HEAD change;
- pull/rebase/merge;
- worktree creation;
- lockfile update;
- toolchain file change;
- CI push.

Actions:

- fetch/materialize source snapshot;
- locate nearest state;
- prewarm dependency and workspace critical path;
- seed likely workers;
- pre-run canonical test subset under optional policy;
- stop immediately under foreground pressure.

## 99. CI canonical writer

CI can act as a higher-trust publication source for release-relevant keys:

- every pushed commit may prebuild canonical profiles;
- CI-signed provenance receives stronger trust classification;
- developer pulls can receive guaranteed-warm artifacts;
- local agent-produced results remain useful but may undergo more verification before release use;
- trust tier is a publication/access policy, not a content-identity difference.

## 100. Fragmentation analyzer

Fleet hit rate is reduced by avoidable key fragmentation. The analyzer should identify:

- multiple versions of hot dependencies;
- feature-unification drift;
- inconsistent lockfiles;
- toolchain drift;
- differing `RUSTFLAGS`/profiles;
- target CPU drift;
- path drift or noncanonical actions;
- command palette drift;
- build-script volatility;
- platform fragmentation;
- duplicated source snapshots that are semantically identical.

Output includes quantified cost and recommended convergence actions:

```text
12.4% of compiler-seconds lost because syn appears in 3 versions
8.1% lost because check/test feature sets diverge
6.7% lost because two workers use a different rustc commit
4.0% lost because one profile uses target-cpu=native
```

## 101. `rch advise`

`rch advise` uses provenance and timing data to recommend codebase changes:

- split crates dominating rebuild tails;
- reduce broad feature coupling;
- move stable APIs behind smaller interface crates;
- isolate proc macros and build scripts;
- align dependency versions;
- reduce generated-code churn;
- identify link bottlenecks;
- identify tests dominating repeated loops;
- suggest profile/linker/toolchain configurations.

Recommendations include evidence, expected saved latency, confidence, and non-claims.

## 102. `rch why`

Required queries:

```text
rch why action <key>
rch why crate <crate>
rch why miss <request-or-build-id>
rch why rebuild <artifact>
rch why worker <decision-id>
rch why volatile <action>
rch why slow <build-id>
```

A miss explanation is a structured diff between prior and current key breakdowns:

- source changed;
- dependency metadata changed;
- dependency implementation changed under LTO;
- flags/profile/features changed;
- environment changed;
- toolchain changed;
- platform changed;
- observed input set changed;
- sandbox policy changed;
- first seen/no prior entry;
- entry quarantined/expired/evicted;
- trust policy refused serving;
- output materialization unavailable.

## 103. Provenance DAG as scheduler and analysis substrate

The daemon reconstructs the action DAG without relying on unstable Cargo unit-graph APIs:

- actions reference dependency artifacts by content identity;
- artifacts reference producing actions;
- build observations establish invocation order and Cargo context;
- provisional metadata edges are explicit;
- test actions reference test binaries and data inputs.

Uses:

- critical-path scheduling;
- rebuild explanation;
- affected-test selection;
- cache bisection;
- nearest incremental ancestor;
- speculative action prediction;
- architectural advice;
- historical performance replay.

## 104. Rust-analyzer benefit

Rust-analyzer-triggered Cargo checks should flow through the same wrappers and action cache where compatible. Shared workspace authority requires rust-analyzer's Cargo invocation to enter the canonical Cargo driver through supported configuration/launcher integration; a noncanonical rust-analyzer parent receives only the admitted dependency/local lane. Metrics distinguish IDE-triggered versus explicit agent commands. Low-latency `.rmeta` and check-profile hits are likely among the most user-visible wins.

---

# Part XV. Test-result caching

## 105. Test action identity and eligibility

Conceptually:

```text
TestActionKey = H_domain(
    "rabs.test-action.vN",
    test_binary_digest,
    exact_test_identity,
    runner_identity,
    arguments,
    presented_environment,
    sandbox_semantic_policy,
    positive_and_negative_data_inputs,
    virtual_working_directory,
    output_platform_contract,
    declared_side_effect_outputs
)
```

A test is result-cache eligible only if:

- all data/process/network/time/randomness inputs are closed;
- it has no unrepresented externally visible side effects;
- fixture generation or shared-state initialization is not being skipped;
- its sandbox and runner semantics are reproducible;
- the project permits cached test results for that lane.

The test-binary digest conservatively invalidates every test in that binary. Finer code-to-test dependency projections are advisory research, not V1 correctness inputs.

The key also includes the nextest/runner profile, retry policy, timeout/slow-timeout policy, fail-fast behavior where observable, setup-script/batch identity, and any injected runner configuration. A test that passes only after a retry is classified flaky/unstable and is not published as an authoritative stable pass merely because its final attempt passed.


Process-per-test isolation does not prove semantic independence. A test that depends on suite ordering, a once-per-suite initializer, a shared database/port/temp root, global external state, or setup/teardown side effects is either executed as a `TestBinaryBatch`/suite action whose key includes that state or is not result-cache eligible. Cached per-test passes must not skip required suite initialization.

## 106. Nextest integration

Preferred initial experiment:

- nextest enumerates tests and launches only policy-independent cases through a validated target-runner/wrapper seam; suite-coupled tests remain in a batch or bypass lane;
- nextest setup scripts, archive/setup state, and once-per-run fixtures execute according to the original profile; they are represented as a batch prerequisite/side effect and are never skipped by independent per-test hits;
- the adapter submits each test or policy-selected batch as an action;
- unchanged eligible passing tests may hit by digest;
- stdout/stderr, exit status, duration, retry/flaky metadata, declared outputs, and input closure are captured;
- V1 serves stable passing results first; deterministic failure serving is a later opt-in with a short TTL after presentation and retry semantics are proven;
- flaky or side-effecting tests are denied;
- per-test resource history improves scheduling.

This integration is shadow-first because target-runner behavior, working directory, process environment, signals, retries, and output ordering must match nextest across supported versions. If the adapter cannot preserve semantics, test execution remains uncached while compile actions still benefit.

## 107. Test data inputs and side effects

Sandbox observation/enforcement captures:

- fixtures, snapshots, and golden files;
- successful and failed opens and directory listings;
- environment and config files;
- dynamically loaded libraries;
- subprocesses and executable selection;
- network/clock/randomness access;
- declared output/state directories.

Networked, timing-sensitive, random, database-mutating, or external-service tests are volatile unless the service/state is a deterministic captured input/output. Cached passes never suppress a required migration, fixture generation, or setup side effect.

## 108. Affected-test selection

The provenance DAG can suggest tests affected by changed source/artifacts and historical data inputs. Selection is advisory and independent from result-cache correctness. CI periodically runs a fresh complete canonical suite, and selected high-risk/release lanes always do so, to detect missing edges and cache masking.

## 109. Doctests

Policy:

- agent inner loop defaults to nextest or a profile that excludes doctests where appropriate;
- doctest compilation and execution remain separate cacheable action classes;
- CI runs canonical doctest coverage;
- doctest generated crate/source identity is canonicalized and explainable.

## 110. Flaky and nondeterministic tests

RABS maintains a test evidence record:

- `ObservedStablePass`;
- `ObservedStableFailure`;
- `FlakyOutcome`;
- `TimingSensitive`;
- `NetworkSensitive`;
- `EnvironmentSensitive`;
- `SideEffecting`;
- `Quarantined`.

A cached passing result is an execution-reuse fact, not proof that the program is correct. Flaky, volatile, side-effecting, or insufficiently isolated results are never served as authoritative passes. Release CI periodically bypasses test-result caching by policy.

# Part XVI. Security, trust, and privacy

## 111. Threat model

Potentially untrusted or fallible parties include:

- agent-generated source and build scripts;
- proc macros and native build tools;
- compromised or misconfigured workers;
- corrupted disks or object stores;
- stale/replayed network messages;
- malicious cache entries;
- accidental secret exposure;
- buggy wrapper/key logic;
- operator configuration drift.

## 112. Durable identity

Each coordinator and worker has a durable cryptographic identity with:

- public-key-derived peer ID;
- key fingerprint;
- generation;
- rotation history;
- revocation state;
- transport/session binding;
- trust scope.

A worker identity used for ATP authorization must be bound to the authenticated transport identity. Configuration labels are aliases, not proof.

## 113. Evidence-based serving tiers

Trust labels describe observed evidence and policy approval rather than asserting semantic correctness:

```text
UnverifiedCandidate
ShadowMatched
ReproducibleSameWorker
ReproducibleCrossWorker
CIPolicyApproved
ProjectReleaseEligible
Quarantined
```

- `ShadowMatched` means a candidate matched an authoritative stock execution under the recorded profile.
- `Reproducible*` means repeated executions matched under the named worker scope.
- `CIPolicyApproved` means an authorized CI lane produced/verified the entry.
- `ProjectReleaseEligible` is a project policy decision; RABS does not claim compilation equivalence proves application correctness.

Serving policy combines evidence tier, isolation profile, output platform, action class, secret/privacy scope, and project lane. Tiers do not alter content digests.

Each `ActionSubscriptionContext` declares a minimum evidence tier and any stricter isolation/privacy requirements. A committed result may exist yet remain ineligible for that subscriber. The coordinator can launch or join a verification attempt, append its evidence, and emit a new immutable `ActionTrustEvaluationRecord`; subscribers are re-evaluated against the latest nonrevoked policy result. Worker compromise, policy change, or discovered divergence can demote/quarantine serving without rewriting `ActionPublicationRecord` or the canonical manifest.

## 114. Provenance receipt

Every committed publication has an associated immutable provenance/evidence receipt containing:

- action key plus key/projection epochs;
- complete descriptor digest;
- producing command snapshot root plus the minimal action-input closure;
- toolchain and platform contracts;
- sandbox policy;
- authenticated worker identity/generation;
- build-operation/action-generation/attempt/execution-lease identity;
- process termination record;
- observed-input closure result;
- output manifest;
- verification level;
- publication timestamp/causal order;
- optional signature or MAC according to trust model;
- redacted capability use;
- non-claims.

The producing result receipt names its producing command snapshot. Each serve/materialization receipt separately names the consuming command snapshot whose minimal closure matched the action key. This preserves reproducibility without pretending one action result belongs to only one full workspace state.

## 115. Kernel sandboxing

Application capabilities do not constrain arbitrary child syscalls. Worker execution must enforce policy using OS isolation:

- read-only immutable inputs;
- writable output/temp only;
- no network by default;
- cgroup resource bounds;
- process-group/session control plus cgroup/PID-namespace or VM descendant containment for profiles that claim no-orphans enforcement;
- controlled devices and pseudo-filesystems;
- syscall restrictions where practical;
- output-path enforcement;
- secret mounts with minimal scope and cleanup.

## 116. Secret handling

Secrets:

- are exposed only through stable logical capability slots, never action/attempt-bearing paths;
- never appear in plaintext key breakdowns, logs, events, or failure bundles;
- do not become sound key inputs merely through a capability ID;
- when output-affecting and cacheable by policy, contribute a trusted opaque HMAC/value-version/scope digest generated outside the untrusted action;
- otherwise make the action noncacheable or nonshareable;
- place outputs in an access-controlled namespace and optionally encrypt them at rest;
- are redacted from child diagnostics where reliably detectable;
- are cleaned during finalization.

The initial deployment is one administrative trust domain, not a hostile multi-tenant service. Secret scoping still applies within that domain.

Source-transfer authorization is enforced before object upload. A project can be trusted for execution while still marking selected source paths local-only or secret-scoped. Cache inventory queries and object-location hints are access-controlled so they do not reveal the existence of restricted objects across namespaces.


### 116.1 Signing, notarization, and credentialed post-processing

Code signing, Apple notarization, package publication, timestamp-authority calls, and similar credentialed external effects are separate actions from deterministic compilation/linking. Unsigned or ad-hoc intermediate binaries may be cached when policy permits; credentialed signatures are keyed/scoped to the exact signing identity and captured response where reproducible, or remain noncacheable side-effecting release steps. Private signing keys never enter ordinary compiler workers or shared cache namespaces.

## 117. Cache poisoning prevention

- agents cannot write shared CAS/action entries directly;
- workers upload immutable objects but cannot unilaterally commit action-cache pointers;
- coordinator verifies object closure and fencing;
- abnormal terminations are not cached;
- schema/toolchain/platform mismatches fail closed;
- sampled stock-build and cross-worker verification run continuously;
- corruption or divergence invokes the narrowest valid location/logical-object/action-entry quarantine, with dependent entries blocked only when their required logical closure is unavailable;
- project release policy may require `CIPolicyApproved` or stronger reproducibility evidence.

- a cryptographically authenticated worker is still a semantic trust principal: digests prove transport/storage integrity, not that a compromised worker executed rustc honestly;
- higher-trust/release serving can require two independent workers, stock differential execution, or CI-policy approval, and worker divergence immediately removes that worker from authoritative publication eligibility.

## 118. Resource-exhaustion defenses

Per-peer and per-action limits:

- concurrent sessions;
- frames per second;
- frame and extension sizes;
- queued control/data bytes;
- in-flight object requests;
- object/manifest depth and fan-out;
- sparse ranges;
- diagnostics volume;
- output count and total bytes;
- process count;
- memory/temp/disk quotas;
- retries and restarts.

Control/cancellation capacity is reserved independently of bulk data.

## 119. Privacy

Default logs and receipts should avoid:

- raw source contents;
- secrets;
- local home/worktree paths;
- full command lines containing credentials;
- unbounded compiler output;
- unnecessary worker network details.

Store hashes, virtual paths, redacted labels, and bounded excerpts. Full failure bundles require explicit retention and access policy.

---

# Part XVII. Observability, evidence, and explainability

## 120. Decision receipt

Every scheduling/execution request produces a durable receipt containing:

```text
request identity
normalized invocation class
key breakdown digest
execution snapshot root and action-input closure
cache lookup decision
singleflight decision
subscriber state
worker candidate rows
selected worker and reasons
transfer plan
budget and priority
attempt authority identity
action lifecycle events
provisional artifact events
output verification
publication decision
latency/resource metrics
fallback/refusal reasons
```

## 121. Event taxonomy

Events should be stable, typed, and causally linked:

```text
BuildIntentObserved
ActionKeyComputed
CacheLookupStarted
CacheHitValidated
CacheMiss
SubscriberJoined
WorkerCandidatesEvaluated
AttemptLeased
InputTransferStarted
SandboxReady
ProcessSpawned
MetadataReady
DiagnosticEmitted
ProcessExited
OutputVerified
PreparedResultOffered
ActionResultCommitted
SubscriberCompleted
CancellationRequested
DrainProgress
OperationReconciled
ObjectQuarantined
```

## 122. Metrics

### User-visible

- intent-to-first-diagnostic;
- intent-to-metadata-ready;
- intent-to-Cargo-completion;
- intent-to-test-result;
- p50/p90/p95 by command/workload;
- save-to-green for IDE/agent workflows.

### Cache

- lookup hit rate;
- served-versus-executed ratio;
- compiler-seconds saved;
- hit rate by action class;
- miss-cause taxonomy;
- deterministic-failure publication hits;
- quarantines/divergence;
- materialization time;
- storage and dedup ratio.

### Scheduler

- queue delay;
- worker selection accuracy;
- predicted versus actual completion;
- jobserver utilization;
- PSI/cgroup pressure;
- starvation/fairness;
- speculation promoted/cancelled/wasted/saved;
- hedging value.

### Transfer

- bytes offered/transferred/deduped;
- time to first useful object;
- resume value;
- throughput/RTT/loss/path migration;
- CPU per GiB;
- retransmission/repair cost;
- object source locality.

### Reliability

- cancellations and drain latency;
- orphan prevention;
- slot/token leaks;
- worker session restarts;
- reconciliation outcomes;
- corruption incidents;
- action divergence;
- nondeterminism denylist size.

## 123. Trace and replay

Every production incident should be convertible into:

- normalized action descriptor;
- event trace;
- network/worker conditions;
- scheduler receipts;
- object manifest references;
- cancellation/lease timeline;
- lab scenario seed where possible;
- minimized replay case.

## 124. Dashboards

Required dashboards:

- fleet posture and worker pressure;
- user-visible latency distributions;
- cache effectiveness and miss causes;
- top expensive/repeated crates/actions;
- action critical paths;
- transfer and CAS health;
- storage/GC/quarantine;
- speculation ROI;
- determinism/verification status;
- key fragmentation and recommended convergence.


---

# Part XVIII. Failure semantics and recovery

## 125. Failure taxonomy

### Deterministic action failures

Examples:

- compiler error;
- linker error caused by inputs/flags;
- deterministic build-script nonzero exit;
- deterministic test assertion failure.

Policy: may be reported and optionally short-term cached if all deterministic-failure conditions pass.

### Volatile action failures

Examples:

- time/network/git-state dependent failure;
- unclosed input;
- flaky test;
- path-sensitive output failure.

Policy: report, do not share-cache as deterministic.

### Infrastructure failures

Examples:

- transport disconnect;
- worker daemon restart;
- disk I/O failure;
- missing/corrupt object;
- sandbox setup failure;
- worker resource exhaustion;
- coordinator internal error.

Policy: retry/fallback according to attempt budget and fencing; never publish or serve as a deterministic failure.

### Cancellation and deadline

Examples:

- subscriber cancellation;
- parent build cancellation;
- queue eviction;
- timeout;
- daemon shutdown;
- speculative brownout.

Policy: explicit cancelled outcome, drain, and no deterministic-failure publication.

### Abnormal process termination

Examples:

- OOM kill;
- SIGKILL/SIGTERM not initiated as normal deterministic tool exit;
- crash signal;
- lost process group.

Policy: infrastructure/abnormal classification, no deterministic-failure publication, and retain the failure bundle.

### Internal panic/invariant failure

Policy:

- quarantine current attempt and any uncommitted outputs;
- produce crashpack;
- escalate supervision as configured;
- fail open locally where safe;
- never continue publication from an uncertain state.

## 126. Edge and coordinator crash recovery

### Edge recovery

An edge durably records only what is needed to reconnect live wrappers/materializations and to reconstruct transcript and stateful delivery frontiers. On restart it:

1. reconnects to the current `CoordinatorAuthority`;
2. reconciles subscriber/operation sequence domains and in-flight transcript/stateful intents;
3. resumes materialization when safe;
4. treats unacknowledged transcript delivery as possibly exposed and uses reconnect/coherent failure or explicit labeled recovery;
5. fails live wrappers coherently after stateful commit intent/commit if state cannot be recovered;
6. permits seamless nonpublishing local fallback only before transcript exposure/uncertainty and before stateful commit intent.

### Coordinator recovery

V1 has one active coordinator. Durable state required before acknowledging authority-bearing transitions includes:

- current/acquired `CoordinatorAuthority` and exclusive local authority-lock evidence;
- build-operation/action identity;
- edge subscriber and per-subscriber observable-commit/delivery state where needed;
- current action generation, attempts, and independent execution leases;
- worker assignment;
- prepared candidate state;
- object pins and root permits;
- publication transaction state;
- reconciliation deadline.

On restart of the configured authority host, or during an explicitly operator-fenced disaster-recovery promotion:

1. acquire the exclusive authority lock, advance the durable term, generate a fresh incarnation ID, and fence the old credential/incarnation before issuing leases;
2. open and verify the metadata database;
3. reconcile filesystem staging, journals, and quarantine;
4. mark sessions disconnected;
5. enumerate nonterminal operations;
6. contact edges/workers and compare last event sequences;
7. close or supersede every nonterminal action generation created under the prior coordinator-authority digest before issuing new publication-eligible leases; old attempts and prepared candidates may contribute verified immutable blobs/evidence but cannot publish under the new term; V1 reruns or explicitly reissues work in a fresh generation rather than silently adopting prior-authority execution;
8. decide resume/cancel/collect/fail for build operations and subscriber delivery using pure state logic;
9. release orphan pins, root permits, and tokens after proof;
10. reject stale-authority publication offers.

The coordinator database is local. Active-active consensus, automatic cross-host failover, and a network-shared SQLite file are not part of V1. If automatic failover is later required, it must use a real consensus/external-fencing design rather than treating a counter in two local databases as authority.

Recovery authority is operationally fenced: before a replacement coordinator can acquire a higher term, the operator must revoke or isolate the prior coordinator through the configured service/host/identity control plane. Peers retain authority high-water marks, and a monotonically increasing number in one restored database alone does not prevent split brain.

## 127. Worker crash recovery

Worker startup:

1. increment durable boot generation, create a fresh process-incarnation ID, and complete coordinator activation/fencing before resuming or accepting authority-bearing work;
2. inspect attempt journals and staging roots;
3. detect live orphan processes and terminate/reap under policy;
4. verify staged objects/manifests;
5. reconstruct resumable transfer state;
6. report operation inventory during session reconciliation;
7. never assume old publication authority survives restart;
8. clean abandoned sandboxes after coordinator decision or lease expiry.

## 128. Network partition

During partition:

- leases continue only until deadline;
- a worker may continue execution if policy permits but cannot renew authority without the coordinator;
- critical control retains reserved local queue capacity;
- objects may be staged locally;
- after lease expiry, a result may be offered later as an immutable candidate but cannot commit without current authority;
- coordinator may hedge/reassign;
- an edge before transcript exposure/uncertainty and before stateful commit intent may fail open locally as a nonpublishing attempt;
- an edge after transcript exposure uses reconnect/coherent failure or explicit labeled recovery, and after stateful commit intent reconnects or fails coherently;
- reconnect reconciliation resolves duplicate attempts, subscriber state, provisional outputs, and event sequences.

## 129. Disk pressure and disk full

Admission must refuse or defer actions before unsafe thresholds. On unexpected disk full:

- fail current write explicitly;
- preserve existing committed CAS objects;
- quarantine incomplete staging;
- release process/slot resources;
- trigger safe reclaim with active-build protection;
- update worker eligibility and refusal receipts;
- do not misclassify as deterministic compile failure.

## 130. Corrupt object recovery

- a digest mismatch quarantines the **location** first;
- another verified location is fetched and compared;
- a valid alternate copy keeps the logical object and action entry usable;
- all-copy/manifest inconsistency escalates to logical-object quarantine;
- semantic output divergence escalates to action-entry quarantine;
- if no valid copy exists, dependent action entries become unavailable and rebuild;
- adjacent objects are scrubbed when device/path failure is suspected;
- every escalation produces an incident receipt.

## 131. Edge/coordinator unavailable and fail-open

Wrapper policy:

- tiny edge connection timeout and circuit breaker;
- if the edge is unavailable, run the original wrapper/tool chain immediately;
- if the coordinator is unavailable before transcript exposure/uncertainty and before stateful commit intent, edge may run a nonpublishing local fallback;
- after transcript exposure, use reconnect/coherent failure or explicit labeled recovery; if a cached/remote deterministic failure, output commit intent, or `.rmeta` has been exposed, do not silently start an independent local producer;
- `RCH_REQUIRE_REMOTE=1` may refuse instead of fallback;
- stale remote attempts are fenced by coordinator/execution lease;
- a later daemon recovery does not retroactively publish an uncoordinated local fallback unless an explicit verification/reconciliation path adopts it safely;
- fallback reason and frontier state are recorded when possible without delaying the command.

## 132. Rolling upgrades

Requirements:

- N/N−1 local and RABS/ATP protocol compatibility;
- key/projection epoch separation;
- coordinator authority fencing during restart and explicitly operator-fenced disaster recovery;
- worker drain before incompatible replacement;
- session capability negotiation;
- no reinterpretation of durable manifests;
- operation reconciliation across versions or explicit safe cancellation;
- edge handling of live wrappers across coordinator upgrades;
- database backend/migration backups and differential checks;
- rollback path and canary workers/edges;
- state-changing 0-RTT remains disabled.

# Part XIX. Compatibility, upstream absorption, and deliberate reuse

## 133. REAPI compatibility mapping

| REAPI | RABS native |
|---|---|
| Digest | `DigestSet` / ATP `ContentId` |
| Directory tree | ATP `SnapshotObject` |
| Command | `ActionDescriptor` |
| Action | `ActionKey` plus policy/platform/toolchain contracts |
| ActionResult | canonical result/artifact bundle plus separately mapped provenance/evidence metadata |
| ByteStream | ATP resumable object stream |
| Execution Operation | supervised `ActionActor` event stream |
| Platform properties | `OutputPlatformContract` plus scheduler-only `ExecutionEligibility` |
| FindMissingBlobs | `FindMissingObjects` |

The mapping should remain documented and tested so an external gateway is straightforward.

## 134. SSH role

SSH remains for:

- initial worker bootstrap;
- deployment before ATP trust is established;
- key/certificate repair;
- diagnostics when native control is unavailable;
- break-glass command execution;
- staged migration fallback.

It should leave the hot authoritative action path after ATP proves superior reliability and performance.

## 135. Existing RCH HTTP/telemetry surfaces

Existing Axum/Hyper/OpenTelemetry services may remain initially. They should be:

- compatibility-isolated;
- supervised independently;
- denied publication authority;
- benchmarked for overhead;
- replaced only when a native implementation improves value rather than merely satisfying stack purity.

## 136. Cargo upstream absorption points

Design RABS to absorb:

- Cargo checksum freshness;
- future user-wide cache/plugin interfaces;
- build-directory isolation improvements;
- rustc `public_api_hash`/RDR when usable;
- stable parallel front-end controls;
- tracked proc-macro path/env APIs;
- Wild incremental linking;
- improved Cargo artifact notifications.

Each upstream improvement should replace a local approximation or enter a key component without invalidating the overall fabric.

## 137. Tool choices

### Adopt/configure

- nightly `-Zthreads` profiles where controlled and validated;
- Cranelift as optional dev/test codegen, not critical path;
- line-table-only debug and unpacked split-debuginfo profiles where useful;
- cargo-hakari or equivalent feature-unification stabilization;
- Wild/lld fast linker selection;
- sccache as interim baseline and competitor during early measurement.

### Measure/gate

- native-CPU rustc/LLVM builds;
- custom PGO/BOLT profile;
- io_uring;
- automatic adaptive controllers;
- time-travel incremental snapshots;
- rmeta analytics.

### Cut

- bespoke incremental linker;
- GPU compiler acceleration;
- custom ThinLTO/GPU backend as part of RABS;
- protocol/CAS reinvention that duplicates ATP/RABS-native work without semantic value.


### 137.1 Licensing, package metadata, and distribution

At the reviewed revisions, both RCH and Asupersync use the same rider-bearing "MIT License (with OpenAI/Anthropic Rider)" text, while RCH's workspace package metadata still advertises plain `MIT`. That mismatch must be corrected before RABS releases or SBOMs are treated as authoritative.

Required policy:

- choose one deliberate RABS repository/license placement and preserve the actual rider text in every distributed derivative where required;
- change Cargo package metadata from misleading plain `MIT` to the correct `LicenseRef-MIT-OpenAI-Anthropic-Rider`/`license-file` representation;
- keep SPDX/SBOM, crate metadata, installer notices, source archives, binary distributions, and website claims consistent;
- run dependency-license compatibility and attribution checks for every release profile;
- do not describe the project as ordinary OSI MIT in marketing or registry metadata;
- treat any future relicensing, dual licensing, or exception as an explicit owner decision and versioned release event, never an agent inference;
- ensure the optional REAPI gateway and compatibility islands do not accidentally impose incompatible redistribution requirements on the native binaries.

---

# Part XX. Performance and measurement program

## 138. Layer 0 configuration pack

Before the distributed core, ship a versioned project configuration pack:

- toolchain profile with `-Zthreads` where supported;
- optional Cranelift dev profile;
- Wild/lld linker configuration;
- debuginfo reductions;
- per-package optimization guidance;
- cargo-hakari/workspace-hack setup;
- canonical command palette;
- sccache interim baseline;
- explicit target CPU baseline;
- profile and feature convergence checks.

This produces immediate value and establishes a realistic baseline.

## 139. Record/replay corpus

M0 deliverable:

- capture every relevant tool invocation with normalized args and input hashes, not source contents by default;
- record command/build/session context;
- retain outcomes, diagnostics digests, output manifests, timing, resource usage, and worker/local execution;
- support replay under stock and RABS paths;
- anonymize/redact as required;
- stratify by repo, action class, agent count, clean/warm state, and command type.

The corpus is simultaneously:

- benchmark input;
- shadow-verification input;
- regression suite;
- key-stability study;
- scheduler training/evaluation data;
- launch evidence.

## 140. Benchmark suite

Required scenarios:

```text
cold clean build
no-op rebuild
single leaf edit
single high-fanout dependency edit
root/application edit
implementation-only upstream edit
public-interface upstream edit
check → test → clippy command alternation
branch ping-pong A ↔ B repeated
new worktree first command
fifteen-agent compile storm
mixed compile/test storm
worker loss during compile
network partition during output upload
cache corruption/refetch
CI commit prewarm then developer pull
rust-analyzer check loop
```

## 141. Reported metrics

For every benchmark:

- whole-command p50/p90/p95 wall time;
- first diagnostic and first metadata-ready latency;
- compiler/linker/test seconds executed versus saved;
- served-versus-executed ratio;
- cache hit rate and miss taxonomy;
- queue delay;
- transfer bytes, dedup ratio, and throughput;
- local/remote CPU and memory;
- storage growth;
- speculation cost/value;
- correctness/divergence result.

## 142. Comparative baselines

Compare against:

- stock Cargo/rustc;
- optimized Layer 0 configuration only;
- sccache local and LAN;
- existing RCH whole-command remote execution;
- RABS whole-command plane;
- RABS fine-grained plane;
- optional REAPI/NativeLink experiment if maintained as an external benchmark.

## 143. Performance gates

A feature may not enter default-on behavior if it:

- violates wrapper/miss overhead SLOs;
- worsens p95 intent-to-result without compensating benefits;
- increases storage or transfer cost beyond documented value;
- produces unexplainable hit-rate degradation;
- reduces cancellation responsiveness or cleanup reliability;
- lacks a rollback switch and evidence receipt.

---

# Part XXI. Verification and proof program

## 144. Trust ladder

### Stage 0: observation only

- wrappers record invocations;
- no cache serving;
- no remote authoritative execution.

### Stage 1: shadow keys and lookups

- compute keys and candidate hits;
- always execute stock path;
- compare expected versus actual availability and result metadata.

### Stage 2: shadow result comparison

- execute candidate cached/remote path privately;
- execute stock path authoritatively;
- byte/semantic compare outputs and diagnostics;
- collect divergence corpus.

### Stage 3: sampled serving

- serve only low-risk registry dependency actions;
- retain high verification sample rate;
- immediate quarantine on divergence.

### Stage 4: broad dependency serving

- add native subcompiles and eligible build scripts;
- cross-worker verification sampling.

### Stage 5: workspace authoritative serving

- only after canonical execroot, observed-input closure, and long shadow evidence.

### Stage 6: tests, incremental state, and speculation

- each capability independently gated.

## 145. Test classes

### Unit

- codecs;
- key normalization;
- state transitions;
- candidate scoring;
- path mapping;
- manifest and digest logic;
- failure classification.

### Property

- encode/decode round trips;
- canonical serialization;
- key stability under irrelevant path/agent changes;
- key sensitivity to every semantic input;
- idempotency;
- monotonic fencing;
- manifest closure and reachability;
- GC never deletes pinned/reachable objects.

### Metamorphic

- equivalent worktrees produce identical keys/results;
- different transport chunking yields identical objects;
- resume versus uninterrupted transfer yields identical result;
- local versus remote execution yields equivalent outputs;
- cache hit versus execution yields identical Cargo-observable stream;
- different worker schedules yield the same committed result.

### Differential

- stock rustc/Cargo versus RABS;
- encoder/decoder implementations;
- native ATP versus fallback transport;
- worker platforms within a compatibility class.

### Lab/deterministic

- cancellation at every await point;
- network delay/loss/reorder/partition;
- worker/coordinator restart;
- lease expiry;
- duplicate/replayed messages;
- hedged result races;
- provisional metadata invalidation;
- stale health evidence;
- pressure brownout.

### Fuzz

- ATP/RABS frames;
- manifests and recursive object graphs;
- key canonicalization inputs;
- path normalization and diagnostic rewriting;
- reconciliation message sequences;
- corrupted journals and sparse ranges;
- CLI/local wrapper protocol.

### Chaos/real-host

- kill daemon mid-publish;
- kill worker mid-compile;
- fill disk;
- corrupt blob;
- restart network interface;
- suspend/resume hosts;
- induce memory PSI/OOM;
- lose Tailscale path;
- rotate identities during drain;
- upgrade coordinator/worker versions independently.

### Soak

- multi-day persistent sessions;
- repeated reconnects;
- high object count;
- millions of action actor lifecycles;
- sustained multi-agent storm;
- long idle followed by burst;
- GC during active work.

## 146. Core deterministic scenarios

Minimum named scenarios:

```text
singleflight_many_subscribers
cancel_one_subscriber_shared_action_survives
cancel_last_subscriber_drains_everything
worker_dies_before_ack
worker_dies_after_metadata_ready
coordinator_dies_after_prepare_before_commit
stale_attempt_result_rejected
hedged_candidate_commit_and_late_divergence_quarantine
bulk_transfer_never_starves_cancel
corrupt_blob_quarantined_and_refetched
disk_full_never_exposes_partial_result
partition_resume_journal_no_duplicate_commit
speculation_browns_out_before_foreground
stale_worker_snapshot_fails_closed
cache_hit_stream_matches_stock_pipelining
virtual_execroot_cross_worktree_equivalence
proc_macro_untracked_input_invalidates_key
build_script_stdout_metadata_replays_exactly
```

## 147. Correctness gates

Before authoritative workspace serving:

- approximately `10^5–10^6` representative shadow actions with zero unexplained divergence;
- stable key equivalence across worktrees/machines in supported platform classes;
- complete observed-input coverage for target action classes;
- no orphan process/slot/pin incidents in stress corpus;
- successful crash and reconciliation matrix;
- protocol canonical fixtures and N/N−1 compatibility;
- storage corruption/refetch proof;
- p95 overhead SLO compliance.


---

# Part XXII. Implementation roadmap with gates

## 148. Program structure

Run the program as coordinated workstreams:

```text
W0  Measurement and replay
W1  Stable protocol/domain schemas
W2  Asupersync runtime/process integration
W3  Canonical execroot and sandbox
W4  Action keys and observed inputs
W5  Durable CAS and publication
W6  ATP control/data transport
W7  Scheduler and jobserver
W8  Cargo/rustc/link/build integration
W9  Test actions
W10 Agent-native speculation and analysis
W11 Security, operations, rollout, and documentation
```

Milestones below describe the critical dependency order. Parallel work is allowed only where interfaces are already fixed.

## 149. M−1: Layer 0 configuration pack

### Deliverables

- versioned recommended Cargo/rustc profiles;
- `-Zthreads` capability detection and opt-in configuration on supported nightly toolchains;
- Wild/lld selection;
- debuginfo and split-debuginfo tuning;
- optional Cranelift dev profile;
- cargo-hakari/workspace-hack guidance and automation;
- explicit target CPU, Apple deployment target, and SDK baselines;
- canonical agent command palette;
- sccache baseline setup;
- benchmark scripts for representative repos.

### Acceptance

- no semantic behavior regression in the intended lane;
- exact toolchain capability detection rather than unconditional unstable flags;
- measured baseline stored in replay/benchmark format;
- every knob can be enabled/disabled cleanly.

### Kill/rollback

Each knob remains optional and is removed from defaults if it regresses representative p95, output equivalence, debugger behavior, or compatibility.

## 150. M0: Record/replay, edge daemon, and shadow skeleton

### Deliverables

- stable `rabs-protocol` local request/event schemas;
- tiny wrappers with full nested-wrapper-chain handling;
- `rabs-edge` skeleton, initially in the existing daemon binary if convenient;
- immediate original-chain fail-open plus separate transcript/stateful delivery-frontier tracking;
- invocation recorder with redaction;
- normalized action-family records and coherent command-snapshot IDs;
- stock execution passthrough;
- SLO instrumentation;
- replay harness;
- stable/beta/nightly wrapper-contract CI matrix;
- initial `rch why` showing raw key-component candidates before serving.

### Acceptance

- wrapper p95 `< 10 ms` before tool execution;
- no behavioral difference from stock passthrough;
- nested `RUSTC_WRAPPER`/`RUSTC_WORKSPACE_WRAPPER` fixtures pass;
- corpus covers target repos and multi-agent sessions;
- edge death falls back immediately without repeated tax;
- no action is published.

### Gate

No authoritative cache serving until replay, shadow comparison, and observable-commit accounting exist.

## 151. M1: Canonical Cargo driver, execroot, and path-equivalence proof

### Deliverables

- Linux canonical Cargo-driver mount namespace;
- nested per-action closed input view prototype;
- fixed visible workspace/path-dependency/toolchain/registry/Cargo-home/output/`OUT_DIR`/incremental/temp/home/secret-slot paths;
- hidden attempt-specific physical backing roots;
- mutation-safe coherent source snapshot capture;
- virtual-to-real diagnostic and materialization translation;
- path-remap flags;
- path and Cargo-unit-identity leak scanner;
- mtime choreography tests;
- checksum-freshness opt-in experiment;
- cross-worktree and cross-worker equivalence harness;
- explicit macOS VM/chroot/host-audit authority matrix.

### Acceptance

- canonical Cargo child argv, `-C metadata`, output filenames, descriptors, and admitted outputs converge across worktrees;
- no action/attempt/snapshot IDs leak into visible paths;
- diagnostics map back correctly;
- no rebuild storms after hit-like materialization;
- Linux strict profile meets the declared isolation boundary;
- macOS unsupported properties produce reduced authority rather than a false pass.

### Gate

Workspace-member shared caching cannot become authoritative before canonical Cargo planning and the platform-specific isolation gate pass.

## 152. M2: Asupersync runtime island and process ownership

### Deliverables

- pinned Asupersync revision and minimal `rabs-profile`;
- `rabs-asupersync` adapter crate;
- explicit edge, coordinator, and worker region trees, deployable initially in combined mode;
- managed process groups for current whole-command remote actions;
- subscriber-aware cancellation skeleton;
- Cargo root-permit obligation type;
- supervision tree;
- action/attempt crashpacks;
- deterministic lab scenarios for cancellation, cleanup, and observable-commit fallback;
- compatibility-isolated existing transport.

### Acceptance

- behavior parity with current RCH whole-command execution;
- no orphan process, root-permit, or double-slot release under chaos tests;
- cancellation and daemon shutdown are bounded on covered paths;
- existing SSH/rsync path remains available.

### Gate

Asupersync lifecycle becomes authoritative before ATP transport does.

## 153. M3: Durable object store, metadata abstraction, and atomic publication core

### Deliverables

- `rabs-cas` filesystem backend with streaming atomic `put_if_absent`;
- ATP object/manifest adapters;
- deterministic tiny-object packs and chunk manifests;
- metadata-store interface;
- reference SQLite-compatible backend;
- FrankenSQLite backend and differential/fault-injection conformance harness;
- staging, journals, pins, leases, quarantine scopes, delayed tombstones;
- coordinator authority/high-water/incarnation-fence tables plus action generation/tombstone, immutable publication, mutable serving, evidence/trust, and coordinator-only publication transaction schemas;
- atomic publication reachability pins, authority-scoped pin leases, revisioned serving validity, reachability GC skeleton, and scrubber;
- corruption/refetch tests;
- object CLI/doctor surfaces.

### Acceptance

- crash during any publication phase never exposes a partial action result;
- a worker cannot commit an action pointer; deterministic failures use the same typed immutable publication path as successes;
- action-generation, serving-state, publication-pin, and authority/incarnation-fence crash/replay invariants pass before the metadata core is trusted;
- one bad object location can be refetched without unnecessarily invalidating a valid logical object;
- startup reconciliation repairs or reports staging/database drift;
- active pins/open readers survive GC;
- FrankenSQLite is not selected as authoritative until it matches the reference backend under the complete suite;
- storage, packing, and dedup metrics are available.

## 154. M4: Registry/git dependency action cache

### Deliverables

- immutable dependency action-family and exact action key;
- checksummed registry/git source manifests;
- exact presented-environment and toolchain/output-platform contracts;
- conservative exact dependency-artifact inputs;
- local CAS lookup and materialization;
- canonical compiler event capture/replay;
- `.rmeta`-first materialization only when `.rmeta` is a declared output;
- exact diagnostics/presentation variant handling;
- deterministic failure classification;
- shadow mode and sampled serving;
- `rch why miss` for dependency actions.

### Acceptance

- zero divergence in a large shadow corpus;
- near-perfect hits for repeated immutable dependencies under the same semantic contract;
- cache-miss overhead `< 1–2%` for admitted non-tiny dependency actions, while tiny probes/pass-throughs meet their absolute-latency cap;
- rustc artifact-notification replay preserves Cargo pipelining;
- first-enable cold rebuild behavior is documented;
- no reduced rlib projection is enabled implicitly.

### Rollout

- observation;
- shadow;
- opt-in sampled serving;
- default-on for selected immutable dependency classes;
- broad dependency serving after cross-worker evidence.

## 155. M5: Native dependency subcompiles and exact link cache

### Deliverables

- `CC/CXX/AR` wrappers;
- header/input closure;
- native toolchain/platform keys;
- build-script parent-child provenance;
- exact link action key and artifact bundle;
- pluggable Wild/lld/system linker profile;
- native and link miss explanations.

### Acceptance

- high-value `-sys`/native dependencies demonstrate substantial reuse;
- no stale native output under header/config changes;
- exact link hits preserve output and diagnostics;
- no bespoke linker code is introduced.

## 156. M6: Authoritative coordinator, fleet singleflight, and resource scheduler

### Deliverables

- `rabs-coord` single-active coordinator authority, durable term/incarnation state, lexicographic peer high-water marks, edge/worker incarnation fences, and external-fencing contract;
- edge/coordinator session and combined deployment mode;
- fleet-wide `DiscoveryActor` and `ActionActor` registries;
- cross-edge subscriber interest and cancellation;
- coordinator-owned Cargo root permits;
- host/worker jobserver integration;
- worker pressure/eligibility snapshots;
- deterministic admission receipts;
- cache locality and transfer break-even scoring;
- foreground/optional/cleanup priorities;
- action history model;
- fifteen-agent multi-host storm benchmark.

### Acceptance

- concurrent identical demand across edge hosts joins one primary attempt lineage; extra retry/recovery/audit/hedge attempts occur only under explicit policy;
- coordinator restart advances the term and creates a new incarnation, closes/supersedes prior-authority active generations, and rejects stale offers; any disaster-recovery move is manual and proves the old authority fenced;
- one subscriber cancellation does not harm others;
- last subscriber cancellation drains resources;
- every Cargo implicit token is backed by a root permit;
- fifteen-agent storm improves at least `2×` at this stage, with `3×` final target;
- no system-wide swap collapse under stress.

## 157. M7: ATP native control plane

### Deliverables

- canonical ATP frame fix;
- explicit `RABS/1 over ATP/0` negotiation;
- durable identities, coordinator authority, and transport binding;
- bounded critical/control/event queues and independent per-domain sequences with explicit causal references;
- edge/coordinator and worker/coordinator heartbeat/capability/pressure streams;
- action submission/join/cancel/lease/reconciliation messages;
- transcript/stateful delivery intent, acknowledgement, uncertainty, completion, and bounded edge-handoff/fencing messages;
- worker prepared-result offer and coordinator commit notification;
- state-changing 0-RTT disabled;
- native QUIC reactor hardening;
- Tailscale path integration;
- shadow comparison against existing RCH control.

### Acceptance

- zero lifecycle disagreement in shadow runs;
- reconnect/reconciliation/event-replay suite passes;
- cancellation, coordinator-authority, lease-renewal, and reconciliation traffic remain responsive under bulk load;
- prolonged soak passes;
- path fallback behavior is explicit.

### Gate

SSH remains authoritative fallback until native control passes all gates.

## 158. M8: ATP object data plane

### Deliverables

- bounded missing-object negotiation;
- deterministic pack, chunk, manifest, and range/bitmap transfer;
- flow-control credit and reserved control capacity;
- resumable sparse writes and journals;
- source snapshot, artifact, toolchain, and incremental-object transfer;
- early-artifact priority path;
- worker/edge local inventory and coordinator-directed seeding;
- dual rsync-versus-ATP private materialization comparison.

### Acceptance

- exact logical tree/materialization equality;
- interrupted transfer resumes without duplicate publication;
- measured throughput and time-to-first-useful-artifact meet targets;
- bounded memory and message rate under adversarial peers;
- one corrupt location is quarantined/refetched correctly;
- ATP is faster or more reliable than rsync in target regimes.

## 159. M9: Whole-command canonical remote execution over ATP

### Deliverables

- canonical Cargo-driver execution on worker;
- immutable coherent source/path-dependency snapshot;
- stable worker execroot and one worker-local jobserver tree;
- whole-command streaming output, cancellation, and bounded final artifact return;
- ATP object deltas and hot target-state reuse;
- explicit externally visible side-effect classification;
- narrowly admitted `CargoWholeCommandBounded` cache profile;
- current RCH fallback bridge.

### Acceptance

- behavior parity with stock/current RCH;
- no mutable-worktree transfer races;
- whole-command remote builds benefit from object deltas and toolchain/target locality;
- unclosed target/build-directory side effects disable result caching without disabling remote execution;
- no cross-worker second-hop child dispatch;
- fail-open frontier remains intact.

## 160. M10: Workspace rustc action plane

### Deliverables

- workspace unit/action-family identity produced by canonical Cargo;
- coherent command snapshot plus minimal positive/negative action closure;
- closed-view enforcement and abort-on-new-read discovery;
- proc-macro input audit with exact environment;
- conservative exact dependency-artifact inputs;
- stable `OUT_DIR`, incremental, temp, and home paths;
- provisional `.rmeta` lifecycle and producer-commit obligations;
- fine-grained remote execution;
- fleet singleflight and action DAG construction;
- stock differential verification.

### Acceptance

- `10^5–10^6` representative shadow actions with zero unexplained divergence before broad serving;
- cross-worktree hit rate materially exceeds path-namespaced and full-snapshot-key baselines;
- Cargo pipelining is equal or better;
- producer failure prevents dependent publication and coherently fails/cancels the live build;
- p95 miss overhead remains within SLO;
- no semantic dependency projection is enabled without its own shadow gate.

## 161. M11: Build-script run caching and hermeticity

### Deliverables

- canonical Cargo-driver interception seam and launcher-shim feasibility matrix;
- exact stdout/stderr bytes, per-stream/event ordering, and Cargo directive capture/replay;
- generated output bundle;
- explicit environment and filesystem/process/network input closure;
- strict time/randomness/git/secret classification;
- registry-aggressive/workspace-audit-first modes;
- deterministic audit and denylist.

### Acceptance

- shim/interposition preserves Cargo fingerprints, mtimes, jobserver, output-cache, and `DEP_<LINKS>_*` semantics across supported Cargo versions;
- target `> 80%` of observed registry build scripts safely cacheable, subject to corpus;
- zero divergence;
- failed/cancelled partial outputs never publish;
- workspace volatile actions are accurately explained.

## 162. M12: Test-result cache

### Deliverables

- nextest target-runner/interception feasibility proof;
- per-test and bounded batch keys;
- positive/negative data-input and side-effect observation;
- stable-pass cache for admitted tests;
- deterministic failure and flaky classifications;
- fixture/setup side-effect protection;
- affected-test advisory model;
- doctest action classes;
- periodic fresh full-suite policy.

### Acceptance

- repeated agent test loops show substantial latency savings;
- zero incorrect passing hits;
- side-effecting/flaky/volatile tests never masquerade as stable hits;
- nextest output, cwd, environment, signals, retries, and status semantics match;
- periodic full-suite validation detects missing edges.

## 163. M13: Incremental time travel

### Deliverables

- stable logical incremental path and hidden snapshot identity;
- compatibility contract across toolchain/profile/output-platform/isolation class;
- content-defined chunking and compression;
- nearest compatible ancestor selection;
- branch/worktree prewarm;
- bounded retention/GC and delayed deletion;
- transfer break-even model;
- exact output+state bundling.

### Acceptance

- branch ping-pong `≥ 3×` faster on target workloads;
- storage growth bounded and explainable;
- snapshots are portable only across proven canonical/platform classes;
- no regression when snapshot transfer is more expensive than rebuild.

### Kill criterion

If representative corpora show poor latency ROI or unacceptable storage/complexity, retain exact artifact caching and defer state serving.

## 164. M14: Speculation, critical path, and CI prewarm

### Deliverables

- save-time watcher;
- git-event prewarm;
- priority promotion;
- SLO brownout;
- provenance-DAG critical-path scheduler;
- CI canonical writer/trust tier;
- speculation ROI dashboard.

### Acceptance

- positive net saved foreground latency after wasted-work accounting;
- foreground p95 improves;
- speculation never causes pressure regression under gates;
- promoted actions retain work correctly.

## 165. M15: Fragmentation analyzer and `rch advise`

### Deliverables

- key-fragmentation model;
- fleet convergence dashboard;
- dependency/version/feature/toolchain/flag recommendations;
- crate rebuild-tail analysis;
- machine-readable and human reports;
- agent-facing suggestions with evidence.

### Acceptance

- recommendations identify measurable compiler-second savings;
- advice is attributable and confidence-labeled;
- no automatic source/config mutation without explicit operator action.

## 166. M16: Evidence-gated frontier

Candidates:

- multi-peer object fetch and worker seeding optimization;
- RaptorQ on measured lossy WAN paths;
- multipath/fan-out;
- automatic transfer-brain tuning;
- external REAPI gateway;
- custom native-CPU rustc/LLVM profile;
- PGO/BOLT experiment;
- future public API hash integration;
- macOS strict VM/chroot serving improvements;
- cross-worker nested child-action dispatch;
- standby coordinator automation or, only if eventually required, stronger replicated coordination.

Every frontier item receives:

- hypothesis;
- corpus/benchmark;
- expected value;
- complexity and risk budget;
- proceed threshold;
- kill criterion;
- rollback plan;
- explicit no-claims.

# Part XXIII. Rollout and operations

## 167. Feature flags and policy modes

Required modes:

```text
off
record-only
shadow-key
shadow-execute
serve-dependencies
serve-selected-workspace
serve-all-eligible
remote-control-shadow
native-atp-control
native-atp-data
speculation-enabled
tests-enabled
incremental-snapshots-enabled
require-remote
```

Modes are independently controllable per repo, action class, worker, and trust tier.

## 168. Canary strategy

- designate canary coordinator and workers;
- route low-risk dependency actions first;
- retain current RCH path for comparison;
- compare performance/correctness automatically;
- promote workers only after canary action success;
- quarantine on cleanup, corruption, identity, or divergence incidents;
- support one-command rollback to prior path.

## 169. Operator commands

Recommended CLI additions:

```text
rch rabs status
rch rabs doctor
rch rabs mode
rch rabs replay
rch rabs shadow-report
rch rabs why ...
rch rabs action show <key>
rch rabs operation show <id>
rch rabs object stat|verify|locate <id>
rch rabs quarantine list|inspect|release
rch rabs gc plan|run|history
rch rabs worker reconcile <worker>
rch rabs cache fragmentation
rch rabs advise
rch rabs benchmark replay
rch rabs protocol compatibility
```

All commands support bounded JSON/TOON output and stable reason codes.

## 170. Doctor checks

- daemon reachability and fail-open latency;
- protocol/version compatibility;
- identity and certificate binding;
- canonical execroot support;
- namespace/sandbox capabilities;
- toolchain consistency;
- target CPU/profile drift;
- jobserver validity;
- disk/CAS health;
- database/filesystem consistency;
- object corruption sample;
- worker pressure freshness;
- Tailscale/direct path quality;
- stale operations and pins;
- GC headroom;
- wrapper-contract matrix status.

## 171. Backup and disaster recovery

- CAS objects are immutable and may be reconstructed from peers/cold storage or rebuilds;
- the selected coordinator metadata backend receives periodic consistent backups;
- loss of ordinary object-location/index hints degrades to cache misses, but authority/publication/generation/trust metadata is restored or explicitly reset/fenced before serving resumes;
- identity keys receive secure backup/rotation policy;
- manifests/provenance for project release-eligible entries may receive stronger replication;
- restore procedure includes object closure verification and schema checks.

## 172. Incident classes

```text
IncorrectResultDivergence
ObjectCorruption
PublicationFenceViolation
OrphanProcessOrResource
ProtocolCompatibilityFailure
WorkerIdentityMismatch
SecretExposure
StorageExhaustion
SchedulerPressureCollapse
CancellationHang
ReconciliationConflict
KeyInstabilityRegression
HitRateFragmentation
```

Every incident class has:

- detection signal;
- automatic containment;
- operator command/runbook;
- evidence bundle;
- recovery path;
- regression test requirement.

## 173. Documentation set

Required documents:

- architecture overview;
- action-key contract;
- canonical execroot contract;
- sandbox policy matrix;
- RABS/ATP protocol specification;
- object/CAS format and GC policy;
- cancellation and obligation contract;
- trust/provenance policy;
- worker admission policy;
- wrapper/Cargo compatibility matrix;
- rollout and rollback guide;
- incident runbooks;
- benchmark methodology;
- agent command palette;
- developer contribution guide;
- unsafe-boundary ledger and review guide.


---

# Part XXIV. Risk register and mitigations

## 174. Risk register

| ID | Risk | Consequence | Primary mitigation | Trigger/indicator |
|---|---|---|---|---|
| R1 | Action key omits a semantic input | wrong artifact served fleet-wide | observed-input closure, shadow mode, key epochs, differential verification | any divergence |
| R2 | Keys remain path-unstable | low hit rate despite correctness | canonical execroot, path leak audit, normalized OUT_DIR/toolchain/registry paths | cross-worktree miss taxonomy |
| R3 | Proc macro reads untracked input | stale compile result | rustc process tracing, tracked APIs, binary dep-info, re-audit | trace/key mismatch |
| R4 | Build script embeds time/git/network state | nondeterministic or stale output | hermetic defaults, explicit captured inputs, volatility classification | determinism audit divergence |
| R5 | Wrapper buffers output and breaks pipelining | severe build slowdown | streaming protocol, early `.rmeta`, golden Cargo event tests | metadata-ready latency regression |
| R6 | Cache-hit mtimes confuse Cargo | rebuild storms or false freshness | coherent materialization policy, checksum freshness option, repeated-hit tests | hit followed by rebuild |
| R7 | Remote jobserver descriptors leak | hangs/oversubscription | strip and replace jobserver state, dedicated tests | stalled rustc or token errors |
| R8 | Asupersync API churn leaks into RABS | broad rewrites and schema instability | `rabs-asupersync` isolation, exact pin, consumer contract CI | adapter compile/contract break |
| R9 | Native QUIC not production-ready | transport hangs/loss/perf regression | shadow plane, reactor hardening, soak/interoperability, SSH fallback | control disagreement or SLO miss |
| R10 | ATP codec noncanonical | replay/signature/transcript instability | sorted maps, golden fixtures, differential tests | byte mismatch for same logical message |
| R11 | CAS publication partially succeeds | poisoned/partial action result | prepare/commit transaction, object closure verification, staging journals | crash-injection test failure |
| R12 | Disk corruption | invalid artifacts | cryptographic verification, quarantine, independent refetch, rebuild | digest mismatch |
| R13 | Worker publishes stale result after partition | wrong winner/result pointer | execution leases and fencing | stale commit attempt |
| R14 | Subscriber cancellation kills shared work | agent interference | reference-counted interests and action actors | shared-action cancellation test failure |
| R15 | Last subscriber leaves expensive orphan work | resource waste | policy-driven action cancellation and quiescent drain | no-interest action continues beyond policy |
| R16 | Speculation harms foreground latency | negative product value | SLO optional class, pressure brownout, ROI accounting | p95 regression or wasted-work spike |
| R17 | Incremental snapshots explode storage | disk pressure and GC churn | FastCDC/zstd, per-repo budgets, nearest-state ROI, kill criterion | storage growth per saved second |
| R18 | Snapshot state is nonportable | crashes or wrong incremental reuse | canonical paths, toolchain/platform contract, dev-only gating | cross-worker divergence |
| R19 | Test cache serves flaky pass | false confidence | determinism records, periodic full runs, denylist | cached result diverges |
| R20 | Worker compromise/agent writes poison cache | supply-chain risk | trusted daemon publication, identity binding, sandbox, signatures/trust tiers | provenance/identity mismatch |
| R21 | Secrets enter cache/logs | privacy/security incident | capability handles, redaction, nonshareable classification | secret scanner finding |
| R22 | Global scheduler causes starvation | agent tail regression | weighted fairness, critical path, starvation bounds, receipts | max wait or fairness metric breach |
| R23 | Remote execution loses on tiny actions | universal tax | transfer break-even and local fast path | predicted/actual negative benefit |
| R24 | Compatibility islands contaminate core | hidden Tokio/runtime complexity | isolated processes/crates, bounded adapters, exit criteria | dependency graph policy violation |
| R25 | Stale health drives bad placement | failures and long tails | freshness/confidence thresholds, fail-closed remote-required policy | snapshot age breach |
| R26 | GC deletes needed objects | broken hits/running actions | durable pins, reachability proof, dry-run receipts, property tests | missing object referenced by valid root |
| R27 | Daemon fail-open is slow | every command pays tax | tiny timeout, circuit breaker, no runtime startup in wrapper | wrapper p95 breach |
| R28 | Deterministic-failure publication admits OOM/signal result | persistent false failures | termination classification before publication eligibility | abnormal termination marked deterministic |
| R29 | Cargo/rustc contract drifts upstream | wrapper breakage | stable/beta/nightly matrix, recorded fixtures, fast release lane | CI red test |
| R30 | Advanced ATP work distracts core | schedule slip | explicit defer list and evidence gates | frontier work before core gate |
| R31 | Custom rustc optimization yields little | maintenance burden | isolated experiment, `<3%` kill criterion | corpus result below threshold |
| R32 | REAPI compatibility becomes architectural drag | native semantics compromised | stateless isolated gateway | native core depends on gateway types |
| R33 | Overly strict sandbox breaks ecosystem | low compatibility | action-class profiles, explicit capabilities, local fallback, explainability | high policy-refusal rate |
| R34 | Overly permissive sandbox harms soundness | wrong cache entries | default-deny, trace audit, shadow verification | unobserved external effect |
| R35 | Provenance/metrics cardinality explodes | memory/storage/OTel pressure | bounded dimensions, hashing/redaction, aggregation tiers | cardinality/queue alerts |
| R36 | Huge diagnostics exhaust memory | daemon/worker OOM | streaming, byte caps, spill to objects, backpressure | diagnostics cap approached |
| R37 | Cross-platform semantics are overclaimed | invalid sharing | explicit compatibility classes and no-claim boundaries | platform differential mismatch |
| R38 | Action family recipe becomes stale | omitted new input | recipe validation, re-discovery on mismatch, sampled re-audit | observed-set drift |
| R39 | Provisional `.rmeta` consumer commits after producer failure | invalid dependent result | dependency obligation and producer-commit fence | producer failure with dependent prepared result |
| R40 | Coordinator DB and filesystem drift | leaked or unreachable objects | startup consistency scan, transactional metadata, repair tooling | consistency check finding |
| R41 | Full workspace root enters every fine-grained key | any source edit invalidates the entire graph | separate command snapshot from minimal action closure | miss fan-out after one-file edit |
| R42 | Attempt/action IDs appear in visible paths | unstable keys and embedded output paths | fixed visible paths, hidden physical backing roots, leak scan | artifact contains attempt/action prefix |
| R43 | Cargo itself runs outside canonical namespace | path-sensitive unit hashes and output names diverge before wrapper | canonical Cargo driver for workspace authority | different `-C metadata` across worktrees |
| R44 | Multiple edge daemons each own authoritative actors | duplicate fleet executions and split publication | one active coordinator authority; edge proxies only | same key leased independently |
| R45 | Environment reads assumed traceable | omitted key inputs and stale results | exact constructed/hash-complete environment | env mutation does not change key |
| R46 | vDSO clock or alternate entropy escapes tracer | nondeterministic shared result | strict virtualization/denial profile or volatile classification | cross-run divergence/time access evidence |
| R47 | macOS APFS clone mistaken for path isolation | concurrent paths remain different | VM/chroot canonical root or reduced authority | macOS workspace keys path-fragment |
| R48 | Shared jobserver ignores Cargo implicit tokens | oversubscription despite one pipe | coordinator-backed Cargo root permit plus local jobserver | active Cargo count exceeds root grants |
| R49 | Semantic rlib projection omits observable bytes | wrong downstream hit | exact artifact default; versioned projection shadow gate | conservative/projected differential mismatch |
| R50 | Worker can issue commit command | publication authority confused or replayed | worker offer only; coordinator transaction commits | worker-originated pointer mutation |
| R51 | One corrupt replica quarantines all copies | unnecessary rebuild/outage | separate location, logical object, manifest, and action quarantine | valid alternate copy exists |
| R52 | Source snapshot mixes concurrent edits | key/result not tied to any real state | filesystem snapshot or pre/post mutation validation/retry | capture consistency failure |
| R53 | Whole-command cache omits target/build side effects | later Cargo freshness/state is wrong | remote-exec-only default; bounded closure for result cache | cache hit followed by inconsistent Cargo state |
| R54 | Per-chunk acknowledgements flood control plane | high CPU/memory/message overhead | range/bitmap ACKs, credits, packs, batching | ACK/message ratio grows with chunk count |
| R55 | Presentation settings fragment semantic artifacts | avoidable misses or wrong transcript replay | canonical compiler events plus presentation variants | color/width-only misses |
| R56 | Secret capability ID used without value version | stale or cross-secret result reuse | opaque HMAC/version/scope digest or no cache | secret rotation leaves key unchanged |
| R57 | New file satisfies a previously failed open | stale hit despite unchanged positive inputs | negative dependency set and directory enumeration | create-file mutation misses invalidation |
| R58 | GC unlinks during a new read/materialization race | missing object for valid active action | tombstone grace, open-reader/materialization pins, final recheck | concurrent GC stress failure |
| R59 | FrankenSQLite bug compromises action index | incorrect publication/recovery | storage abstraction, reference SQLite differential and crash gate | backend differential mismatch |
| R60 | State-changing QUIC 0-RTT replay | duplicate lease/action/publication operation | disable V1 state-changing 0-RTT | replay test changes state twice |
| R61 | Cache hit and action publication share one state enum | incorrect fallback/recovery or duplicate commit | separate build/action/attempt/subscriber state machines | transition-model or replay inconsistency |
| R62 | One overloaded lease field invalidates sibling hedges | valid result rejected or duplicate work mishandled | one action generation plus independent execution leases | hedge renewal/revocation race |
| R63 | Same-key candidates produce different manifests | silent nondeterminism or unsound key | compare-and-set, action quarantine, incident bundle | divergent candidate after/before commit |
| R64 | Provisional lineage checked only one edge deep | transitive invalid descendant commits | canonical transitive ancestor closure and exact-object resolution | A→B→C producer failure scenario |
| R65 | Writable hardlink aliases CAS object | cache corruption through mtime/content mutation | prohibit writable hardlinks; reflink/copy/read-only bind | CAS digest changes after materialization |
| R66 | Cached build-script output merges with stale OUT_DIR | ghost files or missing deletions alter build | key pre-state; clean post-state replacement with tombstones | repeated replay differs from clean run |
| R67 | Concurrent whole-command builds share mutable target state | races, lock contention, contaminated freshness | exclusive target-state lease or private clone | overlapping operation mutation |
| R68 | Control stream shares congested bulk connection | cancellation/lease tail blowup | dedicated control connection or proven scheduler SLO | bulk saturation control p99 breach |
| R69 | Per-test process isolation hides suite coupling | cached pass skips required setup/order effects | batch/suite key or bypass | order/setup mutation changes result |
| R70 | Wrapper recursively intercepts itself or upgrade build | loops, deadlock, unusable bootstrap | bounded chain and authenticated internal bypass | recursion-depth/loop detector fires |
| R71 | Filesystem semantic mismatch across workers | path lookup or generated-output divergence | explicit filesystem semantic class | case/Unicode/symlink differential |
| R72 | Cargo package metadata misstates actual license | inaccurate SBOM/distribution claims | align LicenseRef/license-file and release checks | metadata/LICENSE mismatch gate |
| R73 | Unsynchronized wall clocks decide lease validity | stale or prematurely expired authority | monotonic TTL and renewal sequence | clock-skew chaos failure |
| R74 | Code signing is folded into ordinary link cache | secret exposure or invalid/replayed signature | separate credentialed post-processing action | signing identity/timestamp divergence |
| R75 | Target-state or CAS materialization accepts special/path-conflicting entries | traversal, overwrite, or platform ambiguity | strict manifest path/type validation | malicious manifest fuzz case |
| R76 | Cargo resolves/fetches against mutable ambient index state | nonreproducible graph or unexpected network dependency | explicit captured fetch/resolution phase and offline build | same lockfile resolves differently |
| R77 | Canonical Cargo wants to update Cargo.lock/workspace files | remote build diverges or overwrites agent edits | writable overlay, mutation receipt, content-preconditioned replay or local fallback | workspace mutation/conflict detected |
| R78 | Build tool observes stat/umask/CPU-count/inherited FD state | omitted key input or nondeterminism | canonical process context plus metadata/system probe capture | system-context differential mismatch |
| R79 | Authenticated worker returns malicious but digest-valid output | poisoned semantic result | trust tiers, independent verification, worker quarantine | cross-worker/stock divergence |
| R80 | Canonical result manifest contains attempt-specific evidence | equivalent attempts falsely diverge and quarantine every hedge/audit | split canonical result, attempt evidence, and publication record | same outputs but different attempt IDs yield different result IDs |
| R81 | Compressed/packed representations share one ambiguous logical path | races, unreadable objects, or wrong decoder selection | representation IDs keyed by storage profile and encoded digest | same logical object has conflicting on-disk encoding |
| R82 | Source snapshot uploads denied/secrets because `.gitignore` was trusted | credential/source disclosure | explicit source-capture policy, secret/local-only classes, ACL namespace | secret scanner/access-policy incident |
| R83 | Watcher/mtime digest memoization misses a mutation | stale action key | receipt/file-version evidence, overflow fallback, periodic rehash audit | memoized digest differs from rehash |
| R84 | Canonical build path is embedded and opened at runtime | cached binary fails outside build sandbox | runtime-path portability scan/classification or packaged resource | runtime open of `/__rabs/...` fails |
| R85 | Derived real-path dep-info is treated as canonical object | path-fragmented keys or cross-subscriber corruption | canonical dep-info plus versioned private derivation | subscriber dep-info digest enters shared key |
| R86 | Producer lineage fails after dependent outputs were materialized | dirty target/fingerprint state reused | provisional materialization journal, ownership-safe cleanup, Cargo revalidation | next build skips invalid dependent |
| R87 | Edge/coordinator outage triggers local compile stampede | workstation saturation during fail-open | explicit uncoordinated mode, optional host-local limiter, degraded storm test | many fallback Cargo roots start at once |
| R88 | Restored coordinator uses stale/lower authority | stale leases/publication accepted after rollback | peer-persisted term/credential high-water marks plus operator reset proof | peer accepts lower/reused authority |
| R89 | Non-UTF8 argv/path/env is lossy-normalized | key collision, wrong invocation, or failed materialization | native byte-preserving schemas and escaped display | round-trip fixture changes bytes |
| R90 | Process-group-only cancellation misses setsid/daemonized descendants | orphan processes/tokens | cgroup/PID namespace or VM containment plus bounded group/cgroup kill | descendant survives region close |
| R91 | Nextest retry/setup profile omitted from test key | cached pass skips setup or changes retry semantics | key runner/setup/retry/timeout policy; retry-pass classified flaky | final retry pass served as stable first-pass result |
| R92 | Benchmark timing result is served from cache | meaningless/stale performance evidence | benchmark runs non-result-cacheable by default and hardware/load scoped | cached benchmark contains prior timing |
| R93 | Raw directory order or file metadata cannot be reproduced | cross-worker nondeterminism or stale hit | record observable order/metadata and restrict to proven filesystem/materializer | same entry set yields different output |
| R94 | Wrapper/client signal or slow subscriber is mishandled | leaked attempt, wrong exit semantics, global stream stall | per-subscriber bounded queues, signal/parent-death forwarding, disconnect cancellation | one client stalls peers or SIGINT maps to normal exit |
| R95 | Manifest graph/pack index is cyclic or overlapping | resource exhaustion, traversal, or wrong bytes | acyclic bounded closure validation and range checks | manifest fuzz finds cycle/overlap |
| R96 | Canonical paths change `file!()`/`CARGO_MANIFEST_DIR` or runtime-visible strings | semantically different binary/test/log output served cross-worktree | explicit build-path semantic policy, shadow differential, path-preserving lane | original-path and canonical builds differ observably |
| R97 | Edge/wrapper dies during visible output/event delivery | duplicate event, mixed output, or unsafe local fallback | write-ahead delivery intent, full-write acknowledgement, `DeliveryUncertain` fail-closed state | crash between rename/write and acknowledgement |
| R98 | Concurrent hits install overlapping target paths | target corruption or freshness races | per-operation destination arbiter and declared-path reservations | two bundles claim same path/parent subtree |
| R99 | Trust tier is embedded only in immutable publication | stale approval survives new evidence or compromise | append-only evidence index plus versioned trust evaluations/quarantine override | evidence changes but serving tier does not |
| R100 | Size-optimized workspace profile is reused for daemon/worker | slower scheduling, hashing, transfer, and materialization | binary-specific release profiles and corpus benchmarks | daemon profile regresses latency/throughput |
| R101 | Failed build-script partial state is always discarded | retry behavior diverges from stock Cargo/build script | operation-owned execution or exact failure post-state replay; otherwise local | next retry reads missing partial state |
| R102 | Cargo graph tokens are conflated with worker CPU grants | fleet underutilization or oversubscription | plane-specific frontier/root and execution grants | remote children idle fleet or overload worker |
| R103 | Equal declared result digests hide different canonical manifest bytes | projection/serializer omissions evade divergence checks | byte/object-ID comparison plus projection-completeness quarantine | same digests but different canonical manifest IDs |
| R104 | Partial diagnostics are conflated with Cargo-state commit | either fsync-per-line overhead or unsafe/duplicated fallback transcript | separate transcript and stateful frontiers; labeled recovery only | fallback after partial transcript or diagnostic journal latency spike |
| R105 | Size-optimized wrapper aborts or prints panic before containment | fail-open path disappears or transcript becomes mixed on internal bug | nonprinting pre-exposure hook, panic-unwind top-level guard, or separate minimal parent; abort prohibited by default | wrapper exits/prints panic before exposure decision |
| R106 | Restored/cloned worker reuses boot generation | stale/duplicate daemon can hold or offer leases | fresh incarnation ID, one active incarnation, clone ambiguity fail-closed, hardware-bound enrollment or operator re-enrollment where legitimacy matters | two sessions share worker identity/generation |
| R107 | Working directory is represented twice in the key schema | inconsistent values or needless fragmentation | single authoritative descriptor field and canonical-key component | key breakdown shows two cwd digests |
| R108 | Action generation identity is reused after failure/eviction/metadata repair | stale attempt passes an ABA-style fence | opaque never-reused generation ID plus retained high-water/tombstone | old attempt tuple matches a new generation |
| R109 | One global event sequence spans control and bulk streams | cancellation/lease traffic blocks behind missing bulk data | independent sequence domains and explicit causal references | control p99 waits on bulk sequence gap |
| R110 | Cargo resolution mutates lock/config after the command snapshot is sealed | actions combine pre- and post-resolution state | requested→resolved snapshot lineage and reseal/restart rules | child actions name inconsistent lockfile generations |
| R111 | Action pointer commits before its durable publication pin/root | GC can remove a newly visible result closure | create reachability root/pin in the same commit transaction | committed action references reclaimable objects |
| R112 | Provisional-lineage waiters occupy every Cargo job slot | producer cannot progress or pipelining becomes slower than stock | reserved producer capacity, bounded waiter depth/count, adaptive disable | all slots wait on unresolved ancestors |
| R113 | Authority/publication metadata loss is treated as a harmless cache miss | stale leases, split history, or unsafe republish | restore/reconcile or explicit credential/reset generation before serving | coordinator starts serving after empty/rolled-back DB |
| R114 | Random incarnation ID is treated as proof of clone legitimacy | wrong cloned daemon may be admitted | conflict detection plus hardware-bound enrollment/operator re-enrollment; no unsupported anti-clone claim | two credential-identical clones race activation |
| R115 | Attempt provenance is embedded in canonical result identity | equivalent attempts falsely diverge | separate canonical result, publication, evidence, and serving records | worker/timing change changes canonical manifest |
| R116 | Transcript frame may be partially exposed without acknowledgement | duplicate/mixed output on fallback | transcript in-flight/uncertain frontier and framed full-item replay | connection dies during wrapper write |
| R117 | Action generation and attempt carry two independently mutable full coordinator-authority copies | malformed identity, false stale rejection, or fence bypass | one full attempt/publication authority plus generation authority digest and equality check | authority copies disagree |
| R118 | Edge handoff is modeled as an unconstrained active-incarnation set | two edges materialize/replay the same subscriber concurrently | one active incarnation plus one explicitly named bounded predecessor and handoff token | more than the admitted handoff pair owns rights |
| R119 | Persistence schema omits publication/serving/generation/incarnation fence distinctions | recovery reconstructs an unsafe or ambiguous active state | explicit authoritative tables, constraints, and fail-closed startup reconciliation | required authority/publication/fence row missing |
| R120 | New coordinator term resumes an action generation created under the old authority | stale prepared result publishes after restart | close/supersede old-authority generations; blobs/evidence reusable, publication requires a fresh generation | old authority digest appears in a publication-eligible lease |
| R121 | Raw 32-byte digests from different domains/algorithms are treated as interchangeable | false hit, fence mismatch, or migration corruption | typed algorithm/domain IDs, explicit SHA-256 V1 framing, epoch migration, cross-domain rejection | untyped digest comparison reaches authority/key path |
| R122 | Build-script path-valued directives are replayed as opaque stdout only | downstream links use missing or worker-specific paths/libraries | structured directive manifest, canonical path closure, downstream native dependency edges | replayed `rustc-link-search` path is unavailable/different |
| R123 | Link key hashes argv but not implicit/default library resolution | wrong cached binary after system library/search-path change | closed linker view, selected/negative search inputs, CRT/script/plugin capture | same argv opens different linker inputs |
| R124 | Protocol message names collapse delivery intent, acknowledgement, uncertainty, or completion | reconnect interprets an uncommitted item as exposed or vice versa | distinct transcript/stateful delivery messages and state-machine fixtures | one ambiguous “recorded/exposed” message drives recovery |
| R125 | Canonical result stores logical outputs plus independently mutable dep-info/build-script output lists | equivalent results diverge or contradictory objects pass validation | one role-tagged logical-output map and derived indexes; bundle-root consistency check | specialized output list disagrees with canonical map |
| R126 | Serving state has no durable validity/revision/authority model | expired failure or stale trust decision continues serving after restart | explicit validity with conservative clock handling, monotonic state revision, authority digest, blocking quarantine IDs | clock rollback or stale row preserves eligibility |
| R127 | Pin expiry/release relies on unsynchronized clocks or worker authority | GC deletes live/provisional/publication objects | coordinator-issued lease sequences, conservative restart grace, authority-scoped idempotent release, publication pins coordinator-only | uncertain lease treated expired or worker releases publication root |
| R128 | Two rustc attempts mutate one restored incremental directory or capture state before quiescence | snapshot corruption or state/output mismatch poisons future edits | immutable retained base, private writable clone per attempt, quiescent atomic auxiliary snapshot publication | shared writable inode or partial state snapshot retained |
| R129 | Action reads an undeclared file/tree outside workspace/toolchain closure | secret exfiltration, path instability, or stale cross-host hit | explicit external-input capability with canonical mount/object/privacy/version; otherwise local/volatile | raw host path enters authoritative closure |
| R130 | Single authoritative coordinator is implemented as one contended lock/unbounded queue | fleet tail latency, memory growth, or availability collapse | sharded actor registries, bounded mailboxes, critical-queue isolation, narrow serialized transactions, overload policy | coordinator queue/loop SLO fails under storm |

## 175. High-risk subsystems requiring explicit design review

Before implementation or cutover, require a dedicated design review for:

- key schema and observed-input closure;
- canonical execroot and path remapping;
- publication transaction and fencing;
- provisional `.rmeta` lifecycle;
- worker identity/transport binding;
- durable CAS pins and GC;
- native QUIC control/data cutover;
- sandbox secret/network capabilities;
- incremental snapshot portability;
- test-result cache authority;
- coherent command snapshot versus minimal action closure;
- canonical Cargo-driver behavior and wrapper nesting;
- edge/coordinator authority, high-water recovery, worker process-incarnation fencing, and external fencing;
- exact dependency artifact versus reduced projection;
- jobserver implicit-token/root-permit accounting;
- platform isolation-authority matrix;
- metadata backend conformance and coordinator-only publication;
- layered state machines and per-subscriber transcript/stateful-delivery recovery;
- action-generation/independent-lease hedging and divergent-result conflict policy;
- transitive provisional lineage and exact-object adoption;
- immutable CAS materialization/no-writable-hardlink policy;
- build-script pre-state/post-state replacement semantics;
- licensing/package-metadata/SBOM alignment;
- Cargo resolution/fetch and workspace-mutation replay semantics;
- process/system metadata input closure;
- canonical result versus attempt-evidence/publication identity, semantic/observable divergence, and equal-projection/different-manifest completeness incidents;
- source-capture confidentiality and byte-preserving path/argv/environment schemas;
- edge content-identity index and watcher-overflow recovery;
- logical-object versus storage-representation identity;
- runtime-visible canonical-path portability;
- subscriber-specific dep-info/materialization derivation;
- wrapper signal/TTY/disconnect/panic behavior, transcript-versus-stateful delivery frontiers, and fail-open storm posture;
- test setup/retry/batch semantics and benchmark non-cacheability;
- canonical build-path versus original-path semantic policy;
- subscriber delivery uncertainty and destination-path arbitration;
- evidence-set/trust-evaluation evolution after publication;
- plane-specific Cargo-frontier versus execution-resource grants;
- build-script failure post-state fidelity;
- binary-specific release optimization profiles;
- immutable publication history versus mutable serving disposition;
- action-generation ABA prevention across eviction/repair;
- requested-to-resolved Cargo snapshot lineage;
- protocol sequence-domain separation;
- atomic publication-pin creation and metadata-loss reset semantics;
- provisional-lineage waiter/jobserver progress bounds;
- worker clone ambiguity and enrollment policy.

## 176. Rejected alternatives

### REAPI as the internal architecture

Rejected as the native constitution because RABS benefits materially from Asupersync’s region ownership, cancellation, obligations, ATP object lifecycle, lab replay, and agent-specific semantics. Retained as an optional gateway and conceptual mapping.

### NativeLink/Buildbarn as the core product

Rejected as the primary architecture because the differentiating work is deeply coupled to Cargo pipelining, canonical execroots, observed inputs, provisional metadata, branch-aware state, and agent scheduling. External servers remain useful comparative baselines and possible gateway targets.

### Tokio-first new core

Rejected because Asupersync is the desired production substrate and already contains direct RCH/ATP integration concepts. Tokio compatibility remains transitional/peripheral.

### Full Asupersync in every wrapper

Rejected due to startup latency, binary/dependency weight, nested-runtime hazards, and fail-open complexity.

### Extending `atpd` into the worker

Rejected because `atpd` is intentionally broad while RABS requires a narrow compiler-worker trust and lifecycle model.

### Bespoke incremental linker

Rejected in favor of exact link caching and adopting/contributing to Wild or using lld.

### Mutable rsync worktree as long-term input model

Rejected because it races live changes, produces volatile-file errors, and cannot provide an immutable action identity.

### Path-namespaced workspace keys

Rejected because it destroys cross-worktree/fleet reuse.

### Optimistic dep-info-only soundness

Rejected because proc macros/build scripts can read untracked files and environment.

### GPU/ThinLTO compiler backend project

Rejected as a separate high-risk research program outside RABS.

---

# Part XXV. Concrete schemas and contracts

## 177. Key and input schemas

Suggested logical forms follow. Every identifier, timestamp, duration, budget, peer, and authority type named here is owned by `rabs-protocol`; adapters convert to/from Asupersync types internally. Cross-host deadlines are encoded as relative budgets plus causal/wall-clock diagnostic metadata, never as a foreign runtime's process-local `Instant`.

```rust
struct ActionInputManifest {
    schema_version: u32,
    positive_inputs: Vec<PositiveInput>,
    closure_recipe_epoch: u32,
}

struct ActionKeyBreakdown {
    schema_version: u32,
    key_epoch: u32,
    projection_epoch: u32,
    action_class: ComponentDigest,
    virtual_working_directory: ComponentDigest,
    invocation: ComponentTree,
    action_inputs: ComponentTree,
    negative_dependencies: ComponentTree,
    dependencies: Vec<DependencyComponent>,
    presented_environment: Vec<RedactedEnvironmentComponent>,
    toolchain: ComponentTree,
    output_platform: ComponentTree,
    sandbox_semantic_policy: ComponentDigest,
    build_path_semantic_policy: ComponentDigest,
    execution_semantics: ComponentDigest,
    outputs: ComponentTree,
    final_key: ActionKey,
}

struct ActionSubscriptionContext {
    execution_snapshot_root: ObjectId,
    requesting_edge: PeerId,
    build_operation_id: BuildOperationId,
    subscriber_id: SubscriberId,
    subscriber_kind: SubscriberKind,
    presentation: PresentationContract,
    compiler_events: CanonicalCompilerEventContract,
    pipelining: PipeliningContract,
    path_translation: PathTranslationTableId,
    execution_requirements: ExecutionRequirements,
    minimum_evidence_tier: TrustEvidenceTier,
    queue_priority: Priority,
    deadline_budget: Option<DeadlineBudget>,
}

struct AttemptDispatchContext {
    attempt_authority: AttemptAuthority,
    attempt_purpose: AttemptPurpose,
    selected_execution_snapshot_root: ObjectId,
    selected_worker: PeerId,
    execution_eligibility_receipt: ExecutionEligibilityReceipt,
    resource_grant: ResourceGrant,
    sandbox_implementation: SandboxImplementationId,
    object_source_plan: ObjectSourcePlan,
}
```

Requirements:

- deterministic ordering;
- redaction-safe values;
- full snapshot identity retained in request/provenance but not automatically in the fine-grained key;
- enough information to diff two keys and projections;
- component hashes retained when raw values cannot be logged;
- explicit positive/negative/environment categories;
- machine-readable reason taxonomy.

### 177.1 Authority and execution identity

```rust
struct CoordinatorAuthority {
    cluster_id: ClusterId,
    credential_generation: u64,
    term: u64,
    incarnation_id: CoordinatorIncarnationId,
}

struct ActionGeneration {
    generation_id: ActionGenerationId,
    per_key_ordinal: u64,
    created_under_authority_digest: Digest,
}

struct AttemptAuthority {
    coordinator: CoordinatorAuthority,
    action_key: ActionKey,
    action_generation: ActionGeneration,
    attempt_id: AttemptId,
    execution_lease_id: ExecutionLeaseId,
    lease_renewal_seq: LeaseRenewalSeq,
    worker_peer_id: PeerId,
    worker_boot_generation: WorkerBootGeneration,
    worker_incarnation_id: WorkerIncarnationId,
    execution_policy_digest: Digest,
}

struct PeerAuthorityHighWaterMark {
    cluster_id: ClusterId,
    coordinator_credential_generation: u64,
    highest_term_within_generation: u64,
    last_incarnation_id: CoordinatorIncarnationId,
    operator_reset_generation: u64,
}

struct WorkerIncarnationFenceRecord {
    worker_peer_id: PeerId,
    enrollment_generation: u64,
    highest_boot_generation: WorkerBootGeneration,
    active_incarnation_id: Option<WorkerIncarnationId>,
    active_session_id: Option<SessionId>,
    clone_ambiguity_state: CloneAmbiguityState,
    operator_reset_generation: u64,
}

struct EdgeIncarnationFenceRecord {
    edge_peer_id: PeerId,
    highest_boot_generation: EdgeBootGeneration,
    active_incarnation_id: Option<EdgeIncarnationId>,
    active_session_id: Option<SessionId>,
    handoff_from_incarnation_id: Option<EdgeIncarnationId>,
    handoff_from_session_id: Option<SessionId>,
    handoff_lease_id: Option<EdgeHandoffLeaseId>,
    handoff_renewal_seq: Option<LeaseRenewalSeq>,
    handoff_generation: u64,
    operator_reset_generation: u64,
}

struct SubscriberDeliveryRecord {
    build_operation_id: BuildOperationId,
    subscriber_id: SubscriberId,
    state: SubscriberDeliveryState,
    transcript_exposed: bool,
    pending_transcript_sequence: Option<u64>,
    transcript_delivery_uncertain: bool,
    pending_stateful_commit_sequence: Option<u64>,
    last_fully_delivered_sequence: u64,
    last_stateful_commit_sequence: Option<u64>,
    last_observable_commit_kind: Option<ObservableCommitKind>,
    resumable_token_digest: Digest,
}
```

The action actor may have many subscriber delivery records and many attempts. No scalar operation ID or observable-commit flag is stored on the logical action row.

## 178. Canonical result, attempt evidence, and publication schemas

```rust
enum ResultKind {
    Success,
    DeterministicFailure,
}

struct CanonicalActionResultManifest {
    schema_version: u32,
    action_key: ActionKey,
    canonical_descriptor_digest: Digest,
    key_epoch: u32,
    projection_epoch: u32,
    result_kind: ResultKind,
    artifact_bundle_root: Option<ObjectId>,
    logical_outputs: Vec<LogicalOutputObject>,
    canonical_observations: CanonicalObservationManifest,
    normalized_process_outcome: NormalizedProcessOutcome,
    semantic_result_digest: Digest,
    observable_result_digest: Digest,
}

struct AttemptEvidenceBundle {
    schema_version: u32,
    action_key: ActionKey,
    canonical_result_manifest_id: ObjectId,
    attempt_authority: AttemptAuthority,
    execution_snapshot_root: ObjectId,
    observed_input_report: ObjectId,
    provisional_ancestor_closure: Vec<ProvisionalAncestorRef>,
    provisional_outputs_offered: Vec<LogicalObjectId>,
    isolation_evidence: IsolationEvidenceRecord,
    raw_process_and_event_evidence: ObjectId,
    provenance_receipt: ObjectId,
    verification_observations: VerificationRecord,
    resource_and_timing_observations: ResourceTimingRecord,
    incremental_snapshot: Option<ObjectId>,
}

struct ActionPublicationRecord {
    schema_version: u32,
    action_key: ActionKey,
    canonical_result_manifest_id: ObjectId,
    winner_action_generation: ActionGeneration,
    winner_attempt_id: AttemptId,
    winner_evidence_bundle_id: ObjectId,
    coordinator_authority: CoordinatorAuthority,
    committed_causal_sequence: u64,
}

enum ActionServingDisposition {
    Eligible,
    EvidencePending,
    ExpiredNeedsRevalidation,
    Quarantined,
    ObjectsUnavailable,
    EvictedFromActiveIndex,
}

struct ServingValidity {
    evaluated_at_unix_micros: i64,
    maximum_age_micros: Option<u64>,
    clock_uncertainty_micros: u64,
    coordinator_clock_epoch: u64,
}

struct ActionServingStateRecord {
    schema_version: u32,
    action_key: ActionKey,
    publication_record_id: ObjectId,
    disposition: ActionServingDisposition,
    reason_codes: Vec<ReasonCode>,
    blocking_quarantine_ids: Vec<QuarantineId>,
    policy_epoch: u32,
    state_revision: u64,
    coordinator_authority_digest: Digest,
    validity: ServingValidity,
    revalidation_required: bool,
    updated_causal_sequence: u64,
}

struct ActionTrustEvaluationRecord {
    schema_version: u32,
    action_key: ActionKey,
    canonical_result_manifest_id: ObjectId,
    evidence_set_digest: Digest,
    policy_digest: Digest,
    evaluated_tier: TrustEvidenceTier,
    isolation_scope: IsolationProfileId,
    privacy_scope: AccessScopeId,
    serving_restrictions: Vec<ServingRestriction>,
    evaluated_causal_sequence: u64,
}
```

Canonical result identity contains only output/exit/observable facts that an ordinary cache hit may replay. Its serializer and both digest projections are closed specifications: different canonical manifest bytes with equal declared digests are an incident, not a permitted extension point. It excludes worker identity, attempt/generation IDs, timing, resource use, verification runs, trust tier, command snapshot provenance, provisional lineage, and incremental state. Those remain append-only evidence or auxiliary state and may differ across equivalent attempts.

`logical_outputs` is the single authoritative sorted output/side-effect-object map. Each row carries an output-role tag such as materializable file/tree, dep-info, provisional metadata, build-script metadata/directive manifest, or test side-effect object. Specialized lookup indexes are derived database views and never duplicate independently mutable object lists inside the canonical manifest. `artifact_bundle_root`, when present, is deterministically computed from this map and is validated on decode/publication; deterministic failures have an empty output map and no artifact bundle root.

`semantic_result_digest` is computed over a versioned `SemanticResultProjection` containing declared materializable outputs, build-script/test side-effect outputs, normalized process outcome, and other action-class semantic fields, excluding both digest fields. `observable_result_digest` is computed over that semantic projection plus the canonical compiler/diagnostic/stdout/stderr observation contract, also excluding both digest fields. Semantic divergence quarantines the action. Observation-only divergence receives a narrower replay quarantine; evidence-only divergence is normal.

Physical edge destinations, rewritten dep-info, rendered diagnostic variants, mtimes, and other subscriber materializations are stored separately. Deterministic failures carry no materializable build outputs or provisional metadata, but may carry canonical observations required to report the failure. Incremental snapshots are optional attempt auxiliaries and can have several compatible candidates for one canonical result.

`ActionPublicationRecord` is immutable publication history. Additional evidence bundles attach through an evidence index whose IDs are canonically sorted/deduplicated for `evidence_set_digest`, and serving eligibility is represented by versioned `ActionTrustEvaluationRecord`s. Evidence promotion/demotion never mutates canonical bytes; quarantine state may override every evaluation.

Serving validity is coordinator-evaluated policy, not an action-key input. Durable TTLs use the RABS-owned `ServingValidity` record; wall-clock rollback, clock-epoch discontinuity, or uncertainty that crosses the not-after bound expires serving conservatively. A monotonic `state_revision` and authority digest make serving-state replay/idempotency explicit. Quarantine incident rows remain append-only evidence; the serving row names blocking incidents rather than treating a reason string as authority.

## 179. `WorkerPressureSnapshot` and platform declarations

```rust
struct WorkerPressureSnapshot {
    schema_version: u32,
    worker_peer_id: PeerId,
    worker_boot_generation: WorkerBootGeneration,
    worker_incarnation_id: WorkerIncarnationId,
    captured_at_causal: CausalTimestamp,
    valid_for_micros: u64,
    admin_intent: AdminIntent,
    eligibility: EligibilityState,
    supported_output_platforms: Vec<OutputPlatformClassId>,
    isolation_profiles: Vec<IsolationProfileId>,
    queue: QueueSnapshot,
    cpu: CpuSnapshot,
    memory: MemoryPressureSnapshot,
    io: IoPressureSnapshot,
    disk: DiskSpaceSnapshot,
    cache: CacheWarmthSnapshot,
    toolchains: ToolchainInventoryDigest,
    retrieval: RetrievalReliability,
    cancellation_debt: CancellationDebt,
    path: PathQualitySnapshot,
    confidence_bps: u16,
}
```

Pressure, queue, kernel capability, and cache warmth are execution eligibility, not successful-output key inputs. The coordinator timestamps receipt with its own monotonic clock and treats `valid_for_micros` conservatively after reconnect/restart; `captured_at_causal` orders evidence but is not a cross-host wall-clock age source. The selected output-platform class must still match the action descriptor exactly.

## 180. `DecisionReceipt`

```rust
struct DecisionReceipt {
    schema_version: u32,
    decision_id: DecisionId,
    request_id: RequestId,
    coordinator_authority: CoordinatorAuthority,
    action_key: Option<ActionKey>,
    decision: AdmitDeferRefuseFallback,
    selected_worker: Option<PeerId>,
    candidate_rows: Vec<WorkerCandidateReceipt>,
    local_fallback_allowed: bool,
    subscriber_delivery_state: SubscriberDeliveryState,
    remote_required: bool,
    cargo_root_permit: Option<CargoRootPermitReceipt>,
    budget: BudgetReceipt,
    priority: PriorityReceipt,
    transfer_plan: Option<TransferPlanReceipt>,
    reasons: Vec<ReasonCode>,
    non_claims: Vec<NonClaimCode>,
}
```

## 181. Stable reason-code families

```text
KEY_*
CACHE_*
INPUT_*
PATH_*
TOOLCHAIN_*
PLATFORM_*
SANDBOX_*
WORKER_*
PRESSURE_*
TRANSFER_*
LEASE_*
AUTHORITY_*
CANCEL_*
DELIVERY_*
PUBLICATION_*
EVIDENCE_*
STORAGE_*
VERIFY_*
QUARANTINE_*
FALLBACK_*
PROTOCOL_*
SPECULATION_*
TEST_*
```

Reason codes are append-only within a protocol major version and documented in a registry.

## 182. Local wrapper protocol

The local Unix-socket protocol is simpler than ATP but shares domain schemas.

Requirements:

- length-bounded canonical frames;
- one request plus ordered subscriber-delivery sequence domain with request ID, resumable subscriber token, and last-accepted/possibly-in-flight sequence;
- explicit per-subscriber transcript intent/exposure/uncertainty and stateful commit-intent/commit/uncertainty state, with iterative sequence acknowledgement;
- decoded nested-wrapper-chain identity;
- peer credential check, socket ownership/mode validation, and per-request capability token where supported; TCP fallback is loopback-authenticated and disabled by default;
- bounded reconnect grace on client/edge restart, followed by cancellation according to subscriber policy;
- version negotiation;
- no large source content inline;
- path/presentation context separate from semantic action descriptor;
- edge response that separately names whether seamless fallback, labeled transcript recovery, or no fallback may still occur;
- fixtures across wrapper/edge versions and daemon-death points.

# Part XXVI. Granular implementation backlog

The backlog below is intentionally implementation-oriented. Items marked **P0** block the first authoritative path; **P1** are required for the complete core; **P2** are evidence-gated or later optimizations. Backlog IDs always use a three-digit suffix (for example `R001`); risk-register IDs are deliberately unpadded (for example `R1`) so tools can distinguish them.

## 183. Epic A: Repository and architecture foundation

- [ ] **P0 A001** Create `rabs-protocol`, `rabs-action`, `rabs-key`, `rabs-cas`, `rabs-sandbox`, `rabs-scheduler`, and `rabs-asupersync` crates, with explicit edge/coordinator/worker roles.
- [ ] **P0 A002** Add dependency-direction CI that forbids domain crates from depending on `rabs-asupersync`, Tokio, network servers, or daemon crates.
- [ ] **P0 A003** Pin an exact Asupersync revision and record the pin in an architecture decision record.
- [ ] **P0 A004** Define the minimal `rabs-profile` Asupersync feature set and generate a dependency/feature inventory artifact.
- [ ] **P0 A005** Establish key, protocol, database, object-manifest, and sandbox schema version registries.
- [ ] **P0 A006** Add stable reason-code registry generation and validation.
- [ ] **P0 A007** Create a shared redaction library and data-classification policy.
- [ ] **P0 A008** Add architecture boundary tests ensuring public CLI/wire/persistence types contain no Asupersync types.
- [ ] **P1 A009** Add consumer-driven adapter tests against the pinned Asupersync revision.
- [ ] **P1 A010** Add upgrade bot/report that identifies public API or feature-graph changes in Asupersync before pin updates.
- [ ] **P1 A011** Create unsafe-boundary ledger entries for sandbox/process/network helpers.
- [ ] **P1 A012** Add supply-chain/dependency budget gates for edge, coordinator, and worker binaries.
- [ ] **P0 A013** Define single-active coordinator authority acquisition and combined-role deployment contract.
- [ ] **P0 A014** Define semantic action descriptor versus non-key request/presentation context.
- [ ] **P0 A015** Define supported platform/isolation authority matrix and explicit no-claims.
- [ ] **P0 A016** Align RCH/RABS Cargo license metadata, license files, SBOMs, and release notices with the rider-bearing license.
- [ ] **P0 A017** Define `BuildOperation`, logical action, execution attempt, and subscriber delivery as separate persistence/state-machine domains.
- [ ] **P0 A018** Split canonical result, attempt evidence, auxiliary incremental state, and publication record schemas; add semantic/observable/evidence divergence taxonomy.
- [ ] **P0 A019** Define byte-preserving Unix path/argv/environment wire types and escaped presentation types.
- [ ] **P0 A020** Define immutable publication, append-only evidence index, and versioned trust-evaluation schemas/policies.
- [ ] **P0 A021** Split tiny-wrapper and daemon/worker release profiles and gate them on startup/throughput corpus benchmarks.
- [ ] **P0 A022** Define immutable publication history separately from mutable serving/index/trust disposition.
- [ ] **P0 A023** Define RABS-owned causal timestamp, deadline budget, duration, peer, authority, and sequence-domain wire types; forbid Asupersync type leakage.
- [ ] **P0 A024** Make BuildOperation requested/resolved snapshot lineage and sealed action-generation binding explicit in all domain schemas.

## 184. Epic B: Record/replay and benchmark corpus

- [ ] **P0 B001** Define invocation-record schema with argv, normalized env, cwd mapping, tool identity, outcome, and timing.
- [ ] **P0 B002** Implement redacted recorder in the existing RCH wrapper/daemon path.
- [ ] **P0 B003** Capture rustc, linker, build-script, native compiler, Cargo whole-command, and nextest contexts.
- [ ] **P0 B004** Store input and output digests without storing source contents by default.
- [ ] **P0 B005** Build replay runner that can execute stock and candidate RABS paths.
- [ ] **P0 B006** Add scenario labels: clean, no-op, leaf edit, root edit, branch switch, agent storm, CI, IDE.
- [ ] **P0 B007** Create corpus retention, privacy, export, and minimization policies.
- [ ] **P0 B008** Implement benchmark report with p50/p90/p95 whole-command and action-level metrics.
- [ ] **P0 B009** Capture sccache and current RCH baselines.
- [ ] **P1 B010** Add automatic replay selection stratified by action class, duration, repo, and toolchain.
- [ ] **P1 B011** Add divergence minimizer that extracts the smallest reproducing action/input manifest.
- [ ] **P1 B012** Add intent-to-green reconstruction from agent session timelines.
- [ ] **P1 B013** Add CI regression gates against the corpus.

## 185. Epic C: Tiny wrapper and local daemon protocol

- [ ] **P0 C001** Define local protocol version handshake.
- [ ] **P0 C002** Implement bounded Unix-socket framing and event streaming.
- [ ] **P0 C003** Implement peer-credential checks on supported Unix platforms.
- [ ] **P0 C004** Implement wrapper connection timeout and circuit breaker.
- [ ] **P0 C005** Define separate silent/transcript-exposed/stateful-commit-intent/stateful-commit delivery frontiers.
- [ ] **P0 C006** Implement immediate original-command fallback only before transcript exposure and stateful commit intent, plus explicit labeled transcript recovery where configured.
- [ ] **P0 C007** Stream stdout/stderr/JSON without whole-output buffering.
- [ ] **P0 C008** Preserve exact exit code and signal mapping.
- [ ] **P0 C009** Add stable/beta/nightly argv/env/JSON fixture matrix.
- [ ] **P0 C010** Measure startup and request overhead; gate p95 below 10 ms.
- [ ] **P1 C011** Support client disconnect as subscriber cancellation without destroying shared work.
- [ ] **P1 C012** Add wrapper self-diagnostics and protocol compatibility output.
- [ ] **P1 C013** Add `RUSTC_WRAPPER` first-enable cold-rebuild warning/doctor check.
- [ ] **P0 C014** Implement resumable request/subscriber tokens and edge-restart reconnect sequencing.
- [ ] **P0 C015** Implement bounded wrapper-chain recursion detection and authenticated internal self-host bypass.
- [ ] **P0 C016** Implement SIGINT/SIGTERM/SIGHUP, parent-death, and UDS-disconnect subscriber cancellation with exact signal mapping.
- [ ] **P0 C017** Isolate each subscriber behind a bounded/spillable queue so a slow client cannot stall shared action progress.
- [ ] **P1 C018** Add explicit uncoordinated-local-fallback telemetry and degraded compile-storm benchmark.
- [ ] **P0 C019** Implement write-ahead stateful delivery intent, full-write acknowledgement, iterative sequence replay, reconnect resolution, and `DeliveryUncertain` fail-closed behavior.
- [ ] **P0 C020** Revoke subscriber materialization rights atomically before local fallback and prove no late remote output enters the operation.
- [ ] **P0 C021** Implement transcript-only sequencing and the explicit labeled-recovery policy without fsync-per-diagnostic overhead.
- [ ] **P0 C022** Add a nonprinting pre-exposure panic hook, top-level unwind containment, and prohibit abort-on-panic unless a minimal parent guard proves original-chain fallback.
- [ ] **P0 C023** Implement transcript-intent/in-flight/uncertain sequencing and partial-write recovery.
- [ ] **P0 C024** Preserve Unix signal termination by re-signalling the wrapper where supported; test against stock Cargo.
- [ ] **P0 C025** Define and fence edge boot/incarnation/handoff state for live wrapper resumption.
- [ ] **P0 C026** Implement complete-frame transcript acknowledgement/resume with last-accepted and possibly-in-flight sequence reporting, without per-line fsync.

## 186. Epic D: Canonical execroot and path handling

- [ ] **P0 D001** Define primary-workspace fixed path and stable logical IDs for additional path-dependency repositories.
- [ ] **P0 D002** Define canonical visible path layout that forbids action/attempt/snapshot IDs and a separate hidden backing-path policy.
- [ ] **P0 D003** Implement Linux canonical Cargo-driver namespace and nested action-view materializer.
- [ ] **P0 D004** Mount immutable source snapshot read-only.
- [ ] **P0 D005** Mount canonical toolchain, sysroot, registry, git source, output, and temp roots.
- [ ] **P0 D006** Implement stable logical `OUT_DIR`, incremental, temp, home, and secret-slot mappings.
- [ ] **P0 D007** Implement path-remap flag injection by toolchain capability.
- [ ] **P0 D008** Implement virtual-to-real JSON diagnostic rewriting.
- [ ] **P0 D009** Implement dep-info path rewriting/materialization.
- [ ] **P0 D010** Implement mtime choreography and repeated-hit tests.
- [ ] **P0 D011** Build cross-worktree descriptor/output equality test suite.
- [ ] **P0 D012** Build path leak scanner for outputs and metadata.
- [ ] **P1 D013** Implement and prove a macOS canonical process root via VM/chroot helper; APFS clones alone are not sufficient.
- [ ] **P1 D014** Define platform-specific portability classes.
- [ ] **P1 D015** Add checksum-freshness opt-in and differential tests.
- [ ] **P1 D016** Add symlink/xattr/permission policy tests.
- [ ] **P1 D017** Add canonical pseudo-files and hostname/locale/timezone setup.
- [ ] **P0 D018** Implement coherent snapshot capture with mutation detection/retry and path-dependency closure.
- [ ] **P0 D019** Verify Cargo-generated `-C metadata`, unit hashes, output names, and child argv converge across worktrees.
- [ ] **P0 D020** Add invariant test that no visible path contains an action, attempt, operation, or snapshot ID.
- [ ] **P1 D021** Add macOS VM/chroot and host-audit differential authority tests.
- [ ] **P0 D022** Define and key filesystem semantic classes, including case/Unicode/symlink/permission behavior.
- [ ] **P0 D023** Prohibit writable CAS hardlinks and add inode-alias corruption tests.
- [ ] **P0 D024** Implement exclusive/private mutable target-state leases and whole-command target cloning.
- [ ] **P0 D025** Bind build-script actions to Cargo-provided `OUT_DIR` plus pre-state/post-state replacement semantics.
- [ ] **P0 D026** Capture or canonicalize stat/metadata, umask, rlimit, CPU-count/affinity, argv0/cwd, and inherited-FD semantics.
- [ ] **P0 D027** Add runtime-visible canonical-path portability scanner and local-only classification for build-path-dependent binaries.
- [ ] **P0 D028** Implement canonical dep-info storage plus byte-correct subscriber-specific derivation and bypass-on-unsafe-rewrite.
- [ ] **P0 D029** Implement edge content-identity index, digest singleflight, watcher-overflow detection, and periodic rehash audit.
- [ ] **P0 D030** Implement `BuildPathSemanticPolicy`, original-vs-canonical differential fixtures, and the path-preserving lane.
- [ ] **P0 D031** Implement per-build destination-path reservations and disjoint-bundle materialization concurrency tests.
- [ ] **P0 D032** Implement requested→resolved execution snapshot lineage for Cargo fetch/resolution/lockfile mutation.

## 187. Epic E: Sandbox and observed-input discovery

- [ ] **P0 E001** Define sandbox profile schema by `ActionClass`.
- [ ] **P0 E002** Implement default-deny network namespace on Linux.
- [ ] **P0 E003** Implement scrubbed/fixed environment builder.
- [ ] **P0 E004** Implement cgroup v2 resource envelope setup.
- [ ] **P0 E005** Implement filesystem read/write/exec observation prototype and benchmark overhead.
- [ ] **P0 E006** Parse rustc dep-info into canonical input identities.
- [ ] **P0 E007** Integrate binary dependency dep-info where available.
- [ ] **P0 E008** Capture subprocess/tool invocation graph.
- [ ] **P0 E009** Detect network/git/hostname effects where enforceable and classify clock/randomness according to the isolation profile without assuming syscall tracing is complete.
- [ ] **P0 E010** Define positive input, negative dependency, exact presented-environment, and isolation-evidence schemas.
- [ ] **P0 E011** Implement first-run discovery and recipe persistence.
- [ ] **P0 E012** Implement recipe reuse, validation, and re-discovery on drift.
- [ ] **P0 E013** Implement volatility classification and reason codes.
- [ ] **P0 E014** Add proc-macro untracked-file/env regression fixtures.
- [ ] **P0 E015** Add build-script rerun/metadata directive capture.
- [ ] **P1 E016** Implement project capability policy for controlled network/secrets/git metadata.
- [ ] **P1 E017** Add macOS observation strategy and explicit soundness boundary.
- [ ] **P1 E018** Add sampled re-audit scheduler for previously stable actions.
- [ ] **P1 E019** Add sandbox failure bundle and doctor probes.
- [ ] **P0 E020** Capture failed opens, directory enumerations, symlink chains, and executable lookup negative dependencies.
- [ ] **P0 E021** Enforce the closed authoritative filesystem view and abort/re-discover on a new read.
- [ ] **P0 E022** Add vDSO clock and alternate entropy regression fixtures; classify unsupported profiles volatile.
- [ ] **P1 E023** Add source-snapshot path escape and concurrent-mutation fuzz/property tests.
- [ ] **P0 E024** Require a second closed-view validation execution before first authoritative publication for newly discovered action families, except narrowly admitted immutable fast-path classes.
- [ ] **P0 E025** Add explicit Cargo dependency fetch/resolution object capture and offline canonical execution.
- [ ] **P0 E026** Add workspace-mutation overlay/receipt/conflict-safe replay or bypass for Cargo.lock and manifest writes.
- [ ] **P0 E027** Implement project source-capture policy with denied/local-only/secret-capability classes; never use `.gitignore` as authority.
- [ ] **P0 E028** Record observable directory order and metadata fields or classify the action nonportable/volatile.
- [ ] **P0 E029** Add cgroup/PID-namespace or VM descendant-containment proof beyond process-group membership.
- [ ] **P0 E030** Implement explicit external-input capabilities with stable virtual mounts, object/version/privacy identity, bounded tree closure, and local/volatile fallback for undeclared host reads.

## 188. Epic F: Action keys and explainability

- [ ] **P0 F001** Define canonical serialization for every key component.
- [ ] **P0 F002** Implement `ActionKeyEpoch` registry and invalidation policy.
- [ ] **P0 F003** Implement normalized rustc invocation parser.
- [ ] **P0 F004** Resolve `--extern` paths to content identities.
- [ ] **P0 F005** Normalize response files by content.
- [ ] **P0 F006** Implement exact minimal environment construction/hashing, absent-variable semantics, canonical PATH, and opaque secret-version digests.
- [ ] **P0 F007** Implement `ToolchainContract` and toolchain dataset digest.
- [ ] **P0 F008** Split `OutputPlatformContract` from scheduler-only `ExecutionEligibility`, including CPU/SDK/deployment baselines.
- [ ] **P0 F009** Implement conservative exact dependency-artifact identity; use `.rmeta` only when that is the artifact actually supplied.
- [ ] **P0 F010** Implement versioned dependency projection framework and LTO/exact-artifact ambiguity fail-closed rules.
- [ ] **P0 F011** Implement output declaration digest.
- [ ] **P0 F012** Return `ActionKeyBreakdown` with every key.
- [ ] **P0 F013** Implement key diff and stable miss-cause taxonomy.
- [ ] **P0 F014** Add property tests: irrelevant path/agent differences preserve key.
- [ ] **P0 F015** Add mutation tests: every semantic input changes key.
- [ ] **P0 F016** Implement stable source-independent `ActionFamilyKey`, `DiscoveryActor`, and recipe epochs.
- [ ] **P1 F017** Add future `public_api_hash` extension point.
- [ ] **P1 F018** Add key fragmentation aggregation.
- [ ] **P0 F019** Separate full `ExecutionSnapshotRoot` from fine-grained `ActionInputManifest` in schemas and keys.
- [ ] **P0 F020** Add key mutation tests for newly created files, changed directories, PATH alternatives, and separately modeled absent environment values.
- [ ] **P0 F021** Add `PresentationContract` and canonical compiler-event replay variants without fragmenting semantic keys.
- [ ] **P0 F022** Add exact-versus-projected dependency differential framework and automatic projection rollback.
- [ ] **P0 F023** Define structured `CoordinatorAuthority`, `ActionGeneration`, independent `ExecutionLeaseId`, and worker boot generation.
- [ ] **P0 F024** Store the canonical descriptor object/bytes plus an independent descriptor digest and verify them on every hit to detect serialization, indexing, or collision bugs.
- [ ] **P0 F025** Keep compiler-event and pipelining contracts in request/presentation context unless a versioned proof shows that a setting changes semantic output or exit behavior.
- [ ] **P0 F026** Scope every action-family recipe by stable logical repository identity to prevent unrelated packages with similar unit shapes from sharing discovery recipes.
- [ ] **P0 F027** Ensure environment absence is represented only in `PresentedEnvironment`, not duplicated in filesystem negative dependencies.
- [ ] **P0 F028** Add `BuildPathSemanticPolicy` to descriptor/key breakdown and explain path-policy fragmentation.
- [ ] **P0 F029** Add worker process-incarnation identity and one-active-incarnation fencing to attempt/session schemas.
- [ ] **P0 F030** Remove duplicate working-directory representation and add schema-consistency assertions.
- [ ] **P0 F031** Implement opaque never-reused action-generation IDs and retained ABA-fence tombstones.
- [ ] **P0 F032** Implement publication-history versus serving-disposition transitions, including expiry/revalidation.
- [ ] **P0 F033** Bind each action generation to the canonical creating-authority digest while carrying one full coordinator-authority value in attempt/publication identities; reject representation mismatch.
- [ ] **P0 F034** Specify typed SHA-256 V1 action/schema/authority digest domains, canonical length framing, algorithm migration epochs, and cross-domain comparison rejection.
- [ ] **P0 F035** Define one authoritative role-tagged logical-output map; derive dep-info/build-script/provisional indexes and verify artifact-bundle-root consistency without duplicate manifest fields.

## 189. Epic G: Asupersync runtime, regions, and process lifecycle

- [ ] **P0 G001** Define coordinator and worker region-tree constructors.
- [ ] **P0 G002** Implement RABS obligation adapters.
- [ ] **P0 G003** Implement `ActionActor` on an Asupersync-owned region.
- [ ] **P0 G004** Implement subscriber interest and promotion.
- [ ] **P0 G005** Implement reference-counted cancellation.
- [ ] **P0 G006** Integrate managed process groups and worker-local jobserver.
- [ ] **P0 G007** Implement bounded stdout/stderr drain and spill objects.
- [ ] **P0 G008** Implement graceful TERM → drain → escalation → reap.
- [ ] **P0 G009** Implement precise process termination classification.
- [ ] **P0 G010** Configure supervision policies and restart budgets.
- [ ] **P0 G011** Add action/attempt crashpack generation.
- [ ] **P0 G012** Add lab cancellation-at-every-await suite.
- [ ] **P0 G013** Add nested-runtime prohibition and regression tests.
- [ ] **P1 G014** Add drained race helper for local/remote/hedged attempts.
- [ ] **P1 G015** Add obligation leak and quiescence dashboards.
- [ ] **P1 G016** Migrate current RCH cancellation debt into unified policy.
- [ ] **P0 G017** Implement edge subscriber proxy, coordinator action actor, and worker attempt actor as separate ownership roles.
- [ ] **P0 G018** Implement transcript and stateful-observable obligations plus the safe pre-exposure nonpublishing fallback frontier.
- [ ] **P0 G019** Add coordinator authority fencing and stale-coordinator lab scenarios.
- [ ] **P0 G020** On coordinator term/incarnation change, close prior-authority active generations and reissue publication-eligible work only in fresh authority-bound generations.

## 190. Epic H: Durable CAS and metadata

- [ ] **P0 H001** Define object, chunk, manifest, and artifact-bundle schemas.
- [ ] **P0 H002** Implement streaming ATP content ID, BLAKE3, and optional raw SHA-256.
- [ ] **P0 H003** Implement filesystem blob/chunk store with `put_if_absent`.
- [ ] **P0 H004** Implement deterministic content-defined chunking profile.
- [ ] **P0 H005** Implement zstd policy and metrics.
- [ ] **P0 H006** Implement tree manifests and missing-chunk diff.
- [ ] **P0 H007** Implement staging directories and append journals.
- [ ] **P0 H008** Implement sparse/out-of-order writer and recovery.
- [ ] **P0 H009** Implement metadata-store interface, reference SQLite schema/migrations, and FrankenSQLite differential backend.
- [ ] **P0 H010** Implement object edges, locations, pins, and leases.
- [ ] **P0 H011** Implement worker prepared-result offer and coordinator-only atomic action publication transaction.
- [ ] **P0 H012** Implement separate location, logical-object/manifest, and action-entry quarantine flows.
- [ ] **P0 H013** Implement startup consistency reconciliation.
- [ ] **P0 H014** Implement dry-run and active-safe GC.
- [ ] **P0 H015** Add crash-injection matrix for every publication boundary.
- [ ] **P0 H016** Add property test that GC preserves all pinned/reachable objects.
- [ ] **P1 H017** Add reflink materialization backend.
- [ ] **P1 H018** Add cold-store adapter.
- [ ] **P1 H019** Add peer object seeding.
- [ ] **P1 H020** Add storage-value model by action class and recomputation cost.
- [ ] **P0 H021** Implement deterministic small-object packs and bounded member indexes.
- [ ] **P0 H022** Implement mark/tombstone/grace/unlink GC and open-reader race tests.
- [ ] **P0 H023** Add periodic scrub and location-repair workflows.
- [ ] **P0 H024** Gate FrankenSQLite authority on reference-backend differential, crash, migration, and concurrency suites.
- [ ] **P1 H025** Add project namespace ACL/encryption-at-rest profile for sensitive objects.
- [ ] **P0 H026** Implement same-key/different-semantic-result conflict quarantine, observable-only quarantine, and preservation of all candidate evidence.
- [ ] **P0 H027** Validate manifest paths/types/case-equivalence/symlink containment before storage and materialization.
- [ ] **P0 H028** Implement transitive provisional-ancestor closure and exact-object adoption checks in the commit transaction.
- [ ] **P0 H029** Implement canonical-result/attempt-evidence/publication separation and compatible-evidence append behavior.
- [ ] **P0 H030** Implement storage representation IDs and support multiple verified encodings per logical object without path ambiguity.
- [ ] **P0 H031** Add acyclic manifest-closure, depth/fan-out, and pack range-overlap validation.
- [ ] **P0 H032** Gate commit acknowledgement on explicit CAS-directory plus metadata-transaction durability profile.
- [ ] **P0 H033** Implement append-only evidence indexing and versioned trust-evaluation promotion/demotion without mutating publication identity.
- [ ] **P0 H034** Retain semantic/observable result digests in eviction tombstones long enough to detect recomputation divergence after blob eviction.
- [ ] **P0 H035** Detect equal-projection/different-canonical-manifest conflicts and quarantine as serializer/projection-completeness incidents.
- [ ] **P0 H036** Create the action-publication reachability root/pin atomically in the publication transaction.
- [ ] **P0 H037** Define authority/publication metadata-loss recovery versus explicit cluster credential/reset generation.
- [ ] **P0 H038** Add action generation/tombstone, immutable publication, serving state, evidence/trust, peer high-water, incarnation-fence, and atomic publication-pin tables/constraints.
- [ ] **P0 H039** Enforce canonical logical-output-map role uniqueness and deterministic artifact-bundle-root derivation; reject duplicate or contradictory specialized output indexes.
- [ ] **P0 H040** Implement revisioned authority-bound serving-state records with conservative durable TTL/clock-epoch semantics and explicit blocking-quarantine references.
- [ ] **P0 H041** Implement authority-scoped pin leases, monotonic renewal/release, restart/partition grace, and fail-toward-retention reconciliation; forbid worker release of publication roots.

## 191. Epic I: Scheduler and jobserver

- [ ] **P0 I001** Implement coordinator-owned Cargo root-permit broker plus host/worker-local jobservers.
- [ ] **P0 I002** Acquire a root permit before every managed Cargo process and inject a valid local jobserver for its process tree.
- [ ] **P0 I003** Strip invalid local descriptors from remote action requests.
- [ ] **P0 I004** Create worker-local jobserver bridge.
- [ ] **P0 I005** Define action resource-envelope schema.
- [ ] **P0 I006** Collect CPU/memory/IO/disk/cache/toolchain/path snapshots.
- [ ] **P0 I007** Adapt Asupersync RCH health policy to worker candidate receipts.
- [ ] **P0 I008** Implement hard eligibility exclusions.
- [ ] **P0 I009** Implement predicted completion and transfer break-even score.
- [ ] **P0 I010** Implement weighted fairness and starvation limits.
- [ ] **P0 I011** Implement foreground/optional/cleanup classes.
- [ ] **P0 I012** Integrate SLO brownout for speculation.
- [ ] **P0 I013** Add advisory pool-sizing reports.
- [ ] **P0 I014** Add fifteen-agent storm and pressure-collapse tests.
- [ ] **P1 I015** Build provenance-DAG critical-path estimator.
- [ ] **P1 I016** Implement safe hedging policy, compare-and-set winner validation, and semantic/observable divergence handling.
- [ ] **P1 I017** Add managed pool sizing behind opt-in and replay gate.
- [ ] **P0 I018** Implement one active coordinator action registry shared by all edge hosts.
- [ ] **P0 I019** Add root-permit implicit-token accounting tests across many simultaneous Cargo processes.
- [ ] **P1 I020** Specify and benchmark V1 same-worker child execution; keep second-hop dispatch disabled.
- [ ] **P0 I021** Model each Cargo grant as one implicit token plus `C-1` transferable tokens and prove acyclic permit ordering.
- [ ] **P1 I022** Add hedge tests proving sibling execution leases remain independent within one action generation.
- [ ] **P0 I023** Separate Cargo submission-frontier grants from selected-worker/local execution resource grants across all planes.
- [ ] **P0 I024** Reorder input/disk/execution/jobserver acquisition so no compiler token is held during bulk transfer.
- [ ] **P0 I025** Bound provisional-lineage waiters and reserve producer progress capacity per Cargo root.
- [ ] **P0 I026** Shard coordinator action/discovery registries and bounded mailboxes, isolate critical queues, minimize serialized metadata sections, and gate on burst/storm/recovery capacity metrics.

## 192. Epic J: ATP protocol and native transport

- [ ] **P0 J001** Replace/sort ATP extension maps for canonical frame encoding.
- [ ] **P0 J002** Create ATP/RABS version negotiation schema.
- [ ] **P0 J003** Add golden frame/message fixtures.
- [ ] **P0 J004** Define bounded RABS application envelope.
- [ ] **P0 J005** Implement durable build-operation/action-generation/attempt/execution-lease identifiers.
- [ ] **P0 J006** Implement closed remote computation registry and version checks.
- [ ] **P0 J007** Implement per-peer bounded priority queues.
- [ ] **P0 J008** Reserve control/cancel/lease capacity independently of bulk data.
- [ ] **P0 J009** Bind durable ATP peer identity to TLS/transport identity.
- [ ] **P0 J010** Harden managed QUIC event loop to reactor-driven wakeups.
- [ ] **P0 J011** Replace core wall-clock reads with injected/runtime time.
- [ ] **P0 J012** Implement edge/worker heartbeat, action, lease, cancel, coordinator-authority, ordered event, and reconciliation messages.
- [ ] **P0 J013** Implement bounded missing-object queries, deterministic packs, range/bitmap transfer acknowledgements, credit, and resume.
- [ ] **P0 J014** Add Tailscale path candidates and direct-path preference.
- [ ] **P0 J015** Add TCP/TLS or SSH fallback decision records.
- [ ] **P0 J016** Build native-control shadow comparator against current RCH.
- [ ] **P0 J017** Run interop, loss, long-idle, burst, and multi-day soak suites.
- [ ] **P1 J018** Add adaptive packet/stream batching.
- [ ] **P1 J019** Add worker-to-worker seeding stream.
- [ ] **P2 J020** Evaluate RaptorQ only on measured lossy path corpus.
- [ ] **P2 J021** Evaluate multi-path/fan-out only after single-path core is stable.
- [ ] **P0 J022** Disable and test state-changing QUIC 0-RTT replay.
- [ ] **P0 J023** Implement independent monotonic per-domain sequence/replay windows, bounded retention, causal references, and reconnect resume.
- [ ] **P0 J024** Replace worker commit message with prepared-result offer and coordinator committed-result notification.
- [ ] **P0 J025** Add message recursion/decompression/count limit fuzzing.
- [ ] **P0 J026** Implement monotonic TTL/renewal lease semantics independent of cross-host wall-clock synchronization.
- [ ] **P0 J027** Use a dedicated control connection or pass control-latency-under-bulk saturation gates before authoritative cutover.
- [ ] **P0 J028** Bind handshake/session/leases to worker boot generation plus fresh process-incarnation ID and reject duplicate incarnations.
- [ ] **P0 J029** Implement independent protocol sequence domains with explicit cross-domain causal references.
- [ ] **P0 J030** Add edge incarnation/handoff negotiation and subscriber-materialization fencing.
- [ ] **P0 J031** Align ATP delivery messages with transcript-intent/ack/uncertainty, stateful-intent/ack/uncertainty, delivery-complete, and reconnect state machines.

## 193. Epic K: Cargo/rustc dependency serving

- [ ] **P0 K001** Identify immutable registry/git dependency actions reliably.
- [ ] **P0 K002** Build dependency source snapshot manifests.
- [ ] **P0 K003** Implement local dependency cache lookup.
- [ ] **P0 K004** Implement result materialization with `.rmeta` first.
- [ ] **P0 K005** Replay exact rustc artifact-notification JSON lines after each named output is fully materialized; do not synthesize Cargo outward messages.
- [ ] **P0 K006** Replay diagnostics/stdout/stderr faithfully.
- [ ] **P0 K007** Implement deterministic-failure publication classification plus TTL-governed serving/revalidation.
- [ ] **P0 K008** Implement dependency shadow comparison and serving sample gate.
- [ ] **P0 K009** Add `rch why` for dependency hits/misses/refusals.
- [ ] **P0 K010** Add local/worker/toolchain cache inventory reporting.
- [ ] **P1 K011** Enable remote dependency action execution over ATP.
- [ ] **P1 K012** Add cross-worker determinism audits.
- [ ] **P0 K013** Distinguish rustc artifact notifications from Cargo outward JSON messages in event fixtures.
- [ ] **P0 K014** Add presentation-variant replay or safe structured re-rendering tests.
- [ ] **P0 K015** Capture effective Cargo configuration provenance, source replacement, target runner/linker, aliases, and credential-helper references.
- [ ] **P0 K016** Implement explicit Cargo command eligibility matrix, including compile-only acceleration for `run` and non-cacheable benchmark timing.
- [ ] **P1 K017** Add rust-analyzer canonical Cargo-launch integration and reduced-authority fallback tests.
- [ ] **P0 K018** Classify rustc/Cargo capability probes and preserve exact tiny stdout/exit semantics without remote-dispatch tax.
- [ ] **P0 K019** Preserve effective Cargo-config origin and origin-relative path semantics in canonical planning.

## 194. Epic L: Link and native build acceleration

- [ ] **P0 L001** Implement exact link invocation parser/key.
- [ ] **P0 L002** Hash ordered object/archive/shared-library inputs.
- [ ] **P0 L003** Normalize linker response files and scripts.
- [ ] **P0 L004** Implement link result bundle and diagnostics replay.
- [ ] **P0 L005** Implement Wild/lld/system linker profile detection.
- [ ] **P0 L006** Implement `CC/CXX/AR` wrappers.
- [ ] **P0 L007** Capture native header closure.
- [ ] **P0 L008** Integrate native child actions into build-script provenance.
- [ ] **P0 L009** Add native/link shadow and cross-worker tests.
- [ ] **P1 L010** Add CMake/meson launcher integration where safe.
- [ ] **P0 L011** Discover/enforce linker implicit search closure: selected and missing `-l`/framework candidates, CRT/startup objects, default scripts, plugins, and included response files.

## 195. Epic M: Workspace action serving and pipelining

- [ ] **P0 M001** Implement workspace rustc action-class detection.
- [ ] **P0 M002** Integrate canonical source snapshots and observed-input recipes.
- [ ] **P0 M003** Implement exact workspace dependency-artifact inputs and gated projection epochs.
- [ ] **P0 M004** Implement provisional `.rmeta` upload and pin.
- [ ] **P0 M005** Implement exactly-once logical `MetadataReady`, complete edge materialization, then rustc artifact-notification replay.
- [ ] **P0 M006** Implement dependent-action provisional obligation.
- [ ] **P0 M007** Implement producer failure invalidation and dependent cancellation.
- [ ] **P0 M008** Prevent dependent result commit before producer finalization.
- [ ] **P0 M009** Build action DAG edges from artifact identities.
- [ ] **P0 M010** Run large stock differential shadow corpus.
- [ ] **P0 M011** Add selected-repo sampled serving and quarantine switch.
- [ ] **P1 M012** Run rmeta equality/skip-rate corpus experiment.
- [ ] **P1 M013** Add future public API hash adapter.
- [ ] **P0 M014** Require canonical Cargo-driver provenance before workspace shared publication.
- [ ] **P0 M015** Add full-snapshot-key versus minimal-closure-key hit-rate and invalidation benchmark.
- [ ] **P0 M016** Add producer-failure-after-Cargo-metadata-notification end-to-end tests.
- [ ] **P0 M017** Propagate and transactionally verify transitive provisional lineage, including different-winning-attempt adoption.
- [ ] **P0 M018** Keep shared incremental serving disabled until every incremental input/output state is explicit and gated.
- [ ] **P0 M019** Journal provisional subscriber materializations and implement ownership-safe invalidation/dirty-target recovery after lineage failure.
- [ ] **P0 M020** Withhold descendant terminal success/final readiness until transitive provisional lineage closes, while retaining early-metadata pipelining.

## 196. Epic N: Build-script run cache

- [ ] **P0 N001** Prove canonical-Cargo interception and launcher-shim contracts across stable/beta/nightly; disable run-cache serving if neither preserves semantics.
- [ ] **P0 N002** Capture exact stdout/stderr and Cargo directives.
- [ ] **P0 N003** Capture generated output manifest.
- [ ] **P0 N004** Reconstruct `DEP_<LINKS>_*` metadata semantics on replay.
- [ ] **P0 N005** Apply registry-aggressive/workspace-audit-first policy.
- [ ] **P0 N006** Detect vergen/built/time/git/network patterns.
- [ ] **P0 N007** Add deterministic re-execution audits and denylist.
- [ ] **P0 N008** Add zero-divergence gate and cacheability report.
- [ ] **P1 N009** Add explicit captured-fetch action pattern for network generators.
- [ ] **P0 N010** Verify failed/cancelled build-script state is never published as a shared cache hit and live-operation post-state follows the explicit parity/local policy.
- [ ] **P0 N011** Add exact ordered directive/stdout golden fixtures including `DEP_<LINKS>_*`.
- [ ] **P0 N012** Include pre-run `OUT_DIR`/Cargo output-cache state in eligible keys and atomically replace complete post-state with deletions.
- [ ] **P0 N013** Preserve failed/cancelled build-script live-operation post-state or execute locally; never publish it as a shared hit.
- [ ] **P0 N014** Parse and validate structured Cargo directives, close every path-valued/native-link dependency, and prove exact replay after output-tree installation.

## 197. Epic O: Test actions

- [ ] **P0 O001** Define nextest runner protocol.
- [ ] **P0 O002** Implement per-test and policy-selected batch keys.
- [ ] **P0 O003** Capture fixture/config positive and negative inputs, exact environment, subprocesses, network/time/randomness, and declared side effects.
- [ ] **P0 O004** Cache stable passing results.
- [ ] **P0 O005** Implement deterministic failure and flaky classifications.
- [ ] **P0 O006** Preserve nextest output/timing/retry semantics.
- [ ] **P0 O007** Add periodic full-suite verification.
- [ ] **P0 O008** Add zero-incorrect-pass gate.
- [ ] **P1 O009** Build affected-test advisory graph.
- [ ] **P1 O010** Add doctest compile/run action support.
- [ ] **P0 O011** Prove nextest target-runner/interception cwd, env, signal, retry, and output semantics before serving.
- [ ] **P0 O012** Add side-effecting/setup/fixture-generation ineligibility fixtures.
- [ ] **P1 O013** Add mandatory periodic uncached full-suite policy for release lanes.
- [ ] **P0 O014** Detect suite-order/setup/shared-state coupling and force batch/suite actions or bypass.
- [ ] **P0 O015** Key nextest setup scripts, runner profile, retry/timeout/fail-fast policy, and classify retry-only passes as flaky.
- [ ] **P0 O016** Enforce non-result-cacheable benchmark-run policy and matching hardware/load evidence.

## 198. Epic P: Incremental snapshots and time travel

- [ ] **P1 P001** Define incremental snapshot compatibility contract.
- [ ] **P1 P002** Capture output artifacts and matching state atomically.
- [ ] **P1 P003** Implement FastCDC/zstd snapshot manifest.
- [ ] **P1 P004** Build git/source-state ancestry index.
- [ ] **P1 P005** Implement nearest compatible ancestor selection.
- [ ] **P1 P006** Estimate transfer-versus-rebuild ROI.
- [ ] **P1 P007** Implement branch/worktree prewarm.
- [ ] **P1 P008** Implement per-repo snapshot retention and GC.
- [ ] **P1 P009** Run branch ping-pong benchmark and portability differential.
- [ ] **P2 P010** Disable serving if target ROI/storage gates fail.
- [ ] **P1 P011** Materialize immutable snapshots as per-attempt private writable clones and atomically capture quiescent incremental state with matching outputs; add crash/cancellation cleanup.

## 199. Epic Q: Speculation and agent intelligence

- [ ] **P1 Q001** Implement filesystem edit watcher with stable write debounce.
- [ ] **P1 Q002** Build likely-next-command model from session corpus.
- [ ] **P1 Q003** Generate immutable speculative source snapshots.
- [ ] **P1 Q004** Submit low-priority speculative actions.
- [ ] **P1 Q005** Implement promotion to foreground without restarting.
- [ ] **P1 Q006** Integrate SLO brownout and pressure cancellation.
- [ ] **P1 Q007** Implement git checkout/HEAD/worktree prewarm events.
- [ ] **P1 Q008** Implement CI canonical prewarm/trust tier.
- [ ] **P1 Q009** Build speculation ROI dashboard.
- [ ] **P1 Q010** Gate default-on behavior on positive p95 value.
- [ ] **P1 Q011** Build key-fragmentation analyzer.
- [ ] **P1 Q012** Build `rch advise` evidence reports.

## 200. Epic R: Explainability and operations

- [ ] **P0 R001** Implement stable decision receipt persistence.
- [ ] **P0 R002** Implement `rch why miss/rebuild/worker/volatile/slow`.
- [ ] **P0 R003** Implement action/operation/object inspection commands.
- [ ] **P0 R004** Implement CAS doctor, verify, locate, and quarantine commands.
- [ ] **P0 R005** Implement GC plan/run/history commands.
- [ ] **P0 R006** Implement worker reconcile and stale-operation doctor.
- [ ] **P0 R007** Implement fleet/cache/latency dashboards.
- [ ] **P0 R008** Implement incident bundle generation and runbook links.
- [ ] **P0 R009** Add schema/protocol compatibility doctor.
- [ ] **P1 R010** Implement fragmentation dashboard and convergence recommendations.
- [ ] **P1 R011** Implement action DAG browser and critical-path report.
- [ ] **P1 R012** Add operator rollback and canary orchestration.

## 201. Epic S: Security and trust

- [ ] **P0 S001** Implement durable coordinator/worker identity store and rotation.
- [ ] **P0 S002** Bind peer identity to transport authentication.
- [ ] **P0 S003** Define capability token/receipt schema.
- [ ] **P0 S004** Implement least-privilege operation checks.
- [ ] **P0 S005** Prevent direct agent CAS/action publication.
- [ ] **P0 S006** Implement provenance and evidence-tier receipt; worker identity evidence does not grant commit authority.
- [ ] **P0 S007** Implement secret redaction and nonshareable classification.
- [ ] **P0 S008** Add per-peer resource manager limits.
- [ ] **P0 S009** Add identity mismatch/replay/downgrade tests.
- [ ] **P0 S010** Add supply-chain and unsafe-boundary review gates.
- [ ] **P1 S011** Implement CI canonical writer trust policy.
- [ ] **P1 S012** Add project-defined release-eligibility policy without claiming cache equivalence proves application correctness.
- [ ] **P0 S013** Implement opaque secret value/version/scope digest support and nonshareable fallback.
- [ ] **P0 S014** Define single-administrative-domain V1 and explicit multi-tenant non-claim.
- [ ] **P0 S015** Add source/output namespace access-control tests.
- [ ] **P0 S016** Separate signing/notarization/publication credentials and effects from ordinary compilation/link caching.
- [ ] **P0 S017** Add license/SBOM/package-metadata conformance gate.
- [ ] **P0 S018** Add compromised-worker threat tests and cross-worker/stock verification policy for release tiers.
- [ ] **P0 S019** Enforce source-object namespace ACLs and pre-upload local-only/secret path policy.
- [ ] **P0 S020** Persist and test peer coordinator-authority high-water marks and operator reset proofs.
- [ ] **P0 S021** Implement per-subscriber minimum evidence/isolation/privacy requirements and versioned trust re-evaluation after new evidence.
- [ ] **P0 S022** Persist worker boot-generation high-water marks, enforce one active incarnation, and define operator reset/clone recovery.
- [ ] **P0 S023** Add hardware-bound enrollment/operator re-enrollment option and explicit no-anti-clone claim for software-only identities.
- [ ] **P0 S024** Implement lexicographic credential-generation/term authority high-water comparison and bounded predecessor-naming edge handoff authorization.

## 202. Epic T: Proof, fuzzing, chaos, and soak

- [ ] **P0 T001** Generate live ATP/RABS coverage ledger from test metadata.
- [ ] **P0 T002** Implement all core deterministic scenarios from Section 146.
- [ ] **P0 T003** Add codec, manifest, key, path, and reconciliation fuzz targets.
- [ ] **P0 T004** Add publication crash-injection matrix.
- [ ] **P0 T005** Add daemon/worker kill and restart chaos suite.
- [ ] **P0 T006** Add disk-full and corruption suite.
- [ ] **P0 T007** Add network partition/loss/reorder suite.
- [ ] **P0 T008** Add high-diagnostics and resource-exhaustion suite.
- [ ] **P0 T009** Add N/N−1 rolling-upgrade suite.
- [ ] **P0 T010** Add multi-day session and action-volume soak.
- [ ] **P0 T011** Add stock differential corpus gate.
- [ ] **P1 T012** Add automated failing-trace minimization.
- [ ] **P1 T013** Add proof artifacts to release process.
- [ ] **P0 T014** Add full-snapshot-versus-minimal-closure invalidation tests.
- [ ] **P0 T015** Add coordinator split-brain/authority-rollback/high-water-mark and edge fail-open frontier scenarios.
- [ ] **P0 T016** Add jobserver implicit-token/root-permit stress tests.
- [ ] **P0 T017** Add location-versus-logical quarantine recovery tests.
- [ ] **P0 T018** Add source-capture concurrent-mutation and negative-dependency tests.
- [ ] **P0 T019** Add independent hedge lease, same-key divergent-result, and compare-and-set race scenarios.
- [ ] **P0 T020** Add transitive provisional A→B→C lineage and adoption scenarios.
- [ ] **P0 T021** Add writable-hardlink/inode-alias and malicious manifest special-file/path-collision fuzz cases.
- [ ] **P0 T022** Add build-script stale-OUT_DIR deletion and suite-coupled-test replay scenarios.
- [ ] **P0 T023** Add Cargo.lock mutation/fetch-index capture and concurrent-worktree-conflict scenarios.
- [ ] **P0 T024** Add stat/umask/CPU-topology/inherited-FD mutation tests.
- [ ] **P0 T025** Add canonical-result-versus-attempt-evidence equivalence and observable-only divergence scenarios.
- [ ] **P0 T026** Add non-UTF8 argv/path/env/symlink round-trip fixtures.
- [ ] **P0 T027** Add watcher-overflow/digest-memoization, source-secret policy, and runtime-path portability tests.
- [ ] **P0 T028** Add process-group escape, slow-subscriber, signal-forwarding, and fail-open stampede scenarios.
- [ ] **P0 T029** Add manifest-cycle/pack-overlap/storage-representation race fuzz cases.
- [ ] **P0 T030** Add canonical-path versus original-path semantic fixtures for `file!`, `CARGO_MANIFEST_DIR`, generated strings, and runtime resource lookup.
- [ ] **P0 T031** Add crash-at-every-delivery-boundary and overlapping-materialization destination-arbiter scenarios.
- [ ] **P0 T032** Add evidence-promotion/demotion, trust-policy change, and post-publication worker-compromise serving tests.
- [ ] **P0 T033** Add local-Cargo/remote-child versus whole-command/local-fallback jobserver grant accounting tests.
- [ ] **P0 T034** Add failed build-script partial-state retry parity fixtures and rustc probe-invocation fixtures.
- [ ] **P0 T035** Add equal-result-digests/different-canonical-manifest serializer-projection incident fixtures.
- [ ] **P0 T036** Add partial-transcript crash/fallback and iterative multi-event subscriber-delivery scenarios.
- [ ] **P0 T037** Add wrapper-panic-before/after-exposure tests for nonprinting unwind containment and guarded-abort profiles.
- [ ] **P0 T038** Add cloned/restored-worker duplicate-incarnation and stale-lease scenarios.
- [ ] **P0 T039** Add action-generation ABA, publication-pin crash, and metadata-loss/reset scenarios.
- [ ] **P0 T040** Add cross-stream bulk-gap versus cancellation/lease sequence-domain scenarios.
- [ ] **P0 T041** Add Cargo requested/resolved snapshot mutation and provisional-waiter jobserver saturation scenarios.
- [ ] **P0 T042** Add action-generation authority-digest mismatch, lexicographic peer high-water rollback, and bounded edge-handoff overlap scenarios.
- [ ] **P0 T043** Add coordinator-restart scenarios proving prior-authority prepared candidates cannot publish and fresh-generation rerun/reissue preserves safety.
- [ ] **P0 T044** Add typed-digest domain/algorithm confusion, canonical-length framing, and simulated existing-digest/different-bytes fail-closed fixtures.
- [ ] **P0 T045** Add build-script path-valued directive and linker implicit-search mutation/negative-lookup differential scenarios.
- [ ] **P0 T046** Add protocol fixture/reconnect tests for transcript and stateful delivery intent, acknowledgement, uncertainty, completion, and edge handoff/fencing messages.
- [ ] **P0 T047** Add duplicate dep-info/build-script/output-role and artifact-bundle-root mismatch canonical-manifest rejection fixtures.
- [ ] **P0 T048** Add serving-TTL expiry, wall-clock rollback/epoch discontinuity, stale state-revision replay, and quarantine-reference recovery scenarios.
- [ ] **P0 T049** Add pin-expiry clock-skew, coordinator/worker restart, contradictory lease, duplicate release, and publication-pin release-attempt GC scenarios.
- [ ] **P0 T050** Add concurrent incremental-snapshot restore, writable-alias, mid-capture crash/cancel, and state/output atomicity scenarios.
- [ ] **P0 T051** Add undeclared absolute host read, external-input capability revocation/version, mutable broad-tree, and canonical external-mount differential scenarios.
- [ ] **P0 T052** Add coordinator mailbox/registry shard hot-key, metadata writer backpressure, slow subscriber, telemetry flood, burst admission, and recovery-scan capacity scenarios.

---

# Part XXVII. Recommended first execution tranche

## 203. First 30 implementation days

The highest-value, lowest-regret tranche is:

1. Create domain crate boundaries, layered state/identity schemas, exact Asupersync/Cargo evidence pins, and correct license/SBOM metadata.
2. Ship Layer 0 profiles and capture stock/sccache/current-RCH baselines.
3. Build the invocation record/replay corpus.
4. Build tiny wrappers and `rabs-edge` with nested-wrapper support, sub-10-ms fail-open, and observable-commit accounting.
5. Implement mutation-safe coherent command snapshots and the Linux canonical Cargo-driver namespace.
6. Prove visible paths contain no action/attempt/snapshot IDs and Cargo-generated unit identities converge.
7. Define full snapshot, minimal positive/negative action closure, exact environment, build-path semantic policy, subscription/attempt context, canonical-result/evidence/publication, and trust-evaluation schemas.
8. Implement Asupersync region/process ownership around the existing SSH/rsync whole-command path.
9. Implement durable local CAS, no-writable-hardlink materialization, metadata-store abstraction, reference SQLite backend, and coordinator-only compare-and-set publication skeleton.
10. Implement dependency shadow keys/lookups with conservative exact artifacts and canonical compiler-event capture.
11. Build `rch why miss` before broad cache serving.
12. Start FrankenSQLite differential/fault testing, but do not make it the sole correctness dependency yet.

No native QUIC cutover, speculative compilation, reduced rlib projection, cross-worker nested dispatch, or incremental snapshots should preempt these items.

## 204. First authoritative serving target

The first served class should be:

```text
immutable registry dependency rustc actions
+ checksummed immutable source
+ conservative exact dependency artifacts
+ exact presented environment
+ canonical toolchain/output platform
+ admitted dependency isolation profile
+ no incremental state
+ no unresolved positive or negative inputs
+ normal successful exit
+ local edge CAS materialization
```

Then add:

1. immutable git dependencies;
2. native subcompiles inside dependency build scripts;
3. exact link cache;
4. remote dependency execution;
5. eligible dependency build-script runs after interception proof;
6. selected workspace crates only through canonical Cargo and minimal enforced closure.

## 205. First flagship demonstration

A compelling staged demo:

1. start fifteen agents across several edge hosts and separate worktrees;
2. launch Cargo through canonical driver namespaces;
3. show coherent snapshots but minimal per-action input closures;
4. run overlapping `check`, `test`, and `clippy` workloads;
5. show one coordinator-owned action actor per identical key across hosts;
6. show `.rmeta` fully materialized and its rustc artifact event replayed before bulk outputs;
7. show worker placement using cache locality, root permits, and pressure receipts;
8. show one agent cancelling without killing shared work;
9. disconnect the coordinator before observable commit and demonstrate safe nonpublishing local fallback;
10. repeat after observable commit and demonstrate coherent failure/reconnect rather than mixed execution;
11. switch branches and restore nearest state after that feature's gate;
12. let the watcher seal a quiescent edited snapshot and start optional speculation, then invoke the matching command to promote that same action actor; a subsequent edit demonstrates supersession rather than false promotion;
13. use `rch why` to show a negative-dependency, exact-artifact, or environment miss;
14. use `rch advise` to identify the rebuild tail.

# Part XXVIII. Definition of done

## 206. Core product definition of done

The core RABS product is done when:

- unmodified Cargo/rustc workflows are transparently accelerated through supported canonical launch paths;
- wrapper/edge fail-open and miss-overhead SLOs hold;
- Linux canonical Cargo execution provides stable cross-worktree unit identities and paths;
- the full coherent command snapshot is distinct from minimal enforced action closures;
- selected action classes include positive, negative, exact-environment, dependency, and platform inputs soundly;
- one active coordinator authority provides fleet-wide singleflight and fencing across edge hosts;
- every managed Cargo process consumes a root permit and valid local jobserver;
- dependency, selected workspace, link, native build, and admitted test results publish atomically through coordinator-only commit; canonical results are separated from attempt evidence, semantic divergence quarantines the action, and observation-only divergence disables ordinary replay pending review;
- Cargo pipelining is preserved or improved using exact rustc artifact-event semantics, with transitive provisional lineage closed before descendant publication;
- cancellation drains all process/permit/lease/pin/stream obligations;
- durable CAS survives crash, location corruption, logical quarantine, and GC-race tests;
- the metadata backend abstraction and selected backend pass differential/crash gates;
- native ATP control/data paths pass soak and compatibility gates, with fallback retained;
- `rch why` explains every hit, miss, refusal, projection, and worker decision;
- sampled determinism and stock verification show zero incorrect served results;
- p50/p90 agent trace targets are met on the representative corpus;
- storage growth, privacy scope, GC, pressure behavior, and operations are bounded/documented;
- security boundaries prevent direct untrusted publication and secret-key ambiguity;
- platform serving authority is explicit rather than overclaimed;
- canonical path semantics are explicitly admitted/proven or the path-preserving lane is used;
- subscriber delivery uncertainty, provisional-lineage terminal gating, and destination-path arbitration pass crash/concurrency proofs;
- trust evidence can promote, demote, or quarantine serving without rewriting canonical publication;
- tiny wrappers and long-running daemons/workers use separately benchmarked release profiles;
- publication history, serving disposition, evidence, and retention transitions remain separate and crash-consistent;
- action generation IDs cannot be reused after failure, eviction, restart, or metadata repair;
- Cargo resolution-derived snapshots and protocol sequence domains pass their dedicated differential/chaos gates;
- publication pins are atomic with action-pointer visibility, and provisional waiters cannot starve producer progress;
- rollout, rollback, canary, and incident runbooks are complete.

## 207. Frontier product definition of done

The frontier program is successful only where evidence demonstrates net value:

- incremental time travel materially improves branch workflows under bounded storage;
- speculation saves more foreground latency than it costs;
- critical-path scheduling improves tail latency;
- fragmentation advice leads to measurable convergence;
- advanced ATP transfer features outperform simpler paths in identified regimes;
- external REAPI compatibility expands deployment options without contaminating native semantics.

---

# Part XXIX. Source and evidence basis

## 208. Repository evidence pins used during synthesis

The prior source review examined, among other files:

### Asupersync at reviewed commit `62d398ea17519d7e80cbdb32e062d70647cd58a4`

At the time of this sixth pass, repository `main` was `513aa04f5b0ea045672e170c7c85eb1903510328`, a direct child whose commit description characterized the delta as formatting-only. Behavioral claims in this plan remain pinned to the reviewed commit until CI revalidates the newer pin.

- `README.md`;
- `Cargo.toml`;
- `src/remote/mod.rs`;
- `src/process/mod.rs`;
- `src/supervision.rs`;
- `src/runtime/rch_health/mod.rs`;
- `src/runtime/pool_sizing.rs`;
- `src/runtime/slo_policy_bridge.rs`;
- `src/atp/object.rs`;
- `src/atp/cas.rs`;
- `src/atp/journal/mod.rs`;
- `src/atp/transfer_actor.rs`;
- `src/atp/transfer_brain.rs`;
- `src/atp/identity/mod.rs`;
- `src/net/atp/protocol/{frames,codec,session}.rs`;
- `src/net/quic_native/{mod,managed_endpoint}.rs`;
- `src/lab/mod.rs`;
- `src/observability/mod.rs`;
- `asupersync-tokio-compat/Cargo.toml`;
- ATP proof, coverage, test-contract, fuzz, CI, and conformance surfaces.

### RCH at reviewed commit `484a58e72f8c32047aba9c0adde7d0d10d30d29d`

- `README.md`;
- workspace `Cargo.toml`;
- `rch-common/src/ssh.rs`;
- `rch-common/src/path_topology.rs`;
- `rch-common/src/transfer_hardening.rs`;
- `rchd/src/main.rs`;
- `rchd/src/workers.rs`;
- `rchd/src/cancellation.rs`;
- worker health, telemetry, pressure, reliability, convergence, and API surfaces.


### License evidence checked during the sixth pass

- RCH and Asupersync carried the same rider-bearing license text at the reviewed revisions.
- Asupersync package metadata used `LicenseRef-MIT-OpenAI-Anthropic-Rider`.
- RCH workspace package metadata advertised plain `MIT`, which is inconsistent with its license file and is a P0 release-metadata correction.

The plan also incorporates the two detailed critique documents supplied in the conversation, particularly their emphasis on key stability, canonical execution paths, hermeticity, observed inputs, global jobserver control, Cargo pipelining, mtime discipline, test caching, explainability, replay-based measurement, and explicit kill criteria.

### Cargo at reviewed commit `04b8ad83c7caf921c5bbf830c4323b0f89fe9f9a`

- `src/compiler/job_queue/mod.rs`;
- `src/compiler/job_queue/job_state.rs`;
- `src/compiler/mod.rs` rustc execution and artifact-notification parsing;
- current wrapper nesting and environment documentation;
- current build-directory, checksum-freshness, and parallel-front-end documentation/status.

The review confirmed that Cargo distinguishes metadata and full-artifact dependency edges internally and calls its metadata-complete path after parsing rustc's `.rmeta` artifact notification. RABS therefore replays the rustc event only after complete materialization rather than inventing a Cargo outward message.

## 209. Evidence vocabulary for implementation

Implementation documents and receipts should use:

```text
OBSERVED     directly measured at a pinned revision or environment
VERIFIED     independently reproduced or checked
PARTIAL      implemented or evidenced only for a bounded profile
REPORTED     claimed by a source but not independently verified
TARGET       desired measurable outcome
HYPOTHESIS   plausible mechanism awaiting experiment
OPEN         unresolved decision or missing evidence
BLOCKED      cannot proceed until named prerequisite
DEFERRED     intentionally postponed pending evidence
REJECTED     considered and excluded
```

Claims must carry profile and non-claim boundaries. For example, a Linux/epoll proof does not imply macOS parity; a deterministic lab result does not alone prove real-network throughput; a correct key does not imply stable hit rates.

---

# Final directive

Implementation should optimize for **useful delivered acceleration and trust**, not ceremony. The shortest path to the full vision is not to activate every Asupersync or ATP capability at once. It is to establish the canonical execroot, trustworthy action identity, streamed Cargo fidelity, Asupersync-owned lifecycle, durable atomic storage, and replay-based evidence first; then progressively replace the old transport and add workspace intelligence, tests, incremental time travel, and speculation behind hard gates.

The enduring architectural test is:

> **Does this change make semantically identical concurrent demand collapse onto one stable, trusted, explainable logical action and primary execution lineage across agents and machines, with every additional retry, recovery, hedge, verification, or audit attempt explicit and bounded, while preserving Cargo behavior and guaranteeing per-subscriber delivery correctness, clean cancellation, atomic publication, and safe fallback?**

If yes, it is accretive to RABS. If not, it is outside the critical path regardless of how sophisticated it sounds.
