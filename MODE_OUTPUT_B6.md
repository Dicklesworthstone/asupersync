# MODE_OUTPUT_B6: Analogical Reasoning Analysis of Asupersync

## Thesis

Asupersync is best understood as a synthesis of ideas from at least five distinct engineering traditions -- Erlang/OTP supervision, capability-based OS design, database transaction theory, formal verification of safety-critical systems, and modern structured concurrency proposals (Swift, Kotlin, Java Loom) -- unified under a single Rust async runtime. The project succeeds remarkably at the structural level: its region tree genuinely solves the orphan-task problem that plagues Tokio, its two-phase effects faithfully adapt database ACID semantics to channel operations, and its capability context (Cx) implements a principled capability-security model. However, the analogical analysis reveals tension between the project's ambition for formal rigor (Iris separation logic, Dialectica morphisms, martingale certificates) and the practical reality of a solo-maintainer + AI-agent codebase that has no production users. The strongest analogies (OTP supervision, 2PC transactions) are well-executed; the weakest (capability security vs. seL4, formal verification vs. aircraft control systems) expose areas where the theoretical machinery may exceed the project's ability to maintain or validate it.

---

## Top Findings

### F1: Two-Phase Effects Are a Faithful and Novel Application of Database Transaction Semantics

**Evidence**: `src/channel/mpsc.rs` lines 0-18, `src/obligation/dialectica.rs` lines 0-58, `src/obligation/session_types.rs` lines 24-58

**Source Domain**: Database two-phase commit (2PC) protocol, ACID transaction guarantees

**Reasoning**: The reserve/commit pattern on channels directly maps the database notion of a prepared transaction. In database 2PC, a participant votes YES (prepare) then commits; in Asupersync, `tx.reserve(&cx).await?` is the prepare phase and `permit.send(value)` is the commit. The abort path (dropping the permit) corresponds to a rollback. The Dialectica formalization (`reserve: (Kind, Region) -> Permit`, `resolve: Permit -> {Commit, Abort}`) makes this analogy explicit and rigorous.

**What transfers well**: The core insight -- separating intent from effect to achieve cancel-safety -- is sound and solves a real problem (Tokio's `send().await` can lose messages on cancellation). The five Dialectica contracts (exhaustive resolution, no partial commit, region closure safety, cancellation non-cascading, kind-uniform state machine) mirror the ACID properties faithfully.

**What doesn't transfer**: Database 2PC has a well-known blocking problem (coordinator failure leaves participants in doubt). Asupersync avoids this because its "coordinator" is the runtime itself, which is in-process. However, the `src/remote.rs` saga system for distributed operations will face the same blocking/uncertainty problems that motivated 3PC and Paxos in databases, and the current implementation is explicitly incomplete ("transport-backed remote lifecycle is still being finalized under Track F").

**Severity**: Informational (strength)
**Confidence**: 0.92

---

### F2: OTP Supervision Is Faithfully Ported but Missing Key Erlang Lessons

**Evidence**: `src/supervision.rs` (8451 lines), `src/gen_server.rs`, `src/actor.rs`

**Source Domain**: Erlang/OTP supervisor, gen_server, process linking

**Reasoning**: The SupervisionStrategy (Stop/Restart/Escalate), RestartPolicy (OneForOne/OneForAll/RestForOne), restart rate limiting with sliding windows, and backoff strategies are all direct ports from OTP. The SupervisorBuilder with deterministic start ordering via topological sort of dependencies goes beyond OTP's simple child-spec lists. The GenServer implementation with Call/Cast/Info message types maps directly to gen_server's handle_call/handle_cast/handle_info.

**What transfers well**: The core supervision tree structure, restart policies, escalation semantics, and GenServer message taxonomy are all correctly ported. Budget-aware restarts (`restart_cost`, `min_remaining_for_restart`, `min_polls_for_restart`) extend OTP with resource-awareness that Erlang doesn't need (because its per-process heap GC handles memory differently).

**What's missing from Erlang/OTP**:

1. **Process isolation**: Erlang's killer feature is that one process crashing cannot corrupt another's heap. Asupersync actors share the Rust heap. A panic in one actor is caught, but memory corruption from unsafe code (even though `#![deny(unsafe_code)]` is set) or logic errors that corrupt shared state propagate silently. The `#![deny(unsafe_code)]` global deny is the project's answer, but it's a convention not an isolation boundary.

2. **Hot code loading**: OTP supervisors support code_change callbacks for live upgrades. Asupersync has no equivalent, which limits operational flexibility for long-running systems.

3. **Distribution primitives**: Erlang's `{node(), pid()}` addressing and transparent message passing across nodes is absent. The remote.rs module has protocol definitions but no actual transport.

4. **Process dictionary / ETS**: Erlang provides shared mutable state tables (ETS) with per-table isolation semantics. Asupersync's registry (`src/cx/registry.rs`) exists but the NameRegistrationPolicy is explicitly "spec-level" -- planned but not implemented.

**Severity**: Medium -- the missing isolation and distribution primitives are the parts that make OTP supervision actually useful in production
**Confidence**: 0.85

---

### F3: Capability Security Model Is Principled but Weaker Than Hardware-Enforced Capabilities

**Evidence**: `src/cx/cap.rs` (type-level capability sets), `src/cx/cx.rs` (Cx struct with phantom capability markers), `src/cx/macaroon.rs` (macaroon-style attenuation)

**Source Domain**: seL4 capability system, Fuchsia zircon handles, KeyKOS, EROS

**Reasoning**: Asupersync's `Cx<Caps>` uses const-generic booleans to encode capabilities at the type level (`CapSet<SPAWN, TIME, RANDOM, IO, REMOTE>`). The `SubsetOf` trait enforces narrowing-only (capabilities can be dropped, never gained). Macaroon tokens add runtime attenuation with contextual caveats.

**What transfers well**: The principle of "no ambient authority" is correctly applied -- all effectful operations require an explicit `Cx` parameter. The type-level encoding means capability violations are compile errors, which is strictly stronger than runtime-only capability checking. The sealed trait pattern prevents forgery from external crates. This is closer to a proper capability system than most language-level attempts.

**What doesn't transfer**: Hardware capability systems (seL4, CHERI) enforce isolation through hardware memory protection. Asupersync's capabilities live in the same address space and can be circumvented by:
- Any code that holds an `Arc<parking_lot::RwLock<CxInner>>` directly (the inner field is `pub(crate)`)
- `unsafe` blocks (denied but overridable per-module)
- The thread-local `CURRENT_CX` (line 249 of cx.rs) which reintroduces ambient authority within the crate

The `pub(crate)` visibility on `Cx::inner` is the weakest link -- any module within the crate can bypass the capability system. This is analogous to how a monolithic kernel can bypass its own security mechanisms internally. A microkernel approach (separate crates for different subsystems) would strengthen this.

**Severity**: Low -- this is appropriate for the project's current scope, but should be documented as a known limitation
**Confidence**: 0.88

---

### F4: Structured Concurrency Surpasses Swift/Kotlin/Loom in Formalism but Lags in Ergonomics

**Evidence**: `src/cx/scope.rs` (scope API), README.md "Coming from Tokio?" section, `src/types/policy.rs`

**Source Domain**: Swift structured concurrency (TaskGroup), Kotlin coroutineScope, Java Project Loom (StructuredTaskScope), JEP 453

**Reasoning**: All four systems share the core insight: tasks must be owned by a scope that guarantees completion before the scope exits. Asupersync's region tree is the most rigorous version:

| Feature | Swift TaskGroup | Kotlin coroutineScope | Loom StructuredTaskScope | Asupersync Region |
|---------|----------------|----------------------|--------------------------|-------------------|
| Scope enforces completion | Yes | Yes | Yes | Yes |
| Cancellation protocol | Cooperative (check isCancelled) | CancellationException | Thread interrupt | Multi-phase with budget |
| Cancel-safe channels | No | No | No | Yes (two-phase) |
| Obligation tracking | No | No | No | Yes (linear tokens) |
| Deterministic testing | No | No | No | Yes (lab runtime) |
| Ergonomic API | Yes (async let) | Yes (launch/async) | Yes (fork/join) | No (explicit state threading) |

The ergonomic gap is significant. Compare spawning a task:

- **Swift**: `async let result = doWork()`
- **Kotlin**: `launch { doWork() }`
- **Loom**: `scope.fork(() -> doWork())`
- **Asupersync**: `scope.spawn(&mut state, &cx, move |cx| async move { do_work(&cx).await })`

Asupersync requires threading `&mut state`, `&cx`, a move closure wrapping an async block, and explicit `Cx` plumbing. The proc macros (`scope!`, `spawn!`, `join!`) mitigate this but aren't shown in most examples.

**What transfers well**: The formalism (region tree, obligation registry, Lyapunov potential) provides guarantees no competitor offers. The severity lattice on Outcome (Ok < Err < Cancelled < Panicked) is a genuine innovation over Swift/Kotlin's simpler error models.

**What's missing**: Swift and Kotlin learned from Go that ergonomics drive adoption. The explicit `&mut state` parameter is a particular burden -- it forces the user to manage runtime state threading manually, which other structured concurrency systems hide behind language-level support or smart pointers.

**Severity**: High for adoption, Low for correctness
**Confidence**: 0.90

---

### F5: Go-Channel Simplicity as a Cautionary Mirror

**Evidence**: `src/channel/mpsc.rs`, `src/channel/broadcast.rs`, `src/channel/watch.rs`, `src/channel/session.rs`, `src/channel/fault.rs`, `src/channel/partition.rs`

**Source Domain**: Go channels, CSP (Communicating Sequential Processes)

**Reasoning**: Go's channel model succeeded by being ruthlessly simple: one type (`chan T`), three operations (send, receive, select), and a garbage collector that handles cleanup. Asupersync's channel surface includes: mpsc, oneshot, broadcast, watch, session, fault, partition, and clock_skew channels, each with two-phase semantics, obligation tracking, and Cx-aware operations.

Go demonstrates that a simpler model with known sharp edges (goroutine leaks, panic on closed channel) can achieve massive adoption. The Go team explicitly chose not to prevent goroutine leaks, arguing that the cure (complex ownership tracking) is worse than the disease for most programs.

**What this means for Asupersync**: The project has made the opposite bet -- maximal safety at the cost of complexity. This is defensible for the stated target domains (financial, medical, infrastructure) but makes the learning curve forbidding. A developer familiar with Go channels will see Asupersync's `tx.reserve(&cx).await?.send(value)` as solving a problem they don't believe they have.

The session-typed channels (`src/channel/session.rs`, `src/obligation/session_types.rs`) with formal protocol state machines go even further from Go's simplicity. While theoretically elegant, session types have historically failed to achieve adoption outside of research (Gay & Vasconcelos 2010, Scalas & Yoshida 2019).

**Severity**: Medium -- this is a strategic bet, not a bug
**Confidence**: 0.82

---

### F6: Formal Verification Machinery Exceeds What Can Be Maintained

**Evidence**: `src/obligation/separation_logic.rs` (Iris-style separation logic), `src/obligation/dialectica.rs` (Dialectica morphisms), `src/obligation/lyapunov.rs` (Lyapunov governor), `src/cancel/progress_certificate.rs` (martingale progress certificates), `src/obligation/marking.rs` (VASS marking analysis), `formal/lean/Asupersync.lean`

**Source Domain**: Aircraft/nuclear reactor control systems (DO-178C, IEC 61513), formal methods in safety-critical software (CompCert, seL4, HACL*)

**Reasoning**: Safety-critical systems use formal verification when the cost of failure exceeds the cost of proof. CompCert's verified C compiler, seL4's verified microkernel, and HACL*'s verified crypto all share a key property: the proofs are mechanized end-to-end, maintained alongside the code, and checked by CI. The proofs ARE the specification.

Asupersync has extensive formal specifications (separation logic predicates, Dialectica contracts, martingale bounds, VASS coverability analysis) but these exist primarily as:
1. Rust test code that checks invariants on synthetic traces
2. Lean skeleton proofs that are explicitly described as a "scaffold"
3. In-code mathematical notation in doc comments

The gap between "has formal specifications" and "has mechanized proofs" is enormous. CompCert's C compiler has ~100K lines of Coq proofs for ~30K lines of OCaml. seL4's microkernel has ~10K lines of C backed by ~480K lines of Isabelle proof. Asupersync has 310K lines of Rust and a Lean skeleton.

The danger is that the formal specification comments become stale relative to the actual implementation. The Dialectica contracts in `dialectica.rs` describe five properties, but if the actual obligation state machine in `src/record/` drifts from these contracts, there is no compiler to catch it.

**What transfers well**: The mathematical framework is sound and the specific bounds (Azuma-Hoeffding, Freedman, Ville's inequality) are correctly applied. Having e-processes for anytime-valid monitoring is genuinely useful for the lab runtime's oracle system.

**What doesn't transfer**: The aviation industry's lesson is that partial formal methods can be worse than none -- they create false confidence. Documenting separation logic predicates that aren't mechanically checked may mislead users into believing stronger guarantees than actually exist.

**Severity**: Medium
**Confidence**: 0.78

---

### F7: The Lab Runtime Is the Project's Strongest Differentiator, Analogous to Nothing in the Ecosystem

**Evidence**: `src/lab/` directory, `src/lab/runtime.rs`, `src/lab/explorer.rs`, `src/lab/oracle/`, `src/trace/dpor.rs`

**Source Domain**: Jepsen (distributed systems testing), Loom (Rust concurrency testing), FoundationDB simulation testing, Antithesis

**Reasoning**: The lab runtime combines several ideas that exist separately but have never been unified:

| Capability | Closest analog | Asupersync advantage |
|-----------|---------------|---------------------|
| Deterministic scheduling | Loom | Integrated with the runtime, not a separate tool |
| Virtual time | FoundationDB simulation | First-class time API, not a mock |
| Schedule exploration (DPOR) | Loom / Chess | Coverage semantics via Mazurkiewicz equivalence classes |
| Invariant oracles | Jepsen checkers | Anytime-valid (e-processes), not post-hoc |
| Trace replay | Antithesis | Same seed = same behavior, end-to-end |
| Conformal calibration | None | Distribution-free prediction sets for runtime metrics |

FoundationDB's simulation testing is perhaps the closest analog. Their CTO (Dave Rosenthal) has described it as "the single most important piece of technology at FoundationDB." But FoundationDB's simulation is a custom C++ runtime not available as a library. Asupersync makes this a first-class, reusable testing substrate.

**Severity**: Informational (strength)
**Confidence**: 0.93

---

### F8: The Spork Module Name and OTP Terminology Create a Branding Debt

**Evidence**: `src/spork.rs`, `src/supervision.rs`, `src/gen_server.rs`, `src/actor.rs`

**Source Domain**: Erlang/OTP naming conventions, Akka (JVM actor framework)

**Reasoning**: The project uses "Spork" as a brand name for its OTP-style supervision while simultaneously using direct OTP terminology (gen_server, supervision, one_for_one, rest_for_one). This creates a confusing dual identity. Erlang developers will expect OTP semantics but find Rust ownership semantics. Non-Erlang developers will find unfamiliar terminology with no clear mapping to their mental model.

Akka made a similar choice (porting OTP concepts to JVM) and found that direct terminology mapping confused Java developers. Akka eventually developed its own vocabulary (ActorSystem, Behaviors, Receptionist) that better matched JVM idioms.

Additionally, "Spork" as a brand for supervision doesn't communicate the concept to anyone unfamiliar with the project. It reads as a joke name.

**Severity**: Low (cosmetic, but affects onboarding)
**Confidence**: 0.75

---

### F9: The Outcome Severity Lattice Is a Genuine Semantic Innovation

**Evidence**: README.md lines 489-500, `src/types/` (Outcome type)

**Source Domain**: Algebraic effects research (Plotkin & Pretnar 2009), multi-valued logic, HTTP status code semantics

**Reasoning**: The four-valued `Outcome<T, E>` with severity ordering `Ok < Err < Cancelled < Panicked` solves a real problem that other runtimes handle ad-hoc. In Tokio, a `JoinError` conflates panic and cancellation. In Go, there's no standard way to distinguish "context cancelled" from "operation failed" from "goroutine panicked."

The severity lattice makes combinator behavior compositional: `join_all` aggregates outcomes by taking the supremum of severity. This is analogous to how database isolation levels compose (the tightest constraint wins) or how error-code lattices work in PLC safety systems (the most severe alarm state propagates).

The HTTP mapping (Ok->200, Err->4xx/5xx, Cancelled->499, Panicked->500) shows this isn't purely theoretical.

**Severity**: Informational (strength)
**Confidence**: 0.88

---

### F10: Sharded Lock Ordering Is Sound but Manually Enforced

**Evidence**: `src/runtime/sharded_state.rs` (ShardGuard with canonical order E->D->B->A->C), README.md lock ordering documentation

**Source Domain**: Database lock manager (hierarchical lock ordering), Linux kernel lock ordering (lockdep)

**Reasoning**: The canonical lock acquisition order `E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations)` prevents deadlocks by the classic textbook approach. Linux's lockdep subsystem automatically detects lock ordering violations at runtime. Asupersync uses debug-mode assertions to enforce ordering.

The risk is that as the codebase grows (310K lines, 42 modules, 20 AI agents contributing), someone will introduce a lock ordering violation that debug assertions miss. Linux needed lockdep precisely because manual ordering became untenable at scale. The five-shard model is simple enough that this is currently manageable, but any future shard decomposition will need automated verification.

**Severity**: Low (current), Medium (future risk)
**Confidence**: 0.80

---

## Risks Identified

1. **Formal specification drift**: The extensive mathematical specifications (separation logic, Dialectica contracts, martingale bounds) are not mechanically verified against the implementation. As the codebase evolves under 20+ AI agents, specification-implementation divergence is likely.

2. **Ergonomic barrier to adoption**: The explicit `&mut state`, `&cx` threading pattern, while correct, creates a learning curve that Swift/Kotlin/Go avoid. Without language-level support (which Rust won't provide), this limits the potential user base to teams that specifically need the safety guarantees.

3. **Missing production hardening**: No production deployments means the runtime's behavior under real workloads (memory pressure, partial network failure, clock skew, corrupted inputs) is validated only by the lab runtime. The lab runtime tests the model of the world, not the world itself.

4. **Solo maintainer + AI agent risk**: The codebase is maintained by one human with 20+ AI coding agents. AI agents are excellent at local changes but notoriously bad at maintaining global invariants (like lock ordering). The audit found ~65 bugs, many introduced by agent-authored code.

5. **Feature scope exceeding maintenance capacity**: 42 modules spanning runtime, networking, HTTP/1.1, HTTP/2, HTTP/3, gRPC, databases (Postgres, MySQL, SQLite), messaging (Redis, NATS, Kafka), WebSocket, QUIC, TLS, WASM, and more. Each module is a maintenance commitment. The "parity with Tokio ecosystem" goal means competing with hundreds of maintainers across the Tokio ecosystem.

---

## Recommendations

### P0 (Critical)

1. **Add property-based tests that verify formal specifications**: For each Dialectica contract, write a proptest/quickcheck that generates random obligation sequences and verifies the contract holds. This is cheaper than mechanized proofs and catches drift. Target: `src/obligation/dialectica.rs` contracts 1-5.

### P1 (High Priority)

2. **Invest in ergonomic API sugar**: The proc macros exist but aren't prominent. Create a "Getting Started" guide that uses `scope!`, `spawn!`, `join!` exclusively. Consider whether `&mut state` can be hidden behind a handle that's implicit in the scope context.

3. **Create a "Jepsen-style" integration test suite**: Use the lab runtime to test actual protocol implementations (not just the runtime itself). For example: run the Postgres wire protocol against a simulated network with partition injection. This bridges the gap between lab testing and production reality.

### P2 (Medium Priority)

4. **Document capability system limitations explicitly**: State that `pub(crate)` visibility on `Cx::inner` means intra-crate code can bypass capabilities. This manages expectations and guides future modularization.

5. **Evaluate crate decomposition**: Breaking the monolith into `asupersync-core` (runtime, Cx, obligations) and `asupersync-ecosystem` (HTTP, gRPC, databases) would strengthen capability isolation and reduce compile times.

6. **Add lockdep-style automated lock ordering checks**: Replace or supplement debug assertions with a runtime lock ordering verifier that runs in CI test builds. The Linux lockdep model is well-documented and straightforward to implement for 5 shards.

### P3 (Low Priority)

7. **Reconsider "Spork" branding**: Either commit to OTP terminology (and document the mapping for non-Erlang developers) or develop a native vocabulary that doesn't require Erlang knowledge.

8. **Write a "Why Not Asupersync?" section**: Honest documentation of when NOT to use the project (rapid prototyping, small scripts, Tokio-compatible library requirement) builds trust and saves time.

### P4 (Future)

9. **Explore selective mechanized proofs**: Rather than proving everything, prove the three most critical invariants (region close = quiescence, obligation exhaustive resolution, cancel budget sufficiency) in Lean. A small, maintained proof is worth more than a large stale one.

---

## New Ideas and Extensions

1. **Transaction-log inspired obligation auditing**: Database WAL (write-ahead log) ensures crash recovery. Asupersync could persist obligation state transitions to enable post-crash forensics -- "which obligations were in-flight when the process died?" This would be unique among async runtimes.

2. **Erlang-style process isolation via WASM sandboxing**: Since the project already has WASM support, consider using WASM sandboxes for actor isolation. Each actor runs in its own WASM instance with its own linear memory, providing Erlang-style heap isolation within a single OS process. Wasmtime's component model could enforce capability boundaries.

3. **Capability-based rate limiting from token bucket theory**: The Cx capability model could be extended with rate-limiting capabilities. A `Cx` could carry a token bucket for I/O operations, with the bucket parameters inherited from the parent scope and narrowed (never widened) in child scopes. This would make backpressure a capability, not a convention.

4. **Martingale-based auto-tuning of cancel budgets**: The progress certificate machinery tracks drain convergence. This data could feed back into budget allocation -- if a particular task type consistently drains slowly, future instances get larger budgets. This is analogous to database query optimizer cardinality estimation feedback loops.

5. **Differential dataflow integration for lab oracle**: The lab oracle system uses e-processes and conformal bounds. Integrating with a differential dataflow engine (like Materialize's timely dataflow) would enable incremental re-evaluation of invariants as the system evolves, rather than full re-computation at each step.

---

## Assumptions Ledger

| # | Assumption | Impact if wrong |
|---|-----------|-----------------|
| A1 | The project has no production deployments | If it does, the "missing production hardening" risk is less severe |
| A2 | AI agents contributed a significant fraction of the 310K lines | If not, the "AI agent global invariant" risk is less severe |
| A3 | The Lean proofs are skeletal/incomplete | If they are more complete than described, F6 severity decreases |
| A4 | The proc macros are not heavily used in internal code | If they are, the ergonomic gap (F4) is smaller than assessed |
| A5 | Users will come from Tokio backgrounds | If users come from OTP backgrounds, the terminology debt (F8) is reversed |
| A6 | The `pub(crate)` visibility on `Cx::inner` is intentional for internal ergonomics | If it's an oversight, it's a P1 fix |

---

## Questions for Project Owner

1. **Has the Lean skeleton been checked by `lean --run` recently?** If the proofs don't compile against current Lean 4, the formalization effort may need triage.

2. **What is the intended first production use case?** The answer determines which analogies matter most (database for financial systems, OTP for telecom-style always-on services, capability security for multi-tenant platforms).

3. **Is the explicit `&mut state` parameter a design choice or a current limitation?** If it could be hidden behind a scope-local reference or handle, the ergonomic gap shrinks dramatically.

4. **How are the 20+ AI agents prevented from introducing lock ordering violations?** Is there CI enforcement beyond debug assertions?

5. **What is the testing strategy for the networking stack under adversarial conditions?** The lab runtime provides deterministic scheduling, but does it model packet corruption, partial writes, TCP RST injection, TLS handshake failures?

---

## Points of Uncertainty

- **The effectiveness of e-process oracles in practice**: The mathematical foundations are sound, but it's unclear how often the anytime-valid property is actually exercised versus being a theoretical nicety. Confidence that this buys real debugging value: 0.60.

- **Whether the session type system will see adoption**: Session types have a decades-long track record of academic success and industrial failure. Asupersync's encoding is well-done, but the question is whether any user will actually use `session_protocol!` macros. Confidence: 0.40.

- **Whether DPOR schedule exploration scales**: DPOR's effectiveness depends on the number of independent events. For workloads with many shared channels, the equivalence classes may be too numerous for meaningful coverage. The explorer tracks fingerprints, but there's no documentation of coverage rates on realistic workloads. Confidence: 0.55.

- **Whether the 310K lines can be maintained long-term**: Solo maintainer + AI agents is an unprecedented maintenance model. The audit found ~65 bugs, which is a reasonable rate for 310K lines, but the question is whether this rate increases or decreases as the codebase ages. Confidence in sustainability: 0.50.

---

## Agreements and Tensions with Other Perspectives

**Would agree with a performance analyst (B3)**: The sharded lock design, intrusive queues, SmallVec optimizations, and generation-based timer cancellation are all standard high-performance runtime techniques. The performance story is credible for the hot paths.

**Would agree with a security reviewer (B5)**: The capability model is principled and the sealed-trait anti-forgery pattern is correct. The `#![deny(unsafe_code)]` default is good practice.

**Would tension with a pragmatist/product thinker (B1)**: The project solves problems that most developers don't encounter or don't prioritize. The gap between "theoretically prevents message loss on cancellation" and "I can ship my web app" is vast. A pragmatist would ask: "Show me a production system that was saved by two-phase channel sends."

**Would tension with a complexity analyst (B4)**: The obligation module alone contains separation logic, Dialectica morphisms, Lyapunov governors, VASS marking, CALM-optimized sagas, session types, CRDT conflict resolution, guarded recursion, e-process monitoring, and graded types. This is an extraordinary amount of formal machinery for a single module. An Occam's razor perspective would ask which of these is load-bearing and which is intellectual scaffolding.

**Would tension with a Tokio ecosystem advocate**: Tokio works. It has thousands of production deployments, hundreds of contributors, and a mature ecosystem. Asupersync's correctness advantages are real but theoretical until demonstrated under production load. The Tokio ecosystem's response to cancel-safety concerns (CancellationToken, graceful shutdown patterns, cancel-safe documentation) is "good enough" for most users.

---

## Confidence: 0.82

**Calibration note**: High confidence in the structural analogies (2PC, OTP supervision, capability security, structured concurrency comparison) because these are well-documented source domains with clear mappings. Lower confidence on forward-looking assessments (adoption, maintainability, scaling of formal methods) because these depend on externalities (community growth, production deployment opportunities) that cannot be assessed from code alone. The analysis is limited by not having access to benchmarks, CI results, or production telemetry. The MEMORY.md note that "~65 bugs found" across 587 audited files provides a useful quality signal but represents a snapshot, not a trend.
