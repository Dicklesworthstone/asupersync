# MODE_OUTPUT_I4: Perspective-Taking Analysis of Asupersync

## Thesis

Asupersync is a technically ambitious project that solves real problems in Rust async correctness -- structured concurrency, cancel-safety, and deterministic testing are genuine improvements over the status quo. However, when viewed from the perspectives of the stakeholders who would actually adopt, maintain, debug, audit, or compete with it, a consistent pattern emerges: the project optimizes heavily for theoretical rigor and breadth of surface area while underinvesting in the human-facing surfaces (onboarding, migration friction, debuggability, and sustainability) that determine whether any runtime actually gets used. The 310K+ line codebase, solo maintainer, AI-agent workforce, nightly-only Rust, and "no contributions" policy create a fragility profile that would give pause to any serious evaluator, even one who admires the engineering.

---

## Top Findings

### F1. The Cx-everywhere ergonomic tax is higher than the README admits

**Evidence:** Every async function takes `&Cx`. The "Coming from Tokio?" section acknowledges this ("Extra parameter threading, but testable and auditable") but frames it as a minor syntax difference. In practice, `&Cx` propagation is viral: it infects every function signature, every trait bound, every library boundary. The Quick Example in the README requires `scope`, `state`, `cx`, `FailFast` policy, and explicit `.expect("spawn")` calls just to spawn two tasks. Compare with `tokio::spawn(async { ... })`.

**Reasoning (Rust developer perspective):** A developer evaluating adoption sees that every existing async library, every `impl Future`, every trait object, every dynamic dispatch boundary must be refactored to thread `&Cx`. This is not a "migration" -- it is a rewrite. The README's "Concept Mapping" table maps primitives 1:1, but the mechanical cost of `&Cx` propagation across a real codebase is O(n) in the number of async call sites, not O(1) per primitive.

**Severity:** HIGH  
**Confidence:** 0.92

---

### F2. The examples are toy demonstrations, not onboarding material

**Evidence:** The 13 files in `examples/` include `macros_basic.rs` (which uses a `MiniCx`/`MiniScope` mock that does not actually run anything -- `std::mem::drop(f(MiniCx))`), `external_consumer.rs` (18 lines that construct types and discard them), and `chaos_testing.rs` (demonstrates a hand-rolled `YieldN` future). None of the examples show a realistic end-to-end application: an HTTP server, a database-backed service, a producer-consumer pipeline.

**Reasoning (Rust developer perspective):** Compare with Tokio's examples: echo server, chat server, tinyhttp. Those examples let a developer copy-paste and modify. Asupersync's examples demonstrate that the macros compile, but they do not teach anyone how to build something. A developer evaluating adoption would look at the examples, fail to find a runnable "hello world" service, and move on.

**Severity:** HIGH  
**Confidence:** 0.95

---

### F3. Bus factor of 1 with 310K+ lines is an existential risk

**Evidence:** The project has a single maintainer (Dicklesworthstone), does not accept outside contributions, and uses 20+ AI coding agents as the development workforce. The MEMORY.md tracks agents by name (NavyMill, BlackBear, EmeraldRiver, etc.) with detailed session histories. The codebase is 310K+ lines across 500+ files with 42+ modules.

**Reasoning (solo maintainer perspective):** No human can maintain working knowledge of 310K lines of Rust across runtime internals, HTTP/1.1+H2, gRPC, PostgreSQL wire protocol, MySQL wire protocol, SQLite bindings, RaptorQ fountain codes, DPOR schedule exploration, persistent homology, sheaf theory, formal Lean proofs, WASM browser edition, and 400+ integration tests. The AI agents can produce code, but they cannot make architectural decisions, resolve design tensions, or prioritize. The maintainer's bandwidth is the bottleneck on every decision that requires judgment. One medical emergency, one burnout episode, one competing priority, and the project stalls.

**Severity:** CRITICAL  
**Confidence:** 0.93

---

### F4. The "Coming from Tokio?" migration story is misleading

**Evidence:** The README maps Tokio primitives to Asupersync equivalents in a clean table, then says "the concepts map cleanly." But the caveats reveal the truth: (1) `race!` macro "losers are cancelled by drop, not drained. Use `Scope::race` when loser-drain semantics matter." (2) `join!` and `join_all!` "still await branches sequentially." (3) You need `Scope`, `RuntimeState`, `Cx`, and a `Policy` just to spawn a task. (4) The entire Tokio ecosystem (hyper, axum, tonic, tower, reqwest, sqlx) is forbidden.

**Reasoning (Rust developer perspective):** The migration table creates an impression of compatibility that does not exist. A developer migrating from Tokio cannot bring any of their dependencies. The project reimplements HTTP, gRPC, database clients, and message brokers from scratch. Adopting Asupersync means adopting the entire Asupersync ecosystem -- with its 0.x API stability and single-maintainer support.

**Severity:** HIGH  
**Confidence:** 0.90

---

### F5. Capability security claims are not externally verifiable

**Evidence:** The README states "All effects flow through explicit Cx; no ambient authority." But `Cx` wraps `Arc<parking_lot::RwLock<CxInner>>` and is `Clone`. The `CxHandles` struct contains `Option<IoDriverHandle>`, `Option<TimerDriverHandle>`, `Option<BlockingPoolHandle>`, and other runtime handles. There is a `thread_local!` in `cx.rs`. The `Cx` type has a `Cx::for_testing()` constructor (behind `test-internals`, which is a default feature). There is no formal capability attenuation model enforced by the type system -- `Caps` is a phantom type parameter that defaults to `cap::All`.

**Reasoning (security researcher perspective):** The capability model is a naming convention, not a security boundary. Any code with a `Cx<cap::All>` can do everything. The phantom type parameter `Caps` suggests a plan for capability restriction, but as shipped, the default is `All`. There is no evidence of capability attenuation being enforced at function boundaries in the actual codebase (as opposed to documentation). A security researcher would ask: "Show me where a `Cx` with restricted capabilities is created and where the restriction is enforced." The answer appears to be "the infrastructure exists but is not yet used for real access control."

**Severity:** MEDIUM  
**Confidence:** 0.82

---

### F6. Error messages are well-structured but lack "what should I do?" guidance

**Evidence:** `src/error.rs` defines a rich `ErrorKind` enum (37 variants), `ErrorCategory` (11 categories), `Recoverability` (3 levels), and `RecoveryAction` (6 variants including `BackoffHint`). The `Error` struct carries optional `message`, `source`, and `ErrorContext` (task ID, region ID, object ID, symbol ID). However, error messages are generic strings: "sending on a closed mpsc channel", "mpsc channel is full", "receive operation cancelled".

**Reasoning (production debugger perspective):** The error taxonomy is excellent for programmatic handling (retry logic can dispatch on `RecoveryAction`). But when a developer is staring at a log, they need context: "Channel mpsc-42 in region R17 was closed because parent region R5 entered cancellation at 14:32:05." The `ErrorContext` fields exist but are optional and appear to be populated inconsistently. The Display impl for `Error` likely just shows the kind and message, not the full context chain.

**Severity:** MEDIUM  
**Confidence:** 0.78

---

### F7. The math-heavy algorithms are impressive but create an audit burden

**Evidence:** The README dedicates over 200 lines to "Alien Artifact Quality Algorithms": EXP3/Hedge adaptive scheduling, Freedman/Azuma martingale drain certificates, spectral wait-graph analysis with Cheeger/Fiedler bounds, persistent homology via GF(2) boundary reduction, sheaf-theoretic saga consistency, e-processes with Ville's inequality. These are implemented in production code paths (`src/runtime/scheduler/three_lane.rs`, `src/cancel/progress_certificate.rs`, `src/observability/spectral_health.rs`, `src/trace/boundary.rs`).

**Reasoning (competitor/Tokio maintainer perspective):** A Tokio maintainer would recognize that these algorithms address real problems (adaptive scheduling, deadlock detection) but would question whether the complexity is justified by measured improvements. The README does not report benchmark comparisons with simpler alternatives. "Persistent homology for schedule exploration" is a research-grade technique; has it been shown to find bugs that simpler coverage metrics miss? The risk is that these algorithms become maintenance liabilities -- when they have bugs, very few people can debug them.

**Severity:** MEDIUM  
**Confidence:** 0.80

---

### F8. The AGENTS.md rules reveal deep trust issues with AI agents

**Evidence:** Rule 0: "I AM IN CHARGE, NOT YOU." Rule 1: "YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION. You have a horrible track record of deleting critically important files." The file prohibits `git reset --hard`, `rm -rf`, requires "mandatory explicit plan" even after authorization, and demands documentation of every destructive command. The lessons learned in MEMORY.md include: "rch overwrites uncommitted source: ALWAYS commit before rch", "Explore agent unreliable: High false positive rate."

**Reasoning (AI agent perspective):** These rules are the scars of real incidents. The agents have deleted important files, overwritten uncommitted work, and produced false positives in audits. The response is a control regime of escalating restrictions. This is rational given the failure modes, but it also means the agents operate under heavy constraints that slow development. The rules do not address the deeper issue: AI agents lack the contextual judgment to make architectural decisions in a 310K-line codebase, so every decision above "implement this specific function" must be escalated to the single maintainer.

**Severity:** MEDIUM  
**Confidence:** 0.85

---

### F9. Nightly Rust requirement permanently limits the adoption pool

**Evidence:** The README states "Rust Edition 2024 and tracks the pinned nightly toolchain in rust-toolchain.toml." The `lib.rs` has `#![cfg_attr(feature = "simd-intrinsics", feature(portable_simd))]`. The nightly requirement appears to be for Edition 2024 features.

**Reasoning (Rust developer perspective):** Many organizations mandate stable Rust for production deployments. A nightly-only runtime is automatically disqualified from those environments. This is not a temporary situation -- Edition 2024 features may take 1-2+ years to stabilize. Any developer who adopts Asupersync is locked into nightly for the foreseeable future.

**Severity:** MEDIUM  
**Confidence:** 0.88

---

### F10. 423 integration test files suggest testing breadth but no evidence of CI health

**Evidence:** The `tests/` directory contains 423 `.rs` files including `adversarial_witness_corpus.rs` (47KB), `algebraic_laws.rs` (37KB), `cancel_obligation_invariants.rs` (47KB). The README mentions CI scripts but no CI status badge links to actual passing builds.

**Reasoning (production debugger perspective):** A large test suite is only valuable if it runs and passes. With 423 test files and a nightly-only toolchain, test maintenance is a significant burden. There is no visible evidence (CI badges, GitHub Actions status) that all tests pass on the current commit. The git status shows modified test files (`tests/repro_service_rate_limit.rs`, `tests/service_verification.rs`) in the working tree, suggesting active churn.

**Severity:** MEDIUM  
**Confidence:** 0.75

---

## Risks Identified

1. **Sustainability risk (CRITICAL):** Single maintainer + no contributions policy + 310K lines = fragile project. If the maintainer becomes unavailable, the project dies. The AI agents cannot maintain it independently.

2. **Adoption risk (HIGH):** Nightly-only Rust + no ecosystem compatibility + steep learning curve + no realistic examples = near-zero organic adoption. The project's value proposition requires potential users to abandon their entire async stack.

3. **Correctness verification risk (HIGH):** The project claims formal correctness properties (structured concurrency, cancel-correctness, capability security) but the verification is primarily through internal audits performed by AI agents. The audit process itself has known reliability issues (MEMORY.md: "Explore agent unreliable: High false positive rate").

4. **Complexity ceiling risk (MEDIUM):** The math-heavy algorithms (sheaf theory, persistent homology, e-processes) require domain expertise to maintain. As these algorithms interact with each other and with the rest of the runtime, the interaction surface grows combinatorially.

5. **License risk (LOW-MEDIUM):** "MIT + OpenAI/Anthropic Rider" is a non-standard license. Any organization with a legal review process will flag this for review, adding friction to adoption.

---

## Recommendations

### P0 (Do now)

- **Write 3-5 realistic, runnable examples**: HTTP echo server, producer-consumer pipeline, database-backed service, graceful shutdown. These should compile and run without modification.
- **Audit the "Coming from Tokio?" section for honesty**: Add a "Migration cost" column that honestly estimates effort. Add a "What you lose" section listing ecosystem crates that will not work.

### P1 (Do soon)

- **Set up visible CI**: GitHub Actions badge on the README showing that `cargo check`, `cargo clippy`, and `cargo test` pass. This is table stakes for any open-source project.
- **Create a "Getting Started" guide**: Separate from the README, walking through building a simple application from scratch. Show the full lifecycle: setup, build, test, debug.
- **Stabilize on stable Rust**: Identify what nightly features are actually required and either vendor/polyfill them or make them optional.

### P2 (Do this quarter)

- **Implement real capability attenuation**: The `Caps` phantom type parameter should be used to create restricted `Cx` instances (e.g., `Cx<cap::ReadOnly>`, `Cx<cap::NoSpawn>`). Without this, "capability security" is aspirational, not real.
- **Add structured error context population**: Ensure `ErrorContext` fields (task ID, region ID) are consistently populated at error construction sites, and that `Display` shows them.
- **Publish benchmarks against Tokio**: If the runtime is genuinely faster or more correct, show it with numbers. If it is slower, be honest about the trade-off.

### P3 (Do this year)

- **Consider accepting contributions for peripheral modules**: Database clients, message broker clients, and codec implementations could accept PRs without compromising core runtime integrity. This reduces bus factor risk.
- **Write a "Debugging Asupersync" guide**: How to trace a request through the runtime. How to read trace events. How to use the lab runtime to reproduce production issues. This is what production users need most.

### P4 (Backlog)

- **Create an Asupersync compatibility layer for common Tokio traits**: Even if the implementation is Asupersync-native, implementing `tokio::io::AsyncRead`/`AsyncWrite` trait compatibility would allow gradual migration.
- **Consider publishing to crates.io**: The README mentions `asupersync = "0.2.5"` but the install instructions say `cargo add --git`. Publishing to crates.io is a signal of stability.

---

## New Ideas and Extensions

1. **"Asupersync Lite"**: A minimal crate that provides just `Cx`, `Outcome`, structured concurrency, and channels -- without HTTP, gRPC, databases, RaptorQ, etc. This would lower the adoption barrier dramatically and let users adopt the core ideas incrementally.

2. **Tokio compatibility shim crate**: A separate crate (`asupersync-tokio-compat`) that implements Tokio's public traits using Asupersync internals. This would let existing Tokio-based libraries run on Asupersync without modification.

3. **Interactive WASM playground for the "Coming from Tokio?" examples**: The project already has a WASM demo. Extend it to let developers type Tokio code on the left and see the Asupersync equivalent on the right, with live compilation.

4. **Formal verification of the capability model**: Use the existing Lean infrastructure to prove that a restricted `Cx<Caps>` cannot escalate to `Cx<All>` without going through an authorized path.

5. **"Asupersync for Library Authors" guide**: How to write a library that works with Asupersync's `Cx` pattern. How to make your library runtime-agnostic. This is the critical missing piece for ecosystem growth.

---

## Assumptions Ledger

| ID | Assumption | Confidence | Impact if Wrong |
|----|-----------|------------|-----------------|
| A1 | The project does not accept outside contributions | 0.90 | If it does, F3 severity drops |
| A2 | Nightly Rust is required (not just preferred) | 0.85 | If stable works, F9 is void |
| A3 | The 65+ bugs found by AI audits are real bugs | 0.80 | If many are false positives, the audit process is less trustworthy |
| A4 | No organization is currently using Asupersync in production | 0.95 | If one is, adoption risk assessment is wrong |
| A5 | The maintainer is a solo individual, not a team | 0.90 | If there are silent contributors, F3 severity drops |
| A6 | `Cx<Caps>` capability restriction is not enforced at runtime | 0.75 | If it is, F5 severity drops significantly |

---

## Questions for Project Owner

1. **What is the actual nightly feature gate?** Is it only `portable_simd` behind `simd-intrinsics`, or are there other nightly features required for the default build?

2. **Has any external party evaluated Asupersync for adoption?** If so, what was their primary objection?

3. **What is the plan for the project if you become unavailable?** Is there a succession plan, a foundation, or a trusted co-maintainer?

4. **Have the math-heavy algorithms (spectral health, persistent homology, sheaf consistency) caught real bugs that simpler alternatives would have missed?** Can you point to specific examples?

5. **What is the intended relationship between `Cx<Caps>` phantom types and actual capability enforcement?** Is attenuation planned, implemented, or aspirational?

6. **Why not accept contributions for non-core modules** (database clients, codec implementations, examples)?

7. **How long does a full `cargo test` run take?** With 423 test files, is the full suite practical for CI?

---

## Points of Uncertainty

- **How well do the AI agent audits actually work?** MEMORY.md records "Explore agent unreliable: High false positive rate" but also credits agents with finding 65+ real bugs. The signal-to-noise ratio is unclear.

- **Is the WASM Browser Edition actually functional?** The README has extensive documentation about it, but the status is hedged with "preview", "narrower than shipped JS/TS packages", and "fixture-driven workflow remains the authoritative evidence." It is hard to tell from documentation alone whether this works or is aspirational.

- **What is the actual performance profile?** The README describes many optimizations but provides no benchmark numbers comparing against Tokio or other runtimes. "We made it fast" without numbers is a claim, not evidence.

- **How does the project handle breaking changes?** The README says "0.x.y: Breaking changes may ship in 0.(x+1).0" but the AGENTS.md says "We do not care about backwards compatibility." These are different messages.

---

## Agreements and Tensions with Other Perspectives

**Agreement across all perspectives:** The core idea -- structured concurrency with cancel-correctness and deterministic testing -- addresses a real gap in the Rust ecosystem. Every perspective acknowledges this is a genuine improvement over "spawn and pray."

**Tension: Rust developer vs. maintainer:** The developer wants simplicity and ecosystem compatibility. The maintainer wants correctness and purity. These goals conflict: making `Cx` optional or providing Tokio compatibility would compromise the "no ambient authority" invariant that the maintainer considers non-negotiable.

**Tension: Security researcher vs. competitor:** The security researcher wants the capability model to be real and enforceable. The competitor (Tokio maintainer) would argue that the capability model adds complexity without practical security benefit in most deployments. Both are right depending on the threat model.

**Tension: AI agents vs. maintainer:** The agents need freedom to be productive. The maintainer needs control because the agents have demonstrated poor judgment. This tension is managed through increasingly restrictive rules (AGENTS.md), but the underlying problem -- AI agents lack architectural judgment -- is not solved by more rules.

**Tension: Production debugger vs. math enthusiast:** The debugger wants simple, clear error messages and straightforward trace output. The project instead provides Bayes factors, e-processes, spectral decompositions, and persistent homology. These are powerful tools in expert hands but opaque to a developer trying to figure out why their HTTP request timed out at 3 AM.

---

## Confidence: 0.82

**Calibration note:** I have read the README thoroughly, examined the API surface (lib.rs, cx.rs, error.rs, channel/mpsc.rs), reviewed all examples, and studied AGENTS.md. I have not compiled the project, run the tests, or examined the implementation of the math-heavy algorithms in detail. My assessment of capability enforcement (F5) is based on code structure rather than exhaustive search. The findings about onboarding quality (F1, F2, F4) and sustainability (F3) are high-confidence because they are based on directly observable evidence. The findings about debuggability (F6) and algorithm justification (F7) are somewhat lower confidence because they require deeper implementation knowledge to fully assess.
