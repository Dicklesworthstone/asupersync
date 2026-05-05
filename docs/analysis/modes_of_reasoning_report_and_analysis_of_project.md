# Modes of Reasoning: Comprehensive Analysis of Asupersync

**Date:** 2026-04-07
**Lead Agent:** SapphireHill (claude-opus-4.6)
**Swarm Size:** 10 analytical agents across 6 taxonomy categories
**Project:** Asupersync — 708K-line spec-first, cancel-correct async runtime for Rust

---

## 1. Executive Summary

Asupersync is a technically extraordinary project that solves real problems in Rust async correctness — structured concurrency, cancel-safe channels, deterministic testing — with genuine innovations found nowhere else in the ecosystem. **The core runtime design is sound and the architectural decisions (full Tokio replacement, explicit Cx, multi-phase cancellation, four-valued Outcome) were individually correct.** The lab runtime combining FoundationDB-style simulation, Loom-style exploration, and Jepsen-style oracles is the project's strongest and most unique differentiator.

However, 10 independent analytical lenses converge on five critical findings:

1. **The project has metastasized far beyond its core value proposition.** 708K lines in a single crate, with a 76K-line messaging system, 26K-line RaptorQ library, 22K-line CLI doctor, and 30-40K lines of mathematical machinery with zero operational callers. The minimum viable runtime is ~130K lines; the other ~580K lines are scope creep of varying severity.

2. **Claims systematically exceed implementation.** "No ambient authority" is falsified by `Cx::current()`, 34 global statics, and 26 thread-locals. "Deterministic testing" only holds for the lab runtime. "Feature-complete" coexists with 677 `todo!/unimplemented!/panic!` sites. The Lean proofs are genuine (zero `sorry`) but cover a simplified sequential model, not the concurrent implementation.

3. **Bus factor = 1 is an existential risk.** One maintainer, 708K lines, no outside contributions accepted, AI agents as the sole development workforce. This is not sustainable regardless of AI agent capability.

4. **Ergonomics are the primary adoption barrier.** `&Cx` threading infects every function signature. Migration from Tokio is a full rewrite, not an incremental adoption. Examples are toy demonstrations, not runnable applications.

5. **30-40K lines of "alien artifact" math are dead code.** Persistent homology, sheaf theory, separation logic, Dialectica interpretation, session types, martingale certificates, TLA+ export, and geodesic normalization have zero callers from operational paths. The Lyapunov governor is the positive counterexample of math done right (integrated and load-bearing).

---

## 2. Methodology

### Mode Selection Rationale

The project's nature — a deeply mathematical async runtime at a critical juncture between ambitious engineering and adoption viability — called for modes spanning both **truth vs. adoption** and **ampliative vs. non-ampliative** axes.

| # | Mode | Code | Category | Axis Coverage |
|---|------|------|----------|---------------|
| 1 | Systems-Thinking | F7 | Causal | Descriptive, holistic |
| 2 | Formal-Verification | A3 | Formal | Non-ampliative, truth |
| 3 | Adversarial-Review | H2 | Strategic | Multi-agent, attack |
| 4 | Analogical | B6 | Ampliative | Transfer, adoption |
| 5 | Perspective-Taking | I4 | Dialectical | Multi-agent, adoption |
| 6 | Failure-Mode (FMEA) | F4 | Causal | Action, uncertainty |
| 7 | Scope-Control | L5 | Meta | Normative, scope |
| 8 | Simplicity/MDL | B9 | Ampliative | Non-ampliative, truth |
| 9 | Counterfactual | F3 | Causal | Ampliative, belief |
| 10 | Debiasing | L2 | Meta | Meta-reasoning |

**Categories represented:** 6 of 12 (A, B, F, H, I, L)
**Axes spanned:** 5 of 7 (ampliative/non-ampliative, truth/adoption, descriptive/normative, single/multi-agent, belief/action)
**Antagonistic pairs:** B9 (Simplicity) vs F7 (Systems-Thinking); H2 (Adversarial) vs I4 (Perspective-Taking)

---

## 3. Taxonomy Axis Analysis

### Ampliative vs Non-Ampliative
The non-ampliative modes (A3, B9) found that the formal methods investment is genuine but narrow — the Lean proofs cover what they claim but the scope is a fraction of the codebase. The ampliative modes (B6, F3) generated the most actionable insights: the analogies to Erlang (missing process isolation), databases (two-phase commit faithfully adapted), and capability OSes (weaker than hardware enforcement but principled) identified specific improvement paths.

### Truth vs Adoption
The sharpest tension in the analysis. The "truth" modes (A3, H2) confirmed the core correctness claims are mostly valid for the core runtime but overextended in marketing. The "adoption" modes (I4, B6) revealed that technical correctness may be necessary but is insufficient — ergonomics, ecosystem compatibility, and sustainability determine whether the runtime gets used.

### Descriptive vs Normative
The descriptive modes (F7, F4) mapped the system's actual behavior — feedback loops, failure modes, interaction patterns. The normative modes (L5, L2) asked whether this behavior is *justified* — and concluded that significant scope reduction would better serve the project's mission.

---

## 4. Convergent Findings (KERNEL) — 3+ Modes Agree

### K1: Scope Has Exceeded Sustainable Limits
**Modes:** L5, I4, L2, F3, B9, H2 (6 modes)
**Confidence:** 0.93

708K lines of source code in a single crate with one human maintainer. The messaging module alone (76K lines) is larger than the core runtime (61K). 282 documentation files totaling 3.1 MB. The project attempts to simultaneously replace Tokio, Hyper, Axum, Tower, Tonic, tokio-postgres, mysql_async, tokio-tungstenite, and more — a combined effort maintained by dozens of people in the broader ecosystem.

**Evidence chain:**
- L5§F1: Messaging module is "a second project hiding inside the first" (75,765 lines)
- L5§F7: "The project is trying to replace the entire Tokio ecosystem in one crate"
- I4§F3: Bus factor = 1 is "existential risk" (confirmed by all 6 modes)
- L2§F4: "Not a sustainable development model" — 2,206 commits in 5 weeks
- B9§F3: 9,895 lines of obligation-theory code with zero runtime integration
- F3§F8: Full ecosystem buildout "carries significant risk of overinvestment before validation"

**Kill Thesis test:** Could a smaller scope achieve the same goals? YES — the core value proposition (structured concurrency + cancel-correctness + deterministic testing) is ~130K lines. The remaining 580K is ecosystem surface that could be separate crates or adapter layers.

---

### K2: 30-40K Lines of Mathematical Code Are Dead
**Modes:** B9, L5, F7, L2 (4 modes)
**Confidence:** 0.90

Persistent homology, sheaf theory, separation logic, Dialectica interpretation, session types, martingale drain certificates, conformal calibration, TLA+ export, and geodesic normalization are implemented, tested in isolation, and then never called from any operational path. `grep` for their public types returns zero external callers.

**Evidence chain:**
- B9§F1: Persistent homology / GF(2) boundary — zero callers outside trace/lab chain
- B9§F2: Sheaf consistency — zero callers outside its own file
- B9§F3: Separation logic + Dialectica + session types — 9,895 lines, zero runtime callers
- B9§F4: Martingale drain certificates — zero callers, simpler 10-line alternative exists
- L5§F5: Spectral health monitor — 3,371 lines where cycle detection suffices
- F7§F3: Lyapunov governor suggests but scheduler never consumes suggestions
- L2§F2: "Alien Artifact" section appears twice in README, prioritizes impressiveness

**Positive counterexample:** The Lyapunov governor (`lyapunov.rs`) and EXP3 controller are genuinely integrated, load-bearing, and justified. They demonstrate the RIGHT level of mathematical sophistication.

---

### K3: Claims Systematically Exceed Implementation
**Modes:** H2, I4, L2, A3 (4 modes)
**Confidence:** 0.91

| Claim | Reality | Source |
|-------|---------|--------|
| "No ambient authority" | `Cx::current()` is a thread-local ambient accessor + 34 global statics + 26 thread-locals | H2§F1, H2§F2 |
| "Deterministic testing" | Only in lab runtime; production uses HashMap (random iteration) and Instant::now() | H2§F4 |
| "Feature-complete" | 677 `todo!/unimplemented!/panic!` sites across 138 files | L2§F6 |
| "Formal verification" | Lean proofs cover a simplified sequential model, not the 708K-line concurrent implementation | A3§F2-F3, H2§F5, L2§F7 |
| "Tokio-scale ecosystem" | v0.2.9 with zero known production deployments vs. Tokio's years of production hardening | L2§F5 |
| "Financial, medical, infrastructure" | 5,043 `unwrap()` + 673 `panic!()` in library code | H2§F3 |
| "Capability security" | `Caps` defaults to `All`, `pub(crate)` inner field bypasses capability model | I4§F5, B6§F3 |

---

### K4: Ergonomics Are the Primary Adoption Barrier
**Modes:** I4, B6, F3, L2 (4 modes)
**Confidence:** 0.90

`&Cx` parameter threading infects every async function signature. Migration from Tokio is a full rewrite (no incremental path). Examples are toy demonstrations (no runnable HTTP server, no real application). Nightly-only Rust eliminates organizations with stable-Rust mandates.

**Evidence chain:**
- I4§F1: "&Cx propagation is viral: it infects every function signature, every trait bound, every library boundary"
- B6§F4: Asupersync spawn is `scope.spawn(&mut state, &cx, move |cx| async move { ... })` vs Swift's `async let result = doWork()`
- I4§F2: "None of the examples show a realistic end-to-end application"
- F3§F2: "The ergonomic cost is real" — proc macros mitigate but don't solve

---

### K5: Formal Methods Are Genuine but Narrowly Scoped
**Modes:** A3, H2, L2, L5 (4 modes)
**Confidence:** 0.92

The Lean proofs are real — 5,210 lines, 185 theorems, zero `sorry`, all 22 step constructors covered. This is genuinely rare. But the proofs operate on a sequential model that abstracts away concurrency (locks, atomics, Arc), I/O, and wakers — precisely where production bugs live. The `opaque IsReady` predicate hides the waker subsystem. No refinement link connects the Lean model to the Rust code.

**Evidence chain:**
- A3§F1: "All 6 core invariants constructively proven — this is a strong result"
- A3§F2: "IsReady abstracts the entire waker notification mechanism" (the exact subsystem where bugs occur)
- A3§F3: "Concurrency / lock ordering is entirely outside the formal model"
- A3§F6: Runtime checks `task_count() > 0` vs model's `allTasksCompleted` — refinement unproven

---

## 5. Supported Findings — 2 Modes Agree

### S1: Lock Ordering Enforcement Compiled Out in Release Builds
**Modes:** F4§F3, F7§F8 | **Confidence:** 0.78

The `lock_order` module uses `debug_assert!` and `#[cfg(debug_assertions)]`. In release builds, wrong-order lock acquisition silently deadlocks with no diagnostic. RPN=126 (Severity 9 x Occurrence 2 x Detection 7).

### S2: Monitoring Infrastructure Without Actuation
**Modes:** F7§F3/F6, B9§F5 | **Confidence:** 0.77

The Lyapunov governor computes `SchedulingSuggestion` but the scheduler doesn't consume it. The spectral health monitor observes but doesn't act. These are "powerful sensors without actuators" — closing the loops would create genuinely adaptive runtime behavior.

### S3: Two-Phase Effects Are the Strongest Innovation
**Modes:** B6§F1, F3§F3 | **Confidence:** 0.92

The reserve/commit pattern faithfully adapts database 2PC to channel operations. It solves a real problem (Tokio's `send().await` loses messages on cancellation) with a principled mechanism. The Dialectica formalization makes the guarantees explicit and rigorous.

### S4: Lab Runtime Is the Strongest Differentiator
**Modes:** B6§F7, F7§F7 | **Confidence:** 0.90

The combination of virtual time, deterministic scheduling, DPOR exploration, and oracle suites is unmatched in the Rust ecosystem. This is the system's only truly *closed* verification loop — code changes feed back through deterministic testing.

### S5: AI Agent Development Model Is Novel but Risky
**Modes:** F7§F5, I4§F8, F4§F9, L2§F3/F8 | **Confidence:** 0.83

20+ agents create velocity but quality assurance is AI-auditing-AI with acknowledged false positive rates. Advisory file locking is "heavily contended." AGENTS.md rules reveal trust issues from real incidents (deleted files, overwritten work).

---

## 6. Divergent Findings — Points of Disagreement

### D1: Is the Advanced Math Justified?

| Position | Modes | Argument |
|----------|-------|----------|
| **Unjustified complexity** | B9, L5, L2 | 30-40K lines of dead code. Simpler alternatives (cycle detection, timeouts, percentiles) achieve 95% of benefit at 5% of complexity. |
| **Partially justified** | F3, F7 | DPOR and e-processes provide genuine value. Spectral health and sheaf theory are unproven but not unreasonable research investments. |
| **Justified as design discipline** | A3 | Formal methods force precision in invariant definitions even when proofs cover only the model. |

**Resolution:** The modes are answering different questions. B9/L5/L2 ask "is this complexity earning its keep in production?" (answer: no). F3/A3 ask "did this complexity improve the design process?" (answer: partially). Both are correct. **Recommendation:** Feature-gate exotic math behind a `research` flag; keep the proven foundations (Lyapunov, EXP3, DPOR).

### D2: Is the Monorepo Structure Correct?

| Position | Modes | Argument |
|----------|-------|----------|
| **Should split now** | L5, L2 | Single crate with 708K lines is unmaintainable. Extract RaptorQ, messaging, database clients immediately. |
| **Should not split yet** | F3, F4 | With 20+ agents and cross-cutting invariants, monorepo prevents coordination nightmares. Split after API stabilization. |

**Resolution:** Different time horizons. L5/L2 assess long-term sustainability (split is inevitable). F3/F4 assess current development phase (split now would be disruptive). **Recommendation:** Plan the split; extract stable leaf modules (bytes, codec, raptorq) now; defer core runtime split until API stabilizes.

### D3: Is the "No Contributions" Policy Correct?

| Position | Modes | Argument |
|----------|-------|----------|
| **Existential risk** | I4, L2 | Bus factor = 1 with 708K lines is unsustainable. The policy converts a risk into a guarantee of eventual failure. |
| **Currently correct** | F3 | Invariant density is extreme. A well-meaning PR with wrong lock ordering creates invisible deadlocks. Open contributions only after invariants become enforceable contracts. |

**Resolution:** Both are right at different scales. **Recommendation:** Open leaf modules (database clients, web handlers) to contributions. Keep core runtime (scheduler, regions, obligations, Cx) as maintainer-only until the conformance suite enforces all semantic invariants.

---

## 7. Unique Insights by Mode

| Mode | Unique Finding | Value |
|------|---------------|-------|
| **F7** | Obligation leak detection is a reinforcing loop — a single leak can cascade through the region tree via `handle_obligation_leaks` -> region cancellation -> more leaks | Architectural risk invisible to non-systems analysis |
| **A3** | `Budget.infinite` has `pollQuota := 0`, making it an annihilator (collapses all quotas to 0) rather than an identity element | Correctness bug in formal spec |
| **H2** | `test-internals` is a DEFAULT feature — downstream consumers get `Cx::for_testing()` which bypasses the capability model | Security design flaw |
| **F4** | `TokenSlab` generation wraps after 256 reuses on 32-bit/WASM targets (RPN=126), causing stale waker dispatch | Production bug with specific trigger conditions |
| **F4** | Browser WASM has no preemptive time-slicing; `browser_ready_handoff_limit` defaults to 0 (disabled) | Adoption-blocking for WASM use case |
| **B6** | OTP port faithful but missing Erlang's strongest feature: process heap isolation. Shared-memory actors can't provide crash isolation. | Architectural limitation of the Spork model |
| **L5** | CLI doctor module (`src/cli/doctor/mod.rs`) is a single 21,756-line file — larger than the scheduler | Scope anomaly |

---

## 8. Risk Assessment

| Risk | Severity | Likelihood | Agreement | Source Modes |
|------|----------|------------|-----------|--------------|
| Bus factor = 1 abandonment | CRITICAL | HIGH | 6/10 | I4, L2, L5, F3, H2, F4 |
| Security vulnerabilities in NIH protocol implementations | HIGH | MEDIUM | 3/10 | L2, L5, I4 |
| Lock ordering deadlock in production (debug checks compiled out) | HIGH | LOW | 2/10 | F4, F7 |
| TokenSlab generation wrap on WASM32 (stale wakers) | HIGH | MEDIUM | 1/10 | F4 |
| Claims-reality gap undermining credibility | MEDIUM | HIGH | 4/10 | H2, I4, L2, A3 |
| Dead math code accumulating audit debt | MEDIUM | HIGH | 4/10 | B9, L5, F7, L2 |
| Ergonomics preventing adoption | MEDIUM | HIGH | 4/10 | I4, B6, F3, L2 |
| Async finalizer deadlock (region never reaches quiescence) | HIGH | LOW | 1/10 | F4 |
| EXP3 entropy collapse under adversarial workload | MEDIUM | LOW | 1/10 | F4 |

---

## 9. Recommendations (Prioritized)

### P0 — Critical

1. **Scope reduction: Extract leaf modules into separate crates** — RaptorQ (26K lines), messaging fabric (76K lines), database clients, CLI doctor (22K lines) should be independent crates. This reduces the core runtime by ~200K+ lines.
   - *Supporting modes:* L5, L2, B9, I4 (4 modes)
   - *Effort:* HIGH | *Impact:* Sustainability transformation

2. **Feature-gate dead math behind `research` flag** — Move persistent homology, sheaf theory, separation logic, Dialectica, session types, martingale certificates, conformal calibration, TLA+ export, and geodesic normalization behind an opt-in feature flag. Keep Lyapunov, EXP3, DPOR integrated.
   - *Supporting modes:* B9, L5, F7, L2 (4 modes)
   - *Effort:* LOW | *Impact:* ~30-40K lines removed from default compilation

3. **Honest maturity claims in README** — Replace "Tokio-scale" with accurate descriptors. Add "Production Readiness" section stating: zero known production deployments, solo maintainer, pre-1.0 API, nightly-only. Remove duplicate "Alien Artifact" section.
   - *Supporting modes:* L2, I4, H2 (3 modes)
   - *Effort:* LOW | *Impact:* Credibility with potential adopters

### P1 — High

4. **Build ergonomic Cx facade** — Create a proc macro or wrapper that provides `tokio::spawn`-like ergonomics for common cases while preserving explicit Cx for correctness-critical code. Write 3 runnable example applications (HTTP server, producer-consumer, database-backed service).
   - *Supporting modes:* I4, B6, F3 (3 modes)
   - *Effort:* MEDIUM | *Impact:* Adoption enablement

5. **Enable lock ordering checks in release mode** — Replace `debug_assert!` with a lightweight runtime check (atomic counter tracking lock order, stripped via feature flag for benchmarks only).
   - *Supporting modes:* F4, F7 (2 modes)
   - *Effort:* LOW | *Impact:* Production deadlock prevention

6. **Fix TokenSlab generation wrap on 32-bit targets** — Use u32 generation everywhere or detect wrap and force reallocation.
   - *Supporting modes:* F4 (1 mode)
   - *Effort:* LOW | *Impact:* WASM correctness

7. **Close the Lyapunov-scheduler loop** — Make the scheduler consume `SchedulingSuggestion` from the Lyapunov governor, creating a closed-loop adaptive controller.
   - *Supporting modes:* F7, B9 (2 modes)
   - *Effort:* MEDIUM | *Impact:* Genuine adaptive runtime behavior

### P2 — Medium

8. **Commission professional security audit of protocol implementations** — TLS, PostgreSQL, MySQL, HTTP wire protocol code should be audited by humans before any production use claim.
   - *Supporting modes:* L2, I4, H2 (3 modes)
   - *Effort:* HIGH | *Impact:* Security assurance

9. **Address `Cx::current()` / ambient authority** — Either remove `Cx::current()` from production paths or document it honestly as a pragmatic escape hatch that violates the capability model.
   - *Supporting modes:* H2, B6 (2 modes)
   - *Effort:* MEDIUM | *Impact:* Claims integrity

10. **Sustainability plan** — Either open leaf modules to contributions or document a succession plan. The current model is incompatible with the project's ambitions.
    - *Supporting modes:* I4, L2 (2 modes)
    - *Effort:* LOW | *Impact:* Long-term viability

---

## 10. New Ideas and Extensions

| Idea | Source Mode | Innovation Score | Rationale |
|------|-----------|-----------------|-----------|
| **"Easy mode" Cx facade** with thread-locals internally, explicit path for correctness-critical code | F3, I4 | Significant | Solves the ergonomics problem without sacrificing the core model |
| **Close the Lyapunov-scheduler loop** — make the scheduler actually respond to governor suggestions | F7 | Significant | Turns observation into adaptive control; unique in the runtime landscape |
| **Publish lab runtime as a standalone crate** — independent of the full runtime | B6, L5 | Significant | The lab runtime (virtual time + DPOR + oracles) is the strongest differentiator and could attract users independently |
| **Jepsen-style integration tests** using the lab runtime | B6 | Significant | The lab infrastructure is perfectly suited for distributed systems testing |
| **Property-based tests for Dialectica contracts** — if the theory modules are kept, they should have property tests that exercise the runtime integration | B6 | Incremental | Bridges theory to practice |
| **Waker refinement proof** — extend Lean model to cover waker/readiness semantics (un-opaque `IsReady`) | A3 | Radical | Would close the most significant formal methods gap |

---

## 11. Assumptions Ledger

| Assumption | Questioned By | Status |
|------------|--------------|--------|
| "Mathematical sophistication = correctness" | B9, L2 | CHALLENGED — sophistication without integration is academic overhead |
| "AI agents can substitute for human contributors" | I4, L2 | CHALLENGED — velocity yes, sustainability and trust no |
| "Full ecosystem buildout is necessary for adoption" | L5, F3 | PARTIALLY SUPPORTED — proves the model scales, but creates unsustainable maintenance burden |
| "Formal methods are paying off" | A3, L2 | SUPPORTED WITH CAVEATS — genuine design discipline value, but marketing exceeds verified scope |
| "Tokio replacement requires building everything from scratch" | L2, I4 | CHALLENGED — core runtime must be independent, but application protocols could use adapters |
| "One person + AI agents can maintain 708K lines" | I4, L2, L5 | REJECTED — all modes assessing sustainability agree this is unsustainable |

---

## 12. Open Questions for the Project Owner

1. **Are there any known production deployments?** The maturity claims would be better calibrated with real-world usage data.

2. **What is the succession plan?** If you cannot work on this project for 6 months, what happens?

3. **Has the spectral health monitor ever detected a real issue that simpler cycle detection missed?** If not, the 3,371 lines are unjustified complexity.

4. **Has persistent homology ever prioritized a schedule exploration seed that led to discovering a bug that random exploration wouldn't have found?** If not, it's research code masquerading as infrastructure.

5. **What is the plan for `Cx::current()`?** Is it a pragmatic escape hatch or an eventual removal target?

6. **Would you consider publishing the lab runtime as a standalone crate?** It's the strongest differentiator and could build an audience independently.

7. **What motivated the messaging fabric?** A 76K-line brokerless messaging system is a major project in its own right — was this driven by a specific use case?

---

## 13. Confidence Matrix

| Finding | Confidence | Supporting Modes | Dissenting Modes |
|---------|-----------|-----------------|-----------------|
| K1: Scope exceeds limits | 0.93 | L5, I4, L2, F3, B9, H2 | None |
| K2: Dead math code | 0.90 | B9, L5, F7, L2 | F3 (partial value) |
| K3: Claims exceed implementation | 0.91 | H2, I4, L2, A3 | None |
| K4: Ergonomics barrier | 0.90 | I4, B6, F3, L2 | None |
| K5: Formal methods genuine but narrow | 0.92 | A3, H2, L2, L5 | None |
| S1: Lock ordering debug-only | 0.78 | F4, F7 | — |
| S2: Sensors without actuators | 0.77 | F7, B9 | — |
| S3: Two-phase effects strongest innovation | 0.92 | B6, F3 | — |
| S4: Lab runtime strongest differentiator | 0.90 | B6, F7 | — |

---

## 14. Contribution Scoreboard

| Mode | Code | Findings | Unique | Evidence Quality | Calibration | Mode Fidelity | Score |
|------|------|----------|--------|-----------------|-------------|---------------|-------|
| Adversarial-Review | H2 | 10 | 3 | 0.95 (specific file:line refs) | 0.90 | 0.95 | **0.89** |
| Scope-Control | L5 | 10 | 3 | 0.92 (line counts, ratios) | 0.88 | 0.93 | **0.86** |
| Simplicity/MDL | B9 | 9 | 4 | 0.90 (grep zero-callers proof) | 0.85 | 0.92 | **0.85** |
| Formal-Verification | A3 | 10 | 2 | 0.95 (theorem references) | 0.92 | 0.95 | **0.84** |
| Perspective-Taking | I4 | 10 | 2 | 0.85 (API surface analysis) | 0.85 | 0.90 | **0.82** |
| Systems-Thinking | F7 | 9 | 2 | 0.85 (feedback loop mapping) | 0.82 | 0.88 | **0.79** |
| Failure-Mode (FMEA) | F4 | 14 | 3 | 0.88 (FMEA scores with RPNs) | 0.80 | 0.92 | **0.82** |
| Counterfactual | F3 | 9 | 0 | 0.80 (architectural reasoning) | 0.85 | 0.88 | **0.72** |
| Debiasing | L2 | 8 | 1 | 0.88 (commit counts, grep data) | 0.85 | 0.90 | **0.78** |
| Analogical | B6 | 9 | 1 | 0.85 (cross-domain comparison) | 0.85 | 0.88 | **0.76** |

**Diversity metric:** 6 of 12 categories represented, 5 of 7 axes spanned. Coverage is good; missing categories (C: Uncertainty, D: Vagueness, G: Practical, J: Modal, K: Domain-specific) would add marginal value for this project type.

---

## 15. Mode Performance Notes

**Most productive:** H2 (Adversarial) — produced the most damaging and well-evidenced findings. The `Cx::current()` falsification and `unwrap()` count are knockout observations.

**Most unique:** B9 (Simplicity) — the systematic `grep` for zero-callers across mathematical modules produced findings no other mode could generate. The positive identification of Lyapunov as "math done right" provided essential balance.

**Most surprising:** A3 (Formal Verification) — expected to simply validate the Lean proofs. Instead, identified the `Budget.infinite` identity bug and the critical `opaque IsReady` gap. The nuanced assessment ("genuine but narrow") was exactly what synthesis needed.

**Least productive:** F3 (Counterfactual) — confirmed that major architectural decisions were correct, which is valuable but produced zero unique findings. The counterfactual analysis reinforced rather than challenged.

**Best calibrated:** A3 and H2 — their confidence scores closely matched evidence quality. L2 was slightly overconfident on the Ikea effect finding (0.75 confidence for a speculative psychological claim).

---

## 16. Mode Selection Retrospective

**Good choices:** H2 (Adversarial) and B9 (Simplicity) were the highest-value modes. H2 found concrete falsifications of marketing claims. B9 proved the dead-code finding with grep evidence.

**Would add:** G4 (Prioritization) — a dedicated prioritization mode would have helped rank the 580K lines of non-core code by extraction urgency. K2 (Scientific) — a scientific reasoning mode could have designed experiments to test whether the mathematical machinery provides measurable improvement.

**Would drop:** F3 (Counterfactual) — while useful for confirming decisions, it produced no unique findings. The insights it generated were already captured by other modes.

---

## 17. Appendix: Individual Mode Outputs

Full outputs available in the project root:
- `MODE_OUTPUT_F7.md` — Systems-Thinking (9 findings, 0.80 confidence)
- `MODE_OUTPUT_A3.md` — Formal Verification (10 findings, 0.82 confidence)
- `MODE_OUTPUT_H2.md` — Adversarial Review (10 findings, 0.85 confidence)
- `MODE_OUTPUT_B6.md` — Analogical Reasoning (9 findings, 0.80 confidence)
- `MODE_OUTPUT_I4.md` — Perspective-Taking (10 findings, 0.82 confidence)
- `MODE_OUTPUT_F4.md` — Failure-Mode FMEA (14 findings, 0.78 confidence)
- `MODE_OUTPUT_L5.md` — Scope Control (10 findings, 0.87 confidence)
- `MODE_OUTPUT_B9.md` — Simplicity/MDL (9 findings, 0.83 confidence)
- `MODE_OUTPUT_F3.md` — Counterfactual (9 findings, 0.85 confidence)
- `MODE_OUTPUT_L2.md` — Debiasing (8 findings, 0.82 confidence)

---

## 18. Appendix: Provenance Index

| Report Finding | Source Mode | Source §F | Report Section |
|---------------|-----------|-----------|---------------|
| Scope exceeds limits | L5 | F1, F7 | K1 |
| Bus factor = 1 | I4 | F3 | K1 |
| Dead math code (sheaf, homology) | B9 | F1, F2 | K2 |
| Dead math code (obligation theory) | B9 | F3 | K2 |
| Dead math code (martingale certs) | B9 | F4 | K2 |
| Cx::current() falsifies claims | H2 | F1 | K3 |
| 34 global statics | H2 | F2 | K3 |
| 5,043 unwrap() in library code | H2 | F3 | K3 |
| HashMap non-determinism in production | H2 | F4 | K3 |
| 677 todo!/panic! sites | L2 | F6 | K3 |
| &Cx ergonomic tax | I4 | F1 | K4 |
| Toy examples | I4 | F2 | K4 |
| Lean proofs genuine but narrow | A3 | F1-F8 | K5 |
| IsReady opaque predicate | A3 | F2 | K5 |
| Lock ordering debug-only | F4 | F3 | S1 |
| Lyapunov not consumed by scheduler | F7 | F3 | S2 |
| Two-phase effects innovation | B6 | F1 | S3 |
| Lab runtime differentiator | B6 | F7 | S4 |
| TokenSlab generation wrap | F4 | F6 | §7 Unique |
| Budget.infinite annihilator bug | A3 | F10 | §7 Unique |
| OTP missing process isolation | B6 | F2 | §7 Unique |
| Obligation leak reinforcing loop | F7 | F2 | §7 Unique |

---

*Generated by 10-agent modes-of-reasoning swarm. Total analysis time: ~25 minutes. Total findings: 98 across 10 modes, synthesized into 5 kernel, 5 supported, 3 divergent, and 7 unique findings.*
