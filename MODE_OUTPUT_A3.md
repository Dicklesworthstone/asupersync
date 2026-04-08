# MODE_OUTPUT_A3: Formal Verification Analysis

## Thesis

Asupersync's formal verification investment is unusually serious for a Rust project: 5,210 lines of Lean 4 mechanizing 185 theorems across 22 step constructors, covering all 6 declared core invariants with zero `sorry` and zero errors at build time. The proofs are genuine -- well-formedness preservation, obligation lifecycle completeness, cancellation termination via Lyapunov potential, and single-owner structural invariants are all constructively verified against a faithful small-step operational semantics. However, the verification operates on an idealized model that deliberately abstracts away concurrency (locks, atomics, Arc), I/O drivers, the async executor, and waker mechanics -- the exact subsystems where production bugs live. The formal methods are paying off as a design discipline enforcer and regression barrier, but they cannot catch the classes of bugs (data races, lock ordering violations, waker lost-wakeup) that dominate the project's actual bug history.

## Top Findings

### F1: All 6 Core Invariants Are Constructively Proven (No Sorry, No Axioms)

**Evidence:** `formal/lean/Asupersync.lean` contains 5,210 lines with 185 theorems. `grep sorry` returns 0 matches. The only `opaque` declaration is `IsReady` (line 237), which is a deliberate abstraction of waker/readiness semantics. The `invariant_status_inventory.json` confirms all 6 invariants at `fully_proven` status with 0 gaps.

**Reasoning:** This is a strong result. The proofs cover: (1) structured concurrency via `SingleOwner` + `WellFormed` preservation across all 22 step constructors, (2) region close = quiescence via `close_implies_quiescent` and decomposition theorems, (3) cancellation protocol termination via `cancel_potential` Lyapunov function with strict decrease, (4) race-loser drain via `race_loser_drain_completeness`, (5) no obligation leaks via `execution_obligation_lifecycle_completeness`, and (6) no ambient authority via `no_ambient_effect_without_context`. Each proof operates by exhaustive case analysis over the `Step` inductive, which is mechanically total.

**Severity:** Positive finding (significant asset).
**Confidence:** 0.95

### F2: The Opaque `IsReady` Predicate Hides the Waker/Executor Gap

**Evidence:** Line 237: `opaque IsReady {Value Error Panic : Type} : State Value Error Panic -> TaskId -> Prop`. This is used only in the `enqueue` step constructor (line 321). Being `opaque`, no lemma can unfold it -- it is a black box.

**Reasoning:** `IsReady` abstracts the entire waker notification mechanism, which is precisely where lost-wakeup bugs occur (the project's MEMORY.md documents the `Arc<AtomicBool>` waker dedup pattern as a key technical detail and `Sleep::with_time_getter` as a footgun that "skips waker registration"). The formal model cannot reason about whether tasks that should be ready actually become ready. Liveness properties that depend on waker correctness (e.g., "a task that is awaiting a channel send will eventually be woken when the receiver drains") are unprovable in this model.

**Severity:** HIGH -- this is the most significant semantic gap between spec and implementation.
**Confidence:** 0.92

### F3: Concurrency / Lock Ordering Is Entirely Outside the Formal Model

**Evidence:** The Lean model uses pure functional state (`State Value Error Panic` with `fun r' => if r' = r then ...` for updates). The Rust implementation uses `Arc`, `AtomicU64`, `RwLock`, sharded locks with ordering `E(Config) > D(Instrumentation) > B(Regions) > A(Tasks) > C(Obligations)`, and `ContendedMutex`. None of these appear in the formal model.

**Reasoning:** The formal model is a sequential interleaving semantics. It proves that if transitions fire in a valid order, invariants hold. But the implementation's actual invariants depend on lock ordering, atomic memory ordering (the MEMORY.md notes "CAS consuming resource needs Acquire (not Release)"), and the absence of TOCTOU races between state checks and state mutations. The `region.try_reserve_obligation()` implementation (region.rs:587-609) performs a double-checked lock pattern that is not modeled. `resolve_obligation()` uses `saturating_sub` which silently absorbs underflow -- the spec's strict ledger accounting doesn't model this tolerance.

**Severity:** HIGH -- the gap between sequential model and concurrent implementation is the classical verification challenge.
**Confidence:** 0.90

### F4: `step_preserves_wellformed` Covers All 22 Constructors (Genuine Preservation Proof)

**Evidence:** Lines 3170-3253 of Asupersync.lean dispatch over every `Step` constructor: `enqueue`, `scheduleStep`, `spawn`, `schedule`, `complete`, `reserve`, `commit`, `abort`, `leak`, `cancelRequest`, `cancelMasked`, `cancelAcknowledge`, `cancelFinalize`, `cancelComplete`, `cancelChild`, `cancelPropagate`, `closeBegin`, `closeCancelChildren`, `closeChildrenDone`, `closeRunFinalizer`, `close`, `tick`. The `step_constructor_coverage.json` confirms 22/22 covered, 0 partial, 0 missing.

**Reasoning:** This is the most valuable theorem in the file. It means that no matter what sequence of valid transitions fires, the structural invariants (task-region consistency, obligation-holder consistency, ledger-reserved correspondence, children existence, subregion existence) are maintained. The proof routes through well-factored helpers (`scheduler_change_preserves_wellformed`, `setTask_same_region_preserves_wellformed`, `setRegion_structural_preserves_wellformed`, `resolve_preserves_wellformed`) that make the preservation argument modular and maintainable.

**Severity:** Positive finding (strong structural guarantee).
**Confidence:** 0.95

### F5: Cancellation Termination Proof Is Rigorous but Assumes Task Cooperation

**Evidence:** The `cancel_potential` function (line 3278) assigns: `cancelRequested -> mask + 3`, `cancelling -> 2`, `finalizing -> 1`, `completed -> 0`. Four theorems prove strict decrease: `cancel_masked_potential_decreases`, `cancel_acknowledge_potential_decreases`, `cancel_finalize_potential_decreases`, `cancel_complete_potential_reaches_zero`. The bound is `mask + 3` steps.

**Reasoning:** The Lyapunov argument is clean and correct for the model. However, in the implementation, cancellation termination also depends on: (a) the task actually reaching a checkpoint (the model's `cancelAcknowledge` requires `mask = 0` but not that the task reaches a checkpoint call), (b) cleanup code completing within budget, and (c) finalizers terminating. The model's `cancelFinalize` transition is unconditional (line 478-484: no guard on "cleanup done"), meaning the model allows instant transition from `cancelling` to `finalizing` without modeling what the cleanup code actually does. This is correct abstractly (the step relation is nondeterministic), but it means the bound of `mask + 3` steps does not translate to a wall-clock bound without additional assumptions about task behavior.

**Severity:** MEDIUM -- the proof is honest about its assumptions but the gap is subtle.
**Confidence:** 0.88

### F6: Runtime `can_region_complete_close` Checks `task_count() > 0` Rather Than `allTasksCompleted`

**Evidence:** `src/runtime/state.rs:2386-2388`: the runtime checks `region.task_count() > 0` (tasks removed from list after cleanup) rather than checking each task's state is `Completed`. The Lean model's `Quiescent` (line 268) requires `allTasksCompleted s r.children` -- that every child in the children list has `taskCompleted` state.

**Reasoning:** This is an intentional implementation optimization: tasks are removed from the region's children list upon cleanup, so checking `task_count() > 0` is equivalent to `allTasksCompleted` under the invariant that tasks are only removed after completion. But this equivalence is not formalized. The runtime comment at line 2384-2386 explicitly acknowledges this: "We cannot just check if they are terminal, because their `task_completed` cleanup might not have run yet." This reveals a temporal gap: the model's `taskCompleted` corresponds to a state the implementation passes through transiently, while the runtime uses a different (removal-based) quiescence signal.

**Severity:** MEDIUM -- sound under implementation invariants but the refinement is unproven.
**Confidence:** 0.85

### F7: The `SingleOwner` Invariant Is Proven Inductively but Not Connected to Rust Type System Enforcement

**Evidence:** The `SingleOwner` structure (line 4221) proves bidirectional ownership: `ChildrenOwnParent` (every child's `task.region` matches the parent region) and `TaskInParentChildren` (every task appears in its parent's children list). `step_preserves_single_owner` and `steps_preserve_single_owner` prove preservation through all transitions.

**Reasoning:** In the implementation, single ownership is enforced by the `Scope` API: `scope.spawn()` takes `&mut RuntimeState` and a region reference, adding the task to that region's children. There is no direct connection (refinement proof or generated assertion) linking the Lean `SingleOwner` to the Rust `Scope::spawn`. The invariant is likely maintained in practice (the audit found the `RemoteHandle::join()` cancel leak but not ownership violations), but the formal guarantee operates on the model, not the code. A Rust task could theoretically be added to the wrong region's children list through an internal API misuse without the Lean proof detecting it.

**Severity:** MEDIUM -- the proof is meaningful as a design constraint but lacks runtime binding.
**Confidence:** 0.82

### F8: Obligation Lifecycle Proves "No Leak from Proper Lifecycle" but `no_leak_from_proper_lifecycle` Is Conditional

**Evidence:** Line 4980: `theorem no_leak_from_proper_lifecycle` requires the hypothesis `hProper`: that no task completes while holding a reserved obligation. Line 5000: `execution_obligation_lifecycle_completeness` proves that at close time the ledger is empty and all obligations have valid holders.

**Reasoning:** The `no_leak_from_proper_lifecycle` theorem is conditional -- it says "if tasks always resolve their obligations before completing, then no leak step fires." This is the right theorem to state, but the hypothesis is not discharged. Whether tasks actually resolve obligations before completing depends on implementation-level RAII (Drop impls on permit types). The project has found multiple obligation-leak bugs (MEMORY.md documents "RemoteHandle::join() cancel path leaked runtime state" and "FlushGuard RAII" fixes), confirming that the hypothesis can fail in practice. The formal model correctly identifies leaks as a semantic error (the `LEAK` step constructor) but cannot prevent them.

**Severity:** MEDIUM -- the conditional nature is mathematically honest but means the "no leak" guarantee has assumptions the implementation must satisfy through coding discipline.
**Confidence:** 0.87

### F9: The Formal Semantics Document Is Exceptionally Well-Structured as a Refinement Target

**Evidence:** `asupersync_v4_formal_semantics.md` defines domains (S1.1-1.12), global state (S2), and 15+ transition rules (S3+) with explicit preconditions, labels, and code alignment notes (e.g., lines 401-413 map `pick_next` pseudocode to `ThreeLaneScheduler::next_task` branches). The Lean mechanization follows this structure faithfully, with cross-references to Rust source files in theorem comments (e.g., line 833-843 referencing `src/record/region.rs:659-720`).

**Reasoning:** The spec document serves as the refinement bridge. It is rare to see this level of discipline in an async runtime. The Mazurkiewicz trace theory (S1.8), linear resource discipline (S1.9), and game-theoretic cancellation interpretation (S3.2.5) are not just decoration -- they inform the Lean model's structure. The scheduler fairness lemma (lines 380-413) with explicit code alignment notes demonstrates genuine spec-code correspondence tracking.

**Severity:** Positive finding (high-quality formal documentation).
**Confidence:** 0.93

### F10: Budget Algebra Proofs (Commutativity, Associativity) Are Complete but Identity Element Has a Bug

**Evidence:** Line 1650-1651: `Budget.infinite` is defined as `{ deadline := none, pollQuota := 0, costQuota := none, priority := 0 }`. The `pollQuota` is `0`, but `Budget.combine` uses `Nat.min` for `pollQuota`, so `combine(b, infinite) = { ..., pollQuota := min(b.pollQuota, 0) = 0, ... }`. This means `Budget.infinite` is NOT an identity -- it collapses all poll quotas to 0.

**Reasoning:** For `Budget.infinite` to be a true identity, `pollQuota` should be some maximal value (e.g., `Nat` has no max, so this requires choosing a convention). The section is named `BudgetIdentity` but contains only the helper lemmas `minOpt_none_left` and `minOpt_none_right` -- there is no `Budget.combine_infinite_left` or `Budget.combine_infinite_right` theorem. This suggests the identity proof was attempted but abandoned when the definition was found to be incorrect.

**Severity:** LOW -- the identity element is not used by any other proof, and the commutativity/associativity proofs are correct.
**Confidence:** 0.80

## Risks Identified

1. **Refinement gap is unproven:** No simulation/bisimulation relation connects the Lean `State` to the Rust `RuntimeState`. The proofs guarantee the model is self-consistent, but the model-code correspondence relies on manual audit and conformance tests (~843 lines in `refinement_conformance.rs`), not formal proof.

2. **Waker correctness is the largest unmodeled subsystem:** Lost wakeups, spurious wakeups, and waker deduplication are documented as real bug sources but are entirely outside the formal model's scope.

3. **Async executor / poll loop is not modeled:** The `Step` relation assumes tasks are polled when ready, but the actual polling mechanism (cooperative yielding, task stealing, work-queue management) is not formalized. Fairness under real scheduling depends on `three_lane.rs` implementation correctness.

4. **54 Lean warnings remain:** The baseline report shows `warnings_total: 54` across all runs. While these are not errors, they indicate unused variables or deprecated patterns that may complicate future maintenance.

5. **Model drift risk:** The Lean file was last significantly updated around March 2026. The Rust codebase continues to evolve with ~65 bugs found and fixed since the audit began. Each bug fix potentially introduces a model-code divergence that is not automatically detected.

## Recommendations

**P0: Establish automated refinement checking.**
Add a CI step that extracts the Rust state machine transitions (region state, task state, obligation state) and compares them against the Lean model's `Step` constructors. Even a simple enum-matching check would catch model drift.

**P1: Model the waker/readiness subsystem.**
Replace the `opaque IsReady` with a minimal waker model: a set of pending wakers and a rule for waker firing. This would allow proving basic liveness properties like "a committed send permit eventually wakes the receiver."

**P1: Fix `Budget.infinite` or remove the identity section.**
Either define `pollQuota` as a large sentinel value and prove the identity laws, or delete the `BudgetIdentity` section to avoid confusion.

**P2: Add refinement assertions in the runtime.**
Instrument `RuntimeState` methods with `debug_assert!` checks that mirror the Lean `WellFormed` predicate: task.region exists, obligation.holder exists, ledger contains only reserved obligations. These would serve as dynamic refinement checks.

**P2: Prove `task_count() == 0` equivalence to `allTasksCompleted` under the task-removal invariant.**
Either formalize in Lean or add a detailed proof comment in `state.rs:2384-2400` explaining why the implementation's quiescence check is equivalent to the model's.

**P3: Discharge the `no_leak_from_proper_lifecycle` hypothesis.**
Model RAII Drop semantics for obligation permits to prove that the `hProper` hypothesis is satisfied for the standard channel/sync primitives. This is the hardest recommendation but would close the most significant conditional gap.

**P4: Reduce the 54 Lean warnings.**
Clean up unused variables and deprecated patterns to maintain build hygiene and make the frontier burndown dashboard more useful.

## New Ideas and Extensions

1. **Property-based testing bridge:** Generate random `Step` sequences in Rust, apply them to both the Lean model (via extraction) and the Rust runtime, and compare resulting states. This would be a practical alternative to a full simulation proof.

2. **TLA+ model checking for concurrency:** The spec mentions TLA+ export capability. Model the lock-ordering and atomic-operation aspects in TLA+ and check for deadlocks and races, complementing the Lean safety proofs with concurrent model checking.

3. **Certified code extraction:** For critical state machine transitions (cancel protocol, region close), extract Lean definitions to Rust code that replaces the hand-written implementation. This would close the refinement gap for the most safety-critical paths.

4. **Obligation type-state encoding:** Encode the obligation lifecycle (Reserved -> Committed/Aborted/Leaked) as Rust type states using the typestate pattern, making the `no_leak_from_proper_lifecycle` hypothesis a compile-time guarantee rather than a runtime discipline.

5. **Waker model via ghost state:** Model waker registration as ghost state in the Lean model -- an auxiliary map from `TaskId` to `Set<WakerToken>` that doesn't affect transitions but enables proving wakeup completeness properties.

## Assumptions Ledger

| # | Assumption | Where Used | Risk if Wrong |
|---|-----------|-----------|---------------|
| A1 | The Lean model's `Step` constructors faithfully represent all runtime transitions | All invariant proofs | Proofs would be vacuously true for missing transitions |
| A2 | `IsReady` is satisfiable and consistent | Enqueue step, scheduler proofs | Tasks could be permanently stuck without violating any theorem |
| A3 | Tasks cooperate by calling `checkpoint()` | Cancellation termination | Cancellation could hang indefinitely for non-cooperative tasks |
| A4 | Finalizers terminate within budget | Region close completeness | Regions could fail to close, violating quiescence |
| A5 | Lock ordering is never violated | All runtime invariants | Data races could silently corrupt state that the model assumes consistent |
| A6 | The `RegionRecord.remove_task` operation maintains the task-in-region bijection | SingleOwner invariant | Task could be in a region's children list without the region knowing, or vice versa |
| A7 | `saturating_sub` in `resolve_obligation` never fires (obligations are not double-resolved) | Obligation lifecycle | The model's strict ledger accounting would diverge from implementation behavior |

## Questions for Project Owner

1. Has the Lean file been built successfully against a recent Lean 4 toolchain? The coverage logs show the last build was Feb 2026 with `lean4+rust-nightly-2026-02-05`. Has it been rebuilt since the March/April bug fixes?

2. Are there plans to formalize any concurrency aspects (lock ordering, atomic operations) in either Lean or TLA+?

3. The `no_leak_from_proper_lifecycle` hypothesis -- is there a runtime check that detects when a task completes with held obligations, beyond the `LEAK` step firing? Is this logged/alerted in production?

4. The 54 Lean warnings -- are these being tracked for cleanup, or are they considered acceptable?

5. Is there a mechanism to detect when a Rust code change invalidates a Lean model assumption? The refinement map JSON exists but does it trigger CI failures?

## Points of Uncertainty

- **Lean build freshness:** The last logged build was Feb 2026. The 54 warnings are stable across runs, but the file has been modified since (March 2026 timestamps on coverage files). Whether it still builds cleanly with the current Lean 4 toolchain is unknown.

- **Conformance test coverage depth:** The `refinement_conformance.rs` (843 lines) and `region_lifecycle_conformance.rs` (557 lines) exist, but I did not audit their assertion density. They could be thorough or cursory.

- **Whether `step_preserves_single_owner` covers all constructors:** I confirmed `step_preserves_wellformed` covers all 22, and `SingleOwner` preservation helpers exist for each constructor category, but the master `step_preserves_single_owner` theorem itself was not fully read (it appears in search results at line 3960+ but may use `sorry` in branches I didn't inspect). Given the file has 0 `sorry` occurrences, this concern is resolved.

- **Runtime `advance_region_state` faithfulness:** This iterative state machine driver (state.rs:2417+) is the runtime's close protocol implementation. Its correspondence to the Lean `closeBegin -> closeCancelChildren -> closeChildrenDone -> closeRunFinalizer -> close` sequence has not been formally verified.

## Agreements and Tensions with Other Perspectives

**Agrees with Security (A2):** The no-ambient-authority proof (`no_ambient_effect_without_context`) formally backs the capability-security claims. The `CapabilitySet` partial order proof is a genuine formal guarantee that capability narrowing composes correctly.

**Agrees with Testing (A4):** The conformance test suite bridges formal and empirical. The invariant status inventory cross-references theorems to specific test files, creating a traceability chain from proof to executable check.

**Tension with Performance (A5):** The formal model's sequential semantics cannot verify the correctness of performance optimizations (SeqCst -> Acquire/Release, sharded locking, `saturating_sub`). Performance changes are the most likely to introduce refinement divergences.

**Tension with Pragmatic Engineering (A1):** The formal methods investment (~5K lines of Lean, ~100K tokens of coverage metadata) is substantial. For a project with ~65 bugs found through manual audit, the question of whether formal methods prevented bugs versus documented existing design intent is relevant. The Lyapunov cancellation termination proof, for instance, was likely formalized after the design was already correct, not used to discover the design.

**Tension with Concurrency Analysis (A6):** The formal model deliberately avoids concurrency modeling, yet the project's most critical bugs (waker dedup, lock ordering, atomic ordering) are concurrency bugs. A TLA+ or DPOR-based approach might provide more direct value for the actual bug landscape.

## Confidence: 0.82

**Calibration note:** High confidence in the accuracy of findings about what is proven (the Lean file is readable and the proofs are genuine). Moderate confidence in the assessment of what gaps matter most in practice -- this depends on the project's actual failure modes in production, which I can only infer from the documented bug history. The formal verification is genuinely strong for what it covers; the main uncertainty is whether what it covers is what most needs covering.
