# MODE_OUTPUT_F7: Systems-Thinking Analysis of Asupersync

## Thesis

Asupersync is a deeply coupled control system where five interacting subsystems -- the region ownership tree, the obligation registry, the three-lane scheduler, the cancellation protocol, and the Lyapunov/e-process monitoring layer -- form a network of reinforcing and balancing feedback loops that collectively guarantee convergence to quiescence. The system's structural invariants (no orphan tasks, no leaked obligations, bounded cancellation) are emergent properties of these interacting loops rather than properties of any single subsystem. This architecture creates extraordinary strength (correctness *is* the structure) but also extraordinary fragility at the seams between subsystems, where delays in one loop can cascade through others. The development system -- a solo maintainer coordinating 20+ AI agents -- mirrors this architecture: high parallelism with tight coupling through a shared codebase, creating a meta-system with its own reinforcing/balancing dynamics.

---

## Top Findings

### F1: The Region-Cancel-Scheduler Triangle Is a Balancing Loop With Delay

**Evidence:** `src/runtime/state.rs:1711` (`cancel_request`) propagates cancellation down the region tree, producing `(TaskId, priority)` pairs. These are injected into the cancel lane of the three-lane scheduler (`src/runtime/scheduler/three_lane.rs`). When tasks complete via `task_completed` (line 1989), `advance_region_state` (line 2070) drives the region through Closing -> Draining -> Finalizing -> Closed. Each region close may trigger further cancellation of sibling tasks (line 1646, `cancel_sibling_tasks`).

**Reasoning:** This is a **balancing loop** (B1): cancel request -> schedule cancel-lane tasks -> tasks complete -> region advances -> region closes -> parent region advances. The loop drives V(Sigma) toward zero. However, there is a **structural delay**: async finalizers (line 2460-2470) block region advancement until a scheduler picks them up. If the cancel lane is saturated, finalizer tasks may be starved, creating a secondary delay in the convergence path. The EXP3 adaptive streak limit (line 267) introduces a *variable* delay -- the system tunes its own convergence speed, which could oscillate if the reward signal is noisy.

**Severity:** MEDIUM -- the delay is bounded by the cancel_streak_limit (max 64, from `ADAPTIVE_STREAK_ARMS`), but the interaction between EXP3 arm selection and Lyapunov potential descent is not directly coupled. The EXP3 reward is computed from epoch snapshots (`AdaptiveEpochSnapshot`), not from the Lyapunov governor's `suggest()` output, meaning two independent optimization signals could conflict.

**Confidence:** 0.85

---

### F2: Obligation Leak Detection Is a Reinforcing Loop Under Stress

**Evidence:** `src/runtime/state.rs:2028-2038` -- when a non-cancelled task completes, the system checks for leaked obligations via `collect_obligation_leaks_for_holder`. If leaks exist, `handle_obligation_leaks` is called, which increments `leak_count` (line 361). When `leak_count` exceeds the escalation threshold (`leak_escalation`), the system can escalate to region cancellation. The reentrance guard `handling_leaks` (line 363-367) exists specifically because leak handling can trigger `advance_region_state`, which discovers *more* leaks.

**Reasoning:** This is a **reinforcing loop** (R1): task completes with leaks -> handle_obligation_leaks -> escalation may cancel region -> children cancelled -> more tasks complete -> discover more leaks. Without the reentrance guard, this would be unbounded recursion. With it, the loop is bounded but can still amplify: a single obligation leak in a deep region tree could trigger cascading region cancellation up to the root. The `handling_leaks` boolean is a stock-gating mechanism -- it converts what would be exponential amplification into linear processing.

**Severity:** HIGH -- the interaction between obligation leak escalation and region cancellation is the most dangerous positive feedback path in the system. If `LeakEscalation` thresholds are set too low, a benign coding error (forgetting to commit a send permit) could collapse the entire region tree.

**Confidence:** 0.80

---

### F3: The Lyapunov-Scheduler-EProcess Chain Is an Observability Loop With No Actuation

**Evidence:** `src/obligation/lyapunov.rs:621` -- `suggest()` computes a `SchedulingSuggestion` (DrainObligations, DrainRegions, MeetDeadlines, NoPreference). `src/cancel/progress_certificate.rs` consumes potential values from this governor to issue probabilistic convergence certificates. `src/lab/oracle/eprocess.rs` provides anytime-valid invariant monitoring via e-processes.

**Reasoning:** These three components form a **monitoring chain** but with a critical gap: the Lyapunov governor *suggests* but does not *actuate*. The `SchedulingSuggestion` enum is returned but I find no evidence that the three-lane scheduler consumes it in its dispatch loop. The scheduler's actual priority is hardcoded: cancel > timed > ready (line 4-5 of three_lane.rs doc comment). The Lyapunov-EProcess chain is therefore an **open-loop sensor** in production -- it measures but does not steer. In the lab runtime it feeds oracles for test assertions, but in production the feedback loop is broken.

**Severity:** MEDIUM -- this is a leverage point. Closing this loop (making the scheduler actually respond to Lyapunov suggestions) would create a powerful closed-loop controller. Currently the system relies on the structural properties of the cancel/region/obligation loops rather than adaptive control.

**Confidence:** 0.75

---

### F4: The Two-Phase Channel Protocol Creates a Stock-Flow Bottleneck

**Evidence:** `src/channel/mpsc.rs:1-20` -- the reserve/commit pattern means every send creates an obligation (a "stock" in the obligation registry). The obligation exists from `reserve()` until either `permit.send()` (commit) or drop (abort). `src/runtime/state.rs:2056-2058` -- on task completion, all pending obligations are force-aborted.

**Reasoning:** The obligation registry is a **stock** that accumulates during periods of high concurrency and drains during quiescence. Under burst workloads, the obligation table could grow very large (every in-flight channel send holds a slot). The flow rate in (reservations) is controlled by channel backpressure, but the flow rate out (commits/aborts) depends on scheduler throughput. If the scheduler is bottlenecked (e.g., by cancel-lane saturation), obligations accumulate, the Lyapunov potential rises, and (if the monitoring loop were closed) the system would need to prioritize obligation drain. Since the loop is open (F3), the system relies on structural drainage through task completion.

**Severity:** LOW-MEDIUM -- the two-phase protocol is fundamentally sound, but under extreme load the obligation table could become a memory pressure point. The force-abort on task completion (line 2056-2058) is the safety valve.

**Confidence:** 0.80

---

### F5: The 20+ Agent Development System Has Reinforcing Quality Debt

**Evidence:** `MEMORY.md` documents 65+ bugs found across 587 files by audit, with bugs continuing to be found in each new batch of agent-written code. The audit itself is performed by AI agents (TurquoiseDune, SapphireHill), creating a `write -> audit -> fix -> write` loop. `AGENTS.md` Rule 0 ("I AM IN CHARGE, NOT YOU") and Rule 1 ("NO FILE DELETION") reflect learned-the-hard-way guardrails from agent misbehavior.

**Reasoning:** The development system exhibits a **reinforcing loop** (R2): more agents writing code -> more code to audit -> more bugs found -> more fixes needed -> more agent work -> more code. The solo maintainer is the **bottleneck stock** -- all merge decisions, design decisions, and override decisions flow through one person. This is a classic "limits to growth" archetype: agent parallelism (the growth engine) is bounded by maintainer review capacity (the limiting factor). The audit backlog (65+ bugs found, ongoing discoveries) is the system's shadow inventory. The MEMORY.md file itself (210 lines, 24.8KB, only partially loaded) is a symptom: the coordination overhead is growing faster than the codebase.

**Severity:** HIGH -- this is a systemic risk, not a code risk. The development velocity is impressive but the quality assurance depends on AI-auditing-AI, which has known false positive rates (see "Explore agent unreliable" lesson in MEMORY.md).

**Confidence:** 0.85

---

### F6: The Spectral Health Monitor Is a Leading Indicator With No Trailing Response

**Evidence:** `src/observability/spectral_health.rs:1-63` -- monitors the Fiedler value (second-smallest eigenvalue of the graph Laplacian) for early warning of structural fragmentation. Detects approach to bifurcation points where the system could abruptly transition from healthy to degraded.

**Reasoning:** This is a **sensor for emergent behavior** -- it detects when the task/region dependency graph is approaching a critical transition. The spectral gap is genuinely a systems-level metric: it captures global connectivity that no local check can see. However, like the Lyapunov governor (F3), this is observe-only. There is no actuator that responds to a degrading Fiedler value (e.g., by throttling new region creation or preemptively cancelling weakly-connected subgraphs). The comment on line 17-19 explicitly notes this limitation: "Zero or disconnected spectral connectivity is a topology signal, not by itself a proof of trapped wait-cycle deadlock."

**Severity:** LOW -- as a sensor it is valuable for the lab runtime and diagnostics. The risk is that users will assume it provides protection when it only provides observation.

**Confidence:** 0.75

---

### F7: Deterministic Replay Creates a Closed Verification Loop

**Evidence:** `src/lab/runtime.rs:1-8` -- virtual time, deterministic scheduling, trace capture. `src/trace/dpor.rs:1-34` -- DPOR race detection identifies alternative schedules to explore. `src/trace/replay.rs` -- replays recorded traces. The lab runtime's `run_until_quiescent_with_report()` returns oracle reports that assert structural invariants.

**Reasoning:** This is the system's strongest **balancing loop** (B2): write code -> lab test with deterministic scheduling -> DPOR finds races -> explore alternative schedules -> discover bugs -> fix code. Unlike production monitoring (F3, F6), this loop is *closed*: the output (bug reports) feeds back into the input (code changes). The virtual clock eliminates time-based non-determinism, making the entire state space traversal reproducible. This is the primary mechanism by which the system's emergent properties (cancel-correctness, quiescence) are validated.

**Severity:** N/A (this is a strength, not a risk)

**Confidence:** 0.90

---

### F8: Lock Ordering Is a Fragile Constraint With No Runtime Enforcement

**Evidence:** `MEMORY.md` specifies lock ordering: E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations). `src/runtime/state.rs` shows `RuntimeState` holds `regions: RegionTable`, `tasks: TaskTable`, `obligations: ObligationTable` as separate fields, but many methods take `&mut self`, which serializes access. The `ShardedState` with `ContendedMutex` (mentioned in MEMORY.md) allows independent locking.

**Reasoning:** Lock ordering is a **constraint** on the system's state space that prevents deadlock -- a form of structural invariant like the region tree's ownership property. However, unlike the region tree (which is enforced by the type system via `RegionId` containment), lock ordering is enforced by convention and code review. With 20+ agents writing code, each potentially acquiring locks in different orders, this is a **fragile invariant**. The `ShardedState` design mitigates this by reducing the need for multi-lock acquisition, but any new code that holds two locks simultaneously is a deadlock risk.

**Severity:** MEDIUM -- the 23 tests (from bd-3gyn2, per MEMORY.md) provide regression coverage, but the test surface is finite while the code surface grows with each agent contribution.

**Confidence:** 0.70

---

### F9: The Severity Lattice Creates Monotone Escalation With No De-escalation Path

**Evidence:** `src/record/region.rs:24-47` -- region states form a one-way progression: Open -> Closing -> Draining -> Finalizing -> Closed. The `Outcome` type uses a severity lattice: Ok < Err < Cancelled < Panicked. `src/supervision.rs:1-39` -- supervision strategies can Restart, Stop, or Escalate, but cannot "downgrade" a severity.

**Reasoning:** The severity lattice is a **monotone system** by design: once a region enters Draining, it cannot return to Open. This ensures progress toward quiescence (the Lyapunov function can only decrease). However, this means the system has no **recovery path** short of creating a new region. If a transient failure (network hiccup) triggers cancellation of a deep region subtree, the entire subtree must be rebuilt from scratch via supervision restart. The restart is a **discrete jump** in the system state, not a smooth recovery. For long-lived server processes, this could cause availability cliffs where a brief perturbation leads to a long recovery period (supervision backoff, region reconstruction, state replay).

**Severity:** MEDIUM -- this is a deliberate design choice (monotonicity ensures progress) but creates a tradeoff between safety and availability.

**Confidence:** 0.80

---

## Risks Identified

1. **Cascading obligation leak escalation (R1, from F2):** A misconfigured `LeakEscalation` threshold could cause a single leaked obligation to collapse the entire region tree via cascading cancellation.

2. **EXP3-Lyapunov conflict (from F1):** Two independent optimization signals (EXP3 cancel streak tuning and Lyapunov potential descent) could produce oscillating scheduling behavior if their reward signals diverge.

3. **Development system scaling ceiling (from F5):** The solo-maintainer bottleneck will eventually cap effective agent parallelism, creating a backlog of unreviewed changes that accumulates quality debt.

4. **Lock ordering violation under agent churn (from F8):** As more agents contribute code, the probability of inadvertent lock ordering violations increases quadratically with the number of independent contributors.

5. **Availability cliff under transient failures (from F9):** The monotone severity lattice means recovery from brief perturbations may require full region-tree reconstruction, causing disproportionate downtime.

6. **Open monitoring loops in production (from F3, F6):** The Lyapunov governor and spectral health monitor observe but do not actuate, leaving the system without adaptive control in production.

---

## Recommendations

### P0 (Critical)

- **Close the Lyapunov-scheduler loop.** Wire `LyapunovGovernor::suggest()` output into the three-lane scheduler's dispatch decision. This would create a closed-loop controller that accelerates convergence during drain phases and protects deadlines during normal operation. Start with a soft influence (bias probabilities) rather than hard override.

### P1 (High)

- **Add integration tests for obligation leak escalation cascades.** Specifically test the R1 reinforcing loop: create a region tree of depth N, leak one obligation at the leaf, and verify that escalation behavior is bounded and predictable. Test with various `LeakEscalation` threshold settings.

- **Instrument the EXP3/Lyapunov divergence.** Add a metric that tracks when the EXP3-selected cancel streak limit conflicts with the Lyapunov governor's suggestion (e.g., EXP3 selects arm=64 while Lyapunov suggests DrainObligations). This makes the F1 conflict observable.

### P2 (Medium)

- **Consider a recovery region primitive.** The monotone severity lattice is correct for safety, but a "soft restart" mechanism that preserves region identity while resetting its task set would reduce the availability cliff from F9. This could be modeled as a new state: `Open -> SoftRestart -> Open` that preserves the region's position in the tree but clears its task set.

- **Add compile-time lock ordering checks.** The `ShardGuard` system from bd-3gyn2 provides runtime coverage, but a proc-macro that statically verifies lock acquisition order in functions that touch multiple tables would provide stronger guarantees against F8.

### P3 (Low)

- **Document the system's feedback loop architecture.** The interactions between regions, obligations, scheduler, Lyapunov, EProcess, and spectral monitor form a control system that is currently documented only implicitly through code. A formal control-flow diagram showing the reinforcing/balancing loops would help new contributors (including AI agents) avoid breaking invariants.

- **Add a Spectral Health actuator.** When the Fiedler value drops below the degraded threshold, automatically throttle new region creation (reduce the "inflow" to the dependency graph). This closes the F6 observation loop.

### P4 (Nice-to-have)

- **Formalize the development system as a queuing model.** The solo maintainer is a single-server queue with 20+ Poisson arrivals. Calculate the expected backlog size and determine whether the system is stable (arrival rate < service rate) or accumulating unbounded debt.

---

## New Ideas and Extensions

1. **Lyapunov-guided work stealing.** Instead of the current Power of Two Choices (stealing from the most loaded queue), use the Lyapunov potential breakdown to preferentially steal tasks whose completion would maximally decrease V(Sigma). This connects the monitoring layer to a latent scheduling decision.

2. **Spectral partitioning for region isolation.** When the Fiedler vector identifies the minimum graph cut, use this information to isolate weakly-connected region subtrees into separate scheduling domains. This would prevent failures in one partition from propagating to others.

3. **Meta-e-process for development quality.** Apply the same e-process statistical framework used for invariant monitoring to the development process itself: track the bug discovery rate per agent, and raise an alert when the e-value exceeds a threshold (indicating a statistically significant increase in bug density).

4. **Adaptive escalation thresholds.** Instead of a fixed `LeakEscalation` threshold, use a CUSUM (cumulative sum) detector that adapts to the baseline leak rate. This would prevent the R1 cascade risk from F2 while still detecting genuine degradation.

5. **Hierarchical cancel streak limits.** Instead of a single EXP3-tuned streak limit per worker, allow different limits per region depth. Leaf regions (likely short-lived) could have aggressive cancel limits, while root regions (long-lived servers) could have conservative limits that prefer ready-lane throughput.

---

## Assumptions Ledger

| # | Assumption | Basis | Risk if wrong |
|---|-----------|-------|---------------|
| A1 | The Lyapunov governor's `suggest()` output is not consumed by the production scheduler | Searched for references to `SchedulingSuggestion` in three_lane.rs, found only the type import | If consumed, F3 would be a strength rather than a gap |
| A2 | The EXP3 reward signal and Lyapunov potential are independently computed | Reviewed `AdaptiveEpochSnapshot` and `LyapunovGovernor` -- no shared state | If coupled, F1 conflict risk is lower |
| A3 | The obligation table has no hard capacity limit | Did not find a `max_obligations` config | If bounded, F4 stock accumulation would hit backpressure sooner |
| A4 | Lock ordering violations are possible in agent-contributed code | Based on convention-based enforcement per MEMORY.md | If the ShardGuard system catches all violations at test time, F8 risk is lower |
| A5 | The solo maintainer reviews all merges | Inferred from AGENTS.md rules and MEMORY.md coordination notes | If automated CI gates catch most issues, F5 scaling ceiling is higher |

---

## Questions for Project Owner

1. **Is the Lyapunov governor's scheduling suggestion consumed anywhere in production?** If not, is this intentional (observability only) or a planned feature?

2. **What is the expected steady-state obligation table size under peak load?** Is there a design target for maximum pending obligations?

3. **Has the R1 cascade (obligation leak -> escalation -> region cancellation -> more leaks) been observed in lab testing?** What `LeakEscalation` thresholds are used in practice?

4. **Is the EXP3 adaptive cancel streak used in production, or only in the lab runtime?** The deterministic RNG (`DetRng`) suggests lab-only usage.

5. **How do you manage the merge bottleneck with 20+ agents?** Is there a queuing discipline (FIFO, priority, batching) or is it ad-hoc?

6. **Are there plans to add a "soft restart" or region recovery mechanism?** The monotone severity lattice guarantees safety but may limit availability for long-lived services.

---

## Points of Uncertainty

- **The degree of coupling between the three-lane scheduler and the Lyapunov governor in practice.** I found no direct call path, but there may be indirect coupling through the lab runtime's oracle suite that I did not trace.

- **The actual bug introduction rate per agent.** MEMORY.md records ~65 bugs across ~587 files, but the rate may have decreased as the codebase matured and audit coverage increased.

- **Whether the spectral health monitor is used in production or is lab-only.** The lack of an actuator suggests lab-only, but the implementation appears production-ready.

- **The effective delay in the cancel-region-scheduler balancing loop.** The worst case is bounded by `cancel_streak_limit` * number of workers, but the average case depends on workload characteristics that vary.

---

## Agreements and Tensions with Other Perspectives

- **Agrees with Formal Verification (F4):** The Lyapunov function, martingale certificates, and e-processes are formal methods applied at runtime. The systems view agrees these are powerful but notes they are sensors without actuators (F3).

- **Agrees with Security (F2):** The capability model (`Cx` as explicit authority) is structurally sound. The systems view adds that the *development process* is itself a security boundary -- 20+ AI agents with code write access is a large attack surface for inadvertent defects.

- **Tension with Performance (F5):** The two-phase channel protocol (F4) adds latency to every send operation. From a systems perspective, this is a deliberate tradeoff (correctness stock) that slows the flow rate. Performance-oriented analysis might see this as unnecessary overhead in the common case.

- **Tension with Simplicity (F6):** The system has extraordinary mathematical sophistication (Lyapunov functions, spectral analysis, e-processes, DPOR, EXP3). From a systems perspective, each additional feedback sensor adds complexity to the interaction graph. If the sensors do not actuate (F3, F6), they add cognitive load without proportional benefit in production.

- **Agrees with Resilience Engineering:** The monotone severity lattice (F9) is resilience-correct (always make progress toward safety) but creates brittleness (no graceful recovery path). This is the classic safety-liveness tension.

---

## Confidence: 0.78

**Calibration note:** High confidence in the structural analysis of feedback loops (F1, F2, F7) because these are directly visible in the code. Moderate confidence in the production impact assessments (F3, F6) because I could not trace all call paths in a 310K-line codebase. Lower confidence in the development system analysis (F5) because it relies partly on inference from MEMORY.md rather than direct observation. The codebase is extraordinarily well-engineered; most of my findings are about *gaps between subsystems* rather than defects within them.
