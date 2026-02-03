# Asupersync 4.0 Design Bible

## A spec-first, law‑abiding, cancel‑correct, capability‑secure async runtime for Rust

### (single-thread → multi-core → distributed) with deterministic testing, trace replay, and formalizable semantics

> **North Star:** inside Asupersync’s capability boundary, every concurrent program has (1) a well‑founded ownership tree, (2) explicit cancellation driven to quiescence, (3) deterministic resource cleanup, and (4) compositional building blocks whose semantics are *lawful* and testable under a deterministic lab runtime.

This is a **blank‑slate** design: Asupersync owns the scheduler, cancellation protocol, region model, and (optionally) the I/O reactor. It is built only on Rust’s stable `async/await` and `core::future::Future` + `std::task::{Waker, RawWaker}`.

---

## 0. Executive summary

Asupersync is not “an executor plus helpers.” It is a **semantic platform**:

* A **small kernel** of primitives with a **precise operational semantics**.
* A **capability/effect boundary** (`Cx`) that prevents ambient authority and makes determinism + distribution real.
* **Structured concurrency by construction** (tasks are owned; regions close to quiescence).
* **Cancellation as a protocol**: request → drain → finalize (idempotent, budgeted, schedulable).
* **Two‑phase effects by default** where cancellation can otherwise lose data: reserve/commit + ack tokens + leases.
* **Obligation tracking** (permits/acks/leaves/finalizers) so “futurelock” and effect leaks become detectable and testable.
* A **lab runtime** with virtual time and deterministic scheduling (plus DPOR‑class exploration hooks) so concurrency bugs become testable.
* A **distributed story that is honest**: named computations + leases + idempotency + sagas, not “serialize closures across machines.”

If you use Asupersync primitives, you get **cancel correctness**, **no orphan tasks**, **bounded cleanup**, **predictable shutdown**, and **replayable traces**.

---

## 1. Goals, non-goals, and the soundness frontier

### 1.1 Goals

1. **No orphaned work**: all spawned work is owned by a region; region close guarantees quiescence.
2. **Cancellation you can reason about**: explicit request with downward propagation, upward outcome reporting, and bounded cleanup.
3. **No silent data loss** under cancellation for library primitives (channels, streams, queues, RPC handles).
4. **Local reasoning**: inside a region, “when I leave this block, nothing from it is still running, and its resources are closed.”
5. **Composable concurrency**: join/race/timeout/hedge/quorum/pipeline/retry are safe and interoperable.
6. **Performance + scalability**: zero-cost where possible; predictable overhead where not.
7. **Distributed orchestration**: remote tasks behave like local tasks *semantically*, with explicit leases + idempotency.
8. **Deterministic testability**: virtual time, deterministic scheduling, trace replay, schedule exploration hooks.

### 1.2 Non-goals (core crate)

* Not a full web framework.
* Not “exactly once” distributed execution (we provide *idempotency + leases*; exactly once is a system property).
* Not magical cancellation for arbitrary user futures: non‑cooperative futures can still stall. We define escalation boundaries explicitly.
* Not a compiler feature: we do not require language changes (but we can optionally integrate nightly features).

### 1.3 The soundness frontier (explicit tiers)

Rust today cannot safely support “spawn arbitrary borrowing future onto an arbitrary worker thread” without restrictions.
Asupersync encodes this honestly via **tiers**:

1. **Fibers**: borrow-friendly, region‑pinned, same-thread execution.
2. **Tasks**: parallel, `Send`, migrate across worker threads; captures must be `Send` + valid for region lifetime via region heap.
3. **Actors**: long-lived supervised tasks (still region-owned; no “detached by default”).
4. **Remote tasks**: named computations executed elsewhere with leases + idempotency.

This tiering is *the* mechanism that makes “best ever” credible instead of hand‑wavy.

---

## 2. Glossary

* **Region**: the unit of structured concurrency. Owns tasks/fibers/actors/resources/finalizers; closes to quiescence.
* **Scope**: the typed user handle to a region (`Scope<'r, …>`).
* **Quiescence**: no live children + all registered finalizers have run to completion (or escalated per policy).
* **Outcome**: terminal result of a task/region: Ok / Err / Cancelled / Panicked.
* **Cancellation checkpoint**: an explicit observation point where cancellation can take effect.
* **Masking**: temporarily defer responding to cancellation (bounded by budgets).
* **Obligation**: a linear “must be resolved” token (permit/ack/lease/finalizer handle). Dropping an obligation has defined semantics (abort/nack) and is detectable in lab mode.
* **Two-phase effect**: reserve (cancel-safe) then commit (linear, bounded masking).
* **Lab runtime**: deterministic scheduler + virtual time + trace capture + replay.

---

## 3. The mathematical spine

This section is not decoration. Every algebraic claim corresponds to a real engineering win: fewer surprises, more optimization freedom, and test oracles.

### 3.1 Outcomes form a severity lattice (policy-aware)

We model terminal states with a four-valued outcome:

```
Ok(V) < Err(E) < Cancelled(R) < Panicked(P)
```

This is a **default severity order** used for:

* region outcome aggregation defaults,
* supervision escalation defaults,
* trace summarization.

Policies may override combination behavior, but must remain **monotone**: “worse” states cannot become “better” when aggregated.

### 3.2 Concurrency operators form a near‑semiring (up to observational equivalence)

Two core combinators:

* `⊗` = **Join**: run both, wait both, combine outcomes under policy.
* `⊕` = **Race**: first terminal outcome wins; losers are cancelled and drained.

We treat laws as semantic (observational equivalence under the spec), not “Rust tuple ordering.”

#### Laws (core)

* Associativity:

  * `(a ⊗ b) ⊗ c  ≃  a ⊗ (b ⊗ c)`
  * `(a ⊕ b) ⊕ c  ≃  a ⊕ (b ⊕ c)`
* Identities:

  * `a ⊗ ⊤ ≃ a` where `⊤` is “immediate unit”
  * `a ⊕ ⊥ ≃ a` where `⊥` is “never completes”
* Cancellation correctness law:

  * **Race never abandons losers**: `a ⊕ b` must (1) choose winner, (2) cancel losers, (3) drain losers, then (4) return winner.

#### Conditional laws (opt-in / requires policy + adapter)

* Commutativity:

  * `a ⊗ b ≃ b ⊗ a` if combining is commutative or treated as multiset.
  * `a ⊕ b ≃ b ⊕ a` when symmetric (same type, no schedule-sensitive side effects).

#### Why laws matter

They enable:

* derived combinators with consistent semantics,
* DAG-level optimization when using the `plan` module,
* deterministic test oracles.

#### True concurrency: the semantics is *not* “a total order”

Most runtimes specify concurrency via **interleavings** (total orders of steps). That is an implementation model, not the right mathematics.
The right semantic object is a **trace equivalence class**:

* define an **independence relation** `I` on observable labels (e.g. “two steps commute because they touch disjoint regions/obligations”),
* quotient schedules by adjacent swaps of independent actions (`…ab… ≃ …ba…` when `(a,b) ∈ I`),
* reason about programs up to this equivalence (a **Mazurkiewicz trace** / partial order), not up to a brittle single schedule.

Why this matters inside Asupersync:

* **DPOR becomes semantics-preserving**, not a heuristic: the lab runtime explores **one representative per trace class** (see §18).
* **Trace replay becomes canonicalizable**: you can normalize executions (Foata normal form / “parallel layers”) and compare runs robustly.
* **Observational equivalence** (`≃`) becomes a real thing: many semiring laws are “true up to commuting independent work,” which is exactly what we want for lawful rewrites and plan optimization.

There is an even deeper view (useful later, not required day‑1): the space of executions forms a **directed topological space**; commutations become 2‑cells (squares), higher commutations become higher cubes, and schedule equivalence is **directed homotopy** (dihomotopy). This is the geometric backbone behind "don't explore the same concurrency twice."

*Practical note:* For finite discrete systems, Mazurkiewicz trace equivalence *is* the discrete version of dihomotopy equivalence—optimal DPOR already achieves the topological reduction. The d‑space perspective is a cleaner mathematical lens, not a more powerful algorithm.

#### Experiment: geodesic schedule normalization (Phase 5+)

**Goal:** define a canonical representative per trace class that reduces context switches while preserving observable meaning.

**Normalization procedure (small model):**

1. Define an independence relation `I` on observable labels (same notion as DPOR).
2. Build a dependency DAG: for each pair `i < j`, add edge `i → j` if `(label_i, label_j) ∉ I`.
3. Compute the Foata normal form by repeatedly taking all minimal elements (no incoming edges) as a "parallel layer".
4. Linearize each layer with a stable order (task id, then original index). This yields a deterministic schedule.
5. Optional refinement: define switch cost (# of task changes) and choose the minimum-switch linear extension. The geodesic is the shortest path in the "swap graph" of adjacent independent swaps.

**Toy example (two tasks, independent steps):**

* Task A steps: `a1, a2`; Task B steps: `b1, b2`.
* Raw schedule `S = a1 b1 a2 b2` has 3 task switches.
* Foata layers: `[a1 b1][a2 b2]`.
* Canonical linearization (stable by task id): `a1 a2 b1 b2` has 1 switch.
* Both schedules are trace-equivalent; normalization reduces switches without changing observable outcomes.

**Comparison metrics:** switch count, swap distance to normal form, and trace length (should be identical). Normalized traces should be shorter in "visual entropy" and more stable for diff/replay.

**Tie-in to DPOR/Mazurkiewicz:** adjacent swaps of independent actions are 2-cells; the space of schedules is a cubical complex. Geodesic normalization picks a shortest path in that complex. DPOR already picks one representative per trace class; this normalization makes that representative deterministic and human-readable for replay and debugging.

#### Experiment: persistent directed homology for schedule prioritization (Phase 5+)

**Goal:** prioritize schedules that expose "essential holes" (ordering constraints, deadlock shapes) in the execution space.

**Data required from executions:**

* event structure / partial order with independence relation `I`
* happens-before edges and resource-acquire edges
* cancellation points (to identify truncated regions)
* schedule prefix lengths (for filtration)

**Concrete proxy + filtration + scoring (spec):**

**Proxy complex (local commutation square complex):**

- 0-cells are events in the prefix, indexed by sequence number.
- 1-cells are dependency edges from the trace poset (event structure) restricted to the prefix.
- 2-cells are commuting diamonds: `a→b`, `a→c`, `b→d`, `c→d` with `b < c` and `a < b,c < d`.
- This is the same local commutation proxy used by `src/trace/boundary.rs`.

**Filtration (exact):**

- Parameter `t` is prefix length (`t = 1..n`).
- `K_t` is the square complex built from the trace poset restricted to the first `t` events.
- Monotone: `K_t ⊆ K_{t+1}` by construction (we only add events/edges/squares as `t` grows).

**Scoring (exact):**

- Compute H1 persistence pairs over GF(2) for the filtered complexes `K_1..K_n`.
- Let each pair be `(birth, death)` with `death = n+1` if unpaired.
- Define `persistence = death - birth`.
- Score is a deterministic lexicographic tuple:
- `(long_lived, total_persistence, beta1_final, -n, fingerprint)`
- Rank by lexicographic descending order (higher is better).
- `long_lived` = count of pairs with `persistence ≥ P_min` (default `P_min = 3`).
- `total_persistence` = sum of `persistence` for all pairs.
- `beta1_final` = H1 Betti number of `K_n`.
- `fingerprint` = trace fingerprint (Foata/trace hash) as stable tie-break.

**Performance bounds + fallback:**

- Proxy size: `|V| = O(n)`, `|E| = O(n·d)`, `|S| = O(n²·d)` where `d` is max out-degree.
- Persistence reduction is cubic in matrix size; cap by fixed limits:
- `MAX_VERTICES = 512`, `MAX_EDGES = 20_000`, `MAX_SQUARES = 200_000`, `MAX_MATRIX_BYTES = 64 MiB`.
- If any cap is exceeded, skip persistence and use fallback score:
- `fallback_score = (beta1_final, indep_density, -n, fingerprint)`
- Rank fallback score lexicographically descending.
- `indep_density = (# independent pairs in prefix) / (t·(t-1)/2)` from the trace poset.

**Toy example (classic deadlock shape):**

* Two tasks acquire locks in opposite order: `A: L1 → L2`, `B: L2 → L1`.
* The independence relation admits interleavings that form a cycle in the wait-for graph.
* The cubical complex contains a 1-cycle corresponding to "either order leads to deadlock".
* The heuristic should prioritize the schedule prefix that creates the cycle early, surfacing the deadlock faster than uniform exploration.

**Success metric:** compared to uniform exploration, the heuristic reaches known deadlock or ordering bugs in fewer schedules (lower expected exploration count) in a deterministic lab benchmark.

#### Prototype: static obligation leak checker (Phase 5+)

**Goal:** conservatively flag code paths that may exit a scope while still holding unresolved obligations.

**Abstract domain (flow-sensitive, may-analysis):**

* `Held ⊆ ObligationKind` — the set of obligation kinds that may be pending at a program point.
* `⊔` (join) is set union, `⊥` is empty set.

**Transfer rules (core subset):**

* `reserve(kind)` ⇒ `Held := Held ∪ {kind}`
* `commit(kind)` / `abort(kind)` ⇒ `Held := Held \\ {kind}`
* unknown call ⇒ `Held := Held ∪ Summary(call)` (conservative summary)
* scope exit / function return: if `Held` non-empty ⇒ emit warning.

**Prototype scope (small model):**

* Model only a restricted IR: a list of operations `{reserve, commit, abort, call, branch, loop}`.
* Provide summaries for a small set of functions that manipulate obligations (e.g., semaphore acquire/release, pool checkout/return).
* Diagnostics sorted by (file, line, obligation kind) for determinism.

**Toy example:**

```
reserve(permit)
if cond { commit(permit) }
return
```

* The analysis reports: `permit` may be leaked on the `cond = false` branch.
* If both branches commit/abort, no warning is emitted.

**Prototype deliverable:** a deterministic checker that runs on a hand-written IR (or a tiny subset extracted from `sync/` primitives), emits stable warnings, and is wired into CI as a non-flaky report (warning-only at first).

**Tie-in:** complements the dynamic `ObligationLeakOracle` by catching obvious leaks earlier, without compromising determinism.

#### Experiment: graded / quantitative types for obligations and budgets (Phase 5+)

**Goal:** make “no obligation leaks” a type error in an opt-in surface and encode budget usage as a resource grade.

**Sketch (obligations):**

* `Obligation<K, n>` where `n` is a type-level natural (how many unresolved obligations of kind `K` are held).
* `reserve<K>() -> Obligation<K, 1>`
* `commit(ob: Obligation<K, 1>) -> Obligation<K, 0>`
* `abort(ob: Obligation<K, 1>) -> Obligation<K, 0>`
* `scope` requires all `Obligation<*, n>` to be `n = 0` at exit.

**Sketch (budgets):**

* `Budget<d, q, c>` where grades track deadline/quotas (or a single scalar for now).
* `spend(b: Budget<d, q, c>, cost) -> Budget<d', q', c'>` with `d' ≤ d`, `q' ≤ q`, `c' ≤ c`.
* `fork`/`join` operations require grades to satisfy the semiring laws (min on constraints, add on sequential cost).

**Toy API (leak is untypeable):**

```
fn safe_path() {
    let permit: Obligation<Permit, 1> = reserve::<Permit>();
    let _done: Obligation<Permit, 0> = commit(permit);
}

fn leak_path() {
    let _permit: Obligation<Permit, 1> = reserve::<Permit>();
    // no commit/abort => does not type-check at scope exit
}
```

**Prototype plan:** implement a tiny opt-in module using const generics or typenum (no runtime cost), and prove with compile-fail tests that leaking obligations is rejected. Extend later to encode budget grades.

### 3.3 Budgets compose by a product semiring (min core)

Budgets propagate by “stricter wins”:

```
Budget = Deadline × PollQuota × CostQuota × TraceCtx × Priority
combine(parent, child) = componentwise_min(parent, child)  // except priority: max
```

This gives automatic propagation for deadlines and quotas and makes “why did this cancel?” reasoning local.

#### Budget algebra as idempotent/tropical structure (for planning and scheduling)

The product budget above is an **idempotent** algebra (“tightening twice is the same as tightening once”). When we start doing *planning* (pipelines, DAGs, retries, hedges), we also need a second composition mode:

* **Sequential composition** accumulates time/cost (`+`).
* **Constraint propagation** tightens deadlines/quotas (`min` / meet).

This lands naturally in the world of **tropical / idempotent semirings** (e.g. `(ℝ∪{∞}, min, +)` for best‑case bounds, or `(ℝ∪{∞}, max, +)` for worst‑case critical paths).
Practical payoff:

* the `plan` module can compute **critical paths**, **slack**, and "where did my budget go?" explanations using shortest‑path style algorithms;
* policies and governors can treat budgets as **grades**: a task is scheduled only when it can make progress without violating its grade (deadline/poll/cost).

**Tropical matrix example:**
Budget propagation through a task tree is tropical matrix multiplication:

```
effective_budget[leaf] = min_{path root→leaf} Σ edge_costs
```

This is Floyd-Warshall in the tropical semiring `(ℝ∪{∞}, min, +)`. Critical path = longest path in the `(max, +)` dual.

---

## 4. Non-negotiable invariants

### I1. Tree ownership of live work

Every live task/fiber/actor is owned by exactly one region; regions form a rooted tree.

### I2. Region close = quiescence

A region cannot finish until:

1. all children reach terminal outcomes, and
2. all registered finalizers have run (subject to budgets/escalation policy), and
3. all in-flight **obligations** registered to the region are resolved.

### I3. Cancellation is a protocol (idempotent)

Cancellation is request → drain → finalize, driven by the scheduler.

### I4. Two-phase effects are default when loss is possible

If cancellation can lose data, the safe pattern is the natural one.

### I5. Losers are cancelled and drained

Any combinator that stops awaiting a branch must still drive it to terminal (or escalate).

### I6. Determinism is first-class

Every kernel primitive has a deterministic lab interpretation.

### I7. No ambient authority

All effects flow through explicit capabilities (`Cx`).

---

## 5. Capability/effect boundary (`Cx`)

### 5.1 Capability principles

* No hidden globals required for correctness.
* Effects require explicit capabilities.
* Deterministic substitution: swap `Cx` to change interpretation (prod vs lab vs remote).

#### `Cx` as algebraic effects + handlers (spec level)

Treat the `Cx` surface as an **effect signature** (checkpoint, sleep, trace, reserve/commit, etc.) and each runtime (prod/lab/remote) as a **handler**.
The purpose is not academic purity; it is to make these facts precise:

* **same user program, different interpretation** (lab vs prod) without changing its meaning,
* explicit **equational laws** for optimization and testing.

Example laws we want to hold (up to observational equivalence):

* `trace(e1); trace(e2)  ≃  trace(e2); trace(e1)` when `e1` and `e2` are independent (different tasks/regions),
* `checkpoint(); checkpoint()  ≃  checkpoint()` when no cancel is requested,
* `sleep_until(t1); sleep_until(t2)  ≃  sleep_until(max(t1,t2))` in a model where sleeps only delay readiness.

### 5.2 Core `Cx` surface (kernel)

* identity: `region_id()`, `task_id()`
* budgets: `budget()`, `now()`
* cancellation: `is_cancel_requested()`, `checkpoint()`, `with_cancel_mask()`
* scheduling: `yield_now()`
* timers: `sleep_until()`
* tracing: `trace(event)`

### 5.3 Capability tiers (typed tokens)

* `FiberCap<'r>`: spawn fibers, borrow `'r`, not `Send`.
* `TaskCap<'r>`: spawn `Send` tasks with region-safe storage.
* `IoCap<'r>`: submit I/O; binds in-flight ops to region quiescence.
* `RemoteCap<'r>`: remote named tasks with leases.
* `SupervisorCap<'r>`: supervised actors/restarts.

---

## 6. Regions and scopes

### 6.1 Region lifecycle states

```
Open → Closing → Draining → Finalizing → Closed(outcome)
```

### 6.2 Region close semantics (normative)

1. Mark closing (spawns forbidden).
2. If policy dictates or cancel requested, cancel remaining children.
3. Drain children to terminal outcomes (cancel lane prioritized).
4. Run finalizers (masked, budgeted).
5. Resolve obligations (permits/acks/leases/in-flight I/O).
6. Compute region outcome (policy-defined).

### 6.3 Scope API contracts

* `'r` ties handles to region lifetime.
* Handles are affine; join consumes.
* Dropping handle does not detach work; region still owns task.

### 6.4 Compositional reasoning: separation + rely/guarantee (spec language)

Asupersync’s invariants become dramatically easier to verify if we commit to a compositional logic *in the docs*:

* **Separation logic / separation algebras**: region resources (tasks, obligations, finalizers, in‑flight I/O) are *owned*, and ownership composes with `*` (“disjoint union”).
  * The **frame rule** is the workhorse: proving one component doesn’t require re‑proving the whole world.
* **Rely/Guarantee**: every primitive states what it *relies* on (e.g. fairness assumptions, “parent won’t reclaim region heap while I run”) and what it *guarantees* (e.g. “I checkpoint at most every `k` polls,” “I resolve all obligations before completion”).

This is the right formal home for "Region close = quiescence" and "no obligation leaks" as compositional contracts, not folklore.

**Separation logic assertion syntax:**

```
region(r, s, B)              region r in state s with budget B
task(t, r, S)                task t owned by r in state S
obligation(o, k, t, r)       obligation o of kind k held by t in region r
P * Q                        P and Q hold for disjoint resources
emp                          empty (no resources)
```

Example invariant: `region(r, Open, B) * task(t, r, Running) * obligation(o, Permit, t, r)` asserts disjoint ownership of region, task, and obligation.

---

## 7. Cancellation: explicit, enumerable, schedulable

### 7.1 Task cancellation state machine

```
Created
Running
CancelRequested { reason, budget }
Cancelling     { deadline, poll_budget }
Finalizing     { deadline, poll_budget }
Completed(outcome)
```

### 7.2 Idempotent strengthening

Multiple cancel requests merge: earlier deadline + stricter quotas + higher severity wins.

### 7.3 Checkpoints, masking, commit sections

Primitives declare cancellation behavior:

* checkpointing
* masked (bounded)
* commit (linear token; bounded mask by construction)

### 7.4 Cancel lane priority

Scheduler lanes:

1. cancel
2. timed (EDF-ish)
3. ready

### 7.5 Escalation boundaries

Modes:

* Soft: wait indefinitely (strict correctness).
* Bounded: after deadline/budget, abort-by-drop or panic (policy-controlled, trace-recorded).

### 7.6 Cancellation as an adversarial protocol (game semantics, quantitative)

Cancellation is not a flag; it is a **protocol** between:

* **System** (scheduler/runtime): wants quiescence within a budget.
* **Task** (user future): may cooperate, delay (mask), or stall.

Think of it as a two‑player game with bounded resources:

* System move: `request_cancel(reason, budget)`
* Task moves: `checkpoint`, `mask(k)` (bounded), `work`
* System wins iff the task reaches `Completed(Cancelled(_))` (or other terminal) within the budget under fair scheduling.

Spec requirement (the real "math" promise): primitives must publish a **cancellation responsiveness bound**—at least "max polls between checkpoints" and "max masking depth." Budgets are then not vibes; they are **sufficient conditions** for the system to have a winning strategy (LaSalle/Lyapunov style arguments in §11.5 can mechanize this).

**Theorem (Cancellation Completeness):**
For any task with mask depth `M` and checkpoint interval `C`, if `cleanup_budget ≥ M × C × poll_cost`, then System wins (task reaches terminal state within budget under fair scheduling).

### 7.7 (Optional) Cancellation as annihilation (Geometry of Interaction intuition)

For deep reasoning and future tooling, it is useful to view cancellation as introducing a **zero/annihilator** into a computation’s interaction graph:

* “commit sections” are bounded feedback loops,
* cancellation forces certain paths to evaluate to `0` (no further effect) unless masked,
* obligations ensure that even when a branch is annihilated, its linear resources are conserved (aborted/nacked) rather than leaked.

You do not need this to implement Phase‑0, but it is a powerful conceptual model for bounding cleanup cost and proving "cancellation cannot silently drop linear effects."

*Practical note:* The full GoI formalism (nilpotent operators, trace in a *‑algebra) would require encoding programs as interaction nets—a research project. The operational approach (bounded masks + checkpoint contracts + the Completeness theorem in §7.6) provides equivalent static guarantees with far less machinery.

---

## 8. Two-phase effects + linear obligations

### 8.1 Obligations

Linear tokens:

* `SendPermit<T>` → `send` or `abort`
* `Ack` → `commit` or `nack`
* `Lease` → renew or expire
* `IoOp` → complete/cancel before close

Tracked in obligation registry; `Drop` is safe-by-default (abort/nack) and can be “panic-on-drop” in lab.

#### Linear logic and session types are the *spec* for obligations

The obligation system is not “like” linear logic — it **is** a linear resource discipline:

* obligations live in a linear context `Δ` (“must be used exactly once”) rather than the unrestricted context `Γ`,
* `reserve` introduces a linear resource (`Δ := Δ, o`),
* `commit/abort/nack/expire` eliminates it (`Δ := Δ \\ {o}`),
* reaching the end of a scope with `Δ ≠ ∅` is an **obligation leak**, i.e. a semantic error.

This same idea reappears in **session types** for communication:

* Sender protocol: `reserve → (send | abort)`
* Receiver protocol: `recv → (commit | nack)`

We can start with runtime enforcement (obligation registry + lab checks) and later add stronger static structure (`#[must_use]`, typestate, session-typed endpoints) without changing the meaning.

**Session type notation for two-phase send:**

```
S = !reserve.(?abort.end ⊕ !T.end)
R = dual(S) = ?reserve.(!abort.end ⊕ ?T.end)
```

Reading: Sender (`S`) outputs `reserve`, then either inputs `abort` and terminates, or outputs payload `T` and terminates. Receiver (`R`) is the dual. The `⊕` is internal choice (sender picks); the corresponding `&` in the dual is external choice (receiver follows).

### 8.2 Reserve/commit channels

```
let permit = tx.reserve(cx).await?;
permit.send(msg);
```

Drop permit => abort and release capacity; message not moved => no silent loss.

### 8.3 Ack tokens

```
let (item, ack) = rx.recv_with_ack(cx).await?;
process(item, cx).await?;
ack.commit(); // drop => nack
```

### 8.4 RPC: leases + idempotency

Reserve slot + idempotency key; commit sends; cancel triggers best-effort cancel; lease bounds orphan work.

### 8.5 Permit drop semantics

Release mode: auto-abort/nack + telemetry.
Debug/lab: configurable panic.

### 8.6 Futurelock detector

Detect “holds obligations but stops being polled” conditions; fail in lab/debug.

### 8.7 Obligation accounting as a Petri net / VASS (verification leverage)

For verification and schedule exploration, treat obligations as a **vector addition system**:

* each `reserve(kind)` adds a token to a place,
* each `commit/abort/nack/expire` removes a token,
* region close requires the marking to be **zero**.

This yields simple linear invariants (“no negative tokens,” “close implies zero marking”) that are easy to check from traces and can be used as property‑based test oracles.

### 8.8 Static leak checking (abstract interpretation hook)

Even without a full type system, we can build a sound static check:

* abstract state: “may hold unresolved obligations of kind K” per scope/task,
* `reserve` sets “may hold,” `commit/abort` clears,
* exiting a scope with “may hold” is a compile‑time warning/error.

This is an **abstract interpretation** in the Cousot–Cousot sense: sound, possibly conservative, and extremely valuable as the codebase grows.

---

## 9. Resource management and finalization

### 9.1 Finalizer stack (LIFO)

`defer_async` and `defer_sync`. Run after drain, under cancel mask, LIFO.

### 9.2 Bracket + commit sections

`bracket(acquire, use, release)` with release masked/budgeted.
`commit_section(fut)` for bounded masked critical commits.

### 9.3 Optional async-drop integration

Future-proof; not required.

---

## 10. Memory: region heap + quiescent reclamation

Region owns an arena; reclaimed at close after quiescence.
`RRef<'r, T>` can be `Send`/`Sync` when `T` is.
Debug/lab can attach obligation metadata to allocations.

---

## 11. Scheduling

### 11.1 Lanes

Cancel > timed (EDF bounded) > ready.

### 11.2 Bounded fairness

Avoid starvation via poll budgets and fairness injection.

### 11.3 Cooperative preemption

Yield at checkpoints; poll budget and optional CPU budget.

### 11.4 Admission control/backpressure

Throttle spawn/admission per region; backpressure at reserve points; priorities in budget.

### 11.5 Adaptive governor (optional)

Pluggable controller adjusts runtime knobs from telemetry; default is static.

#### Lyapunov-guided scheduling (optional, but extremely high leverage)

Schedulers are usually heuristics; Asupersync has enough structure to do better.
Define a **potential function** `V(Σ)` over runtime state (regions/tasks/obligations), e.g.:

* number of live children (region “mass”),
* outstanding obligations weighted by age/priority,
* remaining finalizers,
* deadline slack / poll quota pressure.

Then require the governor/scheduler to choose steps that (in expectation or under a bound) **decrease `V`**, or decrease it under cancellation lanes first.
Under standard assumptions (cooperative checkpoints, bounded masking, fairness), LaSalle‑style arguments give: **cancellation converges to quiescence** rather than "we hope it drains."

*Implementation note:* The intuition here is sufficient for design; formal `V(Σ)` transition rules can be added to the operational semantics when the scheduler is actually built and needs verification.

#### Policy seam + determinism rules

The governor must plug into the scheduler through a **narrow policy seam** so the
core scheduler remains correct-by-construction. The policy can *influence*, not
override, the schedule.

Allowed influence surface (explicit):
* deterministic tie-breaking among runnable tasks **within the same lane**,
* selection among multiple ready queues when semantics permit,
* optional bounded promotion (e.g., run cancel-debt tasks earlier) **only if** cancel-lane strictness is preserved.

Hard invariants (non-negotiable):
* **Cancel lane strictness** unless a formal proof allows relaxation.
* **Determinism**: no wall-clock, no ambient RNG, stable iteration order.
* **Bounded fairness**: a runnable task cannot be starved indefinitely.
* **No semantic changes**: only reordering of runnable work, never skipping required protocol steps.

Policy interface (conceptual):
* Input: immutable `RuntimeSnapshot` (no hot-path allocs).
* Output: a **deterministic** ranking or choice among eligible tasks.
* Tie-break rule is fixed and stable (e.g., by TaskId then insertion order).

Evidence ledger (debug-only, trace-backed):
* record `V` decomposition for each decision,
* record candidate comparisons (why X beat Y),
* record policy constraints that forced suboptimal choices.

### 11.6 DAG builder + lawful rewrites (optional)

`plan` module builds DAG nodes, applies rewrites, dedupes shared work, schedules locally or remotely.

---

## 12. Derived combinators

All derived from kernel ops + join/race semantics with drained losers:

* join_all, race_all
* timeout
* first_ok
* quorum(k)
* hedge(delay)
* retry(strategy)
* pipeline
* map_reduce (monoid-based)

---

## 13. Communication + session typing

Base two-phase channels are default.
Optional session-typed channels provide compile-time protocol conformance (dual types, affine endpoints).

Session types scale beyond channels:

* actor request/response and mailbox semantics,
* lease renewal protocols,
* distributed sagas (compensation as a structured dual protocol),
* multiparty protocols (global type → projected local types) for n‑party workflows.

The point is not “types for types’ sake”: session typing gives *by construction* guarantees like “no one can forget to ack,” and can be layered on top of runtime obligation tracking.

---

## 14. Actors + supervision

Actors are region-owned; no detached by default.
Supervision policies (one-for-one, etc.) integrate with region close.
Mailboxes are two-phase.

---

## 15. I/O: region-integrated cancellation barrier (optional but first-class)

In-flight I/O ops are obligations tied to region.
Region memory buffers are safe for zero-copy if region cannot reclaim until op completes/cancels.
I/O submissions can be two-phase.
Reactor is pluggable; lab backend simulates I/O deterministically.

---

## 16. Distributed structured concurrency

Remote tasks are named computations (no closure shipping).
Handles include leases + idempotency keys.
Sagas are structured finalizers.
Durable workflows are an extension crate.

Distributed semantics needs two additional mathematical commitments:

* **Causal time**: traces are partially ordered; use vector clocks (or an equivalent) so we never impose a fake total order on concurrent remote events.
* **Convergent obligation state**: obligation/lease state should form a **join-semilattice** so replicas converge (a CRDT-style view).
  * `Reserved < Committed`, `Reserved < Aborted`.
  * `Committed ⊔ Aborted = Conflict` (protocol violation; surfaced deterministically in traces).

This makes “distributed structured concurrency” honest: we get determinism where possible (causal ordering), and explicit, detectable protocol violations where not.

---

## 17. Observability

Emit causal DAG trace events: parent/child, cancel edges, error edges, obligations, time.
Supports postmortem “why” and replay.

Make the trace model match the true-concurrency semantics:

* record enough edges to reconstruct a **happens-before** partial order,
* normalize traces up to independence (commutation) so replay and diffing are stable,
* keep a small set of “semantic events” (spawn/complete/cancel/reserve/resolve/finalize) that can drive both debugging and proofs.

---

## 18. Deterministic lab runtime + verification

Virtual time + deterministic scheduling + trace capture/replay.
Schedule exploration hooks (DPOR-class foundation).
Property assertions: no task leaks, quiescence, finalizers exactly once, no unresolved obligations, losers drained, deadlines respected.
Operational semantics is TLA+-friendly.

For schedule exploration, “DPOR-class” should mean **optimal DPOR**:

* define independence `I` on labels (from §3.2),
* explore exactly **one execution per Mazurkiewicz trace** (equivalence class),
* use wakeup trees / source sets / sleep sets to avoid redundancy.

Longer-term, directed topological methods (dihomotopy classes of execution paths) can subsume some POR cases, but optimal DPOR is the practical, proven sweet spot.

---

## 19. Normative operational semantics

Small-step kernel state `Σ = (R, T, O, Now)` with explicit rules for spawn, cancel, join, close, obligations.

---

## 20. Rust API skeleton

(See file content in the diff for full skeleton; it includes `Scope`, `Cx`, `Policy`, `Budget`, `Outcome`, and two-phase channels.)

---

## 21. Phase‑0 kernel reference implementation plan

Single-thread deterministic-ready executor with:

* arenas for tasks/regions/obligations
* cancel + ready queues
* timers heap
* RawWaker that schedules TaskId with dedup
* JoinCell waiters and region close barrier waiters
* obligation registry + close waits on obligations too
* trace capture

---

## 22. Roadmap

Phase 0 kernel → Phase 1 parallel scheduler + region heap → Phase 2 I/O → Phase 3 actors/sessions → Phase 4 distributed → Phase 5 DPOR + TLA+ tooling.

---

## 23. The design rule you never compromise on

**Never allow a library primitive to stop being polled while holding an obligation** without either transferring it to a drain/finalizer task, aborting/nacking it, or escalating (trace-recorded).

---

If you want, next I can also produce a **single cohesive “crate layout + file-by-file skeleton”** (with module stubs and the exact structs/enums to implement Phase‑0) that matches this Bible one-to-one.
