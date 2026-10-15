# Scheduler Design Review: Primary Stakeholder vs Universal Optimization

**Bead:** `asupersync-9kuias`
**Author:** SapphireHill (claude-code / opus-4.7)
**Date:** 2026-05-07
**Domain:** `src/runtime/scheduler/*`, `src/runtime/{state,task_table,waker}.rs`, `src/cx/*`

---

## TL;DR

**Primary stakeholder.** The scheduler should optimize for swarm-scale
agent coordination as its declared primary workload, with adaptive
controllers as a secondary safeguard that keeps non-primary workloads in
acceptable envelopes. This is what the current code already does — this
review codifies that decision and lists the implications.

The "universal optimization" alternative is rejected for three reasons:

1. **The project artifacts already commit to a primary stakeholder.**
   `docs/agent_swarm_coordination_workload_contract.md`,
   `artifacts/runtime_workload_corpus_v1.json`, and
   `src/runtime/scheduler/swarm_evidence.rs` define swarm-coordination
   scenarios as the workload denominator. Trying to retrofit "universal"
   onto that denominator after the fact would force every regression
   review to argue why a swarm-shaped fix is acceptable for, say, a hot
   RPC server — which is not a workload the project measures.

2. **The 3-lane scheduler already has *primary-stakeholder defaults +
   adaptive controllers* baked in.** Cancel-streak limit, fast-queue
   stolen-work bound, and timed-lane fairness limit have hard defaults
   tuned for cancel-heavy/coordination-heavy workloads, then EXP3 /
   AdaptiveCancelStreakPolicy / Lyapunov governor / spectral monitor
   adapt them at epoch boundaries when the regime shifts. The
   architecture is hybrid; the question is just which workload the
   defaults are biased toward.

3. **"Universal" is a refusal to make a decision.** Schedulers that try
   to be all things to all workloads end up Pareto-dominated by
   stakeholder-tuned ones at every concrete benchmark. The Tokio
   ecosystem itself bottoms out on workload-specific runtime flavors
   (multi-thread vs current-thread, with/without IO, with/without time).
   Asupersync's chance to differentiate is to pick a stakeholder Tokio
   under-serves and serve it well.

---

## Background

### Stakeholder taxonomy

The candidate primary stakeholders for a structured-concurrency Rust
runtime are:

1. **Latency-bounded RPC servers.** p99 wake-to-run, fairness across
   concurrent requests, low context-switch cost. (Tokio multi-thread is
   already very good here.)
2. **Throughput-bound batch workers.** Saturate cores, minimize
   cancellation overhead, amortize wake costs across large work units.
   (rayon-style work-stealing serves this well.)
3. **Hard-deadline real-time control loops.** Predictable poll budget,
   bounded cleanup, deterministic ordering. (Niche; embedded executors
   like embassy own this.)
4. **Lab-runtime / deterministic replay.** Trace-replayable scheduling,
   no wall-clock leaks, zero ambient state. (Asupersync's `LabRuntime`
   is unique here; few production runtimes invest.)
5. **Swarm-scale agent coordination.** Many cooperating tasks per
   process; cancel-heavy regime shifts; long-tail latency dominates;
   correctness under panic/cleanup is load-bearing; structured
   concurrency invariants must hold under contention. (Asupersync's
   declared use case.)

Tokio targets (1) + (2) and treats (3)/(4)/(5) as
out-of-scope-but-not-hostile. Asupersync's spec-first invariants
(`region close = quiescence`, `cancel is a protocol`, `no obligation
leaks`, `losers are drained`) are precisely the invariants stakeholder
(5) cannot do without and stakeholders (1)/(2) tolerate but rarely
require.

### Evidence the project already chose stakeholder (5)

| Artifact | What it commits to |
|---|---|
| `docs/agent_swarm_coordination_workload_contract.md` | Workload families: `tracker_lock_contention`, `concurrent_rch_proofs`, `fail_closed_dirty_frontier`, `artifact_retrieval_tail`, `proof_runner_fanout`, `stale_in_progress_reclaim`, `coordination_latency_burst`. None are RPC-server-shaped. |
| `artifacts/runtime_workload_corpus_v1.json` | Canonical workload denominator for runtime perf claims. |
| `src/runtime/scheduler/swarm_evidence.rs` | First-class scheduler evidence artifact (`SchedulerEvidenceArtifact`, `SchedulerWorkloadClass`, `SchedulerTopologyDescriptor`) for swarm tuning. |
| `bead asupersync-aj7lx3` | "Operator-grade production proof lane for swarm-scale Asupersync" — current Phase 5 epic. |
| Default `cancel_streak_limit` (effective limit `L_c`, `2*L_c` in `DrainObligations`/`DrainRegions`) | Tuned for cancel-heavy regimes, not for cancel-rare RPC paths. |

### What the existing scheduler already does

The 3-lane scheduler (`cancel > timed > ready`) at
`src/runtime/scheduler/three_lane.rs` is structured as
**primary-stakeholder defaults + adaptive controllers**:

- **Hard defaults** for `cancel_streak_limit`, `steal_batch_size`,
  `fast_queue_fairness_limit`, `timed_lane_fairness_limit`. Each has a
  baseline picked for swarm-coordination scenarios.
- **AdaptiveCancelStreakPolicy** (discounted UCB1 over a fixed arm set)
  picks a per-epoch effective limit `L_c` from observed reward (progress
  + fairness + deadline components). This adapts to workload regime
  shifts while preserving deterministic replay.
- **Lyapunov / progress / spectral health monitors** raise the effective
  limit to `2*L_c` while the runtime is draining obligations or regions
  — the regime where late cancellation can starve real progress.
- **PreemptionFairnessCertificate** (added in `br-asupersync-kznrvh`)
  exports a deterministic per-worker witness that the observed
  dispatches respected the maximum effective limit. This is the
  contract we owe to consumers; it does not commit to wall-clock or
  global-total-order claims.

The existing fairness contract is *worker-local dispatch-step bounds*,
not wall-clock latency or global priority order (formalized by
`br-asupersync-kznrvh`). That is the right contract for stakeholder (5)
and a poor fit for stakeholder (1) — confirming the implicit choice has
already been made.

---

## Trade-offs

### Option A: Primary stakeholder = swarm-scale coordination (recommended)

**Pros:**

- Aligns with the existing workload corpus, swarm-evidence artifact,
  and proof-lane epic.
- Lets the scheduler bias defaults toward cancel-heavy regimes, which
  is what `asupersync_v4_formal_semantics.md` invariants (cancel as a
  protocol, region close = quiescence) make load-bearing anyway.
- Adaptive controllers absorb the long tail of non-primary workloads
  inside acceptable envelopes — RPC-shaped pulses dial down the
  cancel-streak limit; throughput-shaped runs dial down preemption
  pressure; lab-runtime tests use the deterministic-mode profile.
- README claims, fairness certificates, evidence artifacts, and
  validator scripts all align on the same denominator. Reviewers can
  decide regression severity without first relitigating "what is the
  workload."
- Differentiation. Tokio under-serves swarm coordination; rayon, embassy,
  smol all under-serve it; this is a real gap and a real moat.

**Cons:**

- RPC-shaped p99 will likely lag a workload-tuned Tokio config by
  10-30% on identical benchmarks. The marketing position "drop-in
  Tokio replacement" gets weaker.
- Need explicit secondary-stakeholder envelopes (e.g. "RPC p99 within
  2x of `tokio-multi-thread` on the conformance harness") to keep the
  adaptive controllers honest.
- Documentation must clearly say what the defaults are tuned for, so
  users with stakeholder-(1)/(2) workloads do not naively benchmark
  against Tokio and feel cheated.

**What changes if we adopt this:**

1. `README.md` already names swarm-scale; tighten the "Why Asupersync"
   section so it explicitly disclaims RPC-server p99 leadership.
2. `docs/scheduler_design_review_9kuias.md` (this file) becomes the
   canonical reference. Subsequent perf beads cite it instead of
   relitigating.
3. New scheduler tunables added to `SchedulerKnobProfile` must say
   which stakeholder they bias toward and how the adaptive layer
   recovers for the others.
4. Conformance harnesses for non-primary stakeholders (an
   Hyper/Axum-style RPC suite, a rayon-style throughput suite) get
   secondary-envelope thresholds, not primary-envelope thresholds.

### Option B: Universal optimization (not recommended)

**Pros:**

- Easier to market as "the new Tokio."
- No hard choices to defend in design reviews.

**Cons:**

- Pareto-dominated at every benchmark by stakeholder-specialized
  runtimes. Nobody picks "the second-best for what I actually do."
- Forces every scheduler change to argue against four different
  workload denominators. Review velocity suffers; regressions go
  undetected because the goalposts move per-PR.
- Conflicts with the *spec-first* DNA of the project — Asupersync
  exists because Tokio's "universal" approach left structured
  concurrency, cancel-correctness, and bounded cleanup as best-effort
  conventions. Reverting to "be everything to everyone" undoes that.
- The workload contract already exists. Universal would require
  rewriting the contract to remove the swarm-coordination focus —
  which would invalidate `swarm_evidence.rs`, the workload corpus, and
  the proof-lane epic.

### Option C: No primary, but document the *implicit* choice

This is the path of least resistance — leave the code as-is, leave the
defaults as-is, do not write a design review, and let each scheduler
change pick its own stakeholder.

**Why rejected.** This is what we have today. It produced contradictions:
the workload contract names swarm coordination; the fairness contract
gives worker-local dispatch-step bounds (stakeholder-5-shaped); but
README rhetoric still alludes to RPC-style guarantees in places. The
contradictions surface as bead pings every time someone benchmarks
against Tokio and is surprised by the result. Documenting the choice
once costs less than relitigating it per-PR.

---

## Chosen direction

**Primary stakeholder = swarm-scale agent coordination.** The scheduler
optimizes for cancel-heavy / region-close-heavy / coordination-bursty
workloads as its first-order target. Adaptive controllers
(AdaptiveCancelStreakPolicy, Lyapunov governor, spectral health monitor)
keep non-primary workloads inside published envelopes. Evidence
artifacts and certificates (`SchedulerEvidenceArtifact`,
`PreemptionFairnessCertificate`) describe the *worker-local
dispatch-step* contract — not wall-clock or global-total-order — so
consumers can audit what the scheduler actually promises.

### Acceptance criteria for future scheduler changes

1. **Primary-envelope regression check.** A change must not move any
   metric in the swarm workload corpus
   (`artifacts/runtime_workload_corpus_v1.json`) outside its current
   envelope without an explicit justification in the bead body and a
   matching update to `swarm_evidence.rs`.

2. **Secondary-envelope soft regression check.** A change must not move
   secondary-stakeholder metrics (RPC-shaped p99, throughput-shaped
   wake-to-run latency) outside *2x* of the prior best, again without
   bead justification. Adaptive controllers are expected to absorb most
   of the impact; the soft envelope catches cases where they cannot.

3. **Fairness certificate stability.** Any change to the lane priority
   order, the cancel/timed/ready bounds, or the steal-batch sizing must
   either preserve the existing `PreemptionFairnessCertificate` shape
   or bump its schema version with a migration note.

4. **Evidence-or-it-didn't-happen.** Performance claims must point at a
   `SchedulerEvidenceArtifact` (or equivalent deterministic capture).
   No more "I ran it on my laptop and it was faster." This is the same
   bar `kznrvh` set for the fairness contract.

### Non-goals (explicit)

- Beating Tokio multi-thread on synthetic Hyper/Axum benchmarks. We
  are not in that game by choice. The goal is to be the best runtime
  *for swarm coordination*, not the best runtime for everything.
- Sub-microsecond wake-to-run latency at the median. The 3-lane
  scheduler trades a small amount of median latency for fairness
  guarantees and cancellation correctness under regime shifts. Users
  who need sub-µs medians on RPC paths should use a different runtime.
- Removing the adaptive controllers. They are the bridge between the
  primary-stakeholder defaults and the secondary envelopes. Removing
  them would force the primary-stakeholder choice to be even more
  exclusive than it is.

---

## References

- `docs/agent_swarm_coordination_workload_contract.md` — workload
  denominator.
- `artifacts/runtime_workload_corpus_v1.json` — canonical scenarios.
- `src/runtime/scheduler/swarm_evidence.rs` —
  `SchedulerEvidenceArtifact`, `SchedulerKnobProfile`,
  `SchedulerWorkloadClass`.
- `src/runtime/scheduler/three_lane.rs` — fairness contract module
  doc-comment (formalized in `br-asupersync-kznrvh`); adaptive policy
  at `AdaptiveCancelStreakPolicy`; `PreemptionFairnessCertificate`.
- `bead asupersync-aj7lx3` — Operator-grade production proof lane for
  swarm-scale Asupersync (Phase 5 epic).
- `bead br-asupersync-kznrvh` — formalize scheduler fairness bounds.
- `README.md` §"Why Asupersync" — top-level positioning; confirms that
  the differentiators (cancel-correctness, structured concurrency,
  bounded cleanup, deterministic testing) are stakeholder-(5) features.
