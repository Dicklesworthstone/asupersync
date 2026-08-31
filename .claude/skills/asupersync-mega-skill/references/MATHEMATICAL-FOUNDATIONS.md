# Mathematical Foundations and Alien-Artifact Algorithms

Asupersync uses mathematically rigorous machinery where it buys real correctness, determinism, and debuggability. These are implemented, not aspirational.

## Table of Contents

- [Core Mathematical Framework](#core-mathematical-framework)
- [Formal Semantics](#formal-semantics)
- [Discounted-UCB1 Adaptive Cancel Preemption](#discounted-ucb1-adaptive-cancel-preemption)
- [Range-Bounded Drain Certificates (Freedman + Azuma)](#range-bounded-drain-certificates-freedman--azuma)
- [Spectral Wait-Graph Early Warning](#spectral-wait-graph-early-warning)
- [Mazurkiewicz Trace Monoid + Foata Normal Form](#mazurkiewicz-trace-monoid--foata-normal-form)
- [Geodesic Schedule Normalization](#geodesic-schedule-normalization)
- [DPOR Race Detection + Happens-Before](#dpor-race-detection--happens-before)
- [Persistent Homology of Trace Commutation Complexes](#persistent-homology-of-trace-commutation-complexes)
- [Sheaf-Theoretic Consistency Checks](#sheaf-theoretic-consistency-checks)
- [Anytime-Valid Monitoring (E-Processes)](#anytime-valid-monitoring-e-processes)
- [Conformal Calibration](#conformal-calibration)
- [Algebraic Law Sheets + Rewrite Engine](#algebraic-law-sheets--rewrite-engine)
- [TLA+ Export](#tla-export)
- [Explainable Evidence Ledgers](#explainable-evidence-ledgers)

## Core Mathematical Framework

| Concept | Math | Payoff |
|---------|------|--------|
| **Outcomes** | Severity lattice: `Ok < Err < Cancelled < Panicked` | Monotone aggregation, no recovery from worse states |
| **Concurrency** | Near-semiring: `join (x)` and `race (+)` with algebraic laws | Lawful rewrites, DAG optimization |
| **Budgets** | Product meet for runtime budgets (`min` deadline/quotas, `max` priority); min-plus/tropical algebra for deadline-path analysis | Safe budget tightening and critical-path reasoning without conflating the two layers |
| **Obligations** | Linear logic: resources used exactly once | No leaks, static checking possible |
| **Traces** | Mazurkiewicz equivalence (partial orders) | DPOR-style guided exploration (not certified-optimal DPOR), stable replay |
| **Cancellation** | Two-player game with budgets | Scoped completeness when modeled responsiveness assumptions hold and budgets are sufficient |
| **Adaptive scheduling** | Deterministic discounted UCB1 for scheduler cancel preemption; seeded EXP3 for ATP transport adaptation | Dynamic policy selection without conflating distinct controllers |
| **Drain certificates** | Signed-step range bounds + empirical phase diagnostics | Conditional, auditable drain-progress evidence |
| **Structural diagnostics** | Spectral graph theory + conformal + e-processes | Early warning on wait-graph fragmentation |

## Formal Semantics

Small-step operational semantics in `asupersync_v4_formal_semantics.md`. The Lean
project (`formal/lean/Asupersync.lean`) checks six invariants of that abstract
model (structured-concurrency single-owner, region-close quiescence, cancellation
protocol, race loser drain, obligation no-leak, no ambient authority), recorded in
`formal/lean/coverage/invariant_status_inventory.json`. These are Lean-checked
**model** invariants only: the production Rust runtime has not been proved to
refine that model, so this is not a mechanized proof of the executor, adapters,
or transports.

Budget composition is semiring-like:
```text
combine(b1, b2) =
  deadline   := min(b1.deadline,   b2.deadline)
  pollQuota  := min(b1.pollQuota,  b2.pollQuota)
  costQuota  := min(b1.costQuota,  b2.costQuota)
  priority   := max(b1.priority,   b2.priority)
```

## Discounted-UCB1 Adaptive Cancel Preemption

Source: `src/runtime/scheduler/three_lane.rs`

The shipped scheduler policy (`AdaptiveCancelStreakPolicy`) is a deterministic
discounted-UCB1 bandit over arms `{4, 8, 16, 32, 64}`. At each epoch it selects
the largest deterministic UCB score from discounted reward/count state:
```text
score(a) = mean_discounted_reward(a)
           + 2 * sqrt(ln(total_discounted_count))
               / sqrt(discounted_count(a))
```

It updates at `adaptive_cancel_streak_epoch_steps` boundaries (default 128,
enabled by default) from reward blending Lyapunov decrease, fairness pressure,
deadline pressure, and fallback pressure. Deterministic tie-breaking preserves
replay.

A separate seeded EXP3 controller exists in ATP transport adaptation
(`src/net/atp/transport_rq/adaptive.rs`). Keep EXP3's adversarial-regret claims
on that transport surface; do not transfer them to the scheduler UCB1 policy.

Adapts to workload regime shifts while preserving deterministic replay and bounded starvation.

## Range-Bounded Drain Certificates (Freedman + Azuma)

Source: `src/cancel/progress_certificate.rs`

Cancellation drain modeled through signed net-progress deviations:
```text
P(S_t >= x and Q_t <= q) <= exp(-x^2 / (2(q + B*x/3)))
```
For `t >= 1`, `c > 0`, `x > 0`, and `q >= 0`, signed progress
`Y_i = -Delta_i` gives cumulative centered
shortfall `sum(E[Y_i | F_{i-1}] - Y_i)` and `Q_t` is its predictable quadratic
variation. The absolute signed step is bounded by `c`, and `B = 2c` bounds the
centered upper increment. The implementation uses
`Q_t <= t*c^2`. With `B = 2c`, the raw Freedman denominator is never smaller
than Azuma's, so the selected envelope always equals Azuma; the explicit raw
candidate remains for auditability. Realized variance is diagnostic-only, and
exceeding the configured range or dropping an invalid sample (non-finite or
materially negative) disables
concentration claims for that verdict. At the current
same-history horizon, the plug-in mean telescopes to zero deviation, so both
candidate tails are the trivial bound `1`.

Phase classification: `warmup`, `rapid_drain`, `slow_tail`, `stalled`, `quiescent`.

The separate `converging` flag is an empirical trend status over the complete
accepted finite non-negative observation history represented by running statistics. It is
guarded by positive endpoint net progress, stall state, rebound-count and
rebound-magnitude limits, a non-increasing latest step, and the absence of
dropped invalid samples. The conditional calculations do not gate it, and
it is not a future-drift, termination, or probability guarantee.
Incomplete telemetry also suppresses the remaining-step estimate and reports
`warmup` instead of an actionable terminal phase until reset.

The resulting confidence calculation is conditional on the plug-in empirical
net-progress rate; one trace does not prove future drift or bounded completion.
Gross downward credit is phase bookkeeping only. Its accounted-potential total
is pathwise nondecreasing and supplies no Ville or optional-stopping evidence.

## Spectral Wait-Graph Early Warning

Source: `src/observability/spectral_health.rs`

Treats task wait-for graph as dynamic signal. Tracks:
- Fiedler trajectory (algebraic connectivity)
- Spectral gap/radius
- Nonparametric indicator stack: autocorrelation, variance ratio, flicker, skewness, Kendall tau, Spearman rho, Hoeffding's D, distance correlation
- Split conformal bounds for next-step prediction
- Anytime-valid deterioration e-process

Severity: `none / watch / warning / critical`.

## Mazurkiewicz Trace Monoid + Foata Normal Form

Source: `src/trace/canonicalize.rs`

Two traces differing only by swapping adjacent independent events are equivalent. Canonicalized to unique Foata normal form:
```text
M(Sigma, I) = Sigma* / equiv_I
```
Provides canonical fingerprints for schedule exploration and stable replay.

## Geodesic Schedule Normalization

Source: `src/trace/geodesic.rs`, `src/trace/event_structure.rs`

Given dependency DAG (trace poset), constructs valid linear extension minimizing "owner switches" (context-switch entropy proxy) using deterministic heuristics and bounded A* solver.

## DPOR Race Detection + Happens-Before

Source: `src/trace/dpor.rs`, `src/trace/independence.rs`

DPOR-style race detection using minimal happens-before relation (vector clocks per task) plus resource-footprint conflicts. Detected races feed race-guided derivation of deterministic seeds in the explorer; there is no exact-prefix backtracking, so observed equivalence-class counts are campaign metrics, not a certified-optimal-DPOR completeness guarantee.

## Persistent Homology of Trace Commutation Complexes

Source: `src/trace/boundary.rs`, `src/trace/gf2.rs`, `src/trace/scoring.rs`

Square cell complex from commuting diamonds. Betti numbers/persistence quantify "non-trivial scheduling freedom." Deterministic GF(2) bitset linear algebra and boundary-matrix reduction.

Prioritizes exploration toward rare concurrency behaviors.

## Sheaf-Theoretic Consistency Checks

Source: `src/trace/distributed/sheaf.rs`

For distributed obligation tracking: detects obstructions where no global assignment explains all local observations. Catches split-brain saga states that evade pairwise checks.

## Anytime-Valid Monitoring (E-Processes)

Source: `src/lab/oracle/eprocess.rs`, `src/obligation/eprocess.rs`

Ville's inequality: `P_H0(exists t : E_t >= 1/alpha) <= alpha`

Continuously monitor invariants without invalidating significance. Supports optional stopping -- peek after every scheduling step with controlled type-I error.

## Conformal Calibration

Source: `src/lab/conformal.rs`

Split conformal prediction for oracle anomaly thresholds:
```text
P(Y in C(X)) >= 1 - alpha
```
Finite-sample, distribution-free coverage under exchangeability across deterministic seeds.

## Algebraic Law Sheets + Rewrite Engine

Source: `src/combinator/laws.rs`, `src/plan/rewrite.rs`, `src/plan/analysis.rs`

Explicit law sheet for combinators (severity lattices, budget semirings, race/join laws). Rewrite engine guarded by conservative static analyses:
- Obligation-safety lattice
- Cancel-safety lattice
- Deadline min-plus reasoning

## TLA+ Export

Source: `src/trace/tla_export.rs`

Traces exported as TLA+ behaviors with spec skeletons for bounded TLC model checking.

## Explainable Evidence Ledgers

Source: `src/lab/oracle/evidence.rs`

Structured evidence using Bayes factors and log-likelihood contributions. Agent-friendly debugging with equations, substitutions, and one-line intuitions.
