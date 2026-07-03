# Mathematical Foundations and Alien-Artifact Algorithms

Asupersync uses mathematically rigorous machinery where it buys real correctness, determinism, and debuggability. These are implemented, not aspirational.

## Core Mathematical Framework

| Concept | Math | Payoff |
|---------|------|--------|
| **Outcomes** | Severity lattice: `Ok < Err < Cancelled < Panicked` | Monotone aggregation, no recovery from worse states |
| **Concurrency** | Near-semiring: `join (x)` and `race (+)` with algebraic laws | Lawful rewrites, DAG optimization |
| **Budgets** | Tropical semiring: `(R u {inf}, min, +)` | Critical path computation, budget propagation |
| **Obligations** | Linear logic: resources used exactly once | No leaks, static checking possible |
| **Traces** | Mazurkiewicz equivalence (partial orders) | DPOR-style guided coverage, stable replay |
| **Cancellation** | Two-player game with budgets | Completeness: sufficient budgets guarantee termination |
| **Adaptive scheduling** | EXP3/Hedge no-regret online learning | Dynamic preemption without fairness blind spots |
| **Drain certificates** | Martingales + Freedman/Azuma concentration | Quantified confidence that drain reaches quiescence |
| **Structural diagnostics** | Spectral graph theory + conformal + e-processes | Early warning on wait-graph fragmentation |

## Formal Semantics

Small-step operational semantics in `asupersync_v4_formal_semantics.md` with Lean mechanization scaffold (`formal/lean/Asupersync.lean`).

Budget composition is semiring-like:
```text
combine(b1, b2) =
  deadline   := min(b1.deadline,   b2.deadline)
  pollQuota  := min(b1.pollQuota,  b2.pollQuota)
  costQuota  := min(b1.costQuota,  b2.costQuota)
  priority   := max(b1.priority,   b2.priority)
```

## Regret-Bounded Adaptive Cancel Preemption (EXP3/Hedge)

Source: `src/runtime/scheduler/three_lane.rs`

Deterministic EXP3/Hedge over candidate cancel-streak limits {4, 8, 16, 32}:
```text
p_t(a) = (1 - gamma) * w_t(a) / sum_b w_t(b) + gamma / K
w_{t+1}(a) = w_t(a) * exp((gamma / K) * r_hat_t(a))
```
Importance-weighted reward: `r_hat_t(a_t) = r_t / p_t(a_t)`.

Adapts to workload regime shifts while preserving deterministic replay and bounded starvation.

## Variance-Adaptive Drain Certificates (Freedman + Azuma)

Source: `src/cancel/progress_certificate.rs`

Cancellation drain modeled as stochastic progress process:
```text
P(M_t - M_0 >= x) <= exp(-x^2 / (2(V_t + c*x/3)))
```
Where `V_t` is predictable variation and `c` bounds one-step increments.

Phase classification: `warmup`, `rapid_drain`, `slow_tail`, `stalled`, `quiescent`.

Freedman provides tighter variance-aware bound; Azuma is conservative baseline.

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

DPOR-style race detection using minimal happens-before relation (vector clocks per task) plus resource-footprint conflicts. Systematic interleaving exploration targeting truly different behaviors.

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
