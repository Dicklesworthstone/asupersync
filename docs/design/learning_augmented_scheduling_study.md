# Learning-augmented scheduling hints: bounded design study

**Bead:** `asupersync-adaptive-control-plane-yj2nxx.6`
**Decision:** **NO-GO** for a production scheduler experiment on the current
evidence. Reopen only after the evidence gates in [Reopen criteria](#reopen-criteria)
are met.

This study asks a narrow question: can predictions improve an existing scheduler
decision while retaining an explicit consistency/robustness bound, deterministic
replay, and the H5 controller-registry safety contract? It does not propose a
model, add an actuator, or claim that a synthetic predictor is a scheduler win.

## Terms and constraints

For a cost-minimization objective, let `ALG(I, y)` be the cost with prediction
`y`, and `OPT(I)` the relevant offline optimum.

- **Consistency `c`:** the worst-case ratio `ALG(I, y*) / OPT(I)` when the
  prediction is exact.
- **Robustness `r`:** the worst-case ratio over arbitrary predictions. A bound
  that grows with an unbounded cohort or service-time ratio is not a constant
  robustness guarantee.
- A prediction may refine a decision only inside the existing cancel > timed >
  ready ordering. It must not delay cancellation, cross an EDF deadline, orphan
  work, or introduce ambient authority.
- Any future actuator must use the production
  [`ControllerRegistry`](../../src/runtime/kernel.rs), including registration
  validation, decision budgets, Shadow -> Canary -> Active promotion, evidence
  ledger, fallback, and rollback. Direct hot-path actuation would violate H5.
- The incumbent policy is the fallback. Missing, stale, incompatible, or
  replay-divergent prediction evidence must select it exactly.

The definitions follow the learning-augmented convention used by Purohit,
Svitkina, and Kumar: exploit accurate predictions while degrading gracefully
when predictions are bad. Their deterministic ski-rental construction gives a
parameterized `(1 + lambda)` consistency and `(1 + 1/lambda)` robustness
trade-off for `lambda in (0, 1)` [1]. Wei and Zhang subsequently establish
matching lower-bound structure for this setting [2].

## Current scheduler seams

The code audit found three bounded injection points; none requires changing the
public API to study.

1. **Equal-deadline timed ordering.** `TimedTask::cmp` orders the timed lane by
   earliest deadline, then FIFO generation, then `TaskId`
   ([`global_injector.rs:115`](../../src/runtime/scheduler/global_injector.rs)).
   A prediction could replace only the FIFO tie-break within one exact-deadline
   cohort.
2. **Steal-victim selection.** `steal_task` samples two distinct victims with
   `DetRng`, prefers the larger `stealable_len_hint`, tries the other sample,
   then falls back to a circular scan
   ([`stealing.rs:7`](../../src/runtime/scheduler/stealing.rs)). Identical seeds
   already select the same victim.
3. **Idle spin/yield/park timing.** The production three-lane worker spends a
   fixed eight spins and two yields before parking, rechecks concrete work, and
   sizes timed parks from real deadlines
   ([`three_lane.rs:183`](../../src/runtime/scheduler/three_lane.rs),
   [`three_lane.rs:4832`](../../src/runtime/scheduler/three_lane.rs)). Published
   work wakes an actual waiter when possible and retains a Parker permit across
   the final-check/park race
   ([`three_lane.rs:871`](../../src/runtime/scheduler/three_lane.rs)). A hint
   could change the bounded idle threshold, but must not replace enqueue-driven
   wakeup or deadline-derived park bounds.

The existing `scheduler_autotuner_bench` is excluded as win evidence: its
"performance impact" is explicitly simulated from hand-coded parameter ranges
([`scheduler_autotuner_bench.rs:118`](../../benches/scheduler_autotuner_bench.rs)).
The deterministic [`PoolSizingEstimator`](../../src/runtime/pool_sizing.rs)
does maintain aggregate EWMA arrival rate and service-time moments for a pool.
That is useful prior art, but it has no per-task identity or remaining-work
estimate and is not connected to the scheduler queues or idle-gap decisions.

## Profiling evidence

The profiling command ran through forced-remote RCH against exact committed
state, with no overlay:

```text
RCH_WORKERS=ovh-a RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 \
  rch exec --base HEAD --clean-overlay --no-overlay -- \
  env CARGO_TARGET_DIR=/tmp/rch_target_hazy_learning_hints \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_BENCH_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  SCHED_CHURN_WORKERS=4 SCHED_CHURN_IDLE_SECS=2 \
  SCHED_CHURN_LOAD_SECS=3 SCHED_CHURN_M=1,16,64,256 \
  cargo bench -j 2 -p asupersync \
    --bench scheduler_benchmark --bench scheduler_cpu_churn \
    --features runtime-metrics,test-internals,criterion-benches -- \
    'scheduler/(lane_priority/timed_edf_ordering|work_stealing/steal_single|steal_task|parker/cross_thread_unpark)' \
    --noplot
```

Receipt: RCH job `29988810699833457`, worker `ovh-a`, base
`d217d1a46fc164c89d7c87774b1c82623c733e77`, clean-overlay fingerprint
`fe0d5151031be8fda7951fe7fe1f42f7ce344018fdb3ed21e6ada866b230b195`,
exit `0`. The emitted churn JSON is 3,154 bytes with SHA-256
`fd294ff89e44b3e3210c0688f3e7fa3f6773e705832e14ec766d71af446f734a`.

| Candidate seam | Existing benchmark | Measured baseline | What the number bounds |
|---|---|---:|---|
| Equal-deadline refinement | `scheduler/lane_priority/timed_edf_ordering` | median `290.90 ns` (`260.29-329.32 ns`) | Cost of constructing and popping three differently-deadlined tasks. It is an upper ceiling, not an equal-deadline or predictor A/B result. |
| Steal-victim refinement | `scheduler/work_stealing/steal_single` | median `1.0502 us` (`0.97245-1.1272 us`) | One successful steal, including fixture shape. |
| Steal-victim refinement | `scheduler/steal_task/empty_queues/{2,8}` | medians `1.3420 us`, `7.9885 us` | Empty-victim selection and fallback overhead at two and eight victims. |
| Idle prediction | `scheduler/parker/cross_thread_unpark` | median `37.967 us` (`37.803-38.140 us`) | Cross-thread park/unpark cycle including thread creation/join; not the live-runtime enqueue path. |

The real `scheduler_cpu_churn` harness exercised a four-worker runtime with
external enqueues and timer load:

| Tasks `M` | CPU | parks / unparks | enqueue-to-first-execution p50 / p99 / p999 |
|---:|---:|---:|---:|
| idle | `0.0%` sampled | `0 / 0` | n/a |
| 1 | `1.61%` | `1,241 / 1,241` | `12 / 39 / 57 us` |
| 16 | `1.93%` | `1,434 / 1,598` | `11 / 34 / 36 us` |
| 64 | `2.25%` | `1,488 / 1,781` | `12 / 38 / 45 us` |
| 256 | `6.12%` | `2,485 / 3,594` | `12 / 36 / 83 us` |

Each loaded cell had 592 latency samples. These are single-host diagnostic
measurements, not a performance regression gate, predictor comparison, fleet
result, or production-workload claim. The measured path costs establish where
headroom could exist; they do not establish that a predictor can capture it.

## Candidate 1: predicted service time inside an EDF tie

**Model.** For `n` runnable jobs sharing exactly one deadline, preserve their
lane and deadline and minimize unweighted sum of completion times. Let true
service times be `p_i > 0`; order by predicted service time `p_hat_i`, with
stable generation and `TaskId` tie-breaks.

**Bounds.** Exact predictions produce shortest-processing-time order, which is
optimal for this secondary single-machine objective: `c = 1`. If predictions
have a certified multiplicative envelope

```text
p_i / rho <= p_hat_i <= rho * p_i, rho >= 1,
```

then predicted-SPT is at most `rho^2` from optimum. The proof is direct: the
completion-time objective is linear in the ordered processing times;
`cost_p(predicted-SPT) <= rho * cost_p_hat(predicted-SPT) <= rho *
cost_p_hat(true-SPT) <= rho^2 * cost_p(true-SPT)`.

With arbitrary errors there is no constant `r`: predict one service time `P`
as shortest and place it before `n-1` unit jobs. As `P` grows, the ratio to true
SPT approaches `n`; it is unbounded over cohort size. Confidence does not repair
this because an adversary may be confidently wrong.

**Feasibility.** No production task metadata provides a replay-stable remaining
service-time prediction or a runtime-verifiable `rho` certificate. The measured
`290.90 ns` median covers a three-task EDF operation, so even a lookup or model
call can consume the entire local ceiling. The current benchmark also uses
different deadlines and therefore does not measure the target cohort objective.

**Disposition:** NO-GO.

## Candidate 2: predicted remaining work for two-choice stealing

**Model.** Keep the two deterministic sampled victims. Let `w_j` be true
stealable remaining work at victim `j`; select the larger predicted `w_hat_j`
instead of the larger task-count hint.

**Bounds.** Perfect predictions select the best of the sampled pair for this
local workload objective, so `c = 1`. Arbitrary errors can select workload
`epsilon` while rejecting workload `P`, giving unbounded `r` as
`P / epsilon` grows.

The incumbent count rule does have a conditional bound: if every stealable
task's remaining service lies in a known interval `[p_min, p_max]`, choosing the
larger-count queue is `kappa = p_max / p_min` robust for total queued work among
the sampled pair. Asupersync has no such service bound. Restricting predictions
to equal-count ties preserves count semantics but still has unbounded
service-time loss.

**Feasibility.** `DetRng` already makes sampling replayable, and the current
length hint is cheap, local, and advisory. There is no stable workload feature,
model identity, or remaining-work ledger at the stealer boundary. The measured
empty-eight-victim median (`7.9885 us`) is a possible lookup ceiling, but a
prediction cannot skip the correctness-preserving fallback scan when sampled
steals fail or hidden work may exist. No benchmark currently measures useful
work captured per steal.

**Disposition:** NO-GO.

## Candidate 3: predicted idle gap for spin/yield/park

**Model.** Approximate one idle interval as ski rental. Spinning/yielding rents
at unit cost for actual gap `x`; parking and later waking has calibrated cost
`B`. Given predicted gap `y`, the deterministic policy from [1] parks at
`lambda * B` when `y >= B`, otherwise at `B / lambda`. It is
`(1 + lambda)`-consistent and `(1 + 1/lambda)`-robust for
`lambda in (0, 1)`.

This is the only candidate with a known constant consistency/robustness
trade-off under arbitrary prediction error. It is not yet an Asupersync bound:
spins, yields, kernel parks, reactor leadership, deadline-sized waits, CPU
contention, and enqueue latency do not share a calibrated scalar cost. Timer
deadlines also constrain the park duration independently of a predicted idle
gap.

**Feasibility.** The cross-thread microbenchmark exposes a `37.967 us` median
cycle, while the live harness observes `11-12 us` p50 and at most `83 us` p999
in these cells. The values are different paths and must not be substituted for
one another. More importantly, the live idle cell sampled `0.0%` CPU: there is
no measured idle-burn problem to exchange for speculative latency. The exact
enqueue-driven wake must remain authoritative.

**Disposition:** NO-GO until a common cost model and a scheduler-idle-gap
predictor with replay evidence exist.

## Determinism, replay, and H5 admission

Any reopened experiment must satisfy all of the following before actuation:

1. Run the predictor as a pure function over canonical, logical-time features,
   or record its output as first-class trace evidence. No wall-clock query,
   ambient model service, process-global learned state, or nondeterministic
   inference kernel may enter scheduler decisions.
2. Record decision sequence, model/version hash, feature-schema version,
   canonical feature vector or digest, prediction, confidence/error envelope,
   policy parameter (`rho` or `lambda`), incumbent action, proposed action, and
   final action. Replay must fail closed to the incumbent on missing or
   mismatched evidence.
3. Preserve generation/`TaskId` tie-breaks and `DetRng` consumption. Shadow
   evaluation must not consume scheduler RNG or mutate queue state.
4. Register a named target seam and required snapshot fields through H5.
   Start in Shadow, respect per-epoch decision budgets, publish calibration and
   SLO evidence, advance only through Canary, and rollback atomically to the
   incumbent on calibration regression, budget overrun, replay divergence, or
   missing evidence.
5. Declare interference with the existing scheduler recommender and brownout
   guard: shared telemetry, shared knobs, update cadence, timescale separation,
   and conservative precedence. Unknown overlap is `do_not_compose`, consistent
   with the controller-interference contract
   ([`decision_plane_validation_contract.md`](../decision_plane_validation_contract.md)).

## Expected-value screen

The probabilities below are decision priors, not measurements. The saving
ceilings are deliberately optimistic: they assume a predictor could remove the
entire measured local path cost with zero inference overhead.

| Candidate | Optimistic measurable ceiling | Prior chance of a net win after inference | Optimistic expected saving ceiling | Dominant downside | Decision |
|---|---:|---:|---:|---|---|
| EDF tie refinement | `0.291 us` per three-task benchmark iteration | `<= 15%` | `<= 0.044 us` | Unbounded arbitrary-error ratio; missing equal-deadline/service-time evidence | NO-GO |
| Steal-victim refinement | `7.989 us` on the empty-eight path | `<= 10%` | `<= 0.799 us` per matching attempt | Cannot remove fallback; missing remaining-work signal; unbounded arbitrary-error ratio | NO-GO |
| Idle-gap policy | `37.967 us` cross-thread cycle; `83 us` live p999 cell | `<= 20%` | `<= 7.594 us` per comparable wake | No common cost calibration; current idle CPU already sampled at zero; tail/CPU trade | NO-GO |

These upper bounds are insufficient to justify production code or even a
predictor scaffold. The fastest-looking seam has the weakest objective match;
the only constant-robust theory lacks the required cost model and motivating
idle-burn evidence.

## Reopen criteria

Do not file an implementation bead from this study. Reopen with a new design
bead only when all applicable gates have concrete evidence:

- a trace-derived, privacy-reviewed, stable feature and target definition;
- shadow predictions replay byte-identically across fixed LabRuntime seeds;
- a measured error envelope or an arbitrary-error robust wrapper for the exact
  scheduler objective;
- a real existing benchmark extended to compare incumbent vs shadow proposal,
  including inference overhead and adversarial prediction fixtures;
- statistically credible improvement that exceeds noise and preserves cancel,
  deadline, fairness, CPU, and p99/p999 budgets;
- complete H5 registration, controller-interference, promotion, and rollback
  design before any actuator is connected.

## References

1. Manish Purohit, Zoya Svitkina, and Ravi Kumar,
   [“Improving Online Algorithms via ML Predictions,” NeurIPS 2018](https://proceedings.neurips.cc/paper/2018/hash/73a427badebe0e32caa2e1fc7530b7f3-Abstract.html).
2. Alexander Wei and Fred Zhang,
   [“Optimal Robustness-Consistency Trade-offs for Learning-Augmented Online Algorithms”](https://arxiv.org/abs/2010.11443).
3. Michael Mitzenmacher,
   [“The Power of Two Choices in Randomized Load Balancing,” IEEE TPDS 12(10), 2001](https://www.eecs.harvard.edu/~michaelm/postscripts/tpds2001.pdf).
