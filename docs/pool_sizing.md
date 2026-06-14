# Queueing-theoretic pool sizing

`src/runtime/pool_sizing.rs` turns "how many threads / connections?" from a
hand-tuned guess into a stated SLO with queueing theory behind it. It is pure
policy/math: it samples no clock, spawns no worker, opens no connection, and
emits no logs. Runtime integrations feed already-collected observations and
choose how to consume the result.

## The model (galaxy-brain card)

A pool is a queueing system. Two live values matter first:

```text
offered_load R = arrival_rate_per_sec * mean_service_seconds
utilization    = R / k
```

`R = 6.4` means the observed workload would keep 6.4 workers busy forever. A
fixed "min 4, max 32" guess hides that; this module reports it.

The recommendation starts from **square-root staffing**,
`k0 ≈ R + beta * sqrt(R)`, where `beta` is selected from the wait-probability
target. Each candidate size is then verified with an **Erlang-C** wait-probability
calculation scaled by an **Allen–Cunneen** service-variability multiplier
(`(1 + CV²) / 2`, floored at 1.0x), and the smallest size meeting the target
inside the configured floor/ceiling is chosen. The approximation boundary is
intentional: this is an operator and controller input, not a proof of real-host
throughput.

`ManagedPoolSizingController::explain()` renders this as a plain-English card with
the live values substituted, e.g.:

```text
pool-sizing card - recommend 8 workers (bounds 1..=32, reason: first candidate meeting the target)
  offered load R = 6.400 workers (arrival 16.000/s x mean service 400000us)
  square-root staffing k0 = R + beta*sqrt(R) = 8 workers
  at 8 workers: utilization 80.00%, P(wait) ~= 9.20% (target P(wait) <= 10.00%), mean wait ~= 1234us
  service variability multiplier 1.00x (Allen-Cunneen, CV^2 = 1.000)
```

## Two consumption modes

The default posture is **advisory**, consistent with the rest of the repo's
control lanes (advisory first, opt-in managed after soak evidence).

### Advisory (default)

Both pools expose an identical advisory surface:

- `DbPool` / `BlockingPool`: `pool_sizing_bounds()`,
  `pool_sizing_controller_state()`, `advisory_pool_sizing_decision(...)`.

The recommendation is reported via metrics/inspector and logged when the live
size diverges from the recommendation. Operators act. Divergence is computed with
`pool_sizing_divergence(recommended, actual, warn_bps)` (or the controller's
`divergence()`); the default `DEFAULT_DIVERGENCE_WARN_BPS` fires at a **2x** gap
in either direction. Advisory mode never resizes anything.

### Managed (opt-in)

`ManagedPoolSizingController` is the managed-mode brain. It owns an EWMA
estimator, the policy, and the live controller state, and on each `observe()`:

1. folds the observation into the EWMA estimate (deterministic, integer-only);
2. evaluates `decide_pool_sizing` for the current epoch;
3. applies an allowed `Resize` to its tracked size, advancing the last-resize
   epoch and counting the resize.

Two gates prevent flapping:

- **Hysteresis** — the recommendation must move at least `hysteresis_bps`
  (default 20%) relative to the current size before a resize is taken.
- **Cadence** — at least `resize_cadence_epochs` (default 1) must elapse between
  resizes. The first resize is permitted once `epoch >= resize_cadence_epochs`.

The tracked size is always clamped into the configured bounds, so **floors and
ceilings always win** over any recommendation. The controller never mutates a
real pool: an integration seeds it from `pool.pool_sizing_bounds()` /
`pool.pool_sizing_controller_state()`, feeds observations, and reads
`current_size()` to apply the size through the pool's own config surface. This
keeps managed mode opt-in and the controller deterministic for lab replay —
identical observation/epoch sequences yield identical size trajectories.

> Autonomous live resizing of the runtime blocking pool and DB pool requires
> those pools to expose runtime-mutable bounds (today `max_threads` /
> `max_size` are fixed at construction). Until that surface lands and soak
> evidence justifies it, the managed controller is consumed as a recommendation
> source layered over the advisory surfaces above.

## Regime change

After a confirmed workload phase change, an integration (or the change-point
detector / interference harness) calls `reset_estimator()` to clear stale EWMA
learning so the next observation seeds a fresh baseline. A reset never itself
resizes the pool — the live size is preserved across the reset.

## Determinism

Every calculation is integer fixed-point at `POOL_SIZING_SCALE` (1e6) — no
floating point, no wall-clock, no RNG. The Erlang-B/C recursion runs at 1e12
internal precision with round-to-nearest divisions so table values resolve
exactly (M/M/3 with R=2 → 4/9 = 444_444 ppm). This makes the substrate safe to
drive on virtual time in the lab and to replay deterministically.
