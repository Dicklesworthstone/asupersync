# Scheduler-Adjacent Attribution Artifact — Backoff-Loop Wheel-Timer Pump

Bead: `asupersync-rr849p`
Gate: Phase 6 flamegraph (triggered: `src/runtime/scheduler/three_lane.rs` touched).

## Change surface

`ThreeLaneWorker::run_loop` inner backoff loop only: after a deadline-sized
`park_timeout` the worker now breaks to the outer loop so `next_task()`
(PHASE 0 `process_timers`) fires the now-due wheel deadline itself; the
`DeadlineDue` stale-flicker branch breaks only when the timer wheel itself is
due. No dispatch-path, steal-path, or wake-path code changed — the edit is
reachable only from the idle/backoff state.

## Flamegraph status: infra-blocked, precedent fallback

- `rch exec -- cargo flamegraph --package asupersync --freq 997 --bench
  methodology_baselines -o artifacts/flamegraphs/main-rr849p.svg` could not
  sample: the fleet remains `perf_event_paranoid`-restricted for
  unprivileged sampling, matching the precedent recorded in
  `main-u1z5hn-1-3-attribution.md` (no `.svg` has ever been committed
  repo-wide; the sampling half of this gate is fleet-blocked, not specific
  to this change).

## Binding behavioral + performance evidence

- Stall fix proof (the change's purpose): `tests/rr849p_request_cx_read_localization.rs`
  - `rr849p_minimal_tcp_timeout_read_diag`: timeout-wrapped TcpStream read
    completed in **504ms** post-fix vs **4001ms stall (full timeout
    deadline)** pre-fix, identical 500ms-delayed server. Monitor timeline
    pre-fix showed the due wheel timer stranded (`timer_next_ms=Some(0)`,
    `timer_pending=2`, frozen from +551ms to +4509ms); post-fix the wheel
    drains (`timer_pending` returns to 0 within one cadence).
  - `localize_request_cx_read_after_write` (canonical PG repro): CONTROL
    phase passes post-fix; previously panicked at the 4s deadline.
- Timer-layer isolation: `src/time/driver.rs` near-vs-far regression tests
  (aligned virtual 1000 steps, unaligned virtual 2000 steps, wall-clock
  concurrent 200 steps) pass, demonstrating the wheel/driver layer was sound
  and the defect was confined to the scheduler backoff loop's failure to
  pump it.
- `methodology_baselines` criterion run (shared rch worker, 2026-06-12,
  `--features test-internals,criterion-benches`): full suite completed,
  exit 0. Captured tail group vs the committed February
  `artifacts/baseline.json` (different hardware; order-of-magnitude
  agreement plus no pathological outlier is the honest standard):

  | Benchmark | Feb baseline p50 | 2026-06-12 median |
  |---|---|---|
  | budget/is_past_deadline_no_deadline | 0.64 ns | 0.647 ns |
  | budget/is_past_deadline_with_deadline | 0.65 ns | 0.644 ns |
  | budget/consume_poll | 7.73 ns | 7.47 ns |
  | budget/consume_cost | 7.70 ns | 3.19 ns |
  | budget/combine_two | 6.41 ns | 8.87 ns |
  | budget/combine_chain/4 | 49.27 ns | 12.66 ns |
  | budget/combine_chain/16 | 179.65 ns | 31.41 ns |
  | budget/combine_chain/64 | 704.80 ns | 110.23 ns |
  | budget/remaining_time_with_deadline | 1.45 ns | 1.29 ns |
  | budget/remaining_time_no_deadline | 1.42 ns | 1.56 ns |

  No pathological regression; several entries are 4-6x faster than the
  February capture (code evolved since), and the lone nominal increase
  (`combine_two`) is contradicted by its own composite (`combine_chain/4`
  embeds three combines and is ~4x faster), i.e. cross-host noise. The
  touched code path is idle-side only; dispatch-side hot paths are
  additionally covered by the 208-test `scheduler::three_lane` suite
  passing unchanged.

## Non-claims

- Not a kernel-sampled flamegraph; no claim about hot-path function
  attribution.
- No claim of throughput improvement: the change targets idle-state timer
  liveness (correctness), not scheduler throughput.
- The reactor-less fallback I/O regime this fixes remains the default until
  `asupersync-1ajbtl` (default platform reactor wiring) is decided; this
  artifact makes no claim about reactor-backed behavior.
