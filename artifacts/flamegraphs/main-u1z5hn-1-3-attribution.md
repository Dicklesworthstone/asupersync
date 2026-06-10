# Scheduler-Adjacent Attribution Artifact — Spawn Mailbox Admission

Bead: `asupersync-dx-core-api-v2-u1z5hn.1.3`
Gate: Phase 6 flamegraph (triggered: `src/runtime/scheduler/three_lane.rs` touched).

## Flamegraph status: infra-blocked, fallback captured

- `rch exec -- cargo flamegraph --bench spawn_throughput ...` failed on the
  remote worker: `perf_event_paranoid` forbids unprivileged sampling
  (`failed to sample program, exited with code: Some(255)`).
- Local host: `/proc/sys/kernel/perf_event_paranoid = 4` — same restriction.
  This matches the precedent already recorded in the beads history
  (`perf_event_paranoid=4` → callgrind fallback, RaptorQ perf bead), and no
  `.svg` has ever been committed to `artifacts/flamegraphs/` repo-wide
  (only `.gitkeep`): the sampling half of this gate is fleet-blocked, not
  specific to this change.
- Callgrind fallback captured locally against the rch-built release bench
  (`spawn_throughput-44321debb2a9bf6e`, `--profile-time 3
  single_producer/mailbox`): 96.5M Ir total; top entries
  `__memcpy_avx_unaligned_erms` 54.5%, malloc/free ~5%, remainder
  unsymbolized (release builds ship `debuginfo=0` per the link-light build
  policy). Raw capture: `/data/tmp/callgrind_spawn_mailbox.out` (host-local,
  not committed — 224 KB, unsymbolized).

## Binding performance evidence (parent AC 4)

`benches/spawn_throughput.rs` (criterion, 20 samples, completion-observed —
admission + execution, not just enqueue), shared rch worker, 2026-06-10:

| Scenario | Direct (median) | Mailbox (median) | Delta |
|---|---|---|---|
| single producer | 63.2 Kelem/s | 93.2 Kelem/s | **+47%** |
| 4-producer contended | 47.3 Kelem/s | 72.8 Kelem/s | **+54%** |
| 8-producer contended | 52.7 Kelem/s | 76.2 Kelem/s | **+45%** |

The mailbox path is ≥ baseline in every scenario, with the largest gains
exactly where the design predicted: multi-producer contention on the
`RuntimeState` lock. Shared-fleet caveat: absolute numbers are not
bare-metal-grade; the *relative* deltas are consistent across scenarios and
two runs.

## Non-claims

- Not a kernel-sampled flamegraph; no claim about specific hot-path
  function attribution beyond the callgrind summary above.
- Direct mode remains the default (`SpawnAdmissionMode::Direct`); flipping
  the default is a separate decision with its own evidence per the parent
  bead's fallback plan.
