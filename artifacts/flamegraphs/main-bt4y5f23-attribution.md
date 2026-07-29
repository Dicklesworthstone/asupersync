# E1.3 attribution — unified|sharded spawn-path dossier (bt4y5f.2.3)

Changes attributed: the 8fuxnt public gate flip (b403be2a8: builder.rs,
config.rs, scheduler/state_backing.rs — the state_backing touch is what
path-triggers this artifact) and the spawn_throughput shape axis
(2628c423f). Both are behavior-preserving for the default Unified shape by
construction; this artifact records the measured cost relationship between
the shapes on the public spawn path.

Flamegraph SVG: not generatable through the mandated remote lane —
`rch exec -- ... cargo flamegraph` is refused as a non-compilation command
(RCH-E301, `refusing local fallback (non-compilation command)`), the same
wall recorded by the four prior `main-*-attribution.md` notes in this
directory. Attribution below uses the epic's measurement protocol instead:
the WITHIN-RUN unified/sharded ratio is the instrument (both shapes
measured back-to-back in one criterion process on one worker, so host
class and co-tenant drift cancel in the ratio); cross-run absolutes are
direction-only. No waiver claimed; if the rch flamegraph lane becomes
available, an SVG should supersede this note.

## Six-run dossier (ovh-a, shared 4-slot pool, 2026-07-29 14:07–14:58Z)

Instrument: benches/spawn_throughput.rs `spawn_throughput/` group,
1000-spawn bursts, runtime workers=4, criterion midpoints. Ratio =
sharded_time / unified_time; < 1.0 means sharded faster. Run 2 is
contaminated (its UNIFIED single/direct cell inflated +64% alongside the
sharded blowups — co-tenant burst inside the run window; the co-tenant
recompile churn is visible in run 3's pool rebuild) and is excluded from
the clean median but reported, never discarded silently.

| cell | clean median | all-runs median | min | max |
|------|-------------|-----------------|-----|-----|
| single_producer_latched/direct | **0.881** | 0.877 | 0.561 | 0.958 |
| single_producer_latched/mailbox | 1.001 | 1.001 | 0.963 | 1.463 |
| contended_4_producers/direct | 0.983 | 0.986 | 0.917 | 2.008 |
| contended_4_producers/mailbox | 0.980 | 0.984 | 0.956 | 1.166 |
| contended_8_producers/direct | 1.015 | 1.019 | 0.997 | 2.316 |
| contended_8_producers/mailbox | 0.976 | 0.981 | 0.957 | 1.005 |

## Reading (the honest one)

- **No regression**: no cell shows a consistent sharded deficit (worst
  clean median 1.015, inside the ±2% band this fleet resolves).
- **One consistent win**: single-producer/direct is ~12% faster sharded
  in 5/5 clean runs — the uncontended spawn+poll round-trip benefits
  from shard-A isolation immediately.
- **Contended parity, NOT the thesis win**: at workers=4 the contended
  cells are parity ±2%. Architecturally consistent: task completion
  still crosses the unified state lock on BOTH shapes (the unified state
  remains the B/C/D lifecycle owner after E1.2), so producer-side
  contention was already amortized by the mailbox and the remaining
  shared serialization dominates. The shard-A poll-path relief needs
  more polling workers than 4 to become visible — or the remaining
  B/C shard conversions.
- **Default-flip implication (parent AC 3)**: the perf case for flipping
  the default to Sharded is NOT made by this workload scale. Per the
  AC, the no-win is being investigated before proceeding: next
  instrument is a worker-count axis (4 vs 16) on the shaped contended
  cells. The flip decision waits for that evidence; parity means there
  is also no perf argument AGAINST the sharded shape for opt-in users.

Raw log: session scratchpad `run_e13_dossier.log` (6 runs, 0 failures,
worker/dispatch lines preserved). Analysis: `analyze_e13_dossier.py`.
