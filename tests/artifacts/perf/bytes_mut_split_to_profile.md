# BytesMut split_to profile

## Scenario

- Target: `src/bytes/bytes_mut.rs::BytesMut::split_to`
- Workload: existing Criterion `bytes_allocation_profile` benchmark, filtered to `bytes_mut_splitting`
- Command: `rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_superserver_3637090_pane3 cargo bench --bench bytes_allocation_profile --features messaging-fabric,test-internals -- bytes_mut_splitting --sample-size 15 --measurement-time 1 --warm-up-time 1`
- Agent: `IvoryLantern`
- Bead: `asupersync-85ukb2`

## Hotspot Table

| Rank | Location | Metric | Value | Category | Evidence |
|------|----------|--------|-------|----------|----------|
| 1 | `BytesMut::split_to` front-drain frame splitting | mean wall time vs `split_off` comparison path, 8192/512 | 1.0043 us vs 687.37 ns; 1.46x slower | CPU/memmove/alloc | rch Criterion run, 2026-05-12T01:26:48Z |
| 2 | `BytesMut::split_to` front-drain frame splitting | mean wall time vs `split_off` comparison path, 32768/1024 | 5.2206 us vs 1.8851 us; 2.77x slower | CPU/memmove/alloc | rch Criterion run, 2026-05-12T01:26:48Z |
| 3 | `BytesMut::split_to` front-drain frame splitting | mean wall time vs `split_off` comparison path, 131072/4096 | 17.631 us vs 4.9375 us; 3.57x slower | CPU/memmove/alloc | rch Criterion run, 2026-05-12T01:26:48Z |

## Rejected Local Fix

I tested a narrow implementation change that used `Vec::split_off` plus `mem::replace` when the returned prefix was larger than the remaining suffix. It did not ship: the same Criterion filter reported `split_to` regressions of +15.005% for 32768/1024 and +18.224% for 131072/4096.

## Hypothesis Ledger

- `split_to` front-drain representation cost: supports. The current `Vec<u8>` backing copies the prefix and drains the front, so repeated protocol frame extraction repeatedly moves the remaining suffix.
- Simple suffix-smaller `Vec::split_off` branch: rejects. It regressed the measured `split_to` workload.
- Durable fix likely requires representation work: supports. A shared-backing plus offset/len `BytesMut`, or another buffer representation that can advance the front without memmoving the suffix, is the plausible path.
