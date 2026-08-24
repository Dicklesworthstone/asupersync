# Regex fixed-detector terminal receipt

<!-- BEGIN REGEX FIXED DETECTOR TERMINAL RECEIPT -->

Bead: `asupersync-5z2scg.8.2.5`

## Terminal decision

`KEEP_INCUMBENT_DISABLE_REGRESSED_FIXED_FAST_PATHS`

R2.1 through R2.4 established semantic equivalence, exact detector order,
custom-first dispatch, incumbent fallback, and bounded scanner behavior. R2.5
then measured the candidate and incumbent on two named latency hosts and one
heaptrack host. Every candidate latency cell was slower than the incumbent,
and the candidate allocation census reported more allocation calls and more
temporary allocations. Revision `d35453f0b` therefore disables all four
fixed-scanner production paths and preserves the incumbent regex behavior.

The authorized fixed-fast-path set is empty. The email, SSN, payment-card, and
phone scanner implementations remain in the tree for equivalence and bounded-
resource tests, but production automatic detection does not dispatch to them.
Custom patterns have always remained on the incumbent.

## Equivalence and rollback replay

| Surface | Source revision | Forced-remote evidence | Terminal disposition |
| --- | --- | --- | --- |
| Email and SSN | `a3bf8f2cd` | `j-29988810699833424` (3/3) | `KEEP` |
| Payment card and Luhn | `702f1cc78` | `j-29988810699833430` (4/4) | `KEEP` |
| Phone and exact dispatch | `5285afb06` | `j-29988810699833435` (5/5) | `KEEP` |
| Rollback and all fixed-scanner tests | `d35453f0b` | `j-29988810699833448` (45/45) | incumbent enabled |
| Frozen corpus contract after rollback | `d35453f0b` | `j-29988810699833449` (8/8) | `SAME` |

All 62 frozen detector vectors and all 19 public-pipeline vectors are bound in
the JSON receipt. Scanner refusal still falls through without publishing a
partial result. The retained implementation bounds are 1,048,576 input bytes,
65,536 match spans, and 16,777,280 work units.

## Named-host latency evidence

Each cell used 64 warmups and 2,001 measured operations under the release
profile. Values are candidate/incumbent. Throughput is operations per second;
latencies are nanoseconds. The raw 2,001-sample distributions remain in the
referenced RCH job outputs.

| Host/job | Scenario | Throughput | p50 | p95 | p999 |
| --- | --- | ---: | ---: | ---: | ---: |
| `ovh-a` / `j-29988810699833441` | email | 1,797,057 / 11,356,670 | 551 / 90 | 581 / 91 | 721 / 120 |
| `ovh-a` / `j-29988810699833441` | SSN | 2,371,398 / 11,685,353 | 421 / 80 | 431 / 91 | 641 / 201 |
| `ovh-a` / `j-29988810699833441` | card | 1,957,814 / 5,116,103 | 511 / 190 | 511 / 211 | 821 / 471 |
| `ovh-a` / `j-29988810699833441` | phone | 536,058 / 6,069,301 | 1,834 / 161 | 1,883 / 171 | 6,392 / 271 |
| `ovh-a` / `j-29988810699833441` | mixed | 1,787,036 / 12,807,957 | 551 / 80 | 581 / 81 | 751 / 130 |
| `ovh-a` / `j-29988810699833441` | 51,200-byte miss | 977 / 5,486 | 993,809 / 176,480 | 1,194,625 / 219,561 | 1,755,273 / 280,024 |
| `vmi1293453` / `j-29988810699833442` | email | 1,410,846 / 10,516,026 | 531 / 90 | 751 / 120 | 11,187 / 191 |
| `vmi1293453` / `j-29988810699833442` | SSN | 2,394,803 / 10,592,121 | 351 / 100 | 521 / 120 | 6,300 / 511 |
| `vmi1293453` / `j-29988810699833442` | card | 1,840,870 / 4,444,740 | 480 / 210 | 711 / 300 | 10,035 / 2,233 |
| `vmi1293453` / `j-29988810699833442` | phone | 449,006 / 6,998,534 | 2,093 / 131 | 2,504 / 141 | 43,225 / 230 |
| `vmi1293453` / `j-29988810699833442` | mixed | 1,432,944 / 9,050,203 | 701 / 110 | 781 / 120 | 14,201 / 140 |
| `vmi1293453` / `j-29988810699833442` | 51,200-byte miss | 353 / 2,407 | 1,249,530 / 213,058 | 1,679,645 / 240,981 | 68,019,244 / 53,243,494 |

`ovh-a` reported an AMD Ryzen 7 5800X with 16 logical CPUs and
65,729,736 KiB memory. `vmi1293453` reported an AMD EPYC processor with 8
logical CPUs and 30,799,832 KiB memory. These are named-host observations,
not portable performance guarantees.

## Allocation evidence

The evidence-only `thinkstation2` worker supplied heaptrack for isolated
candidate and incumbent runs. Its normal disabled-worker setting was restored
after the two pinned jobs.

| Operation/job | Allocation calls | Temporary allocations | Peak heap | Peak RSS | Leaked |
| --- | ---: | ---: | ---: | ---: | ---: |
| candidate / `j-29988810699833444` | 191,937 | 61,441 | 2.82M | 10.77M | 616.66K |
| incumbent / `j-29988810699833445` | 39,127 | 26,336 | 2.82M | 10.32M | 616.66K |

The candidate therefore increased allocation calls by 152,810 and temporary
allocations by 35,105 in this harness. That observation is the allocation
rollback trigger; it is not a general memory-use claim.

## Replay commands

Latency replay, substituting one of the recorded target IDs:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base 03a6fa83274c65f383c04d9a541bb94b2d3ee54f --clean-overlay --no-overlay -- env R2_5_FIXED_DETECTOR_PERF_TARGET=ovh-a-x86_64 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test --release -j 2 -p asupersync --features metrics --test regex_fixed_detector_terminal_receipt_contract r2_5_release_performance_emitter -- --exact --nocapture
```

Allocation replay on a worker whose live capability receipt includes
`heaptrack`:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base 2264da2b68b026016dc7ed77119f0b585a881f9f --clean-overlay --no-overlay -- env R2_5_FIXED_DETECTOR_PERF_TARGET=ts2-x86_64-heaptrack-candidate R2_5_FIXED_DETECTOR_PERF_OPERATION=candidate CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='scripts/alloc_census.sh --cargo-runner-heaptrack' CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test --release --target x86_64-unknown-linux-gnu -p asupersync --features metrics --test regex_fixed_detector_terminal_receipt_contract r2_5_release_performance_emitter -- --exact --nocapture
```

No local Cargo fallback is approved. Missing remote admission, missing
heaptrack capability, or a non-terminal RCH job is no evidence.

## No-claim boundary

This receipt does not authorize dependency removal, custom-pattern narrowing,
or any fixed-scanner production fast path. It makes no global performance,
production-workload, release-readiness, broad workspace-health, or live-fleet
availability claim. A later fast-path proposal must produce fresh equivalence,
resource, named-host, and allocation evidence and must fail closed again on any
semantic disagreement or regression.

<!-- END REGEX FIXED DETECTOR TERMINAL RECEIPT -->
