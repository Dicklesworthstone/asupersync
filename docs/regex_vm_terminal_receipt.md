# Regex VM terminal receipt

<!-- BEGIN REGEX VM TERMINAL RECEIPT -->

`ASUP-REGEX-VM-TERMINAL-V1` is the fail-closed R3.4 terminal receipt for
`asupersync-5z2scg.8.3.4.4`. It combines the frozen R3.4.1 core, R3.4.2
capture, and R3.4.3 iteration evidence with explicit cooperative cancellation,
adversarial work evidence, and raw two-target measurements.

The terminal disposition is `KEEP_INCUMBENT_DEFER`. The private bounded VM is
not production wiring, the compiler terminal already retains `regex@1.13.1`,
and this bead does not authorize a dependency exit. Missing, unknown, stale,
expired, or drifted evidence keeps that same disposition.

## Explicit cancellation contract

Cancellation is caller-supplied through `VmCancellationControl` and a mutable
probe. It uses no ambient global, thread-local, runtime, clock, task, socket, or
signal state. A checkpoint contains only its deterministic sequence, aggregate
work units, byte offset, and optional IR state. Pattern and haystack bytes are
never retained by the control or its normalized receipts.

The default interval is 1,024 charged work units. A zero interval fails as
`RGX-VM-E001`; an admitted cancellation fails as `RGX-VM-E015`. Built-in work
limits are checked before the probe, so a work-budget failure remains
`RGX-VM-E005` and cannot be rewritten as cancellation. Iterated searches share
one aggregate sequence and budget. Cancellation returns no partial successful
outcome, and an immutable validated program remains reusable afterward.

This is a synchronous cooperative checkpoint surface. It does not claim
`Cx`-cancellation integration, task or obligation management, cooperative
yielding, or preemption between work charges.

## R3.6 bounded cache extension

The R3.6 extension adds a caller-owned `PrivatePatternCache`; there is no
process-global cache or ambient mutable policy. Its LRU key covers the complete
private configuration. A bounded fingerprint is only a lookup prefilter: exact
source equality is required before reuse, so a collision cannot select a
different pattern or limit policy. Exact comparisons and entry scans consume an
explicit lookup-work budget.

Cache misses compile outside the cache-state mutex. Count and conservative
compile-byte ceilings are admitted and released as one coherent accounting
tuple. Because a default compile reserves about 1.135 GiB from the configured
stage ceilings, the default 2 GiB aggregate budget intentionally admits one
in-flight compile. A caller that tightens stage ceilings may explicitly raise
the count. Duplicate misses may compile concurrently under those explicit
limits, but admission rechecks exact equality and retains one winner.

Residents have deterministic logical byte charges. Eviction and shutdown drop
cache ownership without invalidating outstanding leases, and evicted leases
remain charged until their final owner drops. Source pattern bytes are retained
in the collision-safe key for that same lifetime, but never rendered by cache
diagnostics. This is not a memory-erasure, allocator-usable-size, or RSS claim.

Caller-owned cancellation checkpoints run before lookup, before compilation,
and before admission, always outside the cache mutex. Compilation itself remains
synchronously work-bounded rather than promptly preemptible; a cancellation
observed before admission discards the compiled value. Focused tests cover
racing duplicate compilation, controlled use during eviction, pinned capacity,
count and byte refusal, lookup-work refusal, cancellation, idempotent shutdown,
and exact convergence to zero live/in-flight accounting.

The R3.6 release-profile matrix is now measured on Linux x86_64 and Apple
Silicon. Each host ran 1,001 raw samples for six operations over four patterns,
including ASCII captures, Unicode properties, ambiguous alternation, and a wide
full-scan miss. The cache ended every scenario closed with zero entries, live
accounted bytes, or in-flight accounting. Compile and cache-hit paths were
strong, but the owned match path remained orders of magnitude slower than
`regex@1.13.1` on every scenario and both hosts. The disposition therefore
remains `KEEP_INCUMBENT_DEFER`; this extension authorizes no production privacy
wiring, public cutover, or dependency removal.

## Adversarial and replay evidence

The terminal contract checks huge consuming repetition, an ambiguous suffix,
wide alternation, 64 nested captures, a long Greek property run, and the
compiler's retained nullable-loop defer case. It compares supported
non-overlapping rows with `regex@1.13.1`, replays 160 cancellation
interval/cutoff combinations, contains panics, checks deterministic receipts,
and verifies approximately linear charged work for a doubled ambiguous input.

Inherited evidence remains scoped to the predecessor contracts: 1,210 bounded
non-overlapping incumbent comparisons, 726 overlapping model comparisons, 512
property cases, exact core/capture/iteration fixtures, privacy canaries, and
bounded resource receipts.

## Performance provenance

### R3.4 precursor measurements

The artifact stores nine raw nanosecond samples for candidate/incumbent compile
and match operations on each named RCH worker. The workload, worker topology,
toolchain, source hash, incumbent version, profile, and raw distributions are
recorded. Allocation counts and RSS are
`UNKNOWN_NOT_INSTRUMENTED`.

Across both target receipts, every candidate compile sample was lower than its
incumbent counterpart, while every candidate match sample was higher. The
slower unoptimized match distributions and unknown resource cells independently
prevent SAME/BETTER admission and retain the incumbent.

These unoptimized contract-test measurements admit no threshold and make no
performance improvement or no-regression claim. They are provenance cells, not
production benchmark evidence. Their unknown allocation/RSS cells remain
explicit and cannot be treated as SAME or BETTER.

### R3.6 release-profile decision evidence

The permanent harness at revision `3244d50a1d6fb29ea2914b99babd205d88c59522`
measured 1,001 single-operation samples after 32 warmups for owned compile,
incumbent compile, cache miss, cache hit, owned `is_match`, and incumbent
`is_match`. It uses nearest-rank p50/p95/p999 and records the 24,024 raw samples
per target in the terminal RCH receipts. The exact job IDs, hardware, compact
quantiles, throughput, and source/overlay fingerprints are in the artifact.

The p50 match latency alone makes the decision unambiguous:

| Scenario | x86_64 owned / incumbent | Apple M4 Pro owned / incumbent |
|---|---:|---:|
| ASCII capture tail match | 552,288 / 70 ns | 485,458 / 83 ns |
| Unicode property tail match | 409,269 / 40 ns | 385,750 / 42 ns |
| Ambiguous alternation suffix | 506,231 / 40 ns | 429,250 / 42 ns |
| Wide alternation full-scan miss | 3,527,941 / 50 ns | 3,284,334 / 292 ns |

By contrast, cache-hit p50 was 40–100 ns on x86_64 and 41–83 ns on the M4 Pro,
and owned compile p50 beat incumbent compile p50 in every measured scenario.
That does not offset the match-path deficit, so no production cutover is
admitted.

Resource evidence covers the full four-scenario process, not an isolated cache
operation. Linux `heaptrack` observed 53,248,319 allocation calls, 19,075,354
temporary allocations, 1.67M peak heap, 9.99M peak RSS including profiler
overhead, and 944 bytes of process-lifetime residual attributed to stripped-test
startup and pthread TLS rather than the cache. Apple Xcode Allocations observed
53,249,485 allocations, 7,688,683,200 total bytes, 7,688,561,664 transient
bytes, and 121,536 persistent bytes. Direct execution of the exact successful
RCH-built Apple binary under `/usr/bin/time -l` exited zero with 7,766,016 bytes
maximum RSS and 5,849,376 bytes peak memory footprint. These are measurements,
not allocator-usable-size, zero-process-leak, production-RSS, improvement, or
no-regression guarantees.

## Replay

The canonical commands are recorded verbatim in
`artifacts/regex_vm_terminal_receipt_v1.json`. They use exact owned-path clean
overlays on `HEAD`, remote-required RCH admission, disabled incremental
compilation, and warnings as errors. Formatting is checked with the pinned
standalone nightly `rustfmt`, because this host's RCH policy rejects a remote
`cargo fmt` lane.

No local Cargo fallback is approved.

## No-claim boundaries

This receipt makes no complete public regex API or replacement-template
expansion claim; no accepted syntax expansion claim; no persisted VM or
cancellation-state claim; no allocator-usable-size, zero-process-leak,
production-RSS, performance-improvement, no-regression, or binary-size claim;
no target-coverage claim beyond the named x86_64 Linux and Apple Silicon hosts;
no broad workspace-health or release-readiness claim; and no production privacy
wiring or dependency removal claim.

<!-- END REGEX VM TERMINAL RECEIPT -->
