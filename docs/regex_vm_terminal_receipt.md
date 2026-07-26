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

The artifact stores nine raw nanosecond samples for candidate/incumbent compile
and match operations on each named RCH worker. The workload, worker topology,
toolchain, source hash, incumbent version, profile, and raw distributions are
recorded. Allocation counts and RSS are
`UNKNOWN_NOT_INSTRUMENTED`.

Across both target receipts, every candidate compile sample was lower than its
incumbent counterpart, while every candidate match sample was higher. The
slower unoptimized match distributions and unknown resource cells independently
prevent SAME/BETTER admission and retain the incumbent.

These unoptimized contract-test measurements admit no threshold and make no performance improvement or no-regression claim.
They are provenance cells, not production benchmark evidence. Unknown
allocation/RSS cells therefore remain explicit and cannot be treated as SAME
or BETTER.

## Replay

The canonical commands are recorded verbatim in
`artifacts/regex_vm_terminal_receipt_v1.json`. They use an exact seven-path
clean overlay on `HEAD`, remote-required RCH admission, disabled incremental
compilation, and warnings as errors. Formatting is checked with the pinned
standalone nightly `rustfmt`, because this host's RCH policy rejects a remote
`cargo fmt` lane.

No local Cargo fallback is approved.

## No-claim boundaries

This receipt makes no complete public regex API or replacement-template
expansion claim; no accepted syntax expansion claim; no persisted VM or
cancellation-state claim; no allocation, RSS, binary-size, or cross-target
claim; no broad workspace-health or release-readiness claim; and
no production privacy wiring or dependency removal claim.

<!-- END REGEX VM TERMINAL RECEIPT -->
