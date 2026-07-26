# Regex VM iteration, overlap, and zero-width progress contract

<!-- BEGIN REGEX VM ITERATION CONTRACT -->

This document is the human-readable R3.4.3 companion to
`artifacts/regex_vm_iteration_contract_v1.json` for
`asupersync-5z2scg.8.3.4.3`. The private implementation identity is
`ASUP-REGEX-ITERATION-VM-V1`.

The result is a staged, bounded iteration layer over the validated R3.3 IR and
the R3.4.2 one-shot prioritized capture VM. It authorizes deterministic
single-match inspection, `is_match`, capture iteration, explicit overlap
policy, and ordered replacement-span production inside the private
`regex_vm` module. It does not authorize a production cutover.

## Authority and scope

Every attempt still validates the complete `Program` before allocation. The
accepted language, lowering, leftmost-first branch priority, greedy/lazy
selection, and capture participation semantics remain owned by the preceding
compiler and capture contracts. R3.4.3 adds only repeated search and progress.

The iterator retains each `VmMatch` in selection order:

- `VmMatch::span` is the whole-match replacement target;
- `VmMatch::captures` retains participating, unmatched, empty, repeated, and
  Unicode capture spans from R3.4.2;
- `CaptureVmOutcome::is_match()` is the non-allocating one-shot predicate;
- `VmIterationOutcome::replacement_spans()` yields ordered whole-match spans
  without copying or parsing replacement text.

Replacement-template parsing and capture-reference expansion belong to R3.5.
This layer deliberately does not invent `$1`, `${name}`, escaping, or
interpolation behavior.

## Iteration policy

All offsets are UTF-8 byte offsets and every externally retained boundary is
validated with `str::is_char_boundary`.

### Non-overlapping

After a non-empty match, the next search starts at the previous match end.
If that search selects an empty match at exactly the prior non-empty end, the
candidate is recorded and discarded to match incumbent iterator behavior.

After an empty match, the next search starts one complete Unicode scalar after
the match start. To match incumbent non-overlapping behavior, an empty match
that begins exactly where the previous non-empty match ended is discarded and
progress resumes one complete scalar later. A terminal empty match reached
after another empty match is yielded once and then iteration stops.

### Overlapping

After any match, the next search starts one complete Unicode scalar after the
previous match start. A later match may begin inside a previous non-empty
match, but the same start can never be returned twice.

This accepted overlap policy is explicit. It is not silently applied to
replacement: overlapping spans are evidence/analysis targets, while callers
that apply ordered replacements use the non-overlapping policy.

### Zero-width examples

The empty pattern over `éa` yields byte spans:

```text
0..0, 2..2, 3..3
```

It never probes byte offset 1, which is inside `é`. The pattern `a*` over
`baa` yields:

```text
0..0, 1..3
```

The start-empty and consuming selections are retained in order. The terminal
empty begins exactly at the previous non-empty end, so it is recorded as a
discarded adjacent-empty attempt and iteration terminates.

## Aggregate bounds

`IterationVmLimits` makes the existing capture VM ceilings aggregate:

- `capture.vm.max_work_units` covers one bookkeeping unit per search attempt
  plus every nested one-shot VM work count;
- `capture.vm.max_memory_bytes` covers retained matches and the current
  one-shot executor peak at the same time;
- `max_matches` is an exact retained-match ceiling;
- `max_trace_events` bounds normalized iteration receipts.

The retained-memory formula is:

```text
1024
+ max_iteration_trace_events * 80
+ retained_matches * (128 + capture_slots * 32)
```

That retained amount is combined with the current one-shot executor's
accounted peak before admission. The conservative constants dominate the
private Rust types and vector growth policy; focused tests check those size
relationships.

An additional match beyond the ceiling fails with `RGX-VM-E013`. A malformed
search or resume offset fails with `RGX-VM-E014`. Work and memory continue to
use `RGX-VM-E005` and `RGX-VM-E004`. No partial success outcome is returned
after a limit error.

## Normalized replay receipts

Each bounded iteration event contains only:

- monotonic sequence;
- search-start byte offset;
- optional whole-match span;
- optional next-search byte offset;
- the nested one-shot execution fingerprint.
- whether an adjacent empty candidate was discarded.

The aggregate outcome adds match count, search-attempt count, zero-width and
overlap progress counts, total work, peak accounted memory, and a fingerprint
over ordered whole/capture spans. Trace truncation does not stop fingerprint
continuation.

No matched text, pattern text, capture text, or input bytes appear in the
receipt. The four executable privacy probes use the two custom-pattern examples
and the SSN and payment-card-candidate detector patterns from
`src/observability/otel.rs`. Their synthetic inputs are identified in the
artifact by SHA-256. Tests replay each probe twice, compare normalized receipts,
compare spans/captures with `regex@1.13.1`, and assert that serialized receipts
contain none of the synthetic PII values. The compiler terminal contract still
owns unsupported production patterns; this iterator does not widen syntax.

## Evidence

The executable contract retains:

- 15 inline VM tests;
- 20 exact no/one/many/empty/Unicode/capture/overlap fixtures;
- 1,210 bounded non-overlapping comparisons with `regex@1.13.1`;
- 726 accepted-overlap comparisons with an independent `captures_at` plus
  codepoint-progress model;
- 512 generated non-overlapping differential cases;
- four source-grounded privacy-pattern probes with normalized replay receipts;
- long-input deterministic replay;
- panic containment and exact match/work/memory/trace limit failures.

The non-overlapping oracle is the incumbent's `captures_iter`. The overlapping
oracle independently repeats `captures_at`, resuming one Unicode scalar after
the selected match start. Neither oracle calls the candidate's progress helper.

## Proof commands

Run the inline tests through required remote compilation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --overlay-path src/observability/regex_vm.rs -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --features metrics --lib observability::regex_vm::tests -- --nocapture
```

Run the complete predecessor and successor contracts:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --overlay-path src/observability/regex_vm.rs --overlay-path artifacts/regex_vm_iteration_contract_v1.json --overlay-path docs/regex_vm_iteration_contract.md --overlay-path tests/regex_vm_iteration_contract.rs --overlay-path artifacts/regex_vm_captures_contract_v1.json --overlay-path docs/regex_vm_captures_contract.md --overlay-path tests/regex_vm_captures_contract.rs -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --features metrics --test regex_vm_core_contract --test regex_vm_captures_contract --test regex_vm_iteration_contract -- --nocapture
```

Run focused Clippy:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --overlay-path src/observability/regex_vm.rs --overlay-path artifacts/regex_vm_iteration_contract_v1.json --overlay-path docs/regex_vm_iteration_contract.md --overlay-path tests/regex_vm_iteration_contract.rs --overlay-path artifacts/regex_vm_captures_contract_v1.json --overlay-path docs/regex_vm_captures_contract.md --overlay-path tests/regex_vm_captures_contract.rs -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo clippy -p asupersync --features metrics --test regex_vm_core_contract --test regex_vm_captures_contract --test regex_vm_iteration_contract -- -D warnings
```

Formatting is checked with the pinned standalone `rustfmt` when RCH rejects
`cargo fmt --check` as non-compilation work. No local Cargo fallback is approved.

## No-claim boundary

This contract makes:

- no replacement-template parser or capture-reference expansion claim;
- no cancellation or cooperative-yield integration claim;
- no production privacy wiring or dependency-removal claim;
- no accepted-regex-syntax expansion claim;
- no persisted or deserializable VM, capture, iterator, or replacement state
  claim;
- no isolated binary-size or cross-target claim;
- no performance improvement or no-regression claim;
- no broad workspace health or release-readiness claim;
- no live RCH fleet availability claim;
- no local Cargo fallback approval.

`regex@1.13.1` remains the incumbent. The compiler terminal disposition remains
`KEEP_INCUMBENT_DEFER`.

<!-- END REGEX VM ITERATION CONTRACT -->
