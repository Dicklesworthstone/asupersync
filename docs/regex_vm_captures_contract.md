# Regex VM priority and capture contract

<!-- BEGIN REGEX VM CAPTURES CONTRACT -->

This is the operator-readable companion to
`artifacts/regex_vm_captures_contract_v1.json` for
`asupersync-5z2scg.8.3.4.2` and `CAP-REGEX-PRIVACY`.

The private executor is `ASUP-REGEX-PRIORITY-CAPTURE-VM-V1`. It consumes only
programs accepted by the R3.3 validator. The compiler terminal disposition
remains `KEEP_INCUMBENT_DEFER`: this stage does not wire the candidate into
`PrivacyConfig`, remove `regex@1.13.1`, or authorize a production cutover.

## Selection contract

The incumbent policy is leftmost-first, not leftmost-longest. The earliest
start wins. At that start, the first branch in an alternation outranks later
branches even when a later branch would consume more input. Greedy and lazy
quantifiers alter path priority:

- a greedy split prefers the consuming body and keeps an earlier accepted exit
  provisional while the body path remains live;
- a lazy split prefers the exit and discards the lower-priority body once that
  exit accepts;
- `Instruction::Split { preferred, fallback }` is the sole VM ordering
  authority.

The VM processes epsilon closure depth-first. It pushes the fallback before the
preferred arm on its private stack, causing the preferred arm to be visited
first. State deduplication occurs on visit, not when a lower-priority arm is
merely scheduled. The first visited state therefore retains the
higher-priority capture history.

Search adds the program entry at each UTF-8 boundary. A new start is appended
after every live thread from earlier starts, so it cannot displace an earlier
match. Once an accept is observed, lower-priority work is discarded while
already-produced higher-priority work is allowed to continue and replace the
provisional candidate.

## One-byte priority frontier

The R3.3 IR can consume either one raw byte or one Unicode scalar. Directly
placing a matched scalar's target several byte offsets ahead would let
lower-priority one-byte paths be processed out of order.

R3.4.2 instead advances every priority frontier exactly one byte. A matched
multi-byte scalar creates a bounded continuation thread for its remaining one
to three bytes. The scalar has already been validated; continuation only
preserves scheduling order until the target state becomes runnable.

There are four seen keys per state: the state itself plus continuation
remaining lengths one through three. Two offset buckets suffice because every
thread advances at most one byte. The externally reported match and capture
spans must still be UTF-8 boundaries.

## Persistent capture history

Every `Save` appends one immutable node containing the slot, byte offset, and
previous-node index. Threads copy only the head index. This persistent capture
history avoids a capture-slot vector copy on every fork.

At acceptance, the VM walks the selected history newest-first. The first value
for each slot wins:

- capture `n` uses start/end slots `2n-2` and `2n-1`;
- a participating capture is `Some(start, end)`;
- a participating empty capture is `Some(offset, offset)`;
- an unmatched optional capture is `None`;
- a repeated group retains its final participating iteration on the selected
  path.

The whole match span is stored separately because the frozen IR assigns slots
only to explicit capture groups.

## Bounds and diagnostics

The default history ceiling is 262,144 nodes. Each history node is
conservatively charged 64 schema-accounting bytes, with a 256-byte allocation
floor once the history becomes nonempty. Each frontier thread is charged 64
bytes, and every touched-seen reset key is charged 8 bytes. Thread frontiers,
seen keys, reset keys, materialization slots, retained trace, and history nodes
all count against
`VmLimits::max_memory_bytes`. Every scheduling, visit, class comparison,
assertion, save, and materialization step is charged against
`VmLimits::max_work_units`.

Capture-specific failures are:

- `RGX-VM-E010`: capture-history node ceiling;
- `RGX-VM-E011`: structurally invalid internal capture history;
- `RGX-VM-E012`: whole or capture span is not a valid UTF-8 boundary.

Diagnostics contain structural offsets, state/class IDs, and actual/limit
values only. They do not contain the pattern, haystack, or captured text.

## Independent evidence

The focused contract covers:

- 20 exact goldens for ambiguous alternation, priority-sensitive capture
  deduplication, greedy/lazy and counted repeats,
  nested captures, unmatched and empty captures, repeated groups, case
  folding, no-match behavior, and Unicode byte spans;
- 5,115 exhaustive small-language comparisons against `regex@1.13.1`;
- 512 generated priority/capture comparisons against the incumbent;
- anchored-prefix versus anchored-full selection;
- deterministic long-input replay with bounded work, memory, history, and
  trace;
- explicit invalid-limit, history-limit, memory-limit, and work-limit failures;
- panic containment across six adversarial patterns and all ternary
  haystacks through five scalars.

The executor is synchronous and strictly safe. It owns no task, obligation,
permit, socket, file, lock, timer, or background work. Cancellation, timeout,
shutdown, cleanup, and region-quiescence scenarios do not apply to this
one-shot pure computation.

## R3.4.3 successor handoff

R3.4.3 extends the same private source with bounded iteration, explicit overlap
policy, Unicode-safe zero-width progress, and ordered replacement spans. The
live source digest therefore moves to
`artifacts/regex_vm_iteration_contract_v1.json`. This artifact retains the
original R3.4.2 `src/observability/regex_vm.rs` digest as a historical pin.

`tests/regex_vm_captures_contract.rs` still imports and executes the current
source. Its 20 exact fixtures, 5,115 incumbent comparisons, 512 generated
cases, adversarial enumeration, resource failures, and privacy canaries remain
live behavioral evidence even though its original source digest is historical.
The R3.4.3 contract runs the core, capture, and iteration contracts together.

## Remote proof

Run the focused inline unit tests:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path src/observability/regex_vm.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics --lib \
  observability::regex_vm::tests -- --nocapture
```

Run the predecessor and successor contracts together:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path src/observability/regex_vm.rs \
  --overlay-path artifacts/regex_vm_core_contract_v1.json \
  --overlay-path artifacts/regex_vm_captures_contract_v1.json \
  --overlay-path docs/regex_vm_core_contract.md \
  --overlay-path docs/regex_vm_captures_contract.md \
  --overlay-path tests/regex_vm_core_contract.rs \
  --overlay-path tests/regex_vm_captures_contract.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  --test regex_vm_core_contract \
  --test regex_vm_captures_contract -- --nocapture
```

Run focused Clippy:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path src/observability/regex_vm.rs \
  --overlay-path artifacts/regex_vm_core_contract_v1.json \
  --overlay-path artifacts/regex_vm_captures_contract_v1.json \
  --overlay-path docs/regex_vm_core_contract.md \
  --overlay-path docs/regex_vm_captures_contract.md \
  --overlay-path tests/regex_vm_core_contract.rs \
  --overlay-path tests/regex_vm_captures_contract.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-C debuginfo=0' \
  cargo clippy -p asupersync --features metrics \
  --test regex_vm_core_contract \
  --test regex_vm_captures_contract -- -D warnings
```

No local Cargo fallback is approved.

## No-claim boundary

This contract proves only the private one-shot selection and capture surfaces
described above. It makes:

- no iteration, replacement, or zero-width progress API claim;
- no cancellation integration claim;
- no production privacy wiring or dependency removal claim;
- no non-folded byte-mode escape lowering claim;
- no persisted or deserializable VM or capture-state claim;
- no public API or accepted-syntax expansion claim;
- no isolated binary-size or cross-target result claim;
- no performance improvement or no-regression claim;
- no broad workspace health, release-readiness, or live-fleet claim.

<!-- END REGEX VM CAPTURES CONTRACT -->
