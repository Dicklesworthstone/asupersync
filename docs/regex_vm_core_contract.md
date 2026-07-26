# Regex thread-set VM core contract

<!-- BEGIN REGEX VM CORE CONTRACT -->

This is the scoped R3.4.1 contract for
`asupersync-5z2scg.8.3.4.1`, `CAP-REGEX-PRIVACY`, and
`ASUP-REGEX-THREAD-SET-VM-V1`.

The disposition is `STAGED_BOUNDED_VM_CORE`. The implementation is private,
strictly safe, synchronous, deterministic, and resource bounded. It executes
only R3.3 `Program` values that pass `Program::validate` and recognizes whether
the entire UTF-8 haystack is accepted. The compiler terminal remains
`KEEP_INCUMBENT_DEFER`: this contract neither changes the incumbent decision
nor authorizes production matching or dependency exit.

## Execution model

The VM maintains an ordered thread set per byte offset. `Jump`, ordered
`Split`, `Save`, and passing `Assert` instructions extend the epsilon closure
at the same offset. `Consume` advances by one Unicode scalar or one validated
exact byte. First arrival of a state at an offset wins; later arrivals are
deduplicated. This makes epsilon cycles terminate and preserves the R3.3
preferred-before-fallback ordering without recursion.

Mixed Unicode and exact-byte paths use a five-bucket modulo ring. Five is one
more than the maximum four-byte UTF-8 scalar width, so a future thread cannot
collide with a live predecessor bucket. The executor never allocates an
input-length-by-state matrix.

Acceptance means reaching the program's checked `Accept` state at exactly the
haystack byte length. `Save` is epsilon-only in this bead. Capture values,
leftmost search, iteration, and cancellation-aware public matcher APIs remain
downstream.

## Limits and accounting

The default ceilings are:

- input: 1,048,576 bytes;
- live threads at one offset: 262,144;
- accounted VM memory: 16,777,216 bytes;
- charged work: 67,108,864 units;
- retained trace: 256 events.

Accounted memory includes the VM base, five thread vectors, five state-dedup
maps, and the fixed trace capacity. Charged work covers offset visits, state
visits, enqueues, binary-search comparisons for canonical class ranges,
assertion evaluations, and bucket cleanup. Every addition and multiplication
that affects a ceiling is checked.

Trace retention is bounded. Once the event vector reaches its cap, the VM
continues a deterministic fingerprint and marks the trace truncated. Errors
contain stable `RGX-VM-E001` through `RGX-VM-E009` codes and structural
coordinates only; pattern and haystack text are not rendered.

The executor creates no task, obligation, permit, socket, file, lock,
background worker, cancellation protocol, shutdown protocol, or region
lifecycle. Dropping the synchronous call releases all owned memory.

## Evidence

The contract checks empty programs and inputs, literals, Unicode, canonical
classes, input/line/word assertions, captures as epsilon transitions, ordered
splits, duplicate states, epsilon cycles, mixed Unicode/exact-byte paths,
malformed checked IR, each VM ceiling, deterministic replay, trace truncation,
and a 100,000-byte long-input state-visit bound.

An independent checked-IR reachability model and the quarantined incumbent
`regex@1.13.1` are compared over 15 supported patterns and every haystack over
`a`, `b`, `A`, and `é` through four scalars: 5,115 decisions. A 512-case
property lane and deterministic 1,024-case execution and malformed-IR fuzz
lanes run behind `catch_unwind`. Oracle evidence expires at
`2026-10-23T00:00:00Z`, or earlier on the machine receipt's drift conditions.

The retained exact-byte fixture is `(?i-u:é)`, which the R3.3 compiler terminal
lowers to the validated bytes `C3 A9`. The spelling
`(?-u:\xC3\xA9)` remains retained as `RGX-VM-MIN-003` with
`KEEP_INCUMBENT_DEFER`: the current R3.3 lowering does not emit exact-byte IR
for that non-folded spelling. This is a compiler boundary, not an executor
claim.

## Successor handoff

R3.4.2 extends the same private source file with one-shot priority selection
and bounded capture histories. This R3.4.1 packet therefore retains the
original `src/observability/regex_vm.rs` digest as a historical pin rather than
pretending it is still the live source authority. The live source pin and the
new behavior belong to
`artifacts/regex_vm_captures_contract_v1.json`.

The R3.4.1 contract test continues to execute every core recognizer fixture,
model comparison, property case, malformed-IR case, resource ceiling, and
long-input replay against the successor source. Its behavioral evidence remains
live even though its original source digest is historical.

## Replay

Run the VM unit tests remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path src/observability/regex_vm.rs \
  --overlay-path src/observability/mod.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics --lib \
  observability::regex_vm::tests -- --nocapture
```

Run the full contract remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path src/observability/regex_vm.rs \
  --overlay-path src/observability/mod.rs \
  --overlay-path artifacts/regex_vm_core_contract_v1.json \
  --overlay-path docs/regex_vm_core_contract.md \
  --overlay-path tests/regex_vm_core_contract.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  --test regex_vm_core_contract -- --nocapture
```

Run focused Clippy remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path src/observability/regex_vm.rs \
  --overlay-path src/observability/mod.rs \
  --overlay-path artifacts/regex_vm_core_contract_v1.json \
  --overlay-path docs/regex_vm_core_contract.md \
  --overlay-path tests/regex_vm_core_contract.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-C debuginfo=0' \
  cargo clippy -p asupersync --features metrics \
  --test regex_vm_core_contract -- -D warnings
```

No local Cargo fallback is approved.

## No-claim boundary

This packet proves only the private checked-IR whole-haystack VM, its ordered
epsilon closure, bounded accounting, deterministic trace, exact fixtures,
reference/property/fuzz comparisons, source pins, and fail-closed behavior.

- no leftmost search or capture propagation
- no iteration API or cancellation integration
- no production privacy wiring or dependency removal
- no non-folded byte-mode escape lowering claim
- no persisted or deserializable VM state
- no public API or accepted-syntax expansion
- no isolated binary-size or cross-target result
- no performance improvement or no-regression claim
- no broad workspace health or release-readiness claim
- no live RCH fleet availability claim
- no local Cargo fallback approval

<!-- END REGEX VM CORE CONTRACT -->
