# Regex priority and capture lowering contract

<!-- BEGIN REGEX PRIORITY CAPTURE LOWERING CONTRACT -->

This is the operator-readable companion to
`artifacts/regex_priority_capture_lowering_contract_v1.json` for
`asupersync-5z2scg.8.3.3.3` and `CAP-REGEX-PRIVACY`.

R3.2.4 remains the semantic authority with disposition
`KEEP_INCUMBENT_DEFER`. R3.3.1 remains the immutable representation authority
for `ASUP-REGEX-THOMPSON-IR-V1`. R3.3.3 advances the private
`ASUP-REGEX-THOMPSON-LOWERING-V1` compiler to lowering schema version 2 without
changing the IR schema.

## Capture boundary contract

Capture numbering comes from the pinned R3.2.1 AST and follows opening
parenthesis order. Capture `n` maps to the even/odd slot pair `2n-2` and
`2n-1`. The lowerer emits the start `Save` at a zero-width source span located
at the group's byte/scalar start and the end `Save` at a zero-width source span
located at the group's byte/scalar end.

Finite repetition copies reuse the same slot pair, so the winning prioritized
path retains the final participating iteration. A zero-count repetition around
a capture would require an explicit unset-capture representation that the
frozen IR does not have. It therefore fails closed with `RGX-LOWER-E010`
instead of silently renumbering slots or recording a false empty capture.

## Quantifier and priority contract

The full accepted quantifier surface is lowered:

- `?` becomes an ordered child-or-empty `Split`;
- `*` becomes an ordered entry `Split` with a consuming body back-edge;
- `+` enters the body before its ordered consuming back-edge;
- `{n}` emits exactly `n` body instances;
- `{m,}` emits `m` mandatory instances and reuses the last as its consuming
  loop;
- `{m,n}` emits `m` mandatory instances followed by `n-m` ordered optional
  instances.

For greedy forms, `preferred` selects the body and `fallback` selects the exit.
Lazy forms reverse those arms. Alternation retains the R3.3.2 left-to-right
priority contract. The R3.2 parser has already applied scoped `U` greediness
swaps, while scoped case, dot, line, CRLF, Unicode, and whitespace flags have
already shaped the canonical classes, folds, boundaries, and AST by source
span. Flag wrappers therefore remain transparent without losing scope.

Compiler-emitted finite copies clone only state graphs. Canonical class IDs are
shared. Expansion is counted in cloned states and checked against both the
repetition and state ceilings before allocation. A zero-count body is removed
by a deterministic reachability/reindex pass, including any now-unreferenced
classes, before `Program::checked` recomputes the complete resource receipt.

## Nullable-loop and error boundary

An unbounded repetition whose child has zero minimum expansion would introduce
an epsilon cycle into the VM contract. The lowerer detects that condition from
the pinned AST expansion summary and returns `RGX-LOWER-E009`. Finite nullable
repeats remain supported because their state expansion is bounded.

`RGX-LOWER-E011` rejects an invalid or overflowing capture index. State,
transition, class, capture-slot, repetition, memory, and work ceilings remain
the R3.3.1 `RGX-IR-*` errors and retain actual/limit values where available.
Every error returns no executable `Program`.

The compiler is synchronous and owns no task, obligation, permit, socket, file,
lock, or background work. Cancellation, timeout, race, shutdown, cleanup, and
region-quiescence scenarios do not apply to this pure bounded transformation.

## Independent evidence

The focused contract includes:

- structural goldens for zero, one, many, bounded, unbounded, nested, greedy,
  and lazy repeats;
- numbered capture slot and zero-width source-span checks;
- a prioritized IR interpreter that records `Save` slots;
- capture-result comparison against anchored `regex` 1.13.1 fixtures;
- exhaustive small languages over `a`, `b`, and `A` through length four;
- 256 generated atom, quantifier, flag, and haystack cases;
- explicit nullable-loop, capture-erasure, repetition-expansion, state, and
  capture-slot failures.

Run focused unit tests remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path src/observability/regex_lowering.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics --lib \
  observability::regex_lowering::tests -- --nocapture
```

Run the predecessor and successor contracts together remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path artifacts/regex_ir_lowering_contract_v1.json \
  --overlay-path artifacts/regex_priority_capture_lowering_contract_v1.json \
  --overlay-path docs/regex_ir_lowering_contract.md \
  --overlay-path docs/regex_priority_capture_lowering_contract.md \
  --overlay-path src/observability/regex_lowering.rs \
  --overlay-path tests/regex_ir_lowering_contract.rs \
  --overlay-path tests/regex_priority_capture_lowering_contract.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  --test regex_ir_lowering_contract \
  --test regex_priority_capture_lowering_contract -- --nocapture
```

Run focused Clippy remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path artifacts/regex_ir_lowering_contract_v1.json \
  --overlay-path artifacts/regex_priority_capture_lowering_contract_v1.json \
  --overlay-path docs/regex_ir_lowering_contract.md \
  --overlay-path docs/regex_priority_capture_lowering_contract.md \
  --overlay-path src/observability/regex_lowering.rs \
  --overlay-path tests/regex_ir_lowering_contract.rs \
  --overlay-path tests/regex_priority_capture_lowering_contract.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-C debuginfo=0' \
  cargo clippy -p asupersync --features metrics \
  --test regex_ir_lowering_contract \
  --test regex_priority_capture_lowering_contract -- -D warnings
```

No local Cargo fallback is approved.

## Predecessor receipt handoff

The R3.3.2 receipt retains its original source hash and its original structural
scope as historical evidence. Its successor-handoff row names this contract
and explains that the live lowerer source is intentionally mutable across
compiler stages. Frozen R3.2 semantic inputs and the R3.3.1 IR source continue
to be checked live. The R3.3.3 receipt is the live source authority after this
extension.

The admitted remote receipts are source check job `29947326818681042`,
170/170 predecessor-plus-successor contract job `29947326818681058`, focused
Clippy job `29947326818681059`, and focused unit job `29947326818681060`
(8/8). All four exited zero. These receipts prove only the scoped lowering and
contract surfaces described here.

## No-claim boundary

This contract proves only bounded quantifier expansion, greedy/lazy `Split`
ordering, capture slot numbering and source spans, scoped-flag preservation,
typed nullable-loop/capture-erasure failures, deterministic resource
accounting, and agreement of the named independent model fixtures. It proves
no matcher or VM execution correctness and no production wiring or dependency removal.
It also proves no persisted or deserializable IR format, public API, performance
improvement, broad workspace health, release readiness, live RCH fleet availability,
or local Cargo fallback approval.

<!-- END REGEX PRIORITY CAPTURE LOWERING CONTRACT -->
