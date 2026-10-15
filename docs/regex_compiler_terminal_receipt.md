# Regex compiler terminal receipt

<!-- BEGIN REGEX COMPILER TERMINAL RECEIPT -->

This is the sole R3.3 compiler terminal for
`asupersync-5z2scg.8.3.3.4`, `CAP-REGEX-PRIVACY`, and
`ASUP-REGEX-COMPILER-TERMINAL-V1`. It joins the frozen R3.2 semantic terminal,
R3.3.1 checked IR, R3.3.2 structural lowering, and R3.3.3
priority/capture/repetition lowering.

The terminal disposition is `KEEP_INCUMBENT_DEFER`. It authorizes downstream
VM experimentation against checked IR. It does not authorize matching,
production cutover, or removal of `regex` or `regex-syntax`.

## Exact compiler row join

The machine receipt accounts for all 20 `AstNodeKind` variants. `Flags` has
separate scoped and directive rows, and `ClassSet` has separate intersection,
difference, and symmetric-difference rows, for 23 exact rows. Each fixture is
parsed, its expected node/operator is observed, the complete pattern is
lowered, and the returned program is validated again under the recorded
limits.

All six quantifier families and greedy/lazy priority are explicit. Nullable
unbounded repetition remains a typed `RGX-LOWER-E009` `KEEP_DEFER` row.
Zero-count capture erasure remains typed `RGX-LOWER-E010` `KEEP_DEFER`. These
are intentional fail-closed compiler outcomes, not silent omissions.

## Validator and resource evidence

The contract triggers every `RGX-IR-E001` through `RGX-IR-E028` validator
class, including checked arithmetic overflow, invalid schema/entry/accept,
nonterminal and extra accepts, invalid targets/classes/capture slots/spans,
noncanonical or unreferenced classes/slots, unreachable accept/state,
collapsed ordered-split reachability, resource-accounting drift, and every
state/transition/class/range/capture/repetition/memory/work ceiling.

Every successful lower returns a `Program` that already passed
`Program::checked`; the terminal independently calls `Program::validate`
again. Every failure returns no partial `Program`.

## Independent language and priority evidence

The test-owned `bounded_literal_language_enumerator_v1` expands a small
literal/empty/concat/alternation/repetition algebra without using either regex
package. Fourteen patterns are compared over every `a`/`b` haystack through
length five: 882 exact language decisions.

An independent prioritized IR interpreter handles `Jump`, ordered `Split`,
`Consume`, `Assert`, and `Save`. Seven greedy/lazy/alternation/capture goldens
and 512 generated cases compare match and capture spans with the quarantined
incumbent `regex@1.13.1`. Oracle evidence expires at
`2026-10-23T00:00:00Z`, or earlier on any listed dependency, semantic,
candidate-source, or minimized-case drift.

## Bounded fuzz and minimized cases

The compiler fuzz lane deterministically generates 1,024 UTF-8 patterns of at
most 48 scalars from literal, Unicode, escape, class, group, flag, alternation,
and repetition tokens. Compilation runs behind `catch_unwind` with small
state, repetition, memory, and work ceilings; successful programs validate
again and errors expose no program.

The malformed-IR lane performs 1,024 deterministic mutations across schema,
entry, accept, targets, classes, capture slots, spans, resources, and ordered
split reachability. Validation must return a typed error without panic.

The retained minimized cases are:

- `(?:a?)*` -> `RGX-LOWER-E009`, nullable unbounded loop;
- `(a){0}` -> `RGX-LOWER-E010`, missing unset-capture representation;
- `\p{Age:16.0}` -> inherited `RGX-LEX-E004` semantic-terminal
  `KEEP_DEFER`, with the canonical alias retained upstream.

Compilation is a pure synchronous bounded transformation. It owns no task,
obligation, permit, socket, file, lock, background work, cancellation
protocol, shutdown protocol, or region-quiescence lifecycle.

## Replay

Run the terminal contract remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path artifacts/regex_compiler_terminal_receipt_v1.json \
  --overlay-path docs/regex_compiler_terminal_receipt.md \
  --overlay-path tests/regex_compiler_terminal_receipt_contract.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  --test regex_compiler_terminal_receipt_contract -- --nocapture
```

Run focused Clippy remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path artifacts/regex_compiler_terminal_receipt_v1.json \
  --overlay-path docs/regex_compiler_terminal_receipt.md \
  --overlay-path tests/regex_compiler_terminal_receipt_contract.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-C debuginfo=0' \
  cargo clippy -p asupersync --features metrics \
  --test regex_compiler_terminal_receipt_contract -- -D warnings
```

No local Cargo fallback is approved.

## No-claim boundary

This terminal proves only the named compiler, validator, bounded reference,
property, fuzz, source-pin, and fail-closed decision surfaces. It records no
matcher or VM execution correctness and no production wiring or dependency
removal. It also proves no persisted or deserializable IR format, public API or
accepted-syntax expansion, owned Unicode tables, binary-size result,
cross-target execution, performance improvement, broad workspace health,
release readiness, live RCH fleet availability, or local Cargo fallback
approval.

- no matcher or VM execution correctness
- no production wiring or dependency removal

<!-- END REGEX COMPILER TERMINAL RECEIPT -->
