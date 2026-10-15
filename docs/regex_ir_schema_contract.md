# Regex Thompson IR schema contract

<!-- BEGIN REGEX IR SCHEMA CONTRACT -->

This document is the operator-readable companion to
`artifacts/regex_ir_schema_contract_v1.json` for
`asupersync-5z2scg.8.3.3.1` and `CAP-REGEX-PRIVACY`.

R3.2.4 remains the semantic authority. Its terminal disposition is
`KEEP_INCUMBENT_DEFER`: compiler experimentation may continue only while the
pinned R3.2 syntax, Unicode/byte classes, simple folding, and boundary
semantics remain authoritative. This contract stages
`ASUP-REGEX-THOMPSON-IR-V1`; it does not authorize production wiring, matcher
execution, dependency removal, or owned Unicode tables.

## Representation

A program names an explicit entry and sole accept state. Every state carries a
source span and exactly one instruction:

- `Accept` terminates;
- `Jump` is one unconditional epsilon transition;
- `Split` is an ordered epsilon fork whose `preferred` target precedes
  `fallback`;
- `Consume` references one canonical Unicode-scalar or UTF-8-safe byte class;
- `Assert` evaluates one R3.2.3 zero-width boundary;
- `Save` records the current offset in one paired capture boundary slot.

All AST variants have a representation. Empty expressions become a jump or an
entry that is already the accept state. Literals, dot, escapes, POSIX/class-set
operations, and bracket classes consume canonical R3.2.2 classes.
Concatenation patches fragments in order; alternation uses ordered splits.
Captures add paired saves. Noncapturing groups and flag scopes are compile-time
structure. Repetitions use finite jump/split graphs and a checked emitted-copy
counter. R3.2.3 exact UTF-8 byte sequences lower to singleton byte-consume
chains only after the R3.2.2 UTF-8 scope validator accepts them. There is no
`UNKNOWN` representation row.

R3.3.2 owns structural lowering. R3.3.3 owns repetition, greediness, capture,
and scoped-flag lowering. R3.3.4 owns independent model/property/fuzz checks
and the compiler terminal receipt.

## Structural invariants

`Program::checked` computes resources, builds the complete value, and validates
it before returning. Validation is iterative and rejects:

- wrong schema/IR IDs, empty state sets, invalid entry/accept IDs, a nonterminal
  accept, or any additional accept;
- invalid targets, class IDs, capture slots, or structurally invalid spans;
- noncanonical class ranges, unused classes/slots, an unreachable accept, or
  any unreachable state;
- odd capture-slot counts, stale self-reported resources, checked-arithmetic
  overflow, and every configured resource ceiling.

Malformed internal input produces one of the unique `RGX-IR-E001` through
`RGX-IR-E028` typed errors. Diagnostics include only IDs, counts, and source
coordinates; they do not echo raw pattern text.

## Deterministic compiler budgets

Accounting uses fixed schema costs, never Rust `size_of`:

| Item | Accounted bytes |
| --- | ---: |
| Program | 64 |
| State | 48 |
| Class | 32 |
| Class range | 8 |
| Capture slot | 8 |

The memory formula is
`64 + states*48 + classes*32 + class_ranges*8 + capture_slots*8`.
The work formula is
`1 + states + transitions + classes + class_ranges + capture_slots + repetition_expansion`.
All operations are checked.

Default ceilings are 262,144 states, 524,288 transitions, 65,536 classes,
4,096 ranges per class, 1,048,576 total ranges, 4,096 capture slots,
1,048,576 emitted repetition copies, 10 MiB accounted memory, and 8,388,608
work units. A ceiling failure returns a typed error and no `Program`.

The validator is synchronous, finite, and allocation-bounded. It owns no
tasks, obligations, permits, sockets, files, locks, or background work, so
cancellation, shutdown, region-quiescence, and resource-leak scenarios do not
apply to this schema-only bead.

## Diagnostic-only versioning

`diagnostic_json` emits
`asupersync-regex-thompson-ir-diagnostic-v1`, every IR field, resources,
instructions, class ranges, and source coordinates. The capability registry
declares no persisted IR contract. Accordingly the implementation provides no
decoder, its policy is `diagnostic-only-no-deserialization-contract`, and the
JSON is neither executable input nor a cross-version compatibility promise.

## Validation

Run the private schema/unit tests remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics --lib \
  observability::regex_ir::tests -- --nocapture
```

Run the evidence and source-pin contract remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  --test regex_ir_schema_contract -- --nocapture
```

Run the metrics library Clippy lane remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-C debuginfo=0' \
  cargo clippy -p asupersync --features metrics \
  --test regex_ir_schema_contract -- -D warnings
```

No local Cargo fallback is approved.

## No-claim boundary

This contract proves only the private versioned schema, its deterministic
accounting, structural validator, diagnostic golden, source/evidence pins, and
representation inventory. It proves no AST lowering, matcher/VM behavior,
persistent IR format, public API, production wiring, dependency removal,
performance improvement, broad workspace health, or release readiness.

<!-- END REGEX IR SCHEMA CONTRACT -->
