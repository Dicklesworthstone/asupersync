# Regex Thompson IR lowering contract

<!-- BEGIN REGEX IR LOWERING CONTRACT -->

This is the operator-readable companion to
`artifacts/regex_ir_lowering_contract_v1.json` for
`asupersync-5z2scg.8.3.3.2` and `CAP-REGEX-PRIVACY`.

R3.2.4 remains the semantic authority with disposition
`KEEP_INCUMBENT_DEFER`. R3.3.1 remains the immutable representation authority
for `ASUP-REGEX-THOMPSON-IR-V1`. This bead adds the private checked compiler
stage `ASUP-REGEX-THOMPSON-LOWERING-V1`; it does not alter either frozen
authority.

## Lowering boundary

The lowerer runs the pinned R3.2 character, simple-fold, and boundary analysis
before it emits any state. It consumes canonical Unicode/UTF-8-safe byte
classes and resolved boundary kinds by exact source span. Case-insensitive
non-ASCII byte literals that R3.2 accepted as exact UTF-8 sequences become
chains of singleton byte `Consume` states.

AST nodes are already stored in child-before-parent order. The lowerer walks
that order iteratively:

- empty expressions emit a pending `Jump`;
- literals, dot, escapes, and complete bracket classes emit `Consume`;
- input, line, and word boundaries emit `Assert`;
- concatenation patches one fragment's exits to the next entry;
- alternation builds right-associated `Split` states so `preferred` preserves
  source order and `fallback` retains the remaining order;
- noncapturing groups and flag wrappers are compile-time-transparent.

Class-internal AST nodes contribute only through the canonical outer `Class`
result and never emit unreachable states.

The partial graph uses private optional targets. After the root is complete,
all exits are patched to one `Accept`, every optional target is converted to a
concrete instruction, and `Program::checked` recomputes resources and validates
the whole graph. The API returns either that checked `Program` or an error;
partial executable output never escapes.

## Fail-closed errors and budgets

R3.2 analysis and R3.3.1 validator errors retain their stable codes. Lowering
shape failures use `RGX-LOWER-E001` through `RGX-LOWER-E008` and always carry a
source span. Duplicate or unresolved patches and missing semantic rows fail
closed.

Capture and repetition are deliberately distinct errors:

- `RGX-LOWER-E007` — capture lowering belongs to R3.3.3;
- `RGX-LOWER-E008` — repetition/greediness lowering belongs to R3.3.3.

State, class, per-class range, total-range, transition, memory, and work
ceilings are enforced before a `Program` can return. Invalid compile limits
remain `RGX-IR-E001`. Budget errors retain actual/limit values where available.

The compiler is synchronous and owns no task, obligation, permit, socket, file,
lock, or background work. Cancellation, shutdown, and region-quiescence
scenarios do not apply to this pure bounded transformation.

## Evidence and replay

The contract retains deterministic fingerprints for empty, concatenated,
ordered-alternation, fold/exact-byte/boundary, and class/alternation fixtures.
An independent small IR interpreter exhaustively checks bounded haystacks and
256 generated cases against the retained incumbent. Golden checks cover empty
branches and exact preferred/fallback source order. A 250-level noncapturing
fixture proves the lowering walk itself is iterative.

Run focused unit tests remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics --lib \
  observability::regex_lowering::tests -- --nocapture
```

Run the artifact, golden, model, and property contract remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  --test regex_ir_lowering_contract -- --nocapture
```

Run focused Clippy remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec \
  --base HEAD --clean-overlay \
  --overlay-path artifacts/regex_ir_lowering_contract_v1.json \
  --overlay-path docs/regex_ir_lowering_contract.md \
  --overlay-path src/observability/mod.rs \
  --overlay-path src/observability/regex_lowering.rs \
  --overlay-path tests/regex_ir_lowering_contract.rs -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-C debuginfo=0' \
  cargo clippy -p asupersync --features metrics \
  --test regex_ir_lowering_contract -- -D warnings
```

No local Cargo fallback is approved.

## Successor handoff

This receipt retains the original R3.3.2 source hash and deferred-node rows as
historical completion evidence. R3.3.3 intentionally extends the same private
lowerer source under
`artifacts/regex_priority_capture_lowering_contract_v1.json`; that successor
owns the live source pin after the extension. The frozen R3.2 semantic terminal
and R3.3.1 IR source remain live-checked here. This handoff does not rewrite or
broaden the original R3.3.2 claim.

## No-claim boundary

This contract proves only private structural lowering for the named R3.3.2
nodes, exact R3.2 input consumption, ordered patching, deterministic resource
shapes, typed failure, and checked-program construction. It proves no capture
or repetition lowering, matcher/VM execution, persisted or deserializable IR
format, public API, production wiring, dependency removal, owned Unicode
tables, performance improvement, broad workspace health, or release readiness.

<!-- END REGEX IR LOWERING CONTRACT -->
