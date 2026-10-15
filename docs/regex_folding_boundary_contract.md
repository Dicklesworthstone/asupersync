# Regex folding and boundary contract

<!-- BEGIN REGEX FOLDING BOUNDARY CONTRACT -->

This is the operator-readable companion to
`artifacts/regex_folding_boundary_contract_v1.json` for
`asupersync-5z2scg.8.3.2.3`, `CAP-REGEX-PRIVACY`, and
`ASUP-REGEX-FOLD-BOUNDARY-V1`.

## Decision

R3.2.3 is `STAGED_SIMPLE_FOLD_AND_BOUNDARY_SEMANTICS`.

The private `regex_boundaries` module consumes the frozen
`ASUP-REGEX-SYNTAX-V1` parser and the sealed
`ASUP-REGEX-CHAR-SEMANTICS-V1` layer. It adds bounded case-fold and zero-width
boundary semantics without modifying either predecessor source. The production
observability matcher remains on the incumbent `regex` stack.

The retained `regex-syntax@0.8.11` Unicode 16.0.0 tables remain the authority
for simple case folding and Unicode Perl-word membership. No table is copied,
generated, hand-curated, platform-derived, or locale-derived.

## Folding contract

The accepted fold is `UNICODE_SIMPLE_ONE_SCALAR`.

In Unicode mode, each case-insensitive scalar or class is closed under the
retained simple-fold relation and represented as sorted, non-overlapping,
non-adjacent scalar ranges. Examples include:

- Greek sigma equivalence across `σ`, `Σ`, and final sigma `ς`;
- ASCII `k` equivalence with `K` and Kelvin sign `K`;
- ordinary ASCII lower/upper pairs.

Full multi-scalar folds are not part of the incumbent language. In particular,
`ß` does not expand to the two-scalar sequence `ss`. Locale-sensitive mappings,
normalization, canonical-equivalence matching, and grapheme folding are also
absent. Combining sequences remain separate code points.

When `u` is disabled, case-insensitive folding applies only to ASCII letters.
ASCII outputs use the R3.2.2 `UTF8_SAFE_BYTE` alphabet. Non-ASCII raw literals
or byte escapes remain exact bytes and are admitted only when the enclosing
scope has already passed R3.2.2 whole-scope UTF-8 validation. Thus
`(?i-u:k)` never acquires Kelvin sign semantics.

Every case-insensitive character atom is accounted once. The analysis records
both the plain and folded output, making identity folds and actual expansions
distinguishable without compiling a matcher.

## Boundary contract

Boundary evaluation accepts only offsets from zero through haystack length
that are Rust `str` character boundaries. A mid-scalar or out-of-range offset
fails with `RGX-FB-EVAL-E001`.

Input boundaries match only offset zero or haystack length. LF line boundaries
match the input edges plus positions after or before `\n`.

CRLF-aware line boundaries treat a paired `\r\n` as one terminator:

- line end matches before `\r`, not between `\r` and `\n`;
- line start matches after `\n`, not between the pair;
- lone `\r` and lone `\n` still form line edges.

ASCII word membership is exactly `[_0-9A-Za-z]`. Unicode word membership comes
from the pinned Unicode Perl-word table: Alphabetic, Join_Control,
Decimal_Number, Mark, and Connector_Punctuation. A missing adjacent character
has nonword status. The layer defines positive, negative, directional, and
half-boundary truth tables for both alphabets.

`\<` and `\>` remain ASCII word start/end assertions regardless of `u`.
`\b`, `\B`, and the braced word variants select Unicode or ASCII membership
from the active `u` scope.

## Flag scoping

The semantic walk tracks `i`, `m`, `R`, `u`, and `x`.

Ordinary, named, and noncapturing groups inherit their parent state. Scoped
flag groups restore the parent state at close. An unscoped directive updates
only the current group.

Without `m`, `^` and `$` become absolute input boundaries. With `m`, they use
LF boundaries; with both `m` and `R`, they use CRLF-aware boundaries. Folding
and word membership follow the active `i` and `u` flags at each atom or
assertion.

## Limits and diagnostics

The predecessor syntax and character-semantic limits remain in force. This
layer adds:

| Limit | Value | Failure |
| --- | ---: | --- |
| case-insensitive atoms | 1,048,576 | `RGX-FB-E003` |
| ranges in one folded atom | 4,096 | `RGX-FB-E004` |
| aggregate folded ranges | 1,048,576 | `RGX-FB-E005` |
| boundary assertions | 1,048,576 | `RGX-FB-E006` |
| retained translator nesting | 250 | fail closed |

Allocation follows admission: the atom or assertion budget is checked before
growth. Aggregate range and represented-alternative accounting uses checked
arithmetic.

Analysis errors contain only a stable code/category and byte/scalar span.
Boundary-evaluation errors contain only their stable code. Neither path emits
the pattern, haystack, retained-backend wording, or locale data.

## Evidence

The source supplies thirteen deterministic unit/property lanes covering:

- ASCII, Greek sigma, Kelvin, sharp-s, combining-mark, and class folds;
- Unicode-disabled ASCII and exact non-ASCII behavior;
- input, LF, CRLF, Unicode-word, ASCII-word, directional, and half boundaries;
- empty input, lone terminators, CRLF pairing, scoped flags, invalid offsets,
  and every owned resource limit;
- 256 independent ASCII fold-model cases;
- 256 arbitrary UTF-8 determinism and panic-containment cases.

The focused integration contract additionally compares all 18 boundary
variants over an independent haystack corpus and selected simple-fold goldens
against the retained incumbent `regex` engine. This is an R3.2.3 semantic
golden, not the terminal cross-target conformance receipt.

Run the focused private-source contract remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  --test regex_folding_boundary_contract -- --nocapture
```

Run the warning-denied source check remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo check -p asupersync --features metrics --lib
```

Run the focused Clippy lane remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-C debuginfo=0' \
  cargo clippy -p asupersync --features metrics \
  --test regex_folding_boundary_contract -- -D warnings
```

The required broad frontier uses the exact suffix
`--all-targets --keep-going -- -D warnings`.

No local Cargo fallback is approved.

The terminal receipts for source digest
`406f280de9dcc99cedc47c5fcef4f32b6574f2d0d178d3061540c00b15128ab0`
are:

| Lane | Result | RCH receipt |
| --- | --- | --- |
| warning-denied library check | passed | `j-29947326818680927` on `hz1` |
| focused contract | 68 passed, 0 failed | `j-29947326818680928` on `hz2` |
| focused Clippy | passed | `j-29947326818680926` on `hz1` |
| broad all-target Clippy | blocked, no terminal success claimed | `j-29947326818680929` on `hz1`; gracefully cancelled after 261 seconds without progress while the heartbeat remained fresh |

The blocked broad lane does not weaken or expand the focused receipts and does
not establish broad workspace health.

## No-claim boundary

This contract does not authorize removing `regex` or `regex-syntax`, changing
the production matcher, or claiming compiler, matcher, capture, replacement,
privacy, or cache correctness. It does not prove performance improvement, no
regression, broad workspace health, or release readiness.

R3.2.4 retains sole authority for the terminal independent Unicode/byte,
cross-target, and compiled-size conformance receipt consumed by compiler work.

<!-- END REGEX FOLDING BOUNDARY CONTRACT -->
