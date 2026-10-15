# Regex syntax terminal receipt

<!-- BEGIN REGEX SYNTAX TERMINAL RECEIPT -->

This is the operator-readable companion to
`artifacts/regex_syntax_terminal_receipt_v1.json` for
`asupersync-5z2scg.8.3.1.4`, `CAP-REGEX-PRIVACY`, and
`ASUP-REGEX-SYNTAX-V1`.

## Decision

The terminal R3.1 disposition is `KEEP_INCUMBENT_DEFER`.

The bounded candidate lexer/parser now matches all 31 frozen R1 syntax rows,
including grammar-aware extended-mode whitespace/comment elision for
`RGX-SYN-011`. Duplicate capture names are rejected with the stable,
source-free `RGX-PARSE-E013` diagnostic. The terminal disposition remains
`KEEP_INCUMBENT_DEFER` because Unicode property and byte-mode validation are
still downstream cutover blockers; accepted-syntax completion alone does not
authorize incumbent replacement.

This is a successful fail-closed terminal receipt, not a failed implementation
disguised as parity. Missing rows, new divergences, changed source digests, or
expired oracle evidence all preserve `regex` and force a refreshed receipt.

## Authority and revisions

The receipt joins:

| Surface | Revision |
| --- | --- |
| R1 capability inventory | `8b399fa72` |
| grammar/version contract | `4074a2746` |
| bounded lexer | `582da577c` |
| iterative parser | `9056ef793` |
| terminal parity repairs | `69e796eeb727f9772bdadfe6869d9c3d14a10db3` |

The exact candidate source, grammar artifact, and R1 inventory are SHA-256
pinned in the machine receipt. The quarantined incumbent is `regex@1.13.1`;
`regex-syntax@0.8.11` is a structural reference. Error wording is not compared.
The oracle expires on `2026-10-23T00:00:00Z`, and expires earlier if dependency
resolution, language version, or any pinned source digest changes.

## Evidence and repairs

The source lane contains 36 focused syntax tests:

- all 31 R1 syntax rows and all 20 grammar goldens;
- exact category and byte-span parity for the eight rejected goldens;
- a 62-case quarantined-incumbent adversarial compile corpus;
- 16 retained lexer and 23 retained parser minimized regressions;
- four 256-case property lanes, totaling 1,024 generated cases;
- exact pattern, token, node, nesting, repetition-count, and repetition-expansion
  accounting checks;
- a redaction canary proving candidate diagnostics do not render pattern text.

The terminal probe found and repaired three candidate defects:

1. `a**`, `a++`, `a{1}+`, and `a+{2}` are nested repetition in the incumbent,
   not possessive syntax.
2. A repetition with no expression, including `(?i)*`, reports a zero-width
   operator-position span.
3. Empty operands around `&&`, `--`, and `~~` are valid empty-set expressions,
   including `[a&&]`, `[&&a]`, `[a--]`, and `[~~a]`.

Repetition remains arena-bounded: nested operators wrap node IDs and update a
checked finite/unbounded/overflow estimate; they never clone or expand the
subtree.

## Resolved gaps and retained blocker

| Blocker | Minimized evidence | Owner | Disposition |
| --- | --- | --- | --- |
| `RGX-GAP-X-WHITESPACE` | `(?x)a b`, `(?x)a{ 2 , 3 }`, `(?x)[ a-z ]`, spaced escapes/groups | `asupersync-5z2scg.8.3.5.1` | `SAME_R3_5_1` |
| `RGX-GAP-DUPLICATE-CAPTURE-NAME` | `(?P<name>a)\|(?P<name>b)` | `asupersync-5z2scg.8.3.5.1` | `SAME_R3_5_1` (`RGX-PARSE-E013`) |
| `RGX-GAP-UNICODE-PROPERTY-VALIDATION` | `\p{DefinitelyNotAProperty}`, `(?-u:\pL)`, `(?-u:\xFF)` | `asupersync-5z2scg.8.3.2.2` | `DEFER_KEEP_INCUMBENT` |

The first two rows are resolved by R3.5.1 and remain recorded so the minimized
corpus cannot silently regress. The Unicode/property row remains a fail-closed
cutover blocker owned downstream. Any future repair must update the minimized
corpus, row disposition, source digest, and terminal receipt together.

## Limits and privacy

The candidate enforces:

| Limit | Value | Result |
| --- | ---: | --- |
| pattern bytes | 1,048,576 | `RGX-DIAG-PATTERN-TOO-LARGE` |
| tokens, including end | 1,048,576 | `RGX-DIAG-TOKEN-LIMIT` |
| AST arena nodes | 1,048,576 | `RGX-DIAG-AST-LIMIT` |
| nesting | 250 | `RGX-DIAG-NEST-LIMIT` |
| repetition count | `u32::MAX` | `RGX-DIAG-INVALID-REPETITION` |

The first three are candidate-only policy and therefore remain cutover
blockers. Candidate errors expose only stable code/category and byte/scalar
spans. The retained `private-source-canary` never appears in rendered output.

The syntax layer is pure synchronous parsing. It creates no tasks, obligations,
permits, sockets, files, or external effects, so cancellation, shutdown, and
region-quiescence scenarios are not applicable to this receipt.

## Replay

Run the exact source evidence remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  regex_syntax::tests --lib -- --nocapture
```

Run the terminal packet contract remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  --test regex_syntax_terminal_receipt_contract -- --nocapture
```

No local Cargo fallback is approved.

## No-claim boundary

This receipt does not authorize removing `regex` or `regex-syntax`. It does not
prove Unicode/property/byte-mode parity, compiler or matcher correctness,
capture/replace behavior, cache or concurrency behavior, privacy integration,
performance improvement, no regression, broad workspace health, release
readiness, or the canonical dependency-sovereignty E2E. Those remain owned by
their downstream beads.

<!-- END REGEX SYNTAX TERMINAL RECEIPT -->
