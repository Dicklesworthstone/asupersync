# Private regex compile API map

<!-- BEGIN PRIVATE REGEX COMPILE API MAP -->

This is the operator companion to
`artifacts/regex_private_compile_api_map_v1.json` for
`asupersync-5z2scg.8.3.5.1` and `CAP-REGEX-PRIVACY`.

## Result

The R3.5.1 private compile boundary is implemented and source-pinned. The exact
disposition is `KEEP_INCUMBENT_DEFER_PRIVATE_COMPILE_FACADE_READY`: the private
facade is ready, while public wiring and incumbent replacement remain
explicitly unauthorized.

The candidate already has five checked private stages under the `metrics`
feature:

1. syntax lexing and parsing;
2. character semantics;
3. folding and boundary analysis;
4. Thompson lowering; and
5. checked IR validation.

Those stages remain `pub(crate)`. `regex_lowering::compile_private` now joins
them behind `PrivateCompileLimits`, returns a fully revalidated `Program`, and
reports a source-text-free `PrivateCompileError` with a stable stage, code,
span, and bounded numeric detail. The established `regex_lowering::lower`
entrypoint remains intact.

The implementation also completes grammar-aware extended-mode elision and
rejects duplicate capture names with `RGX-PARSE-E013` /
`RGX-DIAG-DUPLICATE-CAPTURE-NAME`. It does not wire a matcher or expose the
candidate publicly.

## Pinned authority

The machine map pins the exact current source revisions, SHA-256 digests, and
line counts for:

- `src/observability/regex_syntax.rs`;
- `src/observability/regex_semantics.rs`;
- `src/observability/regex_boundaries.rs`;
- `src/observability/regex_ir.rs`; and
- `src/observability/regex_lowering.rs`.

It also pins the syntax, semantic, compiler, and VM terminal receipts. The VM
receipt is boundary evidence only: R3.5.1 authorizes compile and validation
mapping, not matching.

Any source or predecessor pin drift requires a fresh map. Drift never upgrades
the disposition; it retains `regex` and `regex-syntax`.

## Complete inherited row join

The map names every inherited machine row rather than inferring coverage from
an aggregate status:

| Family | Rows | Accepted/checked | `KEEP_DEFER` |
| --- | ---: | ---: | ---: |
| syntax terminal | 31 | 31 | 0 |
| semantic terminal | 20 | 19 | 1 |
| compiler AST | 23 | 23 | 0 |
| compiler quantifiers | 10 | 8 | 2 |
| IR validator diagnostics | 28 | 28 typed failures | 0 |

The exact row identifiers live in the machine artifact. The three explicit
retained rows are:

| Row | Surface | Current outcome |
| --- | --- | --- |
| `RGX-COMP-Q-009` | nullable unbounded repetition | `RGX-LOWER-E009` |
| `RGX-COMP-Q-010` | capture erased by zero repetition | `RGX-LOWER-E010` |
| `RGX-R324-U001` | dotted Unicode Age value | `RGX-LEX-E004` |

These rows are explicit and fail closed. Extended mode and duplicate capture
names are now exact, typed R3.5.1 rows rather than retained gaps. None of the
remaining rows is silently accepted as parity, and the joined families have
zero unknown rows.

## R3.5-owned syntax cases

The machine map separates current behavior from the required R3.5.1 behavior.
It includes positive, boundary, and malformed rows for both owned gaps.

Extended-mode proof includes:

- a pattern with no whitespace to elide;
- escaped whitespace, which remains a literal;
- ordinary whitespace and line comments;
- whitespace inside character classes;
- whitespace around counted repetitions, hex escapes, properties, and named
  group prefixes; and
- an unclosed scoped flag group with its typed category.

Duplicate-name coverage includes distinct names, same-style duplicates,
cross-style duplicates, and a malformed empty name. Duplicate names now return
the stable `RGX-PARSE-E013` code and
`RGX-DIAG-DUPLICATE-CAPTURE-NAME` category without borrowing incumbent wording
or rendering the source pattern.

## Aggregate limits

The machine artifact joins every numeric limit owned by syntax, semantic
analysis, lowering, and checked IR:

| Stage | Limit family |
| --- | --- |
| syntax/parser | pattern bytes, tokens, AST nodes, nesting, repetition count |
| character semantics | semantic atoms, ranges per class, total ranges, backend nesting |
| fold/boundary | fold atoms, ranges per fold, total fold ranges, boundary assertions |
| lowering/IR | states, transitions, classes, class ranges, capture slots, repetition expansion, accounted memory, work |

Each row records its exact value, unit, owner stage, and stable failure code.
Lowering introduces no untracked numeric ceiling: it preflights and forwards
the checked IR budgets, then adds the explicit nullable-loop and zero-count
capture dispositions.

## Diagnostic boundary

The stage errors are `LexError`, `ParseError`, `SyntaxError`, `SemanticError`,
`FoldBoundaryError`, `LowerError`, and `CompileError`; the facade owns the
aggregate `PrivateCompileError`. Stable output is limited to codes, stages,
categories, spans, numeric limits, and numeric IR indices where applicable.

The following must never be rendered by `Display` or `Debug`:

- raw pattern text or fragments;
- retained-backend error text;
- haystack text; or
- captured text.

`PrivateCompileError` preserves the stage code, span, and numeric detail
without retaining or rendering source text. Its `Display` and `Debug` forms
were exercised with redaction canaries in the focused source lane.

## Implementation gate

The R3.5.1 implementation gate required:

1. implement grammar-aware extended-mode elision;
2. reject duplicate names with a stable typed code;
3. introduce one private compile facade and aggregate error type;
4. replay every row identifier named by the map; and
5. pass the focused compiler proof against the exact pinned source.

The exact source at revision `432be7270481c5439db00f79910465a269512266`
satisfies that gate. RCH job `29975513699188766` ran the focused private regex
source lane remotely on `vmi1227854` and exited 0. Public wiring still requires
the separately owned R3.5.2 match facade and downstream compile/configuration
evidence.

## Static validation boundary

Validation includes JSON parsing, source and predecessor hash/line-count
reconciliation, exact row-count and identifier reconciliation, `git diff
--check`, and the focused remote compiler proof above. It is not a broad
workspace, benchmark, service, or release gate.

## No-claim boundary

This completes the private R3.5.1 compile boundary only. It makes no claim of
an R3.5.2 private match facade, downstream compile/configuration evidence,
public API or `PrivacyConfig` integration, production wiring, dependency
removal, performance, broad workspace health, or release readiness. The
incumbent stays in place.

<!-- END PRIVATE REGEX COMPILE API MAP -->
