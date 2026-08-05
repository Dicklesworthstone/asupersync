# Private regex compile API map

<!-- BEGIN PRIVATE REGEX COMPILE API MAP -->

This is the operator companion to
`artifacts/regex_private_compile_api_map_v1.json` for
`asupersync-5z2scg.8.3.5.1` and `CAP-REGEX-PRIVACY`.

## Result

The R3.5.1 boundary is now statically mapped, but it is not implemented or
complete. The exact disposition is
`KEEP_INCUMBENT_DEFER_NO_PRIVATE_COMPILE_FACADE`.

The candidate already has five checked private stages under the `metrics`
feature:

1. syntax lexing and parsing;
2. character semantics;
3. folding and boundary analysis;
4. Thompson lowering; and
5. checked IR validation.

Those stages remain `pub(crate)` and are not one compile API. There is no
aggregate private compile error type. The current direct path is
`regex_lowering::lower`, which returns a validated `Program` or a stage-level
`LowerError`; callers can independently call `Program::validate`.

No Rust source changed in this slice. In particular, this map does not create a
facade, change accepted syntax, wire a matcher, or expose anything publicly.

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
| syntax terminal | 31 | 30 | 1 |
| semantic terminal | 20 | 19 | 1 |
| compiler AST | 23 | 23 | 0 |
| compiler quantifiers | 10 | 8 | 2 |
| IR validator diagnostics | 28 | 28 typed failures | 0 |

The exact row identifiers live in the machine artifact. The five explicit
retained rows are:

| Row | Surface | Current outcome |
| --- | --- | --- |
| `RGX-SYN-011` | extended-mode whitespace and comments | `KEEP_DEFER` |
| `RGX-GAP-DUPLICATE-CAPTURE-NAME` | duplicate named captures | `KEEP_DEFER` |
| `RGX-COMP-Q-009` | nullable unbounded repetition | `RGX-LOWER-E009` |
| `RGX-COMP-Q-010` | capture erased by zero repetition | `RGX-LOWER-E010` |
| `RGX-R324-U001` | dotted Unicode Age value | `RGX-LEX-E004` |

These rows are explicit and fail closed. The inherited compiler and semantic
rows are typed; duplicate capture names still lack the required typed
rejection. None is silently accepted as parity, and the joined families have
zero unknown rows.

## R3.5-owned syntax cases

The machine map separates current behavior from the required R3.5.1 behavior.
It includes positive, boundary, and malformed rows for both owned gaps.

Extended-mode coverage includes:

- a pattern with no whitespace to elide;
- escaped whitespace, which remains a literal;
- ordinary whitespace and line comments;
- whitespace inside character classes;
- whitespace around counted repetitions, hex escapes, properties, and named
  group prefixes; and
- an unclosed scoped flag group with its typed category.

Duplicate-name coverage includes distinct names, same-style duplicates,
cross-style duplicates, and a malformed empty name. The duplicate rows remain
`KEEP_DEFER`; a future implementation must allocate a stable error code rather
than borrowing incumbent wording or rendering the source pattern.

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

The existing stage errors are `LexError`, `ParseError`, `SyntaxError`,
`SemanticError`, `FoldBoundaryError`, `LowerError`, and `CompileError`.
Their stable output is limited to codes, categories, spans, numeric limits, and
numeric IR indices where applicable.

The following must never be rendered by `Display` or `Debug`:

- raw pattern text or fragments;
- retained-backend error text;
- haystack text; or
- captured text.

There is not yet one aggregate private compile error. Any future facade must
preserve the stage code, span, and numeric detail without retaining or
rendering source text.

## Implementation gate

Before a Rust implementation can be committed for R3.5.1, it must:

1. implement grammar-aware extended-mode elision;
2. reject duplicate names with a stable typed code;
3. introduce one private compile facade and aggregate error type;
4. replay every row identifier named by the map; and
5. pass the focused compiler proof against the exact pinned source.

This static slice intentionally does not satisfy that gate. It records what the
gate is so later source work cannot narrow the accepted language, omit an
inherited limit, or mistake a terminal `KEEP_DEFER` row for parity.

## Static validation boundary

Validation for this slice is limited to JSON parsing, source and predecessor
hash/line-count reconciliation, exact row-count and identifier reconciliation,
and `git diff --check`.

No Cargo, RCH, compiler, test, lint, formatter, runtime, benchmark, service, or
remote proof lane is represented by this artifact.

## No-claim boundary

This is partial R3.5.1 progress, not completion. It makes no claim of a compiled
private facade, accepted-syntax expansion, duplicate-name enforcement, public
API or `PrivacyConfig` integration, production wiring, dependency removal,
performance, broad workspace health, or release readiness. The incumbent stays
in place.

<!-- END PRIVATE REGEX COMPILE API MAP -->
