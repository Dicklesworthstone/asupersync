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

## R3.5.4 compatibility extension

The `ASUP-REGEX-PRIVATE-API-COMPATIBILITY-V1` extension in the existing
machine map preserves the historical R3.5.1 receipt above and pins the current
R3.5.4 implementation at revision
`da992970cbb0590014a36236682c138cd83b41a4`. Its decision is
`KEEP_INCUMBENT`: the private candidate now has an executable configuration
and reuse boundary, but it does not replace, wrap, re-export, or alter the
public `PrivacyConfig` contract.

The extension maps every required family with an explicit `SAME` or `KEEP`
disposition and has zero `UNKNOWN` rows:

| Family | Disposition | Exact boundary |
| --- | --- | --- |
| compile and validation | `SAME` | private accepted corpus and typed rejection; public `regex::Error` remains `KEEP` |
| match, find, captures, iteration | `SAME` | private immutable compiled value under explicit aggregate limits |
| replacement | `SAME` | compatible total syntax; strict diagnostics remain a separately named private opt-in |
| diagnostics | `KEEP` | private stable secret-safe codes do not replace the public error type or wording |
| limits | `KEEP` | all candidate limits are explicit and round-tripped, but no public limit DTO is added |
| configuration | `KEEP` | versioned private JSON does not change public fields, builders, or direct mutation |

The public `KEEP` rows are deliberately granular. They retain the nested
`observability::otel::PrivacyConfig` path, `SpanConfig` alias, exhaustively
constructible mutable fields, direct `pii_patterns` mutation and recompilation,
the fallible and panicking builders, public `Clone`/`Debug`, the `metrics`
feature gate, byte-regex workflows, built-in detector order/tokens/Luhn policy,
and the production redaction path. They also retain the inherited nullable-loop,
zero-count-capture, and dotted-Age gaps. The candidate remains inaccessible to
external crates.

### Configuration and atomic loading

`PrivatePatternConfig` serializes schema version 1 plus the pattern and every
compile, VM, capture, iteration, replacement, and document limit. The compact
JSON encoding is deterministic. Unknown fields, missing fields, unsupported
schema versions, invalid execution limits, malformed JSON, and invalid patterns
all fail before a `LoadedPrivatePattern` is returned. A failed load cannot
modify an already loaded value.

The default document ceiling is 8,388,608 bytes, covering worst-case JSON
escaping for every pattern admitted by the default 1 MiB lexer budget plus the
numeric recipe. The serializer never returns a document above its selected
ceiling. Serialization is structural rather than admission: callers must still
use `load` or `load_json` to validate schema, limits, and pattern syntax.

Pattern text exists only in the caller-owned explicit recipe and serialized
document. The loaded value drops it after compilation; its `Debug`, all config
errors, and the private compiler error chain omit it. The loaded value is
immutable and `Send + Sync`; the focused test forces eight workers through one
shared start gate and exercises repeated matching and replacement.

The JSON integer representation uses Rust `usize` fields. R3.5.4 proves
same-target round trips only. Values accepted on a 64-bit target but too large
for `usize` on wasm32 are an explicit target-local `KEEP` / no-claim boundary,
not portable configuration evidence.

### Downstream executable evidence

The existing real fixture
`tests/fixtures/downstream-consumer-proof/src/bin/metrics_consumer.rs` compiles
and runs against the path dependency under `metrics-profile`. It proves the
incumbent public path still supports valid and invalid fallible construction,
direct field mutation, repeated redaction, and concurrent shared reuse. It does
not import the private candidate or claim a compatibility shim.

The exact R3.5.4 source passed these forced-remote lanes with no local fallback:

- private regex VM/config: 30 of 30 tests passed on `ovh-a`;
- downstream metrics consumer: process exit 0 on `ovh-a`; and
- metrics library Clippy with `-D warnings`: process exit 0 on `ovh-a`; and
- regex privacy capability inventory contract: 12 of 12 tests passed on
  `vmi1227854`.

This extension is sufficient input for the R3.5.5 terminal receipt. It is not
authorization for public integration or dependency removal.

## R3.5.5 terminal receipt

<!-- BEGIN R3.5.5 PRIVATE API TERMINAL RECEIPT -->

`ASUP-REGEX-R3-5-PRIVATE-API-TERMINAL-V1` records
`KEEP_INCUMBENT_DEFER`. It joins all four R3.5 implementation children without
turning private candidate evidence into public cutover authority. The terminal
binding has 29 exact compatibility rows: 7 `SAME`, 22 `KEEP`, and zero
`UNKNOWN`. The inherited compiler join remains 112 rows with three explicit
`KEEP` gaps, and the 14 R3.5.1-owned syntax cases remain 12 `SAME` plus two
typed `SAME_CATEGORY` matches.

The final review also repaired `RGX-R1-GAP-01` on source revision
`903de8267e50fc5ba5652766157bd2083aee6e4c`. Direct mutation of the legacy
public `pii_patterns` field is still supported, but an invalid entry now causes
whole-value redaction instead of being silently ignored. No public item,
signature, field, feature gate, or construction pattern changed.

Seven routed critical/high findings remain visible and therefore keep the
incumbent decision conservative:

- `RGX-R1-GAP-02`, `RGX-R1-GAP-03`, and `RGX-R1-GAP-04`;
- `RGX-R1-GAP-05`, `RGX-R1-GAP-06`, and `RGX-R1-GAP-09`; and
- `RGX-R1-GAP-11`, whose owner `asupersync-d24mms.11` remains in progress.

Historical evidence is not rewritten. Some R3.5.1 revision/hash pairs describe
current refreshed receipt bytes rather than archival bytes at the named old
revision, and several R3.5.2-R3.5.4 runs did not retain a complete
worker/job/command/timestamp tuple. Those limitations are explicit `KEEP`
evidence debt. The terminal receipt supplies stable case-to-selector bindings
and one fresh source replay lane at the committed evidence-base revision; it
does not manufacture missing historical metadata.

The embedded public-contract replay is the exact pre-final candidate run. The
finalized overlay is deliberately validated after the last receipt edit and
its immutable RCH receipt is retained in the Bead closure comment and commit
handoff, rather than inserted here and creating a self-referential rerun loop.

R3.7.1 independent verification may proceed from this receipt. The overall
R3.7 decision is not ready: R3.6 cache/resource/performance policy and R3.7
independent security/corpus work remain open. In particular, this receipt does not authorize a public re-export. It also does not authorize `PrivacyConfig`
integration, compatibility
shim, production wiring, dependency removal, performance claim, broad workspace
health claim, release-readiness claim, or local Cargo fallback.

<!-- END R3.5.5 PRIVATE API TERMINAL RECEIPT -->

## R3.7.1 full-surface corpus join

<!-- BEGIN R3.7.1 FULL-SURFACE CORPUS JOIN -->

`ASUP-REGEX-R3-7-1-FULL-SURFACE-CORPUS-V1` is the executable join over the
already-shipped syntax, Unicode/byte, compiler/IR, VM, replacement,
configuration, privacy, cache, concurrency, and cancellation corpora. Its
state is `VERIFICATION_READY_KEEP_INCUMBENT_DEFER`: it makes the evidence
replayable and fail-closed, but it does not turn coverage into cutover
authority.

The join binds all 29 R3.5.4 capability rows exactly once, preserving the
existing 7 `SAME` / 22 `KEEP` partition. Twelve surface rows each require one
positive / boundary / malformed triad, for 36 deterministic coverage cases.
Every case names its producer, source path, executable selector, and normalized
expectation. The incumbent is never the sole normative producer: normative
inputs come from published syntax and UCD data, upstream testdata, independent
hand-authored vectors, bounded executable models, deterministic generators,
or the frozen public inventory. `regex` 1.13.1 remains only a quarantined
differential oracle and expires fail-closed to `KEEP_INCUMBENT_DEFER` on
2026-10-23 unless deliberately reviewed.

The live diagnostic census contains 122 live stable error codes across lexer,
parser, semantic, fold/boundary, IR, lowering, configuration, replacement,
cache, and VM execution families. The contract derives those literals from the
current source and requires each family to retain a positive / boundary /
malformed evidence triad. Historical lowering identifiers `RGX-LOWER-E007`
and `RGX-LOWER-E008` are predecessor-only; the live enum intentionally uses
`E009` through `E011` for the remaining rows.

Freshness is explicit. R3.5.4 source pins and R3.5.5 predecessor pins remain
historical snapshots at their named revisions. This join is their live
successor: it verifies current hashes and line counts for all six owned regex
modules, eight producer artifacts, and nine executable corpus sources. It also
records the exact Cargo package checksums and upstream file hashes for the
bounded `regex` 1.13.1 official-source selection, plus UCD 16.0.0 provenance
and license boundaries. A changed live source, artifact, selector, package
resolution, producer, capability, coverage edge, or error code fails the
focused contract instead of silently inheriting stale evidence.

Replay remains remote-only. The machine join records the exact focused,
full-corpus, and source-unit Cargo commands. Terminal clean-overlay job
receipts for the finalized bytes belong in the Bead closure and commit handoff,
avoiding a self-referential edit-and-rerun loop. No local Cargo fallback is
authorized.

This join does not authorize a public re-export, `PrivacyConfig` integration,
production wiring, byte-regex parity, compatibility shim, dependency removal,
performance claim, R3.7.2 fuzz-campaign completion, R3.7.3 security/cross-target
completion, broad workspace-health claim, or release-readiness claim.

<!-- END R3.7.1 FULL-SURFACE CORPUS JOIN -->

## Static validation boundary

Validation includes JSON parsing, source and predecessor hash/line-count
reconciliation, exact row-count and identifier reconciliation, `git diff
--check`, and the focused remote compiler proof above. It is not a broad
workspace, benchmark, service, or release gate.

## No-claim boundary

The historical base completes the private R3.5.1 compile boundary. The R3.5.4
extension adds private match/find/capture/iteration/replacement configuration
and downstream public-compatibility evidence. Neither layer claims public API
or `PrivacyConfig` integration, a compatibility shim, production wiring,
dependency removal, portable oversized cross-target configuration, whole-
operation cancellation, performance, broad workspace health, or release
readiness. The incumbent stays in place.

<!-- END PRIVATE REGEX COMPILE API MAP -->
