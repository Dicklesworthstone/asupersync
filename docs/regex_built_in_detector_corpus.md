# Regex built-in detector corpus

<!-- BEGIN REGEX BUILT-IN DETECTOR CORPUS -->

Bead: `asupersync-5z2scg.8.2.1`
Capability: `CAP-REGEX-PRIVACY`
Artifact: `artifacts/regex_built_in_detector_corpus_v1.json`

This is the independent R2.1 baseline for the four automatic detectors in
`PrivacyConfig`. It freezes the current pattern identities, detector order,
latent match spans, card-candidate validation, whole-value output tokens, and
incumbent fallback rules before any specialized scanner exists.

The dependency decision remains `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`. R2.1
implements no scanner and authorizes no dispatch or cutover.

## Live pipeline

With the `metrics` feature enabled, `PrivacyConfig::redact_pii` follows this
order:

1. every user-supplied custom pattern;
2. built-in email;
3. built-in SSN;
4. built-in payment-card candidates, accepting only candidates that pass Luhn;
5. built-in phone;
6. otherwise preserve the input.

A match replaces the complete input value. The public API exposes neither the
matched substring nor its span. R2.1 records latent incumbent spans as future
scanner equivalence scaffolding; it does not widen the current public API.

| Order | Stable corpus identity | Exact incumbent language | Evaluation | Whole-value result |
| ---: | --- | --- | --- | --- |
| 1 | `RGX-BUILTIN-EMAIL` | `(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b` | existence | `[EMAIL_REDACTED]` |
| 2 | `RGX-BUILTIN-SSN` | `\b\d{3}-\d{2}-\d{4}\b` | existence | `[SSN_REDACTED]` |
| 3 | `RGX-BUILTIN-CARD` | `\b(?:\d[ -]?){13,19}\b` | non-overlapping candidates, then any Luhn-valid candidate | `[CARD_REDACTED]` |
| 4 | `RGX-BUILTIN-PHONE` | `(?x)\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b` | existence | `[PHONE_REDACTED]` |

These identities are corpus names only. At R2.1 capture time, production used
function-local pattern literals and `OnceLock`s. R2.2 now routes only the
hard-coded automatic email and SSN identities through bounded scanners, with
the frozen regexes retained as fail-closed fallbacks. Production still has no
general detector enum or R2.4 fast-path allowset.

## Span semantics and frozen edge behavior

Spans are half-open UTF-8 byte ranges. They are not character, scalar,
display-column, or grapheme indexes. Matching is leftmost-first and
non-overlapping. Unicode mode is active: `\b`, `\d`, `\s`, and email case
folding therefore have Unicode behavior even though most pattern literals look
ASCII-shaped.

The corpus deliberately retains several non-obvious compatibility facts:

- a Unicode word character adjacent to an outer boundary can suppress a
  match, while an adjacent emoji permits the match and shifts byte offsets;
- Unicode simple-fold members such as long s (`ſ`) and Kelvin sign (`K`) are
  accepted by the case-insensitive email character classes, and leading local
  punctuation can fall outside the latent email span;
- the SSN and phone patterns accept Unicode decimal digits, but require their
  literal ASCII punctuation where specified;
- the card pattern recognizes Unicode decimal-digit candidates while the
  incumbent Luhn join counts only digits accepted by `char::to_digit(10)`;
- the phone separator class accepts Unicode whitespace, including a
  non-breaking space;
- the phone match for `+1 (415) 555-2671` begins at the `1`, not the `+`, and
  a leading `(` can likewise fall outside the latent match;
- a card candidate may include a trailing space when the following word
  character supplies the final boundary, but excludes the same space at end
  of input;
- a contiguous overlength digit run produces no sliding-window candidate;
- card validation continues to later candidates and later detector classes
  when a candidate fails Luhn.

The `overlapping` coverage tag includes both selected leftmost/greedy parses
and syntactically shaped windows suppressed by an outer word boundary. The
recorded `expected_matches` remain the authority; the tag never implies that a
suppressed window is returned.

These are compatibility observations, not claims that every accepted or
rejected form is desirable.

## Independent corpus

The machine artifact contains 62 detector vectors:

- 15 email rows;
- 12 SSN rows;
- 17 card-candidate and Luhn rows;
- 18 phone rows.

Every detector covers positive, negative, empty, boundary, maximum,
Unicode-adjacent, separator, adjacent, overlapping, malformed,
false-positive-guard, and false-negative-guard classes. Each row carries a
pattern-safe case ID, stable capability IDs, and a provenance reference. All
values are synthetic.

Expected spans and outcomes were hand-authored from the detector languages,
Unicode boundary model, and Luhn rule. The incumbent is a post-authorship
differential oracle, not the generator or sole specification. The earlier R1
eleven-row corpus remains historical provenance and is expanded rather than
silently rewritten.

An eleven-row R1 crosswalk preserves every historical case ID and maps it to
either an exact-input row or a semantic-equivalent R2 outcome class. The
focused contract checks the crosswalk against the pinned R1 artifact.

For every detector vector, `expected_detector_accepts` composes with the
detector's frozen whole-value token: acceptance yields that token and rejection
preserves the input. The focused contract applies this rule through the public
pipeline so each vector has an exact redaction outcome without duplicating 62
derived strings in the artifact.

Nineteen pipeline vectors separately freeze automatic-detection disablement,
empty/no-match preservation, class tokens, whole-value replacement, detector
priority independent of textual position, invalid-card continuation into a
later card candidate or phone match, exact custom collisions for all four
built-ins, a nonmatching custom pattern continuing to automatic detection, and
custom matching while automatic detection is disabled.

## Exact dispatch identity and fallback

The future R2.4 allowset is closed over eight fields: origin, detector ID,
pattern, regex mode, match strategy, post-filter, output token, and replacement
scope. Equality of pattern text alone is insufficient.

In particular, a user custom pattern whose text is byte-for-byte equal to the
built-in email literal is still a custom pattern. It runs before automatic
detection and yields `[REDACTED]`, not `[EMAIL_REDACTED]`. Custom, drifted,
unrecognized, duplicate, or conflicting identities must stay on the complete
incumbent engine without publishing a partial scanner result.

Eight negative fixtures mutate each identity dimension and require that exact
fallback. R2.1 specifies this allowset but does not implement it.

## Post-capture source-pin refresh

`RGX-R2-SOURCE-PIN-REFRESH-2026-08-06` records a provenance-only refresh of
`artifacts/dependency_capability_baseline_v1.json`. Since the R2.1 corpus was
captured, that shared baseline gained 1,853 lines and lost none. The additions
are five independent Phase-2 static-audit objects: hash-map, host benchmark
metadata, terminal readiness, slab, and visibility macro.

The canonical `CAP-REGEX-PRIVACY` and `CAP-LAB-DETERMINISM` rows are unchanged.
Therefore the baseline authority revision remains
`7390d33f4ac297cd28138c8e1ece38f60b278660`, while the source pin tracks the
current complete file content. The refresh changes none of the 62 detector
vectors, 19 pipeline vectors, eight negative dispatch fixtures, dispatch
allowset, policy, authority decision, or production source.

This is `STATIC_SOURCE_PIN_MAINTENANCE`, not execution evidence. Its execution
state remains `NOT_RUN_BY_R2_1_STATIC_LANE`; it does not complete R2.1 or
authorize dependency exit or cutover.

## Downstream handoff

- R2.2 consumed the email and SSN spans and is implemented with focused remote
  proof in RCH job `j-29988810699833424`: three tests passed on `ovh-a` with
  `-D warnings`. The lane covers every 15-email and 12-SSN R2.1 vector, a
  generated Unicode/boundary differential matrix, bounded large input,
  checked input/work/output ceilings, incumbent fallback, and custom-pattern
  non-dispatch. Corpus/source-pin reconciliation passed 8/8 tests in remote job
  `j-29988810699833426`. These lanes do not prove a performance improvement or
  authorize regex removal.
- R2.3 consumed the 17 card-candidate spans and independent Luhn verdicts and
  is implemented in revision `702f1cc78`. Clean-overlay RCH job
  `j-29988810699833430` passed 4/4 focused tests on `ovh-a` with `-D warnings`:
  every frozen row, generated lengths 13 through 19 across accepted separator
  and Unicode/word-boundary forms, valid and invalid checksums, multiple
  candidates, exact whole-value output, bounded input/work/output refusal,
  incumbent fallback, and custom-pattern non-dispatch. Job
  `j-29988810699833429` exited zero but selected zero tests after its shared-path
  sync omitted the dirty source; it is explicitly discarded as evidence. This
  lane does not prove a performance improvement or authorize regex removal.
- R2.4 consumes phone spans and the closed dispatch identity.
- R2.5 may aggregate the work only after implementation, generated
  equivalence, resource evidence, and named-host measurements exist.

Any disagreement disables the affected future fast path and keeps the
incumbent. No custom language may be narrowed.

## Focused contract

The focused contract is
`tests/regex_built_in_detector_corpus_contract.rs`. It checks source pins,
schema/reference closure, complete coverage classes, exact live patterns and
order, UTF-8 spans, independent Luhn verdicts, public whole-value outputs,
custom-origin separation, negative dispatch fixtures, docs markers, and
fail-closed mutations.

The remote-required command for a later dynamic proof lane is:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path .gitignore \
  --overlay-path artifacts/regex_built_in_detector_corpus_v1.json \
  --overlay-path docs/regex_built_in_detector_corpus.md \
  --overlay-path tests/regex_built_in_detector_corpus_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_regex_built_in_detector_corpus" \
  cargo test -p asupersync --features metrics \
  --test regex_built_in_detector_corpus_contract -- --nocapture
```

R2.1's recorded execution state is `NOT_RUN_BY_R2_1_STATIC_LANE`.
No local Cargo fallback is approved.

## No-claim boundary

This corpus does not implement a scanner, prove performance or resource
bounds, authorize changing/removing `regex`, or authorize production cutover.
It does not establish exhaustive detection, eliminate false positives or false
negatives, prove protection for real personal data, or prove complete
multi-signal privacy wiring. It does not prove broad workspace health, release
readiness, live RCH availability, or local fallback approval. It does not
authorize tracker closure, dependency exit, file deletion, or cancellation of
peer work.

<!-- END REGEX BUILT-IN DETECTOR CORPUS -->
