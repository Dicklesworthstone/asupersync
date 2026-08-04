# Regex syntax grammar contract

<!-- BEGIN REGEX SYNTAX GRAMMAR CONTRACT -->

This is the operator-readable companion to
`artifacts/regex_syntax_grammar_contract_v1.json`. It freezes
`ASUP-REGEX-SYNTAX-V1` for `CAP-REGEX-PRIVACY` and bead
`asupersync-5z2scg.8.3.1.1`.

The contract is deliberately not a cutover. `DEP-ADR-012` remains authoritative:
`regex` stays `KEEP_INCUMBENT`, the candidate is
`SPECIFIED_NOT_IMPLEMENTED`, and cutover is not eligible. Any syntax row that
becomes `UNKNOWN`, or any construct accepted by the incumbent but unsupported
by a candidate, terminates in `KEEP_OR_DEFER`.

## Authority and provenance

The grammar is derived from the executable R1 inventory in
`artifacts/regex_privacy_capability_inventory_v1.json` and checked against the
published syntax for the exact resolved packages:

- `regex@1.13.1`, whose string-regex syntax and match behavior are the
  incumbent authority;
- `regex-syntax@0.8.11`, whose AST and parser diagnostic taxonomy are an
  independent structural reference;
- Unicode Technical Standard #18 revision 25, used for terminology only.

The incumbent remains controlling wherever those references admit multiple
choices. The machine artifact pins the root manifest, lockfile, R1 inventory,
R1 operator document, ADR, package checksums, and the reviewed upstream source
digests. A resolved dependency change therefore forces explicit review instead
of silently redefining version 1.

## Input and match contract

The consumed API accepts UTF-8 Rust `&str` patterns and haystacks. Unicode mode
is enabled by default. Searches are unanchored unless the pattern supplies an
anchor, matches report half-open UTF-8 byte offsets, and alternation uses
leftmost-first branch priority.

Asupersync does not consume `regex::bytes::Regex`. Scoped `u` disablement is
nevertheless part of the string grammar when it preserves the UTF-8 invariant:
`(?-u:\b)` is accepted for an ASCII word boundary, while `(?-u:.)` is rejected
because it can match an invalid UTF-8 byte. Octal escapes are disabled. A
decimal escape such as `\1` remains a rejected backreference rather than being
reinterpreted as octal.

## Precedence and associativity

Outside a bracketed class, precedence runs from most binding to least:

1. atoms: literals, escapes, dot, classes, assertions, and groups;
2. postfix repetition on the immediately preceding atom;
3. ordered concatenation;
4. ordered alternation.

Alternation preserves left-to-right priority. `sam|samwise` matches `sam` in
`samwise`, while `samwise|sam` matches the longer first branch. Concatenation
and alternation normalize to ordered flat sequences; this avoids treating
commutativity as a valid rewrite.

Inside a bracketed class, precedence is:

1. ranges;
2. adjacency union;
3. intersection (`&&`), direct difference (`--`), and symmetric difference
   (`~~`) at equal precedence, evaluated left to right;
4. whole-class negation.

Thus `[\pL--\p{Greek}&&\p{Uppercase}]` is grouped as
`[[\pL--\p{Greek}]&&\p{Uppercase}]`.

## Accepted grammar

The machine artifact owns the normative EBNF-like production strings. In
summary, version 1 requires:

- Unicode scalar literals, ordered concatenation, and ordered alternation;
- numbered captures, both incumbent named-capture spellings, noncapturing
  groups, and scoped or global flag changes;
- `?`, `*`, `+`, `{n}`, `{n,}`, and `{n,m}`, with optional lazy suffixes;
- line and absolute anchors, Unicode and ASCII word-boundary assertions, and
  the empty regex;
- dot, bracketed classes, nested classes, ranges, union, negation,
  intersection, difference, and symmetric difference;
- Unicode properties/scripts, Unicode Perl classes, ASCII POSIX classes,
  punctuation/control escapes, two-digit hex escapes, and Unicode scalar
  escapes;
- the `i`, `m`, `s`, `R`, `U`, `u`, and `x` flags with their incumbent
  defaults and scoping.

The full inventory mapping is machine checked. All 31 `RGX-SYN-*` rows from R1
appear exactly once, preserve their `ACCEPTED` or `REJECTED` state, and point
only to declared construct IDs. This includes empty and zero-width patterns,
empty set classes, nested repetition, CRLF mode, verbose mode, Unicode case
folding, and UTF-8-safe Unicode disablement.

## Intentionally rejected extensions

Version 1 rejects the same broad extension classes as the incumbent:

- lookahead and lookbehind;
- numbered or named backreferences;
- atomic groups and possessive quantifiers;
- conditional subexpressions and recursion.

Malformed groups, classes, repetition ranges, flags, escapes, and string
patterns that could match invalid UTF-8 also remain rejected. These are
compatibility requirements, not a smaller candidate subset: an extension that
the incumbent later accepts is grammar drift and forces `KEEP_OR_DEFER` until a
new language-version review.

## Limits

The frozen incumbent limits are:

| Limit | Value | Outcome |
| --- | ---: | --- |
| syntax nesting | 250 levels | `RGX-DIAG-NEST-LIMIT` |
| repetition count | `u32::MAX` | `RGX-DIAG-INVALID-REPETITION` above the bound |
| compiled NFA size | 10 MiB | `RGX-DIAG-COMPILED-SIZE-LIMIT` |
| hybrid cache | 2 MiB | fall back to a non-hybrid engine |

The current public constructor has no explicit pattern-byte, token-count, or
AST-node limit. Version 1 gives the future bounded lexer/parser provisional
1 MiB pattern, 1,048,576 token, and 1,048,576 AST-node limits. Every one of
those candidate-only limits is marked
`CUTOVER_BLOCKER_UNTIL_POLICY_AND_CORPUS_PROVE_ACCEPTABLE`. They are safe
implementation inputs for R3.1.2 and R3.1.3, but they are not incumbent parity
evidence and may not justify removing `regex`.

## Version and diagnostic policy

`language_version = 1` freezes accepted and rejected syntax, precedence,
normalized AST shapes, diagnostic categories and span policy, limit values and
outcomes, and Unicode/byte-mode semantics. Any change to those fields requires
an explicit language-version review. Editorial changes and added examples may
not alter their meaning.

Human-readable incumbent error wording is intentionally not stable. The
machine contract instead owns typed `RGX-DIAG-*` categories and half-open UTF-8
byte ranges. This lets the future parser produce useful, source-correct errors
without promising another crate's display text.

## Golden corpus

The 20-case golden corpus combines independent published examples with R1
patterns. Each accepted row records its source, normalized AST, complete AST
span, haystack, and expected match span or expected nonmatch. Each rejected row
records its source, normalized diagnostic category, error span, and an
incumbent error fragment used only as a drift probe.

The corpus freezes the consequences of precedence and byte-offset rules, not
just compile success. It includes alternation branch order, lazy repetition,
named capture, scoped flag deltas, class-set precedence, Unicode scripts,
scalar escapes, ASCII word boundaries, an empty UTF-8 match, nested repetition,
lookaround, backreferences, malformed delimiters, invalid repetition/flags,
invalid string byte mode, and a trailing escape.

## Downstream handoff

`asupersync-5z2scg.8.3.1.2` is the next consumer. Its lexer must emit token
kinds and spans compatible with `ASUP-REGEX-SYNTAX-V1`, enforce every declared
limit with the stable diagnostic category, and reject unknown grammar IDs.
R3.1.3 owns the iterative parser and resource accounting.

The real no-mock dependency-sovereignty scenario remains
`regex_adversarial_limits`, owned by `asupersync-5z2scg.8.5`. This
documentation-only gate does not claim that scenario has run.

## Validation

Run the focused contract through the remote-required clean overlay:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/regex_syntax_grammar_contract_v1.json \
  --overlay-path docs/regex_syntax_grammar_contract.md \
  --overlay-path tests/regex_syntax_grammar_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_regex_syntax_grammar_contract" \
  cargo test -p asupersync --features metrics \
  --test regex_syntax_grammar_contract -- --nocapture
```

The contract validates source pins, versions, zero-unknown policy, precedence,
flag and production coverage, the exact R1 mapping, live incumbent behavior,
golden AST/diagnostic span completeness, immutable limits, documentation
markers, and negative mutations for version, limit, and missing-map drift.
No local Cargo fallback is approved if the remote-required lane is blocked.

## No-claim boundary

This artifact does not implement a lexer, parser, compiler, matcher, privacy
fix, or dependency cutover. Normalized AST strings are fixtures, not candidate
parser output. Candidate-only bounds are explicit parity blockers. No
performance, cancellation, memory, fuzz, privacy-completeness, canonical E2E,
broad workspace, release-readiness, or live-fleet claim is made.

<!-- END REGEX SYNTAX GRAMMAR CONTRACT -->
