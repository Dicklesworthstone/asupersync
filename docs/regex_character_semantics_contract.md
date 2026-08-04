# Regex character semantics contract

<!-- BEGIN REGEX CHARACTER SEMANTICS CONTRACT -->

This is the operator-readable companion to
`artifacts/regex_character_semantics_contract_v1.json` for
`asupersync-5z2scg.8.3.2.2`, `CAP-REGEX-PRIVACY`, and
`ASUP-REGEX-CHAR-SEMANTICS-V1`.

## Decision

R3.2.2 is `STAGED_RETAINED_TABLE_BACKEND`.

The new internal semantic layer consumes the bounded
`ASUP-REGEX-SYNTAX-V1` AST and normalizes character-like atoms into checked,
canonical ranges. It is not wired into the observability matcher. The
production `regex` and `regex-syntax` stack remains in place.

Unicode properties are resolved by the exact retained
`regex-syntax@0.8.11` Unicode 16.0.0 tables pinned by R3.2.1. The optional
dependency is named `retained-regex-syntax` in `Cargo.toml` to make that
boundary explicit. It adds no unique package, build script, proc macro, native
code, generated table, or public API.

## Input and alphabets

The reachable consumer accepts Rust `&str` patterns and haystacks. It does not
use `regex::bytes::Regex`.

Unicode mode is enabled by default. Its alphabet is the Unicode scalar set
from U+0000 through U+10FFFF, excluding the surrogate range because surrogates
are not scalar values. Unicode noncharacters such as U+FDD0 and U+10FFFF
remain valid scalar literals. Combining sequences are matched as code points;
this layer does not normalize them.

When `u` is disabled, the class alphabet is an explicitly
`UTF8_SAFE_BYTE` alphabet:

- byte classes emitted for string matching contain only ASCII bytes;
- a raw non-ASCII literal is accepted only when the complete scope remains
  valid UTF-8;
- adjacent byte escapes such as `\xC2\xA0` are checked as a complete scope,
  rather than incorrectly rejecting each byte in isolation;
- an isolated byte such as `\xFF`, a byte-mode dot, or another non-empty match
  that can split/fabricate UTF-8 is rejected;
- Unicode properties in byte mode are rejected before table translation.

No ambient locale or platform character database participates.

## Canonical classes

Unicode ranges use inclusive `char` endpoints. UTF-8-safe byte ranges use
inclusive `u8` endpoints. Ranges are sorted, non-overlapping, and
non-adjacent. Membership uses binary search.

The retained translator supplies the accepted semantics for:

- literals and inclusive ranges;
- adjacent union and whole-class negation;
- nested classes;
- intersection, difference, and symmetric difference;
- Unicode properties and aliases;
- Unicode or ASCII Perl classes according to flag scope;
- ASCII POSIX classes;
- dot in an admissible alphabet;
- the empty class set.

Candidate flags are tracked through ordinary, named, noncapturing, scoped, and
global flag groups. Unicode-disabled scopes receive a whole-scope UTF-8
validation pass so valid multibyte sequences are not narrowed to an
ASCII-only language.

## Limits and fail-closed diagnostics

The syntax limits remain 1,048,576 pattern bytes, 1,048,576 tokens,
1,048,576 AST nodes, and nesting 250. The semantic layer adds:

| Limit | Value | Failure |
| --- | ---: | --- |
| semantic atoms | 1,048,576 | `RGX-SEM-E006` |
| ranges in one class | 4,096 | `RGX-SEM-E007` |
| aggregate ranges | 1,048,576 | `RGX-SEM-E008` |
| retained translator nesting | 250 | fail closed |

Unknown properties produce `RGX-SEM-E001`. A property under disabled Unicode
mode produces `RGX-SEM-E002`. Invalid UTF-8 byte behavior produces
`RGX-SEM-E003`. Backend output must already be canonical and is independently
rechecked before admission.

Errors expose only stable code/category and byte/scalar spans. They never
render the pattern or retained-backend error text. The
`private-source-canary` test pins that privacy property.

## Evidence

The source contains twelve deterministic unit/property lanes:

- Unicode Script, general-category/mark, Perl, and POSIX behavior;
- ASCII range, nested-set, negation, and scalar-edge goldens;
- valid and invalid Unicode-disabled byte scopes;
- unknown-property, byte-property, atom-limit, and range-limit failures;
- exact resource/canonicalization reconciliation;
- 256 independently modeled ASCII interval cases;
- 256 arbitrary UTF-8 determinism and panic-containment cases.

The implementation is pure synchronous analysis. It creates no task,
obligation, permit, socket, file, lock, service, or external process.
Cancellation, shutdown, restart, and quiescence journeys therefore do not
apply at this layer. The aggregate real downstream pattern scenario and the
independent Unicode/byte terminal corpus remain owned by R3.2.4.

Run the focused private-source contract remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features metrics \
  --test regex_character_semantics_contract -- --nocapture
```

Run the warning-denied source check remotely:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo check -p asupersync --features metrics --lib
```

Run the required broad Clippy frontier remotely:

The exact warning frontier suffix is
`--all-targets --keep-going -- -D warnings`.

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-C debuginfo=0' \
  cargo clippy -p asupersync --features metrics \
  --all-targets --keep-going -- -D warnings
```

No local Cargo fallback is approved.

The terminal clean-overlay receipts for source digest
`bd762181da7620330a580152688af7684da371a9a32c144ef09ac5b5d0c2221a`
are:

| Lane | Result | RCH receipt |
| --- | --- | --- |
| warning-denied library check | passed | `j-29947326818680916` on `hz1` |
| focused contract | 53 passed, 0 failed | `j-29947326818680917` on `hz2` |
| focused Clippy | passed | `j-29947326818680914` on `hz1` |
| broad all-target Clippy | blocked, no terminal success claimed | `j-29947326818680915` on `hz1`; gracefully cancelled after 259 seconds without progress while the heartbeat remained fresh |

The blocked broad lane does not weaken or expand the focused receipts and does
not establish broad workspace health.

## No-claim boundary

This contract does not authorize removing `regex` or `regex-syntax`, copying
or owning Unicode tables, or wiring the candidate into production. It does
not prove case folding; word, line, or input boundaries; compiler or matcher
correctness; capture/replace/privacy integration; cache or concurrency
behavior; performance improvement; no regression; broad workspace health; or
release readiness. R3.2.3 owns folding and boundaries. R3.2.4 owns the sole
terminal Unicode/byte conformance and size receipt consumed by compiler work.

<!-- END REGEX CHARACTER SEMANTICS CONTRACT -->
