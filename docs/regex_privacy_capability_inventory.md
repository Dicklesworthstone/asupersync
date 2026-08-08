# Regex/privacy capability inventory

<!-- BEGIN REGEX PRIVACY CAPABILITY INVENTORY -->

This is the operator-readable companion to
`artifacts/regex_privacy_capability_inventory_v1.json`. It freezes the live
`CAP-REGEX-PRIVACY` baseline for `asupersync-5z2scg.8.1` at revision
`23c5ac4074901349fba93617ef11ed5360d3dc61`.

`DEP-ADR-012` remains `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`. This inventory
does not authorize changing or removing `regex`. It identifies the exact
surface that a later implementation must preserve, records defects as routed
gaps instead of desired behavior, and gives later children an executable
syntax, field-policy, detector, resource, concurrency, downstream, and
privacy-threat corpus.

## Live dependency and public surface

The root manifest declares `regex = { version = "1.12", optional = true }`;
the captured lockfile resolves `1.13.1`. The edge is enabled by `metrics` and
is absent from the default feature profile. Upstream default features retain
`std`, `perf`, Unicode, and `regex-syntax/default`.

The only real dependency source owner is `src/observability/otel.rs`. The
historical local `regex` mock in `src/net/atp/chunk/artifact.rs` has been
removed and supplies no dependency evidence. A separate independent
conformance workspace also declares its own regex dependency, but it is not a
member of the root workspace.

The current public path is
`asupersync::observability::otel::PrivacyConfig`, behind `metrics`.
`PrivacyConfig` derives `Debug`, `Clone`, and `Default`, and exposes these
mutable fields:

- `drop_attributes: Vec<String>`
- `drop_labels: Vec<String>`
- `allowed_fields: Vec<String>`
- `pii_patterns: Vec<String>`
- `auto_pii_detection: bool`

Its compiled-pattern cache remains private. The public builders are `new`,
`with_drop_attribute`, `with_drop_label`, `with_allowed_field`,
`with_pii_pattern`, `try_with_pii_pattern`, and
`with_auto_pii_detection`. The public operations are `should_drop_field` and
`redact_pii`.

`PrivacyConfig` is neither Serde-serializable nor re-exported from the
`observability` facade, and it does not appear in
`artifacts/api_surface_map_v1.json`. `SpanConfig` remains a public type alias;
its documentation says deprecated, but it has no Rust `#[deprecated]`
attribute.

## Exact custom-pattern behavior

The accepted language is the incumbent regex 1.13.1 string language with
default Unicode behavior. Matching is unanchored unless the pattern supplies
anchors. A custom match replaces the entire input value with `[REDACTED]`;
the API exposes no capture values, match spans, byte haystacks, partial
replacement, or capture replacement.

The 31-case executable syntax corpus covers:

- literals, alternation, captures, noncapturing groups, counted repetition,
  absolute and line anchors;
- multiline, CRLF, dotall, verbose, ungreedy, and case-insensitive flags;
- Unicode scripts, digits, word boundaries, case folding, and scalar escapes;
- POSIX classes, intersection, subtraction, symmetric difference, and
  Unicode-disabled ASCII boundaries;
- empty patterns, zero-width matches, empty classes, nested repetition, and
  nonmatching values;
- rejected lookaround, backreferences, unclosed groups/classes, invalid
  repetition ranges, and unknown flags.

`try_with_pii_pattern` returns the public `regex::Error`.
`with_pii_pattern` panics with the context
`invalid PrivacyConfig PII regex pattern`. Builder-added patterns compile once
and are cached. A valid entry pushed directly into the public `pii_patterns`
vector takes effect, but it forces fallback recompilation of all pattern
strings on every redaction call and never refreshes the cache.

A directly inserted invalid entry is silently ignored. That observed behavior
is frozen so the regression is visible, not blessed: it conflicts with the
registry invariant that custom privacy patterns are never silently ignored and
is routed as `RGX-R1-GAP-01`.

## Field policy

`should_drop_field` applies this order:

1. exact `drop_attributes` match;
2. exact `drop_labels` match;
3. a nonempty `allowed_fields` allowlist;
4. keep.

The two drop lists are signal-merged despite their signal-specific
documentation. Drop matching is exact and case-sensitive. The allowlist is a
byte-oriented glob supporting only an unescaped `*`; the star crosses dots,
can match zero bytes, and makes a literal star unrepresentable. The 11-case
field corpus freezes exact-name, prefix nonmatch, multi-segment wildcard,
Unicode, empty, precedence, and case-sensitive behavior.

`redact_pii` currently ignores its `field_name` argument. Field admission and
value redaction are separate operations.

## Built-in detector behavior

Automatic detection uses four lazily compiled regexes in this fixed order:

1. email → `[EMAIL_REDACTED]`;
2. SSN → `[SSN_REDACTED]`;
3. payment-card candidate plus Luhn validation → `[CARD_REDACTED]`;
4. phone → `[PHONE_REDACTED]`;
5. otherwise preserve the original value.

Custom patterns run before every built-in and return `[REDACTED]`. All matches
replace the whole value. The 11-case detector corpus includes case-insensitive
email, invalid short TLD, SSN, spaced and hyphenated Luhn-valid cards,
Luhn-invalid retention, phone, detector ordering, and custom-before-built-in.

All four built-ins remain regex-backed. Fixed scanners are therefore a planned
fast path, not current evidence and never a general replacement for
user-supplied patterns.

## Signal wiring and privacy boundary

The production log helpers
`OtlpLogRecord::from_log_entry_with_privacy` and
`OtlpLogRecord::with_filtered_attribute` apply field dropping and value
redaction to the target and structured attributes. The log body/message,
resource attributes, trace/span identifiers, and event name are not passed
through `PrivacyConfig`.

The metrics request builder accepting privacy configuration is gated to
`test` or `fuzz` together with `metrics` and `tracing-integration`; it is not
production exporter wiring. The trace request builder uses unfiltered ordered
attributes. The test/fuzz log wire builder serializes its supplied body and
attributes without privacy filtering. Consequently,
`RGX-R1-GAP-05` remains a critical production multi-signal gap.

Derived `Debug`, fallible regex diagnostics, and panic diagnostics can contain
the raw pattern text. The artifact records that exposure as
`RGX-R1-GAP-03`; no secret-safe diagnostic contract exists yet.

## Resource and concurrency baseline

The upstream defaults captured here are a 10 MiB compiled NFA limit, a 2 MiB
hybrid cache, and syntax nest limit 250. `PrivacyConfig` adds no pattern-count,
pattern-length, haystack-length, time, memory, or cancellation bound.

Custom and fixed `is_match` scans have the incumbent worst-case `O(m*n)`
policy. Card-candidate `find_iter` followed by Luhn validation has the
upstream iterator worst-case `O(m*n^2)`. The executable resource corpus
contains:

- a 64 KiB nested-repetition nonmatch;
- a 251-level nesting rejection;
- a compiled-size-limit rejection;
- eight-thread shared `Arc<PrivacyConfig>` redaction;
- valid and invalid direct-mutation cases.

These bounded probes prove baseline behavior and clean thread joins only. They
do not establish production latency, memory, cancellation, or throughput
envelopes.

## Downstream and marginal graph

The existing external consumer fixture proves only the nested public path,
fallible custom-pattern construction, one custom match, and automatic email
redaction. It does not prove the full syntax corpus, direct mutation,
diagnostics, field policy, real OTLP signal wiring, resource behavior,
concurrency, or a collector journey.

No regex/privacy example, benchmark, dedicated fuzz target, or canonical
dependency-sovereignty result exists. A5 owns three planned scenarios:
`regex_custom_patterns`, `privacy_multisignal_redaction`, and
`regex_adversarial_limits`.

The dependency marginal ledger contains eight `normal:regex` cells. Across the
four `metrics` target cells, removal would marginally remove exactly
`aho-corasick@1.1.4`, `regex@1.13.1`, `regex-automata@0.4.16`, and
`regex-syntax@0.8.11`. The four `workspace-dev-build-audit` cells remove zero
packages because other workspace/dev edges retain the family. The edge adds no
build script, proc macro, or native code.

## Routed gaps

| Gap | Finding | Owner |
| --- | --- | --- |
| `RGX-R1-GAP-01` | directly inserted invalid patterns are silently ignored | A3.5 |
| `RGX-R1-GAP-02` | direct mutation recompiles the unbounded vector on every call | A3.4.4 |
| `RGX-R1-GAP-03` | Debug and syntax diagnostics can expose raw patterns | A3.7.4 |
| `RGX-R1-GAP-04` | no application-level work, input, memory, or cancellation bounds | A3.3 |
| `RGX-R1-GAP-05` | production multi-signal privacy wiring is incomplete | A5 |
| `RGX-R1-GAP-06` | no dedicated fuzz, benchmark, or canonical E2E scenario | A5 |
| `RGX-R1-GAP-07` | no Serde config or facade/API-map exposure | A3.5 |
| `RGX-R1-GAP-08` | `SpanConfig` is not compiler-deprecated | A3.5 |
| `RGX-R1-GAP-09` | registry language is broader than the consumed API | A3.7 |
| `RGX-R1-GAP-10` | fixed detector scanners do not yet exist | A2 |
| `RGX-R1-GAP-11` | the historical ATP local regex mock was removed | resolved |
| `RGX-R1-GAP-12` | no default-feature privacy journey exists | A5 |
| `RGX-R1-GAP-13` | stale ADR source-owner gap was already repaired | registry owner |
| `RGX-R1-GAP-14` | attribute and label drop lists are signal-merged | A5 |

There are zero `UNKNOWN` rows. Every discovered defect is routed to an owner,
and any missing or regressed parity row forces KEEP.

## Validation

Run the focused source-pin, authority, syntax, privacy, field, resource,
concurrency, downstream, documentation, and negative-mutation contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/regex_privacy_capability_inventory_v1.json \
  --overlay-path docs/regex_privacy_capability_inventory.md \
  --overlay-path tests/regex_privacy_capability_inventory_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_regex_privacy_capability_inventory" \
  cargo test -p asupersync --features metrics \
  --test regex_privacy_capability_inventory_contract -- --nocapture
```

No local Cargo fallback is approved when this remote-required lane is blocked.

<!-- END REGEX PRIVACY CAPABILITY INVENTORY -->
