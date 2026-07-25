# DEP-ADR-012: Preserve full user-supplied regex semantics and privacy guarantees; fixed scanners are only a fast path

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.12`
- Capability: `CAP-REGEX-PRIVACY`
- Decision: `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §5 `regex` row

## Context

The real regex surface is smaller than the capability's title suggests, and the
plan's proposed replacement is further away than it sounds.

**One file uses the engine.** `src/observability/otel.rs` holds the whole of it:
the OTLP privacy configuration, where downstream code supplies its own patterns
either through a fallible constructor or by mutating a public string vector
directly. Both paths compile through the full engine, and the direct-mutation
path is deliberate — the matcher detects a stale compiled cache and recompiles,
pinned by its own test.

**The engine's error type is public.** `try_with_pii_pattern` returns
`Result<Self, regex::Error>`, so replacing the engine is a semver-breaking public
API change under `metrics`, not merely an internal swap.

**The plan's fast path does not exist.** §5 proposes "fixed PII scanners +
subset matcher that fails closed on unsupported syntax." But all four built-in
detectors — email, SSN, card, phone — **are themselves regex literals**. The only
hand-rolled matching in the privacy path is the Luhn validity check and a
wildcard glob matcher for field names. So there is nothing to promote: building
non-regex detectors is new work, not extraction. And a fail-closed *subset*
matcher, while the right posture for redaction generally, would reject patterns
that work today — which the registry's no-claim boundary forbids outright:
*"Fixed scanners are not a general regex engine and may never justify dropping
custom user patterns."*

**And there is a mock.** `src/net/atp/chunk/artifact.rs` defines a local module
named `regex` that **shadows the crate** at its call site. Its constructor accepts
any pattern and stores it behind a dead-code allowance; its `find` ignores the
pattern entirely, splitting on whitespace and returning the first token whose
dot-separated parts begin with a digit. The call site passes a real-looking
version pattern that has never matched anything. It is compiled **unconditionally
on non-wasm targets**. It is not a regex consumer, it must not be counted as
replacement scope, and it is a live violation of the repo's no-mock policy that
the plan already flags for deletion.

## Decision

The regex crate stays, at `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`.

1. The **accepted pattern language MUST NOT narrow**. Whatever the incumbent
   accepts today — full Unicode and byte syntax, flags, classes, captures,
   boundaries, case folding, leftmost-first — remains accepted.
2. Both pattern-supplying paths **MUST** keep working: the fallible constructor
   and direct mutation of the public vector.
3. An invalid pattern **MUST** be reported, never silently dropped. Silently
   ignoring a user's privacy pattern is the worst failure this capability has.
4. Detector ordering and the per-class redaction tokens **MUST** be preserved,
   including that a Luhn-invalid digit run is left **unredacted**.
5. Field matching **MUST** stay glob-based and the attribute denylist **MUST**
   stay exact-match — neither may drift toward fuzzy matching.
6. Redaction **MUST** remain fail-closed, and linear-time matching **MUST** be
   preserved.
7. Non-regex detectors **MAY** be added in front of the engine as an
   optimization, provided they are proved equivalent on the patterns they
   accelerate and fall through to the engine otherwise.
8. A narrower fail-closed matcher **DOES NOT** qualify as a replacement.
9. Deleting the ATP chunk mock is **independent** of this decision and may
   proceed immediately.

## Allowed tradeoffs

- Faster equivalence-proved detectors in front of the engine.
- An owned error type replacing the leaked one, as part of a replacement.
- The mock's removal changing version-extraction behavior, reviewed on its own.

## Forbidden compromises

- Narrowing the accepted pattern language, even in the name of safety.
- Silently ignoring, or failing to report, an invalid user pattern.
- Making field matching or the attribute denylist fuzzy.
- Counting the ATP chunk mock as a regex consumer or as partial work.
- Citing the mock's behavior test as regex evidence.

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| RGX-GAP-01 | Registry `source_owners` names `src/observability/mod.rs`, which has **zero** occurrences of regex — not even a comment. The real owner `otel.rs` is absent. Same facade failure mode as the time and futures rows. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| RGX-GAP-02 | The ATP chunk `mod regex` **mock**: accepts any pattern, ignores it, compiled unconditionally on non-wasm. A live no-mock-policy violation. | `asupersync-d24mms.11` |
| RGX-GAP-03 | **All four built-in detectors are regex-backed.** The fixed-scanner fast path does not exist as non-regex code; building it is new work. | `asupersync-5z2scg.8.1` |
| RGX-GAP-04 | `regex::Error` is semver-visible on the public fallible constructor, so a replacement is a breaking API change and must supply an owned error type of equal quality. | `asupersync-5z2scg.8.3.7.4` |
| RGX-GAP-05 | **No regex or privacy fuzz target exists**, though the fuzz build links the engine and the capability declares an adversarial-limits scenario plus a catastrophic-backtracking invariant. | `asupersync-5z2scg.8.5` |
| RGX-GAP-06 | Plan says owned/Phase-5 with a fail-closed subset matcher; the registry says keep-until-parity and forbids narrowing. The registry is later and stricter. | `asupersync-5z2scg.8.1` |
| RGX-GAP-07 | The redaction engine is reachable **only** with `metrics` enabled, since that is the sole feature pulling regex. A build without it has no PII redaction at all. | `asupersync-5z2scg.8.1` |

## Invariant impact checklist

- [x] Accepted pattern language unchanged.
- [x] Both pattern-supplying paths preserved.
- [x] Invalid patterns reported, never silently dropped.
- [x] Detector ordering, tokens, and the Luhn-negative behavior preserved.
- [x] Field globbing and exact-match denylist preserved.
- [x] Fail-closed redaction and linear-time matching preserved.
- [x] The mock recorded as a defect, not as a consumer.
- [x] No compatibility shim introduced.
- [x] No root export changes.

## Evidence

Evidence state is `BASELINE_PLANNED`. Owners: `asupersync-5z2scg.8.1`
(baseline), `.8.3.7.4` (unit), `.8.5` (E2E).

The most consequential gap is RGX-GAP-05. This is a redaction engine processing
untrusted text, the capability explicitly claims resistance to catastrophic
backtracking, and **nothing exercises that claim**. An adversarial and
resource-limit corpus is the precondition, alongside a full-syntax corpus for any
differential comparison — where any pattern the candidate rejects counts as
capability loss, not as a safety win.

## Rollback

Triggered by any previously accepted pattern that stops compiling, any custom
pattern that stops taking effect, any lost or coarsened compile error, any changed
detector ordering or token, any field matcher becoming fuzzy, any regression in
linear-time matching, or any build where redaction silently disappears.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that redaction is complete against real
PII, that the engine resists adversarial input in this configuration, that an
owned engine could match the accepted language, that performance is unchanged, or
that the regex crate may be removed. It also does not certify the capability
registry's source-owner row, which RGX-GAP-01 records as naming a module with
zero regex references.
