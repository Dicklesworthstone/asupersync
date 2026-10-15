# DEP-ADR-011: Owned UTC timestamp/calendar surface for full chrono/time capability, serialization, and UX

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.11`
- Capability: `CAP-TIME-UTC-RFC3339`
- Decision: `ADDITIVE_COEXISTENCE`; capability posture
  `PRESERVE_AND_REPLACE_IF_PARITY` / `BLOCKED_PENDING_EVIDENCE`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §5 `time` and
  `chrono` rows, and the §2.4 "consolidate (Phase 2)" audit finding

## Context

The bead says the one-helper estimate is invalid. The source read confirms that,
but splits the two crates apart cleanly.

**The `time` crate claim is correct.** Exactly one call site exists, in a private
CLI helper converting nanoseconds to RFC 3339. Its signature is integer to
string, so no type escapes. That part of the plan is accurate.

**`chrono` is a different problem entirely.** Ten **public, serde-derived**
fields typed as a chrono UTC datetime across three public modules, plus calendar
arithmetic for expiry and retention. Those fields feed **three JSON index
stores** under the ATP workflow root that are **read as well as written**. So
replacing chrono is not a formatting change — it is a migration that must parse
an existing on-disk corpus, and it is semver-breaking whenever `cli` or
`benchmark-adapters` is enabled.

Two findings make the work more tractable than it first appears:

**The repository already owns two chrono-free RFC 3339 formatters** — one at
second precision built on a civil-from-days conversion, one at nanosecond
precision with correct pre-epoch handling via euclidean division. They are
duplicated logic in two unrelated modules, and they are the natural seed for the
owned type. Consolidating them is Phase-2-sized work that stands on its own.

**But the owned type is genuinely new, not a rename.** `types::Time` is
nanoseconds and serde-derived, yet its wall-clock accessor is *process-epoch*
relative, and it deliberately carries no calendar semantics because it exists for
scheduling and virtual time. Conflating it with a UNIX-epoch instant would either
corrupt scheduling or produce wrong timestamps.

What is owned today: monotone, virtual and logical time; the timer wheel; the
injectable clock seam; RFC 3339 *emission*. What is not: calendar arithmetic,
RFC 3339 *parsing*, and a serde-stable UTC instant type. Those three are exactly
what chrono supplies.

## Decision

An owned UTC timestamp type is authorized as **additive** work. `chrono` and the
`time` crate stay until it demonstrably parses the existing persisted corpus.

1. All ten public field types **MUST** keep their current serde representation
   until an owned type is byte-compatible with it.
2. Index documents written by earlier builds **MUST** continue to deserialize.
   Optional timestamps **MUST** round-trip absence as absence, never as an epoch
   default.
3. The owned type **MUST** parse, not only emit. Emission alone is a third of the
   capability.
4. Both existing owned formatters' precisions — second with `Z`, and nanosecond
   with correct pre-epoch handling — **MUST** be preserved; one is pinned by a
   frozen golden. Consolidating them into one type is the recommended first step.
5. Logical and virtual time **MUST** stay free of calendar semantics, and
   deterministic paths **MUST NOT** acquire an ambient clock.
6. Calendar-duration conversion **MUST** keep failing explicitly rather than
   saturating silently.
7. The `time` crate **MAY** be removed once the owned type subsumes its single
   call site — but **MUST NOT** be removed merely to reduce a count, since doing
   so alone would leave a *third* RFC 3339 implementation beside the two already
   owned.
8. The `chrono` **dev-dependency MUST be retained** as a differential oracle even
   after any future production removal.

## Allowed tradeoffs

- An owned type may improve determinism and ergonomics over chrono.
- Consolidating the two owned formatters is permitted and encouraged now.
- Precision may be made explicit and uniform, provided existing goldens and the
  persisted corpus still round-trip.

## Forbidden compromises

- Changing a public field type before round-trip evidence exists.
- Emitting a new format without a reader for the existing corpus.
- Reusing `types::Time` as the UTC instant.
- Removing the chrono dev-dependency and losing the PostgreSQL temporal oracle.
- Introducing an ambient clock read into a deterministic path.

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| TIM-GAP-01 | Registry `source_owners` names `src/time/mod.rs` — **every file under `src/time/` has zero chrono and zero time-crate references**; it is the async timer module, apparently matched on the word "time". The row names **none** of the four files that actually own chrono, though its own `exposure` cites public-api and persisted-format. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| TIM-GAP-02 | **No round-trip test for any chrono field, and no test at all for the three persisted index stores.** The registry promises round-trip compatible persisted values and nothing measures it. | `asupersync-5z2scg.6.3` |
| TIM-GAP-03 | No byte-level goldens for any chrono-serde document. The CLI golden **scrubs** timestamps, so it is format-blind. | `asupersync-5z2scg.6.3` |
| TIM-GAP-04 | The single `time`-crate call site has exactly one test vector, at a whole-second boundary — no leap-year, fractional, negative-epoch or range case. | `asupersync-5z2scg.6.3` |
| TIM-GAP-05 | Nothing owned **parses** RFC 3339, and the two owned formatters are duplicated logic at different precisions. | `asupersync-5z2scg.6.1` |
| TIM-GAP-06 | `types::Time` is process-epoch relative and calendar-free, so the owned UTC type is new work, not an extension. | `asupersync-5z2scg.6.1` |
| TIM-GAP-07 | chrono is a test-only **differential oracle** for PostgreSQL binary temporal decoding; the dev-dependency must outlive the production one. | `asupersync-5z2scg.6.3` |
| TIM-GAP-08 | Three documents disagree: plan says `time` = REMOVE/Phase 2 and `chrono` = OWN/Phase 5, an audit line says consolidate both in Phase 2, and the registry binds both to one capability whose no-claim boundary says a nanos-to-RFC3339 helper cannot justify removing either. | `asupersync-5z2scg.6.1` |
| TIM-GAP-09 | Neither the registry's baseline command nor any of its three scenario IDs appears anywhere in the repository. | `asupersync-5z2scg.6.7` |

## Invariant impact checklist

- [x] All ten public field types and their serde representation preserved.
- [x] Persisted index readback preserved, including optional-absence round-trip.
- [x] Both owned formatter precisions preserved.
- [x] Calendar-duration conversion keeps explicit failure.
- [x] Logical/virtual time stays calendar-free and clock-injectable.
- [x] chrono dev-dependency retained as an oracle.
- [x] `time`-crate removal gated, not merely permitted.
- [x] No compatibility shim introduced.
- [x] No root export changes.

## Evidence

Evidence state is `BASELINE_PLANNED`. Owners: `asupersync-5z2scg.6.1`
(baseline), `.6.3` (unit), `.6.7` (E2E).

The gating pieces are TIM-GAP-02 and TIM-GAP-03: **round-trip tests and
byte-level goldens for the persisted documents**. Without both, a type swap
cannot see the breakage it would cause. Independent Gregorian calendar vectors
across the full accepted range — including negative epochs and leap rules — are
the other precondition, since the current coverage is a single whole-second
vector.

## Rollback

Triggered by any index document that stops deserializing, any changed rendering
or precision, any optional timestamp that stops round-tripping absence, any
public field type change without downstream evidence, any ambient clock read in a
deterministic path, or drift in either owned formatter's precision.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that the persisted index corpus
round-trips, that the owned formatters are correct across the calendar range,
that an owned UTC type could reach serde or parsing parity, that performance is
unchanged, or that either crate may be removed. It also does not certify the
capability registry's source-owner row, which TIM-GAP-01 records as naming a
module containing no chrono or time-crate code at all.
