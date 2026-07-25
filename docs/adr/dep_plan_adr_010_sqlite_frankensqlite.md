# DEP-ADR-010: Keep the SQLite feature; any FrankenSQLite path must be cycle-safe, official, and equally discoverable

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.10`
- Capability: `CAP-SQLITE`
- Decision: `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §9.1 and the §5
  `rusqlite` + `sqlparser` row; and the bead's own "depends optionally" wording

## Context

The governing fact is **structural, not a matter of taste**: FrankenSQLite
depends on asupersync, so asupersync cannot depend back without a Cargo cycle.
The candidate replacement therefore cannot be an in-workspace oracle, cannot be a
dev-dependency, and cannot be reached by the root feature. Parity must be
measured in the downstream repository or in a neutral consumer depending on both,
with an independent lockfile. The registry states this as a hard rule, and the
oracle policy names it `must-not-enter-asupersync-workspace`.

**The bead's own description is wrong on this point.** It says FrankenSQLite
"already depends **optionally** on asupersync." The downstream manifest carries
no `optional` marker — the likely misreading is `default-features = false` — and
the plan states the dependency is **unconditional**. Every downstream crate takes
it that way. Optionality would have meant some feature configuration could break
the cycle. It cannot. The constraint is absolute, and this ADR does not carry the
bead's wording forward.

**The plan and the registry also disagree.** §9.1 says the `sqlite` feature is
"deprecated/removed" and the integration inverted. The registry and the bead both
make **KEEP** the default terminal result unless an owner approves an equally
discoverable public move after user-journey trials — because Cargo cannot make
the root feature depend on the downstream adapter, and removing the feature after
merely proving downstream parity *would worsen discoverability and force users to
reconstruct the integration themselves*. The registry governs.

**The code itself is good news.** The async wrapper is a genuinely well-built
seam: a single blocking-pool funnel that every public async method routes
through; a budget-derived statement timeout enforced via the engine's progress
handler, where **arming failure is fatal by design** because running unbounded
after a bound was requested would void the contract; and a cancellation protocol
that issues a **real interrupt** and then refuses to report `Cancelled` until the
blocking job acknowledges, under a bounded masked drain — so the connection lock
is released and no statement keeps running unobserved. Three drain outcomes are
distinguished and traced. The row stream carries its own interrupt handle, so
dropping it aborts an in-flight step rather than waiting for a row boundary.

**And one leak that is easy to miss.** Exactly one rusqlite type reaches the
public API, and *not through a signature*: a public `impl rusqlite::ToSql for
SqliteValue`. An audit that greps public signatures for the engine name finds
nothing and concludes the API is clean. It is not — the API is semver-coupled to
the engine, and no swap can preserve this without an equivalent trait.

## Decision

The `sqlite` feature stays, with `rusqlite` and its bundled C, at
`KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`.

1. FrankenSQLite **MUST NOT** be added to this workspace under any
   configuration — not as a dependency, not as a dev-dependency, not as an
   oracle. This is a package-graph impossibility, not a preference.
2. Parity **MUST** be measured from the downstream repository or a neutral
   consumer with an independent lockfile.
3. The checked SQL surface **MUST** stay the default; the `_unchecked` variants
   stay an explicit opt-out. Both halves are the security contract.
4. The effective statement timeout **MUST** remain `min(remaining budget,
   per-connection override)`, and arming failure **MUST** stay fatal.
5. Cancellation **MUST** keep interrupting and then draining before reporting
   cancelled; transaction drop **MUST** keep rolling back, generation-guarded.
6. The engine's `hooks` feature **MUST** be retained — dropping it to trim the
   graph would silently remove statement timeouts.
7. Engine errors **MUST NOT** cross the boundary; the owned error predicates are
   the retry contract.
8. The feature **MUST NOT** be deprecated before an official integration is
   released and demonstrably at least as discoverable.
9. Removal additionally requires **data compatibility** — files written by the
   incumbent, including WAL and unclean-shutdown state — and an **equivalent
   parameter-binding trait** for the leaked impl.

## Allowed tradeoffs

- Building and publishing an official companion/integration crate alongside.
- Improving diagnostics or ergonomics within the frozen surface.
- Fixing the six tokio-macro tests and the lint-suppressed files.

## Forbidden compromises

- Adding FrankenSQLite to this workspace in any form.
- Deprecating the feature before an equally discoverable path is released.
- Making the unchecked SQL path the default.
- Dropping the `hooks` feature, or letting a timeout silently stop being enforced.
- Citing a smaller asupersync-only graph as a combined budget.

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| SQL-GAP-01 | The **bead says "optionally"; the dependency is unconditional.** No feature configuration can break the cycle — the constraint is absolute. | `asupersync-ym2wtv.3.1` |
| SQL-GAP-02 | Plan §9.1 says deprecate/remove and invert; registry and bead make KEEP the default terminal result absent owner approval. | `asupersync-ym2wtv.4` |
| SQL-GAP-03 | The one public leak is a **foreign-trait impl**, not a signature. A signature-grep audit would wrongly call the API engine-clean. | `asupersync-ym2wtv.2.9` |
| SQL-GAP-04 | The registry's baseline command and all four scenario ids are planned; the named e2e scenario appears **nowhere** in the runner script. | `asupersync-ym2wtv.2.1` |
| SQL-GAP-05 | Six tests across two files use `#[tokio::test]`; the root dev-dep does **not** enable `macros` — it arrives only via workspace feature unification. At risk under a package-scoped run, and a poor fit for a crate defined by not depending on tokio. | `asupersync-ym2wtv.2.9` |
| SQL-GAP-06 | Two test files suppress **all** warnings and clippy lints at crate scope; one conformance test asserts nothing and merely prints a notice when the feature is off. | `asupersync-ym2wtv.2.9` |
| SQL-GAP-07 | `sqlparser` pulls a recursion helper carrying C/asm stack-probing code, so the checked SQL surface is a **second** native edge, not a pure-Rust one. | `asupersync-ym2wtv.1` |
| SQL-GAP-08 | Documented timeout caveat: the progress handler runs only while the VM executes, so time blocked on a locked database can overshoot by up to the busy timeout. A real bound, honestly documented. | `asupersync-ym2wtv.2.9` |

## Invariant impact checklist

- [x] Cycle rule preserved and stated as absolute.
- [x] Checked-by-default / unchecked-by-choice preserved.
- [x] Timeout minimum and fatal arming failure preserved.
- [x] Interrupt-then-drain cancellation preserved.
- [x] Generation-guarded transaction rollback preserved.
- [x] `hooks` feature recorded as load-bearing.
- [x] The trait-impl leak recorded, not widened.
- [x] No compatibility shim introduced.
- [x] No root export changes.

## Evidence

Evidence state is `BASELINE_PLANNED`. Owners: `asupersync-ym2wtv.2.1`
(baseline), `.2.9` (unit), `.3.5` (E2E).

The oracle gate here is **structurally constrained**: it cannot be satisfied
inside this workspace at all. The combined graph budget must count *both* sides
of the relocation — the plan is explicit that this is capability relocation, not
zero dependency cost. Data compatibility is a separate gate from API parity and
is not implied by it.

## Rollback

Triggered by any lost public symbol or error predicate; the checked surface
ceasing to be the default; a timeout that stops being enforced or claims a
tighter bound than it delivers; cancellation reporting before the blocking job
acknowledges; a transaction that fails to roll back on drop; a database file that
stops being readable; the leaked trait impl disappearing without an equivalent;
or any attempt to add the downstream engine to this workspace.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that FrankenSQLite could reach semantic
or data parity, that the masked drain or the generation-guarded rollback behave
as stated under load, that the statement timeout holds within its documented
caveat, that the combined graph is smaller or larger, that performance is
unchanged, or that the `sqlite` feature or either engine crate may be removed. It
makes no claim about the downstream project's maturity, and it does not authorize
adding that project to this workspace under any configuration.
