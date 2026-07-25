# FrankenSQLite combined-graph budget

- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Phase: `asupersync-ym2wtv` (Phase 6)
- Bead: `asupersync-ym2wtv.1`
- Governing ADR: [`DEP-ADR-010`](./adr/dep_plan_adr_010_sqlite_frankensqlite.md)
- Artifact: [`artifacts/sqlite_combined_graph_budget_v1.json`](../artifacts/sqlite_combined_graph_budget_v1.json)
- Contract: [`tests/sqlite_combined_graph_budget_contract.rs`](../tests/sqlite_combined_graph_budget_contract.rs)
- Measured: 2026-07-25, `x86_64-unknown-linux-gnu`, release profile

## Method

Four synthesized consumers, each a standalone package **outside** the asupersync
workspace — required, because FrankenSQLite depends on asupersync and measuring
from inside would close the very cycle `DEP-ADR-010` forbids.

| | Consumer | Contents |
|---|---|---|
| **A** | incumbent | `asupersync` with the current `sqlite` feature |
| **B** | proposal | `fsqlite` with `native` + `async-api` |
| **C** | combined, naive | both, as a downstream user would naively write it |
| **D** | combined, patched | both, plus a patch unifying `asupersync` |

Edges counted are `normal` and `build`; `dev` excluded. Graphs are
platform-filtered, so counts reflect what actually resolves on this target.

**Native code is counted only when it is actually compiled.** A package counts
as active C only if it is reachable in the filtered resolve *and* build-depends
on `cc`/`cmake`, with that compiler also resolved. A declared build dependency is
not evidence — that exact trap produced two earlier errors in this program
(the "signal-hook cc shim" and "rdkafka via cmake" corrections).

## Results

| | A incumbent | B proposal | C naive | D patched |
|---|---|---|---|---|
| unique crates | 146 | 179 | 194 | 193 |
| reachable packages | 155 | 191 | 222 | 211 |
| build scripts | 27 | 28 | — | — |
| duplicate-version crates | 9 | 12 | **28** | 18 |
| `asupersync` instances | 1 | 1 | **2** | 1 |
| active C compilation | `libsqlite3-sys`, `psm`, `stacker`, `signal-hook` | `blake3`, `signal-hook` | — | — |

**Net: +33 unique crates**, 131 shared.

## Findings

**GB-01 — the proposal adds dependencies, it does not remove them.** 146 → 179.
The plan already framed this as "capability relocation, not zero dependency
cost"; that framing now has a number attached.

**GB-02 — but it does evict the bundled SQLite C, which is the real win.**
Active C compilation drops from four packages to two. Evicted: `libsqlite3-sys`
(the ~250k-line SQLite amalgamation), plus `psm` and `stacker`, the stack-probing
pair pulled in by `sqlparser`'s recursion helper. Added: `blake3`.
`signal-hook` compiles C in both and is attributable to neither. **Three evicted
against one added** — this is the strongest argument for continuing the campaign.

**GB-03 — critical: a naive combined consumer links _two_ asupersync runtimes.**
Consumer C resolves `asupersync` twice — once from path, once from crates.io,
both `0.3.9` — because FrankenSQLite pins the published version. Cargo treats
them as distinct packages, so `Cx` from one is *not the same type* as `Cx` from
the other. Duplicates rise to 28, including the entire AEAD stack and all three
FrankenSuite crates.

The consequence is not cost, it is coherence: the overlap period `DEP-ADR-010`
requires — the same e2e suite running on both engines during coexistence —
**cannot happen in one binary** unless the graphs are unified first.

**GB-04 — a patch unifies it, but not completely.** Consumer D points
FrankenSQLite's `asupersync` at the local path. It collapses to one instance and
duplicates fall 28 → 18. The residue is genuine version skew between the two
projects' hash and crypto choices, plus `syn` and `hashbrown`. An official
integration must pin these jointly or accept the duplication knowingly.

**GB-05 — `io-uring` has a build script but compiles no C.** It looked native
under a name-based heuristic and is pure Rust under the build-dependency test.
Recorded because the heuristic would have misreported it — the same
declared-versus-active error this program has already made twice.

## Budget threshold and outcome

> A cutover may not increase the consumer's unique-crate count unless it evicts
> native C compilation, and may never leave a supported consumer linking two
> asupersync runtimes.

The proposal **fails** the first clause (+33) and **passes** the second (3 C
packages evicted against 1 added). The decisive constraint is GB-03, which is a
correctness bar rather than a budget bar.

**Terminal outcome: DEFER.** The incumbent `sqlite` feature stands, per
`DEP-ADR-010`. No transitive-eviction or free-capability claim survives this
measurement.

This defers **on graph cost only**. It makes no claim about FrankenSQLite's
correctness, maturity or performance, and does not close the campaign.

## Blocked

| Axis | Why | Unblock |
|---|---|---|
| binary size | The RCH hook intercepts cargo builds and refuses a project outside its canonical root (`/data/projects`); every worker fails preflight for such a path and RCH then refuses local fallback. The consumers must live outside the asupersync tree to satisfy the cycle rule, so the two constraints conflict. | Run the consumers from a path under the RCH canonical root, or obtain explicit authorization for a local release build. |
| compile time | Same RCH constraint. | Same; must be measured cold, per consumer, on one host. |

Recorded BLOCKED rather than omitted: a silent skip is not a green result.

## Reproducibility caveat

Both trees carried uncommitted changes when measured — asupersync 7 modified
paths, FrankenSQLite 23. The recorded revisions identify the baseline, **not** an
exactly reproducible state. A clean-tree re-measure is required before any
cutover decision cites these numbers as final.

## No-claim boundary

This measures dependency-graph cost only, at one profile, target and host, from
working trees that were not clean. It does not measure binary size or compile
time. It makes no claim about FrankenSQLite's correctness, semantic parity,
maturity, performance or data compatibility, and it authorizes no cutover.
