# DEP-ADR-008: Preserve full futures-lite production semantics, public Stream usability, and test executor workflows

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.8`
- Capability: `CAP-FUTURES-STREAMS`
- Decision: `KEEP_UNTIL_PARITY`; capability posture
  `PRESERVE_AND_REPLACE_IF_PARITY` / `BLOCKED_PENDING_EVIDENCE`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §5 `futures-lite`
  row and its §7 Phase-2 work-list entry

## Context

The bead asks for the reference count to be classified by Cargo-built profile
rather than grepped. Doing that turns a frightening number into a precise one.

Of roughly **796 references across 148 files** under `src/`, essentially all sit
inside `#[cfg(test)]` modules. The **production set is six sites in five files**:

| Site | What it is |
|---|---|
| `src/net/atp/sdk/stream.rs` | `impl futures_lite::Stream` for `AtpWriter` and `AtpReader` |
| `src/web/middleware.rs` | `FutureExt::catch_unwind` — poll-phase panic containment |
| `src/web/negotiate.rs` | `FutureExt::catch_unwind` — error-handler panic containment |
| `src/web/router.rs` | `block_on` inside the public, synchronous `Router::handle` |
| `src/signal/shutdown.rs` | `block_on` ×2 driving signal-listener threads |

Plus two doc-comment examples on the public `Notify` API.

The shape of those six is what decides the ADR:

**Exactly one is a public trait impl.** `AtpWriter` and `AtpReader` implement the
*foreign* `futures_lite::Stream`, publicly reachable with no feature gate. That
is the entire public futures-lite surface, and it is the only impl of that trait
anywhere in the crate — everything else in `net`, `io` and `stream` uses
asupersync's **own** `Stream` trait, which is a complete 33-file implementation
with roughly thirty combinators and **zero** futures-lite dependency. The two
traits are structurally identical and completely disjoint: no adapter, no blanket
impl, no conversion. The ATP SDK types are the sole outlier, and they are the
only reason futures-lite appears in the public API at all.

**Three are the executor.** `Router::handle` is a public *non-async* entry point
whose whole async execution is `block_on`, and the two signal listeners block on
dedicated `std` threads outside any runtime. Those define the reentrancy and
nested-runtime contract the bead asks this ADR to *specify* — not to change.

**The plan's framing does not survive this.** It classifies futures-lite as a
Phase-2 *low-risk leaf removal* over "genuinely parallel, disjoint files", with a
`util/future.rs` shim covering `block_on`/`poll_fn`/`zip`/`race`/`yield_now`. But
the capability is public-api exposed, its cutover state is blocked pending
evidence, the file set is roughly **272** including tests, and the shim list omits
`poll_once`, `join_all`, `pending`, `FutureExt::catch_unwind` and `Stream` — the
last two of which are not free functions a helper module can supply.

## Decision

futures-lite stays. Capability posture is `PRESERVE_AND_REPLACE_IF_PARITY`, and
cutover remains **blocked pending evidence**.

1. The public `futures_lite::Stream` impls for `AtpWriter` and `AtpReader`
   **MUST** be preserved. Downstream generic code bounded on that trait must keep
   compiling, and ecosystem extension methods must keep working on those types.
2. asupersync's own `Stream`/`StreamExt` surface **MUST** remain free of any
   futures-lite dependency.
3. Two-stage panic containment — construction-phase and poll-phase — **MUST** be
   preserved in both web sites.
4. `Router::handle` **MUST** remain synchronous and **MUST NOT** begin requiring
   an ambient runtime.
5. Signal listeners **MUST** keep working on dedicated threads outside any
   runtime, and **MUST NOT** become starvable by one.
6. A blocking executor **MUST** remain available to every test target with no
   configuration, since there is no central harness to swap.
7. Any owned replacement **MUST** cover the full consumed surface: `block_on`,
   `poll_fn`, `poll_once`, `zip`, `race`, `join_all`, `yield_now`, `pending`, a
   catch-unwind future adapter, and a `Stream` story for the ATP SDK types.
8. No API may start an executor implicitly; the three production blocking sites
   are explicit and that explicitness is the contract.
9. Porting the ATP SDK types to the crate's own trait — the one bounded step that
   removes **all** public leakage — is permitted but is a **breaking change**
   requiring downstream-consumer evidence first.

## Allowed tradeoffs

- An owned helper layer may be added alongside and matured before any migration.
- Test-side migration may be mechanical once a drop-in `block_on` exists.
- The ATP SDK trait inconsistency may be resolved, as a reviewed breaking change.

## Forbidden compromises

- Removing the public ecosystem `Stream` impls without downstream evidence.
- Making futures-lite optional or dev-only — there is no dev-dependency entry
  today, and the single unconditional entry is what makes it visible to both
  `src` and `tests`.
- Letting `Router::handle` require an ambient runtime.
- Shipping a helper layer that covers only the five functions the plan names.
- Treating the ~149 non-test-filename count as the migration scope; it overstates
  production risk and understates total churn simultaneously.

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| FUT-GAP-01 | Registry `source_owners` names `src/stream/mod.rs` (one futures-lite ref, in a test module) and `src/io/stream_adapters.rs` (**zero**). Every production site is absent, as is `src/stream/stream.rs` where the owned trait is defined. The two named files cover exactly the part with **no** replacement risk. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| FUT-GAP-02 | **The public ecosystem `Stream` impls have no test.** The file's test module never invokes `poll_next` and never imports an extension trait. The one public futures-lite surface is the one with zero coverage. | `asupersync-d24mms.6.5` |
| FUT-GAP-03 | The downstream consumer fixture proves only the *owned* trait and never references futures-lite, so it would not detect a removal breaking the ATP SDK impls. | `asupersync-d24mms.6.10` |
| FUT-GAP-04 | The registry claims features `default` and `test-internals`; futures-lite is unconditional with no feature gate at all. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| FUT-GAP-05 | Registry says evidence planned; the baseline artifact says executable and complete. Same disagreement as `CAP-HTTP-COMPRESSION`, so it is systemic. | `asupersync-dep-p1-foundations-upksjk.5.2` |
| FUT-GAP-06 | The manifest comment describes the dependency as "used by web handler adapter shims" — true for two of six sites, omitting the Stream impls, the router executor and the signal listeners. | `asupersync-d24mms.6.1` |
| FUT-GAP-07 | The ATP SDK types are the crate's only user of the ecosystem trait, with no adapter to the owned one. That inconsistency *is* the public leakage. | `asupersync-d24mms.6` |

## Invariant impact checklist

- [x] Public ecosystem `Stream` impls preserved.
- [x] Owned `Stream` surface stays futures-lite-free.
- [x] Two-stage panic containment preserved.
- [x] `Router::handle` stays synchronous and runtime-free.
- [x] Signal listeners stay runtime-independent.
- [x] Test executor stays universally available.
- [x] No implicit executor introduced.
- [x] Full consumed helper surface recorded, not the plan's partial list.
- [x] No compatibility shim introduced.
- [x] No root export changes.

## Evidence

Evidence state is `BASELINE_PLANNED`. Owners: `asupersync-d24mms.6.1`
(baseline), `.6.5` (unit), `.6.10` (E2E). Scenarios `public_stream_consumer`,
`stream_cancel_backpressure`, `test_block_on`.

The first required class is the one the bead names: **classify every reference by
Cargo-built feature profile**, not by filename. After that, the two gating pieces
are tests for the public ecosystem `Stream` impls (FUT-GAP-02) and a downstream
fixture bounded on the ecosystem trait (FUT-GAP-03) — without both, a cutover
cannot see the breakage it would cause.

## Rollback

Triggered by any downstream that can no longer treat `AtpWriter`/`AtpReader` as
an ecosystem `Stream`, any lost helper, any change in wake/parking behavior,
reentrancy, polling fairness or panic propagation, any `Router::handle` that
begins requiring an ambient runtime, or any starvable signal listener.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that the public ecosystem `Stream` impls
behave correctly, that an owned helper layer could match wake, parking,
reentrancy, fairness or panic semantics, that the migration is mechanically safe,
that performance is unchanged, or that futures-lite may be removed. It also does
not certify the capability registry's source-owner row, feature list or evidence
state, which FUT-GAP-01, -04 and -05 record as incorrect.
