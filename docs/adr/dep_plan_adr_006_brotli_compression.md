# DEP-ADR-006: Preserve Brotli RFC 7932 capability; KEEP incumbent until a full owned parity campaign passes

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.6`
- Capability: `CAP-HTTP-COMPRESSION`
- Decision: `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §5 `brotli` row and
  §7 Phase-3 item 3.6

## Context

The owner directive here was already resolved before this ADR: the plan's own
`brotli` row records the verdict flipping from REMOVE to *"Until then: KEEP"*,
having recognised that Brotli is a real public HTTP compressor and decompressor
and an ATP manifest capability. So this ADR is not re-opening the question. Its
job, per the bead, is to stop the DEFLATE work from treating Brotli as optional
cleanup — and to record the scope a future parity campaign would actually face.

The source read produced two corrections worth having.

**The registry names the wrong file.** `source_owners` lists
`src/web/compress.rs` and `Cargo.toml`. The real codec is
`src/http/compress.rs`, which holds every `brotli::` and `flate2::` call, the
`ContentEncoding` enum, the negotiation algorithm, the codec traits, and the
entire bomb-bound enforcement. The named middleware's only Brotli references sit
inside its `#[cfg(test)]` module; its production code contains none, because it
delegates. A baseline built from that row would inventory a delegating wrapper
and miss the implementation.

**There is a decoy second implementation.** `src/net/atp/compress/` contains a
`CompressionEngine`, an `AlgorithmRegistry` and a `BrotliAdapter` across four
files. It is orphaned: no module declares the directory, nothing outside it
references its types, and — decisively — its gzip function imports `flate2`
*without* a feature gate, which would be a hard compile error on a default build
if it were live. Anyone scoping a replacement from a grep would double-count code
that has never compiled.

Worth noting on the other side: the parts that would survive a codec swap are
already owned. Negotiation, the `Compressor`/`Decompressor` traits, the size
bounds and the BREACH sensitivity policy are all dependency-free.

## Decision

`brotli` and `flate2` stay, at `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`.

1. All four content codings — identity, gzip (including the `x-gzip` alias),
   deflate, Brotli — **MUST** remain supported and negotiable.
2. The negotiation rules **MUST** be preserved exactly: case-insensitive `q`,
   out-of-range or non-finite q-values dropping the entry, missing `q` defaulting
   to 1.0, the RFC 9110 identity default, a non-zero wildcard *not* lowering that
   default, and ties breaking by **server preference order**.
3. The default preference order (Brotli, gzip, deflate, identity) is observable
   behavior via the tie-break rule and **MUST NOT** be reordered silently.
4. Size bounds **MUST** keep refusing before allocation, in both directions, and
   `None` **MUST** remain expressible as unlimited.
5. Codec poisoning **MUST** be preserved: after an error a decompressor never
   resumes and never presents partial output as complete.
6. The BREACH sensitivity policy **MUST** remain, and remain default-on.
7. Building **without** the `compression` feature **MUST** continue to negotiate
   and serve identity rather than fail.
8. Brotli **MUST NOT** be replaced except through a separate security-sensitive
   codec epic. A DEFLATE parity result confers nothing about Brotli.
9. `src/net/atp/compress/` **MUST NOT** be counted as an implementation, as
   coverage, or as replacement scope while it remains uncompiled.

## Allowed tradeoffs

- New codings may be added.
- The two middlewares may converge, provided the stronger policy wins.
- Brotli quality and window defaults may be tuned with evidence.

## Forbidden compromises

- Dropping any coding, or narrowing negotiation.
- Weakening the size bounds, the poisoning behavior, or the sensitivity default.
- Letting a codec crate type into a public signature — note `brotli` currently
  leaks none, while `flate2::Compression` already appears in the level-setting
  constructors.
- Bundling the Brotli campaign into the DEFLATE campaign.
- Citing the orphaned ATP compression directory as partial work.

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| CMP-GAP-01 | Registry `source_owners` names `src/web/compress.rs` (Brotli refs only in its test module) and `Cargo.toml`, omitting `src/http/compress.rs` — the entire codec — plus `src/web/middleware.rs`, `src/atp/manifest.rs` and `src/grpc/codec.rs`. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| CMP-GAP-02 | `src/net/atp/compress/` is orphaned and has never compiled; its gzip path imports `flate2` with no feature gate. | `asupersync-0h6myr.5.1` |
| CMP-GAP-03 | The registry's baseline command names a `web_compression` scenario, but no compression scenario is registered in the e2e runner. | `asupersync-0h6myr.5.7` |
| CMP-GAP-04 | **Two public types named `CompressionMiddleware`** with different behavior — only `web::compress` has the BREACH guard and the 406 path; `web::middleware` silently returns uncompressed. | `asupersync-0h6myr.5.6` |
| CMP-GAP-05 | `flate2::Compression` appears in public signatures; `brotli` exposes no type at all. The two codecs have asymmetric replacement cost. | `asupersync-0h6myr.5.1` |
| CMP-GAP-06 | No Brotli-specific fuzz target; it is fuzzed only inside the shared HTTP decompression target. | `asupersync-0h6myr.5.6` |
| CMP-GAP-07 | The capability registry says evidence is planned while the capability baseline artifact says executable and complete. The same disagreement affects `CAP-FUTURES-STREAMS`, so it is systemic. | `asupersync-dep-p1-foundations-upksjk.5.2` |

## Invariant impact checklist

- [x] All four codings preserved and negotiable.
- [x] Negotiation rules, including the RFC 9110 identity semantics, preserved.
- [x] Default preference order preserved.
- [x] Bomb bounds refuse before allocation, both directions.
- [x] Codec poisoning preserved.
- [x] BREACH sensitivity policy preserved and default-on.
- [x] Feature-off builds still negotiate and serve identity.
- [x] No codec crate type newly exposed.
- [x] No compatibility shim introduced.
- [x] No root export changes.

## Evidence

Evidence state is `BASELINE_PLANNED`. Owners: `asupersync-0h6myr.5.1`
(baseline), `.5.6` (unit), `.5.7` (E2E). Scenarios `web_compression`,
`compression_cross_implementation`, `compression_cancel_bomb`.

Two preconditions are specific to this capability: **real cross-implementation
interop** with at least one independent Brotli producer and one consumer, and a
**dedicated Brotli malformed/bomb corpus**, which CMP-GAP-06 records as absent.
For a security-sensitive codec whose replacement would be a new attack surface,
those are preconditions rather than refinements.

## Rollback

Triggered by any dropped coding, negotiation change, weakened bound or
sensitivity rule, lost poisoning behavior, newly exposed codec type, or any peer
advertising `br` that stops receiving Brotli. Because the decision is KEEP,
rollback means abandoning the replacement attempt.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that the codecs are byte-compatible with
any reference implementation, that cross-implementation interoperability has been
demonstrated, that the bomb bounds have been fuzzed adequately, that an owned RFC
7932 codec is feasible, that performance is unchanged, or that either codec
dependency may be removed. It also does not certify the capability registry's
source-owner row, which CMP-GAP-01 records as incorrect.
