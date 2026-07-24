# DEP-ADR-001: Preserve generic SerdeCodec JSON + MessagePack + Bincode while versioning owned artifacts

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.1`
- Capabilities: `CAP-SERDE-GENERIC`, `CAP-PERSISTED-TRACE-SNAPSHOT`
- Decision: `ADDITIVE_COEXISTENCE`; `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT` for the
  generic formats, `PRESERVE_AND_REPLACE_IF_PARITY` / `BLOCKED_PENDING_EVIDENCE`
  for the persisted artifacts
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §7 item 3.1, the §5
  `bincode-next` + `rmp-serde` disposition row, and the §7 Phase-5 "bincode+rmp
  exit together" sequencing

## Context

The Rev-3 plan asks to "replace public Bincode/MessagePack format variants with
JSON + explicit purpose-built codecs." Read as an API question that sounds
reasonable: trim a public enum, keep JSON, hand-write the few schemas the project
actually owns.

It is not an API question.

**MessagePack is the on-disk encoding of every trace file.** `src/trace/file.rs`
writes trace metadata and each event with `rmp_serde::to_vec` and reads them back
with `rmp_serde::from_slice`. **Bincode encodes distributed-snapshot vector
clocks**, under a pinned `bincode::config::legacy()` chosen for a deterministic
binary representation. Dropping either variant does not narrow an enum — it makes
the existing persisted corpus unreadable.

The generic surface is also real and unrestricted. `SerdeCodec` is a unit struct
with zero inherent methods; all behavior comes from two blanket impls bounded
only by `T: Serialize` and `T: DeserializeOwned` — no `'static`, no sealed
supertrait, no whitelist. `SerializationFormat` has **four** discriminants, not
three, and they are frozen on the wire as header bytes 1, 2, 3 and 255. The
fourth, `Custom`, is not dead: `SerdeCodec` rejects it precisely so a downstream
`Serializer`/`Deserializer` injected through `with_serializer` /
`with_deserializer` can own it.

Two facts cut the other way and are worth stating plainly, because they bound
what this ADR is defending:

- **The codec's error surface is already clean.** Every failure is stringified
  into an owned `SerializationError` or `DeserializationError`; the format crates
  appear only as closure parameter annotations. `SerdeCodec` could swap backends
  tomorrow with no public API change. What must be preserved is therefore the
  accepted *bytes* and data model, not a set of types.
- **The persisted trace path is not clean.** `ReplayTrace::to_bytes` returns
  `Result<Vec<u8>, rmp_serde::encode::Error>` — a format crate in a public return
  type — and `ReplayTraceError` holds a `#[from] rmp_serde::decode::Error`
  variant. There, replacing the encoder *is* a breaking API change.

The versioning the bead asks for partly exists and is preserved rather than
invented: a typed-symbol header version, a trace container version that is
forward-rejecting and backward-accepting, a replay schema version matched by
exact equality, a crash-pack current version *and* a minimum supported floor, and
a per-type name, version and schema hash in `TypeRegistry`.

## Decision

All four `SerializationFormat` discriminants stay. `SerdeCodec` stays generic.
Canonical or owned artifact schemas are **additive**.

1. Every discriminant **MUST** remain selectable, and its header byte value
   **MUST** remain 1, 2, 3 or 255. Removing, renumbering or reordering breaks
   both compilation and stored bytes.
2. `Custom` **MUST** be preserved along with `with_serializer` and
   `with_deserializer`. That trio is the downstream extension point.
3. The codec **MUST** stay generic over arbitrary `Serialize` /
   `DeserializeOwned` with no added bounds.
4. Every accepted persisted artifact **MUST** remain readable: trace files
   compressed and uncompressed, replay traces, crash packs, and distributed
   snapshots.
5. `bincode::config::legacy()` and the `bincode-next` aliasing **MUST NOT** change
   without treating it as a persisted-format change with corpus evidence.
6. Codec errors **MUST** stay owned and distinct — reason-carrying failures, a
   value-too-large variant reporting both size and maximum, and a dedicated
   unknown-format-byte error.
7. The version policies **MUST** be preserved deliberately: forward-rejecting
   container, exact-match replay schema, closed-range crash pack. Their asymmetry
   is intentional and may be changed only with evidence, not drifted into.
8. Canonical JSON or owned schemas **MAY** be adopted for *new* artifact writes
   only once a reader for the existing corpus exists.
9. Replacing either format crate **MUST NOT** be attempted before byte-level
   goldens exist for Bincode and MessagePack, because today nothing would detect
   a divergence (SER-GAP-03).

## Allowed tradeoffs

- Canonical JSON may become the preferred machine-generated form.
- The codec may swap backends internally without an API break, since its errors
  are owned — provided the accepted bytes are unchanged.
- The crash-pack model of a current version plus a minimum supported floor may be
  generalized to the other artifacts.

## Forbidden compromises

- Removing or renumbering any format discriminant, including `Custom`.
- Adding bounds to the codec traits that exclude currently-usable downstream types.
- Making any format crate optional or feature-gated.
- Changing the bincode config or alias as if it were an internal detail.
- Routing persisted reads through a new encoder without a corpus reader.
- Citing the `serialization-golden-harnesses` lanes as codec evidence — they do
  not reference the codec at all.

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| SER-GAP-01 | Registry `source_owners` for `CAP-SERDE-GENERIC` names `src/encoding.rs` and `src/decoding.rs` — both RaptorQ pipelines with zero serde tokens — and omits `src/types/typed_symbol.rs`. **Root cause identified:** `api_surface_snapshot.selectors` maps the `encoding::` and `decoding::` prefixes to this capability, apparently matching the *words*, while `types::` is mapped to API topology. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| SER-GAP-02 | `CAP-PERSISTED-TRACE-SNAPSHOT` names `src/trace/mod.rs`, a pure facade. Real owners are `file.rs`, `replay.rs`, `crashpack.rs`, `event.rs`, `compat.rs`, `streaming.rs`, `integrity.rs`; `src/lab/snapshot_restore.rs` and `src/distributed/snapshot.rs` are named nowhere. `CAP-TRACE-LZ4` has the identical facade error. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| SER-GAP-03 | **No byte-level golden exists for Bincode or MessagePack.** The format tests assert round-trip only; the one frozen serialization golden covers JSON. | `asupersync-5z2scg.3.6` |
| SER-GAP-04 | The persisted trace error surface exposes rmp-serde directly, including in a public return type. | `asupersync-5z2scg.3.3` |
| SER-GAP-05 | No migration reader exists for any persisted artifact — only version rejection. | `asupersync-5z2scg.3.7` |
| SER-GAP-06 | The `bincode-next` alias and the `config::legacy()` pin are recorded nowhere but the call sites. | `asupersync-5z2scg.3.1` |
| SER-GAP-07 | The lab snapshot integrity hash is computed over `serde_json` output, so changing the JSON encoder silently invalidates every stored `content_hash` — a hazard no format test would catch. | `asupersync-5z2scg.3.3` |
| SER-GAP-08 | `artifacts/api_surface_map_v1.json` contains **zero** codec symbols, so the generic surface is invisible to API drift detection. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| SER-GAP-09 | `artifacts/dependency_safety_taxonomy_v1.json` still carries the superseded removal framing and now contradicts this ADR. | `asupersync-dep-p1-foundations-upksjk.5.1` |

Four of these belong to artifacts owned elsewhere. SER-GAP-01, -02 and -08 are
filed as `asupersync-dvgpji`; this ADR does not certify those rows.

## Invariant impact checklist

- [x] All four format discriminants and their wire bytes preserved.
- [x] Codec genericity preserved with no added bounds.
- [x] Custom codec injection points preserved.
- [x] All accepted persisted artifacts remain readable.
- [x] The bincode legacy dialect and alias are frozen as contract.
- [x] Codec errors stay owned and distinct.
- [x] Version policies preserved, including their deliberate asymmetry.
- [x] Resource bounds on untrusted persisted input preserved.
- [x] No compatibility shim or deprecated alias introduced.
- [x] No root export changes, so `artifacts/api_surface_map_v1.json` is untouched.

## Evidence

Evidence state is `BASELINE_PLANNED`: the corpus is specified, not executed.

- Baseline `asupersync-5z2scg.3.1`; unit `asupersync-5z2scg.3.6`; E2E
  `asupersync-5z2scg.3.7`
- Scenarios: `generic_serde_downstream`, `cross_version_artifact`,
  `trace_snapshot_migration`, `trace_cli_replay`, `artifact_rollback`

The standalone consumer fixture already carries the generic contract: it builds
outside the workspace with only `serde` as its own dependency, round-trips a
boundary fixture (extreme integers, an empty-string map key, non-ASCII text, raw
bytes) through all three real formats, and asserts that `Custom` is rejected and
that the codec stays usable after an error. The load-bearing missing piece is
byte goldens for the two binary formats.

## Rollback

Triggered by any previously written artifact that stops loading, any removed or
renumbered discriminant, any loss of the injection points, any change to the
bincode config or a container magic or version, any coarsened codec error, any
changed lab snapshot content hash, or any tightened bound that rejects an
existing artifact. Rollback removes the additive owned-schema path rather than
restoring a deleted format.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that the persisted corpus still loads,
that byte stability holds across format-crate versions, that an owned serializer
could cover the Serde data model, that migration readers are feasible, that
performance is unchanged, or that any format dependency may be removed. It also
does not certify the capability registry's source-owner rows, the api surface
map, or the dependency safety taxonomy, which SER-GAP-01, -02, -08 and -09 record
as incorrect or superseded for these capabilities.
