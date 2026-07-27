# LZ4 terminal KEEP signoff

Bead: `asupersync-0h6myr.4.5`
Capability: `CAP-TRACE-LZ4`
Artifact: `artifacts/lz4_final_signoff_v1.json`
Scenario: `dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd`

The terminal verdict is `KEEP_INCUMBENT_NO_CUTOVER`. This closes the trace LZ4
replacement experiment with a durable, fail-closed decision. It does not
authorize a production, manifest, feature, public-surface, format, or oracle
cutover.

## Decision

| Surface | Verdict | Reason |
| --- | --- | --- |
| Trace production codec | `KEEP lz4_flex 0.14.0` | The owned codec passed scoped correctness evidence but missed the named-host performance gate. |
| Persisted `ASUPERTRACE` bytes | `KEEP` | A4 proved cross-decoding without changing framing, flags, checksums, chunks, migration, or trailing-data acceptance. |
| Root normal dependency edge | `KEEP` | `trace-compression` still selects the incumbent production path. |
| Root development edge | `KEEP` | Tests and differential evidence still require the incumbent oracle. |
| Excluded fuzz-workspace edge | `KEEP =0.14.0` | The current-version differential target remains part of the retained evidence. |
| Owned block codec | `KEEP_SHADOW_ONLY` | It remains private and selectable only through the `test-internals` integration harness. |
| ATP LZ4 consumers | `OUT_OF_SCOPE_KEEP` | Five production call sites belong to the ATP/HTTP compression campaign and independently prevent dependency exit. |

Every production `TraceWriter`, `TraceReader`, iterator, migration, and CLI
journey continues through `Lz4Codec::Incumbent`. The owned enum branch and
integration harness exist only when both `trace-compression` and
`test-internals` are enabled.

## Evidence join

The terminal packet joins five closed prerequisites:

- A1 (`asupersync-0h6myr.4.1`): source, API, format, dependency, consumer,
  resource, evidence-gap, and cutover-authority inventory;
- A2 (`asupersync-0h6myr.4.2`): strictly safe, finite, size-prepended owned
  block encoder/decoder with classified resource errors;
- A3 (`asupersync-0h6myr.4.3`): six independent valid vectors, seventeen
  malformed vectors, four budget vectors, 256 property cases, current-version
  differential checks, and a bounded execution receipt;
- A4 (`asupersync-0h6myr.4.4`): retained v2/v3 artifacts, cross-decode,
  migration, deterministic replay, CLI journeys, malformed/limit behavior,
  interrupted-writer recovery, and the named-host measurement;
- typed-format A7 (`asupersync-5z2scg.3.7`): the cross-phase published-v0.3.9
  migration/replay/CLI/rollback prerequisite.

The A4 committed no-overlay dependency-sovereignty run passed all three
canonical scenarios:

- `lz4_trace_replay`
- `lz4_cross_version_artifact`
- `lz4_malformed_limits`

The terminal aggregate reruns the A1, A3, A4, and A5 contracts after a sparse
`--no-default-features --features trace-compression` check.

## Performance gate

The authoritative A4 receipt records 64 iterations over 95,887 canonical
event-frame bytes on RCH worker `vmi1264463`, an AMD EPYC host:

| Observation | Incumbent | Owned | Owned delta |
| --- | ---: | ---: | ---: |
| Encoded bytes | 29,688 | 28,953 | -2.476% |
| Encode elapsed | 479,433,053 ns | 720,550,247 ns | +50.292% |
| Decode elapsed | 95,060,587 ns | 195,354,661 ns | +105.505% |
| Compressed plus decoded block bytes | 125,575 | 124,840 | -0.585% |

This is a bounded test-profile comparison, not a portable benchmark. It has no
allocation-count instrumentation and its process `VmHWM` is not per-operation
RSS. The substantial elapsed-time regressions fail the cutover gate; the
smaller encoded block is insufficient to produce a GO verdict.

## Gap, graph, and oracle disposition

`LZ4-GAP-04` is closed by the block-only format freeze. A3 closes the
current-version and byte-corpus gaps (`LZ4-GAP-05` and `LZ4-GAP-06`). A4
closes the retained corpus and canonical-scenario gaps (`LZ4-GAP-07` and
`LZ4-GAP-08`).

The following remain explicit KEEP blockers:

- `LZ4-GAP-01`: public Lz4 level is not applied;
- `LZ4-GAP-02`: the documented Auto threshold is not used;
- `LZ4-GAP-03`: persisted byte `1` loses level and Auto intent;
- `LZ4-GAP-09`: block bytes were measured, but allocations and portable RSS
  were not;
- `LZ4-GAP-10`: five ATP production consumers remain outside the trace
  capability;
- `LZ4-GAP-11`: ATP expected-size checks remain after decode allocation;
- the A4 result is one named-host test-profile observation rather than an
  accepted cross-host statistical benchmark.

The live capability registry and cutover policy already say
`KEEP_UNTIL_PARITY`, `KEEP_INCUMBENT`, and
`dependency_exit_allowed: false`. The root normal, root development, and
excluded fuzz-workspace edges remain required. The incumbent also remains the
differential oracle (`KEEP_INCUMBENT_ORACLE`). A successful owned round trip
cannot retire the oracle that defines cross-implementation agreement.

## Rollback

No dependency, source-default, feature, or artifact rollback is needed because
A5 makes no cutover. Existing files remain readable by the incumbent, and A4's
test-only selector can be removed independently without a persisted migration.

A future GO proposal must be a new serialized terminal decision. It must
resolve every KEEP blocker, rerun fresh source/graph/oracle inventories, meet
an accepted performance and resource gate, cover every production consumer,
and retain a tested rollback path. It may not reinterpret this receipt as
latent permission for a partial switch.

## Canonical validation

Focused terminal contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/lz4_final_signoff_v1.json \
  --overlay-path docs/lz4_final_signoff.md \
  --overlay-path docs/lz4_surface_artifact_inventory.md \
  --overlay-path tests/lz4_final_signoff_contract.rs \
  --overlay-path scripts/run_dependency_sovereignty_e2e.sh \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_lz4_a5_signoff" \
  cargo test -p asupersync --test lz4_final_signoff_contract -- --nocapture
```

After committing the exact source state, run the canonical aggregate:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd
```

The runner requires remote execution and uses clean `HEAD` with no overlay. It
retains summary, scenario, validation-stage, environment, artifact-manifest,
and replay-command receipts under `target/e2e-results/dependency-sovereignty/`.

## No-claim boundary

This packet proves a checked terminal KEEP decision, child closure, exact
source-contract hashes, retained scoped codec/corpus/trace evidence, live
manifest/lock/default preservation, explicit gap/graph/oracle disposition,
rollback policy, sparse feature admission, and a canonical aggregate scenario.

It does not prove production cutover, dependency exit, ATP replacement, LZ4
frame/dictionary/block-checksum/content-checksum support, arbitrary historical
compatibility, allocator behavior, portable performance improvement, p50,
p95, or p999 latency, no regression, broad workspace health, release
readiness, live RCH fleet availability, or local Cargo fallback. It grants no
permission to delete files or discard retained rollback artifacts.
