# Owned UTC formatter foundation

- Bead: `asupersync-d24mms.4`
- Capability: `CAP-TIME-UTC-RFC3339`
- Governing decision: `DEP-ADR-011`
- State: `KEEP_PENDING_SPARSE_GRAPH_AND_LEDGER_PROOF`
- Machine packet: [`artifacts/time_utc_rfc3339_foundation_v1.json`](../artifacts/time_utc_rfc3339_foundation_v1.json)
- Focused contract: [`tests/time_utc_rfc3339_foundation_contract.rs`](../tests/time_utc_rfc3339_foundation_contract.rs)

## Outcome

The trace-inspection CLI now formats its existing nonzero `u64` Unix-nanosecond
stamp through an owned, deterministic library function:
`asupersync::time::format_unix_nanos_rfc3339`. The CLI still treats a recorded
value of zero as “timestamp absent,” so existing deterministic traces continue
to omit `created_at` in JSON and the `Created:` line in human output.

This is a bounded source checkpoint, not dependency exit. The optional `time`
edge remains in the `cli` feature while the broader evidence required by
`DEP-ADR-011` is incomplete. The bead therefore remains open.

## Formatter contract

The owned formatter accepts every `u64` count of nanoseconds since the Unix
epoch. That finite type domain maps to UTC years `1970..=2554`.

- Calendar arithmetic is proleptic Gregorian with the 4/100/400-year rules.
- Output uses an uppercase `Z`.
- Whole seconds omit the fractional component.
- Nonzero fractions preserve the exact nanosecond value and remove trailing
  zeroes.
- The formatter itself maps zero to `1970-01-01T00:00:00Z`; the CLI owns its
  separate zero-as-absence policy.
- Formatting reads no clock and has no runtime scheduling role.

The fixed corpus covers the epoch, one nanosecond, fractional trimming, the year
2000 leap day, the year 2100 non-leap boundary, a nine-digit fraction, and
`u64::MAX`.

## CLI journey

The focused contract writes a deterministic empty trace with
`recorded_at = 1582979696123456789` and runs the real binary in compact JSON and
human modes. It checks the complete stdout bytes, including:

```text
2020-02-29T12:34:56.123456789Z
Created: 2020-02-29T12:34:56.123456789Z
```

A second trace uses `recorded_at = 0` and checks the complete JSON and human
payloads with the timestamp field absent according to each output format. The
same finite formatter corpus is compared byte-for-byte with the retained
incumbent formatter while that dependency remains available.

The registered scenario is:

```bash
RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8
```

It selects the stable integration-test function
`dep_sovereignty_asupersync_d24mms_4_b6e90e93b1e8`.

It runs one focused integration-test function with the `cli` feature through a
clean-`HEAD` RCH invocation and does not authorize local Cargo fallback.

## Deferred work and no-claim boundary

This checkpoint does not define negative Unix timestamps, timestamp parsing,
offset conversion, a time-zone database, or leap-second representation. It
does not migrate chrono-backed public fields or persisted representations. It
does not change the ATP or JetStream formatter behavior, remove `time` or
`chrono`, establish the complete sparse dependency graph, refresh the marginal
ledger, or establish broad workspace health.

Those surfaces remain governed by `DEP-ADR-011` and its later evidence gates.
