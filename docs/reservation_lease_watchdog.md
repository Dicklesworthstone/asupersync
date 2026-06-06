# Reservation Lease Watchdog

The reservation lease watchdog turns explicit Agent Mail reservation snapshots,
proof-lane envelopes, command provenance, current time, and expected remaining
RCH duration into a deterministic reservation coverage report. Use it before or
during long all-target proof lanes when a lease may expire before validation
finishes.

The helper is read-only. It does not query Agent Mail, run Cargo, inspect Git,
mutate `.beads/issues.jsonl`, or write artifacts. Renewal is represented as an
explicit plan and result evidence in the report; a plan by itself is not a
renewal receipt.

## Contract Surface

- Helper: `scripts/reservation_lease_watchdog.py`
- Contract artifact: `artifacts/reservation_lease_watchdog_contract_v1.json`
- Rust contract test: `tests/reservation_lease_watchdog_contract.rs`
- Report schema: `reservation-lease-watchdog-report-v1`

## Classifications

- `sufficient-ttl`: every expected path has an active exclusive reservation
  held by the lane agent, and the shortest TTL covers expected remaining proof
  time plus the renewal margin.
- `renew-needed`: every expected path is covered now, but at least one lease
  expires before the expected remaining proof interval plus margin.
- `expired-reservation`: an expected owned reservation is already expired or has
  an invalid expiry timestamp.
- `missing-reservation`: at least one expected owned path lacks an active
  exclusive reservation held by the lane agent.
- `conflicting-reservation`: an active exclusive peer reservation overlaps an
  expected path.
- `renewal-failure`: renewal was required but the explicit renewal result is
  missing or failed.
- `command-provenance-missing`: the proof command, envelope, source
  fingerprint, or remote/no-local-fallback evidence is missing.

## Usage

Emit deterministic dry-run JSON from the checked contract fixture:

```bash
python3 scripts/reservation_lease_watchdog.py \
  --fixture artifacts/reservation_lease_watchdog_contract_v1.json \
  --generated-at 2026-06-06T16:05:00Z \
  --mode dry-run \
  --output json
```

Emit Markdown for Agent Mail or release handoff:

```bash
python3 scripts/reservation_lease_watchdog.py \
  --fixture artifacts/reservation_lease_watchdog_contract_v1.json \
  --generated-at 2026-06-06T16:05:00Z \
  --mode dry-run \
  --output markdown
```

Emit simulated long-lane logs:

```bash
python3 scripts/reservation_lease_watchdog.py \
  --fixture artifacts/reservation_lease_watchdog_contract_v1.json \
  --generated-at 2026-06-06T16:05:00Z \
  --mode renew \
  --output log
```

Focused validation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_reservation_lease_watchdog" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test reservation_lease_watchdog_contract -- --nocapture
```

## Renewal Evidence

Dry-run mode emits a renewal plan only. A renewal plan lists the paths, TTL, lane
agent, and reason that must be renewed through the live Agent Mail reservation
tooling. Closeout evidence must record the explicit renewal result. If the
watchdog is run in `--mode renew` and renewal was needed but no explicit result
is present in the fixture, the row fails closed as `renewal-failure`.

## Shared-Main Use

Use the watchdog after claiming the bead and reserving exact files, before
starting a long RCH lane, and again if the proof is still running near the
renewal threshold. If it reports `renew-needed`, renew the live reservations
before continuing or stop with the blocker. If it reports expired, missing, or
conflicting reservations, do not cite the proof interval as covered.

## Non-Claims

This watchdog does not prove source correctness, does not override live Agent
Mail reservation state, does not authorize branches or worktrees, and does not
make local Cargo fallback acceptable proof. It only makes reservation coverage
and renewal evidence explicit for long shared-main proof lanes.
