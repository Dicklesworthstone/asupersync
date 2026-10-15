# Third-Wave Swarm Operator Runbook

This runbook is the operator-facing signoff surface for `asupersync-ol11aa.9`.
It composes the third-wave guardrails into one fail-closed workflow for shared
`main` work, long RCH proof lanes, Agent Mail coordination, and closeout
evidence. It does not replace live tracker, Git, Agent Mail, reservation, or
RCH state.

## Canonical Files

- Runbook: `docs/third_wave_swarm_operator_runbook.md`
- Runbook contract: `tests/third_wave_swarm_operator_runbook_contract.rs`
- Combined e2e contract: `tests/third_wave_swarm_guardrail_e2e_contract.rs`
- Combined e2e fixture: `artifacts/third_wave_swarm_guardrail_e2e_contract_v1.json`
- Combined e2e runner: `scripts/run_third_wave_swarm_guardrail_e2e.sh`
- Combined e2e helper: `scripts/third_wave_swarm_guardrail_e2e.py`

## Preflight

1. Confirm the workspace is on `main`.
2. Fetch before committing or pushing:

```bash
git fetch origin main
git rev-list --left-right --count HEAD...origin/main
```

3. Treat any dirty file outside the claimed lane as peer dirt until proven
   otherwise. Do not stage peer dirt. If `.beads/issues.jsonl` contains both
   your tracker row and another agent row, stage only your row.
4. Check Agent Mail before editing. Acknowledge every `ack_required` message
   that applies to the lane.
5. Reserve exact files with `file_reservation_paths` before editing. Use
   `renew_file_reservations` for long RCH lanes, and call
   `release_file_reservations` during closeout.

## Guardrail Commands

Run the stale in-progress reaper in report mode before reclaiming work that may
belong to a dead agent:

```bash
python3 scripts/stale_in_progress_bead_reaper.py \
  --fixture artifacts/stale_in_progress_bead_reaper_contract_v1.json \
  --mode report \
  --output json
```

The operator must fail closed unless the report names a stale candidate, excludes live agents, and
does not propose a mutation without explicit apply mode.

Use the br/bv graph drift report when `br ready` and `bv --robot-next` disagree:

```bash
python3 scripts/tracker_graph_drift_report.py \
  --fixture artifacts/tracker_graph_drift_report_contract_v1.json \
  --output json
```

Do not treat empty bv output as no work until br ready, bv next, and bv triage
are current and consistent.

Use the reservation lease watchdog before a long RCH proof lane:

```bash
python3 scripts/reservation_lease_watchdog.py \
  --fixture artifacts/reservation_lease_watchdog_contract_v1.json \
  --mode dry-run \
  --output json
```

Fail closed on expired reservation, missing reservation, conflicting
reservation, missing command provenance, or renewal failure.

Use the lane closeout receipt before claiming a lane is finished:

```bash
python3 scripts/swarm_lane_closeout_receipt.py \
  --fixture artifacts/swarm_lane_closeout_receipt_contract_v1.json \
  --output json
```

The receipt must reject failed proof cited green, missing remote worker
evidence, zero-test exact filters, expired reservation gaps, unverified pushed refs,
and unclassified dirty tree state.

Use the RCH quiet-phase receipt while waiting on long remote lanes:

```bash
python3 scripts/rch_quiet_phase_receipt.py \
  --fixture artifacts/rch_quiet_phase_receipt_contract_v1.json \
  --output json
```

Quiet progress is liveness evidence only. It is not success. No local fallback
is admissible for remote-required validation.

Run the combined e2e proof lane when preparing a handoff or release-prep
operator report:

```bash
bash scripts/run_third_wave_swarm_guardrail_e2e.sh \
  --run-id release-prep
```

The combined e2e lane is tied to `asupersync-ol11aa.9.6`. It proves that the
guardrail fixtures and docs markers stay aligned; it is not a broad workspace
health proof and not a release publish proof.

## Validation

For a source or contract change in this lane, use remote-required RCH for
focused Rust validation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_third_wave_swarm_operator_runbook" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test third_wave_swarm_operator_runbook_contract -- --nocapture
```

After substantive code or contract-test changes, run the broad gates:

```bash
rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_fmt_check" cargo fmt --check
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_check_all_targets" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo check --all-targets
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_clippy_all_targets" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo clippy --all-targets -- -D warnings
```

Never cite local Cargo fallback as proof for these lanes. Never cite a zero-test exact filter as green evidence.

## Closeout Checklist

Before closing a bead:

1. Confirm the bead is claimed by the current Agent Mail identity.
2. Confirm the committed files match the reservation set.
3. Confirm every validation command cited in the close reason has a current
   exit-zero result and, for tests, nonzero executed tests.
4. Commit only the lane files. Leave peer dirt unstaged.
5. Push `main`:

```bash
git push origin main
```

6. Mirror the legacy ref:

```bash
git push origin main:master
```

7. Verify the pushed refs:

```bash
git rev-parse HEAD
git rev-parse origin/main
git rev-parse origin/master
git rev-list --left-right --count HEAD...origin/main
```

8. Release reservations with `release_file_reservations`.
9. Send an Agent Mail closeout in the same thread. Include the commit, pushed
   refs, validation commands, reservation release, and remaining peer dirt.

## Fail-Closed Cases

Stop and repair evidence before closeout when any of these are true:

- stale proof evidence or a stale graph snapshot is being cited as current
- local fallback appeared in a remote-required lane
- a zero-test exact filter is being cited as proof
- RCH worker identity or remote exit evidence is missing
- artifact retrieval is incomplete and not separately classified
- a reservation expired during validation
- a required Agent Mail `ack_required` message is unhandled
- the push or legacy mirror ref is unverified
- owned dirty files remain uncommitted
- peer dirt is staged or unclassified

## Non-Claims

This runbook does not prove runtime correctness, does not certify release
readiness, does not replace the proof-lane manifest, and does not authorize
branches, worktrees, peer-file edits, or local fallback. It is an operator
workflow contract for the third-wave guardrail surfaces.
