# Swarm Pressure Preflight Report

`scripts/swarm_pressure_preflight_report.py` emits a deterministic, dry-run
operator report for deciding whether the shared-main checkout is ready to
dispatch proof lanes or release gates.

The report composes existing artifacts instead of replacing them:

- `artifacts/proof_lane_manifest_v1.json`
- `artifacts/proof_status_snapshot_v1.json`
- `artifacts/runtime_pressure_control_evidence_contract_v1.json`
- proof artifact freshness receipts from `scripts/proof_artifact_freshness_receipt.py`
- proof admission receipts from `scripts/proof_lane_admission_decision.py`
- dirty-tree ownership receipts from `scripts/dirty_tree_ownership_receipt.py`

It is non-mutating. It does not run Cargo, RCH, git mutations, Beads mutations,
Agent Mail sends, cache writes, staging, cleanup, or file deletion.

## Fixture Command

```bash
python3 scripts/swarm_pressure_preflight_report.py \
  --fixture tests/fixtures/swarm_pressure_preflight_report/mixed_pressure.json \
  --repo-path /data/projects/asupersync \
  --generated-at 2026-06-05T08:10:00Z \
  --output json
```

## E2E Logging Command

```bash
scripts/run_swarm_pressure_preflight_report_e2e.sh \
  --fixture tests/fixtures/swarm_pressure_preflight_report/mixed_pressure.json \
  --repo-path /data/projects/asupersync \
  --output-dir "${TMPDIR:-/tmp}/asupersync-swarm-pressure-preflight-e2e"
```

The E2E wrapper logs source artifact paths, versions, digests, proof-lane
envelope states, proof-status decisions, proof-freshness classifications,
admission decisions, pressure classes, dirty-tree blockers, aggregated blockers,
warnings, and the final operator decision.

For the full no-mock acceptance suite, run:

```bash
scripts/run_swarm_pressure_preflight_report_e2e.sh \
  --suite \
  --repo-path /data/projects/asupersync \
  --generated-at 2026-06-05T08:10:00Z \
  --output-dir "${TMPDIR:-/tmp}/asupersync-swarm-pressure-preflight-e2e"
```

The suite covers green workflow, stale exact-filter Cargo proofs that execute
zero tests, missing proof-lane resource envelopes, remote-required lanes
attempted through local fallback, peer-owned dirty-tree blockers, chaos
proof-lane pressure admission queueing, and combined multi-blocker output.

Each case logs its case id, fixture path, source artifact paths, proof-lane
commands, normalized resource envelope values, parsed exact-filter test counts,
dirty-path classifications, expected decision, actual decision, expected and
actual blocker/warning kinds, and the final blocker list. The wrapper also
writes `swarm_pressure_preflight_e2e_summary.json`, a stable JSON summary with
case-level pass/fail rows suitable for CI artifacts.

## Operator Runbook

Run preflight before dispatching broad proof lanes or release gates whenever the
tree has active agent work, pressure admission receipts, stale proof evidence, or
dirty paths from other agents. Treat the output as a fail-closed decision aid:
green means the configured artifacts are internally consistent, not that the
runtime behavior is newly proven.

| Situation | Report signal | Operator decision |
| --- | --- | --- |
| Green workflow | `decision=preflight-pass`, no blockers, no warnings | Release-gate dispatch is allowed if the canonical RCH proof lanes you cite are also fresh. |
| Stale exact filter | `stale-exact-filter-zero-tests` blocker and `exact_filter_executed_tests=0` | Do not cite the command. Verify the exact test name on current `main`, rerun through `RCH_REQUIRE_REMOTE=1 rch exec -- ...`, and replace the stale receipt. |
| Missing resource envelope | `missing-resource-envelope` blocker or `lane_states={"missing-envelope":1}` | Add or correct the proof-lane envelope before dispatch; a lane without finite remote resource bounds is not admissible. |
| Remote-required lane attempted locally | `unsafe-proof-command-prefix` or `unsafe-resource-envelope-policy` | Rewrite the manifest command to use `RCH_REQUIRE_REMOTE=1 rch exec --` and make the envelope require remote execution with local fallback disabled. |
| Peer-owned dirty files | `dirty-tree-release-blocker` with a dirty path owner | Wait for the owner to land or explicitly hand off the path. Do not stash, reset, delete, or stage peer work. |
| Remote admission denied | `proof-admission-blocked` with `proof_may_run_now=false` | Queue, split, or delay the proof lane until pressure and disk preconditions pass. |
| High or critical pressure warning | `runtime-pressure-high` warning | Prefer focused lanes and avoid starting broad checks until pressure drops or admission explicitly allows the lane. |
| Rerun-required proof status | `proof-rerun-required` warning | The report may allow attention-state triage, but the proof cannot be cited as fresh until its canonical RCH lane is rerun. |
| Combined blockers | Multiple blocker kinds in `top_blocker_kinds` | Fix every blocker kind. Clearing only one row does not make the report green. |

Project rules that matter most for this workflow:

- Work only on `main`; do not create branches, worktrees, scratch clones, or pull requests.
- Do not run destructive cleanup. Never delete, reset, clean, stash, or stage peer-owned paths to make a report look clean.
- Use Agent Mail and file reservations before editing shared paths.
- Run Cargo builds, tests, clippy, rustdoc, fuzzing, Lean, and other CPU-heavy proof lanes through RCH. A local shell wrapper is acceptable only when it is a lightweight fixture validator that does not run Cargo or allocate unbounded resources.
- A zero-test exact-filter receipt is diagnostic evidence of a stale command, not proof that the target behavior was tested.

## Golden Examples

The fixture suite keeps these examples synchronized with generated reports. Each
machine-readable row uses stable field names and the human-readable lines mirror
the E2E wrapper logs agents inspect during release prep.

### Machine-Readable Decisions

```json
{"case_id":"green-workflow","decision":"preflight-pass","ready_for_release_gate":true,"ready_to_dispatch_proof_lanes":true,"blocker_kinds":[],"warning_kinds":[]}
{"case_id":"stale-exact-filter-zero-tests","decision":"preflight-blocked","ready_for_release_gate":false,"ready_to_dispatch_proof_lanes":false,"blocker_kinds":["stale-exact-filter-zero-tests"],"warning_kinds":[]}
{"case_id":"missing-resource-envelope","decision":"preflight-blocked","ready_for_release_gate":false,"ready_to_dispatch_proof_lanes":false,"blocker_kinds":["missing-resource-envelope"],"warning_kinds":[]}
{"case_id":"remote-required-lane-attempted-locally","decision":"preflight-blocked","ready_for_release_gate":false,"ready_to_dispatch_proof_lanes":false,"blocker_kinds":["unsafe-proof-command-prefix","unsafe-resource-envelope-policy"],"warning_kinds":[]}
{"case_id":"peer-owned-dirty-tree","decision":"preflight-blocked","ready_for_release_gate":false,"ready_to_dispatch_proof_lanes":false,"blocker_kinds":["dirty-tree-release-blocker"],"warning_kinds":[]}
{"case_id":"chaos-pressure-scenario","decision":"preflight-blocked","ready_for_release_gate":false,"ready_to_dispatch_proof_lanes":false,"blocker_kinds":["proof-admission-blocked"],"warning_kinds":["proof-rerun-required","runtime-pressure-high"]}
{"case_id":"combined-multi-blocker","decision":"preflight-blocked","ready_for_release_gate":false,"ready_to_dispatch_proof_lanes":false,"blocker_kinds":["blocked-proof-status","disk-headroom-insufficient","proof-admission-blocked"],"warning_kinds":[]}
```

### Human-Readable E2E Lines

```text
[swarm-pressure-preflight:e2e] case=green-workflow final decision=preflight-pass ready_for_release_gate=true ready_to_dispatch_proof_lanes=true blockers=0 warnings=0 sources=3
[swarm-pressure-preflight:e2e] case=stale-exact-filter-zero-tests parsed_tests lane=lib-tests exact_filter=default_policy_no_csp_or_permissions executed=0
[swarm-pressure-preflight:e2e] case=stale-exact-filter-zero-tests blocker kind=stale-exact-filter-zero-tests source=proof_freshness_receipt lane=lib-tests claim= path= reason=exact-filter Cargo proof ran zero tests and cannot be cited
[swarm-pressure-preflight:e2e] case=missing-resource-envelope envelope lane_count=1 class_count=0 states={"missing-envelope":1} pressure={}
[swarm-pressure-preflight:e2e] case=remote-required-lane-attempted-locally blocker kind=unsafe-proof-command-prefix source=proof_lane_manifest lane=swarm-pressure-preflight-report-contract claim= path= reason=proof command does not start with the manifest remote-required prefix
[swarm-pressure-preflight:e2e] case=peer-owned-dirty-tree dirty_path path=src/net/tcp/stream.rs classification=peer-owned owner=SageWolf release_blocker=true reason=active peer reservation owns this dirty path
[swarm-pressure-preflight:e2e] case=chaos-pressure-scenario admission receipts=1 admissible=0 blocked=1 decisions={"queue":1}
[swarm-pressure-preflight:e2e] case=chaos-pressure-scenario warning kind=runtime-pressure-high source=proof_admission_receipt lane=proof-lane-pressure-chaos-e2e claim= reason=resource pressure class is critical
[swarm-pressure-preflight:e2e] case=combined-multi-blocker final decision=preflight-blocked ready_for_release_gate=false ready_to_dispatch_proof_lanes=false blockers=3 warnings=0 sources=4
```

### Decision Matrix

| Case ID | Decision | Release gate | Dispatch proof lanes | Blockers | Warnings |
| --- | --- | --- | --- | --- | --- |
| green-workflow | preflight-pass | true | true | [] | [] |
| stale-exact-filter-zero-tests | preflight-blocked | false | false | ["stale-exact-filter-zero-tests"] | [] |
| missing-resource-envelope | preflight-blocked | false | false | ["missing-resource-envelope"] | [] |
| remote-required-lane-attempted-locally | preflight-blocked | false | false | ["unsafe-proof-command-prefix","unsafe-resource-envelope-policy"] | [] |
| peer-owned-dirty-tree | preflight-blocked | false | false | ["dirty-tree-release-blocker"] | [] |
| chaos-pressure-scenario | preflight-blocked | false | false | ["proof-admission-blocked"] | ["proof-rerun-required","runtime-pressure-high"] |
| combined-multi-blocker | preflight-blocked | false | false | ["blocked-proof-status","disk-headroom-insufficient","proof-admission-blocked"] | [] |

## Decisions

`preflight-pass` means all configured source artifacts loaded and no blockers or
warnings were found.

`preflight-attention` means no blocker was found, but at least one warning still
requires operator attention before citing proof. Typical examples are
`rerun-required` proof evidence or high pressure telemetry that suggests queuing
broad lanes.

`preflight-blocked` means at least one configured source proves a preflight
blocker, such as a missing proof-lane resource envelope, exact-filter proof that
ran zero tests, blocked proof status, failed admission decision, insufficient
disk headroom, or peer-owned dirty-tree release blocker.

## Proof Boundary

This report is current-source diagnosis, not behavioral correctness proof. It
proves the configured artifacts were parsed and aggregated consistently. Cargo
checks, clippy, tests, rustdoc, fuzzing, formal Lean builds, and release gates
still require their canonical RCH proof lanes before any behavioral correctness
or release-readiness claim.

## Validation

Rust contract test:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_swarm_pressure_preflight_report" \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS="-D warnings -C debuginfo=0" \
  cargo test -p asupersync --test swarm_pressure_preflight_report_contract -- --nocapture
```

Formatting and syntax checks:

```bash
python3 -m py_compile scripts/swarm_pressure_preflight_report.py
bash -n scripts/run_swarm_pressure_preflight_report_e2e.sh
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_swarm_pressure_preflight_fmt" \
  cargo fmt --check
```
