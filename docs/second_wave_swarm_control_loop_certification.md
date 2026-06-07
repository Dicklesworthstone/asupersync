# Second-Wave Swarm Control-Loop Certification

This bundle is the operator signoff surface for `asupersync-ol11aa.8`. It
aggregates the second-wave child proofs for topology corpus, topology-aware
proof admission, SLO runtime brownout seams, brownout LabRuntime E2E receipts,
stale-proof debt graphing, failed-proof repro receipts, and reservation-aware
fallback work finding.

The certification is intentionally narrow. A green bundle means the second-wave
operator workflow is represented by current, remote-required, nonzero-test
receipts. It is not a release publish proof, not a performance benchmark, not a
substitute for broad check/clippy/test gates, not proof of RCH fleet
availability, and not evidence for unrelated source surfaces. In contract terms:
not a substitute for broad check/clippy/test gates.

## Canonical Files

- Contract artifact: `artifacts/second_wave_swarm_control_loop_certification_v1.json`
- Helper: `scripts/second_wave_swarm_control_loop_certification.py`
- E2E runner: `scripts/run_second_wave_swarm_control_loop_certification_e2e.sh`
- Contract test: `tests/second_wave_swarm_control_loop_certification_contract.rs`
- Operator docs: `docs/second_wave_swarm_control_loop_certification.md`

## Refresh Procedure

Regenerate the JSON report from the checked fixture:

```bash
python3 scripts/second_wave_swarm_control_loop_certification.py \
  --fixture artifacts/second_wave_swarm_control_loop_certification_v1.json \
  --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output json
```

Regenerate the Markdown operator summary:

```bash
python3 scripts/second_wave_swarm_control_loop_certification.py \
  --fixture artifacts/second_wave_swarm_control_loop_certification_v1.json \
  --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output markdown
```

Run the bounded E2E wrapper when preparing a large swarm operation or release
prep handoff:

```bash
bash scripts/run_second_wave_swarm_control_loop_certification_e2e.sh \
  --run-id release-prep
```

The wrapper writes only below
`target/second-wave-swarm-control-loop-certification/run_<id>/`: JSON report,
Markdown report, line-oriented log, and a summary JSON file. It does not run
proof commands or mutate tracker state.

## Required Child Evidence

| Child bead | Evidence | Required command shape |
| --- | --- | --- |
| `asupersync-ol11aa.1` | Large-host topology corpus | `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo test -p asupersync --test large_host_topology_corpus_contract ...` |
| `asupersync-ol11aa.2` | Topology-aware proof admission receipts | `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo test -p asupersync --test proof_lane_admission_decision_contract ...` |
| `asupersync-ol11aa.3` | SLO brownout runtime bridge | `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals runtime_slo_policy_bridge ...` |
| `asupersync-ol11aa.4` | SLO brownout LabRuntime E2E receipts | `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals runtime_slo_brownout_lab_e2e ...` |
| `asupersync-ol11aa.5` | Proof evidence debt graph | `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo test -p asupersync --test proof_evidence_debt_graph_contract ...` |
| `asupersync-ol11aa.6` | Proof lane failure repro receipts | `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo test -p asupersync --test proof_lane_failure_repro_receipt_contract ...` |
| `asupersync-ol11aa.7` | Reservation-aware fallback work finder | `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=... cargo test -p asupersync --test reservation_aware_fallback_work_finder_contract ...` |

## Green, Yellow, Red Semantics

Green rows have a closed child bead, a current receipt head, existing source
references, a remote-required RCH envelope, isolated `CARGO_TARGET_DIR`,
nonzero executed tests, no local fallback, and no advisory-only marker.

Yellow rows are scope limits or open blockers that do not invalidate the bundle
itself. The parent `asupersync-ol11aa` program still has open work such as
`asupersync-tuag6e`, so this certification does not close the parent epic.

Red rows are fail-closed rejection fixtures. The contract must continue to
reject stale heads, missing RCH remote-required envelopes, local fallback,
zero-test evidence, advisory-only evidence, and missing artifacts.

## Contract Proof

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_second_wave_swarm_control_loop_certification CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test second_wave_swarm_control_loop_certification_contract -- --nocapture
```
