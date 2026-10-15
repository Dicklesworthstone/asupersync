# doctor Operator Model Contract

## Scope

`asupersync doctor operator-model` emits the canonical operator personas, missions,
and deterministic decision-loop model for `doctor_asupersync` track 1.

This contract defines:

- stable persona identifiers and mission statements
- deterministic decision-loop definitions used by UI and orchestration layers
- deterministic information architecture (IA) and navigation topology
- global evidence requirements attached to every decision path
- validation invariants for schema consumers

## Command

```bash
asupersync doctor operator-model
```

## Output Schema

The command emits an `OperatorModelContract`.

```json
{
  "contract_version": "doctor-operator-model-v1",
  "personas": [
    {
      "id": "string",
      "label": "string",
      "mission": "string",
      "mission_success_signals": ["string"],
      "primary_views": ["string"],
      "default_decision_loop": "string",
      "high_stakes_decisions": [
        {
          "id": "string",
          "prompt": "string",
          "decision_loop": "string",
          "decision_step": "string",
          "required_evidence": ["string"]
        }
      ]
    }
  ],
  "decision_loops": [
    {
      "id": "string",
      "title": "string",
      "steps": [
        {
          "id": "string",
          "action": "string",
          "required_evidence": ["string"]
        }
      ]
    }
  ],
  "global_evidence_requirements": ["string"],
  "navigation_topology": {
    "version": "doctor-navigation-topology-v1",
    "entry_points": ["string"],
    "screens": [
      {
        "id": "string",
        "label": "string",
        "route": "string",
        "personas": ["string"],
        "primary_panels": ["string"],
        "focus_order": ["string"],
        "recovery_routes": ["string"]
      }
    ],
    "routes": [
      {
        "id": "string",
        "from_screen": "string",
        "to_screen": "string",
        "trigger": "string",
        "guard": "string",
        "outcome": "success|cancelled|failed"
      }
    ],
    "keyboard_bindings": [
      {
        "key": "string",
        "action": "string",
        "scope": "global|screen",
        "target_screen": "string|null",
        "target_panel": "string|null"
      }
    ],
    "route_events": [
      {
        "event": "string",
        "required_fields": ["string"]
      }
    ]
  }
}
```

`navigation_topology` is a deterministic IA layer mapped to the existing
screen/state transition model in `doctor-screen-engine-v1`.

## Contract Invariants

1. `contract_version` is non-empty and versioned.
2. `personas`, `decision_loops`, `global_evidence_requirements`, and `navigation_topology` are non-empty.
3. Persona IDs are unique.
4. Decision-loop IDs are unique.
5. Step IDs are unique within each loop.
6. Every persona references an existing `default_decision_loop`.
7. Every persona declares non-empty, lexically sorted, duplicate-free `mission_success_signals`.
8. Every persona declares non-empty `high_stakes_decisions` with unique decision IDs.
9. Every persona decision references an existing `decision_loop` + `decision_step`.
10. Persona decisions must use the persona's `default_decision_loop`.
11. Decision evidence keys must be non-empty, lexically sorted, duplicate-free, and map to either:
    - step-local evidence requirements, or
    - global evidence requirements.
12. `global_evidence_requirements` is lexically sorted and duplicate-free.
13. `navigation_topology.screens` is lexically ordered by `id`; each screen `id` exists in `doctor-screen-engine-v1`.
14. `navigation_topology.routes` references known screens only and must use deterministic `trigger`/`outcome` pairs.
15. `navigation_topology.keyboard_bindings` keys are unique within scope and stable across runs.
16. `navigation_topology.route_events` required fields are lexically sorted and include `correlation_id`, `screen_id`, `run_id`, and `trace_id`.

## Canonical IA and Navigation Topology (v1)

### Entry Points

- `bead_command_center` for backlog/triage workflows.
- `incident_console` for live-incident containment workflows.
- `gate_status_board` for release gate verification workflows.

### Screen Topology

| Screen ID | Route | Primary Personas | Mission Surface |
|---|---|---|---|
| `bead_command_center` | `/doctor/beads` | `conformance_engineer` | Work prioritization and dependency impact |
| `scenario_workbench` | `/doctor/scenarios` | `conformance_engineer` | Deterministic replay and scenario execution |
| `evidence_timeline` | `/doctor/evidence` | `conformance_engineer`, `runtime_operator` | Trace-linked causality and remediation deltas |
| `incident_console` | `/doctor/incidents` | `runtime_operator` | Active containment actions and stabilization |
| `runtime_health` | `/doctor/runtime` | `runtime_operator` | Live invariants, cancellation phase, obligation pressure |
| `replay_inspector` | `/doctor/replay` | `runtime_operator` | Replay-path verification and artifact drill-down |
| `gate_status_board` | `/doctor/gates` | `release_guardian` | Build/test/lint gate status and risk |
| `artifact_audit` | `/doctor/artifacts` | `release_guardian` | Artifact completeness, schema compliance, replayability |
| `decision_ledger` | `/doctor/ledger` | `release_guardian` | Signoff/hold rationale with evidence pointers |

### Deterministic Route Graph

```
bead_command_center -> scenario_workbench -> evidence_timeline -> bead_command_center
incident_console -> runtime_health -> replay_inspector -> incident_console
gate_status_board -> artifact_audit -> decision_ledger -> gate_status_board
evidence_timeline <-> incident_console
evidence_timeline <-> gate_status_board
```

Route graph policy:

- Intra-persona loops are primary paths and must always exist.
- Cross-persona hops are only allowed through evidence-bearing surfaces (`evidence_timeline`, `gate_status_board`, `incident_console`).
- Navigation state is deterministic and replayable using `(run_id, correlation_id, trace_id)`.

### Panel Focus Model

Each screen has three canonical panels in deterministic left-to-right focus order:

1. `context_panel` (scope, filters, active run/scenario)
2. `primary_panel` (findings, incidents, gate list, or replay artifacts)
3. `action_panel` (remediation or decision affordances)

Focus transitions:

- `tab` advances `context_panel -> primary_panel -> action_panel -> context_panel`.
- `shift+tab` reverses focus.
- `enter` executes focused action in `action_panel` only.
- `esc` cancels pending modal/action and returns focus to `context_panel`.

### Keyboard Navigation Contract (v1)

Global bindings:

- `g b`: go `bead_command_center`
- `g s`: go `scenario_workbench`
- `g e`: go `evidence_timeline`
- `g i`: go `incident_console`
- `g r`: go `runtime_health`
- `g p`: go `replay_inspector`
- `g t`: go `gate_status_board`
- `g a`: go `artifact_audit`
- `g d`: go `decision_ledger`
- `?`: open keymap help overlay (non-destructive)

Per-screen operational bindings:

- `r`: refresh (maps to `idle/ready -> loading`)
- `c`: cancellation request (maps `loading -> cancelled` when acknowledged)
- `x`: open deterministic replay/export actions

### Recovery Paths

Deterministic recovery must exist for each screen:

- `failed -> loading` via `retry`
- `cancelled -> idle` via `retry`
- `ready -> loading` via `refresh`

Cross-screen recovery:

- Any failed/cancelled screen can route to `evidence_timeline` with preserved `correlation_id`.
- `incident_console` failures route to `runtime_health` before returning to `incident_console`.
- `gate_status_board` failures route to `artifact_audit` for evidence completion before reattempting signoff flow.

## Structured Route Logging Contract

Every topology transition emits one deterministic route event.

Event taxonomy:

- `route_entered`
- `route_blocked`
- `focus_changed`
- `focus_invalid`
- `route_recovery_started`
- `route_recovery_completed`

Required event fields:

- `contract_version`
- `navigation_topology_version`
- `event`
- `correlation_id`
- `run_id`
- `trace_id`
- `screen_id`
- `from_state`
- `to_state`
- `trigger`
- `outcome_class`
- `focus_target`
- `latency_ms`

Logging constraints:

- Event ordering is stable by `(run_id, correlation_id, monotonic_event_index)`.
- `route_blocked` and `focus_invalid` must include `diagnostic_reason`.
- Recovery events must include `recovery_route_id` and `rerun_context`.

## Mission-to-IA Alignment Matrix

| Persona | Default Loop | Primary Route Cycle | Evidence Handoff |
|---|---|---|---|
| `conformance_engineer` | `triage_investigate_remediate` | `bead_command_center -> scenario_workbench -> evidence_timeline` | `evidence_timeline -> gate_status_board` |
| `runtime_operator` | `incident_containment` | `incident_console -> runtime_health -> replay_inspector` | `incident_console -> evidence_timeline` |
| `release_guardian` | `release_gate_verification` | `gate_status_board -> artifact_audit -> decision_ledger` | `gate_status_board -> evidence_timeline` |

## Baseline UX Acceptance Matrix (v0)

This section is the Track 1.6 baseline acceptance artifact. It defines core
journey assertions early so downstream implementation tracks can build against a
stable, deterministic contract before final signoff hardening (`asupersync-2b4jj.1.5`).

### Deterministic Identifier and Traceability Rules

- Journey IDs: `journey_<persona>_<loop>`
- Transition assertion IDs: `tx_<journey_id>_<two_digit_index>`
- Evidence assertion IDs: `ev_<journey_id>_<screen_id>_<topic>`
- IDs are lexical and stable across runs.

Each assertion must include traceability pointers:

- `screen_ref`: `doctor-screen-engine-v1` screen id
- `route_ref`: `navigation_topology.routes[].id`
- `decision_loop_ref`: `operator_model.decision_loops[].id`

### Core Journey Baseline

| Journey ID | Persona | Decision Loop Ref | Canonical Path | Mission Outcome |
|---|---|---|---|---|
| `journey_conformance_engineer_triage` | `conformance_engineer` | `triage_investigate_remediate` | `bead_command_center -> scenario_workbench -> evidence_timeline` | Deterministic issue triage with evidence handoff ready |
| `journey_runtime_operator_incident` | `runtime_operator` | `incident_containment` | `incident_console -> runtime_health -> replay_inspector -> incident_console` | Incident containment with replay-verifiable context |
| `journey_release_guardian_gate` | `release_guardian` | `release_gate_verification` | `gate_status_board -> artifact_audit -> decision_ledger -> gate_status_board` | Gate decision made with auditable evidence links |

### Transition Assertions (Baseline)

| Assertion ID | Journey ID | From -> To | Trigger | Expected Panel Focus | Traceability |
|---|---|---|---|---|---|
| `tx_journey_conformance_engineer_triage_01` | `journey_conformance_engineer_triage` | `bead_command_center -> scenario_workbench` | `open_scenario_workbench` | lands on `context_panel` then cycles `context -> primary -> action` | `screen_ref=scenario_workbench`, `route_ref=route_bead_command_center_to_scenario_workbench` |
| `tx_journey_conformance_engineer_triage_02` | `journey_conformance_engineer_triage` | `scenario_workbench -> evidence_timeline` | `open_evidence_timeline` | focus preserves panel order and returns `context_panel` on `esc` | `screen_ref=evidence_timeline`, `route_ref=route_scenario_workbench_to_evidence_timeline` |
| `tx_journey_conformance_engineer_triage_03` | `journey_conformance_engineer_triage` | `evidence_timeline -> bead_command_center` | `return_to_triage` | `action_panel` actions must be disabled until evidence context loaded | `screen_ref=bead_command_center`, `route_ref=route_evidence_timeline_to_bead_command_center` |
| `tx_journey_runtime_operator_incident_01` | `journey_runtime_operator_incident` | `incident_console -> runtime_health` | `inspect_runtime_health` | focus stays deterministic through refresh/retry | `screen_ref=runtime_health`, `route_ref=route_incident_console_to_runtime_health` |
| `tx_journey_runtime_operator_incident_02` | `journey_runtime_operator_incident` | `runtime_health -> replay_inspector` | `open_replay_inspector` | replay inspector opens with `context_panel` selected | `screen_ref=replay_inspector`, `route_ref=route_runtime_health_to_replay_inspector` |
| `tx_journey_runtime_operator_incident_03` | `journey_runtime_operator_incident` | `replay_inspector -> incident_console` | `return_to_incident_console` | selected incident context is restored (no orphan context) | `screen_ref=incident_console`, `route_ref=route_replay_inspector_to_incident_console` |
| `tx_journey_release_guardian_gate_01` | `journey_release_guardian_gate` | `gate_status_board -> artifact_audit` | `audit_artifacts` | `context_panel` must expose gate scope before action enablement | `screen_ref=artifact_audit`, `route_ref=route_gate_status_board_to_artifact_audit` |
| `tx_journey_release_guardian_gate_02` | `journey_release_guardian_gate` | `artifact_audit -> decision_ledger` | `next_stage` | focus may enter `action_panel` only after artifact completeness guard passes | `screen_ref=decision_ledger`, `route_ref=route_artifact_audit_to_decision_ledger` |
| `tx_journey_release_guardian_gate_03` | `journey_release_guardian_gate` | `decision_ledger -> gate_status_board` | `back_to_gates` | returns to previously selected gate row with stable ordering | `screen_ref=gate_status_board`, `route_ref=route_decision_ledger_to_gate_status_board` |

### Evidence Visibility Assertions (Baseline)

| Assertion ID | Journey ID | Screen Ref | Required Evidence Keys | Visibility Assertion |
|---|---|---|---|---|
| `ev_journey_conformance_engineer_triage_evidence_timeline_triage` | `journey_conformance_engineer_triage` | `evidence_timeline` | `obligation_snapshot`, `trace_excerpt`, `scheduler_state` | all required keys visible before `handoff_to_release_guardian` is enabled |
| `ev_journey_conformance_engineer_triage_bead_command_center_backlog` | `journey_conformance_engineer_triage` | `bead_command_center` | `bead_dependencies`, `priority_signals` | triage list must show dependency + priority context in primary panel |
| `ev_journey_runtime_operator_incident_runtime_health` | `journey_runtime_operator_incident` | `runtime_health` | `cancel_phase`, `reactor_backpressure`, `obligation_pressure` | runtime health summary must include current cancellation and obligation pressure state |
| `ev_journey_runtime_operator_incident_replay_inspector` | `journey_runtime_operator_incident` | `replay_inspector` | `trace_pointer`, `seed`, `replay_window` | replay panel must expose exact replay command ingredients |
| `ev_journey_release_guardian_gate_artifact_audit` | `journey_release_guardian_gate` | `artifact_audit` | `build_signature`, `test_provenance`, `lint_digest` | signoff path remains blocked if any required artifact key is missing |
| `ev_journey_release_guardian_gate_decision_ledger` | `journey_release_guardian_gate` | `decision_ledger` | `signoff_rationale`, `risk_classification`, `evidence_pointer_set` | decision ledger entries must include direct evidence pointers for each decision row |

### Unit-Test Scaffolding Requirements (Baseline)

- `UT-UXM-001`: parser validates matrix schema + deterministic ID format (`journey_`, `tx_`, `ev_`).
- `UT-UXM-002`: assertion matcher validates all `screen_ref` and `route_ref` links exist in the active contracts.
- `UT-UXM-003`: deterministic ordering check enforces lexical ordering for journey, transition, and evidence assertion IDs.
- `UT-UXM-004`: baseline oracle loader supports stable fixture replay keyed by `(journey_id, assertion_id)`.

### E2E Baseline Script Requirements (Baseline)

- `E2E-UXM-001`: replay `journey_conformance_engineer_triage` happy path and emit panel-transition transcript.
- `E2E-UXM-002`: replay `journey_runtime_operator_incident` happy path and capture replay-context artifact pointers.
- `E2E-UXM-003`: replay `journey_release_guardian_gate` happy path and assert evidence-gated decision enablement.
- `E2E-UXM-004`: structured logs must include `correlation_id`, `run_id`, `trace_id`, `journey_id`, `assertion_id`, `screen_ref`, `route_ref`, `outcome`.

### Handoff Boundary to Signoff Matrix (`asupersync-2b4jj.1.5`)

This v0 baseline is intentionally limited to primary happy-path journeys and
core evidence visibility gates. Signoff bead `1.5` must extend this matrix with:

- interruption/recovery coverage for every primary journey
- stricter rollout pass/fail thresholds and gating policy
- expanded negative-path assertions (blocked routes, invalid focus, missing evidence)
- final signoff reporting and waiver policy

Signoff work must extend these IDs/additive sections, not replace or rename the
baseline identifiers defined here.

## Final UX Signoff Matrix (v1)

This section is the final signoff layer for bead `asupersync-2b4jj.1.5`.
It extends the v0 baseline with interruption/recovery assertions, stricter
rollout policy, and explicit failure-diagnostics requirements.

### Signoff Journey Coverage

| Signoff Journey ID | Persona | Required Path Cycle | Interruption Coverage | Recovery Coverage |
|---|---|---|---|---|
| `journey_conformance_engineer_triage` | `conformance_engineer` | `bead_command_center -> scenario_workbench -> evidence_timeline -> bead_command_center` | cancellation at `scenario_workbench`, blocked route at `evidence_timeline` | retry-in-place + failure handoff from `scenario_workbench` |
| `journey_runtime_operator_incident` | `runtime_operator` | `incident_console -> runtime_health -> replay_inspector -> incident_console` | cancellation at `incident_console`, blocked route at `runtime_health` | retry-in-place + failure route from `incident_console` to `runtime_health` |
| `journey_release_guardian_gate` | `release_guardian` | `gate_status_board -> artifact_audit -> decision_ledger -> gate_status_board` | cancellation at `artifact_audit`, blocked route at `gate_status_board` | retry-in-place + failure route from `gate_status_board` to `artifact_audit` |

### Interruption and Recovery Assertions (Signoff)

| Assertion ID | Type | Journey | Injected At / Path | Expected Outcome |
|---|---|---|---|---|
| `int_journey_conformance_engineer_triage_01` | interruption | `journey_conformance_engineer_triage` | `scenario_workbench` + cancellation trigger | state becomes `cancelled` with preserved `correlation_id` |
| `int_journey_conformance_engineer_triage_02` | interruption | `journey_conformance_engineer_triage` | `evidence_timeline` + blocked navigation trigger | state becomes `failed` with `diagnostic_reason` |
| `rec_journey_conformance_engineer_triage_01` | recovery | `journey_conformance_engineer_triage` | `scenario_workbench -> scenario_workbench` via retry route | rerun context preserved; state returns to `loading` then `ready` |
| `rec_journey_conformance_engineer_triage_02` | recovery | `journey_conformance_engineer_triage` | `scenario_workbench -> evidence_timeline` failure handoff | evidence surface remains reachable for escalation |
| `int_journey_runtime_operator_incident_01` | interruption | `journey_runtime_operator_incident` | `incident_console` + cancellation trigger | containment flow enters `cancelled` deterministically |
| `int_journey_runtime_operator_incident_02` | interruption | `journey_runtime_operator_incident` | `runtime_health` + blocked navigation trigger | failure state includes remediation hint |
| `rec_journey_runtime_operator_incident_01` | recovery | `journey_runtime_operator_incident` | `incident_console -> incident_console` via retry route | rerun metadata retained end-to-end |
| `rec_journey_runtime_operator_incident_02` | recovery | `journey_runtime_operator_incident` | `incident_console -> runtime_health` failure route | containment resumes with runtime context |
| `int_journey_release_guardian_gate_01` | interruption | `journey_release_guardian_gate` | `artifact_audit` + cancellation trigger | signoff flow halts with deterministic blocked status |
| `int_journey_release_guardian_gate_02` | interruption | `journey_release_guardian_gate` | `gate_status_board` + blocked navigation trigger | state becomes `failed` with clear gate diagnostics |
| `rec_journey_release_guardian_gate_01` | recovery | `journey_release_guardian_gate` | `gate_status_board -> artifact_audit` failure route | missing evidence collection route always available |
| `rec_journey_release_guardian_gate_02` | recovery | `journey_release_guardian_gate` | `artifact_audit -> artifact_audit` via retry route | signoff path only resumes after evidence guard passes |

### Unit-Test Signoff Requirements

- `UT-UXS-001`: signoff matrix parser enforces deterministic schema and ID format.
- `UT-UXS-002`: journeys/assertions must be lexically sorted and duplicate-free.
- `UT-UXS-003`: all `screen_ref` and `route_ref` links must resolve to active contracts.
- `UT-UXS-004`: interruption/recovery assertions are mandatory for every signoff journey.
- `UT-UXS-005`: rollout gate policy validation enforces threshold and required-journey consistency.

### E2E Signoff Script Requirements

- `E2E-UXS-001`: full happy-path execution for all three signoff journeys.
- `E2E-UXS-002`: interruption-path replay for each journey with deterministic failure signatures.
- `E2E-UXS-003`: recovery-path replay for each journey with rerun-context continuity checks.
- `E2E-UXS-004`: on failure, emit state diff (`expected` vs `actual`), missing-evidence markers, and direct rerun command hints.

### Logging Requirements for Signoff Assertions

Every signoff assertion must include:

- `assertion_id`
- `journey_id`
- `correlation_id`
- `run_id`
- `trace_id`
- `screen_id`
- `route_ref`
- `outcome`

Additional failure-path requirements:

- interruption failures: `diagnostic_reason`
- recovery assertions: `rerun_hint`
- all failing assertions: `expected_state`, `actual_state`, `missing_evidence_keys`

### Rollout Gate Policy (Signoff)

Rollout is blocked unless all criteria pass:

1. Minimum aggregate signoff pass rate: `98%`.
2. Critical-severity signoff failures: `0`.
3. Required journeys all green:
`journey_conformance_engineer_triage`, `journey_runtime_operator_incident`, `journey_release_guardian_gate`.
4. Mandatory remediation actions for any failed signoff assertion:
`block_rollout_until_green_signoff`, `capture_state_diff_and_rerun_hint`, `file_followup_bead_with_trace_link`.

## Canonical Personas (v1)

- `conformance_engineer`: drives deterministic reproduction and correctness closure.
- `release_guardian`: enforces release gates and signoff/hold decisions.
- `runtime_operator`: contains live incidents while preserving replayable evidence.

Each canonical persona includes explicit mission success signals and at least two
high-stakes decisions bound to concrete decision-loop steps.

## Canonical Decision Loops (v1)

- `triage_investigate_remediate`
- `release_gate_verification`
- `incident_containment`

## Determinism Guarantees

1. Persona ordering is lexical by `id`.
2. Decision-loop ordering is lexical by `id`.
3. Step ordering is stable and explicit in contract source.
4. Persona mission-success signals are lexically sorted.
5. Persona high-stakes decision evidence keys are lexically sorted.
6. Global evidence requirements are lexically sorted.
7. Navigation screens, routes, bindings, and route-event schema are lexically sorted by key identifiers.
8. Repeated invocations on unchanged code emit byte-stable JSON ordering.

## Compatibility Notes

- New fields must be additive and backward-compatible.
- Existing field names are stable for downstream track consumers.
- New personas/loops may be appended, but existing IDs must not be renamed.
- New navigation screens/routes may be appended, but existing IDs and route semantics must remain stable.
- Breaking semantic changes require a new `contract_version`.
