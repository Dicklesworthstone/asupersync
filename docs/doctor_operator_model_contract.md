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
