# doctor_asupersync Visual Regression Harness and Core Interaction Suite

**Bead**: `asupersync-2b4jj.6.9`
**Parent**: Track 6: Quality gates, packaging, and rollout
**Date**: 2026-03-02
**Author**: SapphireHill

---

## 1. Purpose

This document defines the baseline visual-regression harness contract, golden fixture management policy, and core interaction regression scenarios for `doctor_asupersync` non-remediation workflows. It establishes the deterministic infrastructure for visual snapshot capture, comparison, and drift detection across navigation, timeline, command center, and evidence browsing surfaces.

---

## 2. Harness Infrastructure

### 2.1 Snapshot Data Model

Visual snapshots are represented by `DoctorVisualHarnessSnapshot`:

| Field | Type | Purpose |
|-------|------|---------|
| `snapshot_id` | `String` | Stable identifier for this capture |
| `viewport_width` | `u16` | Viewport width (deterministic) |
| `viewport_height` | `u16` | Viewport height (deterministic) |
| `focused_panel` | `String` | Active panel at capture time |
| `selected_node_id` | `String` | Selected node identifier |
| `stage_digest` | `String` | Deterministic digest of stage/outcome progression |
| `visual_profile` | `String` | Visual profile token (e.g., `frankentui-stable`) |
| `capture_index` | `u32` | Index within smoke run |

### 2.2 Artifact Manifest

`DoctorVisualHarnessArtifactManifest` tracks per-run artifacts:

| Field | Type | Purpose |
|-------|------|---------|
| `schema_version` | `String` | `doctor-visual-harness-manifest-v1` |
| `run_id` | `String` | Deterministic run identifier |
| `scenario_id` | `String` | Scenario identifier |
| `artifact_root` | `String` | Root directory (`artifacts/<run_id>/doctor/e2e/`) |
| `records` | `Vec<ArtifactRecord>` | Lexically ordered manifest entries |

### 2.3 Artifact Record

Each `DoctorVisualHarnessArtifactRecord` contains:

| Field | Type | Constraint |
|-------|------|-----------|
| `artifact_id` | `String` | Stable unique identifier |
| `artifact_class` | `String` | One of: `snapshot`, `metrics`, `replay_metadata`, `structured_log`, `summary`, `transcript` |
| `artifact_path` | `String` | Must start with `artifacts/` |
| `checksum_hint` | `String` | Non-empty; for triage joins |
| `retention_class` | `String` | `hot` (active) or `warm` (archival) |
| `linked_artifacts` | `Vec<String>` | Lexically sorted related artifact IDs |

---

## 3. Visual Profile Mapping

The harness maps terminal outcome classes to visual profiles:

| Outcome Class | Visual Profile | Focused Panel |
|--------------|---------------|--------------|
| `success` | `frankentui-stable` | `summary_panel` |
| `cancelled` | `frankentui-cancel` | `triage_panel` |
| Other (failure) | `frankentui-alert` | `triage_panel` |

Profile selection is deterministic given the same transcript outcome.

---

## 4. Golden Fixture Management

### 4.1 Fixture Location

Visual regression golden fixtures live at:

```
tests/fixtures/doctor_visual_harness/
  manifest.json           # Fixture pack manifest
  snapshot_success.json   # Golden snapshot for success outcome
  snapshot_cancelled.json # Golden snapshot for cancelled outcome
  snapshot_failed.json    # Golden snapshot for failed outcome
  manifest_success.json   # Golden artifact manifest for success
```

### 4.2 Fixture Schema

```json
{
  "schema_version": "doctor-visual-harness-fixture-pack-v1",
  "description": "Baseline golden fixtures for visual regression",
  "fixtures": [
    {
      "fixture_id": "visual-success-baseline",
      "outcome_class": "success",
      "expected_visual_profile": "frankentui-stable",
      "expected_focused_panel": "summary_panel",
      "viewport_width": 120,
      "viewport_height": 40
    }
  ]
}
```

### 4.3 Drift Detection

Snapshot comparison uses field-by-field equality:
- `viewport_width` and `viewport_height` must match golden fixture exactly
- `visual_profile` must match expected profile for outcome class
- `focused_panel` must match expected panel for outcome class
- `stage_digest` must be non-empty and start with `len:`

---

## 5. Core Interaction Regression Scenarios

### 5.1 Navigation Workflow

| Step | Action | Expected Panel | Verification |
|------|--------|---------------|-------------|
| 1 | Initial render | `summary_panel` | Viewport dimensions match |
| 2 | Navigate to triage | `triage_panel` | Panel transition logged |
| 3 | Return to summary | `summary_panel` | Idempotent navigation |

### 5.2 Timeline Browsing

| Step | Action | Expected State |
|------|--------|---------------|
| 1 | Render timeline | Nodes populated |
| 2 | Select node | `selected_node_id` updated |
| 3 | Expand evidence | Evidence panel active |

### 5.3 Command Center

| Step | Action | Expected State |
|------|--------|---------------|
| 1 | Open command center | Panel rendered |
| 2 | List beads | Status board populated |
| 3 | Filter by status | Filtered view consistent |

### 5.4 Evidence Browsing

| Step | Action | Expected State |
|------|--------|---------------|
| 1 | Open evidence panel | Evidence loaded |
| 2 | Sort by severity | Sort order deterministic |
| 3 | Filter by category | Filtered count consistent |

---

## 6. Determinism Invariants

1. **Viewport determinism**: given the same `(viewport_width, viewport_height)`, snapshot layout is identical.
2. **Profile determinism**: given the same outcome class, visual profile is identical.
3. **Panel determinism**: given the same outcome class, focused panel is identical.
4. **Digest determinism**: given the same stage outcomes, `stage_digest` is identical.
5. **Artifact ordering**: manifest records are lexically sorted by `artifact_id`.
6. **Linked artifact ordering**: `linked_artifacts` arrays are lexically sorted and deduplicated.
7. **Retention policy**: `snapshot`, `structured_log`, `transcript` are `hot`; `summary`, `metrics`, `replay_metadata` are `warm`.
8. **Path rooting**: all `artifact_path` values start with `artifacts/`.

---

## 7. CI Validation

### 7.1 Automated Gates

| Gate | Test File | Checks |
|------|----------|--------|
| Snapshot construction | `tests/doctor_visual_regression_harness.rs` | Deterministic snapshot fields |
| Artifact manifest | `tests/doctor_visual_regression_harness.rs` | Manifest schema, record ordering, path rooting |
| Profile mapping | `tests/doctor_visual_regression_harness.rs` | Outcome-to-profile determinism |
| Fixture schema | `tests/doctor_visual_regression_harness.rs` | Fixture pack validation |
| Document coverage | `tests/doctor_visual_regression_harness.rs` | All sections and invariants documented |

### 7.2 Reproduction

```bash
# Run visual regression harness tests
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_visual_docs cargo test --test doctor_visual_regression_harness --features cli -- --nocapture

# Run existing scenario coverage smoke
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_doctor_visual_docs cargo test --test doctor_analyzer_fixture_harness --features cli -- --nocapture
```

---

## 8. Cross-References

- Visual language contract: `docs/doctor_visual_language_contract.md`
- E2E harness contract: `docs/doctor_e2e_harness_contract.md`
- Analyzer fixture harness: `docs/doctor_analyzer_fixture_harness.md`
- Scenario composer: `docs/doctor_scenario_composer_contract.md`
- Logging contract: `docs/doctor_logging_contract.md`
- Implementation: `src/cli/doctor/mod.rs`
- Analyzer fixture tests: `tests/doctor_analyzer_fixture_harness.rs`
- Visual regression tests: `tests/doctor_visual_regression_harness.rs`
