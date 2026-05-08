# Semantic Maintainer Playbook and Onboarding Guide (SEM-11.2)

**Bead**: `asupersync-3cddg.11.2`
**Parent**: SEM-11 Rollout, Enablement, and Recurring Semantic Audits
**Date**: 2026-03-02
**Author**: SapphireHill

---

## 1. Quick Start for New Contributors

### 1.1 Prerequisites

- Rust 2024 edition (`rustc` nightly or latest stable)
- `cargo check --all-targets` must pass before any PR
- Read `AGENTS.md` for code editing rules
- Read `TESTING.md` for test expectations

### 1.2 First-Day Checklist

1. Clone the repository and verify `cargo check --all-targets` passes.
2. Read this playbook end-to-end (15 minutes).
3. Read the canonical contract overview: `docs/semantic_contract_schema.md` (47 rule IDs across 8 domains).
4. Run the quick verification suite: `scripts/semantic_rerun.sh all`.
5. Review the current drift posture: `docs/semantic_harmonization_report.md`.
6. Familiarize yourself with the failure-replay cookbook: `docs/semantic_failure_replay_cookbook.md`.

### 1.3 Key Concepts

- **Canonical Contract**: 47 semantic rules across 8 domains (cancellation, obligation, region, outcome, ownership, combinator, capability, determinism). Source: `docs/semantic_contract_schema.md`.
- **Evidence Classes**: UT (unit test), PT (property test), OC (oracle check), E2E (end-to-end witness), LOG (logging schema), DOC (documentation annotation), CI (CI gate).
- **Readiness Gates**: G1 (Documentation Alignment), G2 (Lean Proof Coverage), G3 (TLA+ Model Checking), G4 (Runtime Conformance), G5 (Property/Law Tests), G6 (Cross-Artifact E2E), G7 (Logging/Diagnostics).
- **Phase Closure**: Phase 1 requires G1+G4 PASS. Full closure requires all G1-G7 PASS.

---

## 2. Semantic Process Workflow

### 2.1 Before Making Changes

1. Identify which canonical rule IDs your change touches. Use `docs/semantic_contract_schema.md` as reference.
2. Check the verification matrix: `docs/semantic_verification_matrix.md` for existing evidence on those rules.
3. Check the runtime gap matrix: `docs/semantic_runtime_gap_matrix.md` for known gaps.
4. If your change modifies runtime-critical modules (`src/runtime/`, `src/cx/`, `src/cancel/`, `src/channel/`, `src/obligation/`, `src/trace/`, `src/lab/`, `formal/lean/`), you must complete the Proof + Conformance Impact Declaration in the PR template.

### 2.2 Quality Gates (Required Before Every Commit)

```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test --lib <module>  # targeted tests for changed modules
```

### 2.3 Semantic Change Review Process

When modifying behavior covered by canonical rules:

1. Annotate your change with the affected rule IDs (e.g., `// Rule #7: cancel_propagate_down`).
2. Ensure unit test coverage exists for each affected rule (UT evidence class).
3. Update `docs/semantic_runtime_gap_matrix.md` if your change resolves or introduces gaps.
4. If the change affects formal projections (Lean/TLA), coordinate with the relevant SEM-06/SEM-07 track owner.
5. Use the PR template's Proof + Conformance Impact Declaration section.

### 2.4 Governance Escalation

For semantic ambiguity or conflicts:
1. Check `docs/semantic_adr_decisions.md` for existing architectural decisions.
2. If no ADR covers the conflict, raise it in the `coord-*` agent mail thread.
3. Follow the escalation path in `docs/semantic_harmonization_charter.md` section on governance and decision rights.
4. Decision board quorum rules and SLA classes are defined in the charter.

---

## 3. Verification Runner Usage

### 3.1 Unified Runner

The unified semantic verification runner (`scripts/run_semantic_verification.sh`) executes all verification suites in a single invocation:

```bash
# Smoke profile (fast, core suites only)
scripts/run_semantic_verification.sh --profile smoke --json

# Full profile (all suites including coverage gate)
scripts/run_semantic_verification.sh --profile full --json

# Forensics profile (full + diagnostics)
scripts/run_semantic_verification.sh --profile forensics --json
```

Output: `target/semantic-verification/verification_report.json` (schema: `semantic-verification-report-v1`).

### 3.2 One-Command Reruns

Use `scripts/semantic_rerun.sh` for targeted reruns when a specific suite fails:

| Suite | Command | What It Tests |
|-------|---------|---------------|
| All suites | `scripts/semantic_rerun.sh all` | Full verification fabric |
| Documentation | `scripts/semantic_rerun.sh docs` | Rule ID annotations, glossary, transitions, invariants |
| Golden fixtures | `scripts/semantic_rerun.sh golden` | 5 canonical golden fixture witnesses |
| Lean proofs | `scripts/semantic_rerun.sh lean` | Lean theorem regression and coverage |
| TLA+ scenarios | `scripts/semantic_rerun.sh tla` | TLA+ state/invariant/scenario validation |
| Logging schema | `scripts/semantic_rerun.sh logging` | Log field completeness and witness replay |
| Coverage gate | `scripts/semantic_rerun.sh coverage` | Per-domain evidence thresholds |
| Runtime conformance | `scripts/semantic_rerun.sh runtime` | Golden fixtures + gap matrix evidence |
| Property/law tests | `scripts/semantic_rerun.sh laws` | Algebraic law tests (join, race, timeout, drain) |
| E2E witnesses | `scripts/semantic_rerun.sh e2e` | Cross-artifact witness replay + adversarial corpus |
| Full diagnostics | `scripts/semantic_rerun.sh forensics` | Full forensics + summary generation |

Options: `--seed N` (deterministic replay), `--verbose` (full output), `--json` (structured output), `--summary` (generate triage report).

### 3.3 Evidence Bundle Assembly

```bash
# Assemble evidence from verification artifacts
scripts/assemble_evidence_bundle.sh --json --phase 1

# Output: target/evidence-bundle/metadata/bundle_manifest.json
```

### 3.4 Human-Readable Summary and Triage

```bash
# Generate verification summary with per-rule detail
scripts/generate_verification_summary.sh --json --verbose

# Output:
#   target/verification-summary/verification_summary.md
#   target/verification-summary/triage_report.md
#   target/verification-summary/verification_summary.json
```

---

## 4. Testing Expectations

### 4.1 Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit tests | `src/*/tests.rs`, `tests/*.rs` | Per-module correctness |
| Integration tests | `tests/*.rs` | Cross-module interaction |
| Conformance tests | `tests/semantic_conformance_harness.rs` | Runtime-vs-contract conformance |
| Golden fixtures | `tests/fixtures/semantic_golden/*.json` | Canonical fixture witnesses |
| Oracle tests | `tests/*_oracle.rs`, `src/lab/oracle/*.rs` | Quiescence, leak, drain, authority oracles |
| Property tests | Tests containing `law_`, `metamorphic_` | Algebraic law verification |
| E2E tests | `tests/semantic_witness_replay_e2e.rs` | Cross-artifact witness scripts |
| Fuzz tests | `fuzz/` | Coverage-guided fuzzing |

### 4.2 Required Evidence per Rule

Every canonical rule ID should have at minimum:
- **UT**: At least one unit test exercising the rule's core behavior.
- **DOC**: Rule ID annotation in relevant source files and docs.

Higher evidence targets (tracked in `docs/semantic_verification_matrix.md`):
- **PT**: Property/law test for combinatory and algebraic rules.
- **OC**: Oracle conformance for runtime-observable invariants.
- **E2E**: Cross-artifact witness for high-risk semantic boundaries.
- **LOG**: Structured log entry for verification-observable events.

### 4.3 No-Mock Policy

Tests must use real `Cx` objects from `LabRuntime` or equivalent test harnesses. Do not mock the runtime's core types. See `TESTING.md` for `Cx` construction patterns.

### 4.4 Deterministic Replay

All tests support deterministic seeds:
```bash
SEED=42 cargo test --test semantic_golden_fixture_validation -- --nocapture
```

Correlation IDs in verification logs:
- `run_id`: Format `svr-{seed:016x}-{wall_ns:016x}` (unique per run)
- `entry_id`: Format `svl-{run_id}-{seq}` (unique per log entry)
- `thread_id`: Agent mail thread ID for coordination context
- `witness_id`: Witness pack ID (e.g., W1.1, W5.2) for E2E evidence

### 4.5 Logging Standards

Every semantic verification log entry must include:
`schema_version`, `entry_id`, `run_id`, `seq`, `timestamp_ns`, `phase`, `rule_id`, `rule_number`, `domain`, `evidence_class`, `scenario_id`, `verdict`, `seed`, `repro_command`.

See `docs/semantic_verification_log_schema.md` for the full schema.

---

## 5. Failure Diagnosis

### 5.1 Triage Decision Tree

When a verification failure occurs:

1. **Identify the failed suite** from CI output or local run.
2. **Look up the recipe** in `docs/semantic_failure_replay_cookbook.md` section 2.
3. **Run the targeted rerun**: `scripts/semantic_rerun.sh <suite> --verbose`.
4. **Check the root cause checklist** in the recipe.
5. **If unclear**, run full diagnostics: `scripts/semantic_rerun.sh forensics`.

### 5.2 Full Diagnostic Pipeline

When the failure source is unclear:

```bash
# Step 1: Full verification suite
scripts/run_semantic_verification.sh --profile forensics --json

# Step 2: Evidence bundle assembly
scripts/assemble_evidence_bundle.sh --json --phase 1

# Step 3: Generate summary with per-rule detail
scripts/generate_verification_summary.sh --json --verbose

# Step 4: Review triage report
cat target/verification-summary/triage_report.md
```

### 5.3 Remote Compilation

CPU-intensive cargo operations must be offloaded via `rch`:
```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_semantic_maintainer_docs cargo test --test semantic_golden_fixture_validation -- --nocapture
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_semantic_maintainer_docs cargo clippy --all-targets -- -D warnings
```

---

## 6. Key Documents Reference

| Document | Path | Purpose |
|----------|------|---------|
| Canonical contract | `docs/semantic_contract_schema.md` | 47 rule IDs, 8 domains |
| Verification matrix | `docs/semantic_verification_matrix.md` | Rule-to-evidence mapping |
| Runtime gap matrix | `docs/semantic_runtime_gap_matrix.md` | CODE-GAP/DOC-GAP/TEST-GAP status |
| Gate evaluation report | `docs/semantic_gate_evaluation_report.md` | G1-G7 gate status |
| Harmonization report | `docs/semantic_harmonization_report.md` | Drift deltas and current alignment |
| Residual risk register | `docs/semantic_residual_risk_register.md` | Bounded risks with owners/expiry |
| Closure recommendation | `docs/semantic_closure_recommendation_packet.md` | Go/no-go assessment |
| Failure-replay cookbook | `docs/semantic_failure_replay_cookbook.md` | Triage tree + rerun recipes |
| Log schema | `docs/semantic_verification_log_schema.md` | Required log fields |
| Harmonization charter | `docs/semantic_harmonization_charter.md` | Governance and invariant baseline |
| ADR decisions | `docs/semantic_adr_decisions.md` | Architectural decisions ledger |
| Change freeze workflow | `docs/semantic_change_freeze_workflow.md` | Freeze policy during SEM execution |
| FOS (annotated) | `docs/formal_operational_semantics.md` | Runtime spec with rule ID annotations |

---

## 7. Onboarding Workflow for Semantic Contributors

### 7.1 Week 1: Orientation

1. Read this playbook and the canonical contract schema.
2. Run `scripts/semantic_rerun.sh all` and verify all suites pass.
3. Review the harmonization report for current drift posture.
4. Read the failure-replay cookbook to understand diagnosis flow.
5. Identify your assigned bead and its dependencies using `br show <bead-id>`.

### 7.2 Week 2: First Contribution

1. Claim your bead: `br update <bead-id> --claim --assignee <name> --status in_progress`.
2. Reserve files via agent mail `file_reservation_paths` to prevent conflicts.
3. Send a coordination message in the bead thread announcing your work surface.
4. Implement the deliverable, following the quality gates in section 2.2.
5. Run the relevant verification suite from section 3.2.
6. Close the bead: `br close <bead-id> --force`.
7. Release file reservations and send completion message.

### 7.3 Ongoing: Semantic Maintenance

1. When modifying runtime-critical code, always check which rule IDs are affected.
2. Run `scripts/semantic_rerun.sh <relevant-suite>` after changes.
3. Update evidence in the verification matrix when adding new tests.
4. Monitor the residual risk register for expiring risks that need attention.

---

## 8. Recurring Audit Procedure

### 8.1 Audit Cadence

Semantic verification audits should run:
- **On every PR**: CI gate checks (G1 and G4 minimum for Phase 1).
- **Weekly**: Full-profile verification run with summary generation.
- **Monthly**: Evidence bundle assembly with gate evaluation against latest thresholds.

### 8.2 Audit Checklist

- [ ] Run `scripts/run_semantic_verification.sh --profile full --json`
- [ ] Run `scripts/assemble_evidence_bundle.sh --json --phase 1`
- [ ] Run `scripts/generate_verification_summary.sh --json --verbose`
- [ ] Review `target/verification-summary/triage_report.md` for new gaps
- [ ] Compare gate status against `docs/semantic_gate_evaluation_report.md`
- [ ] Update `docs/semantic_residual_risk_register.md` for any expired or newly-bounded risks
- [ ] Post audit results in the coordination thread

### 8.3 Drift Detection

Signs of semantic drift:
- New CODE-GAP entries in `docs/semantic_runtime_gap_matrix.md`.
- Gate regression (previously-passing gate now fails).
- Evidence coverage decrease in `docs/semantic_verification_matrix.md`.
- Missing rule ID annotations on new runtime code.

Response:
1. File a bead for the drift source.
2. Run the relevant rerun suite to confirm the regression.
3. Assign ownership and set a bounded remediation timeline.
4. Update the residual risk register if immediate fix is not possible.

---

## 9. Unsafe Code Policy

The project enforces `#![deny(unsafe_code)]` at the crate level. Any use of `unsafe` requires:
1. Explicit `#[allow(unsafe_code)]` annotation on the specific item.
2. A comment explaining why unsafe is necessary and what invariants must hold.
3. Review by at least one maintainer.
4. No `unsafe` is permitted in `src/cx/` (capability security boundary).

---

## 10. Current Program Status

As of 2026-03-02:
- **Phase 1**: PASS (G1 + G4 achieved).
- **Full closure**: NO-GO (G2, G3, G5, G6 deferred).
- **Active tracks**: SEM-06 (Lean alignment), SEM-07 (TLA alignment), SEM-11 (Rollout).
- **Completed tracks**: SEM-01 through SEM-05, SEM-08, SEM-09, SEM-10, SEM-12.
- **Unresolved risks**: See `docs/semantic_residual_risk_register.md` for bounded exceptions.

For the full drift-delta analysis, see `docs/semantic_harmonization_report.md`.
