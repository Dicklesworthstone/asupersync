# Semantic Failure Replay Cookbook (SEM-12.12)

**Bead**: `asupersync-3cddg.12.12`
**Parent**: SEM-12 Comprehensive Verification Fabric

This cookbook helps you move from a CI failure signal to a local root-cause diagnosis quickly, with deterministic inputs and logging context.

---

## 1. Triage Decision Tree

```
CI failure or local verification failure
│
├─ Which suite failed?
│   ├─ docs ─────────── → §2.1 Documentation Alignment Failures
│   ├─ golden ───────── → §2.2 Golden Fixture Failures
│   ├─ lean_validation → §2.3 Lean Proof Failures
│   ├─ tla_validation → §2.4 TLA+ Scenario Failures
│   ├─ logging_schema → §2.5 Logging Schema Failures
│   ├─ coverage_gate ── → §2.6 Coverage Gate Failures
│   └─ unknown ──────── → §3 Full Diagnostic Run
│
├─ Which gate failed?
│   ├─ G1 (Docs) ────── → §2.1
│   ├─ G2 (Lean) ────── → §2.3
│   ├─ G3 (TLA+) ────── → §2.4
│   ├─ G4 (Runtime) ─── → §2.7 Runtime Conformance Failures
│   ├─ G5 (Laws) ────── → §2.8 Property/Law Test Failures
│   ├─ G6 (E2E) ─────── → §2.9 Cross-Artifact E2E Failures
│   └─ G7 (Logging) ─── → §2.5
│
└─ Coverage gap?
    ├─ UT gaps ──────── → §2.2 (golden fixtures define UT evidence)
    ├─ PT gaps ──────── → §2.8 (property tests)
    ├─ OC gaps ──────── → §2.2 (oracle conformance in golden fixtures)
    ├─ E2E gaps ─────── → §2.9 (cross-artifact E2E)
    ├─ LOG gaps ─────── → §2.5 (logging schema)
    └─ DOC gaps ─────── → §2.1 (documentation annotations)
```

---

## 2. Failure Class Recipes

### 2.1 Documentation Alignment Failures (Suite: docs, Gate: G1)

**Symptoms**: Missing rule IDs in docs, glossary gaps, missing transition/invariant documentation.

**Quick rerun**:
```bash
scripts/semantic_rerun.sh docs
```

**Detailed rerun**:
```bash
cargo test --test semantic_docs_lint --test semantic_docs_rule_mapping_lint -- --nocapture
```

**Root cause checklist**:
- [ ] Check `docs/semantic_contract_*.md` for missing rule ID annotations (`#N` pattern)
- [ ] Verify `docs/semantic_contract_glossary.md` has all 11+ entries
- [ ] Verify `docs/semantic_contract_transitions.md` has 15+ PRE/POST references
- [ ] Verify `docs/semantic_contract_invariants.md` has 14+ clauses

**Expected artifacts**:
- `target/semantic-verification/docs_output.txt` — test output with specific assertion failures

**Remediation owner**: `asupersync-3cddg.12.2`

### 2.2 Golden Fixture Failures (Suite: golden, Gate: G4 partial)

**Symptoms**: Fixture validation fails, witness mismatch, rule coverage regression.

**Quick rerun**:
```bash
scripts/semantic_rerun.sh golden
```

**Detailed rerun**:
```bash
cargo test --test semantic_golden_fixture_validation -- --nocapture
```

**Root cause checklist**:
- [ ] Check `tests/fixtures/semantic_golden/` for corrupted or missing JSON fixtures
- [ ] Compare fixture `expected_outcome` fields against runtime behavior changes
- [ ] Verify fixture `rule_ids` match current canonical contract (47 rules)

**Expected artifacts**:
- `target/semantic-verification/golden_output.txt`
- `tests/fixtures/semantic_golden/*.json` — the 5 canonical golden fixtures

**Remediation owner**: `asupersync-3cddg.12.8`

### 2.3 Lean Proof Failures (Suite: lean_validation, Gate: G2)

**Symptoms**: Lean theorem inventory mismatch, coverage matrix drift, regression test failure.

**Quick rerun**:
```bash
scripts/semantic_rerun.sh lean
```

**Detailed rerun**:
```bash
# Validation tests (no Lean toolchain needed)
cargo test --test semantic_lean_regression -- --nocapture

# Full Lean build (requires Lean toolchain)
scripts/run_lean_regression.sh --json
```

**Root cause checklist**:
- [ ] Check `formal/lean/Asupersync.lean` for syntax errors or broken theorem statements
- [ ] Verify `formal/lean/coverage/theorem_surface_inventory.json` matches actual theorems
- [ ] Compare `formal/lean/coverage/lean_coverage_matrix.sample.json` against expected coverage

**Expected artifacts**:
- `target/semantic-verification/lean_validation_output.txt`
- `formal/lean/coverage/baseline_report_v1.json`

**Remediation owner**: `asupersync-3cddg.12.3`

### 2.4 TLA+ Scenario Failures (Suite: tla_validation, Gate: G3)

**Symptoms**: TLA+ spec state names mismatch, invariant list drift, model check property violations.

**Quick rerun**:
```bash
scripts/semantic_rerun.sh tla
```

**Detailed rerun**:
```bash
# Validation tests (no TLC needed)
cargo test --test semantic_tla_scenarios -- --nocapture

# Full TLC model check (requires TLC)
scripts/run_model_check.sh --ci
scripts/run_tla_scenarios.sh --json
```

**Root cause checklist**:
- [ ] Check `formal/tla/Asupersync.tla` for state name changes (compare with scenario test expectations)
- [ ] Verify `formal/tla/output/result.json` shows 0 violations
- [ ] Confirm state space is within 10M bound (currently 23,998 distinct states)
- [ ] Check `formal/tla/Asupersync_MC.cfg` configuration matches spec

**Expected artifacts**:
- `target/semantic-verification/tla_validation_output.txt`
- `formal/tla/output/result.json` — TLC run result

**Key invariants checked**:
TypeInvariant, WellFormedInvariant, NoOrphanTasks, NoLeakedObligations, CloseImpliesQuiescent, MaskBoundedInvariant, MaskMonotoneInvariant, CancelIdempotenceStructural

**Remediation owner**: `asupersync-3cddg.12.4`

### 2.5 Logging Schema Failures (Suite: logging_schema, Gate: G7)

**Symptoms**: Missing required log fields, schema version mismatch, witness replay format errors.

**Quick rerun**:
```bash
scripts/semantic_rerun.sh logging
```

**Detailed rerun**:
```bash
cargo test --test semantic_log_schema_validation --test semantic_witness_replay_e2e -- --nocapture
```

**Root cause checklist**:
- [ ] Verify `docs/semantic_verification_log_schema.md` defines all required fields
- [ ] Check required fields: `schema_version`, `entry_id`, `run_id`, `seq`, `timestamp_ns`, `phase`, `rule_id`, `rule_number`, `domain`, `evidence_class`, `scenario_id`, `verdict`, `seed`, `repro_command`
- [ ] Verify witness replay tests match current log entry format

**Expected artifacts**:
- `target/semantic-verification/logging_schema_output.txt`

**Remediation owner**: `asupersync-3cddg.12.7`

### 2.6 Coverage Gate Failures (Suite: coverage_gate)

**Symptoms**: Domain evidence coverage below threshold, missing evidence classes.

**Quick rerun**:
```bash
scripts/semantic_rerun.sh coverage
```

**Detailed rerun**:
```bash
scripts/run_semantic_verification.sh --profile full --json
# Then check quality_gates section in verification_report.json
```

**Root cause checklist**:
- [ ] Run `scripts/generate_verification_summary.sh --json --verbose` for per-rule gap detail
- [ ] Check global thresholds: UT 100%, PT 40%, E2E 60%
- [ ] Check per-domain thresholds in `docs/semantic_verification_matrix.md`
- [ ] Identify which evidence classes are missing per rule

**Expected artifacts**:
- `target/semantic-verification/verification_report.json` — includes `quality_gates` section
- `target/verification-summary/verification_summary.json` — includes per-domain coverage

**Remediation**: Route gaps to owner beads via `missing_evidence_by_owner` in evidence bundle.

### 2.7 Runtime Conformance Failures (Gate: G4)

**Symptoms**: CODE-GAP count > 0, DOC-GAP annotations missing, conformance test failure.

**Quick rerun**:
```bash
scripts/semantic_rerun.sh runtime
```

**Detailed rerun**:
```bash
cargo test --test semantic_golden_fixture_validation -- --nocapture
scripts/assemble_evidence_bundle.sh --json --skip-runner --phase 1
```

**Root cause checklist**:
- [ ] Check `docs/semantic_runtime_gap_matrix.md` for unresolved CODE-GAPs
- [ ] Verify `src/` files have DOC-GAP annotations with rule IDs
- [ ] Run golden fixture validation for conformance evidence

**Expected artifacts**:
- `target/evidence-bundle/metadata/bundle_manifest.json` — G4 verdict

### 2.8 Property/Law Test Failures (Gate: G5)

**Symptoms**: Missing law test files, algebraic property violations.

**Quick rerun**:
```bash
scripts/semantic_rerun.sh laws
```

**Detailed rerun**:
```bash
cargo test law_join_assoc law_race_comm law_timeout_min metamorphic_drain law_race_abandon -- --nocapture
```

**Root cause checklist**:
- [ ] Check for test files matching `law_join_assoc`, `law_race_comm`, `law_timeout_min`
- [ ] Verify conformance harness has 3+ law/property references
- [ ] Run specific law test that failed

**Remediation owner**: SEM-08 track

### 2.9 Cross-Artifact E2E Failures (Gate: G6)

**Symptoms**: Witness replay failure, adversarial corpus regression, capability audit finding.

**Quick rerun**:
```bash
scripts/semantic_rerun.sh e2e
```

**Detailed rerun**:
```bash
cargo test --test semantic_witness_replay_e2e --test adversarial_witness_corpus -- --nocapture
```

**Root cause checklist**:
- [ ] Check `tests/semantic_witness_replay_e2e.rs` for broken witness expectations
- [ ] Check `tests/adversarial_witness_corpus.rs` for corpus format changes
- [ ] Verify no `unsafe` in `src/cx/` (capability audit)

**Expected artifacts**:
- `target/semantic-verification/logging_schema_output.txt` (includes E2E tests)

---

## 3. Full Diagnostic Run

When the failure source is unclear, run the full diagnostic pipeline:

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

The triage report groups failures by type (suite/gate/coverage) with root-cause hints and rerun commands for each.

---

## 4. Deterministic Replay

All verification runs support deterministic replay through seeds:

```bash
# Log entry schema uses deterministic seeds
# seed: u64 value used for test randomization
# trace_fingerprint: Foata trace hash for ordering verification

# Reproduce a specific run by setting the seed
SEED=42 cargo test --test semantic_golden_fixture_validation -- --nocapture

# Reproduce with full correlation context
# Each log entry includes repro_command field with exact one-liner
```

**Correlation IDs**:
- `run_id`: Format `svr-{seed:016x}-{wall_ns:016x}` — unique per verification run
- `entry_id`: Format `svl-{run_id}-{seq}` — unique per log entry within a run
- `thread_id`: Agent mail thread ID for coordination context
- `witness_id`: Witness pack ID (e.g., W1.1, W5.2) for E2E evidence

---

## 5. Quick Reference: One-Command Reruns

| Failure Class | Rerun Command |
|--------------|---------------|
| All suites | `scripts/semantic_rerun.sh all` |
| Docs only | `scripts/semantic_rerun.sh docs` |
| Golden fixtures | `scripts/semantic_rerun.sh golden` |
| Lean proofs | `scripts/semantic_rerun.sh lean` |
| TLA+ scenarios | `scripts/semantic_rerun.sh tla` |
| Logging schema | `scripts/semantic_rerun.sh logging` |
| Coverage gate | `scripts/semantic_rerun.sh coverage` |
| Runtime conformance | `scripts/semantic_rerun.sh runtime` |
| Property/law tests | `scripts/semantic_rerun.sh laws` |
| E2E witness | `scripts/semantic_rerun.sh e2e` |
| Full diagnostics | `scripts/semantic_rerun.sh forensics` |
| Summary + triage | `scripts/generate_verification_summary.sh --json --verbose` |
| Gate evaluation | `scripts/assemble_evidence_bundle.sh --json --phase 1` |
