# Semantic Enablement FAQ (SEM-11.3)

**Bead**: `asupersync-3cddg.11.3`
**Parent**: SEM-11 Rollout, Enablement, and Recurring Semantic Audits
**Date**: 2026-03-02
**Author**: SapphireHill

This FAQ captures recurring questions from the semantic harmonization program rollout. It serves as a quick-reference companion to the maintainer playbook (`docs/semantic_maintainer_playbook.md`).

---

## General

### Q1: What is semantic harmonization?

Semantic harmonization ensures that four artifact layers — runtime code, documentation, Lean formal proofs, and the TLA+ model — all agree on the same 47 canonical behavioral rules. When these layers drift apart, bugs, specification gaps, and verification failures can hide undetected.

**Reference**: `docs/semantic_harmonization_charter.md`

### Q2: Where is the canonical contract?

The canonical semantic contract lives in `docs/semantic_contract_schema.md`. It defines 47 rule IDs across 8 domains: cancellation (#1-12), obligation (#13-21), region (#22-28), outcome (#29-32), ownership (#33-36), combinator (#37-43), capability (#44-45), and determinism (#46-47).

**Reference**: `docs/semantic_contract_schema.md`

### Q3: What are the 8 semantic domains?

1. **Cancellation** (#1-12): Cancel propagation, cooperative yields, cancel kinds, scope semantics.
2. **Obligation** (#13-21): Lifecycle, finalizers, leak prevention, timeout enforcement.
3. **Region** (#22-28): Structured concurrency, close-implies-quiescence, region trees.
4. **Outcome** (#29-32): Outcome types, severity, deterministic error handling.
5. **Ownership** (#33-36): Task ownership, region membership, capability scoping.
6. **Combinator** (#37-43): Join, race, timeout, bracket, pipeline algebraic laws.
7. **Capability** (#44-45): Ambient authority prevention, capability capsule enforcement.
8. **Determinism** (#46-47): LabRuntime deterministic scheduling, seed-based replay.

### Q4: What is the current program status?

Phase 1 is PASS (gates G1 + G4 achieved). Full closure is NO-GO pending deferred gates G2 (Lean), G3 (TLA+), G5 (Property/Law), and G6 (Cross-Artifact E2E). Active tracks: SEM-06 (Lean alignment), SEM-07 (TLA alignment), SEM-11 (Rollout).

**Reference**: `docs/semantic_harmonization_report.md`

---

## Verification

### Q5: How do I run the verification suite?

Quick options:

```bash
# Run all suites
scripts/semantic_rerun.sh all

# Run specific suite
scripts/semantic_rerun.sh docs          # documentation alignment
scripts/semantic_rerun.sh golden        # golden fixture validation
scripts/semantic_rerun.sh lean          # lean proof regression
scripts/semantic_rerun.sh tla           # TLA+ scenario validation

# Full runner with JSON output
scripts/run_semantic_verification.sh --profile full --json
```

**Reference**: `docs/semantic_maintainer_playbook.md` §3

### Q6: A verification suite failed. What do I do?

1. Identify the failed suite from CI output or local run.
2. Look up the recipe in `docs/semantic_failure_replay_cookbook.md` section 2.
3. Run the targeted rerun: `scripts/semantic_rerun.sh <suite> --verbose`.
4. Check the root cause checklist in the recipe.
5. If unclear, run full diagnostics: `scripts/semantic_rerun.sh forensics`.

**Reference**: `docs/semantic_failure_replay_cookbook.md`

### Q7: What are the quality gates I must pass before committing?

```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test --lib <module>  # for changed modules
```

For CPU-intensive operations, use `rch exec -- <command>` to offload to remote workers.

### Q8: How do I generate the evidence bundle?

```bash
# Step 1: Run verification
scripts/run_semantic_verification.sh --profile full --json

# Step 2: Assemble evidence
scripts/assemble_evidence_bundle.sh --json --phase 1

# Step 3: Generate human summary
scripts/generate_verification_summary.sh --json --verbose
```

**Reference**: `docs/semantic_maintainer_playbook.md` §3.3-3.4

### Q9: What evidence classes exist?

| Class | Abbreviation | Description |
|-------|:------------:|-------------|
| Unit test | UT | Targeted `#[test]` exercising a rule |
| Property test | PT | Randomized/exhaustive property check |
| Oracle check | OC | Lab oracle scenario verification |
| End-to-end | E2E | Cross-artifact witness replay |
| Logging | LOG | Structured log schema validation |
| Documentation | DOC | Rule ID annotation in docs/code |
| CI gate | CI | Automated CI pipeline check |

### Q10: What are the readiness gates?

| Gate | Domain | Minimum for Phase 1 | Full Closure |
|------|--------|---------------------|--------------|
| G1 | Documentation Alignment | PASS (required) | PASS |
| G2 | Lean Proof Coverage | DEFER ok | PASS |
| G3 | TLA+ Model Checking | DEFER ok | PASS |
| G4 | Runtime Conformance | PASS (required) | PASS |
| G5 | Property/Law Tests | DEFER ok | PASS |
| G6 | Cross-Artifact E2E | DEFER ok | PASS |
| G7 | Logging/Diagnostics | PASS | PASS |

---

## Development Workflow

### Q11: I'm adding a new feature. Do I need to worry about semantic rules?

If your feature touches runtime-critical modules (`src/runtime/`, `src/cx/`, `src/cancel/`, `src/channel/`, `src/obligation/`, `src/trace/`, `src/lab/`), yes. Check `docs/semantic_contract_schema.md` for applicable rule IDs and ensure your code respects those rules. Add rule ID annotations to your code and PR.

### Q12: How do I annotate code with rule IDs?

Add comments referencing the canonical rule number:
```rust
// Rule #7: cancel_propagate_down
// Cancellation must propagate from parent region to all child tasks
```

For documentation, reference rule IDs inline: `(#7 cancel_propagate_down)`.

### Q13: What is the no-mock policy?

Tests must use real `Cx` objects from `LabRuntime` or equivalent test harnesses. Do not mock the runtime's core types. This ensures tests exercise actual runtime behavior.

**Reference**: `TESTING.md`

### Q14: How do I use deterministic replay?

Set the `SEED` environment variable:
```bash
SEED=42 cargo test --test semantic_golden_fixture_validation -- --nocapture
```

Each verification log entry includes a `repro_command` field with the exact one-liner to reproduce the run.

### Q15: What is `rch` and when should I use it?

`rch` (Remote Compilation Helper) offloads CPU-intensive builds to remote workers. Use it for:
```bash
rch exec -- cargo test --test <test_name> -- --nocapture
rch exec -- cargo clippy --all-targets -- -D warnings
rch exec -- cargo check --all-targets
```

Use `rch` whenever running full test suites or clippy on the entire codebase.

---

## Governance

### Q16: What if I find a semantic ambiguity between artifacts?

1. Check `docs/semantic_adr_decisions.md` for existing architectural decisions (ADR-001 through ADR-008).
2. If no ADR covers the conflict, raise it in the coordination thread.
3. Follow the escalation path in `docs/semantic_harmonization_charter.md`.
4. Critical semantic conflicts have SLA classes with defined response times.

### Q17: Can I change a canonical rule?

Not during an active change freeze (check `docs/semantic_change_freeze_workflow.md`). Outside of freeze periods, propose an ADR with:
- The rule ID being modified
- Justification and impact analysis
- Evidence that all four artifact layers can be updated consistently
- Follow the governance process in the charter

### Q18: What is the unsafe code policy?

The crate enforces `#![deny(unsafe_code)]`. Any `unsafe` requires:
1. Explicit `#[allow(unsafe_code)]` on the specific item.
2. A comment explaining why unsafe is necessary and what invariants must hold.
3. Maintainer review.
4. No `unsafe` is permitted in `src/cx/` (capability security boundary).

### Q19: What happens when a gate regresses?

1. The regression is detected by CI or periodic audit.
2. File a bead for the drift source.
3. Run the relevant rerun suite to confirm.
4. Assign ownership and set a bounded remediation timeline.
5. Update `docs/semantic_residual_risk_register.md` if immediate fix is not possible.

---

## Coordination

### Q20: How do I coordinate with other agents?

Use MCP Agent Mail for coordination:
1. Send a coordination message when claiming a bead (include planned file surface).
2. Reserve files via `file_reservation_paths` to prevent conflicts.
3. Post progress updates and completion messages.
4. Acknowledge `ack_required` messages promptly.

### Q21: How do I claim a bead?

```bash
br update <bead-id> --claim --assignee <name> --status in_progress
```

If the bead is blocked, use `--force` for controlled prework when the blocker's deliverable is already available.

### Q22: What beads are available for me to work on?

```bash
# List ready (unblocked) beads
br ready

# Get triage recommendations
bv --robot-triage
```

### Q23: How do I close a bead?

1. Verify all acceptance criteria are met.
2. Run relevant tests via `rch exec -- cargo test ...`.
3. Close the bead: `br close <bead-id> --force`.
4. Release file reservations.
5. Send completion message via agent mail.
6. Sync beads: `br sync --flush-only`.
7. Commit and push.

---

## Troubleshooting

### Q24: `cargo check` fails with compilation errors

1. Run `cargo clean -p <crate>` if you see "compiled by incompatible version of rustc" errors.
2. If the error is in a file you didn't modify, check if another agent's changes conflict.
3. Use `rch exec -- cargo check --all-targets` to verify on the remote worker.

### Q25: `cargo fmt --check` fails on files I didn't touch

Pre-existing formatting drift exists in some files. Only fix formatting in files you're actively modifying. Do not commit formatting-only changes to unrelated files.

### Q26: Tests pass locally but fail in CI

1. Check seed differences — use `--seed N` for deterministic replay.
2. Verify file paths are relative to project root (tests run from project root).
3. Check if CI uses a different compilation profile.
4. Use `rch exec -- ...` to test on a clean remote worker.

### Q27: Where do I find the complete document index?

See `docs/semantic_maintainer_playbook.md` §6 for the full reference table of 13 key semantic documents.
