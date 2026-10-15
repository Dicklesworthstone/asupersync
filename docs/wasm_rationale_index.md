# Browser Rationale Index and Decision Ledger (WASM-15)

Contract ID: `wasm-browser-rationale-index-v1`  
Bead: `asupersync-umelq.16.5`  
Depends on: `asupersync-umelq.16.3`, `asupersync-umelq.16.4`, `asupersync-umelq.18.3`

## Purpose

Provide a single, self-contained rationale ledger for Browser Edition decisions
so maintainers can answer "why does this exist?" without reopening planning
threads or external design documents.

This index is intentionally operational:

1. each decision maps to concrete docs/tests/artifacts,
2. tradeoffs and rejected alternatives are explicit,
3. every section has deterministic validation pointers.

## How To Use This Index

When making a Browser Edition change:

1. locate the nearest decision row in this document,
2. confirm your change preserves the listed invariants,
3. update the row if behavior/constraints changed,
4. run the validation bundle in this document,
5. record evidence in Beads + Agent Mail thread for the active bead.

If no row matches your change, add one before merging.

## Decision Register

| Decision ID | Decision | Why | Tradeoff | Rejected Alternatives | Primary Evidence |
|---|---|---|---|---|---|
| BR-DEC-01 | wasm32 browser builds must use exactly one canonical profile (`wasm-browser-minimal/dev/prod/deterministic`) | Prevent partial/ambiguous feature closure and hidden semantic drift | More compile-time gate friction when experimenting | Ad-hoc feature mixes with best-effort behavior | `src/lib.rs` guardrails, `docs/integration.md`, `docs/wasm_quickstart_migration.md` |
| BR-DEC-02 | Browser path keeps capability security (`Cx`/`Scope`) with no ambient authority | Security and effect boundaries are non-negotiable runtime invariants | Integration adapters require explicit context plumbing | Global singleton context for convenience | `docs/integration.md` capability sections, `docs/wasm_platform_trait_seams.md` |
| BR-DEC-03 | Cancellation remains protocolized (request -> drain -> finalize), and race losers must drain | Prevent task/obligation leaks and nondeterministic cleanup | Slightly higher implementation complexity than drop-on-cancel | Fire-and-forget cancellation that abandons losers | `docs/wasm_cancellation_state_machine.md`, `docs/wasm_loser_drain_audit.md`, `tests/obligation_wasm_parity.rs` |
| BR-DEC-04 | Deterministic diagnostics and replay artifacts are first-class deliverables, not optional debug extras | Browser incidents must be reproducible for confidence and CI triage | Extra artifact/log schema work in every lane | Human-only debugging without replay contract | `docs/wasm_flake_governance_and_forensics.md`, `docs/wasm_pilot_observability_contract.md` |
| BR-DEC-05 | Canonical examples (vanilla/TypeScript/React/Next) are reference behavior contracts | Migration success depends on concrete end-to-end patterns | Examples require ongoing maintenance with API changes | Minimal snippet-only docs with no real integration flows | `docs/wasm_canonical_examples.md` (`asupersync-umelq.16.3`) |
| BR-DEC-06 | Cross-framework browser E2E checks are required for confidence claims | Unit tests alone cannot prove user-path reliability in browser contexts | Longer CI runtime and larger artifact surface | Rely only on unit tests and occasional manual smoke tests | `asupersync-umelq.18.3` artifacts + `scripts/run_all_e2e.sh` verify-matrix lanes |
| BR-DEC-07 | Troubleshooting is symptom -> cause -> command -> expected evidence (deterministic) | Reduces operator guesswork and keeps support load bounded | Requires curated cookbook upkeep as failures evolve | Ad-hoc troubleshooting notes without command discipline | `docs/wasm_troubleshooting_compendium.md` (`asupersync-umelq.16.4`) |
| BR-DEC-08 | Forbidden native surfaces on wasm32 (`tls`, `sqlite`, `postgres`, `mysql`, `kafka`, `io-uring`, etc.) are hard compile errors | Browser release safety requires explicit unsupported-surface policy | Some integrations need alternate architecture instead of direct reuse | Silent stubs or runtime no-op shims for unsupported native features | `docs/integration.md` wasm32 guardrails + dependency policy checks |
| BR-DEC-09 | Release channels gate promotion (`nightly` -> `canary` -> `stable`) with policy checks | Prevents undocumented behavior from becoming stable API | Slower promotion cadence | Direct promotion from local success to stable | `docs/wasm_release_channel_strategy.md`, `scripts/check_wasm_optimization_policy.py` |
| BR-DEC-10 | Redaction/log-quality policy is part of quality gates, not post-hoc hygiene | Forensics quality and security must coexist by default | Additional schema assertions and CI policy checks | Free-form logs and optional redaction discipline | `docs/doctor_logging_contract.md`, `tests/e2e_log_quality_schema.rs` |

## Rejected Alternatives (Global)

### 1. "Browser mode with relaxed invariants"

Rejected because it would make browser behavior semantically different from the
core runtime and invalidate structured-concurrency claims.

### 2. "Compatibility shims for native-only features"

Rejected because fake wasm support for native-only surfaces hides failure modes
and creates silent correctness/security gaps.

### 3. "Documentation as narrative only (no command evidence)"

Rejected because non-reproducible docs increase support burden and make CI
triage non-deterministic.

### 4. "One giant monolithic guide with no contract tests"

Rejected because drift is inevitable without doc-contract assertions.

## Change Protocol

When updating Browser Edition behavior:

1. update affected decision row(s) in this file,
2. update linked docs/tests/scripts in the evidence column,
3. ensure new tradeoff/rejected alternatives are explicit,
4. run the validation bundle below,
5. publish evidence in Beads + Agent Mail thread.

If a decision is superseded, keep the old row and mark it `deprecated` in the
Decision column with the replacement decision ID.

## Validation Bundle

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_docs cargo test --test wasm_rationale_index -- --nocapture

python3 scripts/run_browser_onboarding_checks.py --scenario all

bash ./scripts/run_all_e2e.sh --verify-matrix

rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_docs cargo test --test e2e_log_quality_schema -- --nocapture
```

Expected outcomes:

- rationale index contract test passes,
- onboarding/e2e matrix commands complete with deterministic artifact outputs,
- log-quality schema checks remain green.

## Cross-References

- `docs/integration.md`
- `docs/wasm_quickstart_migration.md`
- `docs/wasm_canonical_examples.md`
- `docs/wasm_troubleshooting_compendium.md`
- `docs/wasm_flake_governance_and_forensics.md`
- `docs/doctor_logging_contract.md`
- `docs/semantic_adr_decisions.md`
