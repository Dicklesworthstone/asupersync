# Semantic Lint Rule Inventory

Status: Active
Bead: `asupersync-idea-wizard-fifth-wave-3gaiun.3.1`
Contract: `artifacts/semantic_lint_rule_inventory_v1.json`
Verifier: `tests/semantic_lint_rule_inventory_contract.rs`

<!-- SEMANTIC-LINT-L1-CONTRACT -->

This document is the human-readable projection of the Semantic Lint L1
inventory. The JSON artifact is the source of truth. This page explains the
rule choices, false-positive policy, and engine decisions before any lint rule
is implemented.

The inventory is intentionally scoped to design and governance. It does not
claim that the current source tree is clean. It does not replace Rust compiler
checks, Clippy, lab oracles, RCH proof lanes, or manual review.

<!-- SEMANTIC-LINT-L1-RULE-TABLE -->

## Rule Table

| Rule ID | Risk | Status | Selected engine | Owner bead |
| --- | --- | --- | --- | --- |
| `await-while-holding-capability-resource` | critical | requires-design | rustc-hir | `asupersync-idea-wizard-fifth-wave-3gaiun.3.2` |
| `loop-without-cx-checkpoint` | high | requires-design | hybrid-rustc-hir-ast-grep | `asupersync-idea-wizard-fifth-wave-3gaiun.3.2` |
| `ambient-time-or-entropy-in-lab-sensitive-code` | critical | ready-for-implementation | ast-grep | `asupersync-idea-wizard-fifth-wave-3gaiun.3.2` |
| `ignored-outcome-severity` | high | requires-design | rustc-hir | `asupersync-idea-wizard-fifth-wave-3gaiun.3.2` |
| `drop-based-race-loser-handling` | critical | requires-design | hybrid-rustc-hir-ast-grep | `asupersync-idea-wizard-fifth-wave-3gaiun.3.2` |
| `unbounded-cleanup-budget` | high | ready-for-implementation | ast-grep | `asupersync-idea-wizard-fifth-wave-3gaiun.3.2` |
| `core-tokio-feature-leakage` | critical | ready-for-implementation | cargo-metadata | `asupersync-idea-wizard-fifth-wave-3gaiun.3.2` |

## False-Positive Policy

<!-- SEMANTIC-LINT-L1-ALLOW-POLICY -->

Every future rule must start from an explicit false-positive posture:

| Mode | Meaning |
| --- | --- |
| `deny-by-default` | The rule is precise enough that violations should fail once implementation lands. |
| `warn-before-deny` | The rule is high value but needs calibration and allow markers before deny mode. |
| `inventory-only` | The first implementation reports findings without blocking while semantics are validated. |

Allow markers must include the rule id, a short reason, and an owner bead or
permanent rationale:

```text
asupersync-lint:allow <rule_id> reason=<short reason> owner=<bead-or-permanent-rationale>
```

Markers without both `reason=` and `owner=` are invalid. Permanent rationale is
allowed only when a rule row documents why no bead can own the exception.

## Engine Decisions

<!-- SEMANTIC-LINT-L1-ENGINE-DECISIONS -->

The inventory separates source syntax checks from type-aware and graph-aware
checks:

| Engine | Use it for | Avoid it for |
| --- | --- | --- |
| `ast-grep` | Stable syntax bans such as ambient time calls in lab-sensitive paths. | Type-sensitive guard lifetime and Outcome lattice checks. |
| `rustc-hir` | Type-aware checks such as await-with-guard and ignored Outcome severity. | Dependency graph policy. |
| `hybrid-rustc-hir-ast-grep` | Candidate discovery plus type-aware confirmation, especially race-loser lifecycle and checkpoint rules. | Simple graph invariants. |
| `cargo-metadata` | Feature graph and transitive dependency policy, including no-Tokio production checks. | Source control-flow or lifetime checks. |
| `custom-scanner` | Only narrow generated artifacts or non-Rust inputs where structured parsers are unavailable. | Rust semantic checks where compiler or AST data exists. |

The initial implementation order is:

1. `core-tokio-feature-leakage`
2. `ambient-time-or-entropy-in-lab-sensitive-code`
3. `await-while-holding-capability-resource`

This orders low false-positive graph/syntax rules before the more valuable but
type-aware guard-lifetime rule.

## No Claims

<!-- SEMANTIC-LINT-L1-NO-CLAIMS -->

This L1 contract does not implement any lint rule. It does not certify that the
current tree is free of these issues. It does not make a broad workspace health
claim. It does not authorize local Cargo fallback for future proof lanes.
