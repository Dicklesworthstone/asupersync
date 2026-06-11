# Cleanup Budget Semantic Lint

`scripts/semantic_lint.py` implements the `unbounded-cleanup-budget` rule from
`artifacts/semantic_lint_rule_inventory_v1.json`.

The rule is a first-pass, warning-level semantic lint for cleanup, drain, and
finalizer paths that appear to use unbounded cleanup budgets or ad hoc wall-time
caps instead of a budget derived from the active `Cx` or parent budget. It is
scoped to:

- `src/supervision.rs`
- `src/cancel/`
- `src/runtime/`
- `src/database/`
- `src/http/`
- `tests/`

Example:

```bash
python3 scripts/semantic_lint.py --rule unbounded-cleanup-budget --json src/runtime src/cancel
```

Allowed findings must name a reason and an owner bead on the same line or the
immediately preceding line:

```rust
// asupersync-lint:allow unbounded-cleanup-budget reason=test-fixture owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
let _budget = Budget::INFINITE;
```

This is not a proof that every cleanup path is bounded. It is a deterministic
lint slice with fixtures and no source rewrites. The broader L2 semantic-lint
bead still needs the rustc-HIR-backed await-while-holding-resource and Outcome
severity rules.
