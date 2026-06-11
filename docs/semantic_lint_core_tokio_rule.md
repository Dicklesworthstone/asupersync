# Core Tokio Feature Leakage Semantic Lint

`scripts/semantic_lint.py` implements the `core-tokio-feature-leakage` rule from
`artifacts/semantic_lint_rule_inventory_v1.json`.

The rule classifies no-Tokio dependency-boundary JSON contracts. It is a
deterministic policy check over `artifacts/no_tokio_feature_boundary_contract_v1.json`
and fixture-shaped contracts:

- default and metrics production profiles must be classified as
  `tokio_free_normal_graph`
- production profiles must not declare any `tokio` dependency path fragments
- fuzz/test/dev profiles that carry Tokio must be explicitly quarantined or
  scoped as audit-only surfaces
- proof commands must be routed through `rch exec -- env`, pin
  `CARGO_TARGET_DIR`, and invoke `cargo tree` against Tokio

Example:

```bash
python3 scripts/semantic_lint.py --rule core-tokio-feature-leakage --json artifacts/no_tokio_feature_boundary_contract_v1.json
```

This rule does not run Cargo and does not replace the live cargo-tree proof
lanes. It makes the no-Tokio production boundary machine-checkable as an L2
semantic-lint policy surface, while the actual dependency graph proof remains in
`tests/no_tokio_feature_boundary_contract.rs` and
`tests/no_tokio_production_feature_graph_regression.rs`.
