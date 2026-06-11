<!-- validation-frontier-graph-budgets-v1 -->

# Validation Frontier Graph Budgets

`artifacts/validation_frontier_graph_budgets_v1.json` is the VF6 contract for
focused proof-lane Cargo graph budgets. It complements
`artifacts/proof_lane_manifest_v1.json` and
`artifacts/validation_frontier_inventory_v1.json`: the manifest says what a lane
claims, the inventory classifies the lane, and this contract records the package
budget and forbidden or explicitly scoped heavy edges.

The contract is fixture-backed on purpose. Live Cargo graph checks are proof
commands and must run through `RCH_REQUIRE_REMOTE=1 rch exec -- ...`; the Rust
contract test validates checked cargo-tree excerpts so the verifier itself does
not recreate the broad graph stalls VF6 is trying to prevent.

Budget rows must include:

- the manifest lane id and matching command,
- expected graph roots and feature flags,
- a maximum package-count envelope,
- forbidden packages such as `asupersync-conformance` for focused lanes,
- explicit scoped allowances for known heavy edges, such as fuzz-only
  `opentelemetry-proto -> tonic -> tokio`,
- no-claim boundaries that stop operators from citing a narrow graph as broad
  workspace, release, runtime, or performance evidence.

The contract test is `tests/validation_frontier_graph_budgets_contract.rs`.
Run it with:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_validation_frontier_graph_budgets CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test validation_frontier_graph_budgets_contract -- --nocapture
```

