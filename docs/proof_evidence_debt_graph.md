# Proof Evidence Debt Graph

The proof evidence debt graph is a deterministic operator report for stale,
superseded, blocked, zero-test, local-fallback, missing-envelope, advisory, and
failed proof evidence. It ranks which artifacts need a fresh rerun before they
can be cited for correctness claims.

This report does not certify workspace health. It also does not convert cached,
approved, or advisory-only evidence into a fresh RCH proof. It is a debt and
rerun planner for already recorded proof evidence.

## Contract Surface

- Helper: `scripts/proof_evidence_debt_graph.py`
- Contract artifact: `artifacts/proof_evidence_debt_graph_contract_v1.json`
- Rust contract test: `tests/proof_evidence_debt_graph_contract.rs`
- Operator documentation: `docs/proof_evidence_debt_graph.md`

The helper is read-only. It consumes an explicit fixture or contract JSON file
and emits JSON or Markdown to stdout. It does not run Cargo, inspect Agent Mail,
mutate Git, query the tracker, or rewrite artifacts.

## Reason Codes

The contract fixture exercises each fail-closed reason code exactly once:

- `blocked-by-peer-reservation`: a peer holds an active reservation over a
  touched path, so the lane needs coordination before rerun.
- `dirty-overlap`: the artifact touches paths that are dirty in the source tree.
- `local-fallback`: the proof used local fallback instead of remote-required
  RCH evidence.
- `missing-envelope`: the lane lacks the required RCH command prefix, target
  directory, timeout, memory, or remote-required envelope.
- `zero-tests`: the proof command completed without executing tests.
- `stale-head`: the artifact was recorded at a different source HEAD.
- `superseded-by-newer-artifact`: a newer artifact replaces the older evidence.
- `advisory-only`: the evidence is operator guidance, not correctness proof.
- `failed-proof-status`: the proof status is failed or otherwise non-passing.

Rows with any reason code are not safe to cite for correctness claims. Rows with
`advisory-only` remain advisory even if the underlying command envelope is
otherwise well formed.

## Usage

Emit the deterministic JSON report from the checked contract fixture:

```bash
python3 scripts/proof_evidence_debt_graph.py \
  --fixture artifacts/proof_evidence_debt_graph_contract_v1.json \
  --generated-at 2026-06-06T08:20:00Z \
  --output json
```

Emit the Markdown operator report:

```bash
python3 scripts/proof_evidence_debt_graph.py \
  --fixture artifacts/proof_evidence_debt_graph_contract_v1.json \
  --generated-at 2026-06-06T08:20:00Z \
  --output markdown
```

Validate the contract with the focused RCH lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_proof_evidence_debt_graph" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test proof_evidence_debt_graph_contract -- --nocapture
```

The graph is intentionally narrower than the proof lane manifest and proof
status snapshot. Use it to decide which evidence is stale, blocked, superseded,
or invalid to cite. Use the manifest and focused RCH lanes for actual proof
admission.
