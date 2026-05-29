# Module-Scoped Proof Microharnesses

Module microharnesses are narrow proof lanes for cases where the implementation
is already on `main`, but the historical proof command is trapped behind a broad
`--lib` test graph, legacy harness feature, dev-dependency surface, or silent
remote stall. They are not release gates by themselves.

## Standard Pattern

1. Name the blocked bead, the implementation bead, the proof target, the exact
   Cargo test target, and the guarantee in the runner output.
2. Compile `asupersync` as a dependency from an integration test whenever the
   proof only needs public or `test-internals` API. That avoids compiling the
   crate's broad inline `#[cfg(test)]` graph.
3. Run the proof through `rch exec` with an isolated `CARGO_TARGET_DIR`.
4. Emit a receipt with the bead id, command, target dir, selected worker, last
   compile frontier, test count, pass/fail status, retry recommendation, and
   artifact paths.
5. Declare exclusions in the receipt and in review notes. A microharness must
   never claim to replace the full release proof, the final stub ratchet, or a
   broader e2e lane.

## First Lane: `asupersync-to7e65.12`

The first executable lane is:

```bash
python3 scripts/module_microharness_proof.py --execute --lane raptorq-table-invariant --run-id to7e65_12_$(date -u +%Y%m%dT%H%M%SZ)
```

The runner expands to an `rch` command shaped like:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_l5m170_1_raptorq_table_invariant_<run-id> ASUPERSYNC_PROOF_BEAD=asupersync-to7e65.12 ASUPERSYNC_PROOF_LANE=raptorq-table-invariant cargo test -p asupersync --test raptorq_proof_table_invariant_microharness --no-default-features --features test-internals -- --nocapture
```

Guarantee:

`ProofArtifactDistributionError::RfcTableInvariantViolation` preserves RFC 6330
table corruption evidence in display and JSON serialization, and the old
unsupported-source-block sentinel text does not reappear.

Exclusions:

- It does not run the broad `cargo test --lib` graph.
- It does not prove full RaptorQ encode/decode recovery.
- It does not replace the final mock-code-finder stub scan, inventory
  regeneration, or release proof gates.

The receipt is closeout evidence only for the specific blocked proof target it
names. Any broader claim still needs the corresponding broader proof lane.
