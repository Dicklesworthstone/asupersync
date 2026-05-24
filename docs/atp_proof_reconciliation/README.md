# ATP Proof Reconciliation

This directory records ATP-NR14 reconciliation findings for older closed ATP-N proof claims. The machine-readable inventory is `artifacts/atp_proof_reconciliation_v1.json`, and `tests/atp_proof_reconciliation_contract.rs` enforces the contract.

## Policy

Closed historical ATP-N beads are not deleted or rewritten. If a closure is too broad for the current implementation, the reconciliation artifact marks it stale or superseded and routes release signoff to the current ATP-NR gate.

No row in this inventory directly satisfies ATP-NR13. Accepted rows are foundations only; the release proof aggregator must consume fresh ATP-NR gates and artifacts.

## Findings

| Bead | Historical claim | Current reconciliation | Replacement or release gate |
| --- | --- | --- | --- |
| `asupersync-9tty78` | Per-module unit/property/metamorphic contract and ledger are complete enough for release gates. | Stale and overbroad: the live ledger still reports `TESTED: 0` and all critical path modules are `PLANNED`. | ATP-NR1, ATP-NR3, ATP-NR13 |
| `asupersync-33lyim` | Native QUIC conformance, fuzz, packet lab, and endpoint e2e proof are complete. | Superseded by current ATP-NR native endpoint and release-proof gates. | ATP-NR8, ATP-NR13 |
| `asupersync-fkfntf` | Object graph, manifest, disk, journal, verifier, and crash-resume proof suite is complete. | Superseded by ATP-NR object-transfer and crash/resume gates; the coverage ledger still shows key modules as planned. | ATP-NR6, ATP-NR7, ATP-NR13 |
| `asupersync-m20jwv` | CLI, atpd, SDK, and user-journey scripts with structured logs are complete. | Superseded by current no-mock multiprocess and CLI/SDK/daemon gates. | ATP-NR5, ATP-NR10, ATP-NR13 |
| `asupersync-utdpso` | Structured log, redaction, failure-bundle, and replay-artifact contract exists. | Accepted foundation, reinforced by the ATP-NR4 golden-log corpus. | ATP-NR4, ATP-NR13 |
| `asupersync-z6ehte` | Cross-platform proof lane matrix is complete. | Superseded by ATP-NR11 and ATP-NR13; existing proof-status snapshot is stale under ATP-NR0 policy. | ATP-NR11, ATP-NR13, ATP-NR14 |
| `asupersync-xvaftm` | Definition-of-Done enforcement infrastructure exists. | Accepted governance foundation only. Live truth comes from ATP-NR0 and ATP-NR13. | ATP-NR0, ATP-NR13, ATP-NR14 |

## Dashboard Reflection

ATP-NR14 is now represented in `artifacts/atp_completion_dashboard_contract_v1.json` with required artifacts for this reconciliation. This makes missing reconciliation evidence visible in the ATP-NR0 dashboard and prevents ATP-NR13 from treating broad historical ATP-N closures as fresh release proof.
