# Obligation Query API Proof Note

Commit: `ca5e5c45a`
Bead: `asupersync-core-introspection-nc8h0u.1`

## Claim

The obligation query API added by this slice is observational only. It exposes
snapshot counts, deterministic audit records, individual obligation state, and
panic-unwind leak snapshots without changing obligation acquisition,
commit, abort, leak, or drain transitions.

## Safety Argument

`ObligationCounts` and `ObligationAuditRecord` are computed from existing
ledger/table records on demand. They do not add background sampling, hooks,
callbacks, atomics, or per-transition writes. The query methods iterate over
the existing `BTreeMap` storage and preserve deterministic ordering by
obligation id. Because the write path still updates only the existing
lifecycle fields and counters, the linear-token invariant remains:

```text
total_acquired == committed + aborted + leaked + pending
```

The panic leak snapshot is a structured read of the pre-existing panic leak
counter. It does not alter drop behavior; it makes the existing diagnostic
surface visible to tests and future inspector code.

## Evidence

- RCH `29880940465488027`: `cargo check -p asupersync --lib` passed.
- RCH `29880940465488029`: `cargo check -p asupersync --lib --features test-internals` passed.
- RCH `29880940465488032`: all new obligation doctests passed; the command
  exited red only on unrelated pre-existing doctest failures outside the
  obligation query surface.
- Unit coverage now exercises counts by region/task/kind, deterministic audit
  ordering, leaked-state visibility, direct state lookup, and panic leak
  snapshots.

## Remaining Direct-Main Gate

Hot-path neutrality for this commit is a benchmark evidence item, not a proof
obligation satisfied by this note alone. The required benchmark/flamegraph
evidence is tracked separately on the bead before closeout.
