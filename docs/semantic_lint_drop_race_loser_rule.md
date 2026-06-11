# Drop-Based Race Loser Semantic Lint

`scripts/semantic_lint.py` implements a candidate-scanner slice of the
`drop-based-race-loser-handling` rule from
`artifacts/semantic_lint_rule_inventory_v1.json`.

The rule is scoped to race, scope, channel, and task-handle paths:

- `src/combinator/`
- `src/cx/scope.rs`
- `src/channel/`
- `src/runtime/task_handle.rs`

The first slice reports two deterministic high-signal candidates:

- obvious loser-named handles passed to `drop(...)` without nearby abort, join,
  drain, or cancel evidence
- `defuse_drop_abort(...)` calls in loser-named contexts without nearby
  loser-drain proof language

Example:

```bash
python3 scripts/semantic_lint.py --rule drop-based-race-loser-handling --json src/combinator src/cx/scope.rs
```

Allowed findings must name both a reason and an owner bead on the same line or
the immediately preceding line:

```rust
// asupersync-lint:allow drop-based-race-loser-handling reason=fixture owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
drop(loser_handle);
```

This is not a complete rustc-HIR implementation. It is a deterministic
candidate scanner with fixtures, docs, and no source rewrites; future work still
needs type-aware confirmation that the dropped value owns a task, future,
permit, or cancellation obligation.
