# Ambient Time And Entropy Semantic Lint

`scripts/semantic_lint.py` implements the first production-useful slice of
`asupersync-idea-wizard-fifth-wave-3gaiun.3.2`: the
`ambient-time-or-entropy-in-lab-sensitive-code` rule from
`artifacts/semantic_lint_rule_inventory_v1.json`.

The rule is scoped to deterministic replay-sensitive paths:

- `src/lab/`
- `src/trace/`
- `src/runtime/scheduler/`
- `tests/`

The runner is ast-grep first. In environments where the `ast-grep` binary is not
available, `--engine auto` uses a deterministic contract-limited fallback and
marks the result with `"engine_fallback": true`. Use `--engine ast-grep` when a
strict ast-grep proof is required.

Example:

```bash
python3 scripts/semantic_lint.py --rule ambient-time-or-entropy-in-lab-sensitive-code --json src/lab tests
```

Allowed findings must name both a reason and an owner bead on the same line or
the immediately preceding line:

```rust
// asupersync-lint:allow ambient-time-or-entropy-in-lab-sensitive-code reason=operator-diagnostic owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
let _snapshot = std::time::SystemTime::now();
```

This lane does not close the full L2 semantic-lint bead. The await-while-holding,
ignored-outcome, loop-checkpoint, obligation, and cleanup-budget rules still need
their own implementations and validation.
