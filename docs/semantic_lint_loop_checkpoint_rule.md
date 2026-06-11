# Loop Checkpoint Semantic Lint

`scripts/semantic_lint.py` implements a candidate-scanner slice of the
`loop-without-cx-checkpoint` rule from
`artifacts/semantic_lint_rule_inventory_v1.json`.

The rule looks for async infinite-loop candidates in checkpoint-sensitive paths:

- `src/runtime/`
- `src/lab/`
- `src/transport/`
- `src/database/`
- `src/raptorq/`

The first slice reports `loop { ... .await ... }` and
`while true { ... .await ... }` blocks that do not contain an obvious
`cx.checkpoint()`, cancellation poll, or yield token. Statically bounded `for`
loops are outside this candidate pattern.

Example:

```bash
python3 scripts/semantic_lint.py --rule loop-without-cx-checkpoint --json src/runtime src/lab
```

Allowed findings must name both a reason and an owner bead on the same line or
the immediately preceding line:

```rust
// asupersync-lint:allow loop-without-cx-checkpoint reason=fixture owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
loop {
    poll_once(cx).await;
}
```

This is not a complete rustc-HIR implementation. It is a deterministic
candidate scanner with fixtures, docs, and no source rewrites; future work still
needs type-aware confirmation that the checkpoint is the real `Cx` checkpoint
or a semantically equivalent cancellation poll.
