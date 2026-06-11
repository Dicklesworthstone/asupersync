# Await-Holding Resource Semantic Lint

`scripts/semantic_lint.py` implements a candidate-scanner slice of the
`await-while-holding-capability-resource` rule from
`artifacts/semantic_lint_rule_inventory_v1.json`.

The rule is scoped to resource-sensitive sync, channel, obligation, capability
registry, and database paths:

- `src/sync/`
- `src/channel/`
- `src/obligation/`
- `src/cx/registry.rs`
- `src/database/`

The first slice reports obvious local bindings where a guard, permit, lease, or
capability token reaches a later `.await` before an explicit `drop(name)`.

Example:

```bash
python3 scripts/semantic_lint.py --rule await-while-holding-capability-resource --json src/sync src/database
```

Allowed findings must name both a reason and an owner bead on the same line or
the immediately preceding line:

```rust
let guard = mutex.lock(cx).await;
// asupersync-lint:allow await-while-holding-capability-resource reason=fixture owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
send_work(cx).await;
drop(guard);
```

This is not a complete rustc-HIR implementation. It is a deterministic
candidate scanner with fixtures, docs, and no source rewrites; future work still
needs type-aware confirmation for aliases, tuple fields, helper-returned guards,
and drops performed by helper calls.
