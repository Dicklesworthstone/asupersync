# Ignored Outcome Severity Semantic Lint

`scripts/semantic_lint.py` implements a candidate-scanner slice of the
`ignored-outcome-severity` rule from
`artifacts/semantic_lint_rule_inventory_v1.json`.

The rule is scoped to Outcome-sensitive task, runtime, combinator, lab, and
trace paths:

- `src/runtime/`
- `src/supervision.rs`
- `src/combinator/`
- `src/lab/`
- `src/trace/`

The first slice reports two deterministic high-signal candidates:

- an explicit `Outcome::Cancelled ... => Outcome::Ok` match arm
- explicit `let _ = Outcome::...` ignored severity values

Example:

```bash
python3 scripts/semantic_lint.py --rule ignored-outcome-severity --json src/runtime src/combinator
```

Allowed findings must name both a reason and an owner bead on the same line or
the immediately preceding line:

```rust
// asupersync-lint:allow ignored-outcome-severity reason=fixture owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
let _ = Outcome::Ok(());
```

This is not a complete rustc-HIR implementation. It is a deterministic
candidate scanner with fixtures, docs, and no source rewrites; future work still
needs type-aware confirmation for ignored variables whose type is `Outcome` and
for multi-line severity collapses. Lines that merely contain both
`Outcome::Cancelled` and `Outcome::Ok` in a tuple or test vector are outside
this candidate pattern, as are `let _ = helper(... Outcome::Ok(...))` calls
where the ignored value is the helper result rather than the `Outcome` literal.
