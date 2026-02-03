# Formal Semantics Mechanization

This folder hosts proof-assistant artifacts for the Asupersync small-step semantics.
The source of truth for the rules is:

- `asupersync_v4_formal_semantics.md`

The Lean scaffold lives in `formal/lean/` and is intentionally minimal at first:
- Core domains and state skeletons
- Labels + step relation placeholders
- A place to incrementally encode the rules from the semantics document

## Lean (preferred)

The Lean project is self-contained under `formal/lean/` and does not affect the Rust
crate or Cargo builds. Enter that directory to build:

```bash
cd formal/lean
lake build
```

## Next steps (bd-330st)

- Encode the full domain/state definitions from §1 of the semantics
- Add the small-step rules as inductive constructors
- Prove well-formedness preservation and progress for the operational rules

