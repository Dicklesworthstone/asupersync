# doctor scan-workspace Contract

## Scope

`asupersync doctor scan-workspace` provides deterministic discovery of:

- Cargo workspace members
- capability-flow surfaces referenced by each member
- evidence paths for each detected surface
- non-fatal scan warnings

This contract defines the output schema and determinism guarantees for
`asupersync-2b4jj.2.1`.

## Command

```bash
asupersync doctor scan-workspace --root <workspace-root>
```

## Output Schema

The command emits a `WorkspaceScanReport`.

```json
{
  "root": "string",
  "workspace_manifest": "string",
  "members": [
    {
      "name": "string",
      "relative_path": "string",
      "manifest_path": "string",
      "rust_file_count": 0,
      "capability_surfaces": ["string"]
    }
  ],
  "capability_edges": [
    {
      "member": "string",
      "surface": "string",
      "evidence_count": 0,
      "sample_files": ["string"]
    }
  ],
  "warnings": ["string"]
}
```

## Determinism Guarantees

1. Member ordering is lexical by `relative_path`.
2. Surface ordering is lexical by `surface`.
3. Edge ordering is lexical by `(member, surface)`.
4. Sample file ordering is lexical by relative path.
5. Wildcard expansion (`path/*`) is deterministic.
6. Missing members and unsupported globs are emitted as warnings, not hard failures.

## Surface Taxonomy (v1)

- `cx`
- `scope`
- `runtime`
- `channel`
- `sync`
- `lab`
- `trace`
- `net`
- `io`
- `http`
- `cancel`
- `obligation`

## Warning Semantics

Warnings are advisory and do not fail the command.

Current warning classes:

- missing member manifest (`member missing Cargo.toml`)
- missing wildcard base (`wildcard base missing`)
- unsupported workspace glob form (`unsupported workspace member glob pattern`)

## Compatibility Notes

- New fields must be additive and backward-compatible.
- Existing fields are stable for consumers in doctor track 2.
- Taxonomy expansion should append new surfaces without renaming existing labels.
