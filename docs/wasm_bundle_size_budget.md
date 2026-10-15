# WASM Bundle Size Budget

**Status**: Normative
**Scope**: `@asupersync/browser-core`, `@asupersync/browser`, `@asupersync/react`, `@asupersync/next`

## Purpose

Define per-package and per-artifact bundle-size budgets so that regressions
are caught before they reach consumers. Every budget has a hard ceiling and a
warning threshold. CI gates MUST fail when any hard ceiling is exceeded.

## Budget Table

| Package | Artifact | Warning (KB) | Hard Ceiling (KB) | Notes |
|---|---|---|---|---|
| `@asupersync/browser-core` | `asupersync_bg.wasm` | 400 | 512 | Primary WASM binary (release profile, wasm-opt -Oz) |
| `@asupersync/browser-core` | `index.js` | 36 | 40 | JS facade wrapping wasm-bindgen exports |
| `@asupersync/browser-core` | `asupersync.js` | 20 | 28 | Raw wasm-bindgen glue |
| `@asupersync/browser-core` | Total publishable | 500 | 640 | Sum of all files in `files` array |
| `@asupersync/browser` | `dist/` total | 12 | 20 | SDK layer (excludes browser-core dep) |
| `@asupersync/react` | `dist/` total | 8 | 16 | React adapter (excludes browser dep) |
| `@asupersync/next` | `dist/` total | 10 | 20 | Next adapter (excludes browser dep) |

### Type Declarations

| Package | Artifact | Warning (KB) | Hard Ceiling (KB) |
|---|---|---|---|
| `@asupersync/browser-core` | `index.d.ts` | 12 | 20 |
| `@asupersync/browser-core` | `types.d.ts` | 4 | 8 |
| `@asupersync/browser` | `dist/*.d.ts` total | 8 | 16 |
| `@asupersync/react` | `dist/*.d.ts` total | 6 | 12 |
| `@asupersync/next` | `dist/*.d.ts` total | 6 | 12 |

## Measurement Method

1. **Static check**: Read the `files` array from `package.json`, sum actual
   file sizes on disk for artifacts that exist.
2. **npm pack check**: Run `npm pack --dry-run` and parse the reported
   unpacked size per package.
3. **Gzip transfer size**: For `.wasm` and `.js` files, report gzip-compressed
   size alongside raw size. The gzip ceiling is 60% of the raw ceiling.

## Tolerance Bands

- **Green**: Below warning threshold.
- **Yellow**: Between warning and hard ceiling. CI passes with advisory note.
- **Red**: Above hard ceiling. CI MUST fail.
- **Delta gate**: Any single PR that increases a package by more than 10% of
  its warning threshold triggers a mandatory review comment, even if the
  result is still in the green band.

## Exemptions

Experimental or debug profiles (`--dev`, `--profiling`) are not subject to
these budgets. Only release-profile artifacts shipped via `npm publish` are
gated.

Source maps (`.js.map`, `.wasm.map`) are excluded from budget totals because
they are development aids and not loaded by consumers at runtime.

## Enforcement

- Contract tests in `tests/wasm_bundle_size_budget_contract.rs` validate
  budgets against actual artifacts when present and against `files` array
  completeness when artifacts are not yet built.
- Machine-readable budgets live in `artifacts/wasm_bundle_size_budget_v1.json`
  for CI tooling consumption.
- The `scripts/validate_package_build.sh` script reports size measurements
  during build validation.
