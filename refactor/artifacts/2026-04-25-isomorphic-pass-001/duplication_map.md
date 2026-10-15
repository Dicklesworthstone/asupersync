# Duplication Map — 2026-04-25-isomorphic-pass-001

Generated: 2026-04-25 15:33 UTC
Tools run: (none installed)
Raw outputs: refactor/artifacts/2026-04-25-isomorphic-pass-001/scans/

## How to fill this in

1. Read the scan outputs above.
2. Cluster similar findings into candidates (assign IDs D1, D2, …).
3. For each candidate, fill the table row below.
4. Pass to score_candidates.py.

| ID  | Kind | Locations | LOC each | × | Type | Notes |
|-----|------|-----------|----------|---|------|-------|
| ISO-001 | repeated wasm unsupported-feature compile guards | `src/lib.rs` | 2 | 9 | II | Same `#[cfg(all(target_arch = "wasm32", feature = "..."))] compile_error!(...)` shape with only feature name/message varying; collapsed into one local table macro without changing cfg predicates or emitted messages. |
