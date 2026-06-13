# Memory Residency Inventory

This page is the human-readable companion to
`artifacts/memory_residency_inventory_v1.json`. The artifact is the source of
truth for the M1 bead `asupersync-memory-residency-control-ho2itz.1`.

M1 is inventory-only. It maps the existing memory-residency surfaces, names the
owner row for each guarded claim, records the focused RCH proof command, and
keeps explicit no-claim boundaries in one checked file. It does not change
runtime defaults, allocator behavior, cache eviction behavior, admission
policy, or scheduler selection.

## Guarded Claim Rows

| Claim | Existing surface | Focused proof | No-claim boundary |
| --- | --- | --- | --- |
| `runtime_capacity_hints` | `RuntimeCapacityHints` and capacity smoke fixtures in `src/runtime/config.rs` plus `artifacts/runtime_capacity_hints_smoke_contract_v1.json` | `tests/runtime_capacity_hints_contract.rs` through RCH | No scheduler throughput, allocator replacement, NUMA locality, or release readiness claim. |
| `memory_tier_slab_pool_substrate` | `artifacts/memory_tier_slab_pool_contract_v1.json` and `tests/memory_tier_slab_pool_contract.rs` | Existing slab/pool contract test through RCH | Builds on `asupersync-h6pjqb`; does not replace that certificate. |
| `hot_cold_arena_tiers` | `artifacts/hot_cold_arena_tiers_smoke_contract_v1.json`, `scripts/run_hot_cold_arena_tiers_smoke.sh`, and `tests/hot_cold_arena_tiers.rs` | Hot/cold arena contract test through RCH | No real-host memory savings, p999 improvement, or large-page availability claim. |
| `numa_arena_locality` | `artifacts/numa_arena_locality_smoke_contract_v1.json`, `scripts/run_numa_arena_locality_smoke.sh`, and `tests/numa_arena_locality_contract.rs` | NUMA locality contract test through RCH | No host topology, locality-win, or broad scheduler performance claim. |
| `proof_pack_warmth_planner` | `scripts/proof_pack_warmth_planner.py`, `artifacts/proof_pack_cache_key_contract_v1.json`, and `artifacts/proof_pack_warmth_expected_savings_v1.json` | Proof-pack warmth planner contract through RCH | Cache warmth is not correctness evidence. |
| `runtime_pressure_control_evidence` | `src/runtime/resource_monitor.rs`, `src/runtime/resource_monitor_metamorphic.rs`, `src/runtime/rch_health/mod.rs`, and `artifacts/runtime_pressure_control_evidence_contract_v1.json` | Runtime pressure control evidence contract through RCH | No autonomous admission, throughput, regression-closure, or production-on-by-default claim. |
| `swarm_memory_residency_policy` | `src/runtime/scheduler/swarm_evidence.rs` and `artifacts/swarm_memory_residency_policy_contract_v1.json` | Scheduler swarm evidence artifact test through RCH | No general runtime memory-residency controller claim. |

## Mapped Gap

`artifact_cache_pressure_snapshot` maps `src/runtime/cache.rs` because
`ArtifactMemoryPressureSnapshot` and `ArtifactCache` already expose useful
pressure accounting. It is not a guarded claim yet: there is no dedicated
artifact contract, no focused RCH proof lane, and no M3 live hot/warm/cold
accounting row for cache eviction decisions.

Before this can become a claim, M3 must add a checked artifact for cache
accounting semantics, a focused contract test, and explicit fail-closed
eviction boundaries.

## Overlap Decisions

`asupersync-h6pjqb` is substrate, not duplicated. Scheduler hot-path perf is
outside this inventory, and dirty benchmark files are untouched. Fourth-wave
pressure governance remains the signoff surface for pressure-governor evidence.
Validation frontier remains the proof-interpretation surface and does not grant
local Cargo fallback approval. AppSpec/API surface work owns public API shape;
M1 exposes no API and changes no runtime defaults.

## Required Commands

Use these inventory commands when closing M1:

```bash
rg -n "RuntimeCapacityHints|ArenaTemperaturePolicy|ArtifactMemoryPressureSnapshot|ResourceMonitor|SwarmMemoryResidencyPlan" src artifacts tests docs
jq '.claim_rows[].claim_id' artifacts/memory_residency_inventory_v1.json
python3 -m json.tool artifacts/memory_residency_inventory_v1.json >/dev/null
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_residency_inventory_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test memory_residency_inventory_contract -- --nocapture
```

The next implementation child is
`asupersync-memory-residency-control-ho2itz.2`, the deterministic opt-in
residency policy engine. M2 should consume this inventory instead of re-mining
the source tree.
