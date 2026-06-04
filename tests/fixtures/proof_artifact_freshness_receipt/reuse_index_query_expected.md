# Proof reuse query: proof-reuse-index-query

- lane: proof-reuse-cache-contract
- claim_scope: proof-reuse-cache-schema
- candidates_scanned: 6
- accepted: 1
- refused: 4
- misses: 1
- chosen_proof_id: proof:reuse-index-reusable
- top_rerun_command: RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_proof_reuse_cache_contract cargo test -p asupersync --test proof_reuse_cache_contract -- --nocapture

## Ranked candidates
1. proof:reuse-index-reusable | decision=reusable | safe_to_reuse=true | reasons=<none>
2. proof:reuse-index-stale | decision=refused | safe_to_reuse=false | reasons=stale-head
3. proof:reuse-index-failed | decision=refused | safe_to_reuse=false | reasons=failed-proof-status
4. proof:reuse-index-local-fallback | decision=refused | safe_to_reuse=false | reasons=local-fallback-marker
5. proof:reuse-index-dirty-overlap | decision=refused | safe_to_reuse=false | reasons=dirty-frontier-overlap
6. proof:reuse-index-unrelated-lane | decision=miss | safe_to_reuse=false | reasons=lane-mismatch
