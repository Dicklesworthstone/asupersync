# Bounded-Load Consistent Hashing

`HashRing::bounded_node_for_key` is the opt-in bounded-load variant of the
distributed hash ring. It keeps ordinary consistent hashing as the primary
placement rule, then walks forward on the ring when the primary node is already
at its computed load cap.

For a lookup with `total_load` already assigned over `N` nodes, the cap is:

```text
ceil(((total_load + 1) / N) * (1 + epsilon_per_mille / 1000))
```

`epsilon_per_mille = 0` is the strict mode: after each assignment no node should
exceed the ceiling of the current mean load when the caller's load snapshot is
internally consistent. Higher values trade a bounded amount of skew for fewer
fallback walks away from the primary vnode.

The lookup is deterministic. Vnodes are sorted by hash, node id, and vnode id;
fallback walks skip duplicate vnodes for the same node; the final emergency
fallback chooses the least-loaded node with node-id tie-breaking. This keeps
replay output stable and avoids `HashMap` iteration order in the routing path.

The distributed symbol assigner exposes the behavior through
`AssignmentStrategy::BoundedLoad { epsilon_per_mille, seed }`. Existing
assignment strategies are unchanged, and the bounded strategy is opt-in.

## No-Claim Boundaries

This lane proves the bounded routing primitive and its symbol-assignment
adoption. It does not prove SWIM membership, remote-spawn placement,
cross-machine ATP transfer, broad distributed runtime health, or release
readiness. It also does not claim a performance win without a separate measured
benchmark lane.
