# Asupersync Error Codes

The Asupersync runtime error namespace uses stable `ASUP-Exxx` tokens so
agents, logs, tests, and operators can turn failures into a lookup path. The
machine surface is [`registry.json`](./registry.json). Each code also has a
short remediation page with the same template:

- Symptom
- Probable Causes
- Fix
- Example
- Related

`status = "live"` means the token is already emitted from `src/`.
`status = "reserved"` means the code and remediation page are allocated for
the next source-wiring slice. Reserved codes are still useful for issue
triage, but tests must not claim they are emitted until a source reference
lands.

## First-Day Catalog

| Code | Status | Area | Page |
|------|--------|------|------|
| ASUP-E001 | live | core-runtime | [Runtime unavailable](./ASUP-E001.md) |
| ASUP-E002 | live | core-runtime | [Region not found](./ASUP-E002.md) |
| ASUP-E003 | live | core-runtime | [Region closed](./ASUP-E003.md) |
| ASUP-E004 | live | core-runtime | [Local scheduler unavailable](./ASUP-E004.md) |
| ASUP-E005 | live | core-runtime | [Name registration failed](./ASUP-E005.md) |
| ASUP-E006 | live | core-runtime | [Region at capacity](./ASUP-E006.md) |
| ASUP-E007 | live | core-runtime | [Authorization denied](./ASUP-E007.md) |
| ASUP-E101 | live | obligations | [Obligation leaked](./ASUP-E101.md) |
| ASUP-E102 | live | obligations | [Obligation double resolve](./ASUP-E102.md) |
| ASUP-E103 | live | obligations | [Root-region obligation](./ASUP-E103.md) |
| ASUP-E104 | live | obligations | [Obligation abort missing](./ASUP-E104.md) |
| ASUP-E105 | live | obligations | [Obligation drain timeout](./ASUP-E105.md) |
| ASUP-E201 | live | channels-sync | [Channel closed](./ASUP-E201.md) |
| ASUP-E202 | live | channels-sync | [Send permit leaked](./ASUP-E202.md) |
| ASUP-E203 | live | channels-sync | [Receive cancelled](./ASUP-E203.md) |
| ASUP-E204 | live | channels-sync | [Semaphore permit exhausted](./ASUP-E204.md) |
| ASUP-E205 | live | channels-sync | [Lock-order violation](./ASUP-E205.md) |
| ASUP-E301 | live | cancellation-drain | [Cancel drain timeout](./ASUP-E301.md) |
| ASUP-E302 | live | cancellation-drain | [Race loser not drained](./ASUP-E302.md) |
| ASUP-E303 | live | cancellation-drain | [Finalizer timeout](./ASUP-E303.md) |
| ASUP-E401 | live | lab-replay | [Replay divergence](./ASUP-E401.md) |
| ASUP-E402 | live | lab-replay | [Futurelock detected](./ASUP-E402.md) |
| ASUP-E403 | live | lab-replay | [Lab seed nondeterminism](./ASUP-E403.md) |
| ASUP-E501 | live | net-http | [HTTP deadline exhausted](./ASUP-E501.md) |
| ASUP-E502 | live | net-http | [Web handler panic recovered](./ASUP-E502.md) |
| ASUP-E503 | live | net-http | [Web header rejected](./ASUP-E503.md) |
| ASUP-E601 | live | database | [Database pool acquire timeout](./ASUP-E601.md) |
| ASUP-E701 | live | distributed-remote | [ATP command not implemented](./ASUP-E701.md) |
| ASUP-E702 | live | distributed-remote | [ATP transfer listener bind failed](./ASUP-E702.md) |
| ASUP-E801 | live | raptorq | [ATP RQ no convergence](./ASUP-E801.md) |
| ASUP-E802 | live | raptorq | [ATP capability mismatch](./ASUP-E802.md) |
| ASUP-E803 | live | raptorq | [ATP block-size mismatch](./ASUP-E803.md) |
| ASUP-E804 | live | raptorq | [ATP pacer stall](./ASUP-E804.md) |
| ASUP-E805 | live | raptorq | [ATP decode-rank stall](./ASUP-E805.md) |
| ASUP-E901 | live | config-build | [Config invalid](./ASUP-E901.md) |
| ASUP-E902 | live | config-build | [Semantic lint ambient determinism](./ASUP-E902.md) |
| ASUP-E903 | live | config-build | [Semantic lint await holding resource](./ASUP-E903.md) |
| ASUP-E904 | live | config-build | [Semantic lint loop checkpoint](./ASUP-E904.md) |
| ASUP-E905 | live | config-build | [Semantic lint outcome severity](./ASUP-E905.md) |
| ASUP-E906 | live | config-build | [Semantic lint race loser drain](./ASUP-E906.md) |
| ASUP-E907 | live | config-build | [Semantic lint cleanup budget](./ASUP-E907.md) |
| ASUP-E908 | live | config-build | [Semantic lint core Tokio boundary](./ASUP-E908.md) |
