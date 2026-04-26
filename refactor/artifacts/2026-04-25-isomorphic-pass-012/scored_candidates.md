# Scored Candidates

| Candidate | LOC Saved | Confidence | Risk | Score | Decision |
|---|---:|---:|---:|---:|---|
| Parent-module macro for remaining TCP wasm unsupported-result shims | 2 | 5 | 2 | 5.0 | Landed |

Notes:
- Same subsystem and same error constructor as the already-collapsed `stream` and `split` families.
- Risk is slightly above trivial because the abstraction crosses four sibling modules via a parent-module macro.
