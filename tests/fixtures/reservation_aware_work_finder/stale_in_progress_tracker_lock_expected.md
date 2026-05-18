# Swarm Evidence Dashboard

| Field | Value |
| --- | --- |
| Schema | `reservation-aware-work-finder-v1` |
| Generated | `2026-05-10T09:05:00Z` |
| Current date | `2026-05-10` |
| Agent | `CopperSpring` |
| Repo | `/data/projects/asupersync` |

## Summary
| Metric | Value |
| --- | --- |
| candidates | 2 |
| ready | 1 |
| blocked | 1 |
| ready beads | 1 |
| fallback lanes | 1 |
| stale in-progress | 1 |

## Recommendation
| Field | Value |
| --- | --- |
| category | `run-fallback-lane` |
| candidate | `mock-code-finder:source-only-finder` |
| lane | `mock-code-finder` |
| validation | `source-only` |
| reason | first unblocked candidate by kind and priority |
| safety | no active peer reservation or dirty path blocks the candidate; no tracker mutation required |

Files to reserve:
- `scripts/reservation_aware_work_finder.py`

## Safe Work
| Candidate | Lane | Validation | Safety |
| --- | --- | --- | --- |
| `mock-code-finder:source-only-finder` | `mock-code-finder` | `source-only` | no active peer reservation or dirty path blocks the candidate; no tracker mutation required |

## Blockers
| Candidate | Kind | Owner | Path | Reason |
| --- | --- | --- | --- | --- |
| `asupersync-ready-needs-tracker` | `tracker-active-reservation` | BoldTower | .beads/issues.jsonl | candidate requires a Beads tracker mutation while the tracker ledger is reserved |

## Active Reservations
| Path | Holder | Exclusive | Expires |
| --- | --- | --- | --- |
| `.beads/issues.jsonl` | BoldTower | yes | `2026-05-10T09:30:00Z` |

## Dirty Paths
No dirty paths in snapshot.

## Disk And Proof
| Field | Value |
| --- | --- |
| disk level | `unknown` |
| available | unknown |
| rch heavy work allowed | yes |
| ballast releasable | unknown |
| proof status | `unknown` |
| proof decision | `unknown` |
| proof target | - |
| retrieval status | `unknown` |
| retrieval blocker | - |

## Cleanup Authorization
No cleanup candidates in snapshot.

## Stale In-Progress
| Issue | Owner | Age Minutes | Action | Force Released | Reopened |
| --- | --- | --- | --- | --- | --- |
| `asupersync-stale-agent` | DormantAgent | 140 | coordinate-before-reopen-or-force-release | no | no |

## Safety
| Invariant | Value |
| --- | --- |
| mutating commands executed | no |
| beads mutated | no |
| agent mail mutated | no |
| cargo executed | no |
| branch/worktree operations | no |
| forbidden command tokens | 0 |
