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

## Coordination Churn
| Field | Value |
| --- | --- |
| active agents | 3 |
| ack-required backlog | 2 |
| tracker lock active | yes |
| tracker holder | RubyRobin |
| stale in-progress | 1 |
| max stale age minutes | 180 |
| peer dirty paths | 2 |
| source-only safe | yes |
| next action | `ack-required-mail-before-new-work` |
| stale action | `coordinate-before-reopen-or-force-release` |

## Safe Work
| Candidate | Lane | Validation | Safety |
| --- | --- | --- | --- |
| `mock-code-finder:source-only-finder` | `mock-code-finder` | `source-only` | no active peer reservation or dirty path blocks the candidate; no tracker mutation required |

## Blockers
| Candidate | Kind | Owner | Path | Reason |
| --- | --- | --- | --- | --- |
| `asupersync-vjc3pv.4` | `tracker-active-reservation` | RubyRobin | .beads/issues.jsonl | candidate requires a Beads tracker mutation while the tracker ledger is reserved |

## Active Reservations
| Path | Holder | Exclusive | Expires |
| --- | --- | --- | --- |
| `.beads/issues.jsonl` | RubyRobin | yes | `2026-05-10T09:30:00Z` |
| `src/http/h2/stream.rs` | BoldTower | yes | `2026-05-10T09:25:00Z` |

## Dirty Paths
| Path | Status | Owner |
| --- | --- | --- |
| `scripts/local_scratch_note.txt` | `M` | CopperSpring |
| `src/http/h2/stream.rs` | `M` | BoldTower |
| `tests/swarm_evidence_pack_contract.rs` | `??` | RubyRobin |

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
| `asupersync-stale-owner` | DormantAgent | 180 | coordinate-before-reopen-or-force-release | no | no |

## Safety
| Invariant | Value |
| --- | --- |
| mutating commands executed | no |
| beads mutated | no |
| agent mail mutated | no |
| cargo executed | no |
| branch/worktree operations | no |
| forbidden command tokens | 0 |
