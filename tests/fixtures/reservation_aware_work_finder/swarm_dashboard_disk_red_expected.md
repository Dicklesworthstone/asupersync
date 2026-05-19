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
| ready beads | 0 |
| fallback lanes | 2 |
| stale in-progress | 0 |

## Recommendation
| Field | Value |
| --- | --- |
| category | `run-fallback-lane` |
| candidate | `testing-golden-artifacts:source-only-handoff` |
| lane | `testing-golden-artifacts` |
| validation | `source-only` |
| reason | first unblocked candidate by kind and priority |
| safety | no active peer reservation or dirty path blocks the candidate; no tracker mutation required |

Files to reserve:
- `scripts/reservation_aware_work_finder.py`
- `tests/fixtures/reservation_aware_work_finder/disk_pressure_autopilot_e2e.json`

## Coordination Churn
| Field | Value |
| --- | --- |
| active agents | 0 |
| ack-required backlog | 0 |
| tracker lock active | no |
| tracker holder | - |
| stale in-progress | 0 |
| max stale age minutes | 0 |
| peer dirty paths | 1 |
| source-only safe | yes |
| next action | `avoid-peer-dirty-paths-and-use-safe-recommendation` |
| stale action | `none` |

## Safe Work
| Candidate | Lane | Validation | Safety |
| --- | --- | --- | --- |
| `testing-golden-artifacts:source-only-handoff` | `testing-golden-artifacts` | `source-only` | no active peer reservation or dirty path blocks the candidate; no tracker mutation required |

## Blockers
| Candidate | Kind | Owner | Path | Reason |
| --- | --- | --- | --- | --- |
| `testing-fuzzing:critical-rch-only` | `critical-disk-pressure-rch-heavy` | - | - | critical disk pressure blocks rch/Cargo-heavy recommendations |
| `testing-fuzzing:critical-rch-only` | `active-reservation` | RubyRobin | fuzz/fuzz_targets/websocket_frame_fuzzing.rs | - |
| `testing-fuzzing:critical-rch-only` | `dirty-peer-path` | RubyRobin | fuzz/fuzz_targets/websocket_frame_fuzzing.rs | dirty-entry |

## Active Reservations
| Path | Holder | Exclusive | Expires |
| --- | --- | --- | --- |
| `fuzz/fuzz_targets/websocket_frame_fuzzing.rs` | RubyRobin | yes | `2026-05-18T22:00:00Z` |

## Dirty Paths
| Path | Status | Owner |
| --- | --- | --- |
| `fuzz/fuzz_targets/websocket_frame_fuzzing.rs` | `M` | RubyRobin |

## Disk And Proof
| Field | Value |
| --- | --- |
| disk level | `critical` |
| available | 256.00 MiB |
| rch heavy work allowed | no |
| ballast releasable | 0 B |
| proof status | `pass` |
| proof decision | `pass-with-retrieval-blocker` |
| proof target | `/tmp/rch_target_rubyrobin_websocket` |
| retrieval status | `blocked` |
| retrieval blocker | rsync: [receiver] write failed on "/tmp/.rch-target/websocket_frame_fuzzing": No space left on device (28) |

## Cleanup Authorization
| Candidate | Path | Reclaimable | Requires Auth | Delete Command |
| --- | --- | --- | --- | --- |
| `rch_target_stale_large` | `/tmp/rch_target_stale_large` | 2.00 GiB | yes | none |

## Stale In-Progress
No stale in-progress issues in snapshot.

## Safety
| Invariant | Value |
| --- | --- |
| mutating commands executed | no |
| beads mutated | no |
| agent mail mutated | no |
| cargo executed | no |
| branch/worktree operations | no |
| forbidden command tokens | 0 |
