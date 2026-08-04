# E1.2 subsystem 3b attribution — ordered completion backing (bt4y5f.2.2)

Change: three_lane completion blocks (E1.1 rows T16/T17/T18/T20/T21, plus
the T22 drain) deduplicated into one ordered completion seam
(complete_polled_task_ordered / complete_task_after_unwind_ordered /
drain_ready_finalizers_locked); state.rs finish_task_completion decomposed
into shard-phase table ops. Behavior-preserving by construction; this
artifact attributes the completion-path cost shape after the restructure.

Host: hz2 (both runs same host, same lane, sequential). Baseline =
--no-overlay at HEAD f13fd9f58; change = clean overlay of exactly the five
3b files over the same HEAD. Instrument: benches/spawn_throughput.rs.
Point estimates (criterion midpoints).

## Comparator rows (mailbox over direct, within one run — the instrument)

| row | HEAD | +3b |
|-----|------|-----|
| spawn_throughput single_producer_latched | direct 15.40ms vs mailbox 10.61ms (+45%) | direct 16.46ms vs mailbox 11.31ms (+45%) |
| contended_persistent_latched_4_producers | 18.43ms vs 12.67ms (+46%) | 24.55ms vs 15.39ms (+60%) |
| contended_persistent_latched_8_producers | 24.54ms vs 15.23ms (+61%) | 23.80ms vs 14.37ms (+66%) |
| join_handle_completion spawn_then_await_all | 15.14ms vs 11.06ms (+37%) | 15.21ms vs 8.83ms (+72%) |

Mailbox-over-direct advantage preserved or improved on every comparator
row; the join_handle completion row — the path that carries the new seam —
shows the largest within-run advantage.

## Cross-run absolute deltas (recorded, NOT actionable)

Disjoint rows moved in both directions across the two runs (e.g.
4-producer rows +21..33% slower, join_set_fanout/1000 rows ~20% faster,
join_all/10000 +42% slower while join_all/1000 improved). This is the
documented co-tenant drift class on this host fleet (br-asupersync-87h3es:
clean-HEAD controls red on day-old baselines; drift +15..111% same-host).
Per the epic's measurement protocol these cross-run absolutes are
direction-only; the within-run comparator above is the instrument. No
rows re-recorded; no waiver claimed.
