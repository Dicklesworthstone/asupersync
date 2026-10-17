    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::time::VirtualClock;
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    fn scrub_vclock_output(value: Value) -> Value {
        fn scrub_node_names(text: &str) -> String {
            text.replace("alpha-node", "[NODE_A]")
                .replace("beta-node", "[NODE_B]")
        }

        fn scrub_value(value: &mut Value) {
            match value {
                Value::String(text) => *text = scrub_node_names(text),
                Value::Array(values) => {
                    for entry in values {
                        scrub_value(entry);
                    }
                }
                Value::Object(map) => {
                    for entry in map.values_mut() {
                        scrub_value(entry);
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) => {}
            }
        }

        let mut scrubbed = value;
        scrub_value(&mut scrubbed);
        scrubbed
    }

    #[test]
    fn empty_clocks_are_equal() {
        let a = VectorClock::new();
        let b = VectorClock::new();
        assert_eq!(a.causal_order(&b), CausalOrder::Equal);
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Equal));
    }

    #[test]
    fn increment_creates_happens_before() {
        let n = node("A");
        let mut a = VectorClock::new();
        let b = a.clone();
        a.increment(&n);
        assert_eq!(b.causal_order(&a), CausalOrder::Before);
        assert!(b.happens_before(&a));
    }

    #[test]
    fn concurrent_detection() {
        let na = node("A");
        let nb = node("B");
        let mut a = VectorClock::new();
        let mut b = VectorClock::new();
        a.increment(&na);
        b.increment(&nb);
        assert_eq!(a.causal_order(&b), CausalOrder::Concurrent);
        assert!(a.is_concurrent_with(&b));
        assert_eq!(a.partial_cmp(&b), None);
    }

    #[test]
    fn lamport_tick_and_receive() {
        let clock = LamportClock::new();
        let t1 = clock.tick();
        let t2 = clock.tick();
        assert!(t2 > t1);

        let remote = LamportTime::from_raw(10);
        let merged = clock.receive(remote);
        assert!(merged.raw() > remote.raw());
    }

    #[test]
    #[should_panic(expected = "Lamport clock overflowed while ticking")]
    fn lamport_tick_panics_on_overflow() {
        let clock = LamportClock::with_start(u64::MAX);
        let _ = clock.tick();
    }

    #[test]
    #[should_panic(expected = "Lamport clock overflowed while merging a received time")]
    fn lamport_receive_panics_on_overflow() {
        let clock = LamportClock::with_start(u64::MAX - 1);
        let _ = clock.receive(LamportTime::from_raw(u64::MAX));
    }

    #[test]
    fn hybrid_clock_deterministic_with_virtual_time() {
        let virtual_clock = Arc::new(VirtualClock::new());
        let hlc = HybridClock::new(virtual_clock.clone());

        let t1 = hlc.tick();
        let t2 = hlc.tick();
        assert!(t2 >= t1);

        virtual_clock.advance(1_000);
        let t3 = hlc.tick();
        assert!(t3.physical() >= t2.physical());
    }

    #[test]
    fn hybrid_now_resets_logical_when_physical_advances() {
        let virtual_clock = Arc::new(VirtualClock::new());
        let hlc = HybridClock::new(virtual_clock.clone());

        let t1 = hlc.tick();
        assert_eq!(t1.logical(), 1);

        virtual_clock.advance(1_000);
        let observed = hlc.now();
        assert!(observed.physical() > t1.physical());
        assert_eq!(observed.logical(), 0);

        let t2 = hlc.tick();
        assert!(t2 >= observed);
    }

    #[test]
    #[should_panic(expected = "Hybrid clock logical counter overflowed while ticking")]
    fn hybrid_tick_panics_on_logical_overflow() {
        let time_source: Arc<dyn TimeSource> = Arc::new(VirtualClock::new());
        let hlc = HybridClock {
            time_source,
            state: Mutex::new(HybridState {
                last_physical: Time::ZERO,
                logical: u64::MAX,
            }),
        };

        let _ = hlc.tick();
    }

    #[test]
    #[should_panic(
        expected = "Hybrid clock logical counter overflowed while merging equal physical time"
    )]
    fn hybrid_receive_panics_on_equal_physical_logical_overflow() {
        let time_source: Arc<dyn TimeSource> = Arc::new(VirtualClock::new());
        let hlc = HybridClock {
            time_source,
            state: Mutex::new(HybridState {
                last_physical: Time::ZERO,
                logical: u64::MAX,
            }),
        };

        let _ = hlc.receive(HybridTime::new(Time::ZERO, u64::MAX));
    }

    #[test]
    fn merge_is_least_upper_bound() {
        let na = node("A");
        let nb = node("B");
        #[allow(clippy::many_single_char_names)]
        let mut a = VectorClock::new();
        a.increment(&na);
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);
        b.increment(&nb);
        b.increment(&nb);

        let merged = a.merge(&b);
        assert_eq!(merged.get(&na), 2);
        assert_eq!(merged.get(&nb), 3);
        // Both original clocks happen-before the merge
        assert!(a.happens_before(&merged));
        assert!(b.happens_before(&merged));
    }

    #[test]
    fn merge_is_commutative() {
        let na = node("A");
        let nb = node("B");
        #[allow(clippy::many_single_char_names)]
        let mut a = VectorClock::new();
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);

        assert_eq!(a.merge(&b), b.merge(&a));
    }

    #[test]
    fn merge_is_associative() {
        let na = node("A");
        let nb = node("B");
        let nc = node("C");
        #[allow(clippy::many_single_char_names)]
        let mut a = VectorClock::new();
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);
        let mut c = VectorClock::new();
        c.increment(&nc);

        let ab_c = a.merge(&b).merge(&c);
        let a_bc = a.merge(&b.merge(&c));
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn merge_is_idempotent() {
        let na = node("A");
        #[allow(clippy::many_single_char_names)]
        let mut a = VectorClock::new();
        a.increment(&na);
        assert_eq!(a.merge(&a), a);
    }

    #[test]
    fn receive_merges_and_increments() {
        let na = node("A");
        let nb = node("B");
        #[allow(clippy::many_single_char_names)]
        let mut a = VectorClock::new();
        a.increment(&na); // A: {A:1}

        let mut b = VectorClock::new();
        b.increment(&nb); // B: {B:1}
        b.increment(&nb); // B: {B:2}

        // A receives a message with B's clock
        a.receive(&na, &b); // merge → {A:1, B:2}, then increment → {A:2, B:2}
        assert_eq!(a.get(&na), 2);
        assert_eq!(a.get(&nb), 2);
    }

    #[test]
    fn vector_clock_output_snapshot_scrubbed() {
        let na = node("alpha-node");
        let nb = node("beta-node");
        #[allow(clippy::many_single_char_names)]
        let mut a = VectorClock::new();
        a.increment(&na);
        a.increment(&na);

        let mut b = VectorClock::new();
        b.increment(&nb);

        let merged = a.merge(&b);
        insta::assert_json_snapshot!(
            "vector_clock_output_scrubbed",
            scrub_vclock_output(json!({
                "display": merged.to_string(),
                "debug": format!("{merged:?}"),
                "order_vs_a": format!("{:?}", merged.causal_order(&a)),
            }))
        );
    }

    #[test]
    fn for_node_initializes_to_one() {
        let n = node("X");
        let vc = VectorClock::for_node(&n);
        assert_eq!(vc.get(&n), 1);
        assert_eq!(vc.node_count(), 1);
    }

    #[test]
    fn set_is_monotone() {
        let n = node("A");
        let mut vc = VectorClock::new();
        vc.set(&n, 3);
        assert_eq!(vc.get(&n), 3);

        // Lower value should not regress the clock.
        vc.set(&n, 1);
        assert_eq!(vc.get(&n), 3);

        // Higher value should advance.
        vc.set(&n, 7);
        assert_eq!(vc.get(&n), 7);
    }

    #[test]
    #[should_panic(expected = "Vector clock counter overflowed while incrementing")]
    fn vector_clock_increment_panics_on_overflow() {
        let n = node("A");
        let mut vc = VectorClock::new();
        vc.entries.insert(n.clone(), u64::MAX);
        let _ = vc.increment(&n);
    }

    #[test]
    #[should_panic(expected = "Vector clock counter overflowed while incrementing")]
    fn vector_clock_receive_panics_on_local_overflow() {
        let local = node("A");
        let remote = node("B");
        let mut vc = VectorClock::new();
        vc.entries.insert(local.clone(), u64::MAX);

        let mut remote_clock = VectorClock::new();
        remote_clock.set(&remote, 1);

        vc.receive(&local, &remote_clock);
    }

    #[test]
    fn causal_tracker_send_receive_protocol() {
        let na = node("A");
        let nb = node("B");
        let mut tracker_a = CausalTracker::new(na.clone());
        let mut tracker_b = CausalTracker::new(nb.clone());

        // A does local work
        tracker_a.record_local_event(); // A: {A:1}

        // A sends message to B
        let msg_clock = tracker_a.on_send(); // A: {A:2}
        assert_eq!(msg_clock.get(&na), 2);

        // B receives message from A
        tracker_b.on_receive(&msg_clock); // B: merge({}, {A:2}) → {A:2}, incr → {A:2, B:1}
        assert_eq!(tracker_b.current_clock().get(&na), 2);
        assert_eq!(tracker_b.current_clock().get(&nb), 1);

        // B does more work
        tracker_b.record_local_event(); // B: {A:2, B:2}

        // B's events happen after A's send
        assert!(msg_clock.happens_before(tracker_b.current_clock()));
    }

    #[test]
    fn causal_tracker_transcript_snapshot_scrubbed() {
        let na = node("alpha-node");
        let nb = node("beta-node");
        let mut tracker_a = CausalTracker::new(na);
        let mut tracker_b = CausalTracker::new(nb);
        let node_a = tracker_a.node().as_str().to_string();
        let node_b = tracker_b.node().as_str().to_string();

        let a_local = tracker_a.record_local_event();
        let a_send = tracker_a.on_send();
        tracker_b.on_receive(&a_send);
        let b_after_receive = tracker_b.current_clock().clone();
        let b_local = tracker_b.record_local_event();

        insta::assert_json_snapshot!(
            "causal_tracker_transcript_scrubbed",
            scrub_vclock_output(json!({
                "steps": [
                    {
                        "step": "a_local",
                        "node": node_a,
                        "clock": a_local.to_string(),
                    },
                    {
                        "step": "a_send",
                        "node": tracker_a.node().as_str(),
                        "clock": a_send.to_string(),
                        "order_vs_local": format!("{:?}", a_send.causal_order(&a_local)),
                    },
                    {
                        "step": "b_receive",
                        "node": node_b,
                        "clock": b_after_receive.to_string(),
                        "order_vs_send": format!("{:?}", b_after_receive.causal_order(&a_send)),
                    },
                    {
                        "step": "b_local",
                        "node": tracker_b.node().as_str(),
                        "clock": b_local.to_string(),
                        "send_happens_before": a_send.happens_before(&b_local),
                        "receive_happens_before": b_after_receive.happens_before(&b_local),
                    }
                ]
            }))
        );
    }

    #[test]
    fn causal_event_ordering() {
        let na = node("A");
        let nb = node("B");
        let mut tracker_a = CausalTracker::new(na);
        let mut tracker_b = CausalTracker::new(nb);

        let e1 = tracker_a.record("event-1");
        let e2 = tracker_b.record("event-2");

        // Independent events are concurrent
        assert!(e1.is_concurrent_with(&e2));
        assert!(!e1.happens_before(&e2));
    }

    #[test]
    fn display_formatting() {
        let na = node("A");
        let nb = node("B");
        let mut vc = VectorClock::new();
        vc.increment(&na);
        vc.increment(&nb);
        vc.increment(&nb);
        let display = format!("{vc}");
        assert!(display.contains("A=1"));
        assert!(display.contains("B=2"));
    }

    #[test]
    fn partial_order_after() {
        let na = node("A");
        #[allow(clippy::many_single_char_names)]
        let mut a = VectorClock::new();
        a.increment(&na);
        let b = VectorClock::new();
        assert_eq!(a.causal_order(&b), CausalOrder::After);
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn three_node_diamond() {
        // Classic diamond:
        //   A sends to B and C independently
        //   B and C are concurrent
        //   D receives from both B and C
        let na = node("A");
        let nb = node("B");
        let nc = node("C");
        let nd = node("D");

        let mut ta = CausalTracker::new(na);
        let mut tb = CausalTracker::new(nb);
        let mut tc = CausalTracker::new(nc);
        let mut td = CausalTracker::new(nd);

        // A sends to B and C
        let msg_to_b = ta.on_send();
        let msg_to_c = ta.on_send();

        tb.on_receive(&msg_to_b);
        tc.on_receive(&msg_to_c);

        // B and C do independent work
        let b_clock = tb.on_send();
        let c_clock = tc.on_send();

        // B and C are concurrent
        assert!(b_clock.is_concurrent_with(&c_clock));

        // D receives from B then C
        td.on_receive(&b_clock);
        td.on_receive(&c_clock);

        // D happens after both B and C
        assert!(b_clock.happens_before(td.current_clock()));
        assert!(c_clock.happens_before(td.current_clock()));
    }

    // =========================================================================
    // Wave 55 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn hybrid_time_debug_clone_copy_hash_ord() {
        use std::collections::HashSet;
        let ht = HybridTime::new(Time::from_nanos(1_000), 3);
        let dbg = format!("{ht:?}");
        assert!(dbg.contains("HybridTime"), "{dbg}");
        let copied = ht;
        let cloned = ht;
        assert_eq!(copied, cloned);

        let earlier = HybridTime::new(Time::ZERO, 0);
        assert!(earlier < ht);

        let mut set = HashSet::new();
        set.insert(ht);
        set.insert(earlier);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&ht));
    }

    #[test]
    fn logical_clock_kind_debug_clone_copy_eq() {
        let k = LogicalClockKind::Lamport;
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Lamport"), "{dbg}");
        let copied = k;
        let cloned = k;
        assert_eq!(copied, cloned);
        assert_ne!(k, LogicalClockKind::Vector);
        assert_ne!(k, LogicalClockKind::Hybrid);
    }

    #[test]
    fn logical_time_debug_clone_eq() {
        let lt = LogicalTime::Lamport(LamportTime::from_raw(5));
        let dbg = format!("{lt:?}");
        assert!(dbg.contains("Lamport"), "{dbg}");
        let cloned = lt.clone();
        assert_eq!(lt, cloned);
    }

    #[test]
    fn logical_clock_mode_debug_clone() {
        let mode = LogicalClockMode::Lamport;
        let dbg = format!("{mode:?}");
        assert!(dbg.contains("Lamport"), "{dbg}");
        let cloned = mode;
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }

    // ------------------------------------------------------------------------
    // Golden-artifact: canonical VectorClock serialization snapshot.
    //
    // Freezes the Debug and Display string forms of VectorClock across the
    // states that the rest of the distributed trace layer treats as wire
    // serialization: empty, single-node, multi-node after merge, after a
    // send/receive round-trip, and for each of the four CausalOrder verdicts.
    //
    // BTreeMap-backed entries guarantee deterministic iteration; node names
    // are scrubbed so the golden never captures literal identities.
    // ------------------------------------------------------------------------
    #[test]
    fn canonical_vector_clock_serialization_snapshot() {
        let na = node("alpha-node");
        let nb = node("beta-node");

        // Empty.
        let empty = VectorClock::new();

        // Single-node, initialized to 1.
        let single = VectorClock::for_node(&na);

        // Multi-node after independent increments + merge.
        #[allow(clippy::many_single_char_names)]
        let mut a = VectorClock::new();
        a.increment(&na);
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);
        let merged = a.merge(&b);

        // Post-receive: A learns from B's clock and advances locally.
        let mut c = VectorClock::new();
        c.increment(&na);
        let mut d = VectorClock::new();
        d.increment(&nb);
        d.increment(&nb);
        c.receive(&na, &d); // merge({A:1},{B:2}) → {A:1,B:2}, incr A → {A:2,B:2}

        // Four canonical CausalOrder pairs.
        //   Before:     {A:1}       vs {A:2}
        //   After:      {A:2}       vs {A:1}
        //   Equal:      {A:1,B:1}   vs {A:1,B:1}
        //   Concurrent: {A:1}       vs {B:1}
        let before_lhs = {
            let mut v = VectorClock::new();
            v.increment(&na);
            v
        };
        let before_rhs = {
            let mut v = VectorClock::new();
            v.increment(&na);
            v.increment(&na);
            v
        };
        let equal_lhs = {
            let mut v = VectorClock::new();
            v.increment(&na);
            v.increment(&nb);
            v
        };
        let equal_rhs = {
            let mut v = VectorClock::new();
            v.increment(&na);
            v.increment(&nb);
            v
        };
        let concurrent_lhs = {
            let mut v = VectorClock::new();
            v.increment(&na);
            v
        };
        let concurrent_rhs = {
            let mut v = VectorClock::new();
            v.increment(&nb);
            v
        };

        // set(n, 0) is a documented no-op; record the resulting Display to
        // lock the invariant into the golden.
        let mut zero_set = VectorClock::new();
        zero_set.set(&na, 0);

        insta::assert_json_snapshot!(
            "canonical_vector_clock_serialization",
            scrub_vclock_output(json!({
                "states": {
                    "empty":      { "display": empty.to_string(),  "debug": format!("{empty:?}"),  "node_count": empty.node_count(),  "is_zero": empty.is_zero() },
                    "single":     { "display": single.to_string(), "debug": format!("{single:?}"), "node_count": single.node_count(), "is_zero": single.is_zero() },
                    "merged":     { "display": merged.to_string(), "debug": format!("{merged:?}"), "node_count": merged.node_count(), "is_zero": merged.is_zero() },
                    "post_receive": { "display": c.to_string(),    "debug": format!("{c:?}"),      "node_count": c.node_count(),      "is_zero": c.is_zero() },
                    "set_zero_noop": { "display": zero_set.to_string(), "debug": format!("{zero_set:?}"), "is_zero": zero_set.is_zero() },
                },
                "causal_orders": [
                    { "case": "before",     "lhs": before_lhs.to_string(),     "rhs": before_rhs.to_string(),     "verdict": format!("{:?}", before_lhs.causal_order(&before_rhs)) },
                    { "case": "after",      "lhs": before_rhs.to_string(),     "rhs": before_lhs.to_string(),     "verdict": format!("{:?}", before_rhs.causal_order(&before_lhs)) },
                    { "case": "equal",      "lhs": equal_lhs.to_string(),      "rhs": equal_rhs.to_string(),      "verdict": format!("{:?}", equal_lhs.causal_order(&equal_rhs)) },
                    { "case": "concurrent", "lhs": concurrent_lhs.to_string(), "rhs": concurrent_rhs.to_string(), "verdict": format!("{:?}", concurrent_lhs.causal_order(&concurrent_rhs)) },
                ],
                "iter_determinism": {
                    // BTreeMap ordering guarantees keys sort lexicographically.
                    "merged_keys_in_order": merged.iter()
                        .map(|(n, v)| format!("{}={}", n.as_str(), v))
                        .collect::<Vec<_>>(),
                }
            }))
        );
    }
