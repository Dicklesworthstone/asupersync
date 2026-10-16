    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::TraceEvent;
    use crate::types::{RegionId, TaskId, Time};

    #[test]
    fn independent_events_have_no_causal_edge() {
        let region_a = RegionId::new_for_test(1, 0);
        let region_b = RegionId::new_for_test(2, 0);
        let task_a = TaskId::new_for_test(1, 0);
        let task_b = TaskId::new_for_test(2, 0);

        let t1 = TraceEvent::spawn(1, Time::from_nanos(10), task_a, region_a);
        let t2 = TraceEvent::spawn(2, Time::from_nanos(20), task_b, region_b);

        let es = EventStructure::from_trace(&[t1, t2]);
        assert!(es.causality().is_empty());
    }

    #[test]
    fn dependent_events_form_causal_edge() {
        let region = RegionId::new_for_test(1, 0);
        let task = TaskId::new_for_test(7, 0);

        let t1 = TraceEvent::spawn(1, Time::from_nanos(10), task, region);
        let t2 = TraceEvent::schedule(2, Time::from_nanos(20), task, region);

        let es = EventStructure::from_trace(&[t1, t2]);
        assert_eq!(es.causality().len(), 1);
        assert_eq!(es.causality()[0].0.index(), 0);
        assert_eq!(es.causality()[0].1.index(), 1);
    }

    #[test]
    fn trace_poset_edges_match_dependence_relation() {
        let region_a = RegionId::new_for_test(1, 0);
        let region_b = RegionId::new_for_test(2, 0);
        let task_a = TaskId::new_for_test(1, 0);
        let task_b = TaskId::new_for_test(2, 0);

        let trace = vec![
            TraceEvent::spawn(1, Time::from_nanos(10), task_a, region_a),
            TraceEvent::spawn(2, Time::from_nanos(20), task_b, region_b),
            TraceEvent::schedule(3, Time::from_nanos(30), task_a, region_a),
            TraceEvent::schedule(4, Time::from_nanos(40), task_b, region_b),
        ];

        let poset = TracePoset::from_trace(&trace);

        for i in 0..trace.len() {
            for j in (i + 1)..trace.len() {
                let expected = !independent(&trace[i], &trace[j]);
                assert_eq!(poset.has_edge(i, j), expected, "edge {i}->{j}");
            }
        }

        assert_eq!(
            poset.topo_sort(),
            Some((0..trace.len()).collect::<Vec<usize>>())
        );
    }

    #[test]
    fn trace_poset_owner_key_is_stable_for_task_events() {
        let region = RegionId::new_for_test(1, 0);
        let task = TaskId::new_for_test(7, 0);

        let trace = vec![
            TraceEvent::spawn(1, Time::from_nanos(10), task, region),
            TraceEvent::schedule(2, Time::from_nanos(20), task, region),
        ];

        let poset = TracePoset::from_trace(&trace);
        assert_eq!(poset.owner(0), OwnerKey::Task(task));
        assert_eq!(poset.owner(1), OwnerKey::Task(task));
    }

    #[test]
    fn trace_poset_owner_key_handles_region_timer_and_user_trace() {
        let region = RegionId::new_for_test(42, 0);
        let time = Time::from_nanos(10);

        let trace = vec![
            TraceEvent::region_created(1, time, region, None),
            TraceEvent::timer_scheduled(2, time, 7, time),
            TraceEvent::user_trace(3, time, "hello"),
        ];

        let poset = TracePoset::from_trace(&trace);
        assert_eq!(poset.owner(0), OwnerKey::Region(region));
        assert_eq!(poset.owner(1), OwnerKey::Timer(7));
        assert_eq!(poset.owner(2), OwnerKey::Kind(TraceEventKind::UserTrace));
    }

    // Pure data-type tests (wave 17 – CyanBarn)

    #[test]
    fn event_id_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;

        let id = EventId::new(5);
        let id2 = id;
        assert_eq!(id, id2);
        assert!(format!("{id:?}").contains('5'));

        let mut set = HashSet::new();
        set.insert(id);
        set.insert(EventId::new(10));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn event_id_new_index() {
        let id = EventId::new(42);
        assert_eq!(id.index(), 42);
    }

    #[test]
    fn event_debug_clone_label() {
        let region = RegionId::new_for_test(1, 0);
        let task = TaskId::new_for_test(1, 0);
        let te = TraceEvent::spawn(1, Time::from_nanos(10), task, region);

        let event = Event {
            id: EventId::new(0),
            trace: te,
        };
        let event2 = event.clone();
        assert_eq!(event2.id, EventId::new(0));
        assert!(format!("{event:?}").contains("Event"));

        let label = event.label();
        assert!(format!("{label:?}").contains("Spawn"));
    }

    #[test]
    fn owner_key_debug_clone_copy_eq_hash_ord() {
        use std::collections::HashSet;

        let task = TaskId::new_for_test(1, 0);
        let k1 = OwnerKey::Task(task);
        let k2 = k1;
        assert_eq!(k1, k2);
        assert!(format!("{k1:?}").contains("Task"));

        let mut set = HashSet::new();
        set.insert(k1);
        set.insert(OwnerKey::Timer(7));
        assert_eq!(set.len(), 2);

        // Ord
        assert!(k1 <= k2);
    }

    #[test]
    fn owner_key_all_variants() {
        let task = TaskId::new_for_test(1, 0);
        let region = RegionId::new_for_test(1, 0);
        let variants = [
            OwnerKey::Task(task),
            OwnerKey::Region(region),
            OwnerKey::Timer(0),
            OwnerKey::IoToken(0),
            OwnerKey::Kind(TraceEventKind::UserTrace),
        ];
        for v in &variants {
            assert!(!format!("{v:?}").is_empty());
        }
    }

    #[test]
    fn owner_key_for_event_task() {
        let region = RegionId::new_for_test(1, 0);
        let task = TaskId::new_for_test(7, 0);
        let te = TraceEvent::spawn(1, Time::from_nanos(10), task, region);
        assert_eq!(OwnerKey::for_event(&te), OwnerKey::Task(task));
    }

    #[test]
    fn owner_key_for_event_region() {
        let region = RegionId::new_for_test(1, 0);
        let te = TraceEvent::region_created(1, Time::from_nanos(10), region, None);
        assert_eq!(OwnerKey::for_event(&te), OwnerKey::Region(region));
    }

    #[test]
    fn owner_key_for_event_timer() {
        let te = TraceEvent::timer_scheduled(1, Time::from_nanos(10), 42, Time::from_nanos(100));
        assert_eq!(OwnerKey::for_event(&te), OwnerKey::Timer(42));
    }

    #[test]
    fn trace_poset_debug_clone() {
        let trace = vec![TraceEvent::user_trace(1, Time::from_nanos(10), "a")];
        let poset = TracePoset::from_trace(&trace);
        let poset2 = poset;
        assert!(format!("{poset2:?}").contains("TracePoset"));
    }

    #[test]
    fn event_structure_empty_trace() {
        let es = EventStructure::from_trace(&[]);
        assert!(es.events().is_empty());
        assert!(es.causality().is_empty());
    }
