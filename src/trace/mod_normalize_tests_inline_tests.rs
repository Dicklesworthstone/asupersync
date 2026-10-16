    use super::*;
    use crate::types::{RegionId, TaskId, Time};

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    #[test]
    fn normalize_trace_reduces_switches() {
        // Events in "bad" order: A1, B1, A2, B2 (3 switches)
        // Optimal order: A1, A2, B1, B2 or B1, B2, A1, A2 (1 switch)
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)), // A1
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)), // B1
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)), // A2
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)), // B2
        ];

        let original_cost = trace_switch_cost(&events);
        let (normalized, result) = normalize_trace(&events, &GeodesicConfig::default());
        let normalized_cost = trace_switch_cost(&normalized);

        // Original order has more switches than normalized
        assert!(
            normalized_cost <= original_cost,
            "normalized ({normalized_cost}) should be <= original ({original_cost})"
        );
        assert_eq!(result.switch_count, normalized_cost);
    }

    #[test]
    fn normalize_preserves_events() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];

        let (normalized, _) = normalize_trace_default(&events);
        assert_eq!(normalized.len(), events.len());
    }

    #[test]
    fn trace_switch_cost_empty() {
        assert_eq!(trace_switch_cost(&[]), 0);
    }

    #[test]
    fn trace_switch_cost_single() {
        let events = vec![TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
        assert_eq!(trace_switch_cost(&events), 0);
    }

    #[test]
    fn trace_switch_cost_same_owner() {
        // Same task = same owner = no switches
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
        ];
        assert_eq!(trace_switch_cost(&events), 0);
    }

    #[test]
    fn trace_switch_cost_different_owners() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(1), rid(1)),
        ];
        assert_eq!(trace_switch_cost(&events), 2); // t1->t2->t1
    }
