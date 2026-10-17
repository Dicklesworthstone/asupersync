    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn time_conversions() {
        assert_eq!(Time::from_secs(1).as_nanos(), 1_000_000_000);
        assert_eq!(Time::from_millis(1).as_nanos(), 1_000_000);
        assert_eq!(Time::from_nanos(1).as_nanos(), 1);

        assert_eq!(Time::from_nanos(1_500_000_000).as_secs(), 1);
        assert_eq!(Time::from_nanos(1_500_000_000).as_millis(), 1500);
    }

    #[test]
    fn time_arithmetic() {
        let t1 = Time::from_secs(1);
        let t2 = t1.saturating_add_nanos(500_000_000);
        assert_eq!(t2.as_millis(), 1500);

        let t3 = t2.saturating_sub_nanos(2_000_000_000);
        assert_eq!(t3, Time::ZERO);
    }

    #[test]
    fn time_ordering() {
        assert!(Time::from_secs(1) < Time::from_secs(2));
        assert!(Time::from_millis(1000) == Time::from_secs(1));
    }

    // ---- RegionId ----

    #[test]
    fn region_id_debug_format() {
        let id = RegionId::new_for_test(5, 3);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("RegionId"), "{dbg}");
        assert!(dbg.contains('5'), "{dbg}");
        assert!(dbg.contains('3'), "{dbg}");
    }

    #[test]
    fn region_id_display_format() {
        let id = RegionId::new_for_test(42, 0);
        assert_eq!(format!("{id}"), "R42");
    }

    #[test]
    fn region_id_equality_and_hash() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let a = RegionId::new_for_test(1, 2);
        let b = RegionId::new_for_test(1, 2);
        let c = RegionId::new_for_test(1, 3);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut ha = DetHasher::default();
        let mut hb = DetHasher::default();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn region_id_ordering() {
        let a = RegionId::new_for_test(1, 0);
        let b = RegionId::new_for_test(2, 0);
        assert!(a < b);
        assert!(a <= b);
        assert!(b > a);
    }

    #[test]
    fn region_id_copy_clone() {
        let id = RegionId::new_for_test(1, 0);
        let copied = id;
        let cloned = id;
        assert_eq!(id, copied);
        assert_eq!(id, cloned);
    }

    #[test]
    fn region_id_testing_default() {
        let id = RegionId::testing_default();
        assert_eq!(format!("{id}"), "R0");
    }

    #[test]
    fn region_id_ephemeral_unique() {
        let a = RegionId::new_ephemeral();
        let b = RegionId::new_ephemeral();
        assert_ne!(a, b);
    }

    #[test]
    fn region_id_serde_roundtrip() {
        let id = RegionId::new_for_test(99, 7);
        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: RegionId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    // ---- TaskId ----

    #[test]
    fn task_id_debug_format() {
        let id = TaskId::new_for_test(10, 2);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("TaskId"), "{dbg}");
        assert!(dbg.contains("10"), "{dbg}");
        assert!(dbg.contains('2'), "{dbg}");
    }

    #[test]
    fn task_id_display_format() {
        let id = TaskId::new_for_test(7, 0);
        assert_eq!(format!("{id}"), "T7");
    }

    #[test]
    fn task_id_equality_and_hash() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let a = TaskId::new_for_test(3, 1);
        let b = TaskId::new_for_test(3, 1);
        let c = TaskId::new_for_test(3, 2);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut ha = DetHasher::default();
        let mut hb = DetHasher::default();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn task_id_ordering() {
        let a = TaskId::new_for_test(1, 0);
        let b = TaskId::new_for_test(2, 0);
        assert!(a < b);
    }

    #[test]
    fn task_id_copy_clone() {
        let id = TaskId::new_for_test(5, 1);
        let copied = id;
        let cloned = id;
        assert_eq!(id, copied);
        assert_eq!(id, cloned);
    }

    #[test]
    fn task_id_testing_default() {
        let id = TaskId::testing_default();
        assert_eq!(format!("{id}"), "T0");
    }

    #[test]
    fn task_id_ephemeral_unique() {
        let a = TaskId::new_ephemeral();
        let b = TaskId::new_ephemeral();
        assert_ne!(a, b);
    }

    #[test]
    fn task_id_serde_roundtrip() {
        let id = TaskId::new_for_test(42, 5);
        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: TaskId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    // ---- ObligationId ----

    #[test]
    fn obligation_id_debug_format() {
        let id = ObligationId::new_for_test(8, 1);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("ObligationId"), "{dbg}");
        assert!(dbg.contains('8'), "{dbg}");
    }

    #[test]
    fn obligation_id_display_format() {
        let id = ObligationId::new_for_test(3, 0);
        assert_eq!(format!("{id}"), "O3");
    }

    #[test]
    fn obligation_id_equality_and_hash() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let a = ObligationId::new_for_test(1, 1);
        let b = ObligationId::new_for_test(1, 1);
        let c = ObligationId::new_for_test(2, 1);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut ha = DetHasher::default();
        let mut hb = DetHasher::default();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn obligation_id_ordering() {
        let a = ObligationId::new_for_test(1, 0);
        let b = ObligationId::new_for_test(2, 0);
        assert!(a < b);
    }

    #[test]
    fn obligation_id_copy_clone() {
        let id = ObligationId::new_for_test(1, 0);
        let copied = id;
        let cloned = id;
        assert_eq!(id, copied);
        assert_eq!(id, cloned);
    }

    #[test]
    fn obligation_id_serde_roundtrip() {
        let id = ObligationId::new_for_test(77, 3);
        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: ObligationId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    // ---- Time Display ----

    #[test]
    fn time_display_seconds() {
        let t = Time::from_secs(2);
        let disp = format!("{t}");
        assert_eq!(disp, "2.000s");
    }

    #[test]
    fn time_display_seconds_with_millis() {
        let t = Time::from_nanos(1_234_000_000);
        let disp = format!("{t}");
        assert_eq!(disp, "1.234s");
    }

    #[test]
    fn time_display_milliseconds() {
        let t = Time::from_millis(500);
        let disp = format!("{t}");
        assert_eq!(disp, "500ms");
    }

    #[test]
    fn time_display_microseconds() {
        let t = Time::from_nanos(5_000);
        let disp = format!("{t}");
        assert_eq!(disp, "5us");
    }

    #[test]
    fn time_display_nanoseconds() {
        let t = Time::from_nanos(42);
        let disp = format!("{t}");
        assert_eq!(disp, "42ns");
    }

    #[test]
    fn time_display_zero() {
        assert_eq!(format!("{}", Time::ZERO), "0ns");
    }

    // ---- Time edge cases ----

    #[test]
    fn time_debug_format() {
        let t = Time::from_nanos(100);
        let dbg = format!("{t:?}");
        assert_eq!(dbg, "Time(100ns)");
    }

    #[test]
    fn time_default_is_zero() {
        assert_eq!(Time::default(), Time::ZERO);
    }

    #[test]
    fn time_max_constant() {
        assert_eq!(Time::MAX.as_nanos(), u64::MAX);
    }

    #[test]
    fn time_saturating_add_overflow() {
        let t = Time::MAX;
        let result = t.saturating_add_nanos(1);
        assert_eq!(result, Time::MAX);
    }

    #[test]
    fn time_saturating_sub_underflow() {
        let t = Time::ZERO;
        let result = t.saturating_sub_nanos(100);
        assert_eq!(result, Time::ZERO);
    }

    #[test]
    fn time_duration_since() {
        let t1 = Time::from_secs(5);
        let t2 = Time::from_secs(3);
        assert_eq!(t1.duration_since(t2), 2_000_000_000);
        assert_eq!(t2.duration_since(t1), 0); // saturates at 0
    }

    #[test]
    fn time_add_duration() {
        let t = Time::from_secs(1);
        let result = t + Duration::from_millis(500);
        assert_eq!(result.as_millis(), 1500);
    }

    #[test]
    fn time_from_millis_saturation() {
        let t = Time::from_millis(u64::MAX);
        // Should saturate, not overflow
        assert_eq!(t, Time::MAX);
    }

    #[test]
    fn time_from_secs_saturation() {
        let t = Time::from_secs(u64::MAX);
        assert_eq!(t, Time::MAX);
    }

    #[test]
    fn time_serde_roundtrip() {
        let t = Time::from_nanos(12345);
        let json = serde_json::to_string(&t).expect("serialize");
        let deserialized: Time = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(t, deserialized);
    }

    #[test]
    fn time_hash_consistency() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let a = Time::from_secs(1);
        let b = Time::from_millis(1000);
        assert_eq!(a, b);

        let mut ha = DetHasher::default();
        let mut hb = DetHasher::default();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    /// br-asupersync-u3gsst — bootstrap helpers mint distinct IDs and
    /// keep generation pinned at 1 (the documented contract).
    #[test]
    fn bootstrap_helpers_mint_unique_ids() {
        let r1 = next_bootstrap_region_id();
        let r2 = next_bootstrap_region_id();
        assert_ne!(r1, r2);
        assert_eq!(r1.arena_index().generation(), 1);
        assert_eq!(r2.arena_index().generation(), 1);

        let t1 = next_bootstrap_task_id();
        let t2 = next_bootstrap_task_id();
        assert_ne!(t1, t2);
        assert_eq!(t1.arena_index().generation(), 1);
        assert_eq!(t2.arena_index().generation(), 1);
    }

    /// br-asupersync-o2oa4l — Cross-type ID confusion: a serialised
    /// RegionId must not deserialise as TaskId / ObligationId, even
    /// when their arena (index, generation) tuples are identical.
    /// The discriminant tag rejects the mis-typed payload at the
    /// envelope level.
    #[test]
    fn serde_rejects_cross_type_id_confusion() {
        let region = RegionId::from_arena(ArenaIndex::new(7, 3));
        let json = serde_json::to_string(&region).expect("serialise RegionId");
        // Sanity: the wire form contains the discriminant tag.
        assert!(json.contains("\"kind\""));
        assert!(json.contains("RegionId"));

        // Round-trip back to the original type works.
        let region_back: RegionId = serde_json::from_str(&json).expect("RegionId round-trip");
        assert_eq!(region_back, region);

        // Cross-type deserialisation must fail.
        let task_err = serde_json::from_str::<TaskId>(&json);
        assert!(task_err.is_err(), "TaskId must reject RegionId payload");
        let obl_err = serde_json::from_str::<ObligationId>(&json);
        assert!(
            obl_err.is_err(),
            "ObligationId must reject RegionId payload"
        );
    }

    /// br-asupersync-o2oa4l — TaskId / ObligationId must each reject
    /// payloads tagged for the other type.
    #[test]
    fn serde_rejects_task_obligation_confusion() {
        let task = TaskId::from_arena(ArenaIndex::new(11, 2));
        let task_json = serde_json::to_string(&task).expect("serialise TaskId");
        assert!(serde_json::from_str::<RegionId>(&task_json).is_err());
        assert!(serde_json::from_str::<ObligationId>(&task_json).is_err());
        let task_back: TaskId = serde_json::from_str(&task_json).expect("TaskId round-trip");
        assert_eq!(task_back, task);

        let obl = ObligationId::from_arena(ArenaIndex::new(11, 2));
        let obl_json = serde_json::to_string(&obl).expect("serialise ObligationId");
        assert!(serde_json::from_str::<RegionId>(&obl_json).is_err());
        assert!(serde_json::from_str::<TaskId>(&obl_json).is_err());
    }
