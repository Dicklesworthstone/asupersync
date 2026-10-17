    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::{Value, json};

    fn scrub_pressure_json(value: Value) -> Value {
        let mut scrubbed = value;

        if let Some(headroom) = scrubbed.pointer_mut("/headroom") {
            let formatted = headroom
                .as_f64()
                .map_or_else(|| headroom.to_string(), |value| format!("{value:.2}"));
            *headroom = Value::String(formatted);
        }

        scrubbed
    }

    #[test]
    fn new_starts_at_full_headroom() {
        let p = SystemPressure::new();
        assert!((p.headroom() - 1.0).abs() < f32::EPSILON);
        assert_eq!(p.degradation_level(), 0);
        assert_eq!(p.level_label(), "normal");
    }

    #[test]
    fn set_and_read_headroom() {
        let p = SystemPressure::new();
        p.set_headroom(0.42);
        assert!((p.headroom() - 0.42).abs() < 0.001);
    }

    #[test]
    fn headroom_clamped() {
        let p = SystemPressure::new();
        p.set_headroom(1.5);
        assert!((p.headroom() - 1.0).abs() < f32::EPSILON);
        p.set_headroom(-0.3);
        assert!(p.headroom().abs() < f32::EPSILON);
    }

    #[test]
    fn degradation_levels() {
        let p = SystemPressure::new();
        p.set_headroom(0.9);
        assert_eq!(p.degradation_level(), 0);
        p.set_headroom(0.8);
        assert_eq!(p.degradation_level(), 1);
        p.set_headroom(0.5);
        assert_eq!(p.degradation_level(), 2);
        p.set_headroom(0.25);
        assert_eq!(p.degradation_level(), 3);
        p.set_headroom(0.0);
        assert_eq!(p.degradation_level(), 4);
    }

    #[test]
    fn should_degrade_threshold() {
        let p = SystemPressure::with_headroom(0.3);
        assert!(p.should_degrade(0.5));
        assert!(!p.should_degrade(0.2));
    }

    #[test]
    fn with_headroom_constructor() {
        let p = SystemPressure::with_headroom(0.7);
        assert!((p.headroom() - 0.7).abs() < 0.001);
    }

    #[test]
    fn level_labels() {
        let p = SystemPressure::new();
        p.set_headroom(0.9);
        assert_eq!(p.level_label(), "normal");
        p.set_headroom(0.75);
        assert_eq!(p.level_label(), "light");
        p.set_headroom(0.5);
        assert_eq!(p.level_label(), "moderate");
        p.set_headroom(0.25);
        assert_eq!(p.level_label(), "heavy");
        p.set_headroom(0.0);
        assert_eq!(p.level_label(), "emergency");
    }

    #[test]
    fn pressure_json_snapshot_scrubbed() {
        let p = SystemPressure::with_headroom(0.42);

        insta::assert_json_snapshot!(
            "pressure_json_scrubbed",
            scrub_pressure_json(json!({
                "headroom": p.headroom(),
                "degradation_level": p.degradation_level(),
                "label": p.level_label(),
                "should_degrade_0_5": p.should_degrade(0.5),
            }))
        );
    }

    /// br-asupersync-ksvi5z — NaN inputs to `with_headroom` and
    /// `set_headroom` collapse to 0.0 (fully degraded). Without this,
    /// every `should_degrade(threshold)` returns false (NaN comparison)
    /// and the threshold-based defence is silently disabled.
    #[test]
    fn nan_headroom_collapses_to_fully_degraded() {
        let p = SystemPressure::with_headroom(f32::NAN);
        assert_eq!(p.headroom(), 0.0);
        assert!(p.should_degrade(0.5));
        assert!(p.should_degrade(0.0001));
        // Degradation level at 0.0 headroom is the most-severe band.
        assert_eq!(p.degradation_level(), 4);

        let p2 = SystemPressure::new();
        p2.set_headroom(f32::NAN);
        assert_eq!(p2.headroom(), 0.0);
    }

    /// br-asupersync-ksvi5z — ±∞ inputs also collapse to 0.0.
    #[test]
    fn infinite_headroom_collapses_to_fully_degraded() {
        let p_pos = SystemPressure::with_headroom(f32::INFINITY);
        assert_eq!(p_pos.headroom(), 0.0);
        let p_neg = SystemPressure::with_headroom(f32::NEG_INFINITY);
        assert_eq!(p_neg.headroom(), 0.0);
    }

    /// br-asupersync-ksvi5z — finite-but-out-of-range inputs still clamp
    /// to [0.0, 1.0] (unchanged behaviour, regression guard).
    #[test]
    fn out_of_range_finite_headroom_clamps() {
        let p_high = SystemPressure::with_headroom(2.0);
        assert_eq!(p_high.headroom(), 1.0);
        let p_low = SystemPressure::with_headroom(-0.5);
        assert_eq!(p_low.headroom(), 0.0);
    }
