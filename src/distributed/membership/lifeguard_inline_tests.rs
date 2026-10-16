    use super::*;

    #[test]
    fn awareness_starts_healthy_and_clamps() {
        let mut a = Awareness::new(8);
        assert_eq!(a.score(), 0);
        assert_eq!(a.multiplier(), 1);
        assert_eq!(a.scale(500), 500);

        // Cannot go below zero.
        a.apply_delta(-5);
        assert_eq!(a.score(), 0);

        // Degrade and observe the multiplier grow.
        a.apply_delta(2);
        assert_eq!(a.score(), 2);
        assert_eq!(a.multiplier(), 3);
        assert_eq!(a.scale(500), 1500);

        // Cannot exceed max - 1.
        a.apply_delta(100);
        assert_eq!(a.score(), 7);
        assert_eq!(a.multiplier(), 8);
    }

    #[test]
    fn awareness_min_max_is_clamped_up() {
        let a = Awareness::new(0);
        assert_eq!(a.multiplier(), 1);
        let mut a = Awareness::new(-3);
        a.apply_delta(10);
        // max raised to 1 => score capped at 0.
        assert_eq!(a.score(), 0);
    }

    #[test]
    fn node_scale_floor_is_one() {
        assert!((node_scale(0) - 1.0).abs() < 1e-9);
        assert!((node_scale(1) - 1.0).abs() < 1e-9);
        assert!((node_scale(10) - 1.0).abs() < 1e-9);
        assert!((node_scale(100) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn suspicion_window_shrinks_with_confirmations() {
        // Small cluster: node_scale == 1, min = 4 * 1 * 1000 = 4000ms,
        // max = 6 * 4000 = 24000ms.
        let n = 7;
        let min = min_suspicion_ms(4, n, 1000);
        let max = max_suspicion_ms(min, 6);
        assert_eq!(min, 4000);
        assert_eq!(max, 24000);

        // Zero confirmations => full window.
        assert_eq!(suspicion_timeout_ms(min, max, 0, 3), max);

        // Window is monotonically non-increasing in confirmations.
        let t1 = suspicion_timeout_ms(min, max, 1, 3);
        let t2 = suspicion_timeout_ms(min, max, 2, 3);
        let t3 = suspicion_timeout_ms(min, max, 3, 3);
        assert!(t1 < max);
        assert!(t2 < t1);
        assert!(t3 <= t2);

        // At/over k confirmations => floor.
        assert_eq!(suspicion_timeout_ms(min, max, 3, 3), min);
        assert_eq!(suspicion_timeout_ms(min, max, 10, 3), min);
    }

    #[test]
    fn suspicion_timeout_handles_degenerate_bounds() {
        // max below min is raised to min; k of 0 treated as 1.
        assert_eq!(suspicion_timeout_ms(5000, 1000, 0, 0), 5000);
        assert_eq!(suspicion_timeout_ms(5000, 1000, 5, 0), 5000);
    }
