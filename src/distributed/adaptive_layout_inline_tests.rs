    use super::*;

    #[test]
    fn unknown_quality_uses_static_fallback() {
        // AC4: quality-unknown -> static defaults (never worse than today).
        let cfg = AdaptiveLayoutConfig::default();
        let choice = cfg.derive(None);
        assert_eq!(choice.source_symbols, 16);
        assert_eq!(choice.overhead, 4);
        assert_eq!(choice, cfg.fallback());
    }

    #[test]
    fn outputs_respect_floors_and_ceilings() {
        let cfg = AdaptiveLayoutConfig::default();
        for loss_pct in 0..=100 {
            let q = PathQuality::new(50.0, f64::from(loss_pct) / 100.0, 0);
            let choice = cfg.derive(Some(q));
            assert!(choice.source_symbols >= cfg.min_source_symbols);
            assert!(choice.source_symbols <= cfg.max_source_symbols);
            assert!(choice.overhead >= cfg.min_overhead);
            assert!(choice.overhead <= cfg.max_overhead);
        }
    }

    #[test]
    fn overhead_and_block_size_are_monotone_in_loss() {
        // AC2: worse loss never decreases overhead or block size (RTT fixed).
        let cfg = AdaptiveLayoutConfig::default();
        let mut prev = cfg.derive(Some(PathQuality::new(50.0, 0.0, 0)));
        let mut loss = 0u32;
        while loss <= 100 {
            let q = PathQuality::new(50.0, f64::from(loss) / 100.0, 0);
            let choice = cfg.derive(Some(q));
            assert!(
                choice.overhead >= prev.overhead,
                "overhead regressed at loss {loss}: {} < {}",
                choice.overhead,
                prev.overhead
            );
            assert!(
                choice.source_symbols >= prev.source_symbols,
                "block size regressed at loss {loss}"
            );
            prev = choice;
            loss += 5;
        }
    }

    #[test]
    fn block_size_is_monotone_in_rtt() {
        let cfg = AdaptiveLayoutConfig::default();
        let mut prev = cfg.derive(Some(PathQuality::new(0.0, 0.1, 0)));
        let mut rtt = 0u32;
        while rtt <= 400 {
            let q = PathQuality::new(f64::from(rtt), 0.1, 0);
            let choice = cfg.derive(Some(q));
            assert!(choice.source_symbols >= prev.source_symbols);
            prev = choice;
            rtt += 25;
        }
    }

    #[test]
    fn clean_path_is_smaller_than_lossy_path() {
        let cfg = AdaptiveLayoutConfig::default();
        let clean = cfg.derive(Some(PathQuality::new(10.0, 0.0, 0)));
        let lossy = cfg.derive(Some(PathQuality::new(10.0, 0.5, 0)));
        assert!(lossy.overhead > clean.overhead);
        assert!(lossy.source_symbols > clean.source_symbols);
    }

    #[test]
    fn loss_fraction_is_clamped() {
        let q = PathQuality::new(-5.0, 2.0, 3);
        assert_eq!(q.loss_ewma, 1.0);
        assert_eq!(q.rtt_ewma_ms, 0.0);
    }

    #[test]
    fn determinism() {
        let cfg = AdaptiveLayoutConfig::default();
        let q = PathQuality::new(120.0, 0.12, 2);
        assert_eq!(cfg.derive(Some(q)), cfg.derive(Some(q)));
    }
