    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use insta::assert_snapshot;
    use std::time::Duration;

    // Tolerance for floating-point comparisons.
    const EPS: f64 = 1e-3;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < EPS || (a.is_infinite() && b.is_infinite() && a.signum() == b.signum())
    }

    // -----------------------------------------------------------------------
    // Piecewise-linear curve basics
    // -----------------------------------------------------------------------

    #[test]
    fn zero_curve_evaluates_to_zero() {
        let c = PiecewiseLinearCurve::zero();
        assert!(approx_eq(c.eval(0.0), 0.0));
        assert!(approx_eq(c.eval(1.0), 0.0));
        assert!(approx_eq(c.eval(100.0), 0.0));
    }

    #[test]
    fn affine_curve_evaluates_correctly() {
        // f(t) = 10 + 5*t
        let c = PiecewiseLinearCurve::affine(5.0, 10.0);
        assert!(approx_eq(c.eval(0.0), 10.0));
        assert!(approx_eq(c.eval(1.0), 15.0));
        assert!(approx_eq(c.eval(2.0), 20.0));
        assert!(approx_eq(c.eval(10.0), 60.0));
    }

    #[test]
    fn rate_latency_curve_has_zero_before_latency() {
        // beta(t) = 100 * max(0, t - 0.5)
        let c = PiecewiseLinearCurve::rate_latency(100.0, 0.5);
        assert!(approx_eq(c.eval(0.0), 0.0));
        assert!(approx_eq(c.eval(0.25), 0.0));
        assert!(approx_eq(c.eval(0.5), 0.0));
        assert!(approx_eq(c.eval(1.0), 50.0));
        assert!(approx_eq(c.eval(1.5), 100.0));
    }

    #[test]
    fn from_segments_rejects_unsorted() {
        let segments = vec![Segment::new(1.0, 1.0, 0.0), Segment::new(0.0, 1.0, 0.0)];
        assert!(PiecewiseLinearCurve::from_segments(segments).is_none());
    }

    #[test]
    fn from_segments_rejects_negative_rate() {
        let segments = vec![Segment::new(0.0, -1.0, 0.0)];
        assert!(PiecewiseLinearCurve::from_segments(segments).is_none());
    }

    #[test]
    fn from_segments_rejects_discontinuity() {
        // First segment ends at 5.0, second starts at 10.0 (gap of 5.0).
        let segments = vec![
            Segment::new(0.0, 1.0, 0.0),
            Segment::new(5.0, 2.0, 10.0), // Should be 5.0 at start=5.0
        ];
        assert!(PiecewiseLinearCurve::from_segments(segments).is_none());
    }

    #[test]
    fn from_segments_accepts_valid_continuous_curve() {
        // f(t) = t for [0,1), then f(t) = 1 + 2*(t-1) for [1, ...)
        let segments = vec![Segment::new(0.0, 1.0, 0.0), Segment::new(1.0, 2.0, 1.0)];
        let c = PiecewiseLinearCurve::from_segments(segments).unwrap();
        assert!(approx_eq(c.eval(0.5), 0.5));
        assert!(approx_eq(c.eval(1.0), 1.0));
        assert!(approx_eq(c.eval(2.0), 3.0));
    }

    #[test]
    fn negative_time_evaluates_to_zero() {
        let c = PiecewiseLinearCurve::affine(1.0, 5.0);
        assert!(approx_eq(c.eval(-1.0), 0.0));
        assert!(approx_eq(c.eval(-100.0), 0.0));
    }

    // -----------------------------------------------------------------------
    // Horizontal deviation (delay bound)
    // -----------------------------------------------------------------------

    #[test]
    fn delay_bound_affine_token_bucket_rate_latency() {
        // Classic network calculus example:
        //   alpha(t) = sigma + rho * t   (token bucket: sigma=50, rho=100)
        //   beta(t)  = R * max(0, t-T)   (rate-latency: R=200, T=0.01)
        //
        // Closed form: d* = T + sigma/R = 0.01 + 50/200 = 0.26
        let alpha = ArrivalCurve::token_bucket(100.0, 50.0);
        let beta = ServiceCurve::rate_latency(200.0, 0.01);

        let d = delay_bound(&alpha, &beta);
        assert!(approx_eq(d, 0.26), "expected ~0.26, got {d}");
    }

    #[test]
    fn delay_bound_equal_rates_burst_only() {
        // alpha(t) = 10 + 5*t, beta(t) = 5*t
        // Delay is infinite because arrival has burst but service has no
        // headroom above the rate. The gap alpha(t) - beta(t) = 10 never closes.
        // Actually, when rates are equal, delay = inf { d : 10 + 5*t <= 5*(t+d) }
        //   = inf { d : 10 <= 5d } = 2.0
        let alpha = ArrivalCurve::token_bucket(5.0, 10.0);
        let beta = ServiceCurve::constant_rate(5.0);

        let d = delay_bound(&alpha, &beta);
        assert!(approx_eq(d, 2.0), "expected ~2.0, got {d}");
    }

    #[test]
    fn delay_bound_unstable_system() {
        // Arrival rate exceeds service rate: delay is infinite.
        let alpha = ArrivalCurve::constant_rate(200.0);
        let beta = ServiceCurve::constant_rate(100.0);

        let d = delay_bound(&alpha, &beta);
        assert!(d.is_infinite(), "expected infinite, got {d}");
    }

    #[test]
    fn delay_bound_zero_burst_zero_latency() {
        // alpha(t) = rho*t, beta(t) = R*t where R > rho.
        // Delay should be 0 (or very close).
        let alpha = ArrivalCurve::constant_rate(50.0);
        let beta = ServiceCurve::constant_rate(100.0);

        let d = delay_bound(&alpha, &beta);
        assert!(d < EPS, "expected ~0, got {d}");
    }

    // -----------------------------------------------------------------------
    // Vertical deviation (backlog bound)
    // -----------------------------------------------------------------------

    #[test]
    fn backlog_bound_token_bucket_rate_latency() {
        // alpha(t) = 50 + 100*t, beta(t) = 200*max(0, t - 0.01)
        // Closed form: b* = sigma + rho*T = 50 + 100*0.01 = 51
        let alpha = ArrivalCurve::token_bucket(100.0, 50.0);
        let beta = ServiceCurve::rate_latency(200.0, 0.01);

        let b = backlog_bound(&alpha, &beta);
        assert!(approx_eq(b, 51.0), "expected ~51.0, got {b}");
    }

    #[test]
    fn backlog_bound_unstable_system() {
        let alpha = ArrivalCurve::constant_rate(200.0);
        let beta = ServiceCurve::constant_rate(100.0);

        let b = backlog_bound(&alpha, &beta);
        assert!(b.is_infinite(), "expected infinite, got {b}");
    }

    // -----------------------------------------------------------------------
    // (min,+) convolution properties
    // -----------------------------------------------------------------------

    #[test]
    fn convolution_identity() {
        // Convolution with the zero curve (delta_0 approximation).
        // For a constant-rate curve, convolving with itself should yield
        // a curve with doubled latency characteristics.
        let f = PiecewiseLinearCurve::affine(10.0, 0.0);
        let g = PiecewiseLinearCurve::affine(10.0, 0.0);

        let conv = min_plus_convolution(&f, &g);
        // (f (x) g)(t) = inf_{0<=s<=t} { 10s + 10(t-s) } = 10t
        // For affine functions with same rate and zero burst, convolution is the function itself.
        assert!(
            approx_eq(conv.eval(1.0), 10.0),
            "expected ~10.0, got {}",
            conv.eval(1.0)
        );
    }

    #[test]
    fn convolution_commutativity() {
        // f (x) g = g (x) f
        let f = PiecewiseLinearCurve::affine(5.0, 10.0);
        let g = PiecewiseLinearCurve::rate_latency(8.0, 0.5);

        let fg = min_plus_convolution(&f, &g);
        let gf = min_plus_convolution(&g, &f);

        // Check at several points.
        for &t in &[0.0, 0.5, 1.0, 2.0, 5.0, 10.0] {
            assert!(
                approx_eq(fg.eval(t), gf.eval(t)),
                "commutativity failed at t={t}: fg={}, gf={}",
                fg.eval(t),
                gf.eval(t)
            );
        }
    }

    #[test]
    fn convolution_rate_latency_sum() {
        // For two rate-latency curves:
        //   beta_1(t) = R * max(0, t - T1)
        //   beta_2(t) = R * max(0, t - T2)
        // The convolution is:
        //   (beta_1 (x) beta_2)(t) = R * max(0, t - T1 - T2)
        // (Theorem 3.1.3, Le Boudec & Thiran)
        let beta1 = ServiceCurve::rate_latency(100.0, 0.1);
        let beta2 = ServiceCurve::rate_latency(100.0, 0.2);

        let combined = beta1.sequential(&beta2);

        // Expected: rate=100, latency=0.3
        // At t=0.5: 100 * (0.5 - 0.3) = 20.0
        assert!(
            approx_eq(combined.eval(0.3), 0.0),
            "expected ~0.0 at t=0.3, got {}",
            combined.eval(0.3)
        );
        assert!(
            approx_eq(combined.eval(0.5), 20.0),
            "expected ~20.0 at t=0.5, got {}",
            combined.eval(0.5)
        );
        assert!(
            approx_eq(combined.eval(1.0), 70.0),
            "expected ~70.0 at t=1.0, got {}",
            combined.eval(1.0)
        );
    }

    #[test]
    fn convolution_associativity() {
        // (f (x) g) (x) h = f (x) (g (x) h)
        let f = PiecewiseLinearCurve::rate_latency(10.0, 0.1);
        let g = PiecewiseLinearCurve::rate_latency(15.0, 0.2);
        let h = PiecewiseLinearCurve::rate_latency(20.0, 0.05);

        let fg_h = min_plus_convolution(&min_plus_convolution(&f, &g), &h);
        let f_gh = min_plus_convolution(&f, &min_plus_convolution(&g, &h));

        for &t in &[0.0, 0.5, 1.0, 2.0, 5.0] {
            assert!(
                approx_eq(fg_h.eval(t), f_gh.eval(t)),
                "associativity failed at t={t}: (fg)h={}, f(gh)={}",
                fg_h.eval(t),
                f_gh.eval(t)
            );
        }
    }

    // -----------------------------------------------------------------------
    // Service curve scaling
    // -----------------------------------------------------------------------

    #[test]
    fn service_curve_scaling() {
        let beta = ServiceCurve::rate_latency(100.0, 0.01);
        let scaled = beta.scale(3.0);

        // Rate should triple, latency unchanged.
        assert!(approx_eq(scaled.eval(0.01), 0.0));
        assert!(approx_eq(scaled.eval(0.02), 3.0)); // 300 * 0.01
        assert!(approx_eq(scaled.eval(0.11), 30.0)); // 300 * 0.1
    }

    // -----------------------------------------------------------------------
    // PlanDag integration: join
    // -----------------------------------------------------------------------

    #[test]
    fn dag_join_takes_max_delay() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("fast");
        let b = dag.leaf("slow");
        let joined = dag.join(vec![a, b]);
        dag.set_root(joined);

        let mut analyzer = LatencyAnalyzer::new();
        // fast: delay ~0.05s
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );
        // slow: delay ~0.26s (T=0.01 + sigma/R = 50/200)
        analyzer.annotate(
            b,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 50.0),
                ServiceCurve::rate_latency(200.0, 0.01),
            ),
        );

        let analysis = analyzer.analyze(&dag);

        // Golden artifact: freeze latency analysis output
        insta::assert_snapshot!(analysis.to_string());

        // Join should take the max (slow's delay).
        let root_delay = analysis.end_to_end_delay().unwrap();
        let slow_delay = analysis.delay_at(b).unwrap();
        assert!(
            approx_eq(root_delay, slow_delay),
            "join delay {root_delay} should equal slow delay {slow_delay}"
        );
        // The join delay should be approximately 0.26.
        assert!(
            (root_delay - 0.26).abs() < 0.05,
            "expected join delay ~0.26, got {root_delay}"
        );
    }

    #[test]
    fn dag_join_empty_children_is_zero() {
        let mut dag = PlanDag::new();
        let joined = dag.join(vec![]);
        dag.set_root(joined);

        let analyzer = LatencyAnalyzer::new();
        let analysis = analyzer.analyze(&dag);

        assert!(approx_eq(analysis.end_to_end_delay().unwrap(), 0.0));
    }

    // -----------------------------------------------------------------------
    // PlanDag integration: race
    // -----------------------------------------------------------------------

    #[test]
    fn dag_race_takes_min_delay() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("fast");
        let b = dag.leaf("slow");
        let raced = dag.race(vec![a, b]);
        dag.set_root(raced);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );
        analyzer.annotate(
            b,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 50.0),
                ServiceCurve::rate_latency(200.0, 0.01),
            ),
        );

        let analysis = analyzer.analyze(&dag);

        let root_delay = analysis.end_to_end_delay().unwrap();
        let fast_delay = analysis.delay_at(a).unwrap();
        assert!(
            approx_eq(root_delay, fast_delay),
            "race delay {root_delay} should equal fast delay {fast_delay}"
        );
        assert!(
            root_delay < 0.1,
            "race delay should be small, got {root_delay}"
        );
    }

    #[test]
    fn dag_race_empty_children_is_infinite() {
        let mut dag = PlanDag::new();
        let raced = dag.race(vec![]);
        dag.set_root(raced);

        let analyzer = LatencyAnalyzer::new();
        let analysis = analyzer.analyze(&dag);

        assert!(analysis.end_to_end_delay().unwrap().is_infinite());
    }

    // -----------------------------------------------------------------------
    // PlanDag integration: timeout
    // -----------------------------------------------------------------------

    #[test]
    fn dag_timeout_caps_delay() {
        let mut dag = PlanDag::new();
        let slow = dag.leaf("slow");
        let timed = dag.timeout(slow, Duration::from_millis(100));
        dag.set_root(timed);

        let mut analyzer = LatencyAnalyzer::new();
        // Slow service: delay ~1.0s.
        analyzer.annotate(
            slow,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 100.0),
                ServiceCurve::rate_latency(200.0, 0.5),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let root_delay = analysis.end_to_end_delay().unwrap();

        // Timeout of 100ms should cap the delay.
        assert!(
            root_delay <= 0.1 + EPS,
            "timeout should cap delay to 0.1s, got {root_delay}"
        );
    }

    #[test]
    fn dag_timeout_passthrough_when_child_is_fast() {
        let mut dag = PlanDag::new();
        let fast = dag.leaf("fast");
        let timed = dag.timeout(fast, Duration::from_secs(10));
        dag.set_root(timed);

        let mut analyzer = LatencyAnalyzer::new();
        // Fast service: delay ~0.05s (well under 10s timeout).
        analyzer.annotate(
            fast,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let root_delay = analysis.end_to_end_delay().unwrap();
        let child_delay = analysis.delay_at(fast).unwrap();

        assert!(
            approx_eq(root_delay, child_delay),
            "with generous timeout, delay should match child: root={root_delay}, child={child_delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Nested timeout collapsing (TIMEOUT-MIN law)
    // -----------------------------------------------------------------------

    #[test]
    fn nested_timeout_min_law() {
        // TIMEOUT-MIN: timeout(d1, timeout(d2, f)) ~ timeout(min(d1,d2), f)
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("task");
        let inner_timeout = dag.timeout(leaf, Duration::from_millis(500));
        let outer_timeout = dag.timeout(inner_timeout, Duration::from_millis(200));
        dag.set_root(outer_timeout);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            leaf,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 200.0),
                ServiceCurve::rate_latency(200.0, 1.0), // Slow: ~2s delay.
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let root_delay = analysis.end_to_end_delay().unwrap();

        // min(500ms, 200ms) = 200ms should dominate.
        assert!(
            root_delay <= 0.2 + EPS,
            "nested timeouts should collapse to min: got {root_delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Complex DAG: join of races with timeouts
    // -----------------------------------------------------------------------

    #[test]
    fn complex_dag_join_race_timeout() {
        // Structure:
        //   join(
        //     race(a, b),
        //     timeout(c, 0.5s)
        //   )
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let race_ab = dag.race(vec![a, b]);
        let timeout_c = dag.timeout(c, Duration::from_millis(500));
        let root = dag.join(vec![race_ab, timeout_c]);
        dag.set_root(root);

        let mut analyzer = LatencyAnalyzer::new();
        // a: fast (~0.05s)
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );
        // b: moderate (~0.26s)
        analyzer.annotate(
            b,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 50.0),
                ServiceCurve::rate_latency(200.0, 0.01),
            ),
        );
        // c: slow (~2.0s, will be capped by timeout)
        analyzer.annotate(
            c,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 200.0),
                ServiceCurve::rate_latency(200.0, 1.0),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let root_delay = analysis.end_to_end_delay().unwrap();

        // race(a, b) delay = min(0.05, 0.26) ~ 0.05
        // timeout(c, 0.5) delay = min(2.0, 0.5) = 0.5
        // join delay = max(0.05, 0.5) = 0.5
        assert!(
            (root_delay - 0.5).abs() < 0.1,
            "expected root delay ~0.5, got {root_delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Default curves for unannotated leaves
    // -----------------------------------------------------------------------

    #[test]
    fn default_curves_used_for_unannotated_leaves() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("annotated");
        let b = dag.leaf("unannotated");
        let joined = dag.join(vec![a, b]);
        dag.set_root(joined);

        let mut analyzer = LatencyAnalyzer::with_defaults(
            ArrivalCurve::token_bucket(50.0, 20.0),
            ServiceCurve::rate_latency(100.0, 0.005),
        );
        // Only annotate 'a'.
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );

        let analysis = analyzer.analyze(&dag);

        // Both nodes should have finite delays.
        assert!(analysis.delay_at(a).unwrap().is_finite());
        assert!(analysis.delay_at(b).unwrap().is_finite());
        assert!(analysis.end_to_end_delay().unwrap().is_finite());
    }

    #[test]
    fn missing_annotation_no_defaults_gives_infinity() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("no_annotation");
        dag.set_root(a);

        let analyzer = LatencyAnalyzer::new();
        let analysis = analyzer.analyze(&dag);

        assert!(analysis.delay_at(a).unwrap().is_infinite());
    }

    // -----------------------------------------------------------------------
    // Provenance and bottleneck identification
    // -----------------------------------------------------------------------

    #[test]
    fn provenance_identifies_bottleneck() {
        let mut dag = PlanDag::new();
        let fast = dag.leaf("fast");
        let slow = dag.leaf("slow");
        let joined = dag.join(vec![fast, slow]);
        dag.set_root(joined);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            fast,
            NodeCurves::new(
                ArrivalCurve::constant_rate(10.0),
                ServiceCurve::constant_rate(100.0),
            ),
        );
        analyzer.annotate(
            slow,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 500.0),
                ServiceCurve::rate_latency(200.0, 0.1),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let bound = analysis.root_bound.as_ref().unwrap();

        // The bottleneck should be the slow node.
        assert!(!bound.provenance.is_empty());
        let top = bound.bottleneck().unwrap();
        assert!(
            top.delay > 0.1,
            "bottleneck delay should be significant, got {}",
            top.delay
        );
    }

    #[test]
    fn bound_contribution_display_format() {
        let contribution = BoundContribution {
            node_id: PlanId::new(42),
            delay: 0.123_456_789,
            description: "pipeline stage with high latency".to_string(),
        };

        assert_snapshot!(format!("{contribution}"));
    }

    #[test]
    fn latency_bound_display_format() {
        let bound = LatencyBound {
            delay: 0.123_456,
            backlog: 42.0,
            utilization: 0.75,
            provenance: vec![BoundContribution {
                node_id: PlanId::new(0),
                delay: 0.123_456,
                description: "test node".to_string(),
            }],
        };

        assert_snapshot!(format!("{bound}"));
    }

    #[test]
    fn latency_bound_summary_stable() {
        let bound = LatencyBound {
            delay: 0.5,
            backlog: 100.0,
            utilization: 0.6,
            provenance: vec![BoundContribution {
                node_id: PlanId::new(3),
                delay: 0.5,
                description: "slow".to_string(),
            }],
        };
        let s = bound.summary();
        assert!(s.contains("delay<="));
        assert!(s.contains("bottleneck=node[3]"));
    }

    #[test]
    fn latency_bound_summary_unstable() {
        let bound = LatencyBound {
            delay: f64::INFINITY,
            backlog: f64::INFINITY,
            utilization: 1.5,
            provenance: vec![],
        };
        let s = bound.summary();
        assert!(s.contains("UNSTABLE"));
    }

    // -----------------------------------------------------------------------
    // NodeCurves standalone
    // -----------------------------------------------------------------------

    #[test]
    fn node_curves_utilization() {
        let curves = NodeCurves::new(
            ArrivalCurve::constant_rate(80.0),
            ServiceCurve::constant_rate(100.0),
        );
        assert!(approx_eq(curves.utilization(), 0.8));
    }

    #[test]
    fn node_curves_utilization_zero_service() {
        let curves = NodeCurves::new(
            ArrivalCurve::constant_rate(80.0),
            ServiceCurve::constant_rate(0.0),
        );
        assert!(curves.utilization().is_infinite());
    }

    // -----------------------------------------------------------------------
    // Deconvolution
    // -----------------------------------------------------------------------

    #[test]
    fn deconvolution_token_bucket_rate_latency() {
        // Output arrival curve through a rate-latency server.
        // For alpha(t) = sigma + rho*t through beta(t) = R*max(0, t-T),
        // output: alpha_out(t) = sigma + rho*T + rho*t (burstiness increases by rho*T).
        let alpha = PiecewiseLinearCurve::affine(100.0, 50.0); // rho=100, sigma=50
        let beta = PiecewiseLinearCurve::rate_latency(200.0, 0.01); // R=200, T=0.01

        let output = min_plus_deconvolution(&alpha, &beta);

        // At t=0: output(0) = sup_{s>=0} { alpha(s) - beta(s) }
        //       = sup_{s>=0} { (50 + 100s) - 200*max(0, s-0.01) }
        // The sup occurs at s = T = 0.01: (50 + 1) - 0 = 51
        let val_0 = output.eval(0.0);
        assert!(
            (val_0 - 51.0).abs() < 2.0,
            "deconvolution at t=0: expected ~51, got {val_0}"
        );
    }

    // -----------------------------------------------------------------------
    // Staircase curve
    // -----------------------------------------------------------------------

    #[test]
    fn staircase_curve_step_values() {
        let c = PiecewiseLinearCurve::staircase(10.0, 1.0, 3);
        // After each period, the value should jump by step_size.
        // At t=0.5 (mid first period): ~10.0 (stepped up immediately).
        assert!(c.eval(0.5) >= 9.0 && c.eval(0.5) <= 11.0);
        // At t=1.5 (mid second period): ~20.0.
        assert!(c.eval(1.5) >= 19.0 && c.eval(1.5) <= 21.0);
    }

    // -----------------------------------------------------------------------
    // Algebraic property: race(join(a,b), join(a,c)) delay relationships
    // -----------------------------------------------------------------------

    #[test]
    fn race_join_distributivity_delay() {
        // Verify that d(race(join(a,b), join(a,c))) <= d(join(a, race(b,c)))
        // (The delay of the LHS is at most the delay of the RHS.)
        let mut dag_lhs = PlanDag::new();
        let a1 = dag_lhs.leaf("a");
        let b = dag_lhs.leaf("b");
        let a2 = dag_lhs.leaf("a_copy");
        let c = dag_lhs.leaf("c");
        let lhs_join_with_b = dag_lhs.join(vec![a1, b]);
        let lhs_join_with_c = dag_lhs.join(vec![a2, c]);
        let race_root = dag_lhs.race(vec![lhs_join_with_b, lhs_join_with_c]);
        dag_lhs.set_root(race_root);

        let mut dag_rhs = PlanDag::new();
        let a3 = dag_rhs.leaf("a");
        let b2 = dag_rhs.leaf("b");
        let c2 = dag_rhs.leaf("c");
        let race_bc = dag_rhs.race(vec![b2, c2]);
        let join_root = dag_rhs.join(vec![a3, race_bc]);
        dag_rhs.set_root(join_root);

        let a_curves = NodeCurves::new(
            ArrivalCurve::token_bucket(100.0, 30.0),
            ServiceCurve::rate_latency(200.0, 0.005),
        );
        let b_curves = NodeCurves::new(
            ArrivalCurve::token_bucket(80.0, 50.0),
            ServiceCurve::rate_latency(150.0, 0.01),
        );
        let c_curves = NodeCurves::new(
            ArrivalCurve::token_bucket(60.0, 10.0),
            ServiceCurve::rate_latency(120.0, 0.002),
        );

        let mut analyzer_lhs = LatencyAnalyzer::new();
        analyzer_lhs.annotate(a1, a_curves.clone());
        analyzer_lhs.annotate(b, b_curves.clone());
        analyzer_lhs.annotate(a2, a_curves.clone());
        analyzer_lhs.annotate(c, c_curves.clone());

        let mut analyzer_rhs = LatencyAnalyzer::new();
        analyzer_rhs.annotate(a3, a_curves);
        analyzer_rhs.annotate(b2, b_curves);
        analyzer_rhs.annotate(c2, c_curves);

        let lhs_delay = analyzer_lhs.analyze(&dag_lhs).end_to_end_delay().unwrap();
        let rhs_delay = analyzer_rhs.analyze(&dag_rhs).end_to_end_delay().unwrap();

        // The distributivity law holds at the delay level:
        // race(join(a,b), join(a,c)) delay <= join(a, race(b,c)) delay.
        assert!(
            lhs_delay <= rhs_delay + EPS,
            "distributivity: lhs={lhs_delay} should be <= rhs={rhs_delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Analysis Display
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_summary_format() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::constant_rate(10.0),
                ServiceCurve::constant_rate(20.0),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let summary = analysis.summary();
        assert!(summary.contains("nodes analyzed"));
    }

    #[test]
    fn analysis_display_includes_all_nodes() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let joined = dag.join(vec![a, b]);
        dag.set_root(joined);

        let analyzer = LatencyAnalyzer::with_defaults(
            ArrivalCurve::constant_rate(10.0),
            ServiceCurve::constant_rate(20.0),
        );

        let analysis = analyzer.analyze(&dag);
        assert_snapshot!(format!("{analysis}"));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn single_leaf_dag_analysis() {
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("single");
        dag.set_root(leaf);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            leaf,
            NodeCurves::new(
                ArrivalCurve::token_bucket(50.0, 25.0),
                ServiceCurve::rate_latency(100.0, 0.01),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let delay = analysis.end_to_end_delay().unwrap();

        // Expected: T + sigma/R = 0.01 + 25/100 = 0.26
        assert!(
            (delay - 0.26).abs() < 0.05,
            "single leaf delay expected ~0.26, got {delay}"
        );
    }

    #[test]
    fn dag_with_no_root_has_no_bound() {
        let mut dag = PlanDag::new();
        let _a = dag.leaf("orphan");
        // No root set.

        let analyzer = LatencyAnalyzer::with_defaults(
            ArrivalCurve::constant_rate(10.0),
            ServiceCurve::constant_rate(20.0),
        );

        let analysis = analyzer.analyze(&dag);
        assert!(analysis.root_bound.is_none());
        // But per-node delays should still be computed.
        assert!(!analysis.node_delays.is_empty());
    }

    #[test]
    fn deeply_nested_timeouts() {
        // timeout(100ms, timeout(200ms, timeout(50ms, leaf)))
        // Effective timeout: min(100, 200, 50) = 50ms
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("task");
        let t1 = dag.timeout(leaf, Duration::from_millis(50));
        let t2 = dag.timeout(t1, Duration::from_millis(200));
        let t3 = dag.timeout(t2, Duration::from_millis(100));
        dag.set_root(t3);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            leaf,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 500.0),
                ServiceCurve::rate_latency(200.0, 5.0), // Very slow: ~7.5s.
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let delay = analysis.end_to_end_delay().unwrap();

        assert!(
            delay <= 0.05 + EPS,
            "deeply nested timeouts should collapse to min(50ms): got {delay}"
        );
    }

    #[test]
    fn wide_join_many_children() {
        let mut dag = PlanDag::new();
        let children: Vec<PlanId> = (0..20).map(|i| dag.leaf(format!("child_{i}"))).collect();
        let joined = dag.join(children.clone());
        dag.set_root(joined);

        let mut analyzer = LatencyAnalyzer::new();
        for (i, &child) in children.iter().enumerate() {
            let i_u32 = u32::try_from(i).expect("test uses small child index");
            let burst = f64::from(i_u32).mul_add(5.0, 10.0);
            analyzer.annotate(
                child,
                NodeCurves::new(
                    ArrivalCurve::token_bucket(100.0, burst),
                    ServiceCurve::rate_latency(200.0, 0.001),
                ),
            );
        }

        let analysis = analyzer.analyze(&dag);
        let delay = analysis.end_to_end_delay().unwrap();

        // The slowest child has burst=10+19*5=105, delay ~ 0.001 + 105/200 = 0.526.
        assert!(delay.is_finite());
        assert!(
            delay > 0.4,
            "wide join should be dominated by slowest child, got {delay}"
        );
    }

    #[test]
    fn wide_race_many_children() {
        let mut dag = PlanDag::new();
        let children: Vec<PlanId> = (0..20).map(|i| dag.leaf(format!("child_{i}"))).collect();
        let raced = dag.race(children.clone());
        dag.set_root(raced);

        let mut analyzer = LatencyAnalyzer::new();
        for (i, &child) in children.iter().enumerate() {
            let i_u32 = u32::try_from(i).expect("test uses small child index");
            let burst = f64::from(i_u32).mul_add(5.0, 10.0);
            analyzer.annotate(
                child,
                NodeCurves::new(
                    ArrivalCurve::token_bucket(100.0, burst),
                    ServiceCurve::rate_latency(200.0, 0.001),
                ),
            );
        }

        let analysis = analyzer.analyze(&dag);
        let delay = analysis.end_to_end_delay().unwrap();

        // The fastest child has burst=10, delay ~ 0.001 + 10/200 = 0.051.
        assert!(delay.is_finite());
        assert!(
            delay < 0.15,
            "wide race should be dominated by fastest child, got {delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Monotonicity: adding more work increases delay
    // -----------------------------------------------------------------------

    #[test]
    fn delay_monotonic_in_burst() {
        // Increasing burst should increase delay.
        let service = ServiceCurve::rate_latency(200.0, 0.01);
        let d1 = delay_bound(&ArrivalCurve::token_bucket(100.0, 10.0), &service);
        let d2 = delay_bound(&ArrivalCurve::token_bucket(100.0, 50.0), &service);
        let d3 = delay_bound(&ArrivalCurve::token_bucket(100.0, 100.0), &service);

        assert!(d1 <= d2 + EPS, "d1={d1} should be <= d2={d2}");
        assert!(d2 <= d3 + EPS, "d2={d2} should be <= d3={d3}");
    }

    #[test]
    fn delay_monotonic_in_latency() {
        // Increasing server latency should increase delay.
        let arrival = ArrivalCurve::token_bucket(100.0, 50.0);
        let d1 = delay_bound(&arrival, &ServiceCurve::rate_latency(200.0, 0.0));
        let d2 = delay_bound(&arrival, &ServiceCurve::rate_latency(200.0, 0.1));
        let d3 = delay_bound(&arrival, &ServiceCurve::rate_latency(200.0, 0.5));

        assert!(d1 <= d2 + EPS, "d1={d1} should be <= d2={d2}");
        assert!(d2 <= d3 + EPS, "d2={d2} should be <= d3={d3}");
    }

    // -----------------------------------------------------------------------
    // Isotonicity of convolution
    // -----------------------------------------------------------------------

    #[test]
    fn convolution_isotone() {
        // If f <= g pointwise, then f (x) h <= g (x) h pointwise.
        let f = PiecewiseLinearCurve::affine(5.0, 0.0);
        let g = PiecewiseLinearCurve::affine(10.0, 0.0);
        let h = PiecewiseLinearCurve::rate_latency(8.0, 0.1);

        let fh = min_plus_convolution(&f, &h);
        let gh = min_plus_convolution(&g, &h);

        for &t in &[0.0, 0.5, 1.0, 2.0, 5.0] {
            assert!(
                fh.eval(t) <= gh.eval(t) + EPS,
                "isotonicity failed at t={t}: fh={} > gh={}",
                fh.eval(t),
                gh.eval(t)
            );
        }
    }

    // -----------------------------------------------------------------------
    // Golden artifacts for mathematical Display outputs
    // -----------------------------------------------------------------------

    #[test]
    fn bound_contribution_infinite_delay() {
        let contribution = BoundContribution {
            node_id: PlanId::new(7),
            delay: f64::INFINITY,
            description: "bottleneck node with no service curve".to_string(),
        };

        assert_snapshot!(format!("{contribution}"));
    }

    #[test]
    fn bound_contribution_zero_delay() {
        let contribution = BoundContribution {
            node_id: PlanId::new(0),
            delay: 0.0,
            description: "instant operation".to_string(),
        };

        assert_snapshot!(format!("{contribution}"));
    }

    #[test]
    fn latency_bound_complex_provenance() {
        let bound = LatencyBound {
            delay: 2.345_678,
            backlog: 1234.56,
            utilization: 0.89,
            provenance: vec![
                BoundContribution {
                    node_id: PlanId::new(1),
                    delay: 0.5,
                    description: "database query".to_string(),
                },
                BoundContribution {
                    node_id: PlanId::new(3),
                    delay: 1.2,
                    description: "network request with retry".to_string(),
                },
                BoundContribution {
                    node_id: PlanId::new(5),
                    delay: 0.645_678,
                    description: "computation pipeline".to_string(),
                },
            ],
        };

        assert_snapshot!(format!("{bound}"));
    }

    #[test]
    fn latency_bound_unstable_system() {
        let bound = LatencyBound {
            delay: f64::INFINITY,
            backlog: f64::INFINITY,
            utilization: 1.5,
            provenance: vec![BoundContribution {
                node_id: PlanId::new(2),
                delay: f64::INFINITY,
                description: "overloaded service (rate > capacity)".to_string(),
            }],
        };

        assert_snapshot!(format!("{bound}"));
    }

    #[test]
    fn latency_analysis_complex_dag() {
        let mut dag = PlanDag::new();

        // Build a complex DAG: (a || b || c) && (d || e)
        #[allow(clippy::many_single_char_names)]
        let a = dag.leaf("fast_cache_lookup");
        let b = dag.leaf("slow_database_query");
        let c = dag.leaf("post_processing");
        let d = dag.leaf("parallel_computation");
        let e = dag.leaf("result_aggregation");

        let abc_race = dag.race(vec![a, b, c]);
        let de_race = dag.race(vec![d, e]);
        let final_join = dag.join(vec![abc_race, de_race]);

        dag.set_root(final_join);

        let mut analyzer = LatencyAnalyzer::new();

        // Annotate with diverse service characteristics
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::constant_rate(100.0),
                ServiceCurve::rate_latency(500.0, 0.001),
            ),
        );
        analyzer.annotate(
            b,
            NodeCurves::new(
                ArrivalCurve::token_bucket(50.0, 20.0),
                ServiceCurve::rate_latency(80.0, 0.05),
            ),
        );
        analyzer.annotate(
            c,
            NodeCurves::new(
                ArrivalCurve::constant_rate(50.0),
                ServiceCurve::rate_latency(200.0, 0.01),
            ),
        );
        analyzer.annotate(
            d,
            NodeCurves::new(
                ArrivalCurve::constant_rate(30.0),
                ServiceCurve::rate_latency(150.0, 0.02),
            ),
        );
        analyzer.annotate(
            e,
            NodeCurves::new(
                ArrivalCurve::constant_rate(25.0),
                ServiceCurve::rate_latency(100.0, 0.015),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        assert_snapshot!(format!("{analysis}"));
    }

    #[test]
    fn latency_analysis_single_node_with_annotation() {
        let mut dag = PlanDag::new();
        let single = dag.leaf("annotated_service");
        dag.set_root(single);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            single,
            NodeCurves::new(
                ArrivalCurve::token_bucket(75.5, 25.3),
                ServiceCurve::rate_latency(120.7, 0.0123),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        assert_snapshot!(format!("{analysis}"));
    }

    #[test]
    fn latency_analysis_unannotated_leaves() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("unannotated_service_a");
        let b = dag.leaf("unannotated_service_b");
        let joined = dag.join(vec![a, b]);
        dag.set_root(joined);

        let analyzer = LatencyAnalyzer::with_defaults(
            ArrivalCurve::constant_rate(10.0),
            ServiceCurve::constant_rate(5.0), // Overloaded system
        );

        let analysis = analyzer.analyze(&dag);
        assert_snapshot!(format!("{analysis}"));
    }
