    use super::*;
    use crate::trace::event::TraceEvent;

    struct MockValidator {
        should_pass: bool,
    }

    impl ReplayValidator for MockValidator {
        fn validate_replay(&self, _events: &[TraceEvent]) -> Result<bool> {
            Ok(self.should_pass)
        }

        fn target_description(&self) -> String {
            "Deterministic validation".to_string()
        }
    }

    #[tokio::test]
    async fn test_delta_debugging_minimization() {
        let validator = Arc::new(MockValidator { should_pass: true });
        let mut minimizer = TraceMinimizer::new(
            MinimizationConfig::default(),
            validator,
            MinimizationStrategy::DeltaDebugging,
        );

        let events = vec![]; // Deterministic event fixture starts empty.
        let result = minimizer.minimize(events).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_minimization_config() {
        let config = MinimizationConfig {
            max_iterations: 500,
            target_reduction: 0.2,
            ..Default::default()
        };

        assert_eq!(config.max_iterations, 500);
        assert_eq!(config.target_reduction, 0.2);
    }

    #[tokio::test]
    async fn test_replay_optimizer() {
        let optimizer = ReplayOptimizer::new(MinimizationConfig::default());
        let events = vec![]; // Deterministic event fixture starts empty.

        let result = optimizer.optimize(events).await;
        assert!(result.is_ok());
    }

    #[test]
    fn delta_debugging_tests_each_candidate_and_reports_original_indices() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        struct NeedsSeq(u64);
        impl ReplayValidator for NeedsSeq {
            fn validate_replay(&self, events: &[TraceEvent]) -> Result<bool> {
                Ok(events.iter().any(|event| event.seq == self.0))
            }
            fn target_description(&self) -> String {
                format!("keeps event {}", self.0)
            }
        }

        let events: Vec<TraceEvent> = (0..16)
            .map(|seq| TraceEvent::user_trace(seq, crate::types::Time::ZERO, "event"))
            .collect();
        let mut minimizer = TraceMinimizer::new(
            MinimizationConfig::default(),
            Arc::new(NeedsSeq(5)),
            MinimizationStrategy::DeltaDebugging,
        );
        let minimize = std::pin::pin!(minimizer.minimize(events));
        let Poll::Ready(result) = minimize.poll(&mut Context::from_waker(Waker::noop())) else {
            panic!("the minimizer awaits nothing external");
        };
        let result = result.expect("minimizes");
        assert_eq!(
            (result.minimized_size, result.essential_events.clone()),
            (1, vec![5]),
        );
        assert_eq!(
            result.pruned_events,
            (0..16).filter(|&index| index != 5).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_minimizer_factory() {
        let validator = Arc::new(MockValidator { should_pass: true });

        let minimizer = MinimizerFactory::for_bug_reproduction(validator);
        assert_eq!(minimizer.strategy, MinimizationStrategy::Hybrid);
    }
