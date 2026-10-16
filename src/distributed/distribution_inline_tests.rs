    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::security::key::AuthKey;
    use crate::types::symbol::{ObjectParams, Symbol};
    use serde_json::json;

    fn create_test_replicas(count: usize) -> Vec<ReplicaInfo> {
        (0..count)
            .map(|i| ReplicaInfo::new(&format!("r{i}"), &format!("addr{i}")))
            .collect()
    }

    fn authorized_security_context(replicas: &[ReplicaInfo]) -> SecurityContext {
        let security = SecurityContext::new(AuthKey::from_seed(0xD157_71B0));
        for replica in replicas {
            security
                .authorize_replica(&replica.id, None)
                .expect("test replica id should authorize");
        }
        security
    }

    fn create_test_symbols(count: usize) -> Vec<Symbol> {
        (0..count)
            .map(|i| Symbol::new_for_test(1, 0, i as u32, &[0u8; 128]))
            .collect()
    }

    fn create_test_encoded_state() -> EncodedState {
        EncodedState {
            params: ObjectParams::new_for_test(1, 1024),
            symbols: create_test_symbols(10),
            source_count: 8,
            repair_count: 2,
            original_size: 1000,
            encoded_at: Time::ZERO,
            layout_decision: Default::default(),
        }
    }

    fn canonical_assignment_mapping_snapshot() -> serde_json::Value {
        let replicas = create_test_replicas(4);
        let encoded = EncodedState {
            params: ObjectParams::new_for_test(9, 2048),
            symbols: create_test_symbols(6),
            source_count: 4,
            repair_count: 2,
            original_size: 1536,
            encoded_at: Time::ZERO,
            layout_decision: Default::default(),
        };
        let security = authorized_security_context(&replicas);
        let assignments =
            SymbolDistributor::compute_assignments_with_auth(&encoded, &replicas, &security, None);

        json!({
            "consistency": "quorum",
            "required_acks": SymbolDistributor::required_acks(ConsistencyLevel::Quorum, replicas.len()),
            "source_count": encoded.source_count,
            "repair_count": encoded.repair_count,
            "replica_count": replicas.len(),
            "assignments": assignments.iter().map(|assignment| {
                json!({
                    "replica_id": assignment.replica_id,
                    "symbol_indices": assignment.symbol_indices,
                    "can_decode": assignment.can_decode,
                })
            }).collect::<Vec<_>>(),
        })
    }

    fn make_ack(replica_id: &str, count: u32) -> ReplicaAck {
        ReplicaAck {
            replica_id: replica_id.to_string(),
            symbols_received: count,
            ack_time: Time::ZERO,
        }
    }

    fn make_failure(replica_id: &str) -> ReplicaFailure {
        ReplicaFailure {
            replica_id: replica_id.to_string(),
            error: "connection refused".to_string(),
            error_kind: ErrorKind::NodeUnavailable,
        }
    }

    struct MockSuccessTransport;

    impl DistributorTransport for MockSuccessTransport {
        fn send_symbols(
            &self,
            replica_id: &str,
            symbols: Vec<AuthenticatedSymbol>,
        ) -> impl Future<Output = Result<ReplicaAck, ReplicaFailure>> + Send {
            let replica_id = replica_id.to_string();
            let symbol_count = symbols.len() as u32;
            async move { Ok(make_ack(&replica_id, symbol_count)) }
        }
    }

    #[test]
    fn distribute_with_quorum_consistency() {
        let config = DistributionConfig {
            consistency: ConsistencyLevel::Quorum,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();

        // 2 of 3 replicas succeed (quorum = 2).
        let outcomes = vec![
            Outcome::Ok(make_ack("r0", 10)),
            Outcome::Ok(make_ack("r1", 10)),
            Outcome::Err(make_failure("r2")),
        ];

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(result.quorum_achieved);
        assert_eq!(result.acks.len(), 2);
        assert_eq!(result.failures.len(), 1);
    }

    #[test]
    fn distribute_with_all_consistency() {
        let config = DistributionConfig {
            consistency: ConsistencyLevel::All,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();

        // Only 2 of 3 respond.
        let outcomes = vec![
            Outcome::Ok(make_ack("r0", 10)),
            Outcome::Err(make_failure("r1")),
            Outcome::Ok(make_ack("r2", 10)),
        ];

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(!result.quorum_achieved);
    }

    #[test]
    fn distribute_tracks_failures() {
        let config = DistributionConfig::default();
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();

        let outcomes = vec![
            Outcome::Ok(make_ack("r0", 10)),
            Outcome::Ok(make_ack("r1", 10)),
            Outcome::Err(make_failure("r2")),
        ];

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(!result.failures.is_empty());
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].replica_id, "r2");
    }

    #[test]
    fn evaluate_outcomes_quorum_counts_are_permutation_invariant() {
        let replicas = create_test_replicas(5);
        let encoded = create_test_encoded_state();
        let baseline = vec![
            Outcome::Ok(make_ack("r0", 10)),
            Outcome::Err(make_failure("r1")),
            Outcome::Ok(make_ack("r2", 10)),
            Outcome::Err(make_failure("r3")),
            Outcome::Ok(make_ack("r4", 10)),
        ];
        let permuted = vec![
            Outcome::Err(make_failure("r3")),
            Outcome::Ok(make_ack("r4", 10)),
            Outcome::Ok(make_ack("r0", 10)),
            Outcome::Ok(make_ack("r2", 10)),
            Outcome::Err(make_failure("r1")),
        ];

        let mut baseline_distributor = SymbolDistributor::new(DistributionConfig::default());
        let baseline_result = baseline_distributor.evaluate_outcomes(
            &encoded,
            &replicas,
            baseline,
            Duration::from_millis(50),
        );
        let mut permuted_distributor = SymbolDistributor::new(DistributionConfig::default());
        let permuted_result = permuted_distributor.evaluate_outcomes(
            &encoded,
            &replicas,
            permuted,
            Duration::from_millis(50),
        );

        assert_eq!(
            baseline_result.quorum_achieved,
            permuted_result.quorum_achieved
        );
        assert_eq!(baseline_result.acks.len(), permuted_result.acks.len());
        assert_eq!(
            baseline_result.failures.len(),
            permuted_result.failures.len()
        );
        assert_eq!(
            baseline_result.symbols_distributed,
            permuted_result.symbols_distributed
        );
        assert_eq!(
            baseline_distributor.metrics.distributions_successful,
            permuted_distributor.metrics.distributions_successful
        );
        assert_eq!(
            baseline_distributor.metrics.distributions_failed,
            permuted_distributor.metrics.distributions_failed
        );
        assert_eq!(
            baseline_distributor.metrics.acks_received_total,
            permuted_distributor.metrics.acks_received_total
        );
    }

    #[test]
    fn distribution_metrics_updated() {
        let config = DistributionConfig::default();
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();

        let outcomes = vec![
            Outcome::Ok(make_ack("r0", 10)),
            Outcome::Ok(make_ack("r1", 10)),
            Outcome::Ok(make_ack("r2", 10)),
        ];

        let security = authorized_security_context(&replicas);
        let symbols_sent_total: u64 =
            SymbolDistributor::compute_assignments_with_auth(&encoded, &replicas, &security, None)
                .into_iter()
                .map(|assignment| assignment.symbol_indices.len() as u64)
                .sum();

        distributor.evaluate_outcomes_with_sent(
            &encoded,
            SymbolDistributor::required_acks(distributor.config.consistency, replicas.len()),
            outcomes,
            symbols_sent_total,
            Duration::from_millis(50),
        );

        assert_eq!(distributor.metrics.distributions_total, 1);
        assert_eq!(distributor.metrics.distributions_successful, 1);
        assert_eq!(distributor.metrics.symbols_sent_total, symbols_sent_total);
        assert_eq!(distributor.metrics.acks_received_total, 3);
    }

    #[test]
    fn distribute_counts_symbols_sent_per_replica_attempt() {
        let config = DistributionConfig::default();
        let mut distributor = SymbolDistributor::new(config);
        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();
        let auth_context = authorized_security_context(&replicas);
        let transport = MockSuccessTransport;

        let expected_symbols_sent: u64 = SymbolDistributor::compute_assignments_with_auth(
            &encoded,
            &replicas,
            &auth_context,
            None,
        )
        .into_iter()
        .map(|assignment| assignment.symbol_indices.len() as u64)
        .sum();

        let cx = Cx::for_testing();
        let result = futures_lite::future::block_on(async {
            distributor
                .distribute(&cx, &encoded, &replicas, &transport, &auth_context)
                .await
        });

        assert!(result.quorum_achieved);
        assert_eq!(result.acks.len(), replicas.len());
        assert_eq!(distributor.metrics.distributions_total, 1);
        assert_eq!(
            distributor.metrics.symbols_sent_total,
            expected_symbols_sent
        );
        assert_eq!(
            result.symbols_distributed,
            u32::try_from(expected_symbols_sent).unwrap_or(u32::MAX)
        );
    }

    #[test]
    fn asupersync_8mp6md_distribution_quorum_uses_eligible_attempts() {
        let config = DistributionConfig {
            consistency: ConsistencyLevel::Quorum,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);
        let replicas = create_test_replicas(5);
        let encoded = create_test_encoded_state();
        let security = SecurityContext::new(AuthKey::from_seed(0x008A_110C));
        for replica in &replicas[..2] {
            security
                .authorize_replica(&replica.id, None)
                .expect("eligible replica must authorize");
        }

        let cx = Cx::for_testing();
        let result = futures_lite::future::block_on(distributor.distribute(
            &cx,
            &encoded,
            &replicas,
            &MockSuccessTransport,
            &security,
        ));

        assert!(result.quorum_achieved);
        assert_eq!(result.acks.len(), 2);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn asupersync_8mp6md_distribution_zero_eligible_fails_closed() {
        let config = DistributionConfig {
            consistency: ConsistencyLevel::All,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);
        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();
        let security = SecurityContext::new(AuthKey::from_seed(0x008A_110C));

        let cx = Cx::for_testing();
        let result = futures_lite::future::block_on(distributor.distribute(
            &cx,
            &encoded,
            &replicas,
            &MockSuccessTransport,
            &security,
        ));

        assert!(!result.quorum_achieved);
        assert!(result.acks.is_empty());
        assert_eq!(result.symbols_distributed, 0);
    }

    #[test]
    fn explicit_striped_distribution_sends_each_symbol_once_and_keeps_full_default() {
        struct RecordingTransport(std::sync::Mutex<Vec<(String, Vec<u32>)>>);
        impl DistributorTransport for RecordingTransport {
            async fn send_symbols(&self, replica: &str, symbols: Vec<AuthenticatedSymbol>) -> Result<ReplicaAck, ReplicaFailure> {
                let indices = symbols.iter().map(|symbol| symbol.symbol().esi()).collect();
                self.0.lock().unwrap().push((replica.to_owned(), indices));
                Ok(make_ack(replica, u32::try_from(symbols.len()).unwrap()))
            }
        }
        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();
        let security = authorized_security_context(&replicas);
        let cx = Cx::for_testing();
        let transport = RecordingTransport(std::sync::Mutex::new(Vec::new()));
        let mut distributor = SymbolDistributor::new(DistributionConfig::default());
        let striped = futures_lite::future::block_on(distributor.distribute_with_strategy(
            &cx, &encoded, &replicas, &transport, &security, AssignmentStrategy::Striped,
        ));
        assert!(striped.quorum_achieved);
        assert_eq!(striped.symbols_distributed, 10);
        assert_eq!(*transport.0.lock().unwrap(), vec![
            ("r0".into(), vec![0, 3, 6, 9]), ("r1".into(), vec![1, 4, 7]), ("r2".into(), vec![2, 5, 8]),
        ]);
        let full = futures_lite::future::block_on(distributor.distribute(
            &cx, &encoded, &replicas, &MockSuccessTransport, &security,
        ));
        assert_eq!(full.symbols_distributed, 30);
        assert!(full.acks.iter().all(|ack| ack.symbols_received == 10));
        assert_eq!(distributor.metrics.symbols_sent_total, 40);
    }

    /// br-asupersync-307rnt: distribute() reads its start/end
    /// timestamps via `cx.timer_driver()` and falls back to
    /// `crate::time::wall_now()` only when no driver is installed.
    /// This test exercises the no-driver path (`Cx::for_testing`
    /// has none) and asserts that the resulting duration is at
    /// least non-negative and well-defined; the virtual-clock
    /// determinism path is exercised by lab-runtime integration
    /// tests that wire a `TimerDriverHandle::with_virtual_clock`
    /// through the runtime builder. The key invariant tested here
    /// is that distribute() now accepts a `&Cx` rather than reaching
    /// for ambient `std::time::Instant::now()`.
    #[test]
    fn distribute_duration_is_well_defined_through_cx() {
        let config = DistributionConfig::default();
        let mut distributor = SymbolDistributor::new(config);
        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();
        let auth_context = SecurityContext::for_testing(7);
        let transport = MockSuccessTransport;

        let cx = Cx::for_testing();
        let result = futures_lite::future::block_on(async {
            distributor
                .distribute(&cx, &encoded, &replicas, &transport, &auth_context)
                .await
        });

        // Duration is computed via Time::duration_since which is
        // saturating_sub, so it can never be negative; with the
        // wall_now fallback path it can be very small but not
        // pathological. The point of this test is to confirm
        // distribute() compiles + runs with the new Cx-threaded
        // signature; replay-determinism is covered by integration
        // tests that wire a virtual timer driver.
        assert!(result.duration <= Duration::from_secs(60));
    }

    #[test]
    fn distribute_to_no_replicas() {
        let config = DistributionConfig::default();
        let mut distributor = SymbolDistributor::new(config);

        let replicas: Vec<ReplicaInfo> = vec![];
        let encoded = create_test_encoded_state();

        // No outcomes.
        let outcomes: Vec<Outcome<ReplicaAck, ReplicaFailure>> = vec![];

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        // Quorum required = (0/2)+1 = 1 for Quorum level, but with 0 replicas
        // this fails because required(1) > total(0).
        assert!(!result.quorum_achieved);
        assert_eq!(result.symbols_distributed, 0);
    }

    #[test]
    fn evaluate_outcomes_reports_symbols_from_assignment_plan() {
        let config = DistributionConfig::default();
        let mut distributor = SymbolDistributor::new(config);
        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();
        let assignments = SymbolDistributor::compute_assignments(&encoded, &replicas);
        let expected_symbols_sent: u32 = assignments
            .iter()
            .map(|assignment| assignment.symbol_indices.len() as u32)
            .sum();
        let outcomes: Vec<Outcome<ReplicaAck, ReplicaFailure>> = assignments
            .iter()
            .map(|assignment| {
                Outcome::Ok(make_ack(
                    &assignment.replica_id,
                    assignment.symbol_indices.len() as u32,
                ))
            })
            .collect();

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert_eq!(result.symbols_distributed, expected_symbols_sent);
    }

    #[test]
    fn required_acks_calculation() {
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::One, 3),
            1
        );
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::Quorum, 3),
            2
        );
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::Quorum, 5),
            3
        );
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::All, 3),
            3
        );
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::Local, 3),
            0
        );
    }

    #[test]
    fn local_consistency_always_succeeds() {
        let config = DistributionConfig {
            consistency: ConsistencyLevel::Local,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();

        // Even with all failures, Local consistency needs 0 acks.
        let outcomes = vec![
            Outcome::Err(make_failure("r0")),
            Outcome::Err(make_failure("r1")),
            Outcome::Err(make_failure("r2")),
        ];

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(result.quorum_achieved);
    }

    // ========== Edge case tests (bd-3k9o) ==========

    #[test]
    fn partial_ack_quorum_evaluation() {
        // 5 of 10 replicas ack — quorum is (10/2)+1 = 6, so 5 is NOT enough
        let config = DistributionConfig {
            consistency: ConsistencyLevel::Quorum,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(10);
        let encoded = create_test_encoded_state();

        let mut outcomes: Vec<Outcome<ReplicaAck, ReplicaFailure>> = Vec::new();
        for i in 0..5 {
            outcomes.push(Outcome::Ok(make_ack(&format!("r{i}"), 10)));
        }
        for i in 5..10 {
            outcomes.push(Outcome::Err(make_failure(&format!("r{i}"))));
        }

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(!result.quorum_achieved);
        assert_eq!(result.acks.len(), 5);
        assert_eq!(result.failures.len(), 5);
    }

    #[test]
    fn partial_ack_quorum_exactly_met() {
        // 6 of 10 replicas ack — quorum is (10/2)+1 = 6, exactly met
        let config = DistributionConfig {
            consistency: ConsistencyLevel::Quorum,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(10);
        let encoded = create_test_encoded_state();

        let mut outcomes: Vec<Outcome<ReplicaAck, ReplicaFailure>> = Vec::new();
        for i in 0..6 {
            outcomes.push(Outcome::Ok(make_ack(&format!("r{i}"), 10)));
        }
        for i in 6..10 {
            outcomes.push(Outcome::Err(make_failure(&format!("r{i}"))));
        }

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(result.quorum_achieved);
        assert_eq!(result.acks.len(), 6);
    }

    #[test]
    fn quorum_with_only_one_replica_available() {
        // Quorum config but only 1 replica: required = (1/2)+1 = 1
        let config = DistributionConfig {
            consistency: ConsistencyLevel::Quorum,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(1);
        let encoded = create_test_encoded_state();

        let outcomes = vec![Outcome::Ok(make_ack("r0", 10))];

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(result.quorum_achieved);
    }

    #[test]
    fn quorum_with_one_replica_failing() {
        // Quorum config, 1 replica, it fails: required=1, got 0
        let config = DistributionConfig {
            consistency: ConsistencyLevel::Quorum,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(1);
        let encoded = create_test_encoded_state();

        let outcomes = vec![Outcome::Err(make_failure("r0"))];

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(!result.quorum_achieved);
    }

    #[test]
    fn all_consistency_one_failure_breaks_quorum() {
        let config = DistributionConfig {
            consistency: ConsistencyLevel::All,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(5);
        let encoded = create_test_encoded_state();

        let mut outcomes: Vec<Outcome<ReplicaAck, ReplicaFailure>> = Vec::new();
        for i in 0..4 {
            outcomes.push(Outcome::Ok(make_ack(&format!("r{i}"), 10)));
        }
        outcomes.push(Outcome::Err(make_failure("r4")));

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(!result.quorum_achieved);
        assert_eq!(result.acks.len(), 4);
        assert_eq!(result.failures.len(), 1);
    }

    #[test]
    fn one_consistency_needs_only_one() {
        let config = DistributionConfig {
            consistency: ConsistencyLevel::One,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(5);
        let encoded = create_test_encoded_state();

        // Only first succeeds, rest fail
        let mut outcomes: Vec<Outcome<ReplicaAck, ReplicaFailure>> = Vec::new();
        outcomes.push(Outcome::Ok(make_ack("r0", 10)));
        for i in 1..5 {
            outcomes.push(Outcome::Err(make_failure(&format!("r{i}"))));
        }

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(result.quorum_achieved);
    }

    #[test]
    fn distribution_zero_duration() {
        let config = DistributionConfig::default();
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();

        let outcomes = vec![
            Outcome::Ok(make_ack("r0", 10)),
            Outcome::Ok(make_ack("r1", 10)),
            Outcome::Ok(make_ack("r2", 10)),
        ];

        let result = distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::ZERO);

        assert!(result.quorum_achieved);
        assert_eq!(result.duration, Duration::ZERO);
    }

    #[test]
    fn metrics_accumulate_across_multiple_distributions() {
        let config = DistributionConfig::default();
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();

        // First distribution: success
        let outcomes1 = vec![
            Outcome::Ok(make_ack("r0", 10)),
            Outcome::Ok(make_ack("r1", 10)),
            Outcome::Ok(make_ack("r2", 10)),
        ];
        distributor.evaluate_outcomes(&encoded, &replicas, outcomes1, Duration::from_millis(50));

        // Second distribution: failure
        let outcomes2 = vec![
            Outcome::Err(make_failure("r0")),
            Outcome::Err(make_failure("r1")),
            Outcome::Err(make_failure("r2")),
        ];
        distributor.evaluate_outcomes(&encoded, &replicas, outcomes2, Duration::from_millis(50));

        assert_eq!(distributor.metrics.distributions_total, 2);
        assert_eq!(distributor.metrics.distributions_successful, 1);
        assert_eq!(distributor.metrics.distributions_failed, 1);
        assert_eq!(distributor.metrics.acks_received_total, 3);
        assert_eq!(distributor.metrics.quorum_achieved_count, 1);
        assert_eq!(distributor.metrics.quorum_missed_count, 1);
    }

    #[test]
    fn required_acks_boundary_values() {
        // Even replica counts
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::Quorum, 2),
            2
        ); // (2/2)+1
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::Quorum, 4),
            3
        ); // (4/2)+1
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::Quorum, 100),
            51
        );

        // Single replica
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::One, 1),
            1
        );
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::All, 1),
            1
        );
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::Quorum, 1),
            1
        );
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::Local, 1),
            0
        );

        // Zero replicas
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::Local, 0),
            0
        );
        assert_eq!(
            SymbolDistributor::required_acks(ConsistencyLevel::One, 0),
            1
        ); // Can never be met
    }

    #[test]
    fn cancelled_outcomes_not_counted_as_failures() {
        let config = DistributionConfig::default();
        let mut distributor = SymbolDistributor::new(config);

        let replicas = create_test_replicas(3);
        let encoded = create_test_encoded_state();

        let outcomes = vec![
            Outcome::Ok(make_ack("r0", 10)),
            Outcome::Ok(make_ack("r1", 10)),
            Outcome::Cancelled(crate::types::CancelReason::timeout()),
        ];

        let result =
            distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));

        assert!(result.quorum_achieved);
        assert_eq!(result.acks.len(), 2);
        // Cancelled is not an Error variant, so failures should be empty
        assert!(result.failures.is_empty());
    }

    #[test]
    fn config_accessors() {
        let config = DistributionConfig {
            consistency: ConsistencyLevel::All,
            ack_timeout: Duration::from_secs(10),
            max_concurrent: 5,
            hedge_enabled: true,
            hedge_delay: Duration::from_millis(100),
            encoding_path_quality: None,
        };
        let distributor = SymbolDistributor::new(config);

        assert_eq!(distributor.config().consistency, ConsistencyLevel::All);
        assert_eq!(distributor.config().ack_timeout, Duration::from_secs(10));
        assert_eq!(distributor.config().max_concurrent, 5);
        assert!(distributor.config().hedge_enabled);
    }

    #[test]
    fn distribution_config_applies_path_quality_to_encoding_config() {
        let quality = PathQualitySnapshot::new(120, 150, 4);
        let distribution = DistributionConfig::default().with_encoding_path_quality(quality);
        let encoding = distribution.apply_to_encoding_config(EncodingConfig::default());

        assert_eq!(encoding.path_quality, Some(quality));
    }

    #[test]
    fn debug_format() {
        let distributor = SymbolDistributor::new(DistributionConfig::default());
        let debug = format!("{distributor:?}");
        assert!(debug.contains("SymbolDistributor"));
        assert!(debug.contains("config"));
        assert!(debug.contains("metrics"));
    }

    // =========================================================================
    // Wave 56 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn distribution_config_debug_clone() {
        let cfg = DistributionConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("DistributionConfig"), "{dbg}");
        let cloned = cfg.clone();
        assert_eq!(cfg.max_concurrent, cloned.max_concurrent);
    }

    #[test]
    fn canonical_assignment_mapping() {
        assert_eq!(
            canonical_assignment_mapping_snapshot(),
            json!({
                "assignments": [
                    {
                        "can_decode": true,
                        "replica_id": "r0",
                        "symbol_indices": [0, 1, 2, 3, 4, 5],
                    },
                    {
                        "can_decode": true,
                        "replica_id": "r1",
                        "symbol_indices": [0, 1, 2, 3, 4, 5],
                    },
                    {
                        "can_decode": true,
                        "replica_id": "r2",
                        "symbol_indices": [0, 1, 2, 3, 4, 5],
                    },
                    {
                        "can_decode": true,
                        "replica_id": "r3",
                        "symbol_indices": [0, 1, 2, 3, 4, 5],
                    },
                ],
                "consistency": "quorum",
                "repair_count": 2,
                "replica_count": 4,
                "required_acks": 3,
                "source_count": 4,
            })
        );
    }

    #[test]
    fn replica_ack_debug_clone() {
        let ack = ReplicaAck {
            replica_id: "r0".to_string(),
            symbols_received: 10,
            ack_time: Time::ZERO,
        };
        let dbg = format!("{ack:?}");
        assert!(dbg.contains("ReplicaAck"), "{dbg}");
        let cloned = ack;
        assert_eq!(cloned.replica_id, "r0");
    }

    #[test]
    fn replica_failure_debug_clone() {
        let fail = ReplicaFailure {
            replica_id: "r1".to_string(),
            error: "timeout".to_string(),
            error_kind: ErrorKind::NodeUnavailable,
        };
        let dbg = format!("{fail:?}");
        assert!(dbg.contains("ReplicaFailure"), "{dbg}");
        let cloned = fail;
        assert_eq!(cloned.error, "timeout");
    }
