    use super::*;
    use crate::bytes::Bytes;
    use crate::net::atp::datagram::frame::DatagramFrame;

    fn create_test_datagram(priority: DatagramPriority) -> (DatagramFrame, DatagramMetadata) {
        let frame = DatagramFrame::with_length(Bytes::from_static(b"test"));
        let metadata = DatagramMetadata::new("test").with_priority(priority);
        (frame, metadata)
    }

    fn matrix162_rate_config() -> DatagramRateConfig {
        DatagramRateConfig {
            initial_pacing_bytes_per_s: 1_000_000,
            min_pacing_bytes_per_s: 64_000,
            max_pacing_bytes_per_s: 100_000_000,
            initial_cwnd_bytes: 128_000,
            min_cwnd_bytes: 16_000,
            max_cwnd_bytes: 8_000_000,
            pacing_gain: 1.0,
            cwnd_gain: 2.0,
            loss_backoff_threshold: 0.02,
            loss_backoff_factor: 0.50,
            loss_delivery_headroom: 1.25,
            receiver_window_gain: 1.0,
            min_receiver_window_bytes: 16_000,
            max_receiver_window_bytes: 8_000_000,
            min_rtt_window_micros: 1_000_000,
        }
    }

    fn matrix162_rate_sample(
        at_micros: u64,
        sent_bytes: u64,
        delivered_bytes: u64,
        rtt_micros: u64,
        receiver_credit_bytes: u64,
    ) -> DatagramRateSample {
        DatagramRateSample {
            now_micros: at_micros,
            sent_bytes,
            acked_bytes: delivered_bytes,
            lost_bytes: 0,
            bytes_in_flight: sent_bytes.saturating_sub(delivered_bytes),
            rtt_micros: Some(rtt_micros),
            receiver_credit_bytes: (receiver_credit_bytes > 0).then_some(receiver_credit_bytes),
            receiver_window_bytes: (receiver_credit_bytes > 0).then_some(receiver_credit_bytes),
        }
    }

    fn observe_rate(
        controller: &mut DatagramRateController,
        sample: DatagramRateSample,
    ) -> DatagramRateDecision {
        controller.observe(sample)
    }

    #[test]
    fn matrix162_rate_controller_tracks_ack_clocked_bottleneck_bandwidth() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());

        let clean = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 0),
        );
        assert_eq!(clean.bottleneck_bytes_per_s, 1_000_000);
        assert_eq!(clean.pacing_bytes_per_s, 1_000_000);
        assert_eq!(clean.pacing_rate_bps, 8_000_000);
        assert_eq!(clean.min_rtt_micros, Some(100_000));
        assert_eq!(clean.sender_loss_fraction_ppm, 0);

        let faster = observe_rate(
            &mut controller,
            matrix162_rate_sample(200_000, 200_000, 200_000, 120_000, 0),
        );
        assert_eq!(faster.bottleneck_bytes_per_s, 2_000_000);
        assert_eq!(faster.pacing_bytes_per_s, 2_000_000);
        assert_eq!(faster.pacing_rate_bps, 16_000_000);
        assert_eq!(
            faster.min_rtt_micros,
            Some(100_000),
            "higher RTT inside the min-RTT window must not replace the floor"
        );
        assert!(
            faster.cwnd_bytes > clean.cwnd_bytes,
            "cwnd should grow with the bottleneck-bandwidth estimate"
        );
    }

    #[test]
    fn matrix162_rate_controller_backs_off_on_sender_side_delivery_loss() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());
        let clean = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 0),
        );

        let lossy = observe_rate(
            &mut controller,
            matrix162_rate_sample(200_000, 1_000_000, 100_000, 110_000, 0),
        );
        assert!(
            lossy.sender_loss_fraction_ppm >= 900_000,
            "sender-side sent-vs-delivered loss must see queue overflow"
        );
        assert!(
            lossy.pacing_bytes_per_s < clean.pacing_bytes_per_s,
            "loss must back off the shared pacing authority"
        );
    }

    #[test]
    fn matrix162_rate_controller_tracks_windowed_min_rtt() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());

        let floor = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 0),
        );
        assert_eq!(floor.min_rtt_micros, Some(100_000));

        let in_window = observe_rate(
            &mut controller,
            matrix162_rate_sample(600_000, 100_000, 100_000, 130_000, 0),
        );
        assert_eq!(
            in_window.min_rtt_micros,
            Some(100_000),
            "higher RTT inside the window must not raise the floor"
        );

        let expired = observe_rate(
            &mut controller,
            matrix162_rate_sample(1_300_000, 100_000, 100_000, 140_000, 0),
        );
        assert_eq!(
            expired.min_rtt_micros,
            Some(140_000),
            "expired min-RTT windows may refresh upward"
        );
    }

    #[test]
    fn matrix162_rate_controller_caps_inflight_to_receiver_credit() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());
        let decision = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 1_000_000, 1_000_000, 100_000, 64_000),
        );

        assert_eq!(decision.receiver_credit_bytes, Some(64_000));
        assert!(
            decision.cwnd_bytes > 64_000,
            "test sample should build a larger congestion window than receiver credit"
        );
        assert_eq!(
            decision.send_budget_bytes, 64_000,
            "receiver credit must cap the immediate send budget"
        );
    }

    #[test]
    fn matrix162_rate_controller_replays_deterministically() {
        let samples = [
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 0),
            matrix162_rate_sample(200_000, 1_000_000, 100_000, 120_000, 0),
            matrix162_rate_sample(1_400_000, 1_500_000, 1_500_000, 90_000, 0),
        ];

        let mut left = DatagramRateController::new(matrix162_rate_config());
        let mut right = DatagramRateController::new(matrix162_rate_config());
        let left_decisions: Vec<_> = samples
            .iter()
            .copied()
            .map(|sample| observe_rate(&mut left, sample))
            .collect();
        let right_decisions: Vec<_> = samples
            .iter()
            .copied()
            .map(|sample| observe_rate(&mut right, sample))
            .collect();

        assert_eq!(
            left_decisions, right_decisions,
            "explicit samples must replay to identical controller decisions"
        );
    }

    #[test]
    fn matrix162_rate_controller_enforces_send_slot_and_receiver_credit() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());
        let decision = observe_rate(
            &mut controller,
            matrix162_rate_sample(100_000, 100_000, 100_000, 100_000, 64_000),
        );

        assert!(controller.can_send(0, 1200, decision.receiver_credit_bytes));
        assert!(
            !controller
                .admit_send(
                    100_000,
                    64_000,
                    1200,
                    decision.receiver_credit_bytes,
                    Some(64_000),
                )
                .is_send()
        );
        assert!(controller.try_send(100_000, 0, 1200, decision.receiver_credit_bytes));
        assert!(
            !controller.try_send(100_000, 1200, 1200, decision.receiver_credit_bytes),
            "second send at the same timestamp must wait for the pacing slot"
        );
        let wait = controller.time_until_send_micros(100_000);
        assert!(wait > 0);
        assert!(controller.try_send(100_000 + wait, 1200, 1200, decision.receiver_credit_bytes));
    }

    #[test]
    fn matrix162_rate_controller_configures_shared_receiver_limited_budget() {
        let mut rate = DatagramRateController::new(DatagramRateConfig {
            initial_pacing_bytes_per_s: 48_000,
            min_pacing_bytes_per_s: 48_000,
            max_pacing_bytes_per_s: 48_000,
            initial_cwnd_bytes: 16_000,
            min_cwnd_bytes: 16_000,
            max_cwnd_bytes: 16_000,
            ..DatagramRateConfig::default()
        });
        let decision = rate.observe(DatagramRateSample {
            now_micros: 100_000,
            sent_bytes: 4 * 1200,
            acked_bytes: 4 * 1200,
            lost_bytes: 0,
            bytes_in_flight: 0,
            rtt_micros: Some(100_000),
            receiver_credit_bytes: Some(4 * 1200),
            receiver_window_bytes: Some(4 * 1200),
        });

        let mut controller = CongestionController::new(CongestionConfig::default());
        controller.configure_from_rate_decision(decision, 1200, 32);
        let now = Instant::now();

        let mut burst = 0;
        while controller.try_consume_send_budget(now) {
            burst += 1;
            assert!(
                burst <= 4,
                "receiver-limited shared decision allowed burst {burst}"
            );
        }
        assert_eq!(
            burst, 4,
            "shared receiver credit should limit the legacy token budget"
        );
        assert!(controller.time_until_send_budget(now) > Duration::ZERO);
    }

    #[test]
    fn matrix164_delivery_clocked_loss_persists_across_rounds() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());

        let overflow = controller.observe(DatagramRateSample {
            now_micros: 100_000,
            sent_bytes: 1_000_000,
            acked_bytes: 100_000,
            lost_bytes: 0,
            bytes_in_flight: 900_000,
            rtt_micros: Some(100_000),
            receiver_credit_bytes: None,
            receiver_window_bytes: None,
        });
        assert!(
            overflow.sender_loss_fraction_ppm >= 900_000,
            "sender-side delivery clock must see queue overflow"
        );
        assert!(
            overflow.send_rate_bytes_per_s > overflow.delivery_rate_bytes_per_s,
            "overflow sample should expose offered send rate above delivered rate"
        );
        assert!(
            overflow.loss_limited,
            "delivery-rate overflow should put the controller into loss-limited pacing"
        );

        let clean_tail = controller.observe(DatagramRateSample {
            now_micros: 200_000,
            sent_bytes: 100_000,
            acked_bytes: 100_000,
            lost_bytes: 0,
            bytes_in_flight: 0,
            rtt_micros: Some(100_000),
            receiver_credit_bytes: None,
            receiver_window_bytes: None,
        });
        assert!(
            clean_tail.sender_loss_fraction_ppm >= 800_000,
            "cumulative sent-vs-delivered evidence must not forget prior overflow immediately"
        );
        assert!(
            clean_tail.pacing_bytes_per_s <= overflow.pacing_bytes_per_s,
            "overflow evidence should keep the next controller decision backed off"
        );
    }

    #[test]
    fn matrix164_cwnd_and_receiver_window_subtract_bytes_in_flight() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());
        let decision = controller.observe(DatagramRateSample {
            now_micros: 100_000,
            sent_bytes: 400_000,
            acked_bytes: 400_000,
            lost_bytes: 0,
            bytes_in_flight: 0,
            rtt_micros: Some(100_000),
            receiver_credit_bytes: Some(20_000),
            receiver_window_bytes: Some(128_000),
        });

        let (inflight_limit, send_budget) =
            controller.send_window(110_000, decision.receiver_credit_bytes, Some(128_000));
        assert_eq!(inflight_limit, 128_000);
        assert_eq!(
            send_budget, 18_000,
            "send budget must be min(cwnd/window residual, receiver remaining credit)"
        );
        assert!(
            !controller.window_admits_send(
                110_000,
                20_000,
                decision.receiver_credit_bytes,
                Some(128_000),
            ),
            "datagram that exceeds the residual receiver/cwnd window must be blocked"
        );
        assert!(
            controller.window_admits_send(
                110_000,
                18_000,
                decision.receiver_credit_bytes,
                Some(128_000),
            ),
            "a datagram that fits both residual cwnd and receiver credit should pass"
        );
    }

    #[test]
    fn matrix164_send_admission_distinguishes_wait_from_failure() {
        let mut controller = DatagramRateController::new(matrix162_rate_config());
        let decision =
            controller.observe(matrix162_rate_sample(100_000, 200_000, 200_000, 100_000, 0));

        assert!(controller.try_send(100_000, 0, 1200, None));
        assert_eq!(
            controller.admit_send(100_000, 1200, 1200, decision.receiver_credit_bytes, None,),
            DatagramSendAdmission::Wait {
                wait_micros: controller.time_until_send_micros(100_000)
            },
            "pacing pressure is still viable and must not be surfaced as a fatal transfer error"
        );
        assert!(
            controller
                .admit_send(100_000, 1200, 1200, Some(0), None)
                .is_still_viable(),
            "receiver-credit exhaustion should be a flow-control wait/retry condition"
        );
        assert!(
            controller
                .admit_send(100_000, decision.cwnd_bytes, 1200, None, None)
                .is_still_viable(),
            "cwnd exhaustion should not collapse into a fail-closed transfer abort"
        );
    }

    #[test]
    fn matrix168_ack_clocked_ten_percent_loss_converges_and_bounds_inflight() {
        let link_payload_bytes_per_s = 1_250_000u64;
        let ack_interval_micros = 100_000u64;
        let rtt_micros = 200_000u64;
        let sent_per_ack = link_payload_bytes_per_s * ack_interval_micros / 1_000_000;
        let lost_per_ack = sent_per_ack / 10;
        let acked_per_ack = sent_per_ack - lost_per_ack;
        let steady_inflight = link_payload_bytes_per_s * rtt_micros / 1_000_000;
        let mut controller = DatagramRateController::new(DatagramRateConfig {
            initial_pacing_bytes_per_s: link_payload_bytes_per_s,
            max_pacing_bytes_per_s: 10_000_000,
            initial_cwnd_bytes: steady_inflight,
            cwnd_gain: 1.0,
            loss_backoff_threshold: 0.13,
            ..matrix162_rate_config()
        });

        let mut decision = None;
        for ack in 1..=24u64 {
            decision = Some(controller.observe(DatagramRateSample {
                now_micros: ack * ack_interval_micros,
                sent_bytes: sent_per_ack,
                acked_bytes: acked_per_ack,
                lost_bytes: lost_per_ack,
                bytes_in_flight: steady_inflight,
                rtt_micros: Some(rtt_micros),
                receiver_credit_bytes: None,
                receiver_window_bytes: None,
            }));
        }

        let decision = decision.expect("synthetic ACK stream should produce a decision");
        assert!(
            (1_000_000..=1_300_000).contains(&decision.pacing_bytes_per_s),
            "ACK-clocked 10% loss should converge near delivered bottleneck rate, got {}",
            decision.pacing_bytes_per_s
        );
        assert!(
            (200_000..=300_000).contains(&decision.inflight_limit_bytes),
            "cwnd should settle near BtlBw x RTprop, got {}",
            decision.inflight_limit_bytes
        );
        assert_eq!(
            decision.bytes_in_flight, steady_inflight,
            "transport-provided bytes-in-flight must be preserved in decisions"
        );
        assert!(
            decision.send_budget_bytes
                <= decision
                    .inflight_limit_bytes
                    .saturating_sub(steady_inflight),
            "send budget must subtract already in-flight DATAGRAM bytes"
        );
        assert!(
            !decision.loss_limited,
            "expected-profile 10% loss should converge by ACK clock, not halve every ACK"
        );
        assert!(
            matches!(
                controller.admit_send(
                    decision.min_rtt_micros.unwrap_or(rtt_micros),
                    decision.inflight_limit_bytes,
                    sent_per_ack,
                    None,
                    None,
                ),
                DatagramSendAdmission::CwndBlocked { .. }
            ),
            "cwnd admission must block another burst once BDP-derived in-flight is full"
        );
    }

    #[test]
    fn test_congestion_controller_creation() {
        let config = CongestionConfig::default();
        let controller = CongestionController::new(config);

        assert_eq!(controller.total_queue_depth(), 0);
        assert!(!controller.is_congestion_limited());
        assert!(controller.congestion_window() > 0.0);
    }

    #[test]
    fn test_datagram_enqueuing() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
        controller.enqueue_datagram(frame, metadata).unwrap();

        assert_eq!(controller.total_queue_depth(), 1);
        assert_eq!(controller.queue_depth(DatagramPriority::Normal), 1);
    }

    #[test]
    fn test_priority_ordering() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        // Enqueue low priority first, then high priority
        let (frame1, metadata1) = create_test_datagram(DatagramPriority::Low);
        let (frame2, metadata2) = create_test_datagram(DatagramPriority::High);

        controller.enqueue_datagram(frame1, metadata1).unwrap();
        controller.enqueue_datagram(frame2, metadata2).unwrap();

        // High priority should come out first
        let (_frame, metadata) = controller.try_send_next().unwrap().unwrap();
        assert_eq!(metadata.priority, DatagramPriority::High);
    }

    #[test]
    fn test_congestion_feedback() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        let initial_window = controller.congestion_window();

        // Report loss - should reduce congestion window
        controller.update_congestion_feedback(Some(Duration::from_millis(50)), true);

        assert!(controller.congestion_window() < initial_window);
        assert!(controller.get_stats().congestion_events > 0);
    }

    #[test]
    fn test_token_bucket_algorithm() {
        let mut config = CongestionConfig::default();
        config.algorithm = CongestionAlgorithm::TokenBucket;
        config.max_rate_per_sec = 10;
        config.max_burst_size = 5;

        let mut controller = CongestionController::new(config);

        // Should have initial tokens
        assert!(controller.available_tokens() > 0.0);

        // Send until tokens are exhausted
        for _ in 0..10 {
            let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
            controller.enqueue_datagram(frame, metadata).unwrap();
        }

        // Send a few datagrams
        let mut sent_count = 0;
        while controller.try_send_next().unwrap().is_some() {
            sent_count += 1;
            if sent_count > 10 {
                break; // Prevent infinite loop
            }
        }

        // Should eventually run out of tokens
        assert!(controller.available_tokens() < 1.0);
    }

    #[test]
    fn token_bucket_raw_budget_consumes_without_queue_frames() {
        let mut controller = CongestionController::new(CongestionConfig::default());
        controller.configure_token_bucket(10, 2, Duration::ZERO);
        let now = Instant::now();

        assert!(controller.try_consume_send_budget(now));
        assert!(controller.try_consume_send_budget(now));
        assert!(!controller.try_consume_send_budget(now));
        assert!(controller.time_until_send_budget(now) > Duration::ZERO);
        assert_eq!(controller.total_queue_depth(), 0);
        assert_eq!(controller.get_stats().sent_count, 2);
    }

    #[test]
    fn token_bucket_banks_bounded_schedule_credit_past_burst() {
        let mut controller = CongestionController::new(CongestionConfig::default());
        controller.configure_token_bucket(10, 2, Duration::ZERO);
        let t0 = Instant::now();
        // Drain the nominal burst.
        assert!(controller.try_consume_send_budget(t0));
        assert!(controller.try_consume_send_budget(t0));
        assert!(!controller.try_consume_send_budget(t0));

        // A long stall banks up to 2x burst of schedule credit — the
        // timer-overshoot catch-up that keeps the realized spray rate at the
        // configured rate (MATRIX-208) — and no more.
        let t1 = t0 + Duration::from_secs(10);
        assert!(controller.try_consume_send_budget(t1));
        assert!(controller.try_consume_send_budget(t1));
        assert!(controller.try_consume_send_budget(t1));
        assert!(controller.try_consume_send_budget(t1));
        assert!(
            !controller.try_consume_send_budget(t1),
            "schedule credit must stay bounded at 2x max_burst_size"
        );
    }

    #[test]
    fn configure_for_path_rate_bounds_burst_and_paces_to_datagram_rate() {
        let mut controller = CongestionController::new(CongestionConfig::default());
        // 96 kbit/s over 1200-byte datagrams = 9600 bit/datagram => 10 datagrams/sec.
        controller.configure_for_path_rate(96_000, 1200, 4);
        let now = Instant::now();

        // A single spray burst is bounded by max_burst_datagrams (the qdisc guard).
        let mut burst = 0u32;
        while controller.try_consume_send_budget(now) {
            burst += 1;
            assert!(burst <= 4, "burst {burst} exceeded the configured bound");
        }
        assert_eq!(
            burst, 4,
            "burst should drain exactly the bounded token count"
        );

        // Drained: the pacer now gates, and the hint is ~1/rate (100 ms at 10 dps).
        assert!(!controller.try_consume_send_budget(now));
        let wait = controller.time_until_send_budget(now);
        assert!(wait > Duration::ZERO);
        assert!(
            wait <= Duration::from_millis(150),
            "wait {wait:?} too long for 10 dps"
        );
    }

    #[test]
    fn configure_for_path_rate_faster_link_refills_sooner() {
        let now = Instant::now();
        let mut slow = CongestionController::new(CongestionConfig::default());
        slow.configure_for_path_rate(96_000, 1200, 1); // 10 datagrams/sec
        let mut fast = CongestionController::new(CongestionConfig::default());
        fast.configure_for_path_rate(9_600_000, 1200, 1); // 1000 datagrams/sec

        // Drain the single-token burst on each, then compare refill latency.
        assert!(slow.try_consume_send_budget(now));
        assert!(fast.try_consume_send_budget(now));
        assert!(fast.time_until_send_budget(now) < slow.time_until_send_budget(now));
    }

    #[test]
    fn configure_for_path_rate_clamps_degenerate_rate_to_one_dps() {
        let mut controller = CongestionController::new(CongestionConfig::default());
        // A zero / garbage path estimate must not wedge the pacer at a zero rate.
        controller.configure_for_path_rate(0, 1200, 8);
        let now = Instant::now();

        for _ in 0..8 {
            controller.try_consume_send_budget(now);
        }
        assert!(!controller.try_consume_send_budget(now));
        let wait = controller.time_until_send_budget(now);
        assert!(wait > Duration::ZERO);
        assert!(
            wait <= Duration::from_millis(1100),
            "rate clamp should yield ~1 dps, got {wait:?}"
        );
    }

    #[test]
    fn test_queue_depth_limiting() {
        let mut config = CongestionConfig::default();
        config.max_queue_depth = 3;

        let mut controller = CongestionController::new(config);

        // Fill queue to limit
        for _ in 0..3 {
            let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
            controller.enqueue_datagram(frame, metadata).unwrap();
        }

        // Next enqueue should fail or drop something
        let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
        let result = controller.enqueue_datagram(frame, metadata);

        // Either the enqueue fails or queue depth remains at limit
        if result.is_ok() {
            assert_eq!(controller.total_queue_depth(), 3);
        } else {
            assert!(matches!(
                result,
                Outcome::Err(DatagramError::CongestionDrop)
            ));
        }
    }

    #[test]
    fn test_expired_datagram_cleanup() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        // Create expired datagram
        let frame = DatagramFrame::with_length(Bytes::from_static(b"test"));
        let metadata = DatagramMetadata::new("test")
            .with_priority(DatagramPriority::Normal)
            .with_expiration(
                Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .expect("test instant should support one-second subtraction"),
            ); // Already expired

        controller.enqueue_datagram(frame, metadata).unwrap();
        assert_eq!(controller.total_queue_depth(), 1);

        // Try to send - should clean up expired datagram
        let result = controller.try_send_next().unwrap();
        assert!(result.is_none());
        assert_eq!(controller.total_queue_depth(), 0);
        assert!(controller.get_stats().expired_count > 0);
    }

    #[test]
    fn test_congestion_stats() {
        let config = CongestionConfig::default();
        let mut controller = CongestionController::new(config);

        let (frame, metadata) = create_test_datagram(DatagramPriority::Normal);
        controller.enqueue_datagram(frame, metadata).unwrap();
        controller.try_send_next().unwrap();

        let stats = controller.get_stats();
        assert_eq!(stats.enqueued_count, 1);
        assert_eq!(stats.sent_count, 1);
        assert!(stats.is_performing_well());
    }

    #[test]
    fn test_algorithm_types() {
        for algorithm in [
            CongestionAlgorithm::RateLimited,
            CongestionAlgorithm::Aimd,
            CongestionAlgorithm::TokenBucket,
            CongestionAlgorithm::Adaptive,
        ] {
            let mut config = CongestionConfig::default();
            config.algorithm = algorithm;

            let controller = CongestionController::new(config);
            assert!(controller.congestion_window() > 0.0);
        }
    }
