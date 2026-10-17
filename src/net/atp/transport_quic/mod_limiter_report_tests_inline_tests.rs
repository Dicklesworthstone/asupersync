    use super::*;

    #[test]
    fn window_request_needs_a_clean_warmup_and_then_asks_once_per_window() {
        let window = 1_000;
        let warmup = window * SOURCE_STREAM_WINDOW_PROBE_WARMUP_WINDOWS;
        let mut probe = None;

        // Nothing is asked during the warmup, however clean the path is.
        assert!(!source_stream_window_request_due(
            &mut probe, 1_000, window, 0
        ));
        assert!(!source_stream_window_request_due(
            &mut probe,
            1_000 + warmup - 1,
            window,
            0
        ));
        // The warmup completes on a still-clean path: ask.
        assert!(source_stream_window_request_due(
            &mut probe,
            1_000 + warmup,
            window,
            0
        ));
        // Less than a window further on: no second ask.
        assert!(!source_stream_window_request_due(
            &mut probe,
            1_000 + warmup + window - 1,
            window,
            0
        ));
        // A full window further on: ask again.
        assert!(source_stream_window_request_due(
            &mut probe,
            1_000 + warmup + window,
            window,
            0
        ));
        // One repair episode disqualifies the transfer permanently, even
        // though windows keep going by cleanly afterwards.
        assert!(!source_stream_window_request_due(
            &mut probe,
            1_000 + warmup + 4 * window,
            window,
            1
        ));
        assert!(!source_stream_window_request_due(
            &mut probe,
            1_000 + warmup + 8 * window,
            window,
            1
        ));

        // A path that is already repairing when the gate first runs never
        // asks. The batch counter only ever grows, so no later call can
        // un-disqualify it however far the limit advances.
        let mut lossy = None;
        assert!(!source_stream_window_request_due(
            &mut lossy, 5_000, window, 3
        ));
        assert!(!source_stream_window_request_due(
            &mut lossy,
            5_000 + warmup,
            window,
            3
        ));
        assert!(!source_stream_window_request_due(
            &mut lossy,
            5_000 + warmup + 4 * window,
            window,
            9
        ));

        // A zero window degrades to one ask per byte of progress after the
        // warmup, and never panics.
        let mut zero = None;
        assert!(!source_stream_window_request_due(&mut zero, 5, 0, 0));
        assert!(source_stream_window_request_due(&mut zero, 13, 0, 0));
    }

    #[test]
    fn source_stream_samples_track_the_min_cap_and_peak_unacked() {
        let mut report = QuicSendLimiterReport::default();
        assert_eq!(report.min_unacked_admission_cap_bytes, None);
        assert_eq!(report.peak_stream_send_window_bytes, None);
        report.observe_source_stream(4_000, 10, 90, 500);
        report.observe_source_stream(2_000, 30, 20, 800);
        report.observe_source_stream(3_000, 20, 40, 0);
        assert_eq!(report.min_unacked_admission_cap_bytes, Some(2_000));
        assert_eq!(report.peak_stream_unacked_bytes, 30);
        assert_eq!(
            report.peak_stream_send_window_bytes,
            Some(100),
            "credit remaining plus unacked bytes, at its peak"
        );
        assert_eq!(report.path_bottleneck_bytes_per_s, 800);
    }

    #[test]
    fn stall_accounting_counts_every_reason_and_names_the_longest() {
        let mut report = QuicSendLimiterReport::default();
        assert_eq!(report.dominant_stall(), None);
        assert_eq!(report.total_stall_micros(), 0);

        let held = [
            (QuicSendStallReason::Pacing, 1_000),
            (QuicSendStallReason::Cwnd, 5_000),
            (QuicSendStallReason::StreamCredit, 300),
            (QuicSendStallReason::UnackedGuard, 7_000),
            (QuicSendStallReason::SendQueue, 20),
            (QuicSendStallReason::ReceiverWindow, 4),
            (QuicSendStallReason::Other, 1),
        ];
        for (reason, micros) in held {
            report.note_stall(reason, Duration::from_micros(micros));
            report.note_stall(reason, Duration::from_micros(micros));
        }

        for (reason, micros) in held {
            let stall = report.stall(reason);
            assert_eq!(stall.count, 2, "{}", reason.name());
            assert_eq!(stall.micros, micros * 2, "{}", reason.name());
        }
        let expected_total: u64 = held.iter().map(|(_, micros)| micros * 2).sum();
        assert_eq!(report.total_stall_micros(), expected_total);
        let (dominant, stall) = report.dominant_stall().expect("something stalled");
        assert_eq!(dominant, QuicSendStallReason::UnackedGuard);
        assert_eq!(stall.micros, 14_000);
        assert_eq!(dominant.name(), "unacked_guard");
        assert_eq!(
            report.stalls().map(|(reason, _)| reason),
            QuicSendStallReason::ALL
        );
    }

    #[test]
    fn dominant_stall_ties_resolve_to_report_order_and_ignore_counts() {
        let mut report = QuicSendLimiterReport::default();
        report.note_stall(QuicSendStallReason::Cwnd, Duration::from_micros(10));
        report.note_stall(QuicSendStallReason::Pacing, Duration::from_micros(10));
        // Many short pacing waits still lose to one long cwnd wait.
        for _ in 0..50 {
            report.note_stall(QuicSendStallReason::SendQueue, Duration::from_nanos(10));
        }
        let (dominant, _) = report.dominant_stall().expect("stalled");
        assert_eq!(dominant, QuicSendStallReason::Pacing);
        assert_eq!(report.send_queue.count, 50);
        assert_eq!(report.send_queue.micros, 0);
    }

    #[test]
    fn stall_micros_saturate_instead_of_wrapping() {
        let mut report = QuicSendLimiterReport::default();
        report.note_stall(QuicSendStallReason::Cwnd, Duration::MAX);
        report.note_stall(QuicSendStallReason::Cwnd, Duration::MAX);
        assert_eq!(report.cwnd.micros, u64::MAX);
        assert_eq!(report.total_stall_micros(), u64::MAX);
    }

    #[test]
    fn slice_accounting_never_exceeds_the_loop_wall_time() {
        let mut slices = QuicStallSliceAccounting::default();
        let mut attributed = Duration::ZERO;
        // Deterministic pseudo-random monotone clock with one backwards step.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut clock = Duration::ZERO;
        let mut previous_clock = Duration::ZERO;
        for step in 0..1_000u32 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let advance = Duration::from_micros(state % 5_000);
            clock += advance;
            let observed = if step == 500 {
                // A reading BELOW the last accounted point (a non-monotone
                // clock) must yield an empty slice, never a negative or a
                // double-counted one; the skipped advance is attributed by
                // the next monotone reading.
                previous_clock
                    .checked_sub(Duration::from_millis(3))
                    .unwrap_or(Duration::ZERO)
            } else {
                clock
            };
            let slice = slices.take_slice(observed);
            if step == 500 {
                assert_eq!(slice, Duration::ZERO, "a backwards clock yields no slice");
            }
            attributed += slice;
            assert!(
                attributed <= clock,
                "attributed {attributed:?} > wall {clock:?}"
            );
            previous_clock = clock;
        }
        assert_eq!(attributed, clock, "monotone slices sum to the wall time");
    }

    #[test]
    fn source_stream_admission_classifier_follows_gate_order() {
        assert_eq!(
            classify_source_stream_admission(true, false, false),
            Some(QuicSendStallReason::SendQueue)
        );
        assert_eq!(
            classify_source_stream_admission(false, false, false),
            Some(QuicSendStallReason::StreamCredit)
        );
        assert_eq!(
            classify_source_stream_admission(false, true, false),
            Some(QuicSendStallReason::UnackedGuard)
        );
        assert_eq!(classify_source_stream_admission(false, true, true), None);
    }

    #[test]
    fn blocked_flush_classifier_prefers_cwnd_then_stream_credit() {
        assert_eq!(
            classify_blocked_flush(false, Some(0)),
            QuicSendStallReason::Cwnd
        );
        assert_eq!(
            classify_blocked_flush(true, Some(0)),
            QuicSendStallReason::StreamCredit
        );
        assert_eq!(
            classify_blocked_flush(true, Some(1)),
            QuicSendStallReason::Other
        );
        assert_eq!(
            classify_blocked_flush(true, None),
            QuicSendStallReason::Other
        );
    }

    #[test]
    fn transport_samples_track_peaks_and_slow_start_exit() {
        let mut report = QuicSendLimiterReport::default();
        report.observe_transport(1_000, 12_000, u64::MAX);
        assert!(!report.slow_start_exited);
        assert_eq!(report.final_ssthresh_bytes, None);
        assert_eq!(report.min_congestion_window_bytes, Some(12_000));
        report.observe_transport(50_000, 64_000, u64::MAX);
        report.observe_transport(30_000, 32_000, 32_000);
        assert_eq!(report.transport_samples, 3);
        assert_eq!(report.peak_bytes_in_flight, 50_000);
        assert_eq!(report.peak_congestion_window_bytes, 64_000);
        assert_eq!(report.min_congestion_window_bytes, Some(12_000));
        assert_eq!(report.final_congestion_window_bytes, 32_000);
        assert_eq!(report.final_ssthresh_bytes, Some(32_000));
        assert!(report.slow_start_exited);
    }

    #[test]
    fn stall_reason_names_are_stable_and_distinct() {
        let names: std::collections::BTreeSet<&str> = QuicSendStallReason::ALL
            .iter()
            .map(|reason| reason.name())
            .collect();
        assert_eq!(names.len(), QuicSendStallReason::ALL.len());
        assert!(names.contains("cwnd"));
        assert!(names.contains("stream_credit"));
    }
