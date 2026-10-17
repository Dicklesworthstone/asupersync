    use super::*;

    #[test]
    fn progress_is_monotonic_and_capped() {
        let mut p = TransferProgress::new(1000, 3);
        p.record_bytes(400);
        assert_eq!(p.bytes_done(), 400);
        p.record_bytes(400);
        assert_eq!(p.bytes_done(), 800);
        // Over-recording saturates at the total (never exceeds, never wraps).
        p.record_bytes(9999);
        assert_eq!(p.bytes_done(), 1000);
        assert!(p.is_complete());

        p.record_file();
        p.record_file();
        p.record_file();
        p.record_file(); // beyond total_files -> capped
        assert_eq!(p.files_done(), 3);
    }

    #[test]
    fn snapshot_fraction_rate_and_eta() {
        let mut p = TransferProgress::new(1000, 4);
        p.record_bytes(250);
        let s = p.snapshot(Duration::from_secs(1));
        assert!((s.fraction - 0.25).abs() < 1e-9);
        assert!((s.rate_bytes_per_sec - 250.0).abs() < 1e-9);
        // 750 bytes left at 250 B/s -> ~3s ETA.
        let eta = s.eta.expect("eta while in flight");
        assert!((eta.as_secs_f64() - 3.0).abs() < 1e-6);
    }

    #[test]
    fn snapshot_no_eta_when_done_or_no_time() {
        let mut p = TransferProgress::new(100, 1);
        // No elapsed time yet -> no rate, no ETA.
        assert!(p.snapshot(Duration::ZERO).eta.is_none());
        // Complete -> no ETA.
        p.record_bytes(100);
        let s = p.snapshot(Duration::from_secs(2));
        assert!(s.eta.is_none());
        assert!((s.fraction - 1.0).abs() < 1e-9);
    }

    #[test]
    fn empty_transfer_is_fully_complete() {
        let p = TransferProgress::new(0, 0);
        let s = p.snapshot(Duration::from_secs(1));
        assert!((s.fraction - 1.0).abs() < 1e-9);
        assert!(s.eta.is_none());
        assert!(p.is_complete());
    }

    #[test]
    fn plan_error_maps_from_streaming() {
        let e: PlanError = StreamingError::new("boom").into();
        assert!(matches!(e, PlanError::Source(m) if m.contains("boom")));
    }
