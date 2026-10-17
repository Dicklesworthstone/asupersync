    use super::*;

    #[test]
    fn request_reservation_defaults_preserve_unbounded_shared_admission() {
        let config = NativeH3ListenerConfig::default();
        assert_eq!(config.max_total_request_body_reservation_bytes, None);
        let state = ListenerState::new(Arc::new(Router::new()), config, 3);
        assert!(state.request_body_budget.is_none());
        let mut reservations = RequestBodyReservations::new(None);
        assert!(reservations.admit(StreamId(0), usize::MAX));
        assert!(reservations.admit(StreamId(4), usize::MAX));
        assert!(reservations.held.is_empty());
    }

    #[test]
    fn buffered_reservation_uses_the_smaller_existing_body_ceiling() {
        let mut config = NativeH3ListenerConfig::default();
        assert_eq!(config.request_body_reservation_bytes(), Some(16 * 1024 * 1024));
        config.router = config
            .router
            .max_buffered_body_bytes(100)
            .max_total_buffered_body_bytes(60);
        assert_eq!(config.request_body_reservation_bytes(), Some(60));
        config.router = config.router.max_buffered_body_bytes(25);
        assert_eq!(config.request_body_reservation_bytes(), Some(25));
        config.router = config.router.max_buffered_body_bytes(0);
        assert_eq!(config.request_body_reservation_bytes(), Some(0));
    }

    #[test]
    fn streaming_reservation_covers_queue_and_pending_chunk_without_overflow() {
        let mut config = NativeH3ListenerConfig::default();
        config.streaming_request_body_buffer_bytes = NonZeroUsize::new(64);
        assert_eq!(config.request_body_reservation_bytes(), Some(128));
        config.streaming_request_body_buffer_bytes = NonZeroUsize::new(32 * 1024);
        assert_eq!(config.request_body_reservation_bytes(), Some(48 * 1024));
        config.streaming_request_body_buffer_bytes = NonZeroUsize::new(usize::MAX);
        assert_eq!(config.request_body_reservation_bytes(), None);
    }

    #[test]
    fn peer_stream_id_reuse_does_not_alias_shared_request_credit() {
        let budget = Arc::new(RequestBodyBudget::new(12));
        let mut first = RequestBodyReservations::new(Some(Arc::clone(&budget)));
        let mut second = RequestBodyReservations::new(Some(Arc::clone(&budget)));
        assert!(first.admit(StreamId(0), 8));
        assert!(!second.admit(StreamId(0), 8));
        assert_eq!(budget.used.load(Ordering::Acquire), 8);
        assert_eq!(budget.peak.load(Ordering::Acquire), 8);
        assert_eq!(budget.rejected.load(Ordering::Acquire), 1);
        assert!(second.held.is_empty());
        first.retain(|_| false);
        assert!(second.admit(StreamId(0), 8));
        assert_eq!(budget.used.load(Ordering::Acquire), 8);
        drop(first);
        assert_eq!(budget.used.load(Ordering::Acquire), 8);
        drop(second);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn observing_one_request_again_does_not_recharge_it() {
        let budget = Arc::new(RequestBodyBudget::new(8));
        let mut peer = RequestBodyReservations::new(Some(Arc::clone(&budget)));
        for _ in 0..64 {
            assert!(peer.admit(StreamId(4), 8));
        }
        assert_eq!(peer.held.len(), 1);
        assert_eq!(budget.used.load(Ordering::Acquire), 8);
        assert_eq!(budget.rejected.load(Ordering::Acquire), 0);
        assert!(!peer.admit(StreamId(0), 1));
        drop(peer);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn request_credit_survives_assembly_to_owned_cleanup_transition() {
        let budget = Arc::new(RequestBodyBudget::new(12));
        let mut peer = RequestBodyReservations::new(Some(Arc::clone(&budget)));
        let mut assembly = BTreeSet::from([StreamId(0), StreamId(4), StreamId(8)]);
        let mut owned = BTreeSet::new();
        for id in &assembly {
            assert!(peer.admit(*id, 4));
        }
        // FIN transfers one request to ownership without returning its credit.
        assembly.remove(&StreamId(0));
        owned.insert(StreamId(0));
        // Another request is refused during assembly, with no admitted owner.
        assembly.remove(&StreamId(4));
        peer.retain(|id| assembly.contains(id) || owned.contains(id));
        assert_eq!(budget.used.load(Ordering::Acquire), 8);
        assert!(peer.held.contains_key(&StreamId(0)));
        assert!(!peer.held.contains_key(&StreamId(4)));
        // The same predicate stays true while the owner is draining/finalizing.
        peer.retain(|id| assembly.contains(id) || owned.contains(id));
        assert_eq!(budget.used.load(Ordering::Acquire), 8);
        owned.remove(&StreamId(0));
        peer.retain(|id| assembly.contains(id) || owned.contains(id));
        assert_eq!(budget.used.load(Ordering::Acquire), 4);
        drop(peer);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn zero_and_maximum_request_budgets_fail_closed_without_partial_credit() {
        let zero = Arc::new(RequestBodyBudget::new(0));
        let empty = zero.try_reserve(0).unwrap();
        assert!(zero.try_reserve(1).is_none());
        drop(empty);
        assert_eq!(zero.used.load(Ordering::Acquire), 0);
        let max = Arc::new(RequestBodyBudget::new(usize::MAX));
        let held = max.try_reserve(usize::MAX).unwrap();
        assert!(max.try_reserve(1).is_none());
        assert_eq!(max.used.load(Ordering::Acquire), usize::MAX);
        assert_eq!(max.peak.load(Ordering::Acquire), usize::MAX);
        drop(held);
        assert_eq!(max.used.load(Ordering::Acquire), 0);
        assert!(max.try_reserve(1).is_some());
    }

    #[test]
    fn dropping_request_ledger_during_unwind_refunds_every_reservation() {
        let budget = Arc::new(RequestBodyBudget::new(12));
        let result = std::panic::catch_unwind({
            let budget = Arc::clone(&budget);
            move || {
                let mut peer = RequestBodyReservations::new(Some(budget));
                assert!(peer.admit(StreamId(0), 4));
                assert!(peer.admit(StreamId(4), 8));
                panic!("intentional request owner unwind");
            }
        });
        assert!(result.is_err());
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
        assert_eq!(budget.peak.load(Ordering::Acquire), 12);
        assert_eq!(Arc::strong_count(&budget), 1);
    }
