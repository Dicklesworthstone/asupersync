    use super::*;

    #[test]
    fn omitted_connection_ceiling_preserves_shared_pool_admission() {
        assert_eq!(
            NativeH3ListenerConfig::default().max_buffered_response_bytes_per_connection,
            None
        );
        let aggregate = Arc::new(ResponseBudget::new(8));
        let peer = aggregate.for_connection(None);
        assert!(Arc::ptr_eq(&peer, &aggregate));
        let retained = peer.try_retain(Bytes::from(vec![1; 8]), 8).unwrap();
        assert_eq!(aggregate.used.load(Ordering::Acquire), 8);
        assert!(peer.try_retain(Bytes::from(vec![2; 1]), 1).is_none());
        assert_eq!(aggregate.rejected.load(Ordering::Acquire), 1);
        assert_eq!(aggregate.connection_rejected.load(Ordering::Acquire), 0);
        drop(retained);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn a_full_peer_budget_leaves_shared_capacity_for_another_connection() {
        let aggregate = Arc::new(ResponseBudget::new(8));
        let slow = aggregate.for_connection(Some(4));
        let survivor = aggregate.for_connection(Some(4));
        let held = slow.try_retain(Bytes::from(vec![1; 4]), 4).unwrap();
        assert!(slow.try_retain(Bytes::from(vec![2; 1]), 1).is_none());
        let served = survivor.try_retain(Bytes::from(vec![3; 4]), 4).unwrap();
        assert_eq!(slow.used.load(Ordering::Acquire), 4);
        assert_eq!(survivor.used.load(Ordering::Acquire), 4);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 8);
        assert_eq!(aggregate.peak.load(Ordering::Acquire), 8);
        assert_eq!(aggregate.rejected.load(Ordering::Acquire), 1);
        assert_eq!(aggregate.connection_rejected.load(Ordering::Acquire), 1);
        drop(held);
        assert_eq!(slow.used.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 4);
        drop(served);
        assert_eq!(survivor.used.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn global_refusal_rolls_back_the_connection_reservation() {
        let aggregate = Arc::new(ResponseBudget::new(5));
        let first = aggregate.for_connection(Some(4));
        let second = aggregate.for_connection(Some(4));
        let held = first.try_retain(Bytes::from(vec![1; 4]), 4).unwrap();
        assert!(second.try_retain(Bytes::from(vec![2; 3]), 3).is_none());
        assert_eq!(second.used.load(Ordering::Acquire), 0);
        assert_eq!(second.peak.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 4);
        assert_eq!(aggregate.rejected.load(Ordering::Acquire), 1);
        assert_eq!(aggregate.connection_rejected.load(Ordering::Acquire), 0);
        let retry = second.try_retain(Bytes::from(vec![3; 1]), 1).unwrap();
        assert_eq!(aggregate.used.load(Ordering::Acquire), 5);
        drop((held, retry));
        assert_eq!(aggregate.used.load(Ordering::Acquire), 0);
        assert_eq!(first.used.load(Ordering::Acquire), 0);
        assert_eq!(second.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn connection_ceiling_charges_backing_capacity_not_the_body_slice() {
        let aggregate = Arc::new(ResponseBudget::new(512));
        let peer = aggregate.for_connection(Some(128));
        let mut allocation = Vec::with_capacity(256);
        allocation.extend_from_slice(b"one retained allocation");
        let view = Bytes::from(allocation).slice(0..1);
        assert_eq!(view.len(), 1);
        assert_eq!(view.retained_capacity(), 256);
        assert!(peer.try_retain(view, 1).is_none());
        assert_eq!(peer.used.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.peak.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.connection_rejected.load(Ordering::Acquire), 1);
    }

    #[test]
    fn dropped_connection_publication_refunds_both_budgets() {
        let aggregate = Arc::new(ResponseBudget::new(8));
        let peer = aggregate.for_connection(Some(4));
        let retained = peer.try_retain(Bytes::from(vec![7; 4]), 4).unwrap();
        let (publication, receiver) = oneshot::channel();
        assert!(
            publication
                .send_blocking(RequestReply::Buffered {
                    head: H3ResponseHead::new(200, Vec::new()).unwrap(),
                    body: retained,
                })
                .is_ok()
        );
        assert_eq!(peer.used.load(Ordering::Acquire), 4);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 4);
        drop(receiver);
        assert_eq!(peer.used.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 0);
        // The same connection can immediately admit another full response.
        let replacement = peer.try_retain(Bytes::from(vec![8; 4]), 4).unwrap();
        drop(peer);
        // The retained body keeps its peer and parent accounting alive.
        assert_eq!(aggregate.used.load(Ordering::Acquire), 4);
        drop(replacement);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 0);
        assert_eq!(Arc::strong_count(&aggregate), 1);
    }

    #[test]
    fn individual_size_refusal_does_not_spend_connection_or_global_credit() {
        let aggregate = Arc::new(ResponseBudget::new(8));
        let peer = aggregate.for_connection(Some(4));
        assert!(peer.try_retain(Bytes::from(vec![1; 4]), 3).is_none());
        assert_eq!(peer.used.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.rejected.load(Ordering::Acquire), 1);
        assert_eq!(aggregate.connection_rejected.load(Ordering::Acquire), 0);
    }

    #[test]
    fn zero_connection_ceiling_distinguishes_empty_body_from_empty_backing_slice() {
        let aggregate = Arc::new(ResponseBudget::new(8));
        let peer = aggregate.for_connection(Some(0));
        let empty = peer.try_retain(Bytes::new(), 0).unwrap();
        drop(empty);
        let backed_empty = Bytes::from(vec![1; 4]).slice(0..0);
        assert!(peer.try_retain(backed_empty, 0).is_none());
        assert!(peer.try_retain(Bytes::from(vec![2; 1]), 1).is_none());
        assert_eq!(peer.used.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.used.load(Ordering::Acquire), 0);
        assert_eq!(aggregate.rejected.load(Ordering::Acquire), 2);
        assert_eq!(aggregate.connection_rejected.load(Ordering::Acquire), 2);
    }

    #[test]
    fn concurrent_peer_reservations_cannot_exceed_the_global_ceiling() {
        contended_budgets(false);
    }

    #[test]
    fn concurrent_requests_cannot_exceed_their_connection_ceiling() {
        contended_budgets(true);
    }

    fn contended_budgets(one_peer: bool) {
        const REQUESTS: usize = 8;
        let aggregate = Arc::new(ResponseBudget::new(if one_peer { 64 } else { 12 }));
        let shared = aggregate.for_connection(Some(6));
        let ready = std::sync::Barrier::new(REQUESTS + 1);
        let release = std::sync::Barrier::new(REQUESTS + 1);
        std::thread::scope(|scope| {
            let mut joins = Vec::new();
            for _ in 0..REQUESTS {
                let peer = if one_peer {
                    Arc::clone(&shared)
                } else {
                    aggregate.for_connection(Some(6))
                };
                let ready = &ready;
                let release = &release;
                joins.push(scope.spawn(move || {
                    let retained = peer.try_retain(Bytes::from(vec![1; 4]), 4);
                    ready.wait();
                    release.wait();
                    retained.is_some()
                }));
            }
            ready.wait();
            // Capture the charged state while every accepted body is held.
            // Release all workers before asserting so a regression cannot
            // strand a barrier waiter during unwinding.
            let used = aggregate.used.load(Ordering::Acquire);
            let peer_used = shared.used.load(Ordering::Acquire);
            release.wait();
            let admitted = joins
                .into_iter()
                .map(|join| usize::from(join.join().unwrap()))
                .sum::<usize>();
            let expected = if one_peer { 1 } else { 3 };
            assert_eq!(admitted, expected);
            assert_eq!(used, expected * 4);
            assert_eq!(peer_used, if one_peer { 4 } else { 0 });
            assert_eq!(aggregate.peak.load(Ordering::Acquire), expected * 4);
            assert_eq!(aggregate.used.load(Ordering::Acquire), 0);
            assert_eq!(shared.used.load(Ordering::Acquire), 0);
            assert_eq!(
                aggregate.rejected.load(Ordering::Acquire),
                u64::try_from(REQUESTS - expected).unwrap()
            );
            assert_eq!(
                aggregate.connection_rejected.load(Ordering::Acquire),
                if one_peer { 7 } else { 0 }
            );
        });
    }

    #[test]
    fn prepared_response_keeps_backing_credit_until_publication_is_dropped() {
        let budget = Arc::new(ResponseBudget::new(256));
        let mut allocation = Vec::with_capacity(256);
        allocation.extend_from_slice(b"retained backing");
        let view = Bytes::from(allocation).slice(0..1);
        let body = budget.try_retain(view, 1).expect("full backing fits");
        let (publication, receiver) = oneshot::channel();
        assert!(
            publication
                .send_blocking(RequestReply::Buffered {
                    head: H3ResponseHead::new(200, Vec::new()).unwrap(),
                    body,
                })
                .is_ok()
        );
        assert_eq!(budget.used.load(Ordering::Acquire), 256);
        assert!(budget.try_retain(Bytes::from_static(b"x"), 1).is_none());
        drop(receiver);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
        let replacement = budget.try_retain(Bytes::from(vec![0; 256]), 256).unwrap();
        assert_eq!(budget.used.load(Ordering::Acquire), 256);
        drop(replacement);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
        assert_eq!(budget.peak.load(Ordering::Acquire), 256);
        assert_eq!(budget.rejected.load(Ordering::Acquire), 1);
    }

    #[test]
    fn buffered_response_zero_limit_and_individual_limit_fail_before_publication() {
        let disabled = Arc::new(ResponseBudget::new(0));
        assert!(disabled.try_retain(Bytes::from_static(b"x"), 1).is_none());
        let empty = disabled.try_retain(Bytes::new(), 0).unwrap();
        assert_eq!(disabled.used.load(Ordering::Acquire), 0);
        drop(empty);

        let budget = Arc::new(ResponseBudget::new(256));
        assert!(
            budget
                .try_retain(Bytes::from_static(b"too long"), 1)
                .is_none()
        );
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
        assert_eq!(budget.peak.load(Ordering::Acquire), 0);
        assert_eq!(budget.rejected.load(Ordering::Acquire), 1);
    }
