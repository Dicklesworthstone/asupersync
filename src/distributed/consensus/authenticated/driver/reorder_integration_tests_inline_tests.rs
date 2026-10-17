    use super::super::*;
    use crate::distributed::consensus::authenticated::PbftMembership;
    use crate::types::{CancelKind, Outcome};
    use nkeys::{KeyPair, KeyPairType};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    #[derive(Default)]
    struct Wire {
        blocked: AtomicBool,
        receives: AtomicUsize,
        sends: AtomicUsize,
    }

    impl PbftPacketTransport for Arc<Wire> {
        async fn send_packet(&self, _: &ReplicaId, packet: Vec<u8>) -> Result<()> {
            self.broadcast_packet(packet).await
        }
        async fn broadcast_packet(&self, _: Vec<u8>) -> Result<()> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            if self.blocked.load(Ordering::SeqCst) { std::future::pending::<()>().await; }
            Ok(())
        }
        async fn receive_packet(&self, _: usize) -> Result<Vec<u8>> {
            self.receives.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    fn auth(local: u8) -> Arc<PbftAuthenticator> {
        let key = |i: u8| {
            let seed: [u8; 32] = Sha256::digest([i; 32]).into();
            KeyPair::new_from_raw(KeyPairType::User, seed).unwrap()
        };
        let keys: Vec<_> = (0..4).map(|i| key(i).public_key()).collect();
        Arc::new(PbftAuthenticator::new(
            PbftMembership::new([9; 32], 1, &keys).unwrap(),
            ReplicaId::new(local.to_string()), key(local), 4096,
        ).unwrap())
    }

    fn request() -> ConsensusRequest {
        ConsensusRequest::new("reordered".into(), Time::from_millis(1), b"effect".to_vec())
    }

    fn packets() -> Vec<Vec<u8>> {
        let batch = ConsensusBatch::new(vec![request()]);
        let digest = MessageDigest::of(&batch).unwrap();
        let proposal = PbftMessage::PrePrepare {
            view: ViewNumber(0), sequence: SequenceNumber(1), digest: digest.clone(),
            batch, replica_id: ReplicaId::new("0".into()),
        };
        let mut packets = vec![auth(0).seal(None, &proposal).unwrap()];
        for commit in [false, true] {
            for author in [0, 2] {
                let message = if commit {
                    PbftMessage::Commit { view: ViewNumber(0), sequence: SequenceNumber(1), digest: digest.clone(), replica_id: ReplicaId::new(author.to_string()) }
                } else {
                    PbftMessage::Prepare { view: ViewNumber(0), sequence: SequenceNumber(1), digest: digest.clone(), replica_id: ReplicaId::new(author.to_string()) }
                };
                packets.push(auth(author).seal(None, &message).unwrap());
            }
        }
        packets
    }

    fn permutations(items: &mut [usize], offset: usize, output: &mut Vec<Vec<usize>>) {
        if offset == items.len() { output.push(items.to_vec()); return; }
        for i in offset..items.len() {
            items.swap(offset, i);
            permutations(items, offset + 1, output);
            items.swap(offset, i);
        }
    }

    #[test]
    fn every_signed_proposal_prepare_commit_order_executes_exactly_once() {
        let packets = packets();
        let mut orders = Vec::new();
        permutations(&mut [0, 1, 2, 3, 4], 0, &mut orders);
        assert_eq!(orders.len(), 120);
        let cx = Cx::for_testing();
        for order in orders {
            let applied = Arc::new(AtomicUsize::new(0));
            let count = Arc::clone(&applied);
            let wire = Arc::new(Wire::default());
            let mut node = AuthenticatedPbftNode::new_with_reordering(
                PbftConfig::new(4, 1).unwrap(), Arc::clone(&wire), auth(1),
                move |request: &ConsensusRequest| {
                    count.fetch_add(1, Ordering::SeqCst);
                    Outcome::Ok(request.operation.clone())
                },
            ).unwrap();
            for (position, index) in order.iter().enumerate() {
                assert_eq!(futures_lite::future::block_on(node.process_packet(&cx, &packets[*index])).unwrap(), PbftIngressOutcome::Processed);
                assert_eq!(applied.load(Ordering::SeqCst), usize::from(position == 4), "order {order:?}");
            }
            let response = node.committed_response(&request()).unwrap().unwrap();
            assert_eq!(response.sequence, SequenceNumber(1));
            assert_eq!(response.result, Outcome::Ok(b"effect".to_vec()));
            let sends = wire.sends.load(Ordering::SeqCst);
            for packet in &packets {
                assert_eq!(futures_lite::future::block_on(node.process_packet(&cx, packet)).unwrap(), PbftIngressOutcome::AlreadyApplied(SequenceNumber(1)));
            }
            assert_eq!(wire.sends.load(Ordering::SeqCst), sends);
            assert_eq!(node.reorder.as_ref().unwrap().lock().votes, 0);
        }
    }

    #[test]
    fn cancelled_proposal_send_preserves_early_votes_and_resumes_without_new_input() {
        let cx = Cx::for_testing();
        let wire = Arc::new(Wire::default());
        let mut node = AuthenticatedPbftNode::new_with_reordering(
            PbftConfig::new(4, 1).unwrap(), Arc::clone(&wire), auth(1),
            |request: &ConsensusRequest| Outcome::Ok(request.operation.clone()),
        ).unwrap();
        let packets = packets();
        for packet in &packets[1..] {
            futures_lite::future::block_on(node.process_packet(&cx, packet)).unwrap();
        }
        assert!(node.committed_response(&request()).unwrap().is_none());
        wire.blocked.store(true, Ordering::SeqCst);
        let mut proposal = Box::pin(node.process_packet(&cx, &packets[0]));
        let mut task = Context::from_waker(Waker::noop());
        assert!(proposal.as_mut().poll(&mut task).is_pending());
        assert_eq!(wire.sends.load(Ordering::SeqCst), 1);
        cx.cancel_fast(CancelKind::User);
        let Poll::Ready(Err(error)) = proposal.as_mut().poll(&mut task) else { panic!("cancelled proposal") };
        assert!(error.is_cancelled());
        drop(proposal);
        wire.blocked.store(false, Ordering::SeqCst);
        let fresh = Cx::for_testing();
        assert_eq!(futures_lite::future::block_on(node.receive_one(&fresh)).unwrap(), PbftIngressOutcome::Processed);
        assert_eq!(wire.receives.load(Ordering::SeqCst), 0);
        assert_eq!(node.committed_response(&request()).unwrap().unwrap().result, Outcome::Ok(b"effect".to_vec()));
    }
