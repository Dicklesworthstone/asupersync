    use super::*;
    use crate::distributed::consensus::authenticated::PbftMembership;
    use crate::types::{CancelKind, Outcome};
    use nkeys::{KeyPair, KeyPairType};
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    fn authority(local: usize, count: usize, limit: usize) -> Arc<PbftAuthenticator> {
        let key = |index: usize| {
            let seed: [u8; 32] = Sha256::digest(index.to_le_bytes()).into();
            KeyPair::new_from_raw(KeyPairType::User, seed).unwrap()
        };
        let keys: Vec<_> = (0..count).map(|i| key(i).public_key()).collect();
        Arc::new(PbftAuthenticator::new(
            PbftMembership::new([6; 32], 1, &keys).unwrap(),
            ReplicaId::new(local.to_string()), key(local), limit,
        ).unwrap())
    }

    fn request() -> ConsensusRequest {
        ConsensusRequest::new("caller".into(), Time::from_millis(7), b"payload".to_vec())
    }

    #[derive(Clone, Default)]
    struct Application(Arc<Mutex<Vec<Vec<u8>>>>);

    impl PbftStateMachine for Application {
        fn apply(&mut self, request: &ConsensusRequest) -> Outcome<Vec<u8>, String> {
            self.0.lock().unwrap().push(request.operation.clone());
            let mut result = b"applied:".to_vec();
            result.extend_from_slice(&request.operation);
            Outcome::Ok(result)
        }
    }

    #[derive(Default)]
    struct Network {
        queue: Mutex<VecDeque<(usize, Vec<u8>)>>,
        sent: AtomicUsize,
    }

    struct Endpoint {
        local: usize,
        network: Arc<Network>,
        silent: Option<usize>,
    }

    impl PbftPacketTransport for Endpoint {
        async fn send_packet(&self, recipient: &ReplicaId, packet: Vec<u8>) -> Result<()> {
            let recipient = recipient.as_str().parse::<usize>().unwrap();
            if self.silent != Some(recipient) {
                self.network.queue.lock().unwrap().push_back((recipient, packet));
            }
            self.network.sent.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn broadcast_packet(&self, packet: Vec<u8>) -> Result<()> {
            for recipient in 0..4 {
                if recipient != self.local && self.silent != Some(recipient) {
                    self.network.queue.lock().unwrap().push_back((recipient, packet.clone()));
                }
            }
            self.network.sent.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn receive_packet(&self, limit: usize) -> Result<Vec<u8>> {
            let mut queue = self.network.queue.lock().unwrap();
            let index = queue.iter().position(|(id, _)| *id == self.local)
                .ok_or_else(|| Error::new(ErrorKind::ChannelEmpty))?;
            let (_, packet) = queue.remove(index).unwrap();
            if packet.len() > limit {
                return Err(protocol_error(PbftAuthError::PayloadTooLarge));
            }
            Ok(packet)
        }
    }

    #[test]
    fn signed_four_replica_journey_executes_actual_results_with_one_backup_silent() {
        for silent in [None, Some(3)] {
            let network = Arc::new(Network::default());
            let applications: Vec<_> = (0..4).map(|_| Application::default()).collect();
            let mut nodes: Vec<_> = (0..4).map(|local| {
                AuthenticatedPbftNode::new(
                    PbftConfig::new(4, 1).unwrap(),
                    Endpoint { local, network: Arc::clone(&network), silent },
                    authority(local, 4, 4096), applications[local].clone(),
                ).unwrap()
            }).collect();
            let cx = Cx::for_testing();
            let request = request();
            // Begin at a backup, exercising signed forwarding as well as the
            // primary's proposal, every prepare, and every commit.
            futures_lite::future::block_on(nodes[2].submit_request(&cx, request.clone())).unwrap();
            assert!(nodes[2].committed_response(&request).unwrap().is_none());
            let mut delivered = 0;
            let mut retained_proposal = None;
            loop {
                let next = network.queue.lock().unwrap().pop_front();
                let Some((recipient, packet)) = next else { break };
                if matches!(nodes[recipient].auth.open(&packet).unwrap(), PbftMessage::PrePrepare { .. }) {
                    retained_proposal.get_or_insert_with(|| packet.clone());
                }
                let outcome = futures_lite::future::block_on(nodes[recipient].process_packet(&cx, &packet)).unwrap();
                assert!(matches!(outcome, PbftIngressOutcome::Processed | PbftIngressOutcome::AlreadyApplied(_)));
                delivered += 1;
                assert!(delivered < 500, "message fanout must terminate");
            }
            for local in 0..4 {
                if silent == Some(local) { continue; }
                let response = nodes[local].committed_response(&request).unwrap().unwrap();
                assert_eq!(response.sequence, SequenceNumber::new(1));
                assert_eq!(response.result, Outcome::Ok(b"applied:payload".to_vec()));
                assert_eq!(applications[local].0.lock().unwrap().as_slice(), &[b"payload".to_vec()]);
                let sent = network.sent.load(Ordering::SeqCst);
                let replay = futures_lite::future::block_on(nodes[local].submit_and_wait(&cx, request.clone())).unwrap();
                assert_eq!(replay.result, response.result);
                assert_eq!(replay.sequence, response.sequence);
                assert_eq!(network.sent.load(Ordering::SeqCst), sent);
                if local != 0 {
                    let duplicate = retained_proposal.as_ref().unwrap();
                    let replay = futures_lite::future::block_on(nodes[local].process_packet(&cx, duplicate)).unwrap();
                    assert_eq!(replay, PbftIngressOutcome::AlreadyApplied(SequenceNumber::new(1)));
                    assert_eq!(applications[local].0.lock().unwrap().len(), 1);
                    assert_eq!(network.sent.load(Ordering::SeqCst), sent);
                }
            }
        }
    }

    #[derive(Default)]
    struct IoState {
        receives: AtomicUsize,
        sends: AtomicUsize,
        dropped: AtomicUsize,
        block_send: AtomicBool,
    }

    struct PendingIo(Arc<IoState>);

    impl Drop for PendingIo {
        fn drop(&mut self) { self.0.dropped.fetch_add(1, Ordering::SeqCst); }
    }

    #[derive(Clone)]
    struct ParkedWire(Arc<IoState>);

    impl PbftPacketTransport for ParkedWire {
        fn send_packet(&self, _recipient: &ReplicaId, packet: Vec<u8>) -> impl Future<Output = Result<()>> + Send {
            self.broadcast_packet(packet)
        }
        fn broadcast_packet(&self, _packet: Vec<u8>) -> impl Future<Output = Result<()>> + Send {
            self.0.sends.fetch_add(1, Ordering::SeqCst);
            async {
                if self.0.block_send.load(Ordering::SeqCst) {
                    let _drop = PendingIo(Arc::clone(&self.0));
                    std::future::pending::<()>().await;
                }
                Ok(())
            }
        }
        fn receive_packet(&self, _limit: usize) -> impl Future<Output = Result<Vec<u8>>> + Send {
            // Deliberately effectful future CONSTRUCTION to prove that a
            // pre-cancelled public call never invokes the transport at all.
            self.0.receives.fetch_add(1, Ordering::SeqCst);
            async {
                let _drop = PendingIo(Arc::clone(&self.0));
                std::future::pending().await
            }
        }
    }

    fn node(count: usize, state: &Arc<IoState>, app: Application) -> AuthenticatedPbftNode<ParkedWire, Application> {
        AuthenticatedPbftNode::new(
            PbftConfig::new(count, (count - 1) / 3).unwrap(),
            ParkedWire(Arc::clone(state)), authority(0, count, 4096), app,
        ).unwrap()
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    #[test]
    fn parked_receive_is_woken_by_cancellation_and_its_future_is_dropped() {
        let cx = Cx::for_testing();
        let state = Arc::new(IoState::default());
        let mut node = node(4, &state, Application::default());
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut task = Context::from_waker(&waker);
        let mut receive = Box::pin(node.receive_one(&cx));
        assert!(receive.as_mut().poll(&mut task).is_pending());
        assert_eq!(state.receives.load(Ordering::SeqCst), 1);
        assert_eq!(state.dropped.load(Ordering::SeqCst), 0);
        cx.cancel_fast(CancelKind::User);
        assert!(wakes.0.load(Ordering::SeqCst) > 0, "must wake before a manual repoll");
        let Poll::Ready(Err(error)) = receive.as_mut().poll(&mut task) else { panic!("cancelled receive") };
        assert!(error.is_cancelled());
        assert_eq!(state.dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_a_pending_receive_retires_io_without_detached_work() {
        let cx = Cx::for_testing();
        let state = Arc::new(IoState::default());
        let mut node = node(4, &state, Application::default());
        let mut receive = Box::pin(node.receive_one(&cx));
        assert!(receive.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        drop(receive);
        assert_eq!(state.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(node.last_applied().unwrap(), SequenceNumber::new(0));
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn pre_cancelled_calls_never_construct_a_transport_future() {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let state = Arc::new(IoState::default());
        let mut node = node(1, &state, Application::default());
        assert!(futures_lite::future::block_on(node.receive_one(&cx)).unwrap_err().is_cancelled());
        assert!(futures_lite::future::block_on(node.submit_request(&cx, request())).unwrap_err().is_cancelled());
        assert_eq!(state.receives.load(Ordering::SeqCst), 0);
        assert_eq!(state.sends.load(Ordering::SeqCst), 0);
        assert_eq!(node.last_applied().unwrap(), SequenceNumber::new(0));
    }

    #[test]
    fn waiting_for_a_real_quorum_does_not_return_a_placeholder() {
        let cx = Cx::for_testing();
        let state = Arc::new(IoState::default());
        let app = Application::default();
        let mut node = node(4, &state, app.clone());
        let request = request();
        let mut submit = Box::pin(node.submit_and_wait(&cx, request.clone()));
        assert!(submit.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        assert_eq!(state.receives.load(Ordering::SeqCst), 1);
        assert!(app.0.lock().unwrap().is_empty());
        drop(submit);
        assert!(node.committed_response(&request).unwrap().is_none());
        assert_eq!(state.dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancelled_ambiguous_send_retries_its_original_sequence() {
        let cx = Cx::for_testing();
        let state = Arc::new(IoState::default());
        state.block_send.store(true, Ordering::SeqCst);
        let app = Application::default();
        let mut node = node(1, &state, app.clone());
        let request = request();
        let mut submit = Box::pin(node.submit_request(&cx, request.clone()));
        let mut task = Context::from_waker(Waker::noop());
        assert!(submit.as_mut().poll(&mut task).is_pending());
        assert_eq!(state.sends.load(Ordering::SeqCst), 1);
        cx.cancel_fast(CancelKind::User);
        let Poll::Ready(Err(error)) = submit.as_mut().poll(&mut task) else { panic!("cancelled send") };
        assert!(error.is_cancelled());
        drop(submit);
        assert_eq!(state.dropped.load(Ordering::SeqCst), 1);
        state.block_send.store(false, Ordering::SeqCst);
        let fresh = Cx::for_testing();
        let result = futures_lite::future::block_on(node.submit_and_wait(&fresh, request.clone())).unwrap();
        assert_eq!(result.sequence, SequenceNumber::new(1));
        assert_eq!(result.result, Outcome::Ok(b"applied:payload".to_vec()));
        assert_eq!(app.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn oversized_submission_and_zero_timeout_do_not_reserve_a_sequence() {
        let cx = Cx::for_testing();
        let state = Arc::new(IoState::default());
        let mut node = node(1, &state, Application::default());
        let mut large = request();
        large.operation = vec![255; 8192];
        assert!(futures_lite::future::block_on(node.submit_request(&cx, large)).is_err());
        assert!(futures_lite::future::block_on(node.submit_with_timeout(&cx, request(), Duration::ZERO)).is_err());
        assert_eq!(state.sends.load(Ordering::SeqCst), 0);
        let result = futures_lite::future::block_on(node.submit_and_wait(&cx, request())).unwrap();
        assert_eq!(result.sequence, SequenceNumber::new(1));
    }

    #[test]
    fn unsigned_or_tampered_ingress_never_reaches_application_or_sends_votes() {
        let cx = Cx::for_testing();
        let state = Arc::new(IoState::default());
        let app = Application::default();
        let mut node = node(4, &state, app.clone());
        let message = PbftMessage::Request(request());
        let unsigned = serde_json::to_vec(&message).unwrap();
        let mut tampered = authority(1, 4, 4096).seal(None, &message).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        for packet in [unsigned, tampered] {
            assert!(matches!(futures_lite::future::block_on(node.process_packet(&cx, &packet)).unwrap(), PbftIngressOutcome::Rejected(_)));
        }
        assert_eq!(state.sends.load(Ordering::SeqCst), 0);
        assert_eq!(node.last_applied().unwrap(), SequenceNumber::new(0));
        assert!(app.0.lock().unwrap().is_empty());
    }

    #[test]
    fn oversized_and_empty_signed_batches_are_rejected_before_protocol_admission() {
        let cx = Cx::for_testing();
        let state = Arc::new(IoState::default());
        let app = Application::default();
        let mut config = PbftConfig::new(4, 1).unwrap();
        config.max_batch_size = 1;
        let mut node = AuthenticatedPbftNode::new(
            config,
            ParkedWire(Arc::clone(&state)),
            authority(1, 4, 4096),
            app.clone(),
        ).unwrap();
        let primary = authority(0, 4, 4096);
        for requests in [Vec::new(), vec![request(), request()]] {
            let batch = ConsensusBatch::new(requests);
            let message = PbftMessage::PrePrepare {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(1),
                digest: MessageDigest::of(&batch).unwrap(),
                batch,
                replica_id: ReplicaId::new("0".into()),
            };
            let packet = primary.seal(None, &message).unwrap();
            let result = futures_lite::future::block_on(node.process_packet(&cx, &packet)).unwrap();
            assert_eq!(result, PbftIngressOutcome::Rejected(PbftAuthError::Configuration));
        }
        assert_eq!(state.sends.load(Ordering::SeqCst), 0);
        assert!(app.0.lock().unwrap().is_empty());

        // The same sequence remains usable: rejection did not install a log
        // entry which could conflict with the first valid proposal.
        let batch = ConsensusBatch::new(vec![request()]);
        let proposal = PbftMessage::PrePrepare {
            view: ViewNumber::new(0),
            sequence: SequenceNumber::new(1),
            digest: MessageDigest::of(&batch).unwrap(),
            batch,
            replica_id: ReplicaId::new("0".into()),
        };
        let packet = primary.seal(None, &proposal).unwrap();
        assert_eq!(
            futures_lite::future::block_on(node.process_packet(&cx, &packet)).unwrap(),
            PbftIngressOutcome::Processed,
        );
        assert_eq!(state.sends.load(Ordering::SeqCst), 1);
        assert_eq!(node.last_applied().unwrap(), SequenceNumber::new(0));
    }

    #[test]
    fn membership_protocol_mismatch_is_rejected_before_io() {
        let state = Arc::new(IoState::default());
        let result = AuthenticatedPbftNode::new(
            PbftConfig::new(7, 2).unwrap(), ParkedWire(Arc::clone(&state)),
            authority(0, 4, 4096), Application::default(),
        );
        assert!(result.is_err());
        assert_eq!(state.sends.load(Ordering::SeqCst), 0);
        assert_eq!(state.receives.load(Ordering::SeqCst), 0);
    }
