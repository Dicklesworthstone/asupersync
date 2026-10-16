    use super::*;
    use std::future::{Future, ready};

    #[derive(Default)]
    struct RecordingTransport {
        sent: Mutex<Vec<PbftMessage>>,
        recipients: Mutex<Vec<ReplicaId>>,
    }

    impl PbftTransport for RecordingTransport {
        fn send_to_replica(
            &self,
            replica_id: &ReplicaId,
            message: PbftMessage,
        ) -> impl Future<Output = Result<()>> + Send {
            self.recipients.lock().unwrap().push(replica_id.clone());
            self.sent.lock().unwrap().push(message);
            ready(Ok(()))
        }

        fn broadcast(&self, message: PbftMessage) -> impl Future<Output = Result<()>> + Send {
            self.sent.lock().unwrap().push(message);
            ready(Ok(()))
        }

        fn receive(&self) -> impl Future<Output = Result<PbftMessage>> + Send {
            ready(Err(Error::new(ErrorKind::ChannelEmpty)))
        }
    }

    /// Records every broadcast but the first, which never completes.
    #[derive(Default)]
    struct FirstBroadcastHangs {
        broadcasts: Mutex<usize>,
        sent: Mutex<Vec<PbftMessage>>,
    }

    impl PbftTransport for FirstBroadcastHangs {
        fn send_to_replica(
            &self,
            _replica_id: &ReplicaId,
            _message: PbftMessage,
        ) -> impl Future<Output = Result<()>> + Send {
            ready(Ok(()))
        }

        fn broadcast(&self, message: PbftMessage) -> impl Future<Output = Result<()>> + Send {
            let first = {
                let mut broadcasts = self.broadcasts.lock().unwrap();
                *broadcasts += 1;
                *broadcasts == 1
            };
            if !first {
                self.sent.lock().unwrap().push(message);
            }
            async move {
                if first {
                    std::future::pending::<()>().await;
                }
                Ok(())
            }
        }

        fn receive(&self) -> impl Future<Output = Result<PbftMessage>> + Send {
            ready(Err(Error::new(ErrorKind::ChannelEmpty)))
        }
    }

    #[test]
    fn a_cancelled_proposal_neither_wedges_the_primary_nor_loses_its_request() {
        // The primary's first proposal is dropped mid-broadcast (a caller
        // timeout or select). It used to keep sequence 1 logged without
        // advancing past it, so every later proposal collided with the log
        // entry and failed, and the cancelled request was gone.
        let cx = Cx::for_testing();
        let node = PbftNode::new(
            ReplicaId::new("0".to_owned()),
            PbftConfig::new(4, 1).unwrap(),
            FirstBroadcastHangs::default(),
        )
        .unwrap();
        let request = |operation: u8| {
            ConsensusRequest::new(
                "client".to_owned(),
                Time::from_millis(u64::from(operation)),
                vec![operation],
            )
        };
        {
            let mut cancelled = std::pin::pin!(node.submit_request(&cx, request(1)));
            let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(cancelled.as_mut().poll(&mut task_cx).is_pending());
        }
        futures_lite::future::block_on(node.submit_request(&cx, request(2)))
            .expect("a later proposal must not collide with the cancelled one");
        // Retrying the cancelled request broadcasts its retained proposal.
        futures_lite::future::block_on(node.submit_request(&cx, request(1)))
            .expect("retry the cancelled request");
        let proposals: Vec<(u64, Vec<u8>)> = node
            .transport
            .sent
            .lock()
            .unwrap()
            .iter()
            .filter_map(|message| match message {
                PbftMessage::PrePrepare {
                    sequence, batch, ..
                } => Some((sequence.0, batch.requests[0].operation.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(proposals, vec![(2, vec![2]), (1, vec![1])]);
    }

    fn backup() -> PbftNode<RecordingTransport> {
        PbftNode::new(
            ReplicaId::new("1".to_owned()),
            PbftConfig::new(4, 1).unwrap(),
            RecordingTransport::default(),
        )
        .unwrap()
    }

    fn preprepare(
        node: &PbftNode<RecordingTransport>,
        cx: &Cx,
        sequence: u64,
    ) -> MessageDigest {
        let batch = ConsensusBatch::new(vec![ConsensusRequest::new(
            "client".to_owned(),
            Time::from_millis(sequence),
            sequence.to_le_bytes().to_vec(),
        )]);
        let digest = MessageDigest::of(&batch).unwrap();
        futures_lite::future::block_on(node.process_message(
            cx,
            PbftMessage::PrePrepare {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(sequence),
                digest: digest.clone(),
                batch,
                replica_id: ReplicaId::new("0".to_owned()),
            },
        ))
        .unwrap();
        digest
    }

    fn vote(sequence: u64, digest: &MessageDigest, event: usize) -> PbftMessage {
        let replica_id = ReplicaId::new(if event % 2 == 0 { "0" } else { "2" }.to_owned());
        if event < 2 {
            PbftMessage::Prepare {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(sequence),
                digest: digest.clone(),
                replica_id,
            }
        } else {
            PbftMessage::Commit {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(sequence),
                digest: digest.clone(),
                replica_id,
            }
        }
    }

    #[test]
    fn every_prepare_commit_permutation_executes_only_after_both_quorums() {
        let cx = Cx::for_testing();
        let mut permutations = 0;
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        if a == b || a == c || a == d || b == c || b == d || c == d {
                            continue;
                        }
                        let node = backup();
                        let digest = preprepare(&node, &cx, 1);
                        let mut prepares = 0;
                        let mut commits = 0;
                        for event in [a, b, c, d] {
                            futures_lite::future::block_on(
                                node.process_message(&cx, vote(1, &digest, event)),
                            )
                            .unwrap();
                            if event < 2 {
                                prepares += 1;
                            } else {
                                commits += 1;
                            }
                            let expected = u64::from(prepares == 2 && commits == 2);
                            assert_eq!(node.last_executed(), SequenceNumber::new(expected));
                        }
                        permutations += 1;
                    }
                }
            }
        }
        assert_eq!(permutations, 24);
    }

    #[test]
    fn late_prepare_drains_already_committed_successors_without_extra_packets() {
        let cx = Cx::for_testing();
        let node = backup();
        let first = preprepare(&node, &cx, 1);
        let second = preprepare(&node, &cx, 2);
        for event in [0, 1, 2, 3] {
            futures_lite::future::block_on(node.process_message(&cx, vote(2, &second, event)))
                .unwrap();
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(0));
        for event in [2, 3, 0, 1] {
            futures_lite::future::block_on(node.process_message(&cx, vote(1, &first, event)))
                .unwrap();
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(2));
    }

    #[test]
    fn single_replica_executes_without_transport_loopback() {
        let node = PbftNode::new(
            ReplicaId::new("0".to_owned()),
            PbftConfig::new(1, 0).unwrap(),
            RecordingTransport::default(),
        )
        .unwrap();
        let cx = Cx::for_testing();
        for sequence in 1..=2 {
            let request = ConsensusRequest::new(
                "client".to_owned(),
                Time::from_millis(sequence),
                vec![42],
            );
            futures_lite::future::block_on(node.submit_request(&cx, request)).unwrap();
            assert_eq!(node.last_executed(), SequenceNumber::new(sequence));
        }
    }

    #[test]
    fn duplicate_votes_cannot_replace_distinct_quorum_members() {
        let cx = Cx::for_testing();
        let node = backup();
        let digest = preprepare(&node, &cx, 1);
        for _ in 0..4 {
            for event in [0, 2] {
                futures_lite::future::block_on(node.process_message(&cx, vote(1, &digest, event)))
                    .unwrap();
            }
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(0));
        for event in [3, 1] {
            futures_lite::future::block_on(node.process_message(&cx, vote(1, &digest, event)))
                .unwrap();
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(1));
    }

    #[test]
    fn numeric_replica_aliases_cannot_inflate_either_quorum() {
        let cx = Cx::for_testing();
        let node = backup();
        let digest = preprepare(&node, &cx, 1);
        for alias in ["0", "00", "000"] {
            for mut message in [vote(1, &digest, 0), vote(1, &digest, 2)] {
                match &mut message {
                    PbftMessage::Prepare { replica_id, .. }
                    | PbftMessage::Commit { replica_id, .. } => {
                        *replica_id = ReplicaId::new(alias.to_owned());
                    }
                    _ => unreachable!(),
                }
                futures_lite::future::block_on(node.process_message(&cx, message)).unwrap();
            }
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(0));
        {
            let state = node.state.lock().unwrap();
            let entry = &state.log[&SequenceNumber::new(1)];
            assert_eq!(entry.prepare_msgs.len(), 1);
            assert_eq!(entry.commit_msgs.len(), 1);
        }
        for event in [3, 1] {
            futures_lite::future::block_on(node.process_message(&cx, vote(1, &digest, event)))
                .unwrap();
        }
        assert_eq!(node.last_executed(), SequenceNumber::new(1));
    }

    #[test]
    fn duplicate_preprepare_still_verifies_the_supplied_payload() {
        let cx = Cx::for_testing();
        let node = backup();
        let digest = preprepare(&node, &cx, 1);
        let original_batch = node.state.lock().unwrap().log[&SequenceNumber::new(1)]
            .batch
            .clone();
        let mut tampered_batch = original_batch.clone();
        tampered_batch.requests[0].operation.push(255);
        let duplicate = |batch| PbftMessage::PrePrepare {
            view: ViewNumber::new(0),
            sequence: SequenceNumber::new(1),
            digest: digest.clone(),
            batch,
            replica_id: ReplicaId::new("0".to_owned()),
        };
        assert!(
            futures_lite::future::block_on(node.process_message(&cx, duplicate(tampered_batch)))
                .is_err()
        );
        futures_lite::future::block_on(node.process_message(&cx, duplicate(original_batch)))
            .unwrap();
        assert_eq!(
            MessageDigest::of(&node.state.lock().unwrap().log[&SequenceNumber::new(1)].batch)
                .unwrap(),
            digest
        );
    }

    #[test]
    fn configuration_arithmetic_fails_closed_on_overflow() {
        assert!(PbftConfig::new(usize::MAX, usize::MAX).is_err());
        assert!(PbftConfig::new(0, 0).is_err());
        let mut config = PbftConfig::new(4, 1).unwrap();
        config.fault_tolerance = usize::MAX;
        assert!(!config.is_valid());
        assert_eq!(config.quorum_size(), usize::MAX);
        assert!(
            PbftNode::new(
                ReplicaId::new("0".to_owned()),
                config,
                RecordingTransport::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn execution_rejects_zero_batch_capacity_and_unsafe_quorum_topology() {
        let mut empty_batch = PbftConfig::new(4, 1).unwrap();
        empty_batch.max_batch_size = 0;
        for config in [empty_batch, PbftConfig::new(5, 1).unwrap()] {
            assert!(
                PbftExecution::new(
                    ReplicaId::new("0".to_owned()),
                    config,
                    RecordingTransport::default(),
                    |request: &ConsensusRequest| Outcome::Ok(request.operation.clone()),
                )
                .is_err()
            );
        }
    }

    fn execution(
        calls: Arc<Mutex<Vec<Vec<u8>>>>,
    ) -> PbftExecution<RecordingTransport, impl PbftStateMachine> {
        PbftExecution::new(
            ReplicaId::new("1".to_owned()),
            PbftConfig::new(4, 1).unwrap(),
            RecordingTransport::default(),
            move |request: &ConsensusRequest| {
                calls.lock().unwrap().push(request.operation.clone());
                let mut result = request.operation.clone();
                result.push(99);
                Outcome::Ok(result)
            },
        )
        .unwrap()
    }

    fn propose<S: PbftStateMachine>(
        driver: &PbftExecution<RecordingTransport, S>,
        cx: &Cx,
        sequence: u64,
        requests: Vec<ConsensusRequest>,
    ) -> MessageDigest {
        let batch = ConsensusBatch::new(requests);
        let digest = MessageDigest::of(&batch).unwrap();
        futures_lite::future::block_on(driver.process_message(
            cx,
            PbftMessage::PrePrepare {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(sequence),
                digest: digest.clone(),
                batch,
                replica_id: ReplicaId::new("0".to_owned()),
            },
        ))
        .unwrap();
        digest
    }

    fn finish<S: PbftStateMachine>(
        driver: &PbftExecution<RecordingTransport, S>,
        cx: &Cx,
        sequence: u64,
        digest: &MessageDigest,
    ) {
        // Complete commits before prepares to exercise the repaired path too.
        for event in [2, 3, 0, 1] {
            futures_lite::future::block_on(driver.process_message(cx, vote(sequence, digest, event)))
                .unwrap();
        }
    }

    #[test]
    fn execution_forwards_to_primary_and_never_fabricates_a_result() {
        let cx = Cx::for_testing();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let driver = execution(Arc::clone(&calls));
        let request = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![7]);
        futures_lite::future::block_on(driver.submit_request(&cx, request.clone())).unwrap();
        assert_eq!(
            *driver.node.transport.recipients.lock().unwrap(),
            vec![ReplicaId::new("0".to_owned())]
        );
        assert!(driver.committed_response(&request).unwrap().is_none());
        assert!(calls.lock().unwrap().is_empty());
        let digest = propose(&driver, &cx, 1, vec![request.clone()]);
        assert!(driver.committed_response(&request).unwrap().is_none());
        let before_execution = cx.now();
        finish(&driver, &cx, 1, &digest);
        let response = driver.committed_response(&request).unwrap().unwrap();
        assert_eq!(response.result, Outcome::Ok(vec![7, 99]));
        assert_eq!(response.sequence, SequenceNumber::new(1));
        assert_eq!(response.view, ViewNumber::new(0));
        assert_eq!(response.replica_id, ReplicaId::new("1".to_owned()));
        assert!(response.timestamp >= before_execution);
        assert!(response.timestamp <= cx.now());
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(1));
    }

    #[test]
    fn execution_replays_once_and_rejects_conflicting_client_identity() {
        let cx = Cx::for_testing();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let driver = execution(Arc::clone(&calls));
        let request = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![7]);
        for sequence in 1..=2 {
            // Include an exact duplicate inside each batch as well as across batches.
            let digest = propose(&driver, &cx, sequence, vec![request.clone(), request.clone()]);
            finish(&driver, &cx, sequence, &digest);
        }
        let original = driver.committed_response(&request).unwrap().unwrap();
        assert_eq!(original.sequence, SequenceNumber::new(1));
        assert_eq!(original.result, Outcome::Ok(vec![7, 99]));
        let mut conflict = request.clone();
        conflict.operation = vec![8];
        let digest = propose(&driver, &cx, 3, vec![conflict.clone()]);
        finish(&driver, &cx, 3, &digest);
        let rejected = driver.committed_response(&conflict).unwrap().unwrap();
        assert!(matches!(rejected.result, Outcome::Err(message) if message.contains("reused")));
        assert_eq!(rejected.sequence, SequenceNumber::new(3));
        assert_eq!(*calls.lock().unwrap(), vec![vec![7]]);
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(3));
    }

    #[test]
    fn execution_ignores_a_repeated_proposal_for_an_executed_sequence() {
        // The primary's retry, or a duplicated datagram, can deliver a proposal
        // after this replica executed it. Returning an error there stops `run`.
        let cx = Cx::for_testing();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let driver = execution(Arc::clone(&calls));
        let request = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![7]);
        let digest = propose(&driver, &cx, 1, vec![request.clone()]);
        finish(&driver, &cx, 1, &digest);
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(1));

        let proposal = |requests: Vec<ConsensusRequest>| {
            let batch = ConsensusBatch::new(requests);
            PbftMessage::PrePrepare {
                view: ViewNumber::new(0),
                sequence: SequenceNumber::new(1),
                digest: MessageDigest::of(&batch).unwrap(),
                batch,
                replica_id: ReplicaId::new("0".to_owned()),
            }
        };
        futures_lite::future::block_on(
            driver.process_message(&cx, proposal(vec![request.clone()])),
        )
        .expect("a repeated proposal for an executed sequence must be ignored");
        let mut conflicting = request;
        conflicting.operation = vec![8];
        assert!(
            futures_lite::future::block_on(
                driver.process_message(&cx, proposal(vec![conflicting]))
            )
            .is_err(),
            "a different proposal for an executed sequence is still refused"
        );
        assert_eq!(*calls.lock().unwrap(), vec![vec![7]]);
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(1));
    }

    #[test]
    fn execution_applies_out_of_order_commits_in_log_order() {
        let cx = Cx::for_testing();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let driver = execution(Arc::clone(&calls));
        let first = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![1]);
        let second = ConsensusRequest::new("client".to_owned(), Time::from_millis(2), vec![2]);
        let first_digest = propose(&driver, &cx, 1, vec![first.clone()]);
        let second_digest = propose(&driver, &cx, 2, vec![second.clone()]);
        finish(&driver, &cx, 2, &second_digest);
        assert!(calls.lock().unwrap().is_empty());
        assert!(driver.committed_response(&second).unwrap().is_none());
        finish(&driver, &cx, 1, &first_digest);
        assert_eq!(*calls.lock().unwrap(), vec![vec![1], vec![2]]);
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(2));
        assert_eq!(
            driver.committed_response(&second).unwrap().unwrap().result,
            Outcome::Ok(vec![2, 99])
        );
    }

    #[test]
    fn execution_preserves_application_errors_and_solo_replay_receipts() {
        let cx = Cx::for_testing();
        let driver = PbftExecution::new(
            ReplicaId::new("0".to_owned()),
            PbftConfig::new(1, 0).unwrap(),
            RecordingTransport::default(),
            |request: &ConsensusRequest| {
                if request.operation.is_empty() {
                    Outcome::Err("empty operation".to_owned())
                } else {
                    Outcome::Ok(request.operation.clone())
                }
            },
        )
        .unwrap();
        let invalid = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![]);
        let valid = ConsensusRequest::new("client".to_owned(), Time::from_millis(2), vec![8]);
        for request in [&invalid, &valid, &invalid] {
            futures_lite::future::block_on(driver.submit_request(&cx, request.clone())).unwrap();
        }
        assert_eq!(
            driver.committed_response(&invalid).unwrap().unwrap().result,
            Outcome::Err("empty operation".to_owned())
        );
        assert_eq!(
            driver.committed_response(&valid).unwrap().unwrap().result,
            Outcome::Ok(vec![8])
        );
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(2));
    }

    #[test]
    fn execution_panic_fails_closed_without_reapplying() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cx = Cx::for_testing();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let driver = PbftExecution::new(
            ReplicaId::new("0".to_owned()),
            PbftConfig::new(1, 0).unwrap(),
            RecordingTransport::default(),
            move |_request: &ConsensusRequest| -> Outcome<Vec<u8>, String> {
                seen.fetch_add(1, Ordering::SeqCst);
                panic!("application failed after mutation")
            },
        )
        .unwrap();
        let request = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![1]);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures_lite::future::block_on(driver.submit_request(&cx, request.clone()))
        }));
        assert!(panicked.is_err());
        assert!(driver.last_applied().is_err());
        assert!(driver.committed_response(&request).is_err());
        assert!(futures_lite::future::block_on(driver.submit_request(&cx, request)).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn execution_retry_retains_proposal_after_ambiguous_transport_error() {
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Default)]
        struct AmbiguousTransport {
            failed_once: AtomicBool,
            sent: Mutex<Vec<PbftMessage>>,
        }

        impl PbftTransport for AmbiguousTransport {
            fn send_to_replica(
                &self,
                _replica_id: &ReplicaId,
                message: PbftMessage,
            ) -> impl Future<Output = Result<()>> + Send {
                self.broadcast(message)
            }

            fn broadcast(&self, message: PbftMessage) -> impl Future<Output = Result<()>> + Send {
                self.sent.lock().unwrap().push(message);
                let result = if self.failed_once.swap(true, Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(Error::new(ErrorKind::ConnectionLost))
                };
                ready(result)
            }

            fn receive(&self) -> impl Future<Output = Result<PbftMessage>> + Send {
                ready(Err(Error::new(ErrorKind::ChannelEmpty)))
            }
        }

        let cx = Cx::for_testing();
        let driver = PbftExecution::new(
            ReplicaId::new("0".to_owned()),
            PbftConfig::new(1, 0).unwrap(),
            AmbiguousTransport::default(),
            |request: &ConsensusRequest| Outcome::Ok(request.operation.clone()),
        )
        .unwrap();
        let request = ConsensusRequest::new("client".to_owned(), Time::from_millis(1), vec![6]);
        assert!(
            futures_lite::future::block_on(driver.submit_request(&cx, request.clone())).is_err()
        );
        assert!(driver.committed_response(&request).unwrap().is_none());
        futures_lite::future::block_on(driver.submit_request(&cx, request.clone())).unwrap();
        let sent = driver.node.transport.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].digest().unwrap(), sent[1].digest().unwrap());
        let response = driver.committed_response(&request).unwrap().unwrap();
        assert_eq!(response.sequence, SequenceNumber::new(1));
        assert_eq!(response.result, Outcome::Ok(vec![6]));
        assert_eq!(driver.last_applied().unwrap(), SequenceNumber::new(1));
    }
