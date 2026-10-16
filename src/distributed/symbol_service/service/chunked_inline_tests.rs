    use super::*;
    use crate::distributed::symbol_service::{EncodedSymbolBatch, SymbolBatchLimits, SymbolStoreLimits, encode_symbol_batch};
    use crate::security::{AuthKey, SecurityContext};
    use crate::types::symbol::{ObjectId, Symbol};

    fn fixture(seed: u64) -> EncodedSymbolBatch {
        let security = SecurityContext::new(AuthKey::from_seed(seed));
        let symbols = (0..3).map(|esi| security.sign_symbol(&Symbol::new_for_test(71, 0, esi, &[esi as u8; 128])))
            .collect::<Vec<_>>();
        encode_symbol_batch(&symbols, batch_limits()).unwrap()
    }

    fn batch_limits() -> SymbolBatchLimits {
        SymbolBatchLimits { max_encoded_bytes: 4096, max_symbols: 16, max_payload_bytes: 2048, max_decoded_bytes: 8192 }
    }

    fn make_service(max_uploads: usize, total: usize, per_peer: usize) -> ChunkedSymbolService {
        let store = Arc::new(SymbolReplicaStore::new("replica", AuthKey::from_seed(42), batch_limits(),
            SymbolStoreLimits { max_batches: 4, max_bytes: 16384, max_batches_per_peer: 2, max_bytes_per_peer: 8192 }).unwrap());
        ChunkedSymbolService::new(store,
            SymbolChunkedLimits::new(128, max_uploads, total, per_peer, total, Duration::from_nanos(100)).unwrap())
    }

    fn make_upload(batch: &EncodedSymbolBatch, attempt: u64) -> Upload {
        Upload { key: batch.key(), attempt, total: batch.as_ref().len(), count: batch.symbol_count() }
    }

    fn command(service: &ChunkedSymbolService, peer: &NodeId, now: u64, operation: u8, upload: Upload) -> Result<Vec<u8>, SymbolStoreError> {
        service.handle(peer, Time::from_nanos(now), &request(operation, "replica", &upload_body(upload)).unwrap())
    }

    fn piece(service: &ChunkedSymbolService, peer: &NodeId, now: u64, upload: Upload, offset: usize, data: &[u8]) -> Result<Vec<u8>, SymbolStoreError> {
        let mut body = upload_body(upload);
        body.extend_from_slice(&(offset as u64).to_le_bytes());
        body.extend_from_slice(data);
        service.handle(peer, Time::from_nanos(now), &request(CHUNK, "replica", &body).unwrap())
    }

    fn stage(service: &ChunkedSymbolService, peer: &NodeId, batch: &EncodedSymbolBatch, upload: Upload) {
        command(service, peer, 0, BEGIN, upload).unwrap();
        for (index, chunk) in batch.as_ref().chunks(128).enumerate() {
            piece(service, peer, 1, upload, index * 128, chunk).unwrap();
        }
    }


    struct CommitRelease(Option<std::sync::mpsc::Sender<()>>);

    impl CommitRelease {
        fn release(&mut self) {
            if let Some(sender) = self.0.take() { let _ = sender.send(()); }
        }
    }

    impl Drop for CommitRelease {
        fn drop(&mut self) { self.release(); }
    }

    fn pause_commit(
        service: &ChunkedSymbolService, panic_after_release: bool,
    ) -> (std::sync::mpsc::Receiver<()>, CommitRelease) {
        let (entered, reached) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released = Mutex::new(released);
        *service.commit_hook.lock() = Some(Arc::new(move || {
            entered.send(()).expect("commit pause observer");
            released.lock().recv_timeout(Duration::from_secs(5)).expect("commit pause release");
            assert!(!panic_after_release, "injected commit verification panic");
        }));
        (reached, CommitRelease(Some(release)))
    }

    #[test]
    fn begin_lookup_rechecks_staging_and_completed_publication_without_holding_its_lock() {
        for complete in [false, true] {
            let batch = fixture(42);
            let upload = make_upload(&batch, 1);
            let service = make_service(2, 2 * upload.total, 2);
            let peer = NodeId::new("origin");
            let (entered, reached) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let released = Mutex::new(released);
            let lookups = std::sync::atomic::AtomicUsize::new(0);
            *service.lookup_hook.lock() = Some(Arc::new(move || {
                if lookups.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    entered.send(()).unwrap();
                    released.lock().recv_timeout(Duration::from_secs(15)).expect("lookup release");
                }
            }));
            std::thread::scope(|scope| {
                let mut release = CommitRelease(Some(release));
                let service = &service;
                let peer = &peer;
                let batch = &batch;
                let first = scope.spawn(move || command(service, peer, 0, BEGIN, upload));
                reached.recv_timeout(Duration::from_secs(5)).expect("first lookup returned NotFound");
                let (progressed, progress) = std::sync::mpsc::channel();
                let concurrent = scope.spawn(move || {
                    assert_eq!(service.stats().uploads, 0);
                    assert_eq!(service.reap_expired(Time::ZERO), 0);
                    command(service, peer, 1, BEGIN, upload).unwrap();
                    if complete {
                        for (index, bytes) in batch.as_ref().chunks(128).enumerate() {
                            piece(service, peer, 1, upload, index * 128, bytes).unwrap();
                        }
                        command(service, peer, 2, COMMIT, upload).unwrap();
                        assert_eq!(service.stats().reserved_bytes, 0);
                    } else {
                        piece(service, peer, 1, upload, 0, &batch.as_ref()[..128]).unwrap();
                    }
                    progressed.send(()).unwrap();
                });
                progress.recv_timeout(Duration::from_secs(5))
                    .expect("lookup cannot retain staging or block an independent winner");
                release.release();
                let reply = first.join().unwrap().unwrap();
                assert_eq!(read_progress(&reply, upload).unwrap().0,
                    if complete { upload.total } else { 128 });
                concurrent.join().unwrap();
            });
            if complete {
                assert_eq!(service.stats().uploads, 0,
                    "a stale NotFound cannot recreate staging after the same attempt committed");
                assert_eq!(service.stats().reserved_bytes, 0);
                assert_eq!(service.store.stats().batches, 1);
            } else {
                assert_eq!(service.stats().uploads, 1, "the winning BEGIN is not duplicated");
                assert_eq!(service.stats().reserved_bytes, upload.total);
                command(&service, &peer, 3, ABORT, upload).unwrap();
            }
        }
    }

    #[test]
    fn committing_upload_keeps_credit_without_blocking_other_peers() {
        let batch = fixture(42);
        let upload = make_upload(&batch, 1);
        let service = make_service(3, 3 * upload.total, 1);
        let alice = NodeId::new("alice");
        let bob = NodeId::new("bob");
        let expired = NodeId::new("expired");
        let reader = NodeId::new("reader");
        service.store.put(&reader, batch.as_ref()).unwrap();
        stage(&service, &alice, &batch, upload);
        command(&service, &expired, 0, BEGIN, upload).unwrap();
        command(&service, &bob, 50, BEGIN, upload).unwrap();

        std::thread::scope(|scope| {
            // This release guard lives inside the scope: a failed progress
            // assertion releases the owner before scoped threads are joined.
            let (reached, mut release) = pause_commit(&service, false);
            let service = &service;
            let alice = &alice;
            let bob = &bob;
            let reader = &reader;
            let batch = &batch;
            let commit = scope.spawn(move || command(service, alice, 2, COMMIT, upload));
            reached.recv_timeout(Duration::from_secs(5)).expect("commit reached verification");
            let (progressed, progress) = std::sync::mpsc::channel();
            let other = scope.spawn(move || {
                assert_eq!(service.stats(), SymbolStagingStats {
                    uploads: 3, reserved_bytes: 3 * upload.total, received_bytes: upload.total,
                });
                // Expiry must remove only the abandoned upload. The committing
                // allocation is still owned even after its original deadline.
                assert_eq!(service.reap_expired(Time::from_nanos(120)), 1);
                assert_eq!(service.stats().uploads, 2);
                assert_eq!(service.stats().reserved_bytes, 2 * upload.total);
                let reply = piece(service, bob, 120, upload, 0, &batch.as_ref()[..128]).unwrap();
                assert_eq!(read_progress(&reply, upload).unwrap(), (128, 128));
                let replay = command(service, bob, 121, BEGIN, upload).unwrap();
                assert_eq!(read_progress(&replay, upload).unwrap(), (128, 128));
                let read = service.handle(reader, Time::from_nanos(121),
                    &range_request("replica", upload.key, 0, 128).unwrap()).unwrap();
                let (total, count, bytes) = read_range(&read, upload.key, 0, 128).unwrap();
                assert_eq!((total, count), (upload.total, upload.count));
                assert_eq!(bytes, &batch.as_ref()[..128]);
                assert_eq!(command(service, alice, 122, BEGIN, Upload { attempt: 2, ..upload }),
                    Err(SymbolStoreError::Limit("peer staged uploads")));
                command(service, &NodeId::new("charlie"), 122, BEGIN, upload).unwrap();
                assert_eq!(command(service, &NodeId::new("david"), 122, BEGIN, upload),
                    Err(SymbolStoreError::Limit("staged uploads")));
                assert_eq!(service.stats(), SymbolStagingStats {
                    uploads: 3, reserved_bytes: 3 * upload.total, received_bytes: upload.total + 128,
                });
                assert!(matches!(service.store.get(alice, upload.key), Err(SymbolStoreError::NotFound)));
                progressed.send(()).expect("peer progress observer");
            });
            progress.recv_timeout(Duration::from_secs(5))
                .expect("other peers must progress while commit verification is held");
            release.release();
            let receipt = commit.join().expect("committing thread").expect("verified commit");
            super::super::validate_receipt(&receipt[8..], "replica", upload.key, upload.count).unwrap();
            other.join().expect("independent peer requests");
        });
        assert_eq!(service.stats(), SymbolStagingStats {
            uploads: 2, reserved_bytes: 2 * upload.total, received_bytes: 128,
        });
        assert_eq!(service.store.stats().batches, 2);
        assert_eq!(service.reap_expired(Time::from_nanos(222)), 2);
        assert_eq!(service.stats(), SymbolStagingStats { uploads: 0, reserved_bytes: 0, received_bytes: 0 });
    }

    #[test]
    fn duplicate_commit_and_abort_wait_for_exact_owner_and_wake_on_failure_or_panic() {
        for case in 0..3 {
            let batch = fixture(if case == 1 { 43 } else { 42 });
            let upload = make_upload(&batch, 1);
            let service = make_service(1, upload.total, 1);
            let peer = NodeId::new("origin");
            stage(&service, &peer, &batch, upload);
            std::thread::scope(|scope| {
                let (reached, mut release) = pause_commit(&service, case == 2);
                let service = &service;
                let peer = &peer;
                let owner = scope.spawn(move || std::panic::catch_unwind(
                    std::panic::AssertUnwindSafe(|| command(service, peer, 2, COMMIT, upload)),
                ));
                reached.recv_timeout(Duration::from_secs(5)).expect("owner reached verification");
                let completion = {
                    let state = service.staging.lock();
                    Arc::clone(state.entries[&(peer.clone(), upload.attempt)].commit.as_ref().unwrap())
                };
                let duplicate = scope.spawn(move || command(service, peer, 3, COMMIT, upload));
                let abort = scope.spawn(move || command(service, peer, 3, ABORT, upload));
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                // Map + owner + this witness + both requests prove that the
                // duplicate and abort have reached the real per-attempt wait.
                while Arc::strong_count(&completion) < 5 {
                    assert!(std::time::Instant::now() < deadline, "same-attempt requests did not park");
                    std::thread::yield_now();
                }
                assert!(!*completion.done.lock());
                assert_eq!(service.reap_expired(Time::from_nanos(200)), 0);
                assert_eq!(service.stats(), SymbolStagingStats {
                    uploads: 1, reserved_bytes: upload.total, received_bytes: upload.total,
                });
                release.release();
                let result = owner.join().expect("owner thread catch-unwind");
                match case {
                    0 => { result.expect("successful owner").expect("verified publication"); }
                    1 => { assert_eq!(result.expect("authentication refusal"), Err(SymbolStoreError::Authentication)); }
                    _ => { assert!(result.is_err(), "injected owner panic must be observed"); }
                }
                let replay = duplicate.join().expect("duplicate commit thread");
                if case == 0 {
                    let receipt = replay.expect("duplicate committed receipt");
                    super::super::validate_receipt(&receipt[8..], "replica", upload.key, upload.count).unwrap();
                } else {
                    assert_eq!(replay, Err(SymbolStoreError::NotFound));
                }
                let aborted = abort.join().expect("abort thread").expect("idempotent abort");
                assert_eq!(read_progress(&aborted, upload).unwrap(), (0, 128));
                assert!(*completion.done.lock());
            });
            assert_eq!(service.stats(), SymbolStagingStats { uploads: 0, reserved_bytes: 0, received_bytes: 0 });
            assert_eq!(service.store.stats().batches, usize::from(case == 0));
            *service.commit_hook.lock() = None;
            let healthy = fixture(42);
            let next = make_upload(&healthy, 2);
            let healthy_peer = NodeId::new("healthy");
            stage(&service, &healthy_peer, &healthy, next);
            command(&service, &healthy_peer, 3, COMMIT, next).expect("retired credit is reusable");
            assert_eq!(service.stats().reserved_bytes, 0);
        }
    }

    #[test]
    fn incomplete_upload_is_invisible_and_exact_replays_publish_once() {
        let batch = fixture(42);
        let upload = make_upload(&batch, 1);
        let service = make_service(1, batch.as_ref().len(), 1);
        let peer = NodeId::new("origin");
        let begin = command(&service, &peer, 0, BEGIN, upload).unwrap();
        assert_eq!(read_progress(&begin, upload).unwrap(), (0, 128));
        assert_eq!(service.stats().reserved_bytes, upload.total);
        assert_eq!(service.stats().received_bytes, 0);
        piece(&service, &peer, 1, upload, 0, &batch.as_ref()[..128]).unwrap();
        assert_eq!(command(&service, &peer, 2, COMMIT, upload), Err(SymbolStoreError::Truncated));
        assert_eq!(service.store.stats().batches, 0);
        let replay = piece(&service, &peer, 3, upload, 0, &batch.as_ref()[..128]).unwrap();
        assert_eq!(read_progress(&replay, upload).unwrap(), (128, 128));
        assert_eq!(service.stats().received_bytes, 128);
        assert_eq!(piece(&service, &peer, 3, upload, 256, &batch.as_ref()[256..384]), Err(SymbolStoreError::Conflict));
        assert_eq!(piece(&service, &peer, 3, upload, 0, &[9; 128]), Err(SymbolStoreError::Conflict));
        for (index, bytes) in batch.as_ref()[128..].chunks(128).enumerate() {
            piece(&service, &peer, 4, upload, 128 + index * 128, bytes).unwrap();
        }
        let committed = command(&service, &peer, 5, COMMIT, upload).unwrap();
        assert_eq!(&committed[..8], &upload.attempt.to_le_bytes());
        super::super::validate_receipt(&committed[8..], "replica", upload.key, upload.count).unwrap();
        assert_eq!(service.stats(), SymbolStagingStats { uploads: 0, reserved_bytes: 0, received_bytes: 0 });
        assert_eq!(service.store.stats().batches, 1);
        // No tombstone is needed: immutable exact-key storage handles repeat sends.
        let repeated = Upload { attempt: 9, ..upload };
        let begin = command(&service, &peer, 6, BEGIN, repeated).unwrap();
        assert_eq!(read_progress(&begin, repeated).unwrap().0, upload.total);
        command(&service, &peer, 7, COMMIT, repeated).unwrap();
        command(&service, &peer, 8, ABORT, repeated).unwrap();
        assert_eq!(service.store.stats().batches, 1);
    }

    #[test]
    fn staged_upload_is_allocated_once_whatever_the_chunk_size() {
        let batch = fixture(42);
        let upload = make_upload(&batch, 1);
        let service = make_service(1, batch.as_ref().len(), 1);
        let peer = NodeId::new("origin");
        command(&service, &peer, 0, BEGIN, upload).unwrap();
        let mut staged_at = None;
        for (offset, byte) in batch.as_ref().iter().enumerate() {
            let chunk = std::slice::from_ref(byte);
            piece(&service, &peer, 1, upload, offset, chunk).unwrap();
            let state = service.staging.lock();
            let staged = &state.entries[&(peer.clone(), upload.attempt)].bytes;
            let capacity = staged.capacity();
            assert!(
                capacity >= upload.total,
                "chunk at {offset}: capacity {capacity}"
            );
            let at = staged.as_ptr();
            assert_eq!(
                *staged_at.get_or_insert(at),
                at,
                "chunk at {offset} moved the staged bytes"
            );
        }
        command(&service, &peer, 2, COMMIT, upload).unwrap();
        assert_eq!(service.store.stats().batches, 1);
    }

    #[test]
    fn reservation_limits_origin_isolation_and_fixed_expiry_cannot_be_renewed_by_replay() {
        let batch = fixture(42);
        let first = make_upload(&batch, 1);
        let second = Upload { attempt: 2, ..first };
        let service = make_service(2, 2 * first.total, 1);
        let alice = NodeId::new("alice");
        let bob = NodeId::new("bob");
        command(&service, &alice, 0, BEGIN, first).unwrap();
        assert_eq!(command(&service, &alice, 0, BEGIN, second), Err(SymbolStoreError::Limit("peer staged uploads")));
        command(&service, &bob, 0, BEGIN, first).unwrap();
        assert_eq!(service.stats().reserved_bytes, 2 * first.total);
        assert_eq!(command(&service, &NodeId::new("charlie"), 1, BEGIN, first), Err(SymbolStoreError::Limit("staged uploads")));
        piece(&service, &alice, 50, first, 0, &batch.as_ref()[..128]).unwrap();
        command(&service, &alice, 99, BEGIN, first).unwrap();
        assert_eq!(service.reap_expired(Time::from_nanos(99)), 0);
        assert_eq!(service.reap_expired(Time::from_nanos(100)), 2);
        assert_eq!(service.stats().reserved_bytes, 0);
        assert_eq!(piece(&service, &alice, 101, first, 128, &batch.as_ref()[128..256]), Err(SymbolStoreError::NotFound));
        command(&service, &alice, 101, BEGIN, second).unwrap();
        // A different authenticated origin cannot remove Alice's staging.
        command(&service, &bob, 101, ABORT, second).unwrap();
        assert_eq!(service.stats().uploads, 1);
        command(&service, &alice, 102, ABORT, second).unwrap();
        assert_eq!(service.stats().uploads, 0);
        let tiny = make_service(2, first.total - 1, 2);
        assert_eq!(command(&tiny, &alice, 0, BEGIN, first), Err(SymbolStoreError::Limit("staged bytes")));
    }

    #[test]
    fn invalid_declared_identity_digest_count_or_authentication_never_publishes() {
        for case in 0..4 {
            let batch = fixture(if case == 3 { 43 } else { 42 });
            let mut upload = make_upload(&batch, 1);
            match case {
                0 => {
                    upload.key.object_id = ObjectId::from_u128(999);
                    upload.key = super::super::super::batch::key(upload.key.object_id, batch.as_ref());
                }
                1 => upload.key.digest[0] ^= 1,
                2 => upload.count += 1,
                _ => {}
            }
            let service = make_service(1, 4096, 1);
            let peer = NodeId::new("origin");
            stage(&service, &peer, &batch, upload);
            let result = command(&service, &peer, 2, COMMIT, upload);
            assert_eq!(result, Err(if case == 3 { SymbolStoreError::Authentication } else { SymbolStoreError::Identity }));
            assert_eq!(service.store.stats().batches, 0);
            assert_eq!(service.stats().reserved_bytes, 0);
            // A failed complete upload cannot leave the sole slot unusable.
            let healthy = fixture(42);
            let next = make_upload(&healthy, 2);
            stage(&service, &peer, &healthy, next);
            command(&service, &peer, 3, COMMIT, next).unwrap();
            assert_eq!(service.store.stats().batches, 1);
        }
    }

    #[test]
    fn range_reads_bound_each_frame_and_refuse_cross_origin_or_wrong_identity() {
        let batch = fixture(42);
        let service = make_service(1, 4096, 1);
        let peer = NodeId::new("origin");
        service.store.put(&peer, batch.as_ref()).unwrap();
        let mut bytes = Vec::new();
        while bytes.len() < batch.as_ref().len() {
            let response = service.handle(&peer, Time::ZERO, &range_request("replica", batch.key(), bytes.len(), 1000).unwrap()).unwrap();
            let (total, count, part) = read_range(&response, batch.key(), bytes.len(), 128).unwrap();
            assert_eq!((total, count), (batch.as_ref().len(), batch.symbol_count()));
            assert!(part.len() <= 128);
            bytes.extend_from_slice(part);
        }
        assert_eq!(bytes, batch.as_ref());
        let request = range_request("replica", batch.key(), 0, 128).unwrap();
        assert_eq!(service.handle(&NodeId::new("other"), Time::ZERO, &request), Err(SymbolStoreError::NotFound));
        let mut wrong = batch.key(); wrong.digest[0] ^= 1;
        assert_eq!(service.handle(&peer, Time::ZERO, &range_request("replica", wrong, 0, 128).unwrap()), Err(SymbolStoreError::NotFound));
        assert_eq!(service.handle(&peer, Time::ZERO, &range_request("replica", batch.key(), bytes.len(), 128).unwrap()), Err(SymbolStoreError::Format));
        assert_eq!(service.stats().uploads, 0);
    }

    #[test]
    fn malformed_target_attempt_and_progress_cannot_mutate_or_satisfy_upload() {
        let batch = fixture(42);
        let upload = make_upload(&batch, 1);
        let service = make_service(1, 4096, 1);
        let peer = NodeId::new("origin");
        let wrong_target = request(BEGIN, "different", &upload_body(upload)).unwrap();
        assert_eq!(service.handle(&peer, Time::ZERO, &wrong_target), Err(SymbolStoreError::Identity));
        assert_eq!(service.stats().uploads, 0);
        let begun = command(&service, &peer, 0, BEGIN, upload).unwrap();
        let different = Upload { count: upload.count + 1, ..upload };
        assert_eq!(command(&service, &peer, 1, BEGIN, different), Err(SymbolStoreError::Conflict));
        assert_eq!(command(&service, &peer, 1, ABORT, different), Err(SymbolStoreError::Identity));
        assert_eq!(read_progress(&begun, Upload { attempt: 2, ..upload }), Err(SymbolStoreError::Identity));
        assert_eq!(piece(&service, &peer, 1, upload, 0, &[0; 129]), Err(SymbolStoreError::Limit("chunk bytes")));
        assert_eq!(service.stats().received_bytes, 0);
        assert!(SymbolChunkedLimits::new(0, 1, 1, 1, 1, Duration::from_secs(1)).is_err());
        assert!(SymbolChunkedLimits::new(1, 1, 1, 1, 1, Duration::ZERO).is_err());
    }
