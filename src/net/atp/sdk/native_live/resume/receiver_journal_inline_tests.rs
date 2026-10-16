    use super::super::encode_epoch;
    use super::*;

    fn sample() -> ReceiverCheckpoint {
        let hello = Hello {
            nonce: [7; 32],
            epoch_bytes: 8,
            max_bytes: 64,
        };
        let prefix = advance(
            &initial(&hello),
            &encode_epoch(&initial(&hello), b"prefix01"),
            8,
            64,
        )
        .unwrap();
        let pending = Zeroizing::new(encode_epoch(&prefix, b"abcdefgh"));
        ReceiverCheckpoint {
            client: NativeClientCertificateId::from_sha256([3; 32]),
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            prefix,
            prefix_hash: Sha256::digest(b"prefix01").into(),
            pending_hash: Sha256::digest(b"prefix01abcdefgh").into(),
            used: 1,
            maximum: 4,
            phase: ReceiverCheckpointPhase::Receiving,
            pending,
        }
    }
    fn flushed(old: &ReceiverCheckpoint) -> ReceiverCheckpoint {
        let mut saved = old.clone();
        let hello = saved.validate().unwrap();
        saved.prefix = advance(
            &old.prefix,
            &old.pending,
            hello.epoch_bytes,
            hello.max_bytes,
        )
        .unwrap();
        saved.prefix_hash = old.pending_hash;
        saved.pending = Zeroizing::new(Vec::new());
        saved
    }
    fn finish<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        let mut context = Context::from_waker(std::task::Waker::noop());
        for _ in 0..128 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
        panic!("bounded in-memory revalidation did not complete");
    }

    #[test]
    fn canonical_receiver_checkpoint_roundtrips_exact_pending_bytes_and_client() {
        let saved = sample();
        let bytes = saved.to_canonical_bytes().unwrap();
        assert_eq!(MAX_RECEIVER_CHECKPOINT_BYTES, 65_933);
        assert_eq!(bytes.len(), FIXED + EPOCH_HEADER_BYTES + 8 + 32);
        let decoded = ReceiverCheckpoint::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(
            decoded.to_canonical_bytes().unwrap().as_slice(),
            bytes.as_slice()
        );
        assert_eq!(decoded.client(), saved.client());
        assert_eq!(decoded.pending_bytes(), 8);
        assert_eq!(decoded.attempts(), 1);
        assert!(decoded.committed_receipt().is_none());
        assert!(!format!("{decoded:?}").contains("abcdefgh"));
    }

    #[test]
    fn receiver_decoder_refuses_torn_corrupt_oversized_and_noncanonical_data() {
        let valid = sample().to_canonical_bytes().unwrap();
        for end in 0..valid.len() {
            assert!(ReceiverCheckpoint::from_canonical_bytes(&valid[..end]).is_err());
        }
        let mut longer = valid.to_vec();
        longer.push(0);
        assert!(ReceiverCheckpoint::from_canonical_bytes(&longer).is_err());
        assert!(
            ReceiverCheckpoint::from_canonical_bytes(&vec![0; MAX_RECEIVER_CHECKPOINT_BYTES + 1])
                .is_err()
        );
        for offset in [0, 32, 208, FIXED + EPOCH_HEADER_BYTES, valid.len() - 1] {
            let mut altered = valid.to_vec();
            altered[offset] ^= 1;
            assert!(ReceiverCheckpoint::from_canonical_bytes(&altered).is_err());
        }
        for (offset, value) in [(280, 3), (284, 1)] {
            let mut altered = valid.to_vec();
            altered[offset] = value;
            let body = altered.len() - 32;
            let hash = checksum(&altered[..body]);
            altered[body..].copy_from_slice(&hash);
            assert!(ReceiverCheckpoint::from_canonical_bytes(&altered).is_err());
        }
    }

    #[test]
    fn receiver_transitions_never_skip_wal_or_erase_commit_uncertainty() {
        let pending = sample();
        pending.validate_successor(&pending).unwrap();
        let stable = flushed(&pending);
        stable.validate_successor(&pending).unwrap();
        let mut committing = stable.clone();
        committing.phase = ReceiverCheckpointPhase::Finalizing;
        committing.validate_successor(&stable).unwrap();
        let mut committed = committing.clone();
        committed.phase = ReceiverCheckpointPhase::Committed;
        committed.validate_successor(&committing).unwrap();
        assert!(committed.validate_successor(&stable).is_err());
        assert!(stable.validate_successor(&committing).is_err());
        assert!(committing.validate_successor(&committed).is_err());
        assert!(pending.validate_successor(&stable).is_err());
        let mut wrong = stable;
        wrong.prefix.chain[0] ^= 1;
        assert!(wrong.validate_successor(&pending).is_err());
        let mut rebound = pending.clone();
        rebound.client = NativeClientCertificateId::from_sha256([4; 32]);
        assert!(rebound.validate_successor(&pending).is_err());
        let mut retry = pending.clone();
        retry.used += 1;
        retry.validate_successor(&pending).unwrap();
        assert!(pending.validate_successor(&retry).is_err());
    }

    #[test]
    fn every_surviving_pending_prefix_restores_its_actual_append_position() {
        let saved = sample();
        for tail in 0..=8 {
            let data = &b"prefix01abcdefgh"[..8 + tail];
            let (hash, pending, written) = finish(saved.revalidate(&mut &data[..])).unwrap();
            assert_eq!(digest(&hash), saved.prefix_hash);
            assert_eq!(written, (8 + tail) as u64);
            let pending = pending.unwrap();
            assert_eq!(pending.written, tail);
            assert_eq!(pending.bytes(), b"abcdefgh");
            assert_eq!(pending.next, flushed(&saved).prefix);
        }
    }

    #[test]
    fn revalidation_refuses_changed_prefix_tail_missing_bytes_and_unrecorded_suffix() {
        let saved = sample();
        for data in [
            b"prefix0".as_slice(),
            b"Xrefix01abc",
            b"prefix01abX",
            b"prefix01abcdefghX",
        ] {
            assert!(finish(saved.revalidate(&mut &data[..])).is_err());
        }
        let stable = flushed(&saved);
        assert!(finish(stable.revalidate(&mut b"prefix01abcdefg".as_slice())).is_err());
        assert!(finish(stable.revalidate(&mut b"prefix01abcdefghX".as_slice())).is_err());
    }

    #[test]
    fn unresolved_publication_is_not_restarted_even_when_all_file_bytes_match() {
        let mut saved = flushed(&sample());
        saved.phase = ReceiverCheckpointPhase::Finalizing;
        assert!(finish(saved.revalidate(&mut b"prefix01abcdefgh".as_slice())).is_err());
        assert!(saved.committed_receipt().is_none());
        saved.phase = ReceiverCheckpointPhase::Committed;
        let (_, pending, written) =
            finish(saved.revalidate(&mut b"prefix01abcdefgh".as_slice())).unwrap();
        assert!(pending.is_none());
        assert_eq!(written, 16);
        assert_eq!(
            saved.committed_receipt().unwrap().source_sha256,
            Sha256::digest(b"prefix01abcdefgh").as_slice()
        );
    }
