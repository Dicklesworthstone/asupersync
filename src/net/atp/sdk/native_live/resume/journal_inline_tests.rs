    use super::*;

    fn sample() -> SenderCheckpoint {
        let hello = Hello {
            nonce: [9; 32],
            epoch_bytes: 8,
            max_bytes: 64,
        };
        let first = encode_epoch(&initial(&hello), b"abcdefgh");
        let prefix = advance(&initial(&hello), &first, 8, 64).unwrap();
        let second = encode_epoch(&prefix, b"ijklmnop");
        let next = advance(&prefix, &second, 8, 64).unwrap();
        SenderCheckpoint {
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            prefix,
            prefix_hash: Sha256::digest(b"abcdefgh").into(),
            read_hash: Sha256::digest(b"abcdefghijklmnop").into(),
            server: [3; 32],
            remote: "127.0.0.1:9443".parse().unwrap(),
            domain: "localhost".to_owned(),
            used: 1,
            maximum: 4,
            eof: false,
            pending: Some(PendingIntent {
                bytes: 8,
                hash: Sha256::digest(b"ijklmnop").into(),
                chain: next.chain,
            }),
        }
    }

    fn acknowledged(old: &SenderCheckpoint) -> SenderCheckpoint {
        let mut next = old.clone();
        next.prefix.epochs += 1;
        next.prefix.bytes += old.pending_bytes() as u64;
        next.prefix.chain = old.pending.as_ref().unwrap().chain;
        next.prefix_hash = old.read_hash;
        next.pending = None;
        next
    }

    #[test]
    fn bounded_metadata_roundtrip_keeps_pending_and_attempt_identity() {
        let saved = sample();
        let bytes = saved.to_canonical_bytes().unwrap();
        assert_eq!(MAX_SENDER_CHECKPOINT_BYTES, 667);
        assert_eq!(bytes.len(), FIXED + "localhost".len() + PENDING_BYTES + 32);
        assert!(!bytes.windows(8).any(|window| window == b"ijklmnop"));
        let loaded = SenderCheckpoint::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(
            loaded.to_canonical_bytes().unwrap().as_slice(),
            bytes.as_slice()
        );
        assert_eq!(loaded.source_position(), 16);
        assert_eq!(loaded.attempts(), 1);
        assert_eq!(loaded.maximum_attempts(), 4);
        assert!(!loaded.source_eof());
        assert_eq!(loaded.pending_bytes(), 8);
        assert!(!format!("{loaded:?}").contains("localhost"));
    }

    #[test]
    fn decoder_rejects_torn_corrupt_and_noncanonical_records() {
        let bytes = sample().to_canonical_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(SenderCheckpoint::from_canonical_bytes(&bytes[..end]).is_err());
        }
        let mut changed = bytes.to_vec();
        changed.push(0);
        assert!(SenderCheckpoint::from_canonical_bytes(&changed).is_err());
        for offset in [0, 32, 200, 310, bytes.len() - 1] {
            let mut changed = bytes.to_vec();
            changed[offset] ^= 1;
            assert!(SenderCheckpoint::from_canonical_bytes(&changed).is_err());
        }
        for (offset, value) in [(277, 1), (307, 2), (313, 67)] {
            let mut changed = bytes.to_vec();
            changed[offset] = value;
            let body = changed.len() - 32;
            let hash = checksum(&changed[..body]);
            changed[body..].copy_from_slice(&hash);
            assert!(SenderCheckpoint::from_canonical_bytes(&changed).is_err());
        }
    }

    #[test]
    fn successors_cannot_rebind_skip_or_change_a_pending_epoch() {
        let old = sample();
        old.validate_successor(&old).unwrap();
        let mut attempt = old.clone();
        attempt.used += 1;
        attempt.validate_successor(&old).unwrap();
        let next = acknowledged(&old);
        next.validate_successor(&old).unwrap();
        for changed in [
            {
                let mut c = old.clone();
                c.server[0] ^= 1;
                c
            },
            {
                let mut c = old.clone();
                c.maximum += 1;
                c
            },
            {
                let mut c = old.clone();
                c.pending.as_mut().unwrap().hash[0] ^= 1;
                c
            },
            {
                let mut c = old.clone();
                c.read_hash[0] ^= 1;
                c
            },
            {
                let mut c = next.clone();
                c.prefix.chain[0] ^= 1;
                c
            },
            {
                let mut c = next.clone();
                c.prefix.bytes += 1;
                c
            },
        ] {
            assert!(changed.validate_successor(&old).is_err());
        }
        assert!(old.validate_successor(&next).is_err());
        assert!(old.validate_successor(&attempt).is_err());
    }

    #[test]
    fn eof_is_sticky_and_cannot_coexist_with_pending_data() {
        let old = sample();
        let mut eof = acknowledged(&old);
        eof.eof = true;
        eof.validate_successor(&old).unwrap();
        let roundtrip =
            SenderCheckpoint::from_canonical_bytes(&eof.to_canonical_bytes().unwrap()).unwrap();
        assert!(roundtrip.source_eof());
        let mut changed = eof.clone();
        changed.eof = false;
        assert!(changed.validate_successor(&eof).is_err());
        let mut invalid = old;
        invalid.eof = true;
        assert!(invalid.to_canonical_bytes().is_err());
    }

    #[test]
    fn empty_state_is_bound_to_the_negotiated_hello_and_empty_hash() {
        let mut saved = sample();
        let hello = decode_offer(&saved.agreed).unwrap();
        saved.prefix = initial(&hello);
        saved.prefix_hash = digest(&Sha256::new());
        saved.read_hash = saved.prefix_hash;
        saved.pending = None;
        saved.eof = true;
        saved.validate().unwrap();
        let mut bad = saved.clone();
        bad.prefix.chain[0] ^= 1;
        assert!(bad.validate().is_err());
        saved.read_hash[0] ^= 1;
        assert!(saved.validate().is_err());
    }
