    use super::*;

    fn saved() -> FinalProofCheckpoint {
        let hello = Hello {
            nonce: [7; 32],
            epoch_bytes: 8,
            max_bytes: 64,
        };
        let prefix = initial(&hello);
        FinalProofCheckpoint {
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            receipt: LiveStreamReceipt {
                prefix,
                source_sha256: Sha256::digest(b"").into(),
            },
            server_certificate: [9; 32],
            remote: "127.0.0.1:8443".parse().unwrap(),
            domain: "localhost".to_owned(),
        }
    }

    #[test]
    fn checkpoint_roundtrip_preserves_ipv4_and_scoped_ipv6() {
        for remote in [
            "127.0.0.1:8443".parse().unwrap(),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 17, 23)),
        ] {
            let original = FinalProofCheckpoint { remote, ..saved() };
            let bytes = original.to_canonical_bytes().unwrap();
            assert!(bytes.len() <= MAX_FINAL_PROOF_CHECKPOINT_BYTES);
            let loaded = FinalProofCheckpoint::from_canonical_bytes(&bytes).unwrap();
            assert_eq!(loaded.remote(), remote);
            assert_eq!(loaded.intent(), original.intent());
            assert_eq!(loaded.to_canonical_bytes().unwrap(), bytes);
            assert!(!format!("{loaded:?}").contains("localhost"));
        }
    }

    #[test]
    fn every_truncation_corruption_and_trailing_byte_is_refused() {
        let bytes = saved().to_canonical_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(FinalProofCheckpoint::from_canonical_bytes(&bytes[..end]).is_err());
        }
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(FinalProofCheckpoint::from_canonical_bytes(&changed).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(FinalProofCheckpoint::from_canonical_bytes(&trailing).is_err());
        assert!(
            FinalProofCheckpoint::from_canonical_bytes(&vec![
                0;
                MAX_FINAL_PROOF_CHECKPOINT_BYTES + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn recomputed_checksums_do_not_bypass_shape_or_canonical_address_validation() {
        let bytes = saved().to_canonical_bytes().unwrap();
        // Empty hash/chain, epoch count, nonce agreement, address padding and name length.
        for index in [128, 144, 176, 8 + 16, 245, 267] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            let body = changed.len() - 32;
            let digest = checksum(&changed[..body]);
            changed[body..].copy_from_slice(&digest);
            assert!(
                FinalProofCheckpoint::from_canonical_bytes(&changed).is_err(),
                "field {index}"
            );
        }
    }

    #[test]
    fn remote_completion_flag_never_substitutes_for_exact_final_prefix() {
        let saved = saved();
        let mut state = saved.agreed.to_vec();
        state.extend_from_slice(&encode_final(saved.intent()));
        state.push(0);
        assert!(saved.check_remote_state(&state).is_err());
        state[140] = 1;
        assert!(saved.check_remote_state(&state).is_ok());
        state[140] = 2;
        assert!(saved.check_remote_state(&state).is_err());
        state[140] = 1;
        for index in 0..140 {
            let mut changed = state.clone();
            changed[index] ^= 1;
            assert!(saved.check_remote_state(&changed).is_err());
        }
    }
