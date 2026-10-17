    use super::*;

    #[test]
    fn hello_and_chain_bind_nonce_and_limits() {
        let hello = Hello {
            nonce: [7; 32],
            epoch_bytes: 8,
            max_bytes: 50,
        };
        assert_eq!(
            Hello::decode(&hello.encode()).unwrap().prefix(),
            hello.prefix()
        );
        for other in [
            Hello {
                nonce: [8; 32],
                epoch_bytes: 8,
                max_bytes: 50,
            },
            Hello {
                nonce: [7; 32],
                epoch_bytes: 7,
                max_bytes: 50,
            },
            Hello {
                nonce: [7; 32],
                epoch_bytes: 8,
                max_bytes: 49,
            },
        ] {
            assert_ne!(hello.prefix().chain, other.prefix().chain);
        }
        assert!(Hello::decode(&[0; HELLO_BYTES]).is_err());
        let mut trailing = hello.encode();
        trailing.push(0);
        assert!(Hello::decode(&trailing).is_err());
    }

    #[test]
    fn epoch_rejects_corruption_replay_reordering_and_truncation() {
        let prefix = Hello {
            nonce: [1; 32],
            epoch_bytes: 8,
            max_bytes: 50,
        }
        .prefix();
        let epoch = encode_epoch(&prefix, b"verified");
        let next = advance(&prefix, &epoch, 8, 50).unwrap();
        assert_eq!((next.epochs, next.bytes), (1, 8));
        assert!(advance(&next, &epoch, 8, 50).is_err());
        for index in 0..epoch.len() {
            let mut broken = epoch.clone();
            broken[index] ^= 1;
            assert!(advance(&prefix, &broken, 8, 50).is_err(), "byte {index}");
        }
        for end in 0..epoch.len() {
            assert!(advance(&prefix, &epoch[..end], 8, 50).is_err());
        }
    }

    #[test]
    fn epoch_enforces_limits_and_checked_counters() {
        let mut prefix = Hello {
            nonce: [1; 32],
            epoch_bytes: 8,
            max_bytes: 50,
        }
        .prefix();
        assert!(advance(&prefix, &encode_epoch(&prefix, b""), 8, 50).is_err());
        assert!(advance(&prefix, &encode_epoch(&prefix, b"123"), 2, 50).is_err());
        assert!(matches!(
            advance(&prefix, &encode_epoch(&prefix, b"123"), 8, 2),
            Err(LiveStreamError::TooLarge(2))
        ));
        prefix.bytes = u64::MAX;
        assert!(advance(&prefix, &encode_epoch(&prefix, b"x"), 8, u64::MAX).is_err());
        prefix.bytes = 0;
        prefix.epochs = u64::MAX;
        assert!(advance(&prefix, &encode_epoch(&prefix, b"x"), 8, 50).is_err());
    }

    #[test]
    fn admission_is_shared_and_released_without_wrapping() {
        let admission = Arc::new(Admission {
            active: AtomicUsize::new(0),
            capacity: 1,
        });
        let permit = admission.reserve().unwrap();
        assert!(matches!(
            Arc::clone(&admission).reserve(),
            Err(LiveStreamError::Capacity)
        ));
        drop(permit);
        assert!(admission.reserve().is_ok());
        assert_eq!(admission.active.load(Ordering::Relaxed), 0);
    }
