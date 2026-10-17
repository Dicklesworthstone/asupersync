    use super::*;
    use super::super::super::{NativeClientCertificateId, digest, initial, offer};
    use crate::io::ReadBuf;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use zeroize::Zeroizing;

    fn saved() -> ReceiverCheckpoint {
        let hello = Hello { nonce: [9; 32], epoch_bytes: 8, max_bytes: 64 };
        ReceiverCheckpoint {
            client: NativeClientCertificateId::from_sha256([3; 32]),
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            prefix: initial(&hello),
            prefix_hash: digest(&Sha256::new()),
            pending_hash: digest(&Sha256::new()),
            used: 1,
            maximum: 4,
            phase: ReceiverCheckpointPhase::Receiving,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    fn profile() -> LiveStreamConfig {
        LiveStreamConfig { epoch_bytes: 8, max_bytes: 64, ..LiveStreamConfig::default() }
    }

    #[test]
    fn shared_restoration_binds_the_full_key_and_current_resource_policy() {
        let saved = saved();
        let key = ResumeSessionKey { client: saved.client, nonce: [9; 32] };
        assert!(validate_binding(&saved, key, &profile(), 4).is_ok());
        for changed in [
            ResumeSessionKey { nonce: [8; 32], ..key },
            ResumeSessionKey { client: NativeClientCertificateId::from_sha256([4; 32]), ..key },
        ] {
            assert!(matches!(validate_binding(&saved, changed, &profile(), 4),
                Err(LiveStreamError::Configuration("receiver journal does not match authenticated session key"))));
        }
        for (config, maximum) in [
            (LiveStreamConfig { epoch_bytes: 4, ..profile() }, 4),
            (LiveStreamConfig { max_bytes: 63, ..profile() }, 4),
            (profile(), 3),
        ] {
            assert!(matches!(validate_binding(&saved, key, &config, maximum),
                Err(LiveStreamError::Configuration("receiver journal exceeds shared service policy"))));
        }
    }

    #[test]
    fn policy_validation_does_not_rewrite_history_or_revive_uncertain_commits() {
        let mut saved = saved();
        let key = ResumeSessionKey { client: saved.client, nonce: [9; 32] };
        let before = saved.to_canonical_bytes().unwrap();
        assert!(validate_binding(&saved, key, &profile(), 8).is_ok());
        assert_eq!(saved.maximum_attempts(), 4);
        assert_eq!(saved.to_canonical_bytes().unwrap().as_slice(), before.as_slice());
        saved.phase = ReceiverCheckpointPhase::Finalizing;
        assert!(matches!(validate_binding(&saved, key, &profile(), 4),
            Err(LiveStreamError::Configuration("receiver application commit remains unresolved"))));
        saved.phase = ReceiverCheckpointPhase::Committed;
        assert!(validate_binding(&saved, key, &profile(), 4).is_ok());
        saved.used = 4;
        assert!(matches!(validate_binding(&saved, key, &profile(), 4),
            Err(LiveStreamError::Configuration("receiver journal attempt budget exhausted"))));
    }

    struct Untouched;
    impl ReceiverCheckpointStore for Untouched {
        fn poll_store(self: Pin<&mut Self>, _: &mut Context<'_>, _: &ReceiverCheckpoint) -> Poll<io::Result<()>> {
            panic!("session construction must not persist");
        }
    }
    impl AsyncRead for Untouched {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            panic!("session construction must not read");
        }
    }

    #[test]
    fn constructing_or_debugging_a_factory_result_does_not_drive_providers() {
        let fresh = JournaledSession::new((), Untouched);
        let restored = JournaledSession::restore((), Untouched, Untouched, saved());
        assert_eq!(format!("{fresh:?}"), "JournaledSession { restoring: false, .. }");
        assert_eq!(format!("{restored:?}"), "JournaledSession { restoring: true, .. }");
    }
