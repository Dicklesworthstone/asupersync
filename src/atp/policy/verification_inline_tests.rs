    use super::*;
    use crate::atp::policy::{CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope};
    use crate::net::atp::protocol::PeerId;
    use std::collections::HashSet;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;

    fn fixed_time(seconds_since_epoch: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds_since_epoch)
    }

    fn fixed_issued_at() -> SystemTime {
        fixed_time(1_800_000_000)
    }

    fn fixed_validation_time() -> SystemTime {
        fixed_time(1_800_000_100)
    }

    fn fixed_valid_temporal_scope() -> TemporalScope {
        TemporalScope::window(fixed_time(1_799_999_900), fixed_time(1_800_003_700))
    }

    const fn strong_test_seed() -> [u8; 32] {
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]
    }

    fn create_test_signer() -> CapabilitySigner {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test-key.json");
        let key_store =
            IdentityKeyStore::create(path, strong_test_seed(), 1).expect("create key store");
        CapabilitySigner::new(key_store).expect("create signer")
    }

    fn create_test_capability(signer: &CapabilitySigner) -> Capability {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let mut capability = Capability::new(
            "test-grant-12345".to_string(),
            PeerId::test(1),
            signer.identity().peer_id(),
            ResourceScope::Any,
            actions,
            fixed_valid_temporal_scope(),
            ScopeConstraints::default(),
        );
        capability.issued_at = fixed_issued_at();
        capability
    }

    #[test]
    fn capability_signing_and_verification() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);

        // Sign the capability
        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle
        assert!(!capability.signature.is_empty());

        // Create verifier and add trusted peer
        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        // Verify the capability
        let valid = verifier
            .verify_capability(&capability)
            .expect("verify capability"); // ubs:ignore - test oracle
        assert!(valid);
    }

    #[test]
    fn capability_verification_rejects_tampered_signed_field() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);
        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        capability.grant_id.push_str("-tampered");

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let valid = verifier
            .verify_capability(&capability)
            .expect("verify tampered capability"); // ubs:ignore - test oracle
        assert!(!valid);

        let result = verifier
            .validate_capability_at(&capability, fixed_validation_time())
            .expect("validate tampered capability"); // ubs:ignore - test oracle
        assert!(!result.valid);
        assert!(result.issues.contains(&ValidationIssue::InvalidSignature));
    }

    #[test]
    fn capability_verification_rejects_tampered_signature() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);
        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        capability.signature[0] ^= 0x01;

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let valid = verifier
            .verify_capability(&capability)
            .expect("verify tampered signature"); // ubs:ignore - test oracle
        assert!(!valid);
    }

    #[test]
    fn capability_validation_rejects_missing_signature() {
        let signer = create_test_signer();
        let capability = create_test_capability(&signer);

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let valid = verifier
            .verify_capability(&capability)
            .expect("verify unsigned capability"); // ubs:ignore - test oracle
        assert!(!valid);

        let result = verifier
            .validate_capability_at(&capability, fixed_validation_time())
            .expect("validate unsigned capability"); // ubs:ignore - test oracle
        assert!(!result.valid);
        assert!(result.issues.contains(&ValidationIssue::InvalidSignature));
    }

    #[test]
    fn capability_validation_detects_issues() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);

        // Create invalid capability (empty actions)
        capability.actions.clear();

        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let result = verifier
            .validate_capability_at(&capability, fixed_validation_time())
            .expect("validate capability");
        assert!(!result.valid);
        assert!(result.issues.contains(&ValidationIssue::NoActions));
    }

    #[test]
    fn expired_capability_validation() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);

        // Set capability to expire in the past
        let past = fixed_validation_time() - Duration::from_secs(100);
        capability.temporal = TemporalScope::window(past - Duration::from_secs(100), past);

        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        let mut verifier = CapabilityVerifier::new();
        verifier.add_trusted_peer(signer.identity().clone());

        let result = verifier
            .validate_capability_at(&capability, fixed_validation_time())
            .expect("validate capability");
        assert!(!result.valid);
        assert!(result.issues.contains(&ValidationIssue::TemporalViolation));
    }

    #[test]
    fn untrusted_issuer_verification_fails() {
        let signer = create_test_signer();
        let mut capability = create_test_capability(&signer);
        signer
            .sign_capability(&mut capability)
            .expect("sign capability"); // ubs:ignore - test oracle

        // Create verifier without adding the trusted peer
        let verifier = CapabilityVerifier::new();

        let result = verifier.verify_capability(&capability);
        assert!(result.is_err());
    }

    #[test]
    fn signing_data_is_deterministic() {
        let signer = create_test_signer();
        let capability1 = create_test_capability(&signer);
        let capability2 = create_test_capability(&signer);

        let data1 = signer
            .create_signing_data(&capability1)
            .expect("create signing data");
        let data2 = signer
            .create_signing_data(&capability2)
            .expect("create signing data");

        assert_eq!(data1, data2);
    }
