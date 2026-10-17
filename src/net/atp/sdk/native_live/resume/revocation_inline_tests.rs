    use super::*;

    fn id(number: u32) -> NativeClientCertificateId {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&number.to_be_bytes());
        NativeClientCertificateId::from_sha256(bytes)
    }

    #[test]
    fn revocations_are_monotonic_bounded_and_duplicates_cost_no_capacity() {
        let mut denied = Revocations::default();
        for number in 0..MAX_REVOKED_RESUME_CLIENTS as u32 {
            assert_eq!(denied.insert(id(number)), Ok(true));
            assert_eq!(denied.insert(id(number)), Ok(false));
        }
        assert_eq!(denied.insert(id(1024)), Err(ResumeRevokeError::Capacity));
        assert_eq!(denied.0.len(), MAX_REVOKED_RESUME_CLIENTS);
        for number in 0..MAX_REVOKED_RESUME_CLIENTS as u32 {
            assert!(denied.0.contains(&id(number)));
            assert_eq!(denied.insert(id(number)), Ok(false));
        }
        assert!(!denied.0.contains(&id(1024)));
    }
