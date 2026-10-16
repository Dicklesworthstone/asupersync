    use super::*;

    #[test]
    fn authorization_input_is_bounded_even_for_duplicate_or_infinite_inputs() {
        let id = NativeClientCertificateId::from_sha256([7; 32]);
        assert_eq!(bounded_ids([id, id]).unwrap().len(), 1);
        assert!(bounded_ids(std::iter::repeat_n(id, MAX_NATIVE_AUTHORIZED_CLIENTS)).is_ok());
        assert!(matches!(
            bounded_ids(std::iter::repeat(id)),
            Err(NativeAuthenticationError::TooManyClients)
        ));
        assert!(bounded_ids([]).unwrap().is_empty());
    }

    #[test]
    fn complete_certificate_identity_changes_with_any_der_change() {
        let first = CertificateDer::from(vec![1, 2, 3]);
        let second = CertificateDer::from(vec![1, 2, 4]);
        let digest: [u8; 32] = Sha256::digest(first.as_ref()).into();
        assert_eq!(
            NativeClientCertificateId::from_certificate(&first).as_bytes(),
            &digest
        );
        assert_ne!(
            NativeClientCertificateId::from_certificate(&first),
            NativeClientCertificateId::from_certificate(&second)
        );
    }

    #[test]
    fn empty_roots_are_never_replaced_with_ambient_trust() {
        assert!(matches!(
            NativeClientAuthorization::new(RootCertStore::empty(), []),
            Err(NativeAuthenticationError::EmptyRoots)
        ));
    }

    #[test]
    fn identity_debug_does_not_expose_key_or_certificate_bytes() {
        let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            b"test-key-material".to_vec(),
        ));
        let identity = NativeTlsIdentity::new(
            vec![CertificateDer::from(b"test-certificate-material".to_vec())],
            key,
        )
        .unwrap();
        let debug = format!("{identity:?}");
        assert!(debug.contains("NativeTlsIdentity"));
        assert!(!debug.contains("material"));
        assert!(!debug.contains("116, 101, 115, 116"));
    }
