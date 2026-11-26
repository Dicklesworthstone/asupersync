use super::*;
use std::mem;
use tempfile::tempdir;

fn strong_seed(tag: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync::security::keys::tests");
    hasher.update([tag]);
    hasher.finalize().into()
}

#[test]
fn owned_nkey_kinds_are_exact_and_never_fallback() {
    for (name, symbol, kind, prefix) in [
        ("Account", "A", NkeyEd25519Kind::Account, 0),
        ("Cluster", "C", NkeyEd25519Kind::Cluster, 16),
        ("Module", "M", NkeyEd25519Kind::Module, 96),
        ("Server", "N", NkeyEd25519Kind::Server, 104),
        ("Operator", "O", NkeyEd25519Kind::Operator, 112),
        ("User", "U", NkeyEd25519Kind::User, 160),
        ("Service", "V", NkeyEd25519Kind::Service, 168),
    ] {
        assert_eq!(name.parse(), Ok(kind));
        assert_eq!(symbol.parse(), Ok(kind));
        assert_eq!(kind.to_string(), name);
        assert_eq!(kind.symbol().to_string(), symbol);
        assert_eq!(kind.prefix_byte(), prefix);
    }

    for unknown in ["", "Curve", "X", "Unknown", "user", " User"] {
        assert_eq!(
            unknown.parse::<NkeyEd25519Kind>(),
            Err(NkeyOwnedKeyError::UnknownEd25519Kind {
                actual_len: unknown.len(),
            })
        );
    }
}

#[test]
fn owned_public_forms_are_copyable_comparable_and_type_separated() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_copy<T: Copy>() {}

    assert_send_sync::<NkeyEd25519PublicKey>();
    assert_send_sync::<NkeyCurvePublicKey>();
    assert_copy::<NkeyEd25519PublicKey>();
    assert_copy::<NkeyCurvePublicKey>();

    let user = NkeyEd25519PublicKey::from_bytes(NkeyEd25519Kind::User, [0x11; 32]);
    let account = NkeyEd25519PublicKey::from_bytes(NkeyEd25519Kind::Account, [0x11; 32]);
    let curve = NkeyCurvePublicKey::from_bytes([0x11; 32]);
    assert_ne!(user, account, "the Ed25519 role is part of identity");
    assert_eq!(user.kind(), NkeyEd25519Kind::User);
    assert_eq!(user.into_bytes(), [0x11; 32]);
    assert_eq!(curve.into_bytes(), [0x11; 32]);
    assert_eq!(
        NkeyEd25519PublicKey::try_from_slice(NkeyEd25519Kind::User, &[0x11; 32]),
        Ok(user)
    );
    assert_eq!(NkeyCurvePublicKey::try_from_slice(&[0x11; 32]), Ok(curve));
}

#[test]
fn owned_secret_forms_require_explicit_disposition_and_zeroize_exports() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_signer<T: NkeyEd25519SigningMaterial>(value: &T, expected: NkeyEd25519Kind) {
        assert_eq!(value.kind(), expected);
    }

    assert_send_sync::<NkeyEd25519Seed>();
    assert_send_sync::<NkeyEd25519PrivateKey>();
    assert_send_sync::<NkeyCurveSecretKey>();
    assert!(mem::needs_drop::<NkeyEd25519Seed>());
    assert!(mem::needs_drop::<NkeyEd25519PrivateKey>());
    assert!(mem::needs_drop::<NkeyCurveSecretKey>());
    assert!(mem::needs_drop::<NkeySecretExport<32>>());

    let seed = NkeyEd25519Seed::from_bytes(NkeyEd25519Kind::User, [0x21; 32]);
    let private = NkeyEd25519PrivateKey::from_bytes(NkeyEd25519Kind::Operator, [0x42; 64]);
    let curve = NkeyCurveSecretKey::from_bytes([0x63; 32]);
    assert_signer(&seed, NkeyEd25519Kind::User);
    assert_signer(&private, NkeyEd25519Kind::Operator);

    assert!(matches!(
        seed.export_secret(NkeySecretDisposition::InProcessOperation),
        Err(NkeyOwnedKeyError::SecretDisposition {
            disposition: NkeySecretDisposition::InProcessOperation
        })
    ));

    let mut seed_export = seed
        .export_secret(NkeySecretDisposition::PlaintextSerialization)
        .expect("serialization requires an explicit export guard");
    assert_eq!(
        seed_export.disposition(),
        NkeySecretDisposition::PlaintextSerialization
    );
    assert_eq!(seed_export.as_bytes(), &[0x21; 32]);
    seed_export.zeroize();
    assert_eq!(seed_export.as_bytes(), &[0; 32]);

    let private_export = private
        .export_secret(NkeySecretDisposition::PlaintextPersistence)
        .expect("persistence requires an explicit export guard");
    assert_eq!(private_export.as_bytes(), &[0x42; 64]);

    let curve_export = curve
        .export_secret(NkeySecretDisposition::PlaintextExport)
        .expect("Curve secret export is explicit and zeroizing");
    assert_eq!(curve_export.as_bytes(), &[0x63; 32]);
}

#[test]
fn owned_key_constructors_reject_every_wrong_length_without_echoing_bytes() {
    for actual in [0, 1, 31, 33, 63, 65] {
        let bytes = vec![0xa5; actual];
        let seed_error = NkeyEd25519Seed::try_from_slice(NkeyEd25519Kind::User, &bytes)
            .expect_err("all non-32-byte seed lengths fail");
        assert_eq!(
            seed_error,
            NkeyOwnedKeyError::Length {
                form: NkeyOwnedKeyForm::Ed25519Seed,
                actual,
                expected: 32,
            }
        );
        assert!(!seed_error.to_string().contains("a5"));
    }

    for actual in [0, 1, 32, 63, 65] {
        let bytes = vec![0x5a; actual];
        assert_eq!(
            NkeyEd25519PrivateKey::try_from_slice(NkeyEd25519Kind::Account, &bytes)
                .expect_err("all non-64-byte private lengths fail"),
            NkeyOwnedKeyError::Length {
                form: NkeyOwnedKeyForm::Ed25519Private,
                actual,
                expected: 64,
            }
        );
    }

    assert_eq!(
        NkeyCurvePublicKey::try_from_slice(&[0; 31]),
        Err(NkeyOwnedKeyError::Length {
            form: NkeyOwnedKeyForm::CurvePublic,
            actual: 31,
            expected: 32,
        })
    );
    assert!(matches!(
        NkeyCurveSecretKey::try_from_slice(&[0; 33]),
        Err(NkeyOwnedKeyError::Length {
            form: NkeyOwnedKeyForm::CurveSecret,
            actual: 33,
            expected: 32,
        })
    ));
}

#[test]
fn owned_secret_canary_is_redacted_from_formatting_errors_and_panics() {
    #[derive(Clone)]
    struct TraceBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for TraceBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("trace buffer lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const CANARY: &[u8; 32] = b"NKEY-SECRET-CANARY-0123456789ABC";
    let canary_text = std::str::from_utf8(CANARY).expect("ASCII canary");
    let seed = NkeyEd25519Seed::from_bytes(NkeyEd25519Kind::User, *CANARY);
    let curve = NkeyCurveSecretKey::from_bytes(*CANARY);
    let export = seed
        .export_secret(NkeySecretDisposition::PlaintextExport)
        .expect("explicit canary export");

    for rendered in [
        format!("{seed:?}"),
        seed.to_string(),
        format!("{curve:?}"),
        curve.to_string(),
        format!("{export:?}"),
        export.to_string(),
        NkeyOwnedKeyError::SecretDisposition {
            disposition: NkeySecretDisposition::InProcessOperation,
        }
        .to_string(),
    ] {
        assert!(!rendered.contains(canary_text));
        assert!(
            rendered.to_ascii_lowercase().contains("redacted")
                || rendered.contains("not permitted")
        );
    }

    let panic = std::panic::catch_unwind(|| panic!("{seed:?}"))
        .expect_err("redacted debug panic is captured");
    let panic_text = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("panic text");
    assert!(!panic_text.contains(canary_text));
    assert!(panic_text.contains("<redacted>"));

    let trace_bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer_bytes = std::sync::Arc::clone(&trace_bytes);
    let disposition_error = NkeyOwnedKeyError::SecretDisposition {
        disposition: NkeySecretDisposition::InProcessOperation,
    };
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || TraceBuffer(std::sync::Arc::clone(&writer_bytes)))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(
            seed = ?seed,
            curve = ?curve,
            export = ?export,
            error = ?disposition_error,
            "NKey secret redaction canary"
        );
    });
    let trace = String::from_utf8(trace_bytes.lock().expect("trace buffer lock").clone())
        .expect("trace output is UTF-8");
    assert!(!trace.contains(canary_text));
    assert!(trace.contains("<redacted>"));
}

#[test]
fn ver_a1_asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d_local_invariants() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_copy<T: Copy>() {}

    assert_copy::<NkeyEd25519PublicKey>();
    assert_copy::<NkeyCurvePublicKey>();
    assert_send_sync::<NkeyEd25519Seed>();
    assert_send_sync::<NkeyEd25519PrivateKey>();
    assert_send_sync::<NkeyCurveSecretKey>();
    assert!(mem::needs_drop::<NkeyEd25519Seed>());
    assert!(mem::needs_drop::<NkeyEd25519PrivateKey>());
    assert!(mem::needs_drop::<NkeyCurveSecretKey>());

    let user = NkeyEd25519PublicKey::from_bytes(NkeyEd25519Kind::User, [0x41; 32]);
    let curve = NkeyCurvePublicKey::from_bytes([0x41; 32]);
    assert_eq!(user.kind(), NkeyEd25519Kind::User);
    assert_eq!(user.as_bytes(), &[0x41; 32]);
    assert_eq!(curve.as_bytes(), &[0x41; 32]);
    assert_ne!(format!("{user:?}"), format!("{curve:?}"));

    let seed = NkeyEd25519Seed::from_bytes(NkeyEd25519Kind::User, [0x51; 32]);
    assert!(matches!(
        seed.export_secret(NkeySecretDisposition::InProcessOperation),
        Err(NkeyOwnedKeyError::SecretDisposition {
            disposition: NkeySecretDisposition::InProcessOperation
        })
    ));
}

#[test]
fn ver_a1_asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d_property_matrix() {
    const KINDS: [NkeyEd25519Kind; 7] = [
        NkeyEd25519Kind::Account,
        NkeyEd25519Kind::Cluster,
        NkeyEd25519Kind::Module,
        NkeyEd25519Kind::Server,
        NkeyEd25519Kind::Operator,
        NkeyEd25519Kind::User,
        NkeyEd25519Kind::Service,
    ];

    for case in 0u8..64 {
        let kind = KINDS[usize::from(case) % KINDS.len()];
        let bytes = [case; NKEY_KEY_BYTES];
        let public = NkeyEd25519PublicKey::try_from_slice(kind, &bytes)
            .expect("every exact-width public key is retained exactly");
        let curve_public = NkeyCurvePublicKey::try_from_slice(&bytes)
            .expect("every exact-width Curve public key is retained exactly");
        let seed = NkeyEd25519Seed::try_from_slice(kind, &bytes)
            .expect("every exact-width seed is retained exactly");
        let curve_secret = NkeyCurveSecretKey::try_from_slice(&bytes)
            .expect("every exact-width Curve secret is retained exactly");

        assert_eq!(public.kind(), kind);
        assert_eq!(public.as_bytes(), &bytes);
        assert_eq!(curve_public.as_bytes(), &bytes);

        let seed_export = seed
            .export_secret(NkeySecretDisposition::PlaintextSerialization)
            .expect("explicit serialization disposition permits a guarded export");
        let curve_export = curve_secret
            .export_secret(NkeySecretDisposition::PlaintextExport)
            .expect("explicit export disposition permits a guarded export");
        assert_eq!(seed_export.as_bytes(), &bytes);
        assert_eq!(curve_export.as_bytes(), &bytes);
        assert_eq!(
            seed_export.disposition(),
            NkeySecretDisposition::PlaintextSerialization
        );
        assert_eq!(
            curve_export.disposition(),
            NkeySecretDisposition::PlaintextExport
        );
    }
}

#[test]
fn ver_a1_asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d_lab_lifecycle() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct SecretDropProbe {
        _secret: NkeyCurveSecretKey,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for SecretDropProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    let entered = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let task_entered = Arc::clone(&entered);
    let task_drops = Arc::clone(&drops);
    let probe = SecretDropProbe {
        _secret: NkeyCurveSecretKey::from_bytes([0x73; NKEY_KEY_BYTES]),
        drops: task_drops,
    };

    let mut runtime = crate::lab::runtime::LabRuntime::new(
        crate::lab::config::LabConfig::new(37)
            .max_steps(128)
            .panic_on_leak(false),
    );
    let root = runtime.state.create_root_region(crate::Budget::INFINITE);
    let (task_id, _handle) = runtime
        .state
        .create_task(root, crate::Budget::INFINITE, async move {
            let _probe = probe;
            task_entered.store(true, Ordering::SeqCst);
            loop {
                crate::runtime::yield_now::yield_now().await;
                if crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err())
                    .expect("lab task installs a current Cx")
                {
                    break;
                }
            }
        })
        .expect("create secret-owning task");
    runtime
        .scheduler
        .lock()
        .schedule(task_id, crate::Budget::INFINITE.priority);
    runtime.step_for_test();

    assert!(
        entered.load(Ordering::SeqCst),
        "task reached secret-owning state"
    );
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "secret remains owned before cancellation"
    );

    let reason = crate::CancelReason::user("NKey secret lifecycle test");
    let effects = runtime.state.cancel_task(task_id, &reason);
    let (cancelled, wake_effects) = effects.into_parts();
    assert!(cancelled, "cancellation is recorded for the live task");
    runtime
        .scheduler
        .lock()
        .schedule_cancel(task_id, reason.cleanup_budget().priority);
    wake_effects.dispatch();
    runtime.run_until_quiescent();

    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "secret owner drops exactly once"
    );
    assert_eq!(
        runtime.state.live_task_count(),
        0,
        "cancelled task is retired"
    );
    assert_eq!(
        runtime.state.pending_obligation_count(),
        0,
        "secret lifecycle leaves no pending obligations"
    );
}

#[test]
fn transcript_signing_roundtrips_exact_bytes_and_public_verifiers() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    let store = IdentityKeyStore::create(&path, strong_seed(20), 100).expect("create store");
    let profile = TranscriptSigningProfile::Ed25519Sha256V1;
    let domain = b"frankengraphdb:checkpoint:v1";
    let transcript = b"\0checkpoint\xff\n{\"epoch\":7,\"root\":\"abc\"}";
    let signature = store
        .sign_transcript(profile, domain, transcript)
        .expect("sign exact bytes");
    let public = store.export_public().expect("public identity");
    // Independent wire vector: Python cryptography 50's Ed25519 plus
    // hashlib.sha256 and binascii.crc_hqx for the NKey public encoding.
    assert_eq!(
        public.public_key,
        "UDLMG66HZDPUNEEGMQFYMSVJU3L6FEDIMGFA6WNYR7E5QBGVSBIWAZLC"
    );
    const EXPECTED: [u8; IDENTITY_TRANSCRIPT_SIGNATURE_BYTES] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2f, 0x32, 0x47,
        0x02, 0xdf, 0xcb, 0x1b, 0x36, 0xa1, 0x0e, 0x0c, 0x5a, 0xf0, 0x53, 0xde,
        0x68, 0x64, 0x83, 0xdc, 0xf9, 0x20, 0xee, 0xa3, 0x4c, 0x90, 0x48, 0x2d,
        0x40, 0x25, 0xc3, 0x31, 0xae, 0x8d, 0x27, 0x68, 0xd9, 0x60, 0x5c, 0x40,
        0xc1, 0x26, 0x79, 0xea, 0x81, 0x67, 0xb4, 0x5e, 0x7c, 0x8c, 0x80, 0x1b,
        0x31, 0xbb, 0x23, 0x63, 0x0c, 0x23, 0x74, 0x49, 0xae, 0x7d, 0x33, 0x03,
        0xfa, 0x03, 0x00, 0xcf, 0xc8, 0x43, 0x4a, 0x4e, 0x71, 0xc3, 0x55, 0xc0,
        0x51, 0x06, 0x65, 0x3b, 0x6e, 0xf0, 0x62, 0x27, 0xcc, 0xc4, 0x65, 0x30,
        0xe3, 0x49, 0x29, 0xfa, 0x5e, 0x42, 0xbd, 0xce, 0x07,
    ];
    assert_eq!(signature.to_bytes(), EXPECTED);
    let verifier = IdentityTranscriptVerificationKey::from_public_identity(
        profile,
        &public,
        store.active_generation(),
    )
    .expect("import trusted public identity");

    assert_eq!(signature.profile(), profile);
    assert_eq!(signature.generation(), public.generation);
    assert_eq!(signature.fingerprint(), public.fingerprint);
    assert_eq!(verifier.public_identity(), &public);
    assert_eq!(
        verifier.verify_transcript(domain, transcript, &signature),
        Ok(())
    );
    assert_eq!(
        store.verify_transcript(domain, transcript, &signature),
        Ok(())
    );
    let decoded = IdentityTranscriptSignature::from_bytes(&EXPECTED)
        .expect("decode independent public signature");
    assert_eq!(decoded, signature);
    assert_eq!(
        verifier.verify_transcript(domain, transcript, &decoded),
        Ok(())
    );

    let loaded = IdentityKeyStore::load(&path).expect("reload store");
    assert_eq!(
        loaded
            .sign_transcript(profile, domain, transcript)
            .expect("sign after reload"),
        signature,
        "the explicit profile and same durable identity produce a stable signature"
    );
    let seed = &store.record.keys[0].seed;
    assert!(!format!("{signature:?}").contains(seed));
    assert!(!format!("{verifier:?}").contains(seed));
}

#[test]
fn transcript_signatures_bind_domain_boundaries_and_exact_payload_bytes() {
    let dir = tempdir().expect("tempdir");
    let store =
        IdentityKeyStore::create(dir.path().join("identity.json"), strong_seed(21), 100)
            .expect("create store");
    let profile = TranscriptSigningProfile::Ed25519Sha256V1;
    let signature = store
        .sign_transcript(profile, b"ab", b"c\0")
        .expect("sign");
    for (domain, transcript) in [
        (b"a".as_slice(), b"bc\0".as_slice()),
        (b"ab".as_slice(), b"c".as_slice()),
        (b"ab\0".as_slice(), b"c\0".as_slice()),
        (b"ab".as_slice(), b"C\0".as_slice()),
    ] {
        assert_eq!(
            store.verify_transcript(domain, transcript, &signature),
            Err(IdentityTranscriptError::Verification)
        );
    }

    let max_domain = [0xff; 255];
    let empty = store
        .sign_transcript(profile, &max_domain, b"")
        .expect("empty transcript");
    assert_eq!(store.verify_transcript(&max_domain, b"", &empty), Ok(()));
    assert_eq!(
        store.sign_transcript(profile, b"", b"payload"),
        Err(IdentityTranscriptError::Domain)
    );
    assert_eq!(
        store.sign_transcript(profile, &[0; 256], b"payload"),
        Err(IdentityTranscriptError::Domain)
    );
    assert_eq!(
        store.verify_transcript(b"", b"c\0", &signature),
        Err(IdentityTranscriptError::Domain)
    );
}

#[test]
fn transcript_signature_envelopes_reject_malformed_and_unknown_profiles() {
    for actual in [0, 1, 64, 104, 106, 128] {
        assert_eq!(
            IdentityTranscriptSignature::from_bytes(&vec![0; actual]),
            Err(IdentityTranscriptError::SignatureLength { actual })
        );
    }
    let mut wire = [0; IDENTITY_TRANSCRIPT_SIGNATURE_BYTES];
    wire[8] = 1;
    for profile in [0, 2, 255] {
        wire[0] = profile;
        assert_eq!(
            IdentityTranscriptSignature::from_bytes(&wire),
            Err(IdentityTranscriptError::UnknownProfile(profile))
        );
    }
    wire[0] = TranscriptSigningProfile::Ed25519Sha256V1.wire_id();
    wire[8] = 0;
    assert_eq!(
        IdentityTranscriptSignature::from_bytes(&wire),
        Err(IdentityTranscriptError::InvalidGeneration)
    );
}

#[test]
fn transcript_signatures_reject_key_generation_and_signature_substitution() {
    let dir = tempdir().expect("tempdir");
    let first = IdentityKeyStore::create(dir.path().join("first.json"), strong_seed(22), 100)
        .expect("first store");
    let second = IdentityKeyStore::create(dir.path().join("second.json"), strong_seed(23), 100)
        .expect("second store");
    let profile = TranscriptSigningProfile::Ed25519Sha256V1;
    let signature = first
        .sign_transcript(profile, b"test:v1", b"payload")
        .expect("sign");
    let verifier = first
        .transcript_verification_key(profile)
        .expect("verifier");
    assert_eq!(
        second.verify_transcript(b"test:v1", b"payload", &signature),
        Err(IdentityTranscriptError::IdentityMismatch)
    );

    let mut wire = signature.to_bytes();
    wire[1..9].copy_from_slice(&2_u64.to_be_bytes());
    let retagged = IdentityTranscriptSignature::from_bytes(&wire).expect("retag generation");
    assert_eq!(
        verifier.verify_transcript(b"test:v1", b"payload", &retagged),
        Err(IdentityTranscriptError::IdentityMismatch)
    );
    assert_eq!(
        first.verify_transcript(b"test:v1", b"payload", &retagged),
        Err(IdentityTranscriptError::InactiveGeneration)
    );

    let mut wire = signature.to_bytes();
    let other_public = second.export_public().expect("second identity");
    wire[9..41].copy_from_slice(&other_public.fingerprint.as_bytes());
    let retagged = IdentityTranscriptSignature::from_bytes(&wire).expect("retag fingerprint");
    assert_eq!(
        second.verify_transcript(b"test:v1", b"payload", &retagged),
        Err(IdentityTranscriptError::Verification),
        "rewriting the envelope cannot transfer a signature to another key"
    );

    let mut wire = signature.to_bytes();
    wire[41..].fill(0);
    let forged = IdentityTranscriptSignature::from_bytes(&wire).expect("framed forgery");
    assert_eq!(
        verifier.verify_transcript(b"test:v1", b"payload", &forged),
        Err(IdentityTranscriptError::Verification)
    );
}

#[test]
fn transcript_verifier_import_rejects_untrusted_or_malformed_identity_metadata() {
    let dir = tempdir().expect("tempdir");
    let store = IdentityKeyStore::create(dir.path().join("identity.json"), strong_seed(24), 100)
        .expect("create store");
    let profile = TranscriptSigningProfile::Ed25519Sha256V1;
    let public = store.export_public().expect("public identity");
    let import = |identity: &PublicIdentityKey, active| {
        IdentityTranscriptVerificationKey::from_public_identity(profile, identity, active)
            .expect_err("invalid identity must fail closed")
    };
    assert_eq!(
        import(&public, 0),
        IdentityTranscriptError::InvalidGeneration
    );
    assert_eq!(
        import(&public, 2),
        IdentityTranscriptError::InactiveGeneration
    );
    let mut invalid = public.clone();
    invalid.revoked = true;
    assert_eq!(import(&invalid, 1), IdentityTranscriptError::Revoked);
    let mut invalid = public.clone();
    invalid.fingerprint = KeyFingerprint([0; 32]);
    assert_eq!(
        import(&invalid, 1),
        IdentityTranscriptError::FingerprintMismatch
    );
    let mut invalid = public.clone();
    invalid.public_key = KeyPair::new_from_raw(KeyPairType::Account, strong_seed(25))
        .expect("account key")
        .public_key();
    assert_eq!(import(&invalid, 1), IdentityTranscriptError::PublicKey);
    let mut invalid = public.clone();
    invalid.public_key.make_ascii_lowercase();
    assert_eq!(import(&invalid, 1), IdentityTranscriptError::PublicKey);
    let mut invalid = public;
    invalid.public_key.clone_from(&store.record.keys[0].seed);
    let error = import(&invalid, 1);
    assert_eq!(error, IdentityTranscriptError::PublicKey);
    assert!(!error.to_string().contains(&invalid.public_key));
    assert!(!format!("{error:?}").contains(&invalid.public_key));
}

#[test]
fn transcript_verification_tracks_rotation_and_revocation_in_current_store() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    let mut store = IdentityKeyStore::create(&path, strong_seed(26), 100).expect("create store");
    let profile = TranscriptSigningProfile::Ed25519Sha256V1;
    let old_public = store.export_public().expect("old identity");
    let old_verifier = store
        .transcript_verification_key(profile)
        .expect("old verifier");
    let old_signature = store
        .sign_transcript(profile, b"test:v1", b"payload")
        .expect("sign");
    let new_public = store.rotate(strong_seed(27), 200).expect("rotate");
    assert_eq!(
        store.verify_transcript(b"test:v1", b"payload", &old_signature),
        Err(IdentityTranscriptError::InactiveGeneration)
    );
    assert_eq!(
        IdentityTranscriptVerificationKey::from_public_identity(
            profile,
            &old_public,
            new_public.generation,
        )
        .expect_err("retired key cannot become a current verifier"),
        IdentityTranscriptError::InactiveGeneration
    );
    assert_eq!(
        old_verifier.verify_transcript(b"test:v1", b"payload", &old_signature),
        Ok(()),
        "detached verifiers are explicitly public trust snapshots"
    );
    let current = store
        .sign_transcript(profile, b"test:v1", b"payload")
        .expect("sign after rotation");
    assert_eq!(current.generation(), new_public.generation);
    assert_eq!(current.fingerprint(), new_public.fingerprint);
    assert_ne!(current, old_signature);
    assert_eq!(
        store.verify_transcript(b"test:v1", b"payload", &current),
        Ok(())
    );

    let revoked = store
        .revoke(old_public.fingerprint, 300)
        .expect("revoke old identity");
    assert_eq!(
        IdentityTranscriptVerificationKey::from_public_identity(profile, &revoked, revoked.generation)
            .expect_err("revoked public record is rejected"),
        IdentityTranscriptError::Revoked
    );
    let loaded = IdentityKeyStore::load(&path).expect("load rotated store");
    for current_store in [&store, &loaded] {
        assert_eq!(
            current_store.verify_transcript(b"test:v1", b"payload", &old_signature),
            Err(IdentityTranscriptError::Revoked)
        );
        assert_eq!(
            current_store.verify_transcript(b"test:v1", b"payload", &current),
            Ok(())
        );
    }
}

#[test]
fn transcript_signing_keeps_the_durable_identity_after_failed_rotation() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    let mut store = IdentityKeyStore::create(&path, strong_seed(28), 100).expect("create store");
    let profile = TranscriptSigningProfile::Ed25519Sha256V1;
    let signature = store
        .sign_transcript(profile, b"test:v1", b"payload")
        .expect("sign");
    let pending = pending_path(&path).expect("pending path");
    fs::create_dir(&pending).expect("block persistence");
    assert!(store.rotate(strong_seed(29), 200).is_err());
    assert_eq!(
        store
            .sign_transcript(profile, b"test:v1", b"payload")
            .expect("sign after failed rotation"),
        signature
    );
    assert_eq!(
        store.verify_transcript(b"test:v1", b"payload", &signature),
        Ok(())
    );
    let loaded = IdentityKeyStore::load(&path).expect("load unchanged identity");
    assert_eq!(
        loaded.verify_transcript(b"test:v1", b"payload", &signature),
        Ok(())
    );
}

#[test]
fn create_load_and_export_public_identity_key() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    let store = IdentityKeyStore::create(&path, strong_seed(1), 100).expect("create store");
    let exported = store.export_public().expect("export public");

    assert_eq!(exported.generation, 1);
    assert!(!exported.revoked);
    assert_eq!(
        exported.fingerprint,
        KeyFingerprint::from_public_key(exported.public_key.as_bytes()).expect("fingerprint")
    );

    let loaded = IdentityKeyStore::load(&path).expect("load store");
    assert_eq!(loaded.export_public().unwrap(), exported);
    assert_eq!(loaded.platform(), KeyStorePlatform::current());
}

#[test]
fn debug_redacts_persisted_seed_material() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    let store = IdentityKeyStore::create(&path, strong_seed(4), 100).expect("create store");
    let persisted_seed = store.record.keys[0].seed.clone();

    let store_debug = format!("{store:?}");
    assert!(
        !store_debug.contains(&persisted_seed),
        "IdentityKeyStore Debug must not expose persisted NKey seed"
    );
    assert!(
        store_debug.contains("seed: \"<redacted>\""),
        "IdentityKeyStore Debug should show that seed material was redacted"
    );

    let key_debug = format!("{:?}", store.record.keys[0]);
    assert!(
        !key_debug.contains(&persisted_seed),
        "PersistedIdentityKey Debug must not expose persisted NKey seed"
    );
    assert!(
        key_debug.contains("seed: \"<redacted>\""),
        "PersistedIdentityKey Debug should show that seed material was redacted"
    );
}

#[test]
fn rotate_then_revoke_retired_generation() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    let mut store = IdentityKeyStore::create(&path, strong_seed(2), 100).expect("create store");
    let old = store.export_public().expect("old public");
    let new = store.rotate(strong_seed(3), 200).expect("rotate");

    assert_eq!(new.generation, 2);
    assert_ne!(old.fingerprint, new.fingerprint);
    assert_eq!(store.active_generation(), 2);

    let revoked = store.revoke(old.fingerprint, 300).expect("revoke old");
    assert!(revoked.revoked);
    assert_eq!(
        store.revoke(new.fingerprint, 400).unwrap_err().to_string(),
        format!("cannot revoke active key {}", new.fingerprint)
    );

    let loaded = IdentityKeyStore::load(&path).expect("load rotated store");
    let history = loaded.export_public_history().expect("history");
    assert_eq!(history.len(), 2);
    assert!(history[0].revoked);
    assert!(!history[1].revoked);
}

/// asupersync-s45073 L6: a rotation or revocation the store cannot persist
/// leaves the in-memory store equal to the file, so a restart changes
/// nothing. Before, memory moved first: the active key was one the file
/// did not have, and a revoked key was valid again after a restart.
#[test]
fn a_rotation_that_cannot_persist_leaves_the_store_unchanged() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    let mut store = IdentityKeyStore::create(&path, strong_seed(6), 100).expect("create store");
    let first = store.export_public().expect("first public");
    let pending = pending_path(&path).expect("pending path");

    // A directory at the pending path makes every persist fail.
    fs::create_dir(&pending).expect("block persistence");
    assert!(store.rotate(strong_seed(7), 200).is_err());
    assert_eq!(store.active_generation(), 1);
    assert_eq!(
        store.export_public().expect("active").fingerprint,
        first.fingerprint
    );
    assert_eq!(store.export_public_history().expect("history").len(), 1);

    fs::remove_dir(&pending).expect("unblock persistence");
    let second = store.rotate(strong_seed(7), 300).expect("rotate");
    assert_eq!(second.generation, 2, "a failed rotation uses no generation");
}

/// asupersync-s45073 L6: see the rotation test above.
#[test]
fn a_revocation_that_cannot_persist_leaves_the_key_valid() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    let mut store = IdentityKeyStore::create(&path, strong_seed(8), 100).expect("create store");
    let first = store.export_public().expect("first public");
    store.rotate(strong_seed(9), 200).expect("rotate");
    let pending = pending_path(&path).expect("pending path");

    // A directory at the pending path makes every persist fail.
    fs::create_dir(&pending).expect("block persistence");
    assert!(store.revoke(first.fingerprint, 400).is_err());
    assert!(!store.export_public_history().expect("history")[0].revoked);
    let loaded = IdentityKeyStore::load(&path).expect("load");
    assert!(!loaded.export_public_history().expect("history")[0].revoked);

    fs::remove_dir(&pending).expect("unblock persistence");
    assert!(
        store
            .revoke(first.fingerprint, 500)
            .expect("revoke")
            .revoked
    );
}

#[test]
fn rejects_weak_seed_and_bad_public_key_material() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    assert!(matches!(
        IdentityKeyStore::create(&path, [0; 32], 100),
        Err(KeyStoreError::WeakSeed("all-zero seed"))
    ));
    assert!(matches!(
        KeyFingerprint::from_public_key(&[]),
        Err(KeyStoreError::InvalidPublicKey(_))
    ));
}

#[cfg(unix)]
#[test]
fn pending_symlink_does_not_redirect_key_store_write() {
    use std::io::ErrorKind;
    use std::os::unix::fs::symlink;

    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    let pending = pending_path(&path).expect("pending path");
    let sentinel = dir.path().join("sentinel");
    fs::write(&sentinel, b"do-not-touch").expect("write sentinel");
    symlink(&sentinel, &pending).expect("create pending symlink");

    let err = IdentityKeyStore::create(&path, strong_seed(5), 100).unwrap_err();
    match err {
        KeyStoreError::Io {
            path: failed_path,
            source,
        } => {
            assert_eq!(failed_path, pending);
            assert_eq!(source.kind(), ErrorKind::AlreadyExists);
        }
        other => panic!("unexpected key-store error: {other}"),
    }
    assert_eq!(fs::read(&sentinel).expect("read sentinel"), b"do-not-touch");
    assert!(matches!(
        fs::symlink_metadata(&path),
        Err(error) if error.kind() == ErrorKind::NotFound
    ));
}
