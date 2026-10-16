    use super::*;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            TransportError::ConnectionTimeout.code(),
            "transport_connection_timeout"
        );
        assert_eq!(ProtocolError::NotImplemented.code(), "ASUP-E701");
        assert_eq!(AuthError::GrantExpired.code(), "auth_grant_expired");
        assert_eq!(
            RepairError::InsufficientSymbols.code(),
            "repair_insufficient_symbols"
        );
    }

    #[test]
    fn retryable_classification() {
        assert!(TransportError::ConnectionTimeout.is_retryable());
        assert!(!ProtocolError::NotImplemented.is_retryable());
        assert!(!AuthError::InvalidSignature.is_retryable());
        assert!(RepairError::MissingRepairSymbol.is_retryable());
        assert!(!ManifestError::InvalidFormat.is_retryable());
    }

    #[test]
    fn not_implemented_display_carries_operator_code() {
        let message = ProtocolError::NotImplemented.to_string();
        assert!(message.starts_with("[ASUP-E701]"));
        assert!(message.contains("docs/error_codes/ASUP-E701.md"));
    }

    #[test]
    fn cancel_reason_severity_ordering() {
        let user = AtpCancelReason::UserCancel("test".to_string());
        let shutdown = AtpCancelReason::Shutdown;
        let timeout = AtpCancelReason::Timeout;

        assert!(user.severity() < timeout.severity());
        assert!(timeout.severity() < shutdown.severity());
    }

    #[test]
    fn atp_outcome_constructors() {
        let outcome: AtpOutcome<()> =
            AtpOutcome::transport_error(TransportError::ConnectionTimeout);
        assert!(outcome.is_err());

        let outcome: AtpOutcome<()> = AtpOutcome::atp_cancelled(AtpCancelReason::Timeout);
        assert!(outcome.is_cancelled());
    }

    #[test]
    fn idempotency_key_generation() {
        let key1 = IdempotencyKey::generate("test_input");
        let key2 = IdempotencyKey::generate("test_input");
        let key3 = IdempotencyKey::generate("different_input");

        // Same input should generate same key
        assert_eq!(key1, key2);
        // Different input should generate different key
        assert_ne!(key1, key3);

        // Keys should be prefixed with "atp_"
        assert!(key1.as_str().starts_with("atp_"));
    }

    #[test]
    fn idempotency_key_typed_constructors() {
        let manifest_hash = b"test_manifest_hash";
        let peer_id = "peer123";
        let timestamp = 1000000000;

        let offer_key = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);
        let accept_key = IdempotencyKey::accept(&offer_key, peer_id, timestamp);
        let chunk_key = IdempotencyKey::chunk("transfer123", 42, 1);

        assert!(offer_key.as_str().starts_with("atp_"));
        assert!(accept_key.as_str().starts_with("atp_"));
        assert!(chunk_key.as_str().starts_with("atp_"));

        // Keys should be deterministic for same inputs
        let offer_key2 = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);
        assert_eq!(offer_key, offer_key2);
    }

    #[test]
    fn transfer_transcript_lifecycle() {
        let key = IdempotencyKey::new("test_key");
        let mut transcript = TransferTranscript::new(
            "transfer123".to_string(),
            key.clone(),
            vec![1, 2, 3, 4],
            "peer456".to_string(),
            1000000000,
            1024,
            10,
        );

        assert_eq!(transcript.transfer_id, "transfer123");
        assert_eq!(transcript.idempotency_key, key);
        assert_eq!(transcript.outcome_class, OutcomeClass::Pending);
        assert!(!transcript.is_complete());

        // Test progress tracking
        transcript.update_chunks_completed(5);
        assert_eq!(transcript.progress_percent(), 50.0);

        // Test completion
        let success_outcome = AtpOutcome::ok(());
        transcript.complete(&success_outcome, 2000000000);

        assert_eq!(transcript.outcome_class, OutcomeClass::Success);
        assert!(transcript.is_complete());
        assert_eq!(transcript.duration_nanos(), Some(1000000000));
    }

    #[test]
    fn transfer_transcript_error_handling() {
        let key = IdempotencyKey::new("error_test");
        let mut transcript = TransferTranscript::new(
            "transfer_error".to_string(),
            key,
            vec![],
            "peer".to_string(),
            0,
            100,
            1,
        );

        let error_outcome = AtpOutcome::transport_error(TransportError::ConnectionTimeout);
        transcript.complete(&error_outcome, 1000);

        assert_eq!(transcript.outcome_class, OutcomeClass::Error);
        assert_eq!(
            transcript.error_code,
            Some("transport_connection_timeout".to_string())
        );
    }

    #[test]
    fn transfer_transcript_cancellation_mapping() {
        let key = IdempotencyKey::new("cancel_test");

        // 1. User cancellation with message containing "timeout": typed CancelKind::User wins
        let mut transcript = TransferTranscript::new(
            "transfer_user".to_string(),
            key.clone(),
            vec![],
            "peer".to_string(),
            0,
            100,
            1,
        );
        let user_cancel = Outcome::Cancelled(CancelReason::user("timeout elapsed on slow path"));
        transcript.complete(&user_cancel, 1000);
        assert_eq!(transcript.outcome_class, OutcomeClass::Cancelled);
        assert_eq!(
            transcript.cancellation_source,
            Some(AtpCancelReason::UserCancel(
                "timeout elapsed on slow path".to_string()
            ))
        );

        // 2. Timeout cancellation with message containing "user": typed CancelKind::Timeout wins
        let mut transcript = TransferTranscript::new(
            "transfer_timeout".to_string(),
            key.clone(),
            vec![],
            "peer".to_string(),
            0,
            100,
            1,
        );
        let timeout_cancel = Outcome::Cancelled(
            CancelReason::timeout().with_message("user-requested bound expired"),
        );
        transcript.complete(&timeout_cancel, 1000);
        assert_eq!(transcript.outcome_class, OutcomeClass::Cancelled);
        assert_eq!(
            transcript.cancellation_source,
            Some(AtpCancelReason::Timeout)
        );

        // 3. ATP-specific custom condition without native CancelKind: message substring matches
        let mut transcript = TransferTranscript::new(
            "transfer_race".to_string(),
            key,
            vec![],
            "peer".to_string(),
            0,
            100,
            1,
        );
        let race_cancel =
            Outcome::Cancelled(CancelReason::user("path race lost to secondary donor"));
        transcript.complete(&race_cancel, 1000);
        assert_eq!(
            transcript.cancellation_source,
            Some(AtpCancelReason::PathRaceLost)
        );
    }

    #[test]
    fn parse_atp_cancel_reason_typed_kind_precedence_and_round_trip() {
        // 1. Shutdown with message containing "repair decode" must not be overridden
        let shutdown_with_repair = CancelReason::shutdown().with_message("repair decode abandoned");
        assert_eq!(
            TransferTranscript::parse_atp_cancel_reason(&shutdown_with_repair),
            Some(AtpCancelReason::Shutdown)
        );

        // 2. Shutdown with message containing "path race" must not be overridden
        let shutdown_with_race = CancelReason::shutdown().with_message("path race lost");
        assert_eq!(
            TransferTranscript::parse_atp_cancel_reason(&shutdown_with_race),
            Some(AtpCancelReason::Shutdown)
        );

        // 3. Message-less kinds
        assert_eq!(
            TransferTranscript::parse_atp_cancel_reason(&CancelReason::timeout()),
            Some(AtpCancelReason::Timeout)
        );
        assert_eq!(
            TransferTranscript::parse_atp_cancel_reason(&CancelReason::shutdown()),
            Some(AtpCancelReason::Shutdown)
        );
        assert_eq!(
            TransferTranscript::parse_atp_cancel_reason(&CancelReason::parent_cancelled()),
            Some(AtpCancelReason::ParentCancel)
        );
        assert_eq!(
            TransferTranscript::parse_atp_cancel_reason(&CancelReason::race_lost()),
            Some(AtpCancelReason::PathRaceLost)
        );
        assert_eq!(
            TransferTranscript::parse_atp_cancel_reason(&CancelReason::linked_exit()),
            Some(AtpCancelReason::ParentCancel)
        );

        // 4. Round trip for all AtpCancelReason variants. CancelReason carries
        // only &'static str messages, so to_base_reason maps every payload
        // to its variant's canonical text: the variant survives the round
        // trip, a caller's free-text payload does not.
        assert_eq!(
            TransferTranscript::parse_atp_cancel_reason(
                &AtpCancelReason::UserCancel("custom user cancel".to_string()).to_base_reason()
            ),
            Some(AtpCancelReason::UserCancel("user cancel".to_string()))
        );
        let variants = [
            AtpCancelReason::UserCancel("user cancel".to_string()),
            AtpCancelReason::Timeout,
            AtpCancelReason::Shutdown,
            AtpCancelReason::FailFast("fail-fast".to_string()),
            AtpCancelReason::ParentCancel,
            AtpCancelReason::PathRaceLost,
            AtpCancelReason::RepairDecodeAbandoned,
            AtpCancelReason::DaemonRestart,
            AtpCancelReason::ResourceBudgetExhausted("resource budget exhausted".to_string()),
        ];
        for variant in &variants {
            let base = variant.to_base_reason();
            let parsed = TransferTranscript::parse_atp_cancel_reason(&base);
            assert_eq!(
                parsed.as_ref(),
                Some(variant),
                "round-trip mismatch for {:?}",
                variant
            );
        }
    }

    #[test]
    fn retry_policy_should_retry_logic() {
        let policy = RetryPolicy::default_transfer();

        // Should not retry on success
        let success = AtpOutcome::ok(());
        assert!(!policy.should_retry(&success, 1));

        // Should retry on retryable transport error within max attempts
        let retryable_error: AtpOutcome<()> =
            AtpOutcome::transport_error(TransportError::ConnectionTimeout);
        assert!(policy.should_retry(&retryable_error, 1));
        assert!(policy.should_retry(&retryable_error, 2));
        assert!(!policy.should_retry(&retryable_error, 3)); // At max attempts

        // Should not retry on non-retryable error
        let non_retryable: AtpOutcome<()> = AtpOutcome::auth_error(AuthError::InvalidSignature);
        assert!(!policy.should_retry(&non_retryable, 1));
    }

    #[test]
    fn retry_policy_delay_calculation() {
        let policy = RetryPolicy {
            max_attempts: 5,
            base_delay_ms: 1000,
            max_delay_ms: 10000,
            backoff_multiplier: 2.0,
            jitter_percent: 0, // No jitter for deterministic test
            retry_on_cancel: false,
            retry_conditions: vec![RetryCondition::RetryableErrors],
        };

        let delay1 = policy.delay_for_attempt(1);
        let delay2 = policy.delay_for_attempt(2);
        let delay3 = policy.delay_for_attempt(3);

        assert_eq!(delay1, 1000); // Base delay
        assert_eq!(delay2, 2000); // Base * 2^1
        assert_eq!(delay3, 4000); // Base * 2^2

        // Test max delay clamping
        let delay_high = policy.delay_for_attempt(10);
        assert!(delay_high <= 10000);
    }

    #[test]
    fn retry_condition_matching() {
        let transport_error = AtpError::Transport(TransportError::ConnectionTimeout);
        let auth_error = AtpError::Auth(AuthError::InvalidSignature);

        let code_condition =
            RetryCondition::ErrorCode(vec!["transport_connection_timeout".to_string()]);
        assert!(code_condition.matches(&transport_error));
        assert!(!code_condition.matches(&auth_error));

        let class_condition = RetryCondition::ErrorClass(vec!["transport".to_string()]);
        assert!(class_condition.matches(&transport_error));
        assert!(!class_condition.matches(&auth_error));

        let retryable_condition = RetryCondition::RetryableErrors;
        assert!(retryable_condition.matches(&transport_error)); // Retryable
        assert!(!retryable_condition.matches(&auth_error)); // Not retryable

        let always_condition = RetryCondition::AlwaysRetry;
        assert!(always_condition.matches(&transport_error));
        assert!(always_condition.matches(&auth_error));

        let never_condition = RetryCondition::NeverRetry;
        assert!(!never_condition.matches(&transport_error));
        assert!(!never_condition.matches(&auth_error));
    }

    #[test]
    fn outcome_class_from_outcome() {
        let success: AtpOutcome<()> = AtpOutcome::ok(());
        assert_eq!(OutcomeClass::from_outcome(&success), OutcomeClass::Success);

        let error: AtpOutcome<()> = AtpOutcome::transport_error(TransportError::ConnectionTimeout);
        assert_eq!(OutcomeClass::from_outcome(&error), OutcomeClass::Error);

        let cancelled: AtpOutcome<()> = AtpOutcome::atp_cancelled(AtpCancelReason::Timeout);
        assert_eq!(
            OutcomeClass::from_outcome(&cancelled),
            OutcomeClass::Cancelled
        );

        // Test retryable classification
        assert!(OutcomeClass::Error.is_retryable());
        assert!(OutcomeClass::Cancelled.is_retryable());
        assert!(!OutcomeClass::Success.is_retryable());
        assert!(!OutcomeClass::Panicked.is_retryable());
    }

    #[test]
    fn idempotency_key_all_operation_types() {
        // Test all the specific key generators
        let manifest_hash = b"manifest";
        let peer_id = "peer";
        let timestamp = 123456789;

        let offer_key = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);
        let accept_key = IdempotencyKey::accept(&offer_key, peer_id, timestamp);
        let chunk_key = IdempotencyKey::chunk("transfer", 1, 1);
        let repair_key = IdempotencyKey::repair_group("block", 1, peer_id);
        let commit_key = IdempotencyKey::commit("transfer", b"hash", timestamp);
        let mailbox_key = IdempotencyKey::mailbox_store("mailbox", b"msg", 1);
        let grant_key = IdempotencyKey::grant("issuer", "subject", b"cap", timestamp);
        let relay_key = IdempotencyKey::relay_reservation("relay", "client", 1000, 3600);
        let journal_key = IdempotencyKey::resume_journal("transfer", b"checkpoint", 1);
        let proof_key = IdempotencyKey::final_proof("transfer", b"proof", "verifier");

        // All keys should be unique
        let keys = vec![
            offer_key,
            accept_key,
            chunk_key,
            repair_key,
            commit_key,
            mailbox_key,
            grant_key,
            relay_key,
            journal_key,
            proof_key,
        ];

        for (i, key1) in keys.iter().enumerate() {
            for (j, key2) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(key1, key2, "Keys should be unique");
                }
            }
        }
    }
