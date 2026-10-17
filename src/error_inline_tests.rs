    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::error::Error as _;

    #[derive(Debug)]
    struct Underlying;

    impl fmt::Display for Underlying {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "underlying")
        }
    }

    impl std::error::Error for Underlying {}

    #[test]
    fn display_without_message() {
        let err = Error::new(ErrorKind::Internal);
        assert_eq!(err.to_string(), "Internal");
    }

    #[test]
    fn display_with_message() {
        let err = Error::new(ErrorKind::ChannelEmpty).with_message("no messages");
        assert_eq!(err.to_string(), "ChannelEmpty: no messages");
    }

    #[test]
    fn asup_codes_are_stable_for_live_error_kinds() {
        let cases = [
            (ErrorKind::ObligationLeak, Some("ASUP-E101")),
            (ErrorKind::ObligationAlreadyResolved, Some("ASUP-E102")),
            (ErrorKind::RegionClosed, Some("ASUP-E003")),
            (ErrorKind::AdmissionDenied, Some("ASUP-E006")),
            (ErrorKind::ChannelClosed, Some("ASUP-E201")),
            (ErrorKind::CancelTimeout, Some("ASUP-E301")),
            (ErrorKind::ConfigError, Some("ASUP-E901")),
            (ErrorKind::ChannelEmpty, None),
        ];

        for (kind, expected) in cases {
            assert_eq!(kind.asup_code(), expected, "{kind:?}");
        }
    }

    #[test]
    fn display_prefixes_live_asup_codes() {
        let leak = Error::new(ErrorKind::ObligationLeak);
        assert_eq!(leak.to_string(), "[ASUP-E101] ObligationLeak");

        let double_resolve = Error::new(ErrorKind::ObligationAlreadyResolved);
        assert_eq!(
            double_resolve.to_string(),
            "[ASUP-E102] ObligationAlreadyResolved"
        );

        let channel = Error::new(ErrorKind::ChannelClosed);
        assert_eq!(channel.to_string(), "[ASUP-E201] ChannelClosed");

        let region = Error::new(ErrorKind::RegionClosed);
        assert_eq!(region.to_string(), "[ASUP-E003] RegionClosed");

        let admission = Error::new(ErrorKind::AdmissionDenied);
        assert_eq!(admission.to_string(), "[ASUP-E006] AdmissionDenied");

        let drain = Error::new(ErrorKind::CancelTimeout);
        assert_eq!(drain.to_string(), "[ASUP-E301] CancelTimeout");

        let config = Error::new(ErrorKind::ConfigError).with_message("min_threads exceeds max");
        assert_eq!(
            config.to_string(),
            "[ASUP-E901] ConfigError: min_threads exceeds max"
        );
    }

    #[test]
    fn source_chain_is_exposed() {
        let err = Error::new(ErrorKind::User)
            .with_message("outer")
            .with_source(Underlying);
        let source = err.source().expect("source missing");
        assert_eq!(source.to_string(), "underlying");
    }

    #[test]
    fn from_recv_error() {
        let disconnected: Error = RecvError::Disconnected.into();
        assert_eq!(disconnected.kind(), ErrorKind::ChannelClosed);

        let empty: Error = RecvError::Empty.into();
        assert_eq!(empty.kind(), ErrorKind::ChannelEmpty);
    }

    #[test]
    fn from_send_error() {
        let disconnected: Error = SendError::Disconnected(()).into();
        assert_eq!(disconnected.kind(), ErrorKind::ChannelClosed);

        let full: Error = SendError::Full(()).into();
        assert_eq!(full.kind(), ErrorKind::ChannelFull);
    }

    #[test]
    fn result_ext_adds_message() {
        let res: core::result::Result<(), RecvError> = Err(RecvError::Empty);
        let err = res.context("recv failed").expect_err("expected err");
        assert_eq!(err.kind(), ErrorKind::ChannelEmpty);
        assert_eq!(err.to_string(), "ChannelEmpty: recv failed");
    }

    #[test]
    fn predicates_match_kind() {
        let cancel = Error::new(ErrorKind::Cancelled);
        assert!(cancel.is_cancelled());
        assert!(!cancel.is_timeout());

        let timeout = Error::new(ErrorKind::DeadlineExceeded);
        assert!(!timeout.is_cancelled());
        assert!(timeout.is_timeout());
    }

    #[test]
    fn recovery_action_backoff() {
        let action = ErrorKind::ThresholdTimeout.recovery_action();
        assert!(matches!(action, RecoveryAction::RetryWithBackoff(_)));
    }

    #[test]
    fn error_context_default() {
        let err = Error::new(ErrorKind::Internal);
        assert!(err.context().task_id.is_none());
    }

    #[test]
    fn error_with_full_context() {
        use crate::util::ArenaIndex;

        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region_id = RegionId::from_arena(ArenaIndex::new(2, 0));
        let object_id = ObjectId::new_for_test(123);
        let symbol_id = SymbolId::new_for_test(123, 0, 1);

        let ctx = ErrorContext {
            task_id: Some(task_id),
            region_id: Some(region_id),
            object_id: Some(object_id),
            symbol_id: Some(symbol_id),
            correlation_id: None,
            causal_chain: Vec::new(),
            span_id: None,
            parent_span_id: None,
            async_stack: Vec::new(),
        };

        let err = Error::new(ErrorKind::Internal).with_context(ctx);

        assert_eq!(err.context().task_id, Some(task_id));
        assert_eq!(err.context().region_id, Some(region_id));
        assert_eq!(err.context().object_id, Some(object_id));
        assert_eq!(err.context().symbol_id, Some(symbol_id));
    }

    // ---- ErrorKind category exhaustive coverage ----

    #[test]
    fn error_kind_category_coverage() {
        use ErrorCategory::*;
        let cases: &[(ErrorKind, ErrorCategory)] = &[
            (ErrorKind::Cancelled, Cancellation),
            (ErrorKind::CancelTimeout, Cancellation),
            (ErrorKind::DeadlineExceeded, Budget),
            (ErrorKind::PollQuotaExhausted, Budget),
            (ErrorKind::CostQuotaExhausted, Budget),
            (ErrorKind::ChannelClosed, Channel),
            (ErrorKind::ChannelFull, Channel),
            (ErrorKind::ChannelEmpty, Channel),
            (ErrorKind::ObligationLeak, Obligation),
            (ErrorKind::ObligationAlreadyResolved, Obligation),
            (ErrorKind::RegionClosed, Region),
            (ErrorKind::TaskNotOwned, Region),
            (ErrorKind::AdmissionDenied, Region),
            (ErrorKind::InvalidEncodingParams, Encoding),
            (ErrorKind::DataTooLarge, Encoding),
            (ErrorKind::EncodingFailed, Encoding),
            (ErrorKind::CorruptedSymbol, Encoding),
            (ErrorKind::InsufficientSymbols, Decoding),
            (ErrorKind::DecodingFailed, Decoding),
            (ErrorKind::ObjectMismatch, Decoding),
            (ErrorKind::DuplicateSymbol, Decoding),
            (ErrorKind::ThresholdTimeout, Decoding),
            (ErrorKind::RoutingFailed, Transport),
            (ErrorKind::DispatchFailed, Transport),
            (ErrorKind::StreamEnded, Transport),
            (ErrorKind::SinkRejected, Transport),
            (ErrorKind::ConnectionLost, Transport),
            (ErrorKind::ConnectionRefused, Transport),
            (ErrorKind::ProtocolError, Transport),
            (ErrorKind::RecoveryFailed, Distributed),
            (ErrorKind::LeaseExpired, Distributed),
            (ErrorKind::LeaseRenewalFailed, Distributed),
            (ErrorKind::CoordinationFailed, Distributed),
            (ErrorKind::QuorumNotReached, Distributed),
            (ErrorKind::NodeUnavailable, Distributed),
            (ErrorKind::PartitionDetected, Distributed),
            (ErrorKind::Internal, Internal),
            (ErrorKind::InvalidStateTransition, Internal),
            (ErrorKind::ConfigError, User),
            (ErrorKind::User, User),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.category(), *expected, "{kind:?}");
        }
    }

    #[test]
    fn error_kind_recoverability_classification() {
        // Transient
        for kind in [
            ErrorKind::ChannelFull,
            ErrorKind::ChannelEmpty,
            ErrorKind::AdmissionDenied,
            ErrorKind::ConnectionLost,
            ErrorKind::NodeUnavailable,
            ErrorKind::QuorumNotReached,
            ErrorKind::ThresholdTimeout,
            ErrorKind::LeaseRenewalFailed,
        ] {
            assert_eq!(kind.recoverability(), Recoverability::Transient, "{kind:?}");
            assert!(kind.is_retryable(), "{kind:?} should be retryable");
        }

        // Permanent
        for kind in [
            ErrorKind::Cancelled,
            ErrorKind::ChannelClosed,
            ErrorKind::ObligationLeak,
            ErrorKind::Internal,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConfigError,
        ] {
            assert_eq!(kind.recoverability(), Recoverability::Permanent, "{kind:?}");
            assert!(!kind.is_retryable(), "{kind:?} should not be retryable");
        }

        // Unknown
        for kind in [
            ErrorKind::DeadlineExceeded,
            ErrorKind::EncodingFailed,
            ErrorKind::CorruptedSymbol,
            ErrorKind::User,
        ] {
            assert_eq!(kind.recoverability(), Recoverability::Unknown, "{kind:?}");
            assert!(!kind.is_retryable(), "{kind:?} Unknown is not retryable");
        }
    }

    #[test]
    fn recoverability_predicates() {
        assert!(Recoverability::Transient.should_retry());
        assert!(!Recoverability::Transient.is_permanent());

        assert!(!Recoverability::Permanent.should_retry());
        assert!(Recoverability::Permanent.is_permanent());

        assert!(!Recoverability::Unknown.should_retry());
        assert!(!Recoverability::Unknown.is_permanent());
    }

    #[test]
    fn recovery_action_variants() {
        assert!(matches!(
            ErrorKind::ChannelFull.recovery_action(),
            RecoveryAction::RetryImmediately
        ));
        assert!(matches!(
            ErrorKind::AdmissionDenied.recovery_action(),
            RecoveryAction::RetryWithBackoff(_)
        ));
        assert!(matches!(
            ErrorKind::NodeUnavailable.recovery_action(),
            RecoveryAction::RetryWithBackoff(_)
        ));
        assert!(matches!(
            ErrorKind::ConnectionLost.recovery_action(),
            RecoveryAction::RetryWithNewConnection
        ));
        assert!(matches!(
            ErrorKind::Cancelled.recovery_action(),
            RecoveryAction::Propagate
        ));
        assert!(matches!(
            ErrorKind::ObligationLeak.recovery_action(),
            RecoveryAction::Escalate
        ));
        assert!(matches!(
            ErrorKind::User.recovery_action(),
            RecoveryAction::Custom
        ));
    }

    #[test]
    fn backoff_hint_constants() {
        let d = BackoffHint::DEFAULT;
        assert_eq!(d.initial_delay_ms, 100);
        assert_eq!(d.max_delay_ms, 30_000);
        assert_eq!(d.max_attempts, 5);

        let a = BackoffHint::AGGRESSIVE;
        assert!(a.initial_delay_ms > d.initial_delay_ms);
        assert!(a.max_attempts > d.max_attempts);

        let q = BackoffHint::QUICK;
        assert!(q.initial_delay_ms < d.initial_delay_ms);
        assert!(q.max_attempts < d.max_attempts);

        assert_eq!(BackoffHint::default(), BackoffHint::DEFAULT);
    }

    // ---- Error convenience constructors ----

    #[test]
    fn error_data_too_large() {
        let err = Error::data_too_large(2000, 1000);
        assert_eq!(err.kind(), ErrorKind::DataTooLarge);
        let msg = err.to_string();
        assert!(msg.contains("2000"), "{msg}");
        assert!(msg.contains("1000"), "{msg}");
    }

    #[test]
    fn error_insufficient_symbols() {
        let err = Error::insufficient_symbols(5, 10);
        assert_eq!(err.kind(), ErrorKind::InsufficientSymbols);
        let msg = err.to_string();
        assert!(msg.contains('5'), "{msg}");
        assert!(msg.contains("10"), "{msg}");
    }

    #[test]
    fn error_routing_failed() {
        let err = Error::routing_failed("node-7");
        assert_eq!(err.kind(), ErrorKind::RoutingFailed);
        assert!(err.to_string().contains("node-7"));
    }

    #[test]
    fn error_lease_expired() {
        let err = Error::lease_expired("lease-42");
        assert_eq!(err.kind(), ErrorKind::LeaseExpired);
        assert!(err.to_string().contains("lease-42"));
    }

    #[test]
    fn error_quorum_not_reached() {
        let err = Error::quorum_not_reached(2, 3);
        assert_eq!(err.kind(), ErrorKind::QuorumNotReached);
        let msg = err.to_string();
        assert!(msg.contains('2'), "{msg}");
        assert!(msg.contains('3'), "{msg}");
    }

    #[test]
    fn error_node_unavailable() {
        let err = Error::node_unavailable("node-1");
        assert_eq!(err.kind(), ErrorKind::NodeUnavailable);
        assert!(err.to_string().contains("node-1"));
    }

    #[test]
    fn error_internal() {
        let err = Error::internal("bug found");
        assert_eq!(err.kind(), ErrorKind::Internal);
        assert!(err.to_string().contains("bug found"));
    }

    // ---- Error predicates ----

    #[test]
    fn error_is_predicates() {
        assert!(Error::new(ErrorKind::EncodingFailed).is_encoding_error());
        assert!(!Error::new(ErrorKind::DecodingFailed).is_encoding_error());

        assert!(Error::new(ErrorKind::InsufficientSymbols).is_decoding_error());
        assert!(!Error::new(ErrorKind::EncodingFailed).is_decoding_error());

        assert!(Error::new(ErrorKind::RoutingFailed).is_transport_error());
        assert!(!Error::new(ErrorKind::Internal).is_transport_error());

        assert!(Error::new(ErrorKind::QuorumNotReached).is_distributed_error());
        assert!(!Error::new(ErrorKind::ChannelFull).is_distributed_error());

        assert!(Error::new(ErrorKind::ConnectionLost).is_connection_error());
        assert!(Error::new(ErrorKind::ConnectionRefused).is_connection_error());
        assert!(!Error::new(ErrorKind::RoutingFailed).is_connection_error());
    }

    #[test]
    fn error_cancel_timeout_is_timeout() {
        assert!(Error::new(ErrorKind::CancelTimeout).is_timeout());
        assert!(!Error::new(ErrorKind::CancelTimeout).is_cancelled());
    }

    // ---- Conversion tests ----

    #[test]
    fn recv_error_cancelled_conversion() {
        let err: Error = RecvError::Cancelled.into();
        assert_eq!(err.kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn send_error_cancelled_conversion() {
        let err: Error = SendError::Cancelled(42u32).into();
        assert_eq!(err.kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn cancelled_struct_into_error() {
        let reason = CancelReason::user("test cancel");
        let cancelled = Cancelled { reason };
        let err: Error = cancelled.into();
        assert_eq!(err.kind(), ErrorKind::Cancelled);
        assert!(err.to_string().contains("Cancelled"));
        assert_eq!(
            err.cancel_reason(),
            Some(&CancelReason::user("test cancel"))
        );
    }

    #[test]
    fn cancel_reason_is_carried_without_changing_display() {
        let reason = CancelReason::new(crate::types::CancelKind::Shutdown)
            .with_cause(CancelReason::user("operator stop"));
        let plain = Error::new(ErrorKind::Cancelled);
        assert_eq!(plain.cancel_reason(), None);
        let display = plain.to_string();

        let carried = plain.with_cancel_reason(reason.clone());
        assert_eq!(carried.cancel_reason(), Some(&reason));
        assert_eq!(carried.to_string(), display);
        assert_eq!(carried.clone().cancel_reason(), Some(&reason));

        let unchanged = Error::new(ErrorKind::Cancelled).with_cancel_reason_from(None);
        assert_eq!(unchanged.cancel_reason(), None);
        assert_eq!(
            Error::new(ErrorKind::Internal).cancel_reason(),
            None,
            "only errors built with a reason carry one"
        );
    }

    #[test]
    fn result_ext_with_context_lazy() {
        let res: core::result::Result<(), RecvError> = Err(RecvError::Empty);
        let err = res
            .with_context(|| format!("lazy {}", "context"))
            .expect_err("expected err");
        assert_eq!(err.kind(), ErrorKind::ChannelEmpty);
        assert!(err.to_string().contains("lazy context"));
    }

    // ---- Debug/Clone ----

    #[test]
    fn error_category_debug() {
        for cat in [
            ErrorCategory::Cancellation,
            ErrorCategory::Budget,
            ErrorCategory::Channel,
            ErrorCategory::Obligation,
            ErrorCategory::Region,
            ErrorCategory::Encoding,
            ErrorCategory::Decoding,
            ErrorCategory::Transport,
            ErrorCategory::Distributed,
            ErrorCategory::Internal,
            ErrorCategory::User,
        ] {
            let dbg = format!("{cat:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn acquire_error_debug_eq() {
        let err = AcquireError::Closed;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Closed"), "{dbg}");
        assert_eq!(err, AcquireError::Closed);
    }

    #[test]
    fn error_clone() {
        let err = Error::new(ErrorKind::Internal).with_message("clone me");
        let cloned = err.clone();
        assert_eq!(cloned.kind(), ErrorKind::Internal);
        assert_eq!(cloned.to_string(), err.to_string());
    }

    #[test]
    fn error_no_message() {
        let err = Error::new(ErrorKind::User);
        assert!(err.message().is_none());
    }

    #[test]
    fn error_source_none_without_with_source() {
        let err = Error::new(ErrorKind::User);
        assert!(err.source().is_none());
    }

    // Pure data-type tests (wave 39 – CyanBarn)

    #[test]
    fn error_kind_copy_hash() {
        use std::collections::HashSet;
        let kind = ErrorKind::Internal;
        let copied = kind;
        assert_eq!(copied, ErrorKind::Internal);

        let mut set = HashSet::new();
        set.insert(ErrorKind::Cancelled);
        set.insert(ErrorKind::DeadlineExceeded);
        set.insert(ErrorKind::Cancelled); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn recoverability_copy_hash_eq() {
        use std::collections::HashSet;
        let r = Recoverability::Transient;
        let copied = r;
        assert_eq!(copied, Recoverability::Transient);
        assert_ne!(r, Recoverability::Permanent);

        let mut set = HashSet::new();
        set.insert(Recoverability::Transient);
        set.insert(Recoverability::Permanent);
        set.insert(Recoverability::Unknown);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn recovery_action_copy_hash() {
        use std::collections::HashSet;
        let action = RecoveryAction::Propagate;
        let copied = action;
        assert_eq!(copied, RecoveryAction::Propagate);

        let mut set = HashSet::new();
        set.insert(RecoveryAction::RetryImmediately);
        set.insert(RecoveryAction::Propagate);
        set.insert(RecoveryAction::Escalate);
        set.insert(RecoveryAction::Custom);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn error_category_copy_clone_hash() {
        use std::collections::HashSet;
        let cat = ErrorCategory::Transport;
        let copied = cat;
        let cloned = cat;
        assert_eq!(copied, cloned);

        let mut set = HashSet::new();
        set.insert(ErrorCategory::Cancellation);
        set.insert(ErrorCategory::Budget);
        set.insert(ErrorCategory::Channel);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn backoff_hint_copy_hash_eq() {
        use std::collections::HashSet;
        let hint = BackoffHint::DEFAULT;
        let copied = hint;
        assert_eq!(copied, BackoffHint::DEFAULT);
        assert_ne!(hint, BackoffHint::AGGRESSIVE);

        let mut set = HashSet::new();
        set.insert(BackoffHint::DEFAULT);
        set.insert(BackoffHint::AGGRESSIVE);
        set.insert(BackoffHint::QUICK);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn recv_error_debug_clone_copy() {
        let err = RecvError::Disconnected;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Disconnected"));

        let copied = err;
        assert_eq!(copied, RecvError::Disconnected);

        let cloned = err;
        assert_eq!(cloned, err);
    }

    #[test]
    fn cancelled_clone_eq() {
        let c = Cancelled {
            reason: CancelReason::user("test"),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Cancelled"));

        let cloned = c.clone();
        assert_eq!(cloned, c);
    }

    #[test]
    fn error_context_auto_correlation() {
        let ctx = ErrorContext::new();
        assert!(ctx.correlation_id.is_some());
        assert!(ctx.causal_chain.is_empty());
        assert!(ctx.async_stack.is_empty());
    }

    #[test]
    fn error_context_derive_child() {
        let parent = ErrorContext::new();
        let parent_id = parent.correlation_id.unwrap();

        let child = parent.derive_child("async_operation");

        // Child has new correlation ID
        assert!(child.correlation_id.is_some());
        assert_ne!(child.correlation_id, parent.correlation_id);

        // Causal chain includes parent
        assert_eq!(child.causal_chain, vec![parent_id]);

        // Operation added to stack
        assert_eq!(child.async_stack, vec!["async_operation"]);

        // Spans are updated
        assert!(child.span_id.is_some());
        assert_eq!(child.parent_span_id, parent.span_id);
    }

    #[test]
    fn error_context_causal_chain() {
        let root = ErrorContext::new();
        let child = root.derive_child("level1");
        let grandchild = child.derive_child("level2");

        let root_id = root.correlation_id.unwrap();
        let child_id = child.correlation_id.unwrap();

        let chain = grandchild.full_causal_chain();
        assert_eq!(
            chain,
            vec![root_id, child_id, grandchild.correlation_id.unwrap()]
        );

        assert_eq!(grandchild.root_correlation_id(), Some(root_id));
    }

    #[test]
    fn error_context_async_stack_trace() {
        let ctx = ErrorContext::new()
            .with_operation("spawn_task")
            .with_operation("process_request");

        let trace = ctx.format_async_stack();
        assert_eq!(trace, "spawn_task -> process_request");
    }

    #[test]
    fn error_propagate_across_async() {
        let error = Error::new(ErrorKind::Internal).with_operation("initial_operation");

        let propagated = error.propagate_across_async("async_boundary");

        // Original error correlation should be in causal chain
        let chain = propagated.causal_chain();
        assert!(!chain.is_empty());

        // Async stack should include new operation
        let stack = propagated.async_stack();
        assert!(stack.contains("async_boundary"));
    }

    #[test]
    fn error_correlation_tracking() {
        let err1 = Error::new(ErrorKind::ChannelClosed);
        let err2 = Error::new(ErrorKind::Internal);

        // Different errors get different correlation IDs
        assert_ne!(err1.correlation_id(), err2.correlation_id());
        assert!(err1.correlation_id().is_some());
        assert!(err2.correlation_id().is_some());
    }

    #[test]
    fn error_with_operations() {
        let error = Error::new(ErrorKind::DecodingFailed)
            .with_operation("read_symbol")
            .with_operation("decode_block");

        let stack = error.async_stack();
        assert_eq!(stack, "read_symbol -> decode_block");
    }
