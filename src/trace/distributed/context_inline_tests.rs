    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn trace_context_serialization_roundtrip() {
        let mut rng = DetRng::new(42);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(1),
            SymbolSpanId::new_for_test(0),
            RegionTag::new("us-east-1"),
            &mut rng,
        )
        .with_created_at(Time::from_millis(1000))
        .with_baggage("request_id", "req-123");

        let bytes = ctx.to_bytes();
        let parsed = SymbolTraceContext::from_bytes(&bytes).expect("roundtrip should work");

        assert_eq!(ctx.trace_id(), parsed.trace_id());
        assert_eq!(ctx.span_id(), parsed.span_id());
        assert_eq!(ctx.get_baggage("request_id"), Some("req-123"));
    }

    #[test]
    fn trace_flags_bits() {
        let flags = TraceFlags::NONE.with_sampled().with_debug();
        assert!(flags.is_sampled());
        assert!(flags.is_debug());
    }

    #[test]
    fn trace_flags_individual_bits_are_independent() {
        let sampled_only = TraceFlags::SAMPLED;
        assert!(sampled_only.is_sampled());
        assert!(!sampled_only.is_debug());

        let debug_only = TraceFlags::DEBUG;
        assert!(!debug_only.is_sampled());
        assert!(debug_only.is_debug());

        let none = TraceFlags::NONE;
        assert!(!none.is_sampled());
        assert!(!none.is_debug());
    }

    #[test]
    fn trace_flags_byte_roundtrip() {
        for byte in [0x00, 0x01, 0x02, 0x03, 0xFF] {
            let flags = TraceFlags::from_byte(byte);
            assert_eq!(flags.as_byte(), byte);
        }
    }

    #[test]
    fn child_context_inherits_trace_id_and_flags() {
        let mut rng = DetRng::new(100);
        let parent = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(42),
            SymbolSpanId::new_for_test(0),
            RegionTag::new("eu-west-1"),
            &mut rng,
        )
        .with_baggage("tenant", "acme");

        let child = parent.child(&mut rng);

        assert_eq!(child.trace_id(), parent.trace_id());
        assert_eq!(child.flags(), parent.flags());
        assert_eq!(child.origin_region(), parent.origin_region());
        assert_eq!(child.get_baggage("tenant"), Some("acme"));
    }

    #[test]
    fn child_context_has_unique_span_id_and_correct_parent() {
        let mut rng = DetRng::new(200);
        let parent = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(7),
            SymbolSpanId::new_for_test(0),
            RegionTag::new("test"),
            &mut rng,
        );
        let parent_span = parent.span_id();

        let child = parent.child(&mut rng);

        assert_ne!(
            child.span_id(),
            parent_span,
            "child must have its own span_id"
        );
        assert_eq!(
            child.parent_span_id(),
            parent_span,
            "child parent_span_id must be parent's span_id"
        );
    }

    #[test]
    fn serialization_roundtrip_empty_baggage() {
        let mut rng = DetRng::new(55);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new(0xAAAA_BBBB_CCCC_DDDD, 0x1111_2222_3333_4444),
            SymbolSpanId::new_for_test(99),
            RegionTag::new("ap-south-1"),
            &mut rng,
        )
        .with_created_at(Time::from_millis(5000));

        let bytes = ctx.to_bytes();
        let parsed = SymbolTraceContext::from_bytes(&bytes).expect("should parse");

        assert_eq!(parsed.trace_id(), ctx.trace_id());
        assert_eq!(parsed.parent_span_id(), ctx.parent_span_id());
        assert_eq!(parsed.span_id(), ctx.span_id());
        assert_eq!(parsed.flags(), ctx.flags());
        assert_eq!(parsed.created_at(), ctx.created_at());
        assert_eq!(parsed.origin_region(), ctx.origin_region());
        assert!(parsed.baggage().is_empty());
    }

    #[test]
    fn serialization_roundtrip_multiple_baggage_items() {
        let mut rng = DetRng::new(66);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(1),
            SymbolSpanId::NIL,
            RegionTag::new("us-west-2"),
            &mut rng,
        )
        .with_baggage("request_id", "req-abc-123")
        .with_baggage("user_id", "user-42")
        .with_baggage("correlation", "corr-xyz");

        let bytes = ctx.to_bytes();
        let parsed = SymbolTraceContext::from_bytes(&bytes).expect("should parse");

        assert_eq!(parsed.baggage().len(), 3);
        assert_eq!(parsed.get_baggage("request_id"), Some("req-abc-123"));
        assert_eq!(parsed.get_baggage("user_id"), Some("user-42"));
        assert_eq!(parsed.get_baggage("correlation"), Some("corr-xyz"));
    }

    #[test]
    fn from_bytes_rejects_truncated_data() {
        assert!(SymbolTraceContext::from_bytes(&[]).is_none());
        assert!(SymbolTraceContext::from_bytes(&[0u8; 10]).is_none());
        assert!(SymbolTraceContext::from_bytes(&[0u8; 42]).is_none());
    }

    #[test]
    fn serialization_is_deterministic() {
        let make_ctx = || {
            let mut rng = DetRng::new(77);
            SymbolTraceContext::new_for_encoding(
                DistTraceId::new_for_test(10),
                SymbolSpanId::new_for_test(5),
                RegionTag::new("test-region"),
                &mut rng,
            )
            .with_created_at(Time::from_millis(999))
            .with_baggage("key", "value")
        };

        let bytes_a = make_ctx().to_bytes();
        let bytes_b = make_ctx().to_bytes();
        assert_eq!(
            bytes_a, bytes_b,
            "same context must produce identical bytes"
        );
    }

    #[test]
    fn from_bytes_rejects_oversized_baggage() {
        let mut rng = DetRng::new(42);
        let mut ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(1),
            SymbolSpanId::new_for_test(2),
            RegionTag::new("test"),
            &mut rng,
        );

        // Add baggage items that together exceed MAX_TOTAL_BAGGAGE_SIZE (64KB)
        // Each item is ~16KB, so 5 items = ~80KB > 64KB limit
        let large_value = "x".repeat(16 * 1024); // 16KB
        ctx = ctx
            .with_baggage("key1", &large_value)
            .with_baggage("key2", &large_value)
            .with_baggage("key3", &large_value)
            .with_baggage("key4", &large_value)
            .with_baggage("key5", &large_value); // This should push us over the limit

        let bytes = ctx.to_bytes();

        // The serialized bytes should be created successfully
        assert!(!bytes.is_empty());

        // But deserialization should fail due to baggage size limit
        let parsed = SymbolTraceContext::from_bytes(&bytes);
        assert!(
            parsed.is_none(),
            "Should reject oversized baggage during deserialization"
        );
    }

    #[test]
    fn region_tag_display() {
        let tag = RegionTag::new("us-east-1");
        assert_eq!(format!("{tag}"), "us-east-1");
        assert_eq!(tag.as_str(), "us-east-1");
    }

    #[test]
    fn get_baggage_returns_none_for_missing_key() {
        let mut rng = DetRng::new(88);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(1),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        )
        .with_baggage("exists", "yes");

        assert_eq!(ctx.get_baggage("exists"), Some("yes"));
        assert_eq!(ctx.get_baggage("missing"), None);
    }

    // =========================================================================
    // Wave 44 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn trace_flags_debug_clone_copy_eq_default() {
        let def = TraceFlags::default();
        assert_eq!(def, TraceFlags::NONE);
        assert_eq!(def.as_byte(), 0);
        assert!(!def.is_sampled());
        assert!(!def.is_debug());

        let sampled = TraceFlags::SAMPLED;
        let copied = sampled;
        let cloned = sampled;
        assert_eq!(copied, cloned);
        assert_ne!(def, sampled);

        insta::assert_debug_snapshot!(sampled);
    }

    #[test]
    fn region_tag_debug_clone_eq_hash_display() {
        use std::collections::HashSet;
        let t1 = RegionTag::new("us-west-2");
        let t2 = RegionTag::new("eu-central-1");

        insta::assert_debug_snapshot!(t1);
        assert_eq!(format!("{t1}"), "us-west-2");

        let cloned = t1.clone();
        assert_eq!(cloned, t1);
        assert_ne!(t1, t2);

        let mut set = HashSet::new();
        set.insert(t1.clone());
        set.insert(t2);
        set.insert(t1);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn symbol_trace_context_debug_clone_eq() {
        let mut rng = DetRng::new(99);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(42),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );

        insta::assert_debug_snapshot!(ctx);

        let cloned = ctx.clone();
        assert_eq!(cloned, ctx);
    }
