    use super::*;

    #[test]
    fn trace_context_round_trip() {
        let original = W3CTraceContext::new_root();
        let traceparent = original.to_traceparent();
        let parsed = W3CTraceContext::from_str(&traceparent).expect("parse failed");

        assert_eq!(original.trace_id, parsed.trace_id);
        assert_eq!(original.span_id, parsed.span_id);
        assert_eq!(original.flags.0, parsed.flags.0);
    }

    #[test]
    fn extract_from_http_missing_headers() {
        let headers = HashMap::new();
        let result = extract_from_http(&headers).expect("extraction failed");
        assert!(result.is_none());
    }

    #[test]
    fn extract_from_http_valid_context() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".to_string(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        );

        let result = extract_from_http(&headers).expect("extraction failed");
        let context = result.expect("context should be present");

        assert!(context.flags.is_sampled());
        assert_eq!(
            context.to_traceparent(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
    }

    #[test]
    fn inject_to_grpc_includes_headers() {
        let context = W3CTraceContext::new_root();
        let mut metadata = HashMap::new();

        inject_to_grpc(&context, &mut metadata);

        assert!(metadata.contains_key("traceparent"));
        assert_eq!(metadata["traceparent"], context.to_traceparent());
    }

    #[test]
    fn baggage_extraction_with_traceparent_preserves_context() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".to_string(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        );
        headers.insert("tracestate".to_string(), "vendor=opaque".to_string());
        headers.insert(
            "baggage".to_string(),
            "tenant=alpha,request.class=gold;metadata=kept,user.id=12345".to_string(),
        );

        let propagation =
            extract_propagation_from_http(&headers).expect("propagation extraction failed");
        let context = propagation
            .trace_context
            .expect("trace context should be present");

        assert_eq!(context.tracestate.as_deref(), Some("vendor=opaque"));
        assert_eq!(context.baggage.get("tenant"), Some("alpha"));
        assert_eq!(context.baggage.get("request.class"), Some("gold"));
        assert_eq!(context.baggage.get("user.id"), Some("12345"));
        assert_eq!(propagation.baggage, context.baggage);

        let legacy_context = extract_from_http(&headers)
            .expect("legacy extraction failed")
            .expect("trace context should be present");
        assert_eq!(legacy_context.baggage.get("tenant"), Some("alpha"));
    }

    #[test]
    fn baggage_extraction_does_not_require_traceparent() {
        let mut headers = HashMap::new();
        headers.insert(
            "baggage".to_string(),
            "session.id=sess-abc123,feature.flag=new-ui".to_string(),
        );

        let propagation =
            extract_propagation_from_http(&headers).expect("propagation extraction failed");

        assert!(propagation.trace_context.is_none());
        assert_eq!(propagation.baggage.len(), 2);
        assert_eq!(propagation.baggage.get("session.id"), Some("sess-abc123"));
        assert_eq!(propagation.baggage.get("feature.flag"), Some("new-ui"));
        assert!(
            extract_from_http(&headers)
                .expect("trace-only extraction failed")
                .is_none(),
            "trace-only compatibility API should still report no trace context"
        );
    }

    #[test]
    fn baggage_injection_to_http_and_grpc_is_deterministic() {
        let mut context = W3CTraceContext::new_root();
        context.baggage.insert("tenant", "beta").unwrap();
        context
            .baggage
            .insert("correlation.id", "req-987654")
            .unwrap();
        context.baggage.insert("user.role", "admin").unwrap();

        let mut http_headers = HashMap::new();
        inject_to_http(&context, &mut http_headers).expect("HTTP injection failed");
        assert_eq!(
            http_headers.get("baggage").map(String::as_str),
            Some("correlation.id=req-987654,tenant=beta,user.role=admin")
        );
        let traceparent = context.to_traceparent();
        assert_eq!(
            http_headers.get("traceparent").map(String::as_str),
            Some(traceparent.as_str())
        );

        let mut grpc_metadata = HashMap::new();
        inject_to_grpc(&context, &mut grpc_metadata);
        assert_eq!(grpc_metadata.get("baggage"), http_headers.get("baggage"));
    }

    #[test]
    fn propagation_helpers_accept_alternate_hashers() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::BuildHasherDefault;

        type HeaderMap = HashMap<String, String, BuildHasherDefault<DefaultHasher>>;

        let mut headers = HeaderMap::with_hasher(BuildHasherDefault::default());
        headers.insert(
            "traceparent".to_string(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        );
        headers.insert("baggage".to_string(), "tenant=gamma".to_string());

        let propagation =
            extract_propagation_from_http(&headers).expect("alternate-hasher extraction failed");
        let context = propagation
            .trace_context
            .expect("trace context should be present");
        assert_eq!(context.baggage.get("tenant"), Some("gamma"));

        let mut outbound = HeaderMap::with_hasher(BuildHasherDefault::default());
        inject_to_http(&context, &mut outbound).expect("alternate-hasher HTTP injection failed");
        assert!(outbound.contains_key("traceparent"));
        assert_eq!(
            outbound.get("baggage").map(String::as_str),
            Some("tenant=gamma")
        );

        let mut grpc_metadata = HeaderMap::with_hasher(BuildHasherDefault::default());
        inject_to_grpc(&context, &mut grpc_metadata);
        assert_eq!(
            grpc_metadata.get("traceparent"),
            outbound.get("traceparent")
        );
    }

    #[test]
    fn baggage_percent_decoding_and_metadata_are_handled() {
        let baggage =
            W3CBaggage::from_header("user=alice%20smith;tenant=ignored,encoded=a%2Cb%3Bc,empty=")
                .expect("baggage parse failed");

        assert_eq!(baggage.get("user"), Some("alice smith"));
        assert_eq!(baggage.metadata("user"), Some("tenant=ignored"));
        assert_eq!(baggage.get("encoded"), Some("a,b;c"));
        assert_eq!(baggage.get("empty"), Some(""));
        assert_eq!(
            baggage.to_header().expect("baggage serialization failed"),
            "empty=,encoded=a%2Cb%3Bc,user=alice%20smith;tenant=ignored"
        );
    }

    #[test]
    fn baggage_duplicate_keys_use_last_value_and_invalid_members_fail() {
        let baggage = W3CBaggage::from_header("tenant=alpha,tenant=beta")
            .expect("duplicate baggage parse failed");
        assert_eq!(baggage.get("tenant"), Some("beta"));

        assert!(matches!(
            W3CBaggage::from_header("=value"),
            Err(TraceContextError::InvalidBaggage(_))
        ));
        assert!(matches!(
            W3CBaggage::from_header("bad@key=value"),
            Err(TraceContextError::InvalidBaggage(_))
        ));
        assert!(matches!(
            W3CBaggage::from_header("key=%GG"),
            Err(TraceContextError::InvalidBaggage(_))
        ));
    }

    #[test]
    fn baggage_security_bounds_are_enforced() {
        let long_header = format!("key={}", "x".repeat(MAX_BAGGAGE_HEADER_LENGTH));
        assert!(matches!(
            W3CBaggage::from_header(&long_header),
            Err(TraceContextError::ValueTooLong(_))
        ));

        let too_many = (0..=MAX_BAGGAGE_ITEMS)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(matches!(
            W3CBaggage::from_header(&too_many),
            Err(TraceContextError::TooManyBaggageItems(_))
        ));

        let mut baggage = W3CBaggage::new();
        for index in 0..MAX_BAGGAGE_ITEMS {
            baggage.insert(format!("k{index}"), "v").unwrap();
        }
        assert!(matches!(
            baggage.insert("overflow", "v"),
            Err(TraceContextError::TooManyBaggageItems(_))
        ));
    }

    #[test]
    fn child_context_preserves_trace_id() {
        let parent = W3CTraceContext::new_root();
        let child = parent.create_child();

        assert_eq!(parent.trace_id, child.trace_id);
        assert_eq!(parent.span_id, child.parent_span_id);
        assert_ne!(parent.span_id, child.span_id);
        assert_eq!(parent.baggage, child.baggage);
    }

    #[test]
    fn security_bounds_prevent_amplification() {
        let long_traceparent = "00-".to_string() + &"a".repeat(200);
        let result = W3CTraceContext::from_str(&long_traceparent);

        assert!(matches!(result, Err(TraceContextError::ValueTooLong(_))));
    }

    #[test]
    fn invalid_trace_id_rejected() {
        let invalid = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        let result = W3CTraceContext::from_str(invalid);

        assert!(matches!(result, Err(TraceContextError::InvalidTraceId)));
    }

    #[test]
    fn flags_must_be_exactly_two_hex_digits() {
        let base = "4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7";
        // Well-formed two-hex-digit flags parse.
        assert!(W3CTraceContext::from_str(&format!("00-{base}-01")).is_ok());
        assert!(W3CTraceContext::from_str(&format!("00-{base}-ff")).is_ok());
        // Wrong length, non-hex, sign-prefixed, or whitespace flags must be
        // rejected — the W3C version-00 traceparent format requires exactly two
        // hex digits, and `u8::from_str_radix` would otherwise leniently accept
        // "1" / "+1".
        for bad in ["1", "001", "+1", "0g", "", " 1"] {
            assert!(
                matches!(
                    W3CTraceContext::from_str(&format!("00-{base}-{bad}")),
                    Err(TraceContextError::InvalidFormat(_))
                ),
                "flags {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn continue_or_start_trace_continues_a_valid_trace_as_a_child_span() {
        let upstream = W3CTraceContext::new_root();
        let mut headers = HashMap::new();
        headers.insert("traceparent".to_string(), upstream.to_traceparent());
        headers.insert("tracestate".to_string(), "vendor=a".to_string());
        headers.insert("baggage".to_string(), "user=7".to_string());

        let hop = continue_or_start_trace(&headers);
        assert_eq!(hop.trace_id, upstream.trace_id);
        assert_eq!(hop.parent_span_id, upstream.span_id);
        assert_ne!(hop.span_id, upstream.span_id);
        assert_eq!(hop.flags, upstream.flags);
        assert_eq!(hop.tracestate.as_deref(), Some("vendor=a"));
        assert_eq!(hop.baggage.get("user"), Some("7"));
    }

    #[test]
    fn continue_or_start_trace_restarts_a_missing_or_invalid_trace() {
        let mut headers = HashMap::new();
        headers.insert("tracestate".to_string(), "vendor=a".to_string());
        let fresh = continue_or_start_trace(&headers);
        assert!(
            fresh.tracestate.is_none(),
            "no traceparent: tracestate is dropped"
        );

        headers.insert("traceparent".to_string(), "00-not-a-trace-01".to_string());
        let restarted = continue_or_start_trace(&headers);
        assert!(
            restarted.tracestate.is_none(),
            "invalid traceparent: tracestate is dropped"
        );
        assert_ne!(
            restarted.trace_id, fresh.trace_id,
            "each start is a new trace"
        );
    }

    #[test]
    fn continue_or_start_trace_keeps_the_trace_when_only_baggage_is_malformed() {
        let upstream = W3CTraceContext::new_root();
        let mut headers = HashMap::new();
        headers.insert("traceparent".to_string(), upstream.to_traceparent());
        headers.insert(
            "baggage".to_string(),
            "=".repeat(MAX_BAGGAGE_HEADER_LENGTH + 1),
        );

        let hop = continue_or_start_trace(&headers);
        assert_eq!(hop.trace_id, upstream.trace_id);
        assert!(hop.baggage.is_empty());
    }

    #[test]
    fn continue_or_start_trace_with_replays_the_ids_of_its_entropy() {
        // A counter stands in for a seeded entropy source.
        let seeded = || {
            let mut next = 0u8;
            move |bytes: &mut [u8]| {
                for byte in bytes {
                    next = next.wrapping_add(1);
                    *byte = next;
                }
            }
        };
        let upstream = W3CTraceContext::new_root();
        let mut continued = HashMap::new();
        continued.insert("traceparent".to_string(), upstream.to_traceparent());
        for headers in [HashMap::new(), continued] {
            let first = continue_or_start_trace_with(&headers, seeded());
            let second = continue_or_start_trace_with(&headers, seeded());
            assert_eq!(first, second, "the same entropy gives the same ids");
            assert_ne!(first.span_id, upstream.span_id);
        }

        // An all-zero fill still yields ids W3C accepts.
        let zero = continue_or_start_trace_with(&HashMap::new(), |bytes: &mut [u8]| {
            bytes.fill(0);
        });
        let reparsed = W3CTraceContext::from_str(&zero.to_traceparent()).expect("valid ids");
        assert_eq!(reparsed.trace_id, zero.trace_id);
    }

    #[test]
    fn continue_or_start_trace_keeps_a_tracestate_up_to_512_characters() {
        let upstream = W3CTraceContext::new_root();
        for (len, kept) in [(300, true), (MAX_TRACESTATE_LENGTH + 1, false)] {
            let mut headers = HashMap::new();
            headers.insert("traceparent".to_string(), upstream.to_traceparent());
            headers.insert("tracestate".to_string(), "a".repeat(len));
            let hop = continue_or_start_trace(&headers);
            assert_eq!(
                hop.tracestate.is_some(),
                kept,
                "tracestate of {len} characters"
            );
        }
    }

    /// An incoming tracestate is sent again on every outgoing request of its
    /// trace (asupersync-mu5yhv, d0's LOW 4). One holding a byte that no
    /// header value can carry made each of those requests fail; it is now
    /// dropped. Spaces and tabs around it, which HTTP/2 refuses, are trimmed.
    /// Bytes a header carries, non-ASCII included, are kept as before.
    #[test]
    fn an_incoming_tracestate_with_a_byte_no_header_can_carry_is_dropped() {
        let upstream = W3CTraceContext::new_root();
        for (tracestate, kept) in [
            ("vendor=a,other=b", Some("vendor=a,other=b")),
            ("vendor=a ,\tother=b~c", Some("vendor=a ,\tother=b~c")),
            ("vendor=caf\u{e9}", Some("vendor=caf\u{e9}")),
            (" \tvendor=a\t ", Some("vendor=a")),
            ("vendor=\u{1}a", None),
            ("vendor=a\r\nx-injected: 1", None),
            ("vendor=\u{7f}", None),
            (" \t ", None),
        ] {
            let mut headers = HashMap::new();
            headers.insert("traceparent".to_string(), upstream.to_traceparent());
            headers.insert("tracestate".to_string(), tracestate.to_string());
            let hop = continue_or_start_trace(&headers);
            assert_eq!(hop.tracestate.as_deref(), kept, "continued {tracestate:?}");
            let extracted = extract_from_http(&headers)
                .expect("valid traceparent")
                .expect("trace context");
            assert_eq!(
                extracted.tracestate.as_deref(),
                kept,
                "extracted {tracestate:?}"
            );
        }
    }
