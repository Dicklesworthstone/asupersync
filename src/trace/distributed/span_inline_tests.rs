    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::distributed::context::{RegionTag, SymbolTraceContext};
    use crate::trace::distributed::id::{DistTraceId, SymbolSpanId};
    use crate::util::DetRng;

    fn fresh_span() -> SymbolSpan {
        let mut rng = DetRng::new(42);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(1),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        SymbolSpan::new_encode(ctx, ObjectId::new_for_test(1), Time::from_millis(0))
    }

    // br-asupersync-65gy5c: sensitive-keyword denylist — values
    // whose key matches any denylist entry (case-insensitive
    // substring) are stored as <redacted>.
    #[test]
    fn set_attribute_redacts_authorization_header_65gy5c() {
        let mut span = fresh_span();
        span.set_attribute("Authorization", "Bearer sk_live_ABC123_secret");
        assert_eq!(
            span.attributes().get("Authorization").map(String::as_str),
            Some("<redacted>")
        );
    }

    #[test]
    fn set_attribute_redacts_cookie_x_api_key_password_65gy5c() {
        for key in &[
            "cookie",
            "Set-Cookie",
            "x-api-key",
            "X-Api-Key",
            "password",
            "PASSWORD",
            "session",
        ] {
            let mut span = fresh_span();
            span.set_attribute(*key, "sensitive-value-that-must-not-leak");
            assert_eq!(
                span.attributes().get(*key).map(String::as_str),
                Some("<redacted>"),
                "key {key} should be redacted"
            );
        }
    }

    #[test]
    fn set_attribute_truncates_long_value_65gy5c() {
        let mut span = fresh_span();
        let big = "A".repeat(MAX_SPAN_ATTRIBUTE_VALUE_LEN * 2);
        span.set_attribute("blob", big.clone());
        let stored = span.attributes().get("blob").expect("stored");
        assert!(
            stored.len() <= MAX_SPAN_ATTRIBUTE_VALUE_LEN,
            "stored len {} exceeds cap {}",
            stored.len(),
            MAX_SPAN_ATTRIBUTE_VALUE_LEN,
        );
        // Truncation must include a stable hash suffix so two
        // truncated values from the same input compare equal.
        assert!(stored.contains('…'));
        assert!(stored.contains('#'));
    }

    #[test]
    fn set_attribute_scrubs_control_bytes_65gy5c() {
        let mut span = fresh_span();
        // Newlines + NULs in the value would enable log-injection
        // downstream; they must be replaced with '_'.
        span.set_attribute("path", "/api/v1\n\rINJECTED: HEADER\0\u{1b}[31m");
        let stored = span.attributes().get("path").expect("stored");
        assert!(!stored.contains('\n'));
        assert!(!stored.contains('\r'));
        assert!(!stored.contains('\0'));
        assert!(!stored.contains('\u{1b}'));
        assert!(stored.contains('_'));
    }

    #[test]
    fn set_attribute_caps_cardinality_at_64_65gy5c() {
        let mut span = fresh_span();
        // Insert 100 distinct keys; only the first 64 should occupy
        // their own slots, the rest land in _overflow_attributes.
        for i in 0..100 {
            span.set_attribute(format!("key_{i}"), format!("v_{i}"));
        }
        // Per-key cap is 64; overflow bucket adds 1 more (so total
        // distinct keys is at most 65).
        assert!(
            span.attributes().len() <= MAX_SPAN_ATTRIBUTES_PER_SPAN + 1,
            "cardinality leak: {} attributes",
            span.attributes().len()
        );
        let overflow = span
            .attributes()
            .get("_overflow_attributes")
            .expect("overflow bucket present");
        let n: u64 = overflow.parse().expect("overflow is numeric");
        assert!(n >= 36, "overflow count too low: {n}");
    }

    #[test]
    fn set_attribute_replacing_existing_key_does_not_count_against_cardinality_65gy5c() {
        let mut span = fresh_span();
        // Fill exactly to cap.
        for i in 0..MAX_SPAN_ATTRIBUTES_PER_SPAN {
            span.set_attribute(format!("key_{i}"), "v");
        }
        let len_before = span.attributes().len();
        // Replacing key_0 with a new value must NOT push us into the
        // overflow path even though we're at cap.
        span.set_attribute("key_0", "new_value");
        assert_eq!(span.attributes().len(), len_before);
        assert_eq!(
            span.attributes().get("key_0").map(String::as_str),
            Some("new_value")
        );
    }

    #[test]
    fn span_duration_calculates() {
        let mut rng = DetRng::new(42);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(1),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span =
            SymbolSpan::new_encode(ctx, ObjectId::new_for_test(1), Time::from_millis(100));
        assert!(span.duration().is_none());
        span.complete_ok(Time::from_millis(150));
        assert_eq!(span.duration(), Some(Time::from_millis(50)));
    }

    #[test]
    fn span_error_recording() {
        let mut rng = DetRng::new(7);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(2),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span =
            SymbolSpan::new_decode(ctx, ObjectId::new_for_test(2), 4, Time::from_millis(10));
        span.complete_error(Time::from_millis(20), "decode failed");
        assert_eq!(span.status(), SymbolSpanStatus::Error);
        assert_eq!(span.error_message(), Some("decode failed"));
    }

    #[test]
    fn span_cancelled_status_transition() {
        let mut rng = DetRng::new(10);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(3),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(3), Time::from_millis(0));
        assert_eq!(span.status(), SymbolSpanStatus::InProgress);

        span.complete_cancelled(Time::from_millis(5));
        assert_eq!(span.status(), SymbolSpanStatus::Cancelled);
        assert!(span.end_time().is_some());
        assert!(span.error_message().is_none());
    }

    #[test]
    fn span_dropped_status_transition() {
        let mut rng = DetRng::new(11);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(4),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let sid = SymbolId::new(ObjectId::new_for_test(4), 0, 0);
        let mut span = SymbolSpan::new_transmit(ctx, sid, Time::from_millis(100));
        assert_eq!(span.kind(), SymbolSpanKind::Transmit);

        span.mark_dropped(Time::from_millis(200));
        assert_eq!(span.status(), SymbolSpanStatus::Dropped);
        assert_eq!(span.duration(), Some(Time::from_millis(100)));
    }

    #[test]
    fn span_receive_kind_and_symbol_id() {
        let mut rng = DetRng::new(12);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(5),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let oid = ObjectId::new_for_test(5);
        let sid = SymbolId::new(oid, 3, 0);
        let span = SymbolSpan::new_receive(ctx, sid, Time::from_millis(50));

        assert_eq!(span.kind(), SymbolSpanKind::Receive);
        assert_eq!(span.symbol_id(), Some(sid));
        assert_eq!(span.object_id(), Some(oid));
        assert_eq!(span.status(), SymbolSpanStatus::InProgress);
    }

    #[test]
    fn span_decode_has_symbol_count() {
        let mut rng = DetRng::new(13);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(6),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let span = SymbolSpan::new_decode(ctx, ObjectId::new_for_test(6), 10, Time::from_millis(0));
        assert_eq!(span.kind(), SymbolSpanKind::Decode);
        assert_eq!(span.symbol_count(), Some(10));
        assert!(span.symbol_id().is_none());
    }

    #[test]
    fn span_set_symbol_count() {
        let mut rng = DetRng::new(14);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(7),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(7), Time::from_millis(0));
        assert!(span.symbol_count().is_none());

        span.set_symbol_count(42);
        assert_eq!(span.symbol_count(), Some(42));
    }

    #[test]
    fn span_attributes_set_and_retrieve() {
        let mut rng = DetRng::new(15);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(8),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(8), Time::from_millis(0));

        assert!(span.attributes().is_empty());

        span.set_attribute("codec", "raptorq");
        span.set_attribute("overhead", "1.05");

        assert_eq!(span.attributes().len(), 2);
        assert_eq!(
            span.attributes().get("codec").map(String::as_str),
            Some("raptorq")
        );
        assert_eq!(
            span.attributes().get("overhead").map(String::as_str),
            Some("1.05")
        );
    }

    #[test]
    fn span_attributes_overwrite_existing_key() {
        let mut rng = DetRng::new(16);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(9),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(9), Time::from_millis(0));

        span.set_attribute("retry", "0");
        span.set_attribute("retry", "1");

        assert_eq!(span.attributes().len(), 1);
        assert_eq!(
            span.attributes().get("retry").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn span_ok_completion_clears_in_progress() {
        let mut rng = DetRng::new(17);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(10),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let mut span =
            SymbolSpan::new_encode(ctx, ObjectId::new_for_test(10), Time::from_millis(0));

        assert_eq!(span.status(), SymbolSpanStatus::InProgress);
        assert!(span.end_time().is_none());
        assert!(span.error_message().is_none());

        span.complete_ok(Time::from_millis(50));

        assert_eq!(span.status(), SymbolSpanStatus::Ok);
        assert_eq!(span.end_time(), Some(Time::from_millis(50)));
        assert!(span.error_message().is_none());
    }

    #[test]
    fn span_context_is_accessible() {
        let mut rng = DetRng::new(18);
        let trace_id = DistTraceId::new_for_test(11);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(11), Time::from_millis(0));

        assert_eq!(span.context().trace_id(), trace_id);
    }

    // =========================================================================
    // Wave 53 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn symbol_span_status_debug_clone_copy() {
        let s = SymbolSpanStatus::InProgress;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("InProgress"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn symbol_span_kind_debug_clone_copy() {
        let k = SymbolSpanKind::Encode;
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Encode"), "{dbg}");
        let copied = k;
        let cloned = k;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn symbol_span_debug_clone() {
        let mut rng = DetRng::new(99);
        let ctx = SymbolTraceContext::new_for_encoding(
            DistTraceId::new_for_test(99),
            SymbolSpanId::NIL,
            RegionTag::new("test"),
            &mut rng,
        );
        let span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(99), Time::from_millis(0));
        let dbg = format!("{span:?}");
        assert!(dbg.contains("SymbolSpan"), "{dbg}");
        let cloned = span;
        assert_eq!(cloned.kind(), SymbolSpanKind::Encode);
    }
