    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send,
        unused_must_use
    )]
    use super::*;
    use crate::grpc::Code;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[derive(Debug)]
    struct ResponseOrderInterceptor {
        name: &'static str,
        calls: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl Interceptor for ResponseOrderInterceptor {
        fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
            Ok(())
        }

        fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
            Ok(())
        }

        fn intercept_response_with_request(
            &self,
            _request: &Request<Bytes>,
            _response: &mut Response<Bytes>,
        ) -> Result<(), Status> {
            self.calls.lock().unwrap().push(self.name);
            Ok(())
        }
    }

    #[test]
    fn interceptor_layer_empty() {
        init_test("interceptor_layer_empty");
        let layer = InterceptorLayer::new();
        let empty = layer.is_empty();
        crate::assert_with_log!(empty, "empty", true, empty);
        let len = layer.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("interceptor_layer_empty");
    }

    #[test]
    fn interceptor_layer_chain() {
        init_test("interceptor_layer_chain");
        let layer = InterceptorLayer::new()
            .layer(trace_interceptor())
            .layer(logging_interceptor());

        let empty = layer.is_empty();
        crate::assert_with_log!(!empty, "not empty", false, empty);
        let len = layer.len();
        crate::assert_with_log!(len == 2, "len", 2, len);
        crate::test_complete!("interceptor_layer_chain");
    }

    #[test]
    fn interceptor_layer_request() {
        init_test("interceptor_layer_request");
        let layer = InterceptorLayer::new().layer(trace_interceptor());

        let mut request = Request::new(Bytes::new());
        layer.intercept_request(&mut request).unwrap();

        let has_id = request.metadata().get("x-request-id").is_some();
        crate::assert_with_log!(has_id, "request id", true, has_id);
        crate::test_complete!("interceptor_layer_request");
    }

    #[test]
    fn bearer_auth_interceptor() {
        init_test("bearer_auth_interceptor");
        let interceptor = auth_bearer_interceptor("my-token");

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let auth = request.metadata().get("authorization").unwrap();
        let ok = matches!(auth, MetadataValue::Ascii(s) if s == "Bearer my-token");
        crate::assert_with_log!(ok, "auth header", true, ok);
        crate::test_complete!("bearer_auth_interceptor");
    }

    #[test]
    fn constant_time_eq_correctness() {
        // br-asupersync-2dro05: the timing-safe byte comparison must
        // return the same boolean as ordinary equality for *any* input
        // shape — equal-length differing-first-byte, equal-length
        // differing-last-byte, mismatched lengths, empty inputs, the
        // identical-pointer case. This test pins the *correctness*
        // surface; timing-side-channel resistance is a property of the
        // algorithm (no early-exit) and the `black_box` barrier rather
        // than something a unit test can measure directly.
        init_test("constant_time_eq_correctness");
        // Identical content.
        crate::assert_with_log!(
            super::constant_time_eq(b"hello", b"hello"),
            "identical",
            true,
            super::constant_time_eq(b"hello", b"hello")
        );
        // Differing first byte (would short-circuit fastest under naive ==).
        crate::assert_with_log!(
            !super::constant_time_eq(b"Xello", b"hello"),
            "first-byte differ",
            false,
            super::constant_time_eq(b"Xello", b"hello")
        );
        // Differing last byte (would short-circuit slowest under naive ==).
        crate::assert_with_log!(
            !super::constant_time_eq(b"hellX", b"hello"),
            "last-byte differ",
            false,
            super::constant_time_eq(b"hellX", b"hello")
        );
        // Mismatched lengths: length is not secret; early-return is OK.
        crate::assert_with_log!(
            !super::constant_time_eq(b"hello", b"hellos"),
            "length mismatch (longer)",
            false,
            super::constant_time_eq(b"hello", b"hellos")
        );
        crate::assert_with_log!(
            !super::constant_time_eq(b"hello", b"hell"),
            "length mismatch (shorter)",
            false,
            super::constant_time_eq(b"hello", b"hell")
        );
        // Both empty.
        crate::assert_with_log!(
            super::constant_time_eq(b"", b""),
            "both empty",
            true,
            super::constant_time_eq(b"", b"")
        );
        // One empty, one not.
        crate::assert_with_log!(
            !super::constant_time_eq(b"", b"x"),
            "empty vs non-empty",
            false,
            super::constant_time_eq(b"", b"x")
        );
        // Black-box wrapping: a hostile optimiser cannot fold the
        // comparison into a constant when both sides are computed at
        // runtime. We exercise that with `std::hint::black_box`-wrapped
        // inputs.
        let a = std::hint::black_box(b"super-secret-bearer-token-abcdefg".to_vec());
        let b = std::hint::black_box(b"super-secret-bearer-token-XXXXXXX".to_vec());
        crate::assert_with_log!(
            !super::constant_time_eq(&a, &b),
            "differing tail under black_box",
            false,
            super::constant_time_eq(&a, &b)
        );
        let c = std::hint::black_box(b"super-secret-bearer-token-abcdefg".to_vec());
        crate::assert_with_log!(
            super::constant_time_eq(&a, &c),
            "matching under black_box",
            true,
            super::constant_time_eq(&a, &c)
        );
        crate::test_complete!("constant_time_eq_correctness");
    }

    #[test]
    fn bearer_auth_validator_with_token_accepts_correct_token() {
        // br-asupersync-2dro05: the constant-time `with_token`
        // constructor accepts the exact configured token.
        init_test("bearer_auth_validator_with_token_accepts_correct_token");
        let interceptor = auth_validator_with_token("super-secret-token");
        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("authorization", "Bearer super-secret-token");
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "with_token accepts correct", true, ok);
        crate::test_complete!("bearer_auth_validator_with_token_accepts_correct_token");
    }

    #[test]
    fn bearer_auth_validator_with_token_rejects_wrong_token_at_any_position() {
        // br-asupersync-2dro05: with_token must reject every
        // wrong-token shape — first-byte differ, last-byte differ,
        // shorter, longer — without ever returning `Ok`. The
        // *correctness* surface mirrors what an attacker would probe;
        // timing equivalence across these shapes is the security
        // property `constant_time_eq` provides.
        init_test("bearer_auth_validator_with_token_rejects_wrong_token_at_any_position");
        let interceptor = auth_validator_with_token("super-secret-token");
        for wrong in [
            "Xuper-secret-token",  // first-byte differ
            "super-secret-tokeX",  // last-byte differ
            "super-secret-toke",   // shorter
            "super-secret-tokens", // longer
            "totally-different",   // unrelated
            "",                    // empty
        ] {
            let mut request = Request::new(Bytes::new());
            let header = format!("Bearer {wrong}");
            request.metadata_mut().insert("authorization", &header);
            let err = interceptor.intercept_request(&mut request).is_err();
            crate::assert_with_log!(err, "with_token rejects wrong token", true, err);
        }
        crate::test_complete!(
            "bearer_auth_validator_with_token_rejects_wrong_token_at_any_position"
        );
    }

    #[test]
    fn bearer_auth_validator_success() {
        init_test("bearer_auth_validator_success");
        let interceptor = auth_validator(|token| token == "valid-token");

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("authorization", "Bearer valid-token");

        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "intercept ok", true, ok);
        crate::test_complete!("bearer_auth_validator_success");
    }

    #[test]
    fn bearer_auth_validator_invalid() {
        init_test("bearer_auth_validator_invalid");
        let interceptor = auth_validator(|token| token == "valid-token");

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("authorization", "Bearer invalid-token");

        let err = interceptor.intercept_request(&mut request).unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == Code::Unauthenticated,
            "code",
            Code::Unauthenticated,
            code
        );
        crate::test_complete!("bearer_auth_validator_invalid");
    }

    #[test]
    fn bearer_auth_validator_missing() {
        init_test("bearer_auth_validator_missing");
        let interceptor = auth_validator(|_| true);

        let mut request = Request::new(Bytes::new());
        let err = interceptor.intercept_request(&mut request).unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == Code::Unauthenticated,
            "code",
            Code::Unauthenticated,
            code
        );
        crate::test_complete!("bearer_auth_validator_missing");
    }

    #[test]
    fn bearer_auth_validator_accepts_case_insensitive_scheme() {
        init_test("bearer_auth_validator_accepts_case_insensitive_scheme");
        let interceptor = auth_validator(|token| token == "valid-token");

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("authorization", "bEaReR valid-token");

        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "intercept ok", true, ok);
        crate::test_complete!("bearer_auth_validator_accepts_case_insensitive_scheme");
    }

    #[test]
    fn bearer_auth_validator_rejects_empty_token() {
        init_test("bearer_auth_validator_rejects_empty_token");
        let interceptor = auth_validator(|_| true);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("authorization", "Bearer ");

        let err = interceptor.intercept_request(&mut request).unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == Code::Unauthenticated,
            "code",
            Code::Unauthenticated,
            code
        );
        crate::test_complete!("bearer_auth_validator_rejects_empty_token");
    }

    #[test]
    fn metadata_propagator_marks_keys() {
        init_test("metadata_propagator_marks_keys");
        let interceptor = metadata_propagator(["x-request-id", "x-trace-id"]);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("x-request-id", "req-123");
        request.metadata_mut().insert("x-trace-id", "trace-456");

        interceptor.intercept_request(&mut request).unwrap();

        match request.metadata().get("x-propagate-keys") {
            Some(MetadataValue::Ascii(keys)) => {
                crate::assert_with_log!(
                    keys == "x-request-id x-trace-id",
                    "space-delimited propagate keys",
                    "x-request-id x-trace-id",
                    keys
                );
                let has_comma_separator = keys.contains(",x-trace-id")
                    || keys.contains("x-request-id,")
                    || keys.contains(',');
                crate::assert_with_log!(
                    !has_comma_separator,
                    "comma separator removed",
                    false,
                    has_comma_separator
                );
            }
            other => panic!("expected x-propagate-keys metadata, got: {other:?}"),
        }
        crate::test_complete!("metadata_propagator_marks_keys");
    }

    #[test]
    fn metadata_propagator_rejects_comma_keys() {
        init_test("metadata_propagator_rejects_comma_keys");
        let interceptor = metadata_propagator(["x-request-id", "x,trace,id"]);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("x-request-id", "req-123");

        interceptor.intercept_request(&mut request).unwrap();

        match request.metadata().get("x-propagate-keys") {
            Some(MetadataValue::Ascii(keys)) => {
                crate::assert_with_log!(
                    keys == "x-request-id",
                    "invalid comma key dropped",
                    "x-request-id",
                    keys
                );
            }
            other => panic!("expected x-propagate-keys metadata, got: {other:?}"),
        }
        crate::test_complete!("metadata_propagator_rejects_comma_keys");
    }

    #[test]
    fn rate_limiter_allows_under_limit() {
        init_test("rate_limiter_allows_under_limit");
        let interceptor = rate_limiter(10);
        let mut admitted = Vec::new();

        for _ in 0..10 {
            let mut request = Request::new(Bytes::new());
            let ok = interceptor.intercept_request(&mut request).is_ok();
            crate::assert_with_log!(ok, "intercept ok", true, ok);
            admitted.push(request);
        }

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 10, "count", 10, count);
        drop(admitted);

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count after drop", 0, count);
        crate::test_complete!("rate_limiter_allows_under_limit");
    }

    /// Chained limiters shared one typed extension entry. The second
    /// limiter's lease replaced the first, which released the first
    /// limiter's slot at once, so the outer limit stopped being enforced.
    #[test]
    fn chained_rate_limiters_each_hold_their_own_slot() {
        init_test("chained_rate_limiters_each_hold_their_own_slot");
        let outer = rate_limiter(1);
        let inner = rate_limiter(5);
        let mut first = Request::new(Bytes::new());
        outer.intercept_request(&mut first).expect("outer admits");
        inner.intercept_request(&mut first).expect("inner admits");
        assert_eq!((outer.current_count(), inner.current_count()), (1, 1));

        let mut second = Request::new(Bytes::new());
        let status = outer
            .intercept_request(&mut second)
            .expect_err("the outer limit of 1 still holds");
        assert_eq!(status.code(), Code::ResourceExhausted);

        let mut response = Response::new(Bytes::new());
        inner
            .intercept_response_with_request(&first, &mut response)
            .expect("inner release");
        assert_eq!(
            (outer.current_count(), inner.current_count()),
            (1, 0),
            "each limiter releases only its own slot"
        );
        drop(first);
        assert_eq!(
            outer.current_count(),
            0,
            "dropping the request releases the rest"
        );
        crate::test_complete!("chained_rate_limiters_each_hold_their_own_slot");
    }

    #[test]
    fn rate_limiter_rejects_over_limit() {
        init_test("rate_limiter_rejects_over_limit");
        let interceptor = rate_limiter(2);

        let mut first_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut first_request).is_ok();
        crate::assert_with_log!(ok, "first ok", true, ok);

        let mut second_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut second_request).is_ok();
        crate::assert_with_log!(ok, "second ok", true, ok);

        let mut rejected_request = Request::new(Bytes::new());
        let err = interceptor
            .intercept_request(&mut rejected_request)
            .unwrap_err();
        let code = err.code();
        crate::assert_with_log!(
            code == Code::ResourceExhausted,
            "code",
            Code::ResourceExhausted,
            code
        );
        crate::test_complete!("rate_limiter_rejects_over_limit");
    }

    #[test]
    fn rate_limiter_reset() {
        init_test("rate_limiter_reset");
        let interceptor = rate_limiter(1);

        let mut first_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut first_request).is_ok();
        crate::assert_with_log!(ok, "first ok", true, ok);

        let mut rejected_request = Request::new(Bytes::new());
        let err = interceptor
            .intercept_request(&mut rejected_request)
            .is_err();
        crate::assert_with_log!(err, "second err", true, err);

        interceptor.reset();
        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count", 0, count);

        let mut request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "after reset ok", true, ok);
        crate::test_complete!("rate_limiter_reset");
    }

    #[test]
    fn rate_limiter_reset_ignores_stale_pre_reset_lease_drop() {
        init_test("rate_limiter_reset_ignores_stale_pre_reset_lease_drop");
        let interceptor = rate_limiter(2);

        let mut stale_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut stale_request).is_ok();
        crate::assert_with_log!(ok, "stale request ok", true, ok);

        interceptor.reset();

        let mut fresh_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut fresh_request).is_ok();
        crate::assert_with_log!(ok, "fresh request ok", true, ok);

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 1, "fresh count", 1, count);

        drop(stale_request);

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 1, "count after stale drop", 1, count);

        drop(fresh_request);

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count after fresh drop", 0, count);
        crate::test_complete!("rate_limiter_reset_ignores_stale_pre_reset_lease_drop");
    }

    #[test]
    fn rate_limiter_releases_slot_on_response() {
        init_test("rate_limiter_releases_slot_on_response");
        let interceptor = rate_limiter(1);

        let mut first_request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut first_request).unwrap();

        let mut blocked_request = Request::new(Bytes::new());
        let blocked = interceptor.intercept_request(&mut blocked_request).is_err();
        crate::assert_with_log!(
            blocked,
            "second blocked while first inflight",
            true,
            blocked
        );

        let mut response = Response::new(Bytes::new());
        interceptor
            .intercept_response_with_request(&first_request, &mut response)
            .unwrap();

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count after release", 0, count);

        let mut retry_request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut retry_request).is_ok();
        crate::assert_with_log!(ok, "request after response ok", true, ok);
        crate::test_complete!("rate_limiter_releases_slot_on_response");
    }

    #[test]
    fn rate_limiter_response_without_request_does_not_underflow() {
        init_test("rate_limiter_response_without_request_does_not_underflow");
        let interceptor = rate_limiter(1);

        let mut response = Response::new(Bytes::new());
        interceptor.intercept_response(&mut response).unwrap();

        let count = interceptor.current_count();
        crate::assert_with_log!(count == 0, "count stays at zero", 0, count);

        let mut request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "request after stray response ok", true, ok);
        crate::test_complete!("rate_limiter_response_without_request_does_not_underflow");
    }

    #[test]
    fn timeout_interceptor_adds_header() {
        init_test("timeout_interceptor_adds_header");
        let interceptor = timeout_interceptor(5000);

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let timeout = request.metadata().get("grpc-timeout").unwrap();
        let ok = matches!(timeout, MetadataValue::Ascii(s) if s == "5S");
        crate::assert_with_log!(ok, "timeout header", true, ok);
        crate::test_complete!("timeout_interceptor_adds_header");
    }

    #[test]
    fn timeout_interceptor_uses_valid_eight_digit_timeout_header() {
        init_test("timeout_interceptor_uses_valid_eight_digit_timeout_header");
        let interceptor = timeout_interceptor(100_000_000);

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let timeout = request.metadata().get("grpc-timeout").unwrap();
        let ok = matches!(timeout, MetadataValue::Ascii(s) if s == "100000S");
        crate::assert_with_log!(ok, "large timeout header stays valid", true, ok);
        crate::test_complete!("timeout_interceptor_uses_valid_eight_digit_timeout_header");
    }

    #[test]
    fn timeout_interceptor_preserves_existing() {
        init_test("timeout_interceptor_preserves_existing");
        let interceptor = timeout_interceptor(5000);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("grpc-timeout", "1000m");

        interceptor.intercept_request(&mut request).unwrap();

        let timeout = request.metadata().get("grpc-timeout").unwrap();
        let ok = matches!(timeout, MetadataValue::Ascii(s) if s == "1000m");
        crate::assert_with_log!(ok, "timeout header", true, ok);
        crate::test_complete!("timeout_interceptor_preserves_existing");
    }

    #[test]
    fn timeout_interceptor_repairs_malformed_existing_header() {
        init_test("timeout_interceptor_repairs_malformed_existing_header");
        let interceptor = timeout_interceptor(5000);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("grpc-timeout", "bogus");

        interceptor.intercept_request(&mut request).unwrap();

        let timeout = request.metadata().get("grpc-timeout").unwrap();
        let ok = matches!(timeout, MetadataValue::Ascii(s) if s == "5S");
        crate::assert_with_log!(ok, "malformed timeout repaired", true, ok);

        let timeout_count = request
            .metadata()
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("grpc-timeout"))
            .count();
        crate::assert_with_log!(
            timeout_count == 1,
            "repaired timeout replaces invalid duplicate",
            1,
            timeout_count
        );
        crate::test_complete!("timeout_interceptor_repairs_malformed_existing_header");
    }

    #[test]
    fn fn_interceptor_custom() {
        init_test("fn_interceptor_custom");
        let interceptor = fn_interceptor(|request: &mut Request<Bytes>| {
            request.metadata_mut().insert("x-custom", "value");
            Ok(())
        });

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let value = request.metadata().get("x-custom").unwrap();
        let ok = matches!(value, MetadataValue::Ascii(s) if s == "value");
        crate::assert_with_log!(ok, "custom header", true, ok);
        crate::test_complete!("fn_interceptor_custom");
    }

    #[test]
    fn logging_interceptor_marks_request() {
        init_test("logging_interceptor_marks_request");
        let interceptor = logging_interceptor();

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let logged = request.metadata().get("x-logged").is_some();
        crate::assert_with_log!(logged, "logged header", true, logged);
        crate::test_complete!("logging_interceptor_marks_request");
    }

    #[test]
    fn logging_interceptor_marks_response() {
        init_test("logging_interceptor_marks_response");
        let interceptor = logging_interceptor();

        let mut response = Response::new(Bytes::new());
        interceptor.intercept_response(&mut response).unwrap();

        let logged = response.metadata().get("x-logged").is_some();
        crate::assert_with_log!(logged, "logged header", true, logged);
        crate::test_complete!("logging_interceptor_marks_response");
    }

    #[test]
    fn metadata_propagator_copies_selected_request_metadata_to_response() {
        init_test("metadata_propagator_copies_selected_request_metadata_to_response");
        let interceptor = metadata_propagator(["x-request-id", "x-trace-id"]);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("x-request-id", "req-123");
        request.metadata_mut().insert("x-trace-id", "trace-456");
        request.metadata_mut().insert("x-unrelated", "skip-me");

        let mut response = Response::new(Bytes::new());
        interceptor
            .intercept_response_with_request(&request, &mut response)
            .unwrap();

        let request_id = response.metadata().get("x-request-id");
        let trace_id = response.metadata().get("x-trace-id");
        let unrelated = response.metadata().get("x-unrelated");

        let request_id_ok =
            matches!(request_id, Some(MetadataValue::Ascii(value)) if value == "req-123");
        let trace_id_ok =
            matches!(trace_id, Some(MetadataValue::Ascii(value)) if value == "trace-456");
        crate::assert_with_log!(request_id_ok, "request id propagated", true, request_id_ok);
        crate::assert_with_log!(trace_id_ok, "trace id propagated", true, trace_id_ok);
        crate::assert_with_log!(
            unrelated.is_none(),
            "unrelated absent",
            true,
            unrelated.is_none()
        );
        crate::test_complete!("metadata_propagator_copies_selected_request_metadata_to_response");
    }

    #[test]
    fn metadata_propagator_response_only_hook_is_requestless_noop() {
        init_test("metadata_propagator_response_only_hook_is_requestless_noop");
        let interceptor = metadata_propagator(["x-request-id"]);

        let mut response = Response::new(Bytes::new());
        interceptor.intercept_response(&mut response).unwrap();

        let propagated = response.metadata().get("x-request-id");
        crate::assert_with_log!(
            propagated.is_none(),
            "response-only hook does not invent request metadata",
            true,
            propagated.is_none()
        );
        crate::test_complete!("metadata_propagator_response_only_hook_is_requestless_noop");
    }

    #[test]
    fn interceptor_layer_request_aware_response_hook_preserves_composition() {
        init_test("interceptor_layer_request_aware_response_hook_preserves_composition");
        let layer = InterceptorLayer::new()
            .layer(logging_interceptor())
            .layer(metadata_propagator(["x-request-id"]));

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("x-request-id", "req-123");

        let mut response = Response::new(Bytes::new());
        layer
            .intercept_response_with_request(&request, &mut response)
            .unwrap();

        let logged = response.metadata().get("x-logged");
        let request_id = response.metadata().get("x-request-id");
        let logged_ok = matches!(logged, Some(MetadataValue::Ascii(value)) if value == "true");
        let request_id_ok =
            matches!(request_id, Some(MetadataValue::Ascii(value)) if value == "req-123");
        crate::assert_with_log!(logged_ok, "logging interceptor still runs", true, logged_ok);
        crate::assert_with_log!(
            request_id_ok,
            "request-aware propagation copies metadata",
            true,
            request_id_ok
        );
        crate::test_complete!(
            "interceptor_layer_request_aware_response_hook_preserves_composition"
        );
    }

    #[test]
    fn interceptor_layer_request_aware_response_hook_runs_in_reverse_order() {
        init_test("interceptor_layer_request_aware_response_hook_runs_in_reverse_order");

        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let layer = InterceptorLayer::new()
            .layer(ResponseOrderInterceptor {
                name: "outer",
                calls: std::sync::Arc::clone(&calls),
            })
            .layer(ResponseOrderInterceptor {
                name: "inner",
                calls: std::sync::Arc::clone(&calls),
            });

        let request = Request::new(Bytes::new());
        let mut response = Response::new(Bytes::new());
        layer
            .intercept_response_with_request(&request, &mut response)
            .unwrap();

        let calls = calls.lock().unwrap().clone();
        crate::assert_with_log!(
            calls == vec!["inner", "outer"],
            "request-aware response order",
            vec!["inner", "outer"],
            calls
        );
        crate::test_complete!(
            "interceptor_layer_request_aware_response_hook_runs_in_reverse_order"
        );
    }

    #[test]
    fn tracing_interceptor_generates_request_id() {
        init_test("tracing_interceptor_generates_request_id");
        let interceptor = trace_interceptor();

        let mut request = Request::new(Bytes::new());
        interceptor.intercept_request(&mut request).unwrap();

        let id = request.metadata().get("x-request-id").unwrap();
        let ok = matches!(id, MetadataValue::Ascii(s) if s.starts_with("req-"));
        crate::assert_with_log!(ok, "request id", true, ok);
        crate::test_complete!("tracing_interceptor_generates_request_id");
    }

    #[test]
    fn tracing_interceptor_uses_deterministic_sequential_ids() {
        init_test("tracing_interceptor_uses_deterministic_sequential_ids");
        let interceptor = trace_interceptor();
        let cloned = interceptor.clone();

        let mut first = Request::new(Bytes::new());
        interceptor.intercept_request(&mut first).unwrap();
        let first_id = first.metadata().get("x-request-id").unwrap();

        let mut second = Request::new(Bytes::new());
        cloned.intercept_request(&mut second).unwrap();
        let second_id = second.metadata().get("x-request-id").unwrap();

        let ok = matches!(
            (first_id, second_id),
            (MetadataValue::Ascii(first), MetadataValue::Ascii(second))
                if first == "req-0000000000000001" && second == "req-0000000000000002"
        );
        crate::assert_with_log!(ok, "sequential request ids", true, ok);
        crate::test_complete!("tracing_interceptor_uses_deterministic_sequential_ids");
    }

    #[test]
    fn tracing_interceptor_replaces_unsigned_client_request_id_by_default() {
        init_test("tracing_interceptor_replaces_unsigned_client_request_id_by_default");
        let interceptor = trace_interceptor();

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert(REQUEST_ID_METADATA_KEY, "req-client");
        interceptor.intercept_request(&mut request).unwrap();

        let ok = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-0000000000000001"
        );
        crate::assert_with_log!(ok, "unsigned client request id replaced", true, ok);
        crate::test_complete!("tracing_interceptor_replaces_unsigned_client_request_id_by_default");
    }

    #[test]
    fn tracing_interceptor_preserves_signed_request_id() {
        init_test("tracing_interceptor_preserves_signed_request_id");
        let interceptor =
            trace_interceptor().with_request_id_signature_verifier(|id: &str, sig: &str| {
                id == "req-client" && sig == "valid"
            });

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert(REQUEST_ID_METADATA_KEY, "req-client");
        request
            .metadata_mut()
            .insert(REQUEST_ID_SIGNATURE_METADATA_KEY, "valid");
        interceptor.intercept_request(&mut request).unwrap();

        let ok = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-client"
        );
        crate::assert_with_log!(ok, "signed request id preserved", true, ok);
        crate::test_complete!("tracing_interceptor_preserves_signed_request_id");
    }

    #[test]
    fn tracing_interceptor_replaces_invalid_signature_request_id() {
        init_test("tracing_interceptor_replaces_invalid_signature_request_id");
        let interceptor =
            trace_interceptor().with_request_id_signature_verifier(|_: &str, _: &str| false);

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert(REQUEST_ID_METADATA_KEY, "req-client");
        request
            .metadata_mut()
            .insert(REQUEST_ID_SIGNATURE_METADATA_KEY, "invalid");
        interceptor.intercept_request(&mut request).unwrap();

        let replaced = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-0000000000000001"
        );
        let signature_scrubbed = request
            .metadata()
            .get(REQUEST_ID_SIGNATURE_METADATA_KEY)
            .is_none();
        crate::assert_with_log!(replaced, "invalid signature id replaced", true, replaced);
        crate::assert_with_log!(
            signature_scrubbed,
            "invalid signature scrubbed",
            true,
            signature_scrubbed
        );
        crate::test_complete!("tracing_interceptor_replaces_invalid_signature_request_id");
    }

    #[test]
    fn tracing_interceptor_replaces_empty_signed_request_id() {
        init_test("tracing_interceptor_replaces_empty_signed_request_id");
        let interceptor =
            trace_interceptor().with_request_id_signature_verifier(|_: &str, _: &str| true);

        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert(REQUEST_ID_METADATA_KEY, "");
        request
            .metadata_mut()
            .insert(REQUEST_ID_SIGNATURE_METADATA_KEY, "valid");
        interceptor.intercept_request(&mut request).unwrap();

        let ok = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-0000000000000001"
        );
        crate::assert_with_log!(ok, "empty request id replaced", true, ok);
        crate::test_complete!("tracing_interceptor_replaces_empty_signed_request_id");
    }

    #[test]
    fn tracing_interceptor_trusted_edge_preserves_existing_request_id() {
        init_test("tracing_interceptor_trusted_edge_preserves_existing_request_id");
        let interceptor = trace_interceptor().with_trusted_client_request_ids();

        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert(REQUEST_ID_METADATA_KEY, "req-custom");
        interceptor.intercept_request(&mut request).unwrap();

        let ok = matches!(
            request.metadata().get(REQUEST_ID_METADATA_KEY),
            Some(MetadataValue::Ascii(id)) if id == "req-custom"
        );
        crate::assert_with_log!(ok, "trusted-edge request id preserved", true, ok);
        crate::test_complete!("tracing_interceptor_trusted_edge_preserves_existing_request_id");
    }

    fn ascii_metadata<'a>(request: &'a Request<Bytes>, key: &str) -> Option<&'a str> {
        request.metadata().get(key).and_then(metadata_to_string)
    }

    fn metadata_span(
        request: &Request<Bytes>,
    ) -> crate::observability::w3c_trace_context::W3CTraceContext {
        ascii_metadata(request, "traceparent")
            .expect("the interceptor always writes a traceparent")
            .parse()
            .expect("the written traceparent is valid")
    }

    #[test]
    fn w3c_trace_context_interceptor_continues_the_trace_at_every_hop() {
        init_test("w3c_trace_context_interceptor_continues_the_trace_at_every_hop");
        let upstream = crate::observability::w3c_trace_context::W3CTraceContext::new_root();
        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("traceparent", upstream.to_traceparent());
        request.metadata_mut().insert("tracestate", "vendor=a");
        request.metadata_mut().insert("baggage", "user=7");

        let interceptor = w3c_trace_context_interceptor();
        interceptor.intercept_request(&mut request).unwrap();
        let client_span = metadata_span(&request);
        assert_eq!(client_span.trace_id, upstream.trace_id);
        assert_ne!(client_span.span_id, upstream.span_id);
        assert_eq!(ascii_metadata(&request, "tracestate"), Some("vendor=a"));
        assert_eq!(ascii_metadata(&request, "baggage"), Some("user=7"));

        // The server side of the call continues the client's span.
        interceptor.intercept_request(&mut request).unwrap();
        let server_span = metadata_span(&request);
        assert_eq!(server_span.trace_id, upstream.trace_id);
        assert_ne!(server_span.span_id, client_span.span_id);
        let traceparents = request
            .metadata()
            .iter()
            .filter(|(key, _)| *key == "traceparent")
            .count();
        assert_eq!(traceparents, 1, "the traceparent is replaced, not appended");
        crate::test_complete!("w3c_trace_context_interceptor_continues_the_trace_at_every_hop");
    }

    #[test]
    fn w3c_trace_context_interceptor_restarts_an_invalid_trace_without_its_tracestate() {
        init_test("w3c_trace_context_interceptor_restarts_an_invalid_trace_without_its_tracestate");
        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("traceparent", "00-not-a-trace-01");
        request.metadata_mut().insert("tracestate", "vendor=a");
        request.metadata_mut().insert("baggage", "user=7");

        W3CTraceContextInterceptor::new()
            .intercept_request(&mut request)
            .unwrap();
        // The invalid traceparent is replaced by a new, valid trace.
        let _new_trace = metadata_span(&request);
        assert_eq!(ascii_metadata(&request, "tracestate"), None);
        assert_eq!(ascii_metadata(&request, "baggage"), Some("user=7"));
        crate::test_complete!(
            "w3c_trace_context_interceptor_restarts_an_invalid_trace_without_its_tracestate"
        );
    }

    #[test]
    fn w3c_trace_context_interceptor_drops_malformed_baggage_but_keeps_the_trace() {
        init_test("w3c_trace_context_interceptor_drops_malformed_baggage_but_keeps_the_trace");
        let upstream = crate::observability::w3c_trace_context::W3CTraceContext::new_root();
        let mut request = Request::new(Bytes::new());
        request
            .metadata_mut()
            .insert("traceparent", upstream.to_traceparent());
        request.metadata_mut().insert("baggage", "user");

        w3c_trace_context_interceptor()
            .intercept_request(&mut request)
            .unwrap();
        assert_eq!(
            ascii_metadata(&request, "baggage"),
            None,
            "malformed baggage is not forwarded"
        );
        assert_eq!(metadata_span(&request).trace_id, upstream.trace_id);
        crate::test_complete!(
            "w3c_trace_context_interceptor_drops_malformed_baggage_but_keeps_the_trace"
        );
    }

    #[test]
    fn w3c_trace_context_interceptor_starts_a_trace_per_request_without_one() {
        init_test("w3c_trace_context_interceptor_starts_a_trace_per_request_without_one");
        let interceptor = W3CTraceContextInterceptor::new();
        let mut first = Request::new(Bytes::new());
        let mut second = Request::new(Bytes::new());
        interceptor.intercept_request(&mut first).unwrap();
        interceptor.intercept_request(&mut second).unwrap();

        assert_ne!(
            metadata_span(&first).trace_id,
            metadata_span(&second).trace_id
        );
        assert_eq!(ascii_metadata(&first, "tracestate"), None);
        assert_eq!(ascii_metadata(&first, "baggage"), None);
        crate::test_complete!(
            "w3c_trace_context_interceptor_starts_a_trace_per_request_without_one"
        );
    }
