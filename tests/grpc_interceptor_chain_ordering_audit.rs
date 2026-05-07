//! Audit + regression test for `src/grpc/interceptor.rs`
//! `InterceptorLayer` chain ordering semantics.
//!
//! Operator's question: "when multiple interceptors are
//! registered, are they executed in registration order
//! (typical) or reverse-registration (alternative)?"
//!
//! Audit findings:
//!
//!   The asupersync gRPC interceptor chain uses the classic
//!   ONION-LAYER pattern, identical to how middleware stacks
//!   work in HTTP frameworks (Express, axum, tower):
//!
//!     - **Request path** (`intercept_request`,
//!       interceptor.rs:249-274): iterates
//!       `self.interceptors.iter().enumerate()` —
//!       REGISTRATION ORDER (first added → first executed).
//!       Outer-most interceptor wraps the request first.
//!
//!     - **Response path** (`intercept_response`,
//!       interceptor.rs:276-282): iterates
//!       `self.interceptors.iter().rev()` — REVERSE
//!       REGISTRATION ORDER (last added → first executed).
//!       Inner-most interceptor unwraps the response first.
//!
//!     - **Response-with-request path**
//!       (`intercept_response_with_request`,
//!       interceptor.rs:284-293): same reverse order.
//!
//!     - **Error / cleanup path**
//!       (`intercept_error_with_request`,
//!       interceptor.rs:295-313): reverse order. Combined
//!       with the Err-at-index-i cleanup walk inside
//!       `intercept_request` (line 263:
//!       `self.interceptors[..=index].iter().rev()`), this
//!       guarantees that an interceptor that already entered
//!       (acquired a resource, started a span, took a rate-
//!       limit slot) has its `intercept_error_with_request`
//!       called BEFORE outer interceptors get the cleanup
//!       signal — most recently entered cleans up first
//!       (br-asupersync-9oxmqv).
//!
//!   The doc on `InterceptorLayer::layer()`
//!   (interceptor.rs:200-204) explicitly documents the
//!   ordering: "Interceptors are applied in the order they
//!   are added for requests, and in reverse order for
//!   responses."
//!
//! Verdict: **SOUND**. The chain semantics match the standard
//! onion pattern AND the documented contract. The asymmetric
//! request/response ordering is the correct behavior — it
//! preserves the layering invariant that what an outer layer
//! adds on the way in is the last thing to be undone on the
//! way out.
//!
//! A regression that:
//!   - swapped request iteration to reverse order (would
//!     break the documented contract and confuse operators
//!     building authentication-then-logging stacks),
//!   - swapped response iteration to forward order (would
//!     break the onion semantics — outer layers would unwrap
//!     before inner layers had a chance),
//!   - removed the reverse-order cleanup walk in
//!     intercept_request's Err arm (would leak inner-
//!     interceptor side effects when an inner interceptor
//!     rejected the request — see br-asupersync-9oxmqv),
//!   - changed intercept_error_with_request to forward order
//!     (would call cleanup on outer layers BEFORE inner
//!     layers had released their resources — wrong order),
//! would all be caught here.

use std::path::PathBuf;

fn read_interceptor_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/grpc/interceptor.rs");
    std::fs::read_to_string(&path).expect("read interceptor.rs")
}

fn impl_interceptor_for_layer_body(source: &str) -> &str {
    let marker = "impl Interceptor for InterceptorLayer {";
    let start = source
        .find(marker)
        .expect("impl Interceptor for InterceptorLayer");
    let end_rel = source[start..].find("\n}\n").expect("impl close");
    &source[start..start + end_rel]
}

fn fn_body<'a>(impl_body: &'a str, fn_marker: &str) -> &'a str {
    let start = impl_body.find(fn_marker).expect("function in impl");
    let body_end = impl_body[start..]
        .find("\n    }\n")
        .expect("function body close");
    &impl_body[start..start + body_end]
}

#[test]
fn intercept_request_iterates_in_registration_order() {
    // Pin AUDIT-CRITICAL: the request path uses
    // `self.interceptors.iter().enumerate()` — forward
    // (registration) order. A regression that switched to
    // `.rev()` would break the documented contract and the
    // standard onion-layer pattern.
    let source = read_interceptor_source();
    let impl_body = impl_interceptor_for_layer_body(&source);
    let body = fn_body(
        impl_body,
        "fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {",
    );

    assert!(
        body.contains("self.interceptors.iter().enumerate()"),
        "REGRESSION: intercept_request no longer iterates the \
         interceptor chain via .iter().enumerate() (forward / \
         registration order). The doc explicitly promises \
         registration order for requests; switching to .rev() \
         would break every operator who built a stack expecting \
         request-side outer-first execution.\n\nfn body:\n{body}",
    );

    // Defense-in-depth: forbid the request iteration from
    // explicitly using .rev() at the top level. (The cleanup
    // walk inside the Err arm DOES use .rev(); that's the
    // correct behavior — but the OUTER iteration must be
    // forward.)
    let forward_iter_pos = body.find(".iter().enumerate()").expect("forward iteration");
    let pre_iter = &body[..forward_iter_pos];
    assert!(
        !pre_iter.contains("self.interceptors.iter().rev()"),
        "REGRESSION: intercept_request iterates the chain in \
         REVERSE before reaching the registration-order loop. \
         Even if the registration-order loop is still present, \
         a preceding reverse loop would execute interceptors \
         twice in the wrong order.",
    );
}

#[test]
fn intercept_response_iterates_in_reverse_order() {
    // Pin AUDIT-CRITICAL: the response path uses
    // `self.interceptors.iter().rev()` — reverse (LIFO) order
    // so inner layers unwrap before outer layers. A regression
    // that switched to forward order would break the onion
    // pattern.
    let source = read_interceptor_source();
    let impl_body = impl_interceptor_for_layer_body(&source);
    let body = fn_body(
        impl_body,
        "fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {",
    );

    assert!(
        body.contains("self.interceptors.iter().rev()"),
        "REGRESSION: intercept_response no longer iterates in \
         reverse order via .iter().rev(). The onion-layer \
         pattern requires response unwrapping in LIFO order — \
         what an outer layer wrapped on the way in must be \
         unwrapped LAST on the way out. Forward iteration here \
         would invert the layering.\n\nfn body:\n{body}",
    );

    // Forbid plain forward iteration on responses.
    assert!(
        !body.contains(".iter().enumerate()") && !body.contains(".iter() {"),
        "REGRESSION: intercept_response now contains a forward \
         iteration. The response path MUST be reverse-only.",
    );
}

#[test]
fn intercept_response_with_request_iterates_in_reverse_order() {
    // Pin: the with-request response variant follows the same
    // reverse pattern as plain intercept_response.
    let source = read_interceptor_source();
    let impl_body = impl_interceptor_for_layer_body(&source);
    let body = fn_body(impl_body, "fn intercept_response_with_request(");

    assert!(
        body.contains("self.interceptors.iter().rev()"),
        "REGRESSION: intercept_response_with_request no longer \
         iterates in reverse order. Both response variants must \
         agree on ordering (reverse) — divergence would mean \
         the chain's behavior depended on which response trait \
         method the caller invoked.\n\nfn body:\n{body}",
    );
}

#[test]
fn intercept_error_with_request_iterates_in_reverse_order() {
    // Pin AUDIT-CRITICAL: the error/cleanup path also iterates
    // in reverse order. This is part of the cleanup contract:
    // most-recently-entered interceptor releases its resources
    // first (br-asupersync-9oxmqv).
    let source = read_interceptor_source();
    // Look up the fn directly in `source` rather than within
    // the impl-block slice. The impl slice cuts off just
    // before the impl-close `\n}\n`, which can clip the final
    // method's `\n    }\n` boundary.
    let impl_marker = "impl Interceptor for InterceptorLayer {";
    let impl_pos = source.find(impl_marker).expect("impl block");
    let fn_marker = "fn intercept_error_with_request(";
    let fn_rel = source[impl_pos..]
        .find(fn_marker)
        .expect("intercept_error_with_request inside impl");
    let fn_abs = impl_pos + fn_rel;
    let body_end = source[fn_abs..]
        .find("\n    }\n")
        .expect("function body close");
    let body = &source[fn_abs..fn_abs + body_end];

    assert!(
        body.contains("self.interceptors.iter().rev()"),
        "REGRESSION: intercept_error_with_request no longer \
         iterates in reverse order. Cleanup must follow LIFO so \
         a rate-limit-slot acquired by an inner interceptor is \
         released BEFORE the outer auth interceptor's cleanup \
         (which may decrement different counters). Forward-\
         order cleanup could decrement metrics for resources \
         that haven't been released yet.\n\nfn body:\n{body}",
    );
}

#[test]
fn intercept_request_err_arm_walks_back_in_reverse_for_cleanup() {
    // Pin AUDIT-CRITICAL: when an inner interceptor at index
    // `i` returns Err, the request handler walks
    // `interceptors[..=i].iter().rev()` calling
    // intercept_error_with_request on each. This is the
    // br-asupersync-9oxmqv fix that prevents inner-interceptor
    // resource leaks when an outer interceptor admits the
    // request and an inner one rejects it.
    let source = read_interceptor_source();
    let impl_body = impl_interceptor_for_layer_body(&source);
    let body = fn_body(
        impl_body,
        "fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {",
    );

    assert!(
        body.contains("self.interceptors[..=index].iter().rev()"),
        "REGRESSION: the request-error cleanup walk no longer \
         iterates `interceptors[..=index].iter().rev()`. \
         Without this, an inner interceptor that rejects the \
         request leaves the outer interceptors' acquired \
         resources (rate-limit slots, auth contexts, span \
         handles) leaked. Re: br-asupersync-9oxmqv.\n\n\
         fn body:\n{body}",
    );

    // The cleanup must call intercept_error_with_request on
    // each unwound interceptor.
    assert!(
        body.contains("cleanup.intercept_error_with_request("),
        "REGRESSION: the cleanup walk no longer calls \
         intercept_error_with_request on each unwound \
         interceptor. The trait default no-op would silently \
         sink the cleanup signal.",
    );
}

#[test]
fn layer_doc_explicitly_describes_request_response_ordering() {
    // Pin: the doc on InterceptorLayer::layer() explicitly
    // promises "applied in the order they are added for
    // requests, and in reverse order for responses". A
    // regression that changed the doc would signal a
    // behavioral change worth re-auditing.
    let source = read_interceptor_source();

    let layer_marker = "pub fn layer<I>(mut self, interceptor: I) -> Self";
    let layer_pos = source.find(layer_marker).expect("layer fn");
    let mut doc_start = layer_pos;
    for _ in 0..15 {
        match source[..doc_start].rfind('\n') {
            Some(p) => doc_start = p,
            None => {
                doc_start = 0;
                break;
            }
        }
    }
    let doc_window = &source[doc_start..layer_pos];

    let required_phrases = [
        "in the order they are added",
        "for requests",
        "reverse order for responses",
    ];
    for phrase in &required_phrases {
        assert!(
            doc_window.contains(phrase),
            "REGRESSION: layer() doc no longer mentions \
             `{phrase}`. The doc is the public contract — if \
             ordering changed, both the doc and the \
             implementation must change together.\n\n\
             doc window:\n{doc_window}",
        );
    }
}

#[test]
fn layer_push_appends_to_back_of_vec() {
    // Pin: layer() uses .push() (append to back). A regression
    // to .insert(0, ...) would silently reverse registration
    // order — operators would see their first-registered
    // interceptor execute LAST on requests, breaking onion
    // semantics.
    let source = read_interceptor_source();

    let fn_marker = "pub fn layer<I>(mut self, interceptor: I) -> Self";
    let start = source.find(fn_marker).expect("layer fn");
    let body_end = source[start..].find("\n    }\n").expect("layer body close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.interceptors.push(Arc::new(interceptor));"),
        "REGRESSION: layer() no longer pushes to the back of \
         the Vec. .insert(0, ...) or any reverse-insert pattern \
         would silently reverse the registration order, \
         producing the OPPOSITE of the documented behavior.\n\n\
         fn body:\n{body}",
    );

    // Forbid front-insert patterns explicitly.
    assert!(
        !body.contains("self.interceptors.insert(0,"),
        "REGRESSION: layer() now uses insert(0, ...) — this \
         REVERSES registration order, breaking the documented \
         contract.",
    );
}

// ─── Behavioral end-to-end pin (gated on default features) ──────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::bytes::Bytes;
    use asupersync::grpc::Status;
    use asupersync::grpc::interceptor::InterceptorLayer;
    use asupersync::grpc::server::Interceptor;
    use asupersync::grpc::streaming::Request;
    use std::sync::{Arc, Mutex};

    /// A test interceptor that appends a tag to a shared log
    /// on each callback method, so the test can verify the
    /// observed call order.
    struct TaggingInterceptor {
        tag: &'static str,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Interceptor for TaggingInterceptor {
        fn intercept_request(&self, _req: &mut Request<Bytes>) -> Result<(), Status> {
            self.log.lock().unwrap().push(format!("req:{}", self.tag));
            Ok(())
        }

        fn intercept_response(
            &self,
            _resp: &mut asupersync::grpc::streaming::Response<Bytes>,
        ) -> Result<(), Status> {
            self.log.lock().unwrap().push(format!("resp:{}", self.tag));
            Ok(())
        }
    }

    fn drain_log(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        std::mem::take(&mut *log.lock().unwrap())
    }

    #[test]
    fn requests_execute_in_registration_order() {
        // Pin AUDIT-CRITICAL behavioral: register A, B, C; on
        // request, the log shows req:A, req:B, req:C in that
        // order.
        let log = Arc::new(Mutex::new(Vec::new()));
        let layer = InterceptorLayer::new()
            .layer(TaggingInterceptor {
                tag: "A",
                log: log.clone(),
            })
            .layer(TaggingInterceptor {
                tag: "B",
                log: log.clone(),
            })
            .layer(TaggingInterceptor {
                tag: "C",
                log: log.clone(),
            });

        let mut req = Request::new(Bytes::from_static(b""));
        layer.intercept_request(&mut req).expect("ok");

        let observed = drain_log(&log);
        assert_eq!(
            observed,
            vec![
                "req:A".to_string(),
                "req:B".to_string(),
                "req:C".to_string()
            ],
            "REGRESSION: requests no longer execute in \
             registration order (A, B, C). Observed: \
             {observed:?}. The doc explicitly promises this \
             ordering.",
        );
    }

    #[test]
    fn responses_execute_in_reverse_registration_order() {
        // Pin AUDIT-CRITICAL behavioral: register A, B, C; on
        // response, the log shows resp:C, resp:B, resp:A —
        // LIFO unwind of the onion.
        let log = Arc::new(Mutex::new(Vec::new()));
        let layer = InterceptorLayer::new()
            .layer(TaggingInterceptor {
                tag: "A",
                log: log.clone(),
            })
            .layer(TaggingInterceptor {
                tag: "B",
                log: log.clone(),
            })
            .layer(TaggingInterceptor {
                tag: "C",
                log: log.clone(),
            });

        let mut resp = asupersync::grpc::streaming::Response::new(Bytes::from_static(b""));
        layer.intercept_response(&mut resp).expect("ok");

        let observed = drain_log(&log);
        assert_eq!(
            observed,
            vec![
                "resp:C".to_string(),
                "resp:B".to_string(),
                "resp:A".to_string()
            ],
            "REGRESSION: responses no longer execute in reverse \
             registration order (C, B, A). Observed: \
             {observed:?}. The onion-layer pattern REQUIRES \
             this — what an outer layer wrapped on the way in \
             MUST be unwrapped LAST on the way out.",
        );
    }

    #[test]
    fn full_round_trip_log_shows_onion_pattern() {
        // Pin combined: register A, B, C; the full request +
        // response sequence shows req:A, req:B, req:C, resp:C,
        // resp:B, resp:A — the canonical onion pattern.
        let log = Arc::new(Mutex::new(Vec::new()));
        let layer = InterceptorLayer::new()
            .layer(TaggingInterceptor {
                tag: "A",
                log: log.clone(),
            })
            .layer(TaggingInterceptor {
                tag: "B",
                log: log.clone(),
            })
            .layer(TaggingInterceptor {
                tag: "C",
                log: log.clone(),
            });

        let mut req = Request::new(Bytes::from_static(b""));
        layer.intercept_request(&mut req).expect("ok");
        let mut resp = asupersync::grpc::streaming::Response::new(Bytes::from_static(b""));
        layer.intercept_response(&mut resp).expect("ok");

        let observed = drain_log(&log);
        assert_eq!(
            observed,
            vec![
                "req:A".to_string(),
                "req:B".to_string(),
                "req:C".to_string(),
                "resp:C".to_string(),
                "resp:B".to_string(),
                "resp:A".to_string(),
            ],
            "REGRESSION: the full round-trip does not show the \
             canonical onion pattern. Observed: {observed:?}",
        );
    }

    #[test]
    fn err_in_inner_interceptor_unwinds_in_reverse() {
        // Pin AUDIT-CRITICAL: when interceptor B (registered
        // 2nd of 3) returns Err, the cleanup walk MUST call
        // intercept_error_with_request on B then on A — NOT
        // on C (which never entered) and NOT in forward order.
        let log = Arc::new(Mutex::new(Vec::new()));

        struct ErrInterceptor {
            tag: &'static str,
            log: Arc<Mutex<Vec<String>>>,
        }
        impl Interceptor for ErrInterceptor {
            fn intercept_request(&self, _req: &mut Request<Bytes>) -> Result<(), Status> {
                self.log.lock().unwrap().push(format!("req:{}", self.tag));
                Err(Status::internal("planned failure"))
            }

            fn intercept_response(
                &self,
                _resp: &mut asupersync::grpc::streaming::Response<Bytes>,
            ) -> Result<(), Status> {
                Ok(())
            }
        }

        struct LoggingInterceptor {
            tag: &'static str,
            log: Arc<Mutex<Vec<String>>>,
        }
        impl Interceptor for LoggingInterceptor {
            fn intercept_request(&self, _req: &mut Request<Bytes>) -> Result<(), Status> {
                self.log.lock().unwrap().push(format!("req:{}", self.tag));
                Ok(())
            }

            fn intercept_response(
                &self,
                _resp: &mut asupersync::grpc::streaming::Response<Bytes>,
            ) -> Result<(), Status> {
                Ok(())
            }

            fn intercept_error_with_request(
                &self,
                _request: &Request<Bytes>,
                _status: &mut Status,
            ) -> Result<(), Status> {
                self.log.lock().unwrap().push(format!("err:{}", self.tag));
                Ok(())
            }
        }

        let layer = InterceptorLayer::new()
            .layer(LoggingInterceptor {
                tag: "A",
                log: log.clone(),
            })
            .layer(ErrInterceptor {
                tag: "B",
                log: log.clone(),
            })
            .layer(LoggingInterceptor {
                tag: "C",
                log: log.clone(),
            });

        let mut req = Request::new(Bytes::from_static(b""));
        let result = layer.intercept_request(&mut req);
        assert!(result.is_err());

        let observed = drain_log(&log);
        // Expect: A enters (req:A), B enters and fails (req:B),
        // cleanup walks back through [A, B] in REVERSE: B's
        // err first, then A's err. C never enters.
        assert_eq!(
            observed,
            vec![
                "req:A".to_string(),
                "req:B".to_string(),
                "err:B".to_string(),
                "err:A".to_string(),
            ],
            "REGRESSION: error cleanup did not walk back in \
             reverse. Expected req:A, req:B, err:B, err:A. \
             Observed: {observed:?}. Re: br-asupersync-9oxmqv.",
        );
    }
}
