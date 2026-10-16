    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::handler::Handler;
    use super::super::response::StatusCode;
    use super::*;

    fn call_sync<H: Handler + ?Sized>(handler: &H, req: Request) -> Response {
        futures_lite::future::block_on(Handler::call(handler, &crate::Cx::for_testing(), req))
    }

    impl<S, H> SessionMiddleware<S, H>
    where
        S: SessionStore,
        H: Handler,
    {
        fn call(&self, req: Request) -> Response {
            call_sync(self, req)
        }
    }

    // ================================================================
    // SessionData
    // ================================================================

    #[test]
    fn session_data_insert_get() {
        let mut data = SessionData::new();
        assert!(data.is_empty());
        assert_eq!(data.len(), 0);

        data.insert("user", "alice");
        assert_eq!(data.get("user"), Some("alice"));
        assert_eq!(data.len(), 1);
        assert!(!data.is_empty());
        assert!(data.is_modified());
    }

    #[test]
    fn session_data_remove() {
        let mut data = SessionData::new();
        data.insert("key", "val");
        let removed = data.remove("key");
        assert_eq!(removed.as_deref(), Some("val"));
        assert!(data.is_empty());
    }

    #[test]
    fn session_data_clear() {
        let mut data = SessionData::new();
        data.insert("a", "1");
        data.insert("b", "2");
        data.clear();
        assert!(data.is_empty());
        assert!(data.is_modified());
    }

    #[test]
    fn session_data_keys() {
        let mut data = SessionData::new();
        data.insert("x", "1");
        data.insert("y", "2");
        let mut keys = data.keys();
        keys.sort_unstable();
        assert_eq!(keys, vec!["x", "y"]);
    }

    #[test]
    fn session_data_not_modified_initially() {
        let data = SessionData::new();
        assert!(!data.is_modified());
    }

    #[test]
    fn session_data_debug_clone() {
        let mut data = SessionData::new();
        data.insert("k", "v");
        let dbg = format!("{data:?}");
        assert!(dbg.contains("SessionData"));
        let cloned = data.clone();
        assert_eq!(cloned.get("k"), Some("v"));
    }

    // ================================================================
    // MemoryStore
    // ================================================================

    #[test]
    fn memory_store_save_load() {
        let store = MemoryStore::new();
        let mut data = SessionData::new();
        data.insert("user", "bob");

        store.save("sess1", &data);
        assert_eq!(store.len(), 1);

        let loaded = store.load("sess1").unwrap();
        assert_eq!(loaded.get("user"), Some("bob"));
    }

    #[test]
    fn memory_store_delete() {
        let store = MemoryStore::new();
        store.save("sess1", &SessionData::new());
        assert_eq!(store.len(), 1);

        store.delete("sess1");
        assert!(store.is_empty());
        assert!(store.load("sess1").is_none());
    }

    #[test]
    fn memory_store_load_missing() {
        let store = MemoryStore::new();
        assert!(store.load("nonexistent").is_none());
    }

    #[test]
    fn memory_store_debug_clone() {
        let store = MemoryStore::new();
        let dbg = format!("{store:?}");
        assert!(dbg.contains("MemoryStore"));
    }

    #[test]
    fn memory_store_default() {
        let store = MemoryStore::default();
        assert!(store.is_empty());
    }

    #[test]
    fn bounded_memory_store_evicts_least_recent_session_ne8jdw() {
        let store = MemoryStore::with_max_sessions(2);
        for (id, last_accessed) in [("old", 10_u64), ("current", 20_u64)] {
            let mut data = SessionData::new();
            data.insert(LAST_ACCESSED_KEY, last_accessed.to_string());
            store.save(id, &data);
        }

        let mut newest = SessionData::new();
        newest.insert(LAST_ACCESSED_KEY, "30");
        store.save("new", &newest);

        assert_eq!(store.len(), 2);
        assert!(store.load("old").is_none());
        assert!(store.load("current").is_some());
        assert!(store.load("new").is_some());

        let mut updated = SessionData::new();
        updated.insert(LAST_ACCESSED_KEY, "40");
        store.save("current", &updated);
        assert_eq!(store.len(), 2, "updating in place must not evict");
    }

    #[test]
    #[should_panic(expected = "max_sessions must be greater than zero")]
    fn bounded_memory_store_rejects_zero_capacity_ne8jdw() {
        let _store = MemoryStore::with_max_sessions(0);
    }

    // ================================================================
    // Session ID
    // ================================================================

    #[test]
    fn generate_id_is_valid() {
        let id = generate_session_id().expect("OS entropy must be available in session-id test");
        assert!(is_valid_session_id(&id));
        assert_eq!(id.len(), SESSION_ID_HEX_LEN);
    }

    #[test]
    fn generate_id_uniqueness() {
        let id1 = generate_session_id().expect("OS entropy must be available in session-id test");
        let id2 = generate_session_id().expect("OS entropy must be available in session-id test");
        assert_ne!(id1, id2);
    }

    #[test]
    fn validate_session_id() {
        assert!(is_valid_session_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_session_id("short"));
        assert!(!is_valid_session_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
        assert!(!is_valid_session_id(""));
    }

    // ================================================================
    // Cookie parsing
    // ================================================================

    #[test]
    fn get_cookie_basic() {
        let mut req = Request::new("GET", "/");
        req.headers
            .insert("cookie".to_string(), "session_id=abc123".to_string());
        assert_eq!(get_cookie(&req, "session_id"), Some("abc123".to_string()));
    }

    #[test]
    fn get_cookie_multiple() {
        let mut req = Request::new("GET", "/");
        req.headers.insert(
            "cookie".to_string(),
            "foo=bar; session_id=xyz; other=val".to_string(),
        );
        assert_eq!(get_cookie(&req, "session_id"), Some("xyz".to_string()));
    }

    #[test]
    fn get_cookie_missing() {
        let req = Request::new("GET", "/");
        assert!(get_cookie(&req, "session_id").is_none());
    }

    // ================================================================
    // Set-Cookie header
    // ================================================================

    #[test]
    fn set_cookie_default_config() {
        let config = SessionConfig::default();
        let header = set_cookie_header("sid", "val123", &config);
        assert!(header.contains("sid=val123"));
        assert!(header.contains("Path=/"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Secure"));
    }

    #[test]
    fn set_cookie_secure_strict() {
        let config = SessionConfig {
            secure: true,
            same_site: SameSite::Strict,
            max_age: Some(3600),
            ..Default::default()
        };
        let header = set_cookie_header("sid", "val", &config);
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Max-Age=3600"));
    }

    // ================================================================
    // SessionLayer builder
    // ================================================================

    #[test]
    fn session_layer_builder() {
        let layer = SessionLayer::new(MemoryStore::new())
            .cookie_name("my_session")
            .cookie_path("/app")
            .http_only(false)
            .secure(true)
            .same_site(SameSite::None)
            .max_age(7200)
            .absolute_ttl_seconds(14_400);

        assert_eq!(layer.config.cookie_name, "my_session");
        assert_eq!(layer.config.cookie_path, "/app");
        assert!(!layer.config.http_only);
        assert!(layer.config.secure);
        assert_eq!(layer.config.same_site, SameSite::None);
        assert_eq!(layer.config.max_age, Some(7200));
        assert_eq!(layer.absolute_ttl_seconds, Some(14_400));
    }

    #[test]
    fn session_layer_debug() {
        let layer = SessionLayer::new(MemoryStore::new());
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("SessionLayer"));
    }

    // ================================================================
    // Middleware integration
    // ================================================================

    /// A simple echo handler that reads/writes session data.
    struct TestHandler;

    impl Handler for TestHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            req: Request,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                // Try to get session from extensions.
                req.extensions.get_typed::<Session>().map_or_else(
                    || Response::new(StatusCode::OK, b"no session".to_vec()),
                    |session| {
                        let count = session
                            .get("count")
                            .and_then(|s| s.parse::<u32>().ok())
                            .unwrap_or(0);
                        session.insert("count", (count + 1).to_string());
                        let body = format!("count={}", count + 1);
                        Response::new(StatusCode::OK, body.into_bytes())
                    },
                )
            })
        }
    }

    #[test]
    fn middleware_creates_session_on_first_request() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone());
        let handler = layer.wrap(TestHandler);

        let req = Request::new("GET", "/");
        let resp = handler.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.set_cookies.is_empty());
        let cookie = resp.set_cookies.first().unwrap();
        assert!(cookie.contains("session_id="));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn middleware_loads_existing_session() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store);
        let handler = layer.wrap(TestHandler);

        // First request — creates session.
        let req1 = Request::new("GET", "/");
        let resp1 = handler.call(req1);
        let cookie_header = resp1.set_cookies.first().unwrap().clone();

        // Extract session ID from Set-Cookie.
        let session_id = cookie_header
            .split('=')
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();

        // Second request with session cookie.
        let mut req2 = Request::new("GET", "/");
        req2.headers
            .insert("cookie".to_string(), format!("session_id={session_id}"));
        let resp2 = handler.call(req2);
        let body2 = std::str::from_utf8(&resp2.body).unwrap();
        assert_eq!(body2, "count=2");
    }

    #[test]
    fn middleware_invalid_session_id_creates_new() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone());
        let handler = layer.wrap(TestHandler);

        let mut req = Request::new("GET", "/");
        req.headers
            .insert("cookie".to_string(), "session_id=bad!".to_string());
        let resp = handler.call(req);

        assert!(!resp.set_cookies.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn middleware_fixation_unknown_id_regenerated() {
        // Regression: an attacker-supplied valid-format ID that is not in the
        // store must NOT be accepted — a fresh ID must be generated.
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone());
        let handler = layer.wrap(TestHandler);

        let unknown_attacker_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"; // valid format, not in store
        let mut req = Request::new("GET", "/");
        req.headers.insert(
            "cookie".to_string(),
            format!("session_id={unknown_attacker_id}"),
        );
        let resp = handler.call(req);

        // The response must set a NEW session cookie, not reuse the attacker's ID.
        let cookie = resp.set_cookies.first().unwrap();
        assert!(
            !cookie.contains(unknown_attacker_id),
            "must not reuse attacker-supplied ID"
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn middleware_absolute_ttl_expires_active_session_ne8jdw() {
        let store = MemoryStore::new();
        let expired_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut data = SessionData::new();
        data.insert("user", "alice");
        data.insert(
            CREATED_AT_KEY,
            now_unix_secs().saturating_sub(11).to_string(),
        );
        data.insert(LAST_ACCESSED_KEY, now_unix_secs().to_string());
        store.save(expired_id, &data);

        let handler = SessionLayer::new(store.clone())
            .absolute_ttl_seconds(10)
            .wrap(TestHandler);
        let mut req = Request::new("GET", "/");
        req.headers
            .insert("cookie".to_string(), format!("session_id={expired_id}"));

        let resp = handler.call(req);
        let new_id = extract_set_cookie_id(resp.set_cookies.first().expect("fresh cookie"));
        assert_ne!(new_id, expired_id);
        assert!(store.load(expired_id).is_none());
        assert_eq!(store.len(), 1);
        assert!(
            store
                .load(new_id)
                .and_then(|session| session.get(CREATED_AT_KEY).map(str::to_string))
                .is_some(),
            "replacement session must receive a creation timestamp"
        );
    }

    /// br-asupersync-hifab2: end-to-end session-fixation defence.
    ///
    /// A handler that calls `Session::regenerate()` (the OWASP-mandated
    /// post-login action) MUST cause the middleware to:
    ///   1. issue a NEW session ID in Set-Cookie (different from the
    ///      inbound cookie),
    ///   2. DELETE the old server-side store entry (so the
    ///      pre-authentication ID an attacker might have planted via
    ///      session-fixation can't be replayed), and
    ///   3. PRESERVE the user's session data under the new ID (so the
    ///      authenticated state survives the rotation).
    ///
    /// Without these three properties, an attacker can plant a chosen
    /// session ID on a victim, wait for them to log in, and then hijack
    /// the now-authenticated session by reusing the planted ID.
    #[test]
    fn middleware_regenerate_rotates_id_and_preserves_data() {
        struct LoginHandler;
        impl Handler for LoginHandler {
            fn call(
                &self,
                _cx: &crate::Cx,
                req: Request,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
            {
                Box::pin(async move {
                    if let Some(session) = req.extensions.get_typed::<Session>() {
                        // Simulate a successful login: stash an authenticated
                        // user_id and rotate the session ID.
                        session.insert("user_id", "alice");
                        session.regenerate();
                    }
                    Response::new(StatusCode::OK, b"logged in".to_vec())
                })
            }
        }

        let store = MemoryStore::new();
        // Seed a pre-auth session that the attacker might have planted.
        let attacker_planted_id = "1234567890abcdef1234567890abcdef";
        let mut pre_auth = SessionData::new();
        pre_auth.insert("pre_auth_marker", "still here");
        store.save(attacker_planted_id, &pre_auth);

        let layer = SessionLayer::new(store.clone()).csrf_protection(false);
        let handler = layer.wrap(LoginHandler);

        // Victim arrives with the attacker's planted cookie and "logs in".
        let mut req = Request::new("POST", "/login");
        req.headers.insert(
            "cookie".to_string(),
            format!("session_id={attacker_planted_id}"),
        );
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);

        // Property 1: response carries a NEW session-id cookie that is
        // NOT the attacker-planted one.
        let cookie = resp
            .set_cookies
            .first()
            .expect("middleware must issue Set-Cookie after regenerate");
        assert!(
            !cookie.contains(attacker_planted_id),
            "middleware reused the attacker's planted ID after regenerate(); fixation is OPEN. Set-Cookie: {cookie}"
        );
        let new_id = cookie
            .split('=')
            .nth(1)
            .expect("malformed Set-Cookie")
            .split(';')
            .next()
            .expect("missing cookie value")
            .to_string();
        assert_ne!(
            new_id, attacker_planted_id,
            "regenerate() did not actually rotate the ID"
        );
        assert_eq!(new_id.len(), 32, "new ID must be 32-char hex");

        // Property 2: old server-side store entry is GONE.
        assert!(
            store.load(attacker_planted_id).is_none(),
            "old session id must be deleted from store after regenerate()"
        );

        // Property 3: session data was PRESERVED under the new ID.
        let migrated = store
            .load(&new_id)
            .expect("new session id must be persisted");
        assert_eq!(
            migrated.get("user_id"),
            Some("alice"),
            "post-login user_id was not preserved across regenerate()"
        );

        // Defense in depth: the regenerate flag must NOT have leaked
        // into the saved session data (it's an internal marker).
        assert!(
            migrated.get(REGENERATE_FLAG_KEY).is_none(),
            "REGENERATE_FLAG_KEY leaked into persisted session data"
        );
    }

    #[test]
    fn middleware_clear_session_expires_cookie() {
        // Regression: clearing a session must expire the cookie (Max-Age=0),
        // not re-set it with the same ID.
        struct ClearHandler;
        impl Handler for ClearHandler {
            fn call(
                &self,
                _cx: &crate::Cx,
                req: Request,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
            {
                Box::pin(async move {
                    if let Some(session) = req.extensions.get_typed::<Session>() {
                        session.insert("data", "value"); // ensure non-empty first
                        session.clear();
                    }
                    Response::new(StatusCode::OK, b"cleared".to_vec())
                })
            }
        }

        let store = MemoryStore::new();
        // Seed a session in the store.
        let mut seed = SessionData::new();
        seed.insert("data", "value");
        store.save("abcdef01234567890abcdef012345678", &seed);

        let layer = SessionLayer::new(store.clone());
        let handler = layer.wrap(ClearHandler);

        let mut req = Request::new("GET", "/");
        req.headers.insert(
            "cookie".to_string(),
            "session_id=abcdef01234567890abcdef012345678".to_string(),
        );
        let resp = handler.call(req);
        let cookie = resp.set_cookies.first().unwrap();
        assert!(
            cookie.contains("Max-Age=0"),
            "cookie must be expired on clear"
        );
        assert!(store.is_empty(), "server-side data must be deleted");
    }

    #[test]
    fn generate_id_uses_crypto_randomness() {
        // Verify 16 bytes of entropy → 32 hex chars, all unique.
        let ids: Vec<String> = (0..100)
            .map(|_| {
                generate_session_id().expect("OS entropy must be available in session-id test")
            })
            .collect();
        for id in &ids {
            assert!(is_valid_session_id(id));
        }
        // All 100 must be unique (probability of collision is negligible).
        let set: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(set.len(), 100);
    }

    // ================================================================
    // Session handle
    // ================================================================

    #[test]
    fn session_handle_operations() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        session.insert("key", "value");
        assert!(session.contains("key"));
        assert_eq!(session.get("key"), Some("value".to_string()));

        let _ = session.remove("key");
        assert!(!session.contains("key"));
    }

    #[test]
    fn session_handle_clear() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        session.insert("a", "1");
        session.insert("b", "2");
        session.clear();
        assert!(!session.contains("a"));
    }

    #[test]
    fn session_handle_debug() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        let dbg = format!("{session:?}");
        assert!(dbg.contains("Session"));
    }

    // ================================================================
    // SameSite
    // ================================================================

    #[test]
    fn same_site_variants() {
        let config_none = SessionConfig {
            same_site: SameSite::None,
            ..Default::default()
        };
        let header = set_cookie_header("s", "v", &config_none);
        assert!(header.contains("SameSite=None"));
    }

    // ================================================================
    // br-asupersync-uz7oxb — set_cookie_header injection guard
    // ================================================================

    #[test]
    #[should_panic(expected = "br-asupersync-uz7oxb")]
    fn cookie_name_with_semicolon_panics() {
        let cfg = SessionConfig::default();
        let _ = set_cookie_header("evil; HttpOnly=false; X", "v", &cfg);
    }

    #[test]
    #[should_panic(expected = "br-asupersync-uz7oxb")]
    fn cookie_value_with_semicolon_panics() {
        let cfg = SessionConfig::default();
        let _ = set_cookie_header("s", "v; Domain=attacker.com", &cfg);
    }

    #[test]
    #[should_panic(expected = "br-asupersync-uz7oxb")]
    fn cookie_path_with_crlf_panics() {
        let cfg = SessionConfig {
            cookie_path: "/foo\r\nX-Injected: 1".to_string(),
            ..Default::default()
        };
        let _ = set_cookie_header("s", "v", &cfg);
    }

    #[test]
    fn cookie_helper_accepts_safe_inputs() {
        let cfg = SessionConfig::default();
        let h = set_cookie_header("session", "abcd1234", &cfg);
        assert!(h.starts_with("session=abcd1234; Path=/"));
    }

    // ================================================================
    // br-asupersync-3cvnmo — CSRF token rotation
    // ================================================================

    #[test]
    fn rotate_csrf_token_changes_token() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        // Seed an initial token.
        session.insert(CSRF_TOKEN_KEY, "old-token");
        let new = session
            .rotate_csrf_token()
            .expect("OS entropy must be available in CSRF rotation test");
        assert_ne!(new, "old-token");
        assert_eq!(session.csrf_token().as_deref(), Some(new.as_str()));
    }

    #[test]
    fn regenerate_rotates_csrf_and_sets_flag() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        session.insert(CSRF_TOKEN_KEY, "old-token");
        session.regenerate();
        let inner = session.0.lock();
        assert!(inner.get(REGENERATE_FLAG_KEY).is_some());
        let new_csrf = inner.get(CSRF_TOKEN_KEY).unwrap();
        assert_ne!(new_csrf, "old-token");
    }

    // ================================================================
    // br-asupersync-czbj90 — Origin/Referer extraction + allow-list
    // ================================================================

    fn make_request_with_headers(method: &str, headers: &[(&str, &str)]) -> Request {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.insert((*k).to_string(), (*v).to_string());
        }
        Request {
            method: method.to_string(),
            path: "/api/x".to_string(),
            query: None,
            headers: h,
            body: crate::bytes::Bytes::new(),
            path_params: HashMap::new(),
            extensions: crate::web::extract::Extensions::new(),
        }
    }

    #[test]
    fn referer_origin_strips_path() {
        let req = make_request_with_headers(
            "POST",
            &[("Referer", "https://app.example.com/foo/bar?q=1")],
        );
        let origin = request_origin(&req);
        assert_eq!(origin.as_deref(), Some("https://app.example.com"));
    }

    #[test]
    fn origin_allow_list_match_is_case_insensitive_and_trim_slash() {
        let allowed = vec!["https://App.Example.Com/".to_string()];
        assert!(origin_is_allowed("https://app.example.com", &allowed));
        assert!(origin_is_allowed("HTTPS://APP.EXAMPLE.COM", &allowed));
        assert!(!origin_is_allowed("https://attacker.com", &allowed));
    }

    #[test]
    fn origin_header_takes_precedence_over_referer() {
        let req = make_request_with_headers(
            "POST",
            &[
                ("Origin", "https://app.example.com"),
                ("Referer", "https://other.example.com/"),
            ],
        );
        assert_eq!(
            request_origin(&req).as_deref(),
            Some("https://app.example.com")
        );
    }

    #[test]
    fn null_origin_falls_back_to_referer() {
        let req = make_request_with_headers(
            "POST",
            &[
                ("Origin", "null"),
                ("Referer", "https://app.example.com/foo"),
            ],
        );
        assert_eq!(
            request_origin(&req).as_deref(),
            Some("https://app.example.com")
        );
    }

    // ================================================================
    // br-asupersync-qokau8 / br-asupersync-z74jcy — fail-closed
    // regenerate finalizer (cancel/panic-tolerant)
    // ================================================================

    /// Helper: extract the session-id portion of a Set-Cookie header
    /// produced by `set_cookie_header`.
    fn extract_set_cookie_id(cookie_header: &str) -> &str {
        cookie_header
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
    }

    /// Handler that calls `Session::regenerate()` and then PANICS,
    /// simulating an unwinding cancel-path between the regenerate
    /// call and the middleware's post-handler rotation logic.
    struct PanicAfterRegenerateHandler;
    impl Handler for PanicAfterRegenerateHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            req: Request,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                let session = req
                    .extensions
                    .get_typed::<Session>()
                    .expect("middleware injects Session");
                // Simulate the auth boundary: handler authenticates the
                // user and then rotates the session ID per the hifab2
                // protocol …
                session.regenerate();
                // … then unwinds before returning a Response.
                panic!("simulated handler panic after regenerate");
            })
        }
    }

    /// br-asupersync-qokau8 / br-asupersync-z74jcy: when the handler
    /// calls `Session::regenerate()` and then unwinds (panics) before
    /// returning, the middleware's `RegenerateGuard` MUST fail closed
    /// by deleting the OLD store entry. Otherwise the session-fixation
    /// defense the rotation was supposed to provide is silently
    /// skipped on the cancel path.
    #[test]
    fn regenerate_guard_fails_closed_when_handler_panics() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone()).csrf_protection(false);

        // Seed an existing session so the request is loading-mode
        // (is_new = false). The fail-closed branch only runs for
        // pre-existing sessions; new ones have nothing to invalidate.
        let original_id = "0123456789abcdef0123456789abcdef".to_string();
        let mut seeded = SessionData::new();
        seeded.insert("authed_user", "alice");
        store.save(&original_id, &seeded);
        assert_eq!(store.len(), 1);

        let handler = layer.wrap(PanicAfterRegenerateHandler);

        let mut req = Request::new("POST", "/login");
        req.headers
            .insert("cookie".to_string(), format!("session_id={original_id}"));

        // Run inside catch_unwind so the panic doesn't escape the
        // test. We expect the guard's Drop to have already run by
        // the time catch_unwind returns Err.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.call(req);
        }));
        assert!(
            outcome.is_err(),
            "handler must propagate the panic — the test relies on it"
        );

        // The OLD session must have been deleted from the store on
        // the unwinding path. Without RegenerateGuard, the OLD
        // session would remain in the store and a session-fixation
        // attacker could continue using `original_id`.
        assert_eq!(
            store.len(),
            0,
            "RegenerateGuard must invalidate the OLD session on the cancel/panic path"
        );
    }

    /// Handler that does NOT call regenerate, then panics. The
    /// fail-closed path must be a no-op in this case — only sessions
    /// with a pending regenerate flag are eligible for invalidation.
    struct PanicNoRegenerateHandler;
    impl Handler for PanicNoRegenerateHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            _req: Request,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async { panic!("simulated handler panic without regenerate") })
        }
    }

    /// br-asupersync-qokau8: when the handler panics WITHOUT calling
    /// regenerate, the guard's Drop must NOT delete the existing
    /// session — there's no rotation request, so no fail-closed
    /// invalidation is warranted.
    #[test]
    fn regenerate_guard_drop_is_noop_without_pending_flag() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone());

        let original_id = "fedcba9876543210fedcba9876543210".to_string();
        let mut seeded = SessionData::new();
        seeded.insert("k", "v");
        store.save(&original_id, &seeded);

        let handler = layer.wrap(PanicNoRegenerateHandler);

        let mut req = Request::new("GET", "/");
        req.headers
            .insert("cookie".to_string(), format!("session_id={original_id}"));

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.call(req);
        }));
        assert!(outcome.is_err());

        // The session must still be present — no regenerate flag was
        // set, so the guard had no reason to invalidate.
        assert_eq!(
            store.len(),
            1,
            "guard must NOT invalidate sessions that did not request regenerate"
        );
    }

    struct PanicOnDeleteStore;

    impl SessionStore for PanicOnDeleteStore {
        fn load(&self, _id: &str) -> Option<SessionData> {
            None
        }

        fn save(&self, _id: &str, _data: &SessionData) {}

        fn delete(&self, _id: &str) {
            std::panic::panic_any("delete backend unavailable");
        }
    }

    #[test]
    fn regenerate_guard_drop_suppresses_store_delete_panic_during_handler_unwind() {
        let mut data = SessionData::new();
        data.insert(REGENERATE_FLAG_KEY, "1");
        let session_handle = Arc::new(Mutex::new(data));
        let store = PanicOnDeleteStore;

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = RegenerateGuard {
                armed: true,
                store: &store,
                session_handle,
                session_id: "00112233445566778899aabbccddeeff".to_string(),
                is_new: false,
            };
            std::panic::panic_any("handler failed after requesting regenerate");
        }));

        let panic_payload = outcome.expect_err("the original handler unwind should propagate");
        assert_eq!(
            panic_payload.downcast_ref::<&str>(),
            Some(&"handler failed after requesting regenerate"),
            "the guard must preserve the original handler panic"
        );
    }

    #[test]
    fn regenerate_guard_drop_surfaces_store_delete_panic_without_handler_unwind() {
        let mut data = SessionData::new();
        data.insert(REGENERATE_FLAG_KEY, "1");
        let session_handle = Arc::new(Mutex::new(data));
        let store = PanicOnDeleteStore;

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = RegenerateGuard {
                armed: true,
                store: &store,
                session_handle,
                session_id: "00112233445566778899aabbccddeeff".to_string(),
                is_new: false,
            };
        }));

        let panic_payload = outcome.expect_err("normal-path store.delete panic should propagate");
        assert_eq!(
            panic_payload.downcast_ref::<&str>(),
            Some(&"delete backend unavailable"),
            "normal-path store.delete panics should not be silently swallowed"
        );
    }

    /// br-asupersync-qokau8: happy path — handler calls regenerate
    /// and returns normally. The middleware's explicit rotation logic
    /// MUST run (proving disarm() was called and the guard's Drop
    /// did not double-delete).
    struct RegenerateAndReturnHandler;
    impl Handler for RegenerateAndReturnHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            req: Request,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            Box::pin(async move {
                let session = req
                    .extensions
                    .get_typed::<Session>()
                    .expect("middleware injects Session");
                session.regenerate();
                Response::new(StatusCode::OK, b"ok".to_vec())
            })
        }
    }

    /// Logout as documented: regenerate() then clear(), then return or
    /// panic depending on `panic_after`.
    struct LogoutHandler {
        panic_after: bool,
        note_after: bool,
    }
    impl Handler for LogoutHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            req: Request,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let panic_after = self.panic_after;
            let note_after = self.note_after;
            Box::pin(async move {
                let session = req
                    .extensions
                    .get_typed::<Session>()
                    .expect("middleware injects Session");
                session.regenerate();
                session.clear();
                if note_after {
                    session.insert("flash", "signed out");
                }
                assert!(!panic_after, "simulated failure after logout");
                Response::new(StatusCode::OK, String::new())
            })
        }
    }

    fn seeded_logged_in_session(store: &MemoryStore) -> String {
        let id = "5555666677778888eeeeffff00001111".to_string();
        let mut seeded = SessionData::new();
        seeded.insert("authed_user", "carol");
        store.save(&id, &seeded);
        id
    }

    /// regenerate() followed by clear(), the documented logout, ends the
    /// session on the normal path: the old entry is deleted and the cookie
    /// expired, with no fresh session stored. clear() keeping the
    /// regenerate marker for the failure guard must not change that.
    #[test]
    fn logout_regenerate_then_clear_deletes_the_session_and_expires_the_cookie() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone()).csrf_protection(false);
        let original_id = seeded_logged_in_session(&store);

        let handler = layer.wrap(LogoutHandler {
            panic_after: false,
            note_after: false,
        });
        let mut req = Request::new("POST", "/logout");
        req.headers
            .insert("cookie".to_string(), format!("session_id={original_id}"));
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);

        assert!(
            store.load(&original_id).is_none(),
            "the logged-in session must be gone after logout"
        );
        assert!(store.is_empty(), "logout stores no fresh session");
        let cookie_header = resp.set_cookies.first().expect("Set-Cookie present");
        assert_eq!(extract_set_cookie_id(cookie_header), "");
        assert!(cookie_header.contains("Max-Age=0"), "{cookie_header}");
    }

    /// regenerate(), clear(), then new data: the regenerate request still
    /// applies, so the new data lives under a new ID and the old entry is
    /// gone. clear() used to drop the request, and the data was saved under
    /// the old, logged-in ID (br-asupersync-a1q12q).
    #[test]
    fn regenerate_then_clear_then_insert_rotates_into_a_new_session() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone()).csrf_protection(false);
        let original_id = seeded_logged_in_session(&store);

        let handler = layer.wrap(LogoutHandler {
            panic_after: false,
            note_after: true,
        });
        let mut req = Request::new("POST", "/logout");
        req.headers
            .insert("cookie".to_string(), format!("session_id={original_id}"));
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);

        assert!(store.load(&original_id).is_none(), "the old entry is gone");
        let cookie_header = resp.set_cookies.first().expect("Set-Cookie present");
        let new_id = extract_set_cookie_id(cookie_header);
        assert!(
            !new_id.is_empty() && new_id != original_id,
            "{cookie_header}"
        );
        let saved = store.load(new_id).expect("the new session is stored");
        assert_eq!(saved.get("flash"), Some("signed out"));
        assert_eq!(saved.get("authed_user"), None);
    }

    /// regenerate() then clear(), then a panic: the guard must still delete
    /// the old, logged-in entry. clear() used to erase the flag the guard
    /// checks, so a stolen cookie outlived the logout (br-asupersync-a1q12q).
    #[test]
    fn logout_regenerate_then_clear_then_panic_invalidates_the_old_session() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone()).csrf_protection(false);
        let original_id = seeded_logged_in_session(&store);

        let handler = layer.wrap(LogoutHandler {
            panic_after: true,
            note_after: false,
        });
        let mut req = Request::new("POST", "/logout");
        req.headers
            .insert("cookie".to_string(), format!("session_id={original_id}"));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.call(req);
        }));
        assert!(outcome.is_err(), "the handler panics after logging out");
        assert!(
            store.load(&original_id).is_none(),
            "the old, logged-in session must be invalidated on the panic path"
        );
    }

    #[test]
    fn regenerate_guard_disarmed_on_happy_path_rotates_normally() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone()).csrf_protection(false);

        let original_id = "1111222233334444aaaabbbbccccdddd".to_string();
        let mut seeded = SessionData::new();
        seeded.insert("authed_user", "bob");
        seeded.insert(CREATED_AT_KEY, "123");
        store.save(&original_id, &seeded);
        assert_eq!(store.len(), 1);

        let handler = layer.wrap(RegenerateAndReturnHandler);

        let mut req = Request::new("POST", "/login");
        req.headers
            .insert("cookie".to_string(), format!("session_id={original_id}"));
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);

        // The OLD session was deleted by the explicit rotation
        // logic; a NEW session was minted under a fresh ID and
        // saved. Net store size is 1, but the entry under the
        // ORIGINAL ID is gone.
        let cookie_header = resp.set_cookies.first().expect("Set-Cookie present");
        let new_id = extract_set_cookie_id(cookie_header);
        assert_ne!(new_id, original_id, "ID must rotate");
        assert_eq!(store.len(), 1, "exactly one entry under the new ID");
        assert!(
            store.load(&original_id).is_none(),
            "original session must be deleted after rotation"
        );
        let rotated = store.load(new_id).expect("new session must be present");
        assert_eq!(
            rotated.get(CREATED_AT_KEY),
            Some("123"),
            "ID regeneration must not reset the absolute lifetime"
        );
    }

    /// br-asupersync-ehtkns regression: a handler that emits its own
    /// `Set-Cookie` (e.g. a CSRF or remember-me cookie) MUST keep that
    /// cookie in the wire response after `SessionMiddleware` later
    /// emits the session cookie. Pre-fix, `set_header("set-cookie", _)`
    /// stored the value in `Response::headers: HashMap<String, String>`,
    /// so the middleware silently overwrote whatever the inner handler
    /// produced. Both cookies must now ride out as separate entries in
    /// `Response::set_cookies`.
    #[test]
    fn middleware_preserves_inner_handler_set_cookie() {
        struct CsrfEmittingHandler;
        impl Handler for CsrfEmittingHandler {
            fn call(
                &self,
                _cx: &crate::Cx,
                req: Request,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
            {
                Box::pin(async move {
                    if let Some(session) = req.extensions.get_typed::<Session>() {
                        session.insert("flash", "saved");
                    }
                    let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
                    // Inner handler emits its own cookie via the canonical API.
                    resp.append_set_cookie("csrf_token=abc123; HttpOnly; Path=/");
                    resp
                })
            }
        }

        let store = MemoryStore::new();
        let layer = SessionLayer::new(store);
        let handler = layer.wrap(CsrfEmittingHandler);

        let req = Request::new("GET", "/");
        let resp = handler.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.set_cookies.len(),
            2,
            "expected BOTH the handler's CSRF cookie and the middleware's session cookie; \
             pre-fix the HashMap-backed header store collapsed them to one. \
             Got: {:?}",
            resp.set_cookies
        );
        assert!(
            resp.set_cookies
                .iter()
                .any(|c| c.contains("csrf_token=abc123")),
            "inner handler's CSRF cookie must survive the middleware layer; \
             got {:?}",
            resp.set_cookies
        );
        assert!(
            resp.set_cookies.iter().any(|c| c.contains("session_id=")),
            "session cookie must still be emitted alongside CSRF; got {:?}",
            resp.set_cookies
        );
    }
