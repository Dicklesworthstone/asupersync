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
    fn lab_io_cap_is_not_real() {
        let cap = LabIoCap::new_for_tests();
        assert!(!cap.is_real_io());
        assert_eq!(cap.name(), "lab");
        assert_eq!(cap.capabilities(), IoCapabilities::LAB);
    }

    #[test]
    fn io_not_available_error() {
        let err = IoNotAvailable;
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn io_not_available_debug_clone_eq() {
        let e = IoNotAvailable;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("IoNotAvailable"), "{dbg}");
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn lab_io_cap_debug_default() {
        let c = LabIoCap::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("LabIoCap"), "{dbg}");
    }

    #[test]
    fn lab_io_cap_stats_track_activity() {
        let cap = LabIoCap::new_for_tests();
        assert_eq!(cap.stats(), IoStats::default());
        cap.record_submit();
        cap.record_submit();
        cap.record_complete();
        assert_eq!(
            cap.stats(),
            IoStats {
                submitted: 2,
                completed: 1
            }
        );
    }

    #[test]
    fn lab_io_cap_counters_saturate_at_u64_max() {
        let cap = LabIoCap::new_for_tests();
        let shard = lab_iocap_shard();

        cap.submitted_shards[shard].store(u64::MAX - 1, Ordering::Relaxed);
        cap.record_submit();
        cap.record_submit();
        assert_eq!(
            cap.submitted_shards[shard].load(Ordering::Relaxed),
            u64::MAX
        );

        cap.completed_shards[shard].store(u64::MAX - 1, Ordering::Relaxed);
        cap.record_complete();
        cap.record_complete();
        assert_eq!(
            cap.completed_shards[shard].load(Ordering::Relaxed),
            u64::MAX
        );
    }

    #[test]
    fn lab_io_cap_stats_saturate_shard_totals() {
        let cap = LabIoCap::new_for_tests();
        cap.submitted_shards[0].store(u64::MAX, Ordering::Relaxed);
        cap.submitted_shards[1].store(1, Ordering::Relaxed);
        cap.completed_shards[0].store(u64::MAX - 1, Ordering::Relaxed);
        cap.completed_shards[1].store(3, Ordering::Relaxed);

        assert_eq!(
            cap.stats(),
            IoStats {
                submitted: u64::MAX,
                completed: u64::MAX
            }
        );
        assert_eq!(cap.submitted_total(), u64::MAX);
        assert_eq!(cap.completed_total(), u64::MAX);
    }

    #[test]
    fn fetch_authority_allows_expected_origin_and_method() {
        let authority = FetchAuthority::deny_all()
            .grant_origin("https://api.example.com")
            .grant_method(FetchMethod::Get)
            .grant_method(FetchMethod::Post)
            .with_max_header_count(8);
        let request = FetchRequest::new(FetchMethod::Get, "https://api.example.com/v1/data")
            .with_header("x-trace-id", "t-1");
        assert_eq!(authority.authorize(&request), Ok(()));
    }

    #[test]
    fn fetch_authority_default_is_deny_all() {
        let authority = FetchAuthority::default();
        let request = FetchRequest::new(FetchMethod::Get, "https://api.example.com/v1/data");
        assert_eq!(
            authority.authorize(&request),
            Err(FetchPolicyError::OriginDenied(
                "https://api.example.com".to_owned()
            ))
        );
    }

    #[test]
    fn fetch_authority_denies_unlisted_origin() {
        let authority = FetchAuthority {
            allowed_origins: vec!["https://api.example.com".to_owned()],
            ..FetchAuthority::default()
        };
        let request = FetchRequest::new(FetchMethod::Get, "https://evil.example.com/v1/data");
        assert_eq!(
            authority.authorize(&request),
            Err(FetchPolicyError::OriginDenied(
                "https://evil.example.com".to_owned()
            ))
        );
    }

    #[test]
    fn fetch_authority_denies_ungranted_method() {
        let authority = FetchAuthority::deny_all()
            .grant_origin("https://api.example.com")
            .grant_method(FetchMethod::Get)
            .with_max_header_count(4);
        let request = FetchRequest::new(FetchMethod::Post, "https://api.example.com/v1/data");
        assert_eq!(
            authority.authorize(&request),
            Err(FetchPolicyError::MethodDenied(FetchMethod::Post))
        );
    }

    #[test]
    fn fetch_authority_denies_credentials_when_disallowed() {
        let authority = FetchAuthority::deny_all()
            .grant_origin("https://api.example.com")
            .grant_method(FetchMethod::Get)
            .with_max_header_count(4);
        let request = FetchRequest::new(FetchMethod::Get, "https://api.example.com/v1/data")
            .with_credentials();
        assert_eq!(
            authority.authorize(&request),
            Err(FetchPolicyError::CredentialsDenied)
        );
    }

    #[test]
    fn fetch_authority_allows_credentials_with_explicit_grant() {
        let authority = FetchAuthority::deny_all()
            .grant_origin("https://api.example.com")
            .grant_method(FetchMethod::Get)
            .with_max_header_count(4)
            .with_credentials_allowed();
        let request = FetchRequest::new(FetchMethod::Get, "https://api.example.com/v1/data")
            .with_credentials();
        assert_eq!(authority.authorize(&request), Ok(()));
    }

    #[test]
    fn fetch_authority_enforces_header_budget() {
        let authority = FetchAuthority::deny_all()
            .grant_origin("https://api.example.com")
            .grant_method(FetchMethod::Get)
            .with_max_header_count(1);
        let request = FetchRequest::new(FetchMethod::Get, "https://api.example.com/v1/data")
            .with_header("x-trace-id", "t-1")
            .with_header("x-request-id", "r-1");
        assert_eq!(
            authority.authorize(&request),
            Err(FetchPolicyError::TooManyHeaders { count: 2, limit: 1 })
        );
    }

    #[test]
    fn fetch_authority_rejects_invalid_url() {
        let authority = FetchAuthority::default();
        let request = FetchRequest::new(FetchMethod::Get, "not-a-url");
        assert_eq!(
            authority.authorize(&request),
            Err(FetchPolicyError::InvalidUrl("not-a-url".to_owned()))
        );
    }

    #[test]
    fn fetch_authority_uses_browser_special_url_authority_boundaries() {
        let authority = FetchAuthority::deny_all()
            .grant_origin("https://api.example.com")
            .grant_method(FetchMethod::Get);

        let allowed = FetchRequest::new(FetchMethod::Get, r"https://api.example.com\records");
        assert_eq!(authority.authorize(&allowed), Ok(()));

        for url in [
            r"https://evil.example\@api.example.com/records",
            "https://user:password@evil.example/records",
        ] {
            let denied = FetchRequest::new(FetchMethod::Get, url);
            assert_eq!(
                authority.authorize(&denied),
                Err(FetchPolicyError::OriginDenied(
                    "https://evil.example".to_owned()
                )),
                "fetch policy must use the host selected by browser special-URL parsing: {url}"
            );
        }
    }

    #[test]
    fn browser_fetch_cap_exposes_policies_through_iocap() {
        let timeout = FetchTimeoutPolicy {
            request_timeout_ms: 15_000,
            first_byte_timeout_ms: 2_000,
            between_chunks_timeout_ms: 1_500,
        };
        let stream = FetchStreamPolicy {
            max_request_body_bytes: 1024,
            max_response_body_bytes: 2048,
            max_response_header_bytes: 512,
        };
        let cap = BrowserFetchIoCap::new(
            FetchAuthority::default(),
            timeout,
            stream,
            FetchCancellationPolicy::AbortSignalWithDrain,
        );

        let io_cap: &dyn IoCap = &cap;
        let fetch_cap = io_cap.fetch_cap().expect("fetch cap should be present");
        assert_eq!(fetch_cap.timeout_policy(), timeout);
        assert_eq!(fetch_cap.stream_policy(), stream);
        assert_eq!(
            fetch_cap.cancellation_policy(),
            FetchCancellationPolicy::AbortSignalWithDrain
        );
    }

    fn strict_transport_cap(
        support: BrowserTransportSupport,
        localhost_insecure_ws: bool,
    ) -> BrowserTransportIoCap {
        let mut authority = BrowserTransportAuthority::deny_all()
            .grant_origin("wss://chat.example.com")
            .grant_origin("https://transport.example.com")
            .grant_kind(BrowserTransportKind::WebSocket)
            .grant_kind(BrowserTransportKind::WebTransport)
            .with_max_subprotocol_count(2);
        if localhost_insecure_ws {
            authority = authority.with_localhost_insecure_ws();
        }

        BrowserTransportIoCap::new(
            authority,
            support,
            BrowserTransportCancellationPolicy::CloseThenAbort,
            BrowserTransportReconnectPolicy {
                max_attempts: 2,
                base_delay_ms: 100,
                max_delay_ms: 1_000,
                jitter_ms: 0,
            },
        )
    }

    #[test]
    fn transport_authority_default_is_deny_all() {
        let cap = BrowserTransportIoCap::new(
            BrowserTransportAuthority::default(),
            BrowserTransportSupport::FULL,
            BrowserTransportCancellationPolicy::CloseThenAbort,
            BrowserTransportReconnectPolicy::default(),
        );
        let request =
            BrowserTransportRequest::new(BrowserTransportKind::WebSocket, "wss://chat.example.com");

        assert_eq!(
            cap.authorize(&request),
            Err(BrowserTransportPolicyError::KindDenied(
                BrowserTransportKind::WebSocket
            ))
        );
    }

    #[test]
    fn transport_policy_rejects_insecure_remote_ws() {
        let cap = BrowserTransportIoCap::new(
            BrowserTransportAuthority::deny_all()
                .grant_origin("ws://chat.example.com")
                .grant_kind(BrowserTransportKind::WebSocket)
                .with_max_subprotocol_count(2),
            BrowserTransportSupport::WEBSOCKET_ONLY,
            BrowserTransportCancellationPolicy::CloseThenAbort,
            BrowserTransportReconnectPolicy::default(),
        );
        let request =
            BrowserTransportRequest::new(BrowserTransportKind::WebSocket, "ws://chat.example.com");

        assert_eq!(
            cap.authorize(&request),
            Err(BrowserTransportPolicyError::InsecureScheme {
                kind: BrowserTransportKind::WebSocket,
                scheme: "ws".to_owned()
            })
        );
    }

    #[test]
    fn transport_policy_allows_localhost_ws_when_explicitly_granted() {
        let cap = BrowserTransportIoCap::new(
            BrowserTransportAuthority::deny_all()
                .grant_origin("ws://localhost:8080")
                .grant_kind(BrowserTransportKind::WebSocket)
                .with_max_subprotocol_count(2)
                .with_localhost_insecure_ws(),
            BrowserTransportSupport::WEBSOCKET_ONLY,
            BrowserTransportCancellationPolicy::CloseThenAbort,
            BrowserTransportReconnectPolicy::default(),
        );
        let request =
            BrowserTransportRequest::new(BrowserTransportKind::WebSocket, "ws://localhost:8080");
        assert_eq!(cap.authorize(&request), Ok(()));
    }

    #[test]
    fn transport_policy_uses_browser_backslash_authority_boundary() {
        let cap = strict_transport_cap(BrowserTransportSupport::FULL, false);

        for (kind, url) in [
            (
                BrowserTransportKind::WebSocket,
                r"wss://chat.example.com\socket",
            ),
            (
                BrowserTransportKind::WebTransport,
                r"https://transport.example.com\session",
            ),
        ] {
            let request = BrowserTransportRequest::new(kind, url);
            assert_eq!(
                cap.authorize(&request),
                Ok(()),
                "backslash path must keep the browser-visible allowed origin: {url}"
            );
        }

        for url in [
            r"wss://evil.example\@chat.example.com/socket",
            r"wss://evil.example\\@chat.example.com/socket",
        ] {
            let request = BrowserTransportRequest::new(BrowserTransportKind::WebSocket, url);
            assert_eq!(
                cap.authorize(&request),
                Err(BrowserTransportPolicyError::OriginDenied(
                    "wss://evil.example".to_owned()
                )),
                "raw URL must be authorized against the host the browser will use: {url}"
            );
        }

        for url in [
            r"https://evil.example\@transport.example.com/session",
            r"https://evil.example\\@transport.example.com/session",
        ] {
            let request = BrowserTransportRequest::new(BrowserTransportKind::WebTransport, url);
            assert_eq!(
                cap.authorize(&request),
                Err(BrowserTransportPolicyError::OriginDenied(
                    "https://evil.example".to_owned()
                )),
                "raw URL must be authorized against the host the browser will use: {url}"
            );
        }
    }

    #[test]
    fn transport_url_special_scheme_authority_parity_corpus() {
        for (url, expected) in [
            (
                "wss://user:p%40ss@chat.example.com:8443/socket",
                ("wss", "wss://chat.example.com:8443", "chat.example.com"),
            ),
            (
                r"wss://[2001:db8::1]:8443\socket",
                ("wss", "wss://[2001:db8::1]:8443", "2001:db8::1"),
            ),
            (
                r"https://transport.example.com:9443\session?next=@evil.example#fragment",
                (
                    "https",
                    "https://transport.example.com:9443",
                    "transport.example.com",
                ),
            ),
            (
                r"wss://chat.example.com:8443?next=\@evil.example#fragment",
                ("wss", "wss://chat.example.com:8443", "chat.example.com"),
            ),
            (
                r"wss://chat.example.com:8443#fragment\@evil.example",
                ("wss", "wss://chat.example.com:8443", "chat.example.com"),
            ),
        ] {
            let parsed = parse_browser_transport_url(url).expect("browser URL corpus must parse");
            assert_eq!(
                parsed,
                (
                    expected.0.to_owned(),
                    expected.1.to_owned(),
                    expected.2.to_owned(),
                ),
                "policy tuple must match the browser-visible authority boundary: {url}"
            );
        }
    }

    #[test]
    fn transport_policy_enforces_support_matrix() {
        let cap = strict_transport_cap(BrowserTransportSupport::WEBSOCKET_ONLY, false);
        let request = BrowserTransportRequest::new(
            BrowserTransportKind::WebTransport,
            "https://transport.example.com/session",
        );

        assert_eq!(
            cap.authorize(&request),
            Err(BrowserTransportPolicyError::UnsupportedKind(
                BrowserTransportKind::WebTransport
            ))
        );
    }

    #[test]
    fn transport_policy_enforces_reconnect_limit() {
        let cap = strict_transport_cap(BrowserTransportSupport::FULL, false);
        let request = BrowserTransportRequest::new(
            BrowserTransportKind::WebTransport,
            "https://transport.example.com/session",
        )
        .with_reconnect_attempt(3);

        assert_eq!(
            cap.authorize(&request),
            Err(BrowserTransportPolicyError::ReconnectAttemptExceeded {
                attempt: 3,
                max_attempts: 2
            })
        );
    }

    #[test]
    fn browser_transport_cap_exposes_policies_through_iocap() {
        let reconnect = BrowserTransportReconnectPolicy {
            max_attempts: 4,
            base_delay_ms: 250,
            max_delay_ms: 4_000,
            jitter_ms: 0,
        };
        let cap = BrowserTransportIoCap::new(
            BrowserTransportAuthority::deny_all()
                .grant_origin("wss://chat.example.com")
                .grant_kind(BrowserTransportKind::WebSocket)
                .with_max_subprotocol_count(3),
            BrowserTransportSupport::WEBSOCKET_ONLY,
            BrowserTransportCancellationPolicy::CloseThenAbort,
            reconnect,
        );

        let io_cap: &dyn IoCap = &cap;
        let transport_cap = io_cap
            .transport_cap()
            .expect("browser transport cap should be present");
        assert_eq!(
            transport_cap.support(),
            BrowserTransportSupport::WEBSOCKET_ONLY
        );
        assert_eq!(
            transport_cap.cancellation_policy(),
            BrowserTransportCancellationPolicy::CloseThenAbort
        );
        assert_eq!(transport_cap.reconnect_policy(), reconnect);
    }

    fn strict_entropy_cap() -> BrowserEntropyIoCap {
        BrowserEntropyIoCap::new(
            EntropyAuthority::deny_all()
                .grant_source(EntropySourceKind::WebCrypto)
                .grant_operation(EntropyOperation::NextU64)
                .grant_operation(EntropyOperation::FillBytes)
                .with_max_fill_bytes(64),
            true,
        )
    }

    #[test]
    fn entropy_authority_default_is_deny_all() {
        let cap = BrowserEntropyIoCap::new(EntropyAuthority::default(), false);
        assert_eq!(
            cap.authorize(&EntropyRequest::next_u64(EntropySourceKind::WebCrypto)),
            Err(EntropyPolicyError::SourceDenied(
                EntropySourceKind::WebCrypto
            ))
        );
    }

    #[test]
    fn entropy_policy_denies_oversized_fill() {
        let cap = strict_entropy_cap();
        assert_eq!(
            cap.authorize(&EntropyRequest::fill_bytes(
                EntropySourceKind::WebCrypto,
                65
            )),
            Err(EntropyPolicyError::ByteLengthExceeded {
                requested: 65,
                limit: 64
            })
        );
    }

    #[test]
    fn entropy_policy_allows_explicit_grant_and_exposes_iocap() {
        let cap = strict_entropy_cap();
        assert_eq!(
            cap.authorize(&EntropyRequest::fill_bytes(
                EntropySourceKind::WebCrypto,
                32
            )),
            Ok(())
        );
        let io_cap: &dyn IoCap = &cap;
        let entropy_cap = io_cap.entropy_cap().expect("entropy cap should be present");
        assert!(entropy_cap.deterministic_fallback_enabled());
    }

    fn strict_time_cap(require_monotonic: bool) -> BrowserTimeIoCap {
        BrowserTimeIoCap::new(
            TimeAuthority::deny_all()
                .grant_source(TimeSourceKind::PerformanceNow)
                .grant_source(TimeSourceKind::DeterministicVirtual)
                .grant_operation(TimeOperation::Now)
                .grant_operation(TimeOperation::Sleep)
                .grant_operation(TimeOperation::Interval)
                .with_min_duration_ms(5)
                .with_max_duration_ms(5_000),
            require_monotonic,
        )
    }

    #[test]
    fn time_policy_denies_source_escalation_when_monotonic_required() {
        let cap = strict_time_cap(true);
        assert_eq!(
            cap.authorize(&TimeRequest::now(TimeSourceKind::DateNow)),
            Err(TimePolicyError::SourceDenied(TimeSourceKind::DateNow))
        );
    }

    #[test]
    fn time_policy_enforces_duration_bounds() {
        let cap = strict_time_cap(false);
        assert_eq!(
            cap.authorize(&TimeRequest::sleep(TimeSourceKind::PerformanceNow, 3)),
            Err(TimePolicyError::DurationBelowMinimum {
                requested_ms: 3,
                minimum_ms: 5
            })
        );
        assert_eq!(
            cap.authorize(&TimeRequest::interval(
                TimeSourceKind::PerformanceNow,
                8_000
            )),
            Err(TimePolicyError::DurationAboveMaximum {
                requested_ms: 8_000,
                maximum_ms: 5_000
            })
        );
    }

    #[test]
    fn time_policy_allows_explicit_grant_and_exposes_iocap() {
        let cap = strict_time_cap(true);
        assert_eq!(
            cap.authorize(&TimeRequest::sleep(TimeSourceKind::PerformanceNow, 100)),
            Ok(())
        );
        let io_cap: &dyn IoCap = &cap;
        let time_cap = io_cap.time_cap().expect("time cap should be present");
        assert!(time_cap.require_monotonic());
    }

    fn strict_host_api_cap() -> BrowserHostApiIoCap {
        BrowserHostApiIoCap::new(
            HostApiAuthority::deny_all()
                .grant_surface(HostApiSurface::Crypto)
                .grant_surface(HostApiSurface::Performance),
            true,
        )
    }

    #[test]
    fn host_api_authority_default_is_deny_all() {
        let cap = BrowserHostApiIoCap::new(HostApiAuthority::default(), false);
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::Crypto)),
            Err(HostApiPolicyError::SurfaceDenied(HostApiSurface::Crypto))
        );
    }

    #[test]
    fn host_api_policy_denies_degraded_mode_when_not_allowed() {
        let cap = strict_host_api_cap();
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::Crypto).with_degraded_mode()),
            Err(HostApiPolicyError::DegradedModeDenied(
                HostApiSurface::Crypto
            ))
        );
    }

    #[test]
    fn host_api_policy_allows_explicit_grant_and_exposes_iocap() {
        let cap = BrowserHostApiIoCap::new(
            HostApiAuthority::deny_all()
                .grant_surface(HostApiSurface::Crypto)
                .with_degraded_mode_allowed(),
            true,
        );
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::Crypto).with_degraded_mode()),
            Ok(())
        );
        let io_cap: &dyn IoCap = &cap;
        let host_api_cap = io_cap
            .host_api_cap()
            .expect("host api cap should be present");
        assert!(host_api_cap.require_redaction_safe_diagnostics());
    }

    #[test]
    fn storage_authority_default_is_deny_all() {
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::default(),
            StorageQuotaPolicy::default(),
            StorageConsistencyPolicy::ImmediateReadAfterWrite,
            StorageRedactionPolicy::default(),
        );
        let request = StorageRequest::get(StorageBackend::IndexedDb, "cache:v1", "entry");
        assert_eq!(
            cap.authorize(&request),
            Err(StoragePolicyError::BackendDenied(StorageBackend::IndexedDb))
        );
    }

    #[test]
    fn storage_authority_supports_namespace_prefix_rules() {
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::IndexedDb)
                .grant_operation(StorageOperation::Get)
                .grant_namespace("cache:*"),
            StorageQuotaPolicy::default(),
            StorageConsistencyPolicy::ImmediateReadAfterWrite,
            StorageRedactionPolicy::default(),
        );

        let allowed = StorageRequest::get(StorageBackend::IndexedDb, "cache:user:42", "profile");
        assert_eq!(cap.authorize(&allowed), Ok(()));

        let denied = StorageRequest::get(StorageBackend::IndexedDb, "session:v1", "profile");
        assert_eq!(
            cap.authorize(&denied),
            Err(StoragePolicyError::NamespaceDenied("session:v1".to_owned()))
        );
    }

    #[test]
    fn storage_authority_denies_ungranted_operation() {
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::LocalStorage)
                .grant_operation(StorageOperation::Get)
                .grant_namespace("prefs:*"),
            StorageQuotaPolicy::default(),
            StorageConsistencyPolicy::ImmediateReadAfterWrite,
            StorageRedactionPolicy::default(),
        );

        let request = StorageRequest::set(StorageBackend::LocalStorage, "prefs:v1", "theme", 4);
        assert_eq!(
            cap.authorize(&request),
            Err(StoragePolicyError::OperationDenied(StorageOperation::Set))
        );
    }

    #[test]
    fn storage_authorize_enforces_key_and_value_limits() {
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::LocalStorage)
                .grant_operation(StorageOperation::Set)
                .grant_namespace("*"),
            StorageQuotaPolicy {
                max_key_bytes: 4,
                max_value_bytes: 3,
                ..StorageQuotaPolicy::default()
            },
            StorageConsistencyPolicy::ImmediateReadAfterWrite,
            StorageRedactionPolicy::default(),
        );

        let missing_key = StorageRequest::new(
            StorageBackend::LocalStorage,
            StorageOperation::Set,
            "prefs:v1",
        )
        .with_value_len(2);
        assert_eq!(
            cap.authorize(&missing_key),
            Err(StoragePolicyError::MissingKey(StorageOperation::Set))
        );

        let long_key = StorageRequest::set(StorageBackend::LocalStorage, "prefs:v1", "abcde", 2);
        assert_eq!(
            cap.authorize(&long_key),
            Err(StoragePolicyError::KeyTooLarge { len: 5, limit: 4 })
        );

        let long_value = StorageRequest::set(StorageBackend::LocalStorage, "prefs:v1", "k1", 5);
        assert_eq!(
            cap.authorize(&long_value),
            Err(StoragePolicyError::ValueTooLarge { len: 5, limit: 3 })
        );
    }

    #[test]
    fn browser_storage_cap_exposes_policies_through_iocap() {
        let quota = StorageQuotaPolicy {
            max_total_bytes: 4096,
            max_key_bytes: 64,
            max_value_bytes: 2048,
            max_namespace_bytes: 32,
            max_entries: 64,
        };
        let redaction = StorageRedactionPolicy {
            redact_keys: true,
            redact_namespaces: true,
            redact_value_lengths: false,
        };
        let cap = BrowserStorageIoCap::new(
            StorageAuthority::deny_all()
                .grant_backend(StorageBackend::IndexedDb)
                .grant_operation(StorageOperation::Get)
                .grant_namespace("cache:*"),
            quota,
            StorageConsistencyPolicy::ImmediateReadAfterWrite,
            redaction,
        );
        let io_cap: &dyn IoCap = &cap;
        let storage_cap = io_cap.storage_cap().expect("storage cap should be present");
        assert_eq!(storage_cap.quota_policy(), quota);
        assert_eq!(
            storage_cap.consistency_policy(),
            StorageConsistencyPolicy::ImmediateReadAfterWrite
        );
        assert_eq!(storage_cap.redaction_policy(), redaction);
    }

    // ── Messaging capability tests (bead asupersync-1n453.3) ──────

    #[test]
    fn messaging_authority_grant_covers_all_three_surfaces() {
        let cap = BrowserHostApiIoCap::new(HostApiAuthority::deny_all().grant_messaging(), false);
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::MessageChannel)),
            Ok(())
        );
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::MessagePort)),
            Ok(())
        );
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::BroadcastChannel)),
            Ok(())
        );
    }

    #[test]
    fn messaging_surfaces_denied_by_default() {
        let cap = BrowserHostApiIoCap::new(HostApiAuthority::deny_all(), false);
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::MessagePort)),
            Err(HostApiPolicyError::SurfaceDenied(
                HostApiSurface::MessagePort
            ))
        );
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::BroadcastChannel)),
            Err(HostApiPolicyError::SurfaceDenied(
                HostApiSurface::BroadcastChannel
            ))
        );
    }

    #[test]
    fn individual_messaging_surface_grants_are_independent() {
        let cap = BrowserHostApiIoCap::new(
            HostApiAuthority::deny_all().grant_surface(HostApiSurface::MessagePort),
            false,
        );
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::MessagePort)),
            Ok(())
        );
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::BroadcastChannel)),
            Err(HostApiPolicyError::SurfaceDenied(
                HostApiSurface::BroadcastChannel
            ))
        );
        assert_eq!(
            cap.authorize(&HostApiRequest::new(HostApiSurface::MessageChannel)),
            Err(HostApiPolicyError::SurfaceDenied(
                HostApiSurface::MessageChannel
            ))
        );
    }

    // ====================================================================
    // br-asupersync-qz046d: parse_browser_transport_url userinfo stripping
    // ====================================================================

    #[test]
    fn qz046d_origin_strips_userinfo_when_present() {
        let with = parse_browser_transport_url("ws://attacker:ignored@localhost:8080/path")
            .expect("parse with userinfo");
        let without =
            parse_browser_transport_url("ws://localhost:8080/path").expect("parse without");
        // Both URLs target the same web origin per RFC 6454; the
        // returned tuple's `origin` field must be identical so the
        // allowlist check and the loopback-exemption check agree.
        assert_eq!(with.0, without.0, "scheme");
        assert_eq!(with.1, without.1, "origin must NOT include userinfo");
        assert_eq!(with.2, without.2, "host");
    }

    #[test]
    fn qz046d_origin_strips_userinfo_with_at_in_password() {
        // Edge case: the password legitimately contains an `@` (URL-
        // encoded or not). rsplit_once('@') treats the LAST `@` as
        // the userinfo/host separator, so the resulting origin still
        // canonicalises correctly.
        let parsed =
            parse_browser_transport_url("wss://u:p%40ss@host.example:443/").expect("parse ok");
        assert_eq!(parsed.0, "wss");
        assert_eq!(parsed.1, "wss://host.example:443");
        assert_eq!(parsed.2, "host.example");
    }

    #[test]
    fn qz046d_origin_unchanged_when_no_userinfo() {
        let parsed = parse_browser_transport_url("https://example.com:443/").expect("parse ok");
        assert_eq!(parsed.1, "https://example.com:443");
    }
