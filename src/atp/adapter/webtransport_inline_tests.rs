    use super::*;
    use futures_lite::future::block_on;

    #[test]
    fn test_webtransport_config_default() {
        let config = WebTransportConfig::default();
        assert_eq!(config.session_config.max_bidirectional_streams, 100);
        assert_eq!(config.datagram_config.max_datagram_size, 1200);
        assert!(
            config
                .security_policy
                .feature_permissions
                .webtransport_enabled
        );
    }

    #[test]
    fn test_webtransport_session_lifecycle() {
        block_on(async {
            let mut adapter = WebTransportAdapter::new(WebTransportConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));

            // Start session
            let session_id = adapter
                .start_session(object_id, "https://example.com")
                .await
                .unwrap();
            assert_eq!(adapter.stats.active_sessions, 1);

            // Create stream
            let stream_id = adapter.create_stream(&session_id, 128).await.unwrap();
            assert_eq!(stream_id, 0); // First stream should be ID 0

            // Send frame
            let data = b"ATP frame data";
            adapter
                .send_frame(&session_id, stream_id, data)
                .await
                .unwrap();

            // Send datagram
            let datagram_data = b"ATP datagram";
            adapter
                .send_datagram(&session_id, datagram_data)
                .await
                .unwrap();

            // Close session
            adapter.close_session(&session_id).await.unwrap();
            assert_eq!(adapter.stats.active_sessions, 0);
        });
    }

    #[test]
    fn test_webtransport_negotiation() {
        block_on(async {
            let adapter = WebTransportAdapter::new(WebTransportConfig::default());
            let trace_id = TraceId::from_parts(1, 1);

            let negotiation = adapter.negotiate(trace_id).await.unwrap();
            assert_eq!(negotiation.selected_adapter, AdapterType::WebTransport);
            assert_eq!(
                negotiation.feature_parity.object_support,
                FeatureSupport::Full
            );
            assert_eq!(
                negotiation.feature_parity.proof_support,
                FeatureSupport::Partial
            );
        });
    }

    #[test]
    fn webtransport_rejects_unwired_cert_validation_policies() {
        for mode in [
            CertValidationPolicy::AllowSelfSigned,
            CertValidationPolicy::CustomValidation,
        ] {
            let mut config = WebTransportConfig::default();
            config.security_policy.cert_validation = mode;
            let mut adapter = WebTransportAdapter::new(config);
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([3; 32]));

            let session_err = block_on(adapter.start_session(object_id, "https://example.com"))
                .expect_err("unwired WebTransport cert policy must fail closed");
            assert_eq!(session_err.kind(), ErrorKind::ConfigError);
            let message = session_err
                .message()
                .expect("fail-closed config error should explain the unwired verifier path");
            assert!(
                message.contains("cert_validation") && message.contains(&format!("{mode:?}")),
                "unexpected session error message for {mode:?}: {message}"
            );

            let negotiation_err = block_on(adapter.negotiate(TraceId::from_parts(3, 3)))
                .expect_err("negotiation must not advertise unwired cert validation");
            assert_eq!(negotiation_err.kind(), ErrorKind::ConfigError);
            let message = negotiation_err
                .message()
                .expect("negotiation config error should explain the unwired verifier path");
            assert!(
                message.contains("browser certificate verifier"),
                "unexpected negotiation error message for {mode:?}: {message}"
            );
        }
    }

    #[test]
    fn test_stream_limits() {
        block_on(async {
            let config = WebTransportConfig {
                session_config: WebTransportSessionConfig {
                    max_bidirectional_streams: 1, // Limit to 1 stream
                    max_unidirectional_streams: 1,
                    session_timeout: Duration::from_secs(300),
                    close_timeout: Duration::from_secs(5),
                },
                ..Default::default()
            };

            let mut adapter = WebTransportAdapter::new(config);
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));
            let session_id = adapter
                .start_session(object_id, "https://example.com")
                .await
                .unwrap();

            // First stream should succeed
            adapter.create_stream(&session_id, 128).await.unwrap();

            // Second stream should fail due to limit
            let result = adapter.create_stream(&session_id, 128).await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_stream_frame_and_datagram_queues() {
        block_on(async {
            let mut adapter = WebTransportAdapter::new(WebTransportConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));
            let session_id = adapter
                .start_session(object_id, "https://example.com/atp")
                .await
                .unwrap();
            let stream_id = adapter.create_stream(&session_id, 128).await.unwrap();

            adapter
                .send_frame(&session_id, stream_id, b"stream-frame")
                .await
                .unwrap();
            adapter
                .send_datagram(&session_id, b"datagram")
                .await
                .unwrap();

            let session = adapter.sessions.get(&session_id).unwrap();
            let stream = session.active_streams.get(&stream_id).unwrap();
            assert_eq!(stream.outbound_frames, vec![b"stream-frame".to_vec()]);
            assert_eq!(session.outbound_datagrams, vec![b"datagram".to_vec()]);
        });
    }

    #[test]
    fn test_invalid_webtransport_url_is_rejected() {
        block_on(async {
            let mut adapter = WebTransportAdapter::new(WebTransportConfig::default());
            let object_id = ObjectId::Content(crate::atp::object::ContentId::new([1; 32]));

            let result = adapter.start_session(object_id, "http://example.com").await;

            assert!(matches!(
                result,
                Err(err) if err.kind() == ErrorKind::InvalidInput
            ));
        });
    }
