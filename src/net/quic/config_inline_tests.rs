    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    #[test]
    fn default_config_values() {
        let config = QuicConfig::default();
        assert!(config.cert_chain.is_none());
        assert!(config.private_key.is_none());
        assert!(matches!(config.client_auth, ClientAuth::None));
        assert_eq!(config.max_bi_streams, 100);
        assert_eq!(config.max_uni_streams, 100);
        assert_eq!(config.keep_alive, Some(Duration::from_secs(15)));
        assert_eq!(config.idle_timeout, Duration::from_secs(30));
        assert_eq!(config.initial_max_stream_data, 1024 * 1024);
        assert_eq!(config.initial_max_data, 10 * 1024 * 1024);
        assert!(!config.enable_0rtt);
        assert!(config.alpn_protocols.is_empty());
        assert!(config.root_certs.is_none());
        assert!(config.client_auth_roots.is_none());
        assert!(!config.insecure_skip_verify);
    }

    #[test]
    fn new_equals_default() {
        let new = QuicConfig::new();
        let def = QuicConfig::default();
        assert_eq!(new.max_bi_streams, def.max_bi_streams);
        assert_eq!(new.idle_timeout, def.idle_timeout);
    }

    #[test]
    fn builder_with_cert() {
        let config = QuicConfig::new().with_cert(vec![vec![1, 2, 3]], vec![4, 5, 6]);
        assert!(config.cert_chain.is_some());
        assert_eq!(config.cert_chain.unwrap().len(), 1);
        assert!(config.private_key.is_some());
    }

    #[test]
    fn builder_with_client_auth() {
        let config = QuicConfig::new().with_client_auth(ClientAuth::Required);
        assert!(matches!(config.client_auth, ClientAuth::Required));
    }

    #[test]
    fn builder_max_streams() {
        let config = QuicConfig::new().max_bi_streams(50).max_uni_streams(25);
        assert_eq!(config.max_bi_streams, 50);
        assert_eq!(config.max_uni_streams, 25);
    }

    #[test]
    fn builder_keep_alive() {
        let config = QuicConfig::new().keep_alive(None);
        assert!(config.keep_alive.is_none());

        let config2 = QuicConfig::new().keep_alive(Some(Duration::from_secs(5)));
        assert_eq!(config2.keep_alive, Some(Duration::from_secs(5)));
    }

    #[test]
    fn builder_idle_timeout() {
        let config = QuicConfig::new().idle_timeout(Duration::from_secs(60));
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
    }

    #[test]
    fn builder_flow_control() {
        let config = QuicConfig::new().flow_control(512, 4096);
        assert_eq!(config.initial_max_stream_data, 512);
        assert_eq!(config.initial_max_data, 4096);
    }

    #[test]
    fn builder_enable_0rtt() {
        let config = QuicConfig::new().enable_0rtt(true);
        assert!(config.enable_0rtt);
    }

    #[test]
    fn builder_alpn() {
        let config = QuicConfig::new()
            .alpn(b"h3".to_vec())
            .alpn(b"h3-29".to_vec());
        assert_eq!(config.alpn_protocols.len(), 2);
        assert_eq!(config.alpn_protocols[0], b"h3");
        assert_eq!(config.alpn_protocols[1], b"h3-29");
    }

    #[test]
    fn builder_insecure_skip_verify() {
        let config = QuicConfig::new().insecure_skip_verify(true);
        assert!(config.insecure_skip_verify);
    }

    #[test]
    fn builder_chaining() {
        let config = QuicConfig::new()
            .max_bi_streams(10)
            .max_uni_streams(5)
            .idle_timeout(Duration::from_secs(120))
            .enable_0rtt(true)
            .alpn(b"test".to_vec());

        assert_eq!(config.max_bi_streams, 10);
        assert_eq!(config.max_uni_streams, 5);
        assert_eq!(config.idle_timeout, Duration::from_secs(120));
        assert!(config.enable_0rtt);
        assert_eq!(config.alpn_protocols.len(), 1);
    }

    #[test]
    fn is_valid_for_server_no_cert() {
        let config = QuicConfig::new();
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_with_cert_no_client_auth() {
        let config = QuicConfig::new().with_cert(vec![vec![1]], vec![2]);
        assert!(config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_cert_only_no_key() {
        let mut config = QuicConfig::new();
        config.cert_chain = Some(vec![vec![1]]);
        // No private_key
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_key_only_no_cert() {
        let mut config = QuicConfig::new();
        config.private_key = Some(vec![1]);
        // No cert_chain
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_required_auth_no_roots() {
        let config = QuicConfig::new()
            .with_cert(vec![vec![1]], vec![2])
            .with_client_auth(ClientAuth::Required);
        // No client_auth_roots
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn is_valid_for_server_optional_auth_no_roots() {
        let config = QuicConfig::new()
            .with_cert(vec![vec![1]], vec![2])
            .with_client_auth(ClientAuth::Optional);
        assert!(!config.is_valid_for_server());
    }

    #[test]
    fn to_transport_config_default() {
        let config = QuicConfig::new();
        // Should not panic
        let _transport = config.to_transport_config();
    }

    #[test]
    fn to_transport_config_custom() {
        let config = QuicConfig::new()
            .max_bi_streams(50)
            .max_uni_streams(25)
            .keep_alive(Some(Duration::from_secs(10)))
            .idle_timeout(Duration::from_secs(60))
            .flow_control(2048, 8192);

        let _transport = config.to_transport_config();
    }

    #[test]
    fn to_transport_config_no_keep_alive() {
        let config = QuicConfig::new().keep_alive(None);
        let _transport = config.to_transport_config();
    }

    #[test]
    fn to_transport_config_large_flow_control_capped() {
        // Values larger than u32::MAX should be capped
        let config = QuicConfig::new().flow_control(u64::MAX, u64::MAX);
        let _transport = config.to_transport_config();
    }

    #[test]
    fn client_auth_default() {
        let auth = ClientAuth::default();
        assert!(matches!(auth, ClientAuth::None));
    }

    #[test]
    fn client_auth_debug() {
        let debug = format!("{:?}", ClientAuth::Required);
        assert!(debug.contains("Required"));
    }

    #[test]
    fn client_auth_clone_copy() {
        let a = ClientAuth::Optional;
        let b = a; // Copy
        let c = a.clone();
        assert!(matches!(b, ClientAuth::Optional));
        assert!(matches!(c, ClientAuth::Optional));
    }

    #[test]
    fn config_debug() {
        let config = QuicConfig::new();
        let debug = format!("{config:?}");
        assert!(debug.contains("QuicConfig"));
    }

    #[test]
    fn config_clone() {
        let config = QuicConfig::new().max_bi_streams(42).alpn(b"test".to_vec());
        let cloned = config.clone();
        assert_eq!(cloned.max_bi_streams, 42);
        assert_eq!(cloned.alpn_protocols.len(), 1);
    }
