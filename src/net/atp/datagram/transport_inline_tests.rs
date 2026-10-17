    use super::*;

    #[test]
    fn test_datagram_transport_creation() {
        let transport = DatagramTransport::new(true, 1024).unwrap();
        assert_eq!(transport.local_max_size(), 1024);
        assert!(!transport.is_enabled()); // Peer not configured yet
        assert!(!transport.peer_supports_datagram());

        let disabled = DatagramTransport::disabled();
        assert_eq!(disabled.local_max_size(), 0);
        assert!(!disabled.is_enabled());

        let default_enabled = DatagramTransport::default_enabled();
        assert_eq!(default_enabled.local_max_size(), DEFAULT_MAX_DATAGRAM_SIZE);
    }

    #[test]
    fn test_datagram_transport_validation() {
        // Invalid size - too small
        let result = DatagramTransport::new(true, MIN_DATAGRAM_SIZE - 1);
        assert!(result.is_err());

        // Invalid size - too large
        let result = DatagramTransport::new(true, MAX_DATAGRAM_SIZE + 1);
        assert!(result.is_err());

        // Valid sizes
        assert!(DatagramTransport::new(true, MIN_DATAGRAM_SIZE).is_ok());
        assert!(DatagramTransport::new(true, MAX_DATAGRAM_SIZE).is_ok());
        assert!(DatagramTransport::new(true, DEFAULT_MAX_DATAGRAM_SIZE).is_ok());
    }

    #[test]
    fn test_datagram_config() {
        let config = DatagramConfig::new();
        assert!(!config.enabled);
        config.validate().unwrap();

        let enabled_config = DatagramConfig::enabled();
        assert!(enabled_config.enabled);
        assert!(enabled_config.enable_path_probes);
        assert!(enabled_config.enable_path_beacons);
        assert!(enabled_config.enable_telemetry);

        let probes_only = DatagramConfig::path_probes_only();
        assert!(probes_only.enable_path_probes);
        assert!(!probes_only.enable_path_beacons);
        assert!(!probes_only.enable_telemetry);

        let beacons_only = DatagramConfig::beacons_only();
        assert!(!beacons_only.enable_path_probes);
        assert!(beacons_only.enable_path_beacons);
        assert!(!beacons_only.enable_telemetry);
    }

    #[test]
    fn test_datagram_config_validation() {
        let invalid_config = DatagramConfig::new().with_max_frame_size(MAX_DATAGRAM_SIZE + 1);

        // Validation should clamp the size
        assert_eq!(invalid_config.max_frame_size, MAX_DATAGRAM_SIZE);

        let too_small = DatagramConfig::new().with_max_frame_size(MIN_DATAGRAM_SIZE - 1);

        // Validation should clamp the size
        assert_eq!(too_small.max_frame_size, MIN_DATAGRAM_SIZE);
    }

    #[test]
    fn test_size_validation() {
        let mut transport = DatagramTransport::new(true, 1024).unwrap();

        // Not enabled yet (no peer)
        assert!(transport.validate_size(100).is_err());

        // Apply peer negotiation state.
        transport.peer_enabled = true;
        transport.peer_max_size = Some(512);

        // Should use minimum of local and peer
        assert_eq!(transport.max_frame_size(), Some(512));

        // Valid size
        assert!(transport.validate_size(256).is_ok());

        // Too large
        assert!(transport.validate_size(1024).is_err());
    }

    #[test]
    fn test_transport_parameter_negotiation_uses_rfc9221_id() {
        let transport = DatagramTransport::new(true, 1024).unwrap();
        let mut params = TransportParameters::new();

        transport.add_to_transport_params(&mut params);

        assert_eq!(
            params.get_integer(TransportParamId::MaxDatagramFrameSize),
            Some(1024)
        );
        assert!(
            params
                .get_integer(TransportParamId::MaxIdleTimeout)
                .is_none(),
            "DATAGRAM negotiation must not overwrite max_idle_timeout"
        );
    }

    #[test]
    fn test_peer_params_absent_fail_closed() {
        let mut transport = DatagramTransport::new(true, 1024).unwrap();
        let params = TransportParameters::new();

        transport.process_peer_params(&params).unwrap();

        assert!(!transport.peer_supports_datagram());
        assert!(!transport.is_enabled());
        assert_eq!(transport.peer_max_size(), None);
    }

    #[test]
    fn test_peer_params_enable_with_valid_rfc9221_value() {
        let mut transport = DatagramTransport::new(true, 1024).unwrap();
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::MaxDatagramFrameSize, 512);

        transport.process_peer_params(&params).unwrap();

        assert!(transport.peer_supports_datagram());
        assert!(transport.is_enabled());
        assert_eq!(transport.max_frame_size(), Some(512));
    }

    #[test]
    fn test_datagram_negotiation() {
        let config = DatagramConfig::enabled();
        let transport = DatagramTransport::default_enabled();

        let negotiation = DatagramNegotiation::new(config.clone(), &transport);
        assert!(!negotiation.enabled); // No peer yet

        // With required flag
        let required_config = config.required();
        let required_transport = DatagramTransport::disabled();
        let required_negotiation = DatagramNegotiation::new(required_config, &required_transport);
        assert!(!required_negotiation.is_successful());
    }
