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
    fn test_default_settings() {
        let settings = Settings::default();
        assert_eq!(settings.header_table_size, 4096);
        assert!(settings.enable_push);
        assert_eq!(
            settings.max_concurrent_streams,
            DEFAULT_MAX_CONCURRENT_STREAMS
        );
        assert_eq!(settings.initial_window_size, 65535);
        assert_eq!(settings.max_frame_size, 16384);
        assert_eq!(settings.max_header_list_size, DEFAULT_MAX_HEADER_LIST_SIZE);
    }

    #[test]
    fn test_client_settings() {
        let settings = Settings::client();
        assert!(!settings.enable_push);
    }

    #[test]
    fn test_apply_valid_settings() {
        let mut settings = Settings::default();
        assert!(settings.apply(Setting::InitialWindowSize(32768)).is_ok());
        assert_eq!(settings.initial_window_size, 32768);
    }

    #[test]
    fn test_apply_invalid_initial_window_size() {
        let mut settings = Settings::default();
        // Value too large
        let err = settings
            .apply(Setting::InitialWindowSize(0x8000_0000))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn test_apply_invalid_max_frame_size() {
        let mut settings = Settings::default();
        // Value too small
        let err = settings.apply(Setting::MaxFrameSize(1000)).unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        // Value too large
        let err = settings
            .apply(Setting::MaxFrameSize(0x0100_0000))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn test_apply_max_frame_size_bounds() {
        let mut settings = Settings::default();
        assert!(
            settings
                .apply(Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE))
                .is_ok()
        );
        assert!(
            settings
                .apply(Setting::MaxFrameSize(MAX_MAX_FRAME_SIZE))
                .is_ok()
        );
    }

    #[test]
    fn test_settings_builder() {
        let settings = SettingsBuilder::new()
            .header_table_size(8192)
            .enable_push(false)
            .max_concurrent_streams(100)
            .initial_window_size(131_072)
            .max_frame_size(32768)
            .continuation_timeout_ms(2500)
            .build();

        assert_eq!(settings.header_table_size, 8192);
        assert!(!settings.enable_push);
        assert_eq!(settings.max_concurrent_streams, 100);
        assert_eq!(settings.initial_window_size, 131_072);
        assert_eq!(settings.max_frame_size, 32768);
        assert_eq!(settings.continuation_timeout_ms, 2500);
    }

    #[test]
    fn settings_builder_clamps_protocol_bounded_fields() {
        let settings = SettingsBuilder::new()
            .initial_window_size(MAX_INITIAL_WINDOW_SIZE + 1)
            .max_frame_size(MIN_MAX_FRAME_SIZE - 1)
            .build();

        assert_eq!(settings.initial_window_size, MAX_INITIAL_WINDOW_SIZE);
        assert_eq!(settings.max_frame_size, MIN_MAX_FRAME_SIZE);

        let settings = SettingsBuilder::new()
            .initial_window_size(MAX_INITIAL_WINDOW_SIZE)
            .max_frame_size(MAX_MAX_FRAME_SIZE + 1)
            .build();

        assert_eq!(settings.initial_window_size, MAX_INITIAL_WINDOW_SIZE);
        assert_eq!(settings.max_frame_size, MAX_MAX_FRAME_SIZE);
    }

    #[test]
    fn test_to_settings_minimal() {
        let settings = SettingsBuilder::new()
            .enable_push(false)
            .max_concurrent_streams(100)
            .build();

        let minimal = settings.to_settings_minimal();
        // EnablePush (false != true), MaxConcurrentStreams (100 != MAX), MaxHeaderListSize (65536 != MAX)
        assert_eq!(minimal.len(), 3);
        assert!(minimal.contains(&Setting::EnablePush(false)));
        assert!(minimal.contains(&Setting::MaxConcurrentStreams(100)));
        assert!(minimal.contains(&Setting::MaxHeaderListSize(DEFAULT_MAX_HEADER_LIST_SIZE)));
    }

    #[test]
    fn to_settings_minimal_omits_rfc_unlimited_settings() {
        let settings = SettingsBuilder::new()
            .max_concurrent_streams(u32::MAX)
            .max_header_list_size(u32::MAX)
            .build();

        let minimal = settings.to_settings_minimal();

        assert!(
            minimal.is_empty(),
            "RFC 7540 defaults are implicit and should not be serialized: {minimal:?}"
        );
    }

    #[test]
    fn test_to_settings_for_server_omits_enable_push() {
        let settings = SettingsBuilder::server().enable_push(false).build();
        let serialized = settings.to_settings_for_role(false);
        assert!(
            !serialized
                .iter()
                .any(|setting| matches!(setting, Setting::EnablePush(_)))
        );
    }

    #[test]
    fn test_to_settings_minimal_for_server_omits_enable_push() {
        let settings = SettingsBuilder::server().enable_push(false).build();
        let minimal = settings.to_settings_minimal_for_role(false);
        assert!(
            !minimal
                .iter()
                .any(|setting| matches!(setting, Setting::EnablePush(_)))
        );
    }

    #[test]
    fn server_settings_serialization_is_invariant_to_enable_push() {
        let disabled = SettingsBuilder::server()
            .enable_push(false)
            .header_table_size(8192)
            .max_concurrent_streams(32)
            .initial_window_size(32_768)
            .max_frame_size(32_768)
            .max_header_list_size(16_384)
            .build();
        let mut enabled = disabled.clone();
        enabled.enable_push = true;

        assert_eq!(
            disabled.to_settings_for_role(false),
            enabled.to_settings_for_role(false),
            "server SETTINGS serialization must not depend on enable_push"
        );
        assert_eq!(
            disabled.to_settings_minimal_for_role(false),
            enabled.to_settings_minimal_for_role(false),
            "minimal server SETTINGS serialization must not depend on enable_push"
        );
        assert_ne!(
            disabled.to_settings_for_role(true),
            enabled.to_settings_for_role(true),
            "client serialization still carries enable_push differences"
        );
    }

    #[test]
    fn repeated_settings_apply_with_last_value_wins() {
        let mut settings = Settings::default();
        let sequence = [
            Setting::HeaderTableSize(8192),
            Setting::HeaderTableSize(16_384),
            Setting::EnablePush(false),
            Setting::EnablePush(true),
            Setting::MaxConcurrentStreams(64),
            Setting::MaxConcurrentStreams(128),
            Setting::InitialWindowSize(32_768),
            Setting::InitialWindowSize(MAX_INITIAL_WINDOW_SIZE),
            Setting::MaxFrameSize(32_768),
            Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE),
            Setting::MaxHeaderListSize(16_384),
            Setting::MaxHeaderListSize(32_768),
        ];

        for setting in sequence {
            settings.apply(setting).expect("valid setting applies");
        }

        assert_eq!(settings.header_table_size, 16_384);
        assert!(settings.enable_push);
        assert_eq!(settings.max_concurrent_streams, 128);
        assert_eq!(settings.initial_window_size, MAX_INITIAL_WINDOW_SIZE);
        assert_eq!(settings.max_frame_size, MIN_MAX_FRAME_SIZE);
        assert_eq!(settings.max_header_list_size, 32_768);
    }

    #[test]
    fn client_settings_full_serialization_reconstructs_state() {
        let original = SettingsBuilder::client()
            .header_table_size(8192)
            .enable_push(false)
            .max_concurrent_streams(64)
            .initial_window_size(32_768)
            .max_frame_size(32_768)
            .max_header_list_size(16_384)
            .continuation_timeout_ms(1234)
            .build();

        let mut reconstructed = Settings::default();
        for setting in original.to_settings_for_role(true) {
            reconstructed
                .apply(setting)
                .expect("serialized client setting must be valid");
        }
        reconstructed.continuation_timeout_ms = original.continuation_timeout_ms;

        assert_eq!(reconstructed, original);
    }

    #[test]
    fn invalid_peer_settings_do_not_mutate_existing_state() {
        let mut settings = SettingsBuilder::new()
            .initial_window_size(32_768)
            .max_frame_size(32_768)
            .build();
        let before = settings.clone();

        let err = settings
            .apply(Setting::InitialWindowSize(MAX_INITIAL_WINDOW_SIZE + 1))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError);
        assert_eq!(settings, before);

        let err = settings
            .apply(Setting::MaxFrameSize(MIN_MAX_FRAME_SIZE - 1))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(settings, before);

        let err = settings
            .apply(Setting::MaxFrameSize(MAX_MAX_FRAME_SIZE + 1))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert_eq!(settings, before);
    }

    // --- wave 77 trait coverage ---

    #[test]
    fn settings_debug_clone_eq_default() {
        let s = Settings::default();
        let s2 = s.clone();
        assert_eq!(s, s2);
        let modified = Settings {
            max_frame_size: 32768,
            ..Settings::default()
        };
        assert_ne!(s, modified);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Settings"));
    }

    #[test]
    fn settings_builder_debug_clone() {
        let b = SettingsBuilder::new();
        let b2 = b.clone();
        let dbg = format!("{b:?}");
        assert!(dbg.contains("SettingsBuilder"));
        assert_eq!(b.build(), b2.build());
    }
