    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_error_code_from_u32_known_and_unknown() {
        init_test("test_error_code_from_u32_known_and_unknown");
        crate::assert_with_log!(
            ErrorCode::from_u32(0x0) == ErrorCode::NoError,
            "no error",
            true,
            ErrorCode::from_u32(0x0) == ErrorCode::NoError
        );
        crate::assert_with_log!(
            ErrorCode::from_u32(0x1) == ErrorCode::ProtocolError,
            "protocol error",
            true,
            ErrorCode::from_u32(0x1) == ErrorCode::ProtocolError
        );
        crate::assert_with_log!(
            ErrorCode::from_u32(0x2) == ErrorCode::InternalError,
            "internal error",
            true,
            ErrorCode::from_u32(0x2) == ErrorCode::InternalError
        );
        crate::assert_with_log!(
            ErrorCode::from_u32(0xdead) == ErrorCode::InternalError,
            "unknown maps to internal",
            true,
            ErrorCode::from_u32(0xdead) == ErrorCode::InternalError
        );
        crate::test_complete!("test_error_code_from_u32_known_and_unknown");
    }

    #[test]
    fn error_code_from_u32_covers_rfc7540_section_7_registry() {
        let cases = [
            (0x0, ErrorCode::NoError, "NO_ERROR"),
            (0x1, ErrorCode::ProtocolError, "PROTOCOL_ERROR"),
            (0x2, ErrorCode::InternalError, "INTERNAL_ERROR"),
            (0x3, ErrorCode::FlowControlError, "FLOW_CONTROL_ERROR"),
            (0x4, ErrorCode::SettingsTimeout, "SETTINGS_TIMEOUT"),
            (0x5, ErrorCode::StreamClosed, "STREAM_CLOSED"),
            (0x6, ErrorCode::FrameSizeError, "FRAME_SIZE_ERROR"),
            (0x7, ErrorCode::RefusedStream, "REFUSED_STREAM"),
            (0x8, ErrorCode::Cancel, "CANCEL"),
            (0x9, ErrorCode::CompressionError, "COMPRESSION_ERROR"),
            (0xa, ErrorCode::ConnectError, "CONNECT_ERROR"),
            (0xb, ErrorCode::EnhanceYourCalm, "ENHANCE_YOUR_CALM"),
            (0xc, ErrorCode::InadequateSecurity, "INADEQUATE_SECURITY"),
            (0xd, ErrorCode::Http11Required, "HTTP_1_1_REQUIRED"),
        ];

        for (wire_value, expected_code, display_token) in cases {
            let parsed = ErrorCode::from_u32(wire_value);
            assert_eq!(parsed, expected_code, "wire value {wire_value:#x}");
            assert_eq!(u32::from(parsed), wire_value);
            assert_eq!(parsed.to_string(), display_token);
        }

        for unknown in [0x0e, 0x10, 0xffff_ffff] {
            assert_eq!(ErrorCode::from_u32(unknown), ErrorCode::InternalError);
        }
    }

    #[test]
    fn test_error_code_u32_roundtrip() {
        init_test("test_error_code_u32_roundtrip");
        let code = ErrorCode::FrameSizeError;
        let value: u32 = code.into();
        crate::assert_with_log!(value == 0x6, "frame size code", 0x6u32, value);
        crate::test_complete!("test_error_code_u32_roundtrip");
    }

    #[test]
    fn test_error_code_display_tokens() {
        init_test("test_error_code_display_tokens");
        let no_error = ErrorCode::NoError.to_string();
        let calm = ErrorCode::EnhanceYourCalm.to_string();
        crate::assert_with_log!(
            no_error == "NO_ERROR",
            "no error token",
            "NO_ERROR",
            no_error
        );
        crate::assert_with_log!(
            calm == "ENHANCE_YOUR_CALM",
            "calm token",
            "ENHANCE_YOUR_CALM",
            calm
        );
        crate::test_complete!("test_error_code_display_tokens");
    }

    #[test]
    fn test_h2error_connection_and_stream_variants() {
        init_test("test_h2error_connection_and_stream_variants");
        let conn = H2Error::connection(ErrorCode::Cancel, "bye");
        crate::assert_with_log!(
            conn.is_connection_error(),
            "connection error",
            true,
            conn.is_connection_error()
        );
        crate::assert_with_log!(
            conn.stream_id.is_none(),
            "no stream id",
            true,
            conn.stream_id.is_none()
        );
        let conn_render = conn.to_string();
        crate::assert_with_log!(
            conn_render.contains("connection error"),
            "connection display",
            true,
            conn_render.contains("connection error")
        );

        let stream = H2Error::stream(7, ErrorCode::ProtocolError, "bad");
        crate::assert_with_log!(
            !stream.is_connection_error(),
            "stream error",
            false,
            stream.is_connection_error()
        );
        crate::assert_with_log!(
            stream.stream_id == Some(7),
            "stream id",
            Some(7u32),
            stream.stream_id
        );
        let stream_render = stream.to_string();
        crate::assert_with_log!(
            stream_render.contains("stream 7"),
            "stream display",
            true,
            stream_render.contains("stream 7")
        );
        crate::test_complete!("test_h2error_connection_and_stream_variants");
    }

    #[test]
    fn test_h2error_stream_zero_normalized_to_connection_error() {
        init_test("test_h2error_stream_zero_normalized_to_connection_error");
        let err = H2Error::stream(0, ErrorCode::StreamClosed, "invalid stream id");
        crate::assert_with_log!(
            err.is_connection_error(),
            "stream 0 normalized to connection-level",
            true,
            err.is_connection_error()
        );
        crate::assert_with_log!(
            err.stream_id.is_none(),
            "stream id must be none for normalized error",
            true,
            err.stream_id.is_none()
        );
        crate::assert_with_log!(
            err.to_string().contains("connection error"),
            "display reports connection-level error",
            true,
            err.to_string().contains("connection error")
        );
        crate::test_complete!("test_h2error_stream_zero_normalized_to_connection_error");
    }

    #[test]
    fn test_h2error_helper_constructors_set_codes() {
        init_test("test_h2error_helper_constructors_set_codes");
        let protocol = H2Error::protocol("bad");
        let frame = H2Error::frame_size("size");
        let flow = H2Error::flow_control("flow");
        let compression = H2Error::compression("hpack");
        crate::assert_with_log!(
            protocol.code == ErrorCode::ProtocolError,
            "protocol code",
            true,
            protocol.code == ErrorCode::ProtocolError
        );
        crate::assert_with_log!(
            frame.code == ErrorCode::FrameSizeError,
            "frame size code",
            true,
            frame.code == ErrorCode::FrameSizeError
        );
        crate::assert_with_log!(
            flow.code == ErrorCode::FlowControlError,
            "flow control code",
            true,
            flow.code == ErrorCode::FlowControlError
        );
        crate::assert_with_log!(
            compression.code == ErrorCode::CompressionError,
            "compression code",
            true,
            compression.code == ErrorCode::CompressionError
        );
        crate::test_complete!("test_h2error_helper_constructors_set_codes");
    }

    #[test]
    fn test_h2error_from_io_error_internal() {
        init_test("test_h2error_from_io_error_internal");
        let io_err = std::io::Error::other("io");
        let err = H2Error::from(io_err);
        crate::assert_with_log!(
            err.code == ErrorCode::InternalError,
            "io maps to internal",
            true,
            err.code == ErrorCode::InternalError
        );
        crate::assert_with_log!(
            err.message.contains("io"),
            "message contains io",
            true,
            err.message.contains("io")
        );
        crate::test_complete!("test_h2error_from_io_error_internal");
    }

    #[test]
    fn test_h2error_from_str_protocol() {
        init_test("test_h2error_from_str_protocol");
        let err = H2Error::from("bad");
        crate::assert_with_log!(
            err.code == ErrorCode::ProtocolError,
            "from str protocol",
            true,
            err.code == ErrorCode::ProtocolError
        );
        crate::test_complete!("test_h2error_from_str_protocol");
    }

    #[test]
    fn error_code_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = ErrorCode::Cancel;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, ErrorCode::NoError);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Cancel"));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(!set.contains(&ErrorCode::FlowControlError));
    }
