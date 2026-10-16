    use super::*;

    #[test]
    fn test_atp_error_display() {
        let error = AtpError::Configuration("Invalid timeout".to_string());
        assert_eq!(error.to_string(), "Configuration error: Invalid timeout");
    }

    #[test]
    fn test_write_options_defaults() {
        let options = WriteOptions::default();
        assert_eq!(options.priority, 128);
        assert_eq!(options.compression, CompressionPreference::Auto);
    }
