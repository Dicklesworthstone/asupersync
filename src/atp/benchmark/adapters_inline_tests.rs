    use super::*;

    #[test]
    fn tool_version_parsing_works() {
        let version = ToolVersion::new("scp", "OpenSSH_8.2p1");
        assert_eq!(version.major, Some(8));
        assert_eq!(version.minor, Some(2));
        assert!(version.meets_minimum(7, 0));
        assert!(!version.meets_minimum(9, 0));
    }

    #[test]
    fn version_number_parsing_handles_various_formats() {
        assert_eq!(parse_version_numbers("8.2.1"), (Some(8), Some(2), Some(1)));
        assert_eq!(
            parse_version_numbers("OpenSSH_8.2p1"),
            (Some(8), Some(2), None)
        );
        assert_eq!(parse_version_numbers("7.4"), (Some(7), Some(4), None));
        assert_eq!(parse_version_numbers("no version"), (None, None, None));
    }

    #[tokio::test]
    async fn scp_adapter_creation() {
        let adapter = ScpAdapter::new();
        assert_eq!(adapter.tool_name(), "scp");
        assert!(!adapter.ssh_options.is_empty());
    }

    #[tokio::test]
    async fn tool_availability_check_handles_not_found() {
        // Test with non-existent command
        let output_result = Command::new("non_existent_command_xyz")
            .arg("--version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        assert!(output_result.is_err(), "Non-existent command should fail");
    }

    #[tokio::test]
    async fn rsync_adapter_creation() {
        let adapter = RsyncAdapter::new();
        assert_eq!(adapter.tool_name(), "rsync");
        assert!(!adapter.rsync_options.is_empty());
        assert!(adapter.rsync_options.contains(&"--verbose".to_string()));
    }

    #[tokio::test]
    async fn rsync_adapter_with_custom_options() {
        let custom_options = vec!["--checksum".to_string(), "--compress".to_string()];
        let adapter = RsyncAdapter::with_options(custom_options.clone());
        assert_eq!(adapter.rsync_options, custom_options);
    }

    #[tokio::test]
    async fn curl_adapter_creation() {
        let adapter = CurlAdapter::new();
        assert_eq!(adapter.tool_name(), "curl");
        assert!(!adapter.enable_http3);
        assert!(!adapter.curl_options.is_empty());
    }

    #[tokio::test]
    async fn curl_adapter_http3() {
        let adapter = CurlAdapter::with_http3();
        assert_eq!(adapter.tool_name(), "curl-http3");
        assert!(adapter.enable_http3);
        assert!(adapter.curl_options.contains(&"--http3".to_string()));
    }

    #[tokio::test]
    async fn curl_adapter_with_custom_options() {
        let custom_options = vec!["--max-time".to_string(), "30".to_string()];
        let adapter = CurlAdapter::with_options(custom_options.clone(), false);
        assert_eq!(adapter.curl_options, custom_options);
        assert!(!adapter.enable_http3);
    }
