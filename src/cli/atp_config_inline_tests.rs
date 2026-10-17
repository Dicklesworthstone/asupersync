    use super::*;
    use crate::cli::atp_command_tree::AtpConfig;
    use tempfile::TempDir;

    fn sample_install_config() -> AtpInstallConfig {
        AtpInstallConfig {
            schema_version: ConfigVersion::current(),
            version: Some(Version::parse("1.2.3").expect("valid version")),
            identity_path: PathBuf::from("/tmp/asupersync/identity.key"),
            inbox_dir: PathBuf::from("/tmp/asupersync/inbox"),
            peer_dir: PathBuf::from("/tmp/asupersync/peers"),
            daemon_state_dir: PathBuf::from("/tmp/asupersync/state"),
            receive_safety_policy: ReceiveSafetyPolicy::KnownPeersOnly,
            proof_retention_policy: ProofRetentionPolicy::Days(30),
            enable_tailscale: true,
            allow_relays: false,
            logging_level: "info".to_owned(),
            service_platform: "linux".to_owned(),
            service_daemon_enabled: true,
            service_auto_start: false,
        }
    }

    #[test]
    fn atp_command_toml_and_json_share_one_model_and_exact_golden() {
        let toml = r#"
profile = "media"
chunk_size = 1024
repair_overhead = 0.25
daemon_socket = "./run/../atp.sock"
"#;
        let from_toml: AtpConfig = toml::from_str(toml).expect("ATP TOML layer");
        let canonical = atp_command_to_canonical_json(&from_toml).expect("canonical ATP JSON");

        assert_eq!(
            canonical,
            r#"{"config":{"chunk_size":1024,"compression":null,"daemon_socket":"./run/../atp.sock","encryption":null,"interface":null,"max_concurrent":null,"profile":"media","relay_server":null,"repair_overhead":0.25,"timeout":null,"verbose":null},"schema_version":1}"#
        );
        assert_eq!(
            parse_atp_command_json(&canonical).expect("canonical ATP JSON layer"),
            from_toml
        );
    }

    #[test]
    fn atp_command_empty_unknown_schema_and_nonfinite_rules_are_explicit() {
        let empty_toml: AtpConfig = toml::from_str("").expect("empty ATP TOML layer");
        let empty_json = parse_atp_command_json(r#"{"config":{}}"#).expect("empty ATP JSON layer");
        assert_eq!(empty_json, empty_toml);

        let unknown = parse_atp_command_json(
            r#"{"config":{"profile":"auto","future_field":true},"future_envelope":1}"#,
        )
        .expect("unknown JSON fields retain incumbent tolerance");
        assert_eq!(unknown.profile, Some(AtpProfile::Auto));

        let unsupported =
            parse_atp_command_json(r#"{"schema_version":2,"config":{"profile":"auto"}}"#)
                .expect_err("unsupported outer schema must fail closed");
        assert!(unsupported.to_string().contains("schema version 2"));

        let nonfinite: AtpConfig =
            toml::from_str("repair_overhead = nan").expect("incumbent TOML accepts NaN");
        assert!(nonfinite.repair_overhead.is_some_and(f32::is_nan));
        let error = atp_command_to_canonical_json(&nonfinite)
            .expect_err("non-finite JSON conversion must not become null");
        assert!(error.to_string().contains("must be finite"));
    }

    #[test]
    fn atp_install_toml_and_json_share_one_model_and_exact_golden() {
        let install = sample_install_config();
        let toml = toml::to_string_pretty(&install).expect("install TOML");
        let from_toml: AtpInstallConfig = toml::from_str(&toml).expect("install TOML round trip");
        let canonical = from_toml
            .to_canonical_json()
            .expect("canonical install JSON");

        assert_eq!(
            canonical,
            r#"{"config":{"allow_relays":false,"daemon_state_dir":"/tmp/asupersync/state","enable_tailscale":true,"identity_path":"/tmp/asupersync/identity.key","inbox_dir":"/tmp/asupersync/inbox","logging_level":"info","peer_dir":"/tmp/asupersync/peers","proof_retention_policy":{"Days":30},"receive_safety_policy":"KnownPeersOnly","schema_version":{"schema":1},"service_auto_start":false,"service_daemon_enabled":true,"service_platform":"linux","version":"1.2.3"},"schema_version":1}"#
        );
        assert_eq!(
            AtpInstallConfig::from_json(&canonical).expect("install JSON round trip"),
            install
        );
    }

    #[test]
    fn atp_install_outer_schema_is_additive_but_payload_requirements_remain() {
        let canonical = sample_install_config()
            .to_canonical_json()
            .expect("canonical install JSON");
        let without_outer_version = canonical.replacen(",\"schema_version\":1}", "}", 1);
        assert_eq!(
            AtpInstallConfig::from_json(&without_outer_version)
                .expect("missing outer schema migrates to v1"),
            sample_install_config()
        );
        let with_unknown = canonical.replacen(
            "\"allow_relays\":false",
            "\"future_install_field\":true,\"allow_relays\":false",
            1,
        );
        assert_eq!(
            AtpInstallConfig::from_json(&with_unknown)
                .expect("unknown install JSON fields retain incumbent tolerance"),
            sample_install_config()
        );
        assert!(
            AtpInstallConfig::from_json(r#"{"config":{}}"#).is_err(),
            "required install payload fields must remain required"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atp_install_canonical_paths_require_utf8_without_normalizing() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut install = sample_install_config();
        install.identity_path = PathBuf::from(OsString::from_vec(vec![0xff]));
        let error = install
            .to_canonical_json()
            .expect_err("non-UTF-8 path cannot be represented losslessly in JSON");
        assert!(
            error
                .to_string()
                .contains("identity_path must be valid UTF-8")
        );
    }

    #[test]
    fn test_config_precedence() {
        let mut manager = AtpConfigManager::new();

        // Set daemon policy
        let daemon_config = AtpConfig {
            profile: Some(AtpProfile::BulkFile),
            compression: Some(false),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::DaemonPolicy, daemon_config);

        // Set local config
        let local_config = AtpConfig {
            profile: Some(AtpProfile::SyncTree),
            timeout: Some(600),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::LocalConfig, local_config);

        // Set CLI flags
        // `AtpConfig::default()` carries `profile: Some(AtpProfile::Auto)`, so
        // a layer built from `..Default::default()` would override the local
        // profile with Auto. A CLI layer that did not name a profile leaves
        // it unset.
        let cli_config = AtpConfig {
            timeout: Some(120),
            compression: Some(true),
            profile: None,
            ..Default::default()
        };
        manager.layers.insert(ConfigSource::CliFlags, cli_config);

        let merged = manager.merged_config();

        // CLI flags should override local config for timeout
        assert_eq!(merged.timeout, Some(120));
        // CLI flags should override daemon policy for compression
        assert_eq!(merged.compression, Some(true));
        // Local config should override daemon policy for profile
        assert_eq!(merged.profile, Some(AtpProfile::SyncTree));
    }

    #[test]
    fn test_profile_with_source() {
        let mut manager = AtpConfigManager::new();

        // Only defaults - should return Auto
        let (profile, source) = manager.get_profile_with_source();
        assert_eq!(profile, AtpProfile::Auto);
        assert_eq!(source, ConfigSource::Defaults);

        // Add local config
        let local_config = AtpConfig {
            profile: Some(AtpProfile::Artifact),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::LocalConfig, local_config);

        let (profile, source) = manager.get_profile_with_source();
        assert_eq!(profile, AtpProfile::Artifact);
        assert_eq!(source, ConfigSource::LocalConfig);
    }

    #[test]
    fn test_config_file_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");

        let original_config = AtpConfig {
            profile: Some(AtpProfile::Media),
            chunk_size: Some(1024 * 1024),
            compression: Some(true),
            ..Default::default()
        };

        let manager = AtpConfigManager::new();

        // Save config
        manager
            .save_config_file(&config_path, &original_config)
            .unwrap();

        // Load config
        let loaded_config = manager.load_config_file(&config_path).unwrap();

        assert_eq!(loaded_config.profile, original_config.profile);
        assert_eq!(loaded_config.chunk_size, original_config.chunk_size);
        assert_eq!(loaded_config.compression, original_config.compression);
    }

    #[test]
    fn test_config_resolution_explanation() {
        let mut manager = AtpConfigManager::new();

        // Add multiple layers
        let daemon_config = AtpConfig {
            timeout: Some(300),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::DaemonPolicy, daemon_config);

        let local_config = AtpConfig {
            timeout: Some(600),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::LocalConfig, local_config);

        let resolution = manager.explain_resolution("timeout");

        assert_eq!(resolution.sources.len(), 3); // defaults + daemon + local
        assert_eq!(
            resolution.final_value,
            Some(serde_json::Value::Number(600.into()))
        );
    }
