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
    fn test_dual_value_traditional() {
        let value = DualValue::Traditional(42i32);
        assert_eq!(value.get().unwrap(), 42);
        assert!(!value.uses_raptorq());
    }

    #[test]
    fn test_dual_value_conversion() {
        let mut value = DualValue::Traditional("hello".to_string());
        let config = EncodingConfig::default();

        // Convert to symbol-native
        value.ensure_symbols(&config).unwrap();
        assert!(matches!(value, DualValue::SymbolNative { .. }));

        // Still get same value
        assert_eq!(value.get().unwrap(), "hello".to_string());
    }

    #[test]
    fn test_migration_mode_decisions() {
        // Traditional only never uses RaptorQ
        assert!(!MigrationMode::TraditionalOnly.should_use_raptorq(None, 10000));

        // Symbol-native only always uses RaptorQ
        assert!(MigrationMode::SymbolNativeOnly.should_use_raptorq(None, 10));

        // Hints override mode
        assert!(MigrationMode::TraditionalOnly.should_use_raptorq(Some(true), 10));
        assert!(!MigrationMode::SymbolNativeOnly.should_use_raptorq(Some(false), 10));

        // Adaptive uses heuristics
        assert!(!MigrationMode::Adaptive.should_use_raptorq(None, 100));
        assert!(MigrationMode::Adaptive.should_use_raptorq(None, 10000));
    }

    #[test]
    fn test_migration_builder() {
        let config = configure_migration()
            .enable(MigrationFeature::JoinEncoding)
            .enable(MigrationFeature::RaceEncoding)
            .build();

        assert!(config.is_enabled(MigrationFeature::JoinEncoding));
        assert!(config.is_enabled(MigrationFeature::RaceEncoding));
        assert!(!config.is_enabled(MigrationFeature::DistributedRegions));
    }

    #[test]
    fn test_full_raptorq_mode() {
        let config = configure_migration().full_raptorq().build();

        for feature in MigrationFeature::all() {
            assert!(config.is_enabled(feature));
        }
    }

    #[test]
    fn test_migration_mode_default() {
        let mode = MigrationMode::default();
        assert_eq!(mode, MigrationMode::PreferTraditional);
    }

    #[test]
    fn test_migration_builder_disable() {
        let config = configure_migration()
            .full_raptorq()
            .disable(MigrationFeature::SymbolTracing)
            .build();

        assert!(config.is_enabled(MigrationFeature::JoinEncoding));
        assert!(!config.is_enabled(MigrationFeature::SymbolTracing));
    }

    #[test]
    fn test_per_operation_override() {
        let config = configure_migration()
            .with_mode(MigrationMode::PreferTraditional)
            .override_operation("heavy_join", MigrationMode::PreferSymbolNative)
            .build();

        assert_eq!(config.mode(), MigrationMode::PreferTraditional);
        assert_eq!(
            config.mode_for("heavy_join"),
            MigrationMode::PreferSymbolNative
        );
        assert_eq!(
            config.mode_for("other_op"),
            MigrationMode::PreferTraditional
        );
    }

    // ---- DualValueError ----

    #[test]
    fn dual_value_error_display_serialization() {
        let err = DualValueError::SerializationFailed("bad input".into());
        assert_eq!(err.to_string(), "serialization failed: bad input");
    }

    #[test]
    fn dual_value_error_display_deserialization() {
        let err = DualValueError::DeserializationFailed("unexpected EOF".into());
        assert_eq!(err.to_string(), "deserialization failed: unexpected EOF");
    }

    #[test]
    fn dual_value_error_source_is_none() {
        use std::error::Error;
        let err = DualValueError::SerializationFailed("x".into());
        assert!(err.source().is_none());
    }

    // ---- DualValue predicates ----

    #[test]
    fn dual_value_is_traditional() {
        let val = DualValue::Traditional(100u32);
        assert!(val.is_traditional());
        assert!(!val.uses_raptorq());
    }

    #[test]
    fn dual_value_uses_raptorq_after_ensure_symbols() {
        let mut val = DualValue::Traditional(42u32);
        let config = EncodingConfig::default();
        val.ensure_symbols(&config).unwrap();
        assert!(val.uses_raptorq());
        assert!(!val.is_traditional());
    }

    #[test]
    fn dual_value_ensure_symbols_idempotent() {
        let mut val = DualValue::Traditional(42u32);
        let config = EncodingConfig::default();
        val.ensure_symbols(&config).unwrap();
        assert!(val.uses_raptorq());
        // Second call should be a no-op (already SymbolNative)
        val.ensure_symbols(&config).unwrap();
        assert!(val.uses_raptorq());
        assert_eq!(val.get().unwrap(), 42u32);
    }

    #[test]
    fn dual_value_get_deserialization_failure() {
        // Construct a SymbolNative with garbage bytes that won't parse as u32
        let bad = DualValue::<u32>::SymbolNative {
            serialized: b"not valid json".to_vec(),
            object_id: ObjectId::new_for_test(0),
            _phantom: PhantomData,
        };
        let err = bad.get().unwrap_err();
        assert!(matches!(err, DualValueError::DeserializationFailed(_)));
    }

    #[test]
    fn dual_value_debug_traditional() {
        let val = DualValue::Traditional(99i32);
        let dbg = format!("{val:?}");
        assert!(dbg.contains("Traditional"), "{dbg}");
        assert!(dbg.contains("99"), "{dbg}");
    }

    #[test]
    fn dual_value_debug_symbol_native() {
        let mut val = DualValue::Traditional("hello".to_string());
        let config = EncodingConfig::default();
        val.ensure_symbols(&config).unwrap();
        let dbg = format!("{val:?}");
        assert!(dbg.contains("SymbolNative"), "{dbg}");
        assert!(dbg.contains("bytes"), "{dbg}");
    }

    #[test]
    fn dual_value_ensure_symbols_serialization_failure() {
        #[derive(Clone)]
        struct FailingSerialize;

        impl Serialize for FailingSerialize {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("forced serialization failure"))
            }
        }

        impl<'de> serde::Deserialize<'de> for FailingSerialize {
            fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Ok(Self)
            }
        }

        let mut val = DualValue::Traditional(FailingSerialize);
        let config = EncodingConfig::default();
        let err = val.ensure_symbols(&config).unwrap_err();
        assert!(matches!(err, DualValueError::SerializationFailed(_)));
        assert!(
            val.is_traditional(),
            "failed conversion should preserve original"
        );
    }

    // ---- MigrationConfig ----

    #[test]
    fn migration_config_enabled_features_returns_set() {
        let config = configure_migration()
            .enable(MigrationFeature::EpochBarriers)
            .enable(MigrationFeature::SymbolCancellation)
            .build();

        let features = config.enabled_features();
        assert_eq!(features.len(), 2);
        assert!(features.contains(&MigrationFeature::EpochBarriers));
        assert!(features.contains(&MigrationFeature::SymbolCancellation));
    }

    #[test]
    fn migration_config_default_has_no_features() {
        let config = MigrationConfig::default();
        assert!(config.enabled_features().is_empty());
        assert_eq!(config.mode(), MigrationMode::PreferTraditional);
    }

    // ---- MigrationMode::Adaptive boundary ----

    #[test]
    fn adaptive_mode_boundary_at_1024() {
        // Exactly 1024 should NOT trigger RaptorQ (condition is > 1024)
        assert!(!MigrationMode::Adaptive.should_use_raptorq(None, 1024));
        // 1025 should trigger it
        assert!(MigrationMode::Adaptive.should_use_raptorq(None, 1025));
    }

    #[test]
    fn prefer_symbol_native_without_hint() {
        assert!(MigrationMode::PreferSymbolNative.should_use_raptorq(None, 0));
        assert!(MigrationMode::PreferSymbolNative.should_use_raptorq(None, 9999));
    }

    // ---- MigrationFeature ----

    #[test]
    fn migration_feature_all_has_six_items() {
        assert_eq!(MigrationFeature::all().count(), 6);
    }

    #[test]
    fn migration_feature_all_roundtrip_via_full_raptorq() {
        let config = configure_migration().full_raptorq().build();
        assert_eq!(config.mode(), MigrationMode::SymbolNativeOnly);
        for feature in MigrationFeature::all() {
            assert!(
                config.is_enabled(feature),
                "full_raptorq should enable {feature:?}"
            );
        }
    }

    // ---- MigrationBuilder ----

    #[test]
    fn migration_builder_with_mode() {
        let config = MigrationBuilder::new()
            .with_mode(MigrationMode::Adaptive)
            .build();
        assert_eq!(config.mode(), MigrationMode::Adaptive);
    }

    #[test]
    fn migration_builder_multiple_overrides() {
        let config = configure_migration()
            .override_operation("op_a", MigrationMode::SymbolNativeOnly)
            .override_operation("op_b", MigrationMode::TraditionalOnly)
            .build();
        assert_eq!(config.mode_for("op_a"), MigrationMode::SymbolNativeOnly);
        assert_eq!(config.mode_for("op_b"), MigrationMode::TraditionalOnly);
        // Fallback to global default
        assert_eq!(config.mode_for("op_c"), MigrationMode::PreferTraditional);
    }

    #[test]
    fn migration_mode_debug_clone_copy_default_eq() {
        let m = MigrationMode::Adaptive;
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Adaptive"), "{dbg}");
        let copied: MigrationMode = m;
        let cloned = m;
        assert_eq!(copied, cloned);
        assert_eq!(MigrationMode::default(), MigrationMode::PreferTraditional);
        assert_ne!(m, MigrationMode::TraditionalOnly);
    }

    #[test]
    fn migration_feature_debug_clone_copy_hash_eq() {
        use std::collections::HashSet;
        let f = MigrationFeature::JoinEncoding;
        let dbg = format!("{f:?}");
        assert!(dbg.contains("JoinEncoding"), "{dbg}");
        let copied: MigrationFeature = f;
        let cloned = f;
        assert_eq!(copied, cloned);

        let mut set = HashSet::new();
        set.insert(MigrationFeature::JoinEncoding);
        set.insert(MigrationFeature::RaceEncoding);
        set.insert(MigrationFeature::DistributedRegions);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn migration_config_debug_clone_default() {
        let c = MigrationConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("MigrationConfig"), "{dbg}");
        let cloned = c;
        assert_eq!(format!("{cloned:?}"), dbg);
    }
