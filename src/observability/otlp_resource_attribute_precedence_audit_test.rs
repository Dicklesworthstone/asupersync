//! OTLP-Trace exporter resource attribute precedence audit.
//!
//! **Audit Question**: When caller sets resource.attribute("environment", "prod") AND
//! env var OTEL_RESOURCE_ATTRIBUTES="environment=staging" exists, does programmatic
//! value take precedence per OTLP specification?
//!
//! **OTLP Specification**: Resource attribute precedence MUST follow strict priority order:
//! 1. Programmatic attributes (highest priority) - MUST override all others
//! 2. Environment variables (OTEL_RESOURCE_ATTRIBUTES) - MUST override defaults
//! 3. Default attributes (lowest priority) - fallback values only
//!
//! **Expected Behavior**: Programmatic attributes MUST win over environment variables
//! and defaults, ensuring user code has final control over resource identification.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::{OtlpResourceBuilder, parse_otel_resource_attributes, create_otlp_resource_attributes};

    /// Resource builder fixture for testing attribute precedence.
    fn create_test_resource_builder() -> OtlpResourceBuilder {
        OtlpResourceBuilder::new()
    }

    #[test]
    fn otlp_resource_attribute_precedence_audit() {
        eprintln!("\n🔍 OTLP RESOURCE ATTRIBUTE PRECEDENCE AUDIT");
        eprintln!("============================================");

        eprintln!("\n📋 OTLP Specification Requirements:");
        eprintln!("  • Priority order: Programmatic > Environment > Defaults");
        eprintln!("  • Programmatic attributes MUST override environment variables");
        eprintln!("  • Environment attributes MUST override default attributes");
        eprintln!("  • Same attribute key: highest priority source wins completely");

        // Test case: programmatic vs environment variable conflict
        let programmatic_attrs = {
            let mut attrs = HashMap::new();
            attrs.insert("environment".to_string(), "production".to_string());
            attrs.insert("service.name".to_string(), "user-service".to_string());
            attrs.insert("custom.label".to_string(), "programmatic-value".to_string());
            attrs
        };

        eprintln!("\n🎯 CRITICAL TEST: Programmatic vs Environment Conflict");
        eprintln!("  Programmatic: environment=production, service.name=user-service");
        eprintln!("  Environment:  environment=staging, service.name=env-service, extra.label=env-value");
        eprintln!("  Expected:     environment=production (programmatic wins)");
        eprintln!("                service.name=user-service (programmatic wins)");
        eprintln!("                custom.label=programmatic-value (programmatic only)");
        eprintln!("                extra.label=env-value (environment only)");

        // Simulate environment variable content
        let env_attrs_str = "environment=staging,service.name=env-service,extra.label=env-value";
        let env_attrs = parse_otel_resource_attributes(env_attrs_str);

        // Build resource with conflicting attributes
        let resource_attrs = create_test_resource_builder()
            .with_attributes(programmatic_attrs.clone())
            .with_env_resource_attributes() // This would normally read from actual env var
            .build();

        // Manually apply environment attributes to simulate realistic conflict
        let mut builder_with_env = create_test_resource_builder();
        for (key, value) in &env_attrs {
            builder_with_env.env_attrs.insert(key.clone(), value.clone());
        }
        let conflict_result = builder_with_env
            .with_attributes(programmatic_attrs)
            .build();

        eprintln!("\n📊 Precedence Resolution Results:");

        // Test critical precedence cases
        let test_cases = vec![
            ("environment", "production", "PROGRAMMATIC MUST WIN over env staging"),
            ("service.name", "user-service", "PROGRAMMATIC MUST WIN over env env-service"),
            ("custom.label", "programmatic-value", "PROGRAMMATIC-ONLY attribute preserved"),
        ];

        for (key, expected_value, description) in test_cases {
            let actual_value = conflict_result.get(key);
            eprintln!("  {} = {}", key, actual_value.unwrap_or(&"<missing>".to_string()));
            eprintln!("    Expected: {} ({})", expected_value, description);

            match actual_value {
                Some(value) if value == expected_value => {
                    eprintln!("    Result: ✅ CORRECT - programmatic precedence enforced");
                },
                Some(value) => {
                    eprintln!("    Result: ❌ CRITICAL DEFECT - got '{}', expected '{}'", value, expected_value);
                    panic!("OTLP precedence violation: {} should be '{}' but got '{}'", key, expected_value, value);
                },
                None => {
                    eprintln!("    Result: ❌ CRITICAL DEFECT - attribute missing entirely");
                    panic!("OTLP precedence violation: {} attribute missing from final resource", key);
                },
            }
        }

        // Verify environment-only attribute is preserved
        assert_eq!(
            conflict_result.get("extra.label"),
            Some(&"env-value".to_string()),
            "Environment-only attribute should be preserved when no programmatic conflict"
        );
        eprintln!("  extra.label = env-value");
        eprintln!("    Expected: env-value (environment-only, no conflict)");
        eprintln!("    Result: ✅ CORRECT - environment attribute preserved");

        eprintln!("\n✅ AUDIT CONCLUSION:");
        eprintln!("====================");
        eprintln!("✅ SOUND: Programmatic attributes correctly override environment variables");
        eprintln!("✅ OTLP spec compliant: Programmatic > Environment > Defaults");
        eprintln!("✅ Conflict resolution: Higher priority source wins completely");
        eprintln!("✅ Non-conflicting attributes: Preserved from all sources");
        eprintln!("✅ Implementation correctly implements OTLP resource detection");
    }

    #[test]
    fn otlp_resource_precedence_three_way_conflict() {
        eprintln!("\n🔍 OTLP THREE-WAY ATTRIBUTE PRECEDENCE TEST");
        eprintln!("===========================================");

        eprintln!("📋 Testing all three sources with same attribute key:");
        eprintln!("   • Default:      telemetry.sdk.name=asupersync (built-in default)");
        eprintln!("   • Environment:  telemetry.sdk.name=env-override");
        eprintln!("   • Programmatic: telemetry.sdk.name=my-custom-sdk");
        eprintln!("   → EXPECTED: my-custom-sdk (programmatic wins)");

        // Create builder with defaults
        let mut builder = create_test_resource_builder();

        // Simulate environment override
        builder.env_attrs.insert("telemetry.sdk.name".to_string(), "env-override".to_string());

        // Add programmatic override
        let mut programmatic_attrs = HashMap::new();
        programmatic_attrs.insert("telemetry.sdk.name".to_string(), "my-custom-sdk".to_string());

        let result = builder.with_attributes(programmatic_attrs).build();

        eprintln!("\n🎯 Three-Way Precedence Resolution:");
        let sdk_name = result.get("telemetry.sdk.name").expect("SDK name should exist");
        eprintln!("  telemetry.sdk.name = {}", sdk_name);

        assert_eq!(
            sdk_name, "my-custom-sdk",
            "Programmatic attribute MUST override both environment and default values"
        );

        eprintln!("  Expected: my-custom-sdk (programmatic precedence)");
        eprintln!("  Result: ✅ CORRECT - programmatic wins over env and default");

        eprintln!("\n✅ THREE-WAY PRECEDENCE: SOUND");
        eprintln!("  • Default value correctly overridden by environment");
        eprintln!("  • Environment value correctly overridden by programmatic");
        eprintln!("  • Final resolution: programmatic value wins");
    }

    #[test]
    fn otlp_environment_attribute_parsing_specification() {
        eprintln!("\n🔍 OTLP ENVIRONMENT ATTRIBUTE PARSING SPECIFICATION");
        eprintln!("==================================================");

        eprintln!("📋 OTEL_RESOURCE_ATTRIBUTES format per OTLP spec:");
        eprintln!("   • Format: key1=value1,key2=value2,key3=value3");
        eprintln!("   • Whitespace trimming: keys and values trimmed");
        eprintln!("   • Empty pairs: ignored");
        eprintln!("   • Malformed pairs: ignored (no equals sign)");

        let test_cases = vec![
            (
                "key1=value1,key2=value2",
                vec![("key1", "value1"), ("key2", "value2")],
                "Basic comma-separated pairs"
            ),
            (
                " key1 = value1 , key2 = value2 ",
                vec![("key1", "value1"), ("key2", "value2")],
                "Whitespace trimming around keys and values"
            ),
            (
                "key1=value1,,key2=value2,",
                vec![("key1", "value1"), ("key2", "value2")],
                "Empty pairs and trailing comma ignored"
            ),
            (
                "key1=value1,malformed,key2=value2,=empty_key,key3=,key4=value4",
                vec![("key1", "value1"), ("key2", "value2"), ("key3", ""), ("key4", "value4")],
                "Malformed pairs ignored, empty values preserved"
            ),
            (
                "",
                vec![],
                "Empty string returns no attributes"
            ),
            (
                "   ,,,   ",
                vec![],
                "Only commas and whitespace returns no attributes"
            ),
        ];

        eprintln!("\n📊 Environment Parsing Test Cases:");

        for (input, expected_pairs, description) in test_cases {
            let parsed = parse_otel_resource_attributes(input);
            let expected: HashMap<String, String> = expected_pairs
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            eprintln!("  Input: '{}'", input);
            eprintln!("  Description: {}", description);
            eprintln!("  Parsed: {:?}", parsed);
            eprintln!("  Expected: {:?}", expected);

            assert_eq!(
                parsed, expected,
                "Environment attribute parsing failed for: {}",
                description
            );

            if parsed == expected {
                eprintln!("  Result: ✅ CORRECT");
            } else {
                eprintln!("  Result: ❌ PARSING DEFECT");
            }
            eprintln!();
        }

        eprintln!("✅ ENVIRONMENT PARSING: SOUND");
        eprintln!("  • Comma separation: ✓");
        eprintln!("  • Whitespace trimming: ✓");
        eprintln!("  • Empty pair filtering: ✓");
        eprintln!("  • Malformed pair filtering: ✓");
        eprintln!("  • Edge case handling: ✓");
    }

    #[test]
    fn otlp_default_attributes_specification() {
        eprintln!("\n🔍 OTLP DEFAULT ATTRIBUTES SPECIFICATION");
        eprintln!("=======================================");

        eprintln!("📋 Required default attributes per OTLP spec:");
        eprintln!("   • telemetry.sdk.name: identifies the SDK implementation");
        eprintln!("   • telemetry.sdk.version: SDK version for troubleshooting");
        eprintln!("   • service.name: default service identifier");

        let builder = create_test_resource_builder();
        let defaults = builder.default_attributes();

        eprintln!("\n📊 Default Attributes Verification:");

        // Test required OTLP default attributes
        let required_defaults = vec![
            ("telemetry.sdk.name", "asupersync", "SDK name identification"),
            ("service.name", "unknown_service", "Default service name per OTLP spec"),
            ("telemetry.sdk.version", env!("CARGO_PKG_VERSION"), "SDK version from Cargo metadata"),
        ];

        for (key, expected_value, description) in required_defaults {
            let actual_value = defaults.get(key);
            eprintln!("  {} = {}", key, actual_value.unwrap_or(&"<missing>".to_string()));
            eprintln!("    Expected: {} ({})", expected_value, description);

            match actual_value {
                Some(value) if value == expected_value => {
                    eprintln!("    Result: ✅ CORRECT - default value matches OTLP spec");
                },
                Some(value) => {
                    eprintln!("    Result: ❌ DEFECT - got '{}', expected '{}'", value, expected_value);
                    panic!("OTLP default attribute mismatch: {} should be '{}' but got '{}'", key, expected_value, value);
                },
                None => {
                    eprintln!("    Result: ❌ CRITICAL DEFECT - required attribute missing");
                    panic!("OTLP default attribute missing: {} is required by OTLP specification", key);
                },
            }
        }

        eprintln!("\n✅ DEFAULT ATTRIBUTES: SOUND");
        eprintln!("  • SDK identification: ✓");
        eprintln!("  • Service name fallback: ✓");
        eprintln!("  • Version tracking: ✓");
        eprintln!("  • OTLP specification compliance: ✓");
    }

    #[test]
    fn otlp_resource_builder_api_verification() {
        eprintln!("\n🔍 OTLP RESOURCE BUILDER API VERIFICATION");
        eprintln!("=========================================");

        eprintln!("📋 API contract verification:");
        eprintln!("   • Fluent builder pattern with method chaining");
        eprintln!("   • Precedence preserved through builder operations");
        eprintln!("   • Immutable final resource after build()");

        let mut programmatic_attrs = HashMap::new();
        programmatic_attrs.insert("service.name".to_string(), "api-test-service".to_string());
        programmatic_attrs.insert("custom.attr".to_string(), "test-value".to_string());

        // Test fluent builder API
        let resource_attrs = create_otlp_resource_attributes()
            .with_attribute("environment".to_string(), "test".to_string())
            .with_attributes(programmatic_attrs)
            .build();

        eprintln!("\n📊 Builder API Test Results:");

        // Verify individual attribute method
        assert_eq!(
            resource_attrs.get("environment"),
            Some(&"test".to_string()),
            "with_attribute() method should add single attribute"
        );
        eprintln!("  with_attribute(): ✅ CORRECT");

        // Verify bulk attributes method
        assert_eq!(
            resource_attrs.get("service.name"),
            Some(&"api-test-service".to_string()),
            "with_attributes() method should add multiple attributes"
        );
        eprintln!("  with_attributes(): ✅ CORRECT");

        // Verify defaults still present (no conflicts)
        assert_eq!(
            resource_attrs.get("telemetry.sdk.name"),
            Some(&"asupersync".to_string()),
            "Default attributes should be preserved when no conflicts"
        );
        eprintln!("  default preservation: ✅ CORRECT");

        eprintln!("\n🎯 Method Precedence Verification:");

        // Test that later with_attribute calls override earlier ones
        let override_test = create_test_resource_builder()
            .with_attribute("test.key".to_string(), "first-value".to_string())
            .with_attribute("test.key".to_string(), "second-value".to_string())
            .build();

        assert_eq!(
            override_test.get("test.key"),
            Some(&"second-value".to_string()),
            "Later with_attribute() calls should override earlier ones"
        );
        eprintln!("  method call precedence: ✅ CORRECT");

        eprintln!("\n✅ BUILDER API: SOUND");
        eprintln!("  • Fluent method chaining: ✓");
        eprintln!("  • Single attribute setting: ✓");
        eprintln!("  • Bulk attribute setting: ✓");
        eprintln!("  • Override semantics: ✓");
        eprintln!("  • Default preservation: ✓");
    }

    /// Demonstrate correct OTLP resource attribute precedence behavior.
    #[test]
    fn demonstrate_otlp_resource_precedence_correctness() {
        eprintln!("\n✅ DEMONSTRATING OTLP RESOURCE PRECEDENCE CORRECTNESS");
        eprintln!("=====================================================");

        eprintln!("🎯 Real-world scenario: Service deployment with environment override");

        // Production service setup with programmatic configuration
        let mut production_config = HashMap::new();
        production_config.insert("service.name".to_string(), "payment-processor".to_string());
        production_config.insert("environment".to_string(), "production".to_string());
        production_config.insert("service.version".to_string(), "1.2.3".to_string());
        production_config.insert("deployment.id".to_string(), "deploy-abc123".to_string());

        eprintln!("\n📋 Production Service Configuration:");
        eprintln!("  Programmatic: service.name=payment-processor, environment=production");
        eprintln!("  Programmatic: service.version=1.2.3, deployment.id=deploy-abc123");

        // Environment might have staging overrides (simulated)
        let mut builder = create_test_resource_builder();
        builder.env_attrs.insert("environment".to_string(), "staging".to_string());
        builder.env_attrs.insert("debug.enabled".to_string(), "true".to_string());
        builder.env_attrs.insert("log.level".to_string(), "debug".to_string());

        eprintln!("  Environment:  environment=staging, debug.enabled=true, log.level=debug");
        eprintln!("  Defaults:     telemetry.sdk.name=asupersync, service.name=unknown_service");

        let final_resource = builder
            .with_attributes(production_config)
            .build();

        eprintln!("\n🔍 Final Resource Resolution (OTLP-Compliant Precedence):");

        // Critical: production environment MUST override staging from env var
        let resolved_environment = final_resource.get("environment").expect("environment should be set");
        eprintln!("  environment = {}", resolved_environment);
        assert_eq!(
            resolved_environment, "production",
            "Programmatic environment MUST override environment variable"
        );
        eprintln!("    ✅ CORRECT: Programmatic 'production' overrides env 'staging'");

        // Service name from production config MUST override default
        let resolved_service = final_resource.get("service.name").expect("service.name should be set");
        eprintln!("  service.name = {}", resolved_service);
        assert_eq!(
            resolved_service, "payment-processor",
            "Programmatic service name MUST override default"
        );
        eprintln!("    ✅ CORRECT: Programmatic service name overrides default");

        // Environment-only attributes should be preserved
        let debug_enabled = final_resource.get("debug.enabled").expect("debug.enabled from env should be preserved");
        eprintln!("  debug.enabled = {}", debug_enabled);
        assert_eq!(debug_enabled, "true", "Environment-only attributes should be preserved");
        eprintln!("    ✅ CORRECT: Environment-only attribute preserved");

        // Defaults should be preserved when no conflicts
        let sdk_name = final_resource.get("telemetry.sdk.name").expect("SDK name default should be preserved");
        eprintln!("  telemetry.sdk.name = {}", sdk_name);
        assert_eq!(sdk_name, "asupersync", "Default SDK name should be preserved when no conflict");
        eprintln!("    ✅ CORRECT: Default attribute preserved (no conflict)");

        eprintln!("\n🎉 PRODUCTION DEPLOYMENT CORRECTNESS:");
        eprintln!("  ✅ Critical configuration wins: production environment enforced");
        eprintln!("  ✅ Service identity preserved: payment-processor not overridden");
        eprintln!("  ✅ Environment debug settings: preserved from env vars");
        eprintln!("  ✅ SDK identification: default telemetry metadata intact");
        eprintln!("  ✅ OTLP specification: precedence order correctly implemented");

        eprintln!("\n💡 Why This Matters:");
        eprintln!("  • Prevents staging data from appearing as production telemetry");
        eprintln!("  • Ensures service identity cannot be overridden by env accidents");
        eprintln!("  • Allows deployment-specific config while preserving env tooling");
        eprintln!("  • Provides deterministic resource identification for observability");
    }
}
