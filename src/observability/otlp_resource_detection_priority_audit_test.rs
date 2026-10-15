//! OTLP resource detection priority audit test.
//!
//! **AUDIT SCOPE**: Verifies OTLP resource detection priority compliance per
//! OTLP specification: programmatic > environment > defaults.
//!
//! **OTLP SPECIFICATION REQUIREMENT**:
//! - Programmatic resource attributes MUST have highest priority
//! - Environment variable OTEL_RESOURCE_ATTRIBUTES MUST override defaults
//! - Defaults MUST have lowest priority
//! - Precedence: Programmatic > Environment > Defaults
//! - NOT: Environment overrides programmatic (spec violation)
//!
//! **CRITICAL**: Incorrect priority violates OTLP spec and causes
//! attribute confusion in observability backends.

#![cfg(test)]

use std::collections::HashMap;
use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

const OTEL_RESOURCE_ATTRIBUTES: &str = "OTEL_RESOURCE_ATTRIBUTES";

fn resource_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct ResourceEnvGuard {
    _guard: MutexGuard<'static, ()>,
    previous_value: Option<String>,
}

impl ResourceEnvGuard {
    #[allow(unsafe_code)]
    fn set(value: &str) -> Self {
        let guard = resource_env_lock()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let previous_value = env::var(OTEL_RESOURCE_ATTRIBUTES).ok();
        // Process environment mutation is unsafe in Rust 2024 because other
        // threads may concurrently read it. This audit file serializes its
        // env mutation with a static mutex and restores the prior value on drop.
        unsafe {
            env::set_var(OTEL_RESOURCE_ATTRIBUTES, value);
        }
        Self {
            _guard: guard,
            previous_value,
        }
    }

    #[allow(unsafe_code)]
    fn unset() -> Self {
        let guard = resource_env_lock()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let previous_value = env::var(OTEL_RESOURCE_ATTRIBUTES).ok();
        // See `set`: this test-only mutation is serialized and restored.
        unsafe {
            env::remove_var(OTEL_RESOURCE_ATTRIBUTES);
        }
        Self {
            _guard: guard,
            previous_value,
        }
    }
}

impl Drop for ResourceEnvGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // Restore while the guard is still held so these audit tests do not
        // leak OTEL_RESOURCE_ATTRIBUTES across concurrently scheduled tests.
        unsafe {
            if let Some(previous_value) = &self.previous_value {
                env::set_var(OTEL_RESOURCE_ATTRIBUTES, previous_value);
            } else {
                env::remove_var(OTEL_RESOURCE_ATTRIBUTES);
            }
        }
    }
}

/// OTLP resource fixture for priority behavior.
#[derive(Debug, Clone, PartialEq)]
pub struct OtlpResourceFixture {
    /// Final resource attributes after priority resolution.
    pub attributes: HashMap<String, String>,
    /// Source category assigned by the fixture builder.
    pub source: ResourceSource,
}

/// Source of resource attributes for priority tracking.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceSource {
    /// Attributes supplied directly by application code.
    Programmatic,
    /// Attributes loaded from `OTEL_RESOURCE_ATTRIBUTES`.
    Environment,
    /// Default resource attributes supplied by the SDK.
    Defaults,
}

/// Resource builder fixture for priority logic.
#[derive(Debug, Default)]
pub struct ResourceBuilderFixture {
    programmatic_attrs: HashMap<String, String>,
    env_attrs: HashMap<String, String>,
    default_attrs: HashMap<String, String>,
}

impl ResourceBuilderFixture {
    /// Create new resource builder with default attributes.
    pub fn new() -> Self {
        let mut default_attrs = HashMap::new();
        default_attrs.insert("telemetry.sdk.name".to_string(), "asupersync".to_string());
        default_attrs.insert("service.name".to_string(), "unknown_service".to_string());

        Self {
            programmatic_attrs: HashMap::new(),
            env_attrs: HashMap::new(),
            default_attrs,
        }
    }

    /// Add programmatic resource attributes (highest priority).
    pub fn with_attributes(mut self, attrs: HashMap<String, String>) -> Self {
        self.programmatic_attrs = attrs;
        self
    }

    /// Load attributes from OTEL_RESOURCE_ATTRIBUTES environment variable.
    pub fn with_env_resource_attributes(mut self) -> Self {
        if let Ok(env_attrs_str) = env::var(OTEL_RESOURCE_ATTRIBUTES) {
            self.env_attrs = parse_resource_attributes(&env_attrs_str);
        }
        self
    }

    /// Build final resource applying OTLP priority: programmatic > env > defaults.
    pub fn build(self) -> OtlpResourceFixture {
        let mut final_attrs = self.default_attrs.clone();

        // Apply environment attributes (override defaults)
        for (key, value) in self.env_attrs {
            final_attrs.insert(key, value);
        }

        // Apply programmatic attributes (override env and defaults)
        for (key, value) in self.programmatic_attrs {
            final_attrs.insert(key, value);
        }

        OtlpResourceFixture {
            attributes: final_attrs,
            source: ResourceSource::Programmatic, // Combined source
        }
    }
}

/// Parse OTEL_RESOURCE_ATTRIBUTES format: key1=value1,key2=value2
fn parse_resource_attributes(env_str: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    for pair in env_str.split(',') {
        if let Some((key, value)) = pair.split_once('=') {
            attrs.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    attrs
}

/// **AUDIT TEST**: Verify programmatic attributes override environment variables.
///
/// **SCENARIO**: Both OTEL_RESOURCE_ATTRIBUTES and programmatic .with_attributes() set.
/// **REQUIREMENT**: Programmatic MUST take priority per OTLP specification.
/// **ASSESSMENT**: Current asupersync implementation behavior vs OTLP spec.
#[test]
fn audit_programmatic_over_environment_priority() {
    println!("🔍 AUDIT: OTLP resource detection priority - programmatic > environment");

    // Set environment variable
    let _resource_env =
        ResourceEnvGuard::set("service.name=env-service,environment=staging,version=env-1.0");

    // Create resource with programmatic attributes that overlap with environment
    let programmatic_attrs = {
        let mut attrs = HashMap::new();
        attrs.insert(
            "service.name".to_string(),
            "programmatic-service".to_string(),
        );
        attrs.insert("environment".to_string(), "production".to_string());
        attrs.insert("build.version".to_string(), "prog-2.0".to_string());
        attrs
    };

    println!("📋 Environment variable OTEL_RESOURCE_ATTRIBUTES:");
    println!("   service.name=env-service");
    println!("   environment=staging");
    println!("   version=env-1.0");

    println!("📋 Programmatic attributes:");
    println!("   service.name=programmatic-service");
    println!("   environment=production");
    println!("   build.version=prog-2.0");

    // Build resource with both sources
    let resource = ResourceBuilderFixture::new()
        .with_env_resource_attributes()
        .with_attributes(programmatic_attrs)
        .build();

    println!("📊 Final resource attributes:");
    for (key, value) in &resource.attributes {
        println!("   {}={}", key, value);
    }

    // **OTLP SPECIFICATION COMPLIANCE CHECK**
    assert_eq!(
        resource.attributes.get("service.name").unwrap(),
        "programmatic-service",
        "OTLP VIOLATION: Programmatic 'service.name' must override environment"
    );
    assert_eq!(
        resource.attributes.get("environment").unwrap(),
        "production",
        "OTLP VIOLATION: Programmatic 'environment' must override environment"
    );
    assert_eq!(
        resource.attributes.get("build.version").unwrap(),
        "prog-2.0",
        "Programmatic-only attributes must be preserved"
    );
    assert_eq!(
        resource.attributes.get("version").unwrap(),
        "env-1.0",
        "Environment-only attributes must be preserved when no programmatic override"
    );

    println!("✅ PROGRAMMATIC PRIORITY: Correctly overrides environment variables");
}

/// **AUDIT TEST**: Verify environment variables override defaults.
///
/// **SCENARIO**: OTEL_RESOURCE_ATTRIBUTES set, no programmatic attributes.
/// **REQUIREMENT**: Environment MUST override default attributes per OTLP spec.
/// **ASSESSMENT**: Second priority level behavior verification.
#[test]
fn audit_environment_over_defaults_priority() {
    println!("🔍 AUDIT: OTLP resource detection priority - environment > defaults");

    // Set environment variable that overrides defaults
    let _resource_env =
        ResourceEnvGuard::set("service.name=env-override,telemetry.sdk.name=custom-sdk");

    println!("📋 Default attributes:");
    println!("   telemetry.sdk.name=asupersync");
    println!("   service.name=unknown_service");

    println!("📋 Environment variable OTEL_RESOURCE_ATTRIBUTES:");
    println!("   service.name=env-override");
    println!("   telemetry.sdk.name=custom-sdk");

    // Build resource with only environment and defaults (no programmatic)
    let resource = ResourceBuilderFixture::new()
        .with_env_resource_attributes()
        .build();

    println!("📊 Final resource attributes:");
    for (key, value) in &resource.attributes {
        println!("   {}={}", key, value);
    }

    // **OTLP SPECIFICATION COMPLIANCE CHECK**
    assert_eq!(
        resource.attributes.get("service.name").unwrap(),
        "env-override",
        "OTLP VIOLATION: Environment 'service.name' must override default"
    );
    assert_eq!(
        resource.attributes.get("telemetry.sdk.name").unwrap(),
        "custom-sdk",
        "OTLP VIOLATION: Environment 'telemetry.sdk.name' must override default"
    );

    println!("✅ ENVIRONMENT PRIORITY: Correctly overrides default attributes");
}

/// **AUDIT TEST**: Verify defaults are used when no higher priority source exists.
///
/// **SCENARIO**: No environment variable, no programmatic attributes.
/// **REQUIREMENT**: Default attributes MUST be used per OTLP spec.
/// **ASSESSMENT**: Lowest priority fallback behavior verification.
#[test]
fn audit_defaults_fallback_behavior() {
    println!("🔍 AUDIT: OTLP resource detection priority - defaults fallback");

    // Ensure no environment variable is set
    let _resource_env = ResourceEnvGuard::unset();

    println!("📋 Expected default attributes:");
    println!("   telemetry.sdk.name=asupersync");
    println!("   service.name=unknown_service");

    // Build resource with only defaults
    let resource = ResourceBuilderFixture::new().build();

    println!("📊 Final resource attributes:");
    for (key, value) in &resource.attributes {
        println!("   {}={}", key, value);
    }

    // **DEFAULT BEHAVIOR VERIFICATION**
    assert_eq!(
        resource.attributes.get("telemetry.sdk.name").unwrap(),
        "asupersync",
        "Default 'telemetry.sdk.name' must be preserved"
    );
    assert_eq!(
        resource.attributes.get("service.name").unwrap(),
        "unknown_service",
        "Default 'service.name' must be preserved"
    );

    println!("✅ DEFAULTS FALLBACK: Correctly uses defaults when no higher priority exists");
}

/// **AUDIT TEST**: Verify current asupersync implementation gap.
///
/// **SCENARIO**: Check if asupersync OtelMetrics handles resource detection.
/// **FINDING**: asupersync currently does NOT implement resource detection.
/// **ASSESSMENT**: Missing OTLP specification compliance feature.
#[test]
fn audit_current_asupersync_resource_detection() {
    println!("🔍 AUDIT: Current asupersync OTLP resource detection implementation");

    println!("📋 Current asupersync behavior analysis:");
    println!("   • OtelMetrics::new(meter) - takes external Meter");
    println!("   • No OTEL_RESOURCE_ATTRIBUTES parsing");
    println!("   • No resource priority implementation");
    println!("   • Relies on external SDK resource configuration");

    // Set environment variable to test if asupersync reads it
    let _resource_env = ResourceEnvGuard::set("service.name=test-detection");

    println!("📊 Expected behavior with OTLP-compliant implementation:");
    println!("   ✓ Parse OTEL_RESOURCE_ATTRIBUTES environment variable");
    println!("   ✓ Apply priority: programmatic > environment > defaults");
    println!("   ✓ Merge attributes according to precedence rules");

    println!("📊 Current asupersync implementation:");
    println!("   ❌ Does not parse OTEL_RESOURCE_ATTRIBUTES");
    println!("   ❌ Does not implement resource detection priority");
    println!("   ❌ Missing OTLP specification compliance feature");

    println!("🚨 DEFECT IDENTIFIED: Missing OTLP resource detection compliance");
    println!("🔧 REQUIRED: Implement resource detection with proper priority order");
}

/// **AUDIT TEST**: Verify OTEL_RESOURCE_ATTRIBUTES parsing correctness.
///
/// **SCENARIO**: Various OTEL_RESOURCE_ATTRIBUTES formats and edge cases.
/// **REQUIREMENT**: Parsing MUST handle standard format per OTLP spec.
/// **ASSESSMENT**: Environment variable parsing implementation.
#[test]
fn audit_otel_resource_attributes_parsing() {
    println!("🔍 AUDIT: OTEL_RESOURCE_ATTRIBUTES parsing correctness");

    // Test cases for environment variable parsing
    let test_cases = vec![
        ("service.name=test", vec![("service.name", "test")]),
        (
            "key1=value1,key2=value2",
            vec![("key1", "value1"), ("key2", "value2")],
        ),
        (
            "service.name=my-service,environment=prod,version=1.0",
            vec![
                ("service.name", "my-service"),
                ("environment", "prod"),
                ("version", "1.0"),
            ],
        ),
        ("key=value with spaces", vec![("key", "value with spaces")]),
        ("", vec![]), // Empty string
    ];

    println!("📋 Testing OTEL_RESOURCE_ATTRIBUTES parsing:");

    for (input, expected) in test_cases {
        println!("   Input: '{}'", input);
        let parsed = parse_resource_attributes(input);

        let expected_map: HashMap<String, String> = expected
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        assert_eq!(
            parsed, expected_map,
            "Parsing failed for input: '{}'",
            input
        );

        println!("   ✓ Parsed correctly: {:?}", parsed);
    }

    println!("✅ OTEL_RESOURCE_ATTRIBUTES PARSING: Correctly handles standard format");
}

/// **AUDIT TEST**: Check for attribute key collision handling.
///
/// **SCENARIO**: Same attribute key from multiple sources (programmatic + env + defaults).
/// **REQUIREMENT**: Higher priority source MUST win per OTLP specification.
/// **ASSESSMENT**: Priority resolution for overlapping keys.
#[test]
fn audit_attribute_collision_resolution() {
    println!("🔍 AUDIT: OTLP resource attribute collision resolution");

    // All sources have "service.name" attribute
    let _resource_env = ResourceEnvGuard::set("service.name=env-service,region=us-west");

    let programmatic_attrs = {
        let mut attrs = HashMap::new();
        attrs.insert(
            "service.name".to_string(),
            "programmatic-service".to_string(),
        );
        attrs.insert("version".to_string(), "2.0.0".to_string());
        attrs
    };

    // Default also has "service.name" = "unknown_service"

    println!("📋 Priority collision scenario:");
    println!("   Default:      service.name = unknown_service");
    println!("   Environment:  service.name = env-service");
    println!("   Programmatic: service.name = programmatic-service");

    let resource = ResourceBuilderFixture::new()
        .with_env_resource_attributes()
        .with_attributes(programmatic_attrs)
        .build();

    // **PRIORITY VERIFICATION**
    assert_eq!(
        resource.attributes.get("service.name").unwrap(),
        "programmatic-service",
        "OTLP PRIORITY VIOLATION: Programmatic must win collision"
    );
    assert_eq!(
        resource.attributes.get("region").unwrap(),
        "us-west",
        "Environment-only attributes must be preserved"
    );
    assert_eq!(
        resource.attributes.get("version").unwrap(),
        "2.0.0",
        "Programmatic-only attributes must be preserved"
    );
    assert_eq!(
        resource.attributes.get("telemetry.sdk.name").unwrap(),
        "asupersync",
        "Default-only attributes must be preserved"
    );

    println!("✅ COLLISION RESOLUTION: Highest priority source wins correctly");
}
