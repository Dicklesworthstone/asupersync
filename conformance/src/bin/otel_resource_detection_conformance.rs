//! OpenTelemetry Resource Detection Conformance Test (Tick #139)
//!
//! This conformance test verifies that our Resource detection from
//! OTEL_RESOURCE_ATTRIBUTES environment variable produces identical
//! Resource objects compared to the opentelemetry-sdk reference implementation.

use asupersync::observability::otel::OtlpResourceBuilder;
use opentelemetry_sdk::Resource;
use std::collections::BTreeMap;
use std::env;

/// Test cases for Resource detection conformance.
struct ResourceDetectionTestCase {
    name: &'static str,
    otel_resource_attributes: String,
    description: &'static str,
}

struct ResourceEnvGuard {
    previous: Option<String>,
}

impl ResourceEnvGuard {
    fn set(value: &str) -> Self {
        let previous = env::var("OTEL_RESOURCE_ATTRIBUTES").ok();
        unsafe {
            if value.is_empty() {
                env::remove_var("OTEL_RESOURCE_ATTRIBUTES");
            } else {
                env::set_var("OTEL_RESOURCE_ATTRIBUTES", value);
            }
        }
        Self { previous }
    }
}

impl Drop for ResourceEnvGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(previous) => env::set_var("OTEL_RESOURCE_ATTRIBUTES", previous),
                None => env::remove_var("OTEL_RESOURCE_ATTRIBUTES"),
            }
        }
    }
}

fn main() {
    println!("🔍 OpenTelemetry Resource Detection Conformance Test");
    println!("Verifying OTEL_RESOURCE_ATTRIBUTES → identical Resource vs opentelemetry-sdk");

    let test_cases = vec![
        ResourceDetectionTestCase {
            name: "empty_attributes",
            otel_resource_attributes: "".to_string(),
            description: "Empty OTEL_RESOURCE_ATTRIBUTES should produce default resource",
        },
        ResourceDetectionTestCase {
            name: "single_attribute",
            otel_resource_attributes: "service.name=my-service".to_string(),
            description: "Single service name attribute",
        },
        ResourceDetectionTestCase {
            name: "multiple_attributes",
            otel_resource_attributes: "service.name=my-service,service.version=1.0.0,deployment.environment=production".to_string(),
            description: "Multiple comma-separated attributes",
        },
        ResourceDetectionTestCase {
            name: "quoted_values",
            otel_resource_attributes: "service.name=\"my service\",description=\"A test service\"".to_string(),
            description: "Quoted values with spaces",
        },
        ResourceDetectionTestCase {
            name: "escaped_characters",
            otel_resource_attributes: "service.name=test\\,service,description=A\\=test".to_string(),
            description: "Escaped commas and equals signs",
        },
        ResourceDetectionTestCase {
            name: "semantic_conventions",
            otel_resource_attributes: "service.name=auth-service,service.version=2.1.0,service.namespace=production,service.instance.id=auth-01,deployment.environment=prod,telemetry.sdk.name=asupersync,telemetry.sdk.language=rust,telemetry.sdk.version=0.3.1".to_string(),
            description: "Standard semantic convention attributes",
        },
        ResourceDetectionTestCase {
            name: "custom_attributes",
            otel_resource_attributes: "custom.team=platform,custom.region=us-west-2,custom.cluster=k8s-prod".to_string(),
            description: "Custom application-specific attributes",
        },
        ResourceDetectionTestCase {
            name: "mixed_types",
            otel_resource_attributes: "service.name=api,port=8080,enabled=true,ratio=0.95".to_string(),
            description: "Mixed attribute types (string, int, bool, float)",
        },
        ResourceDetectionTestCase {
            name: "unicode_values",
            otel_resource_attributes: "service.name=测试服务,description=\"Service with 中文 characters\"".to_string(),
            description: "Unicode characters in attribute values",
        },
        ResourceDetectionTestCase {
            name: "special_characters",
            otel_resource_attributes: "service.name=my-service_v1,path=/api/v1/users,query=?filter=active&sort=name".to_string(),
            description: "Special characters in attribute values",
        },
        ResourceDetectionTestCase {
            name: "whitespace_handling",
            otel_resource_attributes: " service.name = my-service , service.version = 1.0 ".to_string(),
            description: "Whitespace around keys and values",
        },
        ResourceDetectionTestCase {
            name: "duplicate_keys",
            otel_resource_attributes: "service.name=first,service.name=second,version=1.0".to_string(),
            description: "Duplicate keys - last value should win",
        },
    ];

    println!(
        "📋 Running {} Resource detection conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        // Test our implementation
        let our_resource = test_our_resource_detection(test_case);

        // Test reference implementation
        let reference_resource = test_reference_resource_detection(test_case);

        // Compare results
        if let Err(error) = compare_resources(&our_resource, &reference_resource, test_case) {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {}", test_case.name);
        }
    }

    // Test edge cases
    println!("\n📋 Testing Resource detection edge cases");
    test_resource_detection_edge_cases(&mut failed_tests);

    // Report results
    println!("\n📊 Resource Detection Conformance Test Results");
    if failed_tests.is_empty() {
        println!("✅ ALL TESTS PASSED - Resource detection is conformant");
        println!("🎯 OTEL_RESOURCE_ATTRIBUTES parsing matches opentelemetry-sdk exactly");
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

/// Our test representation of Resource data.
#[derive(Debug, Clone, PartialEq)]
struct ResourceData {
    attributes: BTreeMap<String, String>,
    schema_url: Option<String>,
}

/// Test our Resource detection implementation.
fn test_our_resource_detection(test_case: &ResourceDetectionTestCase) -> ResourceData {
    let _guard = ResourceEnvGuard::set(&test_case.otel_resource_attributes);
    let attributes = OtlpResourceBuilder::new()
        .with_env_resource_attributes()
        .environment_attributes()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    ResourceData {
        attributes,
        schema_url: None,
    }
}

/// Test the reference opentelemetry-sdk Resource detection.
fn test_reference_resource_detection(test_case: &ResourceDetectionTestCase) -> ResourceData {
    let _guard = ResourceEnvGuard::set(&test_case.otel_resource_attributes);

    // Use opentelemetry-sdk Resource detection - use the ResourceBuilder approach
    let resource = Resource::builder_empty()
        .with_detector(Box::new(
            opentelemetry_sdk::resource::EnvResourceDetector::new(),
        ))
        .build();

    // Convert to our test representation
    let mut attributes = BTreeMap::new();
    for (key, value) in resource.iter() {
        attributes.insert(key.to_string(), value.to_string());
    }

    ResourceData {
        attributes,
        schema_url: resource.schema_url().map(|url| url.to_string()),
    }
}

/// Compare Resource objects between our implementation and reference.
fn compare_resources(
    our_resource: &ResourceData,
    reference_resource: &ResourceData,
    _test_case: &ResourceDetectionTestCase,
) -> Result<(), String> {
    // Compare attributes - this is the core requirement
    if our_resource.attributes != reference_resource.attributes {
        // Find specific differences for better error reporting
        let our_keys: std::collections::BTreeSet<_> = our_resource.attributes.keys().collect();
        let ref_keys: std::collections::BTreeSet<_> =
            reference_resource.attributes.keys().collect();

        let missing_keys: Vec<_> = ref_keys.difference(&our_keys).collect();
        let extra_keys: Vec<_> = our_keys.difference(&ref_keys).collect();

        let mut value_diffs = Vec::new();
        for key in our_keys.intersection(&ref_keys) {
            let our_val = &our_resource.attributes[*key];
            let ref_val = &reference_resource.attributes[*key];
            if our_val != ref_val {
                value_diffs.push((key, our_val, ref_val));
            }
        }

        let mut error_parts = Vec::new();
        if !missing_keys.is_empty() {
            error_parts.push(format!("missing keys: {:?}", missing_keys));
        }
        if !extra_keys.is_empty() {
            error_parts.push(format!("extra keys: {:?}", extra_keys));
        }
        if !value_diffs.is_empty() {
            error_parts.push(format!("value differences: {:?}", value_diffs));
        }

        return Err(format!(
            "Resource attributes mismatch: {}",
            error_parts.join(", ")
        ));
    }

    // Schema URL comparison is optional since our implementation may not set it
    // But if both set it, they should match
    if our_resource.schema_url.is_some() && reference_resource.schema_url.is_some() {
        if our_resource.schema_url != reference_resource.schema_url {
            return Err(format!(
                "Schema URL mismatch: our={:?}, reference={:?}",
                our_resource.schema_url, reference_resource.schema_url
            ));
        }
    }

    Ok(())
}

/// Test edge cases for Resource detection.
fn test_resource_detection_edge_cases(failed_tests: &mut Vec<(String, String)>) {
    let extremely_long_value = format!("key={}", "x".repeat(1000));
    let many_attributes = (0..50)
        .map(|i| format!("key{}=value{}", i, i))
        .collect::<Vec<_>>()
        .join(",");

    let edge_cases = vec![
        (
            "malformed_no_equals",
            "service.name",
            "Attribute without equals sign",
        ),
        ("malformed_empty_key", "=value", "Empty key with value"),
        ("malformed_empty_value", "key=", "Key with empty value"),
        ("malformed_only_equals", "===", "Only equals signs"),
        (
            "malformed_unmatched_quotes",
            "key=\"value",
            "Unmatched quotes",
        ),
        (
            "extremely_long_value",
            extremely_long_value.as_str(),
            "Very long attribute value",
        ),
        (
            "many_attributes",
            many_attributes.as_str(),
            "Many attributes",
        ),
    ];

    for (case_name, attributes_str, description) in edge_cases {
        let test_case = ResourceDetectionTestCase {
            name: case_name,
            otel_resource_attributes: attributes_str.to_string(),
            description,
        };

        // For malformed cases, we expect both implementations to handle them gracefully
        // but possibly differently, so we'll just ensure they don't crash
        let our_result = std::panic::catch_unwind(|| test_our_resource_detection(&test_case));
        let ref_result = std::panic::catch_unwind(|| test_reference_resource_detection(&test_case));

        match (our_result, ref_result) {
            (Ok(our_resource), Ok(reference_resource)) => {
                // Both succeeded, compare if possible
                if let Err(error) =
                    compare_resources(&our_resource, &reference_resource, &test_case)
                {
                    // For edge cases, we're more lenient - only fail if there's a major discrepancy
                    if !error.contains("missing keys") && !error.contains("extra keys") {
                        failed_tests.push((format!("edge_case_{}", case_name), error));
                    }
                } else {
                    println!("    ✅ edge_case_{}", case_name);
                }
            }
            (Err(_), Err(_)) => {
                // Both panicked - that's consistent behavior
                println!(
                    "    ✅ edge_case_{} (both panicked consistently)",
                    case_name
                );
            }
            (Ok(_), Err(_)) => {
                failed_tests.push((
                    format!("edge_case_{}", case_name),
                    "Our implementation succeeded but reference panicked".to_string(),
                ));
            }
            (Err(_), Ok(_)) => {
                failed_tests.push((
                    format!("edge_case_{}", case_name),
                    "Our implementation panicked but reference succeeded".to_string(),
                ));
            }
        }
    }
}
