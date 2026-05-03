#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

// Maximum bounds to prevent OOM during fuzzing
const MAX_ATTRIBUTES_PER_RESOURCE: usize = 50;
const MAX_RESOURCES_TO_MERGE: usize = 10;
const MAX_KEY_LENGTH: usize = 100;
const MAX_VALUE_LENGTH: usize = 200;

/// Arbitrary Resource with attributes for fuzzing.
#[derive(Arbitrary, Debug, Clone)]
struct FuzzResource {
    attributes: Vec<FuzzAttribute>,
}

/// Arbitrary attribute for Resource.
#[derive(Arbitrary, Debug, Clone, PartialEq)]
struct FuzzAttribute {
    key: String,
    value: String,
}

/// Sequence of Resources to merge for fuzzing.
#[derive(Arbitrary, Debug)]
struct FuzzResourceMergeInput {
    resources: Vec<FuzzResource>,
}

/// Resource with normalized attributes.
#[derive(Debug, Clone, PartialEq)]
struct NormalizedResource {
    attributes: HashMap<String, String>,
}

impl FuzzResource {
    /// Convert to normalized resource for testing.
    fn to_normalized(&self) -> NormalizedResource {
        let mut attributes = HashMap::new();

        for attr in &self.attributes {
            // Sanitize key and value to prevent issues
            let sanitized_key = sanitize_string(&attr.key, MAX_KEY_LENGTH);
            let sanitized_value = sanitize_string(&attr.value, MAX_VALUE_LENGTH);

            if !sanitized_key.is_empty() {
                attributes.insert(sanitized_key, sanitized_value);
            }
        }

        NormalizedResource { attributes }
    }
}

impl NormalizedResource {
    /// Create a new empty resource.
    fn new() -> Self {
        Self {
            attributes: HashMap::new(),
        }
    }

    /// Merge another resource into this one using last-wins semantics.
    /// Returns a new resource with merged attributes.
    fn merge(&self, other: &NormalizedResource) -> NormalizedResource {
        let mut merged_attributes = self.attributes.clone();

        // Last-wins: overlay other's attributes on top of ours
        for (key, value) in &other.attributes {
            merged_attributes.insert(key.clone(), value.clone());
        }

        NormalizedResource {
            attributes: merged_attributes,
        }
    }

    /// Merge multiple resources in sequence (left-to-right).
    fn merge_sequence(resources: &[NormalizedResource]) -> NormalizedResource {
        let mut result = NormalizedResource::new();

        for resource in resources {
            result = result.merge(resource);
        }

        result
    }

    /// Get the number of attributes.
    fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    /// Check if this resource contains a specific attribute.
    fn has_attribute(&self, key: &str) -> bool {
        self.attributes.contains_key(key)
    }

    /// Get the value of a specific attribute.
    fn get_attribute(&self, key: &str) -> Option<&String> {
        self.attributes.get(key)
    }
}

/// Sanitize a string for use as an attribute key or value.
fn sanitize_string(input: &str, max_length: usize) -> String {
    // Remove control characters and limit length
    let sanitized: String = input
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .take(max_length)
        .collect();

    sanitized
}

/// Test associativity property: (A ∪ B) ∪ C = A ∪ (B ∪ C)
fn test_associativity(
    a: &NormalizedResource,
    b: &NormalizedResource,
    c: &NormalizedResource,
) -> Result<(), String> {
    // Left-associative: (A ∪ B) ∪ C
    let ab = a.merge(b);
    let left_result = ab.merge(c);

    // Right-associative: A ∪ (B ∪ C)
    let bc = b.merge(c);
    let right_result = a.merge(&bc);

    if left_result != right_result {
        return Err(format!(
            "Associativity violation: (A ∪ B) ∪ C ≠ A ∪ (B ∪ C)\n\
             Left result: {:?}\n\
             Right result: {:?}\n\
             A: {:?}\n\
             B: {:?}\n\
             C: {:?}",
            left_result.attributes,
            right_result.attributes,
            a.attributes,
            b.attributes,
            c.attributes
        ));
    }

    Ok(())
}

/// Test last-wins conflict resolution: if same key appears in multiple resources,
/// the value from the rightmost (last) resource should win.
fn test_last_wins_conflict_resolution(resources: &[NormalizedResource]) -> Result<(), String> {
    if resources.len() < 2 {
        return Ok(()); // Need at least 2 resources for conflicts
    }

    let merged = NormalizedResource::merge_sequence(resources);

    // For each attribute in the merged result, verify it came from the rightmost source
    for (key, merged_value) in &merged.attributes {
        // Find the rightmost resource that has this key
        let mut rightmost_value = None;
        for resource in resources.iter().rev() {
            if let Some(value) = resource.get_attribute(key) {
                rightmost_value = Some(value);
                break;
            }
        }

        match rightmost_value {
            Some(expected_value) => {
                if merged_value != expected_value {
                    return Err(format!(
                        "Last-wins violation for key '{}': expected '{}', got '{}'\n\
                         Resources: {:?}",
                        key,
                        expected_value,
                        merged_value,
                        resources.iter().map(|r| &r.attributes).collect::<Vec<_>>()
                    ));
                }
            }
            None => {
                return Err(format!(
                    "Merged result contains key '{}' = '{}' but no source resource has it\n\
                     Resources: {:?}",
                    key,
                    merged_value,
                    resources.iter().map(|r| &r.attributes).collect::<Vec<_>>()
                ));
            }
        }
    }

    Ok(())
}

/// Test that merge preserves all attributes that don't conflict.
fn test_attribute_preservation(resources: &[NormalizedResource]) -> Result<(), String> {
    let merged = NormalizedResource::merge_sequence(resources);

    // Check that every unique key appears in the merged result
    let mut all_keys = std::collections::HashSet::new();
    for resource in resources {
        all_keys.extend(resource.attributes.keys());
    }

    for key in &all_keys {
        if !merged.has_attribute(key) {
            return Err(format!(
                "Attribute preservation violation: key '{}' missing from merged result\n\
                 Merged: {:?}\n\
                 Resources: {:?}",
                key,
                merged.attributes,
                resources.iter().map(|r| &r.attributes).collect::<Vec<_>>()
            ));
        }
    }

    Ok(())
}

/// Test that empty resource merging works correctly.
fn test_empty_resource_merging(resource: &NormalizedResource) -> Result<(), String> {
    let empty = NormalizedResource::new();

    // Empty ∪ Resource = Resource
    let empty_merged = empty.merge(resource);
    if empty_merged != *resource {
        return Err(format!(
            "Empty merge violation: empty ∪ resource ≠ resource\n\
             Expected: {:?}\n\
             Got: {:?}",
            resource.attributes, empty_merged.attributes
        ));
    }

    // Resource ∪ Empty = Resource
    let resource_merged = resource.merge(&empty);
    if resource_merged != *resource {
        return Err(format!(
            "Resource merge with empty violation: resource ∪ empty ≠ resource\n\
             Expected: {:?}\n\
             Got: {:?}",
            resource.attributes, resource_merged.attributes
        ));
    }

    Ok(())
}

/// Test idempotency: Resource ∪ Resource = Resource (when no conflicts exist).
fn test_idempotency(resource: &NormalizedResource) -> Result<(), String> {
    let self_merged = resource.merge(resource);

    if self_merged != *resource {
        return Err(format!(
            "Idempotency violation: resource ∪ resource ≠ resource\n\
             Expected: {:?}\n\
             Got: {:?}",
            resource.attributes, self_merged.attributes
        ));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent excessive memory usage
    if data.len() > 5_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let fuzz_input = match FuzzResourceMergeInput::arbitrary(&mut unstructured) {
        Ok(input) => input,
        Err(_) => return, // Not enough data to generate arbitrary input
    };

    // Limit the number of resources and attributes to prevent OOM
    let limited_resources: Vec<_> = fuzz_input
        .resources
        .into_iter()
        .take(MAX_RESOURCES_TO_MERGE)
        .map(|mut resource| {
            resource.attributes.truncate(MAX_ATTRIBUTES_PER_RESOURCE);
            resource
        })
        .collect();

    if limited_resources.is_empty() {
        return; // Need at least one resource
    }

    // Convert to normalized resources
    let normalized_resources: Vec<_> = limited_resources
        .iter()
        .map(|r| r.to_normalized())
        .collect();

    // Test 1: Associativity property
    if normalized_resources.len() >= 3 {
        for i in 0..normalized_resources.len().saturating_sub(2) {
            let a = &normalized_resources[i];
            let b = &normalized_resources[i + 1];
            let c = &normalized_resources[i + 2];

            if let Err(e) = test_associativity(a, b, c) {
                panic!("Associativity test failed: {}", e);
            }
        }
    }

    // Test 2: Last-wins conflict resolution
    if let Err(e) = test_last_wins_conflict_resolution(&normalized_resources) {
        panic!("Last-wins conflict resolution test failed: {}", e);
    }

    // Test 3: Attribute preservation
    if let Err(e) = test_attribute_preservation(&normalized_resources) {
        panic!("Attribute preservation test failed: {}", e);
    }

    // Test 4: Empty resource merging
    for resource in &normalized_resources {
        if let Err(e) = test_empty_resource_merging(resource) {
            panic!("Empty resource merging test failed: {}", e);
        }
    }

    // Test 5: Idempotency
    for resource in &normalized_resources {
        if let Err(e) = test_idempotency(resource) {
            panic!("Idempotency test failed: {}", e);
        }
    }

    // Test 6: Verify sequence merge produces expected result count
    let merged = NormalizedResource::merge_sequence(&normalized_resources);

    // Collect all unique keys
    let mut expected_keys = std::collections::HashSet::new();
    for resource in &normalized_resources {
        expected_keys.extend(resource.attributes.keys());
    }

    if merged.attribute_count() != expected_keys.len() {
        panic!(
            "Merged resource attribute count mismatch: expected {}, got {}\n\
             Expected keys: {:?}\n\
             Merged attributes: {:?}",
            expected_keys.len(),
            merged.attribute_count(),
            expected_keys,
            merged.attributes
        );
    }

    // Test 7: Specific conflict scenarios
    if normalized_resources.len() >= 2 {
        // Test that later resources override earlier ones for same keys
        let first = &normalized_resources[0];
        let last = &normalized_resources[normalized_resources.len() - 1];

        for (key, last_value) in &last.attributes {
            let merged = NormalizedResource::merge_sequence(&normalized_resources);

            if let Some(merged_value) = merged.get_attribute(key) {
                if merged_value != last_value {
                    panic!(
                        "Last-wins enforcement failed: key '{}' should have value '{}' but got '{}'\n\
                         Last resource: {:?}",
                        key, last_value, merged_value, last.attributes
                    );
                }
            }
        }
    }

    // Test 8: Verify that merging with different orderings produces different results
    // when conflicts exist (demonstrates last-wins behavior)
    if normalized_resources.len() >= 2 {
        let forward = NormalizedResource::merge_sequence(&normalized_resources);
        let mut reversed = normalized_resources.clone();
        reversed.reverse();
        let backward = NormalizedResource::merge_sequence(&reversed);

        // Find conflicts (same keys in multiple resources)
        let mut has_conflicts = false;
        let mut all_keys = std::collections::HashSet::new();
        let mut key_counts = std::collections::HashMap::new();

        for resource in &normalized_resources {
            for key in resource.attributes.keys() {
                *key_counts.entry(key.clone()).or_insert(0) += 1;
                if key_counts[key] > 1 {
                    has_conflicts = true;
                }
                all_keys.insert(key.clone());
            }
        }

        // If there are conflicts, the forward and backward merge should potentially differ
        if has_conflicts {
            // This is expected - just verify both are valid according to their respective orderings
            for key in &all_keys {
                // Verify forward result uses rightmost value
                if let Some(forward_value) = forward.get_attribute(key) {
                    // Find rightmost value in original order
                    for resource in normalized_resources.iter().rev() {
                        if let Some(expected) = resource.get_attribute(key) {
                            if forward_value != expected {
                                panic!(
                                    "Forward merge last-wins violation for key '{}': expected '{}', got '{}'",
                                    key, expected, forward_value
                                );
                            }
                            break;
                        }
                    }
                }

                // Verify backward result uses rightmost value in reversed order
                if let Some(backward_value) = backward.get_attribute(key) {
                    // Find rightmost value in reversed order
                    for resource in reversed.iter().rev() {
                        if let Some(expected) = resource.get_attribute(key) {
                            if backward_value != expected {
                                panic!(
                                    "Backward merge last-wins violation for key '{}': expected '{}', got '{}'",
                                    key, expected, backward_value
                                );
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
});
