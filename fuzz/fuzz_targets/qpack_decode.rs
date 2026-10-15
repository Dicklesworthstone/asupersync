#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

use asupersync::http::h3_native::{
    H3NativeError, H3QpackMode, QpackFieldPlan, qpack_decode_field_section,
    qpack_encode_field_section, qpack_plan_to_header_fields,
};

/// Structure-aware fuzz input for QPACK operations
#[derive(Arbitrary, Debug)]
struct QpackFuzzInput {
    /// QPACK mode to test (static-only vs dynamic table allowed)
    mode: QpackMode,
    /// Field section bytes to decode
    field_section: Vec<u8>,
    /// Whether to test with simulated dynamic table state
    simulate_dynamic_state: bool,
    /// Maximum field section size to prevent OOM
    max_size: u16,
}

/// QPACK mode for fuzzing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum QpackMode {
    /// Static-only mode
    StaticOnly,
    /// Dynamic table allowed mode
    DynamicAllowed,
}

impl From<QpackMode> for H3QpackMode {
    fn from(mode: QpackMode) -> Self {
        match mode {
            QpackMode::StaticOnly => H3QpackMode::StaticOnly,
            QpackMode::DynamicAllowed => H3QpackMode::DynamicTableAllowed,
        }
    }
}

/// Shadow model to track QPACK decoding state and validate invariants
#[derive(Debug, Default)]
struct QpackShadowModel {
    /// Number of decoded fields
    field_count: usize,
    /// Total decoded bytes processed
    bytes_processed: usize,
    /// Static table references seen (index -> count)
    static_refs: HashMap<u64, usize>,
    /// Dynamic table operations attempted
    dynamic_ops: usize,
    /// Required insert count values seen
    ric_values: Vec<u64>,
    /// Delta base values seen
    delta_base_values: Vec<u64>,
}

impl QpackShadowModel {
    fn record_static_ref(&mut self, index: u64) {
        *self.static_refs.entry(index).or_insert(0) += 1;
    }

    fn record_dynamic_op(&mut self) {
        self.dynamic_ops += 1;
    }

    fn record_ric(&mut self, ric: u64) {
        self.ric_values.push(ric);
    }

    fn record_delta_base(&mut self, delta_base: u64) {
        self.delta_base_values.push(delta_base);
    }

    fn validate_invariants(&self) -> Result<(), String> {
        // Validate static table reference bounds (0-98)
        for &index in self.static_refs.keys() {
            if index > 98 {
                return Err(format!("Invalid static table index: {}", index));
            }
        }

        // Check for reasonable processing bounds
        if self.bytes_processed > 1_000_000 {
            return Err(format!(
                "Excessive bytes processed: {}",
                self.bytes_processed
            ));
        }

        if self.field_count > 10000 {
            return Err(format!("Excessive field count: {}", self.field_count));
        }

        Ok(())
    }
}

/// Test environment for QPACK fuzzing
struct QpackTestEnvironment {
    shadow: QpackShadowModel,
}

impl QpackTestEnvironment {
    fn new() -> Self {
        Self {
            shadow: QpackShadowModel::default(),
        }
    }

    fn test_qpack_decode(&mut self, input: &QpackFuzzInput) -> Result<(), String> {
        // Limit input size to prevent OOM
        let max_size = (input.max_size as usize).clamp(1, 65536);
        if input.field_section.len() > max_size {
            return Ok(()); // Skip oversized inputs
        }

        let mode = H3QpackMode::from(input.mode);
        self.shadow.bytes_processed += input.field_section.len();

        // Test core QPACK decode function
        match qpack_decode_field_section(&input.field_section, mode) {
            Ok(plan) => {
                validate_decoded_plan(&plan, mode, "fuzz input")?;
                self.shadow.field_count += plan.len();

                // Analyze the decoded plan for static table coverage
                for item in &plan {
                    match item {
                        QpackFieldPlan::StaticIndex(index) => {
                            self.shadow.record_static_ref(*index);
                        }
                        QpackFieldPlan::Literal { .. } => {
                            // Literal fields are valid
                        }
                        QpackFieldPlan::DynamicIndex(_)
                        | QpackFieldPlan::DynamicNameLiteral { .. } => {
                            self.shadow.record_dynamic_op();
                        }
                    }
                }

                // If we're in dynamic mode, record dynamic operations
                if mode == H3QpackMode::DynamicTableAllowed {
                    self.shadow.record_dynamic_op();
                }

                validate_header_expansion(&plan, "fuzz input")?;
            }
            Err(H3NativeError::QpackPolicy(_)) => {
                // Policy violations are expected for certain mode/input combinations
            }
            Err(H3NativeError::InvalidFrame(_)) => {
                // Invalid frames are expected with random input
            }
            Err(H3NativeError::UnexpectedEof) => {
                // Truncated input is expected
            }
            Err(e) => {
                return Err(format!("Unexpected QPACK error: {:?}", e));
            }
        }

        self.shadow.validate_invariants()
    }

    fn test_static_table_coverage(&self) -> Result<(), String> {
        // Verify we're exercising the full static table range
        if !self.shadow.static_refs.is_empty() {
            let min_index = *self.shadow.static_refs.keys().min().unwrap();
            let max_index = *self.shadow.static_refs.keys().max().unwrap();

            if min_index > 98 || max_index > 98 {
                return Err(format!(
                    "Static table index out of bounds: min={}, max={}",
                    min_index, max_index
                ));
            }
        }

        Ok(())
    }
}

fn validate_decoded_plan(
    plan: &[QpackFieldPlan],
    mode: H3QpackMode,
    context: &str,
) -> Result<(), String> {
    for item in plan {
        match item {
            QpackFieldPlan::StaticIndex(index) => {
                if *index > 98 {
                    return Err(format!(
                        "{context}: decoded static qpack index out of bounds: {index}"
                    ));
                }
            }
            QpackFieldPlan::Literal { .. } => {}
            QpackFieldPlan::DynamicIndex(_) | QpackFieldPlan::DynamicNameLiteral { .. }
                if mode == H3QpackMode::StaticOnly =>
            {
                return Err(format!(
                    "{context}: static-only decode produced a dynamic qpack plan item"
                ));
            }
            QpackFieldPlan::DynamicIndex(_) | QpackFieldPlan::DynamicNameLiteral { .. } => {}
        }
    }
    Ok(())
}

fn validate_header_expansion(plan: &[QpackFieldPlan], context: &str) -> Result<(), String> {
    let has_dynamic_reference = plan.iter().any(|item| {
        matches!(
            item,
            QpackFieldPlan::DynamicIndex(_) | QpackFieldPlan::DynamicNameLiteral { .. }
        )
    });

    match qpack_plan_to_header_fields(plan, None) {
        Ok(headers) => {
            if headers.len() != plan.len() {
                return Err(format!(
                    "{context}: expanded {} headers from {} qpack plan items",
                    headers.len(),
                    plan.len()
                ));
            }
            if has_dynamic_reference {
                return Err(format!(
                    "{context}: expanded dynamic qpack references without a dynamic table context"
                ));
            }
            Ok(())
        }
        Err(H3NativeError::InvalidFrame(_)) if has_dynamic_reference => Ok(()),
        Err(error) => Err(format!(
            "{context}: qpack header expansion failed for a context-free plan: {error:?}"
        )),
    }
}

fn assert_decode_ok(
    section: &[u8],
    mode: H3QpackMode,
    context: &str,
) -> Result<Vec<QpackFieldPlan>, String> {
    let plan = qpack_decode_field_section(section, mode)
        .map_err(|error| format!("{context}: expected qpack decode success, got {error:?}"))?;
    validate_decoded_plan(&plan, mode, context)?;
    validate_header_expansion(&plan, context)?;
    Ok(plan)
}

fn observe_decode_result(section: &[u8], mode: H3QpackMode, context: &str) -> Result<(), String> {
    match qpack_decode_field_section(section, mode) {
        Ok(plan) => {
            validate_decoded_plan(&plan, mode, context)?;
            validate_header_expansion(&plan, context)
        }
        Err(H3NativeError::QpackPolicy(_))
        | Err(H3NativeError::InvalidFrame(_))
        | Err(H3NativeError::UnexpectedEof) => Ok(()),
        Err(error) => Err(format!(
            "{context}: unexpected qpack decode error: {error:?}"
        )),
    }
}

fn ascii_fragment(data: &[u8], offset: usize, max_len: usize, fallback: &str) -> String {
    if offset >= data.len() || max_len == 0 {
        return fallback.to_string();
    }

    let available = data.len() - offset;
    let len = available.min(max_len).max(1);
    data[offset..offset + len]
        .iter()
        .map(|byte| char::from(b'a' + (byte % 26)))
        .collect()
}

/// Test specific QPACK scenarios
fn test_qpack_edge_cases(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }

    // Test 1: Empty field section with just prefix
    let empty_section = vec![0x00, 0x00]; // RIC=0, Delta Base=0
    let empty_plan = assert_decode_ok(&empty_section, H3QpackMode::StaticOnly, "empty section")?;
    if !empty_plan.is_empty() {
        return Err(format!(
            "empty section decoded {} qpack plan items",
            empty_plan.len()
        ));
    }

    // Test 2: Single static table reference (if we have at least 3 bytes)
    if data.len() >= 3 {
        let index = (data[0] % 99) as u64; // 0-98 range
        let expected = vec![QpackFieldPlan::StaticIndex(index)];
        let single_ref = qpack_encode_field_section(&expected)
            .map_err(|error| format!("single static reference encode failed: {error:?}"))?;
        let decoded = assert_decode_ok(
            &single_ref,
            H3QpackMode::StaticOnly,
            "single static reference",
        )?;
        if decoded != expected {
            return Err(format!(
                "single static reference roundtrip mismatch: expected {expected:?}, got {decoded:?}"
            ));
        }
    }

    // Test 3: Literal field line with known name
    if data.len() >= 10 {
        let value = ascii_fragment(data, 2, 32, "value");
        let mut literal_known = vec![0x00, 0x00]; // Prefix
        literal_known.push(0x50); // Literal with static name reference index 0 (:authority)
        literal_known.push(value.len() as u8); // Value length (non-Huffman)
        literal_known.extend_from_slice(value.as_bytes());
        let decoded = assert_decode_ok(
            &literal_known,
            H3QpackMode::StaticOnly,
            "literal static-name reference",
        )?;
        let expected = vec![QpackFieldPlan::Literal {
            name: ":authority".to_string(),
            value,
        }];
        if decoded != expected {
            return Err(format!(
                "literal static-name reference mismatch: expected {expected:?}, got {decoded:?}"
            ));
        }
    }

    // Test 4: Literal field line with literal name
    if data.len() >= 8 {
        let name = ascii_fragment(data, 1, 7, "x");
        let value = ascii_fragment(data, 1 + name.len(), 32, "v");
        let mut literal_name = vec![0x00, 0x00]; // Prefix
        literal_name.push(0x20 | name.len() as u8); // Literal with literal name
        literal_name.extend_from_slice(name.as_bytes());
        literal_name.push(value.len() as u8); // Value length (non-Huffman)
        literal_name.extend_from_slice(value.as_bytes());
        let decoded =
            assert_decode_ok(&literal_name, H3QpackMode::StaticOnly, "literal name field")?;
        let expected = vec![QpackFieldPlan::Literal { name, value }];
        if decoded != expected {
            return Err(format!(
                "literal name field mismatch: expected {expected:?}, got {decoded:?}"
            ));
        }
    }

    Ok(())
}

/// Test Required Insert Count and Delta Base scenarios
fn test_ric_delta_base_scenarios(data: &[u8], shadow: &mut QpackShadowModel) -> Result<(), String> {
    if data.len() < 2 {
        return Ok(());
    }

    // Test various RIC values
    let ric_values = [0u64, 1, 10, 100, 255, 1000];
    let delta_base_values = [0u64, 1, 5, 50, 127];

    for &ric in &ric_values {
        for &delta_base in &delta_base_values {
            // Record the values being tested
            shadow.record_ric(ric);
            shadow.record_delta_base(delta_base);
            let mut section = Vec::new();

            // Encode RIC (8-bit prefix)
            if ric < 255 {
                section.push(ric as u8);
            } else {
                section.push(255);
                let mut remaining = ric - 255;
                while remaining >= 128 {
                    section.push(0x80 | (remaining as u8 & 0x7F));
                    remaining >>= 7;
                }
                section.push(remaining as u8);
            }

            // Encode Delta Base (7-bit prefix)
            if delta_base < 127 {
                section.push(delta_base as u8);
            } else {
                section.push(127);
                let mut remaining = delta_base - 127;
                while remaining >= 128 {
                    section.push(0x80 | (remaining as u8 & 0x7F));
                    remaining >>= 7;
                }
                section.push(remaining as u8);
            }

            // Test with static-only mode (should reject non-zero RIC)
            let result = qpack_decode_field_section(&section, H3QpackMode::StaticOnly);
            if ric != 0 || delta_base != 0 {
                // Static-only mode permits only the all-zero field-section prefix.
                assert!(matches!(result, Err(H3NativeError::QpackPolicy(_))));
            } else {
                assert_decode_ok(&section, H3QpackMode::StaticOnly, "static zero prefix")?;
            }

            // Test with dynamic mode allowed
            observe_decode_result(&section, H3QpackMode::DynamicTableAllowed, "dynamic prefix")?;
        }
    }

    Ok(())
}

/// Maximum limits for fuzzing
const MAX_FIELD_SECTION_SIZE: usize = 32768;
const MAX_OPERATIONS: usize = 1000;

fuzz_target!(|input: QpackFuzzInput| {
    // Limit input size to prevent timeouts
    if input.field_section.len() > MAX_FIELD_SECTION_SIZE {
        return;
    }

    let mut env = QpackTestEnvironment::new();

    // Test main QPACK decode functionality
    env.test_qpack_decode(&input).unwrap_or_else(|e| {
        panic!("QPACK decode invariant violation: {}", e);
    });

    // Test static table coverage
    env.test_static_table_coverage().unwrap_or_else(|e| {
        panic!("Static table coverage violation: {}", e);
    });

    // Test edge cases with raw input
    test_qpack_edge_cases(&input.field_section).unwrap_or_else(|e| {
        panic!("QPACK edge case test failed: {}", e);
    });

    // Test Required Insert Count and Delta Base scenarios
    test_ric_delta_base_scenarios(&input.field_section, &mut env.shadow).unwrap_or_else(|e| {
        panic!("RIC/Delta Base test failed: {}", e);
    });

    // Limit the number of operations to prevent excessive runtime
    if env.shadow.field_count > MAX_OPERATIONS {
        return;
    }

    // Test mode switching scenarios
    if input.simulate_dynamic_state {
        // Test policy enforcement between modes
        let static_result =
            qpack_decode_field_section(&input.field_section, H3QpackMode::StaticOnly);
        let dynamic_result =
            qpack_decode_field_section(&input.field_section, H3QpackMode::DynamicTableAllowed);

        // Static-only successes contain only context-free field lines, so dynamic mode
        // without a table context must decode the same plan.
        if let Ok(static_plan) = static_result {
            validate_decoded_plan(&static_plan, H3QpackMode::StaticOnly, "mode switch static")
                .unwrap_or_else(|e| panic!("Mode switch static plan failed validation: {}", e));
            match dynamic_result {
                Ok(dynamic_plan) => {
                    validate_decoded_plan(
                        &dynamic_plan,
                        H3QpackMode::DynamicTableAllowed,
                        "mode switch dynamic",
                    )
                    .unwrap_or_else(|e| {
                        panic!("Mode switch dynamic plan failed validation: {}", e);
                    });
                    if dynamic_plan != static_plan {
                        panic!(
                            "Dynamic mode changed a static-only qpack plan: static={:?}, dynamic={:?}",
                            static_plan, dynamic_plan
                        );
                    }
                }
                Err(error) => {
                    panic!(
                        "Dynamic mode failed where static mode succeeded: {:?}",
                        error
                    );
                }
            }
        }
    }
});
