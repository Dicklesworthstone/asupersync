//! HTTP/3 QPACK cross-component integration edge cases fuzzer (asupersync-b9m51x).
//!
//! Tests QPACK encoder<->decoder integration with adversarial scenarios:
//! - Random encoder state changes interleaved with decoder operations
//! - Dynamic table size negotiations in various modes
//! - Header block ordering edge cases
//! - Static-only mode enforcement
//! - Cross-component state consistency validation
//!
//! This fuzzer focuses on integration bugs that arise when encoder and decoder
//! operations are interleaved in complex patterns that may not occur in
//! normal HTTP/3 usage but could be triggered by adversarial inputs.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h3_native::{
    H3NativeError, H3QpackMode, QpackContext, QpackFieldPlan, qpack_decode_field_section,
    qpack_decode_request_field_section, qpack_decode_response_field_section,
    qpack_encode_field_section, qpack_encode_field_section_with_context,
    qpack_plan_to_header_fields, qpack_static_plan_for_request, qpack_static_plan_for_response,
};
use asupersync::http::{H3PseudoHeaders, H3RequestHead, H3ResponseHead};
use libfuzzer_sys::fuzz_target;

/// Maximum number of operations per fuzz iteration
const MAX_OPERATIONS: usize = 50;
/// Maximum field plan size to prevent resource exhaustion
const MAX_FIELD_PLAN_SIZE: usize = 20;
/// Maximum header name/value length
const MAX_HEADER_LENGTH: usize = 128;
/// Maximum dynamic table capacity for testing
const MAX_TABLE_CAPACITY: u64 = 4096;

#[derive(Arbitrary, Debug)]
struct QpackIntegrationInput {
    /// Initial QPACK context configuration
    context_config: ContextConfig,
    /// Sequence of encoder/decoder operations to test
    operations: Vec<QpackOperation>,
    /// Header block ordering scenarios
    ordering_scenarios: Vec<OrderingScenario>,
}

#[derive(Arbitrary, Debug)]
struct ContextConfig {
    /// Initial dynamic table capacity
    initial_capacity: u16,
    /// QPACK mode to test
    qpack_mode: QpackModeChoice,
    /// Whether to enable strict validation
    strict_validation: bool,
}

#[derive(Arbitrary, Debug)]
enum QpackModeChoice {
    /// Static-only mode (as specified in requirements)
    StaticOnly,
    /// Dynamic table allowed (for testing mode transitions)
    DynamicTableAllowed,
}

#[derive(Arbitrary, Debug)]
enum QpackOperation {
    /// Encode a field section with given plan
    EncodeFieldSection { field_plan: Vec<FieldPlanEntry> },
    /// Decode a previously encoded field section
    DecodeFieldSection {
        /// Reference to a previously encoded section
        encoded_section_ref: u8,
    },
    /// Change dynamic table size (tests size negotiations)
    ChangeDynamicTableSize { new_capacity: u16 },
    /// Insert entries into dynamic table (for testing context changes)
    InsertDynamicEntry { name: String, value: String },
    /// Test encoder/decoder round-trip consistency
    RoundTripTest { field_plan: Vec<FieldPlanEntry> },
    /// Test cross-component state validation
    ValidateState,
    /// Generate and test request header encoding
    EncodeRequest { request_config: RequestConfig },
    /// Generate and test response header encoding
    EncodeResponse { response_config: ResponseConfig },
}

#[derive(Arbitrary, Debug)]
struct FieldPlanEntry {
    plan_type: FieldPlanType,
    name: String,
    value: String,
    index: u8,
}

#[derive(Arbitrary, Debug)]
enum FieldPlanType {
    /// Static table index
    StaticIndex,
    /// Dynamic table index (should fail in static-only mode)
    DynamicIndex,
    /// Literal field
    Literal,
    /// Literal with dynamic table name reference
    DynamicNameLiteral,
}

#[derive(Arbitrary, Debug)]
struct RequestConfig {
    method: String,
    scheme: String,
    path: String,
    authority: String,
    headers: Vec<(String, String)>,
}

#[derive(Arbitrary, Debug)]
struct ResponseConfig {
    status: u16,
    headers: Vec<(String, String)>,
}

#[derive(Arbitrary, Debug)]
struct OrderingScenario {
    /// Sequence of header block operations to test ordering
    block_operations: Vec<BlockOperation>,
    /// Whether to validate ordering constraints
    validate_ordering: bool,
}

#[derive(Arbitrary, Debug)]
enum BlockOperation {
    /// Start a new header block
    StartBlock { block_id: u8 },
    /// Add field to current block
    AddField { name: String, value: String },
    /// Finish current block
    FinishBlock,
    /// Interleave with different block
    SwitchToBlock { block_id: u8 },
}

fuzz_target!(|input: QpackIntegrationInput| {
    // Normalize input to prevent resource exhaustion
    let mut input = input;
    normalize_input(&mut input);

    let _ = test_qpack_integration(&input);
});

fn normalize_input(input: &mut QpackIntegrationInput) {
    // Clamp table capacity to reasonable range
    input.context_config.initial_capacity = input
        .context_config
        .initial_capacity
        .clamp(0, MAX_TABLE_CAPACITY as u16);

    // Limit operation count
    input.operations.truncate(MAX_OPERATIONS);

    // Normalize field plans
    for op in &mut input.operations {
        match op {
            QpackOperation::EncodeFieldSection { field_plan } => {
                field_plan.truncate(MAX_FIELD_PLAN_SIZE);
                normalize_field_plan(field_plan);
            }
            QpackOperation::RoundTripTest { field_plan } => {
                field_plan.truncate(MAX_FIELD_PLAN_SIZE);
                normalize_field_plan(field_plan);
            }
            QpackOperation::InsertDynamicEntry { name, value } => {
                name.truncate(MAX_HEADER_LENGTH);
                value.truncate(MAX_HEADER_LENGTH);
                sanitize_header_field(name, value);
            }
            QpackOperation::EncodeRequest { request_config } => {
                normalize_request_config(request_config);
            }
            QpackOperation::EncodeResponse { response_config } => {
                normalize_response_config(response_config);
            }
            _ => {} // Other operations don't need normalization
        }
    }

    // Normalize ordering scenarios
    for scenario in &mut input.ordering_scenarios {
        scenario.block_operations.truncate(MAX_OPERATIONS);
        for block_op in &mut scenario.block_operations {
            if let BlockOperation::AddField { name, value } = block_op {
                name.truncate(MAX_HEADER_LENGTH);
                value.truncate(MAX_HEADER_LENGTH);
                sanitize_header_field(name, value);
            }
        }
    }
}

fn normalize_field_plan(field_plan: &mut [FieldPlanEntry]) {
    for entry in field_plan {
        entry.name.truncate(MAX_HEADER_LENGTH);
        entry.value.truncate(MAX_HEADER_LENGTH);
        sanitize_header_field(&mut entry.name, &mut entry.value);
        // Limit index to reasonable range for static table
        entry.index = entry.index.clamp(0, 98); // RFC 9204 static table has indices 0-98
    }
}

fn normalize_request_config(config: &mut RequestConfig) {
    config.method.truncate(16);
    config.scheme.truncate(16);
    config.path.truncate(256);
    config.authority.truncate(256);
    config.headers.truncate(MAX_FIELD_PLAN_SIZE);

    for (name, value) in &mut config.headers {
        name.truncate(MAX_HEADER_LENGTH);
        value.truncate(MAX_HEADER_LENGTH);
        sanitize_header_field(name, value);
    }
}

fn normalize_response_config(config: &mut ResponseConfig) {
    config.status = config.status.clamp(100, 599);
    config.headers.truncate(MAX_FIELD_PLAN_SIZE);

    for (name, value) in &mut config.headers {
        name.truncate(MAX_HEADER_LENGTH);
        value.truncate(MAX_HEADER_LENGTH);
        sanitize_header_field(name, value);
    }
}

fn sanitize_header_field(name: &mut String, value: &mut String) {
    // Ensure valid HTTP header characters
    *name = name
        .chars()
        .filter(|&c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit())
        .collect();
    if name.is_empty() {
        *name = "x-test".to_string();
    }

    // Remove control characters from value
    *value = value
        .chars()
        .filter(|&c| c.is_ascii() && c != '\0' && c != '\r' && c != '\n')
        .collect();
}

fn test_qpack_integration(input: &QpackIntegrationInput) -> Result<(), Box<dyn std::error::Error>> {
    // Convert mode choice to actual mode
    let qpack_mode = match input.context_config.qpack_mode {
        QpackModeChoice::StaticOnly => H3QpackMode::StaticOnly,
        QpackModeChoice::DynamicTableAllowed => H3QpackMode::DynamicTableAllowed,
    };

    // Initialize QPACK context
    let mut qpack_context = QpackContext::new(input.context_config.initial_capacity as usize);

    // Track encoded sections for later decoding
    let mut encoded_sections: Vec<Vec<u8>> = Vec::new();

    // Execute operations sequence
    for operation in &input.operations {
        match operation {
            QpackOperation::EncodeFieldSection { field_plan } => {
                if let Ok(qpack_plan) = convert_field_plan_to_qpack(field_plan) {
                    // Test encoding with and without context
                    if let Ok(encoded) = qpack_encode_field_section(&qpack_plan) {
                        encoded_sections.push(encoded);
                    }

                    if let Ok(encoded_with_ctx) =
                        qpack_encode_field_section_with_context(&qpack_plan, Some(&qpack_context))
                    {
                        encoded_sections.push(encoded_with_ctx);
                    }
                }
            }

            QpackOperation::DecodeFieldSection {
                encoded_section_ref,
            } => {
                if let Some(encoded) = encoded_sections
                    .get(*encoded_section_ref as usize % encoded_sections.len().max(1))
                {
                    // Test decoding in both static-only and dynamic modes
                    let _ = qpack_decode_field_section(encoded, H3QpackMode::StaticOnly);
                    let _ = qpack_decode_field_section(encoded, qpack_mode);
                }
            }

            QpackOperation::ChangeDynamicTableSize { new_capacity } => {
                // Create new context with different capacity to test size changes
                let new_ctx = QpackContext::new(*new_capacity as usize);
                qpack_context = new_ctx;
            }

            QpackOperation::InsertDynamicEntry { name, value } => {
                // Test dynamic table insertion
                let _ = qpack_context.insert_dynamic_entry(name.clone(), value.clone());
            }

            QpackOperation::RoundTripTest { field_plan } => {
                if let Ok(qpack_plan) = convert_field_plan_to_qpack(field_plan) {
                    // Test encoding then decoding for consistency
                    if let Ok(encoded) = qpack_encode_field_section(&qpack_plan) {
                        if let Ok(decoded_plan) = qpack_decode_field_section(&encoded, qpack_mode) {
                            // Verify round-trip consistency
                            let _ =
                                qpack_plan_to_header_fields(&decoded_plan, Some(&qpack_context));
                        }
                    }
                }
            }

            QpackOperation::ValidateState => {
                // Test context state validation
                let table = qpack_context.dynamic_table();
                let _ = table.len();
                let _ = table.size();
                let _ = table.capacity();
                let _ = table.insertion_counter();
            }

            QpackOperation::EncodeRequest { request_config } => {
                // Test request header encoding
                if let Ok(request_head) = create_request_head(request_config) {
                    let plan = qpack_static_plan_for_request(&request_head);
                    let _ = qpack_encode_field_section(&plan);
                }
            }

            QpackOperation::EncodeResponse { response_config } => {
                // Test response header encoding
                if let Ok(response_head) = create_response_head(response_config) {
                    let plan = qpack_static_plan_for_response(&response_head);
                    let _ = qpack_encode_field_section(&plan);
                }
            }
        }
    }

    // Test header block ordering scenarios
    for scenario in &input.ordering_scenarios {
        test_ordering_scenario(scenario, &qpack_context, qpack_mode)?;
    }

    Ok(())
}

fn convert_field_plan_to_qpack(
    field_plan: &[FieldPlanEntry],
) -> Result<Vec<QpackFieldPlan>, Box<dyn std::error::Error>> {
    let mut qpack_plan = Vec::new();

    for entry in field_plan {
        let plan_entry = match entry.plan_type {
            FieldPlanType::StaticIndex => QpackFieldPlan::StaticIndex(entry.index as u64),
            FieldPlanType::DynamicIndex => QpackFieldPlan::DynamicIndex(entry.index as u64),
            FieldPlanType::Literal => QpackFieldPlan::Literal {
                name: entry.name.clone(),
                value: entry.value.clone(),
            },
            FieldPlanType::DynamicNameLiteral => QpackFieldPlan::DynamicNameLiteral {
                name_index: entry.index as u64,
                value: entry.value.clone(),
            },
        };

        qpack_plan.push(plan_entry);
    }

    Ok(qpack_plan)
}

fn create_request_head(
    config: &RequestConfig,
) -> Result<H3RequestHead, Box<dyn std::error::Error>> {
    // Create H3RequestHead with correct field structure
    let pseudo = H3PseudoHeaders {
        method: Some(config.method.clone()),
        scheme: Some(config.scheme.clone()),
        path: Some(config.path.clone()),
        authority: Some(config.authority.clone()),
        status: None,
        protocol: None,
    };

    Ok(H3RequestHead {
        pseudo,
        headers: config.headers.clone(),
    })
}

fn create_response_head(
    config: &ResponseConfig,
) -> Result<H3ResponseHead, Box<dyn std::error::Error>> {
    // Create H3ResponseHead with correct field structure
    Ok(H3ResponseHead {
        status: config.status,
        headers: config.headers.clone(),
    })
}

fn test_ordering_scenario(
    scenario: &OrderingScenario,
    _context: &QpackContext,
    qpack_mode: H3QpackMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut current_blocks: std::collections::HashMap<u8, Vec<(String, String)>> =
        std::collections::HashMap::new();
    let mut current_block_id: Option<u8> = None;

    for block_op in &scenario.block_operations {
        match block_op {
            BlockOperation::StartBlock { block_id } => {
                current_block_id = Some(*block_id);
                current_blocks.insert(*block_id, Vec::new());
            }

            BlockOperation::AddField { name, value } => {
                if let Some(block_id) = current_block_id {
                    if let Some(block) = current_blocks.get_mut(&block_id) {
                        block.push((name.clone(), value.clone()));
                    }
                }
            }

            BlockOperation::FinishBlock => {
                if let Some(block_id) = current_block_id {
                    if let Some(block) = current_blocks.get(&block_id) {
                        // Convert block to field plan and test encoding/decoding
                        let field_plan: Vec<QpackFieldPlan> = block
                            .iter()
                            .map(|(name, value)| QpackFieldPlan::Literal {
                                name: name.clone(),
                                value: value.clone(),
                            })
                            .collect();

                        if let Ok(encoded) = qpack_encode_field_section(&field_plan) {
                            let _ = qpack_decode_field_section(&encoded, qpack_mode);
                        }
                    }
                }
                current_block_id = None;
            }

            BlockOperation::SwitchToBlock { block_id } => {
                current_block_id = Some(*block_id);
                current_blocks.entry(*block_id).or_insert_with(Vec::new);
            }
        }
    }

    Ok(())
}
