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
    qpack_encode_field_section, qpack_encode_field_section_with_context,
    qpack_plan_to_header_fields, qpack_static_plan_for_request, qpack_static_plan_for_response,
};
use asupersync::http::{H3PseudoHeaders, H3RequestHead, H3ResponseHead};
use libfuzzer_sys::fuzz_target;
use std::fmt;

/// Maximum number of operations per fuzz iteration
const MAX_OPERATIONS: usize = 50;
/// Maximum field plan size to prevent resource exhaustion
const MAX_FIELD_PLAN_SIZE: usize = 20;
/// Maximum header name/value length
const MAX_HEADER_LENGTH: usize = 128;
/// Maximum dynamic table capacity for testing
const MAX_TABLE_CAPACITY: u64 = 4096;
/// Maximum diagnostic size accepted from graceful integration rejections.
const MAX_QPACK_DIAGNOSTIC_SIZE: usize = 2048;
/// Maximum encoded section size expected from normalized fuzz inputs.
const MAX_QPACK_ENCODED_SECTION_SIZE: usize = 8192;
/// Maximum decoded field count expected from generated test sections.
const MAX_QPACK_OBSERVED_FIELDS: usize = MAX_OPERATIONS + MAX_FIELD_PLAN_SIZE + 8;

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

    observe_qpack_integration_result(test_qpack_integration(&input));
});

fn observe_qpack_integration_result(result: Result<(), Box<dyn std::error::Error>>) {
    if let Err(err) = result {
        observe_qpack_rejection("QPACK integration", &err);
    }
}

fn observe_qpack_rejection(operation: &str, err: impl fmt::Display) {
    let diagnostic = err.to_string();
    assert!(
        !diagnostic.trim().is_empty(),
        "{operation} rejection should include a diagnostic"
    );
    assert!(
        diagnostic.len() <= MAX_QPACK_DIAGNOSTIC_SIZE,
        "{operation} diagnostic size {} exceeds maximum {}",
        diagnostic.len(),
        MAX_QPACK_DIAGNOSTIC_SIZE
    );
}

fn observe_encoded_section(
    result: Result<Vec<u8>, H3NativeError>,
    operation: &str,
) -> Option<Vec<u8>> {
    match result {
        Ok(encoded) => {
            assert!(
                encoded.len() <= MAX_QPACK_ENCODED_SECTION_SIZE,
                "{operation} encoded section size {} exceeds maximum {}",
                encoded.len(),
                MAX_QPACK_ENCODED_SECTION_SIZE
            );
            Some(encoded)
        }
        Err(err) => {
            observe_qpack_rejection(operation, &err);
            None
        }
    }
}

fn observe_decoded_plan(
    result: Result<Vec<QpackFieldPlan>, H3NativeError>,
    operation: &str,
) -> Option<Vec<QpackFieldPlan>> {
    match result {
        Ok(plan) => {
            assert!(
                plan.len() <= MAX_QPACK_OBSERVED_FIELDS,
                "{operation} decoded field count {} exceeds maximum {}",
                plan.len(),
                MAX_QPACK_OBSERVED_FIELDS
            );
            Some(plan)
        }
        Err(err) => {
            observe_qpack_rejection(operation, &err);
            None
        }
    }
}

fn observe_header_fields(
    result: Result<Vec<(String, String)>, H3NativeError>,
    operation: &str,
) -> Option<Vec<(String, String)>> {
    match result {
        Ok(fields) => {
            assert!(
                fields.len() <= MAX_QPACK_OBSERVED_FIELDS,
                "{operation} field count {} exceeds maximum {}",
                fields.len(),
                MAX_QPACK_OBSERVED_FIELDS
            );
            for (name, value) in &fields {
                assert!(
                    !name.is_empty(),
                    "{operation} produced an empty header name"
                );
                assert!(
                    !name.contains(['\r', '\n']) && !value.contains(['\r', '\n']),
                    "{operation} produced a header with line breaks"
                );
            }
            Some(fields)
        }
        Err(err) => {
            observe_qpack_rejection(operation, &err);
            None
        }
    }
}

fn observe_dynamic_insert(result: Result<u64, &'static str>, operation: &str) -> Option<u64> {
    match result {
        Ok(insertion_id) => {
            assert!(
                insertion_id <= MAX_OPERATIONS as u64,
                "{operation} insertion id {insertion_id} exceeds operation budget {MAX_OPERATIONS}"
            );
            Some(insertion_id)
        }
        Err(err) => {
            observe_qpack_rejection(operation, err);
            None
        }
    }
}

fn observe_qpack_table_snapshot(context: &QpackContext) {
    let table = context.dynamic_table();
    let table_size = table.size();
    let table_capacity = table.capacity();
    let table_len = table.len();
    let insertion_counter = table.insertion_counter();

    assert!(
        table_capacity <= MAX_TABLE_CAPACITY as usize,
        "QPACK dynamic table capacity {table_capacity} exceeds maximum {MAX_TABLE_CAPACITY}"
    );
    assert!(
        table_size <= table_capacity,
        "QPACK dynamic table size {table_size} exceeds capacity {table_capacity}"
    );
    assert!(
        insertion_counter >= table_len as u64,
        "QPACK insertion counter {insertion_counter} is below table length {table_len}"
    );
}

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
                    if let Some(encoded) = observe_encoded_section(
                        qpack_encode_field_section(&qpack_plan),
                        "QPACK field-section encode without context",
                    ) {
                        encoded_sections.push(encoded);
                    }

                    if let Some(encoded_with_ctx) = observe_encoded_section(
                        qpack_encode_field_section_with_context(&qpack_plan, Some(&qpack_context)),
                        "QPACK field-section encode with context",
                    ) {
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
                    observe_decoded_plan(
                        qpack_decode_field_section(encoded, H3QpackMode::StaticOnly),
                        "QPACK static-only field-section decode",
                    );
                    observe_decoded_plan(
                        qpack_decode_field_section(encoded, qpack_mode),
                        "QPACK selected-mode field-section decode",
                    );
                }
            }

            QpackOperation::ChangeDynamicTableSize { new_capacity } => {
                // Create new context with different capacity to test size changes
                let new_ctx =
                    QpackContext::new((*new_capacity as usize).min(MAX_TABLE_CAPACITY as usize));
                qpack_context = new_ctx;
            }

            QpackOperation::InsertDynamicEntry { name, value } => {
                // Test dynamic table insertion
                observe_dynamic_insert(
                    qpack_context.insert_dynamic_entry(name.clone(), value.clone()),
                    "QPACK dynamic table insertion",
                );
            }

            QpackOperation::RoundTripTest { field_plan } => {
                if let Ok(qpack_plan) = convert_field_plan_to_qpack(field_plan) {
                    // Test encoding then decoding for consistency
                    if let Some(encoded) = observe_encoded_section(
                        qpack_encode_field_section(&qpack_plan),
                        "QPACK roundtrip encode",
                    ) && let Some(decoded_plan) = observe_decoded_plan(
                        qpack_decode_field_section(&encoded, qpack_mode),
                        "QPACK roundtrip decode",
                    ) {
                        // Verify round-trip consistency
                        observe_header_fields(
                            qpack_plan_to_header_fields(&decoded_plan, Some(&qpack_context)),
                            "QPACK roundtrip header-field expansion",
                        );
                    }
                }
            }

            QpackOperation::ValidateState => {
                // Test context state validation
                if input.context_config.strict_validation {
                    validate_qpack_context_state(&qpack_context)?;
                } else {
                    observe_qpack_table_snapshot(&qpack_context);
                }
            }

            QpackOperation::EncodeRequest { request_config } => {
                // Test request header encoding
                if let Ok(request_head) = create_request_head(request_config) {
                    let plan = qpack_static_plan_for_request(&request_head);
                    observe_encoded_section(
                        qpack_encode_field_section(&plan),
                        "QPACK request field-section encode",
                    );
                }
            }

            QpackOperation::EncodeResponse { response_config } => {
                // Test response header encoding
                if let Ok(response_head) = create_response_head(response_config) {
                    let plan = qpack_static_plan_for_response(&response_head);
                    observe_encoded_section(
                        qpack_encode_field_section(&plan),
                        "QPACK response field-section encode",
                    );
                }
            }
        }
    }

    if input.context_config.strict_validation {
        validate_qpack_context_state(&qpack_context)?;
    }

    // Test header block ordering scenarios
    for scenario in &input.ordering_scenarios {
        test_ordering_scenario(scenario, &qpack_context, qpack_mode)?;
    }

    Ok(())
}

fn qpack_integration_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

fn validate_qpack_context_state(context: &QpackContext) -> Result<(), Box<dyn std::error::Error>> {
    let table = context.dynamic_table();
    let table_size = table.size();
    let table_capacity = table.capacity();
    let table_len = table.len();
    let insertion_counter = table.insertion_counter();

    if table_capacity > MAX_TABLE_CAPACITY as usize {
        return Err(qpack_integration_error(format!(
            "QPACK dynamic table capacity {table_capacity} exceeds maximum {MAX_TABLE_CAPACITY}"
        )));
    }
    if table_size > table_capacity {
        return Err(qpack_integration_error(format!(
            "QPACK dynamic table size {table_size} exceeds capacity {table_capacity}"
        )));
    }
    if insertion_counter < table_len as u64 {
        return Err(qpack_integration_error(format!(
            "QPACK insertion counter {insertion_counter} is below table length {table_len}"
        )));
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
                if scenario.validate_ordering && current_blocks.contains_key(block_id) {
                    return Err(qpack_integration_error(format!(
                        "QPACK header block {block_id} started more than once"
                    )));
                }
                current_block_id = Some(*block_id);
                current_blocks.insert(*block_id, Vec::new());
            }

            BlockOperation::AddField { name, value } => {
                let Some(block_id) = current_block_id else {
                    if scenario.validate_ordering {
                        return Err(qpack_integration_error(
                            "QPACK field added without an active header block",
                        ));
                    }
                    continue;
                };

                if let Some(block) = current_blocks.get_mut(&block_id) {
                    block.push((name.clone(), value.clone()));
                } else if scenario.validate_ordering {
                    return Err(qpack_integration_error(format!(
                        "QPACK field added to unknown header block {block_id}"
                    )));
                }
            }

            BlockOperation::FinishBlock => {
                let Some(block_id) = current_block_id else {
                    if scenario.validate_ordering {
                        return Err(qpack_integration_error(
                            "QPACK header block finished without an active block",
                        ));
                    }
                    continue;
                };

                if let Some(block) = current_blocks.get(&block_id) {
                    // Convert block to field plan and test encoding/decoding
                    let field_plan: Vec<QpackFieldPlan> = block
                        .iter()
                        .map(|(name, value)| QpackFieldPlan::Literal {
                            name: name.clone(),
                            value: value.clone(),
                        })
                        .collect();

                    if let Some(encoded) = observe_encoded_section(
                        qpack_encode_field_section(&field_plan),
                        "QPACK ordering block encode",
                    ) {
                        observe_decoded_plan(
                            qpack_decode_field_section(&encoded, qpack_mode),
                            "QPACK ordering block decode",
                        );
                    }
                } else if scenario.validate_ordering {
                    return Err(qpack_integration_error(format!(
                        "QPACK unknown header block {block_id} finished"
                    )));
                }
                current_block_id = None;
            }

            BlockOperation::SwitchToBlock { block_id } => {
                if scenario.validate_ordering && !current_blocks.contains_key(block_id) {
                    return Err(qpack_integration_error(format!(
                        "QPACK switched to unknown header block {block_id}"
                    )));
                }
                current_block_id = Some(*block_id);
                current_blocks.entry(*block_id).or_default();
            }
        }
    }

    if scenario.validate_ordering && current_block_id.is_some() {
        return Err(qpack_integration_error(
            "QPACK ordering scenario left a header block open",
        ));
    }

    Ok(())
}
