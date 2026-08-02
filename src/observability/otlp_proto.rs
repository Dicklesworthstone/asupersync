//! Private, bounded OTLP protobuf models.
//!
//! This module is the implementation side of `protobuf-owned-otlp-schema-v1`.
//! It deliberately remains crate-private and separate from signal adapters,
//! transport framing, generated reference messages, and dependency cutover.
//! The current implementation slice owns the common, resource, metrics, trace,
//! logs, and metrics-collector families plus the shared resource-accounting
//! machinery required by later collector models.

use crate::grpc::protobuf::{
    ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError, ProtobufWireField,
    ProtobufWireLimits, ProtobufWireMessage, UnknownFields, WireType, decode_varint, merge_fields,
    merge_nested_message, zigzag_decode_i32,
};

mod limits_and_error {
    use super::{
        ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError,
        ProtobufWireField, ProtobufWireLimits, ProtobufWireMessage, UnknownFields, WireType,
        merge_fields, merge_nested_message,
    };

    pub(super) const MAX_TOTAL_REPEATED_ITEMS: usize = 65_536;
    pub(super) const MAX_TOTAL_ANY_VALUE_NODES: usize = 4_096;
    pub(super) const MAX_TOTAL_OWNED_BYTES: usize = 4 * 1024 * 1024;

    pub(super) const MAX_ATTRIBUTES: usize = 128;
    pub(super) const MAX_ENTITY_REFS: usize = 128;
    pub(super) const MAX_ENTITY_REF_KEYS: usize = 128;
    pub(super) const MAX_ANY_VALUE_DEPTH: usize = 16;
    pub(super) const MAX_ANY_VALUE_ITEMS: usize = 128;
    pub(super) const MAX_RESOURCE_GROUPS_PER_REQUEST: usize = 64;
    pub(super) const MAX_SCOPES_PER_RESOURCE_GROUP: usize = 128;
    pub(super) const MAX_METRICS_PER_SCOPE: usize = 4_096;
    pub(super) const MAX_SPANS_PER_SCOPE: usize = 4_096;
    pub(super) const MAX_LOG_RECORDS_PER_SCOPE: usize = 4_096;
    pub(super) const MAX_DATA_POINTS_PER_METRIC: usize = 1_000;
    pub(super) const MAX_METRIC_METADATA_ENTRIES: usize = 128;
    pub(super) const MAX_EXEMPLARS_PER_DATA_POINT: usize = 128;
    pub(super) const MAX_HISTOGRAM_BUCKET_COUNTS: usize = 4_096;
    pub(super) const MAX_HISTOGRAM_EXPLICIT_BOUNDS: usize = 4_095;
    pub(super) const MAX_EXPONENTIAL_HISTOGRAM_BUCKETS: usize = 4_096;
    pub(super) const MAX_SUMMARY_QUANTILES: usize = 1_024;
    pub(super) const MAX_EVENTS_PER_SPAN: usize = 128;
    pub(super) const MAX_LINKS_PER_SPAN: usize = 128;

    pub(super) const MAX_ATTRIBUTE_KEY_BYTES: usize = 1_024;
    pub(super) const MAX_ATTRIBUTE_VALUE_BYTES: usize = 4_096;
    pub(super) const MAX_SCHEMA_URL_BYTES: usize = 2_048;
    pub(super) const MAX_SCOPE_NAME_BYTES: usize = 1_024;
    pub(super) const MAX_SCOPE_VERSION_BYTES: usize = 1_024;
    pub(super) const MAX_METRIC_NAME_BYTES: usize = 1_024;
    pub(super) const MAX_METRIC_DESCRIPTION_BYTES: usize = 4_096;
    pub(super) const MAX_METRIC_UNIT_BYTES: usize = 256;
    pub(super) const MAX_SPAN_NAME_BYTES: usize = 1_024;
    pub(super) const MAX_TRACE_STATE_BYTES: usize = 512;
    pub(super) const MAX_EVENT_NAME_BYTES: usize = 1_024;
    pub(super) const MAX_LOG_SEVERITY_TEXT_BYTES: usize = 1_024;
    pub(super) const MAX_LOG_EVENT_NAME_BYTES: usize = 1_024;
    pub(super) const MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES: usize = 4_096;
    pub(super) const MAX_TRACE_ID_BYTES: usize = 16;
    pub(super) const MAX_SPAN_ID_BYTES: usize = 8;

    pub(super) trait OtlpModel: Default + Send + Sized + 'static {
        const COUNTS_AS_ANY_VALUE: bool = false;

        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError>;

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError>;

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            any_value_depth: usize,
        ) -> Result<(), ProtobufWireError>;
    }

    #[derive(Debug)]
    pub(super) struct ValidationBudget {
        repeated_items: usize,
        any_value_nodes: usize,
        owned_bytes: usize,
        work_used: usize,
        work_limit: usize,
        enforce_invariants: bool,
    }

    #[derive(Clone, Copy, Debug)]
    pub(super) struct ValidationReceipt {
        pub(super) repeated_items: usize,
        pub(super) any_value_nodes: usize,
        pub(super) owned_bytes: usize,
        pub(super) work_used: usize,
    }

    impl ValidationBudget {
        pub(super) const fn new(work_limit: usize, enforce_invariants: bool) -> Self {
            Self {
                repeated_items: 0,
                any_value_nodes: 0,
                owned_bytes: 0,
                work_used: 0,
                work_limit,
                enforce_invariants,
            }
        }

        pub(super) const fn enforces_invariants(&self) -> bool {
            self.enforce_invariants
        }

        fn checked_total(
            current: usize,
            amount: usize,
            limit: usize,
            resource: &'static str,
        ) -> Result<usize, ProtobufWireError> {
            let Some(observed) = current.checked_add(amount) else {
                return Err(ProtobufWireError::SchemaLimitExceeded {
                    offset: 0,
                    resource,
                    observed: usize::MAX,
                    limit,
                });
            };
            if observed > limit {
                return Err(ProtobufWireError::SchemaLimitExceeded {
                    offset: 0,
                    resource,
                    observed,
                    limit,
                });
            }
            Ok(observed)
        }

        pub(super) fn repeated(
            &mut self,
            count: usize,
            collection_limit: usize,
            resource: &'static str,
        ) -> Result<(), ProtobufWireError> {
            if count > collection_limit {
                return Err(ProtobufWireError::SchemaLimitExceeded {
                    offset: 0,
                    resource,
                    observed: count,
                    limit: collection_limit,
                });
            }
            self.repeated_items = Self::checked_total(
                self.repeated_items,
                count,
                MAX_TOTAL_REPEATED_ITEMS,
                "total repeated items",
            )?;
            Ok(())
        }

        pub(super) fn any_value_node(&mut self, depth: usize) -> Result<(), ProtobufWireError> {
            if depth > MAX_ANY_VALUE_DEPTH {
                return Err(ProtobufWireError::SchemaLimitExceeded {
                    offset: 0,
                    resource: "AnyValue depth",
                    observed: depth,
                    limit: MAX_ANY_VALUE_DEPTH,
                });
            }
            self.any_value_nodes = Self::checked_total(
                self.any_value_nodes,
                1,
                MAX_TOTAL_ANY_VALUE_NODES,
                "total AnyValue nodes",
            )?;
            Ok(())
        }

        pub(super) fn owned_bytes(
            &mut self,
            length: usize,
            field_limit: usize,
            resource: &'static str,
        ) -> Result<(), ProtobufWireError> {
            if length > field_limit {
                return Err(ProtobufWireError::SchemaLimitExceeded {
                    offset: 0,
                    resource,
                    observed: length,
                    limit: field_limit,
                });
            }
            self.owned_bytes = Self::checked_total(
                self.owned_bytes,
                length,
                MAX_TOTAL_OWNED_BYTES,
                "total owned string and bytes payload",
            )?;
            Ok(())
        }

        pub(super) fn work(&mut self, amount: usize) -> Result<(), ProtobufWireError> {
            let Some(observed) = self.work_used.checked_add(amount) else {
                return Err(ProtobufWireError::WorkLimitExceeded {
                    offset: 0,
                    work: usize::MAX,
                    limit: self.work_limit,
                });
            };
            if observed > self.work_limit {
                return Err(ProtobufWireError::WorkLimitExceeded {
                    offset: 0,
                    work: observed,
                    limit: self.work_limit,
                });
            }
            self.work_used = observed;
            Ok(())
        }

        pub(super) const fn receipt(&self) -> ValidationReceipt {
            ValidationReceipt {
                repeated_items: self.repeated_items,
                any_value_nodes: self.any_value_nodes,
                owned_bytes: self.owned_bytes,
                work_used: self.work_used,
            }
        }
    }

    pub(super) fn validate_root<M: OtlpModel>(
        model: &M,
        work_limit: usize,
        enforce_invariants: bool,
    ) -> Result<ValidationReceipt, ProtobufWireError> {
        let mut budget = ValidationBudget::new(work_limit, enforce_invariants);
        let depth = usize::from(M::COUNTS_AS_ANY_VALUE);
        model.validate_otlp(&mut budget, depth)?;
        Ok(budget.receipt())
    }

    pub(super) fn merge_root<M>(
        target: &mut M,
        input: &[u8],
        limits: ProtobufWireLimits,
    ) -> Result<(), ProtobufWireError>
    where
        M: OtlpModel + ProtoMessage,
    {
        let existing = validate_root(target, limits.max_work, false)?;
        let mut message = ProtobufWireMessage::new(input, limits)?;
        {
            let mut decoder = message.decoder();
            decoder.seed_semantic_budgets(
                existing.repeated_items,
                MAX_TOTAL_REPEATED_ITEMS,
                existing.any_value_nodes,
                MAX_TOTAL_ANY_VALUE_NODES,
                existing.owned_bytes,
                MAX_TOTAL_OWNED_BYTES,
            )?;
            decoder.charge_additional_work(existing.work_used, 0)?;
            if M::COUNTS_AS_ANY_VALUE {
                decoder.enter_semantic_any_value(
                    false,
                    MAX_TOTAL_ANY_VALUE_NODES,
                    MAX_ANY_VALUE_DEPTH,
                    0,
                )?;
            }
            let result = merge_fields(target, &mut decoder);
            if M::COUNTS_AS_ANY_VALUE {
                decoder.leave_semantic_any_value();
            }
            result?;
            let remaining_work = decoder.remaining_work();
            let validated = validate_root(target, remaining_work, true)?;
            let offset = decoder.position();
            decoder.charge_additional_work(validated.work_used, offset)?;
        }
        Ok(())
    }

    pub(super) fn collection_room(
        current: usize,
        additional: usize,
        limit: usize,
        offset: usize,
        resource: &'static str,
    ) -> Result<(), ProtobufWireError> {
        let observed = current.saturating_add(additional);
        if observed > limit {
            return Err(ProtobufWireError::SchemaLimitExceeded {
                offset,
                resource,
                observed,
                limit,
            });
        }
        Ok(())
    }

    pub(super) fn allocation_failed(
        offset: usize,
        resource: &'static str,
        additional: usize,
    ) -> ProtobufWireError {
        ProtobufWireError::AllocationFailed {
            offset,
            resource,
            additional,
        }
    }

    pub(super) fn decode_string(
        field: &ProtobufWireField<'_>,
        decoder: &mut ProtobufWireDecoder<'_, '_>,
        limit: usize,
        resource: &'static str,
    ) -> Result<String, ProtobufWireError> {
        let bytes = field.as_bytes()?;
        if bytes.len() > limit {
            return Err(ProtobufWireError::SchemaLimitExceeded {
                offset: field.value_offset(),
                resource,
                observed: bytes.len(),
                limit,
            });
        }
        decoder.charge_semantic_owned_bytes(
            bytes.len(),
            MAX_TOTAL_OWNED_BYTES,
            field.value_offset(),
        )?;
        let validation_and_copy_work = bytes.len().saturating_mul(2);
        decoder.charge_additional_work(validation_and_copy_work, field.value_offset())?;
        let text = field.as_str()?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(text.len())
            .map_err(|_| allocation_failed(field.value_offset(), resource, text.len()))?;
        owned.push_str(text);
        Ok(owned)
    }

    pub(super) fn decode_bytes(
        field: &ProtobufWireField<'_>,
        decoder: &mut ProtobufWireDecoder<'_, '_>,
        limit: usize,
        resource: &'static str,
    ) -> Result<Vec<u8>, ProtobufWireError> {
        let bytes = field.as_bytes()?;
        if bytes.len() > limit {
            return Err(ProtobufWireError::SchemaLimitExceeded {
                offset: field.value_offset(),
                resource,
                observed: bytes.len(),
                limit,
            });
        }
        decoder.charge_semantic_owned_bytes(
            bytes.len(),
            MAX_TOTAL_OWNED_BYTES,
            field.value_offset(),
        )?;
        decoder.charge_additional_work(bytes.len(), field.value_offset())?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| allocation_failed(field.value_offset(), resource, bytes.len()))?;
        owned.extend_from_slice(bytes);
        Ok(owned)
    }

    pub(super) fn decode_exact_or_empty_bytes(
        field: &ProtobufWireField<'_>,
        decoder: &mut ProtobufWireDecoder<'_, '_>,
        exact_length: usize,
        resource: &'static str,
        invariant: &'static str,
    ) -> Result<Vec<u8>, ProtobufWireError> {
        let bytes = field.as_bytes()?;
        if !bytes.is_empty() && bytes.len() != exact_length {
            return Err(ProtobufWireError::SchemaInvariant {
                offset: field.value_offset(),
                invariant,
            });
        }
        decode_bytes(field, decoder, exact_length, resource)
    }

    pub(super) fn push_string(
        target: &mut Vec<String>,
        field: &ProtobufWireField<'_>,
        decoder: &mut ProtobufWireDecoder<'_, '_>,
        collection_limit: usize,
        string_limit: usize,
        collection_resource: &'static str,
        string_resource: &'static str,
    ) -> Result<(), ProtobufWireError> {
        collection_room(
            target.len(),
            1,
            collection_limit,
            field.offset(),
            collection_resource,
        )?;
        decoder.charge_semantic_repeated_items(1, MAX_TOTAL_REPEATED_ITEMS, field.offset())?;
        let value = decode_string(field, decoder, string_limit, string_resource)?;
        target
            .try_reserve(1)
            .map_err(|_| allocation_failed(field.offset(), collection_resource, 1))?;
        target.push(value);
        Ok(())
    }

    pub(super) fn push_message<'wire, M>(
        target: &mut Vec<M>,
        field: &ProtobufWireField<'wire>,
        decoder: &mut ProtobufWireDecoder<'wire, '_>,
        collection_limit: usize,
        collection_resource: &'static str,
        counts_as_any_value: bool,
    ) -> Result<(), ProtobufWireError>
    where
        M: ProtoMessage,
    {
        collection_room(
            target.len(),
            1,
            collection_limit,
            field.offset(),
            collection_resource,
        )?;
        decoder.charge_semantic_repeated_items(1, MAX_TOTAL_REPEATED_ITEMS, field.offset())?;
        if counts_as_any_value {
            decoder.enter_semantic_any_value(
                true,
                MAX_TOTAL_ANY_VALUE_NODES,
                MAX_ANY_VALUE_DEPTH,
                field.offset(),
            )?;
        }
        let mut value = M::default();
        let result = merge_nested_message(&mut value, field, decoder);
        if counts_as_any_value {
            decoder.leave_semantic_any_value();
        }
        result?;
        target
            .try_reserve(1)
            .map_err(|_| allocation_failed(field.offset(), collection_resource, 1))?;
        target.push(value);
        Ok(())
    }

    pub(super) fn merge_optional_message<'wire, M>(
        target: &mut Option<M>,
        field: &ProtobufWireField<'wire>,
        decoder: &mut ProtobufWireDecoder<'wire, '_>,
        counts_as_any_value: bool,
    ) -> Result<(), ProtobufWireError>
    where
        M: ProtoMessage,
    {
        if counts_as_any_value {
            decoder.enter_semantic_any_value(
                target.is_none(),
                MAX_TOTAL_ANY_VALUE_NODES,
                MAX_ANY_VALUE_DEPTH,
                field.offset(),
            )?;
        }
        let result = if let Some(value) = target {
            merge_nested_message(value, field, decoder)
        } else {
            let mut value = M::default();
            merge_nested_message(&mut value, field, decoder).map(|()| {
                *target = Some(value);
            })
        };
        if counts_as_any_value {
            decoder.leave_semantic_any_value();
        }
        result
    }

    pub(super) fn encode_nested<M: OtlpModel>(
        encoder: &mut ProtobufWireEncoder,
        field_number: u32,
        value: &M,
    ) -> Result<(), ProtobufWireError> {
        encoder.write_nested_message(field_number, |nested| value.encode_fields_unchecked(nested))
    }

    pub(super) fn preserve_unknown<'wire>(
        unknown: &mut UnknownFields,
        field: &ProtobufWireField<'wire>,
        decoder: &mut ProtobufWireDecoder<'wire, '_>,
    ) -> Result<(), ProtobufWireError> {
        let raw = if field.wire_type() == WireType::StartGroup {
            decoder.skip_group(field)?
        } else {
            field.raw()
        };
        decoder.charge_semantic_owned_bytes(raw.len(), MAX_TOTAL_OWNED_BYTES, field.offset())?;
        decoder.charge_additional_work(raw.len(), field.offset())?;
        unknown.try_record_raw(raw)
    }

    pub(super) fn validate_unknown(
        unknown: &UnknownFields,
        budget: &mut ValidationBudget,
    ) -> Result<(), ProtobufWireError> {
        budget.owned_bytes(unknown.len(), MAX_TOTAL_OWNED_BYTES, "unknown field bytes")
    }

    pub(super) fn validate_unique_keys(
        keys: &[super::common_and_resource::KeyValue],
        budget: &mut ValidationBudget,
        invariant: &'static str,
    ) -> Result<(), ProtobufWireError> {
        if !budget.enforces_invariants() {
            return Ok(());
        }
        let key_bytes = keys
            .iter()
            .fold(0usize, |total, key| total.saturating_add(key.key.len()));
        let comparison_work = key_bytes.saturating_mul(keys.len().saturating_sub(1));
        budget.work(comparison_work)?;
        for (index, key) in keys.iter().enumerate() {
            for prior in &keys[..index] {
                if prior.key == key.key {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: 0,
                        invariant,
                    });
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_entity_ref_keys(
        attributes: &[super::common_and_resource::KeyValue],
        entity_refs: &[super::common_and_resource::EntityRef],
        budget: &mut ValidationBudget,
    ) -> Result<(), ProtobufWireError> {
        if !budget.enforces_invariants() {
            return Ok(());
        }
        let attribute_key_bytes = attributes.iter().fold(0usize, |total, attribute| {
            total.saturating_add(attribute.key.len())
        });
        let (referenced_key_count, referenced_key_bytes) = entity_refs
            .iter()
            .flat_map(|entity_ref| {
                entity_ref
                    .id_keys
                    .iter()
                    .chain(&entity_ref.description_keys)
            })
            .fold((0usize, 0usize), |(count, bytes), key| {
                (count.saturating_add(1), bytes.saturating_add(key.len()))
            });
        let comparison_work = attribute_key_bytes
            .saturating_mul(referenced_key_count)
            .saturating_add(referenced_key_bytes.saturating_mul(attributes.len()));
        budget.work(comparison_work)?;

        for entity_ref in entity_refs {
            for key in entity_ref
                .id_keys
                .iter()
                .chain(&entity_ref.description_keys)
            {
                if !attributes.iter().any(|attribute| attribute.key == *key) {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: 0,
                        invariant: "EntityRef keys must reference Resource attributes",
                    });
                }
            }
        }
        Ok(())
    }
}

pub(crate) mod common_and_resource {
    use super::limits_and_error::{
        MAX_ANY_VALUE_ITEMS, MAX_ATTRIBUTE_KEY_BYTES, MAX_ATTRIBUTE_VALUE_BYTES, MAX_ATTRIBUTES,
        MAX_ENTITY_REF_KEYS, MAX_ENTITY_REFS, MAX_SCHEMA_URL_BYTES, MAX_SCOPE_NAME_BYTES,
        MAX_SCOPE_VERSION_BYTES, MAX_TOTAL_OWNED_BYTES, OtlpModel, ValidationBudget, decode_bytes,
        decode_string, encode_nested, merge_optional_message, merge_root, preserve_unknown,
        push_message, push_string, validate_entity_ref_keys, validate_root, validate_unique_keys,
        validate_unknown,
    };
    use super::{
        ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError,
        ProtobufWireField, ProtobufWireLimits, UnknownFields, merge_nested_message,
    };

    macro_rules! impl_proto_message {
        ($type:ty) => {
            impl ProtoMessage for $type {
                fn encode_fields(
                    &self,
                    encoder: &mut ProtobufWireEncoder,
                ) -> Result<(), ProtobufWireError> {
                    let remaining_work = encoder.remaining_work()?;
                    let validation = validate_root(self, remaining_work, true)?;
                    encoder.charge_schema_work(validation.work_used)?;
                    self.encode_fields_unchecked(encoder)
                }

                fn merge_field<'wire>(
                    &mut self,
                    field: &ProtobufWireField<'wire>,
                    decoder: &mut ProtobufWireDecoder<'wire, '_>,
                ) -> Result<bool, ProtobufWireError> {
                    self.merge_otlp_field(field, decoder)
                }

                fn merge_from_bytes(
                    &mut self,
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<(), ProtobufWireError> {
                    // The merge API is explicitly non-atomic. Its validated
                    // existing budget is seeded before any new allocation, so
                    // a failed merge may retain accepted prefix fields but can
                    // never grow the model beyond its aggregate bounds.
                    merge_root(self, input, limits)
                }

                fn decode_from_bytes(
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<Self, ProtobufWireError> {
                    let mut staged = Self::default();
                    merge_root(&mut staged, input, limits)?;
                    Ok(staged)
                }
            }
        };
    }

    #[derive(Clone, Debug, PartialEq)]
    pub(crate) enum AnyValueValue {
        String(String),
        Bool(bool),
        Int(i64),
        Double(f64),
        Array(ArrayValue),
        KeyValueList(KeyValueList),
        Bytes(Vec<u8>),
        StringIndex(i32),
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct AnyValue {
        pub(crate) value: Option<AnyValueValue>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for AnyValue {
        const COUNTS_AS_ANY_VALUE: bool = true;

        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            match &self.value {
                Some(AnyValueValue::String(value)) => encoder.write_string(1, value)?,
                Some(AnyValueValue::Bool(value)) => encoder.write_bool(2, *value)?,
                Some(AnyValueValue::Int(value)) => encoder.write_int64(3, *value)?,
                Some(AnyValueValue::Double(value)) => encoder.write_double(4, *value)?,
                Some(AnyValueValue::Array(value)) => encode_nested(encoder, 5, value)?,
                Some(AnyValueValue::KeyValueList(value)) => encode_nested(encoder, 6, value)?,
                Some(AnyValueValue::Bytes(value)) => encoder.write_bytes(7, value)?,
                Some(AnyValueValue::StringIndex(value)) => encoder.write_int32(8, *value)?,
                None => {}
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => {
                    self.value = Some(AnyValueValue::String(decode_string(
                        field,
                        decoder,
                        MAX_ATTRIBUTE_VALUE_BYTES,
                        "AnyValue string bytes",
                    )?));
                }
                2 => self.value = Some(AnyValueValue::Bool(field.as_varint()? != 0)),
                3 => self.value = Some(AnyValueValue::Int(field.as_varint()?.cast_signed())),
                4 => {
                    self.value = Some(AnyValueValue::Double(f64::from_bits(field.as_fixed64()?)));
                }
                5 => match &mut self.value {
                    Some(AnyValueValue::Array(value)) => {
                        merge_nested_message(value, field, decoder)?;
                    }
                    _ => {
                        let mut value = ArrayValue::default();
                        merge_nested_message(&mut value, field, decoder)?;
                        self.value = Some(AnyValueValue::Array(value));
                    }
                },
                6 => match &mut self.value {
                    Some(AnyValueValue::KeyValueList(value)) => {
                        merge_nested_message(value, field, decoder)?;
                    }
                    _ => {
                        let mut value = KeyValueList::default();
                        merge_nested_message(&mut value, field, decoder)?;
                        self.value = Some(AnyValueValue::KeyValueList(value));
                    }
                },
                7 => {
                    self.value = Some(AnyValueValue::Bytes(decode_bytes(
                        field,
                        decoder,
                        MAX_ATTRIBUTE_VALUE_BYTES,
                        "AnyValue bytes payload",
                    )?));
                }
                8 => {
                    self.value = Some(AnyValueValue::StringIndex(
                        (field.as_varint()? as u32).cast_signed(),
                    ));
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            budget.any_value_node(any_value_depth.max(1))?;
            match &self.value {
                Some(AnyValueValue::String(value)) => budget.owned_bytes(
                    value.len(),
                    MAX_ATTRIBUTE_VALUE_BYTES,
                    "AnyValue string bytes",
                )?,
                Some(AnyValueValue::Array(value)) => {
                    value.validate_otlp(budget, any_value_depth.max(1))?;
                }
                Some(AnyValueValue::KeyValueList(value)) => {
                    value.validate_otlp(budget, any_value_depth.max(1))?;
                }
                Some(AnyValueValue::Bytes(value)) => budget.owned_bytes(
                    value.len(),
                    MAX_ATTRIBUTE_VALUE_BYTES,
                    "AnyValue bytes payload",
                )?,
                Some(
                    AnyValueValue::Bool(_)
                    | AnyValueValue::Int(_)
                    | AnyValueValue::Double(_)
                    | AnyValueValue::StringIndex(_),
                )
                | None => {}
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(AnyValue);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ArrayValue {
        pub(crate) values: Vec<AnyValue>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ArrayValue {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for value in &self.values {
                encode_nested(encoder, 1, value)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            if field.field_number() == 1 {
                push_message(
                    &mut self.values,
                    field,
                    decoder,
                    MAX_ANY_VALUE_ITEMS,
                    "AnyValue array items",
                    true,
                )?;
            } else {
                preserve_unknown(&mut self.unknown_fields, field, decoder)?;
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            budget.repeated(
                self.values.len(),
                MAX_ANY_VALUE_ITEMS,
                "AnyValue array items",
            )?;
            for value in &self.values {
                value.validate_otlp(budget, any_value_depth.saturating_add(1))?;
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ArrayValue);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct KeyValueList {
        pub(crate) values: Vec<KeyValue>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for KeyValueList {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for value in &self.values {
                encode_nested(encoder, 1, value)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            if field.field_number() == 1 {
                push_message(
                    &mut self.values,
                    field,
                    decoder,
                    MAX_ANY_VALUE_ITEMS,
                    "AnyValue kvlist items",
                    false,
                )?;
            } else {
                preserve_unknown(&mut self.unknown_fields, field, decoder)?;
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            budget.repeated(
                self.values.len(),
                MAX_ANY_VALUE_ITEMS,
                "AnyValue kvlist items",
            )?;
            validate_unique_keys(&self.values, budget, "AnyValue kvlist keys must be unique")?;
            for value in &self.values {
                value.validate_otlp(budget, any_value_depth)?;
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(KeyValueList);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct KeyValue {
        pub(crate) key: String,
        pub(crate) value: Option<AnyValue>,
        pub(crate) key_strindex: i32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for KeyValue {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if !self.key.is_empty() {
                encoder.write_string(1, &self.key)?;
            }
            if let Some(value) = &self.value {
                encode_nested(encoder, 2, value)?;
            }
            if self.key_strindex != 0 {
                encoder.write_int32(3, self.key_strindex)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => {
                    self.key = decode_string(
                        field,
                        decoder,
                        MAX_ATTRIBUTE_KEY_BYTES,
                        "attribute key bytes",
                    )?;
                }
                2 => merge_optional_message(&mut self.value, field, decoder, true)?,
                3 => self.key_strindex = (field.as_varint()? as u32).cast_signed(),
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if budget.enforces_invariants() && !self.key.is_empty() && self.key_strindex != 0 {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "KeyValue key and key_strindex are mutually exclusive",
                });
            }
            budget.owned_bytes(
                self.key.len(),
                MAX_ATTRIBUTE_KEY_BYTES,
                "attribute key bytes",
            )?;
            if let Some(value) = &self.value {
                let depth = if any_value_depth == 0 {
                    1
                } else {
                    any_value_depth.saturating_add(1)
                };
                value.validate_otlp(budget, depth)?;
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(KeyValue);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct InstrumentationScope {
        pub(crate) name: String,
        pub(crate) version: String,
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) dropped_attributes_count: u32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for InstrumentationScope {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if !self.name.is_empty() {
                encoder.write_string(1, &self.name)?;
            }
            if !self.version.is_empty() {
                encoder.write_string(2, &self.version)?;
            }
            for attribute in &self.attributes {
                encode_nested(encoder, 3, attribute)?;
            }
            if self.dropped_attributes_count != 0 {
                encoder.write_varint(4, u64::from(self.dropped_attributes_count))?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => {
                    self.name = decode_string(
                        field,
                        decoder,
                        MAX_SCOPE_NAME_BYTES,
                        "instrumentation scope name bytes",
                    )?;
                }
                2 => {
                    self.version = decode_string(
                        field,
                        decoder,
                        MAX_SCOPE_VERSION_BYTES,
                        "instrumentation scope version bytes",
                    )?;
                }
                3 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "instrumentation scope attributes",
                    false,
                )?,
                4 => self.dropped_attributes_count = field.as_varint()? as u32,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            budget.owned_bytes(
                self.name.len(),
                MAX_SCOPE_NAME_BYTES,
                "instrumentation scope name bytes",
            )?;
            budget.owned_bytes(
                self.version.len(),
                MAX_SCOPE_VERSION_BYTES,
                "instrumentation scope version bytes",
            )?;
            budget.repeated(
                self.attributes.len(),
                MAX_ATTRIBUTES,
                "instrumentation scope attributes",
            )?;
            validate_unique_keys(
                &self.attributes,
                budget,
                "instrumentation scope attribute keys must be unique",
            )?;
            for attribute in &self.attributes {
                attribute.validate_otlp(budget, 0)?;
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(InstrumentationScope);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct EntityRef {
        pub(crate) schema_url: String,
        pub(crate) r#type: String,
        pub(crate) id_keys: Vec<String>,
        pub(crate) description_keys: Vec<String>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for EntityRef {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if !self.schema_url.is_empty() {
                encoder.write_string(1, &self.schema_url)?;
            }
            if !self.r#type.is_empty() {
                encoder.write_string(2, &self.r#type)?;
            }
            for key in &self.id_keys {
                encoder.write_string(3, key)?;
            }
            for key in &self.description_keys {
                encoder.write_string(4, key)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => {
                    self.schema_url = decode_string(
                        field,
                        decoder,
                        MAX_SCHEMA_URL_BYTES,
                        "entity schema URL bytes",
                    )?;
                }
                2 => {
                    self.r#type =
                        decode_string(field, decoder, MAX_TOTAL_OWNED_BYTES, "entity type bytes")?;
                }
                3 => push_string(
                    &mut self.id_keys,
                    field,
                    decoder,
                    MAX_ENTITY_REF_KEYS,
                    MAX_ATTRIBUTE_KEY_BYTES,
                    "entity id keys",
                    "entity id key bytes",
                )?,
                4 => push_string(
                    &mut self.description_keys,
                    field,
                    decoder,
                    MAX_ENTITY_REF_KEYS,
                    MAX_ATTRIBUTE_KEY_BYTES,
                    "entity description keys",
                    "entity description key bytes",
                )?,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if budget.enforces_invariants() && self.r#type.is_empty() {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "EntityRef type must be nonempty",
                });
            }
            if budget.enforces_invariants() && self.id_keys.is_empty() {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "EntityRef id_keys must not be empty",
                });
            }
            budget.owned_bytes(
                self.schema_url.len(),
                MAX_SCHEMA_URL_BYTES,
                "entity schema URL bytes",
            )?;
            budget.owned_bytes(
                self.r#type.len(),
                MAX_TOTAL_OWNED_BYTES,
                "entity type bytes",
            )?;
            budget.repeated(self.id_keys.len(), MAX_ENTITY_REF_KEYS, "entity id keys")?;
            for key in &self.id_keys {
                budget.owned_bytes(key.len(), MAX_ATTRIBUTE_KEY_BYTES, "entity id key bytes")?;
            }
            budget.repeated(
                self.description_keys.len(),
                MAX_ENTITY_REF_KEYS,
                "entity description keys",
            )?;
            for key in &self.description_keys {
                budget.owned_bytes(
                    key.len(),
                    MAX_ATTRIBUTE_KEY_BYTES,
                    "entity description key bytes",
                )?;
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(EntityRef);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct Resource {
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) dropped_attributes_count: u32,
        pub(crate) entity_refs: Vec<EntityRef>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for Resource {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for attribute in &self.attributes {
                encode_nested(encoder, 1, attribute)?;
            }
            if self.dropped_attributes_count != 0 {
                encoder.write_varint(2, u64::from(self.dropped_attributes_count))?;
            }
            for entity_ref in &self.entity_refs {
                encode_nested(encoder, 3, entity_ref)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "resource attributes",
                    false,
                )?,
                2 => self.dropped_attributes_count = field.as_varint()? as u32,
                3 => push_message(
                    &mut self.entity_refs,
                    field,
                    decoder,
                    MAX_ENTITY_REFS,
                    "resource entity refs",
                    false,
                )?,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            budget.repeated(self.attributes.len(), MAX_ATTRIBUTES, "resource attributes")?;
            validate_unique_keys(
                &self.attributes,
                budget,
                "resource attribute keys must be unique",
            )?;
            for attribute in &self.attributes {
                attribute.validate_otlp(budget, 0)?;
            }
            budget.repeated(
                self.entity_refs.len(),
                MAX_ENTITY_REFS,
                "resource entity refs",
            )?;
            for entity_ref in &self.entity_refs {
                entity_ref.validate_otlp(budget, 0)?;
            }
            validate_entity_ref_keys(&self.attributes, &self.entity_refs, budget)?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(Resource);
}

pub(crate) mod metrics {
    use super::common_and_resource::{InstrumentationScope, KeyValue, Resource};
    use super::limits_and_error::{
        MAX_ATTRIBUTES, MAX_DATA_POINTS_PER_METRIC, MAX_EXEMPLARS_PER_DATA_POINT,
        MAX_EXPONENTIAL_HISTOGRAM_BUCKETS, MAX_HISTOGRAM_BUCKET_COUNTS,
        MAX_HISTOGRAM_EXPLICIT_BOUNDS, MAX_METRIC_DESCRIPTION_BYTES, MAX_METRIC_METADATA_ENTRIES,
        MAX_METRIC_NAME_BYTES, MAX_METRIC_UNIT_BYTES, MAX_METRICS_PER_SCOPE,
        MAX_RESOURCE_GROUPS_PER_REQUEST, MAX_SCHEMA_URL_BYTES, MAX_SCOPES_PER_RESOURCE_GROUP,
        MAX_SPAN_ID_BYTES, MAX_SUMMARY_QUANTILES, MAX_TOTAL_REPEATED_ITEMS, MAX_TRACE_ID_BYTES,
        OtlpModel, ValidationBudget, allocation_failed, collection_room,
        decode_exact_or_empty_bytes, decode_string, encode_nested, merge_optional_message,
        merge_root, preserve_unknown, push_message, validate_root, validate_unique_keys,
        validate_unknown,
    };
    use super::{
        ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError,
        ProtobufWireField, ProtobufWireLimits, UnknownFields, WireType, decode_varint,
        merge_nested_message, zigzag_decode_i32,
    };

    macro_rules! impl_proto_message {
        ($type:ty) => {
            impl ProtoMessage for $type {
                fn encode_fields(
                    &self,
                    encoder: &mut ProtobufWireEncoder,
                ) -> Result<(), ProtobufWireError> {
                    let remaining_work = encoder.remaining_work()?;
                    let validation = validate_root(self, remaining_work, true)?;
                    encoder.charge_schema_work(validation.work_used)?;
                    self.encode_fields_unchecked(encoder)
                }

                fn merge_field<'wire>(
                    &mut self,
                    field: &ProtobufWireField<'wire>,
                    decoder: &mut ProtobufWireDecoder<'wire, '_>,
                ) -> Result<bool, ProtobufWireError> {
                    self.merge_otlp_field(field, decoder)
                }

                fn merge_from_bytes(
                    &mut self,
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<(), ProtobufWireError> {
                    merge_root(self, input, limits)
                }

                fn decode_from_bytes(
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<Self, ProtobufWireError> {
                    let mut staged = Self::default();
                    merge_root(&mut staged, input, limits)?;
                    Ok(staged)
                }
            }
        };
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i32)]
    pub(crate) enum AggregationTemporality {
        Unspecified = 0,
        Delta = 1,
        Cumulative = 2,
    }

    impl AggregationTemporality {
        pub(crate) const fn from_raw(value: i32) -> Option<Self> {
            match value {
                0 => Some(Self::Unspecified),
                1 => Some(Self::Delta),
                2 => Some(Self::Cumulative),
                _ => None,
            }
        }

        pub(crate) const fn as_raw(self) -> i32 {
            self as i32
        }
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct DataPointFlags(u32);

    impl DataPointFlags {
        pub(crate) const DO_NOT_USE: Self = Self(0);
        pub(crate) const NO_RECORDED_VALUE_MASK: Self = Self(1);

        pub(crate) const fn from_bits_retain(bits: u32) -> Self {
            Self(bits)
        }

        pub(crate) const fn bits(self) -> u32 {
            self.0
        }

        pub(crate) const fn contains(self, mask: Self) -> bool {
            self.0 & mask.0 == mask.0
        }
    }

    fn packed_varint(
        input: &[u8],
        absolute_offset: usize,
    ) -> Result<(u64, usize), ProtobufWireError> {
        decode_varint(input).map_err(|error| match error {
            ProtobufWireError::UnexpectedEof {
                offset,
                needed,
                remaining,
            } => ProtobufWireError::UnexpectedEof {
                offset: absolute_offset.saturating_add(offset),
                needed,
                remaining,
            },
            ProtobufWireError::VarintOverflow { offset } => ProtobufWireError::VarintOverflow {
                offset: absolute_offset.saturating_add(offset),
            },
            other => other,
        })
    }

    fn push_repeated_fixed64<T, F>(
        target: &mut Vec<T>,
        field: &ProtobufWireField<'_>,
        decoder: &mut ProtobufWireDecoder<'_, '_>,
        collection_limit: usize,
        resource: &'static str,
        map: F,
    ) -> Result<(), ProtobufWireError>
    where
        F: Fn(u64) -> T,
    {
        match field.wire_type() {
            WireType::Fixed64 => {
                collection_room(target.len(), 1, collection_limit, field.offset(), resource)?;
                decoder.charge_semantic_repeated_items(
                    1,
                    MAX_TOTAL_REPEATED_ITEMS,
                    field.offset(),
                )?;
                let value = map(field.as_fixed64()?);
                target
                    .try_reserve(1)
                    .map_err(|_| allocation_failed(field.offset(), resource, 1))?;
                target.push(value);
            }
            WireType::LengthDelimited => {
                let bytes = field.as_bytes()?;
                let (chunks, remainder) = bytes.as_chunks::<8>();
                if !remainder.is_empty() {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: field.value_offset(),
                        invariant: "packed fixed64 payload length must be divisible by eight",
                    });
                }
                let count = chunks.len();
                collection_room(
                    target.len(),
                    count,
                    collection_limit,
                    field.offset(),
                    resource,
                )?;
                decoder.charge_semantic_repeated_items(
                    count,
                    MAX_TOTAL_REPEATED_ITEMS,
                    field.offset(),
                )?;
                decoder.charge_additional_work(bytes.len(), field.value_offset())?;
                target
                    .try_reserve(count)
                    .map_err(|_| allocation_failed(field.offset(), resource, count))?;
                target.extend(chunks.iter().map(|chunk| map(u64::from_le_bytes(*chunk))));
            }
            actual => {
                return Err(ProtobufWireError::WireTypeMismatch {
                    offset: field.offset(),
                    expected: WireType::Fixed64,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn push_repeated_varints(
        target: &mut Vec<u64>,
        field: &ProtobufWireField<'_>,
        decoder: &mut ProtobufWireDecoder<'_, '_>,
        collection_limit: usize,
        resource: &'static str,
    ) -> Result<(), ProtobufWireError> {
        match field.wire_type() {
            WireType::Varint => {
                collection_room(target.len(), 1, collection_limit, field.offset(), resource)?;
                decoder.charge_semantic_repeated_items(
                    1,
                    MAX_TOTAL_REPEATED_ITEMS,
                    field.offset(),
                )?;
                let value = field.as_varint()?;
                target
                    .try_reserve(1)
                    .map_err(|_| allocation_failed(field.offset(), resource, 1))?;
                target.push(value);
            }
            WireType::LengthDelimited => {
                let bytes = field.as_bytes()?;
                let parse_work = bytes.len().saturating_mul(2);
                decoder.charge_additional_work(parse_work, field.value_offset())?;
                let mut consumed = 0usize;
                let mut count = 0usize;
                while consumed < bytes.len() {
                    let (_, length) = packed_varint(
                        &bytes[consumed..],
                        field.value_offset().saturating_add(consumed),
                    )?;
                    consumed = consumed.saturating_add(length);
                    count = count.saturating_add(1);
                }
                collection_room(
                    target.len(),
                    count,
                    collection_limit,
                    field.offset(),
                    resource,
                )?;
                decoder.charge_semantic_repeated_items(
                    count,
                    MAX_TOTAL_REPEATED_ITEMS,
                    field.offset(),
                )?;
                target
                    .try_reserve(count)
                    .map_err(|_| allocation_failed(field.offset(), resource, count))?;
                consumed = 0;
                while consumed < bytes.len() {
                    let (value, length) = packed_varint(
                        &bytes[consumed..],
                        field.value_offset().saturating_add(consumed),
                    )?;
                    target.push(value);
                    consumed += length;
                }
            }
            actual => {
                return Err(ProtobufWireError::WireTypeMismatch {
                    offset: field.offset(),
                    expected: WireType::Varint,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn validate_models<M: OtlpModel>(
        values: &[M],
        budget: &mut ValidationBudget,
        collection_limit: usize,
        resource: &'static str,
    ) -> Result<(), ProtobufWireError> {
        budget.repeated(values.len(), collection_limit, resource)?;
        for value in values {
            value.validate_otlp(budget, 0)?;
        }
        Ok(())
    }

    fn validate_attributes(
        attributes: &[KeyValue],
        budget: &mut ValidationBudget,
        resource: &'static str,
        invariant: &'static str,
    ) -> Result<(), ProtobufWireError> {
        budget.repeated(attributes.len(), MAX_ATTRIBUTES, resource)?;
        validate_unique_keys(attributes, budget, invariant)?;
        for attribute in attributes {
            attribute.validate_otlp(budget, 0)?;
        }
        Ok(())
    }

    fn validate_temporality(
        value: i32,
        budget: &ValidationBudget,
    ) -> Result<(), ProtobufWireError> {
        if budget.enforces_invariants()
            && AggregationTemporality::from_raw(value) == Some(AggregationTemporality::Unspecified)
        {
            return Err(ProtobufWireError::SchemaInvariant {
                offset: 0,
                invariant: "aggregation temporality must not be unspecified",
            });
        }
        Ok(())
    }

    fn validate_point_time(
        time_unix_nano: u64,
        budget: &ValidationBudget,
    ) -> Result<(), ProtobufWireError> {
        if budget.enforces_invariants() && time_unix_nano == 0 {
            return Err(ProtobufWireError::SchemaInvariant {
                offset: 0,
                invariant: "metric data point time_unix_nano must be nonzero",
            });
        }
        Ok(())
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct MetricsData {
        pub(crate) resource_metrics: Vec<ResourceMetrics>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for MetricsData {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for resource_metrics in &self.resource_metrics {
                encode_nested(encoder, 1, resource_metrics)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            if field.field_number() == 1 {
                push_message(
                    &mut self.resource_metrics,
                    field,
                    decoder,
                    MAX_RESOURCE_GROUPS_PER_REQUEST,
                    "metric resource groups",
                    false,
                )?;
            } else {
                preserve_unknown(&mut self.unknown_fields, field, decoder)?;
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_models(
                &self.resource_metrics,
                budget,
                MAX_RESOURCE_GROUPS_PER_REQUEST,
                "metric resource groups",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(MetricsData);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ResourceMetrics {
        pub(crate) resource: Option<Resource>,
        pub(crate) scope_metrics: Vec<ScopeMetrics>,
        pub(crate) schema_url: String,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ResourceMetrics {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if let Some(resource) = &self.resource {
                encode_nested(encoder, 1, resource)?;
            }
            for scope_metrics in &self.scope_metrics {
                encode_nested(encoder, 2, scope_metrics)?;
            }
            if !self.schema_url.is_empty() {
                encoder.write_string(3, &self.schema_url)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => merge_optional_message(&mut self.resource, field, decoder, false)?,
                2 => push_message(
                    &mut self.scope_metrics,
                    field,
                    decoder,
                    MAX_SCOPES_PER_RESOURCE_GROUP,
                    "metric scopes per resource group",
                    false,
                )?,
                3 => {
                    self.schema_url = decode_string(
                        field,
                        decoder,
                        MAX_SCHEMA_URL_BYTES,
                        "metric resource schema URL bytes",
                    )?;
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if let Some(resource) = &self.resource {
                resource.validate_otlp(budget, 0)?;
            }
            validate_models(
                &self.scope_metrics,
                budget,
                MAX_SCOPES_PER_RESOURCE_GROUP,
                "metric scopes per resource group",
            )?;
            budget.owned_bytes(
                self.schema_url.len(),
                MAX_SCHEMA_URL_BYTES,
                "metric resource schema URL bytes",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ResourceMetrics);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ScopeMetrics {
        pub(crate) scope: Option<InstrumentationScope>,
        pub(crate) metrics: Vec<Metric>,
        pub(crate) schema_url: String,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ScopeMetrics {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if let Some(scope) = &self.scope {
                encode_nested(encoder, 1, scope)?;
            }
            for metric in &self.metrics {
                encode_nested(encoder, 2, metric)?;
            }
            if !self.schema_url.is_empty() {
                encoder.write_string(3, &self.schema_url)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => merge_optional_message(&mut self.scope, field, decoder, false)?,
                2 => push_message(
                    &mut self.metrics,
                    field,
                    decoder,
                    MAX_METRICS_PER_SCOPE,
                    "metrics per scope",
                    false,
                )?,
                3 => {
                    self.schema_url = decode_string(
                        field,
                        decoder,
                        MAX_SCHEMA_URL_BYTES,
                        "metric scope schema URL bytes",
                    )?;
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if let Some(scope) = &self.scope {
                scope.validate_otlp(budget, 0)?;
            }
            validate_models(
                &self.metrics,
                budget,
                MAX_METRICS_PER_SCOPE,
                "metrics per scope",
            )?;
            budget.owned_bytes(
                self.schema_url.len(),
                MAX_SCHEMA_URL_BYTES,
                "metric scope schema URL bytes",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ScopeMetrics);

    #[derive(Clone, Debug, PartialEq)]
    pub(crate) enum MetricData {
        Gauge(Gauge),
        Sum(Sum),
        Histogram(Histogram),
        ExponentialHistogram(ExponentialHistogram),
        Summary(Summary),
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct Metric {
        pub(crate) name: String,
        pub(crate) description: String,
        pub(crate) unit: String,
        pub(crate) data: Option<MetricData>,
        pub(crate) metadata: Vec<KeyValue>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for Metric {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if !self.name.is_empty() {
                encoder.write_string(1, &self.name)?;
            }
            if !self.description.is_empty() {
                encoder.write_string(2, &self.description)?;
            }
            if !self.unit.is_empty() {
                encoder.write_string(3, &self.unit)?;
            }
            match &self.data {
                Some(MetricData::Gauge(value)) => encode_nested(encoder, 5, value)?,
                Some(MetricData::Sum(value)) => encode_nested(encoder, 7, value)?,
                Some(MetricData::Histogram(value)) => encode_nested(encoder, 9, value)?,
                Some(MetricData::ExponentialHistogram(value)) => {
                    encode_nested(encoder, 10, value)?;
                }
                Some(MetricData::Summary(value)) => encode_nested(encoder, 11, value)?,
                None => {}
            }
            for metadata in &self.metadata {
                encode_nested(encoder, 12, metadata)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => {
                    self.name =
                        decode_string(field, decoder, MAX_METRIC_NAME_BYTES, "metric name bytes")?;
                }
                2 => {
                    self.description = decode_string(
                        field,
                        decoder,
                        MAX_METRIC_DESCRIPTION_BYTES,
                        "metric description bytes",
                    )?;
                }
                3 => {
                    self.unit =
                        decode_string(field, decoder, MAX_METRIC_UNIT_BYTES, "metric unit bytes")?;
                }
                5 => match &mut self.data {
                    Some(MetricData::Gauge(value)) => {
                        merge_nested_message(value, field, decoder)?;
                    }
                    _ => {
                        let mut value = Gauge::default();
                        merge_nested_message(&mut value, field, decoder)?;
                        self.data = Some(MetricData::Gauge(value));
                    }
                },
                7 => match &mut self.data {
                    Some(MetricData::Sum(value)) => {
                        merge_nested_message(value, field, decoder)?;
                    }
                    _ => {
                        let mut value = Sum::default();
                        merge_nested_message(&mut value, field, decoder)?;
                        self.data = Some(MetricData::Sum(value));
                    }
                },
                9 => match &mut self.data {
                    Some(MetricData::Histogram(value)) => {
                        merge_nested_message(value, field, decoder)?;
                    }
                    _ => {
                        let mut value = Histogram::default();
                        merge_nested_message(&mut value, field, decoder)?;
                        self.data = Some(MetricData::Histogram(value));
                    }
                },
                10 => match &mut self.data {
                    Some(MetricData::ExponentialHistogram(value)) => {
                        merge_nested_message(value, field, decoder)?;
                    }
                    _ => {
                        let mut value = ExponentialHistogram::default();
                        merge_nested_message(&mut value, field, decoder)?;
                        self.data = Some(MetricData::ExponentialHistogram(value));
                    }
                },
                11 => match &mut self.data {
                    Some(MetricData::Summary(value)) => {
                        merge_nested_message(value, field, decoder)?;
                    }
                    _ => {
                        let mut value = Summary::default();
                        merge_nested_message(&mut value, field, decoder)?;
                        self.data = Some(MetricData::Summary(value));
                    }
                },
                12 => push_message(
                    &mut self.metadata,
                    field,
                    decoder,
                    MAX_METRIC_METADATA_ENTRIES,
                    "metric metadata entries",
                    false,
                )?,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            budget.owned_bytes(self.name.len(), MAX_METRIC_NAME_BYTES, "metric name bytes")?;
            budget.owned_bytes(
                self.description.len(),
                MAX_METRIC_DESCRIPTION_BYTES,
                "metric description bytes",
            )?;
            budget.owned_bytes(self.unit.len(), MAX_METRIC_UNIT_BYTES, "metric unit bytes")?;
            match &self.data {
                Some(MetricData::Gauge(value)) => value.validate_otlp(budget, 0)?,
                Some(MetricData::Sum(value)) => value.validate_otlp(budget, 0)?,
                Some(MetricData::Histogram(value)) => value.validate_otlp(budget, 0)?,
                Some(MetricData::ExponentialHistogram(value)) => {
                    value.validate_otlp(budget, 0)?;
                }
                Some(MetricData::Summary(value)) => value.validate_otlp(budget, 0)?,
                None => {}
            }
            budget.repeated(
                self.metadata.len(),
                MAX_METRIC_METADATA_ENTRIES,
                "metric metadata entries",
            )?;
            validate_unique_keys(
                &self.metadata,
                budget,
                "metric metadata keys must be unique",
            )?;
            for metadata in &self.metadata {
                metadata.validate_otlp(budget, 0)?;
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(Metric);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct Gauge {
        pub(crate) data_points: Vec<NumberDataPoint>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for Gauge {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for point in &self.data_points {
                encode_nested(encoder, 1, point)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            if field.field_number() == 1 {
                push_message(
                    &mut self.data_points,
                    field,
                    decoder,
                    MAX_DATA_POINTS_PER_METRIC,
                    "gauge data points",
                    false,
                )?;
            } else {
                preserve_unknown(&mut self.unknown_fields, field, decoder)?;
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_models(
                &self.data_points,
                budget,
                MAX_DATA_POINTS_PER_METRIC,
                "gauge data points",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(Gauge);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct Sum {
        pub(crate) data_points: Vec<NumberDataPoint>,
        pub(crate) aggregation_temporality: i32,
        pub(crate) is_monotonic: bool,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for Sum {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for point in &self.data_points {
                encode_nested(encoder, 1, point)?;
            }
            if self.aggregation_temporality != 0 {
                encoder.write_enum(2, self.aggregation_temporality)?;
            }
            if self.is_monotonic {
                encoder.write_bool(3, true)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => push_message(
                    &mut self.data_points,
                    field,
                    decoder,
                    MAX_DATA_POINTS_PER_METRIC,
                    "sum data points",
                    false,
                )?,
                2 => {
                    self.aggregation_temporality = (field.as_varint()? as u32).cast_signed();
                }
                3 => self.is_monotonic = field.as_varint()? != 0,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_models(
                &self.data_points,
                budget,
                MAX_DATA_POINTS_PER_METRIC,
                "sum data points",
            )?;
            validate_temporality(self.aggregation_temporality, budget)?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(Sum);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct Histogram {
        pub(crate) data_points: Vec<HistogramDataPoint>,
        pub(crate) aggregation_temporality: i32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for Histogram {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for point in &self.data_points {
                encode_nested(encoder, 1, point)?;
            }
            if self.aggregation_temporality != 0 {
                encoder.write_enum(2, self.aggregation_temporality)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => push_message(
                    &mut self.data_points,
                    field,
                    decoder,
                    MAX_DATA_POINTS_PER_METRIC,
                    "histogram data points",
                    false,
                )?,
                2 => {
                    self.aggregation_temporality = (field.as_varint()? as u32).cast_signed();
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_models(
                &self.data_points,
                budget,
                MAX_DATA_POINTS_PER_METRIC,
                "histogram data points",
            )?;
            validate_temporality(self.aggregation_temporality, budget)?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(Histogram);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ExponentialHistogram {
        pub(crate) data_points: Vec<ExponentialHistogramDataPoint>,
        pub(crate) aggregation_temporality: i32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ExponentialHistogram {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for point in &self.data_points {
                encode_nested(encoder, 1, point)?;
            }
            if self.aggregation_temporality != 0 {
                encoder.write_enum(2, self.aggregation_temporality)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => push_message(
                    &mut self.data_points,
                    field,
                    decoder,
                    MAX_DATA_POINTS_PER_METRIC,
                    "exponential histogram data points",
                    false,
                )?,
                2 => {
                    self.aggregation_temporality = (field.as_varint()? as u32).cast_signed();
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_models(
                &self.data_points,
                budget,
                MAX_DATA_POINTS_PER_METRIC,
                "exponential histogram data points",
            )?;
            validate_temporality(self.aggregation_temporality, budget)?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ExponentialHistogram);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct Summary {
        pub(crate) data_points: Vec<SummaryDataPoint>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for Summary {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for point in &self.data_points {
                encode_nested(encoder, 1, point)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            if field.field_number() == 1 {
                push_message(
                    &mut self.data_points,
                    field,
                    decoder,
                    MAX_DATA_POINTS_PER_METRIC,
                    "summary data points",
                    false,
                )?;
            } else {
                preserve_unknown(&mut self.unknown_fields, field, decoder)?;
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_models(
                &self.data_points,
                budget,
                MAX_DATA_POINTS_PER_METRIC,
                "summary data points",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(Summary);

    #[derive(Clone, Debug, PartialEq)]
    pub(crate) enum NumberDataPointValue {
        Double(f64),
        Int(i64),
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct NumberDataPoint {
        pub(crate) start_time_unix_nano: u64,
        pub(crate) time_unix_nano: u64,
        pub(crate) value: Option<NumberDataPointValue>,
        pub(crate) exemplars: Vec<Exemplar>,
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) flags: u32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for NumberDataPoint {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if self.start_time_unix_nano != 0 {
                encoder.write_fixed64(2, self.start_time_unix_nano)?;
            }
            if self.time_unix_nano != 0 {
                encoder.write_fixed64(3, self.time_unix_nano)?;
            }
            if let Some(NumberDataPointValue::Double(value)) = &self.value {
                encoder.write_double(4, *value)?;
            }
            for exemplar in &self.exemplars {
                encode_nested(encoder, 5, exemplar)?;
            }
            if let Some(NumberDataPointValue::Int(value)) = &self.value {
                encoder.write_fixed64(6, value.cast_unsigned())?;
            }
            for attribute in &self.attributes {
                encode_nested(encoder, 7, attribute)?;
            }
            if self.flags != 0 {
                encoder.write_varint(8, u64::from(self.flags))?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                2 => self.start_time_unix_nano = field.as_fixed64()?,
                3 => self.time_unix_nano = field.as_fixed64()?,
                4 => {
                    self.value = Some(NumberDataPointValue::Double(f64::from_bits(
                        field.as_fixed64()?,
                    )));
                }
                5 => push_message(
                    &mut self.exemplars,
                    field,
                    decoder,
                    MAX_EXEMPLARS_PER_DATA_POINT,
                    "number data point exemplars",
                    false,
                )?,
                6 => {
                    self.value = Some(NumberDataPointValue::Int(field.as_fixed64()?.cast_signed()));
                }
                7 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "number data point attributes",
                    false,
                )?,
                8 => self.flags = field.as_varint()? as u32,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if budget.enforces_invariants() && self.value.is_none() {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "number data point must contain a recognized value",
                });
            }
            validate_point_time(self.time_unix_nano, budget)?;
            validate_models(
                &self.exemplars,
                budget,
                MAX_EXEMPLARS_PER_DATA_POINT,
                "number data point exemplars",
            )?;
            validate_attributes(
                &self.attributes,
                budget,
                "number data point attributes",
                "number data point attribute keys must be unique",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(NumberDataPoint);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct HistogramDataPoint {
        pub(crate) start_time_unix_nano: u64,
        pub(crate) time_unix_nano: u64,
        pub(crate) count: u64,
        pub(crate) sum: Option<f64>,
        pub(crate) bucket_counts: Vec<u64>,
        pub(crate) explicit_bounds: Vec<f64>,
        pub(crate) exemplars: Vec<Exemplar>,
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) flags: u32,
        pub(crate) min: Option<f64>,
        pub(crate) max: Option<f64>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for HistogramDataPoint {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if self.start_time_unix_nano != 0 {
                encoder.write_fixed64(2, self.start_time_unix_nano)?;
            }
            if self.time_unix_nano != 0 {
                encoder.write_fixed64(3, self.time_unix_nano)?;
            }
            if self.count != 0 {
                encoder.write_fixed64(4, self.count)?;
            }
            if let Some(sum) = self.sum {
                encoder.write_double(5, sum)?;
            }
            if !self.bucket_counts.is_empty() {
                encoder.write_packed_fixed64(6, &self.bucket_counts)?;
            }
            if !self.explicit_bounds.is_empty() {
                encoder.write_packed_doubles(7, &self.explicit_bounds)?;
            }
            for exemplar in &self.exemplars {
                encode_nested(encoder, 8, exemplar)?;
            }
            for attribute in &self.attributes {
                encode_nested(encoder, 9, attribute)?;
            }
            if self.flags != 0 {
                encoder.write_varint(10, u64::from(self.flags))?;
            }
            if let Some(min) = self.min {
                encoder.write_double(11, min)?;
            }
            if let Some(max) = self.max {
                encoder.write_double(12, max)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                2 => self.start_time_unix_nano = field.as_fixed64()?,
                3 => self.time_unix_nano = field.as_fixed64()?,
                4 => self.count = field.as_fixed64()?,
                5 => self.sum = Some(f64::from_bits(field.as_fixed64()?)),
                6 => push_repeated_fixed64(
                    &mut self.bucket_counts,
                    field,
                    decoder,
                    MAX_HISTOGRAM_BUCKET_COUNTS,
                    "histogram bucket counts",
                    |value| value,
                )?,
                7 => push_repeated_fixed64(
                    &mut self.explicit_bounds,
                    field,
                    decoder,
                    MAX_HISTOGRAM_EXPLICIT_BOUNDS,
                    "histogram explicit bounds",
                    f64::from_bits,
                )?,
                8 => push_message(
                    &mut self.exemplars,
                    field,
                    decoder,
                    MAX_EXEMPLARS_PER_DATA_POINT,
                    "histogram exemplars",
                    false,
                )?,
                9 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "histogram attributes",
                    false,
                )?,
                10 => self.flags = field.as_varint()? as u32,
                11 => self.min = Some(f64::from_bits(field.as_fixed64()?)),
                12 => self.max = Some(f64::from_bits(field.as_fixed64()?)),
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_point_time(self.time_unix_nano, budget)?;
            budget.repeated(
                self.bucket_counts.len(),
                MAX_HISTOGRAM_BUCKET_COUNTS,
                "histogram bucket counts",
            )?;
            budget.repeated(
                self.explicit_bounds.len(),
                MAX_HISTOGRAM_EXPLICIT_BOUNDS,
                "histogram explicit bounds",
            )?;
            let numeric_work = self
                .bucket_counts
                .len()
                .saturating_add(self.explicit_bounds.len());
            budget.work(numeric_work)?;
            if budget.enforces_invariants() {
                let shape_matches = if self.bucket_counts.is_empty() {
                    self.explicit_bounds.is_empty()
                } else {
                    self.explicit_bounds
                        .len()
                        .checked_add(1)
                        .is_some_and(|expected| self.bucket_counts.len() == expected)
                };
                if !shape_matches {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: 0,
                        invariant: "histogram buckets must match explicit bounds",
                    });
                }
                if self
                    .explicit_bounds
                    .windows(2)
                    .any(|pair| pair[0].partial_cmp(&pair[1]) != Some(std::cmp::Ordering::Less))
                {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: 0,
                        invariant: "histogram explicit bounds must be strictly increasing",
                    });
                }
                if !self.bucket_counts.is_empty() {
                    let Some(bucket_total) = self
                        .bucket_counts
                        .iter()
                        .try_fold(0u64, |total, value| total.checked_add(*value))
                    else {
                        return Err(ProtobufWireError::SchemaInvariant {
                            offset: 0,
                            invariant: "histogram bucket count sum must fit u64",
                        });
                    };
                    if bucket_total != self.count {
                        return Err(ProtobufWireError::SchemaInvariant {
                            offset: 0,
                            invariant: "histogram count must equal bucket count sum",
                        });
                    }
                }
                if self.count == 0 && self.sum.is_some_and(|sum| sum != 0.0) {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: 0,
                        invariant: "histogram sum must be zero when count is zero",
                    });
                }
            }
            validate_models(
                &self.exemplars,
                budget,
                MAX_EXEMPLARS_PER_DATA_POINT,
                "histogram exemplars",
            )?;
            validate_attributes(
                &self.attributes,
                budget,
                "histogram attributes",
                "histogram attribute keys must be unique",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(HistogramDataPoint);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ExponentialHistogramBuckets {
        pub(crate) offset: i32,
        pub(crate) bucket_counts: Vec<u64>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ExponentialHistogramBuckets {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if self.offset != 0 {
                encoder.write_sint32(1, self.offset)?;
            }
            if !self.bucket_counts.is_empty() {
                encoder.write_packed_varints(2, &self.bucket_counts)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => self.offset = zigzag_decode_i32(field.as_varint()? as u32),
                2 => push_repeated_varints(
                    &mut self.bucket_counts,
                    field,
                    decoder,
                    MAX_EXPONENTIAL_HISTOGRAM_BUCKETS,
                    "exponential histogram buckets per sign",
                )?,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            budget.repeated(
                self.bucket_counts.len(),
                MAX_EXPONENTIAL_HISTOGRAM_BUCKETS,
                "exponential histogram buckets per sign",
            )?;
            budget.work(self.bucket_counts.len())?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ExponentialHistogramBuckets);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ExponentialHistogramDataPoint {
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) start_time_unix_nano: u64,
        pub(crate) time_unix_nano: u64,
        pub(crate) count: u64,
        pub(crate) sum: Option<f64>,
        pub(crate) scale: i32,
        pub(crate) zero_count: u64,
        pub(crate) positive: Option<ExponentialHistogramBuckets>,
        pub(crate) negative: Option<ExponentialHistogramBuckets>,
        pub(crate) flags: u32,
        pub(crate) exemplars: Vec<Exemplar>,
        pub(crate) min: Option<f64>,
        pub(crate) max: Option<f64>,
        pub(crate) zero_threshold: f64,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ExponentialHistogramDataPoint {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for attribute in &self.attributes {
                encode_nested(encoder, 1, attribute)?;
            }
            if self.start_time_unix_nano != 0 {
                encoder.write_fixed64(2, self.start_time_unix_nano)?;
            }
            if self.time_unix_nano != 0 {
                encoder.write_fixed64(3, self.time_unix_nano)?;
            }
            if self.count != 0 {
                encoder.write_fixed64(4, self.count)?;
            }
            if let Some(sum) = self.sum {
                encoder.write_double(5, sum)?;
            }
            if self.scale != 0 {
                encoder.write_sint32(6, self.scale)?;
            }
            if self.zero_count != 0 {
                encoder.write_fixed64(7, self.zero_count)?;
            }
            if let Some(positive) = &self.positive {
                encode_nested(encoder, 8, positive)?;
            }
            if let Some(negative) = &self.negative {
                encode_nested(encoder, 9, negative)?;
            }
            if self.flags != 0 {
                encoder.write_varint(10, u64::from(self.flags))?;
            }
            for exemplar in &self.exemplars {
                encode_nested(encoder, 11, exemplar)?;
            }
            if let Some(min) = self.min {
                encoder.write_double(12, min)?;
            }
            if let Some(max) = self.max {
                encoder.write_double(13, max)?;
            }
            if self.zero_threshold != 0.0 {
                encoder.write_double(14, self.zero_threshold)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "exponential histogram attributes",
                    false,
                )?,
                2 => self.start_time_unix_nano = field.as_fixed64()?,
                3 => self.time_unix_nano = field.as_fixed64()?,
                4 => self.count = field.as_fixed64()?,
                5 => self.sum = Some(f64::from_bits(field.as_fixed64()?)),
                6 => self.scale = zigzag_decode_i32(field.as_varint()? as u32),
                7 => self.zero_count = field.as_fixed64()?,
                8 => merge_optional_message(&mut self.positive, field, decoder, false)?,
                9 => merge_optional_message(&mut self.negative, field, decoder, false)?,
                10 => self.flags = field.as_varint()? as u32,
                11 => push_message(
                    &mut self.exemplars,
                    field,
                    decoder,
                    MAX_EXEMPLARS_PER_DATA_POINT,
                    "exponential histogram exemplars",
                    false,
                )?,
                12 => self.min = Some(f64::from_bits(field.as_fixed64()?)),
                13 => self.max = Some(f64::from_bits(field.as_fixed64()?)),
                14 => self.zero_threshold = f64::from_bits(field.as_fixed64()?),
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_point_time(self.time_unix_nano, budget)?;
            validate_attributes(
                &self.attributes,
                budget,
                "exponential histogram attributes",
                "exponential histogram attribute keys must be unique",
            )?;
            if let Some(positive) = &self.positive {
                positive.validate_otlp(budget, 0)?;
            }
            if let Some(negative) = &self.negative {
                negative.validate_otlp(budget, 0)?;
            }
            if budget.enforces_invariants() {
                let bucket_total = self
                    .positive
                    .iter()
                    .chain(self.negative.iter())
                    .flat_map(|buckets| buckets.bucket_counts.iter())
                    .try_fold(self.zero_count, |total, value| total.checked_add(*value));
                let Some(bucket_total) = bucket_total else {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: 0,
                        invariant: "exponential histogram bucket total must fit u64",
                    });
                };
                if bucket_total != self.count {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: 0,
                        invariant: "exponential histogram count must equal bucket total",
                    });
                }
                if self.count == 0 && self.sum.is_some_and(|sum| sum != 0.0) {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: 0,
                        invariant: "exponential histogram sum must be zero when count is zero",
                    });
                }
            }
            validate_models(
                &self.exemplars,
                budget,
                MAX_EXEMPLARS_PER_DATA_POINT,
                "exponential histogram exemplars",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ExponentialHistogramDataPoint);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct SummaryValueAtQuantile {
        pub(crate) quantile: f64,
        pub(crate) value: f64,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for SummaryValueAtQuantile {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if self.quantile != 0.0 {
                encoder.write_double(1, self.quantile)?;
            }
            if self.value != 0.0 {
                encoder.write_double(2, self.value)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => self.quantile = f64::from_bits(field.as_fixed64()?),
                2 => self.value = f64::from_bits(field.as_fixed64()?),
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if budget.enforces_invariants()
                && (!self.quantile.is_finite() || !(0.0..=1.0).contains(&self.quantile))
            {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "summary quantile must be finite and between zero and one",
                });
            }
            if budget.enforces_invariants() && self.value < 0.0 {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "summary quantile value must not be negative",
                });
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(SummaryValueAtQuantile);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct SummaryDataPoint {
        pub(crate) start_time_unix_nano: u64,
        pub(crate) time_unix_nano: u64,
        pub(crate) count: u64,
        pub(crate) sum: f64,
        pub(crate) quantile_values: Vec<SummaryValueAtQuantile>,
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) flags: u32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for SummaryDataPoint {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if self.start_time_unix_nano != 0 {
                encoder.write_fixed64(2, self.start_time_unix_nano)?;
            }
            if self.time_unix_nano != 0 {
                encoder.write_fixed64(3, self.time_unix_nano)?;
            }
            if self.count != 0 {
                encoder.write_fixed64(4, self.count)?;
            }
            if self.sum != 0.0 {
                encoder.write_double(5, self.sum)?;
            }
            for quantile in &self.quantile_values {
                encode_nested(encoder, 6, quantile)?;
            }
            for attribute in &self.attributes {
                encode_nested(encoder, 7, attribute)?;
            }
            if self.flags != 0 {
                encoder.write_varint(8, u64::from(self.flags))?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                2 => self.start_time_unix_nano = field.as_fixed64()?,
                3 => self.time_unix_nano = field.as_fixed64()?,
                4 => self.count = field.as_fixed64()?,
                5 => self.sum = f64::from_bits(field.as_fixed64()?),
                6 => push_message(
                    &mut self.quantile_values,
                    field,
                    decoder,
                    MAX_SUMMARY_QUANTILES,
                    "summary quantiles",
                    false,
                )?,
                7 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "summary attributes",
                    false,
                )?,
                8 => self.flags = field.as_varint()? as u32,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_point_time(self.time_unix_nano, budget)?;
            budget.repeated(
                self.quantile_values.len(),
                MAX_SUMMARY_QUANTILES,
                "summary quantiles",
            )?;
            budget.work(self.quantile_values.len())?;
            if budget.enforces_invariants()
                && self
                    .quantile_values
                    .windows(2)
                    .any(|pair| pair[0].quantile >= pair[1].quantile)
            {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "summary quantiles must be strictly increasing",
                });
            }
            for quantile in &self.quantile_values {
                quantile.validate_otlp(budget, 0)?;
            }
            if budget.enforces_invariants() && self.count == 0 && self.sum != 0.0 {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "summary sum must be zero when count is zero",
                });
            }
            validate_attributes(
                &self.attributes,
                budget,
                "summary attributes",
                "summary attribute keys must be unique",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(SummaryDataPoint);

    #[derive(Clone, Debug, PartialEq)]
    pub(crate) enum ExemplarValue {
        Double(f64),
        Int(i64),
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct Exemplar {
        pub(crate) time_unix_nano: u64,
        pub(crate) value: Option<ExemplarValue>,
        pub(crate) span_id: Vec<u8>,
        pub(crate) trace_id: Vec<u8>,
        pub(crate) filtered_attributes: Vec<KeyValue>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for Exemplar {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if self.time_unix_nano != 0 {
                encoder.write_fixed64(2, self.time_unix_nano)?;
            }
            if let Some(ExemplarValue::Double(value)) = &self.value {
                encoder.write_double(3, *value)?;
            }
            if !self.span_id.is_empty() {
                encoder.write_bytes(4, &self.span_id)?;
            }
            if !self.trace_id.is_empty() {
                encoder.write_bytes(5, &self.trace_id)?;
            }
            if let Some(ExemplarValue::Int(value)) = &self.value {
                encoder.write_fixed64(6, value.cast_unsigned())?;
            }
            for attribute in &self.filtered_attributes {
                encode_nested(encoder, 7, attribute)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                2 => self.time_unix_nano = field.as_fixed64()?,
                3 => {
                    self.value = Some(ExemplarValue::Double(f64::from_bits(field.as_fixed64()?)));
                }
                4 => {
                    self.span_id = decode_exact_or_empty_bytes(
                        field,
                        decoder,
                        MAX_SPAN_ID_BYTES,
                        "exemplar span ID bytes",
                        "exemplar span ID must be empty or exactly eight bytes",
                    )?;
                }
                5 => {
                    self.trace_id = decode_exact_or_empty_bytes(
                        field,
                        decoder,
                        MAX_TRACE_ID_BYTES,
                        "exemplar trace ID bytes",
                        "exemplar trace ID must be empty or exactly sixteen bytes",
                    )?;
                }
                6 => {
                    self.value = Some(ExemplarValue::Int(field.as_fixed64()?.cast_signed()));
                }
                7 => push_message(
                    &mut self.filtered_attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "exemplar filtered attributes",
                    false,
                )?,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if budget.enforces_invariants() && self.value.is_none() {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "exemplar must contain a recognized value",
                });
            }
            if budget.enforces_invariants()
                && !self.span_id.is_empty()
                && self.span_id.len() != MAX_SPAN_ID_BYTES
            {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "exemplar span ID must be empty or exactly eight bytes",
                });
            }
            if budget.enforces_invariants()
                && !self.trace_id.is_empty()
                && self.trace_id.len() != MAX_TRACE_ID_BYTES
            {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "exemplar trace ID must be empty or exactly sixteen bytes",
                });
            }
            budget.owned_bytes(
                self.span_id.len(),
                MAX_SPAN_ID_BYTES,
                "exemplar span ID bytes",
            )?;
            budget.owned_bytes(
                self.trace_id.len(),
                MAX_TRACE_ID_BYTES,
                "exemplar trace ID bytes",
            )?;
            budget.repeated(
                self.filtered_attributes.len(),
                MAX_ATTRIBUTES,
                "exemplar filtered attributes",
            )?;
            for attribute in &self.filtered_attributes {
                attribute.validate_otlp(budget, 0)?;
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(Exemplar);
}

pub(crate) mod trace {
    use super::common_and_resource::{InstrumentationScope, KeyValue, Resource};
    use super::limits_and_error::{
        MAX_ATTRIBUTES, MAX_EVENT_NAME_BYTES, MAX_EVENTS_PER_SPAN, MAX_LINKS_PER_SPAN,
        MAX_RESOURCE_GROUPS_PER_REQUEST, MAX_SCHEMA_URL_BYTES, MAX_SCOPES_PER_RESOURCE_GROUP,
        MAX_SPAN_ID_BYTES, MAX_SPAN_NAME_BYTES, MAX_SPANS_PER_SCOPE, MAX_TOTAL_OWNED_BYTES,
        MAX_TRACE_ID_BYTES, MAX_TRACE_STATE_BYTES, OtlpModel, ValidationBudget, decode_bytes,
        decode_string, encode_nested, merge_optional_message, merge_root, preserve_unknown,
        push_message, validate_root, validate_unique_keys, validate_unknown,
    };
    use super::{
        ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError,
        ProtobufWireField, ProtobufWireLimits, UnknownFields,
    };

    macro_rules! impl_proto_message {
        ($type:ty) => {
            impl ProtoMessage for $type {
                fn encode_fields(
                    &self,
                    encoder: &mut ProtobufWireEncoder,
                ) -> Result<(), ProtobufWireError> {
                    let remaining_work = encoder.remaining_work()?;
                    let validation = validate_root(self, remaining_work, true)?;
                    encoder.charge_schema_work(validation.work_used)?;
                    self.encode_fields_unchecked(encoder)
                }

                fn merge_field<'wire>(
                    &mut self,
                    field: &ProtobufWireField<'wire>,
                    decoder: &mut ProtobufWireDecoder<'wire, '_>,
                ) -> Result<bool, ProtobufWireError> {
                    self.merge_otlp_field(field, decoder)
                }

                fn merge_from_bytes(
                    &mut self,
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<(), ProtobufWireError> {
                    merge_root(self, input, limits)
                }

                fn decode_from_bytes(
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<Self, ProtobufWireError> {
                    let mut staged = Self::default();
                    merge_root(&mut staged, input, limits)?;
                    Ok(staged)
                }
            }
        };
    }

    fn validate_models<M: OtlpModel>(
        values: &[M],
        budget: &mut ValidationBudget,
        collection_limit: usize,
        resource: &'static str,
    ) -> Result<(), ProtobufWireError> {
        budget.repeated(values.len(), collection_limit, resource)?;
        for value in values {
            value.validate_otlp(budget, 0)?;
        }
        Ok(())
    }

    fn validate_attributes(
        attributes: &[KeyValue],
        budget: &mut ValidationBudget,
        resource: &'static str,
        invariant: &'static str,
    ) -> Result<(), ProtobufWireError> {
        budget.repeated(attributes.len(), MAX_ATTRIBUTES, resource)?;
        validate_unique_keys(attributes, budget, invariant)?;
        for attribute in attributes {
            attribute.validate_otlp(budget, 0)?;
        }
        Ok(())
    }

    fn is_trace_state_key_char(byte: u8) -> bool {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'-' | b'*' | b'/')
    }

    fn is_valid_trace_state_key(key: &str) -> bool {
        let bytes = key.as_bytes();
        if let Some(at) = bytes.iter().position(|byte| *byte == b'@') {
            if bytes[at + 1..].contains(&b'@') {
                return false;
            }
            let tenant = &bytes[..at];
            let system = &bytes[at + 1..];
            (1..=241).contains(&tenant.len())
                && (1..=14).contains(&system.len())
                && (tenant[0].is_ascii_lowercase() || tenant[0].is_ascii_digit())
                && tenant[1..].iter().copied().all(is_trace_state_key_char)
                && system[0].is_ascii_lowercase()
                && system[1..].iter().copied().all(is_trace_state_key_char)
        } else {
            (1..=256).contains(&bytes.len())
                && bytes[0].is_ascii_lowercase()
                && bytes[1..].iter().copied().all(is_trace_state_key_char)
        }
    }

    fn trim_trace_state_ows(value: &str) -> &str {
        value.trim_matches(|character| matches!(character, ' ' | '\t'))
    }

    fn parse_trace_state_member(member: &str) -> Option<(&str, &str)> {
        let member = trim_trace_state_ows(member);
        let (raw_key, raw_value) = member.split_once('=')?;
        if raw_value.contains('=') {
            return None;
        }
        let key = raw_key;
        let value = raw_value;
        if !is_valid_trace_state_key(key)
            || value.is_empty()
            || value.len() > 256
            || value.as_bytes().last().is_some_and(u8::is_ascii_whitespace)
            || !value
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte) && !matches!(byte, b',' | b'='))
        {
            return None;
        }
        Some((key, value))
    }

    fn validate_trace_state(value: &str, entry_count: usize) -> bool {
        if value.is_empty() {
            return entry_count == 0;
        }
        if value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_whitespace)
            || value.as_bytes().last().is_some_and(u8::is_ascii_whitespace)
        {
            return false;
        }
        if entry_count == 0 || entry_count > 32 {
            return false;
        }
        for (index, member) in value.split(',').enumerate() {
            let Some((key, _)) = parse_trace_state_member(member) else {
                return false;
            };
            for prior in value.split(',').take(index) {
                let Some((prior_key, _)) = parse_trace_state_member(prior) else {
                    return false;
                };
                if key == prior_key {
                    return false;
                }
            }
        }
        true
    }

    fn decode_trace_state(
        field: &ProtobufWireField<'_>,
        decoder: &mut ProtobufWireDecoder<'_, '_>,
        resource: &'static str,
    ) -> Result<String, ProtobufWireError> {
        let bytes = field.as_bytes()?;
        if bytes.len() > MAX_TRACE_STATE_BYTES {
            return Err(ProtobufWireError::SchemaLimitExceeded {
                offset: field.value_offset(),
                resource,
                observed: bytes.len(),
                limit: MAX_TRACE_STATE_BYTES,
            });
        }
        // UTF-8 and the hard byte cap are per-occurrence constraints enforced
        // by decode_string. W3C grammar is a final scalar invariant so a later
        // valid occurrence can supersede an earlier malformed value.
        decode_string(field, decoder, MAX_TRACE_STATE_BYTES, resource)
    }

    fn validate_trace_state_value(
        value: &str,
        budget: &mut ValidationBudget,
        resource: &'static str,
    ) -> Result<(), ProtobufWireError> {
        budget.owned_bytes(value.len(), MAX_TRACE_STATE_BYTES, resource)?;
        if budget.enforces_invariants() {
            // Admit the delimiter-counting pass before scanning the value.
            budget.work(value.len())?;
            let entry_count = if value.is_empty() {
                0
            } else {
                value.split(',').count()
            };
            // The grammar check reparses at most 32 bounded members while
            // comparing keys, so admit its conservative work envelope before
            // performing any of those scans.
            if entry_count <= 32 {
                budget.work(value.len().saturating_mul(entry_count))?;
            }
            if !validate_trace_state(value, entry_count) {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "trace state must use the W3C tracestate format",
                });
            }
        }
        Ok(())
    }

    fn id_is_valid(
        value: &[u8],
        exact_length: usize,
        allow_empty: bool,
        require_nonzero: bool,
    ) -> bool {
        (allow_empty && value.is_empty())
            || (value.len() == exact_length
                && (!require_nonzero || value.iter().any(|byte| *byte != 0)))
    }

    fn decode_id(
        field: &ProtobufWireField<'_>,
        decoder: &mut ProtobufWireDecoder<'_, '_>,
        exact_length: usize,
        resource: &'static str,
    ) -> Result<Vec<u8>, ProtobufWireError> {
        // Width and nonzero requirements are final message invariants. A later
        // occurrence must be able to replace an earlier short or all-zero
        // value under protobuf singular-field last-value-wins semantics. The
        // hard byte cap is still checked before allocation.
        decode_bytes(field, decoder, exact_length, resource)
    }

    fn validate_id(
        value: &[u8],
        budget: &mut ValidationBudget,
        exact_length: usize,
        allow_empty: bool,
        require_nonzero: bool,
        resource: &'static str,
        invariant: &'static str,
    ) -> Result<(), ProtobufWireError> {
        if budget.enforces_invariants()
            && !id_is_valid(value, exact_length, allow_empty, require_nonzero)
        {
            return Err(ProtobufWireError::SchemaInvariant {
                offset: 0,
                invariant,
            });
        }
        budget.owned_bytes(value.len(), exact_length, resource)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i32)]
    pub(crate) enum SpanKind {
        Unspecified = 0,
        Internal = 1,
        Server = 2,
        Client = 3,
        Producer = 4,
        Consumer = 5,
    }

    impl SpanKind {
        pub(crate) const fn from_raw(value: i32) -> Option<Self> {
            match value {
                0 => Some(Self::Unspecified),
                1 => Some(Self::Internal),
                2 => Some(Self::Server),
                3 => Some(Self::Client),
                4 => Some(Self::Producer),
                5 => Some(Self::Consumer),
                _ => None,
            }
        }

        pub(crate) const fn as_raw(self) -> i32 {
            self as i32
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i32)]
    pub(crate) enum StatusCode {
        Unset = 0,
        Ok = 1,
        Error = 2,
    }

    impl StatusCode {
        pub(crate) const fn from_raw(value: i32) -> Option<Self> {
            match value {
                0 => Some(Self::Unset),
                1 => Some(Self::Ok),
                2 => Some(Self::Error),
                _ => None,
            }
        }

        pub(crate) const fn as_raw(self) -> i32 {
            self as i32
        }
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct SpanFlags(u32);

    impl SpanFlags {
        pub(crate) const DO_NOT_USE: Self = Self(0);
        pub(crate) const TRACE_FLAGS_MASK: Self = Self(0xff);
        pub(crate) const CONTEXT_HAS_IS_REMOTE_MASK: Self = Self(0x100);
        pub(crate) const CONTEXT_IS_REMOTE_MASK: Self = Self(0x200);

        pub(crate) const fn from_bits_retain(bits: u32) -> Self {
            Self(bits)
        }

        pub(crate) const fn bits(self) -> u32 {
            self.0
        }

        pub(crate) const fn contains(self, mask: Self) -> bool {
            self.0 & mask.0 == mask.0
        }

        pub(crate) const fn trace_flags(self) -> u8 {
            (self.0 & Self::TRACE_FLAGS_MASK.0) as u8
        }

        pub(crate) const fn context_is_remote(self) -> Option<bool> {
            if self.contains(Self::CONTEXT_HAS_IS_REMOTE_MASK) {
                Some(self.contains(Self::CONTEXT_IS_REMOTE_MASK))
            } else {
                None
            }
        }
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct TracesData {
        pub(crate) resource_spans: Vec<ResourceSpans>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for TracesData {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for resource_spans in &self.resource_spans {
                encode_nested(encoder, 1, resource_spans)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => push_message(
                    &mut self.resource_spans,
                    field,
                    decoder,
                    MAX_RESOURCE_GROUPS_PER_REQUEST,
                    "trace resource groups",
                    false,
                )?,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_models(
                &self.resource_spans,
                budget,
                MAX_RESOURCE_GROUPS_PER_REQUEST,
                "trace resource groups",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(TracesData);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ResourceSpans {
        pub(crate) resource: Option<Resource>,
        pub(crate) scope_spans: Vec<ScopeSpans>,
        pub(crate) schema_url: String,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ResourceSpans {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if let Some(resource) = &self.resource {
                encode_nested(encoder, 1, resource)?;
            }
            for scope_spans in &self.scope_spans {
                encode_nested(encoder, 2, scope_spans)?;
            }
            if !self.schema_url.is_empty() {
                encoder.write_string(3, &self.schema_url)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => merge_optional_message(&mut self.resource, field, decoder, false)?,
                2 => push_message(
                    &mut self.scope_spans,
                    field,
                    decoder,
                    MAX_SCOPES_PER_RESOURCE_GROUP,
                    "trace scopes per resource group",
                    false,
                )?,
                3 => {
                    self.schema_url = decode_string(
                        field,
                        decoder,
                        MAX_SCHEMA_URL_BYTES,
                        "trace resource schema URL bytes",
                    )?;
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if let Some(resource) = &self.resource {
                resource.validate_otlp(budget, 0)?;
            }
            validate_models(
                &self.scope_spans,
                budget,
                MAX_SCOPES_PER_RESOURCE_GROUP,
                "trace scopes per resource group",
            )?;
            budget.owned_bytes(
                self.schema_url.len(),
                MAX_SCHEMA_URL_BYTES,
                "trace resource schema URL bytes",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ResourceSpans);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ScopeSpans {
        pub(crate) scope: Option<InstrumentationScope>,
        pub(crate) spans: Vec<Span>,
        pub(crate) schema_url: String,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ScopeSpans {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if let Some(scope) = &self.scope {
                encode_nested(encoder, 1, scope)?;
            }
            for span in &self.spans {
                encode_nested(encoder, 2, span)?;
            }
            if !self.schema_url.is_empty() {
                encoder.write_string(3, &self.schema_url)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => merge_optional_message(&mut self.scope, field, decoder, false)?,
                2 => push_message(
                    &mut self.spans,
                    field,
                    decoder,
                    MAX_SPANS_PER_SCOPE,
                    "spans per scope",
                    false,
                )?,
                3 => {
                    self.schema_url = decode_string(
                        field,
                        decoder,
                        MAX_SCHEMA_URL_BYTES,
                        "trace scope schema URL bytes",
                    )?;
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if let Some(scope) = &self.scope {
                scope.validate_otlp(budget, 0)?;
            }
            validate_models(&self.spans, budget, MAX_SPANS_PER_SCOPE, "spans per scope")?;
            budget.owned_bytes(
                self.schema_url.len(),
                MAX_SCHEMA_URL_BYTES,
                "trace scope schema URL bytes",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ScopeSpans);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct Span {
        pub(crate) trace_id: Vec<u8>,
        pub(crate) span_id: Vec<u8>,
        pub(crate) trace_state: String,
        pub(crate) parent_span_id: Vec<u8>,
        pub(crate) name: String,
        pub(crate) kind: i32,
        pub(crate) start_time_unix_nano: u64,
        pub(crate) end_time_unix_nano: u64,
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) dropped_attributes_count: u32,
        pub(crate) events: Vec<SpanEvent>,
        pub(crate) dropped_events_count: u32,
        pub(crate) links: Vec<SpanLink>,
        pub(crate) dropped_links_count: u32,
        pub(crate) status: Option<Status>,
        pub(crate) flags: u32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for Span {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if !self.trace_id.is_empty() {
                encoder.write_bytes(1, &self.trace_id)?;
            }
            if !self.span_id.is_empty() {
                encoder.write_bytes(2, &self.span_id)?;
            }
            if !self.trace_state.is_empty() {
                encoder.write_string(3, &self.trace_state)?;
            }
            if !self.parent_span_id.is_empty() {
                encoder.write_bytes(4, &self.parent_span_id)?;
            }
            if !self.name.is_empty() {
                encoder.write_string(5, &self.name)?;
            }
            if self.kind != 0 {
                encoder.write_enum(6, self.kind)?;
            }
            if self.start_time_unix_nano != 0 {
                encoder.write_fixed64(7, self.start_time_unix_nano)?;
            }
            if self.end_time_unix_nano != 0 {
                encoder.write_fixed64(8, self.end_time_unix_nano)?;
            }
            for attribute in &self.attributes {
                encode_nested(encoder, 9, attribute)?;
            }
            if self.dropped_attributes_count != 0 {
                encoder.write_varint(10, u64::from(self.dropped_attributes_count))?;
            }
            for event in &self.events {
                encode_nested(encoder, 11, event)?;
            }
            if self.dropped_events_count != 0 {
                encoder.write_varint(12, u64::from(self.dropped_events_count))?;
            }
            for link in &self.links {
                encode_nested(encoder, 13, link)?;
            }
            if self.dropped_links_count != 0 {
                encoder.write_varint(14, u64::from(self.dropped_links_count))?;
            }
            if let Some(status) = &self.status {
                encode_nested(encoder, 15, status)?;
            }
            if self.flags != 0 {
                encoder.write_fixed32(16, self.flags)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => {
                    self.trace_id =
                        decode_id(field, decoder, MAX_TRACE_ID_BYTES, "span trace ID bytes")?;
                }
                2 => {
                    self.span_id = decode_id(field, decoder, MAX_SPAN_ID_BYTES, "span ID bytes")?;
                }
                3 => {
                    self.trace_state =
                        decode_trace_state(field, decoder, "span trace state bytes")?;
                }
                4 => {
                    self.parent_span_id =
                        decode_id(field, decoder, MAX_SPAN_ID_BYTES, "parent span ID bytes")?;
                }
                5 => {
                    self.name =
                        decode_string(field, decoder, MAX_SPAN_NAME_BYTES, "span name bytes")?;
                }
                6 => self.kind = (field.as_varint()? as u32).cast_signed(),
                7 => self.start_time_unix_nano = field.as_fixed64()?,
                8 => self.end_time_unix_nano = field.as_fixed64()?,
                9 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "span attributes",
                    false,
                )?,
                10 => self.dropped_attributes_count = field.as_varint()? as u32,
                11 => push_message(
                    &mut self.events,
                    field,
                    decoder,
                    MAX_EVENTS_PER_SPAN,
                    "span events",
                    false,
                )?,
                12 => self.dropped_events_count = field.as_varint()? as u32,
                13 => push_message(
                    &mut self.links,
                    field,
                    decoder,
                    MAX_LINKS_PER_SPAN,
                    "span links",
                    false,
                )?,
                14 => self.dropped_links_count = field.as_varint()? as u32,
                15 => merge_optional_message(&mut self.status, field, decoder, false)?,
                16 => self.flags = field.as_fixed32()?,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_id(
                &self.trace_id,
                budget,
                MAX_TRACE_ID_BYTES,
                false,
                true,
                "span trace ID bytes",
                "span trace ID must be a nonzero sixteen-byte value",
            )?;
            validate_id(
                &self.span_id,
                budget,
                MAX_SPAN_ID_BYTES,
                false,
                true,
                "span ID bytes",
                "span ID must be a nonzero eight-byte value",
            )?;
            validate_trace_state_value(&self.trace_state, budget, "span trace state bytes")?;
            validate_id(
                &self.parent_span_id,
                budget,
                MAX_SPAN_ID_BYTES,
                true,
                false,
                "parent span ID bytes",
                "parent span ID must be empty or exactly eight bytes",
            )?;
            if budget.enforces_invariants() && self.name.is_empty() {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "span name must not be empty",
                });
            }
            budget.owned_bytes(self.name.len(), MAX_SPAN_NAME_BYTES, "span name bytes")?;
            if budget.enforces_invariants() && self.start_time_unix_nano == 0 {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "span start_time_unix_nano must be nonzero",
                });
            }
            if budget.enforces_invariants() && self.end_time_unix_nano == 0 {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "span end_time_unix_nano must be nonzero",
                });
            }
            if budget.enforces_invariants() && self.end_time_unix_nano < self.start_time_unix_nano {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "span end_time_unix_nano must not precede start_time_unix_nano",
                });
            }
            validate_attributes(
                &self.attributes,
                budget,
                "span attributes",
                "span attribute keys must be unique",
            )?;
            validate_models(&self.events, budget, MAX_EVENTS_PER_SPAN, "span events")?;
            validate_models(&self.links, budget, MAX_LINKS_PER_SPAN, "span links")?;
            if let Some(status) = &self.status {
                status.validate_otlp(budget, 0)?;
            }
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(Span);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct SpanEvent {
        pub(crate) time_unix_nano: u64,
        pub(crate) name: String,
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) dropped_attributes_count: u32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for SpanEvent {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if self.time_unix_nano != 0 {
                encoder.write_fixed64(1, self.time_unix_nano)?;
            }
            if !self.name.is_empty() {
                encoder.write_string(2, &self.name)?;
            }
            for attribute in &self.attributes {
                encode_nested(encoder, 3, attribute)?;
            }
            if self.dropped_attributes_count != 0 {
                encoder.write_varint(4, u64::from(self.dropped_attributes_count))?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => self.time_unix_nano = field.as_fixed64()?,
                2 => {
                    self.name = decode_string(
                        field,
                        decoder,
                        MAX_EVENT_NAME_BYTES,
                        "span event name bytes",
                    )?;
                }
                3 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "span event attributes",
                    false,
                )?,
                4 => self.dropped_attributes_count = field.as_varint()? as u32,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if budget.enforces_invariants() && self.name.is_empty() {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "span event name must not be empty",
                });
            }
            budget.owned_bytes(
                self.name.len(),
                MAX_EVENT_NAME_BYTES,
                "span event name bytes",
            )?;
            validate_attributes(
                &self.attributes,
                budget,
                "span event attributes",
                "span event attribute keys must be unique",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(SpanEvent);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct SpanLink {
        pub(crate) trace_id: Vec<u8>,
        pub(crate) span_id: Vec<u8>,
        pub(crate) trace_state: String,
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) dropped_attributes_count: u32,
        pub(crate) flags: u32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for SpanLink {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if !self.trace_id.is_empty() {
                encoder.write_bytes(1, &self.trace_id)?;
            }
            if !self.span_id.is_empty() {
                encoder.write_bytes(2, &self.span_id)?;
            }
            if !self.trace_state.is_empty() {
                encoder.write_string(3, &self.trace_state)?;
            }
            for attribute in &self.attributes {
                encode_nested(encoder, 4, attribute)?;
            }
            if self.dropped_attributes_count != 0 {
                encoder.write_varint(5, u64::from(self.dropped_attributes_count))?;
            }
            if self.flags != 0 {
                encoder.write_fixed32(6, self.flags)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => {
                    self.trace_id = decode_id(
                        field,
                        decoder,
                        MAX_TRACE_ID_BYTES,
                        "span link trace ID bytes",
                    )?;
                }
                2 => {
                    self.span_id =
                        decode_id(field, decoder, MAX_SPAN_ID_BYTES, "span link span ID bytes")?;
                }
                3 => {
                    self.trace_state =
                        decode_trace_state(field, decoder, "span link trace state bytes")?;
                }
                4 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "span link attributes",
                    false,
                )?,
                5 => self.dropped_attributes_count = field.as_varint()? as u32,
                6 => self.flags = field.as_fixed32()?,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_id(
                &self.trace_id,
                budget,
                MAX_TRACE_ID_BYTES,
                false,
                false,
                "span link trace ID bytes",
                "span link trace ID must be exactly sixteen bytes",
            )?;
            validate_id(
                &self.span_id,
                budget,
                MAX_SPAN_ID_BYTES,
                false,
                false,
                "span link span ID bytes",
                "span link span ID must be exactly eight bytes",
            )?;
            validate_trace_state_value(&self.trace_state, budget, "span link trace state bytes")?;
            validate_attributes(
                &self.attributes,
                budget,
                "span link attributes",
                "span link attribute keys must be unique",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(SpanLink);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct Status {
        pub(crate) message: String,
        pub(crate) code: i32,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for Status {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if !self.message.is_empty() {
                encoder.write_string(2, &self.message)?;
            }
            if self.code != 0 {
                encoder.write_enum(3, self.code)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                2 => {
                    self.message = decode_string(
                        field,
                        decoder,
                        MAX_TOTAL_OWNED_BYTES,
                        "trace status message bytes",
                    )?;
                }
                3 => self.code = (field.as_varint()? as u32).cast_signed(),
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            budget.owned_bytes(
                self.message.len(),
                MAX_TOTAL_OWNED_BYTES,
                "trace status message bytes",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(Status);
}

pub(crate) mod logs {
    use super::common_and_resource::{AnyValue, InstrumentationScope, KeyValue, Resource};
    use super::limits_and_error::{
        MAX_ATTRIBUTES, MAX_LOG_EVENT_NAME_BYTES, MAX_LOG_RECORDS_PER_SCOPE,
        MAX_LOG_SEVERITY_TEXT_BYTES, MAX_RESOURCE_GROUPS_PER_REQUEST, MAX_SCHEMA_URL_BYTES,
        MAX_SCOPES_PER_RESOURCE_GROUP, MAX_SPAN_ID_BYTES, MAX_TRACE_ID_BYTES, OtlpModel,
        ValidationBudget, decode_exact_or_empty_bytes, decode_string, encode_nested,
        merge_optional_message, merge_root, preserve_unknown, push_message, validate_root,
        validate_unique_keys, validate_unknown,
    };
    use super::{
        ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError,
        ProtobufWireField, ProtobufWireLimits, UnknownFields,
    };

    macro_rules! impl_proto_message {
        ($type:ty) => {
            impl ProtoMessage for $type {
                fn encode_fields(
                    &self,
                    encoder: &mut ProtobufWireEncoder,
                ) -> Result<(), ProtobufWireError> {
                    let remaining_work = encoder.remaining_work()?;
                    let validation = validate_root(self, remaining_work, true)?;
                    encoder.charge_schema_work(validation.work_used)?;
                    self.encode_fields_unchecked(encoder)
                }

                fn merge_field<'wire>(
                    &mut self,
                    field: &ProtobufWireField<'wire>,
                    decoder: &mut ProtobufWireDecoder<'wire, '_>,
                ) -> Result<bool, ProtobufWireError> {
                    self.merge_otlp_field(field, decoder)
                }

                fn merge_from_bytes(
                    &mut self,
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<(), ProtobufWireError> {
                    merge_root(self, input, limits)
                }

                fn decode_from_bytes(
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<Self, ProtobufWireError> {
                    let mut staged = Self::default();
                    merge_root(&mut staged, input, limits)?;
                    Ok(staged)
                }
            }
        };
    }

    fn validate_models<M: OtlpModel>(
        values: &[M],
        budget: &mut ValidationBudget,
        collection_limit: usize,
        resource: &'static str,
    ) -> Result<(), ProtobufWireError> {
        budget.repeated(values.len(), collection_limit, resource)?;
        for value in values {
            value.validate_otlp(budget, 0)?;
        }
        Ok(())
    }

    fn validate_attributes(
        attributes: &[KeyValue],
        budget: &mut ValidationBudget,
    ) -> Result<(), ProtobufWireError> {
        budget.repeated(attributes.len(), MAX_ATTRIBUTES, "log record attributes")?;
        validate_unique_keys(
            attributes,
            budget,
            "log record attribute keys must be unique",
        )?;
        for attribute in attributes {
            attribute.validate_otlp(budget, 0)?;
        }
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i32)]
    pub(crate) enum SeverityNumber {
        Unspecified = 0,
        Trace = 1,
        Trace2 = 2,
        Trace3 = 3,
        Trace4 = 4,
        Debug = 5,
        Debug2 = 6,
        Debug3 = 7,
        Debug4 = 8,
        Info = 9,
        Info2 = 10,
        Info3 = 11,
        Info4 = 12,
        Warn = 13,
        Warn2 = 14,
        Warn3 = 15,
        Warn4 = 16,
        Error = 17,
        Error2 = 18,
        Error3 = 19,
        Error4 = 20,
        Fatal = 21,
        Fatal2 = 22,
        Fatal3 = 23,
        Fatal4 = 24,
    }

    impl SeverityNumber {
        pub(crate) const fn from_raw(value: i32) -> Option<Self> {
            match value {
                0 => Some(Self::Unspecified),
                1 => Some(Self::Trace),
                2 => Some(Self::Trace2),
                3 => Some(Self::Trace3),
                4 => Some(Self::Trace4),
                5 => Some(Self::Debug),
                6 => Some(Self::Debug2),
                7 => Some(Self::Debug3),
                8 => Some(Self::Debug4),
                9 => Some(Self::Info),
                10 => Some(Self::Info2),
                11 => Some(Self::Info3),
                12 => Some(Self::Info4),
                13 => Some(Self::Warn),
                14 => Some(Self::Warn2),
                15 => Some(Self::Warn3),
                16 => Some(Self::Warn4),
                17 => Some(Self::Error),
                18 => Some(Self::Error2),
                19 => Some(Self::Error3),
                20 => Some(Self::Error4),
                21 => Some(Self::Fatal),
                22 => Some(Self::Fatal2),
                23 => Some(Self::Fatal3),
                24 => Some(Self::Fatal4),
                _ => None,
            }
        }

        pub(crate) const fn as_raw(self) -> i32 {
            self as i32
        }
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct LogRecordFlags(u32);

    impl LogRecordFlags {
        pub(crate) const DO_NOT_USE: Self = Self(0);
        pub(crate) const TRACE_FLAGS_MASK: Self = Self(0xff);

        pub(crate) const fn from_bits_retain(bits: u32) -> Self {
            Self(bits)
        }

        pub(crate) const fn bits(self) -> u32 {
            self.0
        }

        pub(crate) const fn contains(self, mask: Self) -> bool {
            self.0 & mask.0 == mask.0
        }

        pub(crate) const fn trace_flags(self) -> u8 {
            (self.0 & Self::TRACE_FLAGS_MASK.0) as u8
        }
    }

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct LogsData {
        pub(crate) resource_logs: Vec<ResourceLogs>,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for LogsData {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            for resource_logs in &self.resource_logs {
                encode_nested(encoder, 1, resource_logs)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => push_message(
                    &mut self.resource_logs,
                    field,
                    decoder,
                    MAX_RESOURCE_GROUPS_PER_REQUEST,
                    "log resource groups",
                    false,
                )?,
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            validate_models(
                &self.resource_logs,
                budget,
                MAX_RESOURCE_GROUPS_PER_REQUEST,
                "log resource groups",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(LogsData);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ResourceLogs {
        pub(crate) resource: Option<Resource>,
        pub(crate) scope_logs: Vec<ScopeLogs>,
        pub(crate) schema_url: String,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ResourceLogs {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if let Some(resource) = &self.resource {
                encode_nested(encoder, 1, resource)?;
            }
            for scope_logs in &self.scope_logs {
                encode_nested(encoder, 2, scope_logs)?;
            }
            if !self.schema_url.is_empty() {
                encoder.write_string(3, &self.schema_url)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => merge_optional_message(&mut self.resource, field, decoder, false)?,
                2 => push_message(
                    &mut self.scope_logs,
                    field,
                    decoder,
                    MAX_SCOPES_PER_RESOURCE_GROUP,
                    "log scopes per resource group",
                    false,
                )?,
                3 => {
                    self.schema_url = decode_string(
                        field,
                        decoder,
                        MAX_SCHEMA_URL_BYTES,
                        "log resource schema URL bytes",
                    )?;
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if let Some(resource) = &self.resource {
                resource.validate_otlp(budget, 0)?;
            }
            validate_models(
                &self.scope_logs,
                budget,
                MAX_SCOPES_PER_RESOURCE_GROUP,
                "log scopes per resource group",
            )?;
            budget.owned_bytes(
                self.schema_url.len(),
                MAX_SCHEMA_URL_BYTES,
                "log resource schema URL bytes",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ResourceLogs);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct ScopeLogs {
        pub(crate) scope: Option<InstrumentationScope>,
        pub(crate) log_records: Vec<LogRecord>,
        pub(crate) schema_url: String,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl OtlpModel for ScopeLogs {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if let Some(scope) = &self.scope {
                encode_nested(encoder, 1, scope)?;
            }
            for log_record in &self.log_records {
                encode_nested(encoder, 2, log_record)?;
            }
            if !self.schema_url.is_empty() {
                encoder.write_string(3, &self.schema_url)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => merge_optional_message(&mut self.scope, field, decoder, false)?,
                2 => push_message(
                    &mut self.log_records,
                    field,
                    decoder,
                    MAX_LOG_RECORDS_PER_SCOPE,
                    "log records per scope",
                    false,
                )?,
                3 => {
                    self.schema_url = decode_string(
                        field,
                        decoder,
                        MAX_SCHEMA_URL_BYTES,
                        "log scope schema URL bytes",
                    )?;
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if let Some(scope) = &self.scope {
                scope.validate_otlp(budget, 0)?;
            }
            validate_models(
                &self.log_records,
                budget,
                MAX_LOG_RECORDS_PER_SCOPE,
                "log records per scope",
            )?;
            budget.owned_bytes(
                self.schema_url.len(),
                MAX_SCHEMA_URL_BYTES,
                "log scope schema URL bytes",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(ScopeLogs);

    #[derive(Clone, Debug, Default, PartialEq)]
    pub(crate) struct LogRecord {
        pub(crate) time_unix_nano: u64,
        pub(crate) severity_number: i32,
        pub(crate) severity_text: String,
        pub(crate) body: Option<AnyValue>,
        pub(crate) attributes: Vec<KeyValue>,
        pub(crate) dropped_attributes_count: u32,
        pub(crate) flags: u32,
        pub(crate) trace_id: Vec<u8>,
        pub(crate) span_id: Vec<u8>,
        pub(crate) observed_time_unix_nano: u64,
        pub(crate) event_name: String,
        pub(crate) unknown_fields: UnknownFields,
    }

    impl LogRecord {
        pub(crate) fn has_valid_trace_id(&self) -> bool {
            self.trace_id.len() == MAX_TRACE_ID_BYTES && self.trace_id.iter().any(|byte| *byte != 0)
        }

        pub(crate) fn has_valid_span_id(&self) -> bool {
            self.span_id.len() == MAX_SPAN_ID_BYTES && self.span_id.iter().any(|byte| *byte != 0)
        }

        pub(crate) fn has_valid_span_context(&self) -> bool {
            self.has_valid_trace_id() && self.has_valid_span_id()
        }

        pub(crate) fn is_event(&self) -> bool {
            !self.event_name.is_empty()
        }
    }

    impl OtlpModel for LogRecord {
        fn encode_fields_unchecked(
            &self,
            encoder: &mut ProtobufWireEncoder,
        ) -> Result<(), ProtobufWireError> {
            if self.time_unix_nano != 0 {
                encoder.write_fixed64(1, self.time_unix_nano)?;
            }
            if self.severity_number != 0 {
                encoder.write_enum(2, self.severity_number)?;
            }
            if !self.severity_text.is_empty() {
                encoder.write_string(3, &self.severity_text)?;
            }
            if let Some(body) = &self.body {
                encode_nested(encoder, 5, body)?;
            }
            for attribute in &self.attributes {
                encode_nested(encoder, 6, attribute)?;
            }
            if self.dropped_attributes_count != 0 {
                encoder.write_varint(7, u64::from(self.dropped_attributes_count))?;
            }
            if self.flags != 0 {
                encoder.write_fixed32(8, self.flags)?;
            }
            if !self.trace_id.is_empty() {
                encoder.write_bytes(9, &self.trace_id)?;
            }
            if !self.span_id.is_empty() {
                encoder.write_bytes(10, &self.span_id)?;
            }
            if self.observed_time_unix_nano != 0 {
                encoder.write_fixed64(11, self.observed_time_unix_nano)?;
            }
            if !self.event_name.is_empty() {
                encoder.write_string(12, &self.event_name)?;
            }
            self.unknown_fields.encode(encoder)
        }

        fn merge_otlp_field<'wire>(
            &mut self,
            field: &ProtobufWireField<'wire>,
            decoder: &mut ProtobufWireDecoder<'wire, '_>,
        ) -> Result<bool, ProtobufWireError> {
            match field.field_number() {
                1 => self.time_unix_nano = field.as_fixed64()?,
                2 => self.severity_number = (field.as_varint()? as u32).cast_signed(),
                3 => {
                    self.severity_text = decode_string(
                        field,
                        decoder,
                        MAX_LOG_SEVERITY_TEXT_BYTES,
                        "log severity text bytes",
                    )?;
                }
                5 => merge_optional_message(&mut self.body, field, decoder, true)?,
                6 => push_message(
                    &mut self.attributes,
                    field,
                    decoder,
                    MAX_ATTRIBUTES,
                    "log record attributes",
                    false,
                )?,
                7 => self.dropped_attributes_count = field.as_varint()? as u32,
                8 => self.flags = field.as_fixed32()?,
                9 => {
                    self.trace_id = decode_exact_or_empty_bytes(
                        field,
                        decoder,
                        MAX_TRACE_ID_BYTES,
                        "log record trace ID bytes",
                        "log record trace ID must be empty or exactly sixteen bytes",
                    )?;
                }
                10 => {
                    self.span_id = decode_exact_or_empty_bytes(
                        field,
                        decoder,
                        MAX_SPAN_ID_BYTES,
                        "log record span ID bytes",
                        "log record span ID must be empty or exactly eight bytes",
                    )?;
                }
                11 => self.observed_time_unix_nano = field.as_fixed64()?,
                12 => {
                    self.event_name = decode_string(
                        field,
                        decoder,
                        MAX_LOG_EVENT_NAME_BYTES,
                        "log event name bytes",
                    )?;
                }
                _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
            }
            Ok(true)
        }

        fn validate_otlp(
            &self,
            budget: &mut ValidationBudget,
            _any_value_depth: usize,
        ) -> Result<(), ProtobufWireError> {
            if budget.enforces_invariants()
                && !self.trace_id.is_empty()
                && self.trace_id.len() != MAX_TRACE_ID_BYTES
            {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "log record trace ID must be empty or exactly sixteen bytes",
                });
            }
            if budget.enforces_invariants()
                && !self.span_id.is_empty()
                && self.span_id.len() != MAX_SPAN_ID_BYTES
            {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: 0,
                    invariant: "log record span ID must be empty or exactly eight bytes",
                });
            }
            budget.owned_bytes(
                self.severity_text.len(),
                MAX_LOG_SEVERITY_TEXT_BYTES,
                "log severity text bytes",
            )?;
            if let Some(body) = &self.body {
                body.validate_otlp(budget, 1)?;
            }
            validate_attributes(&self.attributes, budget)?;
            budget.owned_bytes(
                self.trace_id.len(),
                MAX_TRACE_ID_BYTES,
                "log record trace ID bytes",
            )?;
            budget.owned_bytes(
                self.span_id.len(),
                MAX_SPAN_ID_BYTES,
                "log record span ID bytes",
            )?;
            budget.owned_bytes(
                self.event_name.len(),
                MAX_LOG_EVENT_NAME_BYTES,
                "log event name bytes",
            )?;
            validate_unknown(&self.unknown_fields, budget)
        }
    }

    impl_proto_message!(LogRecord);
}

pub(crate) mod collector {
    pub(crate) mod metrics {
        use super::super::limits_and_error::{
            MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES, MAX_RESOURCE_GROUPS_PER_REQUEST, OtlpModel,
            ValidationBudget, decode_string, encode_nested, merge_optional_message, merge_root,
            preserve_unknown, push_message, validate_root, validate_unknown,
        };
        use super::super::metrics::ResourceMetrics;
        use super::super::{
            ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError,
            ProtobufWireField, ProtobufWireLimits, UnknownFields,
        };

        macro_rules! impl_proto_message {
            ($type:ty) => {
                impl ProtoMessage for $type {
                    fn encode_fields(
                        &self,
                        encoder: &mut ProtobufWireEncoder,
                    ) -> Result<(), ProtobufWireError> {
                        let remaining_work = encoder.remaining_work()?;
                        let validation = validate_root(self, remaining_work, true)?;
                        encoder.charge_schema_work(validation.work_used)?;
                        self.encode_fields_unchecked(encoder)
                    }

                    fn merge_field<'wire>(
                        &mut self,
                        field: &ProtobufWireField<'wire>,
                        decoder: &mut ProtobufWireDecoder<'wire, '_>,
                    ) -> Result<bool, ProtobufWireError> {
                        self.merge_otlp_field(field, decoder)
                    }

                    fn merge_from_bytes(
                        &mut self,
                        input: &[u8],
                        limits: ProtobufWireLimits,
                    ) -> Result<(), ProtobufWireError> {
                        merge_root(self, input, limits)
                    }

                    fn decode_from_bytes(
                        input: &[u8],
                        limits: ProtobufWireLimits,
                    ) -> Result<Self, ProtobufWireError> {
                        let mut staged = Self::default();
                        merge_root(&mut staged, input, limits)?;
                        Ok(staged)
                    }
                }
            };
        }

        #[derive(Clone, Debug, Default, PartialEq)]
        pub(crate) struct ExportMetricsServiceRequest {
            pub(crate) resource_metrics: Vec<ResourceMetrics>,
            pub(crate) unknown_fields: UnknownFields,
        }

        impl OtlpModel for ExportMetricsServiceRequest {
            fn encode_fields_unchecked(
                &self,
                encoder: &mut ProtobufWireEncoder,
            ) -> Result<(), ProtobufWireError> {
                for resource_metrics in &self.resource_metrics {
                    encode_nested(encoder, 1, resource_metrics)?;
                }
                self.unknown_fields.encode(encoder)
            }

            fn merge_otlp_field<'wire>(
                &mut self,
                field: &ProtobufWireField<'wire>,
                decoder: &mut ProtobufWireDecoder<'wire, '_>,
            ) -> Result<bool, ProtobufWireError> {
                match field.field_number() {
                    1 => push_message(
                        &mut self.resource_metrics,
                        field,
                        decoder,
                        MAX_RESOURCE_GROUPS_PER_REQUEST,
                        "metric resource groups",
                        false,
                    )?,
                    _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
                }
                Ok(true)
            }

            fn validate_otlp(
                &self,
                budget: &mut ValidationBudget,
                _any_value_depth: usize,
            ) -> Result<(), ProtobufWireError> {
                budget.repeated(
                    self.resource_metrics.len(),
                    MAX_RESOURCE_GROUPS_PER_REQUEST,
                    "metric resource groups",
                )?;
                for resource_metrics in &self.resource_metrics {
                    resource_metrics.validate_otlp(budget, 0)?;
                }
                validate_unknown(&self.unknown_fields, budget)
            }
        }

        impl_proto_message!(ExportMetricsServiceRequest);

        #[derive(Clone, Debug, Default, PartialEq)]
        pub(crate) struct ExportMetricsServiceResponse {
            pub(crate) partial_success: Option<ExportMetricsPartialSuccess>,
            pub(crate) unknown_fields: UnknownFields,
        }

        impl OtlpModel for ExportMetricsServiceResponse {
            fn encode_fields_unchecked(
                &self,
                encoder: &mut ProtobufWireEncoder,
            ) -> Result<(), ProtobufWireError> {
                if let Some(partial_success) = &self.partial_success {
                    encode_nested(encoder, 1, partial_success)?;
                }
                self.unknown_fields.encode(encoder)
            }

            fn merge_otlp_field<'wire>(
                &mut self,
                field: &ProtobufWireField<'wire>,
                decoder: &mut ProtobufWireDecoder<'wire, '_>,
            ) -> Result<bool, ProtobufWireError> {
                match field.field_number() {
                    1 => merge_optional_message(&mut self.partial_success, field, decoder, false)?,
                    _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
                }
                Ok(true)
            }

            fn validate_otlp(
                &self,
                budget: &mut ValidationBudget,
                _any_value_depth: usize,
            ) -> Result<(), ProtobufWireError> {
                if let Some(partial_success) = &self.partial_success {
                    partial_success.validate_otlp(budget, 0)?;
                }
                validate_unknown(&self.unknown_fields, budget)
            }
        }

        impl_proto_message!(ExportMetricsServiceResponse);

        #[derive(Clone, Debug, Default, PartialEq)]
        pub(crate) struct ExportMetricsPartialSuccess {
            pub(crate) rejected_data_points: i64,
            pub(crate) error_message: String,
            pub(crate) unknown_fields: UnknownFields,
        }

        impl OtlpModel for ExportMetricsPartialSuccess {
            fn encode_fields_unchecked(
                &self,
                encoder: &mut ProtobufWireEncoder,
            ) -> Result<(), ProtobufWireError> {
                if self.rejected_data_points != 0 {
                    encoder.write_int64(1, self.rejected_data_points)?;
                }
                if !self.error_message.is_empty() {
                    encoder.write_string(2, &self.error_message)?;
                }
                self.unknown_fields.encode(encoder)
            }

            fn merge_otlp_field<'wire>(
                &mut self,
                field: &ProtobufWireField<'wire>,
                decoder: &mut ProtobufWireDecoder<'wire, '_>,
            ) -> Result<bool, ProtobufWireError> {
                match field.field_number() {
                    1 => self.rejected_data_points = field.as_varint()?.cast_signed(),
                    2 => {
                        self.error_message = decode_string(
                            field,
                            decoder,
                            MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES,
                            "partial-success error message bytes",
                        )?;
                    }
                    _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
                }
                Ok(true)
            }

            fn validate_otlp(
                &self,
                budget: &mut ValidationBudget,
                _any_value_depth: usize,
            ) -> Result<(), ProtobufWireError> {
                if budget.enforces_invariants() && self.rejected_data_points < 0 {
                    return Err(ProtobufWireError::SchemaInvariant {
                        offset: 0,
                        invariant: "partial-success rejected data-point count must be nonnegative",
                    });
                }
                budget.owned_bytes(
                    self.error_message.len(),
                    MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES,
                    "partial-success error message bytes",
                )?;
                validate_unknown(&self.unknown_fields, budget)
            }
        }

        impl_proto_message!(ExportMetricsPartialSuccess);
    }

    macro_rules! impl_collector_proto_message {
        ($type:ty) => {
            impl ProtoMessage for $type {
                fn encode_fields(
                    &self,
                    encoder: &mut ProtobufWireEncoder,
                ) -> Result<(), ProtobufWireError> {
                    let remaining_work = encoder.remaining_work()?;
                    let validation = validate_root(self, remaining_work, true)?;
                    encoder.charge_schema_work(validation.work_used)?;
                    self.encode_fields_unchecked(encoder)
                }

                fn merge_field<'wire>(
                    &mut self,
                    field: &ProtobufWireField<'wire>,
                    decoder: &mut ProtobufWireDecoder<'wire, '_>,
                ) -> Result<bool, ProtobufWireError> {
                    self.merge_otlp_field(field, decoder)
                }

                fn merge_from_bytes(
                    &mut self,
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<(), ProtobufWireError> {
                    merge_root(self, input, limits)
                }

                fn decode_from_bytes(
                    input: &[u8],
                    limits: ProtobufWireLimits,
                ) -> Result<Self, ProtobufWireError> {
                    let mut staged = Self::default();
                    merge_root(&mut staged, input, limits)?;
                    Ok(staged)
                }
            }
        };
    }

    macro_rules! define_collector_family {
        (
            $module:ident,
            $resource_type:ident,
            $request_type:ident,
            $response_type:ident,
            $partial_type:ident,
            $resource_field:ident,
            $resource_name:literal,
            $rejected_field:ident,
            $rejected_invariant:literal
        ) => {
            pub(crate) mod $module {
                use super::super::limits_and_error::{
                    MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES, MAX_RESOURCE_GROUPS_PER_REQUEST,
                    OtlpModel, ValidationBudget, decode_string, encode_nested,
                    merge_optional_message, merge_root, preserve_unknown, push_message,
                    validate_root, validate_unknown,
                };
                use super::super::$module::$resource_type;
                use super::super::{
                    ProtoMessage, ProtobufWireDecoder, ProtobufWireEncoder, ProtobufWireError,
                    ProtobufWireField, ProtobufWireLimits, UnknownFields,
                };

                #[derive(Clone, Debug, Default, PartialEq)]
                pub(crate) struct $request_type {
                    pub(crate) $resource_field: Vec<$resource_type>,
                    pub(crate) unknown_fields: UnknownFields,
                }

                impl OtlpModel for $request_type {
                    fn encode_fields_unchecked(
                        &self,
                        encoder: &mut ProtobufWireEncoder,
                    ) -> Result<(), ProtobufWireError> {
                        for resource_group in &self.$resource_field {
                            encode_nested(encoder, 1, resource_group)?;
                        }
                        self.unknown_fields.encode(encoder)
                    }

                    fn merge_otlp_field<'wire>(
                        &mut self,
                        field: &ProtobufWireField<'wire>,
                        decoder: &mut ProtobufWireDecoder<'wire, '_>,
                    ) -> Result<bool, ProtobufWireError> {
                        match field.field_number() {
                            1 => push_message(
                                &mut self.$resource_field,
                                field,
                                decoder,
                                MAX_RESOURCE_GROUPS_PER_REQUEST,
                                $resource_name,
                                false,
                            )?,
                            _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
                        }
                        Ok(true)
                    }

                    fn validate_otlp(
                        &self,
                        budget: &mut ValidationBudget,
                        _any_value_depth: usize,
                    ) -> Result<(), ProtobufWireError> {
                        budget.repeated(
                            self.$resource_field.len(),
                            MAX_RESOURCE_GROUPS_PER_REQUEST,
                            $resource_name,
                        )?;
                        for resource_group in &self.$resource_field {
                            resource_group.validate_otlp(budget, 0)?;
                        }
                        validate_unknown(&self.unknown_fields, budget)
                    }
                }

                impl_collector_proto_message!($request_type);

                #[derive(Clone, Debug, Default, PartialEq)]
                pub(crate) struct $response_type {
                    pub(crate) partial_success: Option<$partial_type>,
                    pub(crate) unknown_fields: UnknownFields,
                }

                impl OtlpModel for $response_type {
                    fn encode_fields_unchecked(
                        &self,
                        encoder: &mut ProtobufWireEncoder,
                    ) -> Result<(), ProtobufWireError> {
                        if let Some(partial_success) = &self.partial_success {
                            encode_nested(encoder, 1, partial_success)?;
                        }
                        self.unknown_fields.encode(encoder)
                    }

                    fn merge_otlp_field<'wire>(
                        &mut self,
                        field: &ProtobufWireField<'wire>,
                        decoder: &mut ProtobufWireDecoder<'wire, '_>,
                    ) -> Result<bool, ProtobufWireError> {
                        match field.field_number() {
                            1 => merge_optional_message(
                                &mut self.partial_success,
                                field,
                                decoder,
                                false,
                            )?,
                            _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
                        }
                        Ok(true)
                    }

                    fn validate_otlp(
                        &self,
                        budget: &mut ValidationBudget,
                        _any_value_depth: usize,
                    ) -> Result<(), ProtobufWireError> {
                        if let Some(partial_success) = &self.partial_success {
                            partial_success.validate_otlp(budget, 0)?;
                        }
                        validate_unknown(&self.unknown_fields, budget)
                    }
                }

                impl_collector_proto_message!($response_type);

                #[derive(Clone, Debug, Default, PartialEq)]
                pub(crate) struct $partial_type {
                    pub(crate) $rejected_field: i64,
                    pub(crate) error_message: String,
                    pub(crate) unknown_fields: UnknownFields,
                }

                impl OtlpModel for $partial_type {
                    fn encode_fields_unchecked(
                        &self,
                        encoder: &mut ProtobufWireEncoder,
                    ) -> Result<(), ProtobufWireError> {
                        if self.$rejected_field != 0 {
                            encoder.write_int64(1, self.$rejected_field)?;
                        }
                        if !self.error_message.is_empty() {
                            encoder.write_string(2, &self.error_message)?;
                        }
                        self.unknown_fields.encode(encoder)
                    }

                    fn merge_otlp_field<'wire>(
                        &mut self,
                        field: &ProtobufWireField<'wire>,
                        decoder: &mut ProtobufWireDecoder<'wire, '_>,
                    ) -> Result<bool, ProtobufWireError> {
                        match field.field_number() {
                            1 => self.$rejected_field = field.as_varint()?.cast_signed(),
                            2 => {
                                self.error_message = decode_string(
                                    field,
                                    decoder,
                                    MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES,
                                    "partial-success error message bytes",
                                )?;
                            }
                            _ => preserve_unknown(&mut self.unknown_fields, field, decoder)?,
                        }
                        Ok(true)
                    }

                    fn validate_otlp(
                        &self,
                        budget: &mut ValidationBudget,
                        _any_value_depth: usize,
                    ) -> Result<(), ProtobufWireError> {
                        if budget.enforces_invariants() && self.$rejected_field < 0 {
                            return Err(ProtobufWireError::SchemaInvariant {
                                offset: 0,
                                invariant: $rejected_invariant,
                            });
                        }
                        budget.owned_bytes(
                            self.error_message.len(),
                            MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES,
                            "partial-success error message bytes",
                        )?;
                        validate_unknown(&self.unknown_fields, budget)
                    }
                }

                impl_collector_proto_message!($partial_type);
            }
        };
    }

    define_collector_family!(
        trace,
        ResourceSpans,
        ExportTraceServiceRequest,
        ExportTraceServiceResponse,
        ExportTracePartialSuccess,
        resource_spans,
        "trace resource groups",
        rejected_spans,
        "partial-success rejected span count must be nonnegative"
    );

    define_collector_family!(
        logs,
        ResourceLogs,
        ExportLogsServiceRequest,
        ExportLogsServiceResponse,
        ExportLogsPartialSuccess,
        resource_logs,
        "log resource groups",
        rejected_log_records,
        "partial-success rejected log-record count must be nonnegative"
    );
}

#[cfg(test)]
mod tests {
    use crate::grpc::codec::Codec;
    use crate::grpc::protobuf::ProtoCodec;

    use super::collector::logs::{
        ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
    };
    use super::collector::metrics::{
        ExportMetricsPartialSuccess, ExportMetricsServiceRequest, ExportMetricsServiceResponse,
    };
    use super::collector::trace::{
        ExportTracePartialSuccess, ExportTraceServiceRequest, ExportTraceServiceResponse,
    };
    use super::common_and_resource::{
        AnyValue, AnyValueValue, ArrayValue, EntityRef, InstrumentationScope, KeyValue, Resource,
    };
    use super::limits_and_error::{
        MAX_ANY_VALUE_DEPTH, MAX_ANY_VALUE_ITEMS, MAX_ATTRIBUTE_VALUE_BYTES, MAX_ATTRIBUTES,
        MAX_DATA_POINTS_PER_METRIC, MAX_EVENT_NAME_BYTES, MAX_EVENTS_PER_SPAN,
        MAX_EXEMPLARS_PER_DATA_POINT, MAX_EXPONENTIAL_HISTOGRAM_BUCKETS,
        MAX_HISTOGRAM_BUCKET_COUNTS, MAX_HISTOGRAM_EXPLICIT_BOUNDS, MAX_LINKS_PER_SPAN,
        MAX_LOG_EVENT_NAME_BYTES, MAX_LOG_RECORDS_PER_SCOPE, MAX_LOG_SEVERITY_TEXT_BYTES,
        MAX_METRIC_DESCRIPTION_BYTES, MAX_METRIC_METADATA_ENTRIES, MAX_METRIC_NAME_BYTES,
        MAX_METRIC_UNIT_BYTES, MAX_METRICS_PER_SCOPE, MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES,
        MAX_RESOURCE_GROUPS_PER_REQUEST, MAX_SCHEMA_URL_BYTES, MAX_SCOPES_PER_RESOURCE_GROUP,
        MAX_SPAN_ID_BYTES, MAX_SPAN_NAME_BYTES, MAX_SPANS_PER_SCOPE, MAX_SUMMARY_QUANTILES,
        MAX_TOTAL_ANY_VALUE_NODES, MAX_TOTAL_OWNED_BYTES, MAX_TOTAL_REPEATED_ITEMS,
        MAX_TRACE_ID_BYTES, MAX_TRACE_STATE_BYTES, ValidationBudget,
    };
    use super::logs::{
        LogRecord, LogRecordFlags, LogsData, ResourceLogs, ScopeLogs, SeverityNumber,
    };
    use super::metrics::{
        AggregationTemporality, DataPointFlags, Exemplar, ExemplarValue, ExponentialHistogram,
        ExponentialHistogramBuckets, ExponentialHistogramDataPoint, Gauge, Histogram,
        HistogramDataPoint, Metric, MetricData, MetricsData, NumberDataPoint, NumberDataPointValue,
        ResourceMetrics, ScopeMetrics, Sum, Summary, SummaryDataPoint, SummaryValueAtQuantile,
    };
    use super::trace::{
        ResourceSpans, ScopeSpans, Span, SpanEvent, SpanFlags, SpanKind, SpanLink, Status,
        StatusCode, TracesData,
    };
    use super::{
        ProtoMessage, ProtobufWireEncoder, ProtobufWireError, ProtobufWireLimits, UnknownFields,
    };

    fn limits() -> ProtobufWireLimits {
        ProtobufWireLimits::default()
    }

    fn string_value(value: &str) -> AnyValue {
        AnyValue {
            value: Some(AnyValueValue::String(value.to_owned())),
            unknown_fields: UnknownFields::new(),
        }
    }

    fn nested_array(depth: usize) -> AnyValue {
        let mut value = string_value("leaf");
        for _ in 1..depth {
            value = AnyValue {
                value: Some(AnyValueValue::Array(ArrayValue {
                    values: vec![value],
                    unknown_fields: UnknownFields::new(),
                })),
                unknown_fields: UnknownFields::new(),
            };
        }
        value
    }

    fn attribute(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_owned(),
            value: Some(string_value(value)),
            ..KeyValue::default()
        }
    }

    fn unknown_fields(raw: &[u8]) -> UnknownFields {
        let mut unknown = UnknownFields::new();
        unknown
            .try_record_raw(raw)
            .expect("record bounded unknown-field fixture");
        unknown
    }

    fn exemplar(value: ExemplarValue) -> Exemplar {
        Exemplar {
            time_unix_nano: 17,
            value: Some(value),
            span_id: vec![0x22; MAX_SPAN_ID_BYTES],
            trace_id: vec![0x11; MAX_TRACE_ID_BYTES],
            filtered_attributes: vec![attribute("sample", "kept")],
            unknown_fields: UnknownFields::new(),
        }
    }

    fn number_point(value: NumberDataPointValue) -> NumberDataPoint {
        NumberDataPoint {
            start_time_unix_nano: 10,
            time_unix_nano: 20,
            value: Some(value),
            exemplars: Vec::new(),
            attributes: vec![attribute("route", "/")],
            flags: DataPointFlags::NO_RECORDED_VALUE_MASK.bits() | 0x8000_0000,
            unknown_fields: UnknownFields::new(),
        }
    }

    fn span_event() -> SpanEvent {
        SpanEvent {
            time_unix_nano: 15,
            name: "checkpoint".to_owned(),
            attributes: vec![attribute("event.kind", "state")],
            dropped_attributes_count: 1,
            unknown_fields: UnknownFields::new(),
        }
    }

    fn span_link() -> SpanLink {
        SpanLink {
            trace_id: vec![0x33; MAX_TRACE_ID_BYTES],
            span_id: vec![0x44; MAX_SPAN_ID_BYTES],
            trace_state: "vendor=link".to_owned(),
            attributes: vec![attribute("link.kind", "batch")],
            dropped_attributes_count: 2,
            flags: SpanFlags::CONTEXT_HAS_IS_REMOTE_MASK.bits()
                | SpanFlags::CONTEXT_IS_REMOTE_MASK.bits()
                | 0x8000_0001,
            unknown_fields: UnknownFields::new(),
        }
    }

    fn minimal_span() -> Span {
        Span {
            trace_id: vec![0x11; MAX_TRACE_ID_BYTES],
            span_id: vec![0x22; MAX_SPAN_ID_BYTES],
            name: "runtime.operation".to_owned(),
            start_time_unix_nano: 10,
            end_time_unix_nano: 20,
            ..Span::default()
        }
    }

    fn valid_span() -> Span {
        Span {
            trace_state: "vendor=span".to_owned(),
            kind: SpanKind::Internal.as_raw(),
            attributes: vec![attribute("component", "scheduler")],
            dropped_attributes_count: 3,
            dropped_events_count: 4,
            dropped_links_count: 5,
            flags: SpanFlags::TRACE_FLAGS_MASK.bits() | 0x8000_0000,
            ..minimal_span()
        }
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants_trace_round_trip_preserves_every_field_family()
     {
        let mut span = valid_span();
        span.parent_span_id = vec![0x55; MAX_SPAN_ID_BYTES];
        span.kind = -7;
        span.events = vec![span_event()];
        span.links = vec![span_link()];
        span.status = Some(Status {
            message: "operation failed".to_owned(),
            code: -9,
            unknown_fields: UnknownFields::new(),
        });

        let model = TracesData {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource::default()),
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: "asupersync.runtime".to_owned(),
                        version: "1".to_owned(),
                        ..InstrumentationScope::default()
                    }),
                    spans: vec![span],
                    schema_url: "https://opentelemetry.io/schemas/1.37.0".to_owned(),
                    unknown_fields: UnknownFields::new(),
                }],
                schema_url: "https://opentelemetry.io/schemas/1.37.0".to_owned(),
                unknown_fields: UnknownFields::new(),
            }],
            unknown_fields: UnknownFields::new(),
        };

        let first = model
            .encode_to_bytes(limits())
            .expect("encode complete trace family");
        let decoded =
            TracesData::decode_from_bytes(&first, limits()).expect("decode complete trace family");
        assert_eq!(decoded, model);
        assert_eq!(
            decoded
                .encode_to_bytes(limits())
                .expect("repeat complete trace encoding"),
            first
        );

        let decoded_span = &decoded.resource_spans[0].scope_spans[0].spans[0];
        assert_eq!(SpanKind::from_raw(decoded_span.kind), None);
        assert_eq!(
            StatusCode::from_raw(
                decoded_span
                    .status
                    .as_ref()
                    .expect("status must remain present")
                    .code
            ),
            None
        );
        assert_eq!(
            SpanFlags::from_bits_retain(decoded_span.flags).trace_flags(),
            0xff
        );
        let link_flags = SpanFlags::from_bits_retain(decoded_span.links[0].flags);
        assert_eq!(link_flags.context_is_remote(), Some(true));
        assert!(link_flags.contains(SpanFlags::CONTEXT_IS_REMOTE_MASK));
        assert_eq!(link_flags.bits() & 0x8000_0000, 0x8000_0000);
        assert_eq!(
            SpanKind::from_raw(SpanKind::Server.as_raw()),
            Some(SpanKind::Server)
        );
        assert_eq!(
            StatusCode::from_raw(StatusCode::Error.as_raw()),
            Some(StatusCode::Error)
        );
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__property_matrix_trace_presence_merge_reserved_and_wire_types()
     {
        let mut status_message = ProtobufWireEncoder::new(limits());
        status_message
            .write_string(2, "merged")
            .expect("encode status message");
        status_message
            .write_varint(1, 7)
            .expect("encode reserved status tag");
        let status_message = status_message.finish().expect("finish status message");
        let mut status_code = ProtobufWireEncoder::new(limits());
        status_code
            .write_enum(3, -11)
            .expect("encode unknown status code");
        let status_code = status_code.finish().expect("finish status code");

        let mut merged_span = valid_span()
            .encode_to_bytes(limits())
            .expect("encode valid span")
            .to_vec();
        let mut additions = ProtobufWireEncoder::new(limits());
        additions
            .write_message(15, &status_message)
            .expect("encode first status occurrence");
        additions
            .write_message(15, &status_code)
            .expect("encode second status occurrence");
        additions
            .write_varint(17, 9)
            .expect("encode unknown span field");
        merged_span.extend_from_slice(
            &additions
                .finish()
                .expect("finish duplicate status occurrences"),
        );

        let decoded =
            Span::decode_from_bytes(&merged_span, limits()).expect("decode merged status");
        let status = decoded.status.as_ref().expect("status remains present");
        assert_eq!(status.message, "merged");
        assert_eq!(status.code, -11);
        assert_eq!(status.unknown_fields.as_bytes(), [0x08, 0x07]);
        assert_eq!(decoded.unknown_fields.as_bytes(), [0x88, 0x01, 0x09]);
        assert_eq!(
            Span::decode_from_bytes(
                &decoded
                    .encode_to_bytes(limits())
                    .expect("re-encode merged status"),
                limits(),
            )
            .expect("decode canonical merged status"),
            decoded
        );

        let mut last_value_wins = ProtobufWireEncoder::new(limits());
        last_value_wins
            .write_bytes(1, &[0x01; MAX_TRACE_ID_BYTES - 1])
            .expect("encode superseded short trace ID");
        last_value_wins
            .write_bytes(1, &[0x11; MAX_TRACE_ID_BYTES])
            .expect("encode final valid trace ID");
        last_value_wins
            .write_bytes(2, &[0x22; MAX_SPAN_ID_BYTES])
            .expect("encode valid span ID");
        last_value_wins
            .write_string(3, "Vendor=invalid")
            .expect("encode superseded malformed trace state");
        last_value_wins
            .write_string(3, "vendor=valid")
            .expect("encode final valid trace state");
        last_value_wins
            .write_string(5, "last value wins")
            .expect("encode span name");
        last_value_wins
            .write_fixed64(7, 10)
            .expect("encode span start");
        last_value_wins
            .write_fixed64(8, 20)
            .expect("encode span end");
        let last_value_wins = Span::decode_from_bytes(
            &last_value_wins.finish().expect("finish duplicate ID span"),
            limits(),
        )
        .expect("later valid span ID occurrence must supersede earlier invalid value");
        assert_eq!(last_value_wins.trace_id, vec![0x11; MAX_TRACE_ID_BYTES]);
        assert_eq!(last_value_wins.trace_state, "vendor=valid");

        let mut link_last_value_wins = ProtobufWireEncoder::new(limits());
        link_last_value_wins
            .write_bytes(1, &[0; MAX_TRACE_ID_BYTES - 1])
            .expect("encode superseded short link trace ID");
        link_last_value_wins
            .write_bytes(1, &[0x33; MAX_TRACE_ID_BYTES])
            .expect("encode final valid link trace ID");
        link_last_value_wins
            .write_bytes(2, &[0x44; MAX_SPAN_ID_BYTES])
            .expect("encode valid link span ID");
        let link_last_value_wins = SpanLink::decode_from_bytes(
            &link_last_value_wins
                .finish()
                .expect("finish duplicate link ID"),
            limits(),
        )
        .expect("later valid link ID occurrence must supersede earlier invalid value");
        assert_eq!(
            link_last_value_wins.trace_id,
            vec![0x33; MAX_TRACE_ID_BYTES]
        );

        let present_empty = Span {
            status: Some(Status::default()),
            ..valid_span()
        };
        let present_empty_wire = present_empty
            .encode_to_bytes(limits())
            .expect("encode present empty status");
        assert_eq!(
            Span::decode_from_bytes(&present_empty_wire, limits())
                .expect("decode present empty status")
                .status,
            Some(Status::default())
        );

        let mut reserved_resource = ProtobufWireEncoder::new(limits());
        reserved_resource
            .write_varint(1000, 1)
            .expect("encode reserved ResourceSpans tag");
        let reserved_resource = reserved_resource
            .finish()
            .expect("finish reserved ResourceSpans tag");
        let decoded_resource = ResourceSpans::decode_from_bytes(&reserved_resource, limits())
            .expect("decode reserved ResourceSpans tag");
        assert_eq!(
            decoded_resource.unknown_fields.as_bytes(),
            reserved_resource.as_ref()
        );
        assert_eq!(
            decoded_resource
                .encode_to_bytes(limits())
                .expect("re-encode reserved ResourceSpans tag"),
            reserved_resource
        );

        let mut wrong_flags = valid_span()
            .encode_to_bytes(limits())
            .expect("encode valid span for wrong-wire suffix")
            .to_vec();
        let mut wrong_flags_suffix = ProtobufWireEncoder::new(limits());
        wrong_flags_suffix
            .write_varint(16, 1)
            .expect("encode wrong-wire span flags");
        wrong_flags.extend_from_slice(
            &wrong_flags_suffix
                .finish()
                .expect("finish wrong-wire span flags"),
        );
        assert!(matches!(
            Span::decode_from_bytes(&wrong_flags, limits()),
            Err(ProtobufWireError::WireTypeMismatch { .. })
        ));
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants_trace_collection_limits_are_exact()
     {
        TracesData {
            resource_spans: vec![ResourceSpans::default(); MAX_RESOURCE_GROUPS_PER_REQUEST],
            unknown_fields: UnknownFields::new(),
        }
        .encode_to_bytes(limits())
        .expect("exact trace resource-group limit");
        assert!(matches!(
            TracesData {
                resource_spans: vec![
                    ResourceSpans::default();
                    MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                ],
                unknown_fields: UnknownFields::new(),
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "trace resource groups",
                observed,
                limit,
                ..
            }) if observed == MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                && limit == MAX_RESOURCE_GROUPS_PER_REQUEST
        ));

        ResourceSpans {
            scope_spans: vec![ScopeSpans::default(); MAX_SCOPES_PER_RESOURCE_GROUP],
            ..ResourceSpans::default()
        }
        .encode_to_bytes(limits())
        .expect("exact trace scope limit");
        assert!(matches!(
            ResourceSpans {
                scope_spans: vec![ScopeSpans::default(); MAX_SCOPES_PER_RESOURCE_GROUP + 1],
                ..ResourceSpans::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "trace scopes per resource group",
                observed,
                limit,
                ..
            }) if observed == MAX_SCOPES_PER_RESOURCE_GROUP + 1
                && limit == MAX_SCOPES_PER_RESOURCE_GROUP
        ));

        ScopeSpans {
            spans: vec![minimal_span(); MAX_SPANS_PER_SCOPE],
            ..ScopeSpans::default()
        }
        .encode_to_bytes(limits())
        .expect("exact spans-per-scope limit");
        assert!(matches!(
            ScopeSpans {
                spans: vec![minimal_span(); MAX_SPANS_PER_SCOPE + 1],
                ..ScopeSpans::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "spans per scope",
                observed,
                limit,
                ..
            }) if observed == MAX_SPANS_PER_SCOPE + 1 && limit == MAX_SPANS_PER_SCOPE
        ));

        let mut exact_events = valid_span();
        exact_events.events = vec![span_event(); MAX_EVENTS_PER_SPAN];
        exact_events
            .encode_to_bytes(limits())
            .expect("exact span event limit");
        let mut over_events = valid_span();
        over_events.events = vec![span_event(); MAX_EVENTS_PER_SPAN + 1];
        assert!(matches!(
            over_events.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "span events",
                observed,
                limit,
                ..
            }) if observed == MAX_EVENTS_PER_SPAN + 1 && limit == MAX_EVENTS_PER_SPAN
        ));

        let mut exact_links = valid_span();
        exact_links.links = vec![span_link(); MAX_LINKS_PER_SPAN];
        exact_links
            .encode_to_bytes(limits())
            .expect("exact span link limit");
        let mut over_links = valid_span();
        over_links.links = vec![span_link(); MAX_LINKS_PER_SPAN + 1];
        assert!(matches!(
            over_links.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "span links",
                observed,
                limit,
                ..
            }) if observed == MAX_LINKS_PER_SPAN + 1 && limit == MAX_LINKS_PER_SPAN
        ));

        let exact_attributes = (0..MAX_ATTRIBUTES)
            .map(|index| attribute(&format!("trace-key-{index}"), "value"))
            .collect::<Vec<_>>();
        let mut exact_attribute_span = valid_span();
        exact_attribute_span.attributes = exact_attributes;
        exact_attribute_span
            .encode_to_bytes(limits())
            .expect("exact span attribute limit");
        let mut over_attribute_span = valid_span();
        over_attribute_span.attributes = vec![KeyValue::default(); MAX_ATTRIBUTES + 1];
        assert!(matches!(
            over_attribute_span.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "span attributes",
                observed,
                limit,
                ..
            }) if observed == MAX_ATTRIBUTES + 1 && limit == MAX_ATTRIBUTES
        ));

        let span_wire = minimal_span()
            .encode_to_bytes(limits())
            .expect("encode reusable span fixture");
        let mut one_over_wire = ProtobufWireEncoder::new(limits());
        for _ in 0..=MAX_SPANS_PER_SCOPE {
            one_over_wire
                .write_message(2, &span_wire)
                .expect("encode one-over span fixture");
        }
        assert!(matches!(
            ScopeSpans::decode_from_bytes(
                &one_over_wire.finish().expect("finish one-over spans"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "spans per scope",
                observed,
                limit,
                ..
            }) if observed == MAX_SPANS_PER_SCOPE + 1 && limit == MAX_SPANS_PER_SCOPE
        ));
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants_trace_scalar_limits_and_semantics()
     {
        let mut exact = valid_span();
        exact.name = "n".repeat(MAX_SPAN_NAME_BYTES);
        exact.trace_state = format!("a{}={}", "b".repeat(254), "v".repeat(256));
        assert_eq!(exact.trace_state.len(), MAX_TRACE_STATE_BYTES);
        exact.events = vec![SpanEvent {
            name: "e".repeat(MAX_EVENT_NAME_BYTES),
            ..span_event()
        }];
        exact
            .encode_to_bytes(limits())
            .expect("exact trace string limits");

        let mut over_name = valid_span();
        over_name.name = "n".repeat(MAX_SPAN_NAME_BYTES + 1);
        assert!(matches!(
            over_name.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "span name bytes",
                observed,
                limit,
                ..
            }) if observed == MAX_SPAN_NAME_BYTES + 1 && limit == MAX_SPAN_NAME_BYTES
        ));
        let mut over_state = valid_span();
        over_state.trace_state = format!("a{}={}", "b".repeat(255), "v".repeat(256));
        assert_eq!(over_state.trace_state.len(), MAX_TRACE_STATE_BYTES + 1);
        assert!(matches!(
            over_state.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "span trace state bytes",
                ..
            })
        ));
        for malformed_trace_state in [
            "Vendor=value".to_owned(),
            "vendor=one,vendor=two".to_owned(),
            "vendor=value ".to_owned(),
            "vendor==value".to_owned(),
            "vendor =value".to_owned(),
            "vendor=\tvalue".to_owned(),
            (0..33)
                .map(|index| format!("v{index}=value"))
                .collect::<Vec<_>>()
                .join(","),
        ] {
            let mut malformed = valid_span();
            malformed.trace_state = malformed_trace_state;
            assert!(matches!(
                malformed.encode_to_bytes(limits()),
                Err(ProtobufWireError::SchemaInvariant {
                    invariant: "trace state must use the W3C tracestate format",
                    ..
                })
            ));
        }
        let mut work_limited = valid_span();
        work_limited.trace_state = "vendor=value".to_owned();
        let trace_state_work = work_limited.trace_state.len();
        assert!(matches!(
            work_limited.encode_to_bytes(limits().with_max_work(trace_state_work - 1)),
            Err(ProtobufWireError::WorkLimitExceeded { work, limit, .. })
                if work == trace_state_work && limit == trace_state_work - 1
        ));
        let mut over_event_name = span_event();
        over_event_name.name = "e".repeat(MAX_EVENT_NAME_BYTES + 1);
        assert!(matches!(
            over_event_name.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "span event name bytes",
                ..
            })
        ));
        assert!(
            Status {
                message: "x".repeat(MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES + 1),
                ..Status::default()
            }
            .encode_to_bytes(limits())
            .is_ok(),
            "trace status messages use the recorded shared/generic bound, not the partial-success cap"
        );

        for invalid_trace_id in [
            Vec::new(),
            vec![0; MAX_TRACE_ID_BYTES],
            vec![1; MAX_TRACE_ID_BYTES - 1],
            vec![1; MAX_TRACE_ID_BYTES + 1],
        ] {
            let mut span = valid_span();
            span.trace_id = invalid_trace_id;
            assert!(matches!(
                span.encode_to_bytes(limits()),
                Err(ProtobufWireError::SchemaInvariant {
                    invariant: "span trace ID must be a nonzero sixteen-byte value",
                    ..
                })
            ));
        }
        for invalid_span_id in [
            Vec::new(),
            vec![0; MAX_SPAN_ID_BYTES],
            vec![1; MAX_SPAN_ID_BYTES - 1],
            vec![1; MAX_SPAN_ID_BYTES + 1],
        ] {
            let mut span = valid_span();
            span.span_id = invalid_span_id;
            assert!(matches!(
                span.encode_to_bytes(limits()),
                Err(ProtobufWireError::SchemaInvariant {
                    invariant: "span ID must be a nonzero eight-byte value",
                    ..
                })
            ));
        }
        let mut invalid_parent = valid_span();
        invalid_parent.parent_span_id = vec![0; MAX_SPAN_ID_BYTES];
        invalid_parent
            .encode_to_bytes(limits())
            .expect("exact-width zero parent span ID follows the pinned width contract");
        invalid_parent.parent_span_id = vec![1; MAX_SPAN_ID_BYTES - 1];
        assert!(matches!(
            invalid_parent.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "parent span ID must be empty or exactly eight bytes",
                ..
            })
        ));
        assert!(matches!(
            SpanLink::default().encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "span link trace ID must be exactly sixteen bytes",
                ..
            })
        ));
        SpanLink {
            trace_id: vec![0; MAX_TRACE_ID_BYTES],
            span_id: vec![0; MAX_SPAN_ID_BYTES],
            ..SpanLink::default()
        }
        .encode_to_bytes(limits())
        .expect("exact-width zero link IDs follow the pinned width contract");

        let mut empty_name = valid_span();
        empty_name.name.clear();
        assert!(matches!(
            empty_name.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "span name must not be empty",
                ..
            })
        ));
        assert!(matches!(
            SpanEvent::default().encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "span event name must not be empty",
                ..
            })
        ));
        let mut zero_start = valid_span();
        zero_start.start_time_unix_nano = 0;
        assert!(matches!(
            zero_start.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "span start_time_unix_nano must be nonzero",
                ..
            })
        ));
        let mut zero_end = valid_span();
        zero_end.end_time_unix_nano = 0;
        assert!(matches!(
            zero_end.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "span end_time_unix_nano must be nonzero",
                ..
            })
        ));
        let mut reversed = valid_span();
        reversed.start_time_unix_nano = 21;
        reversed.end_time_unix_nano = 20;
        assert!(matches!(
            reversed.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "span end_time_unix_nano must not precede start_time_unix_nano",
                ..
            })
        ));
        let mut duplicate_attributes = valid_span();
        duplicate_attributes.attributes =
            vec![attribute("duplicate", "one"), attribute("duplicate", "two")];
        assert!(matches!(
            duplicate_attributes.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "span attribute keys must be unique",
                ..
            })
        ));

        let mut invalid_id_wire = ProtobufWireEncoder::new(limits());
        invalid_id_wire
            .write_bytes(1, &[1; MAX_TRACE_ID_BYTES - 1])
            .expect("encode invalid trace ID fixture");
        assert!(matches!(
            Span::decode_from_bytes(
                &invalid_id_wire.finish().expect("finish invalid trace ID"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "span trace ID must be a nonzero sixteen-byte value",
                ..
            })
        ));
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__lab_lifecycle_trace_failure_state() {
        let mut malformed = ProtobufWireEncoder::new(limits());
        malformed
            .write_string(5, "retained before ID failure")
            .expect("encode retained span name");
        malformed
            .write_bytes(1, &[1; MAX_TRACE_ID_BYTES - 1])
            .expect("encode invalid trace ID");
        let malformed = malformed.finish().expect("finish malformed span");
        assert!(Span::decode_from_bytes(&malformed, limits()).is_err());

        let mut merge_target = Span::default();
        assert!(merge_target.merge_from_bytes(&malformed, limits()).is_err());
        assert_eq!(merge_target.name, "retained before ID failure");
        assert_eq!(merge_target.trace_id, vec![1; MAX_TRACE_ID_BYTES - 1]);

        let mut valid_merge_target = valid_span();
        assert!(
            valid_merge_target
                .merge_from_bytes(&malformed, limits())
                .is_err()
        );
        assert_eq!(valid_merge_target.name, "retained before ID failure");
        assert_eq!(valid_merge_target.trace_id, vec![1; MAX_TRACE_ID_BYTES - 1]);
        assert_eq!(valid_merge_target.span_id, vec![0x22; MAX_SPAN_ID_BYTES]);
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__downstream_consumer_trace_generic_codec() {
        let model = TracesData {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![valid_span()],
                    ..ScopeSpans::default()
                }],
                ..ResourceSpans::default()
            }],
            unknown_fields: UnknownFields::new(),
        };
        let mut codec: ProtoCodec<TracesData, TracesData> = ProtoCodec::new();
        let encoded = codec.encode(&model).expect("generic traces codec encode");
        assert_eq!(
            codec.decode(&encoded).expect("generic traces codec decode"),
            model
        );
    }

    #[test]
    fn collector_metrics_round_trip_preserves_presence_unknowns_and_merge_semantics() {
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics::default()],
            unknown_fields: UnknownFields::new(),
        };
        let request_wire = request
            .encode_to_bytes(limits())
            .expect("encode metrics export request");
        assert_eq!(
            ExportMetricsServiceRequest::decode_from_bytes(&request_wire, limits())
                .expect("decode metrics export request"),
            request
        );
        assert_eq!(
            request
                .encode_to_bytes(limits())
                .expect("repeat metrics export request encoding"),
            request_wire
        );

        let response = ExportMetricsServiceResponse {
            partial_success: Some(ExportMetricsPartialSuccess {
                rejected_data_points: 2,
                error_message: "two points were rejected".to_owned(),
                unknown_fields: UnknownFields::new(),
            }),
            unknown_fields: UnknownFields::new(),
        };
        let response_wire = response
            .encode_to_bytes(limits())
            .expect("encode metrics export response");
        assert_eq!(
            ExportMetricsServiceResponse::decode_from_bytes(&response_wire, limits())
                .expect("decode metrics export response"),
            response
        );
        assert_eq!(
            response
                .encode_to_bytes(limits())
                .expect("repeat metrics export response encoding"),
            response_wire
        );

        let empty_partial = ExportMetricsServiceResponse {
            partial_success: Some(ExportMetricsPartialSuccess::default()),
            unknown_fields: UnknownFields::new(),
        };
        let empty_wire = empty_partial
            .encode_to_bytes(limits())
            .expect("encode present empty partial success");
        assert_eq!(empty_wire.as_ref(), &[0x0a, 0x00]);
        assert_eq!(
            ExportMetricsServiceResponse::decode_from_bytes(&empty_wire, limits())
                .expect("decode present empty partial success"),
            empty_partial
        );

        let mut count_fragment = ProtobufWireEncoder::new(limits());
        count_fragment
            .write_int64(1, 3)
            .expect("encode rejected count fragment");
        let count_fragment = count_fragment.finish().expect("finish count fragment");
        let mut message_fragment = ProtobufWireEncoder::new(limits());
        message_fragment
            .write_string(2, "retry")
            .expect("encode partial-success message fragment");
        message_fragment
            .write_varint(3, 7)
            .expect("encode nested unknown field");
        let message_fragment = message_fragment.finish().expect("finish message fragment");
        let mut merged_wire = ProtobufWireEncoder::new(limits());
        merged_wire
            .write_message(1, &count_fragment)
            .expect("encode first partial-success occurrence");
        merged_wire
            .write_message(1, &message_fragment)
            .expect("encode second partial-success occurrence");
        merged_wire
            .write_varint(2, 9)
            .expect("encode response unknown field");
        let merged = ExportMetricsServiceResponse::decode_from_bytes(
            &merged_wire.finish().expect("finish merge fixture"),
            limits(),
        )
        .expect("decode merged partial success");
        let partial = merged
            .partial_success
            .expect("partial-success presence must survive merge");
        assert_eq!(partial.rejected_data_points, 3);
        assert_eq!(partial.error_message, "retry");
        assert_eq!(partial.unknown_fields.as_bytes(), [0x18, 0x07]);
        assert_eq!(merged.unknown_fields.as_bytes(), [0x10, 0x09]);
        let canonical_merged = ExportMetricsServiceResponse {
            partial_success: Some(partial),
            unknown_fields: merged.unknown_fields,
        };
        let canonical_merged_wire = canonical_merged
            .encode_to_bytes(limits())
            .expect("re-emit merged response unknown fields");
        assert!(canonical_merged_wire.ends_with(&[0x10, 0x09]));
        assert!(
            canonical_merged_wire
                .windows(2)
                .any(|pair| pair == [0x18, 0x07])
        );
        assert_eq!(
            ExportMetricsServiceResponse::decode_from_bytes(&canonical_merged_wire, limits())
                .expect("decode canonical merged response"),
            canonical_merged
        );
    }

    #[test]
    fn collector_metrics_limits_and_partial_success_invariants_are_exact() {
        let exact_request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics::default(); MAX_RESOURCE_GROUPS_PER_REQUEST],
            unknown_fields: UnknownFields::new(),
        };
        exact_request
            .encode_to_bytes(limits())
            .expect("encode exact metrics export group limit");
        assert!(matches!(
            ExportMetricsServiceRequest {
                resource_metrics: vec![
                    ResourceMetrics::default();
                    MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                ],
                unknown_fields: UnknownFields::new(),
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "metric resource groups",
                observed,
                limit,
                ..
            }) if observed == MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                && limit == MAX_RESOURCE_GROUPS_PER_REQUEST
        ));

        let mut exact_request_wire = ProtobufWireEncoder::new(limits());
        for _ in 0..MAX_RESOURCE_GROUPS_PER_REQUEST {
            exact_request_wire
                .write_message(1, &[])
                .expect("encode exact request group fixture");
        }
        ExportMetricsServiceRequest::decode_from_bytes(
            &exact_request_wire.finish().expect("finish exact request"),
            limits(),
        )
        .expect("decode exact metrics export group limit");
        let mut over_request_wire = ProtobufWireEncoder::new(limits());
        for _ in 0..=MAX_RESOURCE_GROUPS_PER_REQUEST {
            over_request_wire
                .write_message(1, &[])
                .expect("encode one-over request group fixture");
        }
        assert!(matches!(
            ExportMetricsServiceRequest::decode_from_bytes(
                &over_request_wire.finish().expect("finish one-over request"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "metric resource groups",
                observed,
                limit,
                ..
            }) if observed == MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                && limit == MAX_RESOURCE_GROUPS_PER_REQUEST
        ));

        let exact_message = "x".repeat(MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES);
        ExportMetricsPartialSuccess {
            rejected_data_points: 0,
            error_message: exact_message.clone(),
            unknown_fields: UnknownFields::new(),
        }
        .encode_to_bytes(limits())
        .expect("encode exact partial-success message limit");
        assert!(matches!(
            ExportMetricsPartialSuccess {
                rejected_data_points: 0,
                error_message: "x".repeat(MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES + 1),
                unknown_fields: UnknownFields::new(),
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "partial-success error message bytes",
                observed,
                limit,
                ..
            }) if observed == MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES + 1
                && limit == MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES
        ));

        let mut exact_message_wire = ProtobufWireEncoder::new(limits());
        exact_message_wire
            .write_string(2, &exact_message)
            .expect("encode exact partial-success decode fixture");
        ExportMetricsPartialSuccess::decode_from_bytes(
            &exact_message_wire.finish().expect("finish exact message"),
            limits(),
        )
        .expect("decode exact partial-success message limit");
        let mut over_message_wire = ProtobufWireEncoder::new(limits());
        over_message_wire
            .write_string(2, &"x".repeat(MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES + 1))
            .expect("encode one-over partial-success decode fixture");
        assert!(matches!(
            ExportMetricsPartialSuccess::decode_from_bytes(
                &over_message_wire.finish().expect("finish one-over message"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "partial-success error message bytes",
                observed,
                limit,
                ..
            }) if observed == MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES + 1
                && limit == MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES
        ));

        assert!(matches!(
            ExportMetricsPartialSuccess {
                rejected_data_points: -1,
                error_message: String::new(),
                unknown_fields: UnknownFields::new(),
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "partial-success rejected data-point count must be nonnegative",
                ..
            })
        ));
        let mut negative_wire = ProtobufWireEncoder::new(limits());
        negative_wire
            .write_int64(1, -1)
            .expect("encode negative rejected count fixture");
        assert!(matches!(
            ExportMetricsPartialSuccess::decode_from_bytes(
                &negative_wire.finish().expect("finish negative count"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "partial-success rejected data-point count must be nonnegative",
                ..
            })
        ));

        let mut invalid_merge_wire = ProtobufWireEncoder::new(limits());
        invalid_merge_wire
            .write_int64(1, -1)
            .expect("encode invalid merge count");
        invalid_merge_wire
            .write_string(2, "retained before validation failure")
            .expect("encode invalid merge message");
        let mut merge_target = ExportMetricsPartialSuccess::default();
        assert!(
            merge_target
                .merge_from_bytes(
                    &invalid_merge_wire.finish().expect("finish invalid merge"),
                    limits(),
                )
                .is_err()
        );
        assert_eq!(merge_target.rejected_data_points, -1);
        assert_eq!(
            merge_target.error_message,
            "retained before validation failure"
        );

        for accepted in [
            ExportMetricsPartialSuccess {
                rejected_data_points: 0,
                error_message: "warning without rejection".to_owned(),
                unknown_fields: UnknownFields::new(),
            },
            ExportMetricsPartialSuccess {
                rejected_data_points: 1,
                error_message: String::new(),
                unknown_fields: UnknownFields::new(),
            },
        ] {
            let encoded = accepted
                .encode_to_bytes(limits())
                .expect("encode accepted partial-success shape");
            assert_eq!(
                ExportMetricsPartialSuccess::decode_from_bytes(&encoded, limits())
                    .expect("decode accepted partial-success shape"),
                accepted
            );
        }
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__property_matrix_collector_trace_and_logs_round_trip()
     {
        let trace_request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans::default()],
            unknown_fields: unknown_fields(&[0x10, 0x09]),
        };
        let trace_request_wire = trace_request
            .encode_to_bytes(limits())
            .expect("encode trace export request");
        assert_eq!(
            ExportTraceServiceRequest::decode_from_bytes(&trace_request_wire, limits())
                .expect("decode trace export request"),
            trace_request
        );
        assert_eq!(
            trace_request
                .encode_to_bytes(limits())
                .expect("repeat trace export request encoding"),
            trace_request_wire
        );

        let logs_request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs::default()],
            unknown_fields: unknown_fields(&[0x10, 0x0a]),
        };
        let logs_request_wire = logs_request
            .encode_to_bytes(limits())
            .expect("encode logs export request");
        assert_eq!(
            ExportLogsServiceRequest::decode_from_bytes(&logs_request_wire, limits())
                .expect("decode logs export request"),
            logs_request
        );
        assert_eq!(
            logs_request
                .encode_to_bytes(limits())
                .expect("repeat logs export request encoding"),
            logs_request_wire
        );

        let trace_partial = ExportTracePartialSuccess {
            rejected_spans: 2,
            error_message: "two spans were rejected".to_owned(),
            unknown_fields: unknown_fields(&[0x18, 0x07]),
        };
        let trace_partial_wire = trace_partial
            .encode_to_bytes(limits())
            .expect("encode trace partial success");
        assert_eq!(
            ExportTracePartialSuccess::decode_from_bytes(&trace_partial_wire, limits())
                .expect("decode trace partial success"),
            trace_partial
        );
        let trace_response = ExportTraceServiceResponse {
            partial_success: Some(trace_partial),
            unknown_fields: unknown_fields(&[0x10, 0x09]),
        };
        let trace_response_wire = trace_response
            .encode_to_bytes(limits())
            .expect("encode trace export response");
        assert_eq!(
            ExportTraceServiceResponse::decode_from_bytes(&trace_response_wire, limits())
                .expect("decode trace export response"),
            trace_response
        );

        let logs_partial = ExportLogsPartialSuccess {
            rejected_log_records: 3,
            error_message: "three log records were rejected".to_owned(),
            unknown_fields: unknown_fields(&[0x18, 0x08]),
        };
        let logs_partial_wire = logs_partial
            .encode_to_bytes(limits())
            .expect("encode logs partial success");
        assert_eq!(
            ExportLogsPartialSuccess::decode_from_bytes(&logs_partial_wire, limits())
                .expect("decode logs partial success"),
            logs_partial
        );
        let logs_response = ExportLogsServiceResponse {
            partial_success: Some(logs_partial),
            unknown_fields: unknown_fields(&[0x10, 0x0a]),
        };
        let logs_response_wire = logs_response
            .encode_to_bytes(limits())
            .expect("encode logs export response");
        assert_eq!(
            ExportLogsServiceResponse::decode_from_bytes(&logs_response_wire, limits())
                .expect("decode logs export response"),
            logs_response
        );

        let empty_trace_response = ExportTraceServiceResponse {
            partial_success: Some(ExportTracePartialSuccess::default()),
            unknown_fields: UnknownFields::new(),
        };
        let empty_trace_wire = empty_trace_response
            .encode_to_bytes(limits())
            .expect("encode present empty trace partial success");
        assert_eq!(empty_trace_wire.as_ref(), &[0x0a, 0x00]);
        assert_eq!(
            ExportTraceServiceResponse::decode_from_bytes(&empty_trace_wire, limits())
                .expect("decode present empty trace partial success"),
            empty_trace_response
        );
        let empty_logs_response = ExportLogsServiceResponse {
            partial_success: Some(ExportLogsPartialSuccess::default()),
            unknown_fields: UnknownFields::new(),
        };
        let empty_logs_wire = empty_logs_response
            .encode_to_bytes(limits())
            .expect("encode present empty logs partial success");
        assert_eq!(empty_logs_wire.as_ref(), &[0x0a, 0x00]);
        assert_eq!(
            ExportLogsServiceResponse::decode_from_bytes(&empty_logs_wire, limits())
                .expect("decode present empty logs partial success"),
            empty_logs_response
        );

        let mut trace_count = ProtobufWireEncoder::new(limits());
        trace_count
            .write_int64(1, 4)
            .expect("encode rejected span count fragment");
        let trace_count = trace_count.finish().expect("finish span count fragment");
        let mut trace_message = ProtobufWireEncoder::new(limits());
        trace_message
            .write_string(2, "retry trace export")
            .expect("encode trace message fragment");
        trace_message
            .write_varint(3, 11)
            .expect("encode trace partial-success unknown");
        let trace_message = trace_message
            .finish()
            .expect("finish trace message fragment");
        let mut merged_trace_wire = ProtobufWireEncoder::new(limits());
        merged_trace_wire
            .write_message(1, &trace_count)
            .expect("encode first trace partial-success occurrence");
        merged_trace_wire
            .write_message(1, &trace_message)
            .expect("encode second trace partial-success occurrence");
        merged_trace_wire
            .write_varint(2, 12)
            .expect("encode trace response unknown");
        let merged_trace = ExportTraceServiceResponse::decode_from_bytes(
            &merged_trace_wire
                .finish()
                .expect("finish trace merge fixture"),
            limits(),
        )
        .expect("decode merged trace partial success");
        let merged_trace_partial = merged_trace
            .partial_success
            .expect("trace partial-success presence must survive merge");
        assert_eq!(merged_trace_partial.rejected_spans, 4);
        assert_eq!(merged_trace_partial.error_message, "retry trace export");
        assert_eq!(merged_trace_partial.unknown_fields.as_bytes(), [0x18, 0x0b]);
        assert_eq!(merged_trace.unknown_fields.as_bytes(), [0x10, 0x0c]);

        let mut logs_count = ProtobufWireEncoder::new(limits());
        logs_count
            .write_int64(1, 5)
            .expect("encode rejected log-record count fragment");
        let logs_count = logs_count.finish().expect("finish log count fragment");
        let mut logs_message = ProtobufWireEncoder::new(limits());
        logs_message
            .write_string(2, "retry logs export")
            .expect("encode logs message fragment");
        logs_message
            .write_varint(3, 13)
            .expect("encode logs partial-success unknown");
        let logs_message = logs_message.finish().expect("finish logs message fragment");
        let mut merged_logs_wire = ProtobufWireEncoder::new(limits());
        merged_logs_wire
            .write_message(1, &logs_count)
            .expect("encode first logs partial-success occurrence");
        merged_logs_wire
            .write_message(1, &logs_message)
            .expect("encode second logs partial-success occurrence");
        merged_logs_wire
            .write_varint(2, 14)
            .expect("encode logs response unknown");
        let merged_logs = ExportLogsServiceResponse::decode_from_bytes(
            &merged_logs_wire
                .finish()
                .expect("finish logs merge fixture"),
            limits(),
        )
        .expect("decode merged logs partial success");
        let merged_logs_partial = merged_logs
            .partial_success
            .expect("logs partial-success presence must survive merge");
        assert_eq!(merged_logs_partial.rejected_log_records, 5);
        assert_eq!(merged_logs_partial.error_message, "retry logs export");
        assert_eq!(merged_logs_partial.unknown_fields.as_bytes(), [0x18, 0x0d]);
        assert_eq!(merged_logs.unknown_fields.as_bytes(), [0x10, 0x0e]);
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants_collector_trace_and_logs_limits()
    {
        macro_rules! assert_request_limits {
            ($request:ident, $field:ident, $resource:ident, $resource_name:literal) => {{
                $request {
                    $field: vec![$resource::default(); MAX_RESOURCE_GROUPS_PER_REQUEST],
                    unknown_fields: UnknownFields::new(),
                }
                .encode_to_bytes(limits())
                .expect("encode exact collector request group limit");
                assert!(matches!(
                    $request {
                        $field: vec![
                            $resource::default();
                            MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                        ],
                        unknown_fields: UnknownFields::new(),
                    }
                    .encode_to_bytes(limits()),
                    Err(ProtobufWireError::SchemaLimitExceeded {
                        resource,
                        observed,
                        limit,
                        ..
                    }) if resource == $resource_name
                        && observed == MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                        && limit == MAX_RESOURCE_GROUPS_PER_REQUEST
                ));

                let mut exact_wire = ProtobufWireEncoder::new(limits());
                for _ in 0..MAX_RESOURCE_GROUPS_PER_REQUEST {
                    exact_wire
                        .write_message(1, &[])
                        .expect("encode exact collector request fixture");
                }
                $request::decode_from_bytes(
                    &exact_wire.finish().expect("finish exact collector request"),
                    limits(),
                )
                .expect("decode exact collector request group limit");
                let mut over_wire = ProtobufWireEncoder::new(limits());
                for _ in 0..=MAX_RESOURCE_GROUPS_PER_REQUEST {
                    over_wire
                        .write_message(1, &[])
                        .expect("encode one-over collector request fixture");
                }
                assert!(matches!(
                    $request::decode_from_bytes(
                        &over_wire.finish().expect("finish one-over collector request"),
                        limits(),
                    ),
                    Err(ProtobufWireError::SchemaLimitExceeded {
                        resource,
                        observed,
                        limit,
                        ..
                    }) if resource == $resource_name
                        && observed == MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                        && limit == MAX_RESOURCE_GROUPS_PER_REQUEST
                ));
            }};
        }

        assert_request_limits!(
            ExportTraceServiceRequest,
            resource_spans,
            ResourceSpans,
            "trace resource groups"
        );
        assert_request_limits!(
            ExportLogsServiceRequest,
            resource_logs,
            ResourceLogs,
            "log resource groups"
        );

        macro_rules! assert_partial_limits {
            ($partial:ident, $rejected_field:ident, $invariant:literal) => {{
                let exact_message = "x".repeat(MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES);
                $partial {
                    $rejected_field: 0,
                    error_message: exact_message.clone(),
                    unknown_fields: UnknownFields::new(),
                }
                .encode_to_bytes(limits())
                .expect("encode exact collector partial-success message limit");
                assert!(matches!(
                    $partial {
                        $rejected_field: 0,
                        error_message: "x"
                            .repeat(MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES + 1),
                        unknown_fields: UnknownFields::new(),
                    }
                    .encode_to_bytes(limits()),
                    Err(ProtobufWireError::SchemaLimitExceeded {
                        resource: "partial-success error message bytes",
                        observed,
                        limit,
                        ..
                    }) if observed == MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES + 1
                        && limit == MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES
                ));

                let mut exact_wire = ProtobufWireEncoder::new(limits());
                exact_wire
                    .write_string(2, &exact_message)
                    .expect("encode exact collector partial-success message fixture");
                $partial::decode_from_bytes(
                    &exact_wire
                        .finish()
                        .expect("finish exact collector partial-success message"),
                    limits(),
                )
                .expect("decode exact collector partial-success message limit");
                let mut over_wire = ProtobufWireEncoder::new(limits());
                over_wire
                    .write_string(
                        2,
                        &"x".repeat(MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES + 1),
                    )
                    .expect("encode one-over collector partial-success message fixture");
                assert!(matches!(
                    $partial::decode_from_bytes(
                        &over_wire
                            .finish()
                            .expect("finish one-over collector partial-success message"),
                        limits(),
                    ),
                    Err(ProtobufWireError::SchemaLimitExceeded {
                        resource: "partial-success error message bytes",
                        observed,
                        limit,
                        ..
                    }) if observed == MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES + 1
                        && limit == MAX_PARTIAL_SUCCESS_ERROR_MESSAGE_BYTES
                ));

                assert!(matches!(
                    $partial {
                        $rejected_field: -1,
                        error_message: String::new(),
                        unknown_fields: UnknownFields::new(),
                    }
                    .encode_to_bytes(limits()),
                    Err(ProtobufWireError::SchemaInvariant {
                        invariant: $invariant,
                        ..
                    })
                ));

                for accepted in [
                    $partial {
                        $rejected_field: 0,
                        error_message: "warning without rejection".to_owned(),
                        unknown_fields: UnknownFields::new(),
                    },
                    $partial {
                        $rejected_field: 1,
                        error_message: String::new(),
                        unknown_fields: UnknownFields::new(),
                    },
                ] {
                    let encoded = accepted
                        .encode_to_bytes(limits())
                        .expect("encode accepted collector partial-success shape");
                    assert_eq!(
                        $partial::decode_from_bytes(&encoded, limits())
                            .expect("decode accepted collector partial-success shape"),
                        accepted
                    );
                }
            }};
        }

        assert_partial_limits!(
            ExportTracePartialSuccess,
            rejected_spans,
            "partial-success rejected span count must be nonnegative"
        );
        assert_partial_limits!(
            ExportLogsPartialSuccess,
            rejected_log_records,
            "partial-success rejected log-record count must be nonnegative"
        );
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__lab_lifecycle_collector_trace_and_logs_failure_state()
     {
        macro_rules! assert_failure_state {
            ($partial:ident, $rejected_field:ident, $invariant:literal) => {{
                let mut invalid_wire = ProtobufWireEncoder::new(limits());
                invalid_wire
                    .write_int64(1, -1)
                    .expect("encode invalid collector rejected count");
                invalid_wire
                    .write_string(2, "retained before validation failure")
                    .expect("encode collector failure-state message");
                let invalid_wire = invalid_wire
                    .finish()
                    .expect("finish invalid collector partial success");

                assert!(matches!(
                    $partial::decode_from_bytes(&invalid_wire, limits()),
                    Err(ProtobufWireError::SchemaInvariant {
                        invariant: $invariant,
                        ..
                    })
                ));

                let mut merge_target = $partial::default();
                assert!(matches!(
                    merge_target.merge_from_bytes(&invalid_wire, limits()),
                    Err(ProtobufWireError::SchemaInvariant {
                        invariant: $invariant,
                        ..
                    })
                ));
                assert_eq!(merge_target.$rejected_field, -1);
                assert_eq!(
                    merge_target.error_message,
                    "retained before validation failure"
                );
            }};
        }

        assert_failure_state!(
            ExportTracePartialSuccess,
            rejected_spans,
            "partial-success rejected span count must be nonnegative"
        );
        assert_failure_state!(
            ExportLogsPartialSuccess,
            rejected_log_records,
            "partial-success rejected log-record count must be nonnegative"
        );
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__property_matrix_logs_all_fields_round_trip() {
        let record = LogRecord {
            time_unix_nano: 11,
            severity_number: SeverityNumber::Warn3.as_raw(),
            severity_text: "warning".to_owned(),
            body: Some(string_value("structured body")),
            attributes: vec![attribute("service.name", "asupersync")],
            dropped_attributes_count: 2,
            flags: LogRecordFlags::TRACE_FLAGS_MASK.bits() | 0x8000_0000,
            trace_id: vec![0x11; MAX_TRACE_ID_BYTES],
            span_id: vec![0x22; MAX_SPAN_ID_BYTES],
            observed_time_unix_nano: 12,
            event_name: "asupersync.runtime.warning".to_owned(),
            unknown_fields: UnknownFields::new(),
        };
        assert!(record.has_valid_trace_id());
        assert!(record.has_valid_span_id());
        assert!(record.has_valid_span_context());
        assert!(record.is_event());

        let model = LogsData {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![attribute("deployment.environment", "test")],
                    ..Resource::default()
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: "asupersync".to_owned(),
                        version: "0.3.10".to_owned(),
                        ..InstrumentationScope::default()
                    }),
                    log_records: vec![record],
                    schema_url: "https://opentelemetry.io/schemas/1.37.0".to_owned(),
                    unknown_fields: UnknownFields::new(),
                }],
                schema_url: "https://opentelemetry.io/schemas/1.37.0".to_owned(),
                unknown_fields: UnknownFields::new(),
            }],
            unknown_fields: UnknownFields::new(),
        };
        let encoded = model
            .encode_to_bytes(limits())
            .expect("encode complete logs model");
        assert_eq!(
            LogsData::decode_from_bytes(&encoded, limits()).expect("decode complete logs model"),
            model
        );
        assert_eq!(
            model
                .encode_to_bytes(limits())
                .expect("repeat complete logs encoding"),
            encoded
        );

        for raw in 0..=24 {
            assert_eq!(
                SeverityNumber::from_raw(raw)
                    .expect("known severity")
                    .as_raw(),
                raw
            );
        }
        assert_eq!(SeverityNumber::from_raw(25), None);
        assert_eq!(SeverityNumber::from_raw(-1), None);

        let retained_flags = LogRecordFlags::from_bits_retain(0xabcd_ef01);
        assert_eq!(retained_flags.bits(), 0xabcd_ef01);
        assert_eq!(retained_flags.trace_flags(), 0x01);
        assert!(retained_flags.contains(LogRecordFlags::from_bits_retain(1)));
        assert_eq!(LogRecordFlags::DO_NOT_USE.bits(), 0);

        let zero_timestamps = LogRecord::default();
        let zero_wire = zero_timestamps
            .encode_to_bytes(limits())
            .expect("zero timestamps are structurally valid");
        assert!(zero_wire.is_empty());
        assert_eq!(
            LogRecord::decode_from_bytes(&zero_wire, limits()).expect("decode zero timestamps"),
            zero_timestamps
        );
        assert!(!zero_timestamps.is_event());

        let all_zero_ids = LogRecord {
            trace_id: vec![0; MAX_TRACE_ID_BYTES],
            span_id: vec![0; MAX_SPAN_ID_BYTES],
            ..LogRecord::default()
        };
        all_zero_ids
            .encode_to_bytes(limits())
            .expect("all-zero exact-width IDs are structurally retained");
        assert!(!all_zero_ids.has_valid_trace_id());
        assert!(!all_zero_ids.has_valid_span_id());
        assert!(!all_zero_ids.has_valid_span_context());
    }

    #[test]
    fn logs_merge_reserved_and_forward_values_are_preserved() {
        let first_body = string_value("first")
            .encode_to_bytes(limits())
            .expect("encode first body fragment");
        let mut second_body = ProtobufWireEncoder::new(limits());
        second_body
            .write_varint(15, 7)
            .expect("encode body unknown field");
        let second_body = second_body.finish().expect("finish second body fragment");

        let mut record_wire = ProtobufWireEncoder::new(limits());
        record_wire
            .write_enum(2, -7)
            .expect("encode unknown negative severity");
        record_wire
            .write_message(5, &first_body)
            .expect("encode first body occurrence");
        record_wire
            .write_message(5, &second_body)
            .expect("encode second body occurrence");
        record_wire
            .write_fixed32(8, 0xabcd_ef01)
            .expect("encode retained upper flag bits");
        record_wire
            .write_varint(4, 1)
            .expect("encode reserved log-record tag");
        let record = LogRecord::decode_from_bytes(
            &record_wire.finish().expect("finish log merge fixture"),
            limits(),
        )
        .expect("decode merged log record");
        assert_eq!(record.severity_number, -7);
        assert_eq!(SeverityNumber::from_raw(record.severity_number), None);
        assert_eq!(record.flags, 0xabcd_ef01);
        assert_eq!(
            LogRecordFlags::from_bits_retain(record.flags).trace_flags(),
            0x01
        );
        let body = record
            .body
            .as_ref()
            .expect("merged body must remain present");
        assert_eq!(
            body.value.as_ref(),
            Some(&AnyValueValue::String("first".to_owned()))
        );
        assert_eq!(body.unknown_fields.as_bytes(), [0x78, 0x07]);
        assert_eq!(record.unknown_fields.as_bytes(), [0x20, 0x01]);
        let canonical = record
            .encode_to_bytes(limits())
            .expect("re-encode merged log record");
        assert!(canonical.ends_with(&[0x20, 0x01]));
        assert_eq!(
            LogRecord::decode_from_bytes(&canonical, limits())
                .expect("decode canonical merged log record"),
            record
        );

        let mut reserved_resource = ProtobufWireEncoder::new(limits());
        reserved_resource
            .write_varint(1000, 1)
            .expect("encode reserved resource-logs tag");
        let reserved_resource = reserved_resource
            .finish()
            .expect("finish resource reserved fixture");
        assert_eq!(reserved_resource.as_ref(), &[0xc0, 0x3e, 0x01]);
        let decoded_resource = ResourceLogs::decode_from_bytes(&reserved_resource, limits())
            .expect("decode reserved resource-logs tag");
        assert_eq!(
            decoded_resource.unknown_fields.as_bytes(),
            reserved_resource.as_ref()
        );
        assert_eq!(
            decoded_resource
                .encode_to_bytes(limits())
                .expect("re-encode reserved resource-logs tag"),
            reserved_resource
        );

        let mut wrong_wire = ProtobufWireEncoder::new(limits());
        wrong_wire
            .write_varint(8, 1)
            .expect("encode wrong-wire flags fixture");
        assert!(matches!(
            LogRecord::decode_from_bytes(
                &wrong_wire.finish().expect("finish wrong-wire flags"),
                limits(),
            ),
            Err(ProtobufWireError::WireTypeMismatch { .. })
        ));
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants_logs_limits_are_exact() {
        LogsData {
            resource_logs: vec![ResourceLogs::default(); MAX_RESOURCE_GROUPS_PER_REQUEST],
            unknown_fields: UnknownFields::new(),
        }
        .encode_to_bytes(limits())
        .expect("exact log resource-group limit");
        assert!(matches!(
            LogsData {
                resource_logs: vec![
                    ResourceLogs::default();
                    MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                ],
                unknown_fields: UnknownFields::new(),
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log resource groups",
                observed,
                limit,
                ..
            }) if observed == MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                && limit == MAX_RESOURCE_GROUPS_PER_REQUEST
        ));

        ResourceLogs {
            scope_logs: vec![ScopeLogs::default(); MAX_SCOPES_PER_RESOURCE_GROUP],
            ..ResourceLogs::default()
        }
        .encode_to_bytes(limits())
        .expect("exact log scope limit");
        assert!(matches!(
            ResourceLogs {
                scope_logs: vec![ScopeLogs::default(); MAX_SCOPES_PER_RESOURCE_GROUP + 1],
                ..ResourceLogs::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log scopes per resource group",
                observed,
                limit,
                ..
            }) if observed == MAX_SCOPES_PER_RESOURCE_GROUP + 1
                && limit == MAX_SCOPES_PER_RESOURCE_GROUP
        ));

        ScopeLogs {
            log_records: vec![LogRecord::default(); MAX_LOG_RECORDS_PER_SCOPE],
            ..ScopeLogs::default()
        }
        .encode_to_bytes(limits())
        .expect("exact log-record limit");
        assert!(matches!(
            ScopeLogs {
                log_records: vec![LogRecord::default(); MAX_LOG_RECORDS_PER_SCOPE + 1],
                ..ScopeLogs::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log records per scope",
                observed,
                limit,
                ..
            }) if observed == MAX_LOG_RECORDS_PER_SCOPE + 1
                && limit == MAX_LOG_RECORDS_PER_SCOPE
        ));
        let mut over_records_wire = ProtobufWireEncoder::new(limits());
        for _ in 0..=MAX_LOG_RECORDS_PER_SCOPE {
            over_records_wire
                .write_message(2, &[])
                .expect("encode one-over log record fixture");
        }
        assert!(matches!(
            ScopeLogs::decode_from_bytes(
                &over_records_wire.finish().expect("finish one-over records"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log records per scope",
                observed,
                limit,
                ..
            }) if observed == MAX_LOG_RECORDS_PER_SCOPE + 1
                && limit == MAX_LOG_RECORDS_PER_SCOPE
        ));

        let exact_attributes = (0..MAX_ATTRIBUTES)
            .map(|index| KeyValue {
                key: format!("key-{index}"),
                ..KeyValue::default()
            })
            .collect::<Vec<_>>();
        LogRecord {
            attributes: exact_attributes,
            ..LogRecord::default()
        }
        .encode_to_bytes(limits())
        .expect("exact log attribute limit");
        assert!(matches!(
            LogRecord {
                attributes: vec![KeyValue::default(); MAX_ATTRIBUTES + 1],
                ..LogRecord::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log record attributes",
                observed,
                limit,
                ..
            }) if observed == MAX_ATTRIBUTES + 1 && limit == MAX_ATTRIBUTES
        ));
        assert!(matches!(
            LogRecord {
                attributes: vec![attribute("duplicate", "one"), attribute("duplicate", "two")],
                ..LogRecord::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "log record attribute keys must be unique",
                ..
            })
        ));

        ResourceLogs {
            schema_url: "x".repeat(MAX_SCHEMA_URL_BYTES),
            ..ResourceLogs::default()
        }
        .encode_to_bytes(limits())
        .expect("exact log resource schema URL limit");
        assert!(matches!(
            ResourceLogs {
                schema_url: "x".repeat(MAX_SCHEMA_URL_BYTES + 1),
                ..ResourceLogs::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log resource schema URL bytes",
                ..
            })
        ));
        assert!(matches!(
            ScopeLogs {
                schema_url: "x".repeat(MAX_SCHEMA_URL_BYTES + 1),
                ..ScopeLogs::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log scope schema URL bytes",
                ..
            })
        ));

        LogRecord {
            severity_text: "s".repeat(MAX_LOG_SEVERITY_TEXT_BYTES),
            event_name: "e".repeat(MAX_LOG_EVENT_NAME_BYTES),
            ..LogRecord::default()
        }
        .encode_to_bytes(limits())
        .expect("exact log text limits");
        assert!(matches!(
            LogRecord {
                severity_text: "s".repeat(MAX_LOG_SEVERITY_TEXT_BYTES + 1),
                ..LogRecord::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log severity text bytes",
                observed,
                limit,
                ..
            }) if observed == MAX_LOG_SEVERITY_TEXT_BYTES + 1
                && limit == MAX_LOG_SEVERITY_TEXT_BYTES
        ));
        assert!(matches!(
            LogRecord {
                event_name: "e".repeat(MAX_LOG_EVENT_NAME_BYTES + 1),
                ..LogRecord::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log event name bytes",
                observed,
                limit,
                ..
            }) if observed == MAX_LOG_EVENT_NAME_BYTES + 1
                && limit == MAX_LOG_EVENT_NAME_BYTES
        ));
        let mut over_text_wire = ProtobufWireEncoder::new(limits());
        over_text_wire
            .write_string(3, &"s".repeat(MAX_LOG_SEVERITY_TEXT_BYTES + 1))
            .expect("encode one-over log text fixture");
        assert!(matches!(
            LogRecord::decode_from_bytes(
                &over_text_wire.finish().expect("finish one-over log text"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "log severity text bytes",
                observed,
                limit,
                ..
            }) if observed == MAX_LOG_SEVERITY_TEXT_BYTES + 1
                && limit == MAX_LOG_SEVERITY_TEXT_BYTES
        ));

        for invalid_trace_len in [MAX_TRACE_ID_BYTES - 1, MAX_TRACE_ID_BYTES + 1] {
            assert!(matches!(
                LogRecord {
                    trace_id: vec![1; invalid_trace_len],
                    ..LogRecord::default()
                }
                .encode_to_bytes(limits()),
                Err(ProtobufWireError::SchemaInvariant {
                    invariant: "log record trace ID must be empty or exactly sixteen bytes",
                    ..
                })
            ));
        }
        for invalid_span_len in [MAX_SPAN_ID_BYTES - 1, MAX_SPAN_ID_BYTES + 1] {
            assert!(matches!(
                LogRecord {
                    span_id: vec![1; invalid_span_len],
                    ..LogRecord::default()
                }
                .encode_to_bytes(limits()),
                Err(ProtobufWireError::SchemaInvariant {
                    invariant: "log record span ID must be empty or exactly eight bytes",
                    ..
                })
            ));
        }
        let mut invalid_id_wire = ProtobufWireEncoder::new(limits());
        invalid_id_wire
            .write_bytes(9, &[1; MAX_TRACE_ID_BYTES - 1])
            .expect("encode invalid log trace ID fixture");
        assert!(matches!(
            LogRecord::decode_from_bytes(
                &invalid_id_wire.finish().expect("finish invalid log ID"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "log record trace ID must be empty or exactly sixteen bytes",
                ..
            })
        ));

        LogRecord {
            body: Some(nested_array(MAX_ANY_VALUE_DEPTH)),
            ..LogRecord::default()
        }
        .encode_to_bytes(limits())
        .expect("exact log-body AnyValue depth");
        assert!(matches!(
            LogRecord {
                body: Some(nested_array(MAX_ANY_VALUE_DEPTH + 1)),
                ..LogRecord::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "AnyValue depth",
                ..
            })
        ));
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__lab_lifecycle_logs_failure_state() {
        let mut malformed = ProtobufWireEncoder::new(limits());
        malformed
            .write_string(3, "retained before ID failure")
            .expect("encode retained severity text");
        malformed
            .write_bytes(9, &[1; MAX_TRACE_ID_BYTES - 1])
            .expect("encode invalid trace ID");
        let malformed = malformed.finish().expect("finish malformed log record");
        assert!(LogRecord::decode_from_bytes(&malformed, limits()).is_err());

        let mut merge_target = LogRecord::default();
        assert!(merge_target.merge_from_bytes(&malformed, limits()).is_err());
        assert_eq!(merge_target.severity_text, "retained before ID failure");
        assert!(merge_target.trace_id.is_empty());
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__downstream_consumer_logs_generic_codec() {
        let model = LogsData {
            resource_logs: vec![ResourceLogs::default()],
            unknown_fields: UnknownFields::new(),
        };
        let mut codec: ProtoCodec<LogsData, LogsData> = ProtoCodec::new();
        let encoded = codec.encode(&model).expect("generic logs codec encode");
        assert_eq!(
            codec.decode(&encoded).expect("generic logs codec decode"),
            model
        );
    }

    #[test]
    fn common_resource_round_trip_is_deterministic() {
        let resource = Resource {
            attributes: vec![
                KeyValue {
                    key: "service.name".to_owned(),
                    value: Some(string_value("asupersync")),
                    key_strindex: 0,
                    unknown_fields: UnknownFields::new(),
                },
                KeyValue {
                    key: "service.version".to_owned(),
                    value: Some(string_value("0.1.0")),
                    key_strindex: 0,
                    unknown_fields: UnknownFields::new(),
                },
            ],
            dropped_attributes_count: 2,
            entity_refs: vec![EntityRef {
                schema_url: "https://opentelemetry.io/schemas/1.37.0".to_owned(),
                r#type: "service".to_owned(),
                id_keys: vec!["service.name".to_owned()],
                description_keys: vec!["service.version".to_owned()],
                unknown_fields: UnknownFields::new(),
            }],
            unknown_fields: UnknownFields::new(),
        };

        let first = resource.encode_to_bytes(limits()).expect("encode resource");
        let second = resource.encode_to_bytes(limits()).expect("repeat encode");
        assert_eq!(first, second);
        assert_eq!(
            Resource::decode_from_bytes(&first, limits()).expect("decode resource"),
            resource
        );
    }

    #[test]
    fn any_value_same_message_oneof_member_merges_and_other_member_replaces() {
        let two_arrays = [
            0x2a, 0x05, 0x0a, 0x03, 0x0a, 0x01, b'a', 0x2a, 0x05, 0x0a, 0x03, 0x0a, 0x01, b'b',
        ];
        let merged = AnyValue::decode_from_bytes(&two_arrays, limits()).expect("merge arrays");
        let Some(AnyValueValue::Array(array)) = merged.value else {
            panic!("expected merged array member");
        };
        assert_eq!(array.values, vec![string_value("a"), string_value("b")]);

        let mut replaced_bytes = two_arrays.to_vec();
        replaced_bytes.extend_from_slice(&[0x0a, 0x01, b'z']);
        let replaced =
            AnyValue::decode_from_bytes(&replaced_bytes, limits()).expect("replace oneof");
        assert_eq!(replaced.value, Some(AnyValueValue::String("z".to_owned())));
    }

    #[test]
    fn common_limits_accept_exact_boundaries_and_reject_one_over() {
        let exact_string = AnyValue {
            value: Some(AnyValueValue::String("x".repeat(MAX_ATTRIBUTE_VALUE_BYTES))),
            unknown_fields: UnknownFields::new(),
        };
        exact_string
            .encode_to_bytes(limits())
            .expect("exact string limit");

        let over_string = AnyValue {
            value: Some(AnyValueValue::String(
                "x".repeat(MAX_ATTRIBUTE_VALUE_BYTES + 1),
            )),
            unknown_fields: UnknownFields::new(),
        };
        assert!(matches!(
            over_string.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "AnyValue string bytes",
                ..
            })
        ));

        let exact_items = ArrayValue {
            values: vec![AnyValue::default(); MAX_ANY_VALUE_ITEMS],
            unknown_fields: UnknownFields::new(),
        };
        exact_items
            .encode_to_bytes(limits())
            .expect("exact item limit");
        let over_items = ArrayValue {
            values: vec![AnyValue::default(); MAX_ANY_VALUE_ITEMS + 1],
            unknown_fields: UnknownFields::new(),
        };
        assert!(matches!(
            over_items.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "AnyValue array items",
                ..
            })
        ));

        let mut exact_string_wire = ProtobufWireEncoder::new(limits());
        exact_string_wire
            .write_bytes(1, &vec![b'x'; MAX_ATTRIBUTE_VALUE_BYTES])
            .expect("encode exact decode fixture");
        AnyValue::decode_from_bytes(
            &exact_string_wire.finish().expect("finish exact fixture"),
            limits(),
        )
        .expect("decode exact string limit");

        let mut over_string_wire = ProtobufWireEncoder::new(limits());
        over_string_wire
            .write_bytes(1, &vec![b'x'; MAX_ATTRIBUTE_VALUE_BYTES + 1])
            .expect("encode one-over decode fixture");
        assert!(matches!(
            AnyValue::decode_from_bytes(
                &over_string_wire.finish().expect("finish one-over fixture"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "AnyValue string bytes",
                observed,
                limit,
                ..
            }) if observed == MAX_ATTRIBUTE_VALUE_BYTES + 1
                && limit == MAX_ATTRIBUTE_VALUE_BYTES
        ));

        let mut exact_items_wire = ProtobufWireEncoder::new(limits());
        for _ in 0..MAX_ANY_VALUE_ITEMS {
            exact_items_wire
                .write_message(1, &[])
                .expect("encode exact item fixture");
        }
        ArrayValue::decode_from_bytes(
            &exact_items_wire.finish().expect("finish exact items"),
            limits(),
        )
        .expect("decode exact item limit");

        let mut over_items_wire = ProtobufWireEncoder::new(limits());
        for _ in 0..=MAX_ANY_VALUE_ITEMS {
            over_items_wire
                .write_message(1, &[])
                .expect("encode one-over item fixture");
        }
        assert!(matches!(
            ArrayValue::decode_from_bytes(
                &over_items_wire.finish().expect("finish one-over items"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "AnyValue array items",
                observed,
                limit,
                ..
            }) if observed == MAX_ANY_VALUE_ITEMS + 1 && limit == MAX_ANY_VALUE_ITEMS
        ));
    }

    #[test]
    fn recursive_any_value_depth_is_exact_and_fail_closed() {
        let exact = nested_array(MAX_ANY_VALUE_DEPTH)
            .encode_to_bytes(limits())
            .expect("exact AnyValue depth");
        AnyValue::decode_from_bytes(&exact, limits()).expect("decode exact AnyValue depth");
        assert!(matches!(
            nested_array(MAX_ANY_VALUE_DEPTH + 1).encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "AnyValue depth",
                ..
            })
        ));

        let mut nested_wire = Vec::new();
        for _ in 1..=MAX_ANY_VALUE_DEPTH {
            let mut array = ProtobufWireEncoder::new(limits());
            array
                .write_message(1, &nested_wire)
                .expect("wrap array value");
            let array = array.finish().expect("finish array wrapper");
            let mut any_value = ProtobufWireEncoder::new(limits());
            any_value
                .write_message(5, &array)
                .expect("wrap AnyValue array");
            nested_wire = any_value
                .finish()
                .expect("finish AnyValue wrapper")
                .to_vec();
        }
        assert!(matches!(
            AnyValue::decode_from_bytes(&nested_wire, limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "AnyValue depth",
                observed,
                limit,
                ..
            }) if observed == MAX_ANY_VALUE_DEPTH + 1 && limit == MAX_ANY_VALUE_DEPTH
        ));
    }

    #[test]
    fn unknown_group_is_preserved_verbatim() {
        let group = [0x5b, 0x60, 0x01, 0x5c];
        let decoded = Resource::decode_from_bytes(&group, limits()).expect("decode unknown group");
        assert_eq!(decoded.unknown_fields.as_bytes(), group);
        assert_eq!(
            decoded.encode_to_bytes(limits()).expect("re-encode group"),
            group.as_slice()
        );
    }

    #[test]
    fn fresh_decode_returns_no_partial_model_and_merge_documents_partial_mutation() {
        let malformed = [0x0a, 0x02, b'o', b'k', 0x12];
        assert!(AnyValue::decode_from_bytes(&malformed, limits()).is_err());

        let mut existing = AnyValue::default();
        assert!(existing.merge_from_bytes(&malformed, limits()).is_err());
        assert_eq!(existing.value, Some(AnyValueValue::String("ok".to_owned())));

        let payload_len = MAX_TOTAL_OWNED_BYTES - 5;
        let mut raw_encoder =
            ProtobufWireEncoder::new(ProtobufWireLimits::for_message_size(MAX_TOTAL_OWNED_BYTES));
        raw_encoder
            .write_bytes(15, &vec![0; payload_len])
            .expect("encode exact aggregate-owned-byte fixture");
        let raw = raw_encoder.finish().expect("finish aggregate fixture");
        assert_eq!(raw.len(), MAX_TOTAL_OWNED_BYTES);
        let mut unknown_fields = UnknownFields::new();
        unknown_fields
            .try_record_raw(&raw)
            .expect("record exact aggregate fixture");
        let mut resource = Resource {
            unknown_fields,
            ..Resource::default()
        };
        let original_unknown_len = resource.unknown_fields.len();
        assert!(matches!(
            resource.merge_from_bytes(&[0x78, 0x01], limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "total owned string and bytes payload",
                observed,
                limit,
                ..
            }) if observed == MAX_TOTAL_OWNED_BYTES + 2 && limit == MAX_TOTAL_OWNED_BYTES
        ));
        assert_eq!(resource.unknown_fields.len(), original_unknown_len);
    }

    #[test]
    fn malformed_utf8_and_duplicate_attribute_keys_are_typed_errors() {
        assert!(matches!(
            AnyValue::decode_from_bytes(&[0x0a, 0x01, 0xff], limits()),
            Err(ProtobufWireError::InvalidUtf8 { .. })
        ));

        let duplicate = Resource {
            attributes: vec![
                KeyValue {
                    key: "duplicate".to_owned(),
                    ..KeyValue::default()
                },
                KeyValue {
                    key: "duplicate".to_owned(),
                    ..KeyValue::default()
                },
            ],
            ..Resource::default()
        };
        assert!(matches!(
            duplicate.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "resource attribute keys must be unique",
                ..
            })
        ));
    }

    #[test]
    fn pinned_common_and_resource_invariants_fail_closed() {
        let conflicting_key = KeyValue {
            key: "service.name".to_owned(),
            key_strindex: 1,
            ..KeyValue::default()
        };
        assert!(matches!(
            conflicting_key.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "KeyValue key and key_strindex are mutually exclusive",
                ..
            })
        ));
        assert!(matches!(
            KeyValue::decode_from_bytes(&[0x0a, 0x01, b'k', 0x18, 0x01], limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "KeyValue key and key_strindex are mutually exclusive",
                ..
            })
        ));

        assert!(matches!(
            EntityRef::default().encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "EntityRef type must be nonempty",
                ..
            })
        ));
        let missing_id = EntityRef {
            r#type: "service".to_owned(),
            ..EntityRef::default()
        };
        assert!(matches!(
            missing_id.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "EntityRef id_keys must not be empty",
                ..
            })
        ));

        let missing_attribute = Resource {
            entity_refs: vec![EntityRef {
                r#type: "service".to_owned(),
                id_keys: vec!["service.name".to_owned()],
                ..EntityRef::default()
            }],
            ..Resource::default()
        };
        assert!(matches!(
            missing_attribute.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "EntityRef keys must reference Resource attributes",
                ..
            })
        ));

        let comparison_heavy = Resource {
            attributes: vec![
                KeyValue {
                    key: "a".to_owned(),
                    ..KeyValue::default()
                },
                KeyValue {
                    key: "b".to_owned(),
                    ..KeyValue::default()
                },
            ],
            ..Resource::default()
        };
        let mut encoder = ProtobufWireEncoder::new(limits().with_max_work(1));
        assert!(matches!(
            comparison_heavy.encode_fields(&mut encoder),
            Err(ProtobufWireError::WorkLimitExceeded {
                work: 2,
                limit: 1,
                ..
            })
        ));
        assert!(encoder.is_empty());
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants_metrics_round_trip() {
        let mut metric_unknown = UnknownFields::new();
        metric_unknown
            .try_record_raw(&[0x78, 0x01])
            .expect("record metric unknown field");

        let mut gauge_point = number_point(NumberDataPointValue::Double(3.5));
        gauge_point.exemplars = vec![exemplar(ExemplarValue::Int(-7))];
        let gauge = Metric {
            name: "runtime.queue.depth".to_owned(),
            description: "current queue depth".to_owned(),
            unit: "{task}".to_owned(),
            data: Some(MetricData::Gauge(Gauge {
                data_points: vec![gauge_point],
                unknown_fields: UnknownFields::new(),
            })),
            metadata: vec![attribute("stability", "stable")],
            unknown_fields: metric_unknown,
        };

        let sum = Metric {
            name: "runtime.tasks".to_owned(),
            data: Some(MetricData::Sum(Sum {
                data_points: vec![number_point(NumberDataPointValue::Int(9))],
                aggregation_temporality: 77,
                is_monotonic: true,
                unknown_fields: UnknownFields::new(),
            })),
            ..Metric::default()
        };

        let histogram = Metric {
            name: "runtime.latency".to_owned(),
            unit: "ms".to_owned(),
            data: Some(MetricData::Histogram(Histogram {
                data_points: vec![HistogramDataPoint {
                    start_time_unix_nano: 10,
                    time_unix_nano: 20,
                    count: 3,
                    sum: Some(7.0),
                    bucket_counts: vec![1, 2],
                    explicit_bounds: vec![2.5],
                    exemplars: vec![exemplar(ExemplarValue::Double(2.0))],
                    attributes: vec![attribute("worker", "a")],
                    flags: 0x8000_0001,
                    min: Some(1.0),
                    max: Some(4.0),
                    unknown_fields: UnknownFields::new(),
                }],
                aggregation_temporality: AggregationTemporality::Delta.as_raw(),
                unknown_fields: UnknownFields::new(),
            })),
            ..Metric::default()
        };

        let exponential = Metric {
            name: "runtime.payload".to_owned(),
            data: Some(MetricData::ExponentialHistogram(ExponentialHistogram {
                data_points: vec![ExponentialHistogramDataPoint {
                    attributes: vec![attribute("class", "small")],
                    start_time_unix_nano: 10,
                    time_unix_nano: 20,
                    count: 4,
                    sum: Some(8.0),
                    scale: -2,
                    zero_count: 1,
                    positive: Some(ExponentialHistogramBuckets {
                        offset: -1,
                        bucket_counts: vec![1, 2],
                        unknown_fields: UnknownFields::new(),
                    }),
                    negative: None,
                    flags: 0x4000_0000,
                    exemplars: Vec::new(),
                    min: Some(-1.0),
                    max: Some(5.0),
                    zero_threshold: 0.25,
                    unknown_fields: UnknownFields::new(),
                }],
                aggregation_temporality: AggregationTemporality::Cumulative.as_raw(),
                unknown_fields: UnknownFields::new(),
            })),
            ..Metric::default()
        };

        let summary = Metric {
            name: "runtime.summary".to_owned(),
            data: Some(MetricData::Summary(Summary {
                data_points: vec![SummaryDataPoint {
                    start_time_unix_nano: 10,
                    time_unix_nano: 20,
                    count: 2,
                    sum: 3.0,
                    quantile_values: vec![
                        SummaryValueAtQuantile {
                            quantile: 0.0,
                            value: 1.0,
                            unknown_fields: UnknownFields::new(),
                        },
                        SummaryValueAtQuantile {
                            quantile: 1.0,
                            value: 2.0,
                            unknown_fields: UnknownFields::new(),
                        },
                    ],
                    attributes: vec![attribute("kind", "bounded")],
                    flags: 0x2000_0000,
                    unknown_fields: UnknownFields::new(),
                }],
                unknown_fields: UnknownFields::new(),
            })),
            ..Metric::default()
        };

        let model = MetricsData {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![attribute("service.name", "asupersync")],
                    ..Resource::default()
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(InstrumentationScope {
                        name: "asupersync".to_owned(),
                        version: "0.1.0".to_owned(),
                        ..InstrumentationScope::default()
                    }),
                    metrics: vec![gauge, sum, histogram, exponential, summary],
                    schema_url: "https://opentelemetry.io/schemas/1.37.0".to_owned(),
                    unknown_fields: UnknownFields::new(),
                }],
                schema_url: "https://opentelemetry.io/schemas/1.37.0".to_owned(),
                unknown_fields: UnknownFields::new(),
            }],
            unknown_fields: UnknownFields::new(),
        };

        let first = model.encode_to_bytes(limits()).expect("encode metrics");
        let second = model
            .encode_to_bytes(limits())
            .expect("repeat metrics encode");
        assert_eq!(first, second);
        assert_eq!(
            MetricsData::decode_from_bytes(&first, limits()).expect("decode metrics"),
            model
        );
        assert_eq!(AggregationTemporality::from_raw(77), None);
        let flags = DataPointFlags::from_bits_retain(0x8000_0001);
        assert!(flags.contains(DataPointFlags::NO_RECORDED_VALUE_MASK));
        assert_eq!(flags.bits(), 0x8000_0001);
        assert_eq!(DataPointFlags::DO_NOT_USE.bits(), 0);
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__property_matrix_metrics_oneofs_merge() {
        let first_gauge = Gauge {
            data_points: vec![number_point(NumberDataPointValue::Double(1.0))],
            unknown_fields: UnknownFields::new(),
        }
        .encode_to_bytes(limits())
        .expect("encode first gauge");
        let second_gauge = Gauge {
            data_points: vec![number_point(NumberDataPointValue::Int(2))],
            unknown_fields: UnknownFields::new(),
        }
        .encode_to_bytes(limits())
        .expect("encode second gauge");
        let mut metric_wire = ProtobufWireEncoder::new(limits());
        metric_wire
            .write_message(5, &first_gauge)
            .expect("first gauge member");
        metric_wire
            .write_message(5, &second_gauge)
            .expect("second gauge member");
        let merged = Metric::decode_from_bytes(
            &metric_wire.finish().expect("finish merged metric"),
            limits(),
        )
        .expect("decode merged gauge");
        let Some(MetricData::Gauge(gauge)) = merged.data else {
            panic!("expected gauge data");
        };
        assert_eq!(gauge.data_points.len(), 2);

        let mut replacement_wire = ProtobufWireEncoder::new(limits());
        replacement_wire
            .write_message(5, &first_gauge)
            .expect("gauge member");
        replacement_wire
            .write_message(11, &[])
            .expect("summary replacement");
        let replaced = Metric::decode_from_bytes(
            &replacement_wire.finish().expect("finish replacement"),
            limits(),
        )
        .expect("decode replacement");
        assert!(matches!(replaced.data, Some(MetricData::Summary(_))));

        let mut number_wire = ProtobufWireEncoder::new(limits());
        number_wire
            .write_fixed64(3, 1)
            .expect("required point time");
        number_wire.write_double(4, 1.5).expect("double member");
        number_wire
            .write_fixed64(6, (-9i64).cast_unsigned())
            .expect("integer replacement");
        let number = NumberDataPoint::decode_from_bytes(
            &number_wire.finish().expect("finish number point"),
            limits(),
        )
        .expect("decode number point");
        assert_eq!(number.value, Some(NumberDataPointValue::Int(-9)));

        let mut exemplar_wire = ProtobufWireEncoder::new(limits());
        exemplar_wire
            .write_fixed64(3, 1.5f64.to_bits())
            .expect("exemplar double");
        exemplar_wire
            .write_fixed64(6, (-11i64).cast_unsigned())
            .expect("exemplar integer replacement");
        let exemplar = Exemplar::decode_from_bytes(
            &exemplar_wire.finish().expect("finish exemplar"),
            limits(),
        )
        .expect("decode exemplar");
        assert_eq!(exemplar.value, Some(ExemplarValue::Int(-11)));
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants_metrics_limits() {
        MetricsData {
            resource_metrics: vec![ResourceMetrics::default(); MAX_RESOURCE_GROUPS_PER_REQUEST],
            unknown_fields: UnknownFields::new(),
        }
        .encode_to_bytes(limits())
        .expect("exact metric resource group limit");
        assert!(matches!(
            MetricsData {
                resource_metrics: vec![
                    ResourceMetrics::default();
                    MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                ],
                unknown_fields: UnknownFields::new(),
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "metric resource groups",
                observed,
                limit,
                ..
            }) if observed == MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                && limit == MAX_RESOURCE_GROUPS_PER_REQUEST
        ));

        ResourceMetrics {
            scope_metrics: vec![ScopeMetrics::default(); MAX_SCOPES_PER_RESOURCE_GROUP],
            ..ResourceMetrics::default()
        }
        .encode_to_bytes(limits())
        .expect("exact metric scope limit");
        assert!(matches!(
            ResourceMetrics {
                scope_metrics: vec![ScopeMetrics::default(); MAX_SCOPES_PER_RESOURCE_GROUP + 1],
                ..ResourceMetrics::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "metric scopes per resource group",
                ..
            })
        ));

        ScopeMetrics {
            metrics: vec![Metric::default(); MAX_METRICS_PER_SCOPE],
            ..ScopeMetrics::default()
        }
        .encode_to_bytes(limits())
        .expect("exact metrics per scope limit");
        assert!(matches!(
            ScopeMetrics {
                metrics: vec![Metric::default(); MAX_METRICS_PER_SCOPE + 1],
                ..ScopeMetrics::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "metrics per scope",
                ..
            })
        ));

        let minimal_point = NumberDataPoint {
            time_unix_nano: 1,
            value: Some(NumberDataPointValue::Int(0)),
            ..NumberDataPoint::default()
        };
        Gauge {
            data_points: vec![minimal_point.clone(); MAX_DATA_POINTS_PER_METRIC],
            unknown_fields: UnknownFields::new(),
        }
        .encode_to_bytes(limits())
        .expect("exact data point limit");
        assert!(matches!(
            Gauge {
                data_points: vec![minimal_point; MAX_DATA_POINTS_PER_METRIC + 1],
                unknown_fields: UnknownFields::new(),
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "gauge data points",
                ..
            })
        ));

        let minimal_exemplar = Exemplar {
            value: Some(ExemplarValue::Int(0)),
            ..Exemplar::default()
        };
        NumberDataPoint {
            time_unix_nano: 1,
            value: Some(NumberDataPointValue::Int(0)),
            exemplars: vec![minimal_exemplar.clone(); MAX_EXEMPLARS_PER_DATA_POINT],
            ..NumberDataPoint::default()
        }
        .encode_to_bytes(limits())
        .expect("exact exemplar limit");
        assert!(matches!(
            NumberDataPoint {
                time_unix_nano: 1,
                value: Some(NumberDataPointValue::Int(0)),
                exemplars: vec![minimal_exemplar; MAX_EXEMPLARS_PER_DATA_POINT + 1],
                ..NumberDataPoint::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "number data point exemplars",
                ..
            })
        ));

        let exact_histogram = HistogramDataPoint {
            time_unix_nano: 1,
            bucket_counts: vec![0; MAX_HISTOGRAM_BUCKET_COUNTS],
            explicit_bounds: (0..MAX_HISTOGRAM_EXPLICIT_BOUNDS)
                .map(|value| {
                    f64::from(u32::try_from(value).expect("bounded histogram index fits u32"))
                })
                .collect(),
            ..HistogramDataPoint::default()
        };
        exact_histogram
            .encode_to_bytes(limits())
            .expect("exact histogram bucket limits");
        assert!(matches!(
            HistogramDataPoint {
                time_unix_nano: 1,
                bucket_counts: vec![0; MAX_HISTOGRAM_BUCKET_COUNTS + 1],
                ..HistogramDataPoint::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "histogram bucket counts",
                ..
            })
        ));
        assert!(matches!(
            HistogramDataPoint {
                time_unix_nano: 1,
                explicit_bounds: vec![0.0; MAX_HISTOGRAM_EXPLICIT_BOUNDS + 1],
                ..HistogramDataPoint::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "histogram explicit bounds",
                ..
            })
        ));

        ExponentialHistogramBuckets {
            bucket_counts: vec![0; MAX_EXPONENTIAL_HISTOGRAM_BUCKETS],
            ..ExponentialHistogramBuckets::default()
        }
        .encode_to_bytes(limits())
        .expect("exact exponential bucket limit");
        assert!(matches!(
            ExponentialHistogramBuckets {
                bucket_counts: vec![0; MAX_EXPONENTIAL_HISTOGRAM_BUCKETS + 1],
                ..ExponentialHistogramBuckets::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "exponential histogram buckets per sign",
                ..
            })
        ));

        let exact_quantiles = (0..MAX_SUMMARY_QUANTILES)
            .map(|index| SummaryValueAtQuantile {
                quantile: f64::from(u32::try_from(index).expect("bounded quantile index fits u32"))
                    / f64::from(
                        u32::try_from(MAX_SUMMARY_QUANTILES - 1)
                            .expect("bounded quantile count fits u32"),
                    ),
                value: 0.0,
                unknown_fields: UnknownFields::new(),
            })
            .collect();
        SummaryDataPoint {
            time_unix_nano: 1,
            count: 1,
            quantile_values: exact_quantiles,
            ..SummaryDataPoint::default()
        }
        .encode_to_bytes(limits())
        .expect("exact summary quantile limit");
        assert!(matches!(
            SummaryDataPoint {
                time_unix_nano: 1,
                count: 1,
                quantile_values: vec![SummaryValueAtQuantile::default(); MAX_SUMMARY_QUANTILES + 1],
                ..SummaryDataPoint::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "summary quantiles",
                ..
            })
        ));

        let exact_metadata = (0..MAX_METRIC_METADATA_ENTRIES)
            .map(|index| KeyValue {
                key: format!("key-{index}"),
                ..KeyValue::default()
            })
            .collect();
        Metric {
            metadata: exact_metadata,
            ..Metric::default()
        }
        .encode_to_bytes(limits())
        .expect("exact metric metadata limit");
        assert!(matches!(
            Metric {
                metadata: vec![KeyValue::default(); MAX_METRIC_METADATA_ENTRIES + 1],
                ..Metric::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "metric metadata entries",
                ..
            })
        ));

        Metric {
            name: "n".repeat(MAX_METRIC_NAME_BYTES),
            description: "d".repeat(MAX_METRIC_DESCRIPTION_BYTES),
            unit: "u".repeat(MAX_METRIC_UNIT_BYTES),
            ..Metric::default()
        }
        .encode_to_bytes(limits())
        .expect("exact metric string limits");
        for (metric, resource) in [
            (
                Metric {
                    name: "n".repeat(MAX_METRIC_NAME_BYTES + 1),
                    ..Metric::default()
                },
                "metric name bytes",
            ),
            (
                Metric {
                    description: "d".repeat(MAX_METRIC_DESCRIPTION_BYTES + 1),
                    ..Metric::default()
                },
                "metric description bytes",
            ),
            (
                Metric {
                    unit: "u".repeat(MAX_METRIC_UNIT_BYTES + 1),
                    ..Metric::default()
                },
                "metric unit bytes",
            ),
        ] {
            assert!(matches!(
                metric.encode_to_bytes(limits()),
                Err(ProtobufWireError::SchemaLimitExceeded {
                    resource: observed_resource,
                    ..
                }) if observed_resource == resource
            ));
        }

        let mut over_resources_wire = ProtobufWireEncoder::new(limits());
        for _ in 0..=MAX_RESOURCE_GROUPS_PER_REQUEST {
            over_resources_wire
                .write_message(1, &[])
                .expect("write resource group fixture");
        }
        assert!(matches!(
            MetricsData::decode_from_bytes(
                &over_resources_wire
                    .finish()
                    .expect("finish resource groups"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "metric resource groups",
                ..
            })
        ));

        let mut over_buckets_wire = ProtobufWireEncoder::new(limits());
        over_buckets_wire
            .write_packed_fixed64(6, &vec![0; MAX_HISTOGRAM_BUCKET_COUNTS + 1])
            .expect("write bucket fixture");
        assert!(matches!(
            HistogramDataPoint::decode_from_bytes(
                &over_buckets_wire.finish().expect("finish buckets"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "histogram bucket counts",
                ..
            })
        ));
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__local_invariants_metrics_semantics() {
        assert!(matches!(
            Sum::default().encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "aggregation temporality must not be unspecified",
                ..
            })
        ));
        Sum {
            aggregation_temporality: 99,
            ..Sum::default()
        }
        .encode_to_bytes(limits())
        .expect("unknown temporality remains forward-compatible");

        assert!(matches!(
            NumberDataPoint::default().encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "number data point must contain a recognized value",
                ..
            })
        ));
        assert!(matches!(
            NumberDataPoint {
                value: Some(NumberDataPointValue::Int(0)),
                ..NumberDataPoint::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "metric data point time_unix_nano must be nonzero",
                ..
            })
        ));
        assert!(matches!(
            Exemplar::default().encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "exemplar must contain a recognized value",
                ..
            })
        ));

        for invalid in [
            Exemplar {
                value: Some(ExemplarValue::Int(0)),
                span_id: vec![0; MAX_SPAN_ID_BYTES - 1],
                ..Exemplar::default()
            },
            Exemplar {
                value: Some(ExemplarValue::Int(0)),
                trace_id: vec![0; MAX_TRACE_ID_BYTES - 1],
                ..Exemplar::default()
            },
        ] {
            assert!(matches!(
                invalid.encode_to_bytes(limits()),
                Err(ProtobufWireError::SchemaInvariant { .. })
            ));
        }

        let mut short_id_wire = ProtobufWireEncoder::new(limits());
        short_id_wire
            .write_fixed64(6, 0)
            .expect("recognized exemplar value");
        short_id_wire
            .write_bytes(4, &[0; MAX_SPAN_ID_BYTES - 1])
            .expect("short span ID fixture");
        assert!(matches!(
            Exemplar::decode_from_bytes(
                &short_id_wire.finish().expect("finish short ID fixture"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "exemplar span ID must be empty or exactly eight bytes",
                ..
            })
        ));

        let duplicate_attributes = NumberDataPoint {
            time_unix_nano: 1,
            value: Some(NumberDataPointValue::Int(0)),
            attributes: vec![attribute("duplicate", "a"), attribute("duplicate", "b")],
            ..NumberDataPoint::default()
        };
        assert!(matches!(
            duplicate_attributes.encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "number data point attribute keys must be unique",
                ..
            })
        ));

        for invalid in [
            HistogramDataPoint {
                time_unix_nano: 1,
                bucket_counts: vec![1],
                explicit_bounds: vec![1.0],
                ..HistogramDataPoint::default()
            },
            HistogramDataPoint {
                time_unix_nano: 1,
                count: 2,
                bucket_counts: vec![1, 2],
                explicit_bounds: vec![1.0],
                ..HistogramDataPoint::default()
            },
            HistogramDataPoint {
                time_unix_nano: 1,
                count: 2,
                bucket_counts: vec![1, 1, 0],
                explicit_bounds: vec![2.0, 1.0],
                ..HistogramDataPoint::default()
            },
            HistogramDataPoint {
                time_unix_nano: 1,
                sum: Some(1.0),
                ..HistogramDataPoint::default()
            },
        ] {
            assert!(matches!(
                invalid.encode_to_bytes(limits()),
                Err(ProtobufWireError::SchemaInvariant { .. })
            ));
        }

        assert!(matches!(
            ExponentialHistogramDataPoint {
                time_unix_nano: 1,
                count: 2,
                zero_count: 1,
                ..ExponentialHistogramDataPoint::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "exponential histogram count must equal bucket total",
                ..
            })
        ));
        assert!(matches!(
            ExponentialHistogramDataPoint {
                time_unix_nano: 1,
                sum: Some(1.0),
                ..ExponentialHistogramDataPoint::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "exponential histogram sum must be zero when count is zero",
                ..
            })
        ));
        assert!(matches!(
            ExponentialHistogramDataPoint {
                time_unix_nano: 1,
                count: u64::MAX,
                zero_count: u64::MAX,
                positive: Some(ExponentialHistogramBuckets {
                    bucket_counts: vec![1],
                    ..ExponentialHistogramBuckets::default()
                }),
                ..ExponentialHistogramDataPoint::default()
            }
            .encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "exponential histogram bucket total must fit u64",
                ..
            })
        ));

        for invalid in [
            SummaryDataPoint {
                time_unix_nano: 1,
                count: 1,
                quantile_values: vec![SummaryValueAtQuantile {
                    quantile: f64::NAN,
                    ..SummaryValueAtQuantile::default()
                }],
                ..SummaryDataPoint::default()
            },
            SummaryDataPoint {
                time_unix_nano: 1,
                count: 1,
                quantile_values: vec![
                    SummaryValueAtQuantile {
                        quantile: 0.5,
                        ..SummaryValueAtQuantile::default()
                    },
                    SummaryValueAtQuantile {
                        quantile: 0.5,
                        ..SummaryValueAtQuantile::default()
                    },
                ],
                ..SummaryDataPoint::default()
            },
            SummaryDataPoint {
                time_unix_nano: 1,
                count: 1,
                quantile_values: vec![SummaryValueAtQuantile {
                    quantile: 0.5,
                    value: -1.0,
                    ..SummaryValueAtQuantile::default()
                }],
                ..SummaryDataPoint::default()
            },
            SummaryDataPoint {
                time_unix_nano: 1,
                sum: 1.0,
                ..SummaryDataPoint::default()
            },
        ] {
            assert!(matches!(
                invalid.encode_to_bytes(limits()),
                Err(ProtobufWireError::SchemaInvariant { .. })
            ));
        }
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__property_matrix_metrics_packed_and_reserved() {
        let mut unpacked = ProtobufWireEncoder::new(limits());
        unpacked
            .write_fixed64(3, 1)
            .expect("required histogram point time");
        unpacked.write_fixed64(4, 3).expect("histogram count");
        unpacked.write_fixed64(6, 1).expect("first bucket");
        unpacked.write_fixed64(6, 2).expect("second bucket");
        unpacked
            .write_fixed64(7, 2.5f64.to_bits())
            .expect("explicit bound");
        let decoded = HistogramDataPoint::decode_from_bytes(
            &unpacked.finish().expect("finish unpacked histogram"),
            limits(),
        )
        .expect("decode unpacked fixed64 values");
        assert_eq!(decoded.bucket_counts, vec![1, 2]);
        assert_eq!(decoded.explicit_bounds, vec![2.5]);
        let canonical = decoded
            .encode_to_bytes(limits())
            .expect("encode canonical packed histogram");
        assert!(canonical.windows(2).any(|window| window == [0x32, 0x10]));
        assert!(canonical.windows(2).any(|window| window == [0x3a, 0x08]));

        let mut packed_buckets = ProtobufWireEncoder::new(limits());
        packed_buckets
            .write_packed_varints(2, &[1, 127, 128])
            .expect("packed exponential buckets");
        let buckets = ExponentialHistogramBuckets::decode_from_bytes(
            &packed_buckets.finish().expect("finish packed buckets"),
            limits(),
        )
        .expect("decode packed varints");
        assert_eq!(buckets.bucket_counts, vec![1, 127, 128]);

        let malformed_fixed = [0x32, 0x01, 0x00];
        assert!(matches!(
            HistogramDataPoint::decode_from_bytes(&malformed_fixed, limits()),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "packed fixed64 payload length must be divisible by eight",
                ..
            })
        ));
        let malformed_varint = [0x12, 0x01, 0x80];
        assert!(matches!(
            ExponentialHistogramBuckets::decode_from_bytes(&malformed_varint, limits()),
            Err(ProtobufWireError::UnexpectedEof { offset: 3, .. })
        ));

        let mut inconsistent_histogram = ProtobufWireEncoder::new(limits());
        inconsistent_histogram
            .write_fixed64(3, 1)
            .expect("histogram point time");
        inconsistent_histogram
            .write_fixed64(4, 3)
            .expect("histogram point count");
        inconsistent_histogram
            .write_packed_fixed64(6, &[1, 1])
            .expect("histogram point buckets");
        inconsistent_histogram
            .write_packed_doubles(7, &[1.0])
            .expect("histogram point bounds");
        assert!(matches!(
            HistogramDataPoint::decode_from_bytes(
                &inconsistent_histogram
                    .finish()
                    .expect("finish inconsistent histogram"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaInvariant {
                invariant: "histogram count must equal bucket count sum",
                ..
            })
        ));

        let reserved = [0x20, 0x01];
        let metric = Metric::decode_from_bytes(&reserved, limits()).expect("decode reserved tag");
        assert_eq!(metric.unknown_fields.as_bytes(), reserved);
        assert_eq!(
            metric
                .encode_to_bytes(limits())
                .expect("re-encode reserved tag"),
            reserved.as_slice()
        );
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__lab_lifecycle_metrics_failure_state() {
        let malformed = [0x0a, 0x02, b'o', b'k', 0x2a];
        assert!(Metric::decode_from_bytes(&malformed, limits()).is_err());

        let mut merge_target = Metric::default();
        assert!(merge_target.merge_from_bytes(&malformed, limits()).is_err());
        assert_eq!(merge_target.name, "ok");

        let any_value_tree = |tail_items| {
            let mut attributes = (0..31)
                .map(|index| KeyValue {
                    key: format!("aggregate-{index}"),
                    value: Some(AnyValue {
                        value: Some(AnyValueValue::Array(ArrayValue {
                            values: vec![AnyValue::default(); MAX_ANY_VALUE_ITEMS],
                            unknown_fields: UnknownFields::new(),
                        })),
                        unknown_fields: UnknownFields::new(),
                    }),
                    ..KeyValue::default()
                })
                .collect::<Vec<_>>();
            attributes.push(KeyValue {
                key: "aggregate-tail".to_owned(),
                value: Some(AnyValue {
                    value: Some(AnyValueValue::Array(ArrayValue {
                        values: vec![AnyValue::default(); tail_items],
                        unknown_fields: UnknownFields::new(),
                    })),
                    unknown_fields: UnknownFields::new(),
                }),
                ..KeyValue::default()
            });
            Resource {
                attributes,
                ..Resource::default()
            }
        };
        any_value_tree(96)
            .encode_to_bytes(limits())
            .expect("exact aggregate AnyValue-node budget");
        assert!(matches!(
            any_value_tree(97).encode_to_bytes(limits()),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "total AnyValue nodes",
                observed,
                limit,
                ..
            }) if observed == MAX_TOTAL_ANY_VALUE_NODES + 1
                && limit == MAX_TOTAL_ANY_VALUE_NODES
        ));

        let mut repeated_budget = ValidationBudget::new(usize::MAX, true);
        repeated_budget
            .repeated(
                MAX_TOTAL_REPEATED_ITEMS,
                MAX_TOTAL_REPEATED_ITEMS,
                "aggregate repeated-item fixture",
            )
            .expect("exact aggregate repeated-item budget");
        assert!(matches!(
            repeated_budget.repeated(1, 1, "aggregate repeated-item fixture"),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "total repeated items",
                observed,
                limit,
                ..
            }) if observed == MAX_TOTAL_REPEATED_ITEMS + 1
                && limit == MAX_TOTAL_REPEATED_ITEMS
        ));

        let mut full = MetricsData {
            resource_metrics: vec![ResourceMetrics::default(); MAX_RESOURCE_GROUPS_PER_REQUEST],
            unknown_fields: UnknownFields::new(),
        };
        let mut one_more = ProtobufWireEncoder::new(limits());
        one_more
            .write_message(1, &[])
            .expect("one additional resource group");
        assert!(matches!(
            full.merge_from_bytes(
                &one_more.finish().expect("finish one-more fixture"),
                limits(),
            ),
            Err(ProtobufWireError::SchemaLimitExceeded {
                resource: "metric resource groups",
                observed,
                limit,
                ..
            }) if observed == MAX_RESOURCE_GROUPS_PER_REQUEST + 1
                && limit == MAX_RESOURCE_GROUPS_PER_REQUEST
        ));
        assert_eq!(full.resource_metrics.len(), MAX_RESOURCE_GROUPS_PER_REQUEST);
    }

    #[test]
    fn ver_a1_asupersync_5z2scg_1_3_3548cd7b1804__downstream_consumer_collector_requests_generic_codec()
     {
        let metrics_model = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics::default()],
            unknown_fields: UnknownFields::new(),
        };
        let mut metrics_codec: ProtoCodec<
            ExportMetricsServiceRequest,
            ExportMetricsServiceRequest,
        > = ProtoCodec::new();
        let encoded = metrics_codec
            .encode(&metrics_model)
            .expect("generic metrics collector codec encode");
        assert_eq!(
            metrics_codec
                .decode(&encoded)
                .expect("generic metrics collector codec decode"),
            metrics_model
        );

        let trace_model = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans::default()],
            unknown_fields: UnknownFields::new(),
        };
        let mut trace_codec: ProtoCodec<ExportTraceServiceRequest, ExportTraceServiceRequest> =
            ProtoCodec::new();
        let encoded = trace_codec
            .encode(&trace_model)
            .expect("generic trace collector codec encode");
        assert_eq!(
            trace_codec
                .decode(&encoded)
                .expect("generic trace collector codec decode"),
            trace_model
        );

        let logs_model = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs::default()],
            unknown_fields: UnknownFields::new(),
        };
        let mut logs_codec: ProtoCodec<ExportLogsServiceRequest, ExportLogsServiceRequest> =
            ProtoCodec::new();
        let encoded = logs_codec
            .encode(&logs_model)
            .expect("generic logs collector codec encode");
        assert_eq!(
            logs_codec
                .decode(&encoded)
                .expect("generic logs collector codec decode"),
            logs_model
        );
    }
}
