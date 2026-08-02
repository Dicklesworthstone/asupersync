//! Resource-bounded primitives for the Protocol Buffers binary wire format.
//!
//! This kernel is additive to [`super::ProstCodec`]. It provides the checked
//! building blocks needed by owned codecs without narrowing the public
//! `prost::Message` authoring boundary.
//!
//! The decoder is schema-neutral: length-delimited values are exposed as
//! borrowed bytes because the wire alone cannot distinguish strings, bytes,
//! packed scalars, maps, and nested messages. A schema-aware consumer can
//! validate UTF-8 with [`ProtobufWireField::as_str`] or create a shared-budget
//! nested decoder with [`ProtobufWireDecoder::nested_message`].
//!
//! The encoder is deterministic for the same ordered sequence of method calls.
//! It is deliberately not described as canonical: Protocol Buffers permits
//! fields in any order, and canonical map/unknown-field ordering requires
//! schema knowledge above this wire layer.

use crate::bytes::Bytes;

/// Largest field number representable by a Protocol Buffers tag.
pub const MAX_PROTOBUF_FIELD_NUMBER: u32 = (1 << 29) - 1;

/// Protocol Buffers' wire-format message and length-delimited value ceiling.
///
/// The language specification requires serialized messages to remain below
/// 2 GiB, so the largest admitted byte length is `i32::MAX`.
pub const MAX_PROTOBUF_MESSAGE_LEN: usize = i32::MAX as usize;

/// Wire types encoded in the low three bits of a Protocol Buffers field key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WireType {
    /// Base-128 varint (`int*`, `uint*`, `sint*`, bool, and enum).
    Varint = 0,
    /// Eight-byte little-endian value (`fixed64`, `sfixed64`, and double).
    Fixed64 = 1,
    /// Varint length followed by bytes (string, bytes, message, or packed).
    LengthDelimited = 2,
    /// Start delimiter for the deprecated, but still valid, group encoding.
    StartGroup = 3,
    /// End delimiter for the deprecated, but still valid, group encoding.
    EndGroup = 4,
    /// Four-byte little-endian value (`fixed32`, `sfixed32`, and float).
    Fixed32 = 5,
}

impl WireType {
    fn from_id(id: u8, offset: usize) -> Result<Self, ProtobufWireError> {
        match id {
            0 => Ok(Self::Varint),
            1 => Ok(Self::Fixed64),
            2 => Ok(Self::LengthDelimited),
            3 => Ok(Self::StartGroup),
            4 => Ok(Self::EndGroup),
            5 => Ok(Self::Fixed32),
            wire_type => Err(ProtobufWireError::InvalidWireType { offset, wire_type }),
        }
    }
}

/// Checked limits shared by the schema-neutral wire decoder and encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtobufWireLimits {
    /// Maximum bytes in one top-level serialized message.
    pub max_message_len: usize,
    /// Maximum bytes in one length-delimited field.
    pub max_field_len: usize,
    /// Maximum field records, including group delimiters and nested fields.
    pub max_fields: usize,
    /// Maximum combined nested-message and group depth.
    pub max_depth: usize,
    /// Maximum cumulative bytes examined or emitted.
    ///
    /// Nested length-delimited payloads are charged once when borrowed and
    /// again when a schema-aware consumer descends into them.
    pub max_work: usize,
}

impl ProtobufWireLimits {
    /// Construct balanced limits around a top-level message-size ceiling.
    #[must_use]
    pub const fn for_message_size(max_message_len: usize) -> Self {
        Self {
            max_message_len,
            max_field_len: max_message_len,
            max_fields: 65_536,
            max_depth: 100,
            max_work: max_message_len.saturating_mul(4),
        }
    }

    /// Override the maximum length-delimited field size.
    #[must_use]
    pub const fn with_max_field_len(mut self, max_field_len: usize) -> Self {
        self.max_field_len = max_field_len;
        self
    }

    /// Override the aggregate field-record count.
    #[must_use]
    pub const fn with_max_fields(mut self, max_fields: usize) -> Self {
        self.max_fields = max_fields;
        self
    }

    /// Override the combined nested-message and group depth.
    #[must_use]
    pub const fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Override the cumulative decoder or encoder work budget.
    #[must_use]
    pub const fn with_max_work(mut self, max_work: usize) -> Self {
        self.max_work = max_work;
        self
    }

    const fn effective_message_limit(self) -> usize {
        if self.max_message_len < MAX_PROTOBUF_MESSAGE_LEN {
            self.max_message_len
        } else {
            MAX_PROTOBUF_MESSAGE_LEN
        }
    }

    const fn effective_field_limit(self) -> usize {
        let field_limit = if self.max_field_len < MAX_PROTOBUF_MESSAGE_LEN {
            self.max_field_len
        } else {
            MAX_PROTOBUF_MESSAGE_LEN
        };
        if field_limit < self.effective_message_limit() {
            field_limit
        } else {
            self.effective_message_limit()
        }
    }
}

impl Default for ProtobufWireLimits {
    fn default() -> Self {
        Self::for_message_size(super::DEFAULT_MAX_MESSAGE_SIZE)
    }
}

/// Precise, stable failures returned by the owned wire kernel.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtobufWireError {
    /// A top-level message exceeds the configured or wire-format ceiling.
    #[error("protobuf message length {length} exceeds limit {limit}")]
    MessageLimitExceeded {
        /// Observed message length.
        length: usize,
        /// Effective configured limit.
        limit: usize,
    },
    /// A length-delimited field exceeds its limit before allocation.
    #[error("protobuf field at byte {offset} declares length {length}, exceeding limit {limit}")]
    FieldLimitExceeded {
        /// Absolute offset of the length prefix.
        offset: usize,
        /// Declared field length.
        length: u64,
        /// Effective configured limit.
        limit: usize,
    },
    /// The message ended before a complete primitive could be read.
    #[error(
        "truncated protobuf input at byte {offset}: need {needed} byte(s), only {remaining} remain"
    )]
    UnexpectedEof {
        /// Absolute offset where input was required.
        offset: usize,
        /// Required byte count.
        needed: usize,
        /// Remaining byte count.
        remaining: usize,
    },
    /// A base-128 varint uses more than 64 payload bits or never terminates.
    #[error("protobuf varint overflows u64 at byte {offset}")]
    VarintOverflow {
        /// Absolute offset of the malformed varint.
        offset: usize,
    },
    /// A field key used field number zero or exceeded the 29-bit ceiling.
    #[error("invalid protobuf field number {field_number} at byte {offset}")]
    InvalidFieldNumber {
        /// Absolute offset of the field key.
        offset: usize,
        /// Decoded field number.
        field_number: u64,
    },
    /// The low key bits named reserved wire type six or seven.
    #[error("invalid protobuf wire type {wire_type} at byte {offset}")]
    InvalidWireType {
        /// Absolute offset of the field key.
        offset: usize,
        /// Invalid three-bit wire type.
        wire_type: u8,
    },
    /// More field records were observed than the configured aggregate limit.
    #[error("protobuf field count {count} exceeds limit {limit} at byte {offset}")]
    FieldCountExceeded {
        /// Absolute offset of the rejected field.
        offset: usize,
        /// Count that would result from accepting it.
        count: usize,
        /// Configured field-count limit.
        limit: usize,
    },
    /// A nested message or group exceeded the configured depth.
    #[error("protobuf nesting depth {depth} exceeds limit {limit} at byte {offset}")]
    RecursionLimitExceeded {
        /// Absolute offset of the rejected nested value or group.
        offset: usize,
        /// Depth that would result from accepting it.
        depth: usize,
        /// Configured depth limit.
        limit: usize,
    },
    /// Cumulative parser or encoder work exceeded its configured ceiling.
    #[error("protobuf work {work} exceeds limit {limit} at byte {offset}")]
    WorkLimitExceeded {
        /// Absolute input or output offset where the budget was exceeded.
        offset: usize,
        /// Work that would result from accepting the operation.
        work: usize,
        /// Configured work limit.
        limit: usize,
    },
    /// A schema-aware aggregate or per-collection limit was exceeded.
    #[error(
        "protobuf schema resource {resource} reached {observed}, exceeding limit {limit} at byte {offset}"
    )]
    SchemaLimitExceeded {
        /// Absolute input or output offset where the limit was exceeded.
        offset: usize,
        /// Stable schema resource name.
        resource: &'static str,
        /// Value that would result from accepting the operation.
        observed: usize,
        /// Configured schema limit.
        limit: usize,
    },
    /// A bounded allocation failed after all size checks passed.
    #[error(
        "protobuf allocation for {resource} failed at byte {offset} while reserving {additional} additional unit(s)"
    )]
    AllocationFailed {
        /// Absolute input or output offset associated with the allocation.
        offset: usize,
        /// Stable name for the buffer or collection being grown.
        resource: &'static str,
        /// Additional bytes or elements requested.
        additional: usize,
    },
    /// A schema-level semantic invariant rejected an otherwise valid wire message.
    #[error("protobuf schema invariant {invariant} failed at byte {offset}")]
    SchemaInvariant {
        /// Absolute input or output offset associated with the invariant.
        offset: usize,
        /// Stable invariant identifier.
        invariant: &'static str,
    },
    /// A group end tag appeared without a corresponding open group.
    #[error("unexpected protobuf end-group for field {field_number} at byte {offset}")]
    UnexpectedEndGroup {
        /// Absolute offset of the end-group key.
        offset: usize,
        /// Field number on the end-group key.
        field_number: u32,
    },
    /// A group end tag did not use the opening group's field number.
    #[error(
        "mismatched protobuf end-group at byte {offset}: expected field {expected}, got {actual}"
    )]
    MismatchedEndGroup {
        /// Absolute offset of the end-group key.
        offset: usize,
        /// Opening group field number.
        expected: u32,
        /// End-group field number.
        actual: u32,
    },
    /// Input ended while a group was still open.
    #[error("unterminated protobuf group for field {field_number} opened at byte {offset}")]
    UnterminatedGroup {
        /// Absolute offset of the start-group key.
        offset: usize,
        /// Opening group field number.
        field_number: u32,
    },
    /// A string field contained bytes that are not valid UTF-8.
    #[error("invalid UTF-8 in protobuf string at byte {offset}")]
    InvalidUtf8 {
        /// Absolute offset of the string payload.
        offset: usize,
    },
    /// A schema-aware accessor was used with the wrong wire type.
    #[error("protobuf wire type mismatch at byte {offset}: expected {expected:?}, got {actual:?}")]
    WireTypeMismatch {
        /// Absolute offset of the field key.
        offset: usize,
        /// Wire type required by the accessor.
        expected: WireType,
        /// Actual wire type.
        actual: WireType,
    },
    /// An encoder end-group call does not match its open group.
    #[error(
        "protobuf encoder group mismatch at byte {offset}: expected field {expected}, got {actual}"
    )]
    EncoderGroupMismatch {
        /// Current output offset.
        offset: usize,
        /// Opening group field number, or zero when no group is open.
        expected: u32,
        /// Requested end-group field number.
        actual: u32,
    },
}

/// Decoded schema-neutral payload for one field record.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProtobufWireValue<'a> {
    /// Unsigned interpretation of a varint payload.
    Varint(u64),
    /// Raw little-endian 64-bit payload.
    Fixed64(u64),
    /// Borrowed length-delimited bytes.
    LengthDelimited(&'a [u8]),
    /// Start of a deprecated group.
    StartGroup,
    /// End of a deprecated group.
    EndGroup,
    /// Raw little-endian 32-bit payload.
    Fixed32(u32),
}

/// One checked field record borrowed from a serialized message.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProtobufWireField<'a> {
    field_number: u32,
    wire_type: WireType,
    value: ProtobufWireValue<'a>,
    raw: &'a [u8],
    offset: usize,
    value_offset: usize,
}

impl<'a> ProtobufWireField<'a> {
    /// Field number from the decoded key.
    #[must_use]
    pub const fn field_number(&self) -> u32 {
        self.field_number
    }

    /// Wire type from the decoded key.
    #[must_use]
    pub const fn wire_type(&self) -> WireType {
        self.wire_type
    }

    /// Schema-neutral decoded value.
    #[must_use]
    pub const fn value(&self) -> ProtobufWireValue<'a> {
        self.value
    }

    /// Exact bytes for this record, including its key and any length prefix.
    ///
    /// For group delimiters this is only the delimiter key. Use
    /// [`ProtobufWireDecoder::skip_group`] to capture a complete group.
    #[must_use]
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Absolute byte offset of the field key.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Absolute byte offset of the payload.
    #[must_use]
    pub const fn value_offset(&self) -> usize {
        self.value_offset
    }

    /// Return a varint payload or a typed mismatch error.
    pub fn as_varint(&self) -> Result<u64, ProtobufWireError> {
        match self.value {
            ProtobufWireValue::Varint(value) => Ok(value),
            _ => Err(self.type_mismatch(WireType::Varint)),
        }
    }

    /// Return a fixed32 payload or a typed mismatch error.
    pub fn as_fixed32(&self) -> Result<u32, ProtobufWireError> {
        match self.value {
            ProtobufWireValue::Fixed32(value) => Ok(value),
            _ => Err(self.type_mismatch(WireType::Fixed32)),
        }
    }

    /// Return a fixed64 payload or a typed mismatch error.
    pub fn as_fixed64(&self) -> Result<u64, ProtobufWireError> {
        match self.value {
            ProtobufWireValue::Fixed64(value) => Ok(value),
            _ => Err(self.type_mismatch(WireType::Fixed64)),
        }
    }

    /// Return borrowed length-delimited bytes or a typed mismatch error.
    pub fn as_bytes(&self) -> Result<&'a [u8], ProtobufWireError> {
        match self.value {
            ProtobufWireValue::LengthDelimited(value) => Ok(value),
            _ => Err(self.type_mismatch(WireType::LengthDelimited)),
        }
    }

    /// Validate and return a borrowed UTF-8 string.
    pub fn as_str(&self) -> Result<&'a str, ProtobufWireError> {
        let bytes = self.as_bytes()?;
        std::str::from_utf8(bytes).map_err(|_| ProtobufWireError::InvalidUtf8 {
            offset: self.value_offset,
        })
    }

    fn type_mismatch(&self, expected: WireType) -> ProtobufWireError {
        ProtobufWireError::WireTypeMismatch {
            offset: self.offset,
            expected,
            actual: self.wire_type,
        }
    }
}

// In-progress gRPC scaffolding: several fields/methods in this module have
// feature-dependent callers and fall dead under downstream workspaces whose
// feature unification gates those callers off. Allow dead_code at the
// affected sites (crate-wide policy stays deny) until the callers land.
#[derive(Debug)]
#[allow(dead_code)]
struct DecodeState {
    limits: ProtobufWireLimits,
    fields_seen: usize,
    work_used: usize,
    semantic_repeated_items: usize,
    semantic_any_value_nodes: usize,
    semantic_any_value_depth: usize,
    semantic_owned_bytes: usize,
}

impl DecodeState {
    fn charge_field(&mut self, offset: usize) -> Result<(), ProtobufWireError> {
        let Some(count) = self.fields_seen.checked_add(1) else {
            return Err(ProtobufWireError::FieldCountExceeded {
                offset,
                count: usize::MAX,
                limit: self.limits.max_fields,
            });
        };
        if count > self.limits.max_fields {
            return Err(ProtobufWireError::FieldCountExceeded {
                offset,
                count,
                limit: self.limits.max_fields,
            });
        }
        self.fields_seen = count;
        Ok(())
    }

    fn charge_work(&mut self, amount: usize, offset: usize) -> Result<(), ProtobufWireError> {
        let Some(work) = self.work_used.checked_add(amount) else {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset,
                work: usize::MAX,
                limit: self.limits.max_work,
            });
        };
        if work > self.limits.max_work {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset,
                work,
                limit: self.limits.max_work,
            });
        }
        self.work_used = work;
        Ok(())
    }

    #[allow(dead_code)]
    fn charge_semantic(
        current: &mut usize,
        amount: usize,
        limit: usize,
        offset: usize,
        resource: &'static str,
    ) -> Result<(), ProtobufWireError> {
        let Some(observed) = current.checked_add(amount) else {
            return Err(ProtobufWireError::SchemaLimitExceeded {
                offset,
                resource,
                observed: usize::MAX,
                limit,
            });
        };
        if observed > limit {
            return Err(ProtobufWireError::SchemaLimitExceeded {
                offset,
                resource,
                observed,
                limit,
            });
        }
        *current = observed;
        Ok(())
    }
}

/// A bounded top-level message that owns the aggregate decoder budget.
#[derive(Debug)]
pub struct ProtobufWireMessage<'a> {
    input: &'a [u8],
    state: DecodeState,
}

impl<'a> ProtobufWireMessage<'a> {
    /// Validate the top-level length before constructing any wire cursor.
    pub fn new(input: &'a [u8], limits: ProtobufWireLimits) -> Result<Self, ProtobufWireError> {
        let limit = limits.effective_message_limit();
        if input.len() > limit {
            return Err(ProtobufWireError::MessageLimitExceeded {
                length: input.len(),
                limit,
            });
        }
        Ok(Self {
            input,
            state: DecodeState {
                limits,
                fields_seen: 0,
                work_used: 0,
                semantic_repeated_items: 0,
                semantic_any_value_nodes: 0,
                semantic_any_value_depth: 0,
                semantic_owned_bytes: 0,
            },
        })
    }

    /// Borrow a root decoder backed by this message's aggregate budget.
    ///
    /// A message should normally be traversed by one root decoder. Creating
    /// another root decoder intentionally re-examines the bytes and consumes
    /// additional field and work budget.
    pub fn decoder(&mut self) -> ProtobufWireDecoder<'a, '_> {
        ProtobufWireDecoder {
            input: self.input,
            position: 0,
            base_offset: 0,
            depth: 0,
            groups: Vec::new(),
            state: &mut self.state,
        }
    }

    /// Number of field records accepted across root and nested decoders.
    #[must_use]
    pub const fn fields_seen(&self) -> usize {
        self.state.fields_seen
    }

    /// Cumulative bytes examined across root and nested decoders.
    #[must_use]
    pub const fn work_used(&self) -> usize {
        self.state.work_used
    }
}

#[derive(Clone, Copy, Debug)]
struct OpenGroup {
    field_number: u32,
    offset: usize,
}

/// Borrowing, schema-neutral decoder with aggregate resource accounting.
#[derive(Debug)]
pub struct ProtobufWireDecoder<'a, 'budget> {
    input: &'a [u8],
    position: usize,
    base_offset: usize,
    depth: usize,
    groups: Vec<OpenGroup>,
    state: &'budget mut DecodeState,
}

#[allow(dead_code)]
impl<'a> ProtobufWireDecoder<'a, '_> {
    /// Absolute position of the next unread byte.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.base_offset + self.position
    }

    /// Whether every byte has been consumed and every group has been closed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.position == self.input.len() && self.groups.is_empty()
    }

    /// Remaining aggregate work available to schema-aware validation.
    pub(crate) fn remaining_work(&self) -> usize {
        self.state
            .limits
            .max_work
            .saturating_sub(self.state.work_used)
    }

    /// Seed semantic counters from an already validated merge target before
    /// admitting any new field allocation.
    pub(crate) fn seed_semantic_budgets(
        &mut self,
        repeated_items: usize,
        repeated_limit: usize,
        any_value_nodes: usize,
        any_value_node_limit: usize,
        owned_bytes: usize,
        owned_bytes_limit: usize,
    ) -> Result<(), ProtobufWireError> {
        DecodeState::charge_semantic(
            &mut self.state.semantic_repeated_items,
            repeated_items,
            repeated_limit,
            0,
            "total repeated items",
        )?;
        DecodeState::charge_semantic(
            &mut self.state.semantic_any_value_nodes,
            any_value_nodes,
            any_value_node_limit,
            0,
            "total AnyValue nodes",
        )?;
        DecodeState::charge_semantic(
            &mut self.state.semantic_owned_bytes,
            owned_bytes,
            owned_bytes_limit,
            0,
            "total owned string and bytes payload",
        )
    }

    /// Charge schema-specific repeated-item accounting against this message's
    /// shared decode state before reserving or pushing an element.
    pub(crate) fn charge_semantic_repeated_items(
        &mut self,
        amount: usize,
        limit: usize,
        offset: usize,
    ) -> Result<(), ProtobufWireError> {
        DecodeState::charge_semantic(
            &mut self.state.semantic_repeated_items,
            amount,
            limit,
            offset,
            "total repeated items",
        )
    }

    /// Enter one recursive schema value before descending into it.
    ///
    /// `new_node` distinguishes a newly allocated logical value from a
    /// repeated wire occurrence that merges into an existing message-valued
    /// member. Depth is charged for both; aggregate node count only for the
    /// former.
    pub(crate) fn enter_semantic_any_value(
        &mut self,
        new_node: bool,
        node_limit: usize,
        depth_limit: usize,
        offset: usize,
    ) -> Result<(), ProtobufWireError> {
        let Some(depth) = self.state.semantic_any_value_depth.checked_add(1) else {
            return Err(ProtobufWireError::SchemaLimitExceeded {
                offset,
                resource: "AnyValue depth",
                observed: usize::MAX,
                limit: depth_limit,
            });
        };
        if depth > depth_limit {
            return Err(ProtobufWireError::SchemaLimitExceeded {
                offset,
                resource: "AnyValue depth",
                observed: depth,
                limit: depth_limit,
            });
        }
        if new_node {
            DecodeState::charge_semantic(
                &mut self.state.semantic_any_value_nodes,
                1,
                node_limit,
                offset,
                "total AnyValue nodes",
            )?;
        }
        self.state.semantic_any_value_depth = depth;
        Ok(())
    }

    /// Leave a recursive schema value after its nested merge finishes.
    pub(crate) fn leave_semantic_any_value(&mut self) {
        debug_assert!(self.state.semantic_any_value_depth > 0);
        self.state.semantic_any_value_depth = self.state.semantic_any_value_depth.saturating_sub(1);
    }

    /// Charge schema-owned string, bytes, or unknown-field storage before
    /// allocating or copying it.
    pub(crate) fn charge_semantic_owned_bytes(
        &mut self,
        amount: usize,
        limit: usize,
        offset: usize,
    ) -> Result<(), ProtobufWireError> {
        DecodeState::charge_semantic(
            &mut self.state.semantic_owned_bytes,
            amount,
            limit,
            offset,
            "total owned string and bytes payload",
        )
    }

    /// Charge an additional schema-aware scan or copy against the aggregate
    /// wire-work budget.
    pub(crate) fn charge_additional_work(
        &mut self,
        amount: usize,
        offset: usize,
    ) -> Result<(), ProtobufWireError> {
        self.state.charge_work(amount, offset)
    }

    /// Decode the next field, accepting non-minimal but valid varints.
    ///
    /// No allocation depends on a wire-declared length. Length-delimited
    /// payloads are checked and returned as borrowed slices.
    pub fn next_field(&mut self) -> Result<Option<ProtobufWireField<'a>>, ProtobufWireError> {
        if self.position == self.input.len() {
            if let Some(group) = self.groups.last() {
                return Err(ProtobufWireError::UnterminatedGroup {
                    offset: group.offset,
                    field_number: group.field_number,
                });
            }
            return Ok(None);
        }

        let start = self.position;
        let absolute_start = self.base_offset + start;
        self.state.charge_field(absolute_start)?;
        let raw_key = self.read_varint()?;
        let field_number = raw_key >> 3;
        if field_number == 0 || field_number > u64::from(MAX_PROTOBUF_FIELD_NUMBER) {
            return Err(ProtobufWireError::InvalidFieldNumber {
                offset: absolute_start,
                field_number,
            });
        }
        let field_number =
            u32::try_from(field_number).map_err(|_| ProtobufWireError::InvalidFieldNumber {
                offset: absolute_start,
                field_number,
            })?;
        let wire_type = WireType::from_id(raw_key.to_le_bytes()[0] & 0x07, absolute_start)?;
        let mut value_offset = self.base_offset + self.position;

        let value = match wire_type {
            WireType::Varint => ProtobufWireValue::Varint(self.read_varint()?),
            WireType::Fixed64 => {
                let bytes = self.take(8)?;
                let bytes =
                    <&[u8; 8]>::try_from(bytes).map_err(|_| ProtobufWireError::UnexpectedEof {
                        offset: value_offset,
                        needed: 8,
                        remaining: bytes.len(),
                    })?;
                ProtobufWireValue::Fixed64(u64::from_le_bytes(*bytes))
            }
            WireType::LengthDelimited => {
                let length_offset = self.base_offset + self.position;
                let length = self.read_varint()?;
                let field_limit = self.state.limits.effective_field_limit();
                if length > field_limit as u64 {
                    return Err(ProtobufWireError::FieldLimitExceeded {
                        offset: length_offset,
                        length,
                        limit: field_limit,
                    });
                }
                let length =
                    usize::try_from(length).map_err(|_| ProtobufWireError::FieldLimitExceeded {
                        offset: length_offset,
                        length,
                        limit: field_limit,
                    })?;
                value_offset = self.base_offset + self.position;
                ProtobufWireValue::LengthDelimited(self.take(length)?)
            }
            WireType::StartGroup => {
                let depth = self
                    .depth
                    .saturating_add(self.groups.len())
                    .saturating_add(1);
                if depth > self.state.limits.max_depth {
                    return Err(ProtobufWireError::RecursionLimitExceeded {
                        offset: absolute_start,
                        depth,
                        limit: self.state.limits.max_depth,
                    });
                }
                self.groups
                    .try_reserve(1)
                    .map_err(|_| ProtobufWireError::AllocationFailed {
                        offset: absolute_start,
                        resource: "decoder group stack",
                        additional: 1,
                    })?;
                self.groups.push(OpenGroup {
                    field_number,
                    offset: absolute_start,
                });
                ProtobufWireValue::StartGroup
            }
            WireType::EndGroup => {
                let Some(open) = self.groups.pop() else {
                    return Err(ProtobufWireError::UnexpectedEndGroup {
                        offset: absolute_start,
                        field_number,
                    });
                };
                if open.field_number != field_number {
                    return Err(ProtobufWireError::MismatchedEndGroup {
                        offset: absolute_start,
                        expected: open.field_number,
                        actual: field_number,
                    });
                }
                ProtobufWireValue::EndGroup
            }
            WireType::Fixed32 => {
                let bytes = self.take(4)?;
                let bytes =
                    <&[u8; 4]>::try_from(bytes).map_err(|_| ProtobufWireError::UnexpectedEof {
                        offset: value_offset,
                        needed: 4,
                        remaining: bytes.len(),
                    })?;
                ProtobufWireValue::Fixed32(u32::from_le_bytes(*bytes))
            }
        };

        Ok(Some(ProtobufWireField {
            field_number,
            wire_type,
            value,
            raw: &self.input[start..self.position],
            offset: absolute_start,
            value_offset,
        }))
    }

    /// Open a schema-declared nested message while sharing aggregate budgets.
    pub fn nested_message<'nested>(
        &'nested mut self,
        field: &ProtobufWireField<'a>,
    ) -> Result<ProtobufWireDecoder<'a, 'nested>, ProtobufWireError> {
        let bytes = field.as_bytes()?;
        let depth = self
            .depth
            .saturating_add(self.groups.len())
            .saturating_add(1);
        if depth > self.state.limits.max_depth {
            return Err(ProtobufWireError::RecursionLimitExceeded {
                offset: field.value_offset,
                depth,
                limit: self.state.limits.max_depth,
            });
        }
        Ok(ProtobufWireDecoder {
            input: bytes,
            position: 0,
            base_offset: field.value_offset,
            depth,
            groups: Vec::new(),
            state: &mut *self.state,
        })
    }

    /// Consume a complete group and return its exact bytes for preservation.
    ///
    /// `start` must be the most recently returned start-group field.
    pub fn skip_group(
        &mut self,
        start: &ProtobufWireField<'a>,
    ) -> Result<&'a [u8], ProtobufWireError> {
        if start.wire_type != WireType::StartGroup {
            return Err(start.type_mismatch(WireType::StartGroup));
        }
        let Some(open) = self.groups.last() else {
            return Err(ProtobufWireError::UnexpectedEndGroup {
                offset: start.offset,
                field_number: start.field_number,
            });
        };
        if open.field_number != start.field_number || open.offset != start.offset {
            return Err(ProtobufWireError::MismatchedEndGroup {
                offset: start.offset,
                expected: open.field_number,
                actual: start.field_number,
            });
        }

        let target_depth = self.groups.len() - 1;
        while self.groups.len() > target_depth {
            self.next_field()?;
        }
        let relative_start = start.offset - self.base_offset;
        Ok(&self.input[relative_start..self.position])
    }

    fn read_varint(&mut self) -> Result<u64, ProtobufWireError> {
        let start = self.base_offset + self.position;
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.read_byte()?;
            let payload = u64::from(byte & 0x7f);
            if index == 9 && payload > 1 {
                return Err(ProtobufWireError::VarintOverflow { offset: start });
            }
            value |= payload << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ProtobufWireError::VarintOverflow { offset: start })
    }

    fn read_byte(&mut self) -> Result<u8, ProtobufWireError> {
        let Some(&byte) = self.input.get(self.position) else {
            return Err(ProtobufWireError::UnexpectedEof {
                offset: self.base_offset + self.position,
                needed: 1,
                remaining: 0,
            });
        };
        self.state
            .charge_work(1, self.base_offset + self.position)?;
        self.position += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtobufWireError> {
        let remaining = self.input.len() - self.position;
        if length > remaining {
            return Err(ProtobufWireError::UnexpectedEof {
                offset: self.base_offset + self.position,
                needed: length,
                remaining,
            });
        }
        self.state
            .charge_work(length, self.base_offset + self.position)?;
        let start = self.position;
        self.position += length;
        Ok(&self.input[start..self.position])
    }
}

/// Return the shortest base-128 varint length for a `u64`.
#[must_use]
pub const fn encoded_varint_len(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

/// Decode one standalone varint and report the consumed prefix length.
///
/// Valid non-minimal encodings are accepted. More than ten bytes, a
/// continuation bit on byte ten, or payload bits above bit 63 are rejected.
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), ProtobufWireError> {
    let mut value = 0u64;
    for index in 0..10 {
        let Some(&byte) = input.get(index) else {
            return Err(ProtobufWireError::UnexpectedEof {
                offset: index,
                needed: 1,
                remaining: 0,
            });
        };
        let payload = u64::from(byte & 0x7f);
        if index == 9 && payload > 1 {
            return Err(ProtobufWireError::VarintOverflow { offset: 0 });
        }
        value |= payload << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(ProtobufWireError::VarintOverflow { offset: 0 })
}

/// ZigZag-encode an `i32` for a `sint32` field.
#[must_use]
pub const fn zigzag_encode_i32(value: i32) -> u32 {
    ((value << 1) ^ (value >> 31)) as u32
}

/// ZigZag-decode a `sint32` payload.
#[must_use]
pub const fn zigzag_decode_i32(value: u32) -> i32 {
    (value >> 1).cast_signed() ^ -(value & 1).cast_signed()
}

/// ZigZag-encode an `i64` for a `sint64` field.
#[must_use]
pub const fn zigzag_encode_i64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

/// ZigZag-decode a `sint64` payload.
#[must_use]
pub const fn zigzag_decode_i64(value: u64) -> i64 {
    (value >> 1).cast_signed() ^ -(value & 1).cast_signed()
}

fn encode_varint_to_array(mut value: u64) -> ([u8; 10], usize) {
    let mut bytes = [0u8; 10];
    let mut length = 0;
    while value >= 0x80 {
        bytes[length] = (value as u8 & 0x7f) | 0x80;
        value >>= 7;
        length += 1;
    }
    bytes[length] = value as u8;
    (bytes, length + 1)
}

/// One in-place nested message whose length prefix is pending.
#[derive(Clone, Copy, Debug)]
struct OpenMessage {
    field_number: u32,
    start: usize,
}

/// Deterministic, resource-bounded writer for schema-aware owned codecs.
#[derive(Debug)]
pub struct ProtobufWireEncoder {
    output: Vec<u8>,
    limits: ProtobufWireLimits,
    fields_written: usize,
    work_used: usize,
    nested_messages: Vec<OpenMessage>,
    group_floor: usize,
    groups: Vec<u32>,
}

impl ProtobufWireEncoder {
    /// Construct an empty encoder with explicit limits.
    #[must_use]
    pub const fn new(limits: ProtobufWireLimits) -> Self {
        Self {
            output: Vec::new(),
            limits,
            fields_written: 0,
            work_used: 0,
            nested_messages: Vec::new(),
            group_floor: 0,
            groups: Vec::new(),
        }
    }

    /// Construct an encoder using balanced limits around a message-size cap.
    #[must_use]
    pub const fn with_max_size(max_message_len: usize) -> Self {
        Self::new(ProtobufWireLimits::for_message_size(max_message_len))
    }

    /// Current serialized length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.output.len()
    }

    /// Whether no fields have been emitted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.output.is_empty()
    }

    /// Number of emitted field records, including group delimiters.
    #[must_use]
    pub const fn fields_written(&self) -> usize {
        self.fields_written
    }

    /// Cumulative encoding work, including emitted bytes, schema validation,
    /// raw-field parsing, and nested payload shifts.
    #[must_use]
    pub const fn work_used(&self) -> usize {
        self.work_used
    }

    /// Remaining aggregate work available to schema-aware validation after
    /// reserving the unavoidable prefix and payload-shift work of every open
    /// nested-message wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`ProtobufWireError::FieldLimitExceeded`] if an open wrapper's
    /// current payload already exceeds the configured field limit.
    pub fn remaining_work(&self) -> Result<usize, ProtobufWireError> {
        let (_, pending_nested_work) = self.project_nested_wrappers(self.output.len())?;
        Ok(self
            .limits
            .max_work
            .saturating_sub(self.work_used.saturating_add(pending_nested_work)))
    }

    /// Charge schema validation performed before emitting fields.
    ///
    /// # Errors
    ///
    /// Returns the applicable message, field, field-count, work, or allocation
    /// error before changing the committed work counter.
    pub fn charge_schema_work(&mut self, amount: usize) -> Result<(), ProtobufWireError> {
        let Some(prospective_work) = self.work_used.checked_add(amount) else {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset: self.output.len(),
                work: usize::MAX,
                limit: self.limits.max_work,
            });
        };
        self.ensure_output(0, self.fields_written, prospective_work)?;
        self.work_used = prospective_work;
        Ok(())
    }

    /// Borrow the serialized prefix without finishing the encoder.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.output
    }

    /// Finish a message, rejecting any unclosed group.
    pub fn finish(self) -> Result<Bytes, ProtobufWireError> {
        if let Some(&expected) = self.groups.last() {
            return Err(ProtobufWireError::EncoderGroupMismatch {
                offset: self.output.len(),
                expected,
                actual: 0,
            });
        }
        Ok(Bytes::from(self.output))
    }

    /// Emit an unsigned varint field.
    pub fn write_varint(&mut self, field_number: u32, value: u64) -> Result<(), ProtobufWireError> {
        let (payload, payload_len) = encode_varint_to_array(value);
        self.write_record(
            field_number,
            WireType::Varint,
            &payload[..payload_len],
            None,
        )
    }

    /// Emit an `int32`, including ten-byte sign extension for negative values.
    pub fn write_int32(&mut self, field_number: u32, value: i32) -> Result<(), ProtobufWireError> {
        self.write_varint(field_number, value as i64 as u64)
    }

    /// Emit an `int64` using its two's-complement varint representation.
    pub fn write_int64(&mut self, field_number: u32, value: i64) -> Result<(), ProtobufWireError> {
        self.write_varint(field_number, value as u64)
    }

    /// Emit a ZigZag-encoded `sint32`.
    pub fn write_sint32(&mut self, field_number: u32, value: i32) -> Result<(), ProtobufWireError> {
        self.write_varint(field_number, u64::from(zigzag_encode_i32(value)))
    }

    /// Emit a ZigZag-encoded `sint64`.
    pub fn write_sint64(&mut self, field_number: u32, value: i64) -> Result<(), ProtobufWireError> {
        self.write_varint(field_number, zigzag_encode_i64(value))
    }

    /// Emit a bool as canonical zero or one.
    pub fn write_bool(&mut self, field_number: u32, value: bool) -> Result<(), ProtobufWireError> {
        self.write_varint(field_number, u64::from(value))
    }

    /// Emit a raw enum discriminant using the `int32` wire convention.
    pub fn write_enum(&mut self, field_number: u32, value: i32) -> Result<(), ProtobufWireError> {
        self.write_int32(field_number, value)
    }

    /// Emit a four-byte little-endian field.
    pub fn write_fixed32(
        &mut self,
        field_number: u32,
        value: u32,
    ) -> Result<(), ProtobufWireError> {
        self.write_record(field_number, WireType::Fixed32, &value.to_le_bytes(), None)
    }

    /// Emit an eight-byte little-endian field.
    pub fn write_fixed64(
        &mut self,
        field_number: u32,
        value: u64,
    ) -> Result<(), ProtobufWireError> {
        self.write_record(field_number, WireType::Fixed64, &value.to_le_bytes(), None)
    }

    /// Emit an IEEE-754 float using wire type fixed32.
    pub fn write_float(&mut self, field_number: u32, value: f32) -> Result<(), ProtobufWireError> {
        self.write_fixed32(field_number, value.to_bits())
    }

    /// Emit an IEEE-754 double using wire type fixed64.
    pub fn write_double(&mut self, field_number: u32, value: f64) -> Result<(), ProtobufWireError> {
        self.write_fixed64(field_number, value.to_bits())
    }

    /// Emit a borrowed byte string after checking its declared length.
    pub fn write_bytes(
        &mut self,
        field_number: u32,
        value: &[u8],
    ) -> Result<(), ProtobufWireError> {
        self.write_length_delimited(field_number, value)
    }

    /// Emit a valid UTF-8 string.
    pub fn write_string(
        &mut self,
        field_number: u32,
        value: &str,
    ) -> Result<(), ProtobufWireError> {
        self.write_length_delimited(field_number, value.as_bytes())
    }

    /// Emit an already encoded nested message as an opaque payload.
    ///
    /// The wrapper field and payload bytes are bounded, but the encoder cannot
    /// infer which length-delimited records inside `value` are messages rather
    /// than byte strings. Schema implementations that require aggregate nested
    /// field and depth accounting need a reviewed shared-writer path; the safe
    /// downstream authoring surface for that remains pending.
    pub fn write_message(
        &mut self,
        field_number: u32,
        value: &[u8],
    ) -> Result<(), ProtobufWireError> {
        self.write_length_delimited(field_number, value)
    }

    /// Encode a nested message directly into this encoder's output while
    /// sharing field, depth, work, and allocation accounting.
    ///
    /// The nested payload is written in place, then its key and length prefix
    /// are inserted ahead of it. A failed nested write rolls the encoder back
    /// to its exact entry state, so callers never observe a partial field and
    /// no unconstrained temporary message buffer is required.
    ///
    /// # Errors
    ///
    /// Returns a typed wire, schema, allocation, depth, field-count, message,
    /// or work error from the nested callback or shared encoder budget. Every
    /// error restores the encoder's exact entry state.
    #[allow(dead_code)]
    pub(crate) fn write_nested_message<F>(
        &mut self,
        field_number: u32,
        write_payload: F,
    ) -> Result<(), ProtobufWireError>
    where
        F: FnOnce(&mut Self) -> Result<(), ProtobufWireError>,
    {
        let start_len = self.output.len();
        make_key(field_number, WireType::LengthDelimited, start_len)?;
        let start_fields = self.fields_written;
        let start_work = self.work_used;
        let start_nested_messages = self.nested_messages.len();
        let start_groups = self.groups.len();
        let start_group_floor = self.group_floor;
        let depth = start_nested_messages
            .saturating_add(start_groups)
            .saturating_add(1);
        if depth > self.limits.max_depth {
            return Err(ProtobufWireError::RecursionLimitExceeded {
                offset: start_len,
                depth,
                limit: self.limits.max_depth,
            });
        }

        let open_message = OpenMessage {
            field_number,
            start: start_len,
        };
        self.ensure_output_with_wrapper(
            0,
            self.fields_written,
            self.work_used,
            Some(open_message),
        )?;
        self.nested_messages
            .try_reserve(1)
            .map_err(|_| ProtobufWireError::AllocationFailed {
                offset: start_len,
                resource: "encoder nested-message stack",
                additional: 1,
            })?;
        self.nested_messages.push(open_message);
        self.group_floor = start_groups;
        let payload_result = write_payload(self);
        self.group_floor = start_group_floor;
        if let Err(error) = payload_result {
            self.rollback_nested(
                start_len,
                start_fields,
                start_work,
                start_nested_messages,
                start_groups,
                start_group_floor,
            );
            return Err(error);
        }
        if self.groups.len() != start_groups {
            let expected = self.groups.last().copied().unwrap_or(0);
            self.rollback_nested(
                start_len,
                start_fields,
                start_work,
                start_nested_messages,
                start_groups,
                start_group_floor,
            );
            return Err(ProtobufWireError::EncoderGroupMismatch {
                offset: start_len,
                expected,
                actual: 0,
            });
        }
        let closed = self.nested_messages.pop();
        debug_assert_eq!(closed.map(|message| message.start), Some(start_len));

        let payload_len = self.output.len() - start_len;
        let field_limit = self.limits.effective_field_limit();
        if payload_len > field_limit {
            self.rollback_nested(
                start_len,
                start_fields,
                start_work,
                start_nested_messages,
                start_groups,
                start_group_floor,
            );
            return Err(ProtobufWireError::FieldLimitExceeded {
                offset: start_len,
                length: payload_len as u64,
                limit: field_limit,
            });
        }

        let key = match make_key(field_number, WireType::LengthDelimited, start_len) {
            Ok(key) => key,
            Err(error) => {
                self.rollback_nested(
                    start_len,
                    start_fields,
                    start_work,
                    start_nested_messages,
                    start_groups,
                    start_group_floor,
                );
                return Err(error);
            }
        };
        let (key_bytes, key_len) = encode_varint_to_array(u64::from(key));
        let (length_bytes, length_len) = encode_varint_to_array(payload_len as u64);
        let prefix_len = key_len + length_len;
        let Some(prospective_fields) = self.fields_written.checked_add(1) else {
            self.rollback_nested(
                start_len,
                start_fields,
                start_work,
                start_nested_messages,
                start_groups,
                start_group_floor,
            );
            return Err(ProtobufWireError::FieldCountExceeded {
                offset: start_len,
                count: usize::MAX,
                limit: self.limits.max_fields,
            });
        };
        let Some(prospective_work) = self
            .work_used
            .checked_add(prefix_len)
            .and_then(|work| work.checked_add(payload_len))
        else {
            self.rollback_nested(
                start_len,
                start_fields,
                start_work,
                start_nested_messages,
                start_groups,
                start_group_floor,
            );
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset: start_len,
                work: usize::MAX,
                limit: self.limits.max_work,
            });
        };
        if let Err(error) = self.ensure_output(prefix_len, prospective_fields, prospective_work) {
            self.rollback_nested(
                start_len,
                start_fields,
                start_work,
                start_nested_messages,
                start_groups,
                start_group_floor,
            );
            return Err(error);
        }

        let end = self.output.len();
        self.output.resize(end + prefix_len, 0);
        self.output
            .copy_within(start_len..end, start_len + prefix_len);
        self.output[start_len..start_len + key_len].copy_from_slice(&key_bytes[..key_len]);
        self.output[start_len + key_len..start_len + prefix_len]
            .copy_from_slice(&length_bytes[..length_len]);
        self.fields_written = prospective_fields;
        self.work_used = prospective_work;
        Ok(())
    }

    #[allow(dead_code)]
    fn rollback_nested(
        &mut self,
        output_len: usize,
        fields_written: usize,
        work_used: usize,
        nested_messages_len: usize,
        groups_len: usize,
        group_floor: usize,
    ) {
        self.output.truncate(output_len);
        self.fields_written = fields_written;
        self.work_used = work_used;
        self.nested_messages.truncate(nested_messages_len);
        self.groups.truncate(groups_len);
        self.group_floor = group_floor;
    }

    /// Emit packed varint payloads (including bool, enum, and ZigZag values).
    pub fn write_packed_varints(
        &mut self,
        field_number: u32,
        values: &[u64],
    ) -> Result<(), ProtobufWireError> {
        let payload_len = values.iter().try_fold(0usize, |length, &value| {
            length.checked_add(encoded_varint_len(value))
        });
        let Some(payload_len) = payload_len else {
            return Err(ProtobufWireError::FieldLimitExceeded {
                offset: self.output.len(),
                length: u64::MAX,
                limit: self.limits.effective_field_limit(),
            });
        };
        self.prepare_length_delimited(field_number, payload_len)?;
        for &value in values {
            let (bytes, length) = encode_varint_to_array(value);
            self.output.extend_from_slice(&bytes[..length]);
        }
        Ok(())
    }

    /// Emit packed fixed32 payloads.
    pub fn write_packed_fixed32(
        &mut self,
        field_number: u32,
        values: &[u32],
    ) -> Result<(), ProtobufWireError> {
        let Some(payload_len) = values.len().checked_mul(4) else {
            return Err(ProtobufWireError::FieldLimitExceeded {
                offset: self.output.len(),
                length: u64::MAX,
                limit: self.limits.effective_field_limit(),
            });
        };
        self.prepare_length_delimited(field_number, payload_len)?;
        for &value in values {
            self.output.extend_from_slice(&value.to_le_bytes());
        }
        Ok(())
    }

    /// Emit packed fixed64 payloads.
    pub fn write_packed_fixed64(
        &mut self,
        field_number: u32,
        values: &[u64],
    ) -> Result<(), ProtobufWireError> {
        let Some(payload_len) = values.len().checked_mul(8) else {
            return Err(ProtobufWireError::FieldLimitExceeded {
                offset: self.output.len(),
                length: u64::MAX,
                limit: self.limits.effective_field_limit(),
            });
        };
        self.prepare_length_delimited(field_number, payload_len)?;
        for &value in values {
            self.output.extend_from_slice(&value.to_le_bytes());
        }
        Ok(())
    }

    /// Emit packed IEEE-754 doubles without materializing their bit patterns.
    #[allow(dead_code)]
    pub(crate) fn write_packed_doubles(
        &mut self,
        field_number: u32,
        values: &[f64],
    ) -> Result<(), ProtobufWireError> {
        let Some(payload_len) = values.len().checked_mul(8) else {
            return Err(ProtobufWireError::FieldLimitExceeded {
                offset: self.output.len(),
                length: u64::MAX,
                limit: self.limits.effective_field_limit(),
            });
        };
        self.prepare_length_delimited(field_number, payload_len)?;
        for &value in values {
            self.output
                .extend_from_slice(&value.to_bits().to_le_bytes());
        }
        Ok(())
    }

    /// Start a deprecated group while enforcing aggregate depth.
    pub fn start_group(&mut self, field_number: u32) -> Result<(), ProtobufWireError> {
        let key = make_key(field_number, WireType::StartGroup, self.output.len())?;
        let depth = self
            .nested_messages
            .len()
            .saturating_add(self.groups.len())
            .saturating_add(1);
        if depth > self.limits.max_depth {
            return Err(ProtobufWireError::RecursionLimitExceeded {
                offset: self.output.len(),
                depth,
                limit: self.limits.max_depth,
            });
        }
        let key_len = encoded_varint_len(u64::from(key));
        let Some(prospective_fields) = self.fields_written.checked_add(1) else {
            return Err(ProtobufWireError::FieldCountExceeded {
                offset: self.output.len(),
                count: usize::MAX,
                limit: self.limits.max_fields,
            });
        };
        let Some(prospective_work) = self.work_used.checked_add(key_len) else {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset: self.output.len(),
                work: usize::MAX,
                limit: self.limits.max_work,
            });
        };
        self.ensure_output(key_len, prospective_fields, prospective_work)?;
        self.groups
            .try_reserve(1)
            .map_err(|_| ProtobufWireError::AllocationFailed {
                offset: self.output.len(),
                resource: "encoder group stack",
                additional: 1,
            })?;
        self.write_record(field_number, WireType::StartGroup, &[], None)?;
        self.groups.push(field_number);
        Ok(())
    }

    /// End a deprecated group, requiring the opening field number.
    pub fn end_group(&mut self, field_number: u32) -> Result<(), ProtobufWireError> {
        let expected = self.groups.last().copied().unwrap_or(0);
        if self.groups.len() <= self.group_floor || expected != field_number {
            return Err(ProtobufWireError::EncoderGroupMismatch {
                offset: self.output.len(),
                expected,
                actual: field_number,
            });
        }
        self.write_record(field_number, WireType::EndGroup, &[], None)?;
        self.groups.pop();
        Ok(())
    }

    /// Append one or more fully validated raw fields.
    ///
    /// This is the unknown-field preservation path. Complete groups are
    /// accepted; partial group fragments are rejected.
    pub fn write_raw_fields(&mut self, raw: &[u8]) -> Result<(), ProtobufWireError> {
        let Some(preflight_work) = self
            .work_used
            .checked_add(raw.len())
            .and_then(|work| work.checked_add(raw.len()))
        else {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset: self.output.len(),
                work: usize::MAX,
                limit: self.limits.max_work,
            });
        };
        self.check_output_with_wrapper(raw.len(), self.fields_written, preflight_work, None)?;
        let Some(projected_length) = self.output.len().checked_add(raw.len()) else {
            return Err(ProtobufWireError::MessageLimitExceeded {
                length: usize::MAX,
                limit: self.limits.effective_message_limit(),
            });
        };
        let (_, pending_nested_work) = self.project_nested_wrappers(projected_length)?;
        let Some(reserved_non_parser_work) = self
            .work_used
            .checked_add(raw.len())
            .and_then(|work| work.checked_add(pending_nested_work))
        else {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset: self.output.len(),
                work: usize::MAX,
                limit: self.limits.max_work,
            });
        };
        let pending_wrapper_fields = self.nested_messages.len();
        let validation_limits = ProtobufWireLimits {
            max_message_len: raw.len(),
            max_field_len: self.limits.max_field_len,
            max_fields: self
                .limits
                .max_fields
                .saturating_sub(self.fields_written)
                .saturating_sub(pending_wrapper_fields),
            max_depth: self
                .limits
                .max_depth
                .saturating_sub(self.nested_messages.len().saturating_add(self.groups.len())),
            max_work: self
                .limits
                .max_work
                .saturating_sub(reserved_non_parser_work),
        };
        let mut message = ProtobufWireMessage::new(raw, validation_limits)?;
        {
            let mut decoder = message.decoder();
            while decoder.next_field()?.is_some() {}
        }
        let fields = message.fields_seen();
        let Some(prospective_fields) = self.fields_written.checked_add(fields) else {
            return Err(ProtobufWireError::FieldCountExceeded {
                offset: self.output.len(),
                count: usize::MAX,
                limit: self.limits.max_fields,
            });
        };
        let Some(prospective_work) = self
            .work_used
            .checked_add(message.work_used())
            .and_then(|work| work.checked_add(raw.len()))
        else {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset: self.output.len(),
                work: usize::MAX,
                limit: self.limits.max_work,
            });
        };
        self.ensure_output(raw.len(), prospective_fields, prospective_work)?;
        self.output.extend_from_slice(raw);
        self.fields_written = prospective_fields;
        self.work_used = prospective_work;
        Ok(())
    }

    fn write_length_delimited(
        &mut self,
        field_number: u32,
        value: &[u8],
    ) -> Result<(), ProtobufWireError> {
        self.prepare_length_delimited(field_number, value.len())?;
        self.output.extend_from_slice(value);
        Ok(())
    }

    fn prepare_length_delimited(
        &mut self,
        field_number: u32,
        payload_len: usize,
    ) -> Result<(), ProtobufWireError> {
        let field_limit = self.limits.effective_field_limit();
        if payload_len > field_limit {
            return Err(ProtobufWireError::FieldLimitExceeded {
                offset: self.output.len(),
                length: payload_len as u64,
                limit: field_limit,
            });
        }
        let (length_bytes, length_len) = encode_varint_to_array(payload_len as u64);
        self.write_record(
            field_number,
            WireType::LengthDelimited,
            &length_bytes[..length_len],
            Some(payload_len),
        )
    }

    fn write_record(
        &mut self,
        field_number: u32,
        wire_type: WireType,
        immediate_payload: &[u8],
        deferred_payload_len: Option<usize>,
    ) -> Result<(), ProtobufWireError> {
        let key = make_key(field_number, wire_type, self.output.len())?;
        let (key_bytes, key_len) = encode_varint_to_array(u64::from(key));
        let deferred = deferred_payload_len.unwrap_or(0);
        let Some(additional) = key_len
            .checked_add(immediate_payload.len())
            .and_then(|length| length.checked_add(deferred))
        else {
            return Err(ProtobufWireError::MessageLimitExceeded {
                length: usize::MAX,
                limit: self.limits.effective_message_limit(),
            });
        };
        let Some(prospective_fields) = self.fields_written.checked_add(1) else {
            return Err(ProtobufWireError::FieldCountExceeded {
                offset: self.output.len(),
                count: usize::MAX,
                limit: self.limits.max_fields,
            });
        };
        let Some(prospective_work) = self.work_used.checked_add(additional) else {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset: self.output.len(),
                work: usize::MAX,
                limit: self.limits.max_work,
            });
        };
        self.ensure_output(additional, prospective_fields, prospective_work)?;
        self.output.extend_from_slice(&key_bytes[..key_len]);
        self.output.extend_from_slice(immediate_payload);
        self.fields_written = prospective_fields;
        self.work_used = prospective_work;
        Ok(())
    }

    fn ensure_output(
        &mut self,
        additional: usize,
        prospective_fields: usize,
        prospective_work: usize,
    ) -> Result<(), ProtobufWireError> {
        self.ensure_output_with_wrapper(additional, prospective_fields, prospective_work, None)
    }

    fn ensure_output_with_wrapper(
        &mut self,
        additional: usize,
        prospective_fields: usize,
        prospective_work: usize,
        additional_wrapper: Option<OpenMessage>,
    ) -> Result<(), ProtobufWireError> {
        self.check_output_with_wrapper(
            additional,
            prospective_fields,
            prospective_work,
            additional_wrapper,
        )?;
        self.output
            .try_reserve(additional)
            .map_err(|_| ProtobufWireError::AllocationFailed {
                offset: self.output.len(),
                resource: "wire output",
                additional,
            })?;
        Ok(())
    }

    fn check_output_with_wrapper(
        &self,
        additional: usize,
        prospective_fields: usize,
        prospective_work: usize,
        additional_wrapper: Option<OpenMessage>,
    ) -> Result<(), ProtobufWireError> {
        let limit = self.limits.effective_message_limit();
        let Some(length) = self.output.len().checked_add(additional) else {
            return Err(ProtobufWireError::MessageLimitExceeded {
                length: usize::MAX,
                limit,
            });
        };
        let (final_length, pending_nested_work) =
            self.project_nested_wrappers_with(length, additional_wrapper)?;
        if final_length > limit {
            return Err(ProtobufWireError::MessageLimitExceeded {
                length: final_length,
                limit,
            });
        }
        let Some(admitted_fields) = prospective_fields
            .checked_add(self.nested_messages.len())
            .and_then(|fields| fields.checked_add(usize::from(additional_wrapper.is_some())))
        else {
            return Err(ProtobufWireError::FieldCountExceeded {
                offset: self.output.len(),
                count: usize::MAX,
                limit: self.limits.max_fields,
            });
        };
        if admitted_fields > self.limits.max_fields {
            return Err(ProtobufWireError::FieldCountExceeded {
                offset: self.output.len(),
                count: admitted_fields,
                limit: self.limits.max_fields,
            });
        }
        let Some(admitted_work) = prospective_work.checked_add(pending_nested_work) else {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset: self.output.len(),
                work: usize::MAX,
                limit: self.limits.max_work,
            });
        };
        if admitted_work > self.limits.max_work {
            return Err(ProtobufWireError::WorkLimitExceeded {
                offset: self.output.len(),
                work: admitted_work,
                limit: self.limits.max_work,
            });
        }
        Ok(())
    }

    fn project_nested_wrappers(
        &self,
        initial_length: usize,
    ) -> Result<(usize, usize), ProtobufWireError> {
        self.project_nested_wrappers_with(initial_length, None)
    }

    fn project_nested_wrappers_with(
        &self,
        initial_length: usize,
        additional_wrapper: Option<OpenMessage>,
    ) -> Result<(usize, usize), ProtobufWireError> {
        let field_limit = self.limits.effective_field_limit();
        let mut final_length = initial_length;
        let mut pending_nested_work = 0usize;
        for open in additional_wrapper
            .iter()
            .chain(self.nested_messages.iter().rev())
        {
            let Some(payload_len) = final_length.checked_sub(open.start) else {
                return Err(ProtobufWireError::FieldLimitExceeded {
                    offset: open.start,
                    length: u64::MAX,
                    limit: field_limit,
                });
            };
            if payload_len > field_limit {
                return Err(ProtobufWireError::FieldLimitExceeded {
                    offset: open.start,
                    length: payload_len as u64,
                    limit: field_limit,
                });
            }
            let key = (open.field_number << 3) | WireType::LengthDelimited as u32;
            let prefix_len =
                encoded_varint_len(u64::from(key)) + encoded_varint_len(payload_len as u64);
            let Some(projected_work) = pending_nested_work
                .checked_add(payload_len)
                .and_then(|work| work.checked_add(prefix_len))
            else {
                return Err(ProtobufWireError::WorkLimitExceeded {
                    offset: open.start,
                    work: usize::MAX,
                    limit: self.limits.max_work,
                });
            };
            pending_nested_work = projected_work;
            let Some(projected_length) = final_length.checked_add(prefix_len) else {
                return Err(ProtobufWireError::MessageLimitExceeded {
                    length: usize::MAX,
                    limit: self.limits.effective_message_limit(),
                });
            };
            final_length = projected_length;
        }
        Ok((final_length, pending_nested_work))
    }
}

fn make_key(
    field_number: u32,
    wire_type: WireType,
    offset: usize,
) -> Result<u32, ProtobufWireError> {
    if field_number == 0 || field_number > MAX_PROTOBUF_FIELD_NUMBER {
        return Err(ProtobufWireError::InvalidFieldNumber {
            offset,
            field_number: u64::from(field_number),
        });
    }
    Ok((field_number << 3) | wire_type as u32)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;
    use prost::Message;

    use super::*;

    const EXACT_RCH_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_protobuf_wire_a1 cargo test -p asupersync --lib protobuf_wire -- --nocapture";

    #[derive(Clone, PartialEq, prost::Message)]
    struct ScalarModel {
        #[prost(double, tag = "1")]
        double_value: f64,
        #[prost(float, tag = "2")]
        float_value: f32,
        #[prost(int32, tag = "3")]
        int32_value: i32,
        #[prost(int64, tag = "4")]
        int64_value: i64,
        #[prost(uint32, tag = "5")]
        uint32_value: u32,
        #[prost(uint64, tag = "6")]
        uint64_value: u64,
        #[prost(sint32, tag = "7")]
        sint32_value: i32,
        #[prost(sint64, tag = "8")]
        sint64_value: i64,
        #[prost(fixed32, tag = "9")]
        fixed32_value: u32,
        #[prost(fixed64, tag = "10")]
        fixed64_value: u64,
        #[prost(sfixed32, tag = "11")]
        sfixed32_value: i32,
        #[prost(sfixed64, tag = "12")]
        sfixed64_value: i64,
        #[prost(bool, tag = "13")]
        bool_value: bool,
        #[prost(string, tag = "14")]
        string_value: String,
        #[prost(bytes = "vec", tag = "15")]
        bytes_value: Vec<u8>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct Child {
        #[prost(string, tag = "1")]
        name: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
    enum Color {
        Unspecified = 0,
        Green = 7,
    }

    #[derive(Clone, PartialEq, prost::Oneof)]
    enum Choice {
        #[prost(string, tag = "4")]
        Text(String),
        #[prost(uint64, tag = "5")]
        Number(u64),
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct CompositeModel {
        #[prost(sint64, repeated, packed = "true", tag = "1")]
        numbers: Vec<i64>,
        #[prost(message, repeated, tag = "2")]
        children: Vec<Child>,
        #[prost(btree_map = "string, uint32", tag = "3")]
        labels: BTreeMap<String, u32>,
        #[prost(oneof = "Choice", tags = "4, 5")]
        choice: Option<Choice>,
        #[prost(enumeration = "Color", tag = "6")]
        color: i32,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct PackedDoubleModel {
        #[prost(double, repeated, packed = "true", tag = "3")]
        values: Vec<f64>,
    }

    fn generous_limits(size: usize) -> ProtobufWireLimits {
        ProtobufWireLimits::for_message_size(size.max(1))
            .with_max_fields(1_024)
            .with_max_work(size.max(1).saturating_mul(16))
    }

    #[test]
    fn protobuf_wire_official_vectors_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(64);
        let input = [0x08, 0x96, 0x01];
        let mut message = ProtobufWireMessage::new(&input, limits).unwrap();
        let mut decoder = message.decoder();
        let field = decoder.next_field().unwrap().unwrap();
        assert_eq!(field.field_number(), 1);
        assert_eq!(field.as_varint().unwrap(), 150);
        assert!(decoder.next_field().unwrap().is_none());

        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_varint(1, 150).unwrap();
        assert_eq!(encoder.finish().unwrap().as_ref(), input);

        assert_eq!(zigzag_encode_i32(-500), 999);
        assert_eq!(zigzag_decode_i32(999), -500);
        assert_eq!(zigzag_decode_i64(zigzag_encode_i64(i64::MIN)), i64::MIN);
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=official-encoding-vectors fixture=protobuf.dev/encoding seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=exact-wire-match"
        );
    }

    #[test]
    fn protobuf_wire_exhaustive_small_varints_br_asupersync_5z2scg_1_1() {
        for value in 0u64..=u64::from(u16::MAX) {
            let mut encoder = ProtobufWireEncoder::with_max_size(16);
            encoder.write_varint(1, value).unwrap();
            let bytes = encoder.finish().unwrap();
            let (decoded, consumed) = decode_varint(&bytes[1..]).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded_varint_len(value));
        }
        assert_eq!(decode_varint(&[0x81, 0x00]).unwrap(), (1, 2));
        assert!(matches!(
            decode_varint(&[0xff; 10]),
            Err(ProtobufWireError::VarintOverflow { offset: 0 })
        ));
        let mut tenth_payload_overflow = [0xff; 10];
        tenth_payload_overflow[9] = 0x02;
        assert!(matches!(
            decode_varint(&tenth_payload_overflow),
            Err(ProtobufWireError::VarintOverflow { offset: 0 })
        ));
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=exhaustive-small-varints fixture=0..=u16::MAX seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=roundtrip-and-malformed-rejection"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn protobuf_wire_varint_property_br_asupersync_5z2scg_1_1(values in prop::collection::vec(any::<u64>(), 0..64)) {
            let limits = generous_limits(values.len().saturating_mul(12).saturating_add(1));
            let mut encoder = ProtobufWireEncoder::new(limits);
            for &value in &values {
                encoder.write_varint(1, value).unwrap();
            }
            let bytes = encoder.finish().unwrap();
            let mut message = ProtobufWireMessage::new(&bytes, limits).unwrap();
            let mut decoder = message.decoder();
            let mut decoded = Vec::new();
            while let Some(field) = decoder.next_field().unwrap() {
                decoded.push(field.as_varint().unwrap());
            }
            prop_assert_eq!(decoded, values);
        }

        #[test]
        fn protobuf_wire_arbitrary_input_terminates_br_asupersync_5z2scg_1_1(
            wire in prop::collection::vec(any::<u8>(), 0..256)
        ) {
            let limits = ProtobufWireLimits::for_message_size(256)
                .with_max_fields(256)
                .with_max_depth(32)
                .with_max_work(1_024);
            let mut message = ProtobufWireMessage::new(&wire, limits).unwrap();
            let mut decoder = message.decoder();
            let mut steps = 0usize;
            // `Ok(None)` (clean end) and `Err(_)` (bounded refusal) both mean
            // "stop"; the property under test is only that the loop terminates
            // in at most `wire.len()` steps, so both exits are equivalent here.
            while let Ok(Some(_)) = decoder.next_field() {
                steps += 1;
                prop_assert!(steps <= wire.len());
            }
        }
    }

    #[test]
    fn protobuf_wire_scalar_prost_cross_impl_br_asupersync_5z2scg_1_1() {
        let expected = ScalarModel {
            double_value: 1.25,
            float_value: -2.5,
            int32_value: -3,
            int64_value: -4,
            uint32_value: 5,
            uint64_value: u64::MAX,
            sint32_value: -6,
            sint64_value: i64::MIN,
            fixed32_value: 7,
            fixed64_value: 8,
            sfixed32_value: -9,
            sfixed64_value: -10,
            bool_value: true,
            string_value: "wire".to_owned(),
            bytes_value: vec![0, 1, 0xff],
        };
        let limits = generous_limits(512);
        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_double(1, expected.double_value).unwrap();
        encoder.write_float(2, expected.float_value).unwrap();
        encoder.write_int32(3, expected.int32_value).unwrap();
        encoder.write_int64(4, expected.int64_value).unwrap();
        encoder
            .write_varint(5, u64::from(expected.uint32_value))
            .unwrap();
        encoder.write_varint(6, expected.uint64_value).unwrap();
        encoder.write_sint32(7, expected.sint32_value).unwrap();
        encoder.write_sint64(8, expected.sint64_value).unwrap();
        encoder.write_fixed32(9, expected.fixed32_value).unwrap();
        encoder.write_fixed64(10, expected.fixed64_value).unwrap();
        encoder
            .write_fixed32(11, expected.sfixed32_value as u32)
            .unwrap();
        encoder
            .write_fixed64(12, expected.sfixed64_value as u64)
            .unwrap();
        encoder.write_bool(13, expected.bool_value).unwrap();
        encoder.write_string(14, &expected.string_value).unwrap();
        encoder.write_bytes(15, &expected.bytes_value).unwrap();
        let wire = encoder.finish().unwrap();

        assert_eq!(ScalarModel::decode(wire.as_ref()).unwrap(), expected);

        let prost_wire = expected.encode_to_vec();
        let mut message = ProtobufWireMessage::new(&prost_wire, limits).unwrap();
        let mut decoder = message.decoder();
        let mut fields = Vec::new();
        while let Some(field) = decoder.next_field().unwrap() {
            if field.field_number() == 14 {
                assert_eq!(field.as_str().unwrap(), "wire");
            }
            fields.push((field.field_number(), field.wire_type()));
        }
        assert_eq!(fields.len(), 15);
        assert_eq!(fields[0], (1, WireType::Fixed64));
        assert_eq!(fields[14], (15, WireType::LengthDelimited));
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=scalar-cross-implementation fixture=workspace-prost seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=bidirectional-wire-compatibility"
        );
    }

    #[test]
    fn protobuf_wire_composite_model_cross_impl_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(1_024);
        let numbers = [-2, 0, 9, i64::MAX];
        let mut encoder = ProtobufWireEncoder::new(limits);
        let packed = numbers.map(zigzag_encode_i64);
        encoder.write_packed_varints(1, &packed).unwrap();

        for name in ["alpha", "beta"] {
            let mut child = ProtobufWireEncoder::new(limits);
            child.write_string(1, name).unwrap();
            encoder.write_message(2, &child.finish().unwrap()).unwrap();
        }

        for (key, value) in [("a", 1), ("z", 26)] {
            let mut entry = ProtobufWireEncoder::new(limits);
            entry.write_string(1, key).unwrap();
            entry.write_varint(2, value).unwrap();
            encoder.write_message(3, &entry.finish().unwrap()).unwrap();
        }
        encoder.write_string(4, "selected").unwrap();
        encoder.write_enum(6, Color::Green as i32).unwrap();
        let wire = encoder.finish().unwrap();

        let decoded = CompositeModel::decode(wire.as_ref()).unwrap();
        assert_eq!(decoded.numbers, numbers);
        assert_eq!(
            decoded.children,
            vec![
                Child {
                    name: "alpha".to_owned()
                },
                Child {
                    name: "beta".to_owned()
                }
            ]
        );
        assert_eq!(decoded.labels["a"], 1);
        assert_eq!(decoded.labels["z"], 26);
        assert_eq!(decoded.choice, Some(Choice::Text("selected".to_owned())));
        assert_eq!(decoded.color, Color::Green as i32);

        let prost_wire = decoded.encode_to_vec();
        let mut message = ProtobufWireMessage::new(&prost_wire, limits).unwrap();
        let mut decoder = message.decoder();
        let mut child_count = 0;
        while let Some(field) = decoder.next_field().unwrap() {
            if field.field_number() == 2 {
                let mut child_decoder = decoder.nested_message(&field).unwrap();
                let child_name = child_decoder.next_field().unwrap().unwrap();
                assert!(!child_name.as_str().unwrap().is_empty());
                assert!(child_decoder.next_field().unwrap().is_none());
                child_count += 1;
            }
        }
        assert_eq!(child_count, 2);
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=packed-repeated-map-oneof-enum-nested fixture=workspace-prost seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=full-accepted-data-model"
        );
    }

    #[test]
    fn packed_doubles_match_prost_bytes_without_projection_storage() {
        let values = [1.25, -0.0, f64::from_bits(0x7ff8_0000_0000_0042)];
        let mut encoder = ProtobufWireEncoder::new(generous_limits(64));
        encoder.write_packed_doubles(3, &values).unwrap();
        let wire = encoder.finish().unwrap();

        let expected = [
            0x1a, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x3f, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x80, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x7f,
        ];
        assert_eq!(wire.as_ref(), expected);
        assert_eq!(
            wire.as_ref(),
            PackedDoubleModel {
                values: values.to_vec(),
            }
            .encode_to_vec()
        );
    }

    #[test]
    fn packed_doubles_preserve_explicit_empty_record_behavior() {
        let mut encoder = ProtobufWireEncoder::new(generous_limits(16));
        encoder.write_packed_doubles(3, &[]).unwrap();

        assert_eq!(encoder.as_bytes(), [0x1a, 0x00]);
        assert_eq!(encoder.fields_written(), 1);
        assert_eq!(encoder.work_used(), 2);
    }

    #[test]
    fn packed_doubles_reject_limits_without_changing_encoder_state() {
        let limits = generous_limits(64).with_max_field_len(7);
        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_varint(9, 1).unwrap();
        let original = encoder.as_bytes().to_vec();
        let original_fields = encoder.fields_written();
        let original_work = encoder.work_used();

        assert!(matches!(
            encoder.write_packed_doubles(3, &[1.0]),
            Err(ProtobufWireError::FieldLimitExceeded {
                length: 8,
                limit: 7,
                ..
            })
        ));
        assert_eq!(encoder.as_bytes(), original);
        assert_eq!(encoder.fields_written(), original_fields);
        assert_eq!(encoder.work_used(), original_work);
    }

    #[test]
    fn protobuf_wire_unknown_and_group_preservation_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(128);
        let raw = [0x2b, 0x08, 0x96, 0x01, 0x33, 0x0d, 1, 2, 3, 4, 0x34, 0x2c];
        let mut message = ProtobufWireMessage::new(&raw, limits).unwrap();
        let mut decoder = message.decoder();
        let start = decoder.next_field().unwrap().unwrap();
        assert_eq!(start.wire_type(), WireType::StartGroup);
        let preserved = decoder.skip_group(&start).unwrap();
        assert_eq!(preserved, raw);
        assert!(decoder.next_field().unwrap().is_none());

        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_raw_fields(preserved).unwrap();
        assert_eq!(encoder.finish().unwrap().as_ref(), raw);

        let mismatched = [0x2b, 0x34];
        let mut message = ProtobufWireMessage::new(&mismatched, limits).unwrap();
        let mut decoder = message.decoder();
        decoder.next_field().unwrap().unwrap();
        assert!(matches!(
            decoder.next_field(),
            Err(ProtobufWireError::MismatchedEndGroup {
                expected: 5,
                actual: 6,
                ..
            })
        ));
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=unknown-group-preservation fixture=hand-encoded-nested-group seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=exact-preservation-and-mismatch-rejection"
        );
    }

    #[test]
    fn protobuf_wire_resource_limits_fail_closed_br_asupersync_5z2scg_1_1() {
        let message_error =
            ProtobufWireMessage::new(&[0; 5], ProtobufWireLimits::for_message_size(4)).unwrap_err();
        assert!(matches!(
            message_error,
            ProtobufWireError::MessageLimitExceeded {
                length: 5,
                limit: 4
            }
        ));

        let field_limits = ProtobufWireLimits::for_message_size(16).with_max_field_len(2);
        let mut message = ProtobufWireMessage::new(&[0x0a, 0x03, 1, 2, 3], field_limits).unwrap();
        assert!(matches!(
            message.decoder().next_field(),
            Err(ProtobufWireError::FieldLimitExceeded {
                length: 3,
                limit: 2,
                ..
            })
        ));

        let count_limits = generous_limits(16).with_max_fields(1);
        let mut message =
            ProtobufWireMessage::new(&[0x08, 0x01, 0x10, 0x02], count_limits).unwrap();
        let mut decoder = message.decoder();
        decoder.next_field().unwrap();
        assert!(matches!(
            decoder.next_field(),
            Err(ProtobufWireError::FieldCountExceeded {
                count: 2,
                limit: 1,
                ..
            })
        ));

        let work_limits = generous_limits(16).with_max_work(1);
        let mut message = ProtobufWireMessage::new(&[0x08, 0x01], work_limits).unwrap();
        assert!(matches!(
            message.decoder().next_field(),
            Err(ProtobufWireError::WorkLimitExceeded {
                work: 2,
                limit: 1,
                ..
            })
        ));

        let depth_limits = generous_limits(16).with_max_depth(1);
        let nested_wire = [0x0a, 0x02, 0x0a, 0x00];
        let mut message = ProtobufWireMessage::new(&nested_wire, depth_limits).unwrap();
        let mut root = message.decoder();
        let outer = root.next_field().unwrap().unwrap();
        let mut level_one = root.nested_message(&outer).unwrap();
        let inner = level_one.next_field().unwrap().unwrap();
        assert!(matches!(
            level_one.nested_message(&inner),
            Err(ProtobufWireError::RecursionLimitExceeded {
                depth: 2,
                limit: 1,
                ..
            })
        ));

        let group_wire = [0x0b, 0x13, 0x14, 0x0c];
        let mut message = ProtobufWireMessage::new(&group_wire, depth_limits).unwrap();
        let mut decoder = message.decoder();
        decoder.next_field().unwrap().unwrap();
        assert!(matches!(
            decoder.next_field(),
            Err(ProtobufWireError::RecursionLimitExceeded {
                depth: 2,
                limit: 1,
                ..
            })
        ));

        let mut encoder =
            ProtobufWireEncoder::new(generous_limits(16).with_max_fields(1).with_max_work(1));
        assert!(matches!(
            encoder.write_varint(1, 1),
            Err(ProtobufWireError::WorkLimitExceeded {
                work: 2,
                limit: 1,
                ..
            })
        ));
        assert!(encoder.is_empty());
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=resource-limit-matrix fixture=message-field-count-work-depth-boundaries seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=reject-before-allocation"
        );
    }

    #[test]
    fn protobuf_wire_malformed_matrix_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(64);
        let cases: &[(&[u8], fn(&ProtobufWireError) -> bool)] = &[
            (&[0x00], |error| {
                matches!(
                    error,
                    ProtobufWireError::InvalidFieldNumber {
                        field_number: 0,
                        ..
                    }
                )
            }),
            (&[0x0f], |error| {
                matches!(
                    error,
                    ProtobufWireError::InvalidWireType { wire_type: 7, .. }
                )
            }),
            (&[0x0d, 1, 2], |error| {
                matches!(error, ProtobufWireError::UnexpectedEof { needed: 4, .. })
            }),
            (&[0x0a, 0x02, 1], |error| {
                matches!(
                    error,
                    ProtobufWireError::UnexpectedEof {
                        needed: 2,
                        remaining: 1,
                        ..
                    }
                )
            }),
            (&[0x0b], |error| {
                matches!(
                    error,
                    ProtobufWireError::UnterminatedGroup {
                        field_number: 1,
                        ..
                    }
                )
            }),
        ];
        for (wire, predicate) in cases {
            let mut message = ProtobufWireMessage::new(wire, limits).unwrap();
            let mut decoder = message.decoder();
            let error = loop {
                match decoder.next_field() {
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("malformed case was accepted"),
                    Err(error) => break error,
                }
            };
            assert!(predicate(&error), "unexpected error: {error:?}");
        }

        let invalid_utf8 = [0x0a, 0x01, 0xff];
        let mut message = ProtobufWireMessage::new(&invalid_utf8, limits).unwrap();
        let field = message.decoder().next_field().unwrap().unwrap();
        assert!(matches!(
            field.as_str(),
            Err(ProtobufWireError::InvalidUtf8 { offset: 2 })
        ));
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=malformed-wire-matrix fixture=zero-key-reserved-wire-truncation-group-utf8 seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=stable-typed-errors-no-panic"
        );
    }

    #[test]
    fn protobuf_wire_deterministic_ordered_operations_br_asupersync_5z2scg_1_1() {
        fn encode() -> Bytes {
            let limits = generous_limits(128);
            let mut encoder = ProtobufWireEncoder::new(limits);
            encoder.write_varint(9, 1).unwrap();
            encoder.write_varint(2, 3).unwrap();
            encoder.write_varint(2, 5).unwrap();
            encoder.write_string(7, "same").unwrap();
            encoder.finish().unwrap()
        }
        assert_eq!(encode(), encode());
        assert_eq!(encode(), encode());
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=deterministic-ordered-operation-stream fixture=noncanonical-field-order seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=byte-identical-not-canonical"
        );
    }

    #[test]
    fn protobuf_wire_field_key_boundaries_br_asupersync_5z2scg_1_1() {
        let limits = generous_limits(64);
        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_varint(MAX_PROTOBUF_FIELD_NUMBER, 1).unwrap();
        let wire = encoder.finish().unwrap();
        let mut message = ProtobufWireMessage::new(&wire, limits).unwrap();
        let field = message.decoder().next_field().unwrap().unwrap();
        assert_eq!(field.field_number(), MAX_PROTOBUF_FIELD_NUMBER);

        let mut encoder = ProtobufWireEncoder::new(limits);
        assert!(matches!(
            encoder.write_varint(0, 1),
            Err(ProtobufWireError::InvalidFieldNumber {
                field_number: 0,
                ..
            })
        ));
        assert!(matches!(
            encoder.write_varint(MAX_PROTOBUF_FIELD_NUMBER + 1, 1),
            Err(ProtobufWireError::InvalidFieldNumber { .. })
        ));
        assert!(encoder.is_empty());
        eprintln!(
            "bead=asupersync-5z2scg.1.1 scenario=field-key-boundaries fixture=zero-and-29-bit-maximum seed=none command=\"{EXACT_RCH_COMMAND}\" artifact=none expected=max-accepted-neighbors-rejected"
        );
    }

    #[test]
    fn nested_encoder_rolls_back_groups_and_rejects_cross_boundary_close() {
        let limits = generous_limits(128);
        let mut encoder = ProtobufWireEncoder::new(limits);
        encoder.write_varint(9, 1).unwrap();
        let original = encoder.as_bytes().to_vec();
        let original_fields = encoder.fields_written();
        let original_work = encoder.work_used();

        let error = encoder
            .write_nested_message(1, |nested| {
                nested.start_group(2)?;
                Err(ProtobufWireError::SchemaInvariant {
                    offset: nested.len(),
                    invariant: "nested rollback fixture",
                })
            })
            .unwrap_err();
        assert!(matches!(error, ProtobufWireError::SchemaInvariant { .. }));
        assert_eq!(encoder.as_bytes(), original);
        assert_eq!(encoder.fields_written(), original_fields);
        assert_eq!(encoder.work_used(), original_work);

        let mut unclosed = ProtobufWireEncoder::new(limits);
        assert!(matches!(
            unclosed.write_nested_message(1, |nested| nested.start_group(2)),
            Err(ProtobufWireError::EncoderGroupMismatch { .. })
        ));
        assert!(unclosed.is_empty());

        let mut outer = ProtobufWireEncoder::new(limits);
        outer.start_group(2).unwrap();
        let outer_prefix = outer.as_bytes().to_vec();
        assert!(matches!(
            outer.write_nested_message(1, |nested| nested.end_group(2)),
            Err(ProtobufWireError::EncoderGroupMismatch { .. })
        ));
        assert_eq!(outer.as_bytes(), outer_prefix);
        outer.end_group(2).unwrap();
        assert_eq!(outer.finish().unwrap().as_ref(), [0x13, 0x14].as_slice());
    }

    #[test]
    fn nested_encoder_combines_message_group_depth_and_charges_prefix_shift_work() {
        let depth_one = generous_limits(128).with_max_depth(1);
        let mut nested_then_group = ProtobufWireEncoder::new(depth_one);
        assert!(matches!(
            nested_then_group.write_nested_message(1, |nested| nested.start_group(2)),
            Err(ProtobufWireError::RecursionLimitExceeded { depth: 2, .. })
        ));
        assert!(nested_then_group.is_empty());

        let mut group_then_nested = ProtobufWireEncoder::new(depth_one);
        group_then_nested.start_group(1).unwrap();
        assert!(matches!(
            group_then_nested.write_nested_message(2, |_| Ok(())),
            Err(ProtobufWireError::RecursionLimitExceeded { depth: 2, .. })
        ));
        assert!(matches!(
            group_then_nested.write_raw_fields(&[0x1b, 0x1c]),
            Err(ProtobufWireError::RecursionLimitExceeded { .. })
        ));
        group_then_nested.end_group(1).unwrap();

        let work_limited = generous_limits(128).with_max_work(50);
        let mut encoder = ProtobufWireEncoder::new(work_limited);
        encoder
            .write_nested_message(1, |nested| nested.write_bytes(1, &[7; 20]))
            .unwrap();
        assert_eq!(encoder.len(), 24);
        assert_eq!(encoder.work_used(), 46);
        let snapshot = encoder.as_bytes().to_vec();
        assert!(matches!(
            encoder.write_bytes(2, &[8; 4]),
            Err(ProtobufWireError::WorkLimitExceeded { work: 52, .. })
        ));
        assert_eq!(encoder.as_bytes(), snapshot);
        assert_eq!(encoder.work_used(), 46);
    }

    #[test]
    fn preflight_and_counter_overflow_remain_fail_closed_at_maximum_limits() {
        let maximum = ProtobufWireLimits {
            max_message_len: 128,
            max_field_len: 128,
            max_fields: usize::MAX,
            max_depth: usize::MAX,
            max_work: usize::MAX,
        };

        let mut field_overflow = ProtobufWireEncoder::new(maximum);
        field_overflow.fields_written = usize::MAX;
        assert!(matches!(
            field_overflow.write_varint(1, 1),
            Err(ProtobufWireError::FieldCountExceeded {
                count: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));
        assert!(field_overflow.is_empty());

        let mut work_overflow = ProtobufWireEncoder::new(maximum);
        work_overflow.work_used = usize::MAX;
        assert!(matches!(
            work_overflow.write_varint(1, 1),
            Err(ProtobufWireError::WorkLimitExceeded {
                work: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));
        assert!(work_overflow.is_empty());

        let mut field_message = ProtobufWireMessage::new(&[0x08, 0x01], maximum).unwrap();
        field_message.state.fields_seen = usize::MAX;
        assert!(matches!(
            field_message.decoder().next_field(),
            Err(ProtobufWireError::FieldCountExceeded {
                count: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));

        let mut work_message = ProtobufWireMessage::new(&[0x08, 0x01], maximum).unwrap();
        work_message.state.work_used = usize::MAX;
        assert!(matches!(
            work_message.decoder().next_field(),
            Err(ProtobufWireError::WorkLimitExceeded {
                work: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));

        let mut semantic_message = ProtobufWireMessage::new(&[], maximum).unwrap();
        semantic_message.state.semantic_owned_bytes = usize::MAX;
        assert!(matches!(
            semantic_message
                .decoder()
                .charge_semantic_owned_bytes(1, usize::MAX, 0),
            Err(ProtobufWireError::SchemaLimitExceeded {
                observed: usize::MAX,
                limit: usize::MAX,
                ..
            })
        ));

        let no_fields = maximum.with_max_fields(0);
        let mut nested = ProtobufWireEncoder::new(no_fields);
        assert!(matches!(
            nested.write_nested_message(1, |_| Ok(())),
            Err(ProtobufWireError::FieldCountExceeded {
                count: 1,
                limit: 0,
                ..
            })
        ));
        assert_eq!(nested.nested_messages.capacity(), 0);

        let mut group = ProtobufWireEncoder::new(no_fields);
        assert!(matches!(
            group.start_group(1),
            Err(ProtobufWireError::FieldCountExceeded {
                count: 1,
                limit: 0,
                ..
            })
        ));
        assert_eq!(group.groups.capacity(), 0);
    }
}
