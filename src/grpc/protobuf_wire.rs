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
    ///
    /// The default depth is 100. Work includes four message-sized passes plus
    /// one per admitted nesting level, because a nested payload is charged at
    /// each level on descent or when inserting its encoded wrapper. This lets
    /// an ordinary traversal use the advertised byte and depth limits without
    /// exhausting an unrelated, fixed four-pass allowance.
    ///
    /// Repeated traversals and schema-specific work still consume the shared
    /// finite budget. Use [`Self::with_max_work`] to impose a tighter work cap.
    #[must_use]
    pub const fn for_message_size(max_message_len: usize) -> Self {
        Self::for_message_size_and_depth(max_message_len, 100)
    }

    /// Construct byte, depth, and cumulative-work limits together.
    ///
    /// Work is `max_message_len * (max_depth + 4)`, with saturating arithmetic.
    /// A shallow schema can use this constructor to reserve less work than the
    /// default depth of 100. Field count remains capped at 65,536.
    #[must_use]
    pub const fn for_message_size_and_depth(max_message_len: usize, max_depth: usize) -> Self {
        Self {
            max_message_len,
            max_field_len: max_message_len,
            max_fields: 65_536,
            max_depth,
            max_work: max_message_len.saturating_mul(max_depth.saturating_add(4)),
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
    ///
    /// This changes only depth, preserving any work policy already selected.
    /// Use [`Self::for_message_size_and_depth`] to size both limits together.
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

#[derive(Debug)]
struct DecodeState {
    limits: ProtobufWireLimits,
    fields_seen: usize,
    work_used: usize,
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
    semantic_repeated_items: usize,
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
    semantic_any_value_nodes: usize,
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
    semantic_any_value_depth: usize,
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
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

    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
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
                #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
                semantic_repeated_items: 0,
                #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
                semantic_any_value_nodes: 0,
                #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
                semantic_any_value_depth: 0,
                #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
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
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
    pub(crate) fn remaining_work(&self) -> usize {
        self.state
            .limits
            .max_work
            .saturating_sub(self.state.work_used)
    }

    /// Seed semantic counters from an already validated merge target before
    /// admitting any new field allocation.
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
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
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
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
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
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
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
    pub(crate) fn leave_semantic_any_value(&mut self) {
        debug_assert!(self.state.semantic_any_value_depth > 0);
        self.state.semantic_any_value_depth = self.state.semantic_any_value_depth.saturating_sub(1);
    }

    /// Charge schema-owned string, bytes, or unknown-field storage before
    /// allocating or copying it.
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
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
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
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
    /// than byte strings. Schema implementations should use
    /// [`Self::write_nested_message`] to encode children with aggregate field,
    /// depth, work, and allocation accounting.
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
    /// If the callback unwinds, the same rollback happens before the original
    /// panic resumes; a caller that catches it can reuse the encoder.
    ///
    /// # Errors
    ///
    /// Returns a typed wire, schema, allocation, depth, field-count, message,
    /// or work error from the nested callback or shared encoder budget. Every
    /// error restores the encoder's exact entry state.
    pub fn write_nested_message<F>(
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
        let payload_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| write_payload(self)));
        self.group_floor = start_group_floor;
        let payload_result = match payload_result {
            Ok(result) => result,
            Err(payload) => {
                self.rollback_nested(
                    start_len,
                    start_fields,
                    start_work,
                    start_nested_messages,
                    start_groups,
                    start_group_floor,
                );
                std::panic::resume_unwind(payload);
            }
        };
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

    /// Emit packed varints from a lazy projection without allocating a
    /// temporary collection.
    ///
    /// A cloned iterator sizes the payload, checking shared message, field,
    /// and work budgets after every value. This pass stops at the first
    /// refusal, including for an unbounded iterator, before reserving output.
    /// The original iterator then writes directly into the admitted buffer.
    /// Wire bytes and resource accounting match [`Self::write_packed_varints`];
    /// packed scalars do not consume nested-message depth.
    ///
    /// Cloning must replay the same values. If the emitted payload length
    /// differs from the sizing pass, the operation returns
    /// [`ProtobufWireError::SchemaInvariant`].
    ///
    /// Prefer cheaply cloned borrowed projections such as
    /// `values.iter().copied()` or `values.iter().map(...)`. Work and allocation
    /// performed by an iterator's own `Clone` or `next` implementation are
    /// outside the encoder's accounting.
    ///
    /// Errors restore the output and accounting to their entry state. An
    /// iterator panic also restores the encoder before resuming the panic;
    /// effects performed by the iterator itself cannot be rolled back.
    pub fn write_packed_varints_iter<I>(
        &mut self,
        field_number: u32,
        values: I,
    ) -> Result<(), ProtobufWireError>
    where
        I: IntoIterator<Item = u64>,
        I::IntoIter: Clone,
    {
        self.write_packed_iter(field_number, values.into_iter(), encode_varint_to_array)
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

    /// Emit packed fixed32 values without materializing a projected slice.
    ///
    /// Shares the bounded, transactional iterator behavior of
    /// [`Self::write_packed_varints_iter`].
    pub fn write_packed_fixed32_iter<I>(
        &mut self,
        field_number: u32,
        values: I,
    ) -> Result<(), ProtobufWireError>
    where
        I: IntoIterator<Item = u32>,
        I::IntoIter: Clone,
    {
        self.write_packed_iter(field_number, values.into_iter(), |value| {
            (value.to_le_bytes(), 4)
        })
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

    /// Emit packed fixed64 values without materializing a projected slice.
    ///
    /// Shares the bounded, transactional iterator behavior of
    /// [`Self::write_packed_varints_iter`].
    pub fn write_packed_fixed64_iter<I>(
        &mut self,
        field_number: u32,
        values: I,
    ) -> Result<(), ProtobufWireError>
    where
        I: IntoIterator<Item = u64>,
        I::IntoIter: Clone,
    {
        self.write_packed_iter(field_number, values.into_iter(), |value| {
            (value.to_le_bytes(), 8)
        })
    }

    fn write_packed_iter<I, F, const N: usize>(
        &mut self,
        field_number: u32,
        values: I,
        pack: F,
    ) -> Result<(), ProtobufWireError>
    where
        I: Iterator + Clone,
        F: Fn(I::Item) -> ([u8; N], usize),
    {
        let key = make_key(field_number, WireType::LengthDelimited, self.output.len())?;
        let key_len = encoded_varint_len(u64::from(key));
        self.check_packed_payload(key_len, 0)?;
        let mut payload_len = 0usize;
        for value in values.clone() {
            let (_, length) = pack(value);
            payload_len = payload_len.checked_add(length).ok_or(
                ProtobufWireError::FieldLimitExceeded {
                    offset: self.output.len(),
                    length: u64::MAX,
                    limit: self.limits.effective_field_limit(),
                },
            )?;
            self.check_packed_payload(key_len, payload_len)?;
        }

        let start_len = self.output.len();
        let start_fields = self.fields_written;
        let start_work = self.work_used;
        self.prepare_length_delimited(field_number, payload_len)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut remaining = payload_len;
            for value in values {
                let (bytes, length) = pack(value);
                remaining = remaining.checked_sub(length).ok_or(
                    ProtobufWireError::SchemaInvariant {
                        offset: self.output.len(),
                        invariant: "packed iterator changed its encoded length between passes",
                    },
                )?;
                self.output.extend_from_slice(&bytes[..length]);
            }
            if remaining != 0 {
                return Err(ProtobufWireError::SchemaInvariant {
                    offset: self.output.len(),
                    invariant: "packed iterator changed its encoded length between passes",
                });
            }
            Ok(())
        }));
        if !matches!(&result, Ok(Ok(()))) {
            self.output.truncate(start_len);
            self.fields_written = start_fields;
            self.work_used = start_work;
        }
        match result {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn check_packed_payload(
        &self,
        key_len: usize,
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
        let Some(additional) = key_len
            .checked_add(encoded_varint_len(payload_len as u64))
            .and_then(|length| length.checked_add(payload_len))
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
        self.check_output_with_wrapper(additional, prospective_fields, prospective_work, None)
    }

    /// Emit packed IEEE-754 doubles without materializing their bit patterns.
    #[cfg(any(test, all(feature = "metrics", not(target_arch = "wasm32"))))]
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
#[path = "protobuf_wire_inline_tests.rs"]
mod tests;
