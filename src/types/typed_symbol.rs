//! Typed symbol wrappers for encoding and decoding Rust types.
//!
//! Typed symbols attach a fixed header to each symbol payload so receivers can
//! validate type identity, schema version, and serialization format before
//! decoding. The encoder/decoder integrate with the existing RaptorQ
//! pipelines by reserving header space per symbol.

use crate::config::EncodingConfig;
use crate::decoding::{DecodingConfig, DecodingError, DecodingPipeline};
use crate::encoding::{EncodingError, EncodingPipeline};
use crate::security::AuthenticatedSymbol;
use crate::transport::{SymbolSink, SymbolSinkExt, SymbolStream, SymbolStreamExt};
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol_set::SymbolSet;
use crate::types::{ObjectId, ObjectParams, Symbol, SymbolKind};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::any::TypeId;
use std::collections::HashMap;
use std::marker::PhantomData;

/// Magic prefix for typed symbols.
pub const TYPED_SYMBOL_MAGIC: [u8; 4] = *b"TSYM";
/// Header length in bytes.
pub const TYPED_SYMBOL_HEADER_LEN: usize = 27;
/// Current typed-symbol schema version.
pub const TYPED_SYMBOL_VERSION: u16 = 1;

/// Supported serialization formats for typed symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    /// MessagePack (compact binary).
    MessagePack,
    /// Bincode (Rust-native binary).
    Bincode,
    /// JSON (human-readable, larger).
    Json,
    /// Custom format (user-defined serializer).
    Custom,
}

impl SerializationFormat {
    fn to_byte(self) -> u8 {
        match self {
            Self::MessagePack => 1,
            Self::Bincode => 2,
            Self::Json => 3,
            Self::Custom => 255,
        }
    }

    fn from_byte(value: u8) -> Result<Self, TypeMismatchError> {
        match value {
            1 => Ok(Self::MessagePack),
            2 => Ok(Self::Bincode),
            3 => Ok(Self::Json),
            255 => Ok(Self::Custom),
            _ => Err(TypeMismatchError::UnsupportedFormatByte { value }),
        }
    }
}

/// Error returned when serialization fails.
#[derive(Debug, thiserror::Error)]
pub enum SerializationError {
    /// Serialization failed.
    #[error("serialization failed: {reason}")]
    SerializationFailed {
        /// Failure reason.
        reason: String,
    },
    /// Value too large for a single symbol.
    #[error("value too large: {size} bytes exceeds {max} limit")]
    ValueTooLarge {
        /// Size in bytes.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },
    /// Memory for the bounded symbol envelope could not be reserved.
    #[error("allocation failed while reserving {requested} bytes")]
    AllocationFailed {
        /// Requested envelope size.
        requested: usize,
    },
    /// Unsupported type or format.
    #[error("unsupported type: {type_name}")]
    UnsupportedType {
        /// Type name.
        type_name: String,
    },
}

/// Error returned when deserialization fails.
#[derive(Debug, thiserror::Error)]
pub enum DeserializationError {
    /// Deserialization failed.
    #[error("deserialization failed: {reason}")]
    DeserializationFailed {
        /// Failure reason.
        reason: String,
    },
    /// Type mismatch.
    #[error("type mismatch: expected {expected}, got {actual}")]
    TypeMismatch {
        /// Expected type.
        expected: String,
        /// Actual type.
        actual: String,
    },
    /// Schema version mismatch.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema version.
        expected: u32,
        /// Actual schema version.
        actual: u32,
    },
    /// Corrupt symbol data.
    #[error("corrupt symbol data")]
    CorruptData,
}

/// Error returned when a symbol header does not match the expected type.
#[derive(Debug, thiserror::Error)]
pub enum TypeMismatchError {
    /// Invalid magic number.
    #[error("invalid magic number")]
    InvalidMagic,
    /// Unknown or unexpected type ID.
    #[error("unknown type id: {type_id}")]
    UnknownType {
        /// Type identifier.
        type_id: u64,
    },
    /// Unsupported format.
    #[error("unsupported serialization format byte: {value}")]
    UnsupportedFormatByte {
        /// Raw format byte from the symbol header.
        value: u8,
    },
    /// Schema version differs from the version selected by the reader.
    #[error("typed symbol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// Version selected by the reader.
        expected: u16,
        /// Version encoded in the symbol.
        actual: u16,
    },
    /// Schema hash mismatch.
    #[error("schema hash mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema hash.
        expected: u64,
        /// Actual schema hash.
        actual: u64,
    },
}

/// Trusted identity tuple for a typed-symbol header emitted by a legacy writer.
///
/// Typed-symbol writers before the stable SHA-256 header identity used
/// build-sensitive Rust `TypeId` hashing. A current reader therefore cannot
/// safely infer the expected legacy type and schema hashes. Callers may use
/// this tuple only when the values come from a version-provenanced artifact
/// manifest or another trusted schema registry.
///
/// This does not make legacy admission automatic: [`TypedSymbol::try_from_legacy_symbol`]
/// requires an exact match for all three fields before exposing the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyTypedSymbolIdentity {
    /// Schema version encoded by the legacy writer.
    pub version: u16,
    /// Legacy writer's exact type identifier.
    pub type_id: u64,
    /// Legacy writer's exact schema hash.
    pub schema_hash: u64,
}

impl LegacyTypedSymbolIdentity {
    /// Creates an identity pinned by trusted historical provenance.
    #[must_use]
    pub const fn new(version: u16, type_id: u64, schema_hash: u64) -> Self {
        Self {
            version,
            type_id,
            schema_hash,
        }
    }
}

/// Type descriptor registered for typed symbols.
#[derive(Debug, Clone, Copy)]
pub struct TypeDescriptor {
    /// Rust type ID.
    pub type_id: TypeId,
    /// Type name.
    pub name: &'static str,
    /// Schema version.
    pub version: u32,
    /// Schema hash.
    pub schema_hash: u64,
}

/// Registry for known types.
#[derive(Debug, Default)]
pub struct TypeRegistry {
    types: HashMap<TypeId, TypeDescriptor>,
}

const DEFAULT_TYPE_REGISTRY_CAPACITY: usize = 16;

impl TypeRegistry {
    /// Creates a new registry.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_TYPE_REGISTRY_CAPACITY)
    }

    /// Creates a new registry with a caller-specified initial capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            types: HashMap::with_capacity(capacity),
        }
    }

    /// Register a type with name and version.
    pub fn register<T: 'static>(&mut self, name: &'static str, version: u32) {
        let type_id = TypeId::of::<T>();
        let schema_hash = schema_hash::<T>(version);
        self.types.insert(
            type_id,
            TypeDescriptor {
                type_id,
                name,
                version,
                schema_hash,
            },
        );
    }

    /// Returns true if a type is registered.
    #[must_use]
    pub fn is_registered<T: 'static>(&self) -> bool {
        self.types.contains_key(&TypeId::of::<T>())
    }

    /// Returns the descriptor for a registered type.
    #[must_use]
    pub fn get<T: 'static>(&self) -> Option<&TypeDescriptor> {
        self.types.get(&TypeId::of::<T>())
    }

    /// Computes the schema hash for a type.
    #[must_use]
    pub fn schema_hash<T: 'static>(&self) -> u64 {
        self.get::<T>()
            .map_or_else(|| schema_hash::<T>(0), |desc| desc.schema_hash)
    }
}

/// Serializer for typed symbols.
pub trait Serializer<T>: Send + Sync {
    /// Serialize a value using the given format.
    fn serialize(
        &self,
        value: &T,
        format: SerializationFormat,
    ) -> Result<Vec<u8>, SerializationError>;
}

/// Deserializer for typed symbols.
pub trait Deserializer<T>: Send + Sync {
    /// Deserialize a value using the given format.
    fn deserialize(
        &self,
        bytes: &[u8],
        format: SerializationFormat,
    ) -> Result<T, DeserializationError>;
}

/// Serde-backed serializer/deserializer.
#[derive(Debug, Default, Clone, Copy)]
pub struct SerdeCodec;

impl<T: Serialize> Serializer<T> for SerdeCodec {
    fn serialize(
        &self,
        value: &T,
        format: SerializationFormat,
    ) -> Result<Vec<u8>, SerializationError> {
        match format {
            SerializationFormat::MessagePack => {
                rmp_serde::to_vec(value).map_err(|err: rmp_serde::encode::Error| {
                    SerializationError::SerializationFailed {
                        reason: err.to_string(),
                    }
                })
            }
            SerializationFormat::Bincode => {
                bincode::serde::encode_to_vec(value, bincode::config::legacy()).map_err(
                    |err: bincode::error::EncodeError| SerializationError::SerializationFailed {
                        reason: err.to_string(),
                    },
                )
            }
            SerializationFormat::Json => {
                serde_json::to_vec(value).map_err(|err| SerializationError::SerializationFailed {
                    reason: err.to_string(),
                })
            }
            SerializationFormat::Custom => Err(SerializationError::UnsupportedType {
                type_name: std::any::type_name::<T>().to_string(),
            }),
        }
    }
}

impl<T: DeserializeOwned> Deserializer<T> for SerdeCodec {
    fn deserialize(
        &self,
        bytes: &[u8],
        format: SerializationFormat,
    ) -> Result<T, DeserializationError> {
        match format {
            SerializationFormat::MessagePack => {
                rmp_serde::from_slice(bytes).map_err(|err: rmp_serde::decode::Error| {
                    DeserializationError::DeserializationFailed {
                        reason: err.to_string(),
                    }
                })
            }
            SerializationFormat::Bincode => {
                bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
                    .map(|(decoded, _)| decoded)
                    .map_err(|err: bincode::error::DecodeError| {
                        DeserializationError::DeserializationFailed {
                            reason: err.to_string(),
                        }
                    })
            }
            SerializationFormat::Json => serde_json::from_slice(bytes).map_err(|err| {
                DeserializationError::DeserializationFailed {
                    reason: err.to_string(),
                }
            }),
            SerializationFormat::Custom => Err(DeserializationError::DeserializationFailed {
                reason: "custom format not supported".to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TypedHeader {
    version: u16,
    type_id: u64,
    format: SerializationFormat,
    schema_hash: u64,
    payload_len: u32,
}

impl TypedHeader {
    fn new<T: 'static>(format: SerializationFormat, version: u16, payload_len: u32) -> Self {
        Self {
            version,
            type_id: type_id_hash::<T>(),
            format,
            schema_hash: schema_hash::<T>(u32::from(version)),
            payload_len,
        }
    }

    fn encode(self) -> [u8; TYPED_SYMBOL_HEADER_LEN] {
        let mut buf = [0u8; TYPED_SYMBOL_HEADER_LEN];
        buf[..4].copy_from_slice(&TYPED_SYMBOL_MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..14].copy_from_slice(&self.type_id.to_le_bytes());
        buf[14] = self.format.to_byte();
        buf[15..23].copy_from_slice(&self.schema_hash.to_le_bytes());
        buf[23..27].copy_from_slice(&self.payload_len.to_le_bytes());
        buf
    }

    fn decode(bytes: &[u8]) -> Result<Self, TypeMismatchError> {
        if bytes.len() < TYPED_SYMBOL_HEADER_LEN {
            return Err(TypeMismatchError::InvalidMagic);
        }
        if bytes[..4] != TYPED_SYMBOL_MAGIC {
            return Err(TypeMismatchError::InvalidMagic);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        let mut type_id_bytes = [0u8; 8];
        type_id_bytes.copy_from_slice(&bytes[6..14]);
        let type_id = u64::from_le_bytes(type_id_bytes);
        let format = SerializationFormat::from_byte(bytes[14])?;
        let mut schema_bytes = [0u8; 8];
        schema_bytes.copy_from_slice(&bytes[15..23]);
        let schema_hash = u64::from_le_bytes(schema_bytes);
        let mut payload_bytes = [0u8; 4];
        payload_bytes.copy_from_slice(&bytes[23..27]);
        let payload_len = u32::from_le_bytes(payload_bytes);

        Ok(Self {
            version,
            type_id,
            format,
            schema_hash,
            payload_len,
        })
    }
}

/// A typed wrapper around a symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedSymbol<T> {
    symbol: Symbol,
    header: TypedHeader,
    _marker: PhantomData<T>,
}

impl<T> TypedSymbol<T> {
    /// Wrap a raw symbol as typed without validation.
    ///
    /// Caller must ensure the symbol carries a valid typed header for `T`.
    #[must_use]
    pub fn from_symbol_unchecked(symbol: Symbol) -> Self {
        let header = TypedHeader::decode(symbol.data()).expect("typed symbol header missing");
        Self {
            symbol,
            header,
            _marker: PhantomData,
        }
    }

    /// Try to interpret a raw symbol as typed.
    pub fn try_from_symbol(symbol: Symbol) -> Result<Self, TypeMismatchError>
    where
        T: 'static,
    {
        Self::try_from_symbol_with_version(symbol, TYPED_SYMBOL_VERSION)
    }

    /// Try to interpret a raw symbol using an explicitly selected schema version.
    pub fn try_from_symbol_with_version(
        symbol: Symbol,
        expected_version: u16,
    ) -> Result<Self, TypeMismatchError>
    where
        T: 'static,
    {
        let header = TypedHeader::decode(symbol.data())?;
        validate_typed_header::<T>(header, expected_version)?;
        Ok(Self {
            symbol,
            header,
            _marker: PhantomData,
        })
    }

    /// Try to interpret a symbol using an exact, trusted legacy header identity.
    ///
    /// This is the explicit migration boundary for artifacts whose writer used
    /// the pre-stable typed-symbol hash scheme. The identity must be taken from
    /// a version-provenanced corpus or schema registry; copying values from an
    /// untrusted symbol would turn these checks into self-attestation.
    ///
    /// The returned wrapper retains the legacy header and payload. Decode the
    /// value with [`Self::value_with_deserializer`] or
    /// [`Self::into_value_with_deserializer`], then write a current artifact
    /// with [`Self::from_value_with_serializer`] so the stable current identity
    /// is installed without mutating the rollback source.
    pub fn try_from_legacy_symbol(
        symbol: Symbol,
        identity: LegacyTypedSymbolIdentity,
    ) -> Result<Self, TypeMismatchError> {
        let header = TypedHeader::decode(symbol.data())?;
        validate_legacy_typed_header(header, identity)?;
        Ok(Self {
            symbol,
            header,
            _marker: PhantomData,
        })
    }

    /// Validate this wrapper against an explicitly selected schema version.
    fn validate(&self, expected_version: u16) -> Result<(), TypeMismatchError>
    where
        T: 'static,
    {
        validate_typed_header::<T>(self.header, expected_version)
    }

    /// Returns the underlying symbol.
    #[must_use]
    #[inline]
    pub fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    /// Consumes the wrapper and returns the inner symbol.
    #[must_use]
    pub fn into_symbol(self) -> Symbol {
        self.symbol
    }

    /// Returns the serialization format used.
    #[must_use]
    pub const fn format(&self) -> SerializationFormat {
        self.header.format
    }

    /// Returns the schema version encoded in the header.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.header.version
    }

    /// Returns the encoded payload length.
    #[must_use]
    pub const fn payload_len(&self) -> u32 {
        self.header.payload_len
    }

    fn strip_header(&self) -> Result<&[u8], DeserializationError> {
        let data = self.symbol.data();
        let payload_len = self.header.payload_len as usize;
        let end = TYPED_SYMBOL_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(DeserializationError::CorruptData)?;
        if data.len() != end {
            return Err(DeserializationError::CorruptData);
        }
        Ok(&data[TYPED_SYMBOL_HEADER_LEN..end])
    }

    /// Create a typed symbol using an explicitly registered serializer.
    pub fn from_value_with_serializer(
        value: &T,
        format: SerializationFormat,
        version: u16,
        serializer: &impl Serializer<T>,
    ) -> Result<Self, SerializationError>
    where
        T: 'static,
    {
        let payload = serializer.serialize(value, format)?;
        let symbol_size = crate::types::DEFAULT_SYMBOL_SIZE;
        let max_payload = symbol_size.saturating_sub(TYPED_SYMBOL_HEADER_LEN);
        if payload.len() > max_payload {
            return Err(SerializationError::ValueTooLarge {
                size: payload.len(),
                max: max_payload,
            });
        }
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| SerializationError::ValueTooLarge {
                size: payload.len(),
                max: u32::MAX as usize,
            })?;
        let header = TypedHeader::new::<T>(format, version, payload_len);
        let header_bytes = header.encode();
        let envelope_len = TYPED_SYMBOL_HEADER_LEN.checked_add(payload.len()).ok_or(
            SerializationError::ValueTooLarge {
                size: payload.len(),
                max: max_payload,
            },
        )?;

        let mut data = Vec::new();
        data.try_reserve_exact(envelope_len)
            .map_err(|_| SerializationError::AllocationFailed {
                requested: envelope_len,
            })?;
        data.extend_from_slice(&header_bytes);
        data.extend_from_slice(&payload);

        let object_id = object_id_from_bytes::<T>(&payload);
        let symbol = Symbol::new(
            crate::types::SymbolId::new(object_id, 0, 0),
            data,
            SymbolKind::Source,
        );

        Ok(Self {
            symbol,
            header,
            _marker: PhantomData,
        })
    }

    /// Extract the value using an explicitly registered deserializer.
    pub fn into_value_with_deserializer(
        self,
        deserializer: &impl Deserializer<T>,
    ) -> Result<T, DeserializationError> {
        let format = self.header.format;
        let payload = self.strip_header()?;
        deserializer.deserialize(payload, format)
    }

    /// Borrow and decode the value using an explicitly registered deserializer.
    pub fn value_with_deserializer(
        &self,
        deserializer: &impl Deserializer<T>,
    ) -> Result<T, DeserializationError> {
        let payload = self.strip_header()?;
        deserializer.deserialize(payload, self.header.format)
    }
}

fn validate_typed_header<T: 'static>(
    header: TypedHeader,
    expected_version: u16,
) -> Result<(), TypeMismatchError> {
    if header.version != expected_version {
        return Err(TypeMismatchError::VersionMismatch {
            expected: expected_version,
            actual: header.version,
        });
    }
    let expected_type = type_id_hash::<T>();
    if header.type_id != expected_type {
        return Err(TypeMismatchError::UnknownType {
            type_id: header.type_id,
        });
    }
    let expected_schema = schema_hash::<T>(u32::from(header.version));
    if header.schema_hash != expected_schema {
        return Err(TypeMismatchError::SchemaMismatch {
            expected: expected_schema,
            actual: header.schema_hash,
        });
    }
    Ok(())
}

fn validate_legacy_typed_header(
    header: TypedHeader,
    identity: LegacyTypedSymbolIdentity,
) -> Result<(), TypeMismatchError> {
    if header.version != identity.version {
        return Err(TypeMismatchError::VersionMismatch {
            expected: identity.version,
            actual: header.version,
        });
    }
    if header.type_id != identity.type_id {
        return Err(TypeMismatchError::UnknownType {
            type_id: header.type_id,
        });
    }
    if header.schema_hash != identity.schema_hash {
        return Err(TypeMismatchError::SchemaMismatch {
            expected: identity.schema_hash,
            actual: header.schema_hash,
        });
    }
    Ok(())
}

impl<T: Serialize + 'static> TypedSymbol<T> {
    /// Create a typed symbol from a value, using a single symbol payload.
    pub fn from_value(value: &T, format: SerializationFormat) -> Result<Self, SerializationError> {
        Self::from_value_with_version(value, format, TYPED_SYMBOL_VERSION)
    }

    /// Create a typed symbol from a value with an explicit schema version.
    pub fn from_value_with_version(
        value: &T,
        format: SerializationFormat,
        version: u16,
    ) -> Result<Self, SerializationError> {
        let codec = SerdeCodec;
        Self::from_value_with_serializer(value, format, version, &codec)
    }
}

impl<T: DeserializeOwned> TypedSymbol<T> {
    /// Extract the value from a typed symbol.
    pub fn into_value(self) -> Result<T, DeserializationError> {
        let codec = SerdeCodec;
        self.into_value_with_deserializer(&codec)
    }

    /// Borrow and decode the value from the typed symbol.
    pub fn value(&self) -> Result<T, DeserializationError> {
        let codec = SerdeCodec;
        self.value_with_deserializer(&codec)
    }
}

/// Typed encoder for converting values into typed symbols.
pub struct TypedEncoder<T> {
    config: EncodingConfig,
    format: SerializationFormat,
    version: u16,
    serializer: Box<dyn Serializer<T>>,
    _marker: PhantomData<T>,
}

impl<T: 'static> TypedEncoder<T> {
    /// Create a new typed encoder with default config.
    #[must_use]
    pub fn new(format: SerializationFormat) -> Self
    where
        T: Serialize,
    {
        Self::with_config(EncodingConfig::default(), format)
    }

    /// Create a new encoder with custom config.
    #[must_use]
    pub fn with_config(config: EncodingConfig, format: SerializationFormat) -> Self
    where
        T: Serialize,
    {
        Self::with_serializer(config, format, SerdeCodec)
    }

    /// Create with a custom serializer.
    #[must_use]
    pub fn with_serializer(
        config: EncodingConfig,
        format: SerializationFormat,
        serializer: impl Serializer<T> + 'static,
    ) -> Self {
        Self {
            config,
            format,
            version: TYPED_SYMBOL_VERSION,
            serializer: Box::new(serializer),
            _marker: PhantomData,
        }
    }

    /// Select the schema version encoded into subsequent symbols.
    #[must_use]
    pub const fn with_version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Encode a value into typed symbols.
    pub fn encode(
        &mut self,
        object_id: ObjectId,
        value: &T,
    ) -> Result<Vec<TypedSymbol<T>>, EncodingError> {
        let payload = self
            .serializer
            .serialize(value, self.format)
            .map_err(|err| EncodingError::ComputationFailed {
                details: err.to_string(),
            })?;

        let payload_len =
            u32::try_from(payload.len()).map_err(|_| EncodingError::DataTooLarge {
                size: payload.len(),
                limit: u32::MAX as usize,
            })?;

        let header = TypedHeader::new::<T>(self.format, self.version, payload_len);
        let header_bytes = header.encode();

        let inner_symbol_size = inner_symbol_size(self.config.symbol_size)
            .map_err(|reason| EncodingError::InvalidConfig { reason })?;

        if payload.is_empty() {
            let symbol = Symbol::new(
                crate::types::SymbolId::new(object_id, 0, 0),
                vec![0; usize::from(inner_symbol_size)],
                SymbolKind::Source,
            );
            return Ok(vec![wrap_symbol(&symbol, header, &header_bytes)]);
        }

        let mut inner_config = self.config.clone();
        inner_config.symbol_size = inner_symbol_size;

        let pool = SymbolPool::new(PoolConfig {
            symbol_size: inner_symbol_size,
            ..PoolConfig::default()
        });

        let mut pipeline = EncodingPipeline::new(inner_config, pool);
        let mut symbols = Vec::new();

        for result in pipeline.encode(object_id, &payload) {
            let symbol = result?.into_symbol();
            let typed_symbol = wrap_symbol(&symbol, header, &header_bytes);
            symbols.push(typed_symbol);
        }

        Ok(symbols)
    }

    /// Encode into an existing symbol set.
    pub fn encode_into(
        &mut self,
        object_id: ObjectId,
        value: &T,
        set: &mut SymbolSet,
    ) -> Result<usize, EncodingError> {
        let symbols = self.encode(object_id, value)?;
        let mut inserted = 0;
        for symbol in symbols {
            match set.insert(symbol.into_symbol()) {
                crate::types::symbol_set::InsertResult::Inserted { .. } => inserted += 1,
                crate::types::symbol_set::InsertResult::Duplicate => {}
                crate::types::symbol_set::InsertResult::MemoryLimitReached
                | crate::types::symbol_set::InsertResult::BlockLimitReached { .. } => {
                    return Err(EncodingError::ComputationFailed {
                        details: "symbol set rejected insert".to_string(),
                    });
                }
            }
        }
        Ok(inserted)
    }

    /// Encode to a symbol sink.
    pub async fn encode_to_sink<S: SymbolSink + Unpin>(
        &mut self,
        object_id: ObjectId,
        value: &T,
        sink: &mut S,
    ) -> Result<usize, EncodingError>
    where
        T: Send + Sync,
    {
        let symbols = self.encode(object_id, value)?;
        let mut count = 0;
        for symbol in symbols {
            // asupersync-8kumb7: Use new_unauthenticated() to make the lack of
            // authentication explicit. This encoding path has not yet been
            // wired to a runtime-managed key via Cx-rooted capability.
            // The AuthenticatedSymbol will be marked as unverified and
            // downstream cap-aware code will reject it.
            let auth = AuthenticatedSymbol::new_unauthenticated(symbol.into_symbol());
            sink.send(auth)
                .await
                .map_err(|err| EncodingError::ComputationFailed {
                    details: err.to_string(),
                })?;
            count += 1;
        }
        Ok(count)
    }
}

/// Typed decoder for converting typed symbols into values.
pub struct TypedDecoder<T> {
    config: DecodingConfig,
    format: SerializationFormat,
    version: u16,
    deserializer: Box<dyn Deserializer<T>>,
    _marker: PhantomData<T>,
}

impl<T> std::fmt::Debug for TypedEncoder<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedEncoder")
            .field("config", &self.config)
            .field("format", &self.format)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl<T> std::fmt::Debug for TypedDecoder<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedDecoder")
            .field("config", &self.config)
            .field("format", &self.format)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl<T: 'static> TypedDecoder<T> {
    /// Create a new typed decoder.
    ///
    /// br-asupersync-b1fojq: typed decode is an **erasure-only** convenience —
    /// it reconstructs a serialized value from RaptorQ symbols and carries no
    /// [`SecurityContext`](crate::security::SecurityContext), so it explicitly opts out of per-symbol
    /// authentication via [`DecodingConfig::without_auth`]. (Were it to use the
    /// now-fail-closed [`DecodingConfig::default`], every symbol would be
    /// rejected for lack of an auth context.) Callers that need anti-forgery at
    /// the symbol layer must authenticate symbols upstream before decoding, or
    /// use [`Self::with_config`] with an auth-enabled pipeline.
    #[must_use]
    pub fn new(format: SerializationFormat) -> Self
    where
        T: DeserializeOwned,
    {
        Self::with_config(DecodingConfig::without_auth(), format)
    }

    /// Create a decoder with custom config.
    #[must_use]
    pub fn with_config(config: DecodingConfig, format: SerializationFormat) -> Self
    where
        T: DeserializeOwned,
    {
        Self::with_deserializer(config, format, SerdeCodec)
    }

    /// Create with a custom deserializer.
    #[must_use]
    pub fn with_deserializer(
        config: DecodingConfig,
        format: SerializationFormat,
        deserializer: impl Deserializer<T> + 'static,
    ) -> Self {
        Self {
            config,
            format,
            version: TYPED_SYMBOL_VERSION,
            deserializer: Box::new(deserializer),
            _marker: PhantomData,
        }
    }

    /// Select the schema version accepted by subsequent decodes.
    #[must_use]
    pub const fn with_version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Decode typed symbols back to a value.
    pub fn decode<I>(&mut self, symbols: I) -> Result<T, DecodingError>
    where
        I: IntoIterator<Item = TypedSymbol<T>>,
        T: 'static,
    {
        let mut iter = symbols.into_iter();
        let first = iter
            .next()
            .ok_or_else(|| DecodingError::InconsistentMetadata {
                sbn: 0,
                details: "no symbols provided".to_string(),
            })?;

        let header = validate_header::<T>(&first, self.format, self.version)?;
        let object_id = first.symbol().object_id();
        let inner_size = inner_symbol_size(self.config.symbol_size).map_err(|reason| {
            DecodingError::InconsistentMetadata {
                sbn: 0,
                details: reason,
            }
        })?;

        if header.payload_len == 0 {
            validate_empty_typed_symbol(&first, inner_size)?;
            if let Some(extra) = iter.next() {
                return Err(DecodingError::InconsistentMetadata {
                    sbn: extra.symbol().sbn(),
                    details: "empty typed payload must contain exactly one symbol".to_string(),
                });
            }
            return self.deserialize_payload(&[], header);
        }

        let mut pipeline = DecodingPipeline::new(inner_config(&self.config, inner_size));
        pipeline.set_object_params(object_params_for_payload(
            object_id,
            u64::from(header.payload_len),
            inner_size,
            self.config.max_block_size,
        ))?;

        feed_typed_symbol(&mut pipeline, first, inner_size)?;

        for symbol in iter {
            let current = validate_header::<T>(&symbol, self.format, self.version)?;
            if current != header {
                return Err(DecodingError::InconsistentMetadata {
                    sbn: symbol.symbol().sbn(),
                    details: "typed symbol header mismatch".to_string(),
                });
            }
            feed_typed_symbol(&mut pipeline, symbol, inner_size)?;
        }

        let payload = pipeline.into_data()?;
        self.deserialize_payload(&payload, header)
    }

    /// Decode from a symbol set.
    pub fn decode_from_set(&mut self, set: &SymbolSet) -> Result<T, DecodingError>
    where
        T: 'static,
    {
        let symbols = set
            .iter()
            .map(|(_, symbol)| {
                TypedSymbol::try_from_symbol_with_version(symbol.clone(), self.version).map_err(
                    |err| DecodingError::InconsistentMetadata {
                        sbn: symbol.sbn(),
                        details: err.to_string(),
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.decode(symbols)
    }

    /// Decode from a symbol stream.
    pub async fn decode_from_stream<S: SymbolStream + Unpin>(
        &mut self,
        stream: &mut S,
    ) -> Result<T, DecodingError>
    where
        T: 'static,
    {
        let mut header = None;
        let mut pipeline = None;
        let mut inner_size = 0;

        while let Some(result) = stream.next().await {
            let symbol = result.map_err(|err| DecodingError::InconsistentMetadata {
                sbn: 0,
                details: err.to_string(),
            })?;
            let typed =
                TypedSymbol::try_from_symbol_with_version(symbol.into_symbol(), self.version)
                    .map_err(|err| DecodingError::InconsistentMetadata {
                        sbn: 0,
                        details: err.to_string(),
                    })?;

            let current = validate_header::<T>(&typed, self.format, self.version)?;
            if current.payload_len == 0 {
                let empty_inner_size =
                    inner_symbol_size(self.config.symbol_size).map_err(|reason| {
                        DecodingError::InconsistentMetadata {
                            sbn: 0,
                            details: reason,
                        }
                    })?;
                validate_empty_typed_symbol(&typed, empty_inner_size)?;
                return self.deserialize_payload(&[], current);
            }
            if let Some(expected) = header {
                if current != expected {
                    return Err(DecodingError::InconsistentMetadata {
                        sbn: typed.symbol().sbn(),
                        details: "typed symbol header mismatch".to_string(),
                    });
                }
            } else {
                inner_size = inner_symbol_size(self.config.symbol_size).map_err(|reason| {
                    DecodingError::InconsistentMetadata {
                        sbn: 0,
                        details: reason,
                    }
                })?;
                let mut current_pipeline =
                    DecodingPipeline::new(inner_config(&self.config, inner_size));
                current_pipeline.set_object_params(object_params_for_payload(
                    typed.symbol().object_id(),
                    u64::from(current.payload_len),
                    inner_size,
                    self.config.max_block_size,
                ))?;
                header = Some(current);
                pipeline = Some(current_pipeline);
            }

            let is_complete = {
                let pipeline =
                    pipeline
                        .as_mut()
                        .ok_or_else(|| DecodingError::InconsistentMetadata {
                            sbn: typed.symbol().sbn(),
                            details: "typed stream pipeline not initialized".to_string(),
                        })?;
                feed_typed_symbol(pipeline, typed, inner_size)?;
                pipeline.is_complete()
            };

            if is_complete {
                let payload = pipeline
                    .take()
                    .ok_or_else(|| DecodingError::InconsistentMetadata {
                        sbn: 0,
                        details: "typed stream pipeline disappeared before completion".to_string(),
                    })?
                    .into_data()?;
                let header = header.ok_or_else(|| DecodingError::InconsistentMetadata {
                    sbn: 0,
                    details: "typed stream header missing at completion".to_string(),
                })?;
                return self.deserialize_payload(&payload, header);
            }
        }

        let header = header.ok_or_else(|| DecodingError::InconsistentMetadata {
            sbn: 0,
            details: "no symbols provided".to_string(),
        })?;
        let pipeline = pipeline.ok_or_else(|| DecodingError::InconsistentMetadata {
            sbn: 0,
            details: "typed stream pipeline missing at end of stream".to_string(),
        })?;
        let payload = pipeline.into_data()?;
        self.deserialize_payload(&payload, header)
    }

    fn deserialize_payload(&self, payload: &[u8], header: TypedHeader) -> Result<T, DecodingError> {
        self.deserializer
            .deserialize(payload, header.format)
            .map_err(|err| DecodingError::InconsistentMetadata {
                sbn: 0,
                details: err.to_string(),
            })
    }
}

fn inner_symbol_size(symbol_size: u16) -> Result<u16, String> {
    let outer = usize::from(symbol_size);
    if outer <= TYPED_SYMBOL_HEADER_LEN {
        return Err(format!(
            "symbol_size {outer} must exceed typed header length {TYPED_SYMBOL_HEADER_LEN}"
        ));
    }
    let inner = outer - TYPED_SYMBOL_HEADER_LEN;
    u16::try_from(inner).map_err(|_| "inner symbol size overflow".to_string())
}

fn inner_config(config: &DecodingConfig, inner_symbol_size: u16) -> DecodingConfig {
    let mut inner = config.clone();
    inner.symbol_size = inner_symbol_size;
    inner
}

fn wrap_symbol<T>(
    symbol: &Symbol,
    header: TypedHeader,
    header_bytes: &[u8; TYPED_SYMBOL_HEADER_LEN],
) -> TypedSymbol<T> {
    let mut data = Vec::with_capacity(TYPED_SYMBOL_HEADER_LEN + symbol.data().len());
    data.extend_from_slice(header_bytes);
    data.extend_from_slice(symbol.data());
    let typed_symbol = Symbol::new(symbol.id(), data, symbol.kind());
    TypedSymbol {
        symbol: typed_symbol,
        header,
        _marker: PhantomData,
    }
}

fn feed_typed_symbol<T>(
    pipeline: &mut DecodingPipeline,
    symbol: TypedSymbol<T>,
    inner_size: u16,
) -> Result<(), DecodingError> {
    let raw = symbol.into_symbol();
    if raw.data().len() < TYPED_SYMBOL_HEADER_LEN {
        return Err(DecodingError::SymbolSizeMismatch {
            expected: inner_size,
            actual: raw.data().len(),
        });
    }
    let payload = raw.data()[TYPED_SYMBOL_HEADER_LEN..].to_vec();
    if payload.len() != usize::from(inner_size) {
        return Err(DecodingError::SymbolSizeMismatch {
            expected: inner_size,
            actual: payload.len(),
        });
    }
    let inner_symbol = Symbol::new(raw.id(), payload, raw.kind());
    // asupersync-8kumb7: Use new_unauthenticated() to make the lack of
    // authentication explicit. Same caveat as the TypedEncoder::encode_to_sink
    // callsite — a full fix routes a real Cx-anchored AuthKey through the pipeline.
    let auth = AuthenticatedSymbol::new_unauthenticated(inner_symbol);
    let _ = pipeline.feed(auth)?;
    Ok(())
}

fn validate_empty_typed_symbol<T>(
    symbol: &TypedSymbol<T>,
    inner_size: u16,
) -> Result<(), DecodingError> {
    let raw = symbol.symbol();
    let actual = raw
        .data()
        .len()
        .checked_sub(TYPED_SYMBOL_HEADER_LEN)
        .ok_or(DecodingError::SymbolSizeMismatch {
            expected: inner_size,
            actual: raw.data().len(),
        })?;
    if actual != usize::from(inner_size) {
        return Err(DecodingError::SymbolSizeMismatch {
            expected: inner_size,
            actual,
        });
    }
    if raw.kind() != SymbolKind::Source || raw.sbn() != 0 || raw.esi() != 0 {
        return Err(DecodingError::InconsistentMetadata {
            sbn: raw.sbn(),
            details: "empty typed payload sentinel must be source symbol 0:0".to_string(),
        });
    }
    if raw.data()[TYPED_SYMBOL_HEADER_LEN..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(DecodingError::InconsistentMetadata {
            sbn: raw.sbn(),
            details: "empty typed payload sentinel must be zero-filled".to_string(),
        });
    }
    Ok(())
}

fn validate_header<T: 'static>(
    symbol: &TypedSymbol<T>,
    expected_format: SerializationFormat,
    expected_version: u16,
) -> Result<TypedHeader, DecodingError> {
    symbol
        .validate(expected_version)
        .map_err(|err| DecodingError::InconsistentMetadata {
            sbn: symbol.symbol().sbn(),
            details: err.to_string(),
        })?;
    if symbol.header.format != expected_format {
        return Err(DecodingError::InconsistentMetadata {
            sbn: symbol.symbol().sbn(),
            details: "serialization format mismatch".to_string(),
        });
    }
    Ok(symbol.header)
}

fn object_params_for_payload(
    object_id: ObjectId,
    payload_len: u64,
    symbol_size: u16,
    max_block_size: usize,
) -> ObjectParams {
    let symbol_size = usize::from(symbol_size);
    let max_block_size = max_block_size.max(symbol_size);
    let payload_len = payload_len as usize;
    let blocks = payload_len.div_ceil(max_block_size).max(1);
    // `ObjectParams.symbols_per_block` is the maximum per-block K, not the
    // configured byte capacity of a full block. For a single partial block,
    // deriving K from `max_block_size` overstates the declared layout and
    // poisons decode metadata validation.
    let symbols_per_block = if payload_len == 0 {
        0
    } else {
        payload_len.min(max_block_size).div_ceil(symbol_size)
    };
    // Preserve the full sender-side 256-block contract in metadata instead of
    // silently compressing the boundary case to 255.
    let blocks = blocks.min(u16::MAX as usize) as u16;
    let symbols_per_block = symbols_per_block.min(u16::MAX as usize) as u16;
    ObjectParams::new(
        object_id,
        payload_len as u64,
        symbol_size as u16,
        blocks,
        symbols_per_block,
    )
}

fn type_id_hash<T: 'static>() -> u64 {
    let digest = stable_digest(
        b"asupersync.typed-symbol.type-id.v1",
        &[std::any::type_name::<T>().as_bytes()],
    );
    digest_u64(&digest, 0)
}

fn schema_hash<T: 'static>(version: u32) -> u64 {
    let version_bytes = version.to_le_bytes();
    let digest = stable_digest(
        b"asupersync.typed-symbol.schema-hash.v1",
        &[
            std::any::type_name::<T>().as_bytes(),
            version_bytes.as_slice(),
        ],
    );
    digest_u64(&digest, 0)
}

fn object_id_from_bytes<T: 'static>(bytes: &[u8]) -> ObjectId {
    let digest = stable_digest(
        b"asupersync.typed-symbol.object-id.v1",
        &[std::any::type_name::<T>().as_bytes(), bytes],
    );
    ObjectId::new(digest_u64(&digest, 0), digest_u64(&digest, 8))
}

fn stable_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn digest_u64(digest: &[u8; 32], offset: usize) -> u64 {
    u64::from_le_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
        digest[offset + 4],
        digest[offset + 5],
        digest[offset + 6],
        digest[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::transport::error::StreamError;
    use proptest::prelude::*;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct Demo {
        id: u64,
        name: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct EmptyStruct;

    #[derive(Debug, PartialEq, Eq)]
    struct CustomValue {
        id: u32,
        name: String,
    }

    #[derive(Debug, Clone, Copy)]
    struct CustomValueCodec;

    impl Serializer<CustomValue> for CustomValueCodec {
        fn serialize(
            &self,
            value: &CustomValue,
            format: SerializationFormat,
        ) -> Result<Vec<u8>, SerializationError> {
            if format != SerializationFormat::Custom {
                return Err(SerializationError::UnsupportedType {
                    type_name: std::any::type_name::<CustomValue>().to_string(),
                });
            }
            let name_len =
                u32::try_from(value.name.len()).map_err(|_| SerializationError::ValueTooLarge {
                    size: value.name.len(),
                    max: u32::MAX as usize,
                })?;
            let mut bytes = Vec::with_capacity(8 + value.name.len());
            bytes.extend_from_slice(&value.id.to_le_bytes());
            bytes.extend_from_slice(&name_len.to_le_bytes());
            bytes.extend_from_slice(value.name.as_bytes());
            Ok(bytes)
        }
    }

    impl Deserializer<CustomValue> for CustomValueCodec {
        fn deserialize(
            &self,
            bytes: &[u8],
            format: SerializationFormat,
        ) -> Result<CustomValue, DeserializationError> {
            if format != SerializationFormat::Custom || bytes.len() < 8 {
                return Err(DeserializationError::CorruptData);
            }
            let id = u32::from_le_bytes(
                bytes[..4]
                    .try_into()
                    .map_err(|_| DeserializationError::CorruptData)?,
            );
            let name_len = u32::from_le_bytes(
                bytes[4..8]
                    .try_into()
                    .map_err(|_| DeserializationError::CorruptData)?,
            ) as usize;
            if bytes.len() != 8usize.saturating_add(name_len) {
                return Err(DeserializationError::CorruptData);
            }
            let name = std::str::from_utf8(&bytes[8..])
                .map_err(|_| DeserializationError::CorruptData)?
                .to_string();
            Ok(CustomValue { id, name })
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct EmptyCustomValue;

    #[derive(Debug, Clone, Copy)]
    struct EmptyCustomCodec;

    impl Serializer<EmptyCustomValue> for EmptyCustomCodec {
        fn serialize(
            &self,
            _value: &EmptyCustomValue,
            format: SerializationFormat,
        ) -> Result<Vec<u8>, SerializationError> {
            if format == SerializationFormat::Custom {
                Ok(Vec::new())
            } else {
                Err(SerializationError::UnsupportedType {
                    type_name: std::any::type_name::<EmptyCustomValue>().to_string(),
                })
            }
        }
    }

    impl Deserializer<EmptyCustomValue> for EmptyCustomCodec {
        fn deserialize(
            &self,
            bytes: &[u8],
            format: SerializationFormat,
        ) -> Result<EmptyCustomValue, DeserializationError> {
            if format == SerializationFormat::Custom && bytes.is_empty() {
                Ok(EmptyCustomValue)
            } else {
                Err(DeserializationError::CorruptData)
            }
        }
    }

    struct OversizedCustomCodec;

    impl Serializer<CustomValue> for OversizedCustomCodec {
        fn serialize(
            &self,
            _value: &CustomValue,
            _format: SerializationFormat,
        ) -> Result<Vec<u8>, SerializationError> {
            Ok(vec![
                0;
                crate::types::DEFAULT_SYMBOL_SIZE
                    - TYPED_SYMBOL_HEADER_LEN
                    + 1
            ])
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    enum TestEnum {
        Unit,
        Tuple(u32, String),
        Struct { x: i32, y: i32 },
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Nested {
        inner: Box<Option<Self>>,
        value: f64,
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn test_encoding_config() -> EncodingConfig {
        EncodingConfig {
            symbol_size: 64,
            max_block_size: 128,
            repair_overhead: 1.05,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        }
    }

    fn test_decoding_config() -> DecodingConfig {
        DecodingConfig {
            symbol_size: 64,
            max_block_size: 128,
            repair_overhead: 1.05,
            min_overhead: 0,
            max_buffered_symbols: 8192,
            block_timeout: std::time::Duration::from_secs(1),
            verify_auth: false,
        }
    }

    struct ReadyThenPendingStream {
        items: std::vec::IntoIter<AuthenticatedSymbol>,
    }

    impl ReadyThenPendingStream {
        fn new(items: Vec<AuthenticatedSymbol>) -> Self {
            Self {
                items: items.into_iter(),
            }
        }
    }

    impl SymbolStream for ReadyThenPendingStream {
        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
            self.items
                .next()
                .map_or(Poll::Pending, |item| Poll::Ready(Some(Ok(item))))
        }
    }

    #[test]
    fn typed_symbol_single_roundtrip() {
        let value = Demo {
            id: 7,
            name: "alpha".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).expect("symbol");
        let decoded_value = symbol.into_value().expect("decode");
        assert_eq!(value, decoded_value);
    }

    #[test]
    fn typed_symbol_header_v1_has_stable_bytes_for_every_format() {
        let formats = [
            (SerializationFormat::MessagePack, 1),
            (SerializationFormat::Bincode, 2),
            (SerializationFormat::Json, 3),
            (SerializationFormat::Custom, 255),
        ];

        for (format, format_byte) in formats {
            let encoded =
                TypedHeader::new::<Demo>(format, TYPED_SYMBOL_VERSION, 0x0403_0201).encode();
            let expected = [
                0x54,
                0x53,
                0x59,
                0x4d,
                0x01,
                0x00,
                0xd5,
                0x69,
                0x8d,
                0xb3,
                0x03,
                0x72,
                0x7d,
                0xde,
                format_byte,
                0xd9,
                0x3d,
                0x6b,
                0x9c,
                0x7a,
                0xae,
                0xbc,
                0xde,
                0x01,
                0x02,
                0x03,
                0x04,
            ];
            assert_eq!(encoded, expected);
        }
    }

    #[test]
    fn typed_symbol_default_reader_rejects_unknown_version() {
        let value = Demo {
            id: 8,
            name: "versioned".to_string(),
        };
        let symbol = TypedSymbol::from_value_with_version(
            &value,
            SerializationFormat::Bincode,
            TYPED_SYMBOL_VERSION + 1,
        )
        .expect("versioned symbol");

        assert!(matches!(
            TypedSymbol::<Demo>::try_from_symbol(symbol.clone().into_symbol()),
            Err(TypeMismatchError::VersionMismatch {
                expected: TYPED_SYMBOL_VERSION,
                actual: 2,
            })
        ));

        let decoded = TypedSymbol::<Demo>::try_from_symbol_with_version(
            symbol.into_symbol(),
            TYPED_SYMBOL_VERSION + 1,
        )
        .expect("explicit version")
        .into_value()
        .expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn a7_legacy_admission_requires_every_provenance_field() {
        let value = Demo {
            id: 81,
            name: "legacy-provenance".to_string(),
        };
        let symbol = TypedSymbol::from_value_with_version(&value, SerializationFormat::Bincode, 7)
            .expect("versioned symbol");
        let header = symbol.header;
        let identity =
            LegacyTypedSymbolIdentity::new(header.version, header.type_id, header.schema_hash);

        let admitted =
            TypedSymbol::<Demo>::try_from_legacy_symbol(symbol.clone().into_symbol(), identity)
                .expect("trusted identity admits exact header");
        assert_eq!(admitted.value().expect("decode admitted payload"), value);

        assert!(matches!(
            TypedSymbol::<Demo>::try_from_legacy_symbol(
                symbol.clone().into_symbol(),
                LegacyTypedSymbolIdentity::new(
                    identity.version + 1,
                    identity.type_id,
                    identity.schema_hash,
                ),
            ),
            Err(TypeMismatchError::VersionMismatch { .. })
        ));
        assert!(matches!(
            TypedSymbol::<Demo>::try_from_legacy_symbol(
                symbol.clone().into_symbol(),
                LegacyTypedSymbolIdentity::new(
                    identity.version,
                    identity.type_id ^ 1,
                    identity.schema_hash,
                ),
            ),
            Err(TypeMismatchError::UnknownType { .. })
        ));
        assert!(matches!(
            TypedSymbol::<Demo>::try_from_legacy_symbol(
                symbol.into_symbol(),
                LegacyTypedSymbolIdentity::new(
                    identity.version,
                    identity.type_id,
                    identity.schema_hash ^ 1,
                ),
            ),
            Err(TypeMismatchError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn typed_symbol_detects_schema_mismatch_and_exact_length_corruption() {
        let value = Demo {
            id: 9,
            name: "bounded".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).expect("symbol");

        let mut schema_corrupt = symbol.clone().into_symbol();
        schema_corrupt.data_mut()[15] ^= 0x80;
        assert!(matches!(
            TypedSymbol::<Demo>::try_from_symbol(schema_corrupt),
            Err(TypeMismatchError::SchemaMismatch { .. })
        ));

        let truncated = symbol.clone().into_symbol();
        let truncated = Symbol::new(
            truncated.id(),
            truncated.data()[..truncated.data().len() - 1].to_vec(),
            truncated.kind(),
        );
        let truncated = TypedSymbol::<Demo>::try_from_symbol(truncated).expect("valid header");
        assert!(matches!(
            truncated.value(),
            Err(DeserializationError::CorruptData)
        ));

        let trailing = symbol.into_symbol();
        let mut trailing_data = trailing.data().to_vec();
        trailing_data.push(0);
        let trailing = Symbol::new(trailing.id(), trailing_data, trailing.kind());
        let trailing = TypedSymbol::<Demo>::try_from_symbol(trailing).expect("valid header");
        assert!(matches!(
            trailing.value(),
            Err(DeserializationError::CorruptData)
        ));
    }

    #[test]
    fn custom_codec_roundtrips_non_serde_value_in_single_and_multi_symbol_paths() {
        let value = CustomValue {
            id: 17,
            name: "owned-custom-codec".to_string(),
        };
        let symbol = TypedSymbol::from_value_with_serializer(
            &value,
            SerializationFormat::Custom,
            7,
            &CustomValueCodec,
        )
        .expect("custom symbol");
        assert_eq!(symbol.version(), 7);
        assert_eq!(
            symbol
                .value_with_deserializer(&CustomValueCodec)
                .expect("custom decode"),
            value
        );

        let mut encoder = TypedEncoder::with_serializer(
            test_encoding_config(),
            SerializationFormat::Custom,
            CustomValueCodec,
        )
        .with_version(7);
        let symbols = encoder
            .encode(ObjectId::new_for_test(17), &value)
            .expect("custom encode");
        let mut decoder = TypedDecoder::with_deserializer(
            test_decoding_config(),
            SerializationFormat::Custom,
            CustomValueCodec,
        )
        .with_version(7);
        assert_eq!(decoder.decode(symbols).expect("custom decode"), value);
    }

    #[test]
    fn typed_encoder_roundtrips_empty_custom_payload_with_one_bounded_symbol() {
        let mut encoder = TypedEncoder::with_serializer(
            test_encoding_config(),
            SerializationFormat::Custom,
            EmptyCustomCodec,
        );
        let symbols = encoder
            .encode(ObjectId::new_for_test(18), &EmptyCustomValue)
            .expect("empty custom encode");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].payload_len(), 0);
        assert_eq!(symbols[0].symbol().data().len(), 64);

        let mut decoder = TypedDecoder::with_deserializer(
            test_decoding_config(),
            SerializationFormat::Custom,
            EmptyCustomCodec,
        );
        assert_eq!(
            decoder.decode(symbols).expect("empty custom decode"),
            EmptyCustomValue
        );
    }

    #[test]
    fn typed_decoder_rejects_corrupt_empty_payload_sentinel() {
        let mut encoder = TypedEncoder::with_serializer(
            test_encoding_config(),
            SerializationFormat::Custom,
            EmptyCustomCodec,
        );
        let mut symbols = encoder
            .encode(ObjectId::new_for_test(181), &EmptyCustomValue)
            .expect("empty custom encode");
        symbols[0].symbol.data_mut()[TYPED_SYMBOL_HEADER_LEN] = 1;

        let mut decoder = TypedDecoder::with_deserializer(
            test_decoding_config(),
            SerializationFormat::Custom,
            EmptyCustomCodec,
        );
        let error = decoder
            .decode(symbols)
            .expect_err("non-zero sentinel padding must be rejected");
        assert!(matches!(
            error,
            DecodingError::InconsistentMetadata { details, .. }
                if details == "empty typed payload sentinel must be zero-filled"
        ));
    }

    #[test]
    fn typed_symbol_rejects_value_above_single_symbol_limit() {
        let value = CustomValue {
            id: 19,
            name: String::new(),
        };
        let result = TypedSymbol::from_value_with_serializer(
            &value,
            SerializationFormat::Custom,
            TYPED_SYMBOL_VERSION,
            &OversizedCustomCodec,
        );
        assert!(matches!(
            result,
            Err(SerializationError::ValueTooLarge {
                size,
                max
            }) if size == max + 1
        ));
    }

    #[test]
    fn typed_encoder_and_decoder_require_the_same_explicit_version() {
        let value = Demo {
            id: 20,
            name: "configured-version".to_string(),
        };
        let mut encoder =
            TypedEncoder::with_config(test_encoding_config(), SerializationFormat::Json)
                .with_version(9);
        let symbols = encoder
            .encode(ObjectId::new_for_test(20), &value)
            .expect("encode");

        let mut default_decoder =
            TypedDecoder::with_config(test_decoding_config(), SerializationFormat::Json);
        let mismatch = default_decoder
            .decode(symbols.clone())
            .expect_err("default reader must reject version 9");
        assert!(
            mismatch.to_string().contains("expected 1, got 9"),
            "{mismatch}"
        );

        let mut decoder =
            TypedDecoder::with_config(test_decoding_config(), SerializationFormat::Json)
                .with_version(9);
        assert_eq!(decoder.decode(symbols).expect("decode"), value);
    }

    #[test]
    fn typed_encoder_decoder_roundtrip() {
        let value = Demo {
            id: 42,
            name: "beta".to_string(),
        };

        let mut encoder = TypedEncoder::with_config(
            EncodingConfig {
                symbol_size: 64,
                max_block_size: 128,
                repair_overhead: 1.05,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SerializationFormat::Bincode,
        );

        let object_id = ObjectId::new(1, 2);
        let symbols = encoder.encode(object_id, &value).expect("encode");
        assert!(!symbols.is_empty());

        let mut decoder: TypedDecoder<Demo> = TypedDecoder::with_config(
            DecodingConfig {
                symbol_size: 64,
                max_block_size: 128,
                repair_overhead: 1.05,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: std::time::Duration::from_secs(1),
                verify_auth: false,
            },
            SerializationFormat::Bincode,
        );

        let decoded_value = decoder.decode(symbols).expect("decode");
        assert_eq!(value, decoded_value);
    }

    #[test]
    fn object_params_for_small_payload_uses_actual_single_block_k() {
        let params = object_params_for_payload(ObjectId::new_for_test(7), 8, 37, 512);

        assert_eq!(params.source_blocks, 1);
        assert_eq!(params.symbols_per_block, 1);
    }

    #[test]
    fn object_params_for_payload_preserves_256_block_boundary() {
        let params = object_params_for_payload(ObjectId::new_for_test(8), 256, 1, 1);

        assert_eq!(params.source_blocks, 256);
        assert_eq!(params.symbols_per_block, 1);
    }

    #[test]
    fn object_params_for_payload_uses_max_per_block_k_for_partial_multi_block_payload() {
        let params = object_params_for_payload(ObjectId::new_for_test(9), 13, 4, 6);

        assert_eq!(params.source_blocks, 3);
        assert_eq!(params.symbols_per_block, 2);
        assert_eq!(params.total_source_symbols(), 4);
        assert_eq!(params.min_symbols_for_decode(), 4);
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn typed_decoder_accepts_small_single_block_payload_with_large_max_block_size() {
        let value: u64 = 42;

        let mut encoder = TypedEncoder::with_config(
            EncodingConfig {
                symbol_size: 64,
                max_block_size: 512,
                repair_overhead: 1.05,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SerializationFormat::Bincode,
        );

        let mut decoder: TypedDecoder<u64> = TypedDecoder::with_config(
            DecodingConfig {
                symbol_size: 64,
                max_block_size: 512,
                repair_overhead: 1.05,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: std::time::Duration::from_secs(1),
                verify_auth: false,
            },
            SerializationFormat::Bincode,
        );

        let symbols = encoder
            .encode(ObjectId::new_for_test(9), &value)
            .expect("encode");
        let decoded = decoder.decode(symbols).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn typed_decoder_stream_returns_once_object_is_complete_before_eof() {
        let value: u64 = 42;

        let mut encoder = TypedEncoder::with_config(
            EncodingConfig {
                symbol_size: 64,
                max_block_size: 512,
                repair_overhead: 1.05,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SerializationFormat::Bincode,
        );

        let mut decoder: TypedDecoder<u64> = TypedDecoder::with_config(
            DecodingConfig {
                symbol_size: 64,
                max_block_size: 512,
                repair_overhead: 1.05,
                min_overhead: 0,
                max_buffered_symbols: 8192,
                block_timeout: std::time::Duration::from_secs(1),
                verify_auth: false,
            },
            SerializationFormat::Bincode,
        );

        let symbols = encoder
            .encode(ObjectId::new_for_test(11), &value)
            .expect("encode");
        assert!(
            !symbols.is_empty(),
            "test requires at least one encoded symbol for the object"
        );

        let auth_symbols = symbols
            .into_iter()
            .map(|symbol| {
                // asupersync-8kumb7: Use new_unauthenticated() for test symbols
                AuthenticatedSymbol::new_unauthenticated(symbol.into_symbol())
            })
            .collect();
        let mut stream = ReadyThenPendingStream::new(auth_symbols);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(decoder.decode_from_stream(&mut stream));

        match Future::poll(future.as_mut(), &mut cx) {
            Poll::Ready(Ok(actual)) => assert_eq!(actual, value),
            other => panic!(
                "stream decode should finish once the first object is complete, even if the stream stays open: {other:?}"
            ),
        }
    }

    #[test]
    fn test_roundtrip_primitive_types() {
        // u64
        let val_u64: u64 = 12_345_678_901_234;
        let sym = TypedSymbol::from_value(&val_u64, SerializationFormat::Bincode).unwrap();
        assert_eq!(sym.into_value().unwrap(), val_u64);

        // i32
        let val_int: i32 = -42;
        let sym = TypedSymbol::from_value(&val_int, SerializationFormat::Bincode).unwrap();
        assert_eq!(sym.into_value().unwrap(), val_int);

        // bool
        let val_bool = true;
        let sym = TypedSymbol::from_value(&val_bool, SerializationFormat::Bincode).unwrap();
        assert_eq!(sym.into_value().unwrap(), val_bool);

        // String
        let val_str = "hello world".to_string();
        let sym = TypedSymbol::from_value(&val_str, SerializationFormat::Bincode).unwrap();
        assert_eq!(sym.into_value().unwrap(), val_str);
    }

    #[test]
    fn test_roundtrip_struct() {
        let value = Demo {
            id: 999,
            name: "struct_test".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_roundtrip_enum() {
        let variants = [
            TestEnum::Unit,
            TestEnum::Tuple(42, "tuple".to_string()),
            TestEnum::Struct { x: -10, y: 20 },
        ];
        for value in variants {
            let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
            assert_eq!(symbol.into_value().unwrap(), value);
        }
    }

    #[test]
    fn test_roundtrip_vec() {
        let value: Vec<u32> = vec![1, 2, 3, 4, 5];
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.into_value().unwrap(), value);

        let value: Vec<Demo> = vec![
            Demo {
                id: 1,
                name: "a".into(),
            },
            Demo {
                id: 2,
                name: "b".into(),
            },
        ];
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_roundtrip_hashmap() {
        let mut value: HashMap<String, i32> = HashMap::new();
        value.insert("one".to_string(), 1);
        value.insert("two".to_string(), 2);
        value.insert("negative".to_string(), -100);

        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_messagepack_format() {
        let value = Demo {
            id: 1,
            name: "msgpack".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::MessagePack).unwrap();
        assert_eq!(symbol.format(), SerializationFormat::MessagePack);
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_bincode_format() {
        let value = Demo {
            id: 2,
            name: "bincode".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        assert_eq!(symbol.format(), SerializationFormat::Bincode);
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_json_format() {
        let value = Demo {
            id: 3,
            name: "json".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Json).unwrap();
        assert_eq!(symbol.format(), SerializationFormat::Json);
        assert_eq!(symbol.into_value().unwrap(), value);
    }

    #[test]
    fn test_type_mismatch_detected() {
        let value: u64 = 42;
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        let raw = symbol.into_symbol();

        // Try to interpret as a different type
        let result = TypedSymbol::<String>::try_from_symbol(raw);
        assert!(result.is_err());
        match result {
            Err(TypeMismatchError::UnknownType { .. }) => {}
            _ => panic!("Expected UnknownType error"),
        }
    }

    #[test]
    fn test_corrupt_header_detected() {
        // Create a symbol with invalid magic bytes
        let mut data = vec![0u8; TYPED_SYMBOL_HEADER_LEN + 10];
        data[0..4].copy_from_slice(b"XXXX"); // Wrong magic

        let symbol = Symbol::new(
            crate::types::SymbolId::new(ObjectId::new(1, 1), 0, 0),
            data,
            SymbolKind::Source,
        );

        let result = TypedSymbol::<u64>::try_from_symbol(symbol);
        assert!(result.is_err());
        match result {
            Err(TypeMismatchError::InvalidMagic) => {}
            _ => panic!("Expected InvalidMagic error"),
        }
    }

    #[test]
    fn test_unsupported_format_byte_is_reported() {
        let value: u64 = 42;
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        let mut raw = symbol.into_symbol();

        // Corrupt the format byte to an unknown value.
        raw.data_mut()[14] = 4;

        let result = TypedSymbol::<u64>::try_from_symbol(raw);
        match result {
            Err(TypeMismatchError::UnsupportedFormatByte { value: 4 }) => {}
            other => panic!("expected UnsupportedFormatByte {{ value: 4 }}, got {other:?}"),
        }
    }

    #[test]
    fn test_type_registration() {
        let mut registry = TypeRegistry::new();

        assert!(!registry.is_registered::<Demo>());
        registry.register::<Demo>("Demo", 1);
        assert!(registry.is_registered::<Demo>());

        let desc = registry.get::<Demo>().unwrap();
        assert_eq!(desc.name, "Demo");
        assert_eq!(desc.version, 1);
    }

    #[test]
    fn test_type_registry_with_capacity_registration() {
        let mut registry = TypeRegistry::with_capacity(1);
        registry.register::<Demo>("Demo", 2);

        let desc = registry.get::<Demo>().unwrap();
        assert_eq!(desc.name, "Demo");
        assert_eq!(desc.version, 2);
    }

    #[test]
    fn test_schema_hash_stability() {
        // Same type and version should produce same hash
        let hash1 = schema_hash::<Demo>(1);
        let hash2 = schema_hash::<Demo>(1);
        assert_eq!(hash1, hash2);

        // Different version should produce different hash
        let hash3 = schema_hash::<Demo>(2);
        assert_ne!(hash1, hash3);

        // Different type should produce different hash
        let hash4 = schema_hash::<EmptyStruct>(1);
        assert_ne!(hash1, hash4);
    }

    #[test]
    fn test_empty_struct() {
        let value = EmptyStruct;
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        let decoded: EmptyStruct = symbol.into_value().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_deeply_nested_type() {
        let value = Nested {
            inner: Box::new(Some(Nested {
                inner: Box::new(Some(Nested {
                    inner: Box::new(None),
                    value: 3.14,
                })),
                value: 2.71,
            })),
            value: 1.41,
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Bincode).unwrap();
        let decoded: Nested = symbol.into_value().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_header_encode_decode_roundtrip() {
        let header = TypedHeader::new::<Demo>(SerializationFormat::Json, 5, 100);
        let encoded = header.encode();
        let decoded = TypedHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_serialization_format_byte_roundtrip() {
        for format in [
            SerializationFormat::MessagePack,
            SerializationFormat::Bincode,
            SerializationFormat::Json,
            SerializationFormat::Custom,
        ] {
            let byte = format.to_byte();
            let recovered = SerializationFormat::from_byte(byte).unwrap();
            assert_eq!(format, recovered);
        }
    }

    proptest! {
        #[test]
        fn typed_header_property_roundtrips_every_bounded_field(
            version in any::<u16>(),
            payload_len in any::<u32>(),
            format_index in 0usize..4,
        ) {
            let formats = [
                SerializationFormat::MessagePack,
                SerializationFormat::Bincode,
                SerializationFormat::Json,
                SerializationFormat::Custom,
            ];
            let header = TypedHeader::new::<Demo>(
                formats[format_index],
                version,
                payload_len,
            );
            let encoded = header.encode();

            prop_assert_eq!(encoded.len(), TYPED_SYMBOL_HEADER_LEN);
            let decoded = TypedHeader::decode(&encoded).expect("generated header must decode");
            prop_assert_eq!(decoded, header);
        }
    }

    // =========================================================================
    // Wave 59 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn serialization_format_debug_clone_copy_eq() {
        let fmt = SerializationFormat::Json;
        let dbg = format!("{fmt:?}");
        assert!(dbg.contains("Json"), "{dbg}");
        let copied = fmt;
        let cloned = fmt;
        assert_eq!(copied, cloned);
        assert_ne!(fmt, SerializationFormat::Bincode);
    }

    #[test]
    fn typed_symbol_json_snapshot_scrubbed_ids() {
        let value = Demo {
            id: 11,
            name: "typed".to_string(),
        };
        let symbol = TypedSymbol::from_value(&value, SerializationFormat::Json)
            .expect("create typed symbol");

        insta::assert_json_snapshot!(
            "typed_symbol_json_scrubbed_ids",
            serde_json::json!({
                "symbol_id": {
                    "object_id": "[OBJECT_ID]",
                    "sbn": symbol.symbol().sbn(),
                    "esi": symbol.symbol().esi(),
                },
                "kind": symbol.symbol().kind().to_string(),
                "format": format!("{:?}", symbol.format()),
                "version": symbol.version(),
                "payload_len": symbol.payload_len(),
                "value": symbol.value().expect("decode typed symbol"),
            })
        );
    }
}
