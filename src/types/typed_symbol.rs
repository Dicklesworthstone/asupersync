//! Typed symbol wrappers for encoding and decoding Rust types.
//!
//! Typed symbols attach a fixed header to each symbol payload so receivers can
//! validate type identity, schema version, and serialization format before
//! decoding. The encoder/decoder integrate with the existing RaptorQ
//! pipelines by reserving header space per symbol.

use crate::config::EncodingConfig;
use crate::decoding::{DecodingConfig, DecodingError, DecodingPipeline};
use crate::encoding::{EncodingError, EncodingPipeline};
use crate::security::tag::AuthenticationTag;
use crate::security::AuthenticatedSymbol;
use crate::transport::{SymbolSink, SymbolSinkExt, SymbolStream, SymbolStreamExt};
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol_set::SymbolSet;
use crate::types::{ObjectId, ObjectParams, Symbol, SymbolKind};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::any::TypeId;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

/// Magic prefix for typed symbols.
pub const TYPED_SYMBOL_MAGIC: [u8; 4] = *b"TSYM";
/// Header length in bytes.
pub const TYPED_SYMBOL_HEADER_LEN: usize = 27;

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
    /// Schema hash mismatch.
    #[error("schema hash mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema hash.
        expected: u64,
        /// Actual schema hash.
        actual: u64,
    },
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
                rmp_serde::to_vec(value).map_err(|err| SerializationError::SerializationFailed {
                    reason: err.to_string(),
                })
            }
            SerializationFormat::Bincode => {
                bincode::serialize(value).map_err(|err| SerializationError::SerializationFailed {
                    reason: err.to_string(),
                })
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
            SerializationFormat::MessagePack => rmp_serde::from_slice(bytes).map_err(|err| {
                DeserializationError::DeserializationFailed {
                    reason: err.to_string(),
                }
            }),
            SerializationFormat::Bincode => bincode::deserialize(bytes).map_err(|err| {
                DeserializationError::DeserializationFailed {
                    reason: err.to_string(),
                }
            }),
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
        let header = TypedHeader::decode(symbol.data())?;
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
        Ok(Self {
            symbol,
            header,
            _marker: PhantomData,
        })
    }

    /// Returns the underlying symbol.
    #[must_use]
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
        let end = TYPED_SYMBOL_HEADER_LEN + payload_len;
        if data.len() < end {
            return Err(DeserializationError::CorruptData);
        }
        Ok(&data[TYPED_SYMBOL_HEADER_LEN..end])
    }
}

impl<T: Serialize + DeserializeOwned + 'static> TypedSymbol<T> {
    /// Create a typed symbol from a value, using a single symbol payload.
    pub fn from_value(value: &T, format: SerializationFormat) -> Result<Self, SerializationError> {
        let codec = SerdeCodec;
        let payload = codec.serialize(value, format)?;
        let header = TypedHeader::new::<T>(format, 1, payload.len() as u32);
        let header_bytes = header.encode();

        let symbol_size = crate::types::DEFAULT_SYMBOL_SIZE;
        let max_payload = symbol_size.saturating_sub(TYPED_SYMBOL_HEADER_LEN);
        if payload.len() > max_payload {
            return Err(SerializationError::ValueTooLarge {
                size: payload.len(),
                max: max_payload,
            });
        }

        let mut data = Vec::with_capacity(TYPED_SYMBOL_HEADER_LEN + payload.len());
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

    /// Extract the value from a typed symbol.
    pub fn into_value(self) -> Result<T, DeserializationError> {
        let codec = SerdeCodec;
        let payload = self.strip_header()?;
        codec.deserialize(payload, self.header.format)
    }

    /// Borrow and decode the value from the typed symbol.
    pub fn value(&self) -> Result<T, DeserializationError> {
        let codec = SerdeCodec;
        let payload = self.strip_header()?;
        codec.deserialize(payload, self.header.format)
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

impl<T: Serialize + 'static> TypedEncoder<T> {
    /// Create a new typed encoder with default config.
    #[must_use]
    pub fn new(format: SerializationFormat) -> Self {
        Self::with_config(EncodingConfig::default(), format)
    }

    /// Create a new encoder with custom config.
    #[must_use]
    pub fn with_config(config: EncodingConfig, format: SerializationFormat) -> Self {
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
            version: 1,
            serializer: Box::new(serializer),
            _marker: PhantomData,
        }
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
                    })
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
            let auth =
                AuthenticatedSymbol::new_verified(symbol.into_symbol(), AuthenticationTag::zero());
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
            .finish_non_exhaustive()
    }
}

impl<T: DeserializeOwned> TypedDecoder<T> {
    /// Create a new typed decoder with default config.
    #[must_use]
    pub fn new(format: SerializationFormat) -> Self {
        Self::with_config(DecodingConfig::default(), format)
    }

    /// Create a decoder with custom config.
    #[must_use]
    pub fn with_config(config: DecodingConfig, format: SerializationFormat) -> Self {
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
            deserializer: Box::new(deserializer),
            _marker: PhantomData,
        }
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

        let header = validate_header::<T>(&first, self.format)?;
        let object_id = first.symbol().object_id();
        let inner_size = inner_symbol_size(self.config.symbol_size).map_err(|reason| {
            DecodingError::InconsistentMetadata {
                sbn: 0,
                details: reason,
            }
        })?;

        let mut pipeline = DecodingPipeline::new(inner_config(&self.config, inner_size));
        pipeline.set_object_params(object_params_for_payload(
            object_id,
            u64::from(header.payload_len),
            inner_size,
            self.config.max_block_size,
        ))?;

        feed_typed_symbol(&mut pipeline, first, inner_size)?;

        for symbol in iter {
            let current = validate_header::<T>(&symbol, self.format)?;
            if current != header {
                return Err(DecodingError::InconsistentMetadata {
                    sbn: symbol.symbol().sbn(),
                    details: "typed symbol header mismatch".to_string(),
                });
            }
            feed_typed_symbol(&mut pipeline, symbol, inner_size)?;
        }

        let payload = pipeline.into_data()?;
        self.deserializer
            .deserialize(&payload, header.format)
            .map_err(|err| DecodingError::InconsistentMetadata {
                sbn: 0,
                details: err.to_string(),
            })
    }

    /// Decode from a symbol set.
    pub fn decode_from_set(&mut self, set: &SymbolSet) -> Result<T, DecodingError>
    where
        T: 'static,
    {
        let symbols = set
            .iter()
            .map(|(_, symbol)| {
                TypedSymbol::try_from_symbol(symbol.clone()).map_err(|err| {
                    DecodingError::InconsistentMetadata {
                        sbn: symbol.sbn(),
                        details: err.to_string(),
                    }
                })
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
        let mut collected = Vec::new();
        while let Some(result) = stream.next().await {
            let symbol = result.map_err(|err| DecodingError::InconsistentMetadata {
                sbn: 0,
                details: err.to_string(),
            })?;
            let typed = TypedSymbol::try_from_symbol(symbol.into_symbol()).map_err(|err| {
                DecodingError::InconsistentMetadata {
                    sbn: 0,
                    details: err.to_string(),
                }
            })?;
            collected.push(typed);
        }
        self.decode(collected)
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
    let auth = AuthenticatedSymbol::new_verified(inner_symbol, AuthenticationTag::zero());
    let _ = pipeline.feed(auth)?;
    Ok(())
}

fn validate_header<T: 'static>(
    symbol: &TypedSymbol<T>,
    expected_format: SerializationFormat,
) -> Result<TypedHeader, DecodingError> {
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
    let max_block_size = max_block_size.max(usize::from(symbol_size));
    let blocks = (payload_len as usize).div_ceil(max_block_size).max(1);
    let symbols_per_block = max_block_size.div_ceil(usize::from(symbol_size)) as u16;
    ObjectParams::new(
        object_id,
        payload_len,
        symbol_size,
        blocks as u8,
        symbols_per_block,
    )
}

fn type_id_hash<T: 'static>() -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    TypeId::of::<T>().hash(&mut hasher);
    hasher.finish()
}

fn schema_hash<T: 'static>(version: u32) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::any::type_name::<T>().hash(&mut hasher);
    version.hash(&mut hasher);
    hasher.finish()
}

fn object_id_from_bytes<T: 'static>(bytes: &[u8]) -> ObjectId {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    std::any::type_name::<T>().hash(&mut hasher);
    let hash = hasher.finish();
    ObjectId::new(hash, hash.rotate_left(17))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Demo {
        id: u64,
        name: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct EmptyStruct;

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

        let mut decoder = TypedDecoder::with_config(
            DecodingConfig {
                symbol_size: 64,
                max_block_size: 128,
                repair_overhead: 1.05,
                min_overhead: 0,
                max_buffered_symbols: 0,
                block_timeout: std::time::Duration::from_secs(1),
                verify_auth: false,
            },
            SerializationFormat::Bincode,
        );

        let decoded_value = decoder.decode(symbols).expect("decode");
        assert_eq!(value, decoded_value);
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
}
